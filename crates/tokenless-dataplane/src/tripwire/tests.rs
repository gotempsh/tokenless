// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::Utc;
use http::HeaderValue;
use tokenless_core::audit::AuditEvent;
use tokenless_core::egress::EgressPolicy;
use tokenless_core::scope::Scope;
use tokenless_core::seal::{seal, SealPublicKey};
use tokenless_core::session::SessionSigner;
use tokenless_core::snapshot::{
    tripwires_aad, SignedSnapshot, UnmatchedHostPolicy, TRIPWIRE_FORMAT,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::*;
use crate::audit::AuditShipper;
use crate::testing::{https_upstream, running_with, Running};

const DECOY: &str = "sk-decoyvalueforthetripwiretest0123456789";

fn wire(name: &str, value: &str, hosts: &[&str]) -> SnapshotTripwire {
    SnapshotTripwire {
        id: TripwireId::new(),
        name: name.into(),
        value: value.into(),
        hosts: hosts
            .iter()
            .map(|h| HostPattern::parse(h).unwrap())
            .collect(),
    }
}

fn built(list: Vec<SnapshotTripwire>) -> Tripwires {
    Tripwires::build(list).unwrap().unwrap()
}

fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (k, v) in pairs {
        h.insert(*k, HeaderValue::from_str(v).unwrap());
    }
    h
}

#[test]
fn a_decoy_is_found_in_a_header_the_url_or_basic_credentials() {
    let t = built(vec![
        wire("laptop", DECOY, &[]),
        wire("ci", "AKIAQWERTYUIOPASDFGH", &[]),
    ]);
    let uri: Uri = "/v1/models".parse().unwrap();
    let hit = t
        .find(
            &headers(&[("authorization", &format!("Bearer {DECOY}"))]),
            &uri,
        )
        .unwrap();
    assert_eq!(
        (hit.name.as_str(), hit.found_in.as_str()),
        ("laptop", "header authorization")
    );

    let signed =
        "AWS4-HMAC-SHA256 Credential=AKIAQWERTYUIOPASDFGH/20260101/us-east-1/sts/aws4_request";
    let hit = t
        .find(&headers(&[("authorization", signed)]), &uri)
        .unwrap();
    assert_eq!(hit.name, "ci");

    let in_url: Uri = format!("/download?key={DECOY}").parse().unwrap();
    assert_eq!(t.find(&HeaderMap::new(), &in_url).unwrap().found_in, "url");

    let basic = format!(
        "Basic {}",
        STANDARD.encode(format!("x-access-token:{DECOY}"))
    );
    let hit = t
        .find(&headers(&[("authorization", &basic)]), &uri)
        .unwrap();
    assert_eq!(hit.found_in, "header authorization (basic)");

    let clean = headers(&[
        ("authorization", "Bearer sk-somethingelse"),
        ("user-agent", "curl/8"),
    ]);
    assert_eq!(t.find(&clean, &uri), None);
    assert!(Tripwires::build(vec![]).unwrap().is_none());
}

#[test]
fn decoys_are_redacted_whole() {
    let t = built(vec![wire("laptop", DECOY, &[])]);
    assert_eq!(t.redact(&format!("/a/{DECOY}/b")), "/a/***/b");
    assert_eq!(t.redact("/nothing"), "/nothing");
}

#[derive(Default)]
struct Collect(std::sync::Mutex<Vec<AuditEvent>>);

#[async_trait::async_trait]
impl AuditShipper for Collect {
    async fn ship(&self, events: &[AuditEvent]) -> Result<(), crate::DataPlaneError> {
        self.0.lock().unwrap().extend_from_slice(events);
        Ok(())
    }
}

fn with_tripwires(
    r: &Running,
    version: u64,
    policy: UnmatchedHostPolicy,
    list: &[SnapshotTripwire],
) -> SignedSnapshot {
    let mut body = r.f.snapshot_body(
        version,
        vec![(r.rule, Scope::parse("vault:test").unwrap(), &r.host, "t")],
    );
    body.egress = EgressPolicy {
        block_private: false,
        allow: vec![],
    };
    body.unmatched_host_policy = policy;
    body.format = TRIPWIRE_FORMAT;
    body.tripwires = Some(
        seal(
            &SealPublicKey::from(&r.f.keys.seal_secret),
            &serde_json::to_vec(list).unwrap(),
            &tripwires_aad(&r.f.keys.node_id),
        )
        .unwrap(),
    );
    r.f.sign(&body)
}

async fn head(stream: &mut (impl AsyncRead + Unpin)) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).await.unwrap_or(0) == 0 {
            break;
        }
        head.push(byte[0]);
    }
    String::from_utf8_lossy(&head).into_owned()
}

async fn get(tls: &mut (impl AsyncRead + AsyncWrite + Unpin), target: &str, auth: &str) -> String {
    tls.write_all(
        format!("GET /user HTTP/1.1\r\nHost: {target}\r\nAuthorization: {auth}\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    head(tls).await
}

fn another_session(r: &Running) -> String {
    let claims = SessionClaims::new(
        Scope::parse("vault:test").unwrap(),
        vec![r.rule],
        600,
        None,
        BTreeMap::new(),
        Utc::now(),
        3600,
    )
    .unwrap();
    SessionSigner::new(r.f.session_signer.clone())
        .sign(&claims)
        .unwrap()
}

async fn reported(audit: &Collect) -> Vec<AuditEvent> {
    for _ in 0..100 {
        let found: Vec<AuditEvent> = audit
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.action == TRIPWIRE_ACTION)
            .cloned()
            .collect();
        if !found.is_empty() {
            return found;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Vec::new()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_carrying_a_decoy_is_refused_and_cuts_the_session_off() {
    let (port, root) = https_upstream("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
    let target = format!("localhost:{port}");
    let audit = Arc::new(Collect::default());
    let r = running_with(&target, vec![root], 600, audit.clone()).await;
    let laptop = wire("laptop", DECOY, &[]);
    r.installer
        .install(&with_tripwires(
            &r,
            2,
            UnmatchedHostPolicy::Passthrough,
            std::slice::from_ref(&laptop),
        ))
        .unwrap();
    let other = another_session(&r);

    // Ordinary traffic to the same host goes through.
    let mut tls = r.intercepted(&target, "localhost").await;
    assert!(get(&mut tls, &target, "Bearer placeholder")
        .await
        .starts_with("HTTP/1.1 200"));

    let mut tls = r.intercepted(&target, "localhost").await;
    let answer = get(&mut tls, &target, &format!("token {DECOY}")).await;
    assert!(answer.starts_with("HTTP/1.1 403"), "{answer}");

    // Cut off at once, even for what its rule allows; nobody else is.
    let mut stream = tokio::net::TcpStream::connect(r.dp.local_addr())
        .await
        .unwrap();
    stream
        .write_all(
            format!(
                "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Bearer {}\r\n\r\n",
                r.token
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let refused = head(&mut stream).await;
    assert!(refused.starts_with("HTTP/1.1 407"), "{refused}");
    let mut tls = r.intercepted_with(&target, "localhost", &other).await;
    assert!(get(&mut tls, &target, "Bearer placeholder")
        .await
        .starts_with("HTTP/1.1 200"));

    let events = reported(&audit).await;
    assert_eq!(events.len(), 1, "{events:?}");
    let e = &events[0];
    assert_eq!(e.detail["session_id"], r.jti.to_string());
    assert_eq!(e.detail["tripwire_id"], laptop.id.to_string());
    assert_eq!(e.detail["tripwire"], "laptop");
    assert_eq!(e.detail["found_in"], "header authorization");
    assert!(
        e.detail.values().all(|v| !v.contains(DECOY)),
        "the decoy never goes in the audit: {e:?}"
    );
    assert_eq!(
        r.dp.metrics()
            .tripwires_tripped_total
            .load(Ordering::Relaxed),
        1
    );
    assert!(r.dp.snapshot_for_tests().quarantined.contains_key(&r.jti));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn under_deny_a_decoy_s_host_is_opened_to_look_and_still_refused_without_it() {
    let (port, root) = https_upstream("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
    let (decoy_port, _) = https_upstream("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
    let target = format!("localhost:{port}");
    let decoy_host = format!("localhost:{decoy_port}");
    let audit = Arc::new(Collect::default());
    let r = running_with(&target, vec![root], 600, audit.clone()).await;
    let list = [wire("aws", "AKIAQWERTYUIOPASDFGH", &[&decoy_host])];
    r.installer
        .install(&with_tripwires(&r, 2, UnmatchedHostPolicy::Deny, &list))
        .unwrap();

    // No rule covers it: opened, and the request without the decoy refused.
    let mut tls = r.intercepted(&decoy_host, "localhost").await;
    let answer = get(&mut tls, &decoy_host, "Bearer something").await;
    assert!(answer.starts_with("HTTP/1.1 403"), "{answer}");
    assert!(r.dp.snapshot_for_tests().quarantined.is_empty());

    let mut tls = r.intercepted(&decoy_host, "localhost").await;
    let signed =
        "AWS4-HMAC-SHA256 Credential=AKIAQWERTYUIOPASDFGH/20260101/us-east-1/sts/aws4_request";
    let answer = get(&mut tls, &decoy_host, signed).await;
    assert!(answer.starts_with("HTTP/1.1 403"), "{answer}");
    let events = reported(&audit).await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].detail["host"], decoy_host);
    assert!(r.dp.snapshot_for_tests().quarantined.contains_key(&r.jti));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn under_passthrough_a_decoy_s_host_is_tunnelled_untouched() {
    let (port, root) = https_upstream("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
    let (decoy_port, _) = https_upstream("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
    let target = format!("localhost:{port}");
    let decoy_host = format!("localhost:{decoy_port}");
    let r = running_with(&target, vec![root], 600, Arc::new(Collect::default())).await;
    let list = [wire("aws", "AKIAQWERTYUIOPASDFGH", &[&decoy_host])];
    r.installer
        .install(&with_tripwires(
            &r,
            2,
            UnmatchedHostPolicy::Passthrough,
            &list,
        ))
        .unwrap();
    let before =
        r.dp.metrics()
            .tunnels_passthrough_total
            .load(Ordering::Relaxed);
    let _tunnel = r.tunnel(&decoy_host).await;
    for _ in 0..50 {
        if r.dp
            .metrics()
            .tunnels_passthrough_total
            .load(Ordering::Relaxed)
            > before
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the tunnel was not passed through");
}
