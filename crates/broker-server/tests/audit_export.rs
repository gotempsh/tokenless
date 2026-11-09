// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Audit export end to end: a real server sending to a webhook receiver on
//! loopback, which goes down for a while and comes back. Signatures are
//! checked with an HMAC implementation other than the server's.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::routing::post;
use axum::Router;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use broker_server::{RunningServer, Server, ServerConfig};
use serde_json::{json, Value};

#[derive(Default)]
struct Receiver {
    /// (headers, body) of every request, including refused ones.
    requests: Mutex<Vec<(HeaderMap, Bytes)>>,
    down: AtomicBool,
}

async fn hook(State(r): State<Arc<Receiver>>, headers: HeaderMap, body: Bytes) -> StatusCode {
    r.requests.lock().unwrap().push((headers, body));
    if r.down.load(Ordering::SeqCst) {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::NO_CONTENT
    }
}

async fn start_receiver() -> (Arc<Receiver>, String) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let receiver = Arc::new(Receiver::default());
    let app = Router::new()
        .route("/hook", post(hook))
        .with_state(receiver.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (receiver, format!("http://127.0.0.1:{}/hook", addr.port()))
}

async fn admin_session(server: &RunningServer) -> (reqwest::Client, String, String) {
    let generated = server.initial_admin.as_ref().unwrap();
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    let response = http
        .post(format!("http://{}/api/v1/auth/login", server.api_addr))
        .json(&json!({ "username": "admin", "password": generated.password.as_str() }))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let cookie = response.headers()[header::SET_COOKIE.as_str()]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let body: Value = response.json().await.unwrap();
    (
        http,
        cookie,
        body["csrf_token"].as_str().unwrap().to_string(),
    )
}

/// Checks a Standard Webhooks signature with ring's HMAC.
fn verify(secret: &str, headers: &HeaderMap, body: &[u8]) -> bool {
    let key = STANDARD
        .decode(secret.strip_prefix("whsec_").unwrap())
        .unwrap();
    let id = headers["webhook-id"].to_str().unwrap();
    let timestamp = headers["webhook-timestamp"].to_str().unwrap();
    let signed = [id.as_bytes(), b".", timestamp.as_bytes(), b".", body].concat();
    let tag = ring::hmac::sign(
        &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key),
        &signed,
    );
    let expected = format!("v1,{}", STANDARD.encode(tag.as_ref()));
    headers["webhook-signature"].to_str().unwrap() == expected
}

/// The events the receiver accepted, once per batch id, in arrival order.
fn delivered(receiver: &Receiver) -> Vec<Value> {
    let requests = receiver.requests.lock().unwrap();
    let mut seen = std::collections::HashSet::new();
    let mut events = Vec::new();
    for (headers, body) in requests.iter() {
        let body: Value = serde_json::from_slice(body).unwrap();
        let id = headers["webhook-id"].to_str().unwrap().to_string();
        let accepted = body["events"][0]["action"] != "audit_export.test";
        if accepted && seen.insert(id) {
            events.extend(body["events"].as_array().unwrap().iter().cloned());
        }
    }
    events
}

async fn wait_for(what: &str, mut check: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while !check() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_events_reach_a_receiver_that_was_down_without_gaps() {
    let (receiver, url) = start_receiver().await;
    let data = tempfile::tempdir().unwrap();
    let mut config = ServerConfig::new(data.path());
    config.api_listen = "127.0.0.1:0".parse().unwrap();
    config.node_listen = "127.0.0.1:0".parse().unwrap();
    let server = Server::start(config).await.unwrap();
    let api = format!("http://{}/api/v1", server.api_addr);
    let (http, cookie, csrf) = admin_session(&server).await;
    let send = |method: reqwest::Method, path: &str| {
        http.request(method, format!("{api}{path}"))
            .header("cookie", &cookie)
            .header("x-csrf-token", &csrf)
    };

    let created = send(reqwest::Method::POST, "/audit-export/destinations")
        .json(&json!({
            "name": "Loopback SIEM",
            "url": url,
            "auth_header_name": "X-Receiver-Token",
            "auth_header_value": "receiver-token-value",
            "filter": { "action_prefixes": ["vault.", "audit_export."] },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), reqwest::StatusCode::CREATED);
    let created: Value = created.json().await.unwrap();
    let secret = created["signing_secret"].as_str().unwrap().to_string();
    let id = created["destination"]["id"].as_str().unwrap().to_string();
    assert!(secret.starts_with("whsec_"));

    // A test event first: delivered, and the cursor stays put.
    let test: Value = send(
        reqwest::Method::POST,
        &format!("/audit-export/destinations/{id}/test"),
    )
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    assert_eq!(test["delivered"], true);
    assert_eq!(test["status"], 204);

    let vault = |name: &'static str| {
        send(reqwest::Method::POST, "/vaults")
            .json(&json!({ "name": name }))
            .send()
    };
    assert!(vault("one").await.unwrap().status().is_success());
    wait_for("the first vault", || {
        delivered(&receiver)
            .iter()
            .any(|e| e["action"] == "vault.create")
    })
    .await;

    // The receiver goes down: the next event is retried, not lost.
    receiver.down.store(true, Ordering::SeqCst);
    assert!(vault("two").await.unwrap().status().is_success());
    let path = format!("/audit-export/destinations/{id}");
    let mut view = Value::Null;
    for _ in 0..150 {
        view = send(reqwest::Method::GET, &path)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if view["status"] == "retrying" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(view["status"], "retrying", "{view}");
    assert_eq!(view["last_error"], "the receiver answered 503");
    assert!(view["behind"].as_u64().unwrap() >= 1);

    receiver.down.store(false, Ordering::SeqCst);
    wait_for("the second vault after the receiver came back", || {
        delivered(&receiver)
            .iter()
            .filter(|e| e["action"] == "vault.create")
            .count()
            == 2
    })
    .await;

    // Every request was signed and carried the auth header; no event was
    // skipped or repeated across accepted batches.
    let requests = receiver.requests.lock().unwrap().clone();
    for (headers, body) in &requests {
        assert!(verify(&secret, headers, body), "bad signature");
        assert_eq!(headers["x-receiver-token"], "receiver-token-value");
        assert_eq!(headers[header::CONTENT_TYPE.as_str()], "application/json");
    }
    let events = delivered(&receiver);
    let numbers: Vec<u64> = events.iter().map(|e| e["seq"].as_u64().unwrap()).collect();
    assert!(numbers.windows(2).all(|w| w[0] < w[1]), "{numbers:?}");
    assert!(events.iter().all(|e| {
        let action = e["action"].as_str().unwrap();
        action.starts_with("vault.") || action.starts_with("audit_export.")
    }));

    let listed: Value = send(reqwest::Method::GET, "/audit-export/destinations")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let shown = listed.to_string();
    assert!(!shown.contains(&secret) && !shown.contains("receiver-token-value"));
    assert_eq!(listed[0]["has_auth_header"], true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn managing_audit_destinations_needs_an_admin_session() {
    let data = tempfile::tempdir().unwrap();
    let mut config = ServerConfig::new(data.path());
    config.api_listen = "127.0.0.1:0".parse().unwrap();
    config.node_listen = "127.0.0.1:0".parse().unwrap();
    let server = Server::start(config).await.unwrap();
    let api = format!("http://{}/api/v1", server.api_addr);
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    let anonymous = http
        .get(format!("{api}/audit-export/destinations"))
        .send()
        .await
        .unwrap();
    assert_eq!(anonymous.status(), reqwest::StatusCode::UNAUTHORIZED);
    let (http, cookie, _csrf) = admin_session(&server).await;
    // A write without the CSRF header is refused.
    let no_csrf = http
        .post(format!("{api}/audit-export/destinations"))
        .header("cookie", &cookie)
        .json(&json!({ "name": "x", "url": "https://siem.example.test/" }))
        .send()
        .await
        .unwrap();
    assert_eq!(no_csrf.status(), reqwest::StatusCode::FORBIDDEN);
    let bad_id = http
        .get(format!("{api}/audit-export/destinations/not-an-id"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(bad_id.status(), reqwest::StatusCode::BAD_REQUEST);
}
