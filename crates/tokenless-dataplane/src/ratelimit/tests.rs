// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::atomic::Ordering;
use std::sync::Arc;

use tokenless_core::egress::EgressPolicy;
use tokenless_core::scope::Scope;
use tokenless_core::snapshot::{SignedSnapshot, RATE_LIMIT_FORMAT};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::*;
use crate::audit::AuditShipper;
use crate::testing::{https_upstream, running_with, Running};

const SECOND: u64 = 1_000_000_000;

fn limit(per_sec: u32, burst: u32) -> RateLimit {
    RateLimit { per_sec, burst }
}

#[test]
fn a_burst_passes_and_the_rest_waits_for_the_rate() {
    let limiter = RateLimiter::new();
    let s = SessionId::new();
    let l = limit(2, 3);
    for _ in 0..3 {
        assert!(limiter.check_at(&s, l, SECOND).is_ok());
    }
    let wait = limiter.check_at(&s, l, SECOND).unwrap_err();
    assert_eq!(wait, Duration::from_millis(500));
    // Half a second later one more is there, then none.
    assert!(limiter.check_at(&s, l, SECOND + SECOND / 2).is_ok());
    assert!(limiter.check_at(&s, l, SECOND + SECOND / 2).is_err());
    // Idle long enough, the whole burst is back and no more.
    let later = 10 * SECOND;
    for _ in 0..3 {
        assert!(limiter.check_at(&s, l, later).is_ok());
    }
    assert!(limiter.check_at(&s, l, later).is_err());
}

#[test]
fn buckets_are_per_session() {
    let limiter = RateLimiter::new();
    let (a, b) = (SessionId::new(), SessionId::new());
    let l = limit(1, 1);
    assert!(limiter.check_at(&a, l, SECOND).is_ok());
    assert!(limiter.check_at(&a, l, SECOND).is_err());
    assert!(limiter.check_at(&b, l, SECOND).is_ok());
}

#[test]
fn a_sustained_rate_at_the_limit_always_passes() {
    let limiter = RateLimiter::new();
    let s = SessionId::new();
    let l = limit(10, 10);
    for i in 0..1000 {
        assert!(
            limiter.check_at(&s, l, SECOND + i * SECOND / 10).is_ok(),
            "request {i}"
        );
    }
}

#[test]
fn refusals_are_reported_once_a_period_with_their_count() {
    let limiter = RateLimiter::new();
    let (a, b) = (SessionId::new(), SessionId::new());
    let made = std::sync::atomic::AtomicU32::new(0);
    let event = |s: SessionId| {
        made.fetch_add(1, Ordering::Relaxed);
        AuditEvent::new("node:n", RATE_LIMITED_ACTION, AuditOutcome::Denied)
            .detail("session_id", s.to_string())
    };
    for _ in 0..5 {
        limiter.refused(&a, || event(a));
    }
    limiter.refused(&b, || event(b));
    // Built once per session, not per refusal.
    assert_eq!(made.load(Ordering::Relaxed), 2);
    let mut reports = limiter.take_reports();
    reports.sort_by_key(|e| e.detail["refused"].clone());
    let counts: Vec<(&str, &str)> = reports
        .iter()
        .map(|e| {
            (
                e.detail["session_id"].as_str(),
                e.detail["refused"].as_str(),
            )
        })
        .collect();
    assert_eq!(
        counts,
        vec![(b.to_string().as_str(), "1"), (a.to_string().as_str(), "5")]
    );
    assert!(limiter.take_reports().is_empty(), "reported once");
    limiter.refused(&a, || event(a));
    assert_eq!(limiter.take_reports()[0].detail["refused"], "1");
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

fn limited(r: &Running, per_sec: u32, burst: u32) -> SignedSnapshot {
    let mut body = r.f.snapshot_body(
        2,
        vec![(r.rule, Scope::parse("vault:test").unwrap(), &r.host, "t")],
    );
    body.egress = EgressPolicy {
        block_private: false,
        allow: vec![],
    };
    body.format = RATE_LIMIT_FORMAT;
    body.rate_limit = Some(limit(per_sec, burst));
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

async fn get(tls: &mut (impl AsyncRead + AsyncWrite + Unpin), target: &str) -> String {
    tls.write_all(format!("GET /v1/items HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    head(tls).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn past_its_burst_a_session_gets_429_with_retry_after_and_one_report() {
    let (port, root) = https_upstream("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
    let target = format!("localhost:{port}");
    let audit = Arc::new(Collect::default());
    let r = running_with(&target, vec![root], 600, audit.clone()).await;
    r.installer.install(&limited(&r, 1, 2)).unwrap();

    for _ in 0..2 {
        let mut tls = r.intercepted(&target, "localhost").await;
        assert!(get(&mut tls, &target).await.starts_with("HTTP/1.1 200"));
    }
    for _ in 0..3 {
        let mut tls = r.intercepted(&target, "localhost").await;
        let answer = get(&mut tls, &target).await;
        assert!(answer.starts_with("HTTP/1.1 429"), "{answer}");
        assert!(
            answer.to_ascii_lowercase().contains("retry-after: 1\r\n"),
            "{answer}"
        );
    }
    assert_eq!(
        r.dp.metrics()
            .requests_rate_limited_total
            .load(Ordering::Relaxed),
        3
    );

    report(r.dp.shared_for_tests());
    let mut events = Vec::new();
    for _ in 0..100 {
        events = audit
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.action == RATE_LIMITED_ACTION)
            .cloned()
            .collect();
        if !events.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(events.len(), 1, "{events:?}");
    let e = &events[0];
    assert_eq!(e.detail["session_id"], r.jti.to_string());
    assert_eq!(e.detail["refused"], "3");
    assert_eq!(e.detail["host"], target);
    assert_eq!(
        (e.detail["per_sec"].as_str(), e.detail["burst"].as_str()),
        ("1", "2")
    );
    // Not a refusal by policy: it never counts towards a quarantine.
    assert!(r.dp.snapshot_for_tests().quarantined.is_empty());
}
