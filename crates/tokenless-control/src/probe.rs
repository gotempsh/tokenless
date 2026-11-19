// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Outbound test requests ("does this credential work?").
//!
//! The control plane decides *what* to send: the template's declared test
//! request (GET or HEAD on one exact path), to one of the credential's own
//! hosts, with the headers the proxy would inject. A [`CredentialProber`]
//! decides *how*, and must refuse destinations that the [`EgressPolicy`]
//! forbids. The response body is never read, only the status code.
//!
//! Every test sends the real credential to a real host, so tests are
//! limited ([`ProbeLimiter`]) and bounded in time ([`PROBE_TIMEOUT`]).

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use thiserror::Error;
use tokenless_core::egress::EgressPolicy;
use tokenless_core::injection::InjectedHeaders;

/// The longest a test may take, from resolving the host to the status line.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

pub struct ProbeRequest {
    pub host: String,
    pub port: u16,
    pub method: String,
    pub path: String,
    pub headers: InjectedHeaders,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProbeError {
    #[error("{host} resolves to {ip}, which is {reason}; allow the range in Settings to test it")]
    Blocked {
        host: String,
        ip: String,
        reason: String,
    },
    #[error("could not resolve {host}: {reason}")]
    Resolve { host: String, reason: String },
    #[error("test request to {host} failed: {reason}")]
    Request { host: String, reason: String },
    #[error("{host} did not answer within {secs}s")]
    TimedOut { host: String, secs: u64 },
    #[error("outbound test requests are not available in this deployment")]
    Unavailable,
}

#[async_trait]
pub trait CredentialProber: Send + Sync {
    /// Sends the request and returns the response status code. It must
    /// refuse addresses `egress` blocks, follow no redirect and not read
    /// the body.
    async fn probe(&self, request: ProbeRequest, egress: &EgressPolicy) -> Result<u16, ProbeError>;
}

/// A prober for deployments (and tests) that make no outbound calls.
#[derive(Debug, Default, Clone, Copy)]
pub struct DisabledProber;

#[async_trait]
impl CredentialProber for DisabledProber {
    async fn probe(&self, _: ProbeRequest, _: &EgressPolicy) -> Result<u16, ProbeError> {
        Err(ProbeError::Unavailable)
    }
}

/// How many tests may run within [`LIMIT_WINDOW`]: of one credential, by
/// one actor, and in all. A test sends the real credential to a host the
/// caller cannot choose, so this is about cost: neither the upstream nor
/// the control plane gets hammered, and nobody uses the endpoint to watch
/// a service's answers change.
pub const LIMIT_WINDOW: Duration = Duration::from_secs(60);
pub const PER_CREDENTIAL: usize = 5;
pub const PER_ACTOR: usize = 20;
pub const OVERALL: usize = 120;

/// Sliding-window limits on test requests, kept in memory: a restart
/// forgets them, which costs at most one window of extra tests.
#[derive(Debug, Default)]
pub struct ProbeLimiter {
    windows: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl ProbeLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes one test for `credential` by `actor`, or says how long to wait.
    pub fn acquire(&self, credential: &str, actor: &str) -> Result<(), Duration> {
        self.acquire_at(credential, actor, Instant::now())
    }

    /// [`Self::acquire`] at `now`. Every limit must have room; only then
    /// is the test counted against each, so a refused one costs nothing.
    pub fn acquire_at(&self, credential: &str, actor: &str, now: Instant) -> Result<(), Duration> {
        let keys = [
            (format!("credential:{credential}"), PER_CREDENTIAL),
            (format!("actor:{actor}"), PER_ACTOR),
            ("all".to_string(), OVERALL),
        ];
        // A poisoned lock only means a panic elsewhere; the counts are
        // still counts.
        let mut windows = self
            .windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        windows.retain(|_, w| {
            while w
                .front()
                .is_some_and(|t| now.saturating_duration_since(*t) >= LIMIT_WINDOW)
            {
                w.pop_front();
            }
            !w.is_empty()
        });
        let mut wait = Duration::ZERO;
        for (key, limit) in &keys {
            if let Some(w) = windows.get(key) {
                if w.len() >= *limit {
                    let oldest = w.front().copied().unwrap_or(now);
                    let free = LIMIT_WINDOW.saturating_sub(now.saturating_duration_since(oldest));
                    wait = wait.max(free);
                }
            }
        }
        if !wait.is_zero() {
            return Err(wait);
        }
        for (key, _) in keys {
            windows.entry(key).or_default().push_back(now);
        }
        Ok(())
    }
}

/// `text` with every secret value in `headers` (and each injected header
/// value) replaced, so nothing a prober reports can carry the credential
/// into a result, a log or the audit trail.
pub fn redact(text: &str, headers: &InjectedHeaders) -> String {
    let mut out = text.to_string();
    let values = headers.secrets.iter().map(|s| s.expose()).chain(
        headers
            .headers
            .iter()
            .filter(|h| !h.fixed)
            .map(|h| h.value.as_str()),
    );
    for value in values {
        // Very short values would blank out ordinary words.
        if value.len() >= 4 && out.contains(value) {
            out = out.replace(value, "[redacted]");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_limit_holds_and_frees_up_after_the_window() {
        let limiter = ProbeLimiter::new();
        let start = Instant::now();
        for _ in 0..PER_CREDENTIAL {
            limiter.acquire_at("c1", "alice", start).unwrap();
        }
        let wait = limiter.acquire_at("c1", "alice", start).unwrap_err();
        assert_eq!(wait, LIMIT_WINDOW);
        // Another credential still has room, for the same person.
        limiter.acquire_at("c2", "alice", start).unwrap();
        // Once the window has passed, the first one does too.
        let later = start + LIMIT_WINDOW;
        limiter.acquire_at("c1", "alice", later).unwrap();
    }

    #[test]
    fn one_actor_cannot_spread_tests_over_many_credentials() {
        let limiter = ProbeLimiter::new();
        let now = Instant::now();
        for i in 0..PER_ACTOR {
            limiter
                .acquire_at(&format!("c{i}"), "mallory", now)
                .unwrap();
        }
        assert!(limiter.acquire_at("fresh", "mallory", now).is_err());
        limiter.acquire_at("fresh", "bob", now).unwrap();
    }

    #[test]
    fn everyone_together_is_limited_too() {
        let limiter = ProbeLimiter::new();
        let now = Instant::now();
        for i in 0..OVERALL {
            limiter
                .acquire_at(&format!("c{i}"), &format!("a{i}"), now)
                .unwrap();
        }
        assert!(limiter.acquire_at("c-new", "a-new", now).is_err());
    }

    #[test]
    fn a_refused_test_is_not_counted() {
        let limiter = ProbeLimiter::new();
        let start = Instant::now();
        for _ in 0..PER_CREDENTIAL {
            limiter.acquire_at("c1", "alice", start).unwrap();
        }
        for _ in 0..50 {
            assert!(limiter.acquire_at("c1", "alice", start).is_err());
        }
        // The refusals did not use up alice's own allowance.
        for i in 0..PER_ACTOR - PER_CREDENTIAL {
            limiter
                .acquire_at(&format!("x{i}"), "alice", start)
                .unwrap();
        }
    }

    #[test]
    fn redaction_removes_secrets_and_header_values() {
        use tokenless_core::injection::{InjectedHeader, SecretMaterial};
        let headers = InjectedHeaders {
            headers: vec![InjectedHeader {
                name: "authorization".into(),
                value: "Bearer dummy-not-a-real-key".into(),
                fixed: false,
            }],
            substitutions: vec![],
            secrets: vec![SecretMaterial::new("dummy-not-a-real-key")],
        };
        let text = redact(
            "upstream said: Bearer dummy-not-a-real-key / dummy-not-a-real-key",
            &headers,
        );
        assert!(!text.contains("dummy-not-a-real-key"), "{text}");
        assert!(text.contains("[redacted]"));
    }
}
