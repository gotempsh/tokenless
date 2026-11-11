// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cutting off a session that keeps being refused. An agent at work is
//! refused now and then; something trying host after host, path after
//! path, is more likely someone who got onto the agent's machine. Past the
//! snapshot's [`QuarantinePolicy`] the node stops serving the session at
//! once, as if it had been revoked, and reports `proxy.quarantine` so the
//! control plane revokes it everywhere.
//!
//! Load: this runs on refusals only, never on a request that is allowed.
//! Counting is lock-free: a fixed table of [`SLOTS`] atomic slots (about
//! 100 KB), hashed by session, so a flood of refusals neither allocates
//! nor takes a lock. Sessions that collide past [`PROBES`] slots evict
//! each other's counts; a session is never cut off early by that, only
//! later. Cutting off is rare and takes the snapshot's compare-and-swap.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use chrono::{DateTime, Utc};
use tokenless_core::audit::AuditOutcome;
use tokenless_core::ids::SessionId;
use tokenless_core::session::SessionClaims;
use tokenless_core::snapshot::{QuarantinePolicy, QUARANTINE_ACTION};
use tracing::warn;

use crate::metrics::Metrics;
use crate::proxy::ProxyShared;
use crate::state::ActiveSnapshot;

/// Slots in the refusal table; a power of two.
pub const SLOTS: usize = 4096;
/// Slots tried for a session before it takes over one.
pub const PROBES: usize = 4;
/// The most sessions a node keeps cut off while the control plane has not
/// listed them as revoked yet. Past it a session is still cut off, until
/// the next snapshot.
pub const MAX_QUARANTINED: usize = 10_000;

struct Slot {
    /// The session's hash; 0 is a free slot.
    key: AtomicU64,
    /// Seconds since the counter started, when the window began.
    window_start: AtomicU64,
    count: AtomicU32,
}

pub struct RefusalCounter {
    slots: Box<[Slot]>,
    started: Instant,
}

impl Default for RefusalCounter {
    fn default() -> Self {
        Self::new()
    }
}

fn key_of(session: &SessionId) -> u64 {
    let (high, low) = session.0.as_u64_pair();
    (high ^ low) | 1
}

impl RefusalCounter {
    pub fn new() -> Self {
        Self {
            slots: (0..SLOTS)
                .map(|_| Slot {
                    key: AtomicU64::new(0),
                    window_start: AtomicU64::new(0),
                    count: AtomicU32::new(0),
                })
                .collect(),
            started: Instant::now(),
        }
    }

    /// Counts a refusal of `session`. Returns the count when this refusal
    /// is the one that reaches `policy.refusals` within its window, once.
    pub fn refused(&self, session: &SessionId, policy: QuarantinePolicy) -> Option<u32> {
        self.refused_at(session, policy, self.started.elapsed().as_secs())
    }

    fn slot(&self, key: u64, now: u64, window: u64) -> &Slot {
        let first = usize::try_from(key).unwrap_or_default() & (SLOTS - 1);
        let probe = |i: usize| &self.slots[(first + i) & (SLOTS - 1)];
        for i in 0..PROBES {
            let slot = probe(i);
            match slot.key.load(Ordering::Acquire) {
                k if k == key => return slot,
                0 => match slot
                    .key
                    .compare_exchange(0, key, Ordering::AcqRel, Ordering::Acquire)
                {
                    Ok(_) => {
                        slot.window_start.store(now, Ordering::Release);
                        slot.count.store(0, Ordering::Release);
                        return slot;
                    }
                    Err(k) if k == key => return slot,
                    Err(_) => {}
                },
                _ => {}
            }
        }
        // All taken: one whose window is over, or else the first.
        let slot = (0..PROBES)
            .map(probe)
            .find(|s| now.saturating_sub(s.window_start.load(Ordering::Acquire)) >= window)
            .unwrap_or_else(|| probe(0));
        slot.key.store(key, Ordering::Release);
        slot.window_start.store(now, Ordering::Release);
        slot.count.store(0, Ordering::Release);
        slot
    }

    fn refused_at(&self, session: &SessionId, policy: QuarantinePolicy, now: u64) -> Option<u32> {
        let window = u64::from(policy.window_secs);
        let slot = self.slot(key_of(session), now, window);
        let started = slot.window_start.load(Ordering::Acquire);
        if now.saturating_sub(started) >= window
            && slot
                .window_start
                .compare_exchange(started, now, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            slot.count.store(0, Ordering::Release);
        }
        let count = slot.count.fetch_add(1, Ordering::AcqRel).saturating_add(1);
        (count == policy.refusals).then_some(count)
    }
}

impl ActiveSnapshot {
    /// This snapshot with `session` cut off until `exp`.
    pub(crate) fn with_quarantined(&self, session: SessionId, exp: DateTime<Utc>) -> Self {
        let mut next = self.clone();
        next.revoked.insert(session);
        if next.quarantined.len() < MAX_QUARANTINED {
            next.quarantined.insert(session, exp);
        }
        next
    }
}

/// The sessions `previous` cut off that the control plane has not listed
/// as revoked yet and that have not expired: they stay cut off.
pub(crate) fn still_quarantined(
    previous: Option<&ActiveSnapshot>,
    listed: &std::collections::HashSet<SessionId>,
    now: DateTime<Utc>,
) -> HashMap<SessionId, DateTime<Utc>> {
    previous
        .map(|p| {
            p.quarantined
                .iter()
                .filter(|(id, exp)| !listed.contains(id) && **exp > now)
                .map(|(id, exp)| (*id, *exp))
                .collect()
        })
        .unwrap_or_default()
}

/// Counts a refusal of the session behind `claims` and cuts it off when
/// the snapshot's policy says so.
/// Stops serving `claims`' session on this node at once, until the control
/// plane lists it as revoked. False when there is no snapshot to mark it in.
pub(crate) fn cut_off(shared: &ProxyShared, claims: &SessionClaims) -> bool {
    let marked = std::sync::atomic::AtomicBool::new(false);
    shared.snapshot.rcu(|current| {
        current.as_ref().map(|s| {
            marked.store(true, Ordering::Relaxed);
            Arc::new(s.with_quarantined(claims.jti, claims.exp))
        })
    });
    if !marked.load(Ordering::Relaxed) {
        return false;
    }
    shared.snapshot_changed.send_modify(|_| {});
    true
}

pub(crate) fn count_refusal(shared: &ProxyShared, claims: &SessionClaims) {
    let Some(policy) = shared.snapshot.load().as_ref().and_then(|s| s.quarantine) else {
        return;
    };
    let Some(refusals) = shared.refusals.refused(&claims.jti, policy) else {
        return;
    };
    if !cut_off(shared, claims) {
        return;
    }
    Metrics::inc(&shared.metrics.sessions_quarantined_total);
    warn!(
        session_id = %claims.jti,
        refusals,
        window_secs = policy.window_secs,
        "session cut off after repeated refusals"
    );
    let event =
        crate::proxy::session_event(shared, claims, QUARANTINE_ACTION, AuditOutcome::Denied)
            .detail("refusals", refusals.to_string())
            .detail("window_secs", policy.window_secs.to_string())
            .detail(
                "reason",
                format!(
                    "refused {refusals} times within {}s; cut off until someone reviews it",
                    policy.window_secs
                ),
            );
    let _ = shared.audit.try_record(event);
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use tokenless_core::audit::AuditEvent;
    use tokenless_core::egress::EgressPolicy;
    use tokenless_core::scope::Scope;
    use tokenless_core::session::SessionSigner;
    use tokenless_core::snapshot::{SignedSnapshot, UnmatchedHostPolicy, QUARANTINE_FORMAT};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    use super::*;
    use crate::audit::AuditShipper;
    use crate::testing::{https_upstream, running_with, Running};

    const POLICY: QuarantinePolicy = QuarantinePolicy {
        refusals: 3,
        window_secs: 60,
    };

    #[test]
    fn the_refusal_that_reaches_the_threshold_says_so_once() {
        let counter = RefusalCounter::new();
        let s = SessionId::new();
        assert_eq!(counter.refused_at(&s, POLICY, 0), None);
        assert_eq!(counter.refused_at(&s, POLICY, 1), None);
        assert_eq!(counter.refused_at(&s, POLICY, 2), Some(3));
        assert_eq!(counter.refused_at(&s, POLICY, 3), None);
    }

    #[test]
    fn refusals_spread_past_the_window_start_over() {
        let counter = RefusalCounter::new();
        let s = SessionId::new();
        counter.refused_at(&s, POLICY, 0);
        counter.refused_at(&s, POLICY, 30);
        // The window from the first refusal is over.
        assert_eq!(counter.refused_at(&s, POLICY, 61), None);
        assert_eq!(counter.refused_at(&s, POLICY, 62), None);
        assert_eq!(counter.refused_at(&s, POLICY, 63), Some(3));
    }

    #[test]
    fn sessions_are_counted_apart() {
        let counter = RefusalCounter::new();
        let (a, b) = (SessionId::new(), SessionId::new());
        counter.refused_at(&a, POLICY, 0);
        counter.refused_at(&a, POLICY, 0);
        assert_eq!(counter.refused_at(&b, POLICY, 0), None);
        assert_eq!(counter.refused_at(&b, POLICY, 0), None);
        assert_eq!(counter.refused_at(&a, POLICY, 0), Some(3));
    }

    #[test]
    fn many_sessions_fit_without_growing() {
        let counter = RefusalCounter::new();
        let sessions: Vec<SessionId> = (0..SLOTS * 2).map(|_| SessionId::new()).collect();
        for s in &sessions {
            counter.refused_at(s, POLICY, 0);
        }
        // A session counted from the start still reaches the threshold.
        let s = SessionId::new();
        counter.refused_at(&s, POLICY, 0);
        counter.refused_at(&s, POLICY, 0);
        assert_eq!(counter.refused_at(&s, POLICY, 0), Some(3));
        assert_eq!(counter.slots.len(), SLOTS);
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

    /// The running plane's rule, refusing unmatched hosts and cutting off
    /// after 3 refusals; `revoked` listed by the control plane.
    fn policy_snapshot(r: &Running, version: u64, revoked: Vec<SessionId>) -> SignedSnapshot {
        let mut body = r.f.snapshot_body(
            version,
            vec![(r.rule, Scope::parse("vault:test").unwrap(), &r.host, "t")],
        );
        body.egress = EgressPolicy {
            block_private: false,
            allow: vec![],
        };
        body.unmatched_host_policy = UnmatchedHostPolicy::Deny;
        body.quarantine = Some(POLICY);
        body.format = QUARANTINE_FORMAT;
        body.revoked_sessions = revoked;
        r.f.sign(&body)
    }

    async fn connect(r: &Running, target: &str, token: &str) -> String {
        let mut stream = TcpStream::connect(r.dp.local_addr()).await.unwrap();
        stream
            .write_all(
                format!(
                    "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Bearer {token}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if stream.read(&mut byte).await.unwrap_or(0) == 0 {
                break;
            }
            head.push(byte[0]);
        }
        String::from_utf8_lossy(&head)
            .lines()
            .next()
            .unwrap_or_default()
            .to_string()
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_session_refused_too_often_is_cut_off_until_the_control_plane_revokes_it() {
        let (port, root) = https_upstream("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
        let target = format!("localhost:{port}");
        let audit = Arc::new(Collect::default());
        let r = running_with(&target, vec![root], 600, audit.clone()).await;
        r.installer
            .install(&policy_snapshot(&r, 2, vec![]))
            .unwrap();
        let other = another_session(&r);

        assert!(connect(&r, &target, &r.token)
            .await
            .starts_with("HTTP/1.1 200"));
        for _ in 0..POLICY.refusals {
            let answer = connect(&r, "elsewhere.example:443", &r.token).await;
            assert!(answer.starts_with("HTTP/1.1 403"), "{answer}");
        }
        // Cut off: even what its rule allows.
        let answer = connect(&r, &target, &r.token).await;
        assert!(answer.starts_with("HTTP/1.1 407"), "{answer}");
        // Nobody else is.
        assert!(connect(&r, &target, &other)
            .await
            .starts_with("HTTP/1.1 200"));

        // Still cut off under a snapshot that does not list it yet.
        r.installer
            .install(&policy_snapshot(&r, 3, vec![]))
            .unwrap();
        let answer = connect(&r, &target, &r.token).await;
        assert!(answer.starts_with("HTTP/1.1 407"), "{answer}");

        // Reported once, with how many refusals did it.
        let mut reported = Vec::new();
        for _ in 0..100 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            reported = audit
                .0
                .lock()
                .unwrap()
                .iter()
                .filter(|e| e.action == QUARANTINE_ACTION)
                .cloned()
                .collect();
            if !reported.is_empty() {
                break;
            }
        }
        assert_eq!(reported.len(), 1, "{reported:?}");
        assert_eq!(reported[0].detail["session_id"], r.jti.to_string());
        assert_eq!(reported[0].detail["refusals"], "3");
        assert_eq!(reported[0].detail["window_secs"], "60");
        assert_eq!(
            r.dp.metrics()
                .sessions_quarantined_total
                .load(Ordering::Relaxed),
            1
        );

        // Once the control plane lists it, the node stops carrying it.
        r.installer
            .install(&policy_snapshot(&r, 4, vec![r.jti]))
            .unwrap();
        let current = r.dp.snapshot_for_tests();
        assert!(current.quarantined.is_empty());
        assert!(current.revoked.contains(&r.jti));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn no_policy_no_quarantine() {
        let (port, root) = https_upstream("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
        let target = format!("localhost:{port}");
        let r = running_with(&target, vec![root], 600, Arc::new(Collect::default())).await;
        let mut body = r.f.snapshot_body(
            2,
            vec![(r.rule, Scope::parse("vault:test").unwrap(), &r.host, "t")],
        );
        body.egress = EgressPolicy {
            block_private: false,
            allow: vec![],
        };
        body.unmatched_host_policy = UnmatchedHostPolicy::Deny;
        r.installer.install(&r.f.sign(&body)).unwrap();
        for _ in 0..10 {
            connect(&r, "elsewhere.example:443", &r.token).await;
        }
        assert!(connect(&r, &target, &r.token)
            .await
            .starts_with("HTTP/1.1 200"));
    }
}
