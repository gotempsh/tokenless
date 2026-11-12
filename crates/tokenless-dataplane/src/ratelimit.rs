// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! How fast one session may send requests through this node. An agent at
//! work sends a few a second; something emptying an API through a stolen
//! session sends far more. Past the snapshot's [`RateLimit`] a request is
//! answered 429 with `Retry-After` and nothing is forwarded or queued.
//!
//! Load: this runs on every intercepted request. It takes no lock and
//! allocates nothing: a fixed table of [`SLOTS`] atomic slots (about
//! 100 KB), hashed by session, each holding a GCRA bucket in one atomic
//! (the time its bucket is next full), updated with a compare-and-swap.
//! Sessions that collide past [`PROBES`] slots take over an idle one, or
//! else evict each other's buckets; that only ever lets a session send
//! more, never less.
//!
//! Refusals are reported as one `proxy.rate_limited` event per session per
//! [`RATE_LIMIT_REPORT_SECS`], with how many there were, so a flood does
//! not flood the audit log. Only a session's first refusal in a period
//! takes the lock that remembers who to report.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokenless_core::audit::{AuditEvent, AuditOutcome};
use tokenless_core::ids::SessionId;
use tokenless_core::session::SessionClaims;
use tokenless_core::snapshot::{RateLimit, RATE_LIMITED_ACTION, RATE_LIMIT_REPORT_SECS};
use tracing::{debug, warn};

use crate::proxy::ProxyShared;

/// Slots in the bucket table; a power of two.
pub const SLOTS: usize = 4096;
/// Slots tried for a session before it takes over one.
pub const PROBES: usize = 4;
/// The most sessions waiting to be reported at once. Past it a session's
/// refusals are still refused and counted in the metric, and reported in
/// a later period.
pub const MAX_PENDING: usize = SLOTS;

struct Slot {
    /// The session's hash; 0 is a free slot.
    key: AtomicU64,
    /// Nanoseconds since the limiter started when the bucket is full
    /// again (GCRA's theoretical arrival time).
    tat: AtomicU64,
    /// Requests refused since the session was last reported.
    limited: AtomicU32,
}

pub struct RateLimiter {
    slots: Box<[Slot]>,
    started: Instant,
    /// Sessions refused since the last report, with the event to report
    /// them in. Locked only on a session's first refusal in a period.
    pending: Mutex<HashMap<SessionId, AuditEvent>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

fn key_of(session: &SessionId) -> u64 {
    let (high, low) = session.0.as_u64_pair();
    (high ^ low) | 1
}

fn nanos(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            slots: (0..SLOTS)
                .map(|_| Slot {
                    key: AtomicU64::new(0),
                    tat: AtomicU64::new(0),
                    limited: AtomicU32::new(0),
                })
                .collect(),
            started: Instant::now(),
            pending: Mutex::new(HashMap::new()),
        }
    }

    fn now(&self) -> u64 {
        nanos(self.started.elapsed())
    }

    fn probe(&self, key: u64, i: usize) -> &Slot {
        let first = usize::try_from(key).unwrap_or_default() & (SLOTS - 1);
        &self.slots[(first + i) & (SLOTS - 1)]
    }

    /// The session's slot, if it has one.
    fn find(&self, key: u64) -> Option<&Slot> {
        (0..PROBES)
            .map(|i| self.probe(key, i))
            .find(|s| s.key.load(Ordering::Acquire) == key)
    }

    fn slot(&self, key: u64, now: u64) -> &Slot {
        for i in 0..PROBES {
            let slot = self.probe(key, i);
            match slot.key.load(Ordering::Acquire) {
                k if k == key => return slot,
                0 => match slot
                    .key
                    .compare_exchange(0, key, Ordering::AcqRel, Ordering::Acquire)
                {
                    Ok(_) => {
                        slot.tat.store(0, Ordering::Release);
                        slot.limited.store(0, Ordering::Release);
                        return slot;
                    }
                    Err(k) if k == key => return slot,
                    Err(_) => {}
                },
                _ => {}
            }
        }
        // All taken: one whose bucket is full again, so nothing is lost,
        // or else the first.
        let slot = (0..PROBES)
            .map(|i| self.probe(key, i))
            .find(|s| s.tat.load(Ordering::Acquire) <= now)
            .unwrap_or_else(|| self.probe(key, 0));
        slot.key.store(key, Ordering::Release);
        slot.tat.store(0, Ordering::Release);
        slot.limited.store(0, Ordering::Release);
        slot
    }

    /// Takes one request from the session's bucket, or says how long
    /// until one is there.
    pub fn check(&self, session: &SessionId, limit: RateLimit) -> Result<(), Duration> {
        self.check_at(session, limit, self.now())
    }

    fn check_at(&self, session: &SessionId, limit: RateLimit, now: u64) -> Result<(), Duration> {
        let per_sec = u64::from(limit.per_sec.max(1));
        let interval = 1_000_000_000 / per_sec;
        let tolerance = interval.saturating_mul(u64::from(limit.burst.max(1)) - 1);
        let slot = self.slot(key_of(session), now);
        let mut tat = slot.tat.load(Ordering::Acquire);
        loop {
            let from = tat.max(now);
            let ahead = from - now;
            if ahead > tolerance {
                return Err(Duration::from_nanos(ahead - tolerance));
            }
            match slot.tat.compare_exchange_weak(
                tat,
                from.saturating_add(interval),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(current) => tat = current,
            }
        }
    }

    /// Counts a refused request, and remembers the session to report on
    /// its first refusal since it was last reported.
    pub(crate) fn refused(&self, session: &SessionId, event: impl FnOnce() -> AuditEvent) {
        let key = key_of(session);
        let slot = self.slot(key, self.now());
        if slot.limited.fetch_add(1, Ordering::AcqRel) != 0 {
            return;
        }
        let Ok(mut pending) = self.pending.lock() else {
            slot.limited.store(0, Ordering::Release);
            return;
        };
        if pending.len() >= MAX_PENDING && !pending.contains_key(session) {
            // Tried again on its next refusal.
            slot.limited.store(0, Ordering::Release);
            debug!(session_id = %session, "too many rate-limited sessions to report at once");
            return;
        }
        pending.entry(*session).or_insert_with(event);
    }

    /// The sessions refused since the last call, each with how many of its
    /// requests were.
    pub(crate) fn take_reports(&self) -> Vec<AuditEvent> {
        let drained = match self.pending.lock() {
            Ok(mut pending) => std::mem::take(&mut *pending),
            Err(_) => return Vec::new(),
        };
        drained
            .into_iter()
            .map(|(session, event)| {
                // At least the refusal that put it here, if its slot was
                // taken over since.
                let refused = self
                    .find(key_of(&session))
                    .map_or(0, |s| s.limited.swap(0, Ordering::AcqRel))
                    .max(1);
                event.detail("refused", refused.to_string())
            })
            .collect()
    }
}

/// The event a session's refusals are reported in, as of its first one.
pub(crate) fn report_event(
    shared: &ProxyShared,
    claims: &SessionClaims,
    limit: RateLimit,
    host: &str,
    port: u16,
) -> AuditEvent {
    crate::proxy::session_event(shared, claims, RATE_LIMITED_ACTION, AuditOutcome::Denied)
        .detail("host", format!("{host}:{port}"))
        .detail("per_sec", limit.per_sec.to_string())
        .detail("burst", limit.burst.to_string())
        .detail("window_secs", RATE_LIMIT_REPORT_SECS.to_string())
}

/// Records the sessions refused since the last report.
pub(crate) fn report(shared: &ProxyShared) {
    for event in shared.rate.take_reports() {
        if shared.audit.try_record(event).is_err() {
            warn!("a rate-limit report could not be queued; it is dropped");
        }
    }
}

/// Reports every [`RATE_LIMIT_REPORT_SECS`] until the data plane stops,
/// then once more.
pub(crate) async fn run_reports(shared: std::sync::Arc<ProxyShared>) {
    let mut lifecycle = shared.lifecycle.subscribe();
    let mut tick = tokio::time::interval(Duration::from_secs(RATE_LIMIT_REPORT_SECS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = tick.tick() => report(&shared),
            () = crate::shutdown::stopping(&mut lifecycle) => {
                report(&shared);
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests;
