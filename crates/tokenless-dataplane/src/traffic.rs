// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Open traffic counted per session, so a host can wait for a revocation to
//! be enforced: [`DataPlane::session_cut`](crate::DataPlane::session_cut)
//! resolves once the revocation is installed and nothing the session opened
//! is still open.
//!
//! Touched once when a tunnel or gateway stream opens and once when it
//! closes, never per request. The counts are sharded by session so opening
//! one never waits on another session's lock; each critical section is a
//! map update.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex, PoisonError};

use tokenless_core::ids::SessionId;
use tokio::sync::Notify;

const SHARDS: usize = 16;

#[derive(Default)]
pub(crate) struct OpenTraffic {
    shards: [Mutex<HashMap<SessionId, usize>>; SHARDS],
    /// Notified whenever something closes.
    closed: Notify,
}

impl OpenTraffic {
    fn shard(&self, session: &SessionId) -> &Mutex<HashMap<SessionId, usize>> {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        session.hash(&mut hasher);
        &self.shards[(hasher.finish() as usize) % SHARDS]
    }

    /// Counts one more open tunnel or stream under `session` until the
    /// guard is dropped.
    pub fn enter(self: &Arc<Self>, session: SessionId) -> TrafficGuard {
        *self
            .shard(&session)
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(session)
            .or_default() += 1;
        TrafficGuard {
            traffic: self.clone(),
            session,
        }
    }

    /// Tunnels and streams open under `session`.
    pub fn count(&self, session: &SessionId) -> usize {
        self.shard(session)
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(session)
            .copied()
            .unwrap_or(0)
    }

    /// Resolves at the next close. Create it before checking the count, so
    /// a close in between is not missed.
    pub fn closed(&self) -> tokio::sync::futures::Notified<'_> {
        self.closed.notified()
    }
}

pub(crate) struct TrafficGuard {
    traffic: Arc<OpenTraffic>,
    session: SessionId,
}

impl Drop for TrafficGuard {
    fn drop(&mut self) {
        {
            let mut shard = self
                .traffic
                .shard(&self.session)
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(n) = shard.get_mut(&self.session) {
                *n -= 1;
                if *n == 0 {
                    shard.remove(&self.session);
                }
            }
        }
        self.traffic.closed.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn counts_per_session_and_wakes_on_close() {
        let traffic = Arc::new(OpenTraffic::default());
        let (a, b) = (SessionId::new(), SessionId::new());
        let first = traffic.enter(a);
        let second = traffic.enter(a);
        let other = traffic.enter(b);
        assert_eq!((traffic.count(&a), traffic.count(&b)), (2, 1));

        let woke = traffic.closed();
        tokio::pin!(woke);
        woke.as_mut().enable();
        drop(first);
        woke.await;
        assert_eq!(traffic.count(&a), 1);
        drop((second, other));
        assert_eq!((traffic.count(&a), traffic.count(&b)), (0, 0));
        assert!(traffic.shards.iter().all(|s| s.lock().unwrap().is_empty()));
    }
}
