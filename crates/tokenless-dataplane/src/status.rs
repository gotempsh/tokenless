// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! What an embedder shows its users: whether the data plane and each
//! binding can carry traffic, and if not, why.
//!
//! [`DataPlane::status`](crate::DataPlane::status) reads it once;
//! [`DataPlane::events`](crate::DataPlane::events) keeps the latest one in a
//! `watch`, updated when a snapshot arrives, a binding is made or revoked,
//! an upstream fails, or a lease or session runs out, so nobody polls.
//! Every reason is typed and comes from the same checks the proxy makes,
//! never from log text. Nothing here holds a token or a secret.

use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, TimeDelta, Utc};
use serde::Serialize;
use tokenless_core::ids::{NodeId, SessionId};
use tokenless_core::session::SessionClaims;
use tokio::sync::watch;
use tokio::time::sleep_until;

use crate::binding::BindingState;
use crate::proxy::{session_rules, ProxyShared};
use crate::state::ActiveSnapshot;

/// Why something cannot carry traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotReady {
    /// No snapshot is installed yet, or it is older than the one waited
    /// for, or a request-limited session is not in it yet.
    Provisioning,
    /// The snapshot's lease ran out (the control plane is unreachable):
    /// every request is refused until a new one arrives.
    StalePolicy,
    /// None of the session's rules is in the snapshot: they were deleted
    /// or disabled.
    NotConfigured,
    Expired,
    Revoked,
    BindingRevoked,
    /// The token does not verify against the snapshot's keys, or was
    /// minted for another node or binding.
    InvalidSession,
}

impl NotReady {
    pub fn reason(self) -> &'static str {
        match self {
            Self::Provisioning => "waiting for the policy that covers it",
            Self::StalePolicy => {
                "the policy lease expired (control plane unreachable), so all traffic is refused"
            }
            Self::NotConfigured => "none of its rules is in the policy any more",
            Self::Expired => "the session expired",
            Self::Revoked => "the session was revoked",
            Self::BindingRevoked => "the binding was revoked",
            Self::InvalidSession => "the session does not verify here: wrong keys, node or binding",
        }
    }

    /// Will waiting fix it? A later snapshot can; nothing brings back an
    /// expired or revoked session.
    pub fn can_recover(self) -> bool {
        matches!(
            self,
            Self::Provisioning | Self::StalePolicy | Self::NotConfigured
        )
    }
}

/// The last request through a binding that failed upstream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpstreamFailure {
    pub kind: UpstreamFailureKind,
    pub host: String,
    pub port: u16,
    pub at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamFailureKind {
    /// The request could not be sent: connection, TLS or timeout.
    Unreachable,
    /// The upstream answered 401 to a request carrying the injected
    /// credential.
    CredentialRejected,
    /// The credential's `not_after` has passed, so nothing was sent; it
    /// works again once its secret is replaced.
    CredentialExpired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Status {
    /// `None` until a snapshot is installed.
    pub snapshot_version: Option<u64>,
    /// When the snapshot's lease runs out, to the second.
    pub lease_until: Option<DateTime<Utc>>,
    /// Why nothing can be carried now, if so.
    pub problem: Option<NotReady>,
    pub open_connections: usize,
    pub max_connections: usize,
    pub bindings: Vec<BindingStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BindingStatus {
    pub binding_id: String,
    pub generation: u64,
    pub revoked: bool,
    pub open_connections: usize,
    pub max_connections: usize,
    pub sessions: Vec<SessionStatus>,
    pub last_failure: Option<UpstreamFailure>,
}

impl BindingStatus {
    /// Why the binding cannot carry all of its services, if so: its own
    /// revocation, or the first session's problem.
    pub fn problem(&self) -> Option<NotReady> {
        if self.revoked {
            return Some(NotReady::BindingRevoked);
        }
        self.sessions.iter().find_map(|s| s.problem)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionStatus {
    /// `None` when the token could not be read at all.
    pub session_id: Option<SessionId>,
    pub expires_at: Option<DateTime<Utc>>,
    pub problem: Option<NotReady>,
}

/// What stops `claims` from being used through `subject` now, if anything.
pub(crate) fn session_problem(
    snapshot: Option<&ActiveSnapshot>,
    claims: &SessionClaims,
    node: &NodeId,
    subject: &str,
    now: DateTime<Utc>,
) -> Option<NotReady> {
    if now >= claims.exp {
        return Some(NotReady::Expired);
    }
    if claims.aud.is_some_and(|aud| aud != *node) || claims.sub.as_deref() != Some(subject) {
        return Some(NotReady::InvalidSession);
    }
    let Some(snapshot) = snapshot else {
        return Some(NotReady::Provisioning);
    };
    if snapshot.revoked.contains(&claims.jti) {
        return Some(NotReady::Revoked);
    }
    if !snapshot.lease_valid() {
        return Some(NotReady::StalePolicy);
    }
    if claims.request_limit.is_some() && !snapshot.limits.contains_key(&claims.jti) {
        return Some(NotReady::Provisioning);
    }
    if session_rules(snapshot, claims).next().is_none() {
        return Some(NotReady::NotConfigured);
    }
    None
}

fn lease_until(snapshot: &ActiveSnapshot, now: DateTime<Utc>) -> DateTime<Utc> {
    let at = match snapshot
        .lease_deadline
        .checked_duration_since(Instant::now())
    {
        Some(left) => now + TimeDelta::from_std(left).unwrap_or(TimeDelta::MAX),
        None => now,
    };
    // Whole seconds, so a status read twice without a change compares equal.
    DateTime::from_timestamp(at.timestamp(), 0).unwrap_or(at)
}

pub(crate) fn status(shared: &ProxyShared) -> Status {
    let snapshot = shared.snapshot.load_full();
    let now = Utc::now();
    let problem = match snapshot.as_deref() {
        None => Some(NotReady::Provisioning),
        Some(s) if !s.lease_valid() => Some(NotReady::StalePolicy),
        Some(_) => None,
    };
    let bindings = shared
        .live_bindings()
        .iter()
        .map(|b| binding_status(b, snapshot.as_deref(), &shared.node, now))
        .collect();
    Status {
        snapshot_version: snapshot.as_ref().map(|s| s.version),
        lease_until: snapshot.as_deref().map(|s| lease_until(s, now)),
        problem,
        open_connections: shared.max_connections - shared.connections.available_permits(),
        max_connections: shared.max_connections,
        bindings,
    }
}

pub(crate) fn binding_status(
    binding: &BindingState,
    snapshot: Option<&ActiveSnapshot>,
    node: &NodeId,
    now: DateTime<Utc>,
) -> BindingStatus {
    BindingStatus {
        binding_id: binding.id.clone(),
        generation: binding.generation,
        revoked: binding.is_revoked(),
        open_connections: binding.open_connections(),
        max_connections: binding.max_connections,
        sessions: binding.session_statuses(snapshot, node, now),
        last_failure: binding.last_failure(),
    }
}

/// When `status` next changes with nothing happening: a lease or a session
/// running out.
fn next_change(status: &Status) -> Option<DateTime<Utc>> {
    let sessions = status
        .bindings
        .iter()
        .flat_map(|b| &b.sessions)
        .filter(|s| s.problem.is_none())
        .filter_map(|s| s.expires_at);
    let lease = status.lease_until.filter(|_| status.problem.is_none());
    lease.into_iter().chain(sessions).min()
}

/// The longest the status loop sleeps without a change.
const MAX_WAIT: Duration = Duration::from_secs(60);

/// Keeps `tx` at the latest status. Runs O(bindings) per change.
pub(crate) async fn run_status_loop(shared: Arc<ProxyShared>, tx: watch::Sender<Status>) {
    let mut snapshots = shared.snapshot_changed.subscribe();
    let mut changes = shared.status_changed.subscribe();
    loop {
        let current = status(&shared);
        let wake = match next_change(&current) {
            // Just past it: a lease is rounded down to the second.
            Some(at) => {
                (at - Utc::now()).to_std().unwrap_or(Duration::ZERO) + Duration::from_millis(1100)
            }
            None => MAX_WAIT,
        }
        .min(MAX_WAIT);
        tx.send_if_modified(|seen| {
            let changed = *seen != current;
            if changed {
                *seen = current;
            }
            changed
        });
        tokio::select! {
            r = snapshots.changed() => if r.is_err() { return },
            r = changes.changed() => if r.is_err() { return },
            () = sleep_until(tokio::time::Instant::now() + wake) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::timeout;

    use super::*;
    use crate::testing::{https_upstream, running};
    use crate::DataPlaneError;

    /// Waits until the latest status satisfies `ok`, without polling.
    async fn until(rx: &mut watch::Receiver<Status>, ok: impl Fn(&Status) -> bool) -> Status {
        timeout(Duration::from_secs(5), rx.wait_for(|s| ok(s)))
            .await
            .expect("the status never got there")
            .unwrap()
            .clone()
    }

    #[tokio::test]
    async fn events_follow_a_binding_from_bind_to_expiry_and_revocation() {
        let r = running("api.example.com", vec![]).await;
        let mut events = r.dp.events();
        let seen = until(&mut events, |s| s.snapshot_version == Some(1)).await;
        assert_eq!(seen.problem, None);
        assert!(seen.lease_until.is_some());

        let (short, short_id) = r.bound_token("sbx-1", 1, 1);
        let binding = r.bind("sbx-1", vec![short.clone()]);
        let seen = until(&mut events, |s| s.bindings.len() == 1).await;
        let b = &seen.bindings[0];
        assert_eq!((b.binding_id.as_str(), b.generation), ("sbx-1", 1));
        assert_eq!(b.sessions[0].session_id, Some(short_id));
        assert_eq!(b.problem(), None);

        // A session running out is an event too, with nothing else changing.
        let seen = until(&mut events, |s| {
            s.bindings[0].sessions[0].problem == Some(NotReady::Expired)
        })
        .await;
        assert_eq!(seen.bindings[0].problem(), Some(NotReady::Expired));

        binding.revoke();
        let seen = until(&mut events, |s| s.bindings[0].revoked).await;
        assert_eq!(seen.bindings[0].problem(), Some(NotReady::BindingRevoked));

        // Diagnostics never carry a token.
        let json = serde_json::to_string(&r.dp.status()).unwrap();
        assert!(!json.contains(&short), "{json}");
        assert!(!format!("{:?}", r.dp.status()).contains(&short));

        drop(binding);
        let seen = until(&mut events, |s| s.bindings.is_empty()).await;
        assert!(seen.bindings.is_empty());
        r.dp.abort();
    }

    #[tokio::test]
    async fn ready_waits_for_the_snapshot_and_fails_at_once_when_waiting_cannot_help() {
        let r = running("api.example.com", vec![]).await;
        let (token, jti) = r.bound_token("sbx-1", 1, 600);
        let binding = r.bind("sbx-1", vec![token]);
        binding.ready(1, Duration::from_secs(1)).await.unwrap();

        let err = binding
            .ready(2, Duration::from_millis(100))
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                DataPlaneError::NotReady {
                    reason: NotReady::Provisioning,
                    ..
                }
            ),
            "{err}"
        );

        let waiting = {
            let binding = binding.clone();
            tokio::spawn(async move { binding.ready(2, Duration::from_secs(5)).await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        r.installer.install(&r.snapshot(2, vec![])).unwrap();
        waiting.await.unwrap().unwrap();

        r.installer.install(&r.snapshot(3, vec![jti])).unwrap();
        let started = std::time::Instant::now();
        let err = binding.ready(3, Duration::from_secs(5)).await.unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(err.to_string().contains("the session was revoked"), "{err}");
        r.dp.abort();
    }

    /// A credential past its deadline is not sent: the request gets a
    /// typed 503 and the binding says why.
    #[tokio::test]
    async fn a_credential_past_its_deadline_is_not_injected() {
        let (port, root) = https_upstream("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
        let target = format!("localhost:{port}");
        let r = running(&target, vec![root]).await;
        let (token, _) = r.bound_token("sbx-1", 1, 600);
        let binding = r.bind("sbx-1", vec![token]);
        let ahead = Utc::now() + TimeDelta::hours(1);
        r.installer.install(&r.snapshot_until(2, ahead)).unwrap();
        let status = r.request_through(&binding, &target).await;
        assert!(status.contains(" 200 "), "{status}");

        let past = Utc::now() - TimeDelta::seconds(1);
        r.installer.install(&r.snapshot_until(3, past)).unwrap();
        let status = r.request_through(&binding, &target).await;
        assert!(status.contains(" 503 "), "{status}");
        let failure = binding.status().last_failure.unwrap();
        assert_eq!(failure.kind, UpstreamFailureKind::CredentialExpired);
        r.dp.abort();
    }

    #[tokio::test]
    async fn a_rejected_credential_and_an_unreachable_upstream_show_on_the_binding() {
        let (port, root) =
            https_upstream("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n").await;
        let target = format!("localhost:{port}");
        let r = running(&target, vec![root]).await;
        let (token, _) = r.bound_token("sbx-1", 1, 600);
        let binding = r.bind("sbx-1", vec![token]);
        let status = r.request_through(&binding, &target).await;
        assert!(status.contains(" 401 "), "{status}");
        let failure = binding.status().last_failure.unwrap();
        assert_eq!(failure.kind, UpstreamFailureKind::CredentialRejected);
        assert_eq!((failure.host.as_str(), failure.port), ("localhost", port));

        // Nothing listens there any more.
        let dead = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        };
        let target = format!("localhost:{dead}");
        let r = running(&target, vec![]).await;
        let (token, _) = r.bound_token("sbx-1", 1, 600);
        let binding = r.bind("sbx-1", vec![token]);
        let status = r.request_through(&binding, &target).await;
        assert!(status.contains(" 502 "), "{status}");
        let failure = binding.status().last_failure.unwrap();
        assert_eq!(failure.kind, UpstreamFailureKind::Unreachable);
        r.dp.abort();
    }
}
