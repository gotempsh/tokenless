// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bindings: proxy streams whose session comes from the host, not from the
//! client.
//!
//! A host that runs workloads it does not trust (a sandbox, a VM) binds
//! each one: it hands the data plane the workload's sessions and serves the
//! workload's proxy connections through the binding. The workload never
//! sees a token, and nothing it sends can choose another session: a
//! `Proxy-Authorization` header on a bound stream is ignored. Sessions are
//! minted for one binding (`sub` = `<binding id>/<generation>`), so they
//! work only through it, and a binding takes no other session.

use std::fmt;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use arc_swap::ArcSwapOption;
use chrono::{DateTime, Utc};
use tokenless_core::ids::NodeId;
use tokenless_core::session::{binding_subject, verify_session, SessionClaims, SessionError};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{oneshot, watch, Semaphore};
use zeroize::Zeroizing;

use crate::error::DataPlaneError;
use crate::metrics::Metrics;
use crate::proxy::{self, check_session, session_rules, ConnectionGuard, ProxyShared};
use crate::state::ActiveSnapshot;
use crate::status::{
    binding_status, session_problem, BindingStatus, NotReady, SessionStatus, UpstreamFailure,
    UpstreamFailureKind,
};

/// Sessions one binding may hold: one per group of services that share a
/// deadline.
pub const MAX_BINDING_SESSIONS: usize = 16;

/// What [`DataPlane::bind`](crate::DataPlane::bind) needs.
pub struct BindingSpec {
    /// The host's id for the workload, e.g. its sandbox id.
    pub binding_id: String,
    /// Which start of the workload; bumped on every (re)start.
    pub generation: u64,
    /// Session tokens minted for this binding. Kept in memory only and
    /// zeroed when the binding goes away.
    pub sessions: Vec<String>,
    /// Open connections, tunnels included, the workload may hold at once.
    pub max_connections: usize,
}

impl fmt::Debug for BindingSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BindingSpec")
            .field("binding_id", &self.binding_id)
            .field("generation", &self.generation)
            .field("sessions", &self.sessions.len())
            .field("max_connections", &self.max_connections)
            .finish()
    }
}

pub(crate) struct BindingState {
    pub id: String,
    pub generation: u64,
    /// `<binding id>/<generation>`: the `sub` its sessions carry.
    pub subject: Arc<str>,
    tokens: Vec<Zeroizing<String>>,
    /// The sessions' claims, once every token has verified: what the
    /// status reads instead of verifying each token again.
    claims: OnceLock<Vec<SessionClaims>>,
    revoked: watch::Sender<bool>,
    connections: Arc<Semaphore>,
    pub max_connections: usize,
    /// Written only when a request fails upstream, never per request.
    last_failure: ArcSwapOption<UpstreamFailure>,
    status_changed: watch::Sender<u64>,
}

/// The binding is gone from the status once its last holder lets go.
impl Drop for BindingState {
    fn drop(&mut self) {
        self.status_changed.send_modify(|n| *n = n.wrapping_add(1));
    }
}

/// What a tunnel opened through a binding watches: the binding being
/// revoked cuts it.
#[derive(Clone)]
pub(crate) struct BindingWatch {
    pub state: Arc<BindingState>,
    pub revoked: watch::Receiver<bool>,
}

impl BindingState {
    pub fn watch(self: &Arc<Self>) -> BindingWatch {
        BindingWatch {
            state: self.clone(),
            revoked: self.revoked.subscribe(),
        }
    }

    pub fn is_revoked(&self) -> bool {
        *self.revoked.borrow()
    }

    pub fn open_connections(&self) -> usize {
        self.max_connections - self.connections.available_permits()
    }

    pub fn last_failure(&self) -> Option<UpstreamFailure> {
        self.last_failure.load_full().map(|f| (*f).clone())
    }

    /// Notes a request through this binding that failed upstream, for its
    /// status.
    pub fn record_failure(&self, kind: UpstreamFailureKind, host: &str, port: u16) {
        self.last_failure.store(Some(Arc::new(UpstreamFailure {
            kind,
            host: host.to_string(),
            port,
            at: Utc::now(),
        })));
        self.status_changed.send_modify(|n| *n = n.wrapping_add(1));
    }

    fn claims(&self, snapshot: Option<&ActiveSnapshot>) -> Option<&[SessionClaims]> {
        if let Some(claims) = self.claims.get() {
            return Some(claims);
        }
        let snapshot = snapshot?;
        let verified: Vec<_> = self
            .tokens
            .iter()
            .map(|t| verify_session(t, &snapshot.session_keys, Utc::now()).ok())
            .collect::<Option<_>>()?;
        Some(self.claims.get_or_init(|| verified))
    }

    pub fn session_statuses(
        &self,
        snapshot: Option<&ActiveSnapshot>,
        node: &NodeId,
        now: DateTime<Utc>,
    ) -> Vec<SessionStatus> {
        let of = |c: &SessionClaims| SessionStatus {
            session_id: Some(c.jti),
            expires_at: Some(c.exp),
            problem: session_problem(snapshot, c, node, &self.subject, now),
        };
        if let Some(claims) = self.claims(snapshot) {
            return claims.iter().map(of).collect();
        }
        self.tokens
            .iter()
            .map(|token| {
                let Some(s) = snapshot else {
                    return SessionStatus {
                        session_id: None,
                        expires_at: None,
                        problem: Some(NotReady::Provisioning),
                    };
                };
                match verify_session(token, &s.session_keys, now) {
                    Ok(c) => of(&c),
                    Err(SessionError::Expired {
                        session_id,
                        expired_at,
                    }) => SessionStatus {
                        session_id: Some(session_id),
                        expires_at: Some(expired_at),
                        problem: Some(NotReady::Expired),
                    },
                    Err(_) => SessionStatus {
                        session_id: None,
                        expires_at: None,
                        problem: Some(NotReady::InvalidSession),
                    },
                }
            })
            .collect()
    }

    /// The session a CONNECT to `host:port` uses: the one valid session
    /// whose rules cover the host, or, when none does, the first valid one
    /// (the unmatched-host policy then decides).
    pub fn session_for(
        &self,
        snapshot: &ActiveSnapshot,
        host: &str,
        port: u16,
        node: &NodeId,
    ) -> Result<SessionClaims, &'static str> {
        if self.is_revoked() {
            return Err("this binding has been revoked");
        }
        let now = Utc::now();
        let mut valid = self.tokens.iter().filter_map(|token| {
            let claims = verify_session(token, &snapshot.session_keys, now).ok()?;
            check_session(snapshot, &claims, node, Some(&self.subject)).ok()?;
            Some(claims)
        });
        let Some(first) = valid.next() else {
            return Err("no session of this binding is valid: each has expired or been revoked");
        };
        let covers = |c: &SessionClaims| {
            session_rules(snapshot, c).any(|r| r.allow.matches_host(host, port))
        };
        let mut chosen: Option<SessionClaims> = covers(&first).then(|| first.clone());
        for claims in valid {
            if covers(&claims) {
                if chosen.is_some() {
                    return Err("more than one session of this binding covers this host, so none is used; give each service to one session");
                }
                chosen = Some(claims);
            }
        }
        Ok(chosen.unwrap_or(first))
    }
}

/// Why two of a binding's sessions may not be held together, if they may
/// not: both cover some host, so a request there would have no single
/// session, and one session's credential could be used under the other's
/// rules. Each service belongs to one session.
fn overlap(snapshot: &ActiveSnapshot, sessions: &[SessionClaims]) -> Option<String> {
    for (i, first) in sessions.iter().enumerate() {
        for second in &sessions[i + 1..] {
            for a in session_rules(snapshot, first).flat_map(|r| &r.allow.hosts) {
                for b in session_rules(snapshot, second).flat_map(|r| &r.allow.hosts) {
                    if a.overlaps(b) {
                        return Some(format!(
                            "sessions {} and {} both cover {}; give each service to one session",
                            first.jti,
                            second.jti,
                            if a.is_wildcard() { b } else { a }
                        ));
                    }
                }
            }
        }
    }
    None
}

/// A workload bound to its sessions. Serve each of its proxy connections
/// with [`Binding::serve`]. Revoking it, or dropping it, cuts every
/// connection and tunnel it opened. Share it behind an `Arc`.
pub struct Binding {
    state: Arc<BindingState>,
    shared: Arc<ProxyShared>,
}

impl Binding {
    pub(crate) fn new(spec: BindingSpec, shared: Arc<ProxyShared>) -> Result<Self, DataPlaneError> {
        let invalid = |reason: String| DataPlaneError::InvalidBinding {
            binding_id: spec.binding_id.clone(),
            reason,
        };
        let subject = binding_subject(&spec.binding_id, spec.generation)?;
        if spec.sessions.is_empty() || spec.sessions.len() > MAX_BINDING_SESSIONS {
            return Err(invalid(format!(
                "a binding needs 1-{MAX_BINDING_SESSIONS} sessions, got {}",
                spec.sessions.len()
            )));
        }
        if spec.max_connections == 0 {
            return Err(invalid("max_connections must be at least 1".into()));
        }
        // With a snapshot in force, a session that can never work here is
        // refused now rather than on the workload's first request.
        let mut claims = OnceLock::new();
        if let Some(snapshot) = shared.snapshot.load_full() {
            let mut verified: Vec<SessionClaims> = Vec::with_capacity(spec.sessions.len());
            for token in &spec.sessions {
                let claims = verify_session(token, &snapshot.session_keys, Utc::now())
                    .map_err(|e| invalid(format!("a session is not usable: {e}")))?;
                if claims.sub.as_deref() != Some(subject.as_str()) {
                    return Err(invalid(format!(
                        "session {} was minted for {}, not {subject}",
                        claims.jti,
                        claims.sub.as_deref().unwrap_or("use without a binding")
                    )));
                }
                if let Some(aud) = claims.aud.filter(|aud| *aud != shared.node) {
                    return Err(invalid(format!(
                        "session {} is for node {aud}, this node is {}",
                        claims.jti, shared.node
                    )));
                }
                verified.push(claims);
            }
            if let Some(reason) = overlap(&snapshot, &verified) {
                return Err(invalid(reason));
            }
            claims = OnceLock::from(verified);
        }
        let (revoked, _) = watch::channel(false);
        let state = Arc::new(BindingState {
            id: spec.binding_id,
            generation: spec.generation,
            subject: subject.into(),
            tokens: spec.sessions.into_iter().map(Zeroizing::new).collect(),
            claims,
            revoked,
            connections: Arc::new(Semaphore::new(spec.max_connections)),
            max_connections: spec.max_connections,
            last_failure: ArcSwapOption::empty(),
            status_changed: shared.status_changed.clone(),
        });
        shared.register_binding(&state);
        Ok(Self { state, shared })
    }

    pub fn id(&self) -> &str {
        &self.state.id
    }

    /// `<binding id>/<generation>`.
    pub fn subject(&self) -> &str {
        &self.state.subject
    }

    /// Serves one proxy connection from the workload: any byte stream (a
    /// TCP or Unix socket, a container relay, vsock). Returns when the
    /// connection and the tunnel it opened have closed, or when the binding
    /// is revoked. Refused once the data plane is shutting down.
    pub async fn serve<S>(&self, stream: S) -> Result<(), DataPlaneError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let state = &self.state;
        if state.is_revoked() {
            return Err(DataPlaneError::BindingRevoked {
                binding_id: state.id.clone(),
            });
        }
        if !self.shared.is_running() {
            return Err(DataPlaneError::ShuttingDown);
        }
        let Ok(own) = state.connections.clone().try_acquire_owned() else {
            Metrics::inc(&self.shared.metrics.connections_rejected);
            return Err(DataPlaneError::BindingFull {
                binding_id: state.id.clone(),
                max_connections: state.max_connections,
            });
        };
        let Ok(global) = self.shared.connections.clone().try_acquire_owned() else {
            Metrics::inc(&self.shared.metrics.connections_rejected);
            return Err(DataPlaneError::ConnectionLimit {
                max_connections: self.shared.max_connections,
            });
        };
        Metrics::inc(&self.shared.metrics.connections_total);
        let (done_tx, done) = oneshot::channel();
        let guard = Arc::new(ConnectionGuard::new(vec![own, global], Some(done_tx)));
        let connection =
            proxy::serve_stream(stream, self.shared.clone(), Some(self.state.clone()), guard);
        let mut revoked = state.revoked.subscribe();
        tokio::select! {
            () = async {
                connection.await;
                // The tunnel holds the guard until it closes.
                let _ = done.await;
            } => {}
            _ = revoked.wait_for(|r| *r) => {}
        }
        Ok(())
    }

    /// Cuts every connection and tunnel of this binding and refuses new
    /// ones. Idempotent.
    pub fn revoke(&self) {
        if !self.state.revoked.send_replace(true) {
            self.shared.status_bump();
        }
    }

    /// What its sessions can do now; see [`crate::status`].
    pub fn status(&self) -> BindingStatus {
        let snapshot = self.shared.snapshot.load_full();
        binding_status(
            &self.state,
            snapshot.as_deref(),
            &self.shared.node,
            Utc::now(),
        )
    }

    /// Resolves once a snapshot at least `min_version` is in force and
    /// every session of the binding can be used, so the workload can start.
    /// Fails at once on what waiting cannot fix (an expired or revoked
    /// session, a revoked binding), and with the last reason at `timeout`.
    pub async fn ready(&self, min_version: u64, timeout: Duration) -> Result<(), DataPlaneError> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut snapshots = self.shared.snapshot_changed.subscribe();
        let mut revoked = self.state.revoked.subscribe();
        loop {
            let installed = self.shared.snapshot.load().as_ref().map(|s| s.version);
            let problem = match installed {
                Some(v) if v >= min_version => self.status().problem(),
                _ => Some(NotReady::Provisioning),
            };
            let Some(problem) = problem else {
                return Ok(());
            };
            let not_ready = || DataPlaneError::NotReady {
                binding_id: self.state.id.clone(),
                reason: problem,
            };
            if !problem.can_recover() {
                return Err(not_ready());
            }
            tokio::select! {
                _ = snapshots.changed() => {}
                _ = revoked.changed() => {}
                () = tokio::time::sleep_until(deadline) => return Err(not_ready()),
            }
        }
    }
}

impl Drop for Binding {
    fn drop(&mut self) {
        self.revoke();
    }
}

impl fmt::Debug for Binding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Binding")
            .field("subject", &self.state.subject)
            .field("sessions", &self.state.tokens.len())
            .field("revoked", &self.state.is_revoked())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use rustls::pki_types::{CertificateDer, ServerName};
    use tokenless_core::ids::RuleId;
    use tokenless_core::scope::Scope;
    use tokenless_core::session::SessionSigner;
    use tokenless_core::snapshot::UnmatchedHostPolicy;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::net::TcpStream;
    use tokio::time::timeout;
    use tokio_rustls::TlsConnector;

    use super::*;
    use crate::audit::AuditShipper;
    use crate::state::tests::Fixture;
    use crate::state::NodeKeys;
    use crate::tls::upstream_client_config;
    use crate::{DataPlane, DataPlaneConfig};

    struct Discard;

    #[async_trait::async_trait]
    impl AuditShipper for Discard {
        async fn ship(
            &self,
            _: &[tokenless_core::audit::AuditEvent],
        ) -> Result<(), DataPlaneError> {
            Ok(())
        }
    }

    struct Plane {
        f: Fixture,
        dp: DataPlane,
        rule_a: RuleId,
        rule_b: RuleId,
    }

    fn scope() -> Scope {
        Scope::parse("vault:test").unwrap()
    }

    async fn plane() -> Plane {
        plane_with(DataPlaneConfig::default().max_connections).await
    }

    /// Rules for a.example.com and b.example.com; other hosts are denied.
    async fn plane_with(max_connections: usize) -> Plane {
        let f = Fixture::new();
        let keys = NodeKeys {
            node_id: f.keys.node_id,
            seal_secret: f.keys.seal_secret.clone(),
            snapshot_key: f.keys.snapshot_key,
        };
        let config = DataPlaneConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            max_connections,
            ..DataPlaneConfig::default()
        };
        let (dp, installer) = DataPlane::start_embedded(config, keys, Arc::new(Discard))
            .await
            .unwrap();
        let (rule_a, rule_b) = (RuleId::new(), RuleId::new());
        let mut body = f.snapshot_body(
            1,
            vec![
                (rule_a, scope(), "a.example.com", "ta"),
                (rule_b, scope(), "b.example.com", "tb"),
            ],
        );
        body.unmatched_host_policy = UnmatchedHostPolicy::Deny;
        installer.install(&f.sign(&body)).unwrap();
        Plane {
            f,
            dp,
            rule_a,
            rule_b,
        }
    }

    impl Plane {
        fn token(&self, rule: RuleId, bind: impl FnOnce(SessionClaims) -> SessionClaims) -> String {
            self.token_for(rule, 600, bind)
        }

        fn token_for(
            &self,
            rule: RuleId,
            ttl_secs: u64,
            bind: impl FnOnce(SessionClaims) -> SessionClaims,
        ) -> String {
            let claims = SessionClaims::new(
                scope(),
                vec![rule],
                ttl_secs,
                None,
                BTreeMap::new(),
                Utc::now(),
                3600,
            )
            .unwrap();
            SessionSigner::new(self.f.session_signer.clone())
                .sign(&bind(claims))
                .unwrap()
        }

        fn bound(&self, rule: RuleId, id: &str, generation: u64) -> String {
            let node = self.f.keys.node_id;
            self.token(rule, |c| {
                c.for_node(node).for_binding(id, generation).unwrap()
            })
        }

        fn bind(&self, id: &str, sessions: Vec<String>, max_connections: usize) -> Arc<Binding> {
            Arc::new(
                self.dp
                    .bind(BindingSpec {
                        binding_id: id.into(),
                        generation: 1,
                        sessions,
                        max_connections,
                    })
                    .unwrap(),
            )
        }
    }

    /// A workload connection through `binding`: sends CONNECT, optionally
    /// with a header naming another session, and returns the status line.
    async fn connect(
        binding: &Arc<Binding>,
        target: &str,
        spoofed: Option<&str>,
    ) -> (String, DuplexStream) {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let serving = binding.clone();
        tokio::spawn(async move { serving.serve(server).await });
        let header = spoofed
            .map(|t| format!("Proxy-Authorization: Bearer {t}\r\n"))
            .unwrap_or_default();
        client
            .write_all(
                format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{header}\r\n").as_bytes(),
            )
            .await
            .unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if client.read(&mut byte).await.unwrap() == 0 {
                break;
            }
            head.push(byte[0]);
        }
        let status = String::from_utf8_lossy(&head)
            .lines()
            .next()
            .unwrap_or_default()
            .to_string();
        (status, client)
    }

    #[tokio::test]
    async fn each_binding_uses_only_its_own_session_whatever_the_client_sends() {
        let p = plane().await;
        let (token_a, token_b) = (p.bound(p.rule_a, "sbx-a", 1), p.bound(p.rule_b, "sbx-b", 1));
        let a = p.bind("sbx-a", vec![token_a.clone()], 8);
        let b = p.bind("sbx-b", vec![token_b.clone()], 8);

        // A's workload names B's session: still A's session, which does not
        // cover b.example.com, so the deny policy refuses it.
        let (status, _) = connect(&a, "b.example.com:443", Some(&token_b)).await;
        assert!(status.contains(" 403 "), "{status}");
        let (status, _) = connect(&a, "a.example.com:443", Some(&token_b)).await;
        assert!(status.contains(" 200 "), "{status}");
        let (status, _) = connect(&b, "a.example.com:443", Some(&token_a)).await;
        assert!(status.contains(" 403 "), "{status}");
        let (status, _) = connect(&b, "b.example.com:443", None).await;
        assert!(status.contains(" 200 "), "{status}");

        // A bound session presented as a header on the listener is refused.
        let mut stream = TcpStream::connect(p.dp.local_addr()).await.unwrap();
        stream
            .write_all(
                format!("CONNECT a.example.com:443 HTTP/1.1\r\nHost: a.example.com:443\r\nProxy-Authorization: Bearer {token_a}\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        let answer = String::from_utf8_lossy(&buf[..n]);
        assert!(answer.starts_with("HTTP/1.1 407"), "{answer}");
        assert!(answer.contains("works only through it"), "{answer}");
        p.dp.abort();
    }

    /// Two sessions covering one host would leave a request there with no
    /// single session; the binding is refused instead.
    #[tokio::test]
    async fn sessions_that_cover_the_same_host_are_refused_at_bind() {
        let p = plane().await;
        let twice = vec![p.bound(p.rule_a, "sbx-a", 1), p.bound(p.rule_a, "sbx-a", 1)];
        let err =
            p.dp.bind(BindingSpec {
                binding_id: "sbx-a".into(),
                generation: 1,
                sessions: twice,
                max_connections: 8,
            })
            .unwrap_err();
        assert!(
            err.to_string().contains("both cover a.example.com"),
            "{err}"
        );
        p.dp.abort();
    }

    /// One session per group of services that share a deadline: when A's
    /// runs out, B's services keep working.
    #[tokio::test]
    async fn one_service_expires_while_the_other_keeps_working() {
        let p = plane().await;
        let node = p.f.keys.node_id;
        let short = p.token_for(p.rule_a, 1, |c| {
            c.for_node(node).for_binding("sbx-a", 1).unwrap()
        });
        let long = p.bound(p.rule_b, "sbx-a", 1);
        let binding = p.bind("sbx-a", vec![short, long], 8);
        let (status, _) = connect(&binding, "a.example.com:443", None).await;
        assert!(status.contains(" 200 "), "{status}");

        tokio::time::sleep(Duration::from_millis(1500)).await;
        let (status, _) = connect(&binding, "a.example.com:443", None).await;
        assert!(status.contains(" 403 "), "{status}");
        let (status, _) = connect(&binding, "b.example.com:443", None).await;
        assert!(status.contains(" 200 "), "{status}");
        p.dp.abort();
    }

    #[tokio::test]
    async fn sessions_for_another_start_node_or_none_are_refused_at_bind() {
        let p = plane().await;
        let refused = |sessions: Vec<String>| {
            p.dp.bind(BindingSpec {
                binding_id: "sbx-a".into(),
                generation: 2,
                sessions,
                max_connections: 8,
            })
            .unwrap_err()
        };
        let earlier = refused(vec![p.bound(p.rule_a, "sbx-a", 1)]);
        assert!(earlier.to_string().contains("not sbx-a/2"), "{earlier}");
        let other = NodeId::new();
        let elsewhere = refused(vec![p.token(p.rule_a, |c| {
            c.for_node(other).for_binding("sbx-a", 2).unwrap()
        })]);
        assert!(
            elsewhere.to_string().contains(&format!("for node {other}")),
            "{elsewhere}"
        );
        let unbound = refused(vec![p.token(p.rule_a, |c| c)]);
        assert!(
            unbound.to_string().contains("use without a binding"),
            "{unbound}"
        );
        assert!(matches!(
            refused(vec![]),
            DataPlaneError::InvalidBinding { .. }
        ));
        p.dp.abort();
    }

    #[tokio::test]
    async fn revoking_a_binding_cuts_its_open_tunnels_and_refuses_new_ones() {
        let p = plane().await;
        let a = p.bind("sbx-a", vec![p.bound(p.rule_a, "sbx-a", 1)], 8);
        let (status, stream) = connect(&a, "a.example.com:443", None).await;
        assert!(status.contains(" 200 "), "{status}");
        let client =
            upstream_client_config(false, &[CertificateDer::from(p.f.ca_cert_der.clone())])
                .unwrap();
        let mut tls = TlsConnector::from(client)
            .connect(ServerName::try_from("a.example.com").unwrap(), stream)
            .await
            .unwrap();

        a.revoke();
        let mut buf = [0u8; 64];
        let closed = timeout(Duration::from_secs(1), tls.read(&mut buf)).await;
        assert!(matches!(closed, Ok(Ok(0)) | Ok(Err(_))), "{closed:?}");
        let (_, server) = tokio::io::duplex(1024);
        assert!(matches!(
            a.serve(server).await,
            Err(DataPlaneError::BindingRevoked { .. })
        ));
        p.dp.abort();
    }

    #[tokio::test]
    async fn open_tunnels_count_against_the_bindings_connections() {
        let p = plane().await;
        let a = p.bind("sbx-a", vec![p.bound(p.rule_a, "sbx-a", 1)], 1);
        // The tunnel stays open waiting for the client's TLS hello.
        let (status, _open) = connect(&a, "a.example.com:443", None).await;
        assert!(status.contains(" 200 "), "{status}");
        let (_, server) = tokio::io::duplex(1024);
        assert!(matches!(
            a.serve(server).await,
            Err(DataPlaneError::BindingFull {
                max_connections: 1,
                ..
            })
        ));
        p.dp.abort();
    }

    #[tokio::test]
    async fn open_tunnels_count_against_the_data_planes_connections() {
        let p = plane_with(1).await;
        let token = p.token(p.rule_a, |c| c);
        let mut first = TcpStream::connect(p.dp.local_addr()).await.unwrap();
        first
            .write_all(
                format!("CONNECT a.example.com:443 HTTP/1.1\r\nHost: a.example.com:443\r\nProxy-Authorization: Bearer {token}\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let mut buf = vec![0u8; 1024];
        let n = first.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));

        // The tunnel is open, so a second connection is turned away, on the
        // listener and through a binding alike.
        let mut second = TcpStream::connect(p.dp.local_addr()).await.unwrap();
        let read = timeout(Duration::from_secs(1), second.read(&mut buf)).await;
        assert!(matches!(read, Ok(Ok(0)) | Ok(Err(_))), "{read:?}");
        let a = p.bind("sbx-a", vec![p.bound(p.rule_a, "sbx-a", 1)], 8);
        let (_, server) = tokio::io::duplex(1024);
        assert!(matches!(
            a.serve(server).await,
            Err(DataPlaneError::ConnectionLimit { max_connections: 1 })
        ));
        drop(first);
        p.dp.abort();
    }
}
