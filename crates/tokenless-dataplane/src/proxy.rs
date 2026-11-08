// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The forward proxy.
//!
//! `CONNECT host:port` with `Proxy-Authorization` carrying a session token:
//! * no snapshot, or the lease ran out -> 503 (fail closed)
//! * missing / invalid / expired / revoked session -> 407
//! * a rule in the session covers the host -> TLS is intercepted and each
//!   request is checked, audited and injected
//! * otherwise -> plain TCP tunnel, or 403 when the policy is `deny`
//!
//! Plain-HTTP proxy requests are refused: credentials are never injected on
//! plain HTTP and the broker is not a general HTTP proxy.

use std::convert::Infallible;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bytes::Bytes;
use chrono::Utc;
use http::header::{CONNECTION, CONTENT_TYPE, HOST, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls::ClientConfig;
use tokenless_core::audit::{AuditEvent, AuditOutcome};
use tokenless_core::host::parse_authority;
use tokenless_core::ids::NodeId;
use tokenless_core::mcp::{self, McpMessage, NotJsonRpc};
use tokenless_core::path::check_request_path;
use tokenless_core::rule::RuleScope;
use tokenless_core::session::{verify_session, SessionClaims};
use tokenless_core::snapshot::UnmatchedHostPolicy;
use tokenless_core::substitution::{
    apply_to_body, apply_to_header, apply_to_target, wants_body, Applied, BodyKind,
    RenderedSubstitution,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, watch, OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;
use tokio_rustls::LazyConfigAcceptor;
use tracing::{debug, info, warn};

use crate::audit::AuditPipeline;
use crate::binding::BindingState;
use crate::clock;
use crate::cut::{session_end, session_expiry, CutSignal, SessionEnd, SessionWatch};
use crate::metrics::Metrics;
use crate::shutdown::{closed, stopping, Lifecycle};
use crate::state::{ActiveRule, ActiveSnapshot, SnapshotHandle};
use crate::status::UpstreamFailureKind;
use crate::upstream::UpstreamHandle;

/// A body error: the upstream connection's, or a [`StreamCut`](crate::cut::StreamCut).
pub type BodyError = Box<dyn std::error::Error + Send + Sync>;
pub type ProxyBody = BoxBody<Bytes, BodyError>;

const REALM: &str = "Basic realm=\"tokenless\"";
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authorization",
    "proxy-authenticate",
    "te",
    "trailer",
    "upgrade",
];

pub struct ProxyShared {
    /// This node: sessions minted for another are refused.
    pub node: NodeId,
    /// Open client connections and their tunnels, bound or not.
    pub connections: Arc<Semaphore>,
    pub max_connections: usize,
    /// Open MCP gateway connections, limited to `max_connections` apart
    /// from the proxy's.
    pub gateway_connections: Arc<Semaphore>,
    pub snapshot: SnapshotHandle,
    /// Bumped to each applied snapshot's version; open tunnels watch it to
    /// notice their session being revoked.
    pub snapshot_changed: watch::Sender<u64>,
    pub audit: AuditPipeline,
    pub metrics: Arc<Metrics>,
    pub upstream_tls: Arc<ClientConfig>,
    pub connect_timeout: Duration,
    pub node_id: String,
    /// Bindings made on this data plane, for [`crate::DataPlane::status`].
    /// Locked only to bind and to read the status, never per request.
    pub(crate) bindings: std::sync::Mutex<Vec<std::sync::Weak<BindingState>>>,
    /// Bumped when a binding is made or revoked or records a failure.
    pub status_changed: watch::Sender<u64>,
    /// Running, draining or closed; see [`crate::shutdown`].
    pub lifecycle: watch::Sender<Lifecycle>,
    /// Open tunnels and gateway streams per session.
    pub(crate) traffic: Arc<crate::traffic::OpenTraffic>,
}

impl ProxyShared {
    /// What open traffic under `claims` watches to know when to stop.
    pub(crate) fn session_watch(&self, claims: &SessionClaims) -> SessionWatch {
        SessionWatch::new(
            self.snapshot_changed.subscribe(),
            self.snapshot.clone(),
            claims,
        )
        .until_closed(self.lifecycle.subscribe())
    }

    pub(crate) fn is_running(&self) -> bool {
        *self.lifecycle.borrow() == Lifecycle::Running
    }

    pub(crate) fn register_binding(&self, binding: &Arc<BindingState>) {
        let mut all = self
            .bindings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        all.retain(|b| b.strong_count() > 0);
        all.push(Arc::downgrade(binding));
        drop(all);
        self.status_bump();
    }

    /// Bindings still held by their owner, oldest first.
    pub(crate) fn live_bindings(&self) -> Vec<Arc<BindingState>> {
        let mut all = self
            .bindings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        all.retain(|b| b.strong_count() > 0);
        all.iter().filter_map(std::sync::Weak::upgrade).collect()
    }

    pub(crate) fn status_bump(&self) {
        self.status_changed.send_modify(|n| *n = n.wrapping_add(1));
    }
}

pub(crate) fn body(text: impl Into<Bytes>) -> ProxyBody {
    Full::new(text.into())
        .map_err(|never| match never {})
        .boxed()
}

pub(crate) fn respond(status: StatusCode, message: &str) -> Response<ProxyBody> {
    let mut response = Response::new(body(format!("{message}\n")));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
        .headers_mut()
        .insert("x-broker-error", HeaderValue::from_static("1"));
    response
}

fn proxy_auth_required(message: &str) -> Response<ProxyBody> {
    let mut response = respond(StatusCode::PROXY_AUTHENTICATION_REQUIRED, message);
    response
        .headers_mut()
        .insert(PROXY_AUTHENTICATE, HeaderValue::from_static(REALM));
    response
}

/// Extracts the session token from `Proxy-Authorization`. Accepts
/// `Basic base64(<token>:)` (what `http://<token>@host:port` produces),
/// `Basic base64(<anything>:<token>)` and `Bearer <token>`.
pub fn session_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(PROXY_AUTHORIZATION)?.to_str().ok()?.trim();
    let (scheme, rest) = value.split_once(' ')?;
    let rest = rest.trim();
    if scheme.eq_ignore_ascii_case("bearer") {
        return Some(rest.to_string());
    }
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = String::from_utf8(STANDARD.decode(rest).ok()?).ok()?;
    let (user, pass) = decoded.split_once(':').unwrap_or((decoded.as_str(), ""));
    if user.starts_with("v4.public.") {
        Some(user.to_string())
    } else if pass.starts_with("v4.public.") {
        Some(pass.to_string())
    } else {
        None
    }
}

/// Session-level checks that must hold at CONNECT and again on every
/// request inside a tunnel. `binding` is the subject of the binding the
/// traffic came through, `None` when the client presented the token.
pub(crate) fn check_session(
    snapshot: &ActiveSnapshot,
    claims: &SessionClaims,
    node: &NodeId,
    binding: Option<&str>,
) -> Result<(), &'static str> {
    if clock::now() >= claims.exp {
        return Err("proxy session has expired");
    }
    if snapshot.revoked.contains(&claims.jti) {
        return Err("proxy session has been revoked");
    }
    if claims.aud.is_some_and(|aud| aud != *node) {
        return Err("proxy session is for another data plane node");
    }
    match (claims.sub.as_deref(), binding) {
        (None, None) => Ok(()),
        (Some(sub), Some(binding)) if sub == binding => Ok(()),
        (Some(_), Some(_)) => {
            Err("proxy session belongs to another binding, or an earlier start of this one")
        }
        (Some(_), None) => {
            Err("proxy session belongs to a binding and works only through it, not from a header")
        }
        (None, Some(_)) => Err("a binding uses only sessions minted for it"),
    }
}

/// Holds a connection's permits until the connection and the tunnel it
/// opened have both closed, then reports it.
pub(crate) struct ConnectionGuard {
    permits: Vec<OwnedSemaphorePermit>,
    done: Option<oneshot::Sender<()>>,
    /// Told once the permits are back.
    released: Option<Arc<BindingState>>,
}

impl ConnectionGuard {
    pub fn new(permits: Vec<OwnedSemaphorePermit>, done: Option<oneshot::Sender<()>>) -> Self {
        Self {
            permits,
            done,
            released: None,
        }
    }

    /// Wakes whoever waits for `binding`'s connections to close.
    pub fn for_binding(mut self, binding: Arc<BindingState>) -> Self {
        self.released = Some(binding);
        self
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.permits.clear();
        if let Some(binding) = &self.released {
            binding.connection_closed();
        }
        if let Some(done) = self.done.take() {
            let _ = done.send(());
        }
    }
}

pub(crate) fn session_rules<'a>(
    snapshot: &'a ActiveSnapshot,
    claims: &'a SessionClaims,
) -> impl Iterator<Item = &'a ActiveRule> + 'a {
    snapshot
        .rules
        .iter()
        .filter(move |r| r.scope == claims.scope && claims.rules.contains(&r.id))
}

/// Which of a session's rules a request uses.
pub(crate) enum RuleChoice<'a> {
    None,
    One(&'a ActiveRule),
    /// The most specific rules allowing it tie and would send different
    /// credentials, so neither is used.
    Ambiguous(&'a ActiveRule, &'a ActiveRule),
}

/// The rule whose path matches the request most specifically
/// ([`RuleScope::specificity`]), so a service scoped to `/api/*` takes its
/// requests from one allowing `/*` on the same host. Rules that tie are
/// interchangeable only when they send the same thing.
pub(crate) fn choose_rule<'a>(
    rules: impl Iterator<Item = &'a ActiveRule>,
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    query: Option<&str>,
) -> RuleChoice<'a> {
    let mut best: Option<(&ActiveRule, usize)> = None;
    let mut rival: Option<&ActiveRule> = None;
    for rule in rules {
        let Some(rank) = rule
            .allow
            .request_specificity(host, port, method, path, query)
        else {
            continue;
        };
        match best {
            Some((_, top)) if rank < top => {}
            Some((chosen, top)) if rank == top => {
                if rival.is_none() && !chosen.sends_same_as(rule) {
                    rival = Some(rule);
                }
            }
            _ => {
                best = Some((rule, rank));
                rival = None;
            }
        }
    }
    match (best, rival) {
        (None, _) => RuleChoice::None,
        (Some((chosen, _)), None) => RuleChoice::One(chosen),
        (Some((chosen, _)), Some(other)) => RuleChoice::Ambiguous(chosen, other),
    }
}

pub async fn serve(listener: TcpListener, shared: Arc<ProxyShared>) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                warn!(error = %e, "proxy accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(permit) = shared.connections.clone().try_acquire_owned() else {
            Metrics::inc(&shared.metrics.connections_rejected);
            debug!(%peer, "connection limit reached; dropping connection");
            continue;
        };
        Metrics::inc(&shared.metrics.connections_total);
        let _ = stream.set_nodelay(true);
        let guard = Arc::new(ConnectionGuard::new(vec![permit], None));
        tokio::spawn(serve_stream(stream, shared.clone(), None, guard));
    }
}

/// Serves one client connection. With `binding`, sessions come from it and
/// the client's `Proxy-Authorization` is ignored; without, the client
/// presents its token. `guard` is held until the connection and its tunnel
/// have closed, so open tunnels count against the connection limits.
pub(crate) async fn serve_stream<S>(
    stream: S,
    shared: Arc<ProxyShared>,
    binding: Option<Arc<BindingState>>,
    guard: Arc<ConnectionGuard>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let mut lifecycle = shared.lifecycle.subscribe();
    let service = service_fn(move |req| {
        let shared = shared.clone();
        let binding = binding.clone();
        let guard = guard.clone();
        async move { Ok::<_, Infallible>(handle_proxy_request(req, shared, binding, guard).await) }
    });
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(30));
    let connection = builder
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades();
    tokio::pin!(connection);
    let served = tokio::select! {
        served = connection.as_mut() => served,
        () = stopping(&mut lifecycle) => {
            // Draining: a CONNECT being answered still opens its tunnel,
            // and the idle connection then closes; the drain deadline
            // drops one that has not.
            connection.as_mut().graceful_shutdown();
            tokio::select! {
                served = connection.as_mut() => served,
                () = closed(&mut lifecycle) => return,
            }
        }
    };
    if let Err(e) = served {
        debug!(error = %e, "proxy connection ended with error");
    }
}

/// A refusal answered before a tunnel opens. Boxed: a response is large.
type Refused = Box<Response<ProxyBody>>;

/// The session a client presents in `Proxy-Authorization`.
fn header_session(
    req: &Request<Incoming>,
    snapshot: &ActiveSnapshot,
    shared: &ProxyShared,
) -> Result<SessionClaims, Refused> {
    let refuse = |message: &str| {
        Metrics::inc(&shared.metrics.proxy_auth_failures_total);
        Box::new(proxy_auth_required(message))
    };
    let Some(token) = session_token(req.headers()) else {
        return Err(refuse(
            "a proxy session token is required (HTTPS_PROXY=http://<token>@host:port)",
        ));
    };
    let claims = verify_session(&token, &snapshot.session_keys, Utc::now()).map_err(|e| {
        debug!(error = %e, "proxy session rejected");
        refuse(&format!("proxy session rejected: {e}"))
    })?;
    check_session(snapshot, &claims, &shared.node, None).map_err(refuse)?;
    Ok(claims)
}

/// The session a bound CONNECT uses, chosen by its target, and its token's
/// digest.
fn bound_session(
    req: &Request<Incoming>,
    snapshot: &ActiveSnapshot,
    shared: &ProxyShared,
    binding: &BindingState,
) -> Result<(SessionClaims, [u8; 32]), Refused> {
    let Some((host, port)) = req
        .uri()
        .authority()
        .and_then(|a| parse_authority(a.as_str()))
    else {
        return Err(Box::new(respond(
            StatusCode::BAD_REQUEST,
            "CONNECT target must be host:port",
        )));
    };
    binding
        .session_for(snapshot, &host, port, &shared.node)
        .map_err(|reason| {
            Metrics::inc(&shared.metrics.proxy_auth_failures_total);
            Box::new(respond(StatusCode::FORBIDDEN, reason))
        })
}

async fn handle_proxy_request(
    mut req: Request<Incoming>,
    shared: Arc<ProxyShared>,
    binding: Option<Arc<BindingState>>,
    guard: Arc<ConnectionGuard>,
) -> Response<ProxyBody> {
    let Some(snapshot) = shared.snapshot.load_full() else {
        Metrics::inc(&shared.metrics.lease_refusals_total);
        return respond(
            StatusCode::SERVICE_UNAVAILABLE,
            "data plane has no policy snapshot yet; refusing all traffic",
        );
    };
    if !snapshot.lease_valid() {
        Metrics::inc(&shared.metrics.lease_refusals_total);
        return respond(
            StatusCode::SERVICE_UNAVAILABLE,
            "data plane policy lease expired (control plane unreachable); refusing all traffic",
        );
    }
    if binding.is_some() && req.method() != Method::CONNECT {
        return respond(
            StatusCode::FORBIDDEN,
            "only CONNECT (HTTPS) is supported; credentials are never injected on plain HTTP",
        );
    }
    let session = match &binding {
        None => header_session(&req, &snapshot, &shared).map(|claims| (claims, None)),
        Some(binding) => bound_session(&req, &snapshot, &shared, binding)
            .map(|(claims, digest)| (claims, Some(digest))),
    };
    let (claims, bound_token) = match session {
        Ok(session) => session,
        Err(refusal) => return *refusal,
    };
    if req.method() != Method::CONNECT {
        return respond(
            StatusCode::FORBIDDEN,
            "only CONNECT (HTTPS) is supported; credentials are never injected on plain HTTP",
        );
    }
    let Some((host, port)) = req
        .uri()
        .authority()
        .and_then(|a| parse_authority(a.as_str()))
    else {
        return respond(StatusCode::BAD_REQUEST, "CONNECT target must be host:port");
    };
    let intercept = session_rules(&snapshot, &claims).any(|r| r.allow.matches_host(&host, port));
    let excepted = || {
        snapshot
            .passthrough_hosts
            .iter()
            .any(|h| h.matches(&host, port))
    };
    if !intercept && snapshot.policy == UnmatchedHostPolicy::Deny && !excepted() {
        Metrics::inc(&shared.metrics.connect_denied_total);
        audit_best_effort(
            &shared,
            &claims,
            "proxy.connect_denied",
            AuditOutcome::Denied,
            &host,
            port,
            None,
            "no rule for host and unmatched-host policy is deny",
        );
        return respond(
            StatusCode::FORBIDDEN,
            &format!(
                "no rule in this session covers {host}:{port} and the unmatched-host policy is deny; an admin can add it to Settings → Always reachable"
            ),
        );
    }
    let tls_config = if intercept {
        let pattern_host = session_rules(&snapshot, &claims)
            .flat_map(|r| r.allow.hosts.iter())
            .find(|h| h.matches(&host, port))
            .map(|h| h.certificate_name().to_string());
        match pattern_host.and_then(|h| snapshot.tls.config_for(&h)) {
            Some(config) => Some(config),
            None => {
                warn!(%host, port, "no interception certificate for a matched host");
                return respond(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "interception certificate is not ready",
                );
            }
        }
    } else {
        None
    };
    // Passthrough destinations are chosen by the agent, so they are resolved
    // here and checked against the egress policy before the tunnel opens.
    // The tunnel then connects to the checked addresses, never re-resolving.
    let passthrough_addrs = if tls_config.is_none() {
        match resolve_passthrough(&host, port, &snapshot.egress, shared.connect_timeout).await {
            Ok(addrs) => addrs,
            Err(Refusal::Blocked { ip, reason }) => {
                Metrics::inc(&shared.metrics.egress_blocked_total);
                audit_best_effort(
                    &shared,
                    &claims,
                    "proxy.egress_blocked",
                    AuditOutcome::Denied,
                    &host,
                    port,
                    None,
                    &format!("{ip} is {reason}"),
                );
                return respond(
                    StatusCode::FORBIDDEN,
                    &format!(
                        "{host} resolves to {ip}, which is {reason}; an admin can allow this range in Settings → Egress"
                    ),
                );
            }
            Err(Refusal::Unresolvable { reason }) => {
                Metrics::inc(&shared.metrics.upstream_errors_total);
                return respond(
                    StatusCode::BAD_GATEWAY,
                    &format!("could not resolve {host}:{port}: {reason}"),
                );
            }
        }
    } else {
        Vec::new()
    };
    if tls_config.is_none() {
        let reason = if excepted() {
            "always-reachable host; tunnelled untouched"
        } else {
            "no rule covers this host; tunnelled untouched"
        };
        audit_best_effort(
            &shared,
            &claims,
            "proxy.tunnel",
            AuditOutcome::Success,
            &host,
            port,
            None,
            reason,
        );
    }
    // Strict: the tunnel lasts as long as the longest grant that covers its
    // host; each request's streams are watched for their own rule.
    let mut watch = shared.session_watch(&claims).through(binding.as_ref());
    if claims.strict && tls_config.is_some() {
        if let Some(last) = session_rules(&snapshot, &claims)
            .filter(|r| r.allow.matches_host(&host, port))
            .map(|r| claims.rule_deadline(&r.id))
            .max()
        {
            watch = watch.until(last);
        }
    }
    drop(snapshot);

    let on_upgrade = hyper::upgrade::on(&mut req);
    let open = shared.traffic.enter(claims.jti);
    let claims = Arc::new(claims);
    tokio::spawn(async move {
        // The tunnel counts against the connection limits, and as its
        // session's open traffic, until it closes.
        let _guard = guard;
        let _open = open;
        let upgraded = match on_upgrade.await {
            Ok(u) => u,
            Err(e) => {
                debug!(error = %e, "CONNECT upgrade failed");
                return;
            }
        };
        match tls_config {
            Some(config) => {
                Metrics::inc(&shared.metrics.tunnels_intercepted_total);
                intercept_tunnel(
                    TokioIo::new(upgraded),
                    config,
                    host,
                    port,
                    claims,
                    shared,
                    watch,
                    bound_token,
                )
                .await;
            }
            None => {
                Metrics::inc(&shared.metrics.tunnels_passthrough_total);
                passthrough(
                    TokioIo::new(upgraded),
                    &host,
                    port,
                    &passthrough_addrs,
                    &shared,
                    &claims,
                    watch,
                )
                .await;
            }
        }
    });
    Response::new(body(Bytes::new()))
}

enum Refusal {
    Blocked {
        ip: std::net::IpAddr,
        reason: &'static str,
    },
    Unresolvable {
        reason: String,
    },
}

async fn resolve_passthrough(
    host: &str,
    port: u16,
    egress: &tokenless_core::egress::EgressPolicy,
    limit: std::time::Duration,
) -> Result<Vec<std::net::SocketAddr>, Refusal> {
    let resolved: Vec<std::net::SocketAddr> = timeout(limit, tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| Refusal::Unresolvable {
            reason: "DNS lookup timed out".into(),
        })?
        .map_err(|e| Refusal::Unresolvable {
            reason: e.to_string(),
        })?
        .collect();
    let mut first_block = None;
    let allowed: Vec<_> = resolved
        .iter()
        .copied()
        .filter(|addr| match egress.check(addr.ip()) {
            Ok(()) => true,
            Err(reason) => {
                first_block.get_or_insert((addr.ip(), reason));
                false
            }
        })
        .collect();
    if !allowed.is_empty() {
        return Ok(allowed);
    }
    Err(match first_block {
        Some((ip, reason)) => Refusal::Blocked { ip, reason },
        None => Refusal::Unresolvable {
            reason: "no addresses".into(),
        },
    })
}

#[allow(clippy::too_many_arguments)]
async fn passthrough(
    mut client: TokioIo<hyper::upgrade::Upgraded>,
    host: &str,
    port: u16,
    addrs: &[std::net::SocketAddr],
    shared: &ProxyShared,
    claims: &SessionClaims,
    watch: SessionWatch,
) {
    let upstream = timeout(shared.connect_timeout, TcpStream::connect(addrs)).await;
    let mut upstream = match upstream {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            Metrics::inc(&shared.metrics.upstream_errors_total);
            debug!(%host, port, error = %e, "passthrough connect failed");
            return;
        }
        Err(_) => {
            Metrics::inc(&shared.metrics.upstream_errors_total);
            debug!(%host, port, "passthrough connect timed out");
            return;
        }
    };
    tokio::select! {
        copied = tokio::io::copy_bidirectional(&mut client, &mut upstream) => {
            if let Err(e) = copied {
                debug!(%host, port, error = %e, "passthrough tunnel closed");
            }
        }
        end = session_end(watch) => tunnel_cut(shared, claims, host, port, end),
    }
}

/// Records traffic cut because its session ended. The caller drops the
/// connection, which closes both sides.
pub(crate) fn tunnel_cut(
    shared: &ProxyShared,
    claims: &SessionClaims,
    host: &str,
    port: u16,
    end: SessionEnd,
) {
    Metrics::inc(&shared.metrics.tunnels_cut_total);
    info!(session_id = %claims.jti, %host, port, reason = end.reason(), "cut open traffic");
    audit_best_effort(
        shared,
        claims,
        "proxy.tunnel_cut",
        AuditOutcome::Denied,
        host,
        port,
        None,
        end.reason(),
    );
}

#[allow(clippy::too_many_arguments)]
async fn intercept_tunnel(
    io: TokioIo<hyper::upgrade::Upgraded>,
    config: Arc<rustls::ServerConfig>,
    host: String,
    port: u16,
    claims: Arc<SessionClaims>,
    shared: Arc<ProxyShared>,
    watch: SessionWatch,
    bound_token: Option<[u8; 32]>,
) {
    // The handshake is bounded by its own timeouts; the session is watched
    // from the moment requests can flow.
    let binding = watch
        .binding
        .as_ref()
        .map(|b| b.state.clone())
        .zip(bound_token);
    tokio::select! {
        () = intercepted_connection(io, config, host.clone(), port, claims.clone(), shared.clone(), binding) => {}
        end = session_end(watch) => tunnel_cut(&shared, &claims, &host, port, end),
    }
}

/// Resolves once the bound session is no longer one of its binding's;
/// never for a session from a header.
async fn left_binding(binding: Option<(Arc<BindingState>, [u8; 32])>) {
    match binding {
        Some((state, digest)) => state.left(digest).await,
        None => std::future::pending().await,
    }
}

async fn intercepted_connection(
    io: TokioIo<hyper::upgrade::Upgraded>,
    config: Arc<rustls::ServerConfig>,
    host: String,
    port: u16,
    claims: Arc<SessionClaims>,
    shared: Arc<ProxyShared>,
    binding: Option<(Arc<BindingState>, [u8; 32])>,
) {
    let start = match timeout(
        Duration::from_secs(10),
        LazyConfigAcceptor::new(rustls::server::Acceptor::default(), io),
    )
    .await
    {
        Ok(Ok(start)) => start,
        Ok(Err(e)) => {
            debug!(%host, error = %e, "client TLS hello failed");
            return;
        }
        Err(_) => {
            debug!(%host, "client TLS hello timed out");
            return;
        }
    };
    if let Some(sni) = start.client_hello().server_name() {
        if !sni.eq_ignore_ascii_case(&host) {
            warn!(%host, sni, "SNI does not match the CONNECT host; closing tunnel");
            return;
        }
    }
    let tls = match timeout(Duration::from_secs(10), start.into_stream(config)).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(e)) => {
            debug!(%host, error = %e, "client TLS handshake failed (does the client trust the interception CA?)");
            return;
        }
        Err(_) => return,
    };
    let upstream = UpstreamHandle::spawn(
        host.clone(),
        port,
        shared.upstream_tls.clone(),
        shared.connect_timeout,
    );
    let exp = claims.exp;
    let mut lifecycle = shared.lifecycle.subscribe();
    let left = left_binding(binding.clone());
    let (binding, bound_token) = binding.unzip();
    let ctx = Arc::new(TunnelCtx {
        host,
        port,
        claims,
        shared,
        upstream,
        binding,
        bound_token,
    });
    let service = service_fn(move |req| {
        let ctx = ctx.clone();
        async move { Ok::<_, Infallible>(handle_intercepted(req, ctx).await) }
    });
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(60));
    let connection = builder.serve_connection(TokioIo::new(tls), service);
    tokio::pin!(connection);
    let served = tokio::select! {
        served = connection.as_mut() => served,
        () = stopping(&mut lifecycle) => {
            // Draining: requests in flight answer, then the connection
            // closes; the drain deadline cuts it if they do not.
            connection.as_mut().graceful_shutdown();
            connection.await
        }
        () = session_expiry(exp) => {
            // The session may start nothing new, but what is in flight
            // finishes, within the open-traffic grace period that
            // `session_end` enforces around this connection; the client
            // reconnects with its current session.
            connection.as_mut().graceful_shutdown();
            connection.await
        }
        () = left => {
            // The binding was updated without this session: what is in
            // flight finishes (or is cut, if its rule is no longer
            // granted), and the workload reconnects under a current one.
            connection.as_mut().graceful_shutdown();
            connection.await
        }
    };
    if let Err(e) = served {
        debug!(error = %e, "intercepted connection ended with error");
    }
}

/// One upstream target and the session sending to it: an intercepted
/// tunnel, or a request to the MCP gateway.
pub(crate) struct TunnelCtx {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) claims: Arc<SessionClaims>,
    pub(crate) shared: Arc<ProxyShared>,
    pub(crate) upstream: UpstreamHandle,
    /// The binding the tunnel came through, if any.
    pub(crate) binding: Option<Arc<BindingState>>,
    /// The digest of the binding's session token the tunnel was opened
    /// under.
    pub(crate) bound_token: Option<[u8; 32]>,
}

/// Does the request's own Host (or absolute authority) name the CONNECT target?
pub fn request_targets(headers: &HeaderMap, uri: &http::Uri, host: &str, port: u16) -> bool {
    let authority = uri.authority().map(|a| a.as_str().to_string()).or_else(|| {
        headers
            .get(HOST)
            .and_then(|h| h.to_str().ok())
            .map(str::to_string)
    });
    let Some(authority) = authority else {
        return false;
    };
    let explicit_port = !authority.ends_with(']')
        && authority
            .rsplit_once(':')
            .is_some_and(|(_, p)| p.chars().all(|c| c.is_ascii_digit()));
    match parse_authority(&authority) {
        Some((h, p)) => h == host && (!explicit_port || p == port),
        None => false,
    }
}

/// Removes hop-by-hop headers (including any named in `Connection`) and
/// every credential header the rule owns, then injects the rule's headers.
pub fn rewrite_headers(headers: &mut HeaderMap, rule: &ActiveRule) {
    let listed: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|n| HeaderName::from_bytes(n.trim().as_bytes()).ok())
        .collect();
    for name in listed {
        headers.remove(name);
    }
    for name in HOP_BY_HOP {
        headers.remove(*name);
    }
    for name in &rule.strip {
        headers.remove(name);
    }
    for (name, value) in &rule.inject {
        headers.insert(name.clone(), value.clone());
    }
}

/// Largest body the proxy buffers to look for placeholders. Bigger bodies,
/// and bodies of unknown length, are streamed through unchanged.
pub const MAX_SUBSTITUTION_BODY: u64 = 4 * 1024 * 1024;
const BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Swaps placeholders in the request target and in the headers the agent
/// sent. Runs before [`rewrite_headers`], so the broker's own injected
/// values are never scanned and a substituted credential header the rule
/// owns is still replaced by the injected one.
pub fn substitute_head<B>(
    req: &mut Request<B>,
    subs: &[RenderedSubstitution],
    applied: &mut Applied,
) -> Result<(), String> {
    if let Some(target) = req.uri().path_and_query().map(|pq| pq.as_str().to_string()) {
        if let Some(rewritten) = apply_to_target(&target, subs, applied) {
            let mut parts = req.uri().clone().into_parts();
            parts.path_and_query = Some(
                rewritten
                    .parse()
                    .map_err(|e| format!("request target after substitution is invalid: {e}"))?,
            );
            *req.uri_mut() = http::Uri::from_parts(parts)
                .map_err(|e| format!("request URI after substitution is invalid: {e}"))?;
        }
    }
    for (name, value) in req.headers_mut().iter_mut() {
        if name == HOST || name == PROXY_AUTHORIZATION {
            continue;
        }
        if let Some(rewritten) = apply_to_header(value.as_bytes(), subs, applied) {
            let mut new = HeaderValue::from_str(&rewritten)
                .map_err(|_| format!("header '{name}' is not a valid value after substitution"))?;
            new.set_sensitive(true);
            *value = new;
        }
    }
    Ok(())
}

/// Why a body was forwarded without looking for placeholders.
fn body_skip_reason(headers: &HeaderMap) -> Option<&'static str> {
    let encoded = headers
        .get(http::header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| !v.trim().eq_ignore_ascii_case("identity"));
    if encoded {
        return Some("body is compressed");
    }
    match headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        None => Some("body length is unknown (streamed)"),
        Some(0) => Some("body is empty"),
        Some(n) if n > MAX_SUBSTITUTION_BODY => Some("body is larger than 4 MiB"),
        Some(_) => None,
    }
}

/// A request body, either read into memory or left to stream.
enum ReadBody {
    Buffered(http::request::Parts, Bytes),
    /// Not read, with the reason (unknown length, compressed, too large).
    Streamed(Request<Incoming>, &'static str),
}

/// Reads a body of known length up to 4 MiB that is not compressed.
async fn read_body(req: Request<Incoming>) -> Result<ReadBody, (StatusCode, String)> {
    if let Some(reason) = body_skip_reason(req.headers()) {
        return Ok(ReadBody::Streamed(req, reason));
    }
    let (parts, incoming) = req.into_parts();
    let limited = http_body_util::Limited::new(incoming, MAX_SUBSTITUTION_BODY as usize);
    match timeout(BODY_READ_TIMEOUT, limited.collect()).await {
        Ok(Ok(collected)) => Ok(ReadBody::Buffered(parts, collected.to_bytes())),
        Ok(Err(e)) => Err((
            StatusCode::BAD_REQUEST,
            format!("could not read the request body: {e}"),
        )),
        Err(_) => Err((
            StatusCode::REQUEST_TIMEOUT,
            "the request body did not arrive within 30s".to_string(),
        )),
    }
}

/// The first MCP tool call in `messages` that `allow` does not permit.
fn refused_tool<'m>(messages: &'m [McpMessage], allow: &RuleScope) -> Option<&'m str> {
    messages
        .iter()
        .filter_map(|m| m.tool.as_deref())
        .find(|tool| !allow.allows_tool(tool))
}

/// The JSON-RPC answer to a refused body: one error, or one per request in
/// a batch (none of a refused batch is forwarded).
fn mcp_refusal(messages: &[McpMessage], tool: &str, batch: bool) -> Response<ProxyBody> {
    let json = if batch {
        serde_json::Value::Array(
            messages
                .iter()
                .filter(|m| m.id.is_some())
                .map(|m| mcp::refusal(m.id.as_ref(), tool))
                .collect(),
        )
    } else {
        mcp::refusal(messages.first().and_then(|m| m.id.as_ref()), tool)
    };
    let mut response = Response::new(body(json.to_string()));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
        .headers_mut()
        .insert("x-broker-error", HeaderValue::from_static("1"));
    response
}

/// Comma-joined distinct values, at most 512 characters, for audit details.
fn joined<'a>(values: impl Iterator<Item = &'a str>) -> String {
    let mut seen: Vec<&str> = Vec::new();
    for v in values {
        if !seen.contains(&v) {
            seen.push(v);
        }
    }
    seen.join(", ").chars().take(512).collect()
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn audit_best_effort(
    shared: &ProxyShared,
    claims: &SessionClaims,
    action: &str,
    outcome: AuditOutcome,
    host: &str,
    port: u16,
    request: Option<(&str, &str)>,
    reason: &str,
) {
    let event = proxy_event(shared, claims, action, outcome, host, port, request)
        .detail("reason", reason.to_string());
    let _ = shared.audit.try_record(event);
}

fn proxy_event(
    shared: &ProxyShared,
    claims: &SessionClaims,
    action: &str,
    outcome: AuditOutcome,
    host: &str,
    port: u16,
    request: Option<(&str, &str)>,
) -> AuditEvent {
    let mut event = AuditEvent::new(format!("node:{}", shared.node_id), action, outcome)
        .detail("scope", claims.scope.to_string())
        .detail("session_id", claims.jti.to_string())
        .detail("host", format!("{host}:{port}"));
    if let Some((method, path)) = request {
        event = event
            .detail("method", method.to_string())
            .detail("path", path.chars().take(512).collect::<String>());
    }
    for (k, v) in &claims.labels {
        event = event.detail(&format!("label.{k}"), v.clone());
    }
    event
}

pub(crate) async fn handle_intercepted(
    mut req: Request<Incoming>,
    ctx: Arc<TunnelCtx>,
) -> Response<ProxyBody> {
    let shared = &ctx.shared;
    let Some(snapshot) = shared.snapshot.load_full() else {
        Metrics::inc(&shared.metrics.lease_refusals_total);
        return respond(
            StatusCode::SERVICE_UNAVAILABLE,
            "data plane has no policy snapshot; refusing to inject",
        );
    };
    if !snapshot.lease_valid() {
        Metrics::inc(&shared.metrics.lease_refusals_total);
        return respond(
            StatusCode::SERVICE_UNAVAILABLE,
            "data plane policy lease expired (control plane unreachable); refusing to inject",
        );
    }
    let claims = &ctx.claims;
    if let Err(reason) = check_session(
        &snapshot,
        claims,
        &shared.node,
        ctx.binding.as_ref().map(|b| &*b.subject),
    ) {
        Metrics::inc(&shared.metrics.proxy_auth_failures_total);
        return proxy_auth_required(reason);
    }
    if !request_targets(req.headers(), req.uri(), &ctx.host, ctx.port) {
        Metrics::inc(&shared.metrics.requests_denied_total);
        return respond(
            StatusCode::MISDIRECTED_REQUEST,
            "request Host does not match the CONNECT target; credentials are only injected for the tunnel's own host",
        );
    }
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(str::to_string);
    if let Err(rejection) = check_request_path(&path) {
        Metrics::inc(&shared.metrics.requests_denied_total);
        return respond(StatusCode::BAD_REQUEST, rejection.as_str());
    }
    let rule = match choose_rule(
        session_rules(&snapshot, claims),
        &ctx.host,
        ctx.port,
        &method,
        &path,
        query.as_deref(),
    ) {
        RuleChoice::One(rule) => Some(rule),
        RuleChoice::None => None,
        RuleChoice::Ambiguous(first, second) => {
            Metrics::inc(&shared.metrics.requests_denied_total);
            // The event's method and path details carry the request,
            // capped; the reason stays bounded.
            audit_best_effort(
                shared,
                claims,
                "proxy.deny",
                AuditOutcome::Denied,
                &ctx.host,
                ctx.port,
                Some((&method, &path)),
                &format!(
                    "ambiguous_rules: rules {} and {} match equally and send different credentials",
                    first.id, second.id
                ),
            );
            return respond(
                StatusCode::FORBIDDEN,
                &format!(
                    "rules {} and {} in this session both allow {method} {path} on {} and send different credentials; narrow one rule's paths",
                    first.id, second.id, ctx.host
                ),
            );
        }
    };
    let Some(rule) = rule else {
        Metrics::inc(&shared.metrics.requests_denied_total);
        audit_best_effort(
            shared,
            claims,
            "proxy.deny",
            AuditOutcome::Denied,
            &ctx.host,
            ctx.port,
            Some((&method, &path)),
            "no rule in the session allows this method and path",
        );
        return respond(
            StatusCode::FORBIDDEN,
            &format!(
                "no rule in this session allows {method} {path} on {}",
                ctx.host
            ),
        );
    };
    let now = clock::now();
    let rule_deadline = claims.rule_deadline(&rule.id);
    if now >= rule_deadline {
        Metrics::inc(&shared.metrics.requests_denied_total);
        audit_best_effort(
            shared,
            claims,
            "proxy.deny",
            AuditOutcome::Denied,
            &ctx.host,
            ctx.port,
            Some((&method, &path)),
            &format!(
                "grant_expired: the session's grant of rule {} has ended",
                rule.id
            ),
        );
        return respond(
            StatusCode::FORBIDDEN,
            &format!(
                "this session's access to rule {} on {} ended at {}",
                rule.id,
                ctx.host,
                rule_deadline.to_rfc3339()
            ),
        );
    }
    if let (Some(binding), Some(token)) = (&ctx.binding, &ctx.bound_token) {
        // A tunnel opened before an update still serves the requests in
        // flight; it may use only what the binding still grants.
        if !binding.holds(token) && !binding.grants(&snapshot, &rule.id, now) {
            Metrics::inc(&shared.metrics.requests_denied_total);
            audit_best_effort(
                shared,
                claims,
                "proxy.deny",
                AuditOutcome::Denied,
                &ctx.host,
                ctx.port,
                Some((&method, &path)),
                &format!(
                    "grant_removed: no session of the binding grants rule {}",
                    rule.id
                ),
            );
            return respond(
                StatusCode::FORBIDDEN,
                &format!(
                    "rule {} is no longer granted to this workload; reconnect to use its current access",
                    rule.id
                ),
            );
        }
    }
    if let Some(not_after) = rule.not_after.filter(|at| now >= *at) {
        Metrics::inc(&shared.metrics.requests_denied_total);
        audit_best_effort(
            shared,
            claims,
            "proxy.deny",
            AuditOutcome::Denied,
            &ctx.host,
            ctx.port,
            Some((&method, &path)),
            "credential_expired: the credential's not_after has passed",
        );
        if let Some(binding) = &ctx.binding {
            binding.record_failure(UpstreamFailureKind::CredentialExpired, &ctx.host, ctx.port);
        }
        let mut r = respond(
            StatusCode::SERVICE_UNAVAILABLE,
            &format!(
                "the credential for {} expired at {}; nothing was sent, retry once it is replaced",
                ctx.host,
                not_after.to_rfc3339()
            ),
        );
        r.headers_mut()
            .insert("retry-after", HeaderValue::from_static("5"));
        return r;
    }
    if let Some(limit) = claims.request_limit {
        let Some(counter) = snapshot.limits.get(&claims.jti) else {
            let mut r = respond(
                StatusCode::SERVICE_UNAVAILABLE,
                "request-limited session is not provisioned on this node yet; retry shortly",
            );
            r.headers_mut()
                .insert("retry-after", HeaderValue::from_static("1"));
            return r;
        };
        if counter.fetch_add(1, Ordering::Relaxed) >= limit {
            Metrics::inc(&shared.metrics.requests_denied_total);
            return respond(
                StatusCode::TOO_MANY_REQUESTS,
                &format!("session request limit of {limit} reached"),
            );
        }
    }
    let request_id = new_request_id();
    let mut applied = Applied::default();
    let mut body_skipped = None;
    let mut mcp_seen: Option<Vec<McpMessage>> = None;
    if !rule.substitutions.is_empty() {
        if let Err(reason) = substitute_head(&mut req, &rule.substitutions, &mut applied) {
            Metrics::inc(&shared.metrics.requests_denied_total);
            return respond(StatusCode::BAD_REQUEST, &reason);
        }
    }
    let check_tools = rule.allow.mcp_tools.is_some() && method == "POST";
    let req = if check_tools || wants_body(&rule.substitutions) {
        match read_body(req).await {
            Err((status, reason)) => return respond(status, &reason),
            Ok(ReadBody::Streamed(req, reason)) => {
                if check_tools {
                    let reason = format!(
                        "this rule limits MCP tools, so its requests need a JSON body of known length up to 4 MiB that is not compressed ({reason})"
                    );
                    Metrics::inc(&shared.metrics.requests_denied_total);
                    let event = proxy_event(
                        shared,
                        claims,
                        "proxy.deny",
                        AuditOutcome::Denied,
                        &ctx.host,
                        ctx.port,
                        Some((&method, &path)),
                    )
                    .target(format!("rule:{}", rule.id))
                    .detail("credential_id", rule.credential_id.to_string())
                    .detail("reason", reason.clone());
                    let _ = shared.audit.try_record(event);
                    return respond(StatusCode::BAD_REQUEST, &reason);
                }
                body_skipped = Some(reason);
                req.map(|b| b.map_err(BodyError::from).boxed())
            }
            Ok(ReadBody::Buffered(mut parts, bytes)) => {
                if check_tools {
                    let parsed = match mcp::messages(&bytes) {
                        Ok(parsed) => parsed,
                        Err(NotJsonRpc(reason)) => {
                            Metrics::inc(&shared.metrics.requests_denied_total);
                            return respond(
                                StatusCode::BAD_REQUEST,
                                &format!(
                                    "this rule limits MCP tools and the body is not MCP JSON-RPC: {reason}"
                                ),
                            );
                        }
                    };
                    if let Some(tool) = refused_tool(&parsed, &rule.allow) {
                        Metrics::inc(&shared.metrics.requests_denied_total);
                        let event = proxy_event(
                            shared,
                            claims,
                            "proxy.deny",
                            AuditOutcome::Denied,
                            &ctx.host,
                            ctx.port,
                            Some((&method, &path)),
                        )
                        .target(format!("rule:{}", rule.id))
                        .detail("credential_id", rule.credential_id.to_string())
                        .detail("mcp_method", "tools/call")
                        .detail("mcp_tool", tool.to_string())
                        .detail(
                            "reason",
                            format!("MCP tool '{tool}' is not in the rule's allowed tools"),
                        );
                        let _ = shared.audit.try_record(event);
                        let batch = bytes.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'[');
                        return mcp_refusal(&parsed, tool, batch);
                    }
                    mcp_seen = Some(parsed);
                }
                let bytes = if wants_body(&rule.substitutions) {
                    let kind = BodyKind::from_content_type(
                        parts
                            .headers
                            .get(CONTENT_TYPE)
                            .and_then(|v| v.to_str().ok()),
                    );
                    match apply_to_body(&bytes, kind, &rule.substitutions, &mut applied) {
                        Some(rewritten) => Bytes::from(rewritten),
                        None => bytes,
                    }
                } else {
                    bytes
                };
                parts
                    .headers
                    .insert(http::header::CONTENT_LENGTH, HeaderValue::from(bytes.len()));
                Request::from_parts(parts, body(bytes))
            }
        }
    } else {
        req.map(|b| b.map_err(BodyError::from).boxed())
    };
    let mut req = req;
    let mut event = proxy_event(
        shared,
        claims,
        "proxy.inject",
        AuditOutcome::Success,
        &ctx.host,
        ctx.port,
        Some((&method, &path)),
    )
    .target(format!("rule:{}", rule.id))
    .detail("credential_id", rule.credential_id.to_string())
    .detail("request_id", request_id.clone());
    if !applied.is_empty() {
        event = event.detail("substituted", applied.placeholders.join(", "));
    }
    if let Some(reason) = body_skipped {
        event = event.detail("body_not_substituted", reason);
    }
    if let Some(messages) = &mcp_seen {
        event = event.detail(
            "mcp_method",
            joined(messages.iter().map(|m| m.method.as_str())),
        );
        let tools = joined(messages.iter().filter_map(|m| m.tool.as_deref()));
        if !tools.is_empty() {
            event = event.detail("mcp_tool", tools);
        }
    }
    if shared.audit.try_record(event).is_err() {
        return respond(
            StatusCode::SERVICE_UNAVAILABLE,
            "audit pipeline is saturated; refusing to inject a credential without an audit record",
        );
    }
    rewrite_headers(req.headers_mut(), rule);
    let rule_id = rule.id;
    let credential_id = rule.credential_id;
    // Strict sessions and bindings: the upload and the response are cut
    // when this request's grant ends, not just when the tunnel does.
    let mut cut = (claims.strict || ctx.binding.is_some()).then(|| {
        let watch = shared
            .session_watch(claims)
            .through(ctx.binding.as_ref())
            .for_rule(rule, claims);
        let ctx = ctx.clone();
        CutSignal::spawn(watch, 2, move |end| {
            tunnel_cut(&ctx.shared, &ctx.claims, &ctx.host, ctx.port, end);
        })
    });
    if let Some(cut) = &mut cut {
        req = req.map(|b| cut.wrap(b));
    }
    drop(snapshot);
    let started = std::time::Instant::now();
    let sent = ctx.upstream.send(req).await;
    // Best effort: the decision above is the record that must exist; this
    // one only adds what the API answered.
    let mut outcome = proxy_event(
        shared,
        claims,
        "proxy.response",
        AuditOutcome::Success,
        &ctx.host,
        ctx.port,
        Some((&method, &path)),
    )
    .target(format!("rule:{rule_id}"))
    .detail("credential_id", credential_id.to_string())
    .detail("request_id", request_id.clone())
    .detail("duration_ms", started.elapsed().as_millis().to_string());
    match sent {
        Ok(response) => {
            Metrics::inc(&shared.metrics.requests_injected_total);
            let status = response.status().as_u16();
            debug!(rule_id = %rule_id, session_id = %claims.jti, host = %ctx.host, %method, status, "injected credential");
            outcome = outcome.detail("status", status.to_string());
            let _ = shared.audit.try_record(outcome);
            if status == StatusCode::UNAUTHORIZED.as_u16() {
                if let Some(binding) = &ctx.binding {
                    binding.record_failure(
                        UpstreamFailureKind::CredentialRejected,
                        &ctx.host,
                        ctx.port,
                    );
                }
            }
            let response = response.map(|b| b.map_err(BodyError::from).boxed());
            match &mut cut {
                Some(cut) => response.map(|b| cut.wrap(b)),
                None => response,
            }
        }
        Err(e) => {
            Metrics::inc(&shared.metrics.upstream_errors_total);
            warn!(error = %e, "upstream request failed");
            outcome.outcome = AuditOutcome::Failure;
            outcome = outcome
                .detail("status", "502")
                .detail("reason", format!("upstream request failed: {e}"));
            let _ = shared.audit.try_record(outcome);
            if let Some(binding) = &ctx.binding {
                binding.record_failure(UpstreamFailureKind::Unreachable, &ctx.host, ctx.port);
            }
            respond(
                StatusCode::BAD_GATEWAY,
                &format!("upstream request failed: {e}"),
            )
        }
    }
}

/// Pairs a request's decision record with its response record.
fn new_request_id() -> String {
    hex::encode(rand::random::<[u8; 8]>())
}

#[cfg(test)]
mod tests {
    use tokenless_core::host::HostPattern;
    use tokenless_core::ids::{CredentialId, RuleId};
    use tokenless_core::path::{HttpMethod, PathPattern};
    use tokenless_core::rule::RuleScope;
    use tokenless_core::scope::Scope;

    use super::*;

    fn basic(raw: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            PROXY_AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}", STANDARD.encode(raw))).unwrap(),
        );
        h
    }

    #[test]
    fn parses_session_from_proxy_authorization() {
        assert_eq!(
            session_token(&basic("v4.public.abc:")),
            Some("v4.public.abc".into())
        );
        assert_eq!(
            session_token(&basic("x:v4.public.abc")),
            Some("v4.public.abc".into())
        );
        assert_eq!(
            session_token(&basic("v4.public.abc")),
            Some("v4.public.abc".into())
        );
        assert_eq!(session_token(&basic("user:password")), None);
        let mut bearer = HeaderMap::new();
        bearer.insert(
            PROXY_AUTHORIZATION,
            HeaderValue::from_static("Bearer v4.public.xyz"),
        );
        assert_eq!(session_token(&bearer), Some("v4.public.xyz".into()));
        assert_eq!(session_token(&HeaderMap::new()), None);
    }

    #[test]
    fn host_must_match_connect_target() {
        let mut h = HeaderMap::new();
        let origin: http::Uri = "/v1/models".parse().unwrap();
        h.insert(HOST, HeaderValue::from_static("api.example.com"));
        assert!(request_targets(&h, &origin, "api.example.com", 443));
        assert!(request_targets(&h, &origin, "api.example.com", 8443));
        h.insert(HOST, HeaderValue::from_static("api.example.com:8443"));
        assert!(request_targets(&h, &origin, "api.example.com", 8443));
        assert!(!request_targets(&h, &origin, "api.example.com", 443));
        h.insert(HOST, HeaderValue::from_static("evil.example.com"));
        assert!(!request_targets(&h, &origin, "api.example.com", 443));
        let absolute: http::Uri = "https://evil.example.com/x".parse().unwrap();
        h.insert(HOST, HeaderValue::from_static("api.example.com"));
        assert!(!request_targets(&h, &absolute, "api.example.com", 443));
        assert!(!request_targets(
            &HeaderMap::new(),
            &origin,
            "api.example.com",
            443
        ));
    }

    fn rule_for(paths: &[&str], token: &'static str) -> ActiveRule {
        ActiveRule {
            id: RuleId::new(),
            scope: Scope::parse("vault:x").unwrap(),
            credential_id: CredentialId::new(),
            allow: RuleScope {
                hosts: vec![HostPattern::parse("gitlab.com").unwrap()],
                paths: paths
                    .iter()
                    .map(|p| PathPattern::parse(p).unwrap())
                    .collect(),
                methods: vec![HttpMethod::parse("*").unwrap()],
                mcp_tools: None,
                git: None,
            },
            strip: vec![HeaderName::from_static("authorization")],
            inject: vec![(
                HeaderName::from_static("authorization"),
                HeaderValue::from_static(token),
            )],
            substitutions: vec![],
            not_after: None,
        }
    }

    fn chosen(rules: &[&ActiveRule], path: &str) -> Result<Option<RuleId>, (RuleId, RuleId)> {
        match choose_rule(rules.iter().copied(), "gitlab.com", 443, "GET", path, None) {
            RuleChoice::None => Ok(None),
            RuleChoice::One(rule) => Ok(Some(rule.id)),
            RuleChoice::Ambiguous(a, b) => Err((a.id, b.id)),
        }
    }

    #[test]
    fn a_request_uses_the_rule_whose_path_matches_it_most_specifically() {
        let git = rule_for(&["/*"], "Basic git");
        let api = rule_for(&["/api/*"], "Bearer api");
        // Whatever order the session lists them in.
        for rules in [vec![&git, &api], vec![&api, &git]] {
            assert_eq!(chosen(&rules, "/api/v4/projects"), Ok(Some(api.id)));
            assert_eq!(
                chosen(&rules, "/acme/widgets.git/info/refs"),
                Ok(Some(git.id))
            );
        }
        assert_eq!(chosen(&[&api], "/acme/widgets.git/info/refs"), Ok(None));
    }

    #[test]
    fn rules_that_tie_are_refused_only_when_they_send_different_credentials() {
        let first = rule_for(&["/*"], "Bearer one");
        let other = rule_for(&["/*"], "Basic two");
        assert_eq!(
            chosen(&[&first, &other], "/api/v4/projects"),
            Err((first.id, other.id))
        );
        // A more specific rule settles it.
        let api = rule_for(&["/api/*"], "Bearer api");
        assert_eq!(
            chosen(&[&first, &other, &api], "/api/v4/projects"),
            Ok(Some(api.id))
        );
        // Two services holding the same token in the same form are
        // interchangeable.
        let same = rule_for(&["/*"], "Bearer one");
        assert_eq!(chosen(&[&first, &same], "/x"), Ok(Some(first.id)));
    }

    #[test]
    fn rewrite_strips_client_credentials_and_injects() {
        let rule = ActiveRule {
            id: RuleId::new(),
            scope: Scope::parse("vault:x").unwrap(),
            credential_id: CredentialId::new(),
            allow: RuleScope {
                hosts: vec![HostPattern::parse("api.example.com").unwrap()],
                paths: vec![PathPattern::parse("/*").unwrap()],
                methods: vec![HttpMethod::parse("*").unwrap()],
                mcp_tools: None,
                git: None,
            },
            strip: vec![
                HeaderName::from_static("authorization"),
                HeaderName::from_static("x-api-key"),
            ],
            inject: vec![(
                HeaderName::from_static("authorization"),
                HeaderValue::from_static("Bearer broker"),
            )],
            substitutions: vec![],
            not_after: None,
        };
        let mut h = HeaderMap::new();
        h.insert(
            "authorization",
            HeaderValue::from_static("Bearer client-own"),
        );
        h.append("authorization", HeaderValue::from_static("Bearer second"));
        h.insert("x-api-key", HeaderValue::from_static("client-key"));
        h.insert(PROXY_AUTHORIZATION, HeaderValue::from_static("Basic abc"));
        h.insert(CONNECTION, HeaderValue::from_static("x-secret-hop"));
        h.insert("x-secret-hop", HeaderValue::from_static("1"));
        h.insert("accept", HeaderValue::from_static("*/*"));
        rewrite_headers(&mut h, &rule);
        assert_eq!(h.get_all("authorization").iter().count(), 1);
        assert_eq!(h.get("authorization").unwrap(), "Bearer broker");
        assert!(h.get("x-api-key").is_none());
        assert!(h.get(PROXY_AUTHORIZATION).is_none());
        assert!(h.get("x-secret-hop").is_none());
        assert_eq!(h.get("accept").unwrap(), "*/*");
    }

    #[test]
    fn head_substitution_rewrites_target_and_agent_headers_only() {
        use tokenless_core::substitution::SubstitutionLocation::*;
        let subs = vec![RenderedSubstitution {
            placeholder: "__API_KEY__".into(),
            value: "sk/live 1".into(),
            locations: vec![Path, Query, Header],
        }];
        let mut req = Request::builder()
            .uri("/v1/__API_KEY__/items?key=__API_KEY__")
            .header(HOST, "__API_KEY__.example.com")
            .header("x-api-key", "__API_KEY__")
            .header("x-trace", "plain")
            .body(())
            .unwrap();
        let mut applied = Applied::default();
        substitute_head(&mut req, &subs, &mut applied).unwrap();
        assert_eq!(req.uri(), "/v1/sk%2Flive%201/items?key=sk%2Flive%201");
        assert_eq!(req.headers()["x-api-key"], "sk/live 1");
        assert!(req.headers()["x-api-key"].is_sensitive());
        assert_eq!(
            req.headers()[HOST],
            "__API_KEY__.example.com",
            "Host is never rewritten"
        );
        assert_eq!(req.headers()["x-trace"], "plain");
        assert_eq!(applied.placeholders, ["__API_KEY__"]);
    }

    #[test]
    fn only_bounded_uncompressed_bodies_are_buffered() {
        let headers = |pairs: &[(&'static str, &'static str)]| {
            let mut h = HeaderMap::new();
            for (k, v) in pairs {
                h.insert(*k, HeaderValue::from_static(v));
            }
            h
        };
        assert_eq!(
            body_skip_reason(&headers(&[("content-length", "12")])),
            None
        );
        assert_eq!(
            body_skip_reason(&headers(&[
                ("content-length", "12"),
                ("content-encoding", "identity")
            ])),
            None
        );
        assert!(body_skip_reason(&headers(&[
            ("content-length", "12"),
            ("content-encoding", "gzip")
        ]))
        .unwrap()
        .contains("compressed"));
        assert!(body_skip_reason(&headers(&[])).unwrap().contains("unknown"));
        assert!(body_skip_reason(&headers(&[("content-length", "4194305")]))
            .unwrap()
            .contains("4 MiB"));
    }

    #[tokio::test]
    async fn passthrough_resolution_applies_the_egress_policy() {
        use tokenless_core::egress::EgressPolicy;
        let limit = std::time::Duration::from_secs(5);
        let blocked = resolve_passthrough("127.0.0.1", 443, &EgressPolicy::default(), limit).await;
        assert!(matches!(
            blocked,
            Err(Refusal::Blocked {
                reason: "loopback",
                ..
            })
        ));
        let allowing = EgressPolicy {
            block_private: true,
            allow: vec!["127.0.0.0/8".parse().unwrap()],
        };
        let addrs = resolve_passthrough("127.0.0.1", 443, &allowing, limit)
            .await
            .ok()
            .unwrap();
        assert_eq!(addrs, vec!["127.0.0.1:443".parse().unwrap()]);
        // Names are resolved and checked too, so `localhost` cannot bypass it.
        let named = resolve_passthrough("localhost", 443, &EgressPolicy::default(), limit).await;
        assert!(matches!(named, Err(Refusal::Blocked { .. })));
    }

    /// The proxy sends each request upstream once. A request that may not be
    /// idempotent is never replayed, even when the upstream drops it.
    #[tokio::test]
    async fn a_request_the_upstream_drops_is_not_retried() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        use rustls::pki_types::CertificateDer;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_rustls::TlsAcceptor;

        use crate::testing::running;
        use crate::tls::leaf_server_config;

        // An upstream that reads each request and hangs up without answering.
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let upstream_root = CertificateDer::from(cert.cert.der().to_vec());
        let server = leaf_server_config(
            "localhost",
            vec![upstream_root.clone()],
            cert.signing_key.serialize_der(),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let received = Arc::new(AtomicUsize::new(0));
        let counter = received.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = TlsAcceptor::from(server.clone());
                let counter = counter.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        if tls.read(&mut byte).await.unwrap_or(0) == 0 {
                            return;
                        }
                        head.push(byte[0]);
                    }
                    counter.fetch_add(1, Ordering::SeqCst);
                });
            }
        });

        let target = format!("localhost:{port}");
        let r = running(&target, vec![upstream_root]).await;
        let mut tls = r.intercepted(&target, "localhost").await;
        tls.write_all(
            format!("POST /charge HTTP/1.1\r\nHost: {target}\r\nContent-Length: 0\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
        let mut buf = vec![0u8; 4096];
        let n = tls.read(&mut buf).await.unwrap();
        let answer = String::from_utf8_lossy(&buf[..n]);
        assert!(answer.starts_with("HTTP/1.1 502"), "{answer}");

        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(received.load(Ordering::SeqCst), 1);
        r.dp.abort();
    }

    /// Git over HTTPS through a rule that names one repository's paths: a
    /// read rule lets a clone fetch and refuses a push by its path, and a
    /// pack larger than the substitution limit streams to the upstream.
    #[tokio::test]
    async fn git_rules_allow_a_fetch_refuse_a_push_and_stream_a_large_pack() {
        use rustls::pki_types::CertificateDer;
        use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
        use tokio_rustls::TlsAcceptor;

        use crate::testing::running;
        use crate::tls::leaf_server_config;

        async fn read_message(stream: &mut (impl AsyncRead + Unpin)) -> Option<(String, Vec<u8>)> {
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                if stream.read(&mut byte).await.unwrap_or(0) == 0 {
                    return None;
                }
                head.push(byte[0]);
            }
            let head = String::from_utf8_lossy(&head).into_owned();
            let length = head
                .lines()
                .find_map(|l| {
                    let (name, value) = l.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            let mut body = vec![0u8; length];
            stream.read_exact(&mut body).await.unwrap();
            Some((head, body))
        }

        async fn send(
            stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
            head: &str,
            body: &[u8],
        ) -> (String, Vec<u8>) {
            stream.write_all(head.as_bytes()).await.unwrap();
            stream.write_all(body).await.unwrap();
            read_message(stream).await.unwrap()
        }

        // An upstream that answers each request with the size of its body.
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let upstream_root = CertificateDer::from(cert.cert.der().to_vec());
        let server = leaf_server_config(
            "localhost",
            vec![upstream_root.clone()],
            cert.signing_key.serialize_der(),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = TlsAcceptor::from(server.clone());
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    while let Some((_, body)) = read_message(&mut tls).await {
                        let size = body.len().to_string();
                        let answer = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{size}",
                            size.len()
                        );
                        if tls.write_all(answer.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });

        let target = format!("localhost:{port}");
        let r = running(&target, vec![upstream_root]).await;
        let install = |version: u64, paths: &[&str]| {
            let mut body = r.f.snapshot_body(
                version,
                vec![(r.rule, Scope::parse("vault:test").unwrap(), &target, "t")],
            );
            body.egress = tokenless_core::egress::EgressPolicy {
                block_private: false,
                allow: vec![],
            };
            body.rules[0].allow.paths = paths
                .iter()
                .map(|p| PathPattern::parse(p).unwrap())
                .collect();
            body.rules[0].allow.methods = ["GET", "POST"]
                .iter()
                .map(|m| HttpMethod::parse(m).unwrap())
                .collect();
            r.installer.install(&r.f.sign(&body)).unwrap();
        };
        let read = [
            "/acme/widgets.git/info/refs",
            "/acme/widgets.git/git-upload-pack",
        ];
        install(2, &read);

        let mut tls = r.intercepted(&target, "localhost").await;
        let (head, _) = send(
            &mut tls,
            &format!(
                "GET /acme/widgets.git/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: {target}\r\n\r\n"
            ),
            b"",
        )
        .await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        let (head, _) = send(
            &mut tls,
            &format!(
                "POST /acme/widgets.git/git-upload-pack HTTP/1.1\r\nHost: {target}\r\nContent-Length: 4\r\n\r\n"
            ),
            b"0000",
        )
        .await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");

        // A push is refused by its path, and so is another repository.
        let mut tls = r.intercepted(&target, "localhost").await;
        let (head, _) = send(
            &mut tls,
            &format!(
                "POST /acme/widgets.git/git-receive-pack HTTP/1.1\r\nHost: {target}\r\nContent-Length: 4\r\n\r\n"
            ),
            b"0000",
        )
        .await;
        assert!(head.starts_with("HTTP/1.1 403"), "{head}");
        let mut tls = r.intercepted(&target, "localhost").await;
        let (head, _) = send(
            &mut tls,
            &format!(
                "GET /acme/other.git/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: {target}\r\n\r\n"
            ),
            b"",
        )
        .await;
        assert!(head.starts_with("HTTP/1.1 403"), "{head}");

        // With the write paths, a pack over the 4 MiB substitution limit
        // reaches the upstream whole.
        install(3, &[read[0], read[1], "/acme/widgets.git/git-receive-pack"]);
        let pack = vec![b'p'; MAX_SUBSTITUTION_BODY as usize + 1024 * 1024];
        let mut tls = r.intercepted(&target, "localhost").await;
        let (head, body) = send(
            &mut tls,
            &format!(
                "POST /acme/widgets.git/git-receive-pack HTTP/1.1\r\nHost: {target}\r\nContent-Type: application/x-git-receive-pack-request\r\nContent-Length: {}\r\n\r\n",
                pack.len()
            ),
            &pack,
        )
        .await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert_eq!(String::from_utf8_lossy(&body), pack.len().to_string());
        r.dp.abort();
    }

    /// Two services on one host in one session: each request goes to the
    /// rule matching its path most specifically, and rules that tie with
    /// different credentials are refused instead of picked by order.
    #[tokio::test]
    async fn a_session_with_two_services_on_one_host_sends_each_its_own_credential() {
        use std::collections::BTreeMap;

        use tokenless_core::session::{SessionClaims, SessionSigner};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        use crate::audit::AuditShipper;
        use crate::testing::{https_echo_authorization_upstream, running_with};

        #[derive(Default)]
        struct Collect(std::sync::Mutex<Vec<AuditEvent>>);
        #[async_trait::async_trait]
        impl AuditShipper for Collect {
            async fn ship(&self, events: &[AuditEvent]) -> Result<(), crate::DataPlaneError> {
                self.0.lock().unwrap().extend_from_slice(events);
                Ok(())
            }
        }

        let (port, root) = https_echo_authorization_upstream().await;
        let target = format!("localhost:{port}");
        let audit = Arc::new(Collect::default());
        let r = running_with(&target, vec![root], 600, audit.clone()).await;
        let git = r.rule;
        let api = RuleId::new();
        let install = |version: u64, api_paths: &[&str]| {
            let scope = Scope::parse("vault:test").unwrap();
            let mut body = r.f.snapshot_body(
                version,
                vec![
                    (git, scope.clone(), &target, "git"),
                    (api, scope, &target, "api"),
                ],
            );
            body.egress = tokenless_core::egress::EgressPolicy {
                block_private: false,
                allow: vec![],
            };
            body.rules[1].allow.paths = api_paths
                .iter()
                .map(|p| PathPattern::parse(p).unwrap())
                .collect();
            r.installer.install(&r.f.sign(&body)).unwrap();
        };
        let claims = SessionClaims::new(
            Scope::parse("vault:test").unwrap(),
            vec![git, api],
            600,
            None,
            BTreeMap::new(),
            Utc::now(),
            3600,
        )
        .unwrap();
        let token = SessionSigner::new(r.f.session_signer.clone())
            .sign(&claims)
            .unwrap();
        let get = |path: String| {
            let target = target.clone();
            let token = token.clone();
            let r = &r;
            async move {
                let mut tls = r.intercepted_with(&target, "localhost", &token).await;
                tls.write_all(
                    format!("GET {path} HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n")
                        .as_bytes(),
                )
                .await
                .unwrap();
                let mut answer = Vec::new();
                let _ = tls.read_to_end(&mut answer).await;
                String::from_utf8_lossy(&answer).into_owned()
            }
        };

        install(2, &["/*"]);
        let answer = get("/api/v4/projects".into()).await;
        assert!(answer.starts_with("HTTP/1.1 403"), "{answer}");
        assert!(answer.contains("send different credentials"), "{answer}");
        // A long path is recorded capped, never whole.
        let long = format!("/{}", "a".repeat(8000));
        let answer = get(long.clone()).await;
        assert!(answer.starts_with("HTTP/1.1 403"), "{answer}");
        let mut denied = None;
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            denied = audit
                .0
                .lock()
                .unwrap()
                .iter()
                .filter(|e| e.action == "proxy.deny")
                .find(|e| e.detail.get("path").is_some_and(|p| p.starts_with("/aaa")))
                .cloned();
            if denied.is_some() {
                break;
            }
        }
        let denied = denied.expect("the refusal was audited");
        assert!(denied.detail["reason"].starts_with("ambiguous_rules: "));
        for (key, value) in &denied.detail {
            assert!(
                value.len() <= 512,
                "audit detail {key} is {} bytes",
                value.len()
            );
        }

        install(3, &["/api/*"]);
        let answer = get("/api/v4/projects".into()).await;
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
        assert!(answer.ends_with("Bearer api"), "{answer}");
        let answer = get("/acme/widgets.git/info/refs".into()).await;
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
        assert!(answer.ends_with("Bearer git"), "{answer}");
        r.dp.abort();
    }
}
