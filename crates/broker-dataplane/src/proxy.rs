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
use broker_core::audit::{AuditEvent, AuditOutcome};
use broker_core::host::parse_authority;
use broker_core::mcp::{self, McpMessage, NotJsonRpc};
use broker_core::path::check_request_path;
use broker_core::rule::RuleScope;
use broker_core::session::{verify_session, SessionClaims};
use broker_core::snapshot::UnmatchedHostPolicy;
use broker_core::substitution::{
    apply_to_body, apply_to_header, apply_to_target, wants_body, Applied, BodyKind,
    RenderedSubstitution,
};
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
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_rustls::LazyConfigAcceptor;
use tracing::{debug, warn};

use crate::audit::AuditPipeline;
use crate::metrics::Metrics;
use crate::state::{ActiveRule, ActiveSnapshot, SnapshotHandle};
use crate::upstream::UpstreamHandle;

pub type ProxyBody = BoxBody<Bytes, hyper::Error>;

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
    pub snapshot: SnapshotHandle,
    pub audit: AuditPipeline,
    pub metrics: Arc<Metrics>,
    pub upstream_tls: Arc<ClientConfig>,
    pub connect_timeout: Duration,
    pub node_id: String,
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
/// request inside a tunnel.
pub(crate) fn check_session(
    snapshot: &ActiveSnapshot,
    claims: &SessionClaims,
) -> Result<(), &'static str> {
    if Utc::now() >= claims.exp {
        return Err("proxy session has expired");
    }
    if snapshot.revoked.contains(&claims.jti) {
        return Err("proxy session has been revoked");
    }
    Ok(())
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

pub async fn serve(listener: TcpListener, shared: Arc<ProxyShared>, max_connections: usize) {
    let limit = Arc::new(Semaphore::new(max_connections.max(1)));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                warn!(error = %e, "proxy accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            Metrics::inc(&shared.metrics.connections_rejected);
            debug!(%peer, "connection limit reached; dropping connection");
            continue;
        };
        Metrics::inc(&shared.metrics.connections_total);
        let _ = stream.set_nodelay(true);
        let shared = shared.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let shared = shared.clone();
                async move { Ok::<_, Infallible>(handle_proxy_request(req, shared).await) }
            });
            let mut builder = http1::Builder::new();
            builder
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(30));
            if let Err(e) = builder
                .serve_connection(TokioIo::new(stream), service)
                .with_upgrades()
                .await
            {
                debug!(%peer, error = %e, "proxy connection ended with error");
            }
            drop(permit);
        });
    }
}

async fn handle_proxy_request(
    mut req: Request<Incoming>,
    shared: Arc<ProxyShared>,
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
    let Some(token) = session_token(req.headers()) else {
        Metrics::inc(&shared.metrics.proxy_auth_failures_total);
        return proxy_auth_required(
            "a proxy session token is required (HTTPS_PROXY=http://<token>@host:port)",
        );
    };
    let claims = match verify_session(&token, &snapshot.session_keys, Utc::now()) {
        Ok(claims) => claims,
        Err(e) => {
            Metrics::inc(&shared.metrics.proxy_auth_failures_total);
            debug!(error = %e, "proxy session rejected");
            return proxy_auth_required(&format!("proxy session rejected: {e}"));
        }
    };
    if let Err(reason) = check_session(&snapshot, &claims) {
        Metrics::inc(&shared.metrics.proxy_auth_failures_total);
        return proxy_auth_required(reason);
    }
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
    drop(snapshot);

    let on_upgrade = hyper::upgrade::on(&mut req);
    let claims = Arc::new(claims);
    tokio::spawn(async move {
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
                intercept_tunnel(TokioIo::new(upgraded), config, host, port, claims, shared).await;
            }
            None => {
                Metrics::inc(&shared.metrics.tunnels_passthrough_total);
                passthrough(
                    TokioIo::new(upgraded),
                    &host,
                    port,
                    &passthrough_addrs,
                    &shared,
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
    egress: &broker_core::egress::EgressPolicy,
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

async fn passthrough(
    mut client: TokioIo<hyper::upgrade::Upgraded>,
    host: &str,
    port: u16,
    addrs: &[std::net::SocketAddr],
    shared: &ProxyShared,
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
    if let Err(e) = tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
        debug!(%host, port, error = %e, "passthrough tunnel closed");
    }
}

async fn intercept_tunnel(
    io: TokioIo<hyper::upgrade::Upgraded>,
    config: Arc<rustls::ServerConfig>,
    host: String,
    port: u16,
    claims: Arc<SessionClaims>,
    shared: Arc<ProxyShared>,
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
    let ctx = Arc::new(TunnelCtx {
        host,
        port,
        claims,
        shared,
        upstream,
    });
    let service = service_fn(move |req| {
        let ctx = ctx.clone();
        async move { Ok::<_, Infallible>(handle_intercepted(req, ctx).await) }
    });
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(60));
    if let Err(e) = builder.serve_connection(TokioIo::new(tls), service).await {
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
    if let Err(reason) = check_session(&snapshot, claims) {
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
    if let Err(rejection) = check_request_path(&path) {
        Metrics::inc(&shared.metrics.requests_denied_total);
        return respond(StatusCode::BAD_REQUEST, rejection.as_str());
    }
    let Some(rule) = session_rules(&snapshot, claims)
        .find(|r| r.allow.allows(&ctx.host, ctx.port, &method, &path))
    else {
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
                req.map(|b| b.boxed())
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
        req.map(|b| b.boxed())
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
            response.map(|b| b.boxed())
        }
        Err(e) => {
            Metrics::inc(&shared.metrics.upstream_errors_total);
            warn!(error = %e, "upstream request failed");
            outcome.outcome = AuditOutcome::Failure;
            outcome = outcome
                .detail("status", "502")
                .detail("reason", format!("upstream request failed: {e}"));
            let _ = shared.audit.try_record(outcome);
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
    use broker_core::host::HostPattern;
    use broker_core::ids::{CredentialId, RuleId};
    use broker_core::path::{HttpMethod, PathPattern};
    use broker_core::rule::RuleScope;
    use broker_core::scope::Scope;

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
        use broker_core::substitution::SubstitutionLocation::*;
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
        use broker_core::egress::EgressPolicy;
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
}
