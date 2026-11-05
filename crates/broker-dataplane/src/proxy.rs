// SPDX-FileCopyrightText: 2026 credential-broker contributors
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
use broker_core::path::check_request_path;
use broker_core::session::{verify_session, SessionClaims};
use broker_core::snapshot::UnmatchedHostPolicy;
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
use tracing::{debug, info, warn};

use crate::audit::AuditPipeline;
use crate::metrics::Metrics;
use crate::state::{ActiveRule, ActiveSnapshot, SnapshotHandle};
use crate::upstream::UpstreamHandle;

pub type ProxyBody = BoxBody<Bytes, hyper::Error>;

const REALM: &str = "Basic realm=\"credential-broker\"";
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

fn body(text: impl Into<Bytes>) -> ProxyBody {
    Full::new(text.into())
        .map_err(|never| match never {})
        .boxed()
}

fn respond(status: StatusCode, message: &str) -> Response<ProxyBody> {
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
fn check_session(snapshot: &ActiveSnapshot, claims: &SessionClaims) -> Result<(), &'static str> {
    if Utc::now() >= claims.exp {
        return Err("proxy session has expired");
    }
    if snapshot.revoked.contains(&claims.jti) {
        return Err("proxy session has been revoked");
    }
    Ok(())
}

fn session_rules<'a>(
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
    if !intercept && snapshot.policy == UnmatchedHostPolicy::Deny {
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
            "no rule covers this host and the unmatched-host policy is deny",
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
                passthrough(TokioIo::new(upgraded), &host, port, &shared).await;
            }
        }
    });
    Response::new(body(Bytes::new()))
}

async fn passthrough(
    mut client: TokioIo<hyper::upgrade::Upgraded>,
    host: &str,
    port: u16,
    shared: &ProxyShared,
) {
    let upstream = timeout(shared.connect_timeout, TcpStream::connect((host, port))).await;
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

struct TunnelCtx {
    host: String,
    port: u16,
    claims: Arc<SessionClaims>,
    shared: Arc<ProxyShared>,
    upstream: UpstreamHandle,
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

#[allow(clippy::too_many_arguments)]
fn audit_best_effort(
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

async fn handle_intercepted(
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
    let event = proxy_event(
        shared,
        claims,
        "proxy.inject",
        AuditOutcome::Success,
        &ctx.host,
        ctx.port,
        Some((&method, &path)),
    )
    .target(format!("rule:{}", rule.id))
    .detail("credential_id", rule.credential_id.to_string());
    if shared.audit.try_record(event).is_err() {
        return respond(
            StatusCode::SERVICE_UNAVAILABLE,
            "audit pipeline is saturated; refusing to inject a credential without an audit record",
        );
    }
    rewrite_headers(req.headers_mut(), rule);
    let rule_id = rule.id;
    drop(snapshot);
    match ctx.upstream.send(req).await {
        Ok(response) => {
            Metrics::inc(&shared.metrics.requests_injected_total);
            info!(rule_id = %rule_id, session_id = %claims.jti, host = %ctx.host, %method, status = response.status().as_u16(), "injected credential");
            response.map(|b| b.boxed())
        }
        Err(e) => {
            Metrics::inc(&shared.metrics.upstream_errors_total);
            warn!(error = %e, "upstream request failed");
            respond(
                StatusCode::BAD_GATEWAY,
                &format!("upstream request failed: {e}"),
            )
        }
    }
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
            },
            strip: vec![
                HeaderName::from_static("authorization"),
                HeaderName::from_static("x-api-key"),
            ],
            inject: vec![(
                HeaderName::from_static("authorization"),
                HeaderValue::from_static("Bearer broker"),
            )],
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
}
