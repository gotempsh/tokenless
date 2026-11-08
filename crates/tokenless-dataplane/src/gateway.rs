// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The MCP gateway: a plain-HTTP reverse proxy for clients that connect to
//! an MCP server by URL instead of through `HTTPS_PROXY`.
//!
//! A client asks for `http://<listen>/mcp/<host[:port]>/<path>` with
//! `Authorization: Bearer <session token>`. The gateway verifies the token
//! against the snapshot, takes it off the request, and forwards the rest
//! over TLS to `https://<host[:port]>/<path>` exactly as an intercepted
//! tunnel would: same rule match, same credential injection, same MCP tool
//! allowlist, same audit records. Responses (including SSE streams) are
//! passed back as they arrive.
//!
//! The gateway only reaches hosts a rule of the session covers. It never
//! forwards to anything else, so it cannot be used to reach the network.

use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;
use http::header::{AUTHORIZATION, HOST, PROXY_AUTHORIZATION, WWW_AUTHENTICATE};
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokenless_core::audit::AuditOutcome;
use tokenless_core::host::parse_authority;
use tokenless_core::session::verify_session;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{debug, warn};

use crate::cut::{CutBody, SessionWatch};
use crate::metrics::Metrics;
use crate::proxy::{
    audit_best_effort, check_session, handle_intercepted, respond, session_rules, tunnel_cut,
    ProxyBody, ProxyShared, TunnelCtx,
};
use crate::upstream::UpstreamHandle;

/// Every gateway URL starts with this.
pub const PREFIX: &str = "/mcp/";

const USAGE: &str = "the MCP gateway serves /mcp/<host>/<path>, e.g. /mcp/api.example.com/mcp, with Authorization: Bearer <session token>";

/// Splits `/mcp/<authority>[/<path>][?<query>]` into the upstream authority
/// and the request target to send it.
pub fn split_target(path_and_query: &str) -> Option<(&str, String)> {
    let rest = path_and_query.strip_prefix(PREFIX)?;
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    if authority.is_empty() {
        return None;
    }
    let target = if tail.starts_with('/') {
        tail.to_string()
    } else {
        format!("/{tail}")
    };
    Some((authority, target))
}

/// The session token in `Authorization: Bearer <token>`.
pub fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?.trim();
    let (scheme, token) = value.split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("bearer") && token.starts_with("v4.public."))
        .then(|| token.to_string())
}

/// The `Host` header for an upstream: the port only when it is not 443.
fn host_header(host: &str, port: u16) -> String {
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if port == 443 {
        host
    } else {
        format!("{host}:{port}")
    }
}

fn unauthorized(message: &str) -> Response<ProxyBody> {
    let mut response = respond(StatusCode::UNAUTHORIZED, message);
    response.headers_mut().insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"tokenless\""),
    );
    response
}

/// The upstream connection of one client connection. Requests on an
/// HTTP/1 connection arrive one at a time, so the lock is never contended;
/// it only lets the per-request closure keep the connection between calls.
type ConnectionUpstream = Arc<Mutex<Option<(String, u16, UpstreamHandle)>>>;

fn upstream_for(
    slot: &ConnectionUpstream,
    host: &str,
    port: u16,
    shared: &ProxyShared,
) -> UpstreamHandle {
    let mut current = slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some((h, p, handle)) = current.as_ref() {
        if h == host && *p == port {
            return handle.clone();
        }
    }
    let handle = UpstreamHandle::spawn(
        host.to_string(),
        port,
        shared.upstream_tls.clone(),
        shared.connect_timeout,
    );
    *current = Some((host.to_string(), port, handle.clone()));
    handle
}

pub async fn serve(listener: TcpListener, shared: Arc<ProxyShared>, max_connections: usize) {
    let limit = Arc::new(Semaphore::new(max_connections.max(1)));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                warn!(error = %e, "MCP gateway accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            Metrics::inc(&shared.metrics.connections_rejected);
            debug!(%peer, "connection limit reached; dropping MCP gateway connection");
            continue;
        };
        Metrics::inc(&shared.metrics.connections_total);
        let _ = stream.set_nodelay(true);
        let shared = shared.clone();
        tokio::spawn(async move {
            let slot: ConnectionUpstream = Arc::new(Mutex::new(None));
            let service = service_fn(move |req| {
                let shared = shared.clone();
                let slot = slot.clone();
                async move { Ok::<_, Infallible>(handle(req, shared, slot).await) }
            });
            let mut builder = http1::Builder::new();
            builder
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(60));
            if let Err(e) = builder
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                debug!(%peer, error = %e, "MCP gateway connection ended with error");
            }
            drop(permit);
        });
    }
}

async fn handle(
    mut req: Request<Incoming>,
    shared: Arc<ProxyShared>,
    slot: ConnectionUpstream,
) -> Response<ProxyBody> {
    Metrics::inc(&shared.metrics.gateway_requests_total);
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
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_default();
    let Some((authority, target)) = split_target(&path_and_query) else {
        return respond(StatusCode::NOT_FOUND, USAGE);
    };
    let Some((host, port)) = parse_authority(authority) else {
        return respond(
            StatusCode::BAD_REQUEST,
            &format!("'{authority}' is not a host or host:port; {USAGE}"),
        );
    };
    let Some(token) = bearer_token(req.headers()) else {
        Metrics::inc(&shared.metrics.gateway_auth_failures_total);
        return unauthorized(
            "a session token is required: send Authorization: Bearer <session token> (tokenless mcp prints one)",
        );
    };
    let claims = match verify_session(&token, &snapshot.session_keys, Utc::now()) {
        Ok(claims) => claims,
        Err(e) => {
            Metrics::inc(&shared.metrics.gateway_auth_failures_total);
            debug!(error = %e, "MCP gateway session rejected");
            return unauthorized(&format!("session rejected: {e}"));
        }
    };
    if let Err(reason) = check_session(&snapshot, &claims, &shared.node, None) {
        Metrics::inc(&shared.metrics.gateway_auth_failures_total);
        return unauthorized(reason);
    }
    if !session_rules(&snapshot, &claims).any(|r| r.allow.matches_host(&host, port)) {
        Metrics::inc(&shared.metrics.connect_denied_total);
        audit_best_effort(
            &shared,
            &claims,
            "proxy.gateway_denied",
            AuditOutcome::Denied,
            &host,
            port,
            Some((req.method().as_str(), &target)),
            "no rule in the session covers this host",
        );
        return respond(
            StatusCode::FORBIDDEN,
            &format!(
                "no rule in this session covers {}; the MCP gateway only forwards to the session's own services",
                host_header(&host, port)
            ),
        );
    }
    drop(snapshot);

    // The session token is for the gateway alone: it never goes upstream,
    // whatever header the rule injects.
    req.headers_mut().remove(AUTHORIZATION);
    req.headers_mut().remove(PROXY_AUTHORIZATION);
    match target.parse() {
        Ok(uri) => *req.uri_mut() = uri,
        Err(e) => {
            return respond(
                StatusCode::BAD_REQUEST,
                &format!("request target '{target}' is invalid: {e}"),
            )
        }
    }
    match HeaderValue::from_str(&host_header(&host, port)) {
        Ok(value) => {
            req.headers_mut().insert(HOST, value);
        }
        Err(_) => {
            return respond(
                StatusCode::BAD_REQUEST,
                &format!("'{authority}' cannot be sent as a Host header"),
            )
        }
    }

    let upstream = upstream_for(&slot, &host, port, &shared);
    let watch = SessionWatch::new(
        shared.snapshot_changed.subscribe(),
        shared.snapshot.clone(),
        &claims,
    );
    let claims = Arc::new(claims);
    let ctx = Arc::new(TunnelCtx {
        host,
        port,
        claims: claims.clone(),
        shared: shared.clone(),
        upstream,
        binding: None,
    });
    let mut response = handle_intercepted(req, ctx.clone()).await;
    // The client authenticated to the gateway, not to the upstream. An
    // upstream challenge would start an OAuth flow that bypasses the broker,
    // so only the gateway's own refusals carry one.
    if response.headers().get("x-broker-error").is_some() {
        return response;
    }
    response.headers_mut().remove(WWW_AUTHENTICATE);
    // An MCP server may answer with an event stream that stays open; it ends
    // when the session does.
    response.map(|body| {
        CutBody::wrap(body, watch, move |end| {
            tunnel_cut(&ctx.shared, &claims, &ctx.host, ctx.port, end);
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_authority_and_target() {
        assert_eq!(
            split_target("/mcp/api.example.com/mcp/"),
            Some(("api.example.com", "/mcp/".to_string()))
        );
        assert_eq!(
            split_target("/mcp/localhost:8443/v1/x?a=1"),
            Some(("localhost:8443", "/v1/x?a=1".to_string()))
        );
        assert_eq!(
            split_target("/mcp/mcp.example.com"),
            Some(("mcp.example.com", "/".to_string()))
        );
        assert_eq!(
            split_target("/mcp/mcp.example.com?x=1"),
            Some(("mcp.example.com", "/?x=1".to_string()))
        );
        assert_eq!(split_target("/mcp/"), None);
        assert_eq!(split_target("/mcp//path"), None);
        assert_eq!(split_target("/other/api.example.com"), None);
        assert_eq!(split_target("/"), None);
    }

    #[test]
    fn takes_only_bearer_session_tokens() {
        let mut headers = HeaderMap::new();
        assert_eq!(bearer_token(&headers), None);
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer v4.public.abc"),
        );
        assert_eq!(bearer_token(&headers).as_deref(), Some("v4.public.abc"));
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("bearer  v4.public.abc "),
        );
        assert_eq!(bearer_token(&headers).as_deref(), Some("v4.public.abc"));
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer ghp_upstream"),
        );
        assert_eq!(bearer_token(&headers), None);
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Basic djQucHVibGljLmFiYw=="),
        );
        assert_eq!(bearer_token(&headers), None);
    }

    #[test]
    fn host_header_omits_the_default_port() {
        assert_eq!(host_header("api.example.com", 443), "api.example.com");
        assert_eq!(host_header("localhost", 8443), "localhost:8443");
        assert_eq!(host_header("::1", 9000), "[::1]:9000");
    }
}
