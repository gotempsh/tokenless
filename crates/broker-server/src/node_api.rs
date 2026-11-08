// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The node API: enrolment, certificate renewal, the snapshot stream and
//! audit ingest. Served over TLS with an optional client certificate; every
//! endpoint except enrolment requires a valid, unrevoked node certificate.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::extract::{Extension, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use bytes::Bytes;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use serde::{Deserialize, Serialize};
use tokenless_control::model::Node;
use tokenless_control::pki::{issue_server_cert, node_id_from_cert};
use tokenless_control::ControlPlane;
use tokenless_core::ids::NodeId;
use tokenless_core::protocol::{AuditBatch, EnrollRequest, RenewRequest};
use tokenless_core::snapshot::MIN_SNAPSHOT_FORMAT;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use tracing::{debug, info, warn};

use crate::api::{ApiJson, ApiQuery, AppState};
use crate::error::{ApiError, ServerError};

/// The node identity proven by the TLS client certificate, if any.
#[derive(Debug, Clone, Copy)]
pub struct NodePeer(pub Option<NodeId>);

const SERVER_CERT_VALIDITY_DAYS: i64 = 7;
const SERVER_CERT_ROTATE: Duration = Duration::from_secs(24 * 3600);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_NODE_CONNECTIONS: usize = 256;

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn tls_err(reason: impl std::fmt::Display) -> ServerError {
    ServerError::Tls {
        listener: "node API".into(),
        reason: reason.to_string(),
    }
}

/// Builds the node API TLS config with a freshly issued server certificate.
/// The chain is `[leaf, node CA]` so enrolling nodes can pin the CA.
pub fn node_tls_config(
    control: &ControlPlane,
    names: &[String],
) -> Result<Arc<ServerConfig>, ServerError> {
    let ca = &control.keys.node_ca;
    let issued = issue_server_cert(ca, names, chrono::Duration::days(SERVER_CERT_VALIDITY_DAYS))?;
    let ca_der = CertificateDer::from(ca.cert_der.clone());
    let mut roots = RootCertStore::empty();
    roots.add(ca_der.clone()).map_err(tls_err)?;
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider())
        .allow_unauthenticated()
        .build()
        .map_err(tls_err)?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(issued.key_der.to_vec()));
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(tls_err)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![CertificateDer::from(issued.cert_der), ca_der], key)
        .map_err(tls_err)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Reissues the node API certificate daily so it never expires in service.
pub async fn rotate_server_cert(
    control: Arc<ControlPlane>,
    names: Vec<String>,
    tls: Arc<ArcSwap<ServerConfig>>,
) {
    loop {
        tokio::time::sleep(SERVER_CERT_ROTATE).await;
        match node_tls_config(&control, &names) {
            Ok(config) => {
                tls.store(config);
                info!("rotated node API server certificate");
            }
            Err(e) => {
                warn!(error = %e, "node API certificate rotation failed; keeping the current one")
            }
        }
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/node/v1/enroll", post(enroll))
        .route("/node/v1/renew", post(renew))
        .route("/node/v1/snapshots/stream", get(snapshot_stream))
        .route("/node/v1/audit", post(ingest_audit))
        .with_state(state)
}

/// Accepts TLS connections and serves the node router, attaching the
/// client-certificate identity to each request. Connections live in a
/// `JoinSet`, so aborting this task also closes every open snapshot stream.
pub async fn serve(listener: TcpListener, tls: Arc<ArcSwap<ServerConfig>>, app: Router) {
    let limit = Arc::new(Semaphore::new(MAX_NODE_CONNECTIONS));
    let mut connections = JoinSet::new();
    loop {
        while connections.try_join_next().is_some() {}
        let (tcp, peer_addr) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "node API accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            warn!(%peer_addr, "node API connection limit reached; dropping connection");
            continue;
        };
        let acceptor = TlsAcceptor::from(tls.load_full());
        let app = app.clone();
        connections.spawn(async move {
            let _permit = permit;
            let stream = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    debug!(%peer_addr, error = %e, "node API TLS handshake failed");
                    return;
                }
                Err(_) => {
                    debug!(%peer_addr, "node API TLS handshake timed out");
                    return;
                }
            };
            let node = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|chain| chain.first())
                .and_then(|leaf| node_id_from_cert(leaf.as_ref()));
            let service =
                app.map_request(move |mut req: axum::http::Request<hyper::body::Incoming>| {
                    req.extensions_mut().insert(NodePeer(node));
                    req
                });
            let result = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(10))
                .serve_connection(TokioIo::new(stream), TowerToHyperService::new(service))
                .await;
            if let Err(e) = result {
                debug!(%peer_addr, error = %e, "node API connection ended with an error");
            }
        });
    }
}

async fn require_node(control: &ControlPlane, peer: NodePeer) -> Result<Node, ApiError> {
    let id = peer.0.ok_or_else(|| ApiError::Unauthenticated {
        reason: "a node client certificate is required".into(),
    })?;
    Ok(control.nodes.authenticate(&id).await?)
}

async fn enroll(
    State(s): State<Arc<AppState>>,
    ApiJson(req): ApiJson<EnrollRequest>,
) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(s.control.nodes.enroll(req).await?))
}

async fn renew(
    State(s): State<Arc<AppState>>,
    Extension(peer): Extension<NodePeer>,
    ApiJson(req): ApiJson<RenewRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let node = require_node(&s.control, peer).await?;
    Ok(Json(s.control.nodes.renew(&node, req).await?))
}

#[derive(Serialize)]
struct Accepted {
    accepted: usize,
}

async fn ingest_audit(
    State(s): State<Arc<AppState>>,
    Extension(peer): Extension<NodePeer>,
    ApiJson(batch): ApiJson<AuditBatch>,
) -> Result<impl IntoResponse, ApiError> {
    let node = require_node(&s.control, peer).await?;
    let accepted = s.control.nodes.ingest_audit(&node, batch).await?;
    Ok(Json(Accepted { accepted }))
}

struct StreamState {
    control: Arc<ControlPlane>,
    node_id: NodeId,
    changes: tokio::sync::watch::Receiver<tokenless_control::notify::Generation>,
    refresh: Duration,
    first: bool,
    /// The newest snapshot format the node reads.
    reads_format: u32,
    /// Rules left out of the last snapshot sent, logged when it changes.
    withheld_rules: usize,
}

#[derive(Deserialize)]
struct StreamParams {
    /// Sent by nodes from the release that added snapshot format 2; older
    /// nodes send nothing and read format 1.
    #[serde(default = "first_format")]
    reads_format: u32,
}

fn first_format() -> u32 {
    MIN_SNAPSHOT_FORMAT
}

/// One signed snapshot per line (NDJSON). A new one is sent whenever policy
/// or sessions change, and at least every lease/3 so the lease never lapses
/// while the node is connected. The stream ends if the node is revoked.
async fn snapshot_stream(
    State(s): State<Arc<AppState>>,
    Extension(peer): Extension<NodePeer>,
    ApiQuery(params): ApiQuery<StreamParams>,
) -> Result<Response, ApiError> {
    let node = require_node(&s.control, peer).await?;
    let mut changes = s.control.nodes.subscribe();
    changes.borrow_and_update();
    let refresh = Duration::from_secs(u64::from((s.control.nodes.lease_secs() / 3).max(1)));
    info!(node_id = %node.id, reads_format = params.reads_format, "node opened snapshot stream");
    let state = StreamState {
        control: s.control.clone(),
        node_id: node.id,
        changes,
        refresh,
        first: true,
        reads_format: params.reads_format,
        withheld_rules: 0,
    };
    let stream = futures_util::stream::unfold(state, |mut st| async move {
        if !st.first {
            tokio::select! {
                changed = st.changes.changed() => {
                    if changed.is_err() {
                        return None;
                    }
                }
                _ = tokio::time::sleep(st.refresh) => {}
            }
        }
        st.first = false;
        let node = match st.control.nodes.authenticate(&st.node_id).await {
            Ok(n) => n,
            Err(e) => {
                warn!(node_id = %st.node_id, error = %e, "closing snapshot stream");
                return None;
            }
        };
        let snapshot = match st
            .control
            .nodes
            .build_snapshot_for(&node, st.reads_format)
            .await
        {
            Ok(built) => {
                if built.withheld_rules != st.withheld_rules {
                    if built.withheld_rules > 0 {
                        warn!(
                            node_id = %st.node_id,
                            reads_format = st.reads_format,
                            withheld_rules = built.withheld_rules,
                            "this proxy is too old for some services (a secret with an expiry needs a newer proxy); it will not use them until it is upgraded"
                        );
                    } else {
                        info!(node_id = %st.node_id, "this proxy now receives every rule");
                    }
                    st.withheld_rules = built.withheld_rules;
                }
                built.snapshot
            }
            Err(e) => {
                warn!(node_id = %st.node_id, error = %e, "snapshot build failed; closing stream so the node reconnects");
                return None;
            }
        };
        let mut line = match serde_json::to_vec(&snapshot) {
            Ok(l) => l,
            Err(e) => {
                warn!(node_id = %st.node_id, error = %e, "snapshot encoding failed");
                return None;
            }
        };
        line.push(b'\n');
        Some((Ok::<_, std::io::Error>(Bytes::from(line)), st))
    });
    let mut response = Body::from_stream(stream).into_response();
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-ndjson"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}
