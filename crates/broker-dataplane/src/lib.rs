// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Data plane: a forward proxy that injects credentials into requests to
//! hosts covered by a session's rules, and touches nothing else.
//!
//! The data plane is identical in every deployment mode. It knows only its
//! node identity, the signed snapshots it receives and the session tokens
//! clients present.
//!
//! [`DataPlane::start`] runs it as a node: snapshots stream from the control
//! plane's node API and audit batches go back to it. [`DataPlane::start_embedded`]
//! runs it inside another process, which hands it signed snapshots through a
//! [`SnapshotInstaller`] and receives its audit batches through an
//! [`AuditShipper`](audit::AuditShipper). Verification is the same either way.

pub mod audit;
pub mod embedded;
pub mod error;
pub mod gateway;
pub mod metrics;
pub mod node;
pub mod proxy;
pub mod state;
pub mod tls;
pub mod upstream;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwapOption;
use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::Response;
use hyper_util::rt::TokioIo;
use rustls::pki_types::CertificateDer;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::{info, warn};

pub use embedded::SnapshotInstaller;
pub use error::DataPlaneError;
pub use node::{enroll, NodeIdentity};

use crate::audit::{run_batcher, AuditPipeline, AuditShipper, BatcherConfig};
use crate::metrics::Metrics;
use crate::node::{run_renewal_loop, run_snapshot_loop, NodeClient};
use crate::proxy::ProxyShared;
use crate::state::{NodeKeys, SnapshotHandle};

#[derive(Debug, Clone)]
pub struct DataPlaneConfig {
    /// Proxy listener. Defaults to loopback: expose it only on a private address.
    pub listen: SocketAddr,
    pub metrics_listen: Option<SocketAddr>,
    /// MCP gateway listener (plain HTTP, session token in `Authorization`).
    /// Off by default here; `node run` turns it on at 127.0.0.1:3129.
    pub mcp_listen: Option<SocketAddr>,
    /// Trust the Mozilla root set for upstream TLS.
    pub use_public_roots: bool,
    /// Extra upstream roots (e.g. an internal CA for a self-hosted service).
    pub extra_upstream_roots: Vec<CertificateDer<'static>>,
    pub audit_capacity: usize,
    pub audit_batch_max: usize,
    pub audit_flush_interval: Duration,
    pub connect_timeout: Duration,
    pub max_connections: usize,
    /// Where the node identity is persisted after certificate renewal.
    /// Unused when embedded: the host owns the node's keys.
    pub state_path: Option<PathBuf>,
}

impl Default for DataPlaneConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 3128)),
            metrics_listen: None,
            mcp_listen: None,
            use_public_roots: true,
            extra_upstream_roots: Vec::new(),
            audit_capacity: 4096,
            audit_batch_max: 256,
            audit_flush_interval: Duration::from_millis(500),
            connect_timeout: Duration::from_secs(10),
            max_connections: 4096,
            state_path: None,
        }
    }
}

pub struct DataPlane {
    local_addr: SocketAddr,
    metrics_addr: Option<SocketAddr>,
    mcp_addr: Option<SocketAddr>,
    snapshot: SnapshotHandle,
    metrics: Arc<Metrics>,
    tasks: Vec<JoinHandle<()>>,
}

impl DataPlane {
    /// Runs the data plane as a node of a control plane: snapshots stream
    /// from its node API, audit batches go back to it and the client
    /// certificate is renewed before it expires.
    pub async fn start(
        config: DataPlaneConfig,
        identity: NodeIdentity,
    ) -> Result<Self, DataPlaneError> {
        let keys = Arc::new(identity.keys()?);
        let client = Arc::new(NodeClient::new(identity, config.connect_timeout)?);
        let state_path = config.state_path.clone();
        let mut dp = Self::launch(config, keys.clone(), client.clone()).await?;
        dp.tasks.push(tokio::spawn(run_snapshot_loop(
            client.clone(),
            keys,
            dp.snapshot.clone(),
            dp.metrics.clone(),
        )));
        dp.tasks
            .push(tokio::spawn(run_renewal_loop(client, state_path)));
        Ok(dp)
    }

    /// Runs the data plane inside another process. Nothing is fetched: the
    /// host installs each signed snapshot through the returned
    /// [`SnapshotInstaller`], which verifies it exactly as a node does
    /// (signature, node id, version floor, lease), and audit batches go to
    /// `audit`. Until a snapshot is installed, and once its lease runs out,
    /// every request is refused.
    pub async fn start_embedded(
        config: DataPlaneConfig,
        keys: NodeKeys,
        audit: Arc<dyn AuditShipper>,
    ) -> Result<(Self, SnapshotInstaller), DataPlaneError> {
        let keys = Arc::new(keys);
        let dp = Self::launch(config, keys.clone(), audit).await?;
        let installer = SnapshotInstaller::new(keys, dp.snapshot.clone(), dp.metrics.clone());
        Ok((dp, installer))
    }

    /// The listeners, the proxy, the audit batcher and the optional gateway
    /// and metrics endpoints: everything but where snapshots come from.
    async fn launch(
        config: DataPlaneConfig,
        keys: Arc<NodeKeys>,
        shipper: Arc<dyn AuditShipper>,
    ) -> Result<Self, DataPlaneError> {
        let node_id = keys.node_id;
        let metrics = Arc::new(Metrics::default());
        let snapshot: SnapshotHandle = Arc::new(ArcSwapOption::empty());
        let (audit, audit_rx) = AuditPipeline::new(config.audit_capacity, metrics.clone());
        let listener = TcpListener::bind(config.listen).await.map_err(|e| {
            DataPlaneError::io(format!("binding proxy listener {}", config.listen), e)
        })?;
        let local_addr = listener
            .local_addr()
            .map_err(|e| DataPlaneError::io("reading proxy listener address", e))?;
        if !local_addr.ip().is_loopback() {
            warn!(%local_addr, "proxy listener is not on loopback; make sure it is only reachable on a private network");
        }
        let shared = Arc::new(ProxyShared {
            snapshot: snapshot.clone(),
            audit,
            metrics: metrics.clone(),
            upstream_tls: tls::upstream_client_config(
                config.use_public_roots,
                &config.extra_upstream_roots,
            )?,
            connect_timeout: config.connect_timeout,
            node_id: node_id.to_string(),
        });
        let mut mcp_addr = None;
        let mut gateway_task = None;
        if let Some(addr) = config.mcp_listen {
            let listener = TcpListener::bind(addr).await.map_err(|e| {
                DataPlaneError::io(format!("binding MCP gateway listener {addr}"), e)
            })?;
            let bound = listener
                .local_addr()
                .map_err(|e| DataPlaneError::io("reading MCP gateway listener address", e))?;
            if !bound.ip().is_loopback() {
                warn!(%bound, "MCP gateway listener is not on loopback; session tokens reach it over plain HTTP, so make sure it is only reachable on a private network");
            }
            info!(%bound, "MCP gateway listening");
            mcp_addr = Some(bound);
            gateway_task = Some(tokio::spawn(gateway::serve(
                listener,
                shared.clone(),
                config.max_connections,
            )));
        }
        let mut tasks = vec![
            tokio::spawn(proxy::serve(listener, shared, config.max_connections)),
            tokio::spawn(run_batcher(
                audit_rx,
                shipper,
                BatcherConfig {
                    max_batch: config.audit_batch_max,
                    flush_interval: config.audit_flush_interval,
                },
                metrics.clone(),
            )),
        ];
        tasks.extend(gateway_task);
        let mut metrics_addr = None;
        if let Some(addr) = config.metrics_listen {
            let listener = TcpListener::bind(addr)
                .await
                .map_err(|e| DataPlaneError::io(format!("binding metrics listener {addr}"), e))?;
            metrics_addr = listener.local_addr().ok();
            tasks.push(tokio::spawn(serve_metrics(listener, metrics.clone())));
        }
        info!(%local_addr, node_id = %node_id, "data plane proxy listening");
        Ok(Self {
            local_addr,
            metrics_addr,
            mcp_addr,
            snapshot,
            metrics,
            tasks,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn metrics_addr(&self) -> Option<SocketAddr> {
        self.metrics_addr
    }

    /// Where the MCP gateway listens, when it is on.
    pub fn mcp_addr(&self) -> Option<SocketAddr> {
        self.mcp_addr
    }

    /// Version of the snapshot currently in force, if any.
    pub fn snapshot_version(&self) -> Option<u64> {
        self.snapshot.load().as_ref().map(|s| s.version)
    }

    pub fn lease_valid(&self) -> bool {
        self.snapshot
            .load()
            .as_ref()
            .is_some_and(|s| s.lease_valid())
    }

    pub fn metrics(&self) -> Arc<Metrics> {
        self.metrics.clone()
    }

    pub fn shutdown(self) {
        for task in self.tasks {
            task.abort();
        }
    }
}

async fn serve_metrics(listener: TcpListener, metrics: Arc<Metrics>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let metrics = metrics.clone();
        tokio::spawn(async move {
            let service = service_fn(move |_req| {
                let text = metrics.render();
                async move { Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(text)))) }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}
