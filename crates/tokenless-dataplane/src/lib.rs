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
pub mod binding;
pub mod cut;
pub mod embedded;
pub mod error;
pub mod gateway;
pub mod metrics;
pub mod node;
pub mod proxy;
pub mod shutdown;
pub mod state;
pub mod status;
pub mod tls;
pub mod upstream;

#[cfg(test)]
pub(crate) mod testing;

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
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinHandle;
use tracing::{info, warn};

pub use binding::{Binding, BindingSpec};
pub use embedded::SnapshotInstaller;
pub use error::DataPlaneError;
pub use node::{enroll, NodeIdentity};
pub use shutdown::{Lifecycle, ShutdownReport};
pub use status::{
    BindingStatus, NotReady, SessionStatus, Status, UpstreamFailure, UpstreamFailureKind,
};

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
    snapshot_changed: watch::Sender<u64>,
    metrics: Arc<Metrics>,
    shared: Arc<ProxyShared>,
    status: watch::Receiver<Status>,
    /// The listeners: stopped first when shutting down.
    accepting: Vec<JoinHandle<()>>,
    /// Snapshots, renewal, audit and status: kept through the drain.
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
            dp.snapshot_changed.clone(),
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
        let installer = SnapshotInstaller::new(
            keys,
            dp.snapshot.clone(),
            dp.snapshot_changed.clone(),
            dp.metrics.clone(),
        );
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
        let (snapshot_changed, _) = watch::channel(0);
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
        let max_connections = config.max_connections.max(1);
        let shared = Arc::new(ProxyShared {
            node: node_id,
            connections: Arc::new(Semaphore::new(max_connections)),
            max_connections,
            gateway_connections: Arc::new(Semaphore::new(max_connections)),
            snapshot: snapshot.clone(),
            snapshot_changed: snapshot_changed.clone(),
            audit,
            metrics: metrics.clone(),
            upstream_tls: tls::upstream_client_config(
                config.use_public_roots,
                &config.extra_upstream_roots,
            )?,
            connect_timeout: config.connect_timeout,
            node_id: node_id.to_string(),
            bindings: std::sync::Mutex::new(Vec::new()),
            status_changed: watch::channel(0).0,
            lifecycle: watch::channel(Lifecycle::Running).0,
        });
        let (status_tx, status) = watch::channel(status::status(&shared));
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
            gateway_task = Some(tokio::spawn(gateway::serve(listener, shared.clone())));
        }
        let mut accepting = vec![tokio::spawn(proxy::serve(listener, shared.clone()))];
        accepting.extend(gateway_task);
        let tasks = vec![
            tokio::spawn(run_batcher(
                audit_rx,
                shipper,
                BatcherConfig {
                    max_batch: config.audit_batch_max,
                    flush_interval: config.audit_flush_interval,
                },
                metrics.clone(),
                shared.lifecycle.subscribe(),
            )),
            tokio::spawn(status::run_status_loop(shared.clone(), status_tx)),
        ];
        let mut metrics_addr = None;
        if let Some(addr) = config.metrics_listen {
            let listener = TcpListener::bind(addr)
                .await
                .map_err(|e| DataPlaneError::io(format!("binding metrics listener {addr}"), e))?;
            metrics_addr = listener.local_addr().ok();
            accepting.push(tokio::spawn(serve_metrics(listener, metrics.clone())));
        }
        info!(%local_addr, node_id = %node_id, "data plane proxy listening");
        Ok(Self {
            local_addr,
            metrics_addr,
            mcp_addr,
            snapshot,
            snapshot_changed,
            metrics,
            shared,
            status,
            accepting,
            tasks,
        })
    }

    /// Binds a workload to its sessions; see [`binding`]. Its connections
    /// are served with [`Binding::serve`] instead of through the listener,
    /// and count against `max_connections` like the listener's.
    pub fn bind(&self, spec: BindingSpec) -> Result<Binding, DataPlaneError> {
        Binding::new(spec, self.shared.clone())
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

    /// The snapshot in force, its lease and every binding's sessions and
    /// last upstream failure; see [`status`].
    pub fn status(&self) -> Status {
        status::status(&self.shared)
    }

    /// The latest [`Status`], updated when anything in it changes, so an
    /// embedder can follow it without polling. A `watch`: a slow reader
    /// skips to the newest status, nothing queues up.
    pub fn events(&self) -> watch::Receiver<Status> {
        self.status.clone()
    }

    /// Stops without losing what is in flight: nothing new is accepted,
    /// open traffic gets `drain` to finish, what is still open then is cut
    /// and the audit queue gets one last chance to ship. Reports what was
    /// cut and how many audit events never reached the control plane; see
    /// [`shutdown`].
    pub async fn shutdown(self, drain: Duration) -> ShutdownReport {
        for task in &self.accepting {
            task.abort();
        }
        let report = shutdown::drain(&self.shared, tokio::time::Instant::now() + drain).await;
        for task in self.tasks {
            task.abort();
        }
        report
    }

    /// Stops at once: open traffic is cut and queued audit events are
    /// lost. [`DataPlane::shutdown`] is the orderly way.
    pub fn abort(self) {
        self.shared.lifecycle.send_replace(Lifecycle::Closed);
        for task in self.accepting.into_iter().chain(self.tasks) {
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
