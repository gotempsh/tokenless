// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! One upstream connection per intercepted tunnel, owned by a small task so
//! the request path never shares a lock. The connection goes when the
//! tunnel does: nothing keeps forwarding to the upstream after its tunnel
//! was cut.

use std::sync::Arc;
use std::time::Duration;

use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::debug;

use crate::error::DataPlaneError;
use crate::proxy::ProxyBody;

type Reply = oneshot::Sender<Result<Response<Incoming>, DataPlaneError>>;

#[derive(Clone)]
pub struct UpstreamHandle {
    tx: mpsc::Sender<(Request<ProxyBody>, Reply)>,
    host: String,
    port: u16,
}

impl UpstreamHandle {
    pub fn spawn(
        host: String,
        port: u16,
        tls: Arc<ClientConfig>,
        connect_timeout: Duration,
    ) -> Self {
        let (tx, rx) = mpsc::channel(1);
        tokio::spawn(run(rx, host.clone(), port, tls, connect_timeout));
        Self { tx, host, port }
    }

    pub async fn send(
        &self,
        req: Request<ProxyBody>,
    ) -> Result<Response<Incoming>, DataPlaneError> {
        let closed = || DataPlaneError::Upstream {
            host: self.host.clone(),
            port: self.port,
            reason: "upstream task stopped".into(),
        };
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx.send((req, reply_tx)).await.map_err(|_| closed())?;
        reply_rx.await.map_err(|_| closed())?
    }
}

/// Aborts the connection's task when dropped, unless detached.
struct Connection {
    sender: SendRequest<ProxyBody>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Connection {
    /// Lets a connection that takes no more requests finish the response
    /// it is streaming on its own; it ends when the tunnel drops the body.
    fn detach(mut self) {
        self.task = None;
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

async fn connect(
    host: &str,
    port: u16,
    tls: Arc<ClientConfig>,
    connect_timeout: Duration,
) -> Result<Connection, DataPlaneError> {
    let err = |reason: String| DataPlaneError::Upstream {
        host: host.to_string(),
        port,
        reason,
    };
    let tcp = timeout(connect_timeout, TcpStream::connect((host, port)))
        .await
        .map_err(|_| {
            err(format!(
                "TCP connect timed out after {}s",
                connect_timeout.as_secs()
            ))
        })?
        .map_err(|e| err(format!("TCP connect failed: {e}")))?;
    let _ = tcp.set_nodelay(true);
    let name = ServerName::try_from(host.to_string())
        .map_err(|e| err(format!("invalid server name: {e}")))?;
    let stream = timeout(connect_timeout, TlsConnector::from(tls).connect(name, tcp))
        .await
        .map_err(|_| err("TLS handshake timed out".into()))?
        .map_err(|e| err(format!("TLS handshake failed: {e}")))?;
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| err(format!("HTTP handshake failed: {e}")))?;
    let label = format!("{host}:{port}");
    let task = tokio::spawn(async move {
        if let Err(e) = conn.await {
            debug!(upstream = %label, error = %e, "upstream connection closed");
        }
    });
    Ok(Connection {
        sender,
        task: Some(task),
    })
}

async fn run(
    mut rx: mpsc::Receiver<(Request<ProxyBody>, Reply)>,
    host: String,
    port: u16,
    tls: Arc<ClientConfig>,
    connect_timeout: Duration,
) {
    let mut open: Option<Connection> = None;
    while let Some((req, reply)) = rx.recv().await {
        let mut current = match open.take() {
            Some(c) if !c.sender.is_closed() => c,
            _ => match connect(&host, port, tls.clone(), connect_timeout).await {
                Ok(c) => c,
                Err(e) => {
                    let _ = reply.send(Err(e));
                    continue;
                }
            },
        };
        let result = match current.sender.ready().await {
            Ok(()) => {
                current
                    .sender
                    .send_request(req)
                    .await
                    .map_err(|e| DataPlaneError::Upstream {
                        host: host.clone(),
                        port,
                        reason: format!("request failed: {e}"),
                    })
            }
            Err(e) => Err(DataPlaneError::Upstream {
                host: host.clone(),
                port,
                reason: format!("connection not ready: {e}"),
            }),
        };
        // A response still streaming keeps its connection busy, so the next
        // request opens another; this one closes when its body is done.
        if !current.sender.is_closed() {
            open = Some(current);
        } else {
            current.detach();
        }
        let _ = reply.send(result);
    }
}
