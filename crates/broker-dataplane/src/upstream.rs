// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! One upstream connection per intercepted tunnel, owned by a small task so
//! the request path never shares a lock.

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

type Reply = oneshot::Sender<Result<Response<Incoming>, DataPlaneError>>;

#[derive(Clone)]
pub struct UpstreamHandle {
    tx: mpsc::Sender<(Request<Incoming>, Reply)>,
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

    pub async fn send(&self, req: Request<Incoming>) -> Result<Response<Incoming>, DataPlaneError> {
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

async fn connect(
    host: &str,
    port: u16,
    tls: Arc<ClientConfig>,
    connect_timeout: Duration,
) -> Result<SendRequest<Incoming>, DataPlaneError> {
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
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            debug!(upstream = %label, error = %e, "upstream connection closed");
        }
    });
    Ok(sender)
}

async fn run(
    mut rx: mpsc::Receiver<(Request<Incoming>, Reply)>,
    host: String,
    port: u16,
    tls: Arc<ClientConfig>,
    connect_timeout: Duration,
) {
    let mut sender: Option<SendRequest<Incoming>> = None;
    while let Some((req, reply)) = rx.recv().await {
        let mut current = match sender.take() {
            Some(s) if !s.is_closed() => s,
            _ => match connect(&host, port, tls.clone(), connect_timeout).await {
                Ok(s) => s,
                Err(e) => {
                    let _ = reply.send(Err(e));
                    continue;
                }
            },
        };
        let result = match current.ready().await {
            Ok(()) => current
                .send_request(req)
                .await
                .map_err(|e| DataPlaneError::Upstream {
                    host: host.clone(),
                    port,
                    reason: format!("request failed: {e}"),
                }),
            Err(e) => Err(DataPlaneError::Upstream {
                host: host.clone(),
                port,
                reason: format!("connection not ready: {e}"),
            }),
        };
        if !current.is_closed() {
            sender = Some(current);
        }
        let _ = reply.send(result);
    }
}
