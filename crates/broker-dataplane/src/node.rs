// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Node identity and the node's client for the control plane's node API.

use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use broker_core::audit::AuditEvent;
use broker_core::ids::NodeId;
use broker_core::protocol::{
    AuditBatch, EnrollRequest, EnrollResponse, JoinToken, RenewRequest, RenewResponse,
};
use broker_core::seal::{encode_public_key, SealPublicKey, SealSecretKey};
use broker_core::snapshot::{decode_verifying_key, SignedSnapshot};
use bytes::{Bytes, BytesMut};
use chrono::{DateTime, Utc};
use http::header::{CONTENT_TYPE, HOST};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use crate::audit::AuditShipper;
use crate::error::DataPlaneError;
use crate::metrics::Metrics;
use crate::state::{build_active, NodeKeys, SnapshotHandle};
use crate::tls::{mtls_client_config, pinned_client_config, sha256_hex};

const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_SNAPSHOT_LINE: usize = 32 * 1024 * 1024;

/// Everything a node needs to talk to its control plane. Persisted with
/// mode 0600; credentials themselves are never written to disk.
#[derive(Clone, Serialize, Deserialize)]
pub struct NodeIdentity {
    pub control_url: String,
    pub node_id: NodeId,
    pub ca_cert_pem: String,
    pub client_cert_pem: String,
    pub client_key_pem: String,
    pub cert_issued_at: DateTime<Utc>,
    pub cert_not_after: DateTime<Utc>,
    /// X25519 private key, base64.
    pub seal_secret: String,
    /// Ed25519 snapshot verification key, base64.
    pub snapshot_verify_key: String,
}

impl fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeIdentity")
            .field("control_url", &self.control_url)
            .field("node_id", &self.node_id)
            .field("cert_not_after", &self.cert_not_after)
            .finish_non_exhaustive()
    }
}

impl NodeIdentity {
    pub fn keys(&self) -> Result<NodeKeys, DataPlaneError> {
        let secret: [u8; 32] =
            Zeroizing::new(STANDARD.decode(&self.seal_secret).map_err(|e| {
                DataPlaneError::identity(format!("seal secret is not base64: {e}"))
            })?)
            .as_slice()
            .try_into()
            .map_err(|_| DataPlaneError::identity("seal secret must be 32 bytes"))?;
        Ok(NodeKeys {
            node_id: self.node_id,
            seal_secret: SealSecretKey::from(secret),
            snapshot_key: decode_verifying_key(&self.snapshot_verify_key)?,
        })
    }

    pub fn load(path: &Path) -> Result<Self, DataPlaneError> {
        let data = std::fs::read(path).map_err(|e| {
            DataPlaneError::io(format!("reading node identity {}", path.display()), e)
        })?;
        serde_json::from_slice(&data).map_err(|e| {
            DataPlaneError::identity(format!(
                "{} is not a valid node identity: {e}",
                path.display()
            ))
        })
    }

    pub fn save(&self, path: &Path) -> Result<(), DataPlaneError> {
        let json = Zeroizing::new(
            serde_json::to_vec_pretty(self)
                .map_err(|e| DataPlaneError::identity(format!("encoding identity: {e}")))?,
        );
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| DataPlaneError::io(format!("creating {}", parent.display()), e))?;
        }
        let tmp = path.with_extension("tmp");
        {
            use std::io::Write;
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(&tmp)
                .map_err(|e| DataPlaneError::io(format!("writing {}", tmp.display()), e))?;
            file.write_all(&json)
                .map_err(|e| DataPlaneError::io(format!("writing {}", tmp.display()), e))?;
        }
        std::fs::rename(&tmp, path)
            .map_err(|e| DataPlaneError::io(format!("replacing {}", path.display()), e))
    }

    fn client_config(&self) -> Result<Arc<ClientConfig>, DataPlaneError> {
        mtls_client_config(
            &self.ca_cert_pem,
            &self.client_cert_pem,
            &self.client_key_pem,
        )
    }
}

/// `https://host:port` of the control plane's node API.
#[derive(Debug, Clone)]
pub struct ControlEndpoint {
    host: String,
    port: u16,
    server_name: ServerName<'static>,
}

impl ControlEndpoint {
    pub fn parse(url: &str) -> Result<Self, DataPlaneError> {
        let bad = |reason: &str| DataPlaneError::identity(format!("control URL '{url}' {reason}"));
        let rest = url
            .trim()
            .trim_end_matches('/')
            .strip_prefix("https://")
            .ok_or_else(|| bad("must start with https://"))?;
        let (host, port) = match rest.rsplit_once(':') {
            Some((h, p)) if !h.ends_with(']') || h.starts_with('[') => (
                h.trim_matches(|c| c == '[' || c == ']').to_string(),
                p.parse::<u16>().map_err(|_| bad("has an invalid port"))?,
            ),
            _ => (rest.to_string(), 443),
        };
        let server_name =
            ServerName::try_from(host.clone()).map_err(|_| bad("has an invalid host"))?;
        Ok(Self {
            host,
            port,
            server_name,
        })
    }

    fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

async fn send(
    endpoint: &ControlEndpoint,
    tls: Arc<ClientConfig>,
    method: Method,
    path: &str,
    body: Option<Vec<u8>>,
    connect_timeout: Duration,
) -> Result<Response<Incoming>, DataPlaneError> {
    let err = |reason: String| DataPlaneError::Control {
        method: method.to_string(),
        path: path.to_string(),
        reason,
    };
    let tcp = timeout(
        connect_timeout,
        TcpStream::connect((endpoint.host.as_str(), endpoint.port)),
    )
    .await
    .map_err(|_| err("connect timed out".into()))?
    .map_err(|e| err(format!("connect failed: {e}")))?;
    let stream = timeout(
        connect_timeout,
        TlsConnector::from(tls).connect(endpoint.server_name.clone(), tcp),
    )
    .await
    .map_err(|_| err("TLS handshake timed out".into()))?
    .map_err(|e| err(format!("TLS handshake failed: {e}")))?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| err(format!("HTTP handshake failed: {e}")))?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            debug!(error = %e, "node API connection closed");
        }
    });
    let request = Request::builder()
        .method(method.clone())
        .uri(path)
        .header(HOST, endpoint.authority())
        .header(CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body.unwrap_or_default())))
        .map_err(|e| err(format!("building request: {e}")))?;
    sender
        .send_request(request)
        .await
        .map_err(|e| err(format!("request failed: {e}")))
}

async fn read_json<T: DeserializeOwned>(
    method: &Method,
    path: &str,
    response: Response<Incoming>,
) -> Result<T, DataPlaneError> {
    let status = response.status();
    let bytes = Limited::new(response.into_body(), MAX_RESPONSE_BYTES)
        .collect()
        .await
        .map_err(|e| DataPlaneError::Control {
            method: method.to_string(),
            path: path.to_string(),
            reason: format!("reading body: {e}"),
        })?
        .to_bytes();
    if !status.is_success() {
        return Err(DataPlaneError::ControlStatus {
            method: method.to_string(),
            path: path.to_string(),
            status: status.as_u16(),
            body: String::from_utf8_lossy(&bytes).chars().take(500).collect(),
        });
    }
    serde_json::from_slice(&bytes).map_err(|e| DataPlaneError::Control {
        method: method.to_string(),
        path: path.to_string(),
        reason: format!("invalid JSON response: {e}"),
    })
}

fn new_csr() -> Result<(String, Zeroizing<String>), DataPlaneError> {
    let key = KeyPair::generate()
        .map_err(|e| DataPlaneError::identity(format!("generating TLS key: {e}")))?;
    let csr = CertificateParams::new(Vec::<String>::new())
        .and_then(|p| p.serialize_request(&key))
        .and_then(|c| c.pem())
        .map_err(|e| DataPlaneError::identity(format!("building CSR: {e}")))?;
    Ok((csr, Zeroizing::new(key.serialize_pem())))
}

/// Enrols a new node with a one-time join token. The node generates its own
/// TLS key and X25519 key; neither leaves the node.
pub async fn enroll(
    control_url: &str,
    join_token: &str,
    node_name: &str,
) -> Result<NodeIdentity, DataPlaneError> {
    let endpoint = ControlEndpoint::parse(control_url)?;
    let token = JoinToken::parse(join_token)?;
    let (csr_pem, key_pem) = new_csr()?;
    let seal_secret = SealSecretKey::random_from_rng(rand::rngs::OsRng);
    let request = EnrollRequest {
        join_token: join_token.trim().to_string(),
        node_name: node_name.to_string(),
        csr_pem,
        seal_public_key: encode_public_key(&SealPublicKey::from(&seal_secret)),
    };
    let body = serde_json::to_vec(&request)
        .map_err(|e| DataPlaneError::identity(format!("encoding enrolment: {e}")))?;
    let path = "/node/v1/enroll";
    let response = send(
        &endpoint,
        pinned_client_config(&token.ca_fingerprint)?,
        Method::POST,
        path,
        Some(body),
        Duration::from_secs(10),
    )
    .await?;
    let enrolled: EnrollResponse = read_json(&Method::POST, path, response).await?;
    let ca = crate::tls::certs_from_pem("node CA", &enrolled.ca_cert_pem)?;
    if !ca
        .iter()
        .any(|c| sha256_hex(c.as_ref()) == token.ca_fingerprint)
    {
        return Err(DataPlaneError::identity(
            "enrolment response CA does not match the join token fingerprint",
        ));
    }
    info!(node_id = %enrolled.node_id, "enrolled with control plane");
    Ok(NodeIdentity {
        control_url: control_url.trim_end_matches('/').to_string(),
        node_id: enrolled.node_id,
        ca_cert_pem: enrolled.ca_cert_pem,
        client_cert_pem: enrolled.client_cert_pem,
        client_key_pem: key_pem.to_string(),
        cert_issued_at: Utc::now(),
        cert_not_after: enrolled.cert_not_after,
        seal_secret: STANDARD.encode(seal_secret.to_bytes()),
        snapshot_verify_key: enrolled.snapshot_verify_key,
    })
}

/// mTLS client for an enrolled node. The client config is swapped when the
/// certificate is renewed.
pub struct NodeClient {
    endpoint: ControlEndpoint,
    identity: ArcSwap<NodeIdentity>,
    tls: ArcSwap<ClientConfig>,
    connect_timeout: Duration,
}

impl NodeClient {
    pub fn new(identity: NodeIdentity, connect_timeout: Duration) -> Result<Self, DataPlaneError> {
        let endpoint = ControlEndpoint::parse(&identity.control_url)?;
        let tls = identity.client_config()?;
        Ok(Self {
            endpoint,
            identity: ArcSwap::from_pointee(identity),
            tls: ArcSwap::new(tls),
            connect_timeout,
        })
    }

    pub fn identity(&self) -> Arc<NodeIdentity> {
        self.identity.load_full()
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<Response<Incoming>, DataPlaneError> {
        send(
            &self.endpoint,
            self.tls.load_full(),
            method,
            path,
            body,
            self.connect_timeout,
        )
        .await
    }

    /// Renews the client certificate with a freshly generated key.
    pub async fn renew(&self, state_path: Option<&Path>) -> Result<DateTime<Utc>, DataPlaneError> {
        let (csr_pem, key_pem) = new_csr()?;
        let body = serde_json::to_vec(&RenewRequest { csr_pem })
            .map_err(|e| DataPlaneError::identity(format!("encoding renewal: {e}")))?;
        let path = "/node/v1/renew";
        let response = self.call(Method::POST, path, Some(body)).await?;
        let renewed: RenewResponse = read_json(&Method::POST, path, response).await?;
        let mut identity = (*self.identity.load_full()).clone();
        identity.client_cert_pem = renewed.client_cert_pem;
        identity.client_key_pem = key_pem.to_string();
        identity.cert_issued_at = Utc::now();
        identity.cert_not_after = renewed.cert_not_after;
        let tls = identity.client_config()?;
        if let Some(path) = state_path {
            identity.save(path)?;
        }
        self.tls.store(tls);
        self.identity.store(Arc::new(identity));
        info!(not_after = %renewed.cert_not_after, "renewed node client certificate");
        Ok(renewed.cert_not_after)
    }

    /// Opens the snapshot stream and applies each snapshot until it ends.
    pub async fn stream_snapshots(
        &self,
        keys: &NodeKeys,
        handle: &SnapshotHandle,
        metrics: &Metrics,
        on_applied: &(dyn Fn() + Send + Sync),
    ) -> Result<(), DataPlaneError> {
        let path = "/node/v1/snapshots/stream";
        let response = self.call(Method::GET, path, None).await?;
        if response.status() != StatusCode::OK {
            let status = response.status().as_u16();
            let body = Limited::new(response.into_body(), 4096)
                .collect()
                .await
                .map(|b| String::from_utf8_lossy(&b.to_bytes()).to_string())
                .unwrap_or_default();
            return Err(DataPlaneError::ControlStatus {
                method: "GET".into(),
                path: path.into(),
                status,
                body,
            });
        }
        let mut body = response.into_body();
        let mut buffer = BytesMut::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|e| DataPlaneError::Control {
                method: "GET".into(),
                path: path.into(),
                reason: format!("stream interrupted: {e}"),
            })?;
            let Ok(data) = frame.into_data() else {
                continue;
            };
            buffer.extend_from_slice(&data);
            while let Some(pos) = buffer.iter().position(|b| *b == b'\n') {
                let line = buffer.split_to(pos + 1);
                let line = &line[..line.len() - 1];
                if line.is_empty() {
                    continue;
                }
                match serde_json::from_slice::<SignedSnapshot>(line) {
                    Ok(signed) => {
                        let previous = handle.load_full();
                        match build_active(&signed, keys, previous.as_deref(), Utc::now()) {
                            Ok(active) => {
                                debug!(
                                    version = active.version,
                                    rules = active.rules.len(),
                                    "applied snapshot"
                                );
                                handle.store(Some(Arc::new(active)));
                                Metrics::inc(&metrics.snapshots_applied_total);
                                on_applied();
                            }
                            Err(e) => {
                                Metrics::inc(&metrics.snapshots_rejected_total);
                                warn!(error = %e, "rejected snapshot");
                            }
                        }
                    }
                    Err(e) => {
                        Metrics::inc(&metrics.snapshots_rejected_total);
                        warn!(error = %e, "snapshot line is not valid JSON");
                    }
                }
            }
            if buffer.len() > MAX_SNAPSHOT_LINE {
                return Err(DataPlaneError::Control {
                    method: "GET".into(),
                    path: path.into(),
                    reason: format!("snapshot larger than {MAX_SNAPSHOT_LINE} bytes"),
                });
            }
        }
        Ok(())
    }
}

#[async_trait]
impl AuditShipper for NodeClient {
    async fn ship(&self, events: &[AuditEvent]) -> Result<(), DataPlaneError> {
        let path = "/node/v1/audit";
        let body = serde_json::to_vec(&AuditBatch {
            events: events.to_vec(),
        })
        .map_err(|e| DataPlaneError::Control {
            method: "POST".into(),
            path: path.into(),
            reason: format!("encoding audit batch: {e}"),
        })?;
        let response = self.call(Method::POST, path, Some(body)).await?;
        let _: serde_json::Value = read_json(&Method::POST, path, response).await?;
        Ok(())
    }
}

/// Keeps the snapshot stream open, reconnecting with exponential backoff.
pub async fn run_snapshot_loop(
    client: Arc<NodeClient>,
    keys: Arc<NodeKeys>,
    handle: SnapshotHandle,
    metrics: Arc<Metrics>,
) {
    let mut backoff = Duration::from_millis(500);
    loop {
        let applied = std::sync::atomic::AtomicBool::new(false);
        let mark = || applied.store(true, std::sync::atomic::Ordering::Relaxed);
        match client
            .stream_snapshots(&keys, &handle, &metrics, &mark)
            .await
        {
            Ok(()) => debug!("snapshot stream ended; reconnecting"),
            Err(e) => {
                warn!(error = %e, retry_in_ms = backoff.as_millis() as u64, "snapshot stream failed")
            }
        }
        if applied.load(std::sync::atomic::Ordering::Relaxed) {
            backoff = Duration::from_millis(500);
        }
        sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

/// Renews the client certificate once two thirds of its lifetime has passed.
pub async fn run_renewal_loop(client: Arc<NodeClient>, state_path: Option<std::path::PathBuf>) {
    loop {
        let identity = client.identity();
        let lifetime = identity.cert_not_after - identity.cert_issued_at;
        let renew_at = identity.cert_issued_at + lifetime * 2 / 3;
        let wait = (renew_at - Utc::now()).to_std().unwrap_or(Duration::ZERO);
        sleep(wait.min(Duration::from_secs(300))).await;
        if Utc::now() < renew_at {
            continue;
        }
        if let Err(e) = client.renew(state_path.as_deref()).await {
            warn!(error = %e, "certificate renewal failed; retrying in 30s");
            sleep(Duration::from_secs(30)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_control_urls() {
        let e = ControlEndpoint::parse("https://127.0.0.1:8443/").unwrap();
        assert_eq!(e.authority(), "127.0.0.1:8443");
        let e = ControlEndpoint::parse("https://broker.internal.example").unwrap();
        assert_eq!(e.authority(), "broker.internal.example:443");
        assert!(ControlEndpoint::parse("http://127.0.0.1:8443").is_err());
        assert!(ControlEndpoint::parse("https://host:notaport").is_err());
    }
}
