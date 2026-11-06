// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Optional built-in TLS for the management API and UI.
//!
//! The operator supplies a PEM certificate chain and private key, for
//! example from an ACME client. The files are checked once a minute and
//! reloaded when they change, so a renewed certificate is picked up
//! without a restart; a broken renewal keeps the current certificate.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwap;
use axum::Router;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::error::ServerError;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_API_CONNECTIONS: usize = 512;
const RELOAD_CHECK: Duration = Duration::from_secs(60);

/// Paths of the PEM certificate chain and private key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiTlsFiles {
    pub cert: PathBuf,
    pub key: PathBuf,
}

fn tls_err(reason: impl std::fmt::Display) -> ServerError {
    ServerError::Tls {
        listener: "management API".into(),
        reason: reason.to_string(),
    }
}

/// Size and modification time of both files; a change triggers a reload.
type Fingerprint = [(u64, Option<SystemTime>); 2];

fn fingerprint(files: &ApiTlsFiles) -> Option<Fingerprint> {
    let one = |path: &Path| {
        std::fs::metadata(path)
            .ok()
            .map(|m| (m.len(), m.modified().ok()))
    };
    Some([one(&files.cert)?, one(&files.key)?])
}

impl ApiTlsFiles {
    /// Reads both files and builds the rustls configuration.
    pub fn load(&self) -> Result<Arc<ServerConfig>, ServerError> {
        let read = |path: &Path, what: &str| {
            std::fs::read(path).map_err(|e| {
                ServerError::io(format!("reading API TLS {what} {}", path.display()), e)
            })
        };
        let cert_pem = read(&self.cert, "certificate")?;
        let key_pem = zeroize::Zeroizing::new(read(&self.key, "private key")?);
        let chain = CertificateDer::pem_slice_iter(&cert_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                tls_err(format!(
                    "certificate file {} is not valid PEM: {e}",
                    self.cert.display()
                ))
            })?;
        if chain.is_empty() {
            return Err(tls_err(format!(
                "certificate file {} contains no CERTIFICATE block",
                self.cert.display()
            )));
        }
        let key = PrivateKeyDer::from_pem_slice(&key_pem).map_err(|e| {
            tls_err(format!(
                "private key file {} holds no usable PKCS#8, PKCS#1 or SEC1 key: {e}",
                self.key.display()
            ))
        })?;
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(tls_err)?
                .with_no_client_auth()
                .with_single_cert(chain, key)
                .map_err(|e| {
                    tls_err(format!(
                        "certificate {} and key {} do not form a usable pair: {e}",
                        self.cert.display(),
                        self.key.display()
                    ))
                })?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }
}

/// Tracks the files and swaps in a new configuration when they change.
pub struct TlsReloader {
    files: ApiTlsFiles,
    seen: Option<Fingerprint>,
    current: Arc<ArcSwap<ServerConfig>>,
}

impl TlsReloader {
    pub fn new(files: ApiTlsFiles) -> Result<Self, ServerError> {
        let seen = fingerprint(&files);
        let current = Arc::new(ArcSwap::new(files.load()?));
        Ok(Self {
            files,
            seen,
            current,
        })
    }

    pub fn config(&self) -> Arc<ArcSwap<ServerConfig>> {
        self.current.clone()
    }

    /// Reloads if either file changed since the last look. Returns whether
    /// a new configuration is now being served.
    pub fn reload_if_changed(&mut self) -> bool {
        let now = fingerprint(&self.files);
        if now == self.seen {
            return false;
        }
        self.seen = now;
        match self.files.load() {
            Ok(config) => {
                self.current.store(config);
                info!(cert = %self.files.cert.display(), "reloaded management API certificate");
                true
            }
            Err(e) => {
                warn!(error = %e, "management API certificate changed but could not be loaded; keeping the current one");
                false
            }
        }
    }

    pub async fn watch(mut self) {
        loop {
            tokio::time::sleep(RELOAD_CHECK).await;
            self.reload_if_changed();
        }
    }
}

/// Serves `app` over TLS. Connections live in a `JoinSet`, so aborting
/// this task closes them too.
pub async fn serve(listener: TcpListener, tls: Arc<ArcSwap<ServerConfig>>, app: Router) {
    let limit = Arc::new(Semaphore::new(MAX_API_CONNECTIONS));
    let mut connections = JoinSet::new();
    loop {
        while connections.try_join_next().is_some() {}
        let (tcp, peer_addr) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "management API accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            warn!(%peer_addr, "management API connection limit reached; dropping connection");
            continue;
        };
        let acceptor = TlsAcceptor::from(tls.load_full());
        let app = app.clone();
        connections.spawn(async move {
            let _permit = permit;
            let stream = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    debug!(%peer_addr, error = %e, "management API TLS handshake failed");
                    return;
                }
                Err(_) => {
                    debug!(%peer_addr, "management API TLS handshake timed out");
                    return;
                }
            };
            let result = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(10))
                .serve_connection(TokioIo::new(stream), TowerToHyperService::new(app))
                .await;
            if let Err(e) = result {
                debug!(%peer_addr, error = %e, "management API connection ended with an error");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_pair(dir: &Path, name: &str) -> ApiTlsFiles {
        let cert = rcgen::generate_simple_self_signed(vec![name.to_string()]).unwrap();
        let files = ApiTlsFiles {
            cert: dir.join("api.crt"),
            key: dir.join("api.key"),
        };
        std::fs::write(&files.cert, cert.cert.pem()).unwrap();
        std::fs::write(&files.key, cert.signing_key.serialize_pem()).unwrap();
        files
    }

    #[test]
    fn loads_a_pem_pair_and_explains_bad_files() {
        let dir = tempfile::tempdir().unwrap();
        let files = write_pair(dir.path(), "localhost");
        assert!(files.load().is_ok());

        let missing = ApiTlsFiles {
            cert: dir.path().join("absent.crt"),
            key: files.key.clone(),
        };
        let err = missing.load().unwrap_err().to_string();
        assert!(err.contains("absent.crt"), "{err}");

        std::fs::write(dir.path().join("empty.crt"), "not a certificate").unwrap();
        let empty = ApiTlsFiles {
            cert: dir.path().join("empty.crt"),
            key: files.key.clone(),
        };
        let err = empty.load().unwrap_err().to_string();
        assert!(err.contains("no CERTIFICATE"), "{err}");

        // A key from another pair is refused.
        let other = tempfile::tempdir().unwrap();
        let other_files = write_pair(other.path(), "localhost");
        let mismatched = ApiTlsFiles {
            cert: files.cert.clone(),
            key: other_files.key,
        };
        let err = mismatched.load().unwrap_err().to_string();
        assert!(err.contains("usable pair"), "{err}");
    }

    #[test]
    fn reloads_only_when_the_files_change_and_keeps_serving_on_failure() {
        let dir = tempfile::tempdir().unwrap();
        let files = write_pair(dir.path(), "localhost");
        let mut reloader = TlsReloader::new(files.clone()).unwrap();
        let first = reloader.config().load_full();
        assert!(
            !reloader.reload_if_changed(),
            "unchanged files must not reload"
        );

        write_pair(dir.path(), "a-renewed-name.example");
        assert!(reloader.reload_if_changed());
        assert!(!Arc::ptr_eq(&first, &reloader.config().load_full()));

        let before = reloader.config().load_full();
        std::fs::write(&files.key, "broken renewal").unwrap();
        assert!(!reloader.reload_if_changed());
        assert!(Arc::ptr_eq(&before, &reloader.config().load_full()));
    }
}
