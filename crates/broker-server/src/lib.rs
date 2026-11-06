// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Standalone credential broker server: the management API (and UI), the
//! node API, SQLite storage and the master key file.

pub mod api;
pub mod error;
pub mod node_api;
pub mod probe;
pub mod store;

use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use broker_control::cipher::AesGcmCipher;
use broker_control::store::RbacAuthorizer;
use broker_control::{ControlConfig, ControlPlane, Stores};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::{info, warn};
use zeroize::Zeroizing;

pub use error::{ApiError, ServerError};
use store::SqliteStore;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Holds `master.key` and, by default, the SQLite database.
    pub data_dir: PathBuf,
    /// Defaults to `sqlite://<data_dir>/broker.db`.
    pub database_url: Option<String>,
    pub api_listen: SocketAddr,
    pub node_listen: SocketAddr,
    /// DNS names / IPs placed in the node API certificate.
    pub node_api_names: Vec<String>,
    /// Built UI bundle (`broker-ui/dist`) to serve at `/`.
    pub ui_dir: Option<PathBuf>,
    /// Trust the public web PKI for credential validation requests.
    pub validation_public_roots: bool,
    /// Extra CAs trusted for validation requests (self-hosted services).
    pub validation_extra_roots: Vec<rustls::pki_types::CertificateDer<'static>>,
    pub control: ControlConfig,
}

impl ServerConfig {
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: data_dir.into(),
            database_url: None,
            api_listen: SocketAddr::from(([127, 0, 0, 1], 8080)),
            node_listen: SocketAddr::from(([127, 0, 0, 1], 8443)),
            node_api_names: vec!["localhost".into(), "127.0.0.1".into()],
            ui_dir: None,
            validation_public_roots: true,
            validation_extra_roots: Vec::new(),
            control: ControlConfig::default(),
        }
    }
}

pub struct RunningServer {
    pub api_addr: SocketAddr,
    pub node_addr: SocketAddr,
    /// Printed once by the binary; `None` once an admin exists.
    pub setup_token: Option<String>,
    pub control: Arc<ControlPlane>,
    tasks: Vec<JoinHandle<()>>,
}

impl RunningServer {
    pub fn shutdown(self) {
        for task in self.tasks {
            task.abort();
        }
    }
}

const MASTER_KEY_FILE: &str = "master.key";
const UI_SESSION_PURGE: Duration = Duration::from_secs(600);

fn ensure_private_dir(dir: &Path) -> Result<(), ServerError> {
    std::fs::create_dir_all(dir)
        .map_err(|e| ServerError::io(format!("creating data dir {}", dir.display()), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| ServerError::io(format!("restricting data dir {}", dir.display()), e))?;
    }
    Ok(())
}

/// Loads the 32-byte master key, creating it (mode 0600) on first start.
/// Everything sensitive in the database is encrypted under this key.
pub fn load_or_create_master_key(path: &Path) -> Result<Zeroizing<[u8; 32]>, ServerError> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let bytes = Zeroizing::new(bytes);
            let key: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| ServerError::Config {
                    reason: format!(
                        "master key {} must be exactly 32 bytes, found {}",
                        path.display(),
                        bytes.len()
                    ),
                })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = std::fs::metadata(path) {
                    if meta.permissions().mode() & 0o077 != 0 {
                        warn!(path = %path.display(), "master key is readable by group or others; run chmod 600");
                    }
                }
            }
            Ok(Zeroizing::new(key))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key = AesGcmCipher::generate_key();
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(path).map_err(|e| {
                ServerError::io(format!("creating master key {}", path.display()), e)
            })?;
            file.write_all(key.as_ref())
                .and_then(|_| file.sync_all())
                .map_err(|e| {
                    ServerError::io(format!("writing master key {}", path.display()), e)
                })?;
            info!(path = %path.display(), "generated new master key");
            Ok(key)
        }
        Err(e) => Err(ServerError::io(
            format!("reading master key {}", path.display()),
            e,
        )),
    }
}

async fn bind(addr: SocketAddr, what: &str) -> Result<TcpListener, ServerError> {
    TcpListener::bind(addr)
        .await
        .map_err(|e| ServerError::io(format!("binding {what} listener {addr}"), e))
}

pub struct Server;

impl Server {
    pub async fn start(config: ServerConfig) -> Result<RunningServer, ServerError> {
        ensure_private_dir(&config.data_dir)?;
        let key = load_or_create_master_key(&config.data_dir.join(MASTER_KEY_FILE))?;
        let url = config
            .database_url
            .clone()
            .unwrap_or_else(|| format!("sqlite://{}", config.data_dir.join("broker.db").display()));
        let store = Arc::new(SqliteStore::connect(&url).await?);
        let stores = Stores {
            credentials: store.clone(),
            policy: store.clone(),
            audit: store.clone(),
            identity: store.clone(),
            nodes: store,
        };
        let cipher = Arc::new(AesGcmCipher::new(&key)?);
        drop(key);
        let control = Arc::new(
            ControlPlane::new(
                stores,
                Arc::new(RbacAuthorizer),
                cipher,
                Arc::new(probe::HttpProber::new(
                    config.validation_public_roots,
                    &config.validation_extra_roots,
                )?),
                config.control.clone(),
            )
            .await?,
        );
        let setup_token = control.auth.issue_setup_token().await?;
        let state = Arc::new(api::AppState {
            control: control.clone(),
        });

        let api_listener = bind(config.api_listen, "API").await?;
        let api_addr = api_listener
            .local_addr()
            .map_err(|e| ServerError::io("reading API listener address", e))?;
        let node_listener = bind(config.node_listen, "node API").await?;
        let node_addr = node_listener
            .local_addr()
            .map_err(|e| ServerError::io("reading node API listener address", e))?;
        let tls = Arc::new(ArcSwap::new(node_api::node_tls_config(
            &control,
            &config.node_api_names,
        )?));

        let app = api::router(state.clone(), config.ui_dir.clone());
        let mut tasks = Vec::new();
        tasks.push(tokio::spawn(async move {
            if let Err(e) = axum::serve(api_listener, app).await {
                tracing::error!(error = %e, "API server stopped");
            }
        }));
        tasks.push(tokio::spawn(node_api::serve(
            node_listener,
            tls.clone(),
            node_api::router(state),
        )));
        tasks.push(tokio::spawn(node_api::rotate_server_cert(
            control.clone(),
            config.node_api_names.clone(),
            tls,
        )));
        let purge = control.clone();
        tasks.push(tokio::spawn(async move {
            loop {
                tokio::time::sleep(UI_SESSION_PURGE).await;
                match purge.auth.purge_expired_sessions().await {
                    Ok(n) if n > 0 => info!(purged = n, "purged expired UI sessions"),
                    Ok(_) => {}
                    Err(e) => warn!(error = %e, "UI session purge failed"),
                }
            }
        }));
        info!(%api_addr, %node_addr, "credential broker server started");
        Ok(RunningServer {
            api_addr,
            node_addr,
            setup_token,
            control,
            tasks,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_key_is_created_once_and_reused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(MASTER_KEY_FILE);
        let first = load_or_create_master_key(&path).unwrap();
        let second = load_or_create_master_key(&path).unwrap();
        assert_eq!(*first, *second);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn short_master_key_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(MASTER_KEY_FILE);
        std::fs::write(&path, b"short").unwrap();
        let err = load_or_create_master_key(&path).unwrap_err();
        assert!(err.to_string().contains("32 bytes"));
    }
}
