// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Standalone credential broker server: the management API (and UI), the
//! node API, SQLite storage and the root key.

pub mod api;
pub mod api_tls;
pub mod error;
pub mod launcher;
pub mod node_api;
pub mod oidc_transport;
pub mod probe;
pub mod root_key;
pub mod store;
pub mod telemetry;
pub mod webhook_transport;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokenless_control::envelope::Envelope;
pub use tokenless_control::service::auth::GeneratedCredentials;
use tokenless_control::store::RbacAuthorizer;
use tokenless_control::{ControlConfig, ControlPlane, Stores};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::{info, warn};

pub use error::{ApiError, ServerError};
pub use root_key::RootKeyInput;
use store::SqliteStore;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Holds the SQLite database by default, and the root key when none is
    /// supplied.
    pub data_dir: PathBuf,
    /// The root key, kept outside the data directory. `None` reads or
    /// generates `<data_dir>/root.key`.
    pub root_key: Option<RootKeyInput>,
    /// Defaults to `sqlite://<data_dir>/broker.db`.
    pub database_url: Option<String>,
    pub api_listen: SocketAddr,
    pub node_listen: SocketAddr,
    /// DNS names / IPs placed in the node API certificate.
    pub node_api_names: Vec<String>,
    /// Built UI bundle (`broker-ui/dist`) to serve at `/`.
    pub ui_dir: Option<PathBuf>,
    /// Serve the management API over TLS with this certificate and key.
    pub api_tls: Option<api_tls::ApiTlsFiles>,
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
            root_key: None,
            database_url: None,
            api_listen: SocketAddr::from(([127, 0, 0, 1], 8080)),
            node_listen: SocketAddr::from(([127, 0, 0, 1], 8443)),
            node_api_names: vec!["localhost".into(), "127.0.0.1".into()],
            ui_dir: None,
            api_tls: None,
            validation_public_roots: true,
            validation_extra_roots: Vec::new(),
            control: ControlConfig::default(),
        }
    }
}

pub struct RunningServer {
    pub api_addr: SocketAddr,
    /// Whether the management API is served over TLS.
    pub api_tls: bool,
    pub node_addr: SocketAddr,
    /// The admin created on this start, with its generated password, for
    /// the binary to print once; `None` when an account already existed.
    pub initial_admin: Option<GeneratedCredentials>,
    /// Where the root key file sits when it is in the data directory, so a
    /// copy of the directory can decrypt everything; the binary warns.
    pub root_key_in_data_dir: Option<PathBuf>,
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

async fn bind(addr: SocketAddr, what: &str) -> Result<TcpListener, ServerError> {
    TcpListener::bind(addr)
        .await
        .map_err(|e| ServerError::io(format!("binding {what} listener {addr}"), e))
}

pub struct Server;

/// The control plane over the data directory's database, with secrets
/// under the root key, without serving anything.
struct Opened {
    control: Arc<ControlPlane>,
    root_key_in_data_dir: Option<PathBuf>,
}

async fn open_store(config: &ServerConfig) -> Result<Arc<SqliteStore>, ServerError> {
    ensure_private_dir(&config.data_dir)?;
    let url = config
        .database_url
        .clone()
        .unwrap_or_else(|| format!("sqlite://{}", config.data_dir.join("broker.db").display()));
    Ok(Arc::new(SqliteStore::connect(&url).await?))
}

async fn open_control(config: &ServerConfig) -> Result<Opened, ServerError> {
    let store = open_store(config).await?;
    let empty = Envelope::is_empty(store.as_ref()).await?;
    let root = root_key::resolve(config.root_key.as_ref(), &config.data_dir, empty)?;
    let cipher = Arc::new(Envelope::open(&root.key, store.clone()).await?);
    let stores = Stores {
        credentials: store.clone(),
        policy: store.clone(),
        audit: store.clone(),
        identity: store.clone(),
        sso: store.clone(),
        audit_export: store.clone(),
        nodes: store,
    };
    let control = Arc::new(
        ControlPlane::new(
            stores,
            Arc::new(RbacAuthorizer),
            cipher,
            Arc::new(probe::HttpProber::new(
                config.validation_public_roots,
                &config.validation_extra_roots,
            )?),
            Arc::new(oidc_transport::HttpOidcTransport::new(
                config.validation_public_roots,
                &config.validation_extra_roots,
            )?),
            Arc::new(webhook_transport::HttpWebhookTransport::new(
                config.validation_public_roots,
                &config.validation_extra_roots,
            )?),
            config.control.clone(),
        )
        .await?,
    );
    Ok(Opened {
        control,
        root_key_in_data_dir: root.in_data_dir,
    })
}

/// Replaces `username`'s password with a generated one and ends all of the
/// person's sessions. Run by the operator on the server's host, with the
/// same data directory (and database URL) as `serve`; the server may be
/// running.
pub async fn reset_password(
    config: &ServerConfig,
    username: &str,
) -> Result<GeneratedCredentials, ServerError> {
    let opened = open_control(config).await?;
    Ok(opened.control.auth.reset_password(username).await?)
}

/// Replaces the root key: writes a new one to `new_key_file` (which must
/// not exist) and re-wraps the instance key under it. No secret is
/// re-encrypted. Run on the server's host with the current root key in
/// `config`; restart the server with the new key afterwards.
pub async fn rotate_root_key(
    config: &ServerConfig,
    new_key_file: &Path,
) -> Result<(), ServerError> {
    let store = open_store(config).await?;
    let current = root_key::resolve(config.root_key.as_ref(), &config.data_dir, false)?;
    // Creates the hierarchy, or finishes moving secrets into it, under the
    // current key before it is replaced.
    Envelope::open(&current.key, store.clone()).await?;
    let new_key = tokenless_control::cipher::AesGcmCipher::generate_key();
    root_key::write_new(new_key_file, &new_key)?;
    if let Err(e) = Envelope::rotate_root(store.as_ref(), &current.key, &new_key).await {
        // The new key was never used; don't leave a file that looks valid.
        let _ = std::fs::remove_file(new_key_file);
        return Err(e.into());
    }
    info!(path = %new_key_file.display(), "root key replaced");
    Ok(())
}

impl Server {
    pub async fn start(config: ServerConfig) -> Result<RunningServer, ServerError> {
        let Opened {
            control,
            root_key_in_data_dir,
        } = open_control(&config).await?;
        if let Some(path) = &root_key_in_data_dir {
            warn!(
                path = %path.display(),
                "the root key is stored in the data directory, so a copy of the directory can decrypt every secret; move it elsewhere and start with --root-key-file or TOKENLESS_ROOT_KEY"
            );
        }
        let initial_admin = control.auth.create_initial_admin().await?;
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
        match &config.api_tls {
            Some(files) => {
                let reloader = api_tls::TlsReloader::new(files.clone())?;
                tasks.push(tokio::spawn(api_tls::serve(
                    api_listener,
                    reloader.config(),
                    app,
                )));
                tasks.push(tokio::spawn(reloader.watch()));
            }
            None => {
                if !api_addr.ip().is_loopback() {
                    warn!(%api_addr, "management API is plain HTTP on a non-loopback address; pass --api-tls-cert/--api-tls-key or put a TLS proxy in front (the session cookie is Secure, so browsers sign in over plain HTTP only at localhost or 127.0.0.1)");
                }
                tasks.push(tokio::spawn(async move {
                    if let Err(e) = axum::serve(api_listener, app).await {
                        tracing::error!(error = %e, "API server stopped");
                    }
                }));
            }
        }
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
        let export = control.clone();
        tasks.push(tokio::spawn(async move { export.audit_export.run().await }));
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
        let api_tls = config.api_tls.is_some();
        let console = match (&config.ui_dir, api::console_embedded()) {
            (Some(_), _) => "directory",
            (None, true) => "embedded",
            (None, false) => "none",
        };
        info!(%api_addr, api_tls, %node_addr, console, "credential broker server started");
        if console == "none" {
            tracing::warn!(
                "this binary was built without the console; serving the API only. Build broker-ui and pass --ui-dir broker-ui/dist"
            );
        }
        Ok(RunningServer {
            api_addr,
            api_tls,
            node_addr,
            initial_admin,
            root_key_in_data_dir,
            control,
            tasks,
        })
    }
}
