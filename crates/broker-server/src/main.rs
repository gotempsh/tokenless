// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `credential-broker` binary: `serve` runs the control plane, `node join`
//! enrols a data plane, `node run` runs it.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use broker_dataplane::node::{enroll, NodeIdentity};
use broker_dataplane::{DataPlane, DataPlaneConfig};
use broker_server::{Server, ServerConfig};
use clap::{Parser, Subcommand};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "credential-broker",
    version,
    about = "Credential broker for AI agents"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the control plane: management API, UI and node API.
    Serve(ServeArgs),
    /// Data plane node commands.
    Node {
        #[command(subcommand)]
        command: NodeCommand,
    },
}

#[derive(clap::Args)]
struct ServeArgs {
    /// Directory for the master key and SQLite database.
    #[arg(long, default_value = "./data")]
    data_dir: PathBuf,
    /// Database URL (default: sqlite://<data-dir>/broker.db).
    #[arg(long)]
    database_url: Option<String>,
    /// Management API / UI listener. Put a TLS-terminating proxy in front of
    /// it for anything other than loopback.
    #[arg(long, default_value = "127.0.0.1:8080")]
    api_listen: SocketAddr,
    /// Node API listener (TLS, mTLS for enrolled nodes).
    #[arg(long, default_value = "127.0.0.1:8443")]
    node_listen: SocketAddr,
    /// Name or IP to put in the node API certificate (repeatable).
    #[arg(long = "node-api-name", default_values_t = vec!["localhost".to_string(), "127.0.0.1".to_string()])]
    node_api_names: Vec<String>,
    /// Built UI directory to serve at `/`.
    #[arg(long)]
    ui_dir: Option<PathBuf>,
    /// Snapshot lease in seconds; nodes fail closed when it lapses.
    #[arg(long, default_value_t = 60)]
    lease_secs: u32,
}

#[derive(Subcommand)]
enum NodeCommand {
    /// Enrol this node with a one-time join token.
    Join {
        /// Node API URL, e.g. https://127.0.0.1:8443
        #[arg(long)]
        control_url: String,
        /// Join token (`cbj1....`) from the UI or API.
        #[arg(long)]
        token: String,
        #[arg(long, default_value = "node")]
        name: String,
        /// Where to store the node identity (mode 0600).
        #[arg(long, default_value = "./node.json")]
        state: PathBuf,
    },
    /// Run the forward proxy.
    Run {
        #[arg(long, default_value = "./node.json")]
        state: PathBuf,
        /// Proxy listener. Keep it on loopback or a private address.
        #[arg(long, default_value = "127.0.0.1:3128")]
        listen: SocketAddr,
        /// Prometheus metrics listener.
        #[arg(long)]
        metrics_listen: Option<SocketAddr>,
        /// Extra PEM file of CAs trusted for upstream TLS (repeatable).
        #[arg(long = "upstream-ca")]
        upstream_ca: Vec<PathBuf>,
        /// Do not trust the public web PKI roots for upstreams.
        #[arg(long)]
        no_public_roots: bool,
    },
}

fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_current_span(false)
        .init();
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error(transparent)]
    Server(#[from] broker_server::ServerError),
    #[error(transparent)]
    DataPlane(#[from] broker_dataplane::DataPlaneError),
    #[error("I/O failure while {context}: {source}")]
    Io {
        context: String,
        source: std::io::Error,
    },
}

async fn wait_for_shutdown() -> Result<(), CliError> {
    tokio::signal::ctrl_c().await.map_err(|e| CliError::Io {
        context: "waiting for Ctrl-C".into(),
        source: e,
    })
}

async fn serve(args: ServeArgs) -> Result<(), CliError> {
    let mut config = ServerConfig::new(args.data_dir);
    config.database_url = args.database_url;
    config.api_listen = args.api_listen;
    config.node_listen = args.node_listen;
    config.node_api_names = args.node_api_names;
    config.ui_dir = args.ui_dir;
    config.control.lease_secs = args.lease_secs.max(3);
    let running = Server::start(config).await?;
    if let Some(token) = &running.setup_token {
        // Deliberately printed to the terminal, not the structured log, so
        // it is not shipped to log aggregation. It is consumed on first use.
        eprintln!();
        eprintln!("  First-run setup token (single use):");
        eprintln!("    {token}");
        eprintln!(
            "  Open http://{}/ and create the first admin.",
            running.api_addr
        );
        eprintln!();
    }
    wait_for_shutdown().await?;
    info!("shutting down");
    running.shutdown();
    Ok(())
}

async fn node(command: NodeCommand) -> Result<(), CliError> {
    match command {
        NodeCommand::Join {
            control_url,
            token,
            name,
            state,
        } => {
            let identity = enroll(&control_url, &token, &name).await?;
            identity.save(&state)?;
            info!(node_id = %identity.node_id, state = %state.display(), "node enrolled");
            Ok(())
        }
        NodeCommand::Run {
            state,
            listen,
            metrics_listen,
            upstream_ca,
            no_public_roots,
        } => {
            let identity = NodeIdentity::load(&state)?;
            let mut extra = Vec::new();
            for path in upstream_ca {
                let pem = std::fs::read_to_string(&path).map_err(|e| CliError::Io {
                    context: format!("reading upstream CA {}", path.display()),
                    source: e,
                })?;
                extra.extend(broker_dataplane::tls::certs_from_pem(
                    &path.display().to_string(),
                    &pem,
                )?);
            }
            let config = DataPlaneConfig {
                listen,
                metrics_listen,
                use_public_roots: !no_public_roots,
                extra_upstream_roots: extra,
                state_path: Some(state),
                ..DataPlaneConfig::default()
            };
            let dp = DataPlane::start(config, identity).await?;
            wait_for_shutdown().await?;
            info!("shutting down");
            dp.shutdown();
            Ok(())
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    init_logging();
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Serve(args) => serve(args).await,
        Command::Node { command } => node(command).await,
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!(error = %e, "credential-broker exited with an error");
            ExitCode::FAILURE
        }
    }
}
