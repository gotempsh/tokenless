// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `tokenless` binary: `serve` runs the control plane, `node join`
//! enrols a data plane, `node run` runs it, and `session` / `run` put an
//! agent behind it with a session minted from an access bundle.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use broker_dataplane::node::{enroll, NodeIdentity};
use broker_dataplane::{DataPlane, DataPlaneConfig};
use broker_server::launcher::account::{
    self, AddService, ConsoleClient, Prompter, SessionStore, SessionVault, SignIn, Stored,
};
use broker_server::launcher::client::{ApiClient, Credentials, MintRequest, PortServices};
use broker_server::launcher::inject::{self, Assignment};
use broker_server::launcher::port::{check_listen, check_proxy, SessionPort};
use broker_server::launcher::session::LiveSession;
use broker_server::launcher::skill;
use broker_server::launcher::trust::{
    agent_env, fingerprint, fingerprints_match, placeholder_env, shell_quote, write_trust_files,
    TrustFiles,
};
use broker_server::launcher::{parse_duration_secs, parse_label, LauncherError};
use broker_server::{RootKeyInput, Server, ServerConfig};
use clap::{Parser, Subcommand};
use messages::{detail, say};
use serde::Serialize;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

mod messages;

#[derive(Parser)]
#[command(name = "tokenless", version, about = "Credential broker for AI agents")]
struct Cli {
    /// Also say what tokenless itself does (sessions, ports, proxy) on
    /// standard error. Without it `run`, `session` and `mcp` print nothing of
    /// their own when they succeed, so their output is only the command's.
    #[arg(short, long, global = true)]
    verbose: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the control plane: management API, UI and node API.
    Serve(ServeArgs),
    /// Sign in as a person and keep the session in the OS keychain, for
    /// the commands that set up the broker (`service add`, `proxy add`).
    ///
    /// Example:
    ///   tokenless login --username admin
    #[command(verbatim_doc_comment)]
    Login {
        /// Management API URL.
        #[arg(long, env = "TOKENLESS_URL", default_value = "http://127.0.0.1:8080")]
        server: String,
        #[arg(long, default_value = "admin")]
        username: String,
    },
    /// Sign out and remove the session from the OS keychain.
    Logout {
        /// Management API URL.
        #[arg(long, env = "TOKENLESS_URL", default_value = "http://127.0.0.1:8080")]
        server: String,
    },
    /// Services agents can use. Needs `tokenless login`.
    Service {
        #[command(subcommand)]
        command: ServiceCommand,
    },
    /// Proxies that inject credentials. Needs `tokenless login`.
    Proxy {
        #[command(subcommand)]
        command: ProxyCommand,
    },
    /// Server administration, run on the server's host with its data
    /// directory.
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
    /// Data plane node commands.
    Node {
        #[command(subcommand)]
        command: NodeCommand,
    },
    /// Proxy sessions for agents: mint one, end one, or open a session port.
    Session {
        #[command(subcommand)]
        command: SessionCommand,
    },
    /// Run a command behind a session port. Uses the session whose token is
    /// in TOKENLESS_SESSION_TOKEN (create one on the bundle's page), or mints
    /// one from --bundle, renews it while the command runs and ends it when
    /// it exits. Points the command at the proxy with the broker CA trusted.
    ///
    /// Variables can be filled by reference, as `NAME=cb://<service>/<field>`
    /// arguments or lines of an `--env-file`: each becomes the placeholder
    /// the proxy swaps for that secret, never the secret itself. Other
    /// values are passed through as written.
    ///
    /// Examples:
    ///   TOKENLESS_SESSION_TOKEN=v4.public... tokenless run -- claude
    ///   tokenless run --bundle code-review -- claude
    ///   tokenless exec --bundle deploy GITHUB_TOKEN=cb://github/token -- ./release.sh
    #[command(visible_alias = "exec", verbatim_doc_comment)]
    Run(RunArgs),
    /// Connect an MCP client (Claude Code, Cursor, ...) to the MCP servers
    /// of an access bundle. Mints a long-lived session and prints, for each
    /// MCP service, the gateway URL with the session token as its bearer
    /// token. The client never sees the service's credential; end the
    /// session on the Sessions page to cut it off.
    ///
    /// Examples:
    ///   tokenless mcp --bundle code-review
    ///   tokenless mcp --bundle code-review --format json
    #[command(verbatim_doc_comment)]
    Mcp(McpArgs),
    /// Print the agent skill, or install it where Claude Code finds skills.
    /// It tells an agent behind the broker how to see what it can reach,
    /// use placeholders and read the proxy's errors.
    Skill {
        /// Write it to <dir>/tokenless/SKILL.md.
        #[arg(long)]
        install: bool,
        /// Skills directory (default: ~/.claude/skills; use .claude/skills
        /// for one project).
        #[arg(long, requires = "install")]
        dir: Option<PathBuf>,
        /// Replace an installed copy that differs from this version.
        #[arg(long, requires = "install")]
        force: bool,
    },
}

#[derive(clap::Args)]
struct BrokerArgs {
    /// Management API URL.
    #[arg(long, env = "TOKENLESS_URL", default_value = "http://127.0.0.1:8080")]
    server: String,
    /// File holding the API key (`cbk_...`). Without it the key is read
    /// from TOKENLESS_API_KEY, or the `tokenless login` session is used.
    #[arg(long)]
    api_key_file: Option<PathBuf>,
}

#[derive(clap::Args)]
struct MintArgs {
    #[command(flatten)]
    broker: BrokerArgs,
    /// Vault name or id. Not needed with a vault-bound API key.
    #[arg(long, env = "TOKENLESS_VAULT")]
    vault: Option<String>,
    /// Access bundle to mint the session from, by name or id.
    #[arg(long, env = "TOKENLESS_BUNDLE")]
    bundle: Option<String>,
    /// Lifetime of each session (e.g. 90s, 15m, 1h), within the longest
    /// Settings allow. The session port renews the session before it runs
    /// out.
    #[arg(long, default_value = "15m")]
    ttl: String,
    /// Requests each session may make through the proxy.
    #[arg(long)]
    request_limit: Option<u64>,
    /// Label shown on the Sessions page, as key=value (repeatable).
    #[arg(long = "label")]
    labels: Vec<String>,
    /// The session's name on the Sessions page (the `name` label).
    #[arg(long)]
    name: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum McpFormat {
    /// `claude mcp add` commands.
    Claude,
    /// An `mcpServers` JSON block for other clients.
    Json,
}

#[derive(clap::Args)]
struct McpArgs {
    #[command(flatten)]
    broker: BrokerArgs,
    /// Vault name or id. Not needed with a vault-bound API key.
    #[arg(long, env = "TOKENLESS_VAULT")]
    vault: Option<String>,
    /// Access bundle whose MCP services to connect, by name or id.
    #[arg(long, env = "TOKENLESS_BUNDLE")]
    bundle: String,
    /// Lifetime of the token (e.g. 8h, 7d). Default: the longest Settings
    /// allow, since the client keeps it in its configuration.
    #[arg(long)]
    ttl: Option<String>,
    /// Label shown on the Sessions page, as key=value (repeatable).
    #[arg(long = "label")]
    labels: Vec<String>,
    /// The node's MCP gateway (`node run --mcp-listen`).
    #[arg(
        long,
        env = "TOKENLESS_MCP_GATEWAY",
        default_value = broker_server::launcher::mcp::DEFAULT_GATEWAY
    )]
    gateway: String,
    #[arg(long, value_enum, default_value_t = McpFormat::Claude)]
    format: McpFormat,
}

#[derive(clap::Args)]
struct PortArgs {
    /// The data plane proxy to relay to (`node run --listen`).
    #[arg(
        long,
        env = "TOKENLESS_PROXY_ADDRESS",
        default_value = "127.0.0.1:3128"
    )]
    proxy: String,
    /// Refuse to start unless the interception CA has this SHA-256
    /// fingerprint (copy it from the Proxies page).
    #[arg(long)]
    ca_fingerprint: Option<String>,
    /// PEM roots to combine with the broker CA for the agent (default: the
    /// system roots, or SSL_CERT_FILE).
    #[arg(long)]
    trust_base: Option<PathBuf>,
}

/// Where an existing session's token comes from, instead of minting one.
#[derive(clap::Args)]
struct GivenSessionArgs {
    /// File holding a session token (`v4.public...`) to use instead of
    /// minting one. Without it the token is read from
    /// TOKENLESS_SESSION_TOKEN. It is used as is: not renewed, not ended.
    #[arg(long, conflicts_with = "bundle")]
    session_token_file: Option<PathBuf>,
}

#[derive(clap::Args)]
struct RunArgs {
    #[command(flatten)]
    mint: MintArgs,
    #[command(flatten)]
    given: GivenSessionArgs,
    #[command(flatten)]
    port: PortArgs,
    /// Session port address; loopback only. Default: a free port.
    #[arg(long, default_value = "127.0.0.1:0")]
    listen: SocketAddr,
    /// Dotenv-style file of `NAME=cb://<service>/<field>` or `NAME=value`
    /// lines (repeatable). It holds references, not secrets, so it can be
    /// committed. Later files and NAME=... arguments override earlier ones.
    #[arg(long = "env-file", value_name = "PATH")]
    env_files: Vec<PathBuf>,
    /// Variables to set, as `NAME=cb://<service>/<field>` or `NAME=value`.
    #[arg(value_name = "NAME=VALUE")]
    assignments: Vec<String>,
    /// The command to run, after `--`.
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

#[derive(Subcommand)]
enum SessionCommand {
    /// Mint a session from an access bundle and print its token.
    Create {
        #[command(flatten)]
        mint: MintArgs,
        /// Print the session record and token as JSON instead.
        #[arg(long)]
        json: bool,
    },
    /// End a session: the one whose token is in
    /// TOKENLESS_SESSION_TOKEN, or `--id` with an API key allowed to
    /// revoke sessions.
    Revoke {
        #[command(flatten)]
        broker: BrokerArgs,
        #[arg(long)]
        id: Option<String>,
    },
    /// Show what a session can reach and which placeholders it accepts.
    /// Inside `run` or behind `session start` it asks the session port
    /// (TOKENLESS_PROXY); otherwise it uses the token in
    /// TOKENLESS_SESSION_TOKEN.
    Info {
        #[command(flatten)]
        broker: BrokerArgs,
        /// Print JSON instead.
        #[arg(long)]
        json: bool,
    },
    /// Open a session port: a loopback proxy address that adds a session
    /// from the bundle to every request. Runs until Ctrl-C, renewing the
    /// session, then ends it. Point agents at it with the printed exports.
    Start {
        #[command(flatten)]
        mint: MintArgs,
        #[command(flatten)]
        given: GivenSessionArgs,
        #[command(flatten)]
        port: PortArgs,
        /// Session port address; loopback only.
        #[arg(long, default_value = "127.0.0.1:17323")]
        listen: SocketAddr,
        /// Also write the exports to this file (mode 0600) to `source` it.
        #[arg(long)]
        env_file: Option<PathBuf>,
    },
}

#[derive(clap::Args)]
struct ServeArgs {
    /// Directory for the SQLite database (and the root key, when none is
    /// supplied).
    #[arg(long, default_value = "./data")]
    data_dir: PathBuf,
    #[command(flatten)]
    key: RootKeyArgs,
    /// Database URL (default: sqlite://<data-dir>/broker.db).
    #[arg(long)]
    database_url: Option<String>,
    /// Management API / UI listener. Off loopback, serve it over TLS with
    /// --api-tls-cert/--api-tls-key or put a TLS-terminating proxy in front.
    #[arg(long, default_value = "127.0.0.1:8080")]
    api_listen: SocketAddr,
    /// PEM certificate chain for serving the management API over HTTPS.
    /// Reloaded within a minute when the file changes.
    #[arg(long, requires = "api_tls_key")]
    api_tls_cert: Option<PathBuf>,
    /// PEM private key matching --api-tls-cert.
    #[arg(long, requires = "api_tls_cert")]
    api_tls_key: Option<PathBuf>,
    /// Node API listener (TLS, mTLS for enrolled nodes).
    #[arg(long, default_value = "127.0.0.1:8443")]
    node_listen: SocketAddr,
    /// Name or IP to put in the node API certificate (repeatable).
    #[arg(long = "node-api-name", default_values_t = vec!["localhost".to_string(), "127.0.0.1".to_string()])]
    node_api_names: Vec<String>,
    /// Serve the console from this built directory instead of the one
    /// compiled into the binary (for console development).
    #[arg(long)]
    ui_dir: Option<PathBuf>,
    /// Extra PEM file of CAs trusted for credential validation requests,
    /// e.g. a self-hosted service's private CA (repeatable).
    #[arg(long = "validation-ca")]
    validation_ca: Vec<PathBuf>,
    /// Snapshot lease in seconds; nodes fail closed when it lapses.
    #[arg(long, default_value_t = 60)]
    lease_secs: u32,
}

#[derive(Subcommand)]
enum ServiceCommand {
    /// Add a service from a template: asks for its credential without
    /// echoing it, stores it encrypted, and lets the access bundle use it.
    /// Piped input is read as the credential when the template has one
    /// field.
    ///
    /// Examples:
    ///   tokenless service add github --vault work --bundle code-review
    ///   gh auth token | tokenless service add github --vault work --bundle code-review
    #[command(verbatim_doc_comment)]
    Add {
        /// Template id, as on the console's Templates page (github, openai, ...).
        template: String,
        /// Vault to add it to; created when there is none with this name.
        #[arg(long, default_value = "default")]
        vault: String,
        /// Access bundle agents start with (`--bundle` of `tokenless run`);
        /// created when the vault has none with this name.
        #[arg(long)]
        bundle: Option<String>,
        /// Service name (default: the template id).
        #[arg(long)]
        name: Option<String>,
        /// Let agents only read (GET and HEAD).
        #[arg(long)]
        read_only: bool,
        /// Management API URL.
        #[arg(long, env = "TOKENLESS_URL", default_value = "http://127.0.0.1:8080")]
        server: String,
    },
}

#[derive(Subcommand)]
enum ProxyCommand {
    /// Enrol this machine as a proxy. Start it afterwards with
    /// `tokenless node run`.
    Add {
        /// Name shown on the Proxies page.
        #[arg(long, default_value = "node")]
        name: String,
        /// Where to store the proxy's identity (mode 0600).
        #[arg(long, default_value = "./node.json")]
        state: PathBuf,
        /// Node API URL (default: port 8443 of the --server host).
        #[arg(long)]
        control_url: Option<String>,
        /// Management API URL.
        #[arg(long, env = "TOKENLESS_URL", default_value = "http://127.0.0.1:8080")]
        server: String,
    },
}

/// Where the root key comes from. Without either, it is read from (or
/// generated in) the data directory, and the server warns at every start.
#[derive(clap::Args, Clone)]
struct RootKeyArgs {
    /// File holding the root key (32 bytes, or base64), kept outside the
    /// data directory and its backups. Alternatively set TOKENLESS_ROOT_KEY
    /// to the base64 key.
    #[arg(long, env = "TOKENLESS_ROOT_KEY_FILE", value_name = "PATH")]
    root_key_file: Option<PathBuf>,
}

impl RootKeyArgs {
    fn input(&self) -> Option<RootKeyInput> {
        match &self.root_key_file {
            Some(path) => Some(RootKeyInput::File(path.clone())),
            None => std::env::var("TOKENLESS_ROOT_KEY")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .map(|v| RootKeyInput::Value(Zeroizing::new(v))),
        }
    }
}

#[derive(Subcommand)]
enum AdminCommand {
    /// Give an account a new generated password and end its sessions. For
    /// a lost admin password; works while the server is running.
    ResetPassword {
        /// The account to reset.
        #[arg(long, default_value = "admin")]
        username: String,
        /// The server's data directory (the one `serve` uses).
        #[arg(long, default_value = "./data")]
        data_dir: PathBuf,
        /// Database URL, when `serve` uses one.
        #[arg(long)]
        database_url: Option<String>,
        #[command(flatten)]
        key: RootKeyArgs,
    },
    /// Replace the root key. Writes a new key to --out and re-wraps the
    /// instance key under it; no secret is re-encrypted. Restart `serve`
    /// with the new key afterwards and destroy the old one.
    RotateRootKey {
        /// Where to write the new root key; must not exist yet.
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
        /// The server's data directory (the one `serve` uses).
        #[arg(long, default_value = "./data")]
        data_dir: PathBuf,
        /// Database URL, when `serve` uses one.
        #[arg(long)]
        database_url: Option<String>,
        /// The current root key.
        #[command(flatten)]
        key: RootKeyArgs,
    },
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
        /// MCP gateway listener: MCP clients connect to
        /// http://<this>/mcp/<host>/<path> with a session token as a bearer
        /// token (see `tokenless mcp`). Keep it on loopback or a
        /// private address.
        #[arg(long, default_value = "127.0.0.1:3129")]
        mcp_listen: SocketAddr,
        /// Do not start the MCP gateway.
        #[arg(long)]
        no_mcp_gateway: bool,
        /// Extra PEM file of CAs trusted for upstream TLS (repeatable).
        #[arg(long = "upstream-ca")]
        upstream_ca: Vec<PathBuf>,
        /// Do not trust the public web PKI roots for upstreams.
        #[arg(long)]
        no_public_roots: bool,
    },
}

/// Servers log to stdout at `info`. Agent-side commands log to stderr at
/// `warn`, because stdout belongs to the token or to the agent.
fn init_logging(agent_side: bool) {
    let default = if agent_side { "warn" } else { "info" };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
    let builder = tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_current_span(false);
    if agent_side {
        builder.with_writer(std::io::stderr).init();
    } else {
        builder.init();
    }
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error(transparent)]
    Server(#[from] broker_server::ServerError),
    #[error(transparent)]
    DataPlane(#[from] broker_dataplane::DataPlaneError),
    #[error(transparent)]
    Launcher(#[from] LauncherError),
    #[error("I/O failure while {context}: {source}")]
    Io {
        context: String,
        source: std::io::Error,
    },
}

fn read_cas(
    paths: &[PathBuf],
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, CliError> {
    let mut out = Vec::new();
    for path in paths {
        let pem = std::fs::read_to_string(path).map_err(|e| CliError::Io {
            context: format!("reading CA file {}", path.display()),
            source: e,
        })?;
        out.extend(broker_dataplane::tls::certs_from_pem(
            &path.display().to_string(),
            &pem,
        )?);
    }
    Ok(out)
}

async fn wait_for_shutdown() -> Result<(), CliError> {
    tokio::signal::ctrl_c().await.map_err(|e| CliError::Io {
        context: "waiting for Ctrl-C".into(),
        source: e,
    })
}

async fn serve(args: ServeArgs) -> Result<(), CliError> {
    let data_dir = args.data_dir.clone();
    let mut config = ServerConfig::new(args.data_dir);
    config.root_key = args.key.input();
    let key_hint = config.root_key.clone();
    config.database_url = args.database_url;
    config.api_listen = args.api_listen;
    config.node_listen = args.node_listen;
    config.node_api_names = args.node_api_names;
    config.ui_dir = args.ui_dir;
    if let (Some(cert), Some(key)) = (args.api_tls_cert, args.api_tls_key) {
        config.api_tls = Some(broker_server::api_tls::ApiTlsFiles { cert, key });
    }
    config.control.lease_secs = args.lease_secs.max(3);
    config.validation_extra_roots = read_cas(&args.validation_ca)?;
    let running = Server::start(config).await?;
    if let Some(admin) = &running.initial_admin {
        // Printed to the terminal, not the structured log, so it is not
        // shipped to log aggregation. Only its hash is stored.
        print_credentials(
            "Created the first admin. Save these now: the password is shown only once.",
            admin,
        );
        eprintln!(
            "  Lost it? On this host: tokenless admin reset-password --data-dir {}{}",
            data_dir.display(),
            match &key_hint {
                Some(RootKeyInput::File(path)) => format!(" --root-key-file {}", path.display()),
                Some(RootKeyInput::Value(_)) => " (with TOKENLESS_ROOT_KEY set)".into(),
                None => String::new(),
            }
        );
        eprintln!();
        eprintln!(
            "  Sign in at {}://{}/ or with: tokenless login",
            if running.api_tls { "https" } else { "http" },
            sign_in_addr(running.api_addr)
        );
        eprintln!();
    }
    if let Some(path) = &running.root_key_in_data_dir {
        eprintln!(
            "  The root key is in the data directory ({}): a copy of the directory decrypts every secret.",
            path.display()
        );
        eprintln!("  Move it out and start with --root-key-file <path> or TOKENLESS_ROOT_KEY.");
        eprintln!();
    }
    wait_for_shutdown().await?;
    info!("shutting down");
    running.shutdown();
    Ok(())
}

/// An address to sign in at: a wildcard listener (`0.0.0.0`, `::`, as in
/// the container image) is reachable on loopback from this host.
fn sign_in_addr(addr: std::net::SocketAddr) -> std::net::SocketAddr {
    if addr.ip().is_unspecified() {
        let loopback = match addr {
            std::net::SocketAddr::V4(_) => std::net::IpAddr::from(std::net::Ipv4Addr::LOCALHOST),
            std::net::SocketAddr::V6(_) => std::net::IpAddr::from(std::net::Ipv6Addr::LOCALHOST),
        };
        std::net::SocketAddr::new(loopback, addr.port())
    } else {
        addr
    }
}

/// Hidden prompts on the terminal, never echoed or logged.
struct TerminalPrompter;

impl Prompter for TerminalPrompter {
    fn secret(&self, label: &str) -> Result<Zeroizing<String>, LauncherError> {
        rpassword::prompt_password(format!("{label}: "))
            .map(|v| Zeroizing::new(v.trim_end_matches(['\r', '\n']).to_string()))
            .map_err(LauncherError::io(format!(
                "reading {label} from the terminal"
            )))
    }
}

async fn login(server: String, username: String) -> Result<ExitCode, CliError> {
    let prompter = TerminalPrompter;
    let password = prompter.secret(&format!("Password for {username}"))?;
    let session = match account::sign_in(&server, &username, &password, None).await? {
        SignIn::Done(session) => session,
        SignIn::CodeNeeded => {
            let code = prompter.secret("Authenticator code")?;
            match account::sign_in(&server, &username, &password, Some(&code)).await? {
                SignIn::Done(session) => session,
                SignIn::CodeNeeded => {
                    return Err(
                        LauncherError::config("the authenticator code was not accepted").into(),
                    )
                }
            }
        }
    };
    let stored = SessionStore::system().store(&session)?;
    let until = session.expires_at.format("%Y-%m-%d %H:%M UTC").to_string();
    let file = match &stored {
        Stored::Keychain => None,
        Stored::File { path, reason } => Some((path.display().to_string(), reason.to_string())),
    };
    say(messages::signed_in(
        &session.server,
        &session.username,
        &until,
        file.as_ref().map(|(p, r)| (p.as_str(), r.as_str())),
    ));
    Ok(ExitCode::SUCCESS)
}

async fn logout(server: String) -> Result<ExitCode, CliError> {
    let prompter = TerminalPrompter;
    let store = SessionStore::system();
    // Ending it on the server is best effort; the keychain entry goes
    // either way.
    let ended = match ConsoleClient::open(&store, &server, &prompter) {
        Ok(client) => client.logout().await.err(),
        Err(_) => None,
    };
    let server = server.trim().trim_end_matches('/');
    let removed = store.delete(server)?;
    match (removed, ended) {
        (false, _) => say(format_args!("not signed in to {server}")),
        (true, None) => say("signed out"),
        (true, Some(e)) => say(format_args!(
            "signed out here, but {server} could not end the session, which stays valid until it expires: {e}"
        )),
    }
    Ok(ExitCode::SUCCESS)
}

/// The template's credential fields, from the terminal without echo, or
/// from piped input when the template has a single field.
fn read_fields(
    template: &broker_control::model::StoredTemplate,
    prompter: &dyn Prompter,
) -> Result<BTreeMap<String, Zeroizing<String>>, CliError> {
    use std::io::{IsTerminal, Read};
    let fields = &template.template.credential_fields;
    let mut out = BTreeMap::new();
    if !std::io::stdin().is_terminal() {
        let [only] = fields.as_slice() else {
            return Err(LauncherError::config(format!(
                "template '{}' has {} credential fields; run this in a terminal to be asked for each",
                template.template.id,
                fields.len()
            ))
            .into());
        };
        let mut value = Zeroizing::new(String::new());
        std::io::stdin()
            .read_to_string(&mut value)
            .map_err(|e| CliError::Io {
                context: "reading the credential from standard input".into(),
                source: e,
            })?;
        let value = Zeroizing::new(value.trim().to_string());
        if value.is_empty() {
            return Err(
                LauncherError::config("standard input was empty; pipe the credential in").into(),
            );
        }
        out.insert(only.name.clone(), value);
        return Ok(out);
    }
    for field in fields {
        let label = if field.required {
            field.label.clone()
        } else {
            format!("{} (optional, Enter to skip)", field.label)
        };
        let value = prompter.secret(&label)?;
        let value = Zeroizing::new(value.trim().to_string());
        if value.is_empty() {
            if field.required {
                return Err(LauncherError::config(format!("{} is required", field.label)).into());
            }
            continue;
        }
        out.insert(field.name.clone(), value);
    }
    Ok(out)
}

async fn service(command: ServiceCommand) -> Result<ExitCode, CliError> {
    match command {
        ServiceCommand::Add {
            template,
            vault,
            bundle,
            name,
            read_only,
            server,
        } => {
            let prompter = TerminalPrompter;
            let client = ConsoleClient::open(&SessionStore::system(), &server, &prompter)?;
            let template = account::pick_template(client.templates().await?, &template)?;
            if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                say(messages::service_prompt(
                    &template.template.name,
                    vault.trim(),
                ));
            }
            let fields = read_fields(&template, &prompter)?;
            let plan = AddService {
                template_id: template.template.id.clone(),
                name,
                vault,
                bundle,
                read_only,
            };
            let added = client.add_service(&plan, &template, fields).await?;
            say(messages::added_service(&messages::AddedService {
                service: &added.credential.name,
                vault: &added.vault.name,
                vault_created: added.vault_created,
                bundle: added
                    .bundle
                    .as_ref()
                    .map(|(b, created)| (b.name.as_str(), *created)),
                rule: &added.rule.name,
            }));
            Ok(ExitCode::SUCCESS)
        }
    }
}

async fn proxy(command: ProxyCommand) -> Result<ExitCode, CliError> {
    match command {
        ProxyCommand::Add {
            name,
            state,
            control_url,
            server,
        } => {
            let prompter = TerminalPrompter;
            let client = ConsoleClient::open(&SessionStore::system(), &server, &prompter)?;
            let control_url = match control_url {
                Some(url) => url,
                None => account::default_control_url(&server)?,
            };
            let join = client.create_join_token().await?;
            let identity = enroll(&control_url, &join.token, &name).await?;
            identity.save(&state)?;
            say(messages::enrolled(&name, &state.display().to_string()));
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn print_credentials(heading: &str, creds: &broker_server::GeneratedCredentials) {
    eprintln!();
    eprintln!("  {heading}");
    eprintln!();
    eprintln!("    Username  {}", creds.username);
    eprintln!("    Password  {}", creds.password.as_str());
    eprintln!();
    eprintln!("  Keep them in a password manager. Change the password from Account in");
    eprintln!("  the console.");
}

async fn admin(command: AdminCommand) -> Result<(), CliError> {
    match command {
        AdminCommand::ResetPassword {
            username,
            data_dir,
            database_url,
            key,
        } => {
            let mut config = ServerConfig::new(data_dir);
            config.database_url = database_url;
            config.root_key = key.input();
            let creds = broker_server::reset_password(&config, &username).await?;
            print_credentials(
                "Password reset. Save it now: it is shown only once. Every session of this account has ended.",
                &creds,
            );
            eprintln!();
            Ok(())
        }
        AdminCommand::RotateRootKey {
            out,
            data_dir,
            database_url,
            key,
        } => {
            let mut config = ServerConfig::new(data_dir);
            config.database_url = database_url;
            config.root_key = key.input();
            broker_server::rotate_root_key(&config, &out).await?;
            eprintln!();
            eprintln!("  New root key written to {}.", out.display());
            eprintln!();
            eprintln!(
                "  Restart the server with: tokenless serve --root-key-file {} ...",
                out.display()
            );
            eprintln!("  The old key no longer opens this data: destroy it and its copies.");
            eprintln!();
            Ok(())
        }
    }
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
            say(messages::enrolled(&name, &state.display().to_string()));
            Ok(())
        }
        NodeCommand::Run {
            state,
            listen,
            metrics_listen,
            mcp_listen,
            no_mcp_gateway,
            upstream_ca,
            no_public_roots,
        } => {
            let identity = NodeIdentity::load(&state)?;
            let extra = read_cas(&upstream_ca)?;
            let config = DataPlaneConfig {
                listen,
                metrics_listen,
                mcp_listen: (!no_mcp_gateway).then_some(mcp_listen),
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

// ----- agent side -----------------------------------------------------

fn read_api_key(args: &BrokerArgs) -> Result<Option<Zeroizing<String>>, CliError> {
    if let Some(path) = &args.api_key_file {
        let key = std::fs::read_to_string(path).map_err(|e| CliError::Io {
            context: format!("reading the API key file {}", path.display()),
            source: e,
        })?;
        return Ok(Some(Zeroizing::new(key.trim().to_string())));
    }
    Ok(std::env::var("TOKENLESS_API_KEY")
        .ok()
        .map(|k| Zeroizing::new(k.trim().to_string()))
        .filter(|k| !k.is_empty()))
}

/// An API key when one is given; otherwise the session of `tokenless login`
/// for this server, when there is one.
fn client(args: &BrokerArgs) -> Result<Arc<ApiClient>, CliError> {
    let credentials = match read_api_key(args)? {
        Some(key) => Some(Credentials::ApiKey(key)),
        None => {
            let server = args.server.trim().trim_end_matches('/');
            // A session store that cannot be read is the same as not signed
            // in: the error then says how to authenticate.
            match SessionStore::system().load(server) {
                Ok(Some(saved)) if saved.expires_at > chrono::Utc::now() => {
                    Some(Credentials::Session {
                        token: Zeroizing::new(saved.token),
                        csrf_token: saved.csrf_token,
                    })
                }
                Ok(_) => None,
                Err(e) => {
                    tracing::debug!(error = %e, "no saved session");
                    None
                }
            }
        }
    };
    Ok(Arc::new(ApiClient::new(&args.server, credentials)?))
}

fn mint_request(args: &MintArgs, extra: &[(&str, String)]) -> Result<MintRequest, CliError> {
    let Some(bundle) = args.bundle.clone() else {
        return Err(LauncherError::config(
            "say which access bundle to mint the session from with --bundle (or TOKENLESS_BUNDLE), or set TOKENLESS_SESSION_TOKEN to a session you already have",
        )
        .into());
    };
    // The broker enforces its own cap (Settings → Session lifetime) and
    // names it in the error; the session port renews, so short is fine.
    let ttl_secs = parse_duration_secs(&args.ttl)?;
    let mut labels = BTreeMap::new();
    for raw in &args.labels {
        let (k, v) = parse_label(raw)?;
        labels.insert(k, v);
    }
    if let Some(name) = &args.name {
        labels.insert("name".to_string(), name.trim().to_string());
    }
    for (k, v) in extra {
        labels.entry((*k).to_string()).or_insert_with(|| v.clone());
    }
    Ok(MintRequest {
        bundle,
        ttl_secs,
        longest: false,
        request_limit: args.request_limit,
        labels,
    })
}

/// A session token handed over (`--session-token-file`, or
/// TOKENLESS_SESSION_TOKEN when no bundle is given), or `None` to mint one.
/// A bundle and a token together are refused rather than guessed between.
fn given_session(
    mint: &MintArgs,
    given: &GivenSessionArgs,
    from_env: Option<Zeroizing<String>>,
) -> Result<Option<Zeroizing<String>>, CliError> {
    if let Some(path) = &given.session_token_file {
        let token = std::fs::read_to_string(path).map_err(|e| CliError::Io {
            context: format!("reading the session token file {}", path.display()),
            source: e,
        })?;
        return Ok(Some(Zeroizing::new(token.trim().to_string())));
    }
    let Some(token) = from_env else {
        return Ok(None);
    };
    match &mint.bundle {
        Some(bundle) => Err(LauncherError::config(format!(
            "both a bundle to mint a session from ('{bundle}') and TOKENLESS_SESSION_TOKEN are set; unset one"
        ))
        .into()),
        None => Ok(Some(Zeroizing::new(token.trim().to_string()))),
    }
}

/// The session behind a session port: the one handed over, or a new one
/// minted from the bundle and renewed.
async fn open_session(
    client: &Arc<ApiClient>,
    mint: &MintArgs,
    given: Option<Zeroizing<String>>,
    labels: &[(&str, String)],
) -> Result<LiveSession, CliError> {
    if let Some(token) = given {
        return Ok(LiveSession::adopt(client.clone(), &token).await?);
    }
    let request = mint_request(mint, labels)?;
    let vault = client.resolve_vault(mint.vault.as_deref()).await?;
    Ok(LiveSession::start(client.clone(), vault, request).await?)
}

/// Downloads the interception CA, checks a pinned fingerprint and writes
/// the agent's trust files into `dir`.
async fn prepare_trust(
    client: &ApiClient,
    port: &PortArgs,
    dir: &std::path::Path,
) -> Result<(TrustFiles, String), CliError> {
    let (pem, url) = client.interception_ca().await?;
    let actual = fingerprint(&pem)?;
    if let Some(expected) = &port.ca_fingerprint {
        if !fingerprints_match(expected, &actual) {
            return Err(LauncherError::CaMismatch {
                url,
                expected: expected.clone(),
                actual,
            }
            .into());
        }
    }
    let files = write_trust_files(dir, &pem, port.trust_base.as_deref())?;
    if files.base.is_none() {
        say("no system root bundle found, so HTTPS to hosts outside the bundle may fail; pass --trust-base <roots.pem>");
    }
    Ok((files, actual))
}

fn private_dir() -> Result<tempfile::TempDir, CliError> {
    // tempfile creates the directory with mode 0700.
    tempfile::Builder::new()
        .prefix("tokenless-")
        .tempdir()
        .map_err(|e| CliError::Io {
            context: "creating a private directory for the trust files".into(),
            source: e,
        })
}

/// Ctrl-C or, on Unix, SIGTERM.
async fn stop_signal() -> Result<&'static str, CliError> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).map_err(|e| CliError::Io {
            context: "listening for SIGTERM".into(),
            source: e,
        })?;
        tokio::select! {
            r = tokio::signal::ctrl_c() => r.map(|()| "SIGINT").map_err(|e| CliError::Io { context: "waiting for Ctrl-C".into(), source: e }),
            _ = term.recv() => Ok("SIGTERM"),
        }
    }
    #[cfg(not(unix))]
    {
        wait_for_shutdown().await.map(|()| "Ctrl-C")
    }
}

#[derive(Serialize)]
struct CreatedSession<'a> {
    token: &'a str,
    session: &'a broker_control::model::ProxySession,
}

async fn session(command: SessionCommand, verbose: bool) -> Result<ExitCode, CliError> {
    match command {
        SessionCommand::Create { mint, json } => {
            let client = client(&mint.broker)?;
            let vault = client.resolve_vault(mint.vault.as_deref()).await?;
            let minted = client.mint(&vault, &mint_request(&mint, &[])?).await?;
            if json {
                let out = serde_json::to_string_pretty(&CreatedSession {
                    token: &minted.token,
                    session: &minted.session,
                })
                .map_err(|e| LauncherError::config(format!("encoding the session as JSON: {e}")))?;
                println!("{out}");
            } else {
                println!("{}", minted.token);
            }
            detail(verbose, || {
                format!(
                    "session {} expires at {}",
                    minted.session.id,
                    minted.session.expires_at.to_rfc3339()
                )
            });
            Ok(ExitCode::SUCCESS)
        }
        SessionCommand::Info { broker, json } => {
            let client = ApiClient::new(&broker.server, None)?;
            let port = std::env::var("TOKENLESS_PROXY")
                .ok()
                .filter(|p| !p.trim().is_empty());
            let found = match port {
                Some(port) => client.port_services(&port).await?,
                None => {
                    let token = session_token_from_env()?;
                    let discovery = client.discover(&token).await?;
                    PortServices {
                        bundle: discovery.session.bundle.map(|b| b.name),
                        services: discovery.services,
                    }
                }
            };
            if json {
                let out = serde_json::to_string_pretty(&found).map_err(|e| {
                    LauncherError::config(format!("encoding the services as JSON: {e}"))
                })?;
                println!("{out}");
            } else {
                print!("{}", describe_services(&found));
            }
            Ok(ExitCode::SUCCESS)
        }
        SessionCommand::Revoke { broker, id } => {
            let client = client(&broker)?;
            let session = match id {
                Some(id) => client.revoke_by_id(&id).await?,
                None => {
                    let token = session_token_from_env()?;
                    client.revoke_self(&token).await?
                }
            };
            detail(verbose, || format!("session {} ended", session.id));
            Ok(ExitCode::SUCCESS)
        }
        SessionCommand::Start {
            mint,
            given,
            port,
            listen,
            env_file,
        } => {
            let given = given_session(&mint, &given, session_token_from_env().ok())?;
            if given.is_none() {
                mint_request(&mint, &[])?;
            }
            check_listen(listen)?;
            check_proxy(&port.proxy).await?;
            let client = client(&mint.broker)?;
            let dir = private_dir()?;
            let (trust, ca) = prepare_trust(&client, &port, dir.path()).await?;
            let live = open_session(&client, &mint, given, &[]).await?;
            let session_port = match SessionPort::start(
                listen,
                &port.proxy,
                live.auth.clone(),
                live.services_json(),
            )
            .await
            {
                Ok(p) => p,
                Err(e) => {
                    live.end().await;
                    return Err(e.into());
                }
            };
            let exports: String = agent_env(session_port.addr, &trust)
                .into_iter()
                .chain(placeholder_env(&live.services))
                .map(|(k, v)| format!("export {k}={}\n", shell_quote(&v)))
                .collect();
            if let Some(path) = &env_file {
                if let Err(e) = write_private(path, &exports) {
                    session_port.stop();
                    live.end().await;
                    return Err(e);
                }
            }
            let current = live.current.load();
            detail(verbose, || {
                format!(
                    "session port {} relays to the proxy at {} (session {}, renewed before {}). Interception CA {ca}",
                    session_port.addr,
                    port.proxy,
                    current.id,
                    current.expires_at.to_rfc3339()
                )
            });
            // The one line a person needs: what the exports are for and how
            // it ends. The exports themselves go to standard output.
            say(format_args!(
                "session port open for bundle '{}'; point agents at it with these exports{}. Ctrl-C ends it",
                bundle_name(&live),
                env_file
                    .as_ref()
                    .map(|p| format!(" (also in {})", p.display()))
                    .unwrap_or_default()
            ));
            print!("{exports}");
            let signal = stop_signal().await?;
            session_port.stop();
            let ended = live.end().await;
            detail(verbose, || format!("{signal}, ended {ended} session(s)"));
            if let Some(path) = &env_file {
                let _ = std::fs::remove_file(path);
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// The bundle a session was minted from, for messages.
fn bundle_name(live: &LiveSession) -> String {
    live.current
        .load()
        .bundle
        .as_ref()
        .map(|b| b.name.clone())
        .unwrap_or_else(|| "(chosen rules)".to_string())
}

fn session_token_from_env() -> Result<Zeroizing<String>, CliError> {
    std::env::var("TOKENLESS_SESSION_TOKEN")
        .ok()
        .map(Zeroizing::new)
        .filter(|t| !t.trim().is_empty())
        .ok_or_else(|| {
            LauncherError::config(
                "set TOKENLESS_SESSION_TOKEN to the session's token (or run this behind a session port, which sets TOKENLESS_PROXY)",
            )
            .into()
        })
}

/// A readable summary of what a session reaches.
async fn mcp_command(args: McpArgs) -> Result<ExitCode, CliError> {
    use broker_server::launcher::mcp::{claude_command, client_json, endpoints};
    let gateway = args.gateway.trim().trim_end_matches('/').to_string();
    if !gateway.starts_with("http://") && !gateway.starts_with("https://") {
        return Err(LauncherError::config(format!(
            "--gateway '{gateway}' must start with http:// (the node serves it as `node run --mcp-listen`)"
        ))
        .into());
    }
    let mut labels = BTreeMap::new();
    for raw in &args.labels {
        let (k, v) = parse_label(raw)?;
        labels.insert(k, v);
    }
    labels
        .entry("client".to_string())
        .or_insert_with(|| "mcp".to_string());
    let request = MintRequest {
        bundle: args.bundle.clone(),
        ttl_secs: match &args.ttl {
            Some(ttl) => parse_duration_secs(ttl)?,
            None => 0,
        },
        longest: args.ttl.is_none(),
        request_limit: None,
        labels,
    };
    let client = client(&args.broker)?;
    let vault = client.resolve_vault(args.vault.as_deref()).await?;
    let minted = client.mint(&vault, &request).await?;
    let discovery = client.discover(&minted.token).await?;
    let found = endpoints(&discovery.services, &gateway);
    if found.is_empty() {
        // A token for nothing would only be one more thing to revoke.
        let _ = client.revoke_self(&minted.token).await;
        return Err(LauncherError::config(format!(
            "access bundle '{}' has no enabled MCP service; add one (GitHub MCP, Custom MCP server, ...) on the bundle's page, then run this again",
            args.bundle
        ))
        .into());
    }
    match args.format {
        McpFormat::Claude => {
            for e in &found {
                println!("# {} ({})", e.service, e.credential);
                println!("{}\n", claude_command(e, &minted.token));
            }
        }
        McpFormat::Json => {
            let out = client_json(&found, &minted.token).map_err(|e| {
                LauncherError::config(format!("encoding the MCP client configuration: {e}"))
            })?;
            println!("{out}");
        }
    }
    say(messages::mcp_token(
        &minted
            .session
            .expires_at
            .format("%Y-%m-%d %H:%M UTC")
            .to_string(),
        &minted.session.id.to_string(),
        &gateway,
    ));
    Ok(ExitCode::SUCCESS)
}

fn describe_services(found: &PortServices) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    match &found.bundle {
        Some(bundle) => {
            let _ = writeln!(out, "Access bundle: {bundle}");
        }
        None => {
            let _ = writeln!(out, "Session minted from individual rules");
        }
    }
    if found.services.is_empty() {
        let _ = writeln!(out, "This session reaches no services.");
    }
    for s in &found.services {
        let state = if s.enabled {
            ""
        } else {
            " (disabled: no credential is added)"
        };
        let _ = writeln!(out, "\n{} — {}{state}", s.service, s.credential);
        let _ = writeln!(out, "  hosts:   {}", s.hosts.join(", "));
        let _ = writeln!(
            out,
            "  allowed: {} {}",
            s.methods.join(","),
            s.paths.join(" ")
        );
        for p in &s.placeholders {
            let _ = writeln!(out, "  {}", inject::reference(s, p));
            let places: Vec<&str> = p.locations.iter().map(|l| l.as_str()).collect();
            let env = p
                .env
                .as_ref()
                .map(|e| format!(" (exported as {e})"))
                .unwrap_or_default();
            let _ = writeln!(
                out,
                "    send {} in the {} and the proxy puts the real value there{env}",
                p.placeholder,
                places.join(", ")
            );
        }
    }
    out
}

fn write_private(path: &std::path::Path, contents: &str) -> Result<(), CliError> {
    let io = |e| CliError::Io {
        context: format!("writing {}", path.display()),
        source: e,
    };
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    use std::io::Write;
    options
        .open(path)
        .and_then(|mut f| f.write_all(contents.as_bytes()))
        .map_err(io)
}

/// The exit code a shell would report for the child.
fn exit_code(status: std::process::ExitStatus) -> ExitCode {
    if let Some(code) = status.code() {
        return ExitCode::from(u8::try_from(code).unwrap_or(1));
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return ExitCode::from(u8::try_from(128 + sig).unwrap_or(1));
        }
    }
    ExitCode::FAILURE
}

/// Asks the child to stop the way a service manager would. `kill(1)` is
/// used because the workspace forbids `unsafe`, which `libc::kill` needs.
#[cfg(unix)]
fn terminate(pid: u32) {
    let _ = std::process::Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status();
}

/// The env files, then the `NAME=...` arguments, in override order. Read
/// before anything is minted so a typo costs no session.
fn read_assignments(args: &RunArgs) -> Result<Vec<Assignment>, CliError> {
    let mut all = Vec::new();
    for path in &args.env_files {
        let contents = std::fs::read_to_string(path).map_err(|e| CliError::Io {
            context: format!("reading the env file {}", path.display()),
            source: e,
        })?;
        all.extend(inject::parse_env_file(&contents, path)?);
    }
    for raw in &args.assignments {
        all.push(inject::parse_assignment(raw)?);
    }
    Ok(all)
}

async fn run(args: RunArgs, verbose: bool) -> Result<ExitCode, CliError> {
    let assignments = read_assignments(&args)?;
    let program = args.command[0].clone();
    let name = std::path::Path::new(&program)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| program.clone());
    let given = given_session(&args.mint, &args.given, session_token_from_env().ok())?;
    if given.is_none() {
        // Fail on a missing bundle before touching the network.
        mint_request(&args.mint, &[])?;
    }
    check_listen(args.listen)?;
    check_proxy(&args.port.proxy).await?;
    let client = client(&args.mint.broker)?;
    let dir = private_dir()?;
    let (trust, _) = prepare_trust(&client, &args.port, dir.path()).await?;
    let live = open_session(&client, &args.mint, given, &[("command", name.clone())]).await?;
    let session_port = match SessionPort::start(
        args.listen,
        &args.port.proxy,
        live.auth.clone(),
        live.services_json(),
    )
    .await
    {
        Ok(p) => p,
        Err(e) => {
            live.end().await;
            return Err(e.into());
        }
    };
    let trust_env = agent_env(session_port.addr, &trust);
    let reserved: Vec<String> = trust_env.iter().map(|(k, _)| k.clone()).collect();
    let requested = match inject::resolve(&assignments, &live.services, &reserved) {
        Ok(env) => env,
        Err(e) => {
            session_port.stop();
            live.end().await;
            return Err(e.into());
        }
    };
    // Placeholders a service exports by itself, then what was asked for,
    // then the proxy and trust variables, which nothing may override.
    let env: Vec<(String, String)> = placeholder_env(&live.services)
        .into_iter()
        .chain(requested)
        .chain(trust_env)
        .collect();
    detail(verbose, || {
        format!(
            "running '{name}' with bundle '{}' (session {}) through {} -> {}",
            bundle_name(&live),
            live.current.load().id,
            session_port.addr,
            args.port.proxy
        )
    });
    let spawned = inject::agent_command(&program, &args.command[1..], &env).spawn();
    let mut child = match spawned {
        Ok(c) => c,
        Err(e) => {
            session_port.stop();
            live.end().await;
            return Err(CliError::Io {
                context: format!("starting '{program}'"),
                source: e,
            });
        }
    };
    let status = loop {
        tokio::select! {
            status = child.wait() => break status,
            signal = stop_signal() => {
                let signal = signal?;
                // Ctrl-C already reached the child through the terminal's
                // process group; SIGTERM from a service manager did not.
                #[cfg(unix)]
                if signal == "SIGTERM" {
                    if let Some(pid) = child.id() {
                        terminate(pid);
                    }
                }
                info!(signal, "waiting for the command to exit");
            }
        }
    };
    session_port.stop();
    let ended = live.end().await;
    drop(dir);
    let status = status.map_err(|e| CliError::Io {
        context: format!("waiting for '{program}'"),
        source: e,
    })?;
    // Silent otherwise: the command's own output and exit code are the
    // result, and anything added here would end up in what reads them.
    detail(verbose, || {
        format!("'{name}' exited ({status}); ended {ended} session(s)")
    });
    Ok(exit_code(status))
}

fn skill_command(install: bool, dir: Option<PathBuf>, force: bool) -> Result<ExitCode, CliError> {
    if !install {
        print!("{}", skill::SKILL_MD);
        return Ok(ExitCode::SUCCESS);
    }
    let dir = match dir {
        Some(dir) => dir,
        None => skill::default_dir()?,
    };
    let (path, outcome) = skill::install(&dir, force)?;
    let what = match outcome {
        skill::Installed::Created => "installed",
        skill::Installed::Unchanged => "already up to date",
        skill::Installed::Replaced => "replaced",
    };
    say(format_args!("skill {what} at {}", path.display()));
    Ok(ExitCode::SUCCESS)
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let agent_side = matches!(
        cli.command,
        Command::Session { .. }
            | Command::Run(_)
            | Command::Mcp(_)
            | Command::Skill { .. }
            | Command::Admin { .. }
            | Command::Login { .. }
            | Command::Logout { .. }
            | Command::Service { .. }
            | Command::Proxy { .. }
    );
    init_logging(agent_side);
    let result = match cli.command {
        Command::Serve(args) => serve(args).await.map(|()| ExitCode::SUCCESS),
        Command::Node { command } => node(command).await.map(|()| ExitCode::SUCCESS),
        Command::Admin { command } => admin(command).await.map(|()| ExitCode::SUCCESS),
        Command::Login { server, username } => login(server, username).await,
        Command::Logout { server } => logout(server).await,
        Command::Service { command } => service(command).await,
        Command::Proxy { command } => proxy(command).await,
        Command::Session { command } => session(command, cli.verbose).await,
        Command::Run(args) => run(args, cli.verbose).await,
        Command::Mcp(args) => mcp_command(args).await,
        Command::Skill {
            install,
            dir,
            force,
        } => skill_command(install, dir, force),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            if agent_side {
                eprintln!("tokenless: {e}");
            } else {
                error!(error = %e, "tokenless exited with an error");
            }
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wildcard_listener_is_signed_in_to_on_loopback() {
        let at = |s: &str| sign_in_addr(s.parse().unwrap()).to_string();
        assert_eq!(at("0.0.0.0:8080"), "127.0.0.1:8080");
        assert_eq!(at("[::]:8080"), "[::1]:8080");
        assert_eq!(at("192.0.2.10:8080"), "192.0.2.10:8080");
    }

    fn run_args(args: &[&str]) -> RunArgs {
        #[derive(Parser)]
        struct Wrapper {
            #[command(flatten)]
            run: RunArgs,
        }
        let argv = ["tokenless"].iter().chain(args).chain(&["--", "claude"]);
        Wrapper::try_parse_from(argv).unwrap().run
    }

    fn token(value: &str) -> Option<Zeroizing<String>> {
        Some(Zeroizing::new(value.to_string()))
    }

    #[test]
    fn run_uses_a_given_session_or_mints_from_a_bundle_never_both() {
        let given = |args: &[&str], env: Option<Zeroizing<String>>| {
            let a = run_args(args);
            given_session(&a.mint, &a.given, env).map(|t| t.map(|t| t.to_string()))
        };
        // A token in the environment and no bundle: use it as is.
        assert_eq!(
            given(&[], token(" v4.public.abc\n")).unwrap().as_deref(),
            Some("v4.public.abc")
        );
        // A bundle and no token: mint.
        assert_eq!(given(&["--bundle", "code-review"], None).unwrap(), None);
        // Both: refuse rather than guess.
        let err = given(&["--bundle", "code-review"], token("v4.public.abc"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("unset one"), "{err}");
        // Neither: minting then asks for a bundle.
        let none = run_args(&[]);
        assert_eq!(given(&[], None).unwrap(), None);
        let err = mint_request(&none.mint, &[]).unwrap_err().to_string();
        assert!(err.contains("TOKENLESS_SESSION_TOKEN"), "{err}");
        // A token file wins over the environment, and conflicts with --bundle.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("token");
        std::fs::write(&file, "v4.public.file\n").unwrap();
        let path = file.to_str().unwrap();
        assert_eq!(
            given(&["--session-token-file", path], token("v4.public.env"))
                .unwrap()
                .as_deref(),
            Some("v4.public.file")
        );
        #[derive(Parser)]
        struct Wrapper {
            #[command(flatten)]
            run: RunArgs,
        }
        assert!(Wrapper::try_parse_from([
            "tokenless",
            "--session-token-file",
            path,
            "--bundle",
            "x",
            "--",
            "claude"
        ])
        .is_err());
    }

    #[test]
    fn a_session_name_is_its_name_label() {
        let a = run_args(&["--bundle", "code-review", "--name", " laptop "]);
        let request = mint_request(&a.mint, &[("command", "claude".into())]).unwrap();
        assert_eq!(
            request.labels.get("name").map(String::as_str),
            Some("laptop")
        );
        assert_eq!(
            request.labels.get("command").map(String::as_str),
            Some("claude")
        );
    }
}
