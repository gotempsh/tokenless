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
use std::time::Duration;

use broker_server::launcher::account::{
    self, ConsoleClient, Prompter, SessionStore, SessionVault, SignIn, Stored,
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
use broker_server::telemetry::{self, Component, Settings as TelemetrySettings, Telemetry};
use broker_server::update::{self, Outcome as UpdateOutcome, UpdateError};
use broker_server::{RootKeyInput, Server, ServerConfig};
use clap::{Parser, Subcommand};
use messages::{detail, say};
use serde::Serialize;
use tokenless_dataplane::node::{enroll, NodeIdentity};
use tokenless_dataplane::{DataPlane, DataPlaneConfig};
use tracing::{error, info, warn};
use tracing_subscriber::filter::{filter_fn, FilterExt};
use tracing_subscriber::fmt::writer::BoxMakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer as _};
use zeroize::Zeroizing;

mod messages;
mod setup;

#[derive(Parser)]
#[command(
    name = "tokenless",
    version = update::VERSION,
    about = "Credential broker for AI agents",
    after_help = "New here, or setting up for someone? Start with: tokenless status"
)]
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
    /// What is set up on this machine (control plane, sign-in, services,
    /// proxy, agent skill) and the one command to run next. Exits 0 when
    /// agents can be started behind tokenless, 1 when something is missing.
    ///
    /// Examples:
    ///   tokenless status
    ///   tokenless status --json
    #[command(verbatim_doc_comment)]
    Status {
        /// Print the report as JSON, for agents and scripts.
        #[arg(long)]
        json: bool,
        /// Management API URL.
        #[arg(long, env = "TOKENLESS_URL", default_value = setup::DEFAULT_SERVER)]
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
    /// Replace this binary with the latest release, checked against the
    /// release's SHA256SUMS (and its signature, when cosign is installed).
    /// Running servers and proxies keep the old version until restarted.
    Update(UpdateArgs),
}

#[derive(clap::Args)]
struct UpdateArgs {
    /// Only say whether a newer release exists. Exits 10 when one does,
    /// 0 when this is the latest.
    #[arg(long, conflicts_with = "release")]
    check: bool,
    /// Install this release, such as v0.3.0, instead of the latest; even
    /// an older one.
    #[arg(long)]
    release: Option<String>,
    /// Refuse to update unless cosign verifies the release's signature.
    #[arg(long)]
    require_signature: bool,
    /// GitHub repository the releases come from.
    #[arg(long, env = "TOKENLESS_REPO", default_value = update::DEFAULT_REPO)]
    repo: String,
    /// Base URL holding the release files instead of GitHub, for mirrors.
    #[arg(long, env = "TOKENLESS_DOWNLOAD_URL")]
    download_url: Option<String>,
    /// A PEM file of CAs to trust for the downloads, besides the public
    /// ones: for a mirror with an internal CA, or a TLS-inspecting proxy.
    #[arg(long, env = "TOKENLESS_DOWNLOAD_CA")]
    download_ca: Option<PathBuf>,
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
    /// Lifetime of each session (e.g. 90s, 15m, 1h; default 15m), within
    /// the longest Settings allow. The session port renews the session
    /// before it runs out.
    #[arg(long)]
    ttl: Option<String>,
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
    /// Don't say so when the command is Claude Code and the tokenless
    /// skill isn't installed. From the environment, `0`, `false`, `no`,
    /// `off` and empty mean no; anything else means yes.
    #[arg(
        long,
        env = "TOKENLESS_NO_SKILL_HINT",
        value_parser = clap::builder::FalseyValueParser::new()
    )]
    no_skill_hint: bool,
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
        /// File holding the token of the session to end, instead of
        /// TOKENLESS_SESSION_TOKEN.
        #[arg(long, conflicts_with = "id")]
        session_token_file: Option<PathBuf>,
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
    /// Add a service from a template: stores its credential encrypted and
    /// lets the access bundle use it. The credential comes from a prompt
    /// that does not echo it, standard input when piped (one field), a file
    /// the person fills in (--secret-file), or the console (--web). The last
    /// two let an agent run this for a person without seeing the secret.
    ///
    /// Examples:
    ///   tokenless service add github --vault work --bundle code-review
    ///   gh auth token | tokenless service add github --vault work --bundle code-review
    ///   tokenless service add openai --vault personal --bundle my-agent --secret-file
    ///   tokenless service add openai --vault personal --bundle my-agent --web --open
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
        /// Read the credential from a file the person fills in, and wipe and
        /// delete it once the credential is stored. The file is created
        /// (mode 0600) if missing, at ~/.tokenless/incoming/<template>
        /// without a path, and the command waits until it is saved. A file
        /// that was already there is only deleted once its key is stored.
        #[arg(long, value_name = "PATH", num_args = 0..=1, default_missing_value = "", conflicts_with = "web")]
        secret_file: Option<String>,
        /// Don't take the credential here: print the console page that adds
        /// this service, where the person types it, and wait until it is saved.
        #[arg(long, conflicts_with_all = ["name", "read_only"])]
        web: bool,
        /// Open the page (--web) in the browser, or the file (--secret-file)
        /// in the text editor.
        #[arg(long)]
        open: bool,
        /// How long --secret-file and --web wait for the person: 90s, 15m, 1h.
        #[arg(long, default_value = "15m", value_parser = parse_wait)]
        wait: Duration,
        /// With --web, print the page and exit without waiting.
        #[arg(long, requires = "web")]
        no_wait: bool,
        /// Print the result as JSON.
        #[arg(long)]
        json: bool,
        /// Management API URL.
        #[arg(long, env = "TOKENLESS_URL", default_value = "http://127.0.0.1:8080")]
        server: String,
    },
    /// Find the template for a service by its ID, name, host or the
    /// variable a tool reads its key from. Lists the control plane's
    /// templates when signed in, the built-in ones otherwise.
    ///
    /// Examples:
    ///   tokenless service templates OPENAI_API_KEY
    ///   tokenless service templates api.github.com --json
    #[command(verbatim_doc_comment)]
    Templates {
        /// Part of an ID, name, alias, host or variable; all when left out.
        query: Option<String>,
        /// Print the templates as JSON, with their fields and hosts.
        #[arg(long)]
        json: bool,
        /// Management API URL.
        #[arg(long, env = "TOKENLESS_URL", default_value = "http://127.0.0.1:8080")]
        server: String,
    },
}

fn parse_wait(raw: &str) -> Result<Duration, String> {
    parse_duration_secs(raw)
        .map(Duration::from_secs)
        .map_err(|e| e.to_string())
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
        /// On Ctrl-C or SIGTERM, seconds open tunnels get to finish before
        /// they are cut. A second signal cuts them at once.
        #[arg(long, default_value_t = 30)]
        drain_secs: u64,
    },
}

/// Servers log to stdout at `info`. Agent-side commands log to stderr at
/// `warn`, because stdout belongs to the token or to the agent. When
/// `telemetry` sends logs, the same events also go to OpenTelemetry.
fn init_logging(agent_side: bool, telemetry: &Telemetry) {
    let default = if agent_side { "warn" } else { "info" };
    let filter = || EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
    let writer = if agent_side {
        BoxMakeWriter::new(std::io::stderr)
    } else {
        BoxMakeWriter::new(std::io::stdout)
    };
    let stdout = tracing_subscriber::fmt::layer()
        .json()
        .with_current_span(false)
        .with_writer(writer)
        .with_filter(filter().and(filter_fn(|meta| {
            telemetry::shown_locally(meta.target(), meta.level())
        })));
    tracing_subscriber::registry()
        .with(stdout)
        .with(telemetry.log_layer(filter()))
        .init();
}

/// Starts OpenTelemetry export for the server commands, from the `OTEL_*`
/// variables. Agent-side commands send nothing. A setup failure is
/// returned to be logged once logging is up; the server runs without it.
fn start_telemetry(command: &Command) -> (Telemetry, TelemetrySettings, Option<String>) {
    let node_id;
    let component = match command {
        Command::Serve(_) => Component::ControlPlane,
        Command::Node {
            command: NodeCommand::Run { state, .. },
        } => {
            node_id = NodeIdentity::load(state)
                .ok()
                .map(|i| i.node_id.to_string());
            Component::Proxy {
                node_id: node_id.as_deref(),
            }
        }
        _ => return (Telemetry::default(), TelemetrySettings::default(), None),
    };
    let settings = TelemetrySettings::from_process_env();
    match Telemetry::start(&settings, component) {
        Ok(telemetry) => (telemetry, settings, None),
        Err(e) => (Telemetry::default(), settings, Some(e.to_string())),
    }
}

/// Says what the `OTEL_*` variables turned on, and what was ignored.
fn report_telemetry(telemetry: &Telemetry, settings: &TelemetrySettings, failed: Option<String>) {
    for ignored in &settings.ignored {
        warn!(setting = %ignored, "OpenTelemetry setting ignored");
    }
    if let Some(error) = failed {
        error!(%error, "OpenTelemetry export is off: it could not be set up");
    }
    if telemetry.sends_logs() {
        info!(endpoint = %settings.logs_to, "sending logs to OpenTelemetry");
    }
    if telemetry.sends_metrics() {
        info!(endpoint = %settings.metrics_to, "sending proxy metrics to OpenTelemetry");
    }
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error(transparent)]
    Server(#[from] broker_server::ServerError),
    #[error(transparent)]
    DataPlane(#[from] tokenless_dataplane::DataPlaneError),
    #[error(transparent)]
    Launcher(#[from] LauncherError),
    #[error(transparent)]
    Update(#[from] UpdateError),
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
        out.extend(tokenless_dataplane::tls::certs_from_pem(
            &path.display().to_string(),
            &pem,
        )?);
    }
    Ok(out)
}

#[cfg(not(unix))]
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
    let signal = stop_signal().await?;
    info!(signal, "shutting down");
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
            .map_err(|e| no_terminal(label, e))
    }
}

/// Why a prompt failed. Without a terminal (an agent or a script ran the
/// command) it says how to get past the prompt instead.
fn no_terminal(label: &str, e: std::io::Error) -> LauncherError {
    let terminal = std::fs::File::open(if cfg!(windows) { "CONIN$" } else { "/dev/tty" }).is_ok();
    if terminal {
        return LauncherError::io(format!("reading {label} from the terminal"))(e);
    }
    LauncherError::config(format!(
        "this needs {label}, and there is no terminal to type it in. Run tokenless login in a terminal (a sign-in also confirms it is you for a few minutes), then run this again; for a credential, pass --secret-file or --web instead"
    ))
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
    offer_skill();
    Ok(ExitCode::SUCCESS)
}

/// [`skill::missing_hint`] from where `run` was started.
fn skill_hint(program: &str) -> Option<&'static str> {
    let cwd = std::env::current_dir().ok()?;
    let home = home_dir();
    skill::missing_hint(program, &cwd, home.as_deref())
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
}

/// After signing in at a terminal, offers to install the skill for Claude
/// Code when it is set up here and has no copy. Declining changes nothing,
/// and a failed install doesn't undo the sign-in.
fn offer_skill() {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return;
    }
    let Ok(cwd) = std::env::current_dir() else {
        return;
    };
    let Some(dir) = skill::install_offer(&cwd, home_dir().as_deref()) else {
        return;
    };
    let question = format!(
        "tokenless: install the agent skill for Claude Code in {}?",
        dir.display()
    );
    match skill::ask_yes(
        &question,
        &mut std::io::stdin().lock(),
        &mut std::io::stderr(),
    ) {
        Ok(true) => match skill::install(&dir, false) {
            Ok((path, _)) => say(format_args!("installed {}", path.display())),
            Err(e) => say(format_args!("the skill was not installed: {e}")),
        },
        Ok(false) => say("skipped; install it later with: tokenless skill --install"),
        Err(e) => say(format_args!("the skill was not installed: {e}")),
    }
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
    template: &tokenless_control::model::StoredTemplate,
    prompter: &dyn Prompter,
) -> Result<BTreeMap<String, Zeroizing<String>>, CliError> {
    use std::io::{IsTerminal, Read};
    let fields = &template.template.credential_fields;
    let mut out = BTreeMap::new();
    if !std::io::stdin().is_terminal() {
        let [only] = fields.as_slice() else {
            return Err(LauncherError::config(format!(
                "template '{}' has {} credential fields; run this in a terminal to be asked for each, or use --secret-file or --web",
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
                LauncherError::config("standard input was empty; pipe the credential in, or let the person enter it with --secret-file or --web").into(),
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
            secret_file,
            web,
            open,
            wait,
            no_wait,
            json,
            server,
        } => {
            let source = match (web, secret_file) {
                (true, _) => setup::Source::Web { open },
                (false, Some(path)) => setup::Source::File {
                    path: PathBuf::from(path),
                    open,
                },
                (false, None) => setup::Source::Terminal,
            };
            setup::add_service(setup::AddArgs {
                template,
                vault,
                bundle,
                name,
                read_only,
                server,
                source,
                wait: (!no_wait).then_some(wait),
                json,
            })
            .await
        }
        ServiceCommand::Templates {
            query,
            json,
            server,
        } => setup::templates_command(query, json, server).await,
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

/// How a command stopped. Told to stop at once, the process leaves the
/// OpenTelemetry data still queued unsent rather than wait on the collector.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Stopped {
    Normally,
    AtOnce,
}

async fn node(command: NodeCommand, telemetry: &Telemetry) -> Result<Stopped, CliError> {
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
            Ok(Stopped::Normally)
        }
        NodeCommand::Run {
            state,
            listen,
            metrics_listen,
            mcp_listen,
            no_mcp_gateway,
            upstream_ca,
            no_public_roots,
            drain_secs,
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
            telemetry.watch_proxy(dp.metrics());
            let signal = stop_signal().await?;
            info!(signal, drain_secs, "shutting down; open tunnels may finish");
            let report = tokio::select! {
                report = dp.shutdown(Duration::from_secs(drain_secs)) => report,
                _ = stop_signal() => {
                    warn!("second stop signal: stopping without draining");
                    return Ok(Stopped::AtOnce);
                }
            };
            if !report.clean() {
                warn!(
                    cut_connections = report.cut_connections,
                    unshipped_audit_events = report.unshipped_audit_events,
                    "node stopped with traffic cut or audit events unshipped"
                );
            }
            Ok(Stopped::Normally)
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
    signed_in_client(args, &SessionStore::system())
}

/// The client `run` and `session start` use. A given session token needs no
/// sign-in: it authenticates its own calls and the CA download is public. So
/// with one, neither the API key nor the `tokenless login` session is read,
/// and the OS keychain stays closed (macOS asks to unlock it again for each
/// new build of the binary).
fn launcher_client(
    args: &BrokerArgs,
    given: bool,
    saved: &dyn SessionVault,
) -> Result<Arc<ApiClient>, CliError> {
    if given {
        return Ok(Arc::new(ApiClient::new(&args.server, None)?));
    }
    signed_in_client(args, saved)
}

fn signed_in_client(
    args: &BrokerArgs,
    saved: &dyn SessionVault,
) -> Result<Arc<ApiClient>, CliError> {
    let credentials = match read_api_key(args)? {
        Some(key) => Some(Credentials::ApiKey(key)),
        None => {
            let server = args.server.trim().trim_end_matches('/');
            // A session store that cannot be read is the same as not signed
            // in: the error then says how to authenticate.
            match saved.load(server) {
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

/// How long each session `run` mints lasts when --ttl is not given.
const DEFAULT_RUN_TTL: &str = "15m";

/// `run` and `session start` either mint a session or adopt one, so with
/// neither a bundle nor a session they name both ways.
fn bundle_or_session(args: &MintArgs) -> Result<(), CliError> {
    if args.bundle.is_none() {
        return Err(LauncherError::config(
            "say which access bundle to mint the session from with --bundle (or TOKENLESS_BUNDLE), or set TOKENLESS_SESSION_TOKEN to a session you already have",
        )
        .into());
    }
    mint_request(args, &[]).map(|_| ())
}

fn mint_request(args: &MintArgs, extra: &[(&str, String)]) -> Result<MintRequest, CliError> {
    let Some(bundle) = args.bundle.clone() else {
        return Err(LauncherError::config(
            "say which access bundle to mint the session from with --bundle (or TOKENLESS_BUNDLE)",
        )
        .into());
    };
    // The broker enforces its own cap (Settings → Session lifetime) and
    // names it in the error; the session port renews, so short is fine.
    let ttl_secs = parse_duration_secs(args.ttl.as_deref().unwrap_or(DEFAULT_RUN_TTL))?;
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
/// A bundle and a token together are refused rather than guessed between,
/// and so are the flags that shape a new session: a given one keeps the
/// lifetime, request limit and labels it was created with.
fn given_session(
    mint: &MintArgs,
    given: &GivenSessionArgs,
    from_env: Option<Zeroizing<String>>,
) -> Result<Option<Zeroizing<String>>, CliError> {
    let token = if let Some(path) = &given.session_token_file {
        read_token_file(path)?
    } else {
        let Some(token) = from_env else {
            return Ok(None);
        };
        if let Some(bundle) = &mint.bundle {
            return Err(LauncherError::config(format!(
                "both a bundle to mint a session from ('{bundle}') and TOKENLESS_SESSION_TOKEN are set; unset one"
            ))
            .into());
        }
        Zeroizing::new(token.trim().to_string())
    };
    let shaping: Vec<&str> = [
        ("--ttl", mint.ttl.is_some()),
        ("--request-limit", mint.request_limit.is_some()),
        ("--name", mint.name.is_some()),
        ("--label", !mint.labels.is_empty()),
    ]
    .into_iter()
    .filter_map(|(flag, set)| set.then_some(flag))
    .collect();
    if !shaping.is_empty() {
        return Err(LauncherError::config(format!(
            "{} only apply to a session minted with --bundle; a given session token keeps the lifetime, request limit and labels it was created with (create a new session to change them)",
            shaping.join(", ")
        ))
        .into());
    }
    Ok(Some(token))
}

fn read_token_file(path: &std::path::Path) -> Result<Zeroizing<String>, CliError> {
    let token = Zeroizing::new(std::fs::read_to_string(path).map_err(|e| CliError::Io {
        context: format!("reading the session token file {}", path.display()),
        source: e,
    })?);
    Ok(Zeroizing::new(token.trim().to_string()))
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
    session: &'a tokenless_control::model::ProxySession,
}

async fn session(command: SessionCommand, verbose: bool) -> Result<ExitCode, CliError> {
    match command {
        SessionCommand::Create { mint, json } => {
            // A missing bundle fails before any network call.
            let request = mint_request(&mint, &[])?;
            let client = client(&mint.broker)?;
            let vault = client.resolve_vault(mint.vault.as_deref()).await?;
            let minted = client.mint(&vault, &request).await?;
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
        SessionCommand::Revoke {
            broker,
            id,
            session_token_file,
        } => {
            let session = match id {
                Some(id) => client(&broker)?.revoke_by_id(&id).await?,
                None => {
                    // A session ends itself with its own token, so no
                    // sign-in is read (and no keychain is opened).
                    let token = match &session_token_file {
                        Some(path) => read_token_file(path)?,
                        None => session_token_from_env()?,
                    };
                    ApiClient::new(&broker.server, None)?
                        .revoke_self(&token)
                        .await?
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
                bundle_or_session(&mint)?;
            }
            check_listen(listen)?;
            check_proxy(&port.proxy).await?;
            let client = launcher_client(&mint.broker, given.is_some(), &SessionStore::system())?;
            let dir = private_dir()?;
            let (trust, ca) = prepare_trust(&client, &port, dir.path()).await?;
            let live = open_session(&client, &mint, given, &[]).await?;
            let session_port =
                match SessionPort::start(listen, &port.proxy, live.auth.clone(), live.listing())
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
        bundle_or_session(&args.mint)?;
    }
    check_listen(args.listen)?;
    check_proxy(&args.port.proxy).await?;
    let client = launcher_client(&args.mint.broker, given.is_some(), &SessionStore::system())?;
    let dir = private_dir()?;
    let (trust, _) = prepare_trust(&client, &args.port, dir.path()).await?;
    let live = open_session(&client, &args.mint, given, &[("command", name.clone())]).await?;
    let session_port = match SessionPort::start(
        args.listen,
        &args.port.proxy,
        live.auth.clone(),
        live.listing(),
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
    if !args.no_skill_hint && std::io::IsTerminal::is_terminal(&std::io::stderr()) {
        if let Some(hint) = skill_hint(&name) {
            say(hint);
        }
    }
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

/// `--check` exits with this when a newer release exists.
const UPDATE_AVAILABLE: u8 = 10;

/// What `--check` says when `latest` is out: how to update, which in the
/// container `image` is pulling the new tag.
fn available(image: Option<&str>, current: &semver::Version, latest: &semver::Version) -> String {
    match image {
        Some(image) => format!(
            "{latest} is available (this is {current}); pull {image}:{latest} and recreate the container"
        ),
        None => format!("{latest} is available (this is {current}); update with: tokenless update"),
    }
}

async fn update_command(args: UpdateArgs) -> Result<ExitCode, CliError> {
    let image = std::env::var(update::CONTAINER_IMAGE_ENV).ok();
    if let (Some(image), false) = (&image, args.check) {
        return Err(UpdateError::Container {
            image: image.clone(),
        }
        .into());
    }
    let installed = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .map_err(|e| CliError::Io {
            context: "finding this binary".into(),
            source: e,
        })?;
    let current = update::parse_tag(update::VERSION)?;
    let options = update::Options {
        mirror: args.download_url,
        wanted: match args.release {
            Some(tag) => update::Wanted::Release(tag),
            None => update::Wanted::Latest,
        },
        check_only: args.check,
        cosign: update::find_on_path("cosign"),
        require_signature: args.require_signature,
        ca_file: args.download_ca,
        ..update::Options::new(args.repo)
    };
    // A stop signal (Ctrl-C, or systemd stopping the update's unit) ends the
    // update here, so what it staged next to the binary is removed.
    let interrupted = async {
        match stop_signal().await {
            Ok(signal) => signal,
            Err(_) => std::future::pending().await,
        }
    };
    let outcome = tokio::select! {
        outcome = update::update(&options, &installed, &current) => outcome?,
        signal = interrupted => {
            return Err(UpdateError::Interrupted {
                signal,
                binary: installed.display().to_string(),
            }
            .into())
        }
    };
    match outcome {
        UpdateOutcome::UpToDate { current, latest } if latest < current => {
            say(format_args!(
                "this is {current}, newer than the latest release {latest}"
            ));
            Ok(ExitCode::SUCCESS)
        }
        UpdateOutcome::UpToDate { current, .. } => {
            say(format_args!("{current} is the latest release"));
            Ok(ExitCode::SUCCESS)
        }
        UpdateOutcome::Available { current, latest } => {
            say(available(image.as_deref(), &current, &latest));
            Ok(ExitCode::from(UPDATE_AVAILABLE))
        }
        UpdateOutcome::Updated {
            path,
            from,
            to,
            signature_verified,
        } => {
            let checked = if signature_verified {
                "checksum and signature verified"
            } else {
                "checksum verified; install cosign to also verify the signature"
            };
            say(format_args!(
                "updated {} from {from} to {to} ({checked})",
                path.display()
            ));
            say("restart tokenless serve and tokenless node run to use it");
            Ok(ExitCode::SUCCESS)
        }
    }
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
            | Command::Status { .. }
            | Command::Proxy { .. }
            | Command::Update(_)
    );
    let (telemetry, settings, failed) = start_telemetry(&cli.command);
    init_logging(agent_side, &telemetry);
    report_telemetry(&telemetry, &settings, failed);
    let mut stopped = Stopped::Normally;
    let result = match cli.command {
        Command::Serve(args) => serve(args).await.map(|()| ExitCode::SUCCESS),
        Command::Node { command } => node(command, &telemetry).await.map(|how| {
            stopped = how;
            ExitCode::SUCCESS
        }),
        Command::Admin { command } => admin(command).await.map(|()| ExitCode::SUCCESS),
        Command::Login { server, username } => login(server, username).await,
        Command::Logout { server } => logout(server).await,
        Command::Service { command } => service(command).await,
        Command::Status { json, server } => setup::status_command(server, json).await,
        Command::Proxy { command } => proxy(command).await,
        Command::Session { command } => session(command, cli.verbose).await,
        Command::Run(args) => run(args, cli.verbose).await,
        Command::Mcp(args) => mcp_command(args).await,
        Command::Skill {
            install,
            dir,
            force,
        } => skill_command(install, dir, force),
        Command::Update(args) => update_command(args).await,
    };
    let code = match result {
        Ok(code) => code,
        Err(e) => {
            if agent_side {
                eprintln!("tokenless: {e}");
            } else {
                error!(error = %e, "tokenless exited with an error");
            }
            ExitCode::FAILURE
        }
    };
    match stopped {
        Stopped::AtOnce => telemetry.abandon(),
        // Sending what is queued can take the exporters' timeouts; a stop
        // signal meanwhile ends the wait.
        Stopped::Normally => tokio::select! {
            () = telemetry.shutdown() => {}
            () = async {
                if stop_signal().await.is_err() {
                    std::future::pending::<()>().await;
                }
            } => warn!("stop signal: exiting without sending the OpenTelemetry data still queued"),
        },
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_check_in_the_container_says_to_pull_the_image() {
        let (current, latest) = (semver::Version::new(0, 2, 0), semver::Version::new(0, 3, 0));
        assert_eq!(
            available(None, &current, &latest),
            "0.3.0 is available (this is 0.2.0); update with: tokenless update"
        );
        assert_eq!(
            available(Some("ghcr.io/o/tokenless"), &current, &latest),
            "0.3.0 is available (this is 0.2.0); pull ghcr.io/o/tokenless:0.3.0 and recreate the container"
        );
    }

    #[test]
    fn the_version_is_the_build_s_own() {
        let cli = Cli::try_parse_from(["tokenless", "--version"]);
        let Err(e) = cli else {
            panic!("--version prints and exits");
        };
        assert_eq!(
            e.to_string().trim(),
            format!("tokenless {}", update::VERSION)
        );
    }

    /// The `tokenless ...` commands in `md`, each with whether it is a whole
    /// command line (in a shell block, `\` continuations joined) or inline
    /// code, which may only name one (`tokenless run`). Words before a pipe
    /// and `NAME=value` in front are dropped; spans with `<...>` or `...` in
    /// them are patterns and are left out.
    fn suggested_commands(md: &str) -> Vec<(String, bool)> {
        let mut found = Vec::new();
        let mut keep = |span: &str, whole: bool| {
            let span = span.split(" #").next().unwrap_or(span);
            let span = span.rsplit('|').next().unwrap_or(span).trim();
            let words: Vec<&str> = span
                .split_whitespace()
                .skip_while(|w| w.contains('=') && !w.starts_with('-'))
                .collect();
            if words.first() == Some(&"tokenless") && !span.contains('<') && !span.contains("...") {
                found.push((words.join(" "), whole));
            }
        };
        let mut fenced = false;
        let mut command = String::new();
        for line in md.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("```") {
                fenced = !fenced;
                continue;
            }
            if fenced {
                command.push_str(trimmed.trim_end_matches('\\'));
                command.push(' ');
                if !trimmed.ends_with('\\') {
                    keep(&command, true);
                    command.clear();
                }
            } else {
                for span in line.split('`').skip(1).step_by(2) {
                    keep(span, false);
                }
            }
        }
        found
    }

    #[test]
    fn every_command_the_skill_suggests_exists() {
        // An agent runs, or hands the user, what the skill says word for
        // word, so a renamed command or flag must fail here first.
        let commands = suggested_commands(skill::SKILL_MD);
        for wanted in [
            "tokenless serve --data-dir ~/.tokenless",
            "tokenless status --json",
            "tokenless service templates OPENAI_API_KEY --json",
            "tokenless service add openai --vault personal --bundle my-agent --secret-file --open",
            "tokenless service add openai --vault personal --bundle my-agent --web --open",
            "tokenless proxy add --name laptop --state ~/.tokenless/node.json",
            "tokenless node run --state ~/.tokenless/node.json",
            "tokenless run --vault personal --bundle my-agent -- claude",
        ] {
            assert!(
                commands.iter().any(|(c, _)| c == wanted),
                "{wanted}: {commands:#?}"
            );
        }
        for (command, whole) in &commands {
            let Err(e) = Cli::try_parse_from(command.split_whitespace()) else {
                continue;
            };
            // Naming a command leaves out what it needs; it still has to
            // name commands and flags that exist.
            let unknown = matches!(
                e.kind(),
                clap::error::ErrorKind::UnknownArgument | clap::error::ErrorKind::InvalidSubcommand
            );
            if *whole || unknown {
                panic!("the skill suggests `{command}`, which does not parse:\n{e}");
            }
        }
    }

    #[test]
    fn the_skill_keeps_keys_and_identities_out_of_the_project() {
        // The skill's setup runs in the user's project, where `./data` and
        // `./node.json` (the root key, the proxy's private keys) would sit
        // one `git add .` away from a commit. Every command that writes one
        // names a path in the home directory.
        let outside = |path: &std::path::Path| path.starts_with("~/") || path.is_absolute();
        for (command, whole) in suggested_commands(skill::SKILL_MD) {
            let Ok(cli) = Cli::try_parse_from(command.split_whitespace()) else {
                continue;
            };
            let written = match &cli.command {
                Command::Serve(args) => &args.data_dir,
                Command::Proxy {
                    command: ProxyCommand::Add { state, .. },
                }
                | Command::Node {
                    command: NodeCommand::Join { state, .. } | NodeCommand::Run { state, .. },
                } => state,
                _ => continue,
            };
            assert!(whole, "`{command}` is only named, never shown in full");
            assert!(
                outside(written),
                "the skill suggests `{command}`, which writes {} in the project",
                written.display()
            );
        }
    }

    #[test]
    fn update_check_does_not_take_a_release() {
        // A check says whether a newer release exists; a named one is no answer.
        assert!(Cli::try_parse_from(["tokenless", "update", "--check"]).is_ok());
        assert!(Cli::try_parse_from(["tokenless", "update", "--release", "v0.1.0"]).is_ok());
        assert!(
            Cli::try_parse_from(["tokenless", "update", "--check", "--release", "v0.1.0"]).is_err()
        );
    }

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

    #[test]
    fn run_can_be_told_not_to_mention_the_skill() {
        assert!(run_args(&["--no-skill-hint"]).no_skill_hint);
        assert!(!run_args(&[]).no_skill_hint);
    }

    fn token(value: &str) -> Option<Zeroizing<String>> {
        Some(Zeroizing::new(value.to_string()))
    }

    /// A session store that counts how often it is read.
    #[derive(Default)]
    struct CountingVault(std::sync::atomic::AtomicUsize);

    impl SessionVault for CountingVault {
        fn load(&self, _server: &str) -> Result<Option<account::SavedSession>, LauncherError> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(None)
        }
        fn save(&self, _session: &account::SavedSession) -> Result<(), LauncherError> {
            Ok(())
        }
        fn delete(&self, _server: &str) -> Result<bool, LauncherError> {
            Ok(false)
        }
    }

    #[test]
    fn a_given_session_token_never_opens_the_saved_sign_in() {
        let args = run_args(&["--server", "http://127.0.0.1:9"]);
        let vault = CountingVault::default();
        launcher_client(&args.mint.broker, true, &vault).unwrap();
        assert_eq!(vault.0.load(std::sync::atomic::Ordering::SeqCst), 0);
        // Minting from a bundle signs in, so it reads the saved session
        // (unless an API key is set, which comes first).
        if std::env::var_os("TOKENLESS_API_KEY").is_none() {
            launcher_client(&args.mint.broker, false, &vault).unwrap();
            assert_eq!(vault.0.load(std::sync::atomic::Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn a_session_ends_itself_from_a_token_file_or_by_id_never_both() {
        let parse = |args: &[&str]| {
            Cli::try_parse_from(["tokenless", "session", "revoke"].iter().chain(args)).map(|_| ())
        };
        assert!(parse(&["--session-token-file", "token.txt"]).is_ok());
        assert!(parse(&["--id", "4729a575-c2bb-4348-a77b-14aae3808e16"]).is_ok());
        assert!(parse(&["--session-token-file", "token.txt", "--id", "x"]).is_err());
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
        // Flags that shape a new session are refused with a given one,
        // rather than ignored.
        let err = given(
            &["--request-limit", "10", "--ttl", "1h"],
            token("v4.public.abc"),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.starts_with("--ttl, --request-limit only apply"),
            "{err}"
        );
        assert!(given(&["--name", "x"], token("v4.public.abc")).is_err());
        assert!(given(&["--label", "a=b"], token("v4.public.abc")).is_err());
        // Neither: minting then asks for a bundle.
        let none = run_args(&[]);
        assert_eq!(given(&[], None).unwrap(), None);
        let err = bundle_or_session(&none.mint).unwrap_err().to_string();
        assert!(err.contains("TOKENLESS_SESSION_TOKEN"), "{err}");
        // `session create` only mints, so it doesn't suggest a session token
        // it would never read.
        let err = mint_request(&none.mint, &[]).unwrap_err().to_string();
        assert!(err.contains("--bundle"), "{err}");
        assert!(!err.contains("TOKENLESS_SESSION_TOKEN"), "{err}");
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
