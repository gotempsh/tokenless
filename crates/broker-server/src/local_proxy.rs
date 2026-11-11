// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The proxy `serve` runs for agents on its own machine, so one command is
//! enough to try tokenless: `serve`, then `tokenless run -- <agent>`.
//!
//! It is an ordinary proxy (a node) of this control plane, listed under
//! Proxies like any other: on its first start the server mints a join
//! token for itself, enrols over its own node API on loopback, and keeps
//! the identity in the data directory. Later starts reuse it. A proxy
//! whose certificate lapsed while the server was stopped is replaced (the
//! old one revoked); one an admin revoked stays off until its identity file
//! is removed. A server whose proxies run on the agents' machines starts
//! with `--no-proxy` (or `TOKENLESS_NO_BUILTIN_PROXY=1`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::Utc;
use thiserror::Error;
use tokenless_control::{Caller, ControlError, ControlPlane};
use tokenless_core::authz::{Principal, Role};
use tokenless_dataplane::{enroll, DataPlane, DataPlaneConfig, DataPlaneError, NodeIdentity};
use tracing::{info, warn};

/// The name it is listed under in Proxies.
pub const NODE_NAME: &str = "built-in (this server)";
/// Where its identity lives in the data directory.
pub const STATE_FILE: &str = "builtin-proxy.json";
/// How long the join token it mints for itself is valid.
const JOIN_TOKEN_TTL_SECS: u64 = 60;
/// How long `start` waits for its first policy snapshot, so `serve` does
/// not announce a proxy that still refuses everything.
const FIRST_SNAPSHOT_WAIT: Duration = Duration::from_secs(10);

#[derive(Debug, Error)]
pub enum LocalProxyError {
    #[error(
        "the built-in proxy ({node_id}) was revoked in the console, so it stays off; remove {state} to enrol it again, or start with --no-proxy"
    )]
    Revoked { node_id: String, state: String },

    #[error(
        "could not enrol the built-in proxy with this server's node API at {control_url}: {source}; start with --no-proxy to run without it"
    )]
    Enrol {
        control_url: String,
        #[source]
        source: DataPlaneError,
    },

    #[error("could not start the built-in proxy: {listen} is taken ({source}); if another proxy already listens there, start with --no-proxy, or move this one with {flag}")]
    PortTaken {
        listen: SocketAddr,
        flag: &'static str,
        #[source]
        source: std::io::Error,
    },

    #[error("could not start the built-in proxy on {listen}: {source}; start with --no-proxy to run without it")]
    Start {
        listen: SocketAddr,
        #[source]
        source: DataPlaneError,
    },

    #[error("could not use the built-in proxy's identity {state}: {source}")]
    Identity {
        state: String,
        #[source]
        source: DataPlaneError,
    },

    #[error("the built-in proxy could not {operation}: {source}")]
    Control {
        operation: &'static str,
        #[source]
        source: ControlError,
    },
}

/// Where it listens.
#[derive(Debug, Clone)]
pub struct LocalProxyConfig {
    pub listen: SocketAddr,
    /// The MCP gateway, if any.
    pub mcp_listen: Option<SocketAddr>,
    /// Its identity file, normally `<data dir>/builtin-proxy.json`.
    pub state: PathBuf,
}

impl LocalProxyConfig {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 3128)),
            mcp_listen: Some(SocketAddr::from(([127, 0, 0, 1], 3129))),
            state: data_dir.join(STATE_FILE),
        }
    }
}

/// The built-in proxy, running.
pub struct LocalProxy {
    pub listen: SocketAddr,
    pub mcp: Option<SocketAddr>,
    /// Whether it enrolled on this start rather than reusing its identity.
    pub enrolled: bool,
    /// Whether it had its policy by the time `start` returned; if not it
    /// keeps asking, and refuses traffic until it has.
    pub ready: bool,
    data_plane: DataPlane,
}

impl LocalProxy {
    /// Stops accepting, lets open tunnels finish for up to `drain`.
    pub async fn shutdown(self, drain: Duration) {
        let report = self.data_plane.shutdown(drain).await;
        if !report.clean() {
            warn!(
                cut_connections = report.cut_connections,
                unshipped_audit_events = report.unshipped_audit_events,
                "built-in proxy stopped with traffic cut or audit events unshipped"
            );
        }
    }
}

/// The server acting for itself, in the audit log as `service:serve`.
fn server_caller() -> Caller {
    Caller::service(Principal::service("serve", Role::Admin, None))
}

/// The address the built-in proxy dials the node API listening on
/// `node_listen` at: a wildcard listener on loopback.
fn dial_ip(node_listen: SocketAddr) -> IpAddr {
    match node_listen.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    }
}

/// The node API as this host reaches it.
fn node_api_url(node_addr: SocketAddr) -> String {
    format!(
        "https://{}",
        SocketAddr::new(dial_ip(node_addr), node_addr.port())
    )
}

/// Adds the address the built-in proxy dials to the node API
/// certificate's names: `--node-api-name` replaces the loopback defaults,
/// and a certificate without that address fails the proxy's TLS check.
pub fn add_dial_name(names: &mut Vec<String>, node_listen: SocketAddr) {
    let ip = dial_ip(node_listen);
    if !names.iter().any(|n| n.parse::<IpAddr>().ok() == Some(ip)) {
        names.push(ip.to_string());
    }
}

/// Fails with the flag that moves it when `listen` is taken, before the
/// proxy enrols, so a taken port leaves nothing behind in Proxies.
fn check_free(listen: SocketAddr, flag: &'static str) -> Result<(), LocalProxyError> {
    std::net::TcpListener::bind(listen)
        .map(drop)
        .map_err(|source| LocalProxyError::PortTaken {
            listen,
            flag,
            source,
        })
}

/// What to do with the identity on disk.
enum Existing {
    None,
    Use(Box<NodeIdentity>),
    Replace(Box<NodeIdentity>),
}

async fn existing(
    control: &ControlPlane,
    node_addr: SocketAddr,
    config: &LocalProxyConfig,
) -> Result<Existing, LocalProxyError> {
    if !config.state.exists() {
        return Ok(Existing::None);
    }
    let state = config.state.display().to_string();
    let mut identity =
        NodeIdentity::load(&config.state).map_err(|source| LocalProxyError::Identity {
            state: state.clone(),
            source,
        })?;
    let node = match control
        .nodes
        .get_node(&server_caller(), &identity.node_id)
        .await
    {
        Ok(node) => node,
        // Enrolled with another database: start over.
        Err(ControlError::NotFound { .. }) => return Ok(Existing::Replace(Box::new(identity))),
        Err(source) => {
            return Err(LocalProxyError::Control {
                operation: "look itself up",
                source,
            })
        }
    };
    if node.revoked_at.is_some() {
        return Err(LocalProxyError::Revoked {
            node_id: node.id.to_string(),
            state,
        });
    }
    if node.cert_not_after <= Utc::now() {
        return Ok(Existing::Replace(Box::new(identity)));
    }
    // The node API moved (another --node-listen) since it enrolled: same
    // server, same certificate, a new address to dial.
    let control_url = node_api_url(node_addr);
    if identity.control_url != control_url {
        info!(from = %identity.control_url, to = %control_url, "built-in proxy follows the node API to its new address");
        identity.control_url = control_url;
        identity
            .save(&config.state)
            .map_err(|source| LocalProxyError::Identity { state, source })?;
    }
    Ok(Existing::Use(Box::new(identity)))
}

async fn enrol(
    control: &ControlPlane,
    node_addr: SocketAddr,
    state: &Path,
) -> Result<NodeIdentity, LocalProxyError> {
    let issued = control
        .nodes
        .create_join_token(&server_caller(), Some(JOIN_TOKEN_TTL_SECS))
        .await
        .map_err(|source| LocalProxyError::Control {
            operation: "mint its join token",
            source,
        })?;
    let control_url = node_api_url(node_addr);
    let identity = enroll(&control_url, &issued.token, NODE_NAME)
        .await
        .map_err(|source| LocalProxyError::Enrol {
            control_url: control_url.clone(),
            source,
        })?;
    identity
        .save(state)
        .map_err(|source| LocalProxyError::Identity {
            state: state.display().to_string(),
            source,
        })?;
    info!(node_id = %identity.node_id, state = %state.display(), "built-in proxy enrolled");
    Ok(identity)
}

/// Starts the built-in proxy of the server whose node API listens on
/// `node_addr`, enrolling it first when it has no identity yet.
pub async fn start(
    control: &ControlPlane,
    node_addr: SocketAddr,
    config: LocalProxyConfig,
) -> Result<LocalProxy, LocalProxyError> {
    check_free(config.listen, "--proxy-listen")?;
    if let Some(mcp) = config.mcp_listen {
        check_free(mcp, "--proxy-mcp-listen")?;
    }
    let (identity, enrolled) = match existing(control, node_addr, &config).await? {
        Existing::Use(identity) => (*identity, false),
        Existing::None => (enrol(control, node_addr, &config.state).await?, true),
        Existing::Replace(old) => {
            // Its certificate lapsed while the server was stopped, or it
            // belongs to another database: retire it so Proxies lists one.
            if let Err(e) = control
                .nodes
                .revoke_node(&server_caller(), &old.node_id)
                .await
            {
                if !matches!(e, ControlError::NotFound { .. }) {
                    warn!(node_id = %old.node_id, error = %e, "could not revoke the built-in proxy's old identity");
                }
            }
            (enrol(control, node_addr, &config.state).await?, true)
        }
    };
    let node_id = identity.node_id;
    let started = DataPlane::start(
        DataPlaneConfig {
            listen: config.listen,
            mcp_listen: config.mcp_listen,
            state_path: Some(config.state.clone()),
            ..DataPlaneConfig::default()
        },
        identity,
    )
    .await;
    let data_plane = match started {
        Ok(data_plane) => data_plane,
        Err(source) => {
            if enrolled {
                // Enrolled for nothing (a port taken since the check):
                // leave no proxy behind that never connects.
                if let Err(e) = control.nodes.revoke_node(&server_caller(), &node_id).await {
                    warn!(node_id = %node_id, error = %e, "could not revoke the built-in proxy that failed to start");
                }
                if let Err(e) = std::fs::remove_file(&config.state) {
                    warn!(state = %config.state.display(), error = %e, "could not remove the built-in proxy's identity");
                }
            }
            return Err(LocalProxyError::Start {
                listen: config.listen,
                source,
            });
        }
    };
    let mut events = data_plane.events();
    let ready = tokio::time::timeout(
        FIRST_SNAPSHOT_WAIT,
        events.wait_for(|status| status.snapshot_version.is_some()),
    )
    .await
    .is_ok_and(|changed| changed.is_ok());
    if !ready {
        warn!(
            wait_secs = FIRST_SNAPSHOT_WAIT.as_secs(),
            "built-in proxy has no policy yet; it refuses traffic until it gets one"
        );
    }
    Ok(LocalProxy {
        listen: data_plane.local_addr(),
        mcp: data_plane.mcp_addr(),
        enrolled,
        ready,
        data_plane,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wildcard_node_api_is_reached_on_loopback() {
        assert_eq!(
            node_api_url("0.0.0.0:8443".parse().unwrap()),
            "https://127.0.0.1:8443"
        );
        assert_eq!(
            node_api_url("[::]:8443".parse().unwrap()),
            "https://[::1]:8443"
        );
        assert_eq!(
            node_api_url("127.0.0.1:9443".parse().unwrap()),
            "https://127.0.0.1:9443"
        );
    }

    #[test]
    fn the_node_api_certificate_names_the_address_it_dials() {
        let named = |names: &[&str], listen: &str| {
            let mut names: Vec<String> = names.iter().map(|n| n.to_string()).collect();
            add_dial_name(&mut names, listen.parse().unwrap());
            names
        };
        assert_eq!(
            named(&["tokenless.example.com"], "0.0.0.0:8443"),
            ["tokenless.example.com", "127.0.0.1"]
        );
        assert_eq!(
            named(&["tokenless.internal"], "10.0.0.5:8443"),
            ["tokenless.internal", "10.0.0.5"]
        );
        assert_eq!(
            named(&["tokenless.internal"], "[::]:8443"),
            ["tokenless.internal", "::1"]
        );
        // Already there: nothing added.
        assert_eq!(
            named(&["localhost", "127.0.0.1"], "127.0.0.1:8443"),
            ["localhost", "127.0.0.1"]
        );
    }

    #[test]
    fn its_identity_lives_in_the_data_directory() {
        let config = LocalProxyConfig::new(Path::new("/var/lib/tokenless"));
        assert_eq!(
            config.state,
            Path::new("/var/lib/tokenless/builtin-proxy.json")
        );
        assert_eq!(config.listen, "127.0.0.1:3128".parse().unwrap());
    }
}
