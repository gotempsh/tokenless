// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The proxy `serve` runs for agents on its own machine, on a real server:
//! it enrols once and answers `tokenless run`'s check, reuses its identity
//! on the next start, replaces one the server does not know, and stays off
//! once an admin revoked it.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use broker_server::launcher::port::check_proxy;
use broker_server::local_proxy::{self, LocalProxyConfig, LocalProxyError, NODE_NAME};
use broker_server::{RunningServer, Server, ServerConfig};
use tokenless_control::model::PageRequest;
use tokenless_control::Caller;
use tokenless_core::authz::{Principal, Role};
use tokenless_dataplane::NodeIdentity;

async fn server(data: &Path) -> RunningServer {
    let mut config = ServerConfig::new(data);
    config.api_listen = "127.0.0.1:0".parse().unwrap();
    config.node_listen = "127.0.0.1:0".parse().unwrap();
    Server::start(config).await.unwrap()
}

fn proxy_config(state: &Path) -> LocalProxyConfig {
    LocalProxyConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        mcp_listen: None,
        state: state.to_path_buf(),
    }
}

fn admin() -> Caller {
    Caller::service(Principal::service("test", Role::Admin, None))
}

async fn proxies(server: &RunningServer) -> Vec<(String, bool)> {
    let page = server
        .control
        .nodes
        .list_nodes(&admin(), PageRequest::default())
        .await
        .unwrap();
    page.items
        .into_iter()
        .map(|n| (n.name, n.revoked_at.is_some()))
        .collect()
}

#[tokio::test]
async fn serve_runs_one_proxy_and_keeps_it_across_restarts() {
    let data = tempfile::tempdir().unwrap();
    let state = data.path().join(local_proxy::STATE_FILE);
    let server = server(data.path()).await;

    let proxy = local_proxy::start(&server.control, server.node_addr, proxy_config(&state))
        .await
        .unwrap();
    assert!(proxy.enrolled, "the first start enrols");
    assert!(proxy.ready, "it has its policy before serve announces it");
    assert!(proxy.mcp.is_none());
    assert!(state.exists(), "its identity is kept in the data directory");
    assert_eq!(proxies(&server).await, vec![(NODE_NAME.to_string(), false)]);
    check_proxy(&proxy.listen.to_string())
        .await
        .expect("tokenless run finds it");
    let first = NodeIdentity::load(&state).unwrap().node_id;
    proxy.shutdown(Duration::from_secs(1)).await;

    // The next start reuses it: no second proxy in the list.
    let proxy = local_proxy::start(&server.control, server.node_addr, proxy_config(&state))
        .await
        .unwrap();
    assert!(!proxy.enrolled, "a restart reuses its identity");
    assert_eq!(NodeIdentity::load(&state).unwrap().node_id, first);
    assert_eq!(proxies(&server).await.len(), 1);
    proxy.shutdown(Duration::from_secs(1)).await;

    // Revoked in the console, it stays off and says how to bring it back.
    server
        .control
        .nodes
        .revoke_node(&admin(), &first)
        .await
        .unwrap();
    let Err(err) =
        local_proxy::start(&server.control, server.node_addr, proxy_config(&state)).await
    else {
        panic!("a revoked built-in proxy must not start");
    };
    assert!(matches!(err, LocalProxyError::Revoked { .. }), "{err}");
    let message = err.to_string();
    assert!(message.contains(&first.to_string()), "{message}");
    assert!(message.contains(local_proxy::STATE_FILE), "{message}");
    assert!(message.contains("--no-proxy"), "{message}");

    // Removing its identity file enrols a new one.
    std::fs::remove_file(&state).unwrap();
    let proxy = local_proxy::start(&server.control, server.node_addr, proxy_config(&state))
        .await
        .unwrap();
    assert!(proxy.enrolled);
    assert_ne!(NodeIdentity::load(&state).unwrap().node_id, first);
    proxy.shutdown(Duration::from_secs(1)).await;
    server.shutdown();
}

#[tokio::test]
async fn an_identity_from_another_server_is_replaced() {
    let other = tempfile::tempdir().unwrap();
    let state = other.path().join(local_proxy::STATE_FILE);
    let first = server(other.path()).await;
    local_proxy::start(&first.control, first.node_addr, proxy_config(&state))
        .await
        .unwrap()
        .shutdown(Duration::from_secs(1))
        .await;
    first.shutdown();

    // A fresh database with that identity file: the server does not know
    // the proxy, so it enrols a new one instead of failing.
    let data = tempfile::tempdir().unwrap();
    let second = server(data.path()).await;
    let proxy = local_proxy::start(&second.control, second.node_addr, proxy_config(&state))
        .await
        .unwrap();
    assert!(proxy.enrolled);
    assert_eq!(proxies(&second).await, vec![(NODE_NAME.to_string(), false)]);
    proxy.shutdown(Duration::from_secs(1)).await;
    second.shutdown();
}

#[tokio::test]
async fn a_busy_port_is_reported_with_its_flag_and_leaves_no_proxy_behind() {
    let data = tempfile::tempdir().unwrap();
    let state = data.path().join(local_proxy::STATE_FILE);
    let server = server(data.path()).await;
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let taken = taken.local_addr().map(|addr| (taken, addr)).unwrap();

    for (listen, mcp_listen, flag) in [
        (taken.1, None, "--proxy-listen"),
        (
            "127.0.0.1:0".parse().unwrap(),
            Some(taken.1),
            "--proxy-mcp-listen",
        ),
    ] {
        let config = LocalProxyConfig {
            listen,
            mcp_listen,
            state: state.clone(),
        };
        let Err(err) = local_proxy::start(&server.control, server.node_addr, config).await else {
            panic!("a taken port must be reported");
        };
        assert!(matches!(err, LocalProxyError::PortTaken { .. }), "{err}");
        let message = err.to_string();
        assert!(message.contains("--no-proxy"), "{message}");
        assert!(message.contains(flag), "{message}");
        assert!(message.contains(&taken.1.to_string()), "{message}");
    }
    assert!(
        proxies(&server).await.is_empty(),
        "nothing enrolled for a proxy that cannot listen"
    );
    assert!(!state.exists());
    server.shutdown();
}

#[tokio::test]
async fn it_follows_the_node_api_to_a_new_address() {
    let data = tempfile::tempdir().unwrap();
    let state = data.path().join(local_proxy::STATE_FILE);
    let first = server(data.path()).await;
    local_proxy::start(&first.control, first.node_addr, proxy_config(&state))
        .await
        .unwrap()
        .shutdown(Duration::from_secs(1))
        .await;
    let enrolled_at = NodeIdentity::load(&state).unwrap();
    first.shutdown();

    // Restarted with the node API on another port: the same proxy, dialling
    // the new one, with its policy.
    let second = server(data.path()).await;
    assert_ne!(second.node_addr, first_addr(&enrolled_at));
    let proxy = local_proxy::start(&second.control, second.node_addr, proxy_config(&state))
        .await
        .unwrap();
    assert!(!proxy.enrolled);
    assert!(proxy.ready, "it gets its policy from the moved node API");
    let now = NodeIdentity::load(&state).unwrap();
    assert_eq!(now.node_id, enrolled_at.node_id);
    assert_eq!(now.control_url, format!("https://{}", second.node_addr));
    proxy.shutdown(Duration::from_secs(1)).await;
    second.shutdown();
}

fn first_addr(identity: &NodeIdentity) -> SocketAddr {
    identity
        .control_url
        .trim_start_matches("https://")
        .parse()
        .unwrap()
}

#[tokio::test]
async fn it_enrols_when_the_node_api_has_its_own_name() {
    // `--node-api-name tokenless.example.com` replaces the loopback names;
    // serve adds back the address its proxy dials.
    let node_listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let start = |names: Vec<String>| async move {
        let data = tempfile::tempdir().unwrap();
        let mut config = ServerConfig::new(data.path());
        config.api_listen = "127.0.0.1:0".parse().unwrap();
        config.node_listen = node_listen;
        config.node_api_names = names;
        let server = Server::start(config).await.unwrap();
        let state = data.path().join(local_proxy::STATE_FILE);
        let started =
            local_proxy::start(&server.control, server.node_addr, proxy_config(&state)).await;
        (data, server, started)
    };

    let named = vec!["tokenless.example.com".to_string()];
    let (_data, server, started) = start(named.clone()).await;
    let Err(err) = started else {
        panic!("a certificate without the dialled address must fail");
    };
    assert!(matches!(err, LocalProxyError::Enrol { .. }), "{err}");
    assert!(err.to_string().contains("--no-proxy"), "{err}");
    server.shutdown();

    let mut names = named;
    local_proxy::add_dial_name(&mut names, node_listen);
    let (_data, server, started) = start(names).await;
    let proxy = started.unwrap();
    assert!(proxy.enrolled && proxy.ready);
    proxy.shutdown(Duration::from_secs(1)).await;
    server.shutdown();
}
