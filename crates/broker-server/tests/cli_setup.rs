// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Setting up a broker from the terminal: the generated first admin signs
//! in, adds a service and enrols a proxy, the way `tokenless login`,
//! `service add` and `proxy add` do.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use broker_server::launcher::account::{
    self, AddService, ConsoleClient, MemoryVault, Prompter, SessionVault, SignIn,
};
use broker_server::launcher::client::{ApiClient, Credentials, MintRequest};
use broker_server::launcher::LauncherError;
use broker_server::{Server, ServerConfig};
use zeroize::Zeroizing;

/// The terminal is never asked anything in these flows.
struct NoPrompts;

impl Prompter for NoPrompts {
    fn secret(&self, label: &str) -> Result<Zeroizing<String>, LauncherError> {
        panic!("unexpected prompt for {label}")
    }
}

const GITHUB_TOKEN: &str = "ghp_cliSetupTestToken0123456789abcdefABCD";

/// Every byte under `dir`, to look for plaintext in.
fn all_bytes(dir: &std::path::Path) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(all_bytes(&path));
        } else {
            out.extend(std::fs::read(&path).unwrap());
        }
    }
    out
}

#[tokio::test]
async fn the_first_admin_sets_up_a_service_and_a_proxy_from_the_terminal() {
    let data = tempfile::tempdir().unwrap();
    let mut config = ServerConfig::new(data.path());
    config.api_listen = "127.0.0.1:0".parse().unwrap();
    config.node_listen = "127.0.0.1:0".parse().unwrap();
    let server = Server::start(config).await.unwrap();
    let url = format!("http://{}", server.api_addr);
    let admin = server
        .initial_admin
        .as_ref()
        .expect("generated on first start");

    // A wrong password is refused; the generated one signs in.
    assert!(account::sign_in(&url, "admin", "not the password", None)
        .await
        .is_err());
    let SignIn::Done(session) = account::sign_in(&url, &admin.username, &admin.password, None)
        .await
        .unwrap()
    else {
        panic!("the generated admin has no authenticator");
    };
    let vault = MemoryVault::default();
    vault.save(&session).unwrap();

    // Without a saved session the commands say to sign in.
    let other = MemoryVault::default();
    assert!(matches!(
        ConsoleClient::open(&other, &url, &NoPrompts),
        Err(LauncherError::NotSignedIn { .. })
    ));

    let client = ConsoleClient::open(&vault, &url, &NoPrompts).unwrap();
    let template = account::pick_template(client.templates().await.unwrap(), "GitHub").unwrap();
    assert!(account::pick_template(client.templates().await.unwrap(), "no-such").is_err());
    let plan = AddService {
        template_id: "github".into(),
        name: None,
        vault: "work".into(),
        bundle: Some("code-review".into()),
        read_only: false,
    };
    let fields = BTreeMap::from([(
        "token".to_string(),
        Zeroizing::new(GITHUB_TOKEN.to_string()),
    )]);
    let added = client.add_service(&plan, &template, fields).await.unwrap();
    assert!(added.vault_created);
    assert_eq!(added.credential.name, "github");
    let (bundle, created) = added.bundle.as_ref().unwrap();
    assert!(created);
    assert_eq!(bundle.rule_ids, vec![added.rule.id]);

    // A second service joins the same vault and bundle instead of creating them.
    let second = AddService {
        name: Some("github-read".into()),
        read_only: true,
        ..plan
    };
    let fields = BTreeMap::from([(
        "token".to_string(),
        Zeroizing::new(GITHUB_TOKEN.to_string()),
    )]);
    let again = client
        .add_service(&second, &template, fields)
        .await
        .unwrap();
    assert!(!again.vault_created);
    assert_eq!(again.vault.id, added.vault.id);
    let (bundle, created) = again.bundle.as_ref().unwrap();
    assert!(!created);
    assert_eq!(bundle.rule_ids.len(), 2);

    // The token is stored encrypted: it appears nowhere in the data
    // directory, database and write-ahead log included.
    let stored = all_bytes(data.path());
    assert!(!stored
        .windows(GITHUB_TOKEN.len())
        .any(|w| w == GITHUB_TOKEN.as_bytes()));
    // Nor the generated admin password, which is kept only as a hash.
    assert!(!stored
        .windows(admin.password.len())
        .any(|w| w == admin.password.as_bytes()));

    // A join token enrols a proxy.
    let join = client.create_join_token().await.unwrap();
    let control_url = format!("https://{}", server.node_addr);
    let identity = broker_dataplane::node::enroll(&control_url, &join.token, "laptop")
        .await
        .unwrap();
    let state = data.path().join("node.json");
    identity.save(&state).unwrap();
    assert!(state.exists());

    // Without an API key, `tokenless run` mints with the signed-in session.
    let launcher = ApiClient::new(
        &url,
        Some(Credentials::Session {
            token: Zeroizing::new(session.token.clone()),
            csrf_token: session.csrf_token.clone(),
        }),
    )
    .unwrap();
    let work = launcher.resolve_vault(Some("work")).await.unwrap();
    assert_eq!(work, added.vault.id);
    let minted = launcher
        .mint(
            &work,
            &MintRequest {
                bundle: "code-review".into(),
                ttl_secs: 300,
                longest: false,
                request_limit: None,
                labels: BTreeMap::new(),
            },
        )
        .await
        .unwrap();
    assert!(!minted.token.is_empty());
    assert!(ApiClient::new(&url, None)
        .unwrap()
        .resolve_vault(Some("work"))
        .await
        .is_err());

    // Signing out ends the session on the server.
    client.logout().await.unwrap();
    let ended = ConsoleClient::open(&vault, &url, &NoPrompts).unwrap();
    assert!(matches!(
        ended.vaults().await,
        Err(LauncherError::NotSignedIn { .. })
    ));
    server.shutdown();
}

#[tokio::test]
async fn a_lost_admin_password_is_reset_from_the_server_host() {
    let data = tempfile::tempdir().unwrap();
    let mut config = ServerConfig::new(data.path());
    config.api_listen = "127.0.0.1:0".parse().unwrap();
    config.node_listen = "127.0.0.1:0".parse().unwrap();
    let server = Server::start(config).await.unwrap();
    let url = format!("http://{}", server.api_addr);
    let lost = server.initial_admin.as_ref().unwrap().password.clone();
    let SignIn::Done(before) = account::sign_in(&url, "admin", &lost, None).await.unwrap() else {
        panic!("no authenticator yet");
    };

    // While the server runs, against the same data directory.
    let offline = ServerConfig::new(data.path());
    let reset = broker_server::reset_password(&offline, "admin")
        .await
        .unwrap();
    assert_ne!(*reset.password, *lost);
    assert!(broker_server::reset_password(&offline, "nobody")
        .await
        .is_err());

    assert!(account::sign_in(&url, "admin", &lost, None).await.is_err());
    assert!(matches!(
        account::sign_in(&url, "admin", &reset.password, None)
            .await
            .unwrap(),
        SignIn::Done(_)
    ));
    // The session signed in with the old password has ended.
    let vault = MemoryVault::default();
    vault.save(&before).unwrap();
    let client = ConsoleClient::open(&vault, &url, &NoPrompts).unwrap();
    assert!(matches!(
        client.vaults().await,
        Err(LauncherError::NotSignedIn { .. })
    ));

    // A restart does not create another admin.
    server.shutdown();
    let mut again = ServerConfig::new(data.path());
    again.api_listen = "127.0.0.1:0".parse().unwrap();
    again.node_listen = "127.0.0.1:0".parse().unwrap();
    let restarted = Server::start(again).await.unwrap();
    assert!(restarted.initial_admin.is_none());
    restarted.shutdown();
}
