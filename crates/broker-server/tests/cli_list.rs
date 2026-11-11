// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `list` commands on a real server: vaults, services, bundles,
//! sessions and proxies as the signed-in person sees them, as tables and
//! as JSON, and never a secret.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use broker_server::launcher::account::{
    self, AddService, ConsoleClient, MemoryVault, Prompter, SavedSession, SessionVault, SignIn,
};
use broker_server::launcher::LauncherError;
use broker_server::{Server, ServerConfig};
use serde_json::{json, Value};
use tokenless_dataplane::node::enroll;
use zeroize::Zeroizing;

struct NoPrompts;

impl Prompter for NoPrompts {
    fn secret(&self, label: &str) -> Result<Zeroizing<String>, LauncherError> {
        panic!("unexpected prompt for {label}")
    }
}

const GITHUB_TOKEN: &str = "ghp_cliListTestToken0123456789abcdefABCDE";

/// The binary, signed in through a session file in a scratch home (never
/// the OS keychain). Its stdout and stderr.
fn tokenless(home: &std::path::Path, url: &str, args: &[&str]) -> (bool, String, String) {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_tokenless"))
        .args(args)
        .args(["--server", url])
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn json_of(home: &std::path::Path, url: &str, args: &[&str]) -> Vec<Value> {
    let (ok, out, err) = tokenless(home, url, args);
    assert!(ok, "tokenless {args:?} failed: {err}");
    let value: Value = serde_json::from_str(&out).unwrap_or_else(|e| panic!("{e}: {out}"));
    value.as_array().unwrap().clone()
}

/// `POST /api/v1<path>` as the signed-in person, as the console would.
async fn post(url: &str, session: &SavedSession, path: &str, body: Value) -> Value {
    let response = reqwest::Client::new()
        .post(format!("{url}/api/v1{path}"))
        .header(
            "cookie",
            format!(
                "{}={}",
                tokenless_auth::cookie::SESSION_COOKIE,
                session.token
            ),
        )
        .header(tokenless_auth::csrf::CSRF_HEADER, &session.csrf_token)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert!(
        response.status().is_success(),
        "POST {path}: {}",
        response.status()
    );
    response.json().await.unwrap_or(Value::Null)
}

async fn get(url: &str, session: &SavedSession, path: &str) -> (u16, Value) {
    let response = reqwest::Client::new()
        .get(format!("{url}/api/v1{path}"))
        .header(
            "cookie",
            format!(
                "{}={}",
                tokenless_auth::cookie::SESSION_COOKIE,
                session.token
            ),
        )
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    (status, response.json().await.unwrap_or(Value::Null))
}

fn page_ids(page: &Value) -> Vec<String> {
    page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["id"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lists_what_the_console_shows_as_tables_and_json() {
    let data = tempfile::tempdir().unwrap();
    let mut config = ServerConfig::new(data.path());
    config.api_listen = "127.0.0.1:0".parse().unwrap();
    config.node_listen = "127.0.0.1:0".parse().unwrap();
    let server = Server::start(config).await.unwrap();
    let url = format!("http://{}", server.api_addr);
    let admin = server.initial_admin.as_ref().unwrap();
    let SignIn::Done(session) = account::sign_in(&url, &admin.username, &admin.password, None)
        .await
        .unwrap()
    else {
        panic!("the generated admin has no authenticator");
    };
    let home = tempfile::tempdir().unwrap();

    // Signed out, every list says to sign in.
    for args in [
        &["vault", "list"][..],
        &["service", "list"],
        &["bundle", "list"],
        &["session", "list"],
        &["proxy", "list"],
    ] {
        let (ok, _, err) = tokenless(home.path(), &url, args);
        assert!(!ok && err.contains("tokenless login"), "{args:?}: {err}");
    }
    account::SessionFiles::new(home.path().join(".config/tokenless/sessions"))
        .save(&session)
        .unwrap();

    // Nothing yet: a hint on stderr, nothing on stdout, `[]` as JSON.
    let (ok, out, err) = tokenless(home.path(), &url, &["vault", "list"]);
    assert!(
        ok && out.is_empty() && err.contains("no vaults yet"),
        "{out}{err}"
    );
    assert!(json_of(home.path(), &url, &["proxy", "list", "--json"]).is_empty());

    // A vault with two services in one bundle, and a second vault.
    let vault = MemoryVault::default();
    vault.save(&session).unwrap();
    let client = ConsoleClient::open(&vault, &url, &NoPrompts).unwrap();
    let template = account::pick_template(client.templates().await.unwrap(), "github").unwrap();
    let token = || {
        BTreeMap::from([(
            "token".to_string(),
            Zeroizing::new(GITHUB_TOKEN.to_string()),
        )])
    };
    let plan = AddService {
        template_id: "github".into(),
        name: None,
        vault: "work".into(),
        bundle: Some("code-review".into()),
        read_only: false,
    };
    let added = client.add_service(&plan, &template, token()).await.unwrap();
    let read_only = AddService {
        template_id: "github".into(),
        name: Some("github-read".into()),
        vault: "work".into(),
        bundle: Some("code-review".into()),
        read_only: true,
    };
    client
        .add_service(&read_only, &template, token())
        .await
        .unwrap();
    let other = AddService {
        vault: "personal".into(),
        bundle: Some("my-agent".into()),
        ..plan
    };
    client
        .add_service(&other, &template, token())
        .await
        .unwrap();
    let work = added.vault.id;

    // Two sessions from code-review, one of them ended.
    let mint = |ttl: u64| json!({ "bundle": "code-review", "ttl_secs": ttl });
    let live = post(
        &url,
        &session,
        &format!("/vaults/{work}/sessions"),
        mint(600),
    )
    .await;
    let ended = post(
        &url,
        &session,
        &format!("/vaults/{work}/sessions"),
        mint(600),
    )
    .await;
    let live_id = live["session"]["id"].as_str().unwrap().to_string();
    let ended_id = ended["session"]["id"].as_str().unwrap().to_string();
    post(
        &url,
        &session,
        &format!("/sessions/{ended_id}/revoke"),
        json!({}),
    )
    .await;

    // A proxy that enrolled but never ran.
    let join = client.create_join_token().await.unwrap();
    let node_url = format!("https://{}", server.node_addr);
    enroll(&node_url, &join.token, "build-1").await.unwrap();

    let vaults = json_of(home.path(), &url, &["vault", "list", "--json"]);
    let by_name = |rows: &[Value], name: &str| {
        rows.iter()
            .find(|r| r["name"] == name)
            .cloned()
            .unwrap_or_else(|| panic!("no {name} in {rows:?}"))
    };
    let w = by_name(&vaults, "work");
    assert_eq!(
        (w["services"].as_u64(), w["bundles"].as_u64()),
        (Some(2), Some(1))
    );
    assert_eq!(by_name(&vaults, "personal")["services"], 1);

    let services = json_of(
        home.path(),
        &url,
        &["service", "list", "--vault", "work", "--json"],
    );
    assert_eq!(services.len(), 2, "{services:?}");
    let github = by_name(&services, "github");
    assert_eq!(github["vault"], "work");
    assert_eq!(github["template"], "github");
    assert!(github["hosts"]
        .as_array()
        .unwrap()
        .contains(&json!("api.github.com")));
    let (_, table, _) = tokenless(home.path(), &url, &["service", "list"]);
    assert!(table.starts_with("VAULT"), "{table}");
    assert_eq!(
        table.lines().count(),
        4,
        "a header and three services: {table}"
    );
    for (shown, what) in [
        (&table, "table"),
        (&services.iter().map(Value::to_string).collect(), "json"),
    ] {
        assert!(!shown.contains(GITHUB_TOKEN), "a secret in the {what}");
    }

    let bundles = json_of(home.path(), &url, &["bundle", "list", "--json"]);
    let review = by_name(&bundles, "code-review");
    assert_eq!(review["services"], json!(["github", "github-read"]));
    assert_eq!(review["vault"], "work");
    let (_, table, _) = tokenless(
        home.path(),
        &url,
        &["bundle", "list", "--vault", "personal"],
    );
    assert!(
        table.contains("my-agent") && !table.contains("code-review"),
        "{table}"
    );

    // Active sessions by default, every one with --all; by bundle name.
    let active = json_of(home.path(), &url, &["session", "list", "--json"]);
    let ids = |rows: &[Value]| -> Vec<String> {
        rows.iter()
            .map(|r| r["id"].as_str().unwrap().to_string())
            .collect()
    };
    assert_eq!(ids(&active), std::slice::from_ref(&live_id));
    assert_eq!(active[0]["state"], "active");
    assert_eq!(active[0]["bundle"], "code-review");
    let all = json_of(home.path(), &url, &["session", "list", "--all", "--json"]);
    assert_eq!(all.len(), 2, "{all:?}");
    assert_eq!(by_id(&all, &ended_id)["state"], "revoked");
    let in_bundle = json_of(
        home.path(),
        &url,
        &[
            "session",
            "list",
            "--bundle",
            "code-review",
            "--all",
            "--json",
        ],
    );
    assert_eq!(in_bundle.len(), 2);
    assert!(json_of(
        home.path(),
        &url,
        &["session", "list", "--bundle", "my-agent", "--json"]
    )
    .is_empty());
    let one = json_of(
        home.path(),
        &url,
        &["session", "list", "--all", "--limit", "1", "--json"],
    );
    assert_eq!(one.len(), 1, "the newest only");
    let (_, table, _) = tokenless(home.path(), &url, &["session", "list"]);
    assert!(
        table.contains(&live_id) && table.contains("active"),
        "{table}"
    );
    let (ok, _, err) = tokenless(home.path(), &url, &["session", "list", "--bundle", "nope"]);
    assert!(
        !ok && err.contains("no access bundle named 'nope'"),
        "{err}"
    );
    let (ok, _, err) = tokenless(home.path(), &url, &["service", "list", "--vault", "nope"]);
    assert!(
        !ok && err.contains("no vault named 'nope'") && err.contains("work"),
        "{err}"
    );

    let proxies = json_of(home.path(), &url, &["proxy", "list", "--json"]);
    assert_eq!(proxies.len(), 1);
    assert_eq!(proxies[0]["name"], "build-1");
    assert_eq!(proxies[0]["state"], "never_connected");
    let (_, table, _) = tokenless(home.path(), &url, &["proxy", "list"]);
    assert!(table.contains("never connected"), "{table}");

    server.shutdown();
}

fn by_id(rows: &[Value], id: &str) -> Value {
    rows.iter()
        .find(|r| r["id"] == id)
        .cloned()
        .unwrap_or_else(|| panic!("no {id} in {rows:?}"))
}

/// More sessions than one API page holds: the list follows the pages up
/// to `--limit`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_list_longer_than_a_page_follows_the_pages() {
    let data = tempfile::tempdir().unwrap();
    let mut config = ServerConfig::new(data.path());
    config.api_listen = "127.0.0.1:0".parse().unwrap();
    config.node_listen = "127.0.0.1:0".parse().unwrap();
    let server = Server::start(config).await.unwrap();
    let url = format!("http://{}", server.api_addr);
    let admin = server.initial_admin.as_ref().unwrap();
    let SignIn::Done(session) = account::sign_in(&url, &admin.username, &admin.password, None)
        .await
        .unwrap()
    else {
        panic!("the generated admin has no authenticator");
    };
    let vault = MemoryVault::default();
    vault.save(&session).unwrap();
    let client = ConsoleClient::open(&vault, &url, &NoPrompts).unwrap();
    let template = account::pick_template(client.templates().await.unwrap(), "github").unwrap();
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
    let work = client
        .add_service(&plan, &template, fields)
        .await
        .unwrap()
        .vault
        .id;
    for _ in 0..130 {
        post(
            &url,
            &session,
            &format!("/vaults/{work}/sessions"),
            json!({ "bundle": "code-review", "ttl_secs": 600 }),
        )
        .await;
    }
    let home = tempfile::tempdir().unwrap();
    account::SessionFiles::new(home.path().join(".config/tokenless/sessions"))
        .save(&session)
        .unwrap();

    let shown = json_of(
        home.path(),
        &url,
        &["session", "list", "--limit", "125", "--json"],
    );
    assert_eq!(shown.len(), 125);
    let created: Vec<&str> = shown
        .iter()
        .map(|s| s["created_at"].as_str().unwrap())
        .collect();
    assert!(created.windows(2).all(|w| w[0] >= w[1]), "newest first");
    let (_, _, err) = tokenless(home.path(), &url, &["session", "list"]);
    assert!(
        err.contains("showing the newest 20; --limit shows more"),
        "{err}"
    );
    // Exactly the limit, with nothing past it: no hint. One fewer: the hint.
    let (_, _, err) = tokenless(home.path(), &url, &["session", "list", "--limit", "130"]);
    assert!(!err.contains("--limit shows more"), "{err}");
    let (_, _, err) = tokenless(home.path(), &url, &["session", "list", "--limit", "129"]);
    assert!(
        err.contains("showing the newest 129; --limit shows more"),
        "{err}"
    );
    let mut ids: Vec<&str> = shown.iter().map(|s| s["id"].as_str().unwrap()).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 125, "no session twice across pages");

    // A page continues after the last session of the one before: a session
    // minted and one revoked in between neither repeat nor skip a row, as
    // `page=2` would.
    let sessions = format!("/vaults/{work}/sessions?active=true");
    let (_, expected) = get(&url, &session, &format!("{sessions}&page_size=20")).await;
    let expected = page_ids(&expected);
    let (_, first) = get(&url, &session, &format!("{sessions}&page_size=10")).await;
    assert_eq!(page_ids(&first), expected[..10]);
    post(
        &url,
        &session,
        &format!("/vaults/{work}/sessions"),
        json!({ "bundle": "code-review", "ttl_secs": 600 }),
    )
    .await;
    post(
        &url,
        &session,
        &format!("/sessions/{}/revoke", expected[2]),
        json!({}),
    )
    .await;
    let last = &first["items"][9];
    let cursor = format!(
        "after_created_at={}&after_id={}",
        last["created_at"].as_str().unwrap(),
        last["id"].as_str().unwrap()
    );
    let (status, second) = get(&url, &session, &format!("{sessions}&page_size=10&{cursor}")).await;
    assert_eq!(status, 200, "{second}");
    assert_eq!(page_ids(&second), expected[10..20]);
    let (status, problem) = get(
        &url,
        &session,
        &format!("{sessions}&after_id={}", last["id"].as_str().unwrap()),
    )
    .await;
    assert_eq!(status, 400, "half a cursor is refused: {problem}");
    assert!(
        problem["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("after_created_at and after_id go together"),
        "{problem}"
    );
    server.shutdown();
}
