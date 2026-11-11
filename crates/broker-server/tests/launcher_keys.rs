// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Launcher keys on a real server: `tokenless bundle key add|list|revoke`,
//! and what a key can and can't do over the API.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use broker_server::launcher::account::{
    self, AddService, ConsoleClient, MemoryVault, Prompter, SessionVault, SignIn,
};
use broker_server::launcher::LauncherError;
use broker_server::{Server, ServerConfig};
use serde_json::{json, Value};
use zeroize::Zeroizing;

struct NoPrompts;

impl Prompter for NoPrompts {
    fn secret(&self, label: &str) -> Result<Zeroizing<String>, LauncherError> {
        panic!("unexpected prompt for {label}")
    }
}

const GITHUB_TOKEN: &str = "ghp_launcherKeyTestToken0123456789abcdefAB";

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

/// A request with the launcher key as its bearer token.
async fn with_key(
    method: reqwest::Method,
    url: &str,
    key: &str,
    path: &str,
    body: Option<Value>,
) -> (u16, Value) {
    let mut request = reqwest::Client::new()
        .request(method, format!("{url}/api/v1{path}"))
        .bearer_auth(key);
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    (status, response.json().await.unwrap_or(Value::Null))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_launcher_key_starts_its_bundle_s_sessions_and_nothing_else() {
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
    account::SessionFiles::new(home.path().join(".config/tokenless/sessions"))
        .save(&session)
        .unwrap();

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
    client
        .add_service(
            &AddService {
                name: Some("github-deploy".into()),
                bundle: Some("deploy".into()),
                ..plan
            },
            &template,
            token(),
        )
        .await
        .unwrap();
    let work = added.vault.id;

    // Nothing yet: a hint saying how to make one.
    let (ok, out, err) = tokenless(home.path(), &url, &["bundle", "key", "list"]);
    assert!(
        ok && out.is_empty() && err.contains("tokenless bundle key add"),
        "{out}{err}"
    );

    // The key alone on stdout; how to use it on stderr.
    let (ok, out, err) = tokenless(
        home.path(),
        &url,
        &[
            "bundle",
            "key",
            "add",
            "code-review",
            "--name",
            "build-runner",
            "--ttl",
            "10m",
            "--label",
            "machine=runner-1",
        ],
    );
    assert!(ok, "{err}");
    let key = out.trim().to_string();
    assert!(key.starts_with("cbk_") && !key.contains(' '), "{out}");
    assert!(
        err.contains("bundle 'code-review'")
            && err.contains("up to 10m")
            && err.contains("--api-key-file"),
        "{err}"
    );

    // It starts sessions from its bundle, capped to its limits.
    let (status, minted) = with_key(
        reqwest::Method::POST,
        &url,
        &key,
        &format!("/vaults/{work}/sessions"),
        Some(json!({ "bundle": "code-review", "ttl_secs": 7200 })),
    )
    .await;
    assert_eq!(status, 201, "{minted}");
    let s = &minted["session"];
    let lifetime = chrono::DateTime::parse_from_rfc3339(s["expires_at"].as_str().unwrap()).unwrap()
        - chrono::DateTime::parse_from_rfc3339(s["created_at"].as_str().unwrap()).unwrap();
    assert_eq!(lifetime.num_seconds(), 600);
    assert_eq!(s["labels"]["machine"], "runner-1");
    let session_id = s["id"].as_str().unwrap().to_string();

    // `run` finds the vault by name with it.
    let (status, vaults) = with_key(reqwest::Method::GET, &url, &key, "/vaults", None).await;
    assert_eq!(status, 200, "{vaults}");
    assert_eq!(vaults["items"].as_array().unwrap().len(), 1);
    assert_eq!(vaults["items"][0]["name"], "work");

    // Not another bundle, and nothing else in the vault.
    let (status, problem) = with_key(
        reqwest::Method::POST,
        &url,
        &key,
        &format!("/vaults/{work}/sessions"),
        Some(json!({ "bundle": "deploy" })),
    )
    .await;
    assert_eq!(status, 403, "{problem}");
    assert!(
        problem["detail"].as_str().unwrap().contains("launcher key"),
        "{problem}"
    );
    for path in [
        format!("/vaults/{work}/rules"),
        format!("/vaults/{work}/credentials"),
        format!("/vaults/{work}/sessions"),
        format!("/vaults/{work}/launcher-keys"),
        "/audit".to_string(),
    ] {
        let (status, problem) = with_key(reqwest::Method::GET, &url, &key, &path, None).await;
        assert_eq!(status, 403, "{path}: {problem}");
    }

    // Listed without its secret, with when it was last used.
    let (ok, out, err) = tokenless(home.path(), &url, &["bundle", "key", "list", "--json"]);
    assert!(ok, "{err}");
    assert!(!out.contains(&key), "the key must never be listed");
    let rows: Vec<Value> = serde_json::from_str(&out).unwrap();
    assert_eq!(rows.len(), 1, "{out}");
    assert_eq!(rows[0]["bundle"], "code-review");
    assert_eq!(rows[0]["name"], "build-runner");
    assert_eq!(rows[0]["state"], "active");
    assert!(rows[0]["last_used_at"].is_string(), "{out}");
    let (ok, out, _) = tokenless(home.path(), &url, &["bundle", "key", "list"]);
    assert!(
        ok && out.contains("build-runner") && out.contains("10m") && out.contains("active"),
        "{out}"
    );

    // Revoking it ends the session it started and the key stops working.
    let (ok, _, err) = tokenless(
        home.path(),
        &url,
        &["bundle", "key", "revoke", "build-runner", "--vault", "work"],
    );
    assert!(ok, "{err}");
    assert!(err.contains("ended 1 live session it had started"), "{err}");
    let ended: Value = reqwest::Client::new()
        .get(format!("{url}/api/v1/sessions/{session_id}"))
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
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(ended["revoked_at"].is_string(), "{ended}");
    let (status, _) = with_key(
        reqwest::Method::POST,
        &url,
        &key,
        &format!("/vaults/{work}/sessions"),
        Some(json!({ "bundle": "code-review" })),
    )
    .await;
    assert_eq!(status, 401);
    let (ok, _, err) = tokenless(home.path(), &url, &["bundle", "key", "revoke", "nobody"]);
    assert!(!ok && err.contains("no launcher key 'nobody'"), "{err}");
}
