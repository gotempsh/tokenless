// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tripwires on a real server: `tokenless tripwire add|list|remove`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use broker_server::launcher::account::{
    self, AddService, ConsoleClient, MemoryVault, Prompter, SessionVault, SignIn,
};
use broker_server::launcher::LauncherError;
use broker_server::{Server, ServerConfig};
use serde_json::Value;
use zeroize::Zeroizing;

struct NoPrompts;

impl Prompter for NoPrompts {
    fn secret(&self, label: &str) -> Result<Zeroizing<String>, LauncherError> {
        panic!("unexpected prompt for {label}")
    }
}

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tripwire_is_planted_listed_and_removed_from_the_cli() {
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
    client
        .add_service(
            &AddService {
                template_id: "github".into(),
                name: None,
                vault: "work".into(),
                bundle: None,
                read_only: false,
            },
            &template,
            BTreeMap::from([(
                "token".to_string(),
                Zeroizing::new("ghp_tripwireCliTestToken0123456789abcdefAB".to_string()),
            )]),
        )
        .await
        .unwrap();

    let (ok, out, err) = tokenless(home.path(), &url, &["tripwire", "list"]);
    assert!(
        ok && out.is_empty() && err.contains("tokenless tripwire add"),
        "{out}{err}"
    );

    // The credentials file block alone on stdout, the rest on stderr.
    let (ok, out, err) = tokenless(
        home.path(),
        &url,
        &["tripwire", "add", "--kind", "aws", "--name", "build-runner"],
    );
    assert!(ok, "{err}");
    assert!(
        out.starts_with("[default]\naws_access_key_id = AKIA"),
        "{out}"
    );
    assert!(out.contains("aws_secret_access_key = "), "{out}");
    assert!(
        err.contains("~/.aws/credentials")
            && err.contains("export AWS_ACCESS_KEY_ID=")
            && err.contains("shown only once"),
        "{err}"
    );
    let decoy = out
        .lines()
        .nth(1)
        .unwrap()
        .trim_start_matches("aws_access_key_id = ")
        .to_string();

    let (ok, out, err) = tokenless(home.path(), &url, &["tripwire", "list", "--json"]);
    assert!(ok, "{err}");
    assert!(!out.contains(&decoy), "never listed: {out}");
    let rows: Vec<Value> = serde_json::from_str(&out).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["name"], "build-runner");
    assert_eq!(rows[0]["kind"], "aws");
    assert_eq!(rows[0]["prefix"], decoy[..8]);
    let (ok, out, _) = tokenless(home.path(), &url, &["tripwire", "list"]);
    assert!(
        ok && out.contains("build-runner") && out.contains("never"),
        "{out}"
    );

    let (ok, _, err) = tokenless(
        home.path(),
        &url,
        &["tripwire", "add", "--kind", "gcp", "--name", "x"],
    );
    assert!(
        !ok && err.contains("one of: aws, github, openai, generic"),
        "{err}"
    );

    let (ok, _, err) = tokenless(home.path(), &url, &["tripwire", "remove", "build-runner"]);
    assert!(ok && err.contains("proxies stop looking for it"), "{err}");
    let (ok, _, err) = tokenless(home.path(), &url, &["tripwire", "remove", "build-runner"]);
    assert!(!ok && err.contains("no tripwire 'build-runner'"), "{err}");

    // `alerts ack` pages through every open alert for a short id, and
    // sends a whole one straight to the broker.
    assert!(client.open_alerts().await.unwrap().is_empty());
    let (ok, _, err) = tokenless(home.path(), &url, &["alerts", "ack", "0123abcd"]);
    assert!(!ok && err.contains("no open alert '0123abcd'"), "{err}");
    let whole = "0123abcd-0000-4000-8000-000000000000";
    let (ok, _, err) = tokenless(home.path(), &url, &["alerts", "ack", whole]);
    assert!(!ok && err.contains("404") && err.contains(whole), "{err}");
}
