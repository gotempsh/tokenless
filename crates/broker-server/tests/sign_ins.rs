// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Sign-ins on a real server: `tokenless sign-ins list|revoke`, and that
//! ending one signs that client out and nobody else.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use broker_server::launcher::account::{self, SessionVault, SignIn, USER_AGENT};
use broker_server::{Server, ServerConfig};
use serde_json::{json, Value};

const BROWSER: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0) Gecko/20100101 Firefox/140.0";

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

/// Signs in the way the console does; the session cookie.
async fn browser_sign_in(url: &str, username: &str, password: &str) -> String {
    let response = reqwest::Client::new()
        .post(format!("{url}/api/v1/auth/login"))
        .header("user-agent", BROWSER)
        .json(&json!({ "username": username, "password": password }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    response
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

async fn signed_in(url: &str, cookie: &str) -> bool {
    reqwest::Client::new()
        .get(format!("{url}/api/v1/auth/me"))
        .header("cookie", cookie)
        .send()
        .await
        .unwrap()
        .status()
        == 200
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sign_ins_are_listed_and_ended_one_at_a_time_or_all_at_once() {
    let data = tempfile::tempdir().unwrap();
    let mut config = ServerConfig::new(data.path());
    config.api_listen = "127.0.0.1:0".parse().unwrap();
    config.node_listen = "127.0.0.1:0".parse().unwrap();
    let server = Server::start(config).await.unwrap();
    let url = format!("http://{}", server.api_addr);
    let admin = server.initial_admin.as_ref().unwrap();
    let SignIn::Done(session) = account::sign_in(
        &url,
        &admin.username,
        &admin.password,
        None,
        account::SignInFor::Manage,
    )
    .await
    .unwrap() else {
        panic!("the generated admin has no authenticator");
    };
    let home = tempfile::tempdir().unwrap();
    account::SessionFiles::new(home.path().join(".config/tokenless/sessions"))
        .save(&session)
        .unwrap();
    let laptop = browser_sign_in(&url, &admin.username, &admin.password).await;

    // Both listed; the CLI's marked as the one asking.
    let (ok, out, err) = tokenless(home.path(), &url, &["sign-ins", "list", "--json"]);
    assert!(ok, "{err}");
    let rows: Vec<Value> = serde_json::from_str(&out).unwrap();
    assert_eq!(rows.len(), 2, "{out}");
    let cli = rows.iter().find(|r| r["current"] == true).unwrap();
    assert_eq!(cli["client"], "cli");
    assert_eq!(cli["user_agent"], USER_AGENT);
    let browser = rows.iter().find(|r| r["current"] == false).unwrap();
    assert_eq!(browser["device"], "Firefox on macOS");
    assert!(
        !out.contains(&session.token),
        "a sign-in's token is never listed"
    );
    let (ok, out, _) = tokenless(home.path(), &url, &["sign-ins", "list"]);
    assert!(
        ok && out.contains("(this one)") && out.contains("Firefox on macOS"),
        "{out}"
    );

    // Ending this one is `logout`'s job.
    let short: String = cli["id"].as_str().unwrap().chars().take(8).collect();
    let (ok, _, err) = tokenless(home.path(), &url, &["sign-ins", "revoke", &short]);
    assert!(!ok && err.contains("tokenless logout"), "{err}");

    // Ending the laptop's signs it out, and only it.
    let short: String = browser["id"].as_str().unwrap().chars().take(8).collect();
    let (ok, _, err) = tokenless(home.path(), &url, &["sign-ins", "revoke", &short]);
    assert!(ok && err.contains("Firefox on macOS"), "{err}");
    assert!(!signed_in(&url, &laptop).await);
    let (ok, out, _) = tokenless(home.path(), &url, &["sign-ins", "list", "--json"]);
    assert!(ok);
    assert_eq!(serde_json::from_str::<Vec<Value>>(&out).unwrap().len(), 1);

    // Everywhere else.
    let phone = browser_sign_in(&url, &admin.username, &admin.password).await;
    let tablet = browser_sign_in(&url, &admin.username, &admin.password).await;
    let (ok, _, err) = tokenless(home.path(), &url, &["sign-ins", "revoke", "--others"]);
    assert!(ok && err.contains("ended 2 sign-ins"), "{err}");
    assert!(!signed_in(&url, &phone).await && !signed_in(&url, &tablet).await);

    // An admin signs a person out everywhere: here, themselves.
    let (ok, out, err) = tokenless(
        home.path(),
        &url,
        &["sign-ins", "list", "--user", &admin.username, "--json"],
    );
    assert!(ok, "{err}");
    assert_eq!(serde_json::from_str::<Vec<Value>>(&out).unwrap().len(), 1);
    let (ok, _, err) = tokenless(
        home.path(),
        &url,
        &["sign-ins", "revoke", "--user", &admin.username],
    );
    assert!(ok && err.contains("ended 1 sign-in."), "{err}");
    let (ok, _, err) = tokenless(home.path(), &url, &["sign-ins", "list"]);
    assert!(!ok && err.contains("login"), "{err}");

    let (ok, _, err) = tokenless(home.path(), &url, &["sign-ins", "revoke"]);
    assert!(!ok && err.contains("--others"), "{err}");
}
