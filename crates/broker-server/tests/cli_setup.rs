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
    let identity = tokenless_dataplane::node::enroll(&control_url, &join.token, "laptop")
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
                renews: None,
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

/// What an agent uses to set up tokenless for a person: whether a control
/// plane answers, who is signed in, what exists, and a secret handed over in
/// a file the person fills in, which is gone once it is stored.
#[tokio::test]
async fn an_agent_hands_over_a_secret_in_a_file_without_seeing_it() {
    use broker_server::launcher::secret_file;
    use std::time::Duration;

    let data = tempfile::tempdir().unwrap();
    let mut config = ServerConfig::new(data.path());
    config.api_listen = "127.0.0.1:0".parse().unwrap();
    config.node_listen = "127.0.0.1:0".parse().unwrap();
    let server = Server::start(config).await.unwrap();
    let url = format!("http://{}", server.api_addr);
    let admin = server.initial_admin.as_ref().unwrap();

    assert_eq!(account::probe(&url).await.unwrap(), url);
    let unused = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let nowhere = format!("http://{}", unused.local_addr().unwrap());
    drop(unused);
    let why = account::probe(&nowhere).await.unwrap_err();
    assert_eq!(why, "nothing is listening there");

    let SignIn::Done(session) = account::sign_in(&url, &admin.username, &admin.password, None)
        .await
        .unwrap()
    else {
        panic!("the generated admin has no authenticator");
    };
    let vault = MemoryVault::default();
    vault.save(&session).unwrap();
    let client = ConsoleClient::open(&vault, &url, &NoPrompts).unwrap();
    assert_eq!(client.me().await.unwrap().username, admin.username);
    assert!(client.nodes().await.unwrap().is_empty());

    // The command creates the file, the person saves the key in it.
    let home = tempfile::tempdir().unwrap();
    let path = secret_file::default_path(home.path(), "openai");
    let template = account::pick_template(client.templates().await.unwrap(), "openai").unwrap();
    let fields = &template.template.credential_fields;
    secret_file::prepare(&path, "OpenAI", "personal", fields).unwrap();
    const KEY: &str = "sk-fileHandoffTestKey0123456789abcdef";
    let person = {
        let path = path.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let instructions = std::fs::read_to_string(&path).unwrap();
            std::fs::write(&path, format!("{instructions}{KEY}\n")).unwrap();
        })
    };
    let values = secret_file::wait(
        &path,
        fields,
        Duration::from_secs(10),
        Duration::from_millis(50),
        |e| panic!("the saved key did not parse: {e}"),
    )
    .await
    .unwrap();
    person.await.unwrap();

    let plan = AddService {
        template_id: "openai".into(),
        name: None,
        vault: "personal".into(),
        bundle: Some("my-agent".into()),
        read_only: false,
    };
    let added = client.add_service(&plan, &template, values).await.unwrap();
    // Only once the key is stored is the file deleted.
    secret_file::remove(&path).unwrap();
    assert!(!path.exists());
    let listed = client.credentials(&added.vault.id).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "openai");
    assert_eq!(listed[0].template_id, "openai");
    let stored = all_bytes(data.path());
    assert!(
        !stored.windows(KEY.len()).any(|w| w == KEY.as_bytes()),
        "the key is stored encrypted"
    );

    // The console page for --web opens on this vault and bundle.
    let (bundle, _) = added.bundle.as_ref().unwrap();
    assert_eq!(
        account::add_service_url(
            &format!("{url}/"),
            "openai",
            Some(&added.vault.id),
            Some(&bundle.id)
        )
        .unwrap(),
        format!(
            "{url}/#/add-service/openai?vault={}&bundle={}",
            added.vault.id, bundle.id
        )
    );
    assert_eq!(
        account::add_service_url(&url, "openai", None, None).unwrap(),
        format!("{url}/#/add-service/openai")
    );
    server.shutdown();
}

/// The `tokenless` binary as an agent runs it for a person, signed in
/// through a session file in a scratch home (never the OS keychain).
struct Cli {
    home: tempfile::TempDir,
    url: String,
}

impl Cli {
    fn new(url: &str, session: &account::SavedSession) -> Self {
        let home = tempfile::tempdir().unwrap();
        account::SessionFiles::new(home.path().join(".config/tokenless/sessions"))
            .save(session)
            .unwrap();
        Cli {
            home,
            url: url.to_string(),
        }
    }

    fn spawn(&self, args: &[&str]) -> std::process::Child {
        std::process::Command::new(env!("CARGO_BIN_EXE_tokenless"))
            .args(args)
            .args(["--server", &self.url])
            .env_clear()
            .env("HOME", self.home.path())
            .env("PATH", "/usr/bin:/bin")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap()
    }
}

/// `PATCH /api/v1<path>` as the signed-in person, as the console would.
async fn patch(url: &str, session: &account::SavedSession, path: &str, body: serde_json::Value) {
    let response = reqwest::Client::new()
        .patch(format!("{url}/api/v1{path}"))
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
        "PATCH {path}: {}",
        response.status()
    );
}

/// Waits for `path` to appear, for up to ten seconds.
async fn appears(path: &std::path::Path) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !path.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "{} never appeared",
            path.display()
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

async fn finish(child: std::process::Child) -> std::process::Output {
    tokio::task::spawn_blocking(move || child.wait_with_output().unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn service_add_takes_the_secret_from_a_file_or_the_console_never_from_the_agent() {
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
    let cli = Cli::new(&url, &session);

    // --secret-file: the command creates the file, the person fills it in.
    const KEY: &str = "sk-binaryHandoffTestKey0123456789abcdef";
    let child = cli.spawn(&[
        "service",
        "add",
        "openai",
        "--vault",
        "personal",
        "--bundle",
        "my-agent",
        "--secret-file",
        "--wait",
        "1m",
        "--json",
    ]);
    let file = cli.home.path().join(".tokenless/incoming/openai");
    appears(&file).await;
    let instructions = std::fs::read_to_string(&file).unwrap();
    assert!(
        instructions.contains("Paste it below this line"),
        "{instructions}"
    );
    std::fs::write(&file, format!("{instructions}{KEY}\n")).unwrap();
    let out = finish(child).await;
    let (stdout, stderr) = (
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(out.status.success(), "{stdout}{stderr}");
    assert!(!file.exists(), "the secret file is deleted");
    assert!(
        !stdout.contains(KEY) && !stderr.contains(KEY),
        "{stdout}{stderr}"
    );
    let added: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(added["service"], "openai");
    assert_eq!(added["vault"], "personal");
    assert_eq!(added["bundle"], "my-agent");
    assert_eq!(
        added["run"],
        "tokenless run --vault personal --bundle my-agent -- <command>"
    );
    assert!(stderr.contains(&file.display().to_string()), "{stderr}");

    // The key is read but cannot be stored (a service of that name is
    // already in the vault): the file keeps it for another try.
    let child = cli.spawn(&[
        "service",
        "add",
        "openai",
        "--vault",
        "personal",
        "--secret-file",
        "--wait",
        "1m",
    ]);
    appears(&file).await;
    let instructions = std::fs::read_to_string(&file).unwrap();
    std::fs::write(&file, format!("{instructions}{KEY}\n")).unwrap();
    let out = finish(child).await;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(stderr.contains("already exists"), "{stderr}");
    assert!(
        stderr.contains("nothing was stored") && stderr.contains("still holds the key"),
        "{stderr}"
    );
    assert!(!stderr.contains(KEY), "{stderr}");
    assert!(
        std::fs::read_to_string(&file).unwrap().contains(KEY),
        "a failed store keeps the key in the file"
    );
    // Run again with the problem fixed, it reads the file it left.
    let out = finish(cli.spawn(&[
        "service",
        "add",
        "openai",
        "--vault",
        "personal",
        "--name",
        "openai-work",
        "--secret-file",
        "--wait",
        "1m",
    ]))
    .await;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(!file.exists(), "stored at last, the file is deleted");

    // Stored, then a later step fails: a rule already holds the name, so the
    // credential is saved but its rule is not. The key is in the vault, so
    // the file goes and the person is told what was stored.
    let vault = MemoryVault::default();
    vault.save(&session).unwrap();
    let client = ConsoleClient::open(&vault, &url, &NoPrompts).unwrap();
    let personal = client
        .vaults()
        .await
        .unwrap()
        .into_iter()
        .find(|v| v.name == "personal")
        .unwrap();
    let rule = client
        .rules(&personal.id)
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.name == "openai-work")
        .unwrap();
    patch(
        &url,
        &session,
        &format!("/rules/{}", rule.id),
        serde_json::json!({ "name": "taken" }),
    )
    .await;
    let child = cli.spawn(&[
        "service",
        "add",
        "openai",
        "--vault",
        "personal",
        "--name",
        "taken",
        "--secret-file",
        "--wait",
        "1m",
    ]);
    appears(&file).await;
    let instructions = std::fs::read_to_string(&file).unwrap();
    std::fs::write(&file, format!("{instructions}{KEY}\n")).unwrap();
    let out = finish(child).await;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains(
            "the service 'taken' is stored in vault 'personal', but creating its rule failed"
        ),
        "{stderr}"
    );
    assert!(!stderr.contains("nothing was stored"), "{stderr}");
    assert!(!file.exists(), "a stored key's file is deleted");

    // A bundle name the server would refuse is refused before the person is
    // asked for the key at all.
    let out = finish(cli.spawn(&[
        "service",
        "add",
        "openai",
        "--vault",
        "personal",
        "--name",
        "openai-spaced",
        "--bundle",
        "my agent",
        "--secret-file",
        "--wait",
        "1m",
    ]))
    .await;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(stderr.contains("access bundle name 'my agent'"), "{stderr}");
    assert!(
        !file.exists(),
        "no file is made for a command that cannot work"
    );

    // A file that was already there is the person's: giving up on it leaves
    // it alone.
    let theirs = cli.home.path().join("notes.env");
    std::fs::write(&theirs, "# my notes\n").unwrap();
    let out = finish(cli.spawn(&[
        "service",
        "add",
        "openai",
        "--vault",
        "personal",
        "--secret-file",
        theirs.to_str().unwrap(),
        "--wait",
        "1s",
    ]))
    .await;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(stderr.contains("nothing was saved"), "{stderr}");
    assert_eq!(std::fs::read_to_string(&theirs).unwrap(), "# my notes\n");

    // Stopped while it waits: the file goes, nothing is stored.
    let child = cli.spawn(&[
        "service",
        "add",
        "anthropic",
        "--vault",
        "personal",
        "--secret-file",
    ]);
    let file = cli.home.path().join(".tokenless/incoming/anthropic");
    appears(&file).await;
    std::fs::write(&file, "# half typed\nsk-ant-").unwrap();
    #[cfg(unix)]
    {
        assert!(std::process::Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .unwrap()
            .success());
        let out = finish(child).await;
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success());
        assert!(stderr.contains("nothing was stored"), "{stderr}");
        assert!(!file.exists(), "a stopped handoff deletes the file");
    }
    #[cfg(not(unix))]
    {
        let mut child = child;
        child.kill().unwrap();
        let _ = finish(child).await;
    }

    // --web: the command prints the console page and waits for the service.
    let vault = MemoryVault::default();
    vault.save(&session).unwrap();
    let client = ConsoleClient::open(&vault, &url, &NoPrompts).unwrap();
    let child = cli.spawn(&[
        "service", "add", "github", "--vault", "personal", "--bundle", "my-agent", "--web",
        "--wait", "1m", "--json",
    ]);
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    // The person saves the form in the console. The page saves the service
    // and its rule first and puts the rule in the bundle in a later request;
    // here that comes after a poll has already seen the new service.
    let template = account::pick_template(client.templates().await.unwrap(), "github").unwrap();
    let plan = AddService {
        template_id: "github".into(),
        name: None,
        vault: "personal".into(),
        bundle: None,
        read_only: true,
    };
    let fields = BTreeMap::from([(
        "token".to_string(),
        Zeroizing::new(GITHUB_TOKEN.to_string()),
    )]);
    let saved = client.add_service(&plan, &template, fields).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(4)).await;
    let my_agent = client
        .bundles(&saved.vault.id)
        .await
        .unwrap()
        .into_iter()
        .find(|b| b.name == "my-agent")
        .unwrap();
    let mut rule_ids = my_agent.rule_ids.clone();
    rule_ids.push(saved.rule.id);
    patch(
        &url,
        &session,
        &format!("/bundles/{}", my_agent.id),
        serde_json::json!({ "rule_ids": rule_ids }),
    )
    .await;
    let out = finish(child).await;
    let (stdout, stderr) = (
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(out.status.success(), "{stdout}{stderr}");
    assert!(
        stderr.contains(&format!("{url}/#/add-service/github?vault="))
            && stderr.contains("&bundle="),
        "{stderr}"
    );
    let added: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(added["service"], "github");
    assert_eq!(added["vault"], "personal");
    // The bundle it joined on the page, which already existed.
    assert_eq!(added["bundle"], "my-agent", "{added:#}");
    assert_eq!(added["bundle_created"], false);
    assert_eq!(added["vault_created"], false);
    assert_eq!(
        added["run"],
        "tokenless run --vault personal --bundle my-agent -- <command>"
    );

    // status sees it all, short of a proxy.
    let out = finish(cli.spawn(&["status", "--json"])).await;
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let state = |id: &str| {
        report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == id)
            .unwrap()["state"]
            .clone()
    };
    assert_eq!(state("signed_in"), "ok", "{report:#}");
    assert_eq!(state("services"), "ok", "{report:#}");
    assert_eq!(state("bundle"), "ok", "{report:#}");
    assert_eq!(state("proxy"), "missing", "{report:#}");
    assert_eq!(
        report["next"],
        format!("tokenless proxy add --name <this machine> --state ~/.tokenless/node.json --server {url}")
    );
    server.shutdown();
}
