// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Git scopes with a real `git` client: clones, fetches and pushes through
//! the proxy to a local HTTPS upstream running `git http-backend`, trusting
//! the interception CA from a file the way an agent's Git does. Skipped,
//! with a message, where `git` or its `http-backend` is not installed.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokenless_core::git::GitScope;
use tokenless_core::ids::RuleId;
use tokenless_core::path::{HttpMethod, PathPattern};
use tokenless_core::scope::Scope;
use tokenless_core::session::{SessionClaims, SessionSigner};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio_rustls::TlsAcceptor;

use crate::testing::{https_listener, running, Running};

/// What the upstream was asked, as `METHOD /path?query`.
type Seen = Arc<Mutex<Vec<String>>>;

/// Whether `git` and `git http-backend` are here.
async fn git_available() -> bool {
    let Ok(out) = Command::new("git").arg("--exec-path").output().await else {
        return false;
    };
    let exec = String::from_utf8_lossy(&out.stdout).trim().to_string();
    out.status.success() && Path::new(&exec).join("git-http-backend").exists()
}

/// Runs `git` with no user or system configuration and no proxy from the
/// environment, so only what the test passes applies.
async fn git<S: AsRef<std::ffi::OsStr>>(
    home: &Path,
    dir: &Path,
    args: &[S],
) -> std::process::Output {
    let mut cmd = Command::new("git");
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", home.join("gitconfig"))
        .env("GIT_TERMINAL_PROMPT", "0")
        .args([
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.com",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(args)
        .current_dir(dir)
        .kill_on_drop(true);
    tokio::time::timeout(Duration::from_secs(60), cmd.output())
        .await
        .expect("git finishes")
        .unwrap()
}

#[track_caller]
fn ok(out: &std::process::Output) -> String {
    assert!(
        out.status.success(),
        "git failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Deterministic bytes that do not compress, so a pack really is large.
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// A bare repository at `root/<name>.git` whose `main` holds `files`.
async fn seed(home: &Path, root: &Path, name: &str, files: &[(&str, &[u8])]) {
    let bare = root.join(format!("{name}.git"));
    std::fs::create_dir_all(&bare).unwrap();
    ok(&git(home, &bare, &["init", "--bare", "-q"]).await);
    let work = home.join(format!("seed-{}", name.replace('/', "-")));
    std::fs::create_dir_all(&work).unwrap();
    ok(&git(home, &work, &["init", "-q"]).await);
    for (file, content) in files {
        std::fs::write(work.join(file), content).unwrap();
    }
    ok(&git(home, &work, &["add", "."]).await);
    ok(&git(home, &work, &["commit", "-q", "-m", "seed"]).await);
    let target = bare.to_string_lossy().into_owned();
    ok(&git(home, &work, &["push", "-q", &target, "main"]).await);
}

/// A local HTTPS upstream for `localhost` serving the repositories under
/// `root` through `git http-backend`. It answers 401 unless the request
/// carries `Authorization: Bearer t`, the credential the proxy injects, and
/// redirects anything under `acme/moved` to `acme/other`.
async fn git_upstream(
    root: PathBuf,
    seen: Seen,
) -> (u16, rustls::pki_types::CertificateDer<'static>) {
    let (listener, server, cert) = https_listener().await;
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = TlsAcceptor::from(server.clone());
            let (root, seen) = (root.clone(), seen.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let service = service_fn(move |req| serve(req, root.clone(), seen.clone(), port));
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    (port, cert)
}

async fn serve(
    req: Request<Incoming>,
    root: PathBuf,
    seen: Seen,
    port: u16,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or_default().to_string();
    seen.lock()
        .unwrap()
        .push(format!("{method} {path}?{query}"));
    let header = |name: &str| {
        req.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let answer = |status: StatusCode, headers: &[(&str, String)]| {
        let mut response = Response::builder().status(status);
        for (name, value) in headers {
            response = response.header(*name, value);
        }
        Ok(response.body(Full::new(Bytes::new())).unwrap())
    };
    if header("authorization").as_deref() != Some("Bearer t") {
        return answer(StatusCode::UNAUTHORIZED, &[]);
    }
    if let Some(rest) = path.strip_prefix("/acme/moved.git/") {
        let location = format!("https://localhost:{port}/acme/other.git/{rest}?{query}");
        return answer(StatusCode::FOUND, &[("location", location)]);
    }
    let content_type = header("content-type").unwrap_or_default();
    let encoding = header("content-encoding").unwrap_or_default();
    let protocol = header("git-protocol").unwrap_or_default();
    let body = req.into_body().collect().await.unwrap().to_bytes();

    let mut child = Command::new("git")
        .arg("http-backend")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", root.join("gitconfig"))
        .env("GIT_PROJECT_ROOT", &root)
        .env("GIT_HTTP_EXPORT_ALL", "1")
        // http-backend allows receive-pack to an authenticated user.
        .env("REMOTE_USER", "test")
        .env("REMOTE_ADDR", "127.0.0.1")
        .env("REQUEST_METHOD", &method)
        .env("PATH_INFO", &path)
        .env("QUERY_STRING", &query)
        .env("CONTENT_TYPE", content_type)
        .env("CONTENT_LENGTH", body.len().to_string())
        .env("HTTP_CONTENT_ENCODING", encoding)
        .env("GIT_PROTOCOL", protocol)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    tokio::spawn(async move {
        let _ = stdin.write_all(&body).await;
    });
    let out = child.wait_with_output().await.unwrap();

    // CGI output: headers, a blank line, the body.
    let split = out
        .stdout
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| (i, i + 4))
        .or_else(|| {
            out.stdout
                .windows(2)
                .position(|w| w == b"\n\n")
                .map(|i| (i, i + 2))
        })
        .unwrap();
    let head = String::from_utf8_lossy(&out.stdout[..split.0]).into_owned();
    let mut response = Response::builder();
    for line in head.lines() {
        let (name, value) = line.split_once(':').unwrap();
        if name.eq_ignore_ascii_case("status") {
            let code: u16 = value.trim()[..3].parse().unwrap();
            response = response.status(code);
        } else {
            response = response.header(name.trim(), value.trim());
        }
    }
    Ok(response
        .body(Full::new(Bytes::copy_from_slice(&out.stdout[split.1..])))
        .unwrap())
}

/// The CA a data plane intercepts with, as the PEM file Git trusts.
fn ca_pem(r: &Running, dir: &Path) -> PathBuf {
    let b64 = STANDARD.encode(&r.f.ca_cert_der);
    let lines: Vec<&str> = b64
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    let path = dir.join("ca.pem");
    std::fs::write(
        &path,
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            lines.join("\n")
        ),
    )
    .unwrap();
    path
}

/// Installs one rule per scope on the data plane's host, all injecting
/// `Bearer t` for `GET` and `POST`, and returns a session token for each.
fn install_git_rules(r: &Running, scopes: Vec<GitScope>) -> Vec<String> {
    let scope = Scope::parse("vault:test").unwrap();
    let rules: Vec<RuleId> = scopes.iter().map(|_| RuleId::new()).collect();
    let mut body = r.f.snapshot_body(
        2,
        rules
            .iter()
            .map(|id| (*id, scope.clone(), r.host.as_str(), "t"))
            .collect(),
    );
    body.egress = tokenless_core::egress::EgressPolicy {
        block_private: false,
        allow: vec![],
    };
    for (rule, git) in body.rules.iter_mut().zip(scopes) {
        rule.allow.paths = vec![PathPattern::parse("/*").unwrap()];
        rule.allow.methods = vec![
            HttpMethod::parse("GET").unwrap(),
            HttpMethod::parse("POST").unwrap(),
        ];
        rule.allow.git = Some(git);
    }
    r.installer.install(&r.f.sign(&body)).unwrap();
    rules
        .into_iter()
        .map(|rule| {
            let claims = SessionClaims::new(
                scope.clone(),
                vec![rule],
                600,
                None,
                BTreeMap::new(),
                Utc::now(),
                3600,
            )
            .unwrap();
            SessionSigner::new(r.f.session_signer.clone())
                .sign(&claims)
                .unwrap()
        })
        .collect()
}

#[tokio::test]
async fn a_real_git_client_clones_and_pushes_only_what_its_scope_allows() {
    if !git_available().await {
        eprintln!("skipping: git or git http-backend is not installed");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let (home, root) = (tmp.path().join("home"), tmp.path().join("repos"));
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&root).unwrap();
    // A pack of several megabytes, streamed both ways.
    let big = noise(6 * 1024 * 1024, 7);
    seed(&home, &root, "acme/widgets", &[("big.bin", &big)]).await;
    seed(&home, &root, "acme/other", &[("other.txt", b"not yours")]).await;

    let seen: Seen = Arc::default();
    let (port, cert) = git_upstream(root.clone(), seen.clone()).await;
    let r = running(&format!("localhost:{port}"), vec![cert]).await;
    let ca = ca_pem(&r, tmp.path());
    let tokens = install_git_rules(
        &r,
        vec![
            GitScope::new(vec!["acme/widgets".into(), "acme/moved".into()], false).unwrap(),
            GitScope::new(vec!["acme/widgets".into()], true).unwrap(),
        ],
    );
    let (read, push) = (&tokens[0], &tokens[1]);
    let proxy = r.dp.local_addr();
    let url = |repo: &str| format!("https://localhost:{port}/{repo}");
    // `git` through the proxy with `token`, trusting its CA.
    let through = |token: &str, args: &[&str]| {
        let mut all = vec![
            "-c".to_string(),
            format!("http.proxy=http://x:{token}@{proxy}"),
            "-c".into(),
            "http.proxyAuthMethod=basic".into(),
            "-c".into(),
            format!("http.sslCAInfo={}", ca.display()),
        ];
        all.extend(args.iter().map(|a| a.to_string()));
        all
    };
    macro_rules! git_through {
        ($dir:expr, $token:expr, $($arg:expr),+) => {
            git(&home, $dir, &through($token, &[$($arg),+])).await
        };
    }

    // Read access clones its repository, the pack intact.
    let widgets = url("acme/widgets.git");
    ok(&git_through!(
        tmp.path(),
        read,
        "clone",
        "-q",
        &widgets,
        "clone"
    ));
    let clone = tmp.path().join("clone");
    assert_eq!(std::fs::read(clone.join("big.bin")).unwrap(), big);

    // Another repository is refused at discovery; the upstream never sees it.
    let out = git_through!(tmp.path(), read, "clone", "-q", &url("acme/other.git"), "o");
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("403"),
        "{out:?}"
    );

    // A redirect is the client's to follow, and the request it makes then
    // is checked like any other: refused, as acme/other is not in scope.
    let out = git_through!(tmp.path(), read, "clone", "-q", &url("acme/moved.git"), "m");
    assert!(!out.status.success());

    // Read access cannot push: refused at discovery, before any pack.
    std::fs::write(clone.join("more.bin"), noise(3 * 1024 * 1024, 11)).unwrap();
    ok(&git(&home, &clone, &["add", "more.bin"]).await);
    ok(&git(&home, &clone, &["commit", "-q", "-m", "more"]).await);
    let out = git_through!(&clone, read, "push", "-q", "origin", "main");
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("403"),
        "{out:?}"
    );
    {
        let seen = seen.lock().unwrap();
        assert!(seen.iter().all(|s| !s.contains("receive-pack")), "{seen:?}");
        assert!(seen.iter().all(|s| !s.contains("/acme/other")), "{seen:?}");
        assert_eq!(
            seen.iter().filter(|s| s.contains("/acme/moved")).count(),
            1,
            "{seen:?}"
        );
    }

    // Push access pushes the new pack, and fetches.
    ok(&git_through!(&clone, push, "push", "-q", &widgets, "main"));
    let bare = root.join("acme/widgets.git");
    let head = ok(&git(&home, &bare, &["log", "-1", "--format=%s", "main"]).await);
    assert_eq!(head.trim(), "more");
    ok(&git_through!(&clone, push, "fetch", "-q", &widgets));
    assert!(seen
        .lock()
        .unwrap()
        .iter()
        .any(|s| s.starts_with("POST /acme/widgets.git/git-receive-pack")));
}
