// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `tokenless` binary reading its settings from the environment.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

/// `tokenless run -- true` with `TOKENLESS_NO_SKILL_HINT` set to `value`
/// and nothing else configured. Its standard error.
fn run_with_hint_setting(value: &str) -> String {
    let home = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_tokenless"))
        .args(["run", "--", "true"])
        .env_clear()
        .env("HOME", home.path())
        .env("TOKENLESS_NO_SKILL_HINT", value)
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Any value of TOKENLESS_NO_SKILL_HINT parses, so exporting it in a shell
/// never stops `run` from starting. Without a bundle or session, `run`
/// stops at that, before any network access.
#[test]
fn any_value_of_the_skill_hint_setting_lets_run_start() {
    for value in ["1", "0", "true", "false", "yes", "no", "on", "off", ""] {
        let stderr = run_with_hint_setting(value);
        assert!(
            !stderr.contains("invalid value") && !stderr.contains("value is required"),
            "TOKENLESS_NO_SKILL_HINT={value:?}: {stderr}"
        );
        assert!(
            stderr.contains("which access bundle"),
            "TOKENLESS_NO_SKILL_HINT={value:?}: {stderr}"
        );
    }
}

/// `serve` shuts down on SIGTERM, which `docker stop` and systemd send,
/// instead of dying at once: its shutdown runs, and the telemetry still
/// queued is sent.
#[cfg(unix)]
#[test]
fn serve_shuts_down_on_sigterm() {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;

    let data = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_tokenless"))
        .arg("serve")
        .arg("--data-dir")
        .arg(data.path())
        .args([
            "--api-listen",
            "127.0.0.1:0",
            "--node-listen",
            "127.0.0.1:0",
        ])
        .env_clear()
        .env("HOME", data.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pid = child.id().to_string();
    // A serve that never stops fails the test rather than hanging it.
    let watchdog = pid.clone();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(60));
        let _ = Command::new("kill").args(["-KILL", &watchdog]).status();
    });
    let mut lines = BufReader::new(child.stdout.take().unwrap())
        .lines()
        .map_while(Result::ok);
    assert!(
        lines.any(|l| l.contains("server started")),
        "serve did not start"
    );
    assert!(Command::new("kill")
        .args(["-TERM", &pid])
        .status()
        .unwrap()
        .success());
    let rest: Vec<String> = lines.collect();
    let status = child.wait().unwrap();
    assert!(status.success(), "{status:?}: {rest:?}");
    assert!(
        rest.iter()
            .any(|l| l.contains("shutting down") && l.contains("SIGTERM")),
        "{rest:?}"
    );
}

/// `tokenless update` stopped mid-download by SIGTERM (systemd stopping the
/// update's unit) leaves nothing next to the binary.
#[cfg(unix)]
#[test]
fn an_interrupted_update_leaves_nothing_next_to_the_binary() {
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    // A mirror that accepts connections and never answers.
    let mirror = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", mirror.local_addr().unwrap());
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in mirror.incoming().flatten() {
            held.push(stream);
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let binary = dir.path().join("tokenless");
    std::fs::copy(env!("CARGO_BIN_EXE_tokenless"), &binary).unwrap();
    let staged = || {
        std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(".tokenless-update-")
            })
            .count()
    };
    let child = Command::new(&binary)
        .args(["update", "--download-url", &url])
        .env_clear()
        .env("HOME", dir.path())
        .env("PATH", "/usr/bin:/bin")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while staged() == 0 {
        assert!(Instant::now() < deadline, "the update never staged a file");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap()
        .success());
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("stopped by SIGTERM"), "{stderr}");
    assert_eq!(staged(), 0, "the staged file is removed");
}

/// A URL nothing listens on.
fn nowhere() -> String {
    let unused = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    format!("http://{}", unused.local_addr().unwrap())
}

/// `tokenless <args>` with only `HOME` set: its exit code, output and
/// standard error.
fn tokenless(home: &std::path::Path, args: &[&str]) -> (Option<i32>, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_tokenless"))
        .args(args)
        .env_clear()
        .env("HOME", home)
        .output()
        .unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The first thing an agent runs on a machine with nothing set up: it fails,
/// and its JSON names the one command to run next.
#[test]
fn status_on_a_bare_machine_says_to_start_a_control_plane() {
    let home = tempfile::tempdir().unwrap();
    let server = nowhere();
    let (code, out, err) = tokenless(home.path(), &["status", "--json", "--server", &server]);
    assert_eq!(code, Some(1), "{out}{err}");
    let report: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(report["ready"], false);
    assert_eq!(report["checks"][0]["id"], "control_plane");
    assert_eq!(report["checks"][0]["state"], "failed");
    assert_eq!(
        report["next"],
        format!("start the control plane at {server}, or pass --server")
    );
    // For people, the same as text, ending in what to do.
    let (code, out, _) = tokenless(home.path(), &["status", "--server", &server]);
    assert_eq!(code, Some(1));
    assert!(
        out.contains("!!  Control plane") && out.contains("Next:\n"),
        "{out}"
    );
}

/// With a control plane up but nobody signed in, `status` says to sign in.
#[cfg(unix)]
#[test]
fn status_with_a_control_plane_says_to_sign_in() {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;

    let data = tempfile::tempdir().unwrap();
    let mut serve = Command::new(env!("CARGO_BIN_EXE_tokenless"))
        .arg("serve")
        .arg("--data-dir")
        .arg(data.path())
        .args([
            "--api-listen",
            "127.0.0.1:0",
            "--node-listen",
            "127.0.0.1:0",
        ])
        .env_clear()
        .env("HOME", data.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let started = BufReader::new(serve.stdout.take().unwrap())
        .lines()
        .map_while(Result::ok)
        .find(|l| l.contains("server started"))
        .expect("serve started");
    let line: serde_json::Value = serde_json::from_str(&started).unwrap();
    let api = line["fields"]["api_addr"]
        .as_str()
        .or_else(|| line["api_addr"].as_str())
        .unwrap_or_else(|| panic!("no api_addr in {started}"))
        .to_string();
    let server = format!("http://{api}");
    let home = tempfile::tempdir().unwrap();
    let (code, out, err) = tokenless(home.path(), &["status", "--json", "--server", &server]);
    let _ = serve.kill();
    let _ = serve.wait();
    assert_eq!(code, Some(1), "{out}{err}");
    let report: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(report["checks"][0]["state"], "ok", "{report:#}");
    assert_eq!(report["checks"][1]["id"], "signed_in");
    assert_eq!(report["checks"][1]["state"], "missing");
    assert_eq!(report["next"], format!("tokenless login --server {server}"));
}

/// Finding the template for a tool's variable works before anything is set
/// up, from the built-in catalogue.
#[test]
fn templates_find_a_variable_s_service_before_any_setup() {
    let home = tempfile::tempdir().unwrap();
    let server = nowhere();
    let (code, out, err) = tokenless(
        home.path(),
        &[
            "service",
            "templates",
            "OPENAI_API_KEY",
            "--json",
            "--server",
            &server,
        ],
    );
    assert_eq!(code, Some(0), "{err}");
    let rows: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(rows[0]["id"], "openai", "{rows:#}");
    assert_eq!(rows[0]["fields"][0]["name"], "api_key");
    let (code, out, err) = tokenless(
        home.path(),
        &["service", "templates", "github", "--server", &server],
    );
    assert_eq!(code, Some(0));
    assert!(out.starts_with("ID ") && out.contains("\ngithub "), "{out}");
    assert!(err.contains("built-in templates"), "{err}");
    let (code, _, err) = tokenless(
        home.path(),
        &[
            "service",
            "templates",
            "no-such-service-anywhere",
            "--server",
            &server,
        ],
    );
    assert_eq!(code, Some(1));
    assert!(err.contains("no template matches"), "{err}");
}

/// An agent without a terminal is told how to hand the secret over instead
/// of failing on an empty standard input.
#[test]
fn service_add_flags_for_a_secret_the_agent_never_sees_parse() {
    let home = tempfile::tempdir().unwrap();
    let server = nowhere();
    for args in [
        vec![
            "service",
            "add",
            "openai",
            "--secret-file",
            "--server",
            &server,
        ],
        vec![
            "service",
            "add",
            "openai",
            "--secret-file",
            "/tmp/k",
            "--wait",
            "5m",
            "--server",
            &server,
        ],
        vec![
            "service",
            "add",
            "openai",
            "--web",
            "--open",
            "--no-wait",
            "--json",
            "--server",
            &server,
        ],
    ] {
        let (code, _, err) = tokenless(home.path(), &args);
        assert_eq!(code, Some(1), "{args:?}");
        // Parsed, then stopped at the sign-in.
        assert!(err.contains("not signed in"), "{args:?}: {err}");
    }
    for (args, why) in [
        (
            vec!["service", "add", "openai", "--web", "--secret-file"],
            "cannot be used with",
        ),
        (
            vec!["service", "add", "openai", "--web", "--read-only"],
            "cannot be used with",
        ),
        (vec!["service", "add", "openai", "--no-wait"], "--web"),
    ] {
        let (code, _, err) = tokenless(home.path(), &args);
        assert_eq!(code, Some(2), "{args:?}");
        assert!(err.contains(why), "{args:?}: {err}");
    }
}
