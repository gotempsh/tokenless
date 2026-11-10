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
