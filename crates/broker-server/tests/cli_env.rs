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
