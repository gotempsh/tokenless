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
