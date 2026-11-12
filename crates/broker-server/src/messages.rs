// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! What the CLI says on standard error when a command succeeds.
//!
//! Agents and scripts often read a command's standard error together with
//! its output, so a command that wraps or feeds another program (`run`,
//! `session`, `mcp`) says nothing on success unless `--verbose` asks for
//! it. A command a person runs to set something up says what changed in
//! one line. Errors and warnings are always printed.

use std::fmt::Display;

/// Prints one `tokenless: ...` line to standard error.
pub fn say(line: impl Display) {
    eprintln!("tokenless: {line}");
}

/// Prints one line only when `--verbose` was given.
pub fn detail(verbose: bool, line: impl FnOnce() -> String) {
    if verbose {
        say(line());
    }
}

fn new_marker(created: bool) -> &'static str {
    if created {
        " (new)"
    } else {
        ""
    }
}

/// Before the credential prompt of `service add`, so nobody types a key
/// without knowing where it goes.
pub fn service_prompt(template: &str, vault: &str) -> String {
    format!("{template} for vault '{vault}'. Stored encrypted; nobody can read it back.")
}

/// When `service add --secret-file` read the key but could not store it:
/// the file is kept, so running the command again picks it up.
pub fn kept_secret_file(path: &str) -> String {
    format!(
        "nothing was stored, and {path} still holds the key. Fix what the error below says (a sign-in, for instance: tokenless login), then run the same command again and it reads the file; or delete the file yourself"
    )
}

pub struct AddedService<'a> {
    pub service: &'a str,
    pub vault: &'a str,
    pub vault_created: bool,
    /// The bundle it joined, and whether `service add` created it.
    pub bundle: Option<(&'a str, bool)>,
    pub rule: &'a str,
}

/// The one line `service add` prints. It shows how to start an agent only
/// when the bundle is new: adding to an existing bundle changes nothing in
/// how it is used.
pub fn added_service(a: &AddedService<'_>) -> String {
    let vault = format!("vault '{}'{}", a.vault, new_marker(a.vault_created));
    match a.bundle {
        Some((bundle, true)) => format!(
            "added {} to {vault} and access bundle '{bundle}' (new). Start an agent: tokenless run --vault {} --bundle {bundle} -- <command>",
            a.service, a.vault
        ),
        Some((bundle, false)) => {
            format!("added {} to {vault} and access bundle '{bundle}'", a.service)
        }
        None => format!(
            "added {} to {vault}, in no access bundle yet: pass --bundle, or add rule '{}' to one in the console",
            a.service, a.rule
        ),
    }
}

/// `login`. Where the session is kept is only news when it is not the
/// keychain.
pub fn signed_in(
    server: &str,
    user: &str,
    until: &str,
    manage: bool,
    file: Option<(&str, &str)>,
) -> String {
    let what = if manage {
        "to manage the broker"
    } else {
        "to start sessions (tokenless run); to change the broker, tokenless login --manage"
    };
    match file {
        None => format!("signed in to {server} as {user} until {until}, {what}"),
        Some((path, reason)) => format!(
            "signed in to {server} as {user} until {until}, {what}. No OS keychain here ({reason}), so the session is in {path}, readable only by you"
        ),
    }
}

/// `proxy add` and `node join`.
pub fn enrolled(name: &str, state: &str) -> String {
    format!("enrolled proxy '{name}'. Start it with: tokenless node run --state {state}")
}

/// `mcp`: the one thing to know about the token it printed, and what has to
/// be running for it to work.
pub fn mcp_token(until: &str, session_id: &str, gateway: &str) -> String {
    format!(
        "this token lasts until {until} and is all the client holds; cut it off with: tokenless session revoke --id {session_id}. Needs a proxy serving its MCP gateway at {gateway}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn added(bundle: Option<(&'static str, bool)>, vault_created: bool) -> String {
        added_service(&AddedService {
            service: "github",
            vault: "work",
            vault_created,
            bundle,
            rule: "github",
        })
    }

    #[test]
    fn adding_a_service_is_one_line() {
        for line in [
            added(Some(("code-review", true)), true),
            added(Some(("code-review", false)), false),
            added(None, false),
        ] {
            assert!(!line.contains('\n'), "{line}");
        }
    }

    #[test]
    fn only_a_new_bundle_gets_the_run_hint() {
        assert_eq!(
            added(Some(("code-review", true)), true),
            "added github to vault 'work' (new) and access bundle 'code-review' (new). Start an agent: tokenless run --vault work --bundle code-review -- <command>"
        );
        assert_eq!(
            added(Some(("code-review", false)), false),
            "added github to vault 'work' and access bundle 'code-review'"
        );
        assert!(added(None, false).contains("in no access bundle yet"));
    }

    #[test]
    fn the_keychain_goes_unmentioned() {
        assert_eq!(
            signed_in(
                "https://broker.example",
                "ana",
                "2026-11-09 10:00 UTC",
                false,
                None
            ),
            "signed in to https://broker.example as ana until 2026-11-09 10:00 UTC, to start sessions (tokenless run); to change the broker, tokenless login --manage"
        );
        assert!(signed_in(
            "https://broker.example",
            "ana",
            "2026-11-09 10:00 UTC",
            true,
            None
        )
        .ends_with("to manage the broker"));
        let file = signed_in(
            "https://broker.example",
            "ana",
            "2026-11-09 10:00 UTC",
            false,
            Some((
                "/home/a/.config/tokenless/session.json",
                "no secret service",
            )),
        );
        assert!(file.contains("readable only by you"), "{file}");
    }

    #[test]
    fn enrolling_names_the_next_command() {
        assert_eq!(
            enrolled("laptop", "./node.json"),
            "enrolled proxy 'laptop'. Start it with: tokenless node run --state ./node.json"
        );
    }
}
