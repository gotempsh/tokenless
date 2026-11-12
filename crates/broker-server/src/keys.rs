// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `tokenless bundle key`: launcher keys, for agent machines. A launcher key
//! only starts sessions from one access bundle, so the machine holds no
//! sign-in that reaches anything else.

use std::collections::BTreeMap;
use std::process::ExitCode;

use broker_server::launcher::account::ConsoleClient;
use broker_server::launcher::listing::{relative, table};
use broker_server::launcher::{parse_duration_secs, parse_label, LauncherError};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use tokenless_control::model::{AccessBundle, Vault};
use tokenless_control::service::launcher_keys::LauncherKey;

use super::list::{open, pick_vault, print_json};
use super::messages::say;
use super::{CliError, TerminalPrompter};

pub struct AddKey {
    pub bundle: String,
    pub vault: Option<String>,
    pub name: String,
    pub ttl: Option<String>,
    pub request_limit: Option<u64>,
    pub proxy: Option<String>,
    pub labels: Vec<String>,
    pub expires_in_days: Option<u32>,
    pub server: String,
}

/// The vault `reference` names, or the only one there is.
async fn vault_of(client: &ConsoleClient<'_>, reference: Option<&str>) -> Result<Vault, CliError> {
    let all = client.vaults().await?;
    pick_vault(&all, reference)
}

fn bundle_of(
    bundles: &[AccessBundle],
    reference: &str,
    vault: &Vault,
) -> Result<AccessBundle, CliError> {
    bundles
        .iter()
        .find(|b| b.name == reference || b.id.to_string() == reference)
        .cloned()
        .ok_or_else(|| {
            let names: Vec<&str> = bundles.iter().map(|b| b.name.as_str()).collect();
            LauncherError::config(format!(
                "no access bundle named '{reference}' in vault '{}'; its bundles: {}",
                vault.name,
                if names.is_empty() {
                    "none".to_string()
                } else {
                    names.join(", ")
                }
            ))
            .into()
        })
}

/// Prints the key alone on stdout, so `> key.txt` captures just it, and how
/// to use it on stderr.
pub async fn add(args: AddKey) -> Result<ExitCode, CliError> {
    let prompter = TerminalPrompter;
    let client = open(&args.server, &prompter)?;
    let vault = vault_of(&client, args.vault.as_deref()).await?;
    let bundles = client.bundles(&vault.id).await?;
    let bundle = bundle_of(&bundles, &args.bundle, &vault)?;
    let max_ttl_secs = args.ttl.as_deref().map(parse_duration_secs).transpose()?;
    let mut labels = BTreeMap::new();
    for raw in &args.labels {
        let (k, v) = parse_label(raw)?;
        labels.insert(k, v);
    }
    let node_id = match &args.proxy {
        None => None,
        Some(reference) => {
            let nodes = client.nodes().await?;
            let node = nodes
                .iter()
                .find(|n| n.name == *reference || n.id.to_string() == *reference)
                .ok_or_else(|| {
                    LauncherError::config(format!(
                        "no proxy named '{reference}'; see them with: tokenless proxy list"
                    ))
                })?;
            Some(node.id)
        }
    };
    let created = client
        .create_launcher_key(
            &vault.id,
            &json!({
                "name": args.name,
                "bundle": bundle.id.to_string(),
                "max_ttl_secs": max_ttl_secs,
                "request_limit": args.request_limit,
                "node_id": node_id,
                "labels": labels,
                "expires_in_days": args.expires_in_days,
            }),
        )
        .await?;
    let key = &created.launcher_key;
    println!("{}", created.key);
    say(format!(
        "Launcher key '{}' for bundle '{}' in vault '{}': it starts sessions of up to {} and nothing else, until {}. It is shown only once.",
        key.name,
        bundle.name,
        vault.name,
        duration(key.max_ttl_secs),
        key.expires_at.format("%Y-%m-%d"),
    ));
    say(format!(
        "On the agent machine, put it in a file only you can read and run:\n  tokenless run --api-key-file <file> --vault {} --bundle {} -- <command>",
        vault.name, bundle.name
    ));
    Ok(ExitCode::SUCCESS)
}

/// `900` as `15m`, `3600` as `1h`.
fn duration(secs: u64) -> String {
    match secs {
        s if s % 3600 == 0 => format!("{}h", s / 3600),
        s if s % 60 == 0 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyState {
    Active,
    Expired,
    Revoked,
}

impl KeyState {
    fn of(key: &LauncherKey, now: DateTime<Utc>) -> Self {
        if key.revoked_at.is_some() {
            KeyState::Revoked
        } else if key.expires_at <= now {
            KeyState::Expired
        } else {
            KeyState::Active
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct KeyRow {
    pub vault: String,
    pub bundle: String,
    #[serde(flatten)]
    pub key: LauncherKey,
    pub state: KeyState,
}

pub fn key_table(rows: &[KeyRow], now: DateTime<Utc>) -> String {
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            let state = match r.state {
                KeyState::Active => format!("active, expires {}", relative(r.key.expires_at, now)),
                KeyState::Expired => format!("expired {}", relative(r.key.expires_at, now)),
                KeyState::Revoked => format!(
                    "revoked {}",
                    r.key
                        .revoked_at
                        .map(|t| relative(t, now))
                        .unwrap_or_default()
                ),
            };
            vec![
                r.vault.clone(),
                r.bundle.clone(),
                r.key.name.clone(),
                r.key.prefix.clone(),
                duration(r.key.max_ttl_secs),
                r.key
                    .last_used_at
                    .map(|t| relative(t, now))
                    .unwrap_or_else(|| "never".into()),
                state,
            ]
        })
        .collect();
    table(
        &[
            "VAULT",
            "BUNDLE",
            "NAME",
            "PREFIX",
            "SESSIONS UP TO",
            "LAST USED",
            "STATE",
        ],
        &cells,
    )
}

pub async fn list(
    vault: Option<String>,
    bundle: Option<String>,
    json: bool,
    server: String,
) -> Result<ExitCode, CliError> {
    let prompter = TerminalPrompter;
    let client = open(&server, &prompter)?;
    let vault = vault_of(&client, vault.as_deref()).await?;
    let (bundles, keys) =
        futures_util::try_join!(client.bundles(&vault.id), client.launcher_keys(&vault.id))?;
    let only = bundle
        .as_deref()
        .map(|b| bundle_of(&bundles, b, &vault))
        .transpose()?;
    let now = Utc::now();
    let rows: Vec<KeyRow> = keys
        .into_iter()
        .filter(|k| only.as_ref().is_none_or(|b| b.id == k.bundle_id))
        .map(|key| KeyRow {
            vault: vault.name.clone(),
            bundle: bundles
                .iter()
                .find(|b| b.id == key.bundle_id)
                .map(|b| b.name.clone())
                .unwrap_or_else(|| format!("{} (deleted)", key.bundle_id)),
            state: KeyState::of(&key, now),
            key,
        })
        .collect();
    if json {
        print_json(&rows)?;
    } else if rows.is_empty() {
        say("no launcher keys yet; give an agent machine one with: tokenless bundle key add <bundle> --name <machine>");
    } else {
        print!("{}", key_table(&rows, now));
    }
    Ok(ExitCode::SUCCESS)
}

/// `key` is a name, prefix or id. A name used by several keys is refused,
/// listing their prefixes.
pub async fn revoke(
    key: String,
    vault: Option<String>,
    server: String,
) -> Result<ExitCode, CliError> {
    let prompter = TerminalPrompter;
    let client = open(&server, &prompter)?;
    let vault = vault_of(&client, vault.as_deref()).await?;
    let keys = client.launcher_keys(&vault.id).await?;
    let exact: Vec<&LauncherKey> = keys
        .iter()
        .filter(|k| k.prefix == key || k.id.to_string() == key)
        .collect();
    let matches: Vec<&LauncherKey> = if exact.is_empty() {
        keys.iter()
            .filter(|k| k.name == key && k.revoked_at.is_none())
            .collect()
    } else {
        exact
    };
    let target = match matches.as_slice() {
        [one] => *one,
        [] => {
            return Err(LauncherError::config(format!(
                "no launcher key '{key}' in vault '{}'; see them with: tokenless bundle key list --vault {}",
                vault.name, vault.name
            ))
            .into())
        }
        several => {
            let prefixes: Vec<&str> = several.iter().map(|k| k.prefix.as_str()).collect();
            return Err(LauncherError::config(format!(
                "several launcher keys are named '{key}' ({}); revoke one by its prefix",
                prefixes.join(", ")
            ))
            .into());
        }
    };
    let revoked = client.revoke_launcher_key(&vault.id, &target.id).await?;
    say(format!(
        "Revoked launcher key '{}' ({}); ended {} live session{} it had started.",
        revoked.launcher_key.name,
        revoked.launcher_key.prefix,
        revoked.sessions_revoked,
        if revoked.sessions_revoked == 1 {
            ""
        } else {
            "s"
        }
    ));
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_read_as_typed() {
        assert_eq!(duration(900), "15m");
        assert_eq!(duration(3600), "1h");
        assert_eq!(duration(90), "90s");
    }
}
