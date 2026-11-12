// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `tokenless tripwire`: decoy credentials to plant on an agent's machine.
//! A request through a proxy that carries one cuts its session off and
//! raises an alert.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use broker_server::launcher::account::ConsoleClient;
use broker_server::launcher::listing::{relative, table};
use broker_server::launcher::LauncherError;
use chrono::{DateTime, Utc};
use tokenless_control::model::{Tripwire, Vault};
use tokenless_core::tripwire::TripwireKind;

use super::list::{open, pick_vault, print_json};
use super::messages::say;
use super::{CliError, TerminalPrompter};

async fn vault_of(client: &ConsoleClient<'_>, reference: Option<&str>) -> Result<Vault, CliError> {
    let all = client.vaults().await?;
    pick_vault(&all, reference)
}

pub fn parse_kind(raw: &str) -> Result<TripwireKind, CliError> {
    TripwireKind::parse(raw).ok_or_else(|| {
        let kinds: Vec<&str> = TripwireKind::ALL.iter().map(|k| k.as_str()).collect();
        LauncherError::config(format!(
            "'{raw}' is not a tripwire kind; one of: {}",
            kinds.join(", ")
        ))
        .into()
    })
}

/// Prints the first way to plant it alone on stdout, so
/// `>> ~/.aws/credentials` or `>> .env` takes just it, and the rest on
/// stderr. An AWS decoy is a profile of its own when this machine's
/// credentials file has a default one.
pub async fn add(
    kind: String,
    name: String,
    vault: Option<String>,
    server: String,
) -> Result<ExitCode, CliError> {
    let kind = parse_kind(&kind)?;
    let prompter = TerminalPrompter;
    let client = open(&server, &prompter)?;
    let vault = vault_of(&client, vault.as_deref()).await?;
    let created = client.create_tripwire(&vault.id, &name, kind).await?;
    let mut ways = created.plant.iter();
    if let Some(first) = ways.next() {
        let mut text = first.text.clone();
        // Appended to a file that has a default profile already, a second
        // one would break the AWS tools that read it.
        if kind == TripwireKind::Aws && has_default_profile(aws_credentials().as_deref()) {
            let profile = profile_name(&created.tripwire.name);
            text = text.replacen("[default]", &format!("[{profile}]"), 1);
            say(format!(
                "Your AWS credentials file has a default profile already, so the decoy is the '{profile}' profile."
            ));
        }
        println!("{text}");
        say(format!(
            "Tripwire '{}' in vault '{}' ({} decoy). The lines above go in {}; it is shown only once.",
            created.tripwire.name,
            vault.name,
            kind.as_str(),
            first.place
        ));
    }
    for way in ways {
        say(format!("Or in {}:\n{}", way.place, indent(&way.text)));
    }
    say("Plant it where the agent itself never looks: a request through a proxy that carries it cuts that session off and raises an alert.");
    Ok(ExitCode::SUCCESS)
}

/// The AWS credentials file on this machine, where the tools read it.
fn aws_credentials() -> Option<PathBuf> {
    let set = |name| std::env::var_os(name).filter(|v| !v.is_empty());
    set("AWS_SHARED_CREDENTIALS_FILE")
        .map(PathBuf::from)
        .or_else(|| set("HOME").map(|home| PathBuf::from(home).join(".aws/credentials")))
}

fn has_default_profile(file: Option<&Path>) -> bool {
    file.and_then(|f| std::fs::read_to_string(f).ok())
        .is_some_and(|text| text.lines().any(|l| l.trim() == "[default]"))
}

/// The tripwire's name as an AWS profile name.
fn profile_name(name: &str) -> String {
    let profile: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let profile = profile.trim_matches('-');
    if profile.is_empty() {
        "backup".into()
    } else {
        profile.into()
    }
}

fn indent(text: &str) -> String {
    text.lines()
        .map(|l| format!("  {l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn tripwire_table(rows: &[(String, Tripwire)], now: DateTime<Utc>) -> String {
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|(vault, t)| {
            vec![
                vault.clone(),
                t.name.clone(),
                t.kind.as_str().to_string(),
                format!("{}…", t.prefix),
                relative(t.created_at, now),
                t.last_tripped_at
                    .map(|at| relative(at, now))
                    .unwrap_or_else(|| "never".into()),
            ]
        })
        .collect();
    table(
        &["VAULT", "NAME", "KIND", "STARTS", "PLANTED", "TRIPPED"],
        &cells,
    )
}

pub async fn list(vault: Option<String>, json: bool, server: String) -> Result<ExitCode, CliError> {
    let prompter = TerminalPrompter;
    let client = open(&server, &prompter)?;
    let vault = vault_of(&client, vault.as_deref()).await?;
    let wires = client.tripwires(&vault.id).await?;
    if json {
        print_json(&wires)?;
    } else if wires.is_empty() {
        say(format!(
            "no tripwires in vault '{}' yet; plant one with: tokenless tripwire add --kind aws --name <machine>",
            vault.name
        ));
    } else {
        let rows: Vec<(String, Tripwire)> =
            wires.into_iter().map(|t| (vault.name.clone(), t)).collect();
        print!("{}", tripwire_table(&rows, Utc::now()));
    }
    Ok(ExitCode::SUCCESS)
}

/// `reference` is a name, the start of its decoy as `list` shows it, or an id.
pub async fn remove(
    reference: String,
    vault: Option<String>,
    server: String,
) -> Result<ExitCode, CliError> {
    let prompter = TerminalPrompter;
    let client = open(&server, &prompter)?;
    let vault = vault_of(&client, vault.as_deref()).await?;
    let wires = client.tripwires(&vault.id).await?;
    let matches: Vec<&Tripwire> = wires
        .iter()
        .filter(|t| t.name == reference || t.prefix == reference || t.id.to_string() == reference)
        .collect();
    let target = match matches.as_slice() {
        [one] => *one,
        [] => {
            return Err(LauncherError::config(format!(
                "no tripwire '{reference}' in vault '{}'; see them with: tokenless tripwire list --vault {}",
                vault.name, vault.name
            ))
            .into())
        }
        _ => {
            return Err(LauncherError::config(format!(
                "'{reference}' matches {} tripwires; give its id",
                matches.len()
            ))
            .into())
        }
    };
    client.delete_tripwire(&target.id).await?;
    say(format!(
        "Deleted tripwire '{}': proxies stop looking for it. Remove the decoy from where it was planted too.",
        target.name
    ));
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokenless_core::ids::{TripwireId, VaultId};

    #[test]
    fn kinds_are_named_and_unknown_ones_list_the_rest() {
        assert_eq!(parse_kind("aws").unwrap(), TripwireKind::Aws);
        let err = parse_kind("gcp").unwrap_err().to_string();
        assert!(err.contains("aws, github, openai, generic"), "{err}");
    }

    #[test]
    fn the_table_shows_the_start_of_the_decoy_and_when_it_was_tripped() {
        let now = Utc::now();
        let t = Tripwire {
            id: TripwireId::new(),
            vault_id: VaultId::new(),
            name: "laptop".into(),
            kind: TripwireKind::Github,
            value: "ghp_secretpart".into(),
            prefix: "ghp_secr".into(),
            created_by: "user:x".into(),
            created_at: now,
            last_tripped_at: None,
        };
        let out = tripwire_table(&[("work".into(), t)], now);
        assert!(
            out.contains("laptop") && out.contains("ghp_secr…") && out.contains("never"),
            "{out}"
        );
        assert!(!out.contains("ghp_secretpart"), "{out}");
    }
}
