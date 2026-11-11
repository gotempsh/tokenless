// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `list` commands: vaults, services, bundles, sessions and proxies,
//! as the signed-in person sees them in the console. A table on stdout for
//! people, the same rows as JSON with `--json`; hints go to stderr, so the
//! output stays parseable.

use std::collections::HashMap;
use std::process::ExitCode;

use broker_server::launcher::account::{ConsoleClient, SessionScope, SessionStore};
use broker_server::launcher::listing;
use broker_server::launcher::LauncherError;
use chrono::Utc;
use futures_util::future::try_join_all;
use serde::Serialize;
use tokenless_control::model::{TemplateStatus, Vault};
use tokenless_core::ids::VaultId;
use tokenless_core::template::ServiceTemplate;

use super::messages::say;
use super::{CliError, TerminalPrompter};

/// How many sessions `session list` shows without `--limit`.
pub const DEFAULT_SESSION_LIMIT: usize = 20;

pub(crate) fn open<'p>(
    server: &str,
    prompter: &'p TerminalPrompter,
) -> Result<ConsoleClient<'p>, CliError> {
    Ok(ConsoleClient::open(
        &SessionStore::system(),
        server,
        prompter,
    )?)
}

pub(crate) fn print_json(value: &impl Serialize) -> Result<(), CliError> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|e| LauncherError::config(format!("encoding the output as JSON: {e}")))?;
    println!("{text}");
    Ok(())
}

/// The rows as JSON, or as a table; with no rows, `empty` on stderr
/// instead of a bare header (JSON still prints `[]`).
fn output<R: Serialize>(
    rows: &[R],
    json: bool,
    table: impl FnOnce(&[R]) -> String,
    empty: &str,
) -> Result<ExitCode, CliError> {
    if json {
        print_json(&rows)?;
    } else if rows.is_empty() {
        say(empty);
    } else {
        print!("{}", table(rows));
    }
    Ok(ExitCode::SUCCESS)
}

/// The vaults `reference` (a name or id) picks, or every vault without one.
fn pick_vaults(all: &[Vault], reference: Option<&str>) -> Result<Vec<Vault>, CliError> {
    let Some(reference) = reference else {
        return Ok(all.to_vec());
    };
    match all
        .iter()
        .find(|v| v.name == reference || v.id.to_string() == reference)
    {
        Some(v) => Ok(vec![v.clone()]),
        None => {
            let names: Vec<&str> = all.iter().map(|v| v.name.as_str()).collect();
            Err(LauncherError::config(format!(
                "no vault named '{reference}'; the vaults you can see: {}",
                if names.is_empty() {
                    "none".to_string()
                } else {
                    names.join(", ")
                }
            ))
            .into())
        }
    }
}

/// The vault `reference` (a name or id) picks, or the only one there is.
pub(crate) fn pick_vault(all: &[Vault], reference: Option<&str>) -> Result<Vault, CliError> {
    if reference.is_some() {
        return pick_vaults(all, reference).map(|mut v| v.remove(0));
    }
    match all {
        [only] => Ok(only.clone()),
        [] => Err(LauncherError::config(
            "no vaults yet; one is created with the first service: tokenless service add <template> --vault personal --bundle my-agent",
        )
        .into()),
        several => {
            let names: Vec<&str> = several.iter().map(|v| v.name.as_str()).collect();
            Err(LauncherError::config(format!(
                "several vaults ({}); say which with --vault",
                names.join(", ")
            ))
            .into())
        }
    }
}

/// Fetches something for each vault at once.
async fn per_vault<T, F, Fut>(vaults: &[Vault], fetch: F) -> Result<HashMap<VaultId, T>, CliError>
where
    F: Fn(VaultId) -> Fut,
    Fut: std::future::Future<Output = Result<T, LauncherError>>,
{
    let fetched = try_join_all(vaults.iter().map(|v| {
        let id = v.id;
        let fut = fetch(id);
        async move { fut.await.map(|t| (id, t)) }
    }))
    .await?;
    Ok(fetched.into_iter().collect())
}

pub async fn vaults(json: bool, server: String) -> Result<ExitCode, CliError> {
    let prompter = TerminalPrompter;
    let client = open(&server, &prompter)?;
    let vaults = client.vaults().await?;
    let services = per_vault(&vaults, |id| {
        let client = &client;
        async move { client.credentials(&id).await.map(|c| c.len()) }
    })
    .await?;
    let bundles = per_vault(&vaults, |id| {
        let client = &client;
        async move { client.bundles(&id).await.map(|b| b.len()) }
    })
    .await?;
    let rows = listing::vault_rows(&vaults, &services, &bundles);
    output(
        &rows,
        json,
        |r| listing::vault_table(r, Utc::now()),
        "no vaults yet; one is created with the first service: tokenless service add <template> --vault personal --bundle my-agent",
    )
}

pub async fn services(
    vault: Option<String>,
    json: bool,
    server: String,
) -> Result<ExitCode, CliError> {
    let prompter = TerminalPrompter;
    let client = open(&server, &prompter)?;
    let all = client.vaults().await?;
    let vaults = pick_vaults(&all, vault.as_deref())?;
    let credentials = per_vault(&vaults, |id| {
        let client = &client;
        async move { client.credentials(&id).await }
    })
    .await?;
    // Every approved version: a service keeps the version it was made on.
    let approved: Vec<ServiceTemplate> = client
        .templates()
        .await?
        .into_iter()
        .filter(|t| t.status == TemplateStatus::Approved)
        .map(|t| t.template)
        .collect();
    let credentials: Vec<_> = vaults
        .iter()
        .flat_map(|v| credentials.get(&v.id).cloned().unwrap_or_default())
        .collect();
    let rows = listing::service_rows(&credentials, &all, &approved);
    output(
        &rows,
        json,
        |r| listing::service_table(r, Utc::now()),
        "no services yet; find a template with: tokenless service templates <name or variable>",
    )
}

pub async fn bundles(
    vault: Option<String>,
    json: bool,
    server: String,
) -> Result<ExitCode, CliError> {
    let prompter = TerminalPrompter;
    let client = open(&server, &prompter)?;
    let all = client.vaults().await?;
    let vaults = pick_vaults(&all, vault.as_deref())?;
    let fetched = per_vault(&vaults, |id| {
        let client = &client;
        async move {
            let (bundles, rules, credentials) = futures_util::try_join!(
                client.bundles(&id),
                client.rules(&id),
                client.credentials(&id)
            )?;
            Ok((bundles, rules, credentials))
        }
    })
    .await?;
    let mut rows = Vec::new();
    for vault in &vaults {
        if let Some((bundles, rules, credentials)) = fetched.get(&vault.id) {
            rows.extend(listing::bundle_rows(bundles, &all, rules, credentials));
        }
    }
    output(
        &rows,
        json,
        |r| listing::bundle_table(r, Utc::now()),
        "no access bundles yet; one is created with a service: tokenless service add <template> --vault personal --bundle my-agent",
    )
}

pub async fn sessions(
    vault: Option<String>,
    bundle: Option<String>,
    all: bool,
    limit: usize,
    json: bool,
    server: String,
) -> Result<ExitCode, CliError> {
    let prompter = TerminalPrompter;
    let client = open(&server, &prompter)?;
    let vaults = client.vaults().await?;
    let picked = pick_vaults(&vaults, vault.as_deref())?;
    let scope = match (&bundle, &vault) {
        (Some(reference), _) => {
            // A bundle by name or id, in the vault given or any vault.
            let found = per_vault(&picked, |id| {
                let client = &client;
                async move { client.bundles(&id).await }
            })
            .await?;
            let matching: Vec<_> = found
                .values()
                .flatten()
                .filter(|b| &b.name == reference || &b.id.to_string() == reference)
                .collect();
            match matching.as_slice() {
                [one] => SessionScope::Bundle(one.id),
                [] => {
                    return Err(LauncherError::config(format!(
                        "no access bundle named '{reference}'{}",
                        vault.as_deref().map(|v| format!(" in vault '{v}'")).unwrap_or_default()
                    ))
                    .into())
                }
                _ => {
                    return Err(LauncherError::config(format!(
                        "more than one vault has an access bundle named '{reference}'; name the vault with --vault"
                    ))
                    .into())
                }
            }
        }
        (None, Some(_)) => match picked.first() {
            Some(v) => SessionScope::Vault(v.id),
            None => SessionScope::Everywhere,
        },
        (None, None) => SessionScope::Everywhere,
    };
    let found = client.sessions(&scope, !all, limit).await?;
    let now = Utc::now();
    let rows = listing::session_rows(&found.sessions, &vaults, now);
    if !json && found.more {
        say(format_args!(
            "showing the newest {limit}; --limit shows more"
        ));
    }
    output(
        &rows,
        json,
        |r| listing::session_table(r, now),
        if all {
            "no sessions yet; tokenless run --bundle <bundle> -- <agent> mints one"
        } else {
            "no active sessions; --all includes ended ones"
        },
    )
}

pub async fn proxies(json: bool, server: String) -> Result<ExitCode, CliError> {
    let prompter = TerminalPrompter;
    let client = open(&server, &prompter)?;
    let nodes =
        match client.nodes().await {
            Err(LauncherError::Api { status: 403, .. }) => return Err(LauncherError::config(
                "only an admin can see proxies; ask one, or check the Proxies page in the console",
            )
            .into()),
            other => other?,
        };
    let now = Utc::now();
    let rows = listing::proxy_rows(&nodes, now);
    output(
        &rows,
        json,
        |r| listing::proxy_table(r, now),
        "no proxies yet; enrol this machine with: tokenless proxy add --name <this machine> --state ~/.tokenless/node.json",
    )
}
