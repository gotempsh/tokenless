// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `tokenless sign-ins`: the browsers and CLI logins signed in as you, and
//! ending them; an admin signs someone out everywhere.

use std::process::ExitCode;

use broker_server::launcher::account::ConsoleClient;
use broker_server::launcher::listing::{relative, table};
use broker_server::launcher::LauncherError;
use chrono::{DateTime, Utc};
use tokenless_control::service::auth::SignIn;

use super::list::{open, print_json};
use super::messages::say;
use super::{CliError, TerminalPrompter};

/// The id as the table shows it: enough to tell sign-ins apart and to
/// revoke one by.
fn short_id(s: &SignIn) -> String {
    s.id.to_string().chars().take(8).collect()
}

pub fn sign_in_table(rows: &[SignIn], now: DateTime<Utc>) -> String {
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|s| {
            vec![
                short_id(s),
                if s.current {
                    format!("{} (this one)", s.device)
                } else {
                    s.device.clone()
                },
                relative(s.created_at, now),
                relative(s.last_used_at, now),
                relative(s.expires_at, now),
            ]
        })
        .collect();
    table(
        &["ID", "CLIENT", "SIGNED IN", "LAST USED", "EXPIRES"],
        &cells,
    )
}

async fn user_id(
    client: &ConsoleClient<'_>,
    username: &str,
) -> Result<tokenless_core::ids::UserId, CliError> {
    let wanted = username.trim().to_ascii_lowercase();
    client
        .users()
        .await?
        .into_iter()
        .find(|u| u.username == wanted || u.id.to_string() == username)
        .map(|u| u.id)
        .ok_or_else(|| {
            LauncherError::config(format!("no person named '{username}' has an account here"))
                .into()
        })
}

pub async fn list(user: Option<String>, json: bool, server: String) -> Result<ExitCode, CliError> {
    let prompter = TerminalPrompter;
    let client = open(&server, &prompter)?;
    let rows = match &user {
        None => client.sign_ins().await?,
        Some(name) => {
            let id = user_id(&client, name).await?;
            client.user_sign_ins(&id).await?
        }
    };
    if json {
        print_json(&rows)?;
    } else if rows.is_empty() {
        say(format!(
            "'{}' is not signed in anywhere",
            user.as_deref().unwrap_or_default()
        ));
    } else {
        print!("{}", sign_in_table(&rows, Utc::now()));
    }
    Ok(ExitCode::SUCCESS)
}

pub enum Revoke {
    /// One of yours, by id or the start of it.
    One(String),
    /// All of yours but this one.
    Others,
    /// All of someone's, for an admin.
    User(String),
}

pub async fn revoke(what: Revoke, server: String) -> Result<ExitCode, CliError> {
    let prompter = TerminalPrompter;
    let client = open(&server, &prompter)?;
    match what {
        Revoke::Others => {
            let done = client.revoke_other_sign_ins().await?;
            say(format!(
                "Signed out everywhere else: ended {} sign-in{}. This one stays signed in.",
                done.revoked,
                plural(done.revoked)
            ));
        }
        Revoke::User(name) => {
            let id = user_id(&client, &name).await?;
            let done = client.revoke_user_sign_ins(&id).await?;
            say(format!(
                "Signed '{name}' out everywhere: ended {} sign-in{}. Their sessions already started keep running until they expire; end those with: tokenless session revoke",
                done.revoked,
                plural(done.revoked)
            ));
        }
        Revoke::One(reference) => {
            let all = client.sign_ins().await?;
            let matches: Vec<&SignIn> = all
                .iter()
                .filter(|s| {
                    s.id.to_string()
                        .starts_with(&reference.to_ascii_lowercase())
                })
                .collect();
            let target = match matches.as_slice() {
                [one] => *one,
                [] => {
                    return Err(LauncherError::config(format!(
                        "no sign-in '{reference}'; see yours with: tokenless sign-ins list"
                    ))
                    .into())
                }
                _ => {
                    return Err(LauncherError::config(format!(
                        "'{reference}' matches {} sign-ins; give more of the id",
                        matches.len()
                    ))
                    .into())
                }
            };
            if target.current {
                return Err(LauncherError::config(format!(
                    "{} is this sign-in; to end it, run: tokenless logout",
                    short_id(target)
                ))
                .into());
            }
            client.revoke_sign_in(&target.id).await?;
            say(format!(
                "Ended sign-in {} ({}).",
                short_id(target),
                target.device
            ));
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn plural(n: u64) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}
