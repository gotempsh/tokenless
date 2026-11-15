// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `tokenless vault member` and `tokenless vault join`: who works in a vault.

use std::process::ExitCode;

use broker_server::launcher::listing::{relative, table};
use broker_server::launcher::LauncherError;
use chrono::Utc;
use clap::ValueEnum;
use tokenless_control::model::VaultMember;
use tokenless_core::authz::Role;

use super::list::{open, pick_vault, print_json};
use super::messages::say;
use super::{CliError, TerminalPrompter};

/// The roles a person can hold inside a vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum VaultRoleArg {
    Admin,
    Editor,
    Viewer,
    Runner,
}

impl From<VaultRoleArg> for Role {
    fn from(role: VaultRoleArg) -> Self {
        match role {
            VaultRoleArg::Admin => Role::Admin,
            VaultRoleArg::Editor => Role::Editor,
            VaultRoleArg::Viewer => Role::Viewer,
            VaultRoleArg::Runner => Role::Runner,
        }
    }
}

pub fn member_table(members: &[VaultMember], now: chrono::DateTime<Utc>) -> String {
    let cells: Vec<Vec<String>> = members
        .iter()
        .map(|m| {
            vec![
                m.username.clone(),
                m.role.to_string(),
                m.added_by.clone(),
                relative(m.added_at, now),
            ]
        })
        .collect();
    table(&["USERNAME", "ROLE", "ADDED BY", "ADDED"], &cells)
}

pub async fn list(vault: String, json: bool, server: String) -> Result<ExitCode, CliError> {
    let prompter = TerminalPrompter;
    let client = open(&server, &prompter)?;
    let vault = pick_vault(&client.vaults().await?, Some(&vault))?;
    let members = client.vault_members(&vault.id).await?;
    if json {
        print_json(&members)?;
    } else {
        print!("{}", member_table(&members, Utc::now()));
    }
    Ok(ExitCode::SUCCESS)
}

pub async fn set(
    vault: String,
    username: String,
    role: VaultRoleArg,
    server: String,
) -> Result<ExitCode, CliError> {
    let prompter = TerminalPrompter;
    let client = open(&server, &prompter)?;
    let vault = pick_vault(&client.vaults().await?, Some(&vault))?;
    let member = client
        .put_vault_member(&vault.id, &username, role.into())
        .await?;
    say(format!(
        "{} is {} in vault '{}'",
        member.username, member.role, vault.name
    ));
    Ok(ExitCode::SUCCESS)
}

pub async fn remove(vault: String, username: String, server: String) -> Result<ExitCode, CliError> {
    let prompter = TerminalPrompter;
    let client = open(&server, &prompter)?;
    let vault = pick_vault(&client.vaults().await?, Some(&vault))?;
    let members = client.vault_members(&vault.id).await?;
    let Some(member) = members.iter().find(|m| m.username == username) else {
        return Err(LauncherError::config(format!(
            "'{username}' is not a member of vault '{}'; see who is with: tokenless vault member list {}",
            vault.name, vault.name
        ))
        .into());
    };
    client
        .remove_vault_member(&vault.id, &member.user_id)
        .await?;
    say(format!(
        "{username} is no longer a member of vault '{}'",
        vault.name
    ));
    Ok(ExitCode::SUCCESS)
}

pub async fn join(vault: String, server: String) -> Result<ExitCode, CliError> {
    let prompter = TerminalPrompter;
    let client = open(&server, &prompter)?;
    let vault = pick_vault(&client.vaults().await?, Some(&vault))?;
    client.join_vault(&vault.id).await?;
    say(format!("you are an admin of vault '{}'", vault.name));
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokenless_core::ids::{UserId, VaultId};

    #[test]
    fn every_vault_role_and_only_those_can_be_given() {
        for (arg, role) in [
            (VaultRoleArg::Admin, Role::Admin),
            (VaultRoleArg::Editor, Role::Editor),
            (VaultRoleArg::Viewer, Role::Viewer),
            (VaultRoleArg::Runner, Role::Runner),
        ] {
            assert_eq!(Role::from(arg), role);
            assert!(role.is_vault_role());
        }
        assert!(VaultRoleArg::from_str("member", true).is_err());
    }

    #[test]
    fn the_member_table_says_who_gave_each_role() {
        let now = Utc::now();
        let out = member_table(
            &[VaultMember {
                vault_id: VaultId::new(),
                user_id: UserId::new(),
                username: "someone".into(),
                role: Role::Runner,
                added_by: "sso:corp".into(),
                added_at: now,
            }],
            now,
        );
        assert!(out.contains("USERNAME"), "{out}");
        assert!(out.contains("someone"), "{out}");
        assert!(out.contains("runner"), "{out}");
        assert!(out.contains("sso:corp"), "{out}");
    }
}
