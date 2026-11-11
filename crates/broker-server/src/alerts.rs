// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `tokenless alerts`: what the proxies reported that someone should look
//! at, and marking it looked at.

use std::process::ExitCode;

use broker_server::launcher::listing::{relative, table};
use broker_server::launcher::LauncherError;
use chrono::{DateTime, Utc};
use tokenless_control::model::Alert;

use super::list::{open, print_json};
use super::messages::say;
use super::{CliError, TerminalPrompter};

/// How many `list` shows; the console pages through the rest.
const SHOWN: u64 = 50;

fn short_id(a: &Alert) -> String {
    a.id.to_string().chars().take(8).collect()
}

pub fn alert_table(rows: &[Alert], now: DateTime<Utc>) -> String {
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|a| {
            vec![
                short_id(a),
                a.kind.as_str().replace('_', " "),
                relative(a.raised_at, now),
                a.acknowledged_at
                    .map(|t| format!("seen {}", relative(t, now)))
                    .unwrap_or_else(|| "open".into()),
                a.summary.clone(),
            ]
        })
        .collect();
    table(&["ID", "KIND", "RAISED", "STATE", "WHAT HAPPENED"], &cells)
}

pub async fn list(all: bool, json: bool, server: String) -> Result<ExitCode, CliError> {
    let prompter = TerminalPrompter;
    let client = open(&server, &prompter)?;
    let page = client.alerts(all, SHOWN).await?;
    if json {
        print_json(&page.items)?;
    } else if page.items.is_empty() {
        say(if all {
            "no alerts yet: a session cut off, refused often or used through a second proxy raises one"
        } else {
            "no open alerts; see the acknowledged ones with: tokenless alerts list --all"
        });
    } else {
        print!("{}", alert_table(&page.items, Utc::now()));
        if page.total > page.items.len() as u64 {
            say(format!(
                "{} more; the console's Alerts page lists them all",
                page.total - page.items.len() as u64
            ));
        }
    }
    Ok(ExitCode::SUCCESS)
}

pub async fn acknowledge(reference: String, server: String) -> Result<ExitCode, CliError> {
    let prompter = TerminalPrompter;
    let client = open(&server, &prompter)?;
    let wanted = reference.to_ascii_lowercase();
    let open_alerts = client.alerts(false, 100).await?;
    let matches: Vec<&Alert> = open_alerts
        .items
        .iter()
        .filter(|a| a.id.to_string().starts_with(&wanted))
        .collect();
    let target = match matches.as_slice() {
        [one] => *one,
        [] => {
            return Err(LauncherError::config(format!(
                "no open alert '{reference}'; see them with: tokenless alerts list"
            ))
            .into())
        }
        _ => {
            return Err(LauncherError::config(format!(
                "'{reference}' matches {} alerts; give more of the id",
                matches.len()
            ))
            .into())
        }
    };
    client.acknowledge_alert(&target.id).await?;
    say(format!(
        "Acknowledged alert {}: {}",
        short_id(target),
        target.summary
    ));
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::TimeDelta;
    use tokenless_control::model::AlertKind;
    use tokenless_core::ids::AlertId;

    use super::*;

    #[test]
    fn the_table_says_what_happened_and_whether_someone_looked() {
        let now = Utc::now();
        let alert = |kind: AlertKind, acknowledged: bool| Alert {
            id: AlertId::new(),
            kind,
            dedup_key: String::new(),
            summary: format!("{} summary", kind.as_str()),
            vault_id: None,
            session_id: None,
            node_id: None,
            detail: BTreeMap::new(),
            raised_at: now - TimeDelta::minutes(5),
            acknowledged_at: acknowledged.then(|| now - TimeDelta::minutes(1)),
            acknowledged_by: None,
        };
        let rows = [
            alert(AlertKind::NewProxy, false),
            alert(AlertKind::Quarantine, true),
        ];
        let out = alert_table(&rows, now);
        let lines: Vec<&str> = out.lines().collect();
        assert!(
            lines[0].starts_with("ID") && lines[0].contains("WHAT HAPPENED"),
            "{out}"
        );
        assert!(lines[1].starts_with(&short_id(&rows[0])), "{out}");
        assert!(
            lines[1].contains("new proxy")
                && lines[1].contains("open")
                && lines[1].contains("new_proxy summary"),
            "{out}"
        );
        assert!(
            lines[2].contains("quarantine") && lines[2].contains("seen "),
            "{out}"
        );
    }
}
