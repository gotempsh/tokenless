// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Alerts: audit signals that someone should look at now, such as a
//! session cut off for probing or one used through a second proxy.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokenless_core::ids::{AlertId, NodeId, SessionId, VaultId};

/// What raised an alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertKind {
    /// A proxy cut a session off after repeated refusals. Always raised.
    Quarantine,
    /// A request carried a tripwire credential: someone took a decoy from
    /// the agent's machine. Always raised.
    Tripwire,
    /// A session was refused often, below the quarantine threshold or with
    /// quarantine off.
    Refusals,
    /// A session was used through a proxy other than the one it first used.
    NewProxy,
}

impl AlertKind {
    pub const ALL: [AlertKind; 4] = [
        AlertKind::Quarantine,
        AlertKind::Tripwire,
        AlertKind::Refusals,
        AlertKind::NewProxy,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            AlertKind::Quarantine => "quarantine",
            AlertKind::Tripwire => "tripwire",
            AlertKind::Refusals => "refusals",
            AlertKind::NewProxy => "new_proxy",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == raw)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alert {
    pub id: AlertId,
    pub kind: AlertKind,
    /// One alert per key: the same signal on the same session raises it
    /// once.
    #[serde(skip)]
    pub dedup_key: String,
    /// What happened, as a sentence.
    pub summary: String,
    pub vault_id: Option<VaultId>,
    pub session_id: Option<SessionId>,
    pub node_id: Option<NodeId>,
    /// Flat details, never secret material.
    pub detail: BTreeMap<String, String>,
    pub raised_at: DateTime<Utc>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    /// Who acknowledged it, as an audit actor.
    pub acknowledged_by: Option<String>,
}

/// Which alerts to list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AlertFilter {
    /// Only those nobody has acknowledged.
    pub open_only: bool,
    pub vault_id: Option<VaultId>,
    pub session_id: Option<SessionId>,
    pub kind: Option<AlertKind>,
}

/// A count of refusals within a window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefusalThreshold {
    pub refusals: u32,
    pub window_secs: u32,
}

/// The signals that can be tuned. A quarantine and a tripwire hit always
/// raise an alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertSettings {
    /// Raise an alert for a session refused this often; `None` for never.
    #[serde(default = "default_refusals")]
    pub refusals: Option<RefusalThreshold>,
    /// Raise an alert when a session is used through a second proxy.
    #[serde(default = "default_true")]
    pub new_proxy: bool,
}

fn default_refusals() -> Option<RefusalThreshold> {
    Some(RefusalThreshold {
        refusals: 10,
        window_secs: 300,
    })
}

fn default_true() -> bool {
    true
}

impl Default for AlertSettings {
    /// Half the default quarantine threshold, so the alert comes first.
    fn default() -> Self {
        Self {
            refusals: default_refusals(),
            new_proxy: true,
        }
    }
}
