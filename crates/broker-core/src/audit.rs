// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Audit records shared by the control plane and data plane nodes.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ids::{AuditEventId, VaultId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Success,
    Denied,
    Failure,
}

impl AuditOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditOutcome::Success => "success",
            AuditOutcome::Denied => "denied",
            AuditOutcome::Failure => "failure",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "success" => Some(AuditOutcome::Success),
            "denied" => Some(AuditOutcome::Denied),
            "failure" => Some(AuditOutcome::Failure),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: AuditEventId,
    pub at: DateTime<Utc>,
    /// `user:<id>`, `api_key:<prefix>`, `node:<id>`, `session:<id>` or `system`.
    pub actor: String,
    /// Dotted action name, e.g. `credential.create` or `proxy.inject`.
    pub action: String,
    pub outcome: AuditOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_id: Option<VaultId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Flat string details. Never contains secret material.
    #[serde(default)]
    pub detail: BTreeMap<String, String>,
}

impl AuditEvent {
    pub fn new(actor: impl Into<String>, action: impl Into<String>, outcome: AuditOutcome) -> Self {
        Self {
            id: AuditEventId::new(),
            at: Utc::now(),
            actor: actor.into(),
            action: action.into(),
            outcome,
            vault_id: None,
            target: None,
            detail: BTreeMap::new(),
        }
    }

    pub fn vault(mut self, vault_id: VaultId) -> Self {
        self.vault_id = Some(vault_id);
        self
    }

    pub fn target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    pub fn detail(mut self, key: &str, value: impl Into<String>) -> Self {
        self.detail.insert(key.to_string(), value.into());
        self
    }

    /// The session this event is about: the one it targets (minted,
    /// relabelled, revoked), else the one that made the request (the
    /// proxy's `session_id` detail). The SQLite store indexes the same
    /// rule as `audit_events.session_ref` (migration 0010).
    pub fn session_ref(&self) -> Option<&str> {
        match self
            .target
            .as_deref()
            .and_then(|t| t.strip_prefix("session:"))
        {
            Some(id) => Some(id),
            None => self.detail.get("session_id").map(String::as_str),
        }
    }
}
