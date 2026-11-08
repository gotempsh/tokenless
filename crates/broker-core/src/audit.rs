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

    /// The service (credential) this event is about: the one it targets
    /// (created, secret replaced, deleted), else the one its `credential_id`
    /// detail names (a brokered request, a rule over it). Older `rule.create`
    /// events named it `credential`. The SQLite store
    /// indexes the same rule as `audit_events.credential_ref` (migration
    /// 0012).
    pub fn credential_ref(&self) -> Option<&str> {
        if let Some(id) = self
            .target
            .as_deref()
            .and_then(|t| t.strip_prefix("credential:"))
        {
            return Some(id);
        }
        let named = self.detail.get("credential_id");
        let legacy = || {
            (self.action == "rule.create")
                .then(|| self.detail.get("credential"))
                .flatten()
        };
        named.or_else(legacy).map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(action: &str) -> AuditEvent {
        AuditEvent::new("user:test", action, AuditOutcome::Success)
    }

    #[test]
    fn credential_ref_reads_the_target_then_the_detail() {
        let targeted = event("credential.rotate").target("credential:c1");
        assert_eq!(targeted.credential_ref(), Some("c1"));
        let request = event("proxy.inject")
            .target("rule:r1")
            .detail("credential_id", "c2");
        assert_eq!(request.credential_ref(), Some("c2"));
        assert_eq!(event("vault.create").credential_ref(), None);
    }

    #[test]
    fn credential_ref_reads_rule_creations_recorded_before_the_rename() {
        let old = event("rule.create")
            .target("rule:r1")
            .detail("credential", "c3");
        assert_eq!(old.credential_ref(), Some("c3"));
        // Only rule.create ever used that key.
        let other = event("bundle.create").detail("credential", "c3");
        assert_eq!(other.credential_ref(), None);
    }
}
