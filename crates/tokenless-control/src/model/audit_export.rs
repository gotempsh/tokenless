// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Audit export: the webhook receivers audit events are sent to, and how
//! far each has got.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokenless_core::audit::{AuditEvent, AuditOutcome};
use tokenless_core::ids::{AuditDestinationId, VaultId};

/// The most destinations one instance sends to.
pub const MAX_AUDIT_DESTINATIONS: usize = 10;

/// How a batch of events is written in a request body.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadFormat {
    /// One JSON object holding the batch's events.
    #[default]
    Json,
    /// One event per line, for log pipelines.
    Ndjson,
}

impl PayloadFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            PayloadFormat::Json => "json",
            PayloadFormat::Ndjson => "ndjson",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "json" => Some(PayloadFormat::Json),
            "ndjson" => Some(PayloadFormat::Ndjson),
            _ => None,
        }
    }

    pub fn content_type(self) -> &'static str {
        match self {
            PayloadFormat::Json => "application/json",
            PayloadFormat::Ndjson => "application/x-ndjson",
        }
    }
}

/// Which events a destination receives. Every non-empty list must match;
/// an empty list matches everything.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditFilter {
    /// `credential.` matches `credential.create`; `proxy.inject` matches
    /// only itself and longer names.
    #[serde(default)]
    pub action_prefixes: Vec<String>,
    #[serde(default)]
    pub outcomes: Vec<AuditOutcome>,
    #[serde(default)]
    pub vault_ids: Vec<VaultId>,
}

impl AuditFilter {
    pub fn matches(&self, event: &AuditEvent) -> bool {
        (self.action_prefixes.is_empty()
            || self
                .action_prefixes
                .iter()
                .any(|p| event.action.starts_with(p.as_str())))
            && (self.outcomes.is_empty() || self.outcomes.contains(&event.outcome))
            && (self.vault_ids.is_empty()
                || event.vault_id.is_some_and(|v| self.vault_ids.contains(&v)))
    }
}

/// How far a destination has got, written by the sender. Changing a
/// destination's settings never touches it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeliveryState {
    /// The sequence number of the last event sent (or passed over by the
    /// filter). The next batch starts after it.
    pub cursor: u64,
    pub last_success_at: Option<DateTime<Utc>>,
    pub last_attempt_at: Option<DateTime<Utc>>,
    /// When the current run of failures began; `None` once a batch gets
    /// through.
    pub failing_since: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub consecutive_failures: u32,
}

/// A webhook receiver audit events are sent to.
#[derive(Clone, PartialEq, Eq)]
pub struct AuditDestination {
    pub id: AuditDestinationId,
    pub name: String,
    pub url: String,
    pub format: PayloadFormat,
    /// One extra header for receivers that authenticate that way
    /// (`Authorization: Splunk …`). The value is encrypted at rest.
    pub auth_header_name: Option<String>,
    pub auth_header_value_enc: Option<Vec<u8>>,
    /// The `whsec_…` secret requests are signed with, encrypted at rest.
    pub signing_secret_enc: Vec<u8>,
    pub filter: AuditFilter,
    /// Paused by an admin: nothing is sent until resumed, and nothing is
    /// lost meanwhile.
    pub paused: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub delivery: DeliveryState,
}

tokenless_core::redacted_debug!(AuditDestination {
    id, name, url, format, auth_header_name, filter, paused, created_at,
    updated_at, delivery;
    auth_header_value_enc, signing_secret_enc
});

#[cfg(test)]
mod tests {
    use super::*;

    fn event(action: &str, outcome: AuditOutcome, vault: Option<VaultId>) -> AuditEvent {
        let mut e = AuditEvent::new("system", action, outcome);
        e.vault_id = vault;
        e
    }

    #[test]
    fn an_empty_filter_matches_everything() {
        let f = AuditFilter::default();
        assert!(f.matches(&event("proxy.inject", AuditOutcome::Success, None)));
        assert!(f.matches(&event("x", AuditOutcome::Denied, Some(VaultId::new()))));
    }

    #[test]
    fn every_non_empty_list_must_match() {
        let vault = VaultId::new();
        let f = AuditFilter {
            action_prefixes: vec!["credential.".into(), "proxy.inject".into()],
            outcomes: vec![AuditOutcome::Denied],
            vault_ids: vec![vault],
        };
        assert!(f.matches(&event(
            "credential.create",
            AuditOutcome::Denied,
            Some(vault)
        )));
        assert!(f.matches(&event("proxy.inject", AuditOutcome::Denied, Some(vault))));
        assert!(!f.matches(&event("rule.create", AuditOutcome::Denied, Some(vault))));
        assert!(!f.matches(&event(
            "credential.create",
            AuditOutcome::Success,
            Some(vault)
        )));
        assert!(!f.matches(&event(
            "credential.create",
            AuditOutcome::Denied,
            Some(VaultId::new())
        )));
        // An event with no vault never matches a vault filter.
        assert!(!f.matches(&event("credential.create", AuditOutcome::Denied, None)));
    }
}
