// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Records persisted by the store traits.

use std::collections::BTreeMap;

use broker_core::authz::Role;
use broker_core::egress::EgressPolicy;
use broker_core::host::HostPattern;
use broker_core::ids::{
    ApiKeyId, CredentialId, InviteId, NodeId, RuleId, SessionId, UserId, VariableId, VaultId,
};
use broker_core::rule::RuleScope;
use broker_core::scope::Scope;
use broker_core::snapshot::UnmatchedHostPolicy;
use broker_core::template::ServiceTemplate;
use broker_core::variables::CustomHeader;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const DEFAULT_PAGE_SIZE: u64 = 20;
pub const MAX_PAGE_SIZE: u64 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageRequest {
    pub page: u64,
    pub page_size: u64,
}

impl PageRequest {
    pub fn new(page: Option<u64>, page_size: Option<u64>) -> Self {
        Self {
            page: page.unwrap_or(1).max(1),
            page_size: page_size
                .unwrap_or(DEFAULT_PAGE_SIZE)
                .clamp(1, MAX_PAGE_SIZE),
        }
    }

    pub fn offset(&self) -> u64 {
        (self.page - 1).saturating_mul(self.page_size)
    }

    /// Slices an already sorted list (memory stores).
    pub fn apply<T: Clone>(&self, items: &[T]) -> Page<T> {
        let start = usize::try_from(self.offset())
            .unwrap_or(usize::MAX)
            .min(items.len());
        let end = start
            .saturating_add(usize::try_from(self.page_size).unwrap_or(usize::MAX))
            .min(items.len());
        Page {
            items: items[start..end].to_vec(),
            total: items.len() as u64,
            page: self.page,
            page_size: self.page_size,
        }
    }
}

impl Default for PageRequest {
    fn default() -> Self {
        Self::new(None, None)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub total: u64,
    pub page: u64,
    pub page_size: u64,
}

impl<T> Page<T> {
    pub fn map<U>(self, f: impl FnMut(T) -> U) -> Page<U> {
        Page {
            items: self.items.into_iter().map(f).collect(),
            total: self.total,
            page: self.page,
            page_size: self.page_size,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vault {
    pub id: VaultId,
    pub name: String,
    pub scope: Scope,
    pub created_at: DateTime<Utc>,
}

/// Credential metadata. There is deliberately no type that carries both the
/// metadata and a decrypted secret: nothing can serialise one back out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialMeta {
    pub id: CredentialId,
    pub vault_id: VaultId,
    pub name: String,
    pub template_id: String,
    pub template_version: u32,
    /// Admin-set host override that widened the template (empty if none).
    pub host_override: Vec<HostPattern>,
    pub field_names: Vec<String>,
    /// Headers sent alongside the injected credential. Configuration, not
    /// secrets: secret parts come from `{{VARIABLE}}` references.
    #[serde(default)]
    pub custom_headers: Vec<CustomHeader>,
    /// Variable keys referenced by the secret fields and custom headers.
    #[serde(default)]
    pub variable_refs: Vec<String>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A named secret referenced as `{{KEY}}`. The value is stored encrypted
/// and is write-only: no role can read it back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Variable {
    pub id: VariableId,
    pub key: String,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_by: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemplateSource {
    Builtin,
    Imported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemplateStatus {
    Approved,
    PendingApproval,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredTemplate {
    pub template: ServiceTemplate,
    pub yaml: String,
    pub source: TemplateSource,
    pub status: TemplateStatus,
    pub imported_by: Option<String>,
    pub approved_by: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub id: RuleId,
    pub vault_id: VaultId,
    pub credential_id: CredentialId,
    pub name: String,
    pub allow: RuleScope,
    pub enabled: bool,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxySession {
    pub id: SessionId,
    pub vault_id: VaultId,
    pub rule_ids: Vec<RuleId>,
    pub labels: BTreeMap<String, String>,
    pub request_limit: Option<u64>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    pub unmatched_host_policy: UnmatchedHostPolicy,
    /// Which addresses passthrough tunnels and validation requests may reach.
    #[serde(default)]
    pub egress: EgressPolicy,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            unmatched_host_policy: UnmatchedHostPolicy::Passthrough,
            egress: EgressPolicy::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: UserId,
    pub username: String,
    pub password_hash: String,
    /// TOTP secret encrypted with the at-rest cipher; `None` when the
    /// person signs in with a password only.
    pub totp_secret_enc: Option<Vec<u8>>,
    pub totp_last_step: Option<u64>,
    pub role: Role,
    pub created_at: DateTime<Utc>,
    /// A disabled user cannot log in and has no UI sessions.
    pub disabled_at: Option<DateTime<Utc>>,
}

/// A single-use invitation for a person to create an account with a role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invite {
    pub id: InviteId,
    #[serde(skip)]
    pub token_hash: String,
    pub role: Role,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub accepted_at: Option<DateTime<Utc>>,
    pub accepted_by: Option<UserId>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl Invite {
    /// Neither accepted, revoked nor expired at `now`.
    pub fn is_pending(&self, now: DateTime<Utc>) -> bool {
        self.accepted_at.is_none() && self.revoked_at.is_none() && self.expires_at > now
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UiSession {
    pub token_hash: String,
    pub user_id: UserId,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub step_up_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: ApiKeyId,
    pub name: String,
    /// Public lookup prefix (`cbk_xxxxxxxxxxxx`).
    pub prefix: String,
    #[serde(skip)]
    pub secret_hash: String,
    pub vault_id: VaultId,
    pub role: Role,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinTokenRecord {
    pub id: String,
    pub secret_hash: String,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    pub id: NodeId,
    pub name: String,
    /// X25519 public key (base64) credentials are sealed to.
    pub seal_public_key: String,
    pub cert_serial: String,
    pub cert_not_after: DateTime<Utc>,
    pub enrolled_at: DateTime<Utc>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditQuery {
    pub vault_id: Option<VaultId>,
    pub action_prefix: Option<String>,
    /// Events whose `session_id` detail is this session (proxy traffic).
    pub session_id: Option<SessionId>,
    pub page: PageRequest,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_request_clamps() {
        let p = PageRequest::new(Some(0), Some(1000));
        assert_eq!(p.page, 1);
        assert_eq!(p.page_size, MAX_PAGE_SIZE);
        assert_eq!(PageRequest::new(None, None).page_size, DEFAULT_PAGE_SIZE);
    }

    #[test]
    fn page_apply_slices() {
        let items: Vec<u32> = (0..45).collect();
        let page = PageRequest::new(Some(3), Some(20)).apply(&items);
        assert_eq!(page.items, (40..45).collect::<Vec<_>>());
        assert_eq!(page.total, 45);
        let beyond = PageRequest::new(Some(9), Some(20)).apply(&items);
        assert!(beyond.items.is_empty());
    }
}
