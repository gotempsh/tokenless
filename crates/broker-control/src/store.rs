// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The seams an embedding system implements.
//!
//! `CredentialStore`, `PolicyStore`, `AuditSink` and `Authorizer` are the
//! four traits a host platform supplies to run the broker natively.
//! `IdentityStore` and `NodeStore` back the standalone login and node
//! enrolment flows. `broker-conformance` holds the behaviour every
//! implementation must exhibit.

use async_trait::async_trait;
use broker_core::audit::AuditEvent;
use broker_core::authz::{rbac_decide, Action, Decision, Principal};
use broker_core::ids::{ApiKeyId, CredentialId, NodeId, RuleId, SessionId, UserId, VaultId};
use chrono::{DateTime, Utc};

use crate::error::StoreError;
use crate::model::{
    ApiKey, AuditQuery, CredentialMeta, JoinTokenRecord, Node, Page, PageRequest, ProxySession,
    Rule, Settings, StoredTemplate, UiSession, User, Vault,
};

/// Stores credential metadata and an opaque, already-encrypted secret blob.
///
/// The store never sees plaintext and there is no method that returns a
/// decrypted secret. `load_secret_ciphertext` exists only so the control
/// plane can seal credentials to data plane nodes.
#[async_trait]
pub trait CredentialStore: Send + Sync {
    async fn insert_credential(
        &self,
        meta: CredentialMeta,
        ciphertext: Vec<u8>,
    ) -> Result<(), StoreError>;
    async fn get_credential(&self, id: &CredentialId)
        -> Result<Option<CredentialMeta>, StoreError>;
    async fn list_credentials(
        &self,
        vault_id: &VaultId,
        page: PageRequest,
    ) -> Result<Page<CredentialMeta>, StoreError>;
    /// Replaces the secret; `NotFound` if the credential does not exist.
    async fn replace_secret(
        &self,
        id: &CredentialId,
        ciphertext: Vec<u8>,
        field_names: Vec<String>,
        updated_at: DateTime<Utc>,
    ) -> Result<(), StoreError>;
    /// `NotFound` if the credential does not exist.
    async fn delete_credential(&self, id: &CredentialId) -> Result<(), StoreError>;
    async fn load_secret_ciphertext(
        &self,
        id: &CredentialId,
    ) -> Result<Option<Vec<u8>>, StoreError>;
}

/// Vaults, templates, rules, proxy sessions and instance settings.
#[async_trait]
pub trait PolicyStore: Send + Sync {
    /// `Conflict` if a vault with the same name exists.
    async fn insert_vault(&self, vault: Vault) -> Result<(), StoreError>;
    async fn get_vault(&self, id: &VaultId) -> Result<Option<Vault>, StoreError>;
    async fn list_vaults(&self, page: PageRequest) -> Result<Page<Vault>, StoreError>;

    /// Inserts a template version. `Conflict` if that id+version exists.
    async fn insert_template(&self, template: StoredTemplate) -> Result<(), StoreError>;
    async fn get_template(
        &self,
        id: &str,
        version: u32,
    ) -> Result<Option<StoredTemplate>, StoreError>;
    /// All versions, ordered by id then version.
    async fn list_templates(&self) -> Result<Vec<StoredTemplate>, StoreError>;
    async fn approve_template(
        &self,
        id: &str,
        version: u32,
        approved_by: &str,
    ) -> Result<(), StoreError>;

    async fn insert_rule(&self, rule: Rule) -> Result<(), StoreError>;
    async fn get_rule(&self, id: &RuleId) -> Result<Option<Rule>, StoreError>;
    async fn list_rules(
        &self,
        vault_id: &VaultId,
        page: PageRequest,
    ) -> Result<Page<Rule>, StoreError>;
    /// Every enabled rule across vaults, for snapshot building.
    async fn list_enabled_rules(&self) -> Result<Vec<Rule>, StoreError>;
    async fn count_rules_for_credential(&self, id: &CredentialId) -> Result<u64, StoreError>;
    /// `NotFound` if the rule does not exist.
    async fn update_rule(&self, rule: Rule) -> Result<(), StoreError>;
    async fn delete_rule(&self, id: &RuleId) -> Result<(), StoreError>;

    async fn insert_session(&self, session: ProxySession) -> Result<(), StoreError>;
    async fn get_session(&self, id: &SessionId) -> Result<Option<ProxySession>, StoreError>;
    async fn list_sessions(
        &self,
        vault_id: &VaultId,
        page: PageRequest,
    ) -> Result<Page<ProxySession>, StoreError>;
    /// Returns false if it was already revoked. `NotFound` if missing.
    async fn revoke_session(&self, id: &SessionId, at: DateTime<Utc>) -> Result<bool, StoreError>;
    /// Revoked sessions that have not yet expired (the set nodes must know).
    async fn list_revoked_unexpired(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Vec<SessionId>, StoreError>;
    /// Unrevoked, unexpired sessions with a request limit.
    async fn list_limited_active(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Vec<(SessionId, u64)>, StoreError>;

    async fn get_settings(&self) -> Result<Settings, StoreError>;
    async fn put_settings(&self, settings: Settings) -> Result<(), StoreError>;
}

/// Append-only audit log.
#[async_trait]
pub trait AuditSink: Send + Sync {
    async fn record(&self, events: &[AuditEvent]) -> Result<(), StoreError>;
    /// Newest first.
    async fn query(&self, query: &AuditQuery) -> Result<Page<AuditEvent>, StoreError>;
}

/// Decides whether a principal may perform an action. Step-up MFA is
/// enforced by the services on top of this, so an embedding authoriser
/// cannot accidentally waive it.
#[async_trait]
pub trait Authorizer: Send + Sync {
    async fn authorize(
        &self,
        principal: &Principal,
        action: Action,
        vault: Option<&VaultId>,
    ) -> Decision;
}

/// The built-in role-based authoriser.
#[derive(Debug, Default, Clone, Copy)]
pub struct RbacAuthorizer;

#[async_trait]
impl Authorizer for RbacAuthorizer {
    async fn authorize(
        &self,
        principal: &Principal,
        action: Action,
        vault: Option<&VaultId>,
    ) -> Decision {
        rbac_decide(principal, action, vault)
    }
}

/// People, UI sessions, the setup token and API keys (standalone mode).
#[async_trait]
pub trait IdentityStore: Send + Sync {
    async fn count_users(&self) -> Result<u64, StoreError>;
    /// `Conflict` if the username is taken.
    async fn insert_user(&self, user: User) -> Result<(), StoreError>;
    async fn get_user(&self, id: &UserId) -> Result<Option<User>, StoreError>;
    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, StoreError>;
    /// Atomically records a used TOTP step if it is newer than the stored
    /// one. Returns false when the step was already used (replay).
    async fn advance_totp_step(&self, id: &UserId, step: u64) -> Result<bool, StoreError>;

    async fn insert_ui_session(&self, session: UiSession) -> Result<(), StoreError>;
    async fn get_ui_session(&self, token_hash: &str) -> Result<Option<UiSession>, StoreError>;
    async fn set_ui_session_step_up(
        &self,
        token_hash: &str,
        at: DateTime<Utc>,
    ) -> Result<(), StoreError>;
    async fn delete_ui_session(&self, token_hash: &str) -> Result<(), StoreError>;
    async fn delete_expired_ui_sessions(&self, now: DateTime<Utc>) -> Result<u64, StoreError>;

    /// Replaces any outstanding setup token with this one.
    async fn replace_setup_token(
        &self,
        token_hash: &str,
        at: DateTime<Utc>,
    ) -> Result<(), StoreError>;
    /// Atomically consumes the setup token. Returns false if it does not
    /// match or was already consumed.
    async fn consume_setup_token(&self, token_hash: &str) -> Result<bool, StoreError>;

    /// `Conflict` if the prefix exists.
    async fn insert_api_key(&self, key: ApiKey) -> Result<(), StoreError>;
    async fn get_api_key_by_prefix(&self, prefix: &str) -> Result<Option<ApiKey>, StoreError>;
    async fn list_api_keys(&self, page: PageRequest) -> Result<Page<ApiKey>, StoreError>;
    /// Returns false if already revoked. `NotFound` if missing.
    async fn revoke_api_key(&self, id: &ApiKeyId, at: DateTime<Utc>) -> Result<bool, StoreError>;
    async fn touch_api_key(&self, id: &ApiKeyId, at: DateTime<Utc>) -> Result<(), StoreError>;
}

/// Data plane nodes, join tokens, key material and the snapshot counter.
#[async_trait]
pub trait NodeStore: Send + Sync {
    async fn insert_join_token(&self, token: JoinTokenRecord) -> Result<(), StoreError>;
    /// Atomically consumes an unexpired, unconsumed token whose hash matches.
    async fn consume_join_token(
        &self,
        id: &str,
        secret_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<bool, StoreError>;

    async fn insert_node(&self, node: Node) -> Result<(), StoreError>;
    async fn get_node(&self, id: &NodeId) -> Result<Option<Node>, StoreError>;
    async fn list_nodes(&self, page: PageRequest) -> Result<Page<Node>, StoreError>;
    async fn update_node_cert(
        &self,
        id: &NodeId,
        serial: &str,
        not_after: DateTime<Utc>,
    ) -> Result<(), StoreError>;
    async fn touch_node(&self, id: &NodeId, at: DateTime<Utc>) -> Result<(), StoreError>;
    /// Returns false if already revoked. `NotFound` if missing.
    async fn revoke_node(&self, id: &NodeId, at: DateTime<Utc>) -> Result<bool, StoreError>;

    async fn get_key_material(&self, name: &str) -> Result<Option<Vec<u8>>, StoreError>;
    /// Stores `value` unless `name` exists; returns whichever value is stored.
    async fn put_key_material_if_absent(
        &self,
        name: &str,
        value: Vec<u8>,
    ) -> Result<Vec<u8>, StoreError>;

    /// Strictly increasing across restarts.
    async fn next_snapshot_version(&self) -> Result<u64, StoreError>;
}
