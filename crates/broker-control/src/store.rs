// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The seams an embedding system implements.
//!
//! `CredentialStore`, `PolicyStore`, `AuditSink` and `Authorizer` are the
//! four traits a host platform supplies to run the broker natively.
//! `IdentityStore` and `NodeStore` back the standalone login and node
//! enrolment flows. `broker-conformance` holds the behaviour every
//! implementation must exhibit.

use std::collections::BTreeMap;

use async_trait::async_trait;
use broker_core::audit::AuditEvent;
use broker_core::authz::{rbac_decide, Action, Decision, Principal, Role};
use broker_core::ids::{
    ApiKeyId, BundleId, CredentialId, InviteId, NodeId, RuleId, SessionId, UserId, VariableId,
    VaultId,
};
use broker_core::substitution::Substitution;
use broker_core::variables::CustomHeader;
use chrono::{DateTime, Utc};

use crate::error::StoreError;
use crate::model::{
    AccessBundle, ApiKey, AuditQuery, CredentialMeta, Invite, JoinTokenRecord, Node, Page,
    PageRequest, ProxySession, Rule, Settings, StoredTemplate, UiSession, User, Variable, Vault,
    VaultDeletion,
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
        audit: &[AuditEvent],
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
        variable_refs: Vec<String>,
        updated_at: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError>;
    /// Replaces the custom headers; `NotFound` if the credential does not exist.
    async fn update_custom_headers(
        &self,
        id: &CredentialId,
        custom_headers: Vec<CustomHeader>,
        variable_refs: Vec<String>,
        updated_at: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError>;
    /// Replaces the substitutions; `NotFound` if the credential does not exist.
    async fn update_substitutions(
        &self,
        id: &CredentialId,
        substitutions: Vec<Substitution>,
        updated_at: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError>;
    /// Credentials in every vault that reference at least one variable.
    async fn list_credentials_with_variables(&self) -> Result<Vec<CredentialMeta>, StoreError>;

    /// `Conflict` if a variable with the same key exists.
    async fn insert_variable(
        &self,
        variable: Variable,
        ciphertext: Vec<u8>,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError>;
    async fn get_variable(&self, id: &VariableId) -> Result<Option<Variable>, StoreError>;
    /// Ordered by key.
    async fn list_variables(&self, page: PageRequest) -> Result<Page<Variable>, StoreError>;
    /// The given keys that exist; unknown keys are left out.
    async fn existing_variable_keys(&self, keys: &[String]) -> Result<Vec<String>, StoreError>;
    /// `NotFound` if the variable does not exist.
    async fn replace_variable_value(
        &self,
        id: &VariableId,
        ciphertext: Vec<u8>,
        updated_by: &str,
        updated_at: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError>;
    /// `NotFound` if it does not exist; `Conflict` if a credential still
    /// references its key. The check and the delete are one transaction.
    async fn delete_variable(
        &self,
        id: &VariableId,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError>;
    /// Encrypted values of the given keys, for rendering.
    async fn load_variable_ciphertexts(
        &self,
        keys: &[String],
    ) -> Result<Vec<(Variable, Vec<u8>)>, StoreError>;
    /// `NotFound` if the credential does not exist.
    async fn delete_credential(
        &self,
        id: &CredentialId,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError>;
    async fn load_secret_ciphertext(
        &self,
        id: &CredentialId,
    ) -> Result<Option<Vec<u8>>, StoreError>;
}

/// Vaults, templates, rules, proxy sessions and instance settings.
#[async_trait]
pub trait PolicyStore: Send + Sync {
    /// `Conflict` if a vault with the same name exists.
    async fn insert_vault(&self, vault: Vault, audit: &[AuditEvent]) -> Result<(), StoreError>;
    async fn get_vault(&self, id: &VaultId) -> Result<Option<Vault>, StoreError>;
    async fn list_vaults(&self, page: PageRequest) -> Result<Page<Vault>, StoreError>;
    /// Deletes the vault, its credentials, rules and bundles, and revokes
    /// at `at` its live sessions and the API keys bound to it, all at once.
    /// `NotFound` if missing.
    async fn delete_vault(
        &self,
        id: &VaultId,
        at: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<VaultDeletion, StoreError>;
    /// Sessions of the vault that are neither revoked nor expired at `now`.
    async fn count_live_sessions(
        &self,
        vault_id: &VaultId,
        now: DateTime<Utc>,
    ) -> Result<u64, StoreError>;

    /// Inserts a template version. `Conflict` if that id+version exists.
    async fn insert_template(
        &self,
        template: StoredTemplate,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError>;
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
        audit: &[AuditEvent],
    ) -> Result<(), StoreError>;

    async fn insert_rule(&self, rule: Rule, audit: &[AuditEvent]) -> Result<(), StoreError>;
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
    async fn update_rule(&self, rule: Rule, audit: &[AuditEvent]) -> Result<(), StoreError>;
    /// Also removes the rule from every access bundle that lists it.
    async fn delete_rule(&self, id: &RuleId, audit: &[AuditEvent]) -> Result<(), StoreError>;

    /// `Conflict` if the vault already has a bundle with this name.
    async fn insert_bundle(
        &self,
        bundle: AccessBundle,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError>;
    async fn get_bundle(&self, id: &BundleId) -> Result<Option<AccessBundle>, StoreError>;
    async fn get_bundle_by_name(
        &self,
        vault_id: &VaultId,
        name: &str,
    ) -> Result<Option<AccessBundle>, StoreError>;
    /// Ordered by name.
    async fn list_bundles(
        &self,
        vault_id: &VaultId,
        page: PageRequest,
    ) -> Result<Page<AccessBundle>, StoreError>;
    /// Replaces name, description and rules. `NotFound` if it does not
    /// exist, `Conflict` if the new name is taken in the vault.
    async fn update_bundle(
        &self,
        bundle: AccessBundle,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError>;
    /// Deletes the bundle and revokes, at `at`, its sessions that are still
    /// live. Returns how many were revoked; `NotFound` if missing.
    async fn delete_bundle(
        &self,
        id: &BundleId,
        at: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<u64, StoreError>;

    async fn insert_session(
        &self,
        session: ProxySession,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError>;
    async fn get_session(&self, id: &SessionId) -> Result<Option<ProxySession>, StoreError>;
    /// Newest first; every vault when `vault_id` is `None`.
    async fn list_sessions(
        &self,
        vault_id: Option<&VaultId>,
        page: PageRequest,
    ) -> Result<Page<ProxySession>, StoreError>;
    /// Returns false if it was already revoked. `NotFound` if missing.
    async fn revoke_session(
        &self,
        id: &SessionId,
        at: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<bool, StoreError>;
    /// Replaces a session's labels; `NotFound` if missing.
    async fn update_session_labels(
        &self,
        id: &SessionId,
        labels: BTreeMap<String, String>,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError>;
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
    async fn put_settings(
        &self,
        settings: Settings,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError>;
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
    async fn insert_user(&self, user: User, audit: &[AuditEvent]) -> Result<(), StoreError>;
    async fn get_user(&self, id: &UserId) -> Result<Option<User>, StoreError>;
    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, StoreError>;
    /// Newest first.
    async fn list_users(&self, page: PageRequest) -> Result<Page<User>, StoreError>;
    /// Sets a user's role and disabled time in one step; disabling also
    /// deletes the user's UI sessions. `NotFound` if the user is missing,
    /// `Conflict` (changing nothing) if no enabled admin would remain.
    async fn update_user_access(
        &self,
        id: &UserId,
        role: Role,
        disabled_at: Option<DateTime<Utc>>,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError>;

    /// `Conflict` if the id or token hash exists.
    async fn insert_invite(&self, invite: Invite, audit: &[AuditEvent]) -> Result<(), StoreError>;
    async fn get_invite_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<Invite>, StoreError>;
    /// Newest first.
    async fn list_invites(&self, page: PageRequest) -> Result<Page<Invite>, StoreError>;
    /// Returns false if the invite was already accepted or revoked.
    /// `NotFound` if missing.
    async fn revoke_invite(
        &self,
        id: &InviteId,
        at: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<bool, StoreError>;
    /// Atomically marks the pending invite with this token hash and role as
    /// accepted by `user` (unexpired at `user.created_at`) and inserts the
    /// user. Returns false, changing nothing, when there is no such invite.
    /// `Conflict` (invite left pending) if the username is taken.
    async fn accept_invite(
        &self,
        token_hash: &str,
        user: User,
        audit: &[AuditEvent],
    ) -> Result<bool, StoreError>;
    /// Atomically records a used TOTP step if it is newer than the stored
    /// one. Returns false when the step was already used (replay).
    async fn advance_totp_step(&self, id: &UserId, step: u64) -> Result<bool, StoreError>;

    async fn insert_ui_session(
        &self,
        session: UiSession,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError>;
    async fn get_ui_session(&self, token_hash: &str) -> Result<Option<UiSession>, StoreError>;
    async fn set_ui_session_step_up(
        &self,
        token_hash: &str,
        at: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError>;
    async fn delete_ui_session(
        &self,
        token_hash: &str,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError>;
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
    async fn insert_api_key(&self, key: ApiKey, audit: &[AuditEvent]) -> Result<(), StoreError>;
    async fn get_api_key_by_prefix(&self, prefix: &str) -> Result<Option<ApiKey>, StoreError>;
    async fn list_api_keys(&self, page: PageRequest) -> Result<Page<ApiKey>, StoreError>;
    /// Returns false if already revoked. `NotFound` if missing.
    async fn revoke_api_key(
        &self,
        id: &ApiKeyId,
        at: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<bool, StoreError>;
    async fn touch_api_key(&self, id: &ApiKeyId, at: DateTime<Utc>) -> Result<(), StoreError>;
}

/// Data plane nodes, join tokens, key material and the snapshot counter.
#[async_trait]
pub trait NodeStore: Send + Sync {
    async fn insert_join_token(
        &self,
        token: JoinTokenRecord,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError>;
    /// Atomically consumes an unexpired, unconsumed token whose hash matches.
    async fn consume_join_token(
        &self,
        id: &str,
        secret_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<bool, StoreError>;

    async fn insert_node(&self, node: Node, audit: &[AuditEvent]) -> Result<(), StoreError>;
    async fn get_node(&self, id: &NodeId) -> Result<Option<Node>, StoreError>;
    async fn list_nodes(&self, page: PageRequest) -> Result<Page<Node>, StoreError>;
    async fn update_node_cert(
        &self,
        id: &NodeId,
        serial: &str,
        not_after: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError>;
    async fn touch_node(&self, id: &NodeId, at: DateTime<Utc>) -> Result<(), StoreError>;
    /// Returns false if already revoked. `NotFound` if missing.
    async fn revoke_node(
        &self,
        id: &NodeId,
        at: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<bool, StoreError>;

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
