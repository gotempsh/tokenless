// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Records persisted by the store traits.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokenless_core::authz::Role;
use tokenless_core::egress::EgressPolicy;
use tokenless_core::host::HostPattern;
use tokenless_core::ids::{
    ApiKeyId, BundleId, CredentialId, InviteId, NodeId, RuleId, SessionId, SignInId, UserId,
    VariableId, VaultId,
};
use tokenless_core::rule::RuleScope;
use tokenless_core::scope::Scope;
use tokenless_core::snapshot::UnmatchedHostPolicy;
use tokenless_core::substitution::Substitution;
use tokenless_core::template::ServiceTemplate;
use tokenless_core::variables::CustomHeader;

mod audit_export;
mod sso;
pub use audit_export::*;
pub use sso::*;

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

/// What deleting a vault removed. Audit events and the (revoked) session
/// records are kept: proxies must keep refusing those tokens until they
/// expire.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultDeletion {
    pub credentials: u64,
    pub rules: u64,
    pub bundles: u64,
    pub sessions_revoked: u64,
    pub api_keys_revoked: u64,
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
    /// Placeholders the agent sends that the proxy replaces with one of the
    /// secret fields. Configuration only; the values stay sealed.
    #[serde(default)]
    pub substitutions: Vec<Substitution>,
    /// When the secret stops being valid upstream, for one that expires
    /// (an installation token, say). The proxy stops injecting it then,
    /// with a typed error, rather than sending a credential the upstream
    /// will refuse. Set with the secret; replacing the secret replaces it.
    #[serde(default)]
    pub not_after: Option<DateTime<Utc>>,
    /// Counts the secrets this credential has held: 1 when created, one
    /// more on each rotation. A rotation can name the generation it
    /// replaces, so two refreshers cannot overwrite each other.
    #[serde(default = "first_generation")]
    pub secret_generation: u64,
    /// The caller-chosen id of the rotation that set the current secret,
    /// so a retried rotation is recognised rather than applied twice.
    #[serde(default)]
    pub rotation_id: Option<String>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

fn first_generation() -> u64 {
    1
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

/// A named, reusable list of a vault's rules for one kind of job, such as
/// `code-review` with the GitHub and Slack rules. Sessions are minted from
/// it by name; each session keeps the rules it was minted with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessBundle {
    pub id: BundleId,
    pub vault_id: VaultId,
    pub name: String,
    pub description: String,
    /// Sorted, without duplicates. Deleting a rule removes it from bundles.
    pub rule_ids: Vec<RuleId>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// The bundle a session was minted from, as it was named at the time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionBundle {
    pub id: BundleId,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxySession {
    pub id: SessionId,
    pub vault_id: VaultId,
    pub rule_ids: Vec<RuleId>,
    #[serde(default)]
    pub bundle: Option<SessionBundle>,
    pub labels: BTreeMap<String, String>,
    pub request_limit: Option<u64>,
    /// The only node that accepts it, when minted for one.
    #[serde(default)]
    pub node_id: Option<NodeId>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Where the previous page of a session list ended. Lists are newest
/// first, ties broken by id, so the next page starts after this session
/// whatever was minted or ended in between.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionCursor {
    pub created_at: DateTime<Utc>,
    pub id: SessionId,
}

impl From<&ProxySession> for SessionCursor {
    fn from(session: &ProxySession) -> Self {
        Self {
            created_at: session.created_at,
            id: session.id,
        }
    }
}

/// Which sessions a list returns within its vault or bundle.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionListing {
    /// Only those neither revoked nor expired.
    pub active: bool,
    /// Only those after this one.
    pub after: Option<SessionCursor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    pub unmatched_host_policy: UnmatchedHostPolicy,
    /// Which addresses passthrough tunnels and validation requests may reach.
    #[serde(default)]
    pub egress: EgressPolicy,
    /// Hosts every session may tunnel to under the `deny` policy, such as
    /// package registries. Never intercepted, never given a credential.
    #[serde(default)]
    pub passthrough_hosts: Vec<HostPattern>,
    /// The longest session anyone may mint, in seconds.
    #[serde(default = "default_max_session_ttl")]
    pub max_session_ttl_secs: u64,
}

fn default_max_session_ttl() -> u64 {
    tokenless_core::session::DEFAULT_MAX_SESSION_TTL_SECS
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            unmatched_host_policy: UnmatchedHostPolicy::Passthrough,
            egress: EgressPolicy::default(),
            passthrough_hosts: Vec::new(),
            max_session_ttl_secs: default_max_session_ttl(),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
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
    /// Set for a person who signs in with single sign-on, never with a
    /// password: the account at the provider they sign in as.
    pub sso: Option<SsoIdentity>,
}

tokenless_core::redacted_debug!(User {
    id, username, totp_last_step, role, created_at, disabled_at, sso;
    password_hash, totp_secret_enc
});

/// A single-use invitation for a person to create an account with a role.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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

tokenless_core::redacted_debug!(Invite {
    id, role, created_by, created_at, expires_at, accepted_at, accepted_by, revoked_at;
    token_hash
});

impl Invite {
    /// Neither accepted, revoked nor expired at `now`.
    pub fn is_pending(&self, now: DateTime<Utc>) -> bool {
        self.accepted_at.is_none() && self.revoked_at.is_none() && self.expires_at > now
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct UiSession {
    /// What the person sees and revokes it by; the token hash never
    /// leaves the server.
    pub id: SignInId,
    pub token_hash: String,
    pub user_id: UserId,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub step_up_at: Option<DateTime<Utc>>,
    /// Updated at most once a minute while the sign-in is used.
    pub last_used_at: DateTime<Utc>,
    /// The client's `User-Agent` when it signed in, cut to
    /// [`MAX_USER_AGENT`] bytes.
    pub user_agent: Option<String>,
}

/// The longest `User-Agent` kept with a sign-in.
pub const MAX_USER_AGENT: usize = 256;

tokenless_core::redacted_debug!(UiSession { id, user_id, created_at, expires_at, step_up_at, last_used_at, user_agent; token_hash });

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Set on a launcher key: the key can only start sessions from this
    /// bundle, within these limits. `None` for an ordinary API key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch: Option<LaunchScope>,
}

tokenless_core::redacted_debug!(ApiKey {
    id, name, prefix, vault_id, role, created_by, created_at, expires_at, revoked_at, last_used_at, launch;
    secret_hash
});

/// What a launcher key may do: start sessions from one access bundle, for
/// an agent machine that should hold nothing broader than that. Every
/// session it starts gets these limits whatever the request asks for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchScope {
    pub bundle_id: BundleId,
    /// The longest session the key starts, at most what Settings allow.
    pub max_ttl_secs: u64,
    /// Requests each session may make; the request may ask for fewer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_limit: Option<u64>,
    /// Only this proxy accepts the key's sessions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<NodeId>,
    /// Stamped on every session the key starts, over the request's own.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct JoinTokenRecord {
    pub id: String,
    pub secret_hash: String,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
}

tokenless_core::redacted_debug!(JoinTokenRecord { id, created_by, created_at, expires_at, consumed_at; secret_hash });

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
    /// Sent only the rules of live sessions minted for it, rather than
    /// every enabled rule, so it never holds sealed credentials for
    /// workloads it does not run. Embedded data planes are.
    #[serde(default)]
    pub scoped_rules: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditQuery {
    pub vault_id: Option<VaultId>,
    pub action_prefix: Option<String>,
    /// The session's own history (events targeting `session:<id>`: minted,
    /// relabelled, revoked) and its traffic (events whose `session_id`
    /// detail is this session): `AuditEvent::session_ref`.
    pub session_id: Option<SessionId>,
    /// One service's history and traffic: `AuditEvent::credential_ref`.
    pub credential_id: Option<CredentialId>,
    pub page: PageRequest,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every public type holding a secret prints `***` for it under `{:?}`,
    /// whatever reaches a log line, an error or a panic. A freshly minted
    /// session still serializes its token: that is how it is returned, once.
    #[test]
    fn secret_holding_types_never_debug_their_secrets() {
        use crate::service::auth::{
            ChangePassword, DisableAuthenticator, EnableAuthenticator, LoginOutcome, LoginRequest,
            SessionAuth, StepUpProof, TotpEnrollment, UserSummary,
        };
        use crate::service::nodes::JoinTokenIssued;
        use crate::service::sessions::MintedSession;
        use crate::service::users::{AcceptInviteRequest, InviteIssued};
        use crate::service::Caller;

        const SECRET: &str = "SEKRET-do-not-print";
        let s = || SECRET.to_string();
        let now = Utc::now();
        let summary = UserSummary {
            id: UserId::new(),
            username: "ada".into(),
            role: Role::Admin,
            created_at: now,
            disabled_at: None,
            totp_enrolled: true,
            sso_provider_id: None,
        };
        let invite = Invite {
            id: InviteId::new(),
            token_hash: s(),
            role: Role::Editor,
            created_by: "admin".into(),
            created_at: now,
            expires_at: now,
            accepted_at: None,
            accepted_by: None,
            revoked_at: None,
        };
        let session = ProxySession {
            id: SessionId::new(),
            vault_id: VaultId::new(),
            rule_ids: vec![RuleId::new()],
            bundle: None,
            labels: BTreeMap::new(),
            request_limit: None,
            node_id: None,
            created_by: "admin".into(),
            created_at: now,
            expires_at: now,
            revoked_at: None,
        };
        let minted = MintedSession {
            token: s(),
            session,
        };
        let debugged = [
            format!(
                "{:?}",
                User {
                    id: UserId::new(),
                    username: "ada".into(),
                    password_hash: s(),
                    totp_secret_enc: Some(SECRET.as_bytes().to_vec()),
                    totp_last_step: None,
                    role: Role::Admin,
                    created_at: now,
                    disabled_at: None,
                    sso: None,
                }
            ),
            format!("{invite:?}"),
            format!(
                "{:?}",
                UiSession {
                    id: SignInId::new(),
                    token_hash: s(),
                    user_id: UserId::new(),
                    created_at: now,
                    expires_at: now,
                    step_up_at: None,
                    last_used_at: now,
                    user_agent: None,
                }
            ),
            format!(
                "{:?}",
                ApiKey {
                    id: ApiKeyId::new(),
                    name: "ci".into(),
                    prefix: "cbk_x".into(),
                    secret_hash: s(),
                    vault_id: VaultId::new(),
                    role: Role::Editor,
                    created_by: "admin".into(),
                    created_at: now,
                    expires_at: now,
                    revoked_at: None,
                    last_used_at: None,
                    launch: None,
                }
            ),
            format!(
                "{:?}",
                JoinTokenRecord {
                    id: "j".into(),
                    secret_hash: s(),
                    created_by: "admin".into(),
                    created_at: now,
                    expires_at: now,
                    consumed_at: None,
                }
            ),
            format!(
                "{:?}",
                TotpEnrollment {
                    secret: s(),
                    otpauth_url: format!("otpauth://totp/x?secret={SECRET}"),
                }
            ),
            format!(
                "{:?}",
                ChangePassword {
                    current_password: s(),
                    new_password: s(),
                }
            ),
            format!(
                "{:?}",
                EnableAuthenticator {
                    secret: s(),
                    code: s(),
                    password: s(),
                }
            ),
            format!(
                "{:?}",
                DisableAuthenticator {
                    code: s(),
                    password: s(),
                }
            ),
            format!(
                "{:?}",
                LoginRequest {
                    username: "ada".into(),
                    password: s(),
                    totp_code: Some(s()),
                }
            ),
            format!(
                "{:?}",
                StepUpProof {
                    code: Some(s()),
                    password: Some(s()),
                }
            ),
            format!(
                "{:?}",
                LoginOutcome {
                    token: s(),
                    csrf_token: s(),
                    user: summary.clone(),
                    expires_at: now,
                    max_age_secs: 60,
                }
            ),
            format!(
                "{:?}",
                SessionAuth {
                    caller: Caller::service(tokenless_core::authz::Principal::service(
                        "test",
                        Role::Admin,
                        None,
                    )),
                    token_hash: s(),
                    sign_in_id: SignInId::new(),
                    user: summary.clone(),
                    expires_at: now,
                }
            ),
            format!(
                "{:?}",
                InviteIssued {
                    token: s(),
                    invite: invite.clone(),
                }
            ),
            format!(
                "{:?}",
                AcceptInviteRequest {
                    invite_token: s(),
                    username: "ada".into(),
                    password: s(),
                    totp_secret: Some(s()),
                    totp_code: Some(s()),
                }
            ),
            format!(
                "{:?}",
                JoinTokenIssued {
                    token: s(),
                    token_id: "j".into(),
                    expires_at: now,
                }
            ),
            format!("{minted:?}"),
        ];
        for text in &debugged {
            assert!(!text.contains(SECRET), "a secret in Debug output: {text}");
            assert!(text.contains("***"), "{text}");
        }
        let json = serde_json::to_string(&minted).unwrap();
        assert!(
            json.contains(SECRET),
            "the minted token is returned: {json}"
        );
    }

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
