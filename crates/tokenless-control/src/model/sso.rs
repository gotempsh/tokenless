// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Single sign-on: OpenID Connect providers, the sign-ins in progress with
//! them, and whether people may still sign in with a password.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokenless_core::authz::Role;
use tokenless_core::ids::{OidcProviderId, UserId};

/// The most providers one instance holds.
pub const MAX_OIDC_PROVIDERS: usize = 20;
/// The most group mappings one provider holds.
pub const MAX_ROLE_MAPPINGS: usize = 100;

/// Who may still sign in with a username and password.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PasswordSignIn {
    #[default]
    Everyone,
    /// Local admins only, to get in when the identity provider cannot be
    /// reached. Everyone else signs in with single sign-on.
    AdminsOnly,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignInSettings {
    #[serde(default)]
    pub password_sign_in: PasswordSignIn,
}

/// People in `group` at the provider get `role`. A person in several
/// mapped groups gets the highest of their roles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleMapping {
    pub group: String,
    pub role: Role,
}

/// An OpenID Connect provider people sign in with.
#[derive(Clone, PartialEq, Eq)]
pub struct OidcProvider {
    pub id: OidcProviderId,
    /// In the sign-in URLs: `/api/v1/auth/oidc/<slug>/start`.
    pub slug: String,
    /// On the sign-in button.
    pub name: String,
    /// The issuer, exactly as in its discovery document and ID tokens.
    pub issuer: String,
    pub client_id: String,
    /// Encrypted at rest; `None` for a public client, which proves itself
    /// with PKCE alone.
    pub client_secret_enc: Option<Vec<u8>>,
    /// This instance's callback, as registered at the provider.
    pub redirect_uri: String,
    /// Requested on top of `openid`.
    pub scopes: Vec<String>,
    /// Where the groups are in the ID token or userinfo, as a dotted path
    /// (`groups`, `realm_access.roles`).
    pub groups_claim: String,
    /// The claim a new account's username comes from.
    pub username_claim: String,
    pub role_mappings: Vec<RoleMapping>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

tokenless_core::redacted_debug!(OidcProvider {
    id, slug, name, issuer, client_id, redirect_uri, scopes, groups_claim,
    username_claim, role_mappings, enabled, created_at, updated_at;
    client_secret_enc
});

/// The account at a provider that a person signs in as.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SsoIdentity {
    pub provider_id: OidcProviderId,
    /// The provider's `sub`: stable and never reassigned, unlike an email.
    pub subject: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OidcPurpose {
    /// Sign in, creating the account on first use.
    Login,
    /// Prove again who is behind an existing session.
    StepUp,
}

impl OidcPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            OidcPurpose::Login => "login",
            OidcPurpose::StepUp => "step_up",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "login" => Some(OidcPurpose::Login),
            "step_up" => Some(OidcPurpose::StepUp),
            _ => None,
        }
    }
}

/// A sign-in sent to a provider and not yet back. The server keeps
/// nothing: the browser that started it carries it in a sealed cookie
/// (encrypted and authenticated), so the answer is accepted only there,
/// and starting sign-ins anonymously fills no table.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcRequest {
    /// Hash of the `state` sent to the provider; the answer must match it.
    pub state_hash: String,
    pub provider_id: OidcProviderId,
    pub purpose: OidcPurpose,
    pub nonce: String,
    pub pkce_verifier: String,
    /// For a step-up: the session it refreshes and its person.
    pub ui_session_hash: Option<String>,
    pub user_id: Option<UserId>,
    /// A path on this instance to go back to afterwards.
    pub return_to: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

tokenless_core::redacted_debug!(OidcRequest {
    provider_id, purpose, user_id, return_to, created_at, expires_at;
    state_hash, nonce, pkce_verifier, ui_session_hash
});
