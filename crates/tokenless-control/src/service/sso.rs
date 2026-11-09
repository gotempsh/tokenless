// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Single sign-on with OpenID Connect providers: the authorization code
//! flow with PKCE, people's groups mapped to roles, accounts created on
//! first sign-in, and step-up by signing in at the provider again.
//!
//! A sign-in in progress is an [`OidcRequest`] the starting browser
//! carries in a sealed cookie (see [`FLOW_CONTEXT`]): the server stores
//! nothing until the provider answers, so anonymous starts cannot fill a
//! table or crowd out real sign-ins. It expires after [`REQUEST_TTL_SECS`],
//! the answer's `state` must match it, and the callback clears the cookie;
//! the provider refuses a code used twice. The ID token is checked against the
//! provider's published keys and must carry the request's nonce. The role
//! comes from the provider's groups at every sign-in; a person whose groups
//! map to no role is refused, and told which groups were seen.

pub mod brand;
pub mod oidc;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration as StdDuration, Instant};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokenless_auth::jwt::{self, JwkSet, JwtError};
use tokenless_auth::sealed::SealKey;
use tokenless_auth::token;
use tokenless_core::audit::{AuditEvent, AuditOutcome};
use tokenless_core::authz::{Action, Role};
use tokenless_core::ids::{OidcProviderId, UserId};
use tracing::{info, warn};
use url::Url;

pub use self::brand::ProviderBrand;
use self::oidc::{Discovery, Expected, OidcTransport, CALLBACK_PATH};
use super::auth::{open_ui_session, LoginOutcome, SessionAuth};
use super::{AuditRecorder, Caller, ControlConfig, Guard};
use crate::cipher::{KeyScope, SecretCipher};
use crate::error::{ControlError, StoreError};
use crate::keys::KeyRing;
use crate::model::{
    OidcProvider, OidcPurpose, OidcRequest, PasswordSignIn, RoleMapping, SignInSettings,
    SsoIdentity, User, MAX_OIDC_PROVIDERS, MAX_ROLE_MAPPINGS,
};
use crate::store::{IdentityStore, SsoStore};

/// How long a sign-in at the provider may take.
pub const REQUEST_TTL_SECS: u64 = 600;
/// What the flow cookie is sealed for; a value sealed for anything else
/// does not open as one.
pub const FLOW_CONTEXT: &[u8] = b"tokenless|oidc-request|v1";
/// How long a provider's discovery document and keys are reused.
const METADATA_TTL: StdDuration = StdDuration::from_secs(15 * 60);
/// The soonest the keys are fetched again for a token signed by an unknown key.
const KEY_REFRESH_MIN: StdDuration = StdDuration::from_secs(30);
const MAX_RETURN_TO: usize = 512;

pub fn default_groups_claim() -> String {
    "groups".into()
}

pub fn default_username_claim() -> String {
    "preferred_username".into()
}

fn enabled_by_default() -> bool {
    true
}

/// A provider as the API shows it: never the client secret.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OidcProviderView {
    pub id: OidcProviderId,
    pub slug: String,
    pub name: String,
    pub issuer: String,
    /// Read from the issuer, for the logo.
    pub brand: ProviderBrand,
    pub client_id: String,
    pub has_client_secret: bool,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub groups_claim: String,
    pub username_claim: String,
    pub role_mappings: Vec<RoleMapping>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<&OidcProvider> for OidcProviderView {
    fn from(p: &OidcProvider) -> Self {
        Self {
            id: p.id,
            slug: p.slug.clone(),
            name: p.name.clone(),
            issuer: p.issuer.clone(),
            brand: ProviderBrand::of_issuer(&p.issuer),
            client_id: p.client_id.clone(),
            has_client_secret: p.client_secret_enc.is_some(),
            redirect_uri: p.redirect_uri.clone(),
            scopes: p.scopes.clone(),
            groups_claim: p.groups_claim.clone(),
            username_claim: p.username_claim.clone(),
            role_mappings: p.role_mappings.clone(),
            enabled: p.enabled,
            created_at: p.created_at,
            updated_at: p.updated_at,
        }
    }
}

/// A provider to create, or the whole of one to replace.
#[derive(Clone, Deserialize)]
pub struct OidcProviderInput {
    pub slug: String,
    pub name: String,
    pub issuer: String,
    pub client_id: String,
    /// Write-only. On a replace, leaving it out keeps the stored secret.
    #[serde(default)]
    pub client_secret: Option<String>,
    /// Remove the stored secret: the client becomes public (PKCE only).
    #[serde(default)]
    pub clear_client_secret: bool,
    pub redirect_uri: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default = "default_groups_claim")]
    pub groups_claim: String,
    #[serde(default = "default_username_claim")]
    pub username_claim: String,
    #[serde(default)]
    pub role_mappings: Vec<RoleMapping>,
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
}

tokenless_core::redacted_debug!(OidcProviderInput {
    slug, name, issuer, client_id, clear_client_secret, redirect_uri, scopes,
    groups_claim, username_claim, role_mappings, enabled;
    client_secret
});

/// A provider on the sign-in page.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignInProvider {
    pub slug: String,
    pub name: String,
    pub brand: ProviderBrand,
}

/// How people can sign in here; public, for the sign-in page.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignInOptions {
    pub providers: Vec<SignInProvider>,
    pub password_sign_in: PasswordSignIn,
}

/// The provider a person signs in with, for their own account page.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SsoSignIn {
    pub provider_id: OidcProviderId,
    pub slug: String,
    pub name: String,
    pub brand: ProviderBrand,
}

/// Where to send the browser, with the cookie that ties the answer to it.
pub struct SsoRedirect {
    pub authorization_url: String,
    /// The sealed sign-in in progress: the flow cookie's value.
    pub browser_token: String,
    pub max_age_secs: u64,
}

tokenless_core::redacted_debug!(SsoRedirect { max_age_secs; authorization_url, browser_token });

/// The provider's answer, as query parameters on the callback.
#[derive(Clone, Default, Deserialize)]
pub struct SsoCallback {
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_description: Option<String>,
}

tokenless_core::redacted_debug!(SsoCallback { error, error_description; state, code });

#[derive(Debug)]
pub enum SsoCompleted {
    SignedIn {
        login: LoginOutcome,
        return_to: String,
    },
    SteppedUp {
        at: DateTime<Utc>,
        return_to: String,
    },
}

/// A sign-in that did not complete, and where the browser goes to say so.
#[derive(Debug)]
pub struct SsoFailed {
    pub purpose: OidcPurpose,
    pub return_to: String,
    pub error: ControlError,
}

/// A provider's discovery document and keys, as last fetched.
struct Metadata {
    discovery: Discovery,
    keys: JwkSet,
    fetched: Instant,
    keys_fetched: Instant,
}

pub struct SsoService {
    identity: Arc<dyn IdentityStore>,
    sso: Arc<dyn SsoStore>,
    cipher: Arc<dyn SecretCipher>,
    keys: Arc<KeyRing>,
    guard: Guard,
    audit: AuditRecorder,
    config: ControlConfig,
    transport: Arc<dyn OidcTransport>,
    metadata: Mutex<HashMap<String, Arc<Metadata>>>,
    /// Seals sign-ins in progress into the flow cookie.
    flow_key: SealKey,
}

fn client_secret_aad(id: &OidcProviderId) -> Vec<u8> {
    format!("oidc-client-secret|{id}").into_bytes()
}

fn validation(message: impl Into<String>) -> ControlError {
    ControlError::validation(message)
}

fn check_name(what: &str, value: &str, max: usize) -> Result<String, ControlError> {
    let v = value.trim();
    if v.is_empty() || v.len() > max || v.chars().any(char::is_control) {
        return Err(validation(format!("{what} must be 1-{max} characters")));
    }
    Ok(v.to_string())
}

fn check_claim_path(what: &str, value: &str) -> Result<String, ControlError> {
    let v = value.trim();
    let ok = (1..=200).contains(&v.len())
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-.:/".contains(c));
    if !ok {
        return Err(validation(format!(
            "{what} '{v}' must be a claim name or dotted path of letters, digits and _ - . : /"
        )));
    }
    Ok(v.to_string())
}

/// A path on this instance; anything else would make the callback an open
/// redirect.
fn check_return_to(value: Option<&str>) -> Result<String, ControlError> {
    let v = value.unwrap_or("/");
    let ok = v.starts_with('/')
        && !v.starts_with("//")
        && !v.contains('\\')
        && v.len() <= MAX_RETURN_TO
        && !v.chars().any(char::is_control);
    if !ok {
        return Err(validation(format!(
            "return_to must be a path on this instance starting with '/', up to {MAX_RETURN_TO} characters"
        )));
    }
    Ok(v.to_string())
}

impl SsoService {
    #[allow(clippy::too_many_arguments, reason = "each is a separate dependency")]
    pub fn new(
        identity: Arc<dyn IdentityStore>,
        sso: Arc<dyn SsoStore>,
        cipher: Arc<dyn SecretCipher>,
        keys: Arc<KeyRing>,
        guard: Guard,
        audit: AuditRecorder,
        config: ControlConfig,
        transport: Arc<dyn OidcTransport>,
    ) -> Result<Self, ControlError> {
        let flow_key = SealKey::derive(&keys.csrf_key, "oidc-flow-cookie")?;
        Ok(Self {
            identity,
            sso,
            cipher,
            keys,
            guard,
            audit,
            config,
            transport,
            metadata: Mutex::new(HashMap::new()),
            flow_key,
        })
    }

    // ----- administration ------------------------------------------------

    pub async fn list_providers(
        &self,
        caller: &Caller,
    ) -> Result<Vec<OidcProviderView>, ControlError> {
        self.guard.check(caller, Action::UserRead, None).await?;
        Ok(self
            .sso
            .list_oidc_providers()
            .await?
            .iter()
            .map(OidcProviderView::from)
            .collect())
    }

    pub async fn get_provider(
        &self,
        caller: &Caller,
        id: &OidcProviderId,
    ) -> Result<OidcProviderView, ControlError> {
        self.guard.check(caller, Action::UserRead, None).await?;
        Ok(OidcProviderView::from(&self.provider(id).await?))
    }

    async fn provider(&self, id: &OidcProviderId) -> Result<OidcProvider, ControlError> {
        self.sso
            .get_oidc_provider(id)
            .await?
            .ok_or_else(|| ControlError::not_found("identity provider", id))
    }

    /// Checks everything but the secret, and that the issuer's discovery
    /// document can be read, when the provider is to be enabled.
    async fn checked(
        &self,
        id: OidcProviderId,
        req: &OidcProviderInput,
        created_at: DateTime<Utc>,
        client_secret_enc: Option<Vec<u8>>,
    ) -> Result<OidcProvider, ControlError> {
        let slug = req.slug.trim().to_string();
        let slug_ok = (2..=32).contains(&slug.len())
            && slug
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            && !slug.starts_with('-');
        if !slug_ok {
            return Err(validation(format!(
                "slug '{slug}' must be 2-32 characters of a-z, 0-9 and '-', not starting with '-'"
            )));
        }
        let issuer = req.issuer.trim().to_string();
        let issuer_url = oidc::check_url("issuer", &issuer).map_err(validation)?;
        if issuer_url.query().is_some() {
            return Err(validation(format!(
                "issuer '{issuer}' must not have a query"
            )));
        }
        let redirect_uri = req.redirect_uri.trim().to_string();
        let redirect = oidc::check_url("redirect_uri", &redirect_uri).map_err(validation)?;
        if redirect.path() != CALLBACK_PATH || redirect.query().is_some() {
            return Err(validation(format!(
                "redirect_uri '{redirect_uri}' must be this instance's address followed by {CALLBACK_PATH}, as registered at the provider"
            )));
        }
        let mut scopes = Vec::new();
        for scope in &req.scopes {
            let s = scope.trim();
            let ok = (1..=64).contains(&s.len())
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "_-.:/".contains(c));
            if !ok {
                return Err(validation(format!(
                    "scope '{s}' must be 1-64 letters, digits or _ - . : /"
                )));
            }
            if s != "openid" && !scopes.iter().any(|x| x == s) {
                scopes.push(s.to_string());
            }
        }
        if scopes.len() > 20 {
            return Err(validation("at most 20 scopes besides 'openid'"));
        }
        if req.role_mappings.len() > MAX_ROLE_MAPPINGS {
            return Err(validation(format!(
                "at most {MAX_ROLE_MAPPINGS} group mappings"
            )));
        }
        let mut role_mappings: Vec<RoleMapping> = Vec::new();
        for m in &req.role_mappings {
            let group = check_name("a mapped group", &m.group, 256)?;
            if role_mappings.iter().any(|x| x.group == group) {
                return Err(validation(format!(
                    "group '{group}' is mapped twice; give each group one role"
                )));
            }
            role_mappings.push(RoleMapping {
                group,
                role: m.role,
            });
        }
        if req.enabled && role_mappings.is_empty() {
            return Err(validation(
                "map at least one group to a role: without one nobody can sign in",
            ));
        }
        let provider = OidcProvider {
            id,
            slug,
            name: check_name("name", &req.name, 60)?,
            issuer,
            client_id: check_name("client_id", &req.client_id, 255)?,
            client_secret_enc,
            redirect_uri,
            scopes,
            groups_claim: check_claim_path("groups_claim", &req.groups_claim)?,
            username_claim: check_claim_path("username_claim", &req.username_claim)?,
            role_mappings,
            enabled: req.enabled,
            created_at,
            updated_at: Utc::now(),
        };
        if provider.enabled {
            self.fetch_discovery(&provider).await.map_err(|e| {
                validation(format!(
                    "could not use issuer '{}': {e}; check the issuer URL and that this server can reach it",
                    provider.issuer
                ))
            })?;
        }
        Ok(provider)
    }

    async fn encrypt_secret(
        &self,
        id: &OidcProviderId,
        secret: &str,
    ) -> Result<Vec<u8>, ControlError> {
        let secret = secret.trim();
        if secret.is_empty() || secret.len() > 1024 {
            return Err(validation("client_secret must be 1-1024 characters"));
        }
        self.cipher
            .encrypt(
                KeyScope::Instance,
                secret.as_bytes(),
                &client_secret_aad(id),
            )
            .await
    }

    pub async fn create_provider(
        &self,
        caller: &Caller,
        req: OidcProviderInput,
    ) -> Result<OidcProviderView, ControlError> {
        self.guard
            .check(caller, Action::IdentityProviderManage, None)
            .await?;
        if self.sso.list_oidc_providers().await?.len() >= MAX_OIDC_PROVIDERS {
            return Err(validation(format!(
                "an instance holds at most {MAX_OIDC_PROVIDERS} identity providers"
            )));
        }
        let id = OidcProviderId::new();
        let secret = match req.client_secret.as_deref() {
            Some(s) => Some(self.encrypt_secret(&id, s).await?),
            None => None,
        };
        let provider = self.checked(id, &req, Utc::now(), secret).await?;
        let event = AuditEvent::new(
            caller.actor(),
            "identity_provider.create",
            AuditOutcome::Success,
        )
        .target(format!("oidc_provider:{id}"))
        .detail("slug", provider.slug.clone())
        .detail("issuer", provider.issuer.clone())
        .detail("enabled", provider.enabled.to_string());
        match self
            .sso
            .insert_oidc_provider(provider.clone(), &[event])
            .await
        {
            Ok(()) => {}
            Err(StoreError::Conflict { .. }) => {
                return Err(ControlError::Conflict {
                    message: format!("an identity provider with slug '{}' exists", provider.slug),
                })
            }
            Err(e) => return Err(e.into()),
        }
        info!(provider = %provider.slug, issuer = %provider.issuer, "identity provider added");
        Ok(OidcProviderView::from(&provider))
    }

    pub async fn update_provider(
        &self,
        caller: &Caller,
        id: &OidcProviderId,
        req: OidcProviderInput,
    ) -> Result<OidcProviderView, ControlError> {
        self.guard
            .check(caller, Action::IdentityProviderManage, None)
            .await?;
        let current = self.provider(id).await?;
        let secret = match (req.client_secret.as_deref(), req.clear_client_secret) {
            (Some(_), true) => {
                return Err(validation(
                    "send a new client_secret or clear_client_secret, not both",
                ))
            }
            (Some(s), false) => Some(self.encrypt_secret(id, s).await?),
            (None, true) => None,
            (None, false) => current.client_secret_enc.clone(),
        };
        let provider = self.checked(*id, &req, current.created_at, secret).await?;
        if current.enabled && !provider.enabled {
            self.keep_a_way_in(id).await?;
        }
        let event = AuditEvent::new(
            caller.actor(),
            "identity_provider.update",
            AuditOutcome::Success,
        )
        .target(format!("oidc_provider:{id}"))
        .detail("slug", provider.slug.clone())
        .detail("issuer", provider.issuer.clone())
        .detail("enabled", provider.enabled.to_string())
        .detail(
            "client_secret",
            match (req.client_secret.is_some(), req.clear_client_secret) {
                (true, _) => "replaced",
                (false, true) => "removed",
                (false, false) => "kept",
            },
        );
        match self
            .sso
            .update_oidc_provider(provider.clone(), &[event])
            .await
        {
            Ok(()) => {}
            Err(StoreError::Conflict { .. }) => {
                return Err(ControlError::Conflict {
                    message: format!("an identity provider with slug '{}' exists", provider.slug),
                })
            }
            Err(e) => return Err(e.into()),
        }
        self.forget_metadata(&current.issuer);
        info!(provider = %provider.slug, enabled = provider.enabled, "identity provider changed");
        Ok(OidcProviderView::from(&provider))
    }

    pub async fn delete_provider(
        &self,
        caller: &Caller,
        id: &OidcProviderId,
    ) -> Result<(), ControlError> {
        self.guard
            .check(caller, Action::IdentityProviderManage, None)
            .await?;
        let current = self.provider(id).await?;
        if current.enabled {
            self.keep_a_way_in(id).await?;
        }
        let event = AuditEvent::new(
            caller.actor(),
            "identity_provider.delete",
            AuditOutcome::Success,
        )
        .target(format!("oidc_provider:{id}"))
        .detail("slug", current.slug.clone());
        match self.sso.delete_oidc_provider(id, &[event]).await {
            Ok(()) => {}
            Err(StoreError::Conflict { detail, .. }) => {
                return Err(ControlError::Conflict {
                    message: format!(
                        "identity provider '{}' cannot be deleted: {detail}; turn it off instead, which signs them out",
                        current.slug
                    ),
                })
            }
            Err(e) => return Err(e.into()),
        }
        self.forget_metadata(&current.issuer);
        Ok(())
    }

    /// With password sign-in limited to admins, the last enabled provider
    /// is everyone else's only way in.
    async fn keep_a_way_in(&self, leaving: &OidcProviderId) -> Result<(), ControlError> {
        if self.sso.get_sign_in_settings().await?.password_sign_in != PasswordSignIn::AdminsOnly {
            return Ok(());
        }
        let others = self
            .sso
            .list_oidc_providers()
            .await?
            .iter()
            .any(|p| p.enabled && p.id != *leaving);
        if others {
            Ok(())
        } else {
            Err(ControlError::Conflict {
                message: "this is the only enabled identity provider and password sign-in is limited to admins; allow password sign-in for everyone first, or enable another provider".into(),
            })
        }
    }

    pub async fn get_sign_in_settings(
        &self,
        caller: &Caller,
    ) -> Result<SignInSettings, ControlError> {
        self.guard.check(caller, Action::UserRead, None).await?;
        Ok(self.sso.get_sign_in_settings().await?)
    }

    pub async fn put_sign_in_settings(
        &self,
        caller: &Caller,
        settings: SignInSettings,
    ) -> Result<SignInSettings, ControlError> {
        self.guard
            .check(caller, Action::IdentityProviderManage, None)
            .await?;
        if settings.password_sign_in == PasswordSignIn::AdminsOnly
            && !self
                .sso
                .list_oidc_providers()
                .await?
                .iter()
                .any(|p| p.enabled)
        {
            return Err(validation(
                "enable an identity provider before limiting password sign-in to admins: nobody else could sign in",
            ));
        }
        let event = AuditEvent::new(caller.actor(), "settings.sign_in", AuditOutcome::Success)
            .detail(
                "password_sign_in",
                match settings.password_sign_in {
                    PasswordSignIn::Everyone => "everyone",
                    PasswordSignIn::AdminsOnly => "admins_only",
                },
            );
        self.sso
            .put_sign_in_settings(settings.clone(), &[event])
            .await?;
        Ok(settings)
    }

    /// For the sign-in page, before anyone is signed in.
    pub async fn sign_in_options(&self) -> Result<SignInOptions, ControlError> {
        let providers = self
            .sso
            .list_oidc_providers()
            .await?
            .into_iter()
            .filter(|p| p.enabled)
            .map(|p| SignInProvider {
                brand: ProviderBrand::of_issuer(&p.issuer),
                slug: p.slug,
                name: p.name,
            })
            .collect();
        Ok(SignInOptions {
            providers,
            password_sign_in: self.sso.get_sign_in_settings().await?.password_sign_in,
        })
    }

    /// The provider `user` signs in with, if any.
    pub async fn sign_in_of(&self, user_provider: Option<&OidcProviderId>) -> Option<SsoSignIn> {
        let id = user_provider?;
        match self.sso.get_oidc_provider(id).await {
            Ok(Some(p)) => Some(SsoSignIn {
                brand: ProviderBrand::of_issuer(&p.issuer),
                provider_id: p.id,
                slug: p.slug,
                name: p.name,
            }),
            Ok(None) => None,
            Err(e) => {
                warn!(provider = %id, error = %e, "could not read a user's identity provider");
                None
            }
        }
    }

    // ----- provider metadata ---------------------------------------------

    fn idp_error(provider: &OidcProvider, operation: &'static str, reason: String) -> ControlError {
        ControlError::IdentityProvider {
            provider: provider.slug.clone(),
            operation,
            reason,
        }
    }

    fn forget_metadata(&self, issuer: &str) {
        if let Ok(mut cache) = self.metadata.lock() {
            cache.remove(issuer);
        }
    }

    async fn get_json(
        &self,
        provider: &OidcProvider,
        operation: &'static str,
        url: &Url,
        bearer: Option<&str>,
    ) -> Result<Vec<u8>, ControlError> {
        let reply = self
            .transport
            .get(url, bearer)
            .await
            .map_err(|e| Self::idp_error(provider, operation, format!("GET {url}: {e}")))?;
        if !(200..300).contains(&reply.status) {
            return Err(Self::idp_error(
                provider,
                operation,
                format!("GET {url} answered HTTP {}", reply.status),
            ));
        }
        Ok(reply.body)
    }

    async fn fetch_discovery(&self, provider: &OidcProvider) -> Result<Discovery, ControlError> {
        let url = oidc::discovery_url(&provider.issuer)
            .map_err(|e| Self::idp_error(provider, "discovery", e))?;
        let body = self.get_json(provider, "discovery", &url, None).await?;
        oidc::parse_discovery(&provider.issuer, &body)
            .map_err(|e| Self::idp_error(provider, "discovery", e))
    }

    async fn fetch_keys(
        &self,
        provider: &OidcProvider,
        discovery: &Discovery,
    ) -> Result<JwkSet, ControlError> {
        let url = oidc::check_url("jwks_uri", &discovery.jwks_uri)
            .map_err(|e| Self::idp_error(provider, "keys", e))?;
        let body = self.get_json(provider, "keys", &url, None).await?;
        serde_json::from_slice(&body).map_err(|e| {
            Self::idp_error(provider, "keys", format!("the key set is not valid: {e}"))
        })
    }

    /// The provider's metadata, fetched again once stale or, with
    /// `refresh_keys`, its keys when they were fetched long enough ago.
    async fn metadata(
        &self,
        provider: &OidcProvider,
        refresh_keys: bool,
    ) -> Result<Arc<Metadata>, ControlError> {
        let cached = self
            .metadata
            .lock()
            .ok()
            .and_then(|c| c.get(&provider.issuer).cloned());
        let fresh = match cached {
            Some(m) if m.fetched.elapsed() < METADATA_TTL => {
                if refresh_keys && m.keys_fetched.elapsed() >= KEY_REFRESH_MIN {
                    let keys = self.fetch_keys(provider, &m.discovery).await?;
                    Arc::new(Metadata {
                        discovery: m.discovery.clone(),
                        keys,
                        fetched: m.fetched,
                        keys_fetched: Instant::now(),
                    })
                } else {
                    return Ok(m);
                }
            }
            _ => {
                let discovery = self.fetch_discovery(provider).await?;
                let keys = self.fetch_keys(provider, &discovery).await?;
                Arc::new(Metadata {
                    discovery,
                    keys,
                    fetched: Instant::now(),
                    keys_fetched: Instant::now(),
                })
            }
        };
        if let Ok(mut cache) = self.metadata.lock() {
            // One entry per issuer, and issuers are at most the providers.
            if cache.len() > 4 * MAX_OIDC_PROVIDERS {
                cache.clear();
            }
            cache.insert(provider.issuer.clone(), fresh.clone());
        }
        Ok(fresh)
    }

    // ----- signing in ----------------------------------------------------

    /// Starts a sign-in (or, with `session`, a step-up) at the provider
    /// with this slug.
    pub async fn begin(
        &self,
        slug: &str,
        purpose: OidcPurpose,
        return_to: Option<&str>,
        session: Option<&SessionAuth>,
    ) -> Result<SsoRedirect, ControlError> {
        let return_to = check_return_to(return_to)?;
        let provider = self
            .sso
            .get_oidc_provider_by_slug(slug)
            .await?
            .filter(|p| p.enabled)
            .ok_or_else(|| ControlError::not_found("identity provider", slug))?;
        let (ui_session_hash, user_id) = match purpose {
            OidcPurpose::Login => (None, None),
            OidcPurpose::StepUp => {
                let session = session.ok_or_else(|| ControlError::Unauthenticated {
                    reason: "sign in before stepping up".into(),
                })?;
                if session.user.sso_provider_id != Some(provider.id) {
                    return Err(ControlError::Forbidden {
                        reason: format!(
                            "'{}' does not sign in with '{}', so it cannot step up there",
                            session.user.username, provider.slug
                        ),
                    });
                }
                (Some(session.token_hash.clone()), Some(session.user.id))
            }
        };
        let meta = self.metadata(&provider, false).await?;
        let mut url = oidc::check_url(
            "authorization_endpoint",
            &meta.discovery.authorization_endpoint,
        )
        .map_err(|e| Self::idp_error(&provider, "sign-in", e))?;
        let state = token::random_value();
        let nonce = token::random_value();
        let verifier = token::random_value();
        let scope = std::iter::once("openid")
            .chain(provider.scopes.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" ");
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("response_type", "code")
                .append_pair("client_id", &provider.client_id)
                .append_pair("redirect_uri", &provider.redirect_uri)
                .append_pair("scope", &scope)
                .append_pair("state", &state)
                .append_pair("nonce", &nonce)
                .append_pair("code_challenge", &oidc::pkce_challenge(&verifier))
                .append_pair("code_challenge_method", "S256");
            if purpose == OidcPurpose::StepUp {
                // A fresh sign-in at the provider, not its existing session.
                q.append_pair("prompt", "login").append_pair("max_age", "0");
            }
        }
        let now = Utc::now();
        let request = OidcRequest {
            state_hash: token::hash_token(&state),
            provider_id: provider.id,
            purpose,
            nonce,
            pkce_verifier: verifier,
            ui_session_hash,
            user_id,
            return_to,
            created_at: now,
            expires_at: now + Duration::seconds(REQUEST_TTL_SECS as i64),
        };
        let sealed = serde_json::to_vec(&request).map_err(|e| ControlError::Crypto {
            operation: "seal single sign-on flow cookie".into(),
            reason: e.to_string(),
        })?;
        let browser_token = self.flow_key.seal(FLOW_CONTEXT, &sealed);
        Ok(SsoRedirect {
            authorization_url: url.into(),
            browser_token,
            max_age_secs: REQUEST_TTL_SECS,
        })
    }

    /// Finishes a sign-in with the provider's answer and the flow cookie
    /// of the browser it came back to.
    pub async fn complete(
        &self,
        callback: SsoCallback,
        browser_token: Option<&str>,
    ) -> Result<SsoCompleted, SsoFailed> {
        let unknown = |error: ControlError| SsoFailed {
            purpose: OidcPurpose::Login,
            return_to: "/".into(),
            error,
        };
        let state = callback
            .state
            .as_deref()
            .filter(|s| !s.is_empty() && s.len() <= 256)
            .ok_or_else(|| unknown(validation("the provider's answer has no state")))?;
        let request = browser_token
            .and_then(|t| self.flow_key.open(FLOW_CONTEXT, t))
            .and_then(|plain| serde_json::from_slice::<OidcRequest>(&plain).ok())
            .ok_or_else(|| {
                unknown(ControlError::Unauthenticated {
                    reason: "this browser has no sign-in in progress: it was started in another browser, has expired or was already used; start again here".into(),
                })
            })?;
        let fail = |error: ControlError| SsoFailed {
            purpose: request.purpose,
            return_to: request.return_to.clone(),
            error,
        };
        if request.expires_at <= Utc::now() {
            return Err(fail(ControlError::Unauthenticated {
                reason: "this sign-in took too long and has expired; start again".into(),
            }));
        }
        if !token::hashes_equal(&token::hash_token(state), &request.state_hash) {
            return Err(fail(ControlError::Unauthenticated {
                reason: "the provider's answer is for another sign-in than the one this browser started; start again".into(),
            }));
        }
        let provider = match self.sso.get_oidc_provider(&request.provider_id).await {
            Ok(Some(p)) if p.enabled => p,
            Ok(_) => {
                return Err(fail(ControlError::not_found(
                    "identity provider",
                    request.provider_id,
                )))
            }
            Err(e) => return Err(fail(e.into())),
        };
        match self.finish(&provider, &request, &callback).await {
            Ok(done) => Ok(done),
            Err(error) => {
                let action = match request.purpose {
                    OidcPurpose::Login => "auth.login",
                    OidcPurpose::StepUp => "auth.step_up",
                };
                let actor = request
                    .user_id
                    .map_or_else(|| "anonymous".to_string(), |u| format!("user:{u}"));
                warn!(provider = %provider.slug, error = %error, "single sign-on failed");
                self.audit
                    .record(
                        AuditEvent::new(actor, action, AuditOutcome::Denied)
                            .target(format!("oidc_provider:{}", provider.id))
                            .detail("method", "sso")
                            .detail("provider", provider.slug.clone())
                            .detail("reason", error.to_string()),
                    )
                    .await;
                Err(fail(error))
            }
        }
    }

    async fn finish(
        &self,
        provider: &OidcProvider,
        request: &OidcRequest,
        callback: &SsoCallback,
    ) -> Result<SsoCompleted, ControlError> {
        if let Some(error) = &callback.error {
            return Err(Self::idp_error(
                provider,
                "sign-in",
                format!(
                    "the provider refused: {}",
                    oidc::provider_error(error, callback.error_description.as_deref())
                ),
            ));
        }
        let code = callback
            .code
            .as_deref()
            .filter(|c| !c.is_empty() && c.len() <= 4096)
            .ok_or_else(|| validation("the provider's answer has no code"))?;
        let meta = self.metadata(provider, false).await?;
        let tokens = self
            .exchange(provider, &meta.discovery, request, code)
            .await?;
        let id_token = tokens
            .get("id_token")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                Self::idp_error(
                    provider,
                    "token",
                    "the token response has no id_token".into(),
                )
            })?;
        let claims = self.verify(provider, meta, id_token).await?;
        let now = Utc::now();
        let id = oidc::check_id_token(
            &claims,
            &Expected {
                issuer: &provider.issuer,
                client_id: &provider.client_id,
                nonce: &request.nonce,
                now,
            },
        )
        .map_err(|e| Self::idp_error(provider, "ID token", e))?;
        let signed_in_at = id.auth_time.map(|t| t.min(now));
        match request.purpose {
            OidcPurpose::StepUp => self.step_up(provider, request, &id, signed_in_at).await,
            OidcPurpose::Login => {
                let access_token = tokens.get("access_token").and_then(Value::as_str);
                let claims = self
                    .with_userinfo(provider, claims, access_token, &id.subject)
                    .await?;
                self.sign_in(provider, request, &id.subject, &claims, signed_in_at)
                    .await
            }
        }
    }

    /// The authorization code exchange (OpenID Connect Core §3.1.3).
    async fn exchange(
        &self,
        provider: &OidcProvider,
        discovery: &Discovery,
        request: &OidcRequest,
        code: &str,
    ) -> Result<Map<String, Value>, ControlError> {
        let url = oidc::check_url("token_endpoint", &discovery.token_endpoint)
            .map_err(|e| Self::idp_error(provider, "token", e))?;
        let secret = match &provider.client_secret_enc {
            Some(enc) => {
                let plain = self
                    .cipher
                    .decrypt(enc, &client_secret_aad(&provider.id))
                    .await?;
                Some(String::from_utf8(plain.to_vec()).map_err(|_| {
                    ControlError::crypto(
                        "oidc.client_secret",
                        format!("provider {}: stored secret is not UTF-8", provider.id),
                    )
                })?)
            }
            None => None,
        };
        let secret = secret.map(zeroize::Zeroizing::new);
        let mut form: Vec<(&str, &str)> = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &provider.redirect_uri),
            ("code_verifier", &request.pkce_verifier),
            ("client_id", &provider.client_id),
        ];
        // RFC 6749 §2.3.1: Basic takes the form-encoded id and secret.
        let encoded: Option<(String, zeroize::Zeroizing<String>)> = match &secret {
            Some(s) if !discovery.secret_in_form() => Some((
                form_encode(&provider.client_id),
                zeroize::Zeroizing::new(form_encode(s)),
            )),
            _ => None,
        };
        if let (Some(s), None) = (&secret, &encoded) {
            form.push(("client_secret", s.as_str()));
        }
        let basic = encoded.as_ref().map(|(id, s)| (id.as_str(), s.as_str()));
        let reply = self
            .transport
            .post_form(&url, &form, basic)
            .await
            .map_err(|e| Self::idp_error(provider, "token", format!("POST {url}: {e}")))?;
        let body: Map<String, Value> = match serde_json::from_slice(&reply.body) {
            Ok(Value::Object(m)) => m,
            _ => Map::new(),
        };
        if !(200..300).contains(&reply.status) {
            let error = body
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("no error code");
            return Err(Self::idp_error(
                provider,
                "token",
                format!(
                    "the token endpoint answered HTTP {}: {}",
                    reply.status,
                    oidc::provider_error(
                        error,
                        body.get("error_description").and_then(Value::as_str)
                    )
                ),
            ));
        }
        if body.is_empty() {
            return Err(Self::idp_error(
                provider,
                "token",
                "the token response is not a JSON object".into(),
            ));
        }
        Ok(body)
    }

    async fn verify(
        &self,
        provider: &OidcProvider,
        meta: Arc<Metadata>,
        id_token: &str,
    ) -> Result<Map<String, Value>, ControlError> {
        let algorithms = meta.discovery.algorithms();
        match jwt::verify(id_token, &meta.keys, &algorithms) {
            Ok(v) => Ok(v.claims),
            // The provider may have rotated its keys since they were fetched.
            Err(JwtError::NoKey { .. }) => {
                let meta = self.metadata(provider, true).await?;
                jwt::verify(id_token, &meta.keys, &algorithms)
                    .map(|v| v.claims)
                    .map_err(|e| Self::idp_error(provider, "ID token", e.to_string()))
            }
            Err(e) => Err(Self::idp_error(provider, "ID token", e.to_string())),
        }
    }

    /// Adds what the userinfo endpoint says when the ID token lacks the
    /// groups or username claim.
    async fn with_userinfo(
        &self,
        provider: &OidcProvider,
        mut claims: Map<String, Value>,
        access_token: Option<&str>,
        subject: &str,
    ) -> Result<Map<String, Value>, ControlError> {
        let missing = oidc::claim(&claims, &provider.groups_claim).is_none()
            || oidc::claim(&claims, &provider.username_claim).is_none();
        let meta = self.metadata(provider, false).await?;
        let (Some(endpoint), Some(access_token), true) =
            (&meta.discovery.userinfo_endpoint, access_token, missing)
        else {
            return Ok(claims);
        };
        let url = oidc::check_url("userinfo_endpoint", endpoint)
            .map_err(|e| Self::idp_error(provider, "userinfo", e))?;
        let body = self
            .get_json(provider, "userinfo", &url, Some(access_token))
            .await?;
        let Ok(Value::Object(info)) = serde_json::from_slice::<Value>(&body) else {
            return Err(Self::idp_error(
                provider,
                "userinfo",
                "the userinfo response is not a JSON object".into(),
            ));
        };
        // OpenID Connect Core §5.3.2: it must be about the same person.
        if info.get("sub").and_then(Value::as_str) != Some(subject) {
            return Err(Self::idp_error(
                provider,
                "userinfo",
                "the userinfo response is about another subject".into(),
            ));
        }
        for (name, value) in info {
            claims.entry(name).or_insert(value);
        }
        Ok(claims)
    }

    fn refuse(&self, provider: &OidcProvider, reason: String) -> ControlError {
        ControlError::SsoRefused {
            provider: provider.slug.clone(),
            reason,
        }
    }

    async fn sign_in(
        &self,
        provider: &OidcProvider,
        request: &OidcRequest,
        subject: &str,
        claims: &Map<String, Value>,
        signed_in_at: Option<DateTime<Utc>>,
    ) -> Result<SsoCompleted, ControlError> {
        let groups = oidc::groups(oidc::claim(claims, &provider.groups_claim));
        let Some(role) = oidc::mapped_role(&provider.role_mappings, &groups) else {
            let seen = if groups.is_empty() {
                format!(
                    "none (the '{}' claim is missing or empty)",
                    provider.groups_claim
                )
            } else {
                let mut shown: Vec<&str> = groups.iter().take(20).map(String::as_str).collect();
                if groups.len() > 20 {
                    shown.push("…");
                }
                shown.join(", ")
            };
            return Err(self
                .refuse(
                    provider,
                    format!(
                        "none of your groups at {} is mapped to a role here; groups seen: {seen}. An admin maps groups to roles in the provider's settings",
                        provider.name
                    ),
                ));
        };
        let user = match self.sso.get_user_by_sso(&provider.id, subject).await? {
            Some(user) => self.sync_role(provider, user, role).await?,
            None => self.create_user(provider, subject, claims, role).await?,
        };
        let event = AuditEvent::new(
            format!("user:{}", user.id),
            "auth.login",
            AuditOutcome::Success,
        )
        .target(format!("oidc_provider:{}", provider.id))
        .detail("username", user.username.clone())
        .detail("method", "sso")
        .detail("provider", provider.slug.clone())
        .detail("role", role.as_str());
        let login = open_ui_session(
            self.identity.as_ref(),
            &self.keys,
            &self.config,
            &user,
            signed_in_at,
            event,
        )
        .await?;
        info!(user_id = %user.id, provider = %provider.slug, role = %role, "signed in with single sign-on");
        Ok(SsoCompleted::SignedIn {
            login,
            return_to: request.return_to.clone(),
        })
    }

    async fn sync_role(
        &self,
        provider: &OidcProvider,
        mut user: User,
        role: Role,
    ) -> Result<User, ControlError> {
        if user.disabled_at.is_some() {
            return Err(self.refuse(
                provider,
                format!("the account '{}' has been disabled here", user.username),
            ));
        }
        if user.role == role {
            return Ok(user);
        }
        let event = AuditEvent::new("system", "user.update", AuditOutcome::Success)
            .target(format!("user:{}", user.id))
            .detail("username", user.username.clone())
            .detail("previous_role", user.role.as_str())
            .detail("role", role.as_str())
            .detail("reason", format!("groups at {}", provider.slug));
        // Role only, and only while enabled: an admin disabling the account
        // during this sign-in is never undone by it.
        match self.sso.set_sso_role(&user.id, role, &[event]).await {
            Ok(true) => {}
            Ok(false) => {
                return Err(self.refuse(
                    provider,
                    format!("the account '{}' has been disabled here", user.username),
                ))
            }
            Err(StoreError::Conflict { .. }) => {
                return Err(self
                    .refuse(
                        provider,
                        format!(
                            "your groups now give '{}' the {role} role, but it is the last enabled admin here; another admin must exist first",
                            user.username
                        ),
                    ))
            }
            Err(e) => return Err(e.into()),
        }
        user.role = role;
        Ok(user)
    }

    async fn create_user(
        &self,
        provider: &OidcProvider,
        subject: &str,
        claims: &Map<String, Value>,
        role: Role,
    ) -> Result<User, ControlError> {
        let username = oidc::username(oidc::claim(claims, &provider.username_claim)).ok_or_else(
            || ControlError::SsoRefused {
                provider: provider.slug.clone(),
                reason: format!(
                    "the provider sent no usable '{}' claim to name the account: 3-128 characters of a-z, 0-9, _ - . @ +",
                    provider.username_claim
                ),
            },
        )?;
        if self
            .identity
            .get_user_by_username(&username)
            .await?
            .is_some()
        {
            return Err(self
                .refuse(
                    provider,
                    format!(
                        "the username '{username}' belongs to another account here, so it is not given to a {} account; an admin can rename or remove that account",
                        provider.name
                    ),
                ));
        }
        let user = User {
            id: UserId::new(),
            username: username.clone(),
            // Never a valid hash: this account has no password.
            password_hash: String::new(),
            totp_secret_enc: None,
            totp_last_step: None,
            role,
            created_at: Utc::now(),
            disabled_at: None,
            sso: Some(SsoIdentity {
                provider_id: provider.id,
                subject: subject.to_string(),
            }),
        };
        let event = AuditEvent::new("system", "user.create", AuditOutcome::Success)
            .target(format!("user:{}", user.id))
            .detail("username", username.clone())
            .detail("role", role.as_str())
            .detail("method", "sso")
            .detail("provider", provider.slug.clone());
        match self.identity.insert_user(user.clone(), &[event]).await {
            Ok(()) => {
                info!(user_id = %user.id, username = %username, provider = %provider.slug, "account created at first single sign-on");
                Ok(user)
            }
            // The same person signing in twice at once: use the account
            // the other sign-in created.
            Err(StoreError::Conflict { .. }) => {
                match self.sso.get_user_by_sso(&provider.id, subject).await? {
                    Some(existing) => self.sync_role(provider, existing, role).await,
                    None => Err(self.refuse(
                        provider,
                        format!("the username '{username}' was just taken by another account"),
                    )),
                }
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn step_up(
        &self,
        provider: &OidcProvider,
        request: &OidcRequest,
        id: &oidc::IdToken,
        signed_in_at: Option<DateTime<Utc>>,
    ) -> Result<SsoCompleted, ControlError> {
        let (Some(session_hash), Some(user_id)) = (&request.ui_session_hash, request.user_id)
        else {
            return Err(validation("this step-up has no session to refresh"));
        };
        let user = self
            .sso
            .get_user_by_sso(&provider.id, &id.subject)
            .await?
            .filter(|u| u.id == user_id)
            .ok_or_else(|| ControlError::Forbidden {
                reason: format!(
                    "the step-up at {} signed in as a different person than this session's",
                    provider.name
                ),
            })?;
        if user.disabled_at.is_some() {
            return Err(self.refuse(
                provider,
                format!("the account '{}' has been disabled here", user.username),
            ));
        }
        // A step-up proves a sign-in made for it, not an earlier one the
        // provider remembered.
        let skew = Duration::seconds(oidc::CLOCK_SKEW_SECS);
        let at = signed_in_at
            .filter(|at| *at + skew >= request.created_at)
            .ok_or_else(|| {
                Self::idp_error(
                    provider,
                    "step-up",
                    "the provider did not sign the person in again (its ID token has no recent auth_time); it must honour max_age=0".into(),
                )
            })?;
        let event = AuditEvent::new(
            format!("user:{}", user.id),
            "auth.step_up",
            AuditOutcome::Success,
        )
        .detail("method", "sso")
        .detail("provider", provider.slug.clone());
        match self
            .identity
            .set_ui_session_step_up(session_hash, at, &[event])
            .await
        {
            Ok(()) => {}
            Err(StoreError::NotFound { .. }) => {
                return Err(ControlError::Unauthenticated {
                    reason: "the session this step-up was for has ended; sign in again".into(),
                })
            }
            Err(e) => return Err(e.into()),
        }
        Ok(SsoCompleted::SteppedUp {
            at,
            return_to: request.return_to.clone(),
        })
    }
}

/// `application/x-www-form-urlencoded` for one value.
fn form_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}
