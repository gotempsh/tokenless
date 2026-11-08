// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! People and API keys: the generated first admin, password + TOTP login,
//! UI sessions, step-up MFA, password and authenticator changes, and API
//! key issuance.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration as StdDuration, Instant};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tokenless_auth::{cookie, csrf, password, token, totp};
use tokenless_core::audit::{AuditEvent, AuditOutcome};
use tokenless_core::authz::{Action, Principal, PrincipalKind, Role};
use tokenless_core::ids::{ApiKeyId, OidcProviderId, UserId, VaultId};
use tracing::{info, warn};
use zeroize::Zeroizing;

use super::{AuditRecorder, Caller, ControlConfig, Guard};
use crate::cipher::{KeyScope, SecretCipher};
use crate::error::ControlError;
use crate::keys::KeyRing;
use crate::model::{ApiKey, Page, PageRequest, PasswordSignIn, UiSession, User};
use crate::store::{IdentityStore, SsoStore};

const MAX_FAILED_LOGINS: u32 = 5;
const LOGIN_WINDOW: StdDuration = StdDuration::from_secs(300);
const LIMITER_CAPACITY: usize = 10_000;
const MAX_API_KEY_DAYS: u32 = 365;

/// A person as the API shows them: never the password hash or TOTP secret.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserSummary {
    pub id: UserId,
    pub username: String,
    pub role: Role,
    pub created_at: DateTime<Utc>,
    pub disabled_at: Option<DateTime<Utc>>,
    /// Whether the person signs in with an authenticator code as well.
    pub totp_enrolled: bool,
    /// The provider a single sign-on account signs in with; `None` for a
    /// password account.
    pub sso_provider_id: Option<OidcProviderId>,
}

impl From<&User> for UserSummary {
    fn from(u: &User) -> Self {
        Self {
            id: u.id,
            username: u.username.clone(),
            role: u.role,
            created_at: u.created_at,
            disabled_at: u.disabled_at,
            totp_enrolled: u.totp_secret_enc.is_some(),
            sso_provider_id: u.sso.as_ref().map(|s| s.provider_id),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TotpEnrollment {
    pub secret: String,
    pub otpauth_url: String,
}

// The otpauth URL carries the secret too.
tokenless_core::redacted_debug!(TotpEnrollment { ; secret, otpauth_url });

/// The username of the admin created on first start.
pub const INITIAL_ADMIN: &str = "admin";

/// Credentials the server generated, to be shown to the operator once.
pub struct GeneratedCredentials {
    pub username: String,
    pub password: Zeroizing<String>,
}

impl std::fmt::Debug for GeneratedCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeneratedCredentials")
            .field("username", &self.username)
            .field("password", &"***")
            .finish()
    }
}

#[derive(Clone, Deserialize)]
pub struct ChangePassword {
    pub current_password: String,
    pub new_password: String,
}

tokenless_core::redacted_debug!(ChangePassword { ; current_password, new_password });

/// Turns on an authenticator: the secret from `new_totp_enrollment`, the
/// first code it shows, and the password to prove it is the account owner.
#[derive(Clone, Deserialize)]
pub struct EnableAuthenticator {
    pub secret: String,
    pub code: String,
    pub password: String,
}

tokenless_core::redacted_debug!(EnableAuthenticator { ; secret, code, password });

#[derive(Clone, Deserialize)]
pub struct DisableAuthenticator {
    pub code: String,
    pub password: String,
}

tokenless_core::redacted_debug!(DisableAuthenticator { ; code, password });

#[derive(Clone, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    /// Required only for accounts with an authenticator enrolled.
    #[serde(default)]
    pub totp_code: Option<String>,
}

tokenless_core::redacted_debug!(LoginRequest { username; password, totp_code });

/// Proof for a step-up: the authenticator code, or the password for an
/// account without an authenticator.
#[derive(Clone, Default, Deserialize)]
pub struct StepUpProof {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

tokenless_core::redacted_debug!(StepUpProof { ; code, password });

pub struct LoginOutcome {
    pub token: String,
    pub csrf_token: String,
    pub user: UserSummary,
    pub expires_at: DateTime<Utc>,
    pub max_age_secs: u64,
}

tokenless_core::redacted_debug!(LoginOutcome { user, expires_at, max_age_secs; token, csrf_token });

/// A verified UI session.
#[derive(Clone)]
pub struct SessionAuth {
    pub caller: Caller,
    pub token_hash: String,
    pub user: UserSummary,
    pub expires_at: DateTime<Utc>,
}

tokenless_core::redacted_debug!(SessionAuth { caller, user, expires_at; token_hash });

#[derive(Debug, Clone, Deserialize)]
pub struct CreateApiKey {
    pub name: String,
    pub vault_id: VaultId,
    pub role: Role,
    pub expires_in_days: u32,
}

pub(super) fn validate_username(username: &str) -> Result<(), ControlError> {
    let ok = (3..=64).contains(&username.len())
        && username
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-' | '.'));
    if ok {
        Ok(())
    } else {
        Err(ControlError::validation(
            "username must be 3-64 characters of a-z, 0-9, '_', '-' or '.'",
        ))
    }
}

fn non_empty(value: &Option<String>) -> Option<&str> {
    value.as_deref().map(str::trim).filter(|v| !v.is_empty())
}

/// An authenticator a new account enrols with, already verified.
pub(super) struct VerifiedTotp<'a> {
    secret: &'a str,
    step: u64,
}

/// Checks a new account's username and password and, when given, its
/// TOTP secret and first code. Both TOTP fields or neither.
pub(super) fn check_new_account<'a>(
    username: &str,
    password_plain: &str,
    totp_secret: &'a Option<String>,
    totp_code: &Option<String>,
) -> Result<Option<VerifiedTotp<'a>>, ControlError> {
    validate_username(username)?;
    password::check_password_policy(password_plain)?;
    match (non_empty(totp_secret), non_empty(totp_code)) {
        (None, None) => Ok(None),
        (Some(secret), Some(code)) => {
            let step =
                totp::verify_code(secret, username, code, unix_now(), None)?.ok_or_else(|| {
                    ControlError::validation(
                        "the TOTP code does not match the secret; check the authenticator clock",
                    )
                })?;
            Ok(Some(VerifiedTotp { secret, step }))
        }
        (Some(_), None) => Err(ControlError::validation(
            "enter the 6-digit code from the authenticator to finish enrolling it",
        )),
        (None, Some(_)) => Err(ControlError::validation(
            "a TOTP code was sent without the secret it belongs to",
        )),
    }
}

pub(super) async fn build_user(
    cipher: &dyn SecretCipher,
    username: &str,
    password_plain: &str,
    totp: Option<VerifiedTotp<'_>>,
    role: Role,
) -> Result<User, ControlError> {
    let id = UserId::new();
    let (totp_secret_enc, totp_last_step) = match totp {
        Some(t) => (
            Some(
                cipher
                    .encrypt(KeyScope::Instance, t.secret.as_bytes(), &totp_aad(&id))
                    .await?,
            ),
            Some(t.step),
        ),
        None => (None, None),
    };
    Ok(User {
        id,
        username: username.to_string(),
        password_hash: password::hash_password(password_plain)?,
        totp_secret_enc,
        totp_last_step,
        role,
        created_at: Utc::now(),
        disabled_at: None,
        sso: None,
    })
}

/// Refuses `what` for a single sign-on account, whose password and second
/// factor live at its provider.
fn local_account(user: &User, what: &str) -> Result<(), ControlError> {
    match &user.sso {
        None => Ok(()),
        Some(sso) => Err(ControlError::validation(format!(
            "cannot {what} for '{}': it signs in with single sign-on (provider {}), which manages its password and second factor",
            user.username, sso.provider_id
        ))),
    }
}

/// Starts a UI session for `user`, recording `event` with it.
pub(super) async fn open_ui_session(
    identity: &dyn IdentityStore,
    keys: &KeyRing,
    config: &ControlConfig,
    user: &User,
    step_up_at: Option<DateTime<Utc>>,
    event: AuditEvent,
) -> Result<LoginOutcome, ControlError> {
    let now = Utc::now();
    let max_age = config.ui_session_ttl_secs;
    let expires_at = now + Duration::seconds(i64::try_from(max_age).unwrap_or(43_200));
    let plaintext = token::new_token(token::SESSION_PREFIX);
    let token_hash = token::hash_token(&plaintext);
    identity
        .insert_ui_session(
            UiSession {
                token_hash: token_hash.clone(),
                user_id: user.id,
                created_at: now,
                expires_at,
                step_up_at,
            },
            &[event],
        )
        .await?;
    Ok(LoginOutcome {
        token: plaintext,
        csrf_token: csrf::derive(&keys.csrf_key, &token_hash),
        user: UserSummary::from(user),
        expires_at,
        max_age_secs: max_age,
    })
}

fn unix_now() -> u64 {
    u64::try_from(Utc::now().timestamp()).unwrap_or(0)
}

/// Per-username failed login counter. Control plane only; bounded size.
struct LoginLimiter {
    failures: Mutex<HashMap<String, (u32, Instant)>>,
}

impl LoginLimiter {
    fn new() -> Self {
        Self {
            failures: Mutex::new(HashMap::new()),
        }
    }

    fn check(&self, username: &str) -> Result<(), ControlError> {
        let Ok(map) = self.failures.lock() else {
            return Ok(());
        };
        if let Some((count, since)) = map.get(username) {
            let elapsed = since.elapsed();
            if *count >= MAX_FAILED_LOGINS && elapsed < LOGIN_WINDOW {
                return Err(ControlError::RateLimited {
                    subject: format!("login for '{username}'"),
                    retry_after_secs: (LOGIN_WINDOW - elapsed).as_secs().max(1),
                });
            }
        }
        Ok(())
    }

    fn fail(&self, username: &str) {
        let Ok(mut map) = self.failures.lock() else {
            return;
        };
        if map.len() >= LIMITER_CAPACITY {
            map.retain(|_, (_, since)| since.elapsed() < LOGIN_WINDOW);
            if map.len() >= LIMITER_CAPACITY {
                map.clear();
            }
        }
        let entry = map
            .entry(username.to_string())
            .or_insert((0, Instant::now()));
        if entry.1.elapsed() >= LOGIN_WINDOW {
            *entry = (0, Instant::now());
        }
        entry.0 += 1;
    }

    fn reset(&self, username: &str) {
        if let Ok(mut map) = self.failures.lock() {
            map.remove(username);
        }
    }
}

pub struct AuthService {
    identity: Arc<dyn IdentityStore>,
    sso: Arc<dyn SsoStore>,
    cipher: Arc<dyn SecretCipher>,
    keys: Arc<KeyRing>,
    guard: Guard,
    audit: AuditRecorder,
    config: ControlConfig,
    limiter: LoginLimiter,
    dummy_hash: String,
}

pub(crate) fn totp_aad(user_id: &UserId) -> Vec<u8> {
    format!("user-totp|{user_id}").into_bytes()
}

impl AuthService {
    pub fn new(
        identity: Arc<dyn IdentityStore>,
        sso: Arc<dyn SsoStore>,
        cipher: Arc<dyn SecretCipher>,
        keys: Arc<KeyRing>,
        guard: Guard,
        audit: AuditRecorder,
        config: ControlConfig,
    ) -> Result<Self, ControlError> {
        Ok(Self {
            identity,
            sso,
            cipher,
            keys,
            guard,
            audit,
            config,
            limiter: LoginLimiter::new(),
            dummy_hash: password::dummy_hash()?,
        })
    }

    pub fn new_totp_enrollment(&self, username: &str) -> Result<TotpEnrollment, ControlError> {
        validate_username(username)?;
        let secret = totp::generate_secret();
        let otpauth_url = totp::otpauth_url(&secret, username)?;
        Ok(TotpEnrollment {
            secret,
            otpauth_url,
        })
    }

    /// On first start, while no account exists, creates the admin with a
    /// generated password and returns it so the operator can save it. It is
    /// returned this once; only its hash is stored. `None` once anyone has
    /// an account.
    pub async fn create_initial_admin(&self) -> Result<Option<GeneratedCredentials>, ControlError> {
        if self.identity.count_users().await? > 0 {
            return Ok(None);
        }
        let password = password::generate_password();
        let user = build_user(
            self.cipher.as_ref(),
            INITIAL_ADMIN,
            &password,
            None,
            Role::Admin,
        )
        .await?;
        let id = user.id;
        let event = AuditEvent::new("system", "auth.setup", AuditOutcome::Success)
            .target(format!("user:{id}"))
            .detail("username", INITIAL_ADMIN);
        match self.identity.insert_user(user, &[event]).await {
            Ok(()) => {}
            // Another server sharing the database created it first.
            Err(crate::error::StoreError::Conflict { .. }) => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        info!(user_id = %id, username = INITIAL_ADMIN, "first admin created with a generated password");
        Ok(Some(GeneratedCredentials {
            username: INITIAL_ADMIN.to_string(),
            password,
        }))
    }

    /// Replaces a person's password with a generated one and signs them
    /// out everywhere. For the operator of the server, who has its data
    /// directory; not exposed over the API.
    pub async fn reset_password(
        &self,
        username: &str,
    ) -> Result<GeneratedCredentials, ControlError> {
        let username = username.trim().to_ascii_lowercase();
        let user = self
            .identity
            .get_user_by_username(&username)
            .await?
            .ok_or_else(|| ControlError::not_found("user", &username))?;
        local_account(&user, "reset the password")?;
        let password = password::generate_password();
        let hash = password::hash_password(&password)?;
        let event = AuditEvent::new("system", "user.password_reset", AuditOutcome::Success)
            .target(format!("user:{}", user.id))
            .detail("username", username.clone());
        self.identity
            .set_user_password(&user.id, &hash, None, &[event])
            .await?;
        warn!(user_id = %user.id, username = %username, "password reset by the server operator; all of the user's sessions ended");
        Ok(GeneratedCredentials { username, password })
    }

    async fn session_user(&self, auth: &SessionAuth) -> Result<User, ControlError> {
        self.identity
            .get_user(&auth.user.id)
            .await?
            .ok_or_else(|| ControlError::not_found("user", auth.user.id))
    }

    /// Checks the account's own password before a change to its sign-in,
    /// counting a wrong one like a failed login.
    async fn confirm_password(
        &self,
        auth: &SessionAuth,
        user: &User,
        presented: &str,
        action: &'static str,
    ) -> Result<(), ControlError> {
        self.limiter.check(&user.username)?;
        if password::verify_password(&user.password_hash, presented)? {
            return Ok(());
        }
        self.limiter.fail(&user.username);
        self.audit
            .record(AuditEvent::new(
                auth.caller.actor(),
                action,
                AuditOutcome::Denied,
            ))
            .await;
        Err(ControlError::Unauthenticated {
            reason: "the current password is incorrect".into(),
        })
    }

    /// Changes the signed-in person's password. This session stays signed
    /// in; every other session of the account ends.
    pub async fn change_password(
        &self,
        auth: &SessionAuth,
        req: &ChangePassword,
    ) -> Result<(), ControlError> {
        let user = self.session_user(auth).await?;
        local_account(&user, "change the password")?;
        self.confirm_password(auth, &user, &req.current_password, "user.password_change")
            .await?;
        password::check_password_policy(&req.new_password)?;
        if req.new_password == req.current_password {
            return Err(ControlError::validation(
                "the new password must differ from the current one",
            ));
        }
        let hash = password::hash_password(&req.new_password)?;
        let event = AuditEvent::new(
            auth.caller.actor(),
            "user.password_change",
            AuditOutcome::Success,
        )
        .target(format!("user:{}", user.id));
        self.identity
            .set_user_password(&user.id, &hash, Some(&auth.token_hash), &[event])
            .await?;
        info!(user_id = %user.id, "password changed; other sessions ended");
        Ok(())
    }

    /// Turns on an authenticator for the signed-in person. From then on,
    /// signing in asks for its code.
    pub async fn enable_authenticator(
        &self,
        auth: &SessionAuth,
        req: &EnableAuthenticator,
    ) -> Result<UserSummary, ControlError> {
        let user = self.session_user(auth).await?;
        local_account(&user, "add an authenticator")?;
        if user.totp_secret_enc.is_some() {
            return Err(ControlError::Conflict {
                message: format!(
                    "user '{}' already has an authenticator; remove it before adding another",
                    user.username
                ),
            });
        }
        self.confirm_password(auth, &user, &req.password, "auth.totp_enable")
            .await?;
        let secret = req.secret.trim();
        let step = totp::verify_code(secret, &user.username, req.code.trim(), unix_now(), None)?
            .ok_or_else(|| {
                ControlError::validation(
                    "the code does not match this authenticator; check the device's clock and use the code it shows now",
                )
            })?;
        let secret_enc = self
            .cipher
            .encrypt(KeyScope::Instance, secret.as_bytes(), &totp_aad(&user.id))
            .await?;
        let event = AuditEvent::new(
            auth.caller.actor(),
            "auth.totp_enable",
            AuditOutcome::Success,
        )
        .target(format!("user:{}", user.id));
        self.identity
            .set_user_totp(&user.id, Some(secret_enc), Some(step), &[event])
            .await?;
        info!(user_id = %user.id, "authenticator turned on");
        let mut summary = UserSummary::from(&user);
        summary.totp_enrolled = true;
        Ok(summary)
    }

    /// Turns the signed-in person's authenticator off; it takes the
    /// password and a current code.
    pub async fn disable_authenticator(
        &self,
        auth: &SessionAuth,
        req: &DisableAuthenticator,
    ) -> Result<UserSummary, ControlError> {
        let user = self.session_user(auth).await?;
        local_account(&user, "remove an authenticator")?;
        if user.totp_secret_enc.is_none() {
            return Err(ControlError::Conflict {
                message: format!("user '{}' has no authenticator to remove", user.username),
            });
        }
        self.confirm_password(auth, &user, &req.password, "auth.totp_disable")
            .await?;
        if !self.verify_totp(&user, req.code.trim()).await? {
            self.limiter.fail(&user.username);
            self.audit
                .record(AuditEvent::new(
                    auth.caller.actor(),
                    "auth.totp_disable",
                    AuditOutcome::Denied,
                ))
                .await;
            return Err(ControlError::Unauthenticated {
                reason: "the authenticator code is invalid or was already used".into(),
            });
        }
        let event = AuditEvent::new(
            auth.caller.actor(),
            "auth.totp_disable",
            AuditOutcome::Success,
        )
        .target(format!("user:{}", user.id));
        self.identity
            .set_user_totp(&user.id, None, None, &[event])
            .await?;
        info!(user_id = %user.id, "authenticator turned off");
        let mut summary = UserSummary::from(&user);
        summary.totp_enrolled = false;
        Ok(summary)
    }

    async fn verify_totp(&self, user: &User, code: &str) -> Result<bool, ControlError> {
        let Some(secret_enc) = &user.totp_secret_enc else {
            return Ok(false);
        };
        let secret = self.cipher.decrypt(secret_enc, &totp_aad(&user.id)).await?;
        let secret = std::str::from_utf8(&secret)
            .map_err(|e| ControlError::crypto("totp.decode", format!("user {}: {e}", user.id)))?;
        match totp::verify_code(
            secret,
            &user.username,
            code,
            unix_now(),
            user.totp_last_step,
        )? {
            Some(step) => Ok(self.identity.advance_totp_step(&user.id, step).await?),
            None => Ok(false),
        }
    }

    /// Accounts with an authenticator must present a valid code; accounts
    /// without one have no second factor to check.
    async fn second_factor_ok(
        &self,
        user: &User,
        code: &Option<String>,
    ) -> Result<bool, ControlError> {
        match (&user.totp_secret_enc, non_empty(code)) {
            (None, _) => Ok(true),
            (Some(_), Some(code)) => self.verify_totp(user, code).await,
            (Some(_), None) => Ok(false),
        }
    }

    pub async fn login(&self, req: LoginRequest) -> Result<LoginOutcome, ControlError> {
        let username = req.username.trim().to_ascii_lowercase();
        self.limiter.check(&username)?;
        let user = self.identity.get_user_by_username(&username).await?;
        // A single sign-on account has no password: it fails like a wrong
        // one, after the same work, so neither reveals which it is.
        let password_ok = match &user {
            Some(u) if u.sso.is_none() => {
                password::verify_password(&u.password_hash, &req.password)?
            }
            _ => {
                let _ = password::verify_password(&self.dummy_hash, &req.password);
                false
            }
        };
        // The right password for an account with an authenticator, sent
        // without a code, asks for the code; it is not a failed attempt.
        if let (Some(u), true) = (&user, password_ok) {
            if u.disabled_at.is_none()
                && u.totp_secret_enc.is_some()
                && non_empty(&req.totp_code).is_none()
            {
                return Err(ControlError::SecondFactorRequired {
                    username: u.username.clone(),
                });
            }
        }
        let user = match (user, password_ok) {
            (Some(u), true)
                if u.disabled_at.is_none() && self.second_factor_ok(&u, &req.totp_code).await? =>
            {
                u
            }
            _ => {
                self.limiter.fail(&username);
                warn!(username = %username, "login failed");
                self.audit
                    .record(
                        AuditEvent::new("anonymous", "auth.login", AuditOutcome::Denied)
                            .detail("username", username.clone()),
                    )
                    .await;
                return Err(ControlError::Unauthenticated {
                    reason: "invalid username, password or TOTP code".into(),
                });
            }
        };
        self.limiter.reset(&username);
        if let Err(e) = self.password_sign_in_allowed(&user).await? {
            self.audit
                .record(
                    AuditEvent::new(
                        format!("user:{}", user.id),
                        "auth.login",
                        AuditOutcome::Denied,
                    )
                    .detail("username", user.username.clone())
                    .detail("reason", "password sign-in is limited to admins"),
                )
                .await;
            return Err(e);
        }
        let event = AuditEvent::new(
            format!("user:{}", user.id),
            "auth.login",
            AuditOutcome::Success,
        )
        .detail("username", user.username.clone())
        .detail("method", "password");
        open_ui_session(
            self.identity.as_ref(),
            &self.keys,
            &self.config,
            &user,
            Some(Utc::now()),
            event,
        )
        .await
    }

    /// `Err` inside `Ok` when the settings keep this password account out:
    /// with password sign-in limited to admins, everyone else uses single
    /// sign-on.
    async fn password_sign_in_allowed(
        &self,
        user: &User,
    ) -> Result<Result<(), ControlError>, ControlError> {
        if user.role == Role::Admin {
            return Ok(Ok(()));
        }
        let settings = self.sso.get_sign_in_settings().await?;
        Ok(match settings.password_sign_in {
            PasswordSignIn::Everyone => Ok(()),
            PasswordSignIn::AdminsOnly => Err(ControlError::Forbidden {
                reason: format!(
                    "password sign-in is limited to admins here; '{}' signs in with single sign-on",
                    user.username
                ),
            }),
        })
    }

    pub async fn authenticate_session(
        &self,
        session_token: &str,
    ) -> Result<SessionAuth, ControlError> {
        let unauth = |reason: &str| ControlError::Unauthenticated {
            reason: reason.to_string(),
        };
        if !session_token.starts_with(token::SESSION_PREFIX) {
            return Err(unauth("session cookie is malformed"));
        }
        let token_hash = token::hash_token(session_token);
        let session = self
            .identity
            .get_ui_session(&token_hash)
            .await?
            .ok_or_else(|| unauth("session is unknown or has been logged out"))?;
        if session.expires_at <= Utc::now() {
            self.identity.delete_ui_session(&token_hash, &[]).await?;
            return Err(unauth("session has expired"));
        }
        let user = self
            .identity
            .get_user(&session.user_id)
            .await?
            .ok_or_else(|| unauth("session user no longer exists"))?;
        if user.disabled_at.is_some() {
            return Err(unauth("the account has been disabled"));
        }
        match &user.sso {
            // Turning a provider off ends its people's sessions.
            Some(sso) => {
                let enabled = self
                    .sso
                    .get_oidc_provider(&sso.provider_id)
                    .await?
                    .is_some_and(|p| p.enabled);
                if !enabled {
                    return Err(unauth(
                        "the account's single sign-on provider has been turned off",
                    ));
                }
            }
            None => {
                if let Err(ControlError::Forbidden { reason }) =
                    self.password_sign_in_allowed(&user).await?
                {
                    return Err(ControlError::Unauthenticated { reason });
                }
            }
        }
        Ok(SessionAuth {
            caller: Caller {
                principal: Principal {
                    kind: PrincipalKind::User,
                    actor: format!("user:{}", user.id),
                    role: user.role,
                    vault: None,
                },
                step_up_at: session.step_up_at,
                // A single sign-on account steps up at its provider.
                second_factor: user.totp_secret_enc.is_some() || user.sso.is_some(),
            },
            token_hash,
            user: UserSummary::from(&user),
            expires_at: session.expires_at,
        })
    }

    pub fn csrf_token(&self, token_hash: &str) -> String {
        csrf::derive(&self.keys.csrf_key, token_hash)
    }

    pub fn verify_csrf(&self, token_hash: &str, presented: &str) -> bool {
        csrf::verify(&self.keys.csrf_key, token_hash, presented)
    }

    /// Re-proves the person behind a session. With an authenticator
    /// enrolled only its code counts, so a stolen password cannot stand in
    /// for the second factor; without one the password is re-checked.
    pub async fn step_up(
        &self,
        auth: &SessionAuth,
        proof: &StepUpProof,
    ) -> Result<DateTime<Utc>, ControlError> {
        let user = self
            .identity
            .get_user(&auth.user.id)
            .await?
            .ok_or_else(|| ControlError::not_found("user", auth.user.id))?;
        if let Some(sso) = &user.sso {
            return Err(ControlError::validation(format!(
                "'{}' steps up at its single sign-on provider: open GET /api/v1/auth/oidc/<provider>/start?purpose=step_up in the browser (provider {})",
                user.username, sso.provider_id
            )));
        }
        self.limiter.check(&user.username)?;
        let (ok, reason) = match (&user.totp_secret_enc, non_empty(&proof.code)) {
            (Some(_), Some(code)) => (
                self.verify_totp(&user, code).await?,
                "TOTP code is invalid or was already used",
            ),
            (Some(_), None) => (false, "enter the code from your authenticator app"),
            (None, _) => (
                match proof.password.as_deref() {
                    Some(p) if !p.is_empty() => password::verify_password(&user.password_hash, p)?,
                    _ => false,
                },
                "password is incorrect",
            ),
        };
        if !ok {
            self.limiter.fail(&user.username);
            self.audit
                .record(AuditEvent::new(
                    auth.caller.actor(),
                    "auth.step_up",
                    AuditOutcome::Denied,
                ))
                .await;
            return Err(ControlError::Unauthenticated {
                reason: reason.into(),
            });
        }
        let now = Utc::now();
        let event = AuditEvent::new(auth.caller.actor(), "auth.step_up", AuditOutcome::Success);
        self.identity
            .set_ui_session_step_up(&auth.token_hash, now, &[event])
            .await?;
        Ok(now)
    }

    pub async fn logout(&self, auth: &SessionAuth) -> Result<(), ControlError> {
        let event = AuditEvent::new(auth.caller.actor(), "auth.logout", AuditOutcome::Success);
        self.identity
            .delete_ui_session(&auth.token_hash, &[event])
            .await?;
        Ok(())
    }

    /// Deletes expired UI sessions; returns how many.
    pub async fn purge_expired_sessions(&self) -> Result<u64, ControlError> {
        Ok(self.identity.delete_expired_ui_sessions(Utc::now()).await?)
    }

    pub async fn authenticate_api_key(&self, presented: &str) -> Result<Caller, ControlError> {
        let unauth = |reason: &str| ControlError::Unauthenticated {
            reason: reason.to_string(),
        };
        let parts =
            token::parse_api_key(presented.trim()).map_err(|_| unauth("API key is malformed"))?;
        let key = self
            .identity
            .get_api_key_by_prefix(&parts.prefix)
            .await?
            .ok_or_else(|| unauth("API key is unknown"))?;
        if !token::hashes_equal(&key.secret_hash, &token::hash_token(&parts.full)) {
            return Err(unauth("API key is unknown"));
        }
        let now = Utc::now();
        if key.revoked_at.is_some() {
            return Err(unauth("API key has been revoked"));
        }
        if key.expires_at <= now {
            return Err(unauth("API key has expired"));
        }
        if key
            .last_used_at
            .is_none_or(|t| now - t > Duration::minutes(1))
        {
            if let Err(e) = self.identity.touch_api_key(&key.id, now).await {
                warn!(api_key = %key.prefix, error = %e, "failed to record API key use");
            }
        }
        Ok(Caller {
            principal: Principal {
                kind: PrincipalKind::ApiKey,
                actor: format!("api_key:{}", key.prefix),
                role: key.role,
                vault: Some(key.vault_id),
            },
            step_up_at: None,
            second_factor: false,
        })
    }

    pub async fn create_api_key(
        &self,
        caller: &Caller,
        req: CreateApiKey,
    ) -> Result<(String, ApiKey), ControlError> {
        self.guard
            .check(caller, Action::ApiKeyManage, Some(&req.vault_id))
            .await?;
        if req.role == Role::Admin {
            return Err(ControlError::validation(
                "API keys cannot be given the admin role",
            ));
        }
        let name = req.name.trim();
        if name.is_empty() || name.len() > 100 {
            return Err(ControlError::validation(
                "API key name must be 1-100 characters",
            ));
        }
        if req.expires_in_days == 0 || req.expires_in_days > MAX_API_KEY_DAYS {
            return Err(ControlError::validation(format!(
                "expires_in_days must be between 1 and {MAX_API_KEY_DAYS}"
            )));
        }
        let parts = token::new_api_key();
        let now = Utc::now();
        let key = ApiKey {
            id: ApiKeyId::new(),
            name: name.to_string(),
            prefix: parts.prefix.clone(),
            secret_hash: token::hash_token(&parts.full),
            vault_id: req.vault_id,
            role: req.role,
            created_by: caller.actor().to_string(),
            created_at: now,
            expires_at: now + Duration::days(i64::from(req.expires_in_days)),
            revoked_at: None,
            last_used_at: None,
        };
        let event = AuditEvent::new(caller.actor(), "api_key.create", AuditOutcome::Success)
            .vault(req.vault_id)
            .target(format!("api_key:{}", key.prefix))
            .detail("role", key.role.as_str())
            .detail("expires_at", key.expires_at.to_rfc3339());
        self.identity.insert_api_key(key.clone(), &[event]).await?;
        Ok((parts.full, key))
    }

    pub async fn list_api_keys(
        &self,
        caller: &Caller,
        page: PageRequest,
    ) -> Result<Page<ApiKey>, ControlError> {
        self.guard.check(caller, Action::ApiKeyManage, None).await?;
        Ok(self.identity.list_api_keys(page).await?)
    }

    pub async fn revoke_api_key(&self, caller: &Caller, id: &ApiKeyId) -> Result<(), ControlError> {
        self.guard.check(caller, Action::ApiKeyManage, None).await?;
        let event = AuditEvent::new(caller.actor(), "api_key.revoke", AuditOutcome::Success)
            .target(format!("api_key:{id}"));
        self.identity
            .revoke_api_key(id, Utc::now(), &[event])
            .await?;
        Ok(())
    }

    pub fn session_cookie(outcome: &LoginOutcome) -> String {
        cookie::session_cookie(&outcome.token, outcome.max_age_secs)
    }
}
