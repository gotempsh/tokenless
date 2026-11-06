// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! People and API keys: first-admin setup, password + TOTP login, UI
//! sessions, step-up MFA and API key issuance.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration as StdDuration, Instant};

use broker_auth::{cookie, csrf, password, token, totp};
use broker_core::audit::{AuditEvent, AuditOutcome};
use broker_core::authz::{Action, Principal, PrincipalKind, Role};
use broker_core::ids::{ApiKeyId, UserId, VaultId};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use super::{AuditRecorder, Caller, ControlConfig, Guard};
use crate::cipher::SecretCipher;
use crate::error::ControlError;
use crate::keys::KeyRing;
use crate::model::{ApiKey, Page, PageRequest, UiSession, User};
use crate::store::IdentityStore;

const MAX_FAILED_LOGINS: u32 = 5;
const LOGIN_WINDOW: StdDuration = StdDuration::from_secs(300);
const LIMITER_CAPACITY: usize = 10_000;
const MAX_API_KEY_DAYS: u32 = 365;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserSummary {
    pub id: UserId,
    pub username: String,
    pub role: Role,
}

impl From<&User> for UserSummary {
    fn from(u: &User) -> Self {
        Self {
            id: u.id,
            username: u.username.clone(),
            role: u.role,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpEnrollment {
    pub secret: String,
    pub otpauth_url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SetupRequest {
    pub setup_token: String,
    pub username: String,
    pub password: String,
    pub totp_secret: String,
    pub totp_code: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub totp_code: String,
}

pub struct LoginOutcome {
    pub token: String,
    pub csrf_token: String,
    pub user: UserSummary,
    pub expires_at: DateTime<Utc>,
    pub max_age_secs: u64,
}

/// A verified UI session.
#[derive(Debug, Clone)]
pub struct SessionAuth {
    pub caller: Caller,
    pub token_hash: String,
    pub user: UserSummary,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateApiKey {
    pub name: String,
    pub vault_id: VaultId,
    pub role: Role,
    pub expires_in_days: u32,
}

fn validate_username(username: &str) -> Result<(), ControlError> {
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
    cipher: Arc<dyn SecretCipher>,
    keys: Arc<KeyRing>,
    guard: Guard,
    audit: AuditRecorder,
    config: ControlConfig,
    limiter: LoginLimiter,
    dummy_hash: String,
}

fn totp_aad(user_id: &UserId) -> Vec<u8> {
    format!("user-totp|{user_id}").into_bytes()
}

impl AuthService {
    pub fn new(
        identity: Arc<dyn IdentityStore>,
        cipher: Arc<dyn SecretCipher>,
        keys: Arc<KeyRing>,
        guard: Guard,
        audit: AuditRecorder,
        config: ControlConfig,
    ) -> Result<Self, ControlError> {
        Ok(Self {
            identity,
            cipher,
            keys,
            guard,
            audit,
            config,
            limiter: LoginLimiter::new(),
            dummy_hash: password::dummy_hash()?,
        })
    }

    pub async fn setup_required(&self) -> Result<bool, ControlError> {
        Ok(self.identity.count_users().await? == 0)
    }

    /// When no account exists yet, mints a fresh one-time setup token
    /// (invalidating any earlier one) for the operator to read from the
    /// console. Returns `None` once an admin exists.
    pub async fn issue_setup_token(&self) -> Result<Option<String>, ControlError> {
        if !self.setup_required().await? {
            return Ok(None);
        }
        let plaintext = token::new_token(token::SETUP_PREFIX);
        self.identity
            .replace_setup_token(&token::hash_token(&plaintext), Utc::now())
            .await?;
        Ok(Some(plaintext))
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

    pub async fn complete_setup(&self, req: SetupRequest) -> Result<UserSummary, ControlError> {
        validate_username(&req.username)?;
        password::check_password_policy(&req.password)?;
        let step = totp::verify_code(
            &req.totp_secret,
            &req.username,
            &req.totp_code,
            unix_now(),
            None,
        )?
        .ok_or_else(|| {
            ControlError::validation(
                "the TOTP code does not match the secret; check the authenticator clock",
            )
        })?;
        if !self.setup_required().await? {
            return Err(ControlError::Conflict {
                message: "setup has already been completed".into(),
            });
        }
        if !self
            .identity
            .consume_setup_token(&token::hash_token(req.setup_token.trim()))
            .await?
        {
            return Err(ControlError::Unauthenticated {
                reason: "setup token is invalid or was already used".into(),
            });
        }
        let id = UserId::new();
        let user = User {
            id,
            username: req.username.clone(),
            password_hash: password::hash_password(&req.password)?,
            totp_secret_enc: self
                .cipher
                .encrypt(req.totp_secret.trim().as_bytes(), &totp_aad(&id))?,
            totp_last_step: Some(step),
            role: Role::Admin,
            created_at: Utc::now(),
        };
        let event = AuditEvent::new(format!("user:{id}"), "auth.setup", AuditOutcome::Success)
            .target(format!("user:{id}"))
            .detail("username", user.username.clone());
        self.identity.insert_user(user.clone(), &[event]).await?;
        info!(user_id = %id, username = %user.username, "first admin created from setup token");
        Ok(UserSummary::from(&user))
    }

    async fn verify_totp(&self, user: &User, code: &str) -> Result<bool, ControlError> {
        let secret = self
            .cipher
            .decrypt(&user.totp_secret_enc, &totp_aad(&user.id))?;
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

    pub async fn login(&self, req: LoginRequest) -> Result<LoginOutcome, ControlError> {
        let username = req.username.trim().to_ascii_lowercase();
        self.limiter.check(&username)?;
        let user = self.identity.get_user_by_username(&username).await?;
        let password_ok = match &user {
            Some(u) => password::verify_password(&u.password_hash, &req.password)?,
            None => {
                let _ = password::verify_password(&self.dummy_hash, &req.password);
                false
            }
        };
        let user = match (user, password_ok) {
            (Some(u), true) if self.verify_totp(&u, &req.totp_code).await? => u,
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
        let now = Utc::now();
        let max_age = self.config.ui_session_ttl_secs;
        let expires_at = now + Duration::seconds(i64::try_from(max_age).unwrap_or(43_200));
        let plaintext = token::new_token(token::SESSION_PREFIX);
        let token_hash = token::hash_token(&plaintext);
        let event = AuditEvent::new(
            format!("user:{}", user.id),
            "auth.login",
            AuditOutcome::Success,
        )
        .detail("username", user.username.clone());
        self.identity
            .insert_ui_session(
                UiSession {
                    token_hash: token_hash.clone(),
                    user_id: user.id,
                    created_at: now,
                    expires_at,
                    step_up_at: Some(now),
                },
                &[event],
            )
            .await?;
        Ok(LoginOutcome {
            token: plaintext,
            csrf_token: csrf::derive(&self.keys.csrf_key, &token_hash),
            user: UserSummary::from(&user),
            expires_at,
            max_age_secs: max_age,
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
        Ok(SessionAuth {
            caller: Caller {
                principal: Principal {
                    kind: PrincipalKind::User,
                    actor: format!("user:{}", user.id),
                    role: user.role,
                    vault: None,
                },
                step_up_at: session.step_up_at,
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

    pub async fn step_up(
        &self,
        auth: &SessionAuth,
        code: &str,
    ) -> Result<DateTime<Utc>, ControlError> {
        let user = self
            .identity
            .get_user(&auth.user.id)
            .await?
            .ok_or_else(|| ControlError::not_found("user", auth.user.id))?;
        if !self.verify_totp(&user, code).await? {
            self.audit
                .record(AuditEvent::new(
                    auth.caller.actor(),
                    "auth.step_up",
                    AuditOutcome::Denied,
                ))
                .await;
            return Err(ControlError::Unauthenticated {
                reason: "TOTP code is invalid or was already used".into(),
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
