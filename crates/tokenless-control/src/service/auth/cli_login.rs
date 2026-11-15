// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded, short-lived browser approvals. Only the initiating CLI knows
//! the polling secret; the browser sees a separate confirmation code.
use super::*;

const LIFETIME: StdDuration = StdDuration::from_secs(300);
const CAPACITY: usize = 256;

pub(super) struct PendingCliLogin {
    expires: Instant,
    code: String,
    provider: String,
    manage: bool,
    approved_session: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct CliLoginStarted {
    pub device_code: String,
    pub user_code: String,
    pub expires_in: u64,
}
tokenless_core::redacted_debug!(CliLoginStarted { expires_in; device_code, user_code });

#[derive(Serialize, Deserialize)]
pub struct CliLoginDetails {
    pub provider: String,
    pub manage: bool,
}

impl AuthService {
    fn cli_logins(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, HashMap<String, PendingCliLogin>>, ControlError> {
        let mut pending = self
            .cli_logins
            .lock()
            .map_err(|_| ControlError::validation("CLI sign-in queue is unavailable"))?;
        pending.retain(|_, entry| entry.expires > Instant::now());
        Ok(pending)
    }

    pub async fn begin_cli_login(
        &self,
        provider: &str,
        manage: bool,
    ) -> Result<CliLoginStarted, ControlError> {
        if !self
            .sso
            .list_oidc_providers()
            .await?
            .iter()
            .any(|p| p.enabled && p.slug == provider)
        {
            return Err(ControlError::validation(format!(
                "single sign-on provider '{provider}' is not enabled"
            )));
        }
        let mut pending = self.cli_logins()?;
        if pending.len() >= CAPACITY {
            return Err(ControlError::validation(
                "too many pending CLI sign-ins; try again in five minutes",
            ));
        }
        let device_code = token::new_token("cli");
        let code = loop {
            let candidate = token::hash_token(&token::new_token("confirm"))[..12].to_uppercase();
            if !pending.values().any(|p| p.code == candidate) {
                break candidate;
            }
        };
        pending.insert(
            token::hash_token(&device_code),
            PendingCliLogin {
                expires: Instant::now() + LIFETIME,
                code: code.clone(),
                provider: provider.into(),
                manage,
                approved_session: None,
            },
        );
        Ok(CliLoginStarted {
            device_code,
            user_code: code,
            expires_in: LIFETIME.as_secs(),
        })
    }

    pub fn cli_login_details(&self, code: &str) -> Result<CliLoginDetails, ControlError> {
        let pending = self.cli_logins()?;
        let entry = pending.values().find(|p| p.code == code).ok_or_else(|| {
            ControlError::validation(
                "CLI sign-in code is unknown or expired; restart tokenless login",
            )
        })?;
        Ok(CliLoginDetails {
            provider: entry.provider.clone(),
            manage: entry.manage,
        })
    }

    pub async fn approve_cli_login(
        &self,
        auth: &SessionAuth,
        code: &str,
    ) -> Result<(), ControlError> {
        if auth.caller.sign_in != SignInScope::Full {
            return Err(ControlError::Forbidden {
                reason: "a launch-only sign-in cannot approve another sign-in".into(),
            });
        }
        let details = self.cli_login_details(code)?;
        let user = self.session_user(auth).await?;
        let provider_id =
            user.sso
                .as_ref()
                .map(|s| &s.provider_id)
                .ok_or_else(|| ControlError::Forbidden {
                    reason: "sign in with the requested identity provider to approve this CLI"
                        .into(),
                })?;
        let provider = self
            .sso
            .get_oidc_provider(provider_id)
            .await?
            .ok_or_else(|| ControlError::not_found("identity provider", provider_id))?;
        if !provider.enabled || provider.slug != details.provider {
            return Err(ControlError::Forbidden {
                reason: format!("this CLI sign-in requires provider '{}'", details.provider),
            });
        }
        self.guard
            .require_step_up(&auth.caller, Action::ApiKeyManage)?;
        let mut pending = self.cli_logins()?;
        let entry = pending
            .values_mut()
            .find(|p| p.code == code)
            .ok_or_else(|| {
                ControlError::validation("CLI sign-in code expired; restart tokenless login")
            })?;
        if entry.approved_session.is_some() {
            return Err(ControlError::Conflict {
                message: "CLI sign-in was already approved".into(),
            });
        }
        entry.approved_session = Some(auth.token_hash.clone());
        Ok(())
    }

    pub async fn poll_cli_login(
        &self,
        device_code: &str,
    ) -> Result<Option<LoginOutcome>, ControlError> {
        let entry = {
            let mut pending = self.cli_logins()?;
            let key = token::hash_token(device_code);
            let entry = pending
                .get(&key)
                .ok_or_else(|| ControlError::Unauthenticated {
                    reason: "CLI sign-in is unknown, expired or already used".into(),
                })?;
            if entry.approved_session.is_none() {
                return Ok(None);
            }
            pending
                .remove(&key)
                .ok_or_else(|| ControlError::validation("CLI sign-in was consumed"))?
        };
        let hash = entry
            .approved_session
            .ok_or_else(|| ControlError::validation("CLI sign-in has no approval"))?;
        let auth = self.authenticate_session_hash(hash).await?;
        let user = self.session_user(&auth).await?;
        let remaining = (auth.expires_at - Utc::now()).num_seconds().max(0) as u64;
        let grant = SignInGrant {
            scope: if entry.manage {
                SignInScope::Full
            } else {
                SignInScope::Launch
            },
            ttl_secs: Some(if entry.manage {
                remaining.min(3600)
            } else {
                remaining
            }),
            step_up_at: auth.caller.step_up_at,
        };
        let event = AuditEvent::new(auth.caller.actor(), "auth.login", AuditOutcome::Success)
            .detail("method", "cli_sso")
            .detail("provider", entry.provider);
        open_ui_session(
            self.identity.as_ref(),
            &self.keys,
            &self.config,
            &user,
            Some("tokenless/cli-sso"),
            grant,
            event,
        )
        .await
        .map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cipher::AesGcmCipher, envelope::Envelope, memory::MemoryStore, store::RbacAuthorizer,
    };

    async fn auth() -> AuthService {
        let store = Arc::new(MemoryStore::new());
        let cipher = Arc::new(
            Envelope::open(&AesGcmCipher::generate_key(), store.clone())
                .await
                .unwrap(),
        );
        let keys = Arc::new(
            KeyRing::load_or_create(store.as_ref(), cipher.as_ref())
                .await
                .unwrap(),
        );
        AuthService::new(
            store.clone(),
            store.clone(),
            cipher,
            keys,
            Guard::new(Arc::new(RbacAuthorizer), 300),
            AuditRecorder::new(store),
            ControlConfig::default(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn expired_approval_cannot_be_viewed_or_redeemed() {
        let auth = auth().await;
        auth.cli_logins.lock().unwrap().insert(
            token::hash_token("device"),
            PendingCliLogin {
                expires: Instant::now() - StdDuration::from_secs(1),
                code: "confirm".into(),
                provider: "corp".into(),
                manage: false,
                approved_session: Some("browser".into()),
            },
        );
        assert!(auth.cli_login_details("confirm").is_err());
        assert!(auth.poll_cli_login("device").await.is_err());
        assert!(auth.cli_logins.lock().unwrap().is_empty());
    }
}
