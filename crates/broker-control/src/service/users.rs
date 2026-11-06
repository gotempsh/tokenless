// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! People management: invitations, role changes and disabling accounts.
//!
//! People hold one instance-wide role (admin, editor or viewer). The store
//! refuses any change that would leave no enabled admin, so the instance
//! can never lock itself out.

use std::sync::Arc;

use broker_auth::{token, totp};
use broker_core::audit::{AuditEvent, AuditOutcome};
use broker_core::authz::{Action, Role};
use broker_core::ids::{InviteId, UserId};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tracing::info;

use super::auth::{build_user, check_new_account, validate_username, TotpEnrollment, UserSummary};
use super::{Caller, Guard};
use crate::cipher::SecretCipher;
use crate::error::{ControlError, StoreError};
use crate::model::{Invite, Page, PageRequest};
use crate::store::IdentityStore;

pub const DEFAULT_INVITE_HOURS: u32 = 72;
pub const MAX_INVITE_HOURS: u32 = 7 * 24;

#[derive(Debug, Clone, Deserialize)]
pub struct CreateInvite {
    pub role: Role,
    /// Defaults to 72 hours; at most 7 days.
    pub expires_in_hours: Option<u32>,
}

/// The invitation and its token, which is shown exactly once.
#[derive(Debug, Clone, Serialize)]
pub struct InviteIssued {
    pub token: String,
    pub invite: Invite,
}

/// What the person holding an invite token is being offered.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InviteInfo {
    pub role: Role,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AcceptInviteRequest {
    pub invite_token: String,
    pub username: String,
    pub password: String,
    /// Omit both TOTP fields for a password-only account.
    #[serde(default)]
    pub totp_secret: Option<String>,
    #[serde(default)]
    pub totp_code: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct UpdateUser {
    pub role: Option<Role>,
    pub disabled: Option<bool>,
}

fn person_role(role: Role) -> Result<Role, ControlError> {
    match role {
        Role::Admin | Role::Editor | Role::Viewer => Ok(role),
        Role::SessionIssuer => Err(ControlError::validation(
            "the session_issuer role is for API keys; people are admin, editor or viewer",
        )),
    }
}

fn invalid_invite() -> ControlError {
    ControlError::Unauthenticated {
        reason: "invite is invalid, expired, revoked or already used".into(),
    }
}

pub struct UserService {
    identity: Arc<dyn IdentityStore>,
    cipher: Arc<dyn SecretCipher>,
    guard: Guard,
}

impl UserService {
    pub fn new(
        identity: Arc<dyn IdentityStore>,
        cipher: Arc<dyn SecretCipher>,
        guard: Guard,
    ) -> Self {
        Self {
            identity,
            cipher,
            guard,
        }
    }

    pub async fn list_users(
        &self,
        caller: &Caller,
        page: PageRequest,
    ) -> Result<Page<UserSummary>, ControlError> {
        self.guard.check(caller, Action::UserRead, None).await?;
        let page = self.identity.list_users(page).await?;
        Ok(Page {
            items: page.items.iter().map(UserSummary::from).collect(),
            total: page.total,
            page: page.page,
            page_size: page.page_size,
        })
    }

    /// Changes a person's role and/or disables or re-enables them.
    /// Disabling ends their UI sessions immediately.
    pub async fn update_user(
        &self,
        caller: &Caller,
        id: &UserId,
        req: UpdateUser,
    ) -> Result<UserSummary, ControlError> {
        self.guard.check(caller, Action::UserManage, None).await?;
        if req.role.is_none() && req.disabled.is_none() {
            return Err(ControlError::validation(
                "nothing to change: set 'role' and/or 'disabled'",
            ));
        }
        let mut user = self
            .identity
            .get_user(id)
            .await?
            .ok_or_else(|| ControlError::not_found("user", id))?;
        let role = req.role.map(person_role).transpose()?.unwrap_or(user.role);
        let disabled_at = match req.disabled {
            Some(true) => user.disabled_at.or_else(|| Some(Utc::now())),
            Some(false) => None,
            None => user.disabled_at,
        };
        if disabled_at.is_some()
            && user.disabled_at.is_none()
            && caller.actor() == format!("user:{id}")
        {
            return Err(ControlError::validation(
                "you cannot disable your own account; another admin has to",
            ));
        }
        let event = AuditEvent::new(caller.actor(), "user.update", AuditOutcome::Success)
            .target(format!("user:{id}"))
            .detail("username", user.username.clone())
            .detail("previous_role", user.role.as_str())
            .detail("role", role.as_str())
            .detail("disabled", disabled_at.is_some().to_string());
        match self
            .identity
            .update_user_access(id, role, disabled_at, &[event])
            .await
        {
            Ok(()) => {}
            Err(StoreError::Conflict { .. }) => {
                return Err(ControlError::Conflict {
                    message: format!(
                    "user '{}' is the last enabled admin; promote or enable another admin first",
                    user.username
                ),
                })
            }
            Err(e) => return Err(e.into()),
        }
        info!(user_id = %id, role = role.as_str(), disabled = disabled_at.is_some(), "updated user access");
        user.role = role;
        user.disabled_at = disabled_at;
        Ok(UserSummary::from(&user))
    }

    pub async fn list_invites(
        &self,
        caller: &Caller,
        page: PageRequest,
    ) -> Result<Page<Invite>, ControlError> {
        self.guard.check(caller, Action::UserRead, None).await?;
        Ok(self.identity.list_invites(page).await?)
    }

    pub async fn create_invite(
        &self,
        caller: &Caller,
        req: CreateInvite,
    ) -> Result<InviteIssued, ControlError> {
        self.guard.check(caller, Action::UserManage, None).await?;
        let role = person_role(req.role)?;
        let hours = req.expires_in_hours.unwrap_or(DEFAULT_INVITE_HOURS);
        if hours == 0 || hours > MAX_INVITE_HOURS {
            return Err(ControlError::validation(format!(
                "expires_in_hours must be between 1 and {MAX_INVITE_HOURS}"
            )));
        }
        let plaintext = token::new_token(token::INVITE_PREFIX);
        let now = Utc::now();
        let invite = Invite {
            id: InviteId::new(),
            token_hash: token::hash_token(&plaintext),
            role,
            created_by: caller.actor().to_string(),
            created_at: now,
            expires_at: now + Duration::hours(i64::from(hours)),
            accepted_at: None,
            accepted_by: None,
            revoked_at: None,
        };
        let event = AuditEvent::new(caller.actor(), "user.invite", AuditOutcome::Success)
            .target(format!("invite:{}", invite.id))
            .detail("role", role.as_str())
            .detail("expires_at", invite.expires_at.to_rfc3339());
        self.identity
            .insert_invite(invite.clone(), &[event])
            .await?;
        Ok(InviteIssued {
            token: plaintext,
            invite,
        })
    }

    pub async fn revoke_invite(&self, caller: &Caller, id: &InviteId) -> Result<(), ControlError> {
        self.guard.check(caller, Action::UserManage, None).await?;
        let event = AuditEvent::new(caller.actor(), "user.invite.revoke", AuditOutcome::Success)
            .target(format!("invite:{id}"));
        self.identity
            .revoke_invite(id, Utc::now(), &[event])
            .await?;
        Ok(())
    }

    async fn pending_invite(&self, invite_token: &str) -> Result<Invite, ControlError> {
        let invite_token = invite_token.trim();
        if !invite_token.starts_with(token::INVITE_PREFIX) {
            return Err(invalid_invite());
        }
        self.identity
            .get_invite_by_token_hash(&token::hash_token(invite_token))
            .await?
            .filter(|i| i.is_pending(Utc::now()))
            .ok_or_else(invalid_invite)
    }

    /// Unauthenticated: shows the holder of a token what it offers.
    pub async fn inspect_invite(&self, invite_token: &str) -> Result<InviteInfo, ControlError> {
        let invite = self.pending_invite(invite_token).await?;
        Ok(InviteInfo {
            role: invite.role,
            expires_at: invite.expires_at,
        })
    }

    /// Unauthenticated: a TOTP secret for the invitee to enrol. It is bound
    /// to the account only when `accept_invite` succeeds with a code for it.
    pub async fn invite_totp(
        &self,
        invite_token: &str,
        username: &str,
    ) -> Result<TotpEnrollment, ControlError> {
        self.pending_invite(invite_token).await?;
        validate_username(username)?;
        let secret = totp::generate_secret();
        let otpauth_url = totp::otpauth_url(&secret, username)?;
        Ok(TotpEnrollment {
            secret,
            otpauth_url,
        })
    }

    /// Unauthenticated: creates the account the invite offers.
    pub async fn accept_invite(
        &self,
        req: AcceptInviteRequest,
    ) -> Result<UserSummary, ControlError> {
        let totp = check_new_account(
            &req.username,
            &req.password,
            &req.totp_secret,
            &req.totp_code,
        )?;
        let invite = self.pending_invite(&req.invite_token).await?;
        let user = build_user(
            self.cipher.as_ref(),
            &req.username,
            &req.password,
            totp,
            invite.role,
        )?;
        let event = AuditEvent::new(
            format!("user:{}", user.id),
            "user.invite.accept",
            AuditOutcome::Success,
        )
        .target(format!("user:{}", user.id))
        .detail("username", user.username.clone())
        .detail("role", user.role.as_str())
        .detail("invite", invite.id.to_string())
        .detail("invited_by", invite.created_by.clone());
        let accepted = match self
            .identity
            .accept_invite(&invite.token_hash, user.clone(), &[event])
            .await
        {
            Ok(accepted) => accepted,
            Err(StoreError::Conflict { .. }) => {
                return Err(ControlError::Conflict {
                    message: format!("username '{}' is already taken", user.username),
                })
            }
            Err(e) => return Err(e.into()),
        };
        if !accepted {
            return Err(invalid_invite());
        }
        info!(user_id = %user.id, role = user.role.as_str(), invite = %invite.id, "invite accepted");
        Ok(UserSummary::from(&user))
    }
}
