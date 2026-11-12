// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Vault membership: who may work in each vault, and with which role.
//!
//! A vault's admins add and remove its members; an instance admin who is
//! not a member oversees the vault (reads it, its audit log and alerts,
//! revokes its sessions and keys) and joins it, audited, to do more.

use std::sync::Arc;

use chrono::Utc;
use serde::Deserialize;
use tokenless_core::audit::{AuditEvent, AuditOutcome};
use tokenless_core::authz::{Action, Role};
use tokenless_core::ids::{UserId, VaultId};
use tracing::info;

use super::{Caller, Guard};
use crate::error::{ControlError, StoreError};
use crate::model::{Page, PageRequest, Vault, VaultGrant, VaultMember};
use crate::store::{IdentityStore, MembershipStore, PolicyStore};

/// Adds a person to a vault, or changes their role in it.
#[derive(Debug, Clone, Deserialize)]
pub struct PutMember {
    pub username: String,
    pub role: Role,
}

/// Checks that `role` can be held inside a vault.
pub fn check_vault_role(role: Role) -> Result<(), ControlError> {
    if role.is_vault_role() {
        return Ok(());
    }
    Err(ControlError::validation(format!(
        "'{role}' is not a role inside a vault; use admin, editor, viewer or runner"
    )))
}

pub struct MemberService {
    members: Arc<dyn MembershipStore>,
    identity: Arc<dyn IdentityStore>,
    policy: Arc<dyn PolicyStore>,
    guard: Guard,
}

impl MemberService {
    pub fn new(
        members: Arc<dyn MembershipStore>,
        identity: Arc<dyn IdentityStore>,
        policy: Arc<dyn PolicyStore>,
        guard: Guard,
    ) -> Self {
        Self {
            members,
            identity,
            policy,
            guard,
        }
    }

    /// The person's own vaults and roles, for their session.
    pub async fn vaults_of(&self, user: &UserId) -> Result<Vec<VaultGrant>, ControlError> {
        Ok(self.members.user_vaults(user).await?)
    }

    async fn vault(&self, id: &VaultId) -> Result<Vault, ControlError> {
        self.policy
            .get_vault(id)
            .await?
            .ok_or_else(|| ControlError::not_found("vault", id))
    }

    pub async fn list(
        &self,
        caller: &Caller,
        vault: &VaultId,
        page: PageRequest,
    ) -> Result<Page<VaultMember>, ControlError> {
        self.guard
            .check(caller, Action::VaultRead, Some(vault))
            .await?;
        self.vault(vault).await?;
        Ok(self.members.list_vault_members(vault, page).await?)
    }

    /// Adds an existing person to the vault, or changes their role there.
    /// Only instance admins invite new people.
    pub async fn put(
        &self,
        caller: &Caller,
        vault_id: &VaultId,
        req: PutMember,
    ) -> Result<VaultMember, ControlError> {
        self.guard
            .check(caller, Action::VaultMemberManage, Some(vault_id))
            .await?;
        check_vault_role(req.role)?;
        let vault = self.vault(vault_id).await?;
        let username = req.username.trim();
        let user = self
            .identity
            .get_user_by_username(username)
            .await?
            .ok_or_else(|| {
                ControlError::validation(format!(
                    "nobody is called '{username}' on this instance; an instance admin invites new people from People"
                ))
            })?;
        let previous = self.members.vault_role(vault_id, &user.id).await?;
        let member = VaultMember {
            vault_id: *vault_id,
            user_id: user.id,
            username: user.username.clone(),
            role: req.role,
            added_by: caller.actor().to_string(),
            added_at: Utc::now(),
        };
        let event = AuditEvent::new(caller.actor(), "vault.member.put", AuditOutcome::Success)
            .vault(*vault_id)
            .target(format!("vault:{vault_id}"))
            .detail("vault", vault.name.clone())
            .detail("user", format!("user:{}", user.id))
            .detail("username", user.username.clone())
            .detail("previous_role", previous.map_or("none", |r| r.as_str()))
            .detail("role", req.role.as_str());
        self.members
            .put_vault_member(member.clone(), &[event])
            .await
            .map_err(|e| last_admin(e, &vault, &user.username))?;
        info!(vault_id = %vault_id, user_id = %user.id, role = req.role.as_str(), "set vault member");
        Ok(member)
    }

    /// Removes a person from the vault. Anyone may leave a vault; removing
    /// someone else takes the vault's admin role.
    pub async fn remove(
        &self,
        caller: &Caller,
        vault_id: &VaultId,
        user_id: &UserId,
    ) -> Result<(), ControlError> {
        let leaving = caller.user_id().as_ref() == Some(user_id);
        let action = if leaving {
            Action::VaultRead
        } else {
            Action::VaultMemberManage
        };
        self.guard.check(caller, action, Some(vault_id)).await?;
        let vault = self.vault(vault_id).await?;
        let username = self
            .identity
            .get_user(user_id)
            .await?
            .map_or_else(|| user_id.to_string(), |u| u.username);
        let event = AuditEvent::new(caller.actor(), "vault.member.remove", AuditOutcome::Success)
            .vault(*vault_id)
            .target(format!("vault:{vault_id}"))
            .detail("vault", vault.name.clone())
            .detail("user", format!("user:{user_id}"))
            .detail("username", username.clone());
        let removed = self
            .members
            .remove_vault_member(vault_id, user_id, &[event])
            .await
            .map_err(|e| last_admin(e, &vault, &username))?;
        if !removed {
            return Err(ControlError::NotFound {
                entity: "vault member",
                id: format!("{username} in vault {}", vault.name),
            });
        }
        info!(vault_id = %vault_id, user_id = %user_id, "removed vault member");
        Ok(())
    }

    /// An instance admin makes themselves an admin of the vault. Recorded
    /// in the audit log, so the vault's members can see who stepped in.
    pub async fn join(
        &self,
        caller: &Caller,
        vault_id: &VaultId,
    ) -> Result<VaultMember, ControlError> {
        self.guard
            .check(caller, Action::VaultJoin, Some(vault_id))
            .await?;
        let vault = self.vault(vault_id).await?;
        let Some(user_id) = caller.user_id() else {
            return Err(ControlError::Forbidden {
                reason: format!(
                    "{} is not a person, so it cannot join a vault",
                    caller.actor()
                ),
            });
        };
        let user = self
            .identity
            .get_user(&user_id)
            .await?
            .ok_or_else(|| ControlError::not_found("user", user_id))?;
        let previous = self.members.vault_role(vault_id, &user_id).await?;
        if previous == Some(Role::Admin) {
            return Err(ControlError::Conflict {
                message: format!(
                    "{} is already an admin of vault {}",
                    user.username, vault.name
                ),
            });
        }
        let member = VaultMember {
            vault_id: *vault_id,
            user_id,
            username: user.username.clone(),
            role: Role::Admin,
            added_by: caller.actor().to_string(),
            added_at: Utc::now(),
        };
        let event = AuditEvent::new(caller.actor(), "vault.join", AuditOutcome::Success)
            .vault(*vault_id)
            .target(format!("vault:{vault_id}"))
            .detail("vault", vault.name.clone())
            .detail("username", user.username.clone())
            .detail("previous_role", previous.map_or("none", |r| r.as_str()));
        self.members
            .put_vault_member(member.clone(), &[event])
            .await?;
        info!(vault_id = %vault_id, user_id = %user_id, "instance admin joined vault");
        Ok(member)
    }
}

fn last_admin(error: StoreError, vault: &Vault, username: &str) -> ControlError {
    match error {
        StoreError::Conflict { .. } => ControlError::Conflict {
            message: format!(
                "{username} is the last admin of vault {}; make someone else its admin first",
                vault.name
            ),
        },
        StoreError::NotFound { entity, id } => ControlError::NotFound { entity, id },
        e => e.into(),
    }
}

#[cfg(test)]
mod tests;
