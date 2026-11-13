// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use async_trait::async_trait;
use tokenless_core::audit::AuditEvent;
use tokenless_core::authz::Role;
use tokenless_core::ids::{UserId, VaultId};

use super::{Inner, MemoryStore};
use crate::error::StoreError;
use crate::model::{Page, PageRequest, Vault, VaultGrant, VaultMember};
use crate::store::MembershipStore;

/// Whether the vault would still have an admin with `user` given `role`
/// (`None`: removed).
fn keeps_an_admin(inner: &Inner, vault: &VaultId, user: &UserId, role: Option<Role>) -> bool {
    let was_admin = inner
        .members
        .get(&(*vault, *user))
        .is_some_and(|m| m.role == Role::Admin);
    if !was_admin || role == Some(Role::Admin) {
        return true;
    }
    inner
        .members
        .values()
        .any(|m| &m.vault_id == vault && &m.user_id != user && m.role == Role::Admin)
}

#[async_trait]
impl MembershipStore for MemoryStore {
    async fn vault_role(&self, vault: &VaultId, user: &UserId) -> Result<Option<Role>, StoreError> {
        Ok(self.lock()?.members.get(&(*vault, *user)).map(|m| m.role))
    }

    async fn vault_member(
        &self,
        vault: &VaultId,
        user: &UserId,
    ) -> Result<Option<VaultMember>, StoreError> {
        let inner = self.lock()?;
        Ok(inner.members.get(&(*vault, *user)).map(|m| VaultMember {
            username: inner
                .users
                .get(&m.user_id)
                .map_or_else(|| m.username.clone(), |u| u.username.clone()),
            ..m.clone()
        }))
    }

    async fn user_vaults(&self, user: &UserId) -> Result<Vec<VaultGrant>, StoreError> {
        let mut grants: Vec<_> = self
            .lock()?
            .members
            .values()
            .filter(|m| &m.user_id == user)
            .map(|m| VaultGrant {
                vault_id: m.vault_id,
                role: m.role,
            })
            .collect();
        grants.sort_by_key(|g| g.vault_id.to_string());
        Ok(grants)
    }

    async fn list_vault_members(
        &self,
        vault: &VaultId,
        page: PageRequest,
    ) -> Result<Page<VaultMember>, StoreError> {
        let inner = self.lock()?;
        let mut items: Vec<_> = inner
            .members
            .values()
            .filter(|m| &m.vault_id == vault)
            .map(|m| VaultMember {
                username: inner
                    .users
                    .get(&m.user_id)
                    .map_or_else(|| m.username.clone(), |u| u.username.clone()),
                ..m.clone()
            })
            .collect();
        items.sort_by(|a, b| a.username.cmp(&b.username));
        Ok(page.apply(&items))
    }

    async fn put_vault_member(
        &self,
        member: VaultMember,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        if !inner.vaults.contains_key(&member.vault_id) {
            return Err(StoreError::not_found("vault", member.vault_id));
        }
        if !inner.users.contains_key(&member.user_id) {
            return Err(StoreError::not_found("user", member.user_id));
        }
        if !keeps_an_admin(&inner, &member.vault_id, &member.user_id, Some(member.role)) {
            return Err(StoreError::Conflict {
                entity: "vault member",
                detail: format!(
                    "user {} is the last admin of vault {}",
                    member.user_id, member.vault_id
                ),
            });
        }
        inner
            .members
            .insert((member.vault_id, member.user_id), member);
        inner.audit.extend_from_slice(audit);
        Ok(())
    }

    async fn remove_vault_member(
        &self,
        vault: &VaultId,
        user: &UserId,
        audit: &[AuditEvent],
    ) -> Result<bool, StoreError> {
        let mut inner = self.lock()?;
        if !inner.members.contains_key(&(*vault, *user)) {
            return Ok(false);
        }
        if !keeps_an_admin(&inner, vault, user, None) {
            return Err(StoreError::Conflict {
                entity: "vault member",
                detail: format!("user {user} is the last admin of vault {vault}"),
            });
        }
        inner.members.remove(&(*vault, *user));
        inner.audit.extend_from_slice(audit);
        Ok(true)
    }

    async fn insert_vault_with_admin(
        &self,
        vault: Vault,
        creator: VaultMember,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        if inner.vaults.values().any(|v| v.name == vault.name) {
            return Err(StoreError::Conflict {
                entity: "vault",
                detail: format!("name '{}' exists", vault.name),
            });
        }
        if !inner.users.contains_key(&creator.user_id) {
            return Err(StoreError::not_found("user", creator.user_id));
        }
        let member = VaultMember {
            vault_id: vault.id,
            role: Role::Admin,
            ..creator
        };
        inner.members.insert((vault.id, member.user_id), member);
        inner.vaults.insert(vault.id, vault);
        inner.audit.extend_from_slice(audit);
        Ok(())
    }
}
