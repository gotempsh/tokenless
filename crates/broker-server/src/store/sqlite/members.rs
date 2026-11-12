// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use async_trait::async_trait;
use sqlx::sqlite::SqliteRow;
use sqlx::{Sqlite, Transaction};
use tokenless_control::model::{Page, PageRequest, Vault, VaultGrant, VaultMember};
use tokenless_control::store::MembershipStore;
use tokenless_control::StoreError;
use tokenless_core::audit::AuditEvent;
use tokenless_core::authz::Role;
use tokenless_core::ids::{UserId, VaultId};

use super::{db, exists_tx, finish, get, get_id, get_ts, role, to_i64, ts, SqliteStore};

fn member_from_row(row: &SqliteRow) -> Result<VaultMember, StoreError> {
    Ok(VaultMember {
        vault_id: get_id(row, "vault_id")?,
        user_id: get_id(row, "user_id")?,
        username: get(row, "username")?,
        role: role(row)?,
        added_by: get(row, "added_by")?,
        added_at: get_ts(row, "added_at")?,
    })
}

/// Whether the vault keeps an admin once `user` holds `role` there
/// (`None`: removed).
async fn keeps_an_admin(
    tx: &mut Transaction<'static, Sqlite>,
    vault: &VaultId,
    user: &UserId,
    role: Option<Role>,
) -> Result<bool, StoreError> {
    if role == Some(Role::Admin) {
        return Ok(true);
    }
    let row = sqlx::query(
        "SELECT \
            EXISTS (SELECT 1 FROM vault_members WHERE vault_id = ? AND user_id = ? AND role = 'admin') AS was_admin, \
            EXISTS (SELECT 1 FROM vault_members WHERE vault_id = ? AND user_id <> ? AND role = 'admin') AS other_admin",
    )
    .bind(vault.to_string())
    .bind(user.to_string())
    .bind(vault.to_string())
    .bind(user.to_string())
    .fetch_one(&mut **tx)
    .await
    .map_err(db("count vault admins", "vault_member"))?;
    Ok(get::<i64>(&row, "was_admin")? == 0 || get::<i64>(&row, "other_admin")? == 1)
}

fn last_admin(vault: &VaultId, user: &UserId) -> StoreError {
    StoreError::Conflict {
        entity: "vault member",
        detail: format!("user {user} is the last admin of vault {vault}"),
    }
}

async fn put_member_tx(
    tx: &mut Transaction<'static, Sqlite>,
    m: &VaultMember,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO vault_members (vault_id, user_id, role, added_by, added_at) VALUES (?, ?, ?, ?, ?) \
         ON CONFLICT (vault_id, user_id) DO UPDATE SET role = excluded.role, added_by = excluded.added_by, added_at = excluded.added_at",
    )
    .bind(m.vault_id.to_string())
    .bind(m.user_id.to_string())
    .bind(m.role.as_str())
    .bind(&m.added_by)
    .bind(ts(&m.added_at))
    .execute(&mut **tx)
    .await
    .map_err(db("put vault member", "vault_member"))?;
    Ok(())
}

#[async_trait]
impl MembershipStore for SqliteStore {
    async fn vault_role(&self, vault: &VaultId, user: &UserId) -> Result<Option<Role>, StoreError> {
        sqlx::query("SELECT role FROM vault_members WHERE vault_id = ? AND user_id = ?")
            .bind(vault.to_string())
            .bind(user.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db("get vault role", "vault_member"))?
            .as_ref()
            .map(role)
            .transpose()
    }

    async fn vault_member(
        &self,
        vault: &VaultId,
        user: &UserId,
    ) -> Result<Option<VaultMember>, StoreError> {
        sqlx::query(
            "SELECT m.vault_id, m.user_id, u.username, m.role, m.added_by, m.added_at \
             FROM vault_members m JOIN users u ON u.id = m.user_id \
             WHERE m.vault_id = ? AND m.user_id = ?",
        )
        .bind(vault.to_string())
        .bind(user.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(db("get vault member", "vault_member"))?
        .as_ref()
        .map(member_from_row)
        .transpose()
    }

    async fn user_vaults(&self, user: &UserId) -> Result<Vec<VaultGrant>, StoreError> {
        sqlx::query("SELECT vault_id, role FROM vault_members WHERE user_id = ? ORDER BY vault_id")
            .bind(user.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(db("list user vaults", "vault_member"))?
            .iter()
            .map(|r| {
                Ok(VaultGrant {
                    vault_id: get_id(r, "vault_id")?,
                    role: role(r)?,
                })
            })
            .collect()
    }

    async fn list_vault_members(
        &self,
        vault: &VaultId,
        page: PageRequest,
    ) -> Result<Page<VaultMember>, StoreError> {
        let total = self
            .count(
                "SELECT COUNT(*) AS n FROM vault_members WHERE vault_id = ?",
                Some(&vault.to_string()),
            )
            .await?;
        let rows = sqlx::query(
            "SELECT m.vault_id, m.user_id, u.username, m.role, m.added_by, m.added_at \
             FROM vault_members m JOIN users u ON u.id = m.user_id \
             WHERE m.vault_id = ? ORDER BY u.username LIMIT ? OFFSET ?",
        )
        .bind(vault.to_string())
        .bind(to_i64(page.page_size))
        .bind(to_i64(page.offset()))
        .fetch_all(&self.pool)
        .await
        .map_err(db("list vault members", "vault_member"))?;
        Ok(Page {
            items: rows.iter().map(member_from_row).collect::<Result<_, _>>()?,
            total,
            page: page.page,
            page_size: page.page_size,
        })
    }

    async fn put_vault_member(
        &self,
        member: VaultMember,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut tx = self.begin("put_vault_member").await?;
        if !exists_tx(&mut tx, "vaults", &member.vault_id.to_string()).await? {
            return Err(StoreError::not_found("vault", member.vault_id));
        }
        if !exists_tx(&mut tx, "users", &member.user_id.to_string()).await? {
            return Err(StoreError::not_found("user", member.user_id));
        }
        if !keeps_an_admin(
            &mut tx,
            &member.vault_id,
            &member.user_id,
            Some(member.role),
        )
        .await?
        {
            return Err(last_admin(&member.vault_id, &member.user_id));
        }
        put_member_tx(&mut tx, &member).await?;
        finish(tx, audit, "put_vault_member").await
    }

    async fn remove_vault_member(
        &self,
        vault: &VaultId,
        user: &UserId,
        audit: &[AuditEvent],
    ) -> Result<bool, StoreError> {
        let mut tx = self.begin("remove_vault_member").await?;
        if !keeps_an_admin(&mut tx, vault, user, None).await? {
            return Err(last_admin(vault, user));
        }
        let removed = sqlx::query("DELETE FROM vault_members WHERE vault_id = ? AND user_id = ?")
            .bind(vault.to_string())
            .bind(user.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db("remove vault member", "vault_member"))?
            .rows_affected();
        if removed == 0 {
            return Ok(false);
        }
        finish(tx, audit, "remove_vault_member")
            .await
            .map(|()| true)
    }

    async fn insert_vault_with_admin(
        &self,
        vault: Vault,
        creator: VaultMember,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut tx = self.begin("insert_vault_with_admin").await?;
        if !exists_tx(&mut tx, "users", &creator.user_id.to_string()).await? {
            return Err(StoreError::not_found("user", creator.user_id));
        }
        sqlx::query("INSERT INTO vaults (id, name, scope, created_at) VALUES (?, ?, ?, ?)")
            .bind(vault.id.to_string())
            .bind(&vault.name)
            .bind(vault.scope.to_string())
            .bind(ts(&vault.created_at))
            .execute(&mut *tx)
            .await
            .map_err(db("insert vault", "vault"))?;
        put_member_tx(
            &mut tx,
            &VaultMember {
                vault_id: vault.id,
                role: Role::Admin,
                ..creator
            },
        )
        .await?;
        finish(tx, audit, "insert_vault_with_admin").await
    }
}
