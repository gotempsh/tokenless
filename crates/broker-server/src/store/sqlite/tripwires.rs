// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! [`TripwireStore`] on SQLite (migration 0021).

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::sqlite::SqliteRow;
use tokenless_control::model::{Page, PageRequest, Tripwire};
use tokenless_control::store::TripwireStore;
use tokenless_control::StoreError;
use tokenless_core::audit::AuditEvent;
use tokenless_core::ids::{TripwireId, VaultId};
use tokenless_core::tripwire::TripwireKind;

use super::{db, finish, get, get_id, get_opt_ts, get_ts, to_i64, to_u64, ts, SqliteStore};

fn tripwire_from_row(row: &SqliteRow) -> Result<Tripwire, StoreError> {
    let kind: String = get(row, "kind")?;
    Ok(Tripwire {
        id: get_id(row, "id")?,
        vault_id: get_id(row, "vault_id")?,
        name: get(row, "name")?,
        kind: TripwireKind::parse(&kind).ok_or_else(|| {
            StoreError::backend("decode kind", format!("unknown tripwire kind '{kind}'"))
        })?,
        value: get(row, "value")?,
        prefix: get(row, "prefix")?,
        created_by: get(row, "created_by")?,
        created_at: get_ts(row, "created_at")?,
        last_tripped_at: get_opt_ts(row, "last_tripped_at")?,
    })
}

#[async_trait]
impl TripwireStore for SqliteStore {
    async fn insert_tripwire(&self, t: Tripwire, audit: &[AuditEvent]) -> Result<(), StoreError> {
        let mut tx = self.begin("insert_tripwire").await?;
        sqlx::query(
            "INSERT INTO tripwires (id, vault_id, name, kind, value, prefix, created_by, created_at, last_tripped_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)",
        )
        .bind(t.id.to_string())
        .bind(t.vault_id.to_string())
        .bind(&t.name)
        .bind(t.kind.as_str())
        .bind(&t.value)
        .bind(&t.prefix)
        .bind(&t.created_by)
        .bind(ts(&t.created_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| match db("insert tripwire", "tripwire")(e) {
            StoreError::Conflict { entity, .. } => StoreError::Conflict {
                entity,
                detail: format!(
                    "vault {} already has a tripwire named '{}'",
                    t.vault_id, t.name
                ),
            },
            other => other,
        })?;
        finish(tx, audit, "insert_tripwire").await
    }

    async fn get_tripwire(&self, id: &TripwireId) -> Result<Option<Tripwire>, StoreError> {
        sqlx::query("SELECT * FROM tripwires WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db("get tripwire", "tripwire"))?
            .as_ref()
            .map(tripwire_from_row)
            .transpose()
    }

    async fn list_tripwires(
        &self,
        vault_id: &VaultId,
        page: PageRequest,
    ) -> Result<Page<Tripwire>, StoreError> {
        let vault = vault_id.to_string();
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tripwires WHERE vault_id = ?")
            .bind(&vault)
            .fetch_one(&self.pool)
            .await
            .map_err(db("count tripwires", "tripwire"))?;
        let rows = sqlx::query(
            "SELECT * FROM tripwires WHERE vault_id = ? ORDER BY created_at DESC, id LIMIT ? OFFSET ?",
        )
        .bind(&vault)
        .bind(to_i64(page.page_size))
        .bind(to_i64(page.offset()))
        .fetch_all(&self.pool)
        .await
        .map_err(db("list tripwires", "tripwire"))?;
        Ok(Page {
            items: rows
                .iter()
                .map(tripwire_from_row)
                .collect::<Result<_, _>>()?,
            total: to_u64(total),
            page: page.page,
            page_size: page.page_size,
        })
    }

    async fn all_tripwires(&self, limit: u64) -> Result<Vec<Tripwire>, StoreError> {
        sqlx::query("SELECT * FROM tripwires ORDER BY created_at DESC, id LIMIT ?")
            .bind(to_i64(limit))
            .fetch_all(&self.pool)
            .await
            .map_err(db("list all tripwires", "tripwire"))?
            .iter()
            .map(tripwire_from_row)
            .collect()
    }

    async fn delete_tripwire(
        &self,
        id: &TripwireId,
        audit: &[AuditEvent],
    ) -> Result<bool, StoreError> {
        let mut tx = self.begin("delete_tripwire").await?;
        let removed = sqlx::query("DELETE FROM tripwires WHERE id = ?")
            .bind(id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db("delete tripwire", "tripwire"))?
            .rows_affected();
        if removed == 0 {
            return Ok(false);
        }
        finish(tx, audit, "delete_tripwire").await.map(|()| true)
    }

    async fn tripwire_tripped(&self, id: &TripwireId, at: DateTime<Utc>) -> Result<(), StoreError> {
        sqlx::query("UPDATE tripwires SET last_tripped_at = ? WHERE id = ?")
            .bind(ts(&at))
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(db("mark tripwire tripped", "tripwire"))?;
        Ok(())
    }
}
