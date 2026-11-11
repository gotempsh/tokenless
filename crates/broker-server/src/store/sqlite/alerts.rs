// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! [`AlertStore`] on SQLite (migration 0020).

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::sqlite::SqliteRow;
use tokenless_control::model::{Alert, AlertFilter, AlertKind, Page, PageRequest};
use tokenless_control::store::AlertStore;
use tokenless_control::StoreError;
use tokenless_core::audit::AuditEvent;
use tokenless_core::ids::AlertId;

use super::{
    db, finish, from_json, get, get_id, get_opt_id, get_opt_ts, get_ts, opt_ts, to_i64, to_json,
    to_u64, ts, SqliteStore,
};

fn alert_from_row(row: &SqliteRow) -> Result<Alert, StoreError> {
    let kind: String = get(row, "kind")?;
    Ok(Alert {
        id: get_id(row, "id")?,
        kind: AlertKind::parse(&kind).ok_or_else(|| {
            StoreError::backend("decode kind", format!("unknown alert kind '{kind}'"))
        })?,
        dedup_key: get(row, "dedup_key")?,
        summary: get(row, "summary")?,
        vault_id: get_opt_id(row, "vault_id")?,
        session_id: get_opt_id(row, "session_id")?,
        node_id: get_opt_id(row, "node_id")?,
        detail: from_json("detail", &get::<String>(row, "detail")?)?,
        raised_at: get_ts(row, "raised_at")?,
        acknowledged_at: get_opt_ts(row, "acknowledged_at")?,
        acknowledged_by: get(row, "acknowledged_by")?,
    })
}

const FILTER: &str = "FROM alerts WHERE (? = 0 OR acknowledged_at IS NULL) AND (? IS NULL OR vault_id = ?) AND (? IS NULL OR session_id = ?) AND (? IS NULL OR kind = ?)";

#[async_trait]
impl AlertStore for SqliteStore {
    async fn insert_alert(&self, a: Alert, audit: &[AuditEvent]) -> Result<bool, StoreError> {
        let mut tx = self.begin("insert_alert").await?;
        let result = sqlx::query(
            "INSERT INTO alerts (id, kind, dedup_key, summary, vault_id, session_id, node_id, detail, raised_at, acknowledged_at, acknowledged_by) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(dedup_key) DO NOTHING",
        )
        .bind(a.id.to_string())
        .bind(a.kind.as_str())
        .bind(&a.dedup_key)
        .bind(&a.summary)
        .bind(a.vault_id.map(|v| v.to_string()))
        .bind(a.session_id.map(|s| s.to_string()))
        .bind(a.node_id.map(|n| n.to_string()))
        .bind(to_json("detail", &a.detail)?)
        .bind(ts(&a.raised_at))
        .bind(opt_ts(&a.acknowledged_at))
        .bind(&a.acknowledged_by)
        .execute(&mut *tx)
        .await
        .map_err(db("insert alert", "alert"))?;
        if result.rows_affected() == 0 {
            return Ok(false);
        }
        finish(tx, audit, "insert_alert").await.map(|()| true)
    }

    async fn get_alert(&self, id: &AlertId) -> Result<Option<Alert>, StoreError> {
        sqlx::query("SELECT * FROM alerts WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db("get alert", "alert"))?
            .as_ref()
            .map(alert_from_row)
            .transpose()
    }

    async fn list_alerts(
        &self,
        filter: &AlertFilter,
        page: PageRequest,
    ) -> Result<Page<Alert>, StoreError> {
        let open = i64::from(filter.open_only);
        let vault = filter.vault_id.map(|v| v.to_string());
        let session = filter.session_id.map(|s| s.to_string());
        let kind = filter.kind.map(AlertKind::as_str);
        let total: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) {FILTER}"))
            .bind(open)
            .bind(&vault)
            .bind(&vault)
            .bind(&session)
            .bind(&session)
            .bind(kind)
            .bind(kind)
            .fetch_one(&self.pool)
            .await
            .map_err(db("count alerts", "alert"))?;
        let rows = sqlx::query(&format!(
            "SELECT * {FILTER} ORDER BY raised_at DESC, id LIMIT ? OFFSET ?"
        ))
        .bind(open)
        .bind(&vault)
        .bind(&vault)
        .bind(&session)
        .bind(&session)
        .bind(kind)
        .bind(kind)
        .bind(to_i64(page.page_size))
        .bind(to_i64(page.offset()))
        .fetch_all(&self.pool)
        .await
        .map_err(db("list alerts", "alert"))?;
        Ok(Page {
            items: rows.iter().map(alert_from_row).collect::<Result<_, _>>()?,
            total: to_u64(total),
            page: page.page,
            page_size: page.page_size,
        })
    }

    async fn acknowledge_alert(
        &self,
        id: &AlertId,
        by: &str,
        at: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<bool, StoreError> {
        let mut tx = self.begin("acknowledge_alert").await?;
        let result = sqlx::query(
            "UPDATE alerts SET acknowledged_at = ?, acknowledged_by = ? WHERE id = ? AND acknowledged_at IS NULL",
        )
        .bind(ts(&at))
        .bind(by)
        .bind(id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(db("acknowledge alert", "alert"))?;
        if result.rows_affected() == 1 {
            return finish(tx, audit, "acknowledge_alert").await.map(|()| true);
        }
        let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM alerts WHERE id = ?")
            .bind(id.to_string())
            .fetch_one(&mut *tx)
            .await
            .map_err(db("find alert", "alert"))?;
        if exists == 0 {
            return Err(StoreError::not_found("alert", id));
        }
        Ok(false)
    }
}
