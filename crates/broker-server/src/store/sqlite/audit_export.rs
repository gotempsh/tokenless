// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! [`AuditExportStore`] on SQLite: destinations, their delivery state, and
//! the audit log read by sequence number (migration 0017).

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::sqlite::SqliteRow;
use tokenless_control::model::{AuditDestination, DeliveryState, PayloadFormat};
use tokenless_control::store::AuditExportStore;
use tokenless_control::StoreError;
use tokenless_core::audit::AuditEvent;
use tokenless_core::ids::AuditDestinationId;

use super::{
    audit_from_row, db, finish, from_json, get, get_id, get_opt_ts, get_ts, opt_ts, to_i64,
    to_json, to_u64, ts, SqliteStore,
};

const COLUMNS: &str = "id, name, url, format, auth_header_name, auth_header_value_enc, signing_secret_enc, filter, paused, created_at, updated_at, cursor, last_success_at, last_attempt_at, failing_since, last_error, consecutive_failures, retry_until";

fn destination_from_row(row: &SqliteRow) -> Result<AuditDestination, StoreError> {
    let format: String = get(row, "format")?;
    Ok(AuditDestination {
        id: get_id(row, "id")?,
        name: get(row, "name")?,
        url: get(row, "url")?,
        format: PayloadFormat::parse(&format).ok_or_else(|| {
            StoreError::backend("decode format", format!("unknown format '{format}'"))
        })?,
        auth_header_name: get(row, "auth_header_name")?,
        auth_header_value_enc: get(row, "auth_header_value_enc")?,
        signing_secret_enc: get(row, "signing_secret_enc")?,
        filter: from_json("filter", &get::<String>(row, "filter")?)?,
        paused: get::<i64>(row, "paused")? != 0,
        created_at: get_ts(row, "created_at")?,
        updated_at: get_ts(row, "updated_at")?,
        delivery: DeliveryState {
            cursor: to_u64(get(row, "cursor")?),
            last_success_at: get_opt_ts(row, "last_success_at")?,
            last_attempt_at: get_opt_ts(row, "last_attempt_at")?,
            failing_since: get_opt_ts(row, "failing_since")?,
            last_error: get(row, "last_error")?,
            consecutive_failures: u32::try_from(get::<i64>(row, "consecutive_failures")?)
                .unwrap_or(u32::MAX),
            retry_until: get::<Option<i64>>(row, "retry_until")?.map(to_u64),
        },
    })
}

fn missing(id: &AuditDestinationId) -> StoreError {
    StoreError::not_found("audit_destination", id)
}

#[async_trait]
impl AuditExportStore for SqliteStore {
    async fn insert_audit_destination(
        &self,
        d: AuditDestination,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut tx = self.begin("insert_audit_destination").await?;
        sqlx::query(&format!(
            "INSERT INTO audit_destinations ({COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        ))
        .bind(d.id.to_string())
        .bind(&d.name)
        .bind(&d.url)
        .bind(d.format.as_str())
        .bind(&d.auth_header_name)
        .bind(&d.auth_header_value_enc)
        .bind(&d.signing_secret_enc)
        .bind(to_json("filter", &d.filter)?)
        .bind(i64::from(d.paused))
        .bind(ts(&d.created_at))
        .bind(ts(&d.updated_at))
        .bind(to_i64(d.delivery.cursor))
        .bind(opt_ts(&d.delivery.last_success_at))
        .bind(opt_ts(&d.delivery.last_attempt_at))
        .bind(opt_ts(&d.delivery.failing_since))
        .bind(&d.delivery.last_error)
        .bind(i64::from(d.delivery.consecutive_failures))
        .bind(d.delivery.retry_until.map(to_i64))
        .execute(&mut *tx)
        .await
        .map_err(db("insert audit destination", "audit_destination"))?;
        finish(tx, audit, "insert_audit_destination").await
    }

    async fn get_audit_destination(
        &self,
        id: &AuditDestinationId,
    ) -> Result<Option<AuditDestination>, StoreError> {
        sqlx::query(&format!(
            "SELECT {COLUMNS} FROM audit_destinations WHERE id = ?"
        ))
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(db("get audit destination", "audit_destination"))?
        .map(|row| destination_from_row(&row))
        .transpose()
    }

    async fn list_audit_destinations(&self) -> Result<Vec<AuditDestination>, StoreError> {
        sqlx::query(&format!(
            "SELECT {COLUMNS} FROM audit_destinations ORDER BY created_at, id"
        ))
        .fetch_all(&self.pool)
        .await
        .map_err(db("list audit destinations", "audit_destination"))?
        .iter()
        .map(destination_from_row)
        .collect()
    }

    async fn update_audit_destination(
        &self,
        d: AuditDestination,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut tx = self.begin("update_audit_destination").await?;
        let result = sqlx::query(
            "UPDATE audit_destinations SET name = ?, url = ?, format = ?, auth_header_name = ?, auth_header_value_enc = ?, signing_secret_enc = ?, filter = ?, paused = ?, updated_at = ?, retry_until = NULL WHERE id = ?",
        )
        .bind(&d.name)
        .bind(&d.url)
        .bind(d.format.as_str())
        .bind(&d.auth_header_name)
        .bind(&d.auth_header_value_enc)
        .bind(&d.signing_secret_enc)
        .bind(to_json("filter", &d.filter)?)
        .bind(i64::from(d.paused))
        .bind(ts(&d.updated_at))
        .bind(d.id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(db("update audit destination", "audit_destination"))?;
        if result.rows_affected() == 0 {
            return Err(missing(&d.id));
        }
        finish(tx, audit, "update_audit_destination").await
    }

    async fn delete_audit_destination(
        &self,
        id: &AuditDestinationId,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut tx = self.begin("delete_audit_destination").await?;
        let result = sqlx::query("DELETE FROM audit_destinations WHERE id = ?")
            .bind(id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db("delete audit destination", "audit_destination"))?;
        if result.rows_affected() == 0 {
            return Err(missing(id));
        }
        finish(tx, audit, "delete_audit_destination").await
    }

    async fn latest_audit_seq(&self) -> Result<u64, StoreError> {
        let row = sqlx::query("SELECT COALESCE(MAX(seq), 0) AS seq FROM audit_events")
            .fetch_one(&self.pool)
            .await
            .map_err(db("read latest audit sequence", "audit"))?;
        Ok(to_u64(get(&row, "seq")?))
    }

    async fn audit_events_after(
        &self,
        after: u64,
        limit: usize,
    ) -> Result<Vec<(u64, AuditEvent)>, StoreError> {
        let rows = sqlx::query(
            "SELECT seq, id, at, actor, action, outcome, vault_id, target, detail FROM audit_events WHERE seq > ? ORDER BY seq LIMIT ?",
        )
        .bind(to_i64(after))
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .fetch_all(&self.pool)
        .await
        .map_err(db("read audit events after a sequence number", "audit"))?;
        rows.iter()
            .map(|row| Ok((to_u64(get(row, "seq")?), audit_from_row(row)?)))
            .collect()
    }

    async fn advance_audit_cursor(
        &self,
        id: &AuditDestinationId,
        from: u64,
        to: u64,
        at: DateTime<Utc>,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE audit_destinations SET cursor = ?, last_success_at = ?, last_attempt_at = ?, failing_since = NULL, last_error = NULL, consecutive_failures = 0, retry_until = NULL WHERE id = ? AND cursor = ?",
        )
        .bind(to_i64(to))
        .bind(ts(&at))
        .bind(ts(&at))
        .bind(id.to_string())
        .bind(to_i64(from))
        .execute(&self.pool)
        .await
        .map_err(db("advance audit cursor", "audit_destination"))?;
        Ok(result.rows_affected() == 1)
    }

    async fn record_audit_delivery_failure(
        &self,
        id: &AuditDestinationId,
        from: u64,
        to: u64,
        error: &str,
        at: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE audit_destinations SET last_attempt_at = ?, failing_since = COALESCE(failing_since, ?), last_error = ?, consecutive_failures = consecutive_failures + 1, retry_until = CASE WHEN cursor = ? THEN ? ELSE retry_until END WHERE id = ?",
        )
        .bind(ts(&at))
        .bind(ts(&at))
        .bind(error)
        .bind(to_i64(from))
        .bind(to_i64(to))
        .bind(id.to_string())
        .execute(&self.pool)
        .await
        .map_err(db("record audit delivery failure", "audit_destination"))?;
        Ok(())
    }

    async fn set_audit_cursor(
        &self,
        id: &AuditDestinationId,
        to: u64,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut tx = self.begin("set_audit_cursor").await?;
        let result = sqlx::query(
            "UPDATE audit_destinations SET cursor = ?, failing_since = NULL, last_error = NULL, consecutive_failures = 0, retry_until = NULL WHERE id = ?",
        )
        .bind(to_i64(to))
        .bind(id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(db("set audit cursor", "audit_destination"))?;
        if result.rows_affected() == 0 {
            return Err(missing(id));
        }
        finish(tx, audit, "set_audit_cursor").await
    }
}
