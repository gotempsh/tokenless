// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SQLite implementation of every store trait.
//!
//! Queries are plain SQL with bound parameters and no SQLite-only syntax
//! beyond `ON CONFLICT DO NOTHING` and `RETURNING`, both of which PostgreSQL
//! shares, so a Postgres store can reuse them with `$n` placeholders.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow, SqliteSynchronous,
};
use sqlx::{Row, Sqlite, SqlitePool, Transaction};
use tokenless_control::model::{
    AccessBundle, ApiKey, AuditQuery, CredentialMeta, Invite, JoinTokenRecord, Node, Page,
    PageRequest, ProxySession, Rule, SessionBundle, Settings, SsoIdentity, StoredTemplate,
    TemplateSource, TemplateStatus, UiSession, User, Variable, Vault, VaultDeletion,
};
use tokenless_control::store::{
    AuditSink, CiphertextOwner, CredentialStore, IdentityStore, NewSecret, NodeStore, PolicyStore,
    SecretReplaced, StoredCiphertext,
};
use tokenless_control::StoreError;
use tokenless_core::audit::{AuditEvent, AuditOutcome};
use tokenless_core::authz::Role;
use tokenless_core::ids::{
    ApiKeyId, BundleId, CredentialId, InviteId, NodeId, OidcProviderId, RuleId, SessionId, UserId,
    VariableId, VaultId,
};
use tokenless_core::session::open_traffic_horizon;
use tokenless_core::substitution::Substitution;
use tokenless_core::template::ServiceTemplate;
use tokenless_core::variables::CustomHeader;

mod sso;

pub struct SqliteStore {
    pool: SqlitePool,
}

fn ts(dt: &DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(SecondsFormat::Micros, true)
}

fn opt_ts(dt: &Option<DateTime<Utc>>) -> Option<String> {
    dt.as_ref().map(ts)
}

fn parse_ts(column: &str, value: &str) -> Result<DateTime<Utc>, StoreError> {
    DateTime::parse_from_rfc3339(value)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| StoreError::backend(&format!("decode {column}"), format!("'{value}': {e}")))
}

fn to_json<T: Serialize>(column: &str, value: &T) -> Result<String, StoreError> {
    serde_json::to_string(value).map_err(|e| StoreError::backend(&format!("encode {column}"), e))
}

fn from_json<T: DeserializeOwned>(column: &str, value: &str) -> Result<T, StoreError> {
    serde_json::from_str(value).map_err(|e| StoreError::backend(&format!("decode {column}"), e))
}

fn to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn to_u64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

fn db(operation: &'static str, entity: &'static str) -> impl Fn(sqlx::Error) -> StoreError {
    move |e| match &e {
        sqlx::Error::Database(d) if d.is_unique_violation() => StoreError::Conflict {
            entity,
            detail: d.message().to_string(),
        },
        _ => StoreError::backend(operation, e),
    }
}

fn get<T>(row: &SqliteRow, column: &str) -> Result<T, StoreError>
where
    T: for<'r> sqlx::Decode<'r, sqlx::Sqlite> + sqlx::Type<sqlx::Sqlite>,
{
    row.try_get(column)
        .map_err(|e| StoreError::backend(&format!("read column {column}"), e))
}

fn get_ts(row: &SqliteRow, column: &str) -> Result<DateTime<Utc>, StoreError> {
    parse_ts(column, &get::<String>(row, column)?)
}

fn get_opt_ts(row: &SqliteRow, column: &str) -> Result<Option<DateTime<Utc>>, StoreError> {
    get::<Option<String>>(row, column)?
        .map(|v| parse_ts(column, &v))
        .transpose()
}

fn get_id<T: FromStr>(row: &SqliteRow, column: &str) -> Result<T, StoreError>
where
    T::Err: std::fmt::Display,
{
    let raw: String = get(row, column)?;
    raw.parse().map_err(|e: T::Err| {
        StoreError::backend(&format!("decode {column}"), format!("'{raw}': {e}"))
    })
}

fn get_opt_id<T: FromStr>(row: &SqliteRow, column: &str) -> Result<Option<T>, StoreError>
where
    T::Err: std::fmt::Display,
{
    get::<Option<String>>(row, column)?
        .map(|raw| {
            raw.parse().map_err(|e: T::Err| {
                StoreError::backend(&format!("decode {column}"), format!("'{raw}': {e}"))
            })
        })
        .transpose()
}

fn role(row: &SqliteRow) -> Result<Role, StoreError> {
    let raw: String = get(row, "role")?;
    Role::parse(&raw)
        .ok_or_else(|| StoreError::backend("decode role", format!("unknown role '{raw}'")))
}

impl SqliteStore {
    /// Opens (creating if needed) the database and applies migrations.
    pub async fn connect(url: &str) -> Result<Self, StoreError> {
        let options = SqliteConnectOptions::from_str(url)
            .map_err(|e| StoreError::backend("parse database url", e))?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(Duration::from_secs(5))
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(10))
            .connect_with(options)
            .await
            .map_err(|e| StoreError::backend("open database", e))?;
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(|e| StoreError::backend("run migrations", e))?;
        Ok(Self { pool })
    }

    async fn count(&self, sql: &str, bind: Option<&str>) -> Result<u64, StoreError> {
        let mut q = sqlx::query(sql);
        if let Some(b) = bind {
            q = q.bind(b.to_string());
        }
        let row = q.fetch_one(&self.pool).await.map_err(db("count", "row"))?;
        Ok(to_u64(get::<i64>(&row, "n")?))
    }

    /// Starts a write transaction. IMMEDIATE takes the write lock up front, so
    /// a writer that finds another one busy waits out `busy_timeout`; a
    /// deferred transaction that reads first and writes later fails at once
    /// with "database is locked" when another write lands in between.
    async fn begin(
        &self,
        operation: &'static str,
    ) -> Result<Transaction<'static, Sqlite>, StoreError> {
        self.pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|e| StoreError::backend(&format!("begin {operation}"), e))
    }

    async fn exists(&self, table: &'static str, id: &str) -> Result<bool, StoreError> {
        let sql = format!("SELECT COUNT(*) AS n FROM {table} WHERE id = ?");
        Ok(self.count(&sql, Some(id)).await? > 0)
    }
}

async fn exists_tx(
    tx: &mut Transaction<'static, Sqlite>,
    table: &'static str,
    id: &str,
) -> Result<bool, StoreError> {
    let sql = format!("SELECT COUNT(*) AS n FROM {table} WHERE id = ?");
    let row = sqlx::query(&sql)
        .bind(id.to_string())
        .fetch_one(&mut **tx)
        .await
        .map_err(db("count", "row"))?;
    Ok(get::<i64>(&row, "n")? > 0)
}

async fn write_audit(
    tx: &mut Transaction<'static, Sqlite>,
    events: &[AuditEvent],
) -> Result<(), StoreError> {
    for e in events {
        sqlx::query("INSERT INTO audit_events (id, at, actor, action, outcome, vault_id, target, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(e.id.to_string())
            .bind(ts(&e.at))
            .bind(&e.actor)
            .bind(&e.action)
            .bind(e.outcome.as_str())
            .bind(e.vault_id.map(|v| v.to_string()))
            .bind(&e.target)
            .bind(to_json("detail", &e.detail)?)
            .execute(&mut **tx)
            .await
            .map_err(db("insert audit event", "audit"))?;
    }
    Ok(())
}

/// Writes the change's audit events in its transaction and commits both.
async fn finish(
    mut tx: Transaction<'static, Sqlite>,
    audit: &[AuditEvent],
    operation: &'static str,
) -> Result<(), StoreError> {
    write_audit(&mut tx, audit).await?;
    tx.commit()
        .await
        .map_err(|e| StoreError::backend(&format!("commit {operation}"), e))
}

fn generation_i64(generation: u64) -> Result<i64, StoreError> {
    i64::try_from(generation)
        .map_err(|_| StoreError::backend("store credential generation", "beyond i64"))
}

fn credential_from_row(row: &SqliteRow) -> Result<CredentialMeta, StoreError> {
    Ok(CredentialMeta {
        id: get_id(row, "id")?,
        vault_id: get_id(row, "vault_id")?,
        name: get(row, "name")?,
        template_id: get(row, "template_id")?,
        template_version: u32::try_from(get::<i64>(row, "template_version")?).unwrap_or(0),
        host_override: from_json("host_override", &get::<String>(row, "host_override")?)?,
        field_names: from_json("field_names", &get::<String>(row, "field_names")?)?,
        custom_headers: from_json("custom_headers", &get::<String>(row, "custom_headers")?)?,
        variable_refs: from_json("variable_refs", &get::<String>(row, "variable_refs")?)?,
        substitutions: from_json("substitutions", &get::<String>(row, "substitutions")?)?,
        not_after: get_opt_ts(row, "not_after")?,
        secret_generation: u64::try_from(get::<i64>(row, "secret_generation")?).unwrap_or(0),
        rotation_id: get(row, "rotation_id")?,
        created_by: get(row, "created_by")?,
        created_at: get_ts(row, "created_at")?,
        updated_at: get_ts(row, "updated_at")?,
    })
}

const CREDENTIAL_COLUMNS: &str = "id, vault_id, name, template_id, template_version, host_override, field_names, custom_headers, variable_refs, substitutions, not_after, secret_generation, rotation_id, created_by, created_at, updated_at";

fn variable_from_row(row: &SqliteRow) -> Result<Variable, StoreError> {
    Ok(Variable {
        id: get_id(row, "id")?,
        key: get(row, "key")?,
        created_by: get(row, "created_by")?,
        created_at: get_ts(row, "created_at")?,
        updated_by: get(row, "updated_by")?,
        updated_at: get_ts(row, "updated_at")?,
    })
}

const VARIABLE_COLUMNS: &str = "id, key, created_by, created_at, updated_by, updated_at";

/// `?, ?, ...` for an `IN` list of `n` values (at least one).
fn placeholders(n: usize) -> String {
    vec!["?"; n.max(1)].join(", ")
}

#[async_trait]
impl CredentialStore for SqliteStore {
    async fn insert_credential(
        &self,
        meta: CredentialMeta,
        ciphertext: Vec<u8>,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut tx = self.begin("insert_credential").await?;
        sqlx::query(
            "INSERT INTO credentials (id, vault_id, name, template_id, template_version, host_override, field_names, custom_headers, variable_refs, substitutions, not_after, secret_generation, rotation_id, created_by, created_at, updated_at, secret) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(meta.id.to_string())
        .bind(meta.vault_id.to_string())
        .bind(&meta.name)
        .bind(&meta.template_id)
        .bind(i64::from(meta.template_version))
        .bind(to_json("host_override", &meta.host_override)?)
        .bind(to_json("field_names", &meta.field_names)?)
        .bind(to_json("custom_headers", &meta.custom_headers)?)
        .bind(to_json("variable_refs", &meta.variable_refs)?)
        .bind(to_json("substitutions", &meta.substitutions)?)
        .bind(opt_ts(&meta.not_after))
        .bind(generation_i64(meta.secret_generation)?)
        .bind(&meta.rotation_id)
        .bind(&meta.created_by)
        .bind(ts(&meta.created_at))
        .bind(ts(&meta.updated_at))
        .bind(ciphertext)
        .execute(&mut *tx)
        .await
        .map_err(db("insert credential", "credential"))?;
        finish(tx, audit, "insert_credential").await
    }

    async fn get_credential(
        &self,
        id: &CredentialId,
    ) -> Result<Option<CredentialMeta>, StoreError> {
        let sql = format!("SELECT {CREDENTIAL_COLUMNS} FROM credentials WHERE id = ?");
        sqlx::query(&sql)
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db("get credential", "credential"))?
            .map(|r| credential_from_row(&r))
            .transpose()
    }

    async fn list_credentials(
        &self,
        vault_id: &VaultId,
        page: PageRequest,
    ) -> Result<Page<CredentialMeta>, StoreError> {
        let total = self
            .count(
                "SELECT COUNT(*) AS n FROM credentials WHERE vault_id = ?",
                Some(&vault_id.to_string()),
            )
            .await?;
        let sql = format!(
            "SELECT {CREDENTIAL_COLUMNS} FROM credentials WHERE vault_id = ? ORDER BY created_at DESC, id LIMIT ? OFFSET ?"
        );
        let rows = sqlx::query(&sql)
            .bind(vault_id.to_string())
            .bind(to_i64(page.page_size))
            .bind(to_i64(page.offset()))
            .fetch_all(&self.pool)
            .await
            .map_err(db("list credentials", "credential"))?;
        Ok(Page {
            items: rows
                .iter()
                .map(credential_from_row)
                .collect::<Result<_, _>>()?,
            total,
            page: page.page,
            page_size: page.page_size,
        })
    }

    async fn replace_secret(
        &self,
        id: &CredentialId,
        secret: NewSecret,
        updated_at: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<SecretReplaced, StoreError> {
        let mut tx = self.begin("replace_secret").await?;
        let row =
            sqlx::query("SELECT secret_generation, rotation_id FROM credentials WHERE id = ?")
                .bind(id.to_string())
                .fetch_optional(&mut *tx)
                .await
                .map_err(db("read credential generation", "credential"))?
                .ok_or_else(|| StoreError::not_found("credential", id))?;
        let current = u64::try_from(get::<i64>(&row, "secret_generation")?).unwrap_or(0);
        let rotation_id: Option<String> = get(&row, "rotation_id")?;
        if secret.rotation_id.is_some() && secret.rotation_id == rotation_id {
            return Ok(SecretReplaced::AlreadyApplied {
                generation: current,
            });
        }
        let stale = |current| StoreError::StaleGeneration {
            id: id.to_string(),
            expected: secret.expected_generation.unwrap_or(current),
            current,
        };
        if secret.expected_generation.is_some_and(|e| e != current) {
            return Err(stale(current));
        }
        // Compare and swap on the generation read above, so a rotation
        // committed in between makes this one stale rather than lost.
        let result = sqlx::query(
            "UPDATE credentials SET secret = ?, field_names = ?, variable_refs = ?, not_after = ?, secret_generation = secret_generation + 1, rotation_id = ?, updated_at = ? WHERE id = ? AND secret_generation = ?",
        )
        .bind(secret.ciphertext.as_slice())
        .bind(to_json("field_names", &secret.field_names)?)
        .bind(to_json("variable_refs", &secret.variable_refs)?)
        .bind(opt_ts(&secret.not_after))
        .bind(&secret.rotation_id)
        .bind(ts(&updated_at))
        .bind(id.to_string())
        .bind(generation_i64(current)?)
        .execute(&mut *tx)
        .await
        .map_err(db("replace credential secret", "credential"))?;
        if result.rows_affected() == 0 {
            let now: Option<i64> =
                sqlx::query_scalar("SELECT secret_generation FROM credentials WHERE id = ?")
                    .bind(id.to_string())
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(db("read credential generation", "credential"))?;
            return Err(match now {
                None => StoreError::not_found("credential", id),
                Some(now) => stale(u64::try_from(now).unwrap_or(0)),
            });
        }
        finish(tx, audit, "replace_secret").await?;
        Ok(SecretReplaced::Written {
            generation: current + 1,
        })
    }

    async fn delete_credential(
        &self,
        id: &CredentialId,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut tx = self.begin("delete_credential").await?;
        let result = sqlx::query("DELETE FROM credentials WHERE id = ?")
            .bind(id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db("delete credential", "credential"))?;
        if result.rows_affected() == 0 {
            return Err(StoreError::not_found("credential", id));
        }
        finish(tx, audit, "delete_credential").await
    }

    async fn load_secret_ciphertext(
        &self,
        id: &CredentialId,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        sqlx::query("SELECT secret FROM credentials WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db("load credential secret", "credential"))?
            .map(|r| get::<Vec<u8>>(&r, "secret"))
            .transpose()
    }

    async fn update_custom_headers(
        &self,
        id: &CredentialId,
        custom_headers: Vec<CustomHeader>,
        variable_refs: Vec<String>,
        updated_at: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut tx = self.begin("update_custom_headers").await?;
        let result = sqlx::query(
            "UPDATE credentials SET custom_headers = ?, variable_refs = ?, updated_at = ? WHERE id = ?",
        )
        .bind(to_json("custom_headers", &custom_headers)?)
        .bind(to_json("variable_refs", &variable_refs)?)
        .bind(ts(&updated_at))
        .bind(id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(db("update credential custom headers", "credential"))?;
        if result.rows_affected() == 0 {
            return Err(StoreError::not_found("credential", id));
        }
        finish(tx, audit, "update_custom_headers").await
    }

    async fn update_substitutions(
        &self,
        id: &CredentialId,
        substitutions: Vec<Substitution>,
        updated_at: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut tx = self.begin("update_substitutions").await?;
        let result =
            sqlx::query("UPDATE credentials SET substitutions = ?, updated_at = ? WHERE id = ?")
                .bind(to_json("substitutions", &substitutions)?)
                .bind(ts(&updated_at))
                .bind(id.to_string())
                .execute(&mut *tx)
                .await
                .map_err(db("update credential substitutions", "credential"))?;
        if result.rows_affected() == 0 {
            return Err(StoreError::not_found("credential", id));
        }
        finish(tx, audit, "update_substitutions").await
    }

    async fn list_credentials_with_variables(&self) -> Result<Vec<CredentialMeta>, StoreError> {
        let sql = format!(
            "SELECT {CREDENTIAL_COLUMNS} FROM credentials WHERE variable_refs != '[]' ORDER BY name, id"
        );
        sqlx::query(&sql)
            .fetch_all(&self.pool)
            .await
            .map_err(db("list credentials with variables", "credential"))?
            .iter()
            .map(credential_from_row)
            .collect()
    }

    async fn insert_variable(
        &self,
        variable: Variable,
        ciphertext: Vec<u8>,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut tx = self.begin("insert_variable").await?;
        sqlx::query(
            "INSERT INTO variables (id, key, value, created_by, created_at, updated_by, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(variable.id.to_string())
        .bind(&variable.key)
        .bind(ciphertext)
        .bind(&variable.created_by)
        .bind(ts(&variable.created_at))
        .bind(&variable.updated_by)
        .bind(ts(&variable.updated_at))
        .execute(&mut *tx)
        .await
        .map_err(db("insert variable", "variable"))?;
        finish(tx, audit, "insert_variable").await
    }

    async fn get_variable(&self, id: &VariableId) -> Result<Option<Variable>, StoreError> {
        let sql = format!("SELECT {VARIABLE_COLUMNS} FROM variables WHERE id = ?");
        sqlx::query(&sql)
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db("get variable", "variable"))?
            .map(|r| variable_from_row(&r))
            .transpose()
    }

    async fn list_variables(&self, page: PageRequest) -> Result<Page<Variable>, StoreError> {
        let total = self
            .count("SELECT COUNT(*) AS n FROM variables", None)
            .await?;
        let sql = format!("SELECT {VARIABLE_COLUMNS} FROM variables ORDER BY key LIMIT ? OFFSET ?");
        let rows = sqlx::query(&sql)
            .bind(to_i64(page.page_size))
            .bind(to_i64(page.offset()))
            .fetch_all(&self.pool)
            .await
            .map_err(db("list variables", "variable"))?;
        Ok(Page {
            items: rows
                .iter()
                .map(variable_from_row)
                .collect::<Result<_, _>>()?,
            total,
            page: page.page,
            page_size: page.page_size,
        })
    }

    async fn existing_variable_keys(&self, keys: &[String]) -> Result<Vec<String>, StoreError> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let sql = format!(
            "SELECT key FROM variables WHERE key IN ({})",
            placeholders(keys.len())
        );
        let mut q = sqlx::query(&sql);
        for key in keys {
            q = q.bind(key.clone());
        }
        q.fetch_all(&self.pool)
            .await
            .map_err(db("find variable keys", "variable"))?
            .iter()
            .map(|r| get::<String>(r, "key"))
            .collect()
    }

    async fn replace_variable_value(
        &self,
        id: &VariableId,
        ciphertext: Vec<u8>,
        updated_by: &str,
        updated_at: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut tx = self.begin("replace_variable_value").await?;
        let result = sqlx::query(
            "UPDATE variables SET value = ?, updated_by = ?, updated_at = ? WHERE id = ?",
        )
        .bind(ciphertext)
        .bind(updated_by)
        .bind(ts(&updated_at))
        .bind(id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(db("replace variable value", "variable"))?;
        if result.rows_affected() == 0 {
            return Err(StoreError::not_found("variable", id));
        }
        finish(tx, audit, "replace_variable_value").await
    }

    async fn delete_variable(
        &self,
        id: &VariableId,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut tx = self.begin("delete_variable").await?;
        let key: String = sqlx::query("SELECT key FROM variables WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(db("delete variable", "variable"))?
            .map(|r| get::<String>(&r, "key"))
            .transpose()?
            .ok_or_else(|| StoreError::not_found("variable", id))?;
        let row = sqlx::query(
            "SELECT COUNT(*) AS n FROM credentials, json_each(credentials.variable_refs) WHERE json_each.value = ?",
        )
        .bind(&key)
        .fetch_one(&mut *tx)
        .await
        .map_err(db("delete variable", "variable"))?;
        let users = to_u64(get::<i64>(&row, "n")?);
        if users > 0 {
            return Err(StoreError::Conflict {
                entity: "variable",
                detail: format!("variable '{key}' is referenced by {users} credential(s)"),
            });
        }
        sqlx::query("DELETE FROM variables WHERE id = ?")
            .bind(id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db("delete variable", "variable"))?;
        finish(tx, audit, "delete_variable").await
    }

    async fn load_variable_ciphertexts(
        &self,
        keys: &[String],
    ) -> Result<Vec<(Variable, Vec<u8>)>, StoreError> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let sql = format!(
            "SELECT {VARIABLE_COLUMNS}, value FROM variables WHERE key IN ({})",
            placeholders(keys.len())
        );
        let mut q = sqlx::query(&sql);
        for key in keys {
            q = q.bind(key.clone());
        }
        q.fetch_all(&self.pool)
            .await
            .map_err(db("load variable values", "variable"))?
            .iter()
            .map(|r| Ok((variable_from_row(r)?, get::<Vec<u8>>(r, "value")?)))
            .collect()
    }
}

fn vault_from_row(row: &SqliteRow) -> Result<Vault, StoreError> {
    let scope: String = get(row, "scope")?;
    Ok(Vault {
        id: get_id(row, "id")?,
        name: get(row, "name")?,
        scope: tokenless_core::scope::Scope::parse(&scope)
            .map_err(|e| StoreError::backend("decode scope", e))?,
        created_at: get_ts(row, "created_at")?,
    })
}

fn template_from_row(row: &SqliteRow) -> Result<StoredTemplate, StoreError> {
    let yaml: String = get(row, "yaml")?;
    let template =
        ServiceTemplate::from_yaml(&yaml).map_err(|e| StoreError::backend("decode template", e))?;
    let source = match get::<String>(row, "source")?.as_str() {
        "builtin" => TemplateSource::Builtin,
        _ => TemplateSource::Imported,
    };
    let status = match get::<String>(row, "status")?.as_str() {
        "approved" => TemplateStatus::Approved,
        _ => TemplateStatus::PendingApproval,
    };
    Ok(StoredTemplate {
        template,
        yaml,
        source,
        status,
        imported_by: get(row, "imported_by")?,
        approved_by: get(row, "approved_by")?,
        created_at: get_ts(row, "created_at")?,
    })
}

fn rule_from_row(row: &SqliteRow) -> Result<Rule, StoreError> {
    Ok(Rule {
        id: get_id(row, "id")?,
        vault_id: get_id(row, "vault_id")?,
        credential_id: get_id(row, "credential_id")?,
        name: get(row, "name")?,
        allow: from_json("allow", &get::<String>(row, "allow")?)?,
        enabled: get::<i64>(row, "enabled")? != 0,
        created_by: get(row, "created_by")?,
        created_at: get_ts(row, "created_at")?,
        updated_at: get_ts(row, "updated_at")?,
    })
}

fn session_from_row(row: &SqliteRow) -> Result<ProxySession, StoreError> {
    let bundle = match (
        get::<Option<String>>(row, "bundle_id")?,
        get::<Option<String>>(row, "bundle_name")?,
    ) {
        (Some(id), Some(name)) => Some(SessionBundle {
            id: id.parse().map_err(|e: uuid::Error| {
                StoreError::backend("decode bundle_id", format!("'{id}': {e}"))
            })?,
            name,
        }),
        _ => None,
    };
    Ok(ProxySession {
        id: get_id(row, "id")?,
        vault_id: get_id(row, "vault_id")?,
        rule_ids: from_json("rule_ids", &get::<String>(row, "rule_ids")?)?,
        bundle,
        labels: from_json("labels", &get::<String>(row, "labels")?)?,
        request_limit: get::<Option<i64>>(row, "request_limit")?.map(to_u64),
        node_id: get_opt_id(row, "node_id")?,
        created_by: get(row, "created_by")?,
        created_at: get_ts(row, "created_at")?,
        expires_at: get_ts(row, "expires_at")?,
        revoked_at: get_opt_ts(row, "revoked_at")?,
    })
}

const RULE_COLUMNS: &str =
    "id, vault_id, credential_id, name, allow, enabled, created_by, created_at, updated_at";
const SESSION_COLUMNS: &str = "id, vault_id, rule_ids, labels, request_limit, node_id, created_by, created_at, expires_at, revoked_at, bundle_id, bundle_name";

/// Bundle columns plus its rule ids as a JSON array, in one statement.
const BUNDLE_SELECT: &str = "SELECT b.id, b.vault_id, b.name, b.description, b.created_by, b.created_at, b.updated_at, (SELECT json_group_array(r.rule_id) FROM access_bundle_rules r WHERE r.bundle_id = b.id) AS rule_ids FROM access_bundles b";

fn bundle_from_row(row: &SqliteRow) -> Result<AccessBundle, StoreError> {
    let mut rule_ids: Vec<RuleId> = from_json("rule_ids", &get::<String>(row, "rule_ids")?)?;
    rule_ids.sort();
    Ok(AccessBundle {
        id: get_id(row, "id")?,
        vault_id: get_id(row, "vault_id")?,
        name: get(row, "name")?,
        description: get(row, "description")?,
        rule_ids,
        created_by: get(row, "created_by")?,
        created_at: get_ts(row, "created_at")?,
        updated_at: get_ts(row, "updated_at")?,
    })
}

async fn write_bundle_rules(
    tx: &mut Transaction<'static, Sqlite>,
    bundle: &AccessBundle,
) -> Result<(), StoreError> {
    sqlx::query("DELETE FROM access_bundle_rules WHERE bundle_id = ?")
        .bind(bundle.id.to_string())
        .execute(&mut **tx)
        .await
        .map_err(db("clear access bundle rules", "access_bundle"))?;
    for rule_id in &bundle.rule_ids {
        sqlx::query("INSERT INTO access_bundle_rules (bundle_id, rule_id) VALUES (?, ?)")
            .bind(bundle.id.to_string())
            .bind(rule_id.to_string())
            .execute(&mut **tx)
            .await
            .map_err(db("insert access bundle rule", "access_bundle"))?;
    }
    Ok(())
}

#[async_trait]
impl PolicyStore for SqliteStore {
    async fn insert_vault(&self, vault: Vault, audit: &[AuditEvent]) -> Result<(), StoreError> {
        let mut tx = self.begin("insert_vault").await?;
        sqlx::query("INSERT INTO vaults (id, name, scope, created_at) VALUES (?, ?, ?, ?)")
            .bind(vault.id.to_string())
            .bind(&vault.name)
            .bind(vault.scope.to_string())
            .bind(ts(&vault.created_at))
            .execute(&mut *tx)
            .await
            .map_err(db("insert vault", "vault"))?;
        finish(tx, audit, "insert_vault").await
    }

    async fn delete_vault(
        &self,
        id: &VaultId,
        at: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<VaultDeletion, StoreError> {
        let mut tx = self.begin("delete_vault").await?;
        let vault = id.to_string();
        let removed = sqlx::query("DELETE FROM vaults WHERE id = ?")
            .bind(&vault)
            .execute(&mut *tx)
            .await
            .map_err(db("delete vault", "vault"))?
            .rows_affected();
        if removed == 0 {
            return Err(StoreError::not_found("vault", id));
        }
        // Bundle membership goes before its bundles; sessions and API keys
        // are revoked, not deleted, so their tokens stay refused.
        let mut done = VaultDeletion::default();
        sqlx::query("DELETE FROM access_bundle_rules WHERE bundle_id IN (SELECT id FROM access_bundles WHERE vault_id = ?)")
            .bind(&vault)
            .execute(&mut *tx)
            .await
            .map_err(db("delete vault bundle members", "vault"))?;
        done.bundles = sqlx::query("DELETE FROM access_bundles WHERE vault_id = ?")
            .bind(&vault)
            .execute(&mut *tx)
            .await
            .map_err(db("delete vault bundles", "vault"))?
            .rows_affected();
        done.rules = sqlx::query("DELETE FROM rules WHERE vault_id = ?")
            .bind(&vault)
            .execute(&mut *tx)
            .await
            .map_err(db("delete vault rules", "vault"))?
            .rows_affected();
        done.credentials = sqlx::query("DELETE FROM credentials WHERE vault_id = ?")
            .bind(&vault)
            .execute(&mut *tx)
            .await
            .map_err(db("delete vault credentials", "vault"))?
            .rows_affected();
        done.sessions_revoked = sqlx::query(
            "UPDATE proxy_sessions SET revoked_at = ? WHERE vault_id = ? AND revoked_at IS NULL AND expires_at > ?",
        )
        .bind(ts(&at))
        .bind(&vault)
        .bind(ts(&open_traffic_horizon(at)))
        .execute(&mut *tx)
        .await
        .map_err(db("revoke vault sessions", "vault"))?
        .rows_affected();
        done.api_keys_revoked = sqlx::query(
            "UPDATE api_keys SET revoked_at = ? WHERE vault_id = ? AND revoked_at IS NULL",
        )
        .bind(ts(&at))
        .bind(&vault)
        .execute(&mut *tx)
        .await
        .map_err(db("revoke vault api keys", "vault"))?
        .rows_affected();
        finish(tx, audit, "delete_vault").await.map(|()| done)
    }

    async fn count_live_sessions(
        &self,
        vault_id: &VaultId,
        now: DateTime<Utc>,
    ) -> Result<u64, StoreError> {
        let row = sqlx::query(
            "SELECT COUNT(*) AS n FROM proxy_sessions WHERE vault_id = ? AND revoked_at IS NULL AND expires_at > ?",
        )
        .bind(vault_id.to_string())
        .bind(ts(&now))
        .fetch_one(&self.pool)
        .await
        .map_err(db("count live sessions", "session"))?;
        Ok(u64::try_from(get::<i64>(&row, "n")?).unwrap_or(0))
    }

    async fn get_vault(&self, id: &VaultId) -> Result<Option<Vault>, StoreError> {
        sqlx::query("SELECT id, name, scope, created_at FROM vaults WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db("get vault", "vault"))?
            .map(|r| vault_from_row(&r))
            .transpose()
    }

    async fn list_vaults(&self, page: PageRequest) -> Result<Page<Vault>, StoreError> {
        let total = self.count("SELECT COUNT(*) AS n FROM vaults", None).await?;
        let rows = sqlx::query("SELECT id, name, scope, created_at FROM vaults ORDER BY created_at DESC, id LIMIT ? OFFSET ?")
            .bind(to_i64(page.page_size))
            .bind(to_i64(page.offset()))
            .fetch_all(&self.pool)
            .await
            .map_err(db("list vaults", "vault"))?;
        Ok(Page {
            items: rows.iter().map(vault_from_row).collect::<Result<_, _>>()?,
            total,
            page: page.page,
            page_size: page.page_size,
        })
    }

    async fn insert_template(
        &self,
        t: StoredTemplate,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut tx = self.begin("insert_template").await?;
        sqlx::query("INSERT INTO templates (id, version, yaml, source, status, imported_by, approved_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(&t.template.id)
            .bind(i64::from(t.template.version))
            .bind(&t.yaml)
            .bind(match t.source {
                TemplateSource::Builtin => "builtin",
                TemplateSource::Imported => "imported",
            })
            .bind(match t.status {
                TemplateStatus::Approved => "approved",
                TemplateStatus::PendingApproval => "pending_approval",
            })
            .bind(&t.imported_by)
            .bind(&t.approved_by)
            .bind(ts(&t.created_at))
            .execute(&mut *tx)
            .await
            .map_err(db("insert template", "template"))?;
        finish(tx, audit, "insert_template").await
    }

    async fn get_template(
        &self,
        id: &str,
        version: u32,
    ) -> Result<Option<StoredTemplate>, StoreError> {
        sqlx::query("SELECT * FROM templates WHERE id = ? AND version = ?")
            .bind(id)
            .bind(i64::from(version))
            .fetch_optional(&self.pool)
            .await
            .map_err(db("get template", "template"))?
            .map(|r| template_from_row(&r))
            .transpose()
    }

    async fn list_templates(&self) -> Result<Vec<StoredTemplate>, StoreError> {
        sqlx::query("SELECT * FROM templates ORDER BY id, version")
            .fetch_all(&self.pool)
            .await
            .map_err(db("list templates", "template"))?
            .iter()
            .map(template_from_row)
            .collect()
    }

    async fn approve_template(
        &self,
        id: &str,
        version: u32,
        approved_by: &str,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut tx = self.begin("approve_template").await?;
        let result = sqlx::query("UPDATE templates SET status = 'approved', approved_by = ? WHERE id = ? AND version = ?")
            .bind(approved_by)
            .bind(id)
            .bind(i64::from(version))
            .execute(&mut *tx)
            .await
            .map_err(db("approve template", "template"))?;
        if result.rows_affected() == 0 {
            return Err(StoreError::not_found("template", format!("{id}@{version}")));
        }
        finish(tx, audit, "approve_template").await
    }

    async fn insert_rule(&self, rule: Rule, audit: &[AuditEvent]) -> Result<(), StoreError> {
        let mut tx = self.begin("insert_rule").await?;
        sqlx::query("INSERT INTO rules (id, vault_id, credential_id, name, allow, enabled, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(rule.id.to_string())
            .bind(rule.vault_id.to_string())
            .bind(rule.credential_id.to_string())
            .bind(&rule.name)
            .bind(to_json("allow", &rule.allow)?)
            .bind(i64::from(rule.enabled))
            .bind(&rule.created_by)
            .bind(ts(&rule.created_at))
            .bind(ts(&rule.updated_at))
            .execute(&mut *tx)
            .await
            .map_err(db("insert rule", "rule"))?;
        finish(tx, audit, "insert_rule").await
    }

    async fn get_rule(&self, id: &RuleId) -> Result<Option<Rule>, StoreError> {
        let sql = format!("SELECT {RULE_COLUMNS} FROM rules WHERE id = ?");
        sqlx::query(&sql)
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db("get rule", "rule"))?
            .map(|r| rule_from_row(&r))
            .transpose()
    }

    async fn list_rules(
        &self,
        vault_id: &VaultId,
        page: PageRequest,
    ) -> Result<Page<Rule>, StoreError> {
        let total = self
            .count(
                "SELECT COUNT(*) AS n FROM rules WHERE vault_id = ?",
                Some(&vault_id.to_string()),
            )
            .await?;
        let sql = format!("SELECT {RULE_COLUMNS} FROM rules WHERE vault_id = ? ORDER BY created_at DESC, id LIMIT ? OFFSET ?");
        let rows = sqlx::query(&sql)
            .bind(vault_id.to_string())
            .bind(to_i64(page.page_size))
            .bind(to_i64(page.offset()))
            .fetch_all(&self.pool)
            .await
            .map_err(db("list rules", "rule"))?;
        Ok(Page {
            items: rows.iter().map(rule_from_row).collect::<Result<_, _>>()?,
            total,
            page: page.page,
            page_size: page.page_size,
        })
    }

    async fn list_enabled_rules(&self) -> Result<Vec<Rule>, StoreError> {
        let sql = format!("SELECT {RULE_COLUMNS} FROM rules WHERE enabled = 1 ORDER BY id");
        sqlx::query(&sql)
            .fetch_all(&self.pool)
            .await
            .map_err(db("list enabled rules", "rule"))?
            .iter()
            .map(rule_from_row)
            .collect()
    }

    async fn count_rules_for_credential(&self, id: &CredentialId) -> Result<u64, StoreError> {
        self.count(
            "SELECT COUNT(*) AS n FROM rules WHERE credential_id = ?",
            Some(&id.to_string()),
        )
        .await
    }

    async fn update_rule(&self, rule: Rule, audit: &[AuditEvent]) -> Result<(), StoreError> {
        let mut tx = self.begin("update_rule").await?;
        let result = sqlx::query(
            "UPDATE rules SET name = ?, allow = ?, enabled = ?, updated_at = ? WHERE id = ?",
        )
        .bind(&rule.name)
        .bind(to_json("allow", &rule.allow)?)
        .bind(i64::from(rule.enabled))
        .bind(ts(&rule.updated_at))
        .bind(rule.id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(db("update rule", "rule"))?;
        if result.rows_affected() == 0 {
            return Err(StoreError::not_found("rule", rule.id));
        }
        finish(tx, audit, "update_rule").await
    }

    async fn delete_rule(&self, id: &RuleId, audit: &[AuditEvent]) -> Result<(), StoreError> {
        let mut tx = self.begin("delete_rule").await?;
        let result = sqlx::query("DELETE FROM rules WHERE id = ?")
            .bind(id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db("delete rule", "rule"))?;
        if result.rows_affected() == 0 {
            return Err(StoreError::not_found("rule", id));
        }
        sqlx::query("DELETE FROM access_bundle_rules WHERE rule_id = ?")
            .bind(id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db("remove rule from access bundles", "access_bundle"))?;
        finish(tx, audit, "delete_rule").await
    }

    async fn insert_bundle(
        &self,
        bundle: AccessBundle,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut tx = self.begin("insert_bundle").await?;
        sqlx::query("INSERT INTO access_bundles (id, vault_id, name, description, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind(bundle.id.to_string())
            .bind(bundle.vault_id.to_string())
            .bind(&bundle.name)
            .bind(&bundle.description)
            .bind(&bundle.created_by)
            .bind(ts(&bundle.created_at))
            .bind(ts(&bundle.updated_at))
            .execute(&mut *tx)
            .await
            .map_err(db("insert access bundle", "access_bundle"))?;
        write_bundle_rules(&mut tx, &bundle).await?;
        finish(tx, audit, "insert_bundle").await
    }

    async fn get_bundle(&self, id: &BundleId) -> Result<Option<AccessBundle>, StoreError> {
        let sql = format!("{BUNDLE_SELECT} WHERE b.id = ?");
        sqlx::query(&sql)
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db("get access bundle", "access_bundle"))?
            .map(|r| bundle_from_row(&r))
            .transpose()
    }

    async fn get_bundle_by_name(
        &self,
        vault_id: &VaultId,
        name: &str,
    ) -> Result<Option<AccessBundle>, StoreError> {
        let sql = format!("{BUNDLE_SELECT} WHERE b.vault_id = ? AND b.name = ?");
        sqlx::query(&sql)
            .bind(vault_id.to_string())
            .bind(name)
            .fetch_optional(&self.pool)
            .await
            .map_err(db("get access bundle by name", "access_bundle"))?
            .map(|r| bundle_from_row(&r))
            .transpose()
    }

    async fn list_bundles(
        &self,
        vault_id: Option<&VaultId>,
        page: PageRequest,
    ) -> Result<Page<AccessBundle>, StoreError> {
        // `? IS NULL` selects every vault when no vault is given.
        let vault = vault_id.map(|v| v.to_string());
        let row = sqlx::query(
            "SELECT COUNT(*) AS n FROM access_bundles WHERE (? IS NULL OR vault_id = ?)",
        )
        .bind(vault.clone())
        .bind(vault.clone())
        .fetch_one(&self.pool)
        .await
        .map_err(db("count access bundles", "access_bundle"))?;
        let total = to_u64(get::<i64>(&row, "n")?);
        let sql = format!(
            "{BUNDLE_SELECT} WHERE (? IS NULL OR b.vault_id = ?) ORDER BY b.name, b.vault_id LIMIT ? OFFSET ?"
        );
        let rows = sqlx::query(&sql)
            .bind(vault.clone())
            .bind(vault)
            .bind(to_i64(page.page_size))
            .bind(to_i64(page.offset()))
            .fetch_all(&self.pool)
            .await
            .map_err(db("list access bundles", "access_bundle"))?;
        Ok(Page {
            items: rows.iter().map(bundle_from_row).collect::<Result<_, _>>()?,
            total,
            page: page.page,
            page_size: page.page_size,
        })
    }

    async fn update_bundle(
        &self,
        bundle: AccessBundle,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut tx = self.begin("update_bundle").await?;
        let result = sqlx::query(
            "UPDATE access_bundles SET name = ?, description = ?, updated_at = ? WHERE id = ?",
        )
        .bind(&bundle.name)
        .bind(&bundle.description)
        .bind(ts(&bundle.updated_at))
        .bind(bundle.id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(db("update access bundle", "access_bundle"))?;
        if result.rows_affected() == 0 {
            return Err(StoreError::not_found("access_bundle", bundle.id));
        }
        write_bundle_rules(&mut tx, &bundle).await?;
        finish(tx, audit, "update_bundle").await
    }

    async fn delete_bundle(
        &self,
        id: &BundleId,
        at: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<u64, StoreError> {
        let mut tx = self.begin("delete_bundle").await?;
        let result = sqlx::query("DELETE FROM access_bundles WHERE id = ?")
            .bind(id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db("delete access bundle", "access_bundle"))?;
        if result.rows_affected() == 0 {
            return Err(StoreError::not_found("access_bundle", id));
        }
        sqlx::query("DELETE FROM access_bundle_rules WHERE bundle_id = ?")
            .bind(id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db("delete access bundle rules", "access_bundle"))?;
        let revoked = sqlx::query(
            "UPDATE proxy_sessions SET revoked_at = ? WHERE bundle_id = ? AND revoked_at IS NULL AND expires_at > ?",
        )
        .bind(ts(&at))
        .bind(id.to_string())
        .bind(ts(&open_traffic_horizon(at)))
        .execute(&mut *tx)
        .await
        .map_err(db("revoke access bundle sessions", "session"))?
        .rows_affected();
        finish(tx, audit, "delete_bundle").await.map(|()| revoked)
    }

    async fn insert_session(
        &self,
        s: ProxySession,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut tx = self.begin("insert_session").await?;
        sqlx::query("INSERT INTO proxy_sessions (id, vault_id, rule_ids, labels, request_limit, node_id, created_by, created_at, expires_at, revoked_at, bundle_id, bundle_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(s.id.to_string())
            .bind(s.vault_id.to_string())
            .bind(to_json("rule_ids", &s.rule_ids)?)
            .bind(to_json("labels", &s.labels)?)
            .bind(s.request_limit.map(to_i64))
            .bind(s.node_id.map(|n| n.to_string()))
            .bind(&s.created_by)
            .bind(ts(&s.created_at))
            .bind(ts(&s.expires_at))
            .bind(opt_ts(&s.revoked_at))
            .bind(s.bundle.as_ref().map(|b| b.id.to_string()))
            .bind(s.bundle.as_ref().map(|b| b.name.clone()))
            .execute(&mut *tx)
            .await
            .map_err(db("insert session", "session"))?;
        finish(tx, audit, "insert_session").await
    }

    async fn get_session(&self, id: &SessionId) -> Result<Option<ProxySession>, StoreError> {
        let sql = format!("SELECT {SESSION_COLUMNS} FROM proxy_sessions WHERE id = ?");
        sqlx::query(&sql)
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db("get session", "session"))?
            .map(|r| session_from_row(&r))
            .transpose()
    }

    async fn list_sessions(
        &self,
        vault_id: Option<&VaultId>,
        bundle_id: Option<&BundleId>,
        page: PageRequest,
    ) -> Result<Page<ProxySession>, StoreError> {
        // `? IS NULL` drops a filter that was not given.
        let vault = vault_id.map(|v| v.to_string());
        let bundle = bundle_id.map(|b| b.to_string());
        let row = sqlx::query(
            "SELECT COUNT(*) AS n FROM proxy_sessions WHERE (? IS NULL OR vault_id = ?) AND (? IS NULL OR bundle_id = ?)",
        )
        .bind(vault.clone())
        .bind(vault.clone())
        .bind(bundle.clone())
        .bind(bundle.clone())
        .fetch_one(&self.pool)
        .await
        .map_err(db("count sessions", "session"))?;
        let total = to_u64(get::<i64>(&row, "n")?);
        let sql = format!("SELECT {SESSION_COLUMNS} FROM proxy_sessions WHERE (? IS NULL OR vault_id = ?) AND (? IS NULL OR bundle_id = ?) ORDER BY created_at DESC, id LIMIT ? OFFSET ?");
        let rows = sqlx::query(&sql)
            .bind(vault.clone())
            .bind(vault)
            .bind(bundle.clone())
            .bind(bundle)
            .bind(to_i64(page.page_size))
            .bind(to_i64(page.offset()))
            .fetch_all(&self.pool)
            .await
            .map_err(db("list sessions", "session"))?;
        Ok(Page {
            items: rows
                .iter()
                .map(session_from_row)
                .collect::<Result<_, _>>()?,
            total,
            page: page.page,
            page_size: page.page_size,
        })
    }

    async fn revoke_session(
        &self,
        id: &SessionId,
        at: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<bool, StoreError> {
        let mut tx = self.begin("revoke_session").await?;
        let result = sqlx::query(
            "UPDATE proxy_sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
        )
        .bind(ts(&at))
        .bind(id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(db("revoke session", "session"))?;
        if result.rows_affected() == 1 {
            return finish(tx, audit, "revoke_session").await.map(|()| true);
        }
        if exists_tx(&mut tx, "proxy_sessions", &id.to_string()).await? {
            finish(tx, audit, "revoke_session").await.map(|()| false)
        } else {
            Err(StoreError::not_found("session", id))
        }
    }

    async fn update_session_labels(
        &self,
        id: &SessionId,
        labels: BTreeMap<String, String>,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut tx = self.begin("update_session_labels").await?;
        let result = sqlx::query("UPDATE proxy_sessions SET labels = ? WHERE id = ?")
            .bind(to_json("labels", &labels)?)
            .bind(id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db("update session labels", "session"))?;
        if result.rows_affected() == 0 {
            return Err(StoreError::not_found("session", id));
        }
        finish(tx, audit, "update_session_labels").await
    }

    async fn list_revoked_unexpired(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Vec<SessionId>, StoreError> {
        sqlx::query("SELECT id FROM proxy_sessions WHERE revoked_at IS NOT NULL AND expires_at > ? ORDER BY id")
            .bind(ts(&now))
            .fetch_all(&self.pool)
            .await
            .map_err(db("list revoked sessions", "session"))?
            .iter()
            .map(|r| get_id(r, "id"))
            .collect()
    }

    async fn list_limited_active(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Vec<(SessionId, u64)>, StoreError> {
        sqlx::query("SELECT id, request_limit FROM proxy_sessions WHERE revoked_at IS NULL AND request_limit IS NOT NULL AND expires_at > ? ORDER BY id")
            .bind(ts(&now))
            .fetch_all(&self.pool)
            .await
            .map_err(db("list limited sessions", "session"))?
            .iter()
            .map(|r| Ok((get_id(r, "id")?, to_u64(get::<i64>(r, "request_limit")?))))
            .collect()
    }

    async fn list_live_sessions_for_node(
        &self,
        node: &NodeId,
        now: DateTime<Utc>,
    ) -> Result<Vec<ProxySession>, StoreError> {
        let sql = format!("SELECT {SESSION_COLUMNS} FROM proxy_sessions WHERE node_id = ? AND revoked_at IS NULL AND expires_at > ? ORDER BY id");
        sqlx::query(&sql)
            .bind(node.to_string())
            .bind(ts(&now))
            .fetch_all(&self.pool)
            .await
            .map_err(db("list a node's live sessions", "session"))?
            .iter()
            .map(session_from_row)
            .collect()
    }

    async fn get_settings(&self) -> Result<Settings, StoreError> {
        let row = sqlx::query("SELECT value FROM settings WHERE key = 'instance'")
            .fetch_optional(&self.pool)
            .await
            .map_err(db("get settings", "settings"))?;
        match row {
            Some(r) => from_json("settings", &get::<String>(&r, "value")?),
            None => Ok(Settings::default()),
        }
    }

    async fn put_settings(
        &self,
        settings: Settings,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut tx = self.begin("put_settings").await?;
        sqlx::query("INSERT INTO settings (key, value) VALUES ('instance', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
            .bind(to_json("settings", &settings)?)
            .execute(&mut *tx)
            .await
            .map_err(db("put settings", "settings"))?;
        finish(tx, audit, "put_settings").await
    }
}

fn audit_from_row(row: &SqliteRow) -> Result<AuditEvent, StoreError> {
    let outcome: String = get(row, "outcome")?;
    Ok(AuditEvent {
        id: get_id(row, "id")?,
        at: get_ts(row, "at")?,
        actor: get(row, "actor")?,
        action: get(row, "action")?,
        outcome: AuditOutcome::parse(&outcome).ok_or_else(|| {
            StoreError::backend("decode outcome", format!("unknown outcome '{outcome}'"))
        })?,
        vault_id: get::<Option<String>>(row, "vault_id")?
            .map(|v| {
                v.parse()
                    .map_err(|e| StoreError::backend("decode vault_id", e))
            })
            .transpose()?,
        target: get(row, "target")?,
        detail: from_json("detail", &get::<String>(row, "detail")?)?,
    })
}

#[async_trait]
impl AuditSink for SqliteStore {
    async fn record(&self, events: &[AuditEvent]) -> Result<(), StoreError> {
        let tx = self.begin("record audit").await?;
        finish(tx, events, "record audit").await
    }

    async fn query(&self, query: &AuditQuery) -> Result<Page<AuditEvent>, StoreError> {
        let mut filter = String::from(" WHERE 1 = 1");
        if query.vault_id.is_some() {
            // Narrowed to a session or a service, the vault only confirms
            // the caller may read it: `+` keeps SQLite on the narrower
            // index instead of walking the whole vault's history.
            if query.session_id.is_some() || query.credential_id.is_some() {
                filter.push_str(" AND +vault_id = ?");
            } else {
                filter.push_str(" AND vault_id = ?");
            }
        }
        if query.action_prefix.is_some() {
            filter.push_str(" AND substr(action, 1, ?) = ?");
        }
        if query.session_id.is_some() {
            // Indexed (migration 0010): a live session's page polls this.
            filter.push_str(" AND session_ref = ?");
        }
        if query.credential_id.is_some() {
            // Indexed (migration 0012): a service's page lists its log.
            filter.push_str(" AND credential_ref = ?");
        }
        let count_sql = format!("SELECT COUNT(*) AS n FROM audit_events{filter}");
        let list_sql =
            format!("SELECT * FROM audit_events{filter} ORDER BY at DESC, id LIMIT ? OFFSET ?");
        let mut count = sqlx::query(&count_sql);
        let mut list = sqlx::query(&list_sql);
        if let Some(v) = &query.vault_id {
            count = count.bind(v.to_string());
            list = list.bind(v.to_string());
        }
        if let Some(prefix) = &query.action_prefix {
            let len = i64::try_from(prefix.chars().count()).unwrap_or(0);
            count = count.bind(len).bind(prefix.clone());
            list = list.bind(len).bind(prefix.clone());
        }
        if let Some(id) = &query.session_id {
            count = count.bind(id.to_string());
            list = list.bind(id.to_string());
        }
        if let Some(id) = &query.credential_id {
            count = count.bind(id.to_string());
            list = list.bind(id.to_string());
        }
        let total = to_u64(get::<i64>(
            &count
                .fetch_one(&self.pool)
                .await
                .map_err(db("count audit events", "audit"))?,
            "n",
        )?);
        let rows = list
            .bind(to_i64(query.page.page_size))
            .bind(to_i64(query.page.offset()))
            .fetch_all(&self.pool)
            .await
            .map_err(db("query audit events", "audit"))?;
        Ok(Page {
            items: rows.iter().map(audit_from_row).collect::<Result<_, _>>()?,
            total,
            page: query.page.page,
            page_size: query.page.page_size,
        })
    }

    async fn latest_at(
        &self,
        vault_id: &VaultId,
        action: &str,
    ) -> Result<Option<DateTime<Utc>>, StoreError> {
        // One entry of audit_events_vault_action_at (migration 0011), no count.
        let row = sqlx::query(
            "SELECT at FROM audit_events WHERE vault_id = ? AND action = ? ORDER BY at DESC LIMIT 1",
        )
        .bind(vault_id.to_string())
        .bind(action)
        .fetch_optional(&self.pool)
        .await
        .map_err(db("find the latest audit event", "audit"))?;
        row.map(|r| get_ts(&r, "at")).transpose()
    }
}

fn user_from_row(row: &SqliteRow) -> Result<User, StoreError> {
    Ok(User {
        id: get_id(row, "id")?,
        username: get(row, "username")?,
        password_hash: get(row, "password_hash")?,
        totp_secret_enc: get::<Option<Vec<u8>>>(row, "totp_secret_enc")?,
        totp_last_step: get::<Option<i64>>(row, "totp_last_step")?.map(to_u64),
        role: role(row)?,
        created_at: get_ts(row, "created_at")?,
        disabled_at: get_opt_ts(row, "disabled_at")?,
        sso: match get_opt_id::<OidcProviderId>(row, "sso_provider_id")? {
            Some(provider_id) => Some(SsoIdentity {
                provider_id,
                subject: get(row, "sso_subject")?,
            }),
            None => None,
        },
    })
}

fn invite_from_row(row: &SqliteRow) -> Result<Invite, StoreError> {
    Ok(Invite {
        id: get_id(row, "id")?,
        token_hash: get(row, "token_hash")?,
        role: role(row)?,
        created_by: get(row, "created_by")?,
        created_at: get_ts(row, "created_at")?,
        expires_at: get_ts(row, "expires_at")?,
        accepted_at: get_opt_ts(row, "accepted_at")?,
        accepted_by: get::<Option<String>>(row, "accepted_by")?
            .map(|raw| {
                raw.parse::<UserId>()
                    .map_err(|e| StoreError::backend("decode accepted_by", format!("'{raw}': {e}")))
            })
            .transpose()?,
        revoked_at: get_opt_ts(row, "revoked_at")?,
    })
}

async fn insert_user_tx(tx: &mut Transaction<'static, Sqlite>, u: &User) -> Result<(), StoreError> {
    sqlx::query("INSERT INTO users (id, username, password_hash, totp_secret_enc, totp_last_step, role, created_at, disabled_at, sso_provider_id, sso_subject) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(u.id.to_string())
        .bind(&u.username)
        .bind(&u.password_hash)
        .bind(&u.totp_secret_enc)
        .bind(u.totp_last_step.map(to_i64))
        .bind(u.role.as_str())
        .bind(ts(&u.created_at))
        .bind(opt_ts(&u.disabled_at))
        .bind(u.sso.as_ref().map(|s| s.provider_id.to_string()))
        .bind(u.sso.as_ref().map(|s| s.subject.clone()))
        .execute(&mut **tx)
        .await
        .map_err(db("insert user", "user"))?;
    Ok(())
}

fn api_key_from_row(row: &SqliteRow) -> Result<ApiKey, StoreError> {
    Ok(ApiKey {
        id: get_id(row, "id")?,
        name: get(row, "name")?,
        prefix: get(row, "prefix")?,
        secret_hash: get(row, "secret_hash")?,
        vault_id: get_id(row, "vault_id")?,
        role: role(row)?,
        created_by: get(row, "created_by")?,
        created_at: get_ts(row, "created_at")?,
        expires_at: get_ts(row, "expires_at")?,
        revoked_at: get_opt_ts(row, "revoked_at")?,
        last_used_at: get_opt_ts(row, "last_used_at")?,
    })
}

#[async_trait]
impl IdentityStore for SqliteStore {
    async fn count_users(&self) -> Result<u64, StoreError> {
        self.count("SELECT COUNT(*) AS n FROM users", None).await
    }

    async fn insert_user(&self, u: User, audit: &[AuditEvent]) -> Result<(), StoreError> {
        let mut tx = self.begin("insert_user").await?;
        insert_user_tx(&mut tx, &u).await?;
        finish(tx, audit, "insert_user").await
    }

    async fn get_user(&self, id: &UserId) -> Result<Option<User>, StoreError> {
        sqlx::query("SELECT * FROM users WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db("get user", "user"))?
            .map(|r| user_from_row(&r))
            .transpose()
    }

    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, StoreError> {
        sqlx::query("SELECT * FROM users WHERE username = ?")
            .bind(username)
            .fetch_optional(&self.pool)
            .await
            .map_err(db("get user by name", "user"))?
            .map(|r| user_from_row(&r))
            .transpose()
    }

    async fn list_users(&self, page: PageRequest) -> Result<Page<User>, StoreError> {
        let total = self.count("SELECT COUNT(*) AS n FROM users", None).await?;
        let rows = sqlx::query("SELECT * FROM users ORDER BY created_at DESC, id LIMIT ? OFFSET ?")
            .bind(to_i64(page.page_size))
            .bind(to_i64(page.offset()))
            .fetch_all(&self.pool)
            .await
            .map_err(db("list users", "user"))?;
        Ok(Page {
            items: rows.iter().map(user_from_row).collect::<Result<_, _>>()?,
            total,
            page: page.page,
            page_size: page.page_size,
        })
    }

    async fn update_user_access(
        &self,
        id: &UserId,
        role: Role,
        disabled_at: Option<DateTime<Utc>>,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        // The UPDATE comes first so the transaction holds the write lock
        // before the admin count is read; concurrent changes serialise.
        let mut tx = self.begin("update_user_access").await?;
        let result = sqlx::query("UPDATE users SET role = ?, disabled_at = ? WHERE id = ?")
            .bind(role.as_str())
            .bind(opt_ts(&disabled_at))
            .bind(id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db("update user access", "user"))?;
        if result.rows_affected() == 0 {
            return Err(StoreError::not_found("user", id));
        }
        let row = sqlx::query(
            "SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND disabled_at IS NULL",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(db("count enabled admins", "user"))?;
        if get::<i64>(&row, "n")? == 0 {
            return Err(StoreError::Conflict {
                entity: "user",
                detail: format!("changing user {id} would leave no enabled admin"),
            });
        }
        if disabled_at.is_some() {
            sqlx::query("DELETE FROM ui_sessions WHERE user_id = ?")
                .bind(id.to_string())
                .execute(&mut *tx)
                .await
                .map_err(db("delete disabled user's sessions", "ui_session"))?;
        }
        finish(tx, audit, "update_user_access").await
    }

    async fn set_user_password(
        &self,
        id: &UserId,
        password_hash: &str,
        keep_session: Option<&str>,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut tx = self.begin("set_user_password").await?;
        let result = sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
            .bind(password_hash)
            .bind(id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db("set user password", "user"))?;
        if result.rows_affected() == 0 {
            return Err(StoreError::not_found("user", id));
        }
        sqlx::query("DELETE FROM ui_sessions WHERE user_id = ? AND token_hash IS NOT ?")
            .bind(id.to_string())
            .bind(keep_session)
            .execute(&mut *tx)
            .await
            .map_err(db("sign the user out elsewhere", "ui_session"))?;
        finish(tx, audit, "set_user_password").await
    }

    async fn set_user_totp(
        &self,
        id: &UserId,
        secret_enc: Option<Vec<u8>>,
        last_step: Option<u64>,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut tx = self.begin("set_user_totp").await?;
        let step = last_step
            .map(|s| {
                i64::try_from(s).map_err(|_| {
                    StoreError::backend("encode totp step", format!("step {s} is out of range"))
                })
            })
            .transpose()?;
        let result =
            sqlx::query("UPDATE users SET totp_secret_enc = ?, totp_last_step = ? WHERE id = ?")
                .bind(secret_enc)
                .bind(step)
                .bind(id.to_string())
                .execute(&mut *tx)
                .await
                .map_err(db("set user authenticator", "user"))?;
        if result.rows_affected() == 0 {
            return Err(StoreError::not_found("user", id));
        }
        finish(tx, audit, "set_user_totp").await
    }

    async fn insert_invite(&self, i: Invite, audit: &[AuditEvent]) -> Result<(), StoreError> {
        let mut tx = self.begin("insert_invite").await?;
        sqlx::query("INSERT INTO invites (id, token_hash, role, created_by, created_at, expires_at, accepted_at, accepted_by, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(i.id.to_string())
            .bind(&i.token_hash)
            .bind(i.role.as_str())
            .bind(&i.created_by)
            .bind(ts(&i.created_at))
            .bind(ts(&i.expires_at))
            .bind(opt_ts(&i.accepted_at))
            .bind(i.accepted_by.map(|u| u.to_string()))
            .bind(opt_ts(&i.revoked_at))
            .execute(&mut *tx)
            .await
            .map_err(db("insert invite", "invite"))?;
        finish(tx, audit, "insert_invite").await
    }

    async fn get_invite_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<Invite>, StoreError> {
        sqlx::query("SELECT * FROM invites WHERE token_hash = ?")
            .bind(token_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(db("get invite", "invite"))?
            .map(|r| invite_from_row(&r))
            .transpose()
    }

    async fn list_invites(&self, page: PageRequest) -> Result<Page<Invite>, StoreError> {
        let total = self
            .count("SELECT COUNT(*) AS n FROM invites", None)
            .await?;
        let rows =
            sqlx::query("SELECT * FROM invites ORDER BY created_at DESC, id LIMIT ? OFFSET ?")
                .bind(to_i64(page.page_size))
                .bind(to_i64(page.offset()))
                .fetch_all(&self.pool)
                .await
                .map_err(db("list invites", "invite"))?;
        Ok(Page {
            items: rows.iter().map(invite_from_row).collect::<Result<_, _>>()?,
            total,
            page: page.page,
            page_size: page.page_size,
        })
    }

    async fn revoke_invite(
        &self,
        id: &InviteId,
        at: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<bool, StoreError> {
        let mut tx = self.begin("revoke_invite").await?;
        let result = sqlx::query(
            "UPDATE invites SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL AND accepted_at IS NULL",
        )
        .bind(ts(&at))
        .bind(id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(db("revoke invite", "invite"))?;
        if result.rows_affected() == 1 {
            return finish(tx, audit, "revoke_invite").await.map(|()| true);
        }
        if exists_tx(&mut tx, "invites", &id.to_string()).await? {
            finish(tx, audit, "revoke_invite").await.map(|()| false)
        } else {
            Err(StoreError::not_found("invite", id))
        }
    }

    async fn accept_invite(
        &self,
        token_hash: &str,
        user: User,
        audit: &[AuditEvent],
    ) -> Result<bool, StoreError> {
        let mut tx = self.begin("accept_invite").await?;
        let result = sqlx::query(
            "UPDATE invites SET accepted_at = ?, accepted_by = ? WHERE token_hash = ? AND role = ? AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > ?",
        )
        .bind(ts(&user.created_at))
        .bind(user.id.to_string())
        .bind(token_hash)
        .bind(user.role.as_str())
        .bind(ts(&user.created_at))
        .execute(&mut *tx)
        .await
        .map_err(db("accept invite", "invite"))?;
        if result.rows_affected() == 0 {
            return Ok(false);
        }
        insert_user_tx(&mut tx, &user).await?;
        finish(tx, audit, "accept_invite").await.map(|()| true)
    }

    async fn advance_totp_step(&self, id: &UserId, step: u64) -> Result<bool, StoreError> {
        let result = sqlx::query("UPDATE users SET totp_last_step = ? WHERE id = ? AND (totp_last_step IS NULL OR totp_last_step < ?)")
            .bind(to_i64(step))
            .bind(id.to_string())
            .bind(to_i64(step))
            .execute(&self.pool)
            .await
            .map_err(db("advance totp step", "user"))?;
        if result.rows_affected() == 1 {
            return Ok(true);
        }
        if self.exists("users", &id.to_string()).await? {
            Ok(false)
        } else {
            Err(StoreError::not_found("user", id))
        }
    }

    async fn insert_ui_session(
        &self,
        s: UiSession,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut tx = self.begin("insert_ui_session").await?;
        sqlx::query("INSERT INTO ui_sessions (token_hash, user_id, created_at, expires_at, step_up_at) VALUES (?, ?, ?, ?, ?)")
            .bind(&s.token_hash)
            .bind(s.user_id.to_string())
            .bind(ts(&s.created_at))
            .bind(ts(&s.expires_at))
            .bind(opt_ts(&s.step_up_at))
            .execute(&mut *tx)
            .await
            .map_err(db("insert ui session", "ui_session"))?;
        finish(tx, audit, "insert_ui_session").await
    }

    async fn get_ui_session(&self, token_hash: &str) -> Result<Option<UiSession>, StoreError> {
        let row = sqlx::query("SELECT * FROM ui_sessions WHERE token_hash = ?")
            .bind(token_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(db("get ui session", "ui_session"))?;
        row.map(|r| {
            Ok(UiSession {
                token_hash: get(&r, "token_hash")?,
                user_id: get_id(&r, "user_id")?,
                created_at: get_ts(&r, "created_at")?,
                expires_at: get_ts(&r, "expires_at")?,
                step_up_at: get_opt_ts(&r, "step_up_at")?,
            })
        })
        .transpose()
    }

    async fn set_ui_session_step_up(
        &self,
        token_hash: &str,
        at: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut tx = self.begin("set_ui_session_step_up").await?;
        let result = sqlx::query("UPDATE ui_sessions SET step_up_at = ? WHERE token_hash = ?")
            .bind(ts(&at))
            .bind(token_hash)
            .execute(&mut *tx)
            .await
            .map_err(db("set step-up", "ui_session"))?;
        if result.rows_affected() == 0 {
            return Err(StoreError::not_found("ui_session", "<hash>"));
        }
        finish(tx, audit, "set_ui_session_step_up").await
    }

    async fn delete_ui_session(
        &self,
        token_hash: &str,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut tx = self.begin("delete_ui_session").await?;
        sqlx::query("DELETE FROM ui_sessions WHERE token_hash = ?")
            .bind(token_hash)
            .execute(&mut *tx)
            .await
            .map_err(db("delete ui session", "ui_session"))?;
        finish(tx, audit, "delete_ui_session").await
    }

    async fn delete_expired_ui_sessions(&self, now: DateTime<Utc>) -> Result<u64, StoreError> {
        Ok(sqlx::query("DELETE FROM ui_sessions WHERE expires_at <= ?")
            .bind(ts(&now))
            .execute(&self.pool)
            .await
            .map_err(db("purge ui sessions", "ui_session"))?
            .rows_affected())
    }

    async fn insert_api_key(&self, k: ApiKey, audit: &[AuditEvent]) -> Result<(), StoreError> {
        let mut tx = self.begin("insert_api_key").await?;
        sqlx::query("INSERT INTO api_keys (id, name, prefix, secret_hash, vault_id, role, created_by, created_at, expires_at, revoked_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(k.id.to_string())
            .bind(&k.name)
            .bind(&k.prefix)
            .bind(&k.secret_hash)
            .bind(k.vault_id.to_string())
            .bind(k.role.as_str())
            .bind(&k.created_by)
            .bind(ts(&k.created_at))
            .bind(ts(&k.expires_at))
            .bind(opt_ts(&k.revoked_at))
            .bind(opt_ts(&k.last_used_at))
            .execute(&mut *tx)
            .await
            .map_err(db("insert api key", "api_key"))?;
        finish(tx, audit, "insert_api_key").await
    }

    async fn get_api_key_by_prefix(&self, prefix: &str) -> Result<Option<ApiKey>, StoreError> {
        sqlx::query("SELECT * FROM api_keys WHERE prefix = ?")
            .bind(prefix)
            .fetch_optional(&self.pool)
            .await
            .map_err(db("get api key", "api_key"))?
            .map(|r| api_key_from_row(&r))
            .transpose()
    }

    async fn list_api_keys(&self, page: PageRequest) -> Result<Page<ApiKey>, StoreError> {
        let total = self
            .count("SELECT COUNT(*) AS n FROM api_keys", None)
            .await?;
        let rows =
            sqlx::query("SELECT * FROM api_keys ORDER BY created_at DESC, id LIMIT ? OFFSET ?")
                .bind(to_i64(page.page_size))
                .bind(to_i64(page.offset()))
                .fetch_all(&self.pool)
                .await
                .map_err(db("list api keys", "api_key"))?;
        Ok(Page {
            items: rows
                .iter()
                .map(api_key_from_row)
                .collect::<Result<_, _>>()?,
            total,
            page: page.page,
            page_size: page.page_size,
        })
    }

    async fn revoke_api_key(
        &self,
        id: &ApiKeyId,
        at: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<bool, StoreError> {
        let mut tx = self.begin("revoke_api_key").await?;
        let result =
            sqlx::query("UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL")
                .bind(ts(&at))
                .bind(id.to_string())
                .execute(&mut *tx)
                .await
                .map_err(db("revoke api key", "api_key"))?;
        if result.rows_affected() == 1 {
            return finish(tx, audit, "revoke_api_key").await.map(|()| true);
        }
        if exists_tx(&mut tx, "api_keys", &id.to_string()).await? {
            finish(tx, audit, "revoke_api_key").await.map(|()| false)
        } else {
            Err(StoreError::not_found("api_key", id))
        }
    }

    async fn touch_api_key(&self, id: &ApiKeyId, at: DateTime<Utc>) -> Result<(), StoreError> {
        sqlx::query("UPDATE api_keys SET last_used_at = ? WHERE id = ?")
            .bind(ts(&at))
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(db("touch api key", "api_key"))?;
        Ok(())
    }
}

fn node_from_row(row: &SqliteRow) -> Result<Node, StoreError> {
    Ok(Node {
        id: get_id(row, "id")?,
        name: get(row, "name")?,
        seal_public_key: get(row, "seal_public_key")?,
        cert_serial: get(row, "cert_serial")?,
        cert_not_after: get_ts(row, "cert_not_after")?,
        enrolled_at: get_ts(row, "enrolled_at")?,
        last_seen_at: get_opt_ts(row, "last_seen_at")?,
        revoked_at: get_opt_ts(row, "revoked_at")?,
        scoped_rules: get::<i64>(row, "scoped_rules")? != 0,
    })
}

#[async_trait]
impl NodeStore for SqliteStore {
    async fn insert_join_token(
        &self,
        t: JoinTokenRecord,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut tx = self.begin("insert_join_token").await?;
        sqlx::query("INSERT INTO join_tokens (id, secret_hash, created_by, created_at, expires_at, consumed_at) VALUES (?, ?, ?, ?, ?, ?)")
            .bind(&t.id)
            .bind(&t.secret_hash)
            .bind(&t.created_by)
            .bind(ts(&t.created_at))
            .bind(ts(&t.expires_at))
            .bind(opt_ts(&t.consumed_at))
            .execute(&mut *tx)
            .await
            .map_err(db("insert join token", "join_token"))?;
        finish(tx, audit, "insert_join_token").await
    }

    async fn consume_join_token(
        &self,
        id: &str,
        secret_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<bool, StoreError> {
        Ok(sqlx::query("UPDATE join_tokens SET consumed_at = ? WHERE id = ? AND secret_hash = ? AND consumed_at IS NULL AND expires_at > ?")
            .bind(ts(&now))
            .bind(id)
            .bind(secret_hash)
            .bind(ts(&now))
            .execute(&self.pool)
            .await
            .map_err(db("consume join token", "join_token"))?
            .rows_affected()
            == 1)
    }

    async fn insert_node(&self, n: Node, audit: &[AuditEvent]) -> Result<(), StoreError> {
        let mut tx = self.begin("insert_node").await?;
        sqlx::query("INSERT INTO nodes (id, name, seal_public_key, cert_serial, cert_not_after, enrolled_at, last_seen_at, revoked_at, scoped_rules) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(n.id.to_string())
            .bind(&n.name)
            .bind(&n.seal_public_key)
            .bind(&n.cert_serial)
            .bind(ts(&n.cert_not_after))
            .bind(ts(&n.enrolled_at))
            .bind(opt_ts(&n.last_seen_at))
            .bind(opt_ts(&n.revoked_at))
            .bind(i64::from(n.scoped_rules))
            .execute(&mut *tx)
            .await
            .map_err(db("insert node", "node"))?;
        finish(tx, audit, "insert_node").await
    }

    async fn get_node(&self, id: &NodeId) -> Result<Option<Node>, StoreError> {
        sqlx::query("SELECT * FROM nodes WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db("get node", "node"))?
            .map(|r| node_from_row(&r))
            .transpose()
    }

    async fn list_nodes(&self, page: PageRequest) -> Result<Page<Node>, StoreError> {
        let total = self.count("SELECT COUNT(*) AS n FROM nodes", None).await?;
        let rows =
            sqlx::query("SELECT * FROM nodes ORDER BY enrolled_at DESC, id LIMIT ? OFFSET ?")
                .bind(to_i64(page.page_size))
                .bind(to_i64(page.offset()))
                .fetch_all(&self.pool)
                .await
                .map_err(db("list nodes", "node"))?;
        Ok(Page {
            items: rows.iter().map(node_from_row).collect::<Result<_, _>>()?,
            total,
            page: page.page,
            page_size: page.page_size,
        })
    }

    async fn update_node_cert(
        &self,
        id: &NodeId,
        serial: &str,
        not_after: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut tx = self.begin("update_node_cert").await?;
        let result =
            sqlx::query("UPDATE nodes SET cert_serial = ?, cert_not_after = ? WHERE id = ?")
                .bind(serial)
                .bind(ts(&not_after))
                .bind(id.to_string())
                .execute(&mut *tx)
                .await
                .map_err(db("update node cert", "node"))?;
        if result.rows_affected() == 0 {
            return Err(StoreError::not_found("node", id));
        }
        finish(tx, audit, "update_node_cert").await
    }

    async fn touch_node(&self, id: &NodeId, at: DateTime<Utc>) -> Result<(), StoreError> {
        sqlx::query("UPDATE nodes SET last_seen_at = ? WHERE id = ?")
            .bind(ts(&at))
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(db("touch node", "node"))?;
        Ok(())
    }

    async fn revoke_node(
        &self,
        id: &NodeId,
        at: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<bool, StoreError> {
        let mut tx = self.begin("revoke_node").await?;
        let result =
            sqlx::query("UPDATE nodes SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL")
                .bind(ts(&at))
                .bind(id.to_string())
                .execute(&mut *tx)
                .await
                .map_err(db("revoke node", "node"))?;
        if result.rows_affected() == 1 {
            return finish(tx, audit, "revoke_node").await.map(|()| true);
        }
        if exists_tx(&mut tx, "nodes", &id.to_string()).await? {
            finish(tx, audit, "revoke_node").await.map(|()| false)
        } else {
            Err(StoreError::not_found("node", id))
        }
    }

    async fn get_key_material(&self, name: &str) -> Result<Option<Vec<u8>>, StoreError> {
        sqlx::query("SELECT value FROM key_material WHERE name = ?")
            .bind(name)
            .fetch_optional(&self.pool)
            .await
            .map_err(db("get key material", "key_material"))?
            .map(|r| get::<Vec<u8>>(&r, "value"))
            .transpose()
    }

    async fn put_key_material_if_absent(
        &self,
        name: &str,
        value: Vec<u8>,
    ) -> Result<Vec<u8>, StoreError> {
        sqlx::query(
            "INSERT INTO key_material (name, value) VALUES (?, ?) ON CONFLICT(name) DO NOTHING",
        )
        .bind(name)
        .bind(value)
        .execute(&self.pool)
        .await
        .map_err(db("put key material", "key_material"))?;
        self.get_key_material(name).await?.ok_or_else(|| {
            StoreError::backend("put key material", format!("'{name}' missing after insert"))
        })
    }

    async fn replace_key_material(
        &self,
        name: &str,
        value: Vec<u8>,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut tx = self.begin("replace_key_material").await?;
        let result = sqlx::query("UPDATE key_material SET value = ? WHERE name = ?")
            .bind(value)
            .bind(name)
            .execute(&mut *tx)
            .await
            .map_err(db("replace key material", "key_material"))?;
        if result.rows_affected() == 0 {
            return Err(StoreError::not_found("key material", name));
        }
        finish(tx, audit, "replace_key_material").await
    }

    async fn list_ciphertexts(&self) -> Result<Vec<StoredCiphertext>, StoreError> {
        let mut out = Vec::new();
        for row in sqlx::query("SELECT id, vault_id, secret FROM credentials")
            .fetch_all(&self.pool)
            .await
            .map_err(db("list credential ciphertexts", "credential"))?
        {
            out.push(StoredCiphertext {
                owner: CiphertextOwner::Credential {
                    id: get_id(&row, "id")?,
                    vault_id: get_id(&row, "vault_id")?,
                },
                ciphertext: get(&row, "secret")?,
            });
        }
        for row in sqlx::query("SELECT id, value FROM variables")
            .fetch_all(&self.pool)
            .await
            .map_err(db("list variable ciphertexts", "variable"))?
        {
            out.push(StoredCiphertext {
                owner: CiphertextOwner::Variable {
                    id: get_id(&row, "id")?,
                },
                ciphertext: get(&row, "value")?,
            });
        }
        for row in
            sqlx::query("SELECT id, totp_secret_enc FROM users WHERE totp_secret_enc IS NOT NULL")
                .fetch_all(&self.pool)
                .await
                .map_err(db("list authenticator ciphertexts", "user"))?
        {
            out.push(StoredCiphertext {
                owner: CiphertextOwner::UserTotp {
                    id: get_id(&row, "id")?,
                },
                ciphertext: get(&row, "totp_secret_enc")?,
            });
        }
        for row in sqlx::query(
            "SELECT id, client_secret_enc FROM oidc_providers WHERE client_secret_enc IS NOT NULL",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db("list identity provider ciphertexts", "oidc_provider"))?
        {
            out.push(StoredCiphertext {
                owner: CiphertextOwner::OidcClientSecret {
                    id: get_id(&row, "id")?,
                },
                ciphertext: get(&row, "client_secret_enc")?,
            });
        }
        for row in sqlx::query("SELECT name, value FROM key_material")
            .fetch_all(&self.pool)
            .await
            .map_err(db("list key material", "key_material"))?
        {
            out.push(StoredCiphertext {
                owner: CiphertextOwner::KeyMaterial {
                    name: get(&row, "name")?,
                },
                ciphertext: get(&row, "value")?,
            });
        }
        Ok(out)
    }

    async fn replace_ciphertexts(
        &self,
        changes: &[(StoredCiphertext, Vec<u8>)],
        audit: &[AuditEvent],
    ) -> Result<u64, StoreError> {
        let mut tx = self.begin("replace_ciphertexts").await?;
        let mut replaced = 0;
        for (old, new) in changes {
            let (sql, key) = match &old.owner {
                CiphertextOwner::Credential { id, .. } => (
                    "UPDATE credentials SET secret = ? WHERE id = ? AND secret = ?",
                    id.to_string(),
                ),
                CiphertextOwner::Variable { id } => (
                    "UPDATE variables SET value = ? WHERE id = ? AND value = ?",
                    id.to_string(),
                ),
                CiphertextOwner::UserTotp { id } => (
                    "UPDATE users SET totp_secret_enc = ? WHERE id = ? AND totp_secret_enc = ?",
                    id.to_string(),
                ),
                CiphertextOwner::KeyMaterial { name } => (
                    "UPDATE key_material SET value = ? WHERE name = ? AND value = ?",
                    name.clone(),
                ),
                CiphertextOwner::OidcClientSecret { id } => (
                    "UPDATE oidc_providers SET client_secret_enc = ? WHERE id = ? AND client_secret_enc = ?",
                    id.to_string(),
                ),
            };
            let result = sqlx::query(sql)
                .bind(new)
                .bind(key)
                .bind(&old.ciphertext)
                .execute(&mut *tx)
                .await
                .map_err(db("replace ciphertext", "ciphertext"))?;
            replaced += result.rows_affected();
        }
        finish(tx, audit, "replace_ciphertexts").await?;
        Ok(replaced)
    }

    async fn next_snapshot_version(&self) -> Result<u64, StoreError> {
        let row = sqlx::query(
            "UPDATE counters SET value = value + 1 WHERE name = 'snapshot_version' RETURNING value",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(db("next snapshot version", "counter"))?;
        Ok(to_u64(get::<i64>(&row, "value")?))
    }
}
