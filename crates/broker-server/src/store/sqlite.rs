// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SQLite implementation of every store trait.
//!
//! Queries are plain SQL with bound parameters and no SQLite-only syntax
//! beyond `ON CONFLICT DO NOTHING` and `RETURNING`, both of which PostgreSQL
//! shares, so a Postgres store can reuse them with `$n` placeholders.

use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use broker_control::model::{
    ApiKey, AuditQuery, CredentialMeta, JoinTokenRecord, Node, Page, PageRequest, ProxySession,
    Rule, Settings, StoredTemplate, TemplateSource, TemplateStatus, UiSession, User, Vault,
};
use broker_control::store::{AuditSink, CredentialStore, IdentityStore, NodeStore, PolicyStore};
use broker_control::StoreError;
use broker_core::audit::{AuditEvent, AuditOutcome};
use broker_core::authz::Role;
use broker_core::ids::{ApiKeyId, CredentialId, NodeId, RuleId, SessionId, UserId, VaultId};
use broker_core::template::ServiceTemplate;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow, SqliteSynchronous,
};
use sqlx::{Row, Sqlite, SqlitePool, Transaction};

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

    async fn begin(
        &self,
        operation: &'static str,
    ) -> Result<Transaction<'static, Sqlite>, StoreError> {
        self.pool
            .begin()
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

fn credential_from_row(row: &SqliteRow) -> Result<CredentialMeta, StoreError> {
    Ok(CredentialMeta {
        id: get_id(row, "id")?,
        vault_id: get_id(row, "vault_id")?,
        name: get(row, "name")?,
        template_id: get(row, "template_id")?,
        template_version: u32::try_from(get::<i64>(row, "template_version")?).unwrap_or(0),
        host_override: from_json("host_override", &get::<String>(row, "host_override")?)?,
        field_names: from_json("field_names", &get::<String>(row, "field_names")?)?,
        created_by: get(row, "created_by")?,
        created_at: get_ts(row, "created_at")?,
        updated_at: get_ts(row, "updated_at")?,
    })
}

const CREDENTIAL_COLUMNS: &str = "id, vault_id, name, template_id, template_version, host_override, field_names, created_by, created_at, updated_at";

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
            "INSERT INTO credentials (id, vault_id, name, template_id, template_version, host_override, field_names, created_by, created_at, updated_at, secret) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(meta.id.to_string())
        .bind(meta.vault_id.to_string())
        .bind(&meta.name)
        .bind(&meta.template_id)
        .bind(i64::from(meta.template_version))
        .bind(to_json("host_override", &meta.host_override)?)
        .bind(to_json("field_names", &meta.field_names)?)
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
        ciphertext: Vec<u8>,
        field_names: Vec<String>,
        updated_at: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut tx = self.begin("replace_secret").await?;
        let result = sqlx::query(
            "UPDATE credentials SET secret = ?, field_names = ?, updated_at = ? WHERE id = ?",
        )
        .bind(ciphertext)
        .bind(to_json("field_names", &field_names)?)
        .bind(ts(&updated_at))
        .bind(id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(db("replace credential secret", "credential"))?;
        if result.rows_affected() == 0 {
            return Err(StoreError::not_found("credential", id));
        }
        finish(tx, audit, "replace_secret").await
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
}

fn vault_from_row(row: &SqliteRow) -> Result<Vault, StoreError> {
    let scope: String = get(row, "scope")?;
    Ok(Vault {
        id: get_id(row, "id")?,
        name: get(row, "name")?,
        scope: broker_core::scope::Scope::parse(&scope)
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
    Ok(ProxySession {
        id: get_id(row, "id")?,
        vault_id: get_id(row, "vault_id")?,
        rule_ids: from_json("rule_ids", &get::<String>(row, "rule_ids")?)?,
        labels: from_json("labels", &get::<String>(row, "labels")?)?,
        request_limit: get::<Option<i64>>(row, "request_limit")?.map(to_u64),
        created_by: get(row, "created_by")?,
        created_at: get_ts(row, "created_at")?,
        expires_at: get_ts(row, "expires_at")?,
        revoked_at: get_opt_ts(row, "revoked_at")?,
    })
}

const RULE_COLUMNS: &str =
    "id, vault_id, credential_id, name, allow, enabled, created_by, created_at, updated_at";
const SESSION_COLUMNS: &str =
    "id, vault_id, rule_ids, labels, request_limit, created_by, created_at, expires_at, revoked_at";

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
        finish(tx, audit, "delete_rule").await
    }

    async fn insert_session(
        &self,
        s: ProxySession,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut tx = self.begin("insert_session").await?;
        sqlx::query("INSERT INTO proxy_sessions (id, vault_id, rule_ids, labels, request_limit, created_by, created_at, expires_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(s.id.to_string())
            .bind(s.vault_id.to_string())
            .bind(to_json("rule_ids", &s.rule_ids)?)
            .bind(to_json("labels", &s.labels)?)
            .bind(s.request_limit.map(to_i64))
            .bind(&s.created_by)
            .bind(ts(&s.created_at))
            .bind(ts(&s.expires_at))
            .bind(opt_ts(&s.revoked_at))
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
        vault_id: &VaultId,
        page: PageRequest,
    ) -> Result<Page<ProxySession>, StoreError> {
        let total = self
            .count(
                "SELECT COUNT(*) AS n FROM proxy_sessions WHERE vault_id = ?",
                Some(&vault_id.to_string()),
            )
            .await?;
        let sql = format!("SELECT {SESSION_COLUMNS} FROM proxy_sessions WHERE vault_id = ? ORDER BY created_at DESC, id LIMIT ? OFFSET ?");
        let rows = sqlx::query(&sql)
            .bind(vault_id.to_string())
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
            filter.push_str(" AND vault_id = ?");
        }
        if query.action_prefix.is_some() {
            filter.push_str(" AND substr(action, 1, ?) = ?");
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
}

fn user_from_row(row: &SqliteRow) -> Result<User, StoreError> {
    Ok(User {
        id: get_id(row, "id")?,
        username: get(row, "username")?,
        password_hash: get(row, "password_hash")?,
        totp_secret_enc: get(row, "totp_secret_enc")?,
        totp_last_step: get::<Option<i64>>(row, "totp_last_step")?.map(to_u64),
        role: role(row)?,
        created_at: get_ts(row, "created_at")?,
    })
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
        sqlx::query("INSERT INTO users (id, username, password_hash, totp_secret_enc, totp_last_step, role, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind(u.id.to_string())
            .bind(&u.username)
            .bind(&u.password_hash)
            .bind(&u.totp_secret_enc)
            .bind(u.totp_last_step.map(to_i64))
            .bind(u.role.as_str())
            .bind(ts(&u.created_at))
            .execute(&mut *tx)
            .await
            .map_err(db("insert user", "user"))?;
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

    async fn replace_setup_token(
        &self,
        token_hash: &str,
        at: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        sqlx::query("INSERT INTO setup_tokens (singleton, token_hash, created_at) VALUES (1, ?, ?) ON CONFLICT(singleton) DO UPDATE SET token_hash = excluded.token_hash, created_at = excluded.created_at")
            .bind(token_hash)
            .bind(ts(&at))
            .execute(&self.pool)
            .await
            .map_err(db("replace setup token", "setup_token"))?;
        Ok(())
    }

    async fn consume_setup_token(&self, token_hash: &str) -> Result<bool, StoreError> {
        Ok(
            sqlx::query("DELETE FROM setup_tokens WHERE singleton = 1 AND token_hash = ?")
                .bind(token_hash)
                .execute(&self.pool)
                .await
                .map_err(db("consume setup token", "setup_token"))?
                .rows_affected()
                == 1,
        )
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
        sqlx::query("INSERT INTO nodes (id, name, seal_public_key, cert_serial, cert_not_after, enrolled_at, last_seen_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(n.id.to_string())
            .bind(&n.name)
            .bind(&n.seal_public_key)
            .bind(&n.cert_serial)
            .bind(ts(&n.cert_not_after))
            .bind(ts(&n.enrolled_at))
            .bind(opt_ts(&n.last_seen_at))
            .bind(opt_ts(&n.revoked_at))
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
