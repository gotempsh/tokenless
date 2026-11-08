// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Upgrades of an existing database: what each migration keeps and drops.

#![allow(clippy::expect_used)]

use std::borrow::Cow;

use broker_control::model::{AuditQuery, PageRequest};
use broker_control::store::{AuditSink, IdentityStore, PolicyStore};
use broker_core::ids::{ApiKeyId, SessionId, VaultId};
use broker_server::store::SqliteStore;
use sqlx::sqlite::SqlitePoolOptions;

/// A database at migration `before`, as an older release left it.
async fn database_before(before: i64) -> (tempfile::TempDir, String, sqlx::SqlitePool) {
    let dir = tempfile::tempdir().expect("tempdir");
    let url = format!(
        "sqlite://{}?mode=rwc",
        dir.path().join("broker.db").display()
    );
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("open");
    let mut older = sqlx::migrate!("./migrations");
    older.migrations = Cow::Owned(
        older
            .migrations
            .iter()
            .filter(|m| m.version < before)
            .cloned()
            .collect(),
    );
    older.run(&pool).await.expect("older migrations");
    (dir, url, pool)
}

const AT: &str = "2026-01-01T00:00:00.000000Z";

#[tokio::test]
async fn upgrading_retires_issuer_keys_and_keeps_the_session_cap() {
    let (_dir, url, pool) = database_before(9).await;
    let vault = VaultId::new().to_string();
    sqlx::query("INSERT INTO vaults (id, name, scope, created_at) VALUES (?, 'work', ?, ?)")
        .bind(&vault)
        .bind(format!("vault:{vault}"))
        .bind(AT)
        .execute(&pool)
        .await
        .expect("vault");
    for (prefix, role) in [
        ("cbk_issuer01", "session_issuer"),
        ("cbk_editor01", "editor"),
    ] {
        sqlx::query(
            "INSERT INTO api_keys (id, name, prefix, secret_hash, vault_id, role, created_by, created_at, expires_at) \
             VALUES (?, ?, ?, 'hash', ?, ?, 'user:test', ?, '2099-01-01T00:00:00.000000Z')",
        )
        .bind(ApiKeyId::new().to_string())
        .bind(role)
        .bind(prefix)
        .bind(&vault)
        .bind(role)
        .bind(AT)
        .execute(&pool)
        .await
        .expect("api key");
    }
    pool.close().await;

    let store = SqliteStore::connect(&url).await.expect("upgrade");
    let keys = store
        .list_api_keys(PageRequest::new(None, None))
        .await
        .expect("keys decode after the upgrade");
    let prefixes: Vec<_> = keys.items.iter().map(|k| k.prefix.as_str()).collect();
    assert_eq!(prefixes, ["cbk_editor01"]);
    assert_eq!(
        store
            .get_settings()
            .await
            .expect("settings")
            .max_session_ttl_secs,
        3600,
        "an existing instance keeps the cap it had"
    );
}

#[tokio::test]
async fn upgrading_keeps_a_saved_session_cap() {
    let (_dir, url, pool) = database_before(9).await;
    sqlx::query("INSERT INTO settings (key, value) VALUES ('instance', '{\"unmatched_host_policy\":\"deny\",\"max_session_ttl_secs\":28800}')")
        .execute(&pool)
        .await
        .expect("settings");
    pool.close().await;
    let store = SqliteStore::connect(&url).await.expect("upgrade");
    let settings = store.get_settings().await.expect("settings");
    assert_eq!(settings.max_session_ttl_secs, 28_800);
}

#[tokio::test]
async fn a_new_instance_allows_week_long_sessions() {
    let dir = tempfile::tempdir().expect("tempdir");
    let url = format!("sqlite://{}", dir.path().join("broker.db").display());
    let store = SqliteStore::connect(&url).await.expect("connect");
    assert_eq!(
        store
            .get_settings()
            .await
            .expect("settings")
            .max_session_ttl_secs,
        7 * 24 * 3600
    );
}

#[tokio::test]
async fn upgrading_indexes_the_audit_log_by_session() {
    let (_dir, url, pool) = database_before(10).await;
    let session = SessionId::new().to_string();
    let other = SessionId::new().to_string();
    for (id, at, action, target, detail) in [
        (
            "e1",
            "2026-01-01T00:00:01.000000Z",
            "session.mint",
            format!("session:{session}"),
            "{}".to_string(),
        ),
        (
            "e2",
            "2026-01-01T00:00:02.000000Z",
            "proxy.inject",
            "rule:r1".to_string(),
            format!(r#"{{"session_id":"{session}"}}"#),
        ),
        (
            "e3",
            "2026-01-01T00:00:03.000000Z",
            "proxy.inject",
            "rule:r1".to_string(),
            format!(r#"{{"session_id":"{other}"}}"#),
        ),
        (
            "e4",
            "2026-01-01T00:00:04.000000Z",
            "rule.create",
            "rule:r1".to_string(),
            "{}".to_string(),
        ),
    ] {
        sqlx::query(
            "INSERT INTO audit_events (id, at, actor, action, outcome, vault_id, target, detail) \
             VALUES (?, ?, 'user:test', ?, 'success', NULL, ?, ?)",
        )
        .bind(uuid_like(id))
        .bind(at)
        .bind(action)
        .bind(target)
        .bind(detail)
        .execute(&pool)
        .await
        .expect("audit event");
    }
    pool.close().await;

    let store = SqliteStore::connect(&url).await.expect("upgrade");
    let found = store
        .query(&AuditQuery {
            session_id: Some(session.parse().expect("session id")),
            ..Default::default()
        })
        .await
        .expect("query by session");
    let actions: Vec<_> = found.items.iter().map(|e| e.action.as_str()).collect();
    assert_eq!(
        actions,
        ["proxy.inject", "session.mint"],
        "events recorded before the upgrade are found"
    );
    assert_eq!(found.total, 2);

    // Answered from the index, not by reading every event.
    let pool = SqlitePoolOptions::new()
        .connect(&url)
        .await
        .expect("reopen");
    let plan: Vec<String> = sqlx::query(
        "EXPLAIN QUERY PLAN SELECT COUNT(*) FROM audit_events WHERE 1 = 1 AND session_ref = ?",
    )
    .bind(&session)
    .fetch_all(&pool)
    .await
    .expect("query plan")
    .iter()
    .map(|r| sqlx::Row::get::<String, _>(r, "detail"))
    .collect();
    assert!(
        plan.iter().any(|d| d.contains("audit_events_session_at")),
        "expected the session index, got {plan:?}"
    );
}

/// A UUID-shaped id, stable per name, for rows written with raw SQL.
fn uuid_like(name: &str) -> String {
    format!(
        "00000000-0000-4000-8000-{:0>12}",
        name.trim_start_matches('e')
    )
}

#[tokio::test]
async fn upgrading_finds_a_vaults_last_request_without_counting_its_history() {
    let (_dir, url, pool) = database_before(11).await;
    let work = VaultId::new();
    let idle = VaultId::new();
    for (vault, name) in [(work, "work"), (idle, "idle")] {
        sqlx::query("INSERT INTO vaults (id, name, scope, created_at) VALUES (?, ?, ?, ?)")
            .bind(vault.to_string())
            .bind(name)
            .bind(format!("vault:{vault}"))
            .bind(AT)
            .execute(&pool)
            .await
            .expect("vault");
    }
    for (id, at, action, vault) in [
        ("e1", "2026-01-01T00:00:01.000000Z", "proxy.inject", work),
        ("e2", "2026-01-01T00:00:03.000000Z", "proxy.inject", work),
        // Newer, but not brokered requests (e3 shares the prefix), or in
        // another vault (e5).
        (
            "e3",
            "2026-01-01T00:00:05.000000Z",
            "proxy.injection_failed",
            work,
        ),
        ("e4", "2026-01-01T00:00:06.000000Z", "rule.create", work),
        ("e5", "2026-01-01T00:00:07.000000Z", "rule.create", idle),
    ] {
        sqlx::query(
            "INSERT INTO audit_events (id, at, actor, action, outcome, vault_id, target, detail) \
             VALUES (?, ?, 'user:test', ?, 'success', ?, 'rule:r1', '{}')",
        )
        .bind(uuid_like(id))
        .bind(at)
        .bind(action)
        .bind(vault.to_string())
        .execute(&pool)
        .await
        .expect("audit event");
    }
    pool.close().await;

    let store = SqliteStore::connect(&url).await.expect("upgrade");
    let latest = store
        .latest_at(&work, "proxy.inject")
        .await
        .expect("latest in work");
    assert_eq!(
        latest.map(|at| at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
        Some("2026-01-01T00:00:03Z".to_string()),
        "the newest exact match, not a longer action or another vault's event"
    );
    assert_eq!(
        store
            .latest_at(&idle, "proxy.inject")
            .await
            .expect("latest in idle"),
        None
    );

    // One index entry: no scan of the vault's events and no sort.
    let pool = SqlitePoolOptions::new()
        .connect(&url)
        .await
        .expect("reopen");
    let plan: Vec<String> = sqlx::query(
        "EXPLAIN QUERY PLAN SELECT at FROM audit_events WHERE vault_id = ? AND action = ? ORDER BY at DESC LIMIT 1",
    )
    .bind(work.to_string())
    .bind("proxy.inject")
    .fetch_all(&pool)
    .await
    .expect("query plan")
    .iter()
    .map(|r| sqlx::Row::get::<String, _>(r, "detail"))
    .collect();
    assert!(
        plan.iter()
            .any(|d| d.contains("audit_events_vault_action_at")),
        "expected the vault and action index, got {plan:?}"
    );
    assert!(
        !plan.iter().any(|d| d.contains("TEMP B-TREE")),
        "expected no sort, got {plan:?}"
    );
}
