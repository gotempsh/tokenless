// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Upgrades of an existing database: what each migration keeps and drops.

#![allow(clippy::expect_used)]

use std::borrow::Cow;

use broker_control::model::PageRequest;
use broker_control::store::{IdentityStore, PolicyStore};
use broker_core::ids::{ApiKeyId, VaultId};
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
