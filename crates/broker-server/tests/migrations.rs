// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Upgrades of an existing database: what each migration keeps and drops.

#![allow(clippy::expect_used)]

use std::borrow::Cow;

use broker_server::store::SqliteStore;
use sqlx::sqlite::SqlitePoolOptions;
use tokenless_control::model::{AuditQuery, PageRequest};
use tokenless_control::store::{AuditSink, IdentityStore, PolicyStore};
use tokenless_core::ids::{ApiKeyId, CredentialId, SessionId, VaultId};

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

#[tokio::test]
async fn upgrading_indexes_the_audit_log_by_service() {
    let (_dir, url, pool) = database_before(12).await;
    let vault = VaultId::new();
    let credential = CredentialId::new().to_string();
    let other = CredentialId::new().to_string();
    sqlx::query("INSERT INTO vaults (id, name, scope, created_at) VALUES (?, 'work', ?, ?)")
        .bind(vault.to_string())
        .bind(format!("vault:{vault}"))
        .bind(AT)
        .execute(&pool)
        .await
        .expect("vault");
    for (id, at, action, target, detail) in [
        (
            "e1",
            "2026-01-01T00:00:01.000000Z",
            "credential.create",
            format!("credential:{credential}"),
            "{}".to_string(),
        ),
        (
            "e2",
            "2026-01-01T00:00:02.000000Z",
            "proxy.inject",
            "rule:r1".to_string(),
            format!(r#"{{"credential_id":"{credential}"}}"#),
        ),
        (
            "e3",
            "2026-01-01T00:00:03.000000Z",
            "proxy.inject",
            "rule:r2".to_string(),
            format!(r#"{{"credential_id":"{other}"}}"#),
        ),
        (
            "e4",
            "2026-01-01T00:00:04.000000Z",
            "vault.create",
            format!("vault:{vault}"),
            "{}".to_string(),
        ),
        // A rule created before the detail key was renamed.
        (
            "e5",
            "2026-01-01T00:00:05.000000Z",
            "rule.create",
            "rule:r1".to_string(),
            format!(r#"{{"credential":"{credential}"}}"#),
        ),
    ] {
        sqlx::query(
            "INSERT INTO audit_events (id, at, actor, action, outcome, vault_id, target, detail) \
             VALUES (?, ?, 'user:test', ?, 'success', ?, ?, ?)",
        )
        .bind(uuid_like(id))
        .bind(at)
        .bind(action)
        .bind(vault.to_string())
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
            vault_id: Some(vault),
            credential_id: Some(credential.parse().expect("credential id")),
            ..Default::default()
        })
        .await
        .expect("query by service");
    let actions: Vec<_> = found.items.iter().map(|e| e.action.as_str()).collect();
    assert_eq!(
        actions,
        ["rule.create", "proxy.inject", "credential.create"],
        "events recorded before the upgrade are found, and only this service's"
    );
    assert_eq!(found.total, 3);

    // The service index, even with the vault the page passes along: not a
    // walk through every event in the vault.
    let pool = SqlitePoolOptions::new()
        .connect(&url)
        .await
        .expect("reopen");
    let plan: Vec<String> = sqlx::query(
        "EXPLAIN QUERY PLAN SELECT * FROM audit_events WHERE 1 = 1 AND +vault_id = ? \
         AND credential_ref = ? ORDER BY at DESC, id LIMIT ? OFFSET ?",
    )
    .bind(vault.to_string())
    .bind(&credential)
    .bind(20)
    .bind(0)
    .fetch_all(&pool)
    .await
    .expect("query plan")
    .iter()
    .map(|r| sqlx::Row::get::<String, _>(r, "detail"))
    .collect();
    assert!(
        plan.iter()
            .any(|d| d.contains("audit_events_credential_at")),
        "expected the service index, got {plan:?}"
    );
}

#[tokio::test]
async fn upgrading_numbers_the_audit_log_for_export_in_write_order() {
    use tokenless_control::store::AuditExportStore;
    use tokenless_core::audit::{AuditEvent, AuditOutcome};

    let (_dir, url, pool) = database_before(17).await;
    let mut written = Vec::new();
    for i in 0..3 {
        let id = tokenless_core::ids::AuditEventId::new().to_string();
        sqlx::query(
            "INSERT INTO audit_events (id, at, actor, action, outcome, vault_id, target, detail) \
             VALUES (?, ?, 'system', ?, 'success', NULL, NULL, '{}')",
        )
        .bind(&id)
        .bind(AT)
        .bind(format!("old.{i}"))
        .execute(&pool)
        .await
        .expect("audit event");
        written.push(id);
    }
    pool.close().await;

    let store = SqliteStore::connect(&url).await.expect("upgrade");
    assert_eq!(store.latest_audit_seq().await.expect("latest"), 3);
    // A new event is numbered after the old ones.
    store
        .record(&[AuditEvent::new("system", "new", AuditOutcome::Success)])
        .await
        .expect("record");
    let events = store.audit_events_after(0, 10).await.expect("events");
    let numbers: Vec<u64> = events.iter().map(|(n, _)| *n).collect();
    let actions: Vec<&str> = events.iter().map(|(_, e)| e.action.as_str()).collect();
    assert_eq!(numbers, [1, 2, 3, 4]);
    assert_eq!(actions, ["old.0", "old.1", "old.2", "new"]);
    let ids: Vec<String> = events[..3].iter().map(|(_, e)| e.id.to_string()).collect();
    assert_eq!(ids, written);
}

#[tokio::test]
async fn upgrading_keeps_sign_ins_and_gives_them_an_id() {
    let (_dir, url, pool) = database_before(19).await;
    let user = tokenless_core::ids::UserId::new();
    for hash in ["sign-in-a", "sign-in-b"] {
        sqlx::query(
            "INSERT INTO ui_sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, '2099-01-01T00:00:00.000000Z')",
        )
        .bind(hash)
        .bind(user.to_string())
        .bind(AT)
        .execute(&pool)
        .await
        .expect("sign-in");
    }
    pool.close().await;

    let store = SqliteStore::connect(&url).await.expect("upgrade");
    let a = store
        .get_ui_session("sign-in-a")
        .await
        .expect("get")
        .expect("the sign-in survives the upgrade");
    let b = store
        .get_ui_session("sign-in-b")
        .await
        .expect("get")
        .expect("the sign-in survives the upgrade");
    assert_ne!(a.id, b.id, "each sign-in gets its own id");
    // Use before the upgrade was never recorded: an idle timeout counts
    // from the upgrade, not from signing in.
    let since = chrono::Utc::now() - a.last_used_at;
    assert!(
        a.last_used_at > a.created_at && since < chrono::TimeDelta::seconds(60),
        "last used at the upgrade, not at sign-in: {}",
        a.last_used_at
    );
    assert_eq!(a.user_agent, None);
    let listed = store
        .list_ui_sessions(
            &user,
            chrono::Utc::now(),
            None,
            PageRequest::new(Some(1), Some(10)),
        )
        .await
        .expect("list");
    assert_eq!(listed.total, 2);
}

#[tokio::test]
async fn upgrading_keeps_everyone_s_access_as_vault_memberships() {
    use tokenless_control::model::{SignInScope, VaultGrant};
    use tokenless_control::store::{MembershipStore, SsoStore};
    use tokenless_core::authz::Role;
    use tokenless_core::ids::{InviteId, OidcProviderId, UserId};

    let (_dir, url, pool) = database_before(23).await;
    let (work, side) = (VaultId::new(), VaultId::new());
    for (id, name) in [(work, "work"), (side, "side")] {
        sqlx::query("INSERT INTO vaults (id, name, scope, created_at) VALUES (?, ?, ?, ?)")
            .bind(id.to_string())
            .bind(name)
            .bind(format!("vault:{id}"))
            .bind(AT)
            .execute(&pool)
            .await
            .expect("vault");
    }
    let provider = OidcProviderId::new();
    sqlx::query(
        "INSERT INTO oidc_providers (id, slug, name, issuer, client_id, client_secret_enc, redirect_uri, scopes, groups_claim, username_claim, role_mappings, enabled, created_at, updated_at) \
         VALUES (?, 'corp', 'Corp', 'https://idp.example.test', 'tokenless', NULL, 'https://broker.example.test/api/v1/auth/oidc/callback', '[]', 'groups', 'preferred_username', ?, 1, ?, ?)",
    )
    .bind(provider.to_string())
    .bind(r#"[{"group":"devs","role":"editor"},{"group":"ops","role":"admin"}]"#)
    .bind(AT)
    .bind(AT)
    .execute(&pool)
    .await
    .expect("provider");
    let people = [
        ("root", "admin", None),
        ("dev", "editor", None),
        ("auditor", "viewer", None),
        ("sso-dev", "editor", Some(provider)),
    ];
    let mut ids = Vec::new();
    for (name, role, sso) in people {
        let id = UserId::new();
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, role, created_at, sso_provider_id, sso_subject) VALUES (?, ?, 'hash', ?, ?, ?, ?)",
        )
        .bind(id.to_string())
        .bind(name)
        .bind(role)
        .bind(AT)
        .bind(sso.map(|p| p.to_string()))
        .bind(sso.map(|_| format!("subject-{name}")))
        .execute(&pool)
        .await
        .expect("user");
        ids.push(id);
    }
    for (hash, role) in [("invite-editor", "editor"), ("invite-admin", "admin")] {
        sqlx::query(
            "INSERT INTO invites (id, token_hash, role, created_by, created_at, expires_at) VALUES (?, ?, ?, 'user:test', ?, '2099-01-01T00:00:00.000000Z')",
        )
        .bind(InviteId::new().to_string())
        .bind(hash)
        .bind(role)
        .bind(AT)
        .execute(&pool)
        .await
        .expect("invite");
    }
    sqlx::query(
        "INSERT INTO ui_sessions (token_hash, user_id, created_at, expires_at, id, last_used_at) VALUES ('sign-in', ?, ?, '2099-01-01T00:00:00.000000Z', ?, ?)",
    )
    .bind(ids[1].to_string())
    .bind(AT)
    .bind(tokenless_core::ids::SignInId::new().to_string())
    .bind(AT)
    .execute(&pool)
    .await
    .expect("sign-in");
    sqlx::query(
        "INSERT INTO ui_sessions (token_hash, user_id, created_at, expires_at, id, last_used_at, user_agent) VALUES ('cli-sign-in', ?, ?, '2099-01-01T00:00:00.000000Z', ?, ?, 'tokenless/0.9.0')",
    )
    .bind(ids[1].to_string())
    .bind(AT)
    .bind(tokenless_core::ids::SignInId::new().to_string())
    .bind(AT)
    .execute(&pool)
    .await
    .expect("CLI sign-in");
    pool.close().await;

    let store = SqliteStore::connect(&url).await.expect("upgrade");
    let both = |role| {
        let mut grants = vec![
            VaultGrant {
                vault_id: work,
                role,
            },
            VaultGrant {
                vault_id: side,
                role,
            },
        ];
        grants.sort_by_key(|g| g.vault_id.to_string());
        grants
    };
    for (id, (name, old, _)) in ids.iter().zip(people) {
        let user = store.get_user(id).await.expect("get").expect("user kept");
        let instance = if old == "admin" {
            Role::Admin
        } else {
            Role::Member
        };
        assert_eq!(user.role, instance, "{name} is an instance {instance}");
        let vault_role = Role::parse(old).expect("old role");
        assert_eq!(
            store.user_vaults(id).await.expect("vaults"),
            both(vault_role),
            "{name} keeps the {old} role in every vault"
        );
    }
    let sso_member = store
        .list_vault_members(&work, PageRequest::new(None, None))
        .await
        .expect("members")
        .items
        .into_iter()
        .find(|m| m.username == "sso-dev")
        .expect("listed");
    assert_eq!(
        sso_member.added_by, "sso:corp",
        "its groups can take it back"
    );

    let editor_invite = store
        .get_invite_by_token_hash("invite-editor")
        .await
        .expect("get")
        .expect("kept");
    assert_eq!(editor_invite.role, Role::Member);
    assert_eq!(editor_invite.vaults, both(Role::Editor));
    let admin_invite = store
        .get_invite_by_token_hash("invite-admin")
        .await
        .expect("get")
        .expect("kept");
    assert_eq!(
        (admin_invite.role, admin_invite.vaults.len()),
        (Role::Admin, 0)
    );

    let mappings = store
        .get_oidc_provider(&provider)
        .await
        .expect("get")
        .expect("kept")
        .role_mappings;
    assert_eq!(mappings[0].group, "devs");
    assert_eq!(mappings[0].role, Role::Member);
    let mut mapped = mappings[0].vaults.clone();
    mapped.sort_by_key(|g| g.vault_id.to_string());
    assert_eq!(mapped, both(Role::Editor));
    assert_eq!(
        (mappings[1].role, mappings[1].vaults.len()),
        (Role::Admin, 0)
    );

    let sign_in = store
        .get_ui_session("sign-in")
        .await
        .expect("get")
        .expect("kept");
    assert_eq!(sign_in.scope, SignInScope::Full);
    let cli = store
        .get_ui_session("cli-sign-in")
        .await
        .expect("get")
        .expect("kept");
    assert_eq!(
        cli.scope,
        SignInScope::Launch,
        "a terminal sign-in from before only starts sessions"
    );
}
