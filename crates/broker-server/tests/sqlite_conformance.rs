// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Runs the trait conformance suites against the SQLite store.

#![allow(clippy::expect_used)]

use broker_server::store::SqliteStore;

async fn store() -> (tempfile::TempDir, SqliteStore) {
    let dir = tempfile::tempdir().expect("tempdir");
    let url = format!("sqlite://{}", dir.path().join("broker.db").display());
    let store = SqliteStore::connect(&url).await.expect("connect");
    (dir, store)
}

macro_rules! suite {
    ($name:ident) => {
        #[tokio::test]
        async fn $name() {
            let (_dir, store) = store().await;
            if let Err(failure) = broker_conformance::$name(&store).await {
                panic!("{failure}");
            }
        }
    };
}

suite!(credential_store_suite);
suite!(variable_store_suite);
suite!(policy_store_suite);
suite!(bundle_store_suite);
suite!(audit_sink_suite);
suite!(identity_store_suite);
suite!(user_management_suite);
suite!(node_store_suite);
suite!(audited_writes_suite);
suite!(vault_deletion_suite);

/// If the audit row cannot be written the change it describes must not be
/// committed either. A reused event id makes the audit insert fail.
#[tokio::test]
async fn a_failed_audit_insert_rolls_back_the_change() {
    use broker_control::model::{PageRequest, Vault};
    use broker_control::store::{AuditSink, PolicyStore};
    use broker_core::audit::{AuditEvent, AuditOutcome};
    use broker_core::ids::VaultId;
    use broker_core::scope::Scope;

    let (_dir, store) = store().await;
    let event = AuditEvent::new("user:test", "vault.create", AuditOutcome::Success);
    store
        .record(std::slice::from_ref(&event))
        .await
        .expect("seed event");

    let id = VaultId::new();
    let vault = Vault {
        id,
        name: "rolled-back".into(),
        scope: Scope::for_vault(&id),
        created_at: chrono::Utc::now(),
    };
    let result = store.insert_vault(vault, &[event]).await;
    assert!(result.is_err(), "reused audit id must fail the write");
    assert!(
        store.get_vault(&id).await.expect("get vault").is_none(),
        "the vault must not survive a failed audit insert"
    );
    let vaults = store
        .list_vaults(PageRequest::new(None, None))
        .await
        .expect("list vaults");
    assert_eq!(vaults.total, 0);
}
