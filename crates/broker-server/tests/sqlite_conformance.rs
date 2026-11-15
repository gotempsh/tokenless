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
            if let Err(failure) = tokenless_conformance::$name(&store).await {
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
suite!(sso_store_suite);
suite!(audit_export_store_suite);
suite!(alert_store_suite);
suite!(tripwire_store_suite);
suite!(membership_store_suite);
suite!(node_store_suite);
suite!(audited_writes_suite);
suite!(vault_deletion_suite);

/// An embedded data plane whose control services run on the SQLite store.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_embedded_data_plane_on_sqlite_passes_the_dataplane_suite() {
    use std::sync::Arc;

    use tokenless_control::cipher::AesGcmCipher;
    use tokenless_control::envelope::Envelope;
    use tokenless_control::probe::DisabledProber;
    use tokenless_control::store::RbacAuthorizer;
    use tokenless_control::{Caller, ControlConfig, ControlServices, ServiceStores};
    use tokenless_core::authz::{Principal, Role};

    let (_dir, store) = store().await;
    let store = Arc::new(store);
    let cipher = Arc::new(
        Envelope::open(&AesGcmCipher::generate_key(), store.clone())
            .await
            .expect("envelope"),
    );
    let control = Arc::new(
        ControlServices::new(
            ServiceStores {
                credentials: store.clone(),
                policy: store.clone(),
                audit: store.clone(),
                nodes: store.clone(),
                alerts: store.clone(),
                tripwires: store.clone(),
            },
            Arc::new(RbacAuthorizer),
            cipher,
            Arc::new(DisabledProber),
            ControlConfig {
                lease_secs: 3,
                ..ControlConfig::default()
            },
        )
        .await
        .expect("control services"),
    );
    let host = Caller::service(Principal::service("conformance-host", Role::Admin, None));
    if let Err(failure) =
        tokenless_conformance::dataplane::dataplane_suite(control.clone(), &host).await
    {
        panic!("{failure}");
    }
    // It leaves nothing behind in the embedder's stores.
    let page = tokenless_control::model::PageRequest::new(None, Some(100));
    let nodes = control.nodes.list_nodes(&host, page).await.unwrap().items;
    assert!(!nodes.is_empty());
    assert!(
        nodes.iter().all(|n| n.revoked_at.is_some()),
        "a node left enrolled"
    );
    let vaults = control.policy.list_vaults(&host, page).await.unwrap().items;
    assert!(
        vaults
            .iter()
            .all(|v| !v.name.starts_with("conformance-dataplane")),
        "a vault left behind"
    );
}

/// If the audit row cannot be written the change it describes must not be
/// committed either. A reused event id makes the audit insert fail.
#[tokio::test]
async fn a_failed_audit_insert_rolls_back_the_change() {
    use tokenless_control::model::{PageRequest, Vault};
    use tokenless_control::store::{AuditSink, PolicyStore};
    use tokenless_core::audit::{AuditEvent, AuditOutcome};
    use tokenless_core::ids::VaultId;
    use tokenless_core::scope::Scope;

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
        .list_vaults(
            &tokenless_control::model::VaultScope::All,
            PageRequest::new(None, None),
        )
        .await
        .expect("list vaults");
    assert_eq!(vaults.total, 0);
}

/// Writers that read before they write must wait their turn, not fail with
/// "database is locked" because another write landed in between.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_writers_wait_instead_of_failing() {
    use std::sync::Arc;
    use tokenless_control::model::Variable;
    use tokenless_control::store::CredentialStore;
    use tokenless_core::ids::VariableId;

    let (_dir, store) = store().await;
    let store = Arc::new(store);
    let now = chrono::Utc::now();
    let mut ids = Vec::new();
    for i in 0..32 {
        let variable = Variable {
            id: VariableId::new(),
            key: format!("KEY_{i}"),
            created_by: "user:test".into(),
            created_at: now,
            updated_by: "user:test".into(),
            updated_at: now,
        };
        ids.push(variable.id);
        store
            .insert_variable(variable, b"v".to_vec(), &[])
            .await
            .expect("insert variable");
    }
    // Each delete reads the variable and its references, then deletes it.
    let mut tasks = tokio::task::JoinSet::new();
    for id in ids {
        let store = Arc::clone(&store);
        tasks.spawn(async move { store.delete_variable(&id, &[]).await });
    }
    while let Some(result) = tasks.join_next().await {
        result.expect("task").expect("concurrent delete");
    }
}
