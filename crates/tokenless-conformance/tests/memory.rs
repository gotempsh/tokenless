// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The reference in-memory store must pass its own conformance suite.

use tokenless_conformance::*;
use tokenless_control::memory::MemoryStore;
use tokenless_control::store::RbacAuthorizer;

#[tokio::test]
async fn memory_store_passes_credential_suite() {
    credential_store_suite(&MemoryStore::new()).await.unwrap();
}

#[tokio::test]
async fn memory_store_passes_variable_suite() {
    variable_store_suite(&MemoryStore::new()).await.unwrap();
}

#[tokio::test]
async fn memory_store_passes_policy_suite() {
    policy_store_suite(&MemoryStore::new()).await.unwrap();
}

#[tokio::test]
async fn memory_store_passes_bundle_suite() {
    bundle_store_suite(&MemoryStore::new()).await.unwrap();
}

#[tokio::test]
async fn memory_store_passes_audit_suite() {
    audit_sink_suite(&MemoryStore::new()).await.unwrap();
}

#[tokio::test]
async fn memory_store_passes_identity_suite() {
    identity_store_suite(&MemoryStore::new()).await.unwrap();
}

#[tokio::test]
async fn memory_store_passes_user_management_suite() {
    user_management_suite(&MemoryStore::new()).await.unwrap();
}

#[tokio::test]
async fn memory_store_passes_node_suite() {
    node_store_suite(&MemoryStore::new()).await.unwrap();
}

#[tokio::test]
async fn memory_store_passes_audited_writes_suite() {
    audited_writes_suite(&MemoryStore::new()).await.unwrap();
}

#[tokio::test]
async fn rbac_authorizer_passes_authorizer_suite() {
    authorizer_suite(&RbacAuthorizer).await.unwrap();
}

#[tokio::test]
async fn memory_store_passes_vault_deletion_suite() {
    vault_deletion_suite(&MemoryStore::new()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_embedded_data_plane_on_the_memory_store_passes_the_dataplane_suite() {
    use std::sync::Arc;

    use tokenless_control::cipher::AesGcmCipher;
    use tokenless_control::envelope::Envelope;
    use tokenless_control::probe::DisabledProber;
    use tokenless_control::{Caller, ControlConfig, ControlServices, ServiceStores};
    use tokenless_core::authz::{Principal, Role};

    let store = Arc::new(MemoryStore::new());
    let cipher = Arc::new(
        Envelope::open(&AesGcmCipher::generate_key(), store.clone())
            .await
            .unwrap(),
    );
    let control = Arc::new(
        ControlServices::new(
            ServiceStores {
                credentials: store.clone(),
                policy: store.clone(),
                audit: store.clone(),
                nodes: store.clone(),
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
        .unwrap(),
    );
    let host = Caller::service(Principal::service("conformance-host", Role::Admin, None));
    if let Err(failure) = dataplane::dataplane_suite(control, &host).await {
        panic!("{failure}");
    }
}
