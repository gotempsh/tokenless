// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The reference in-memory store must pass its own conformance suite.

use broker_conformance::*;
use broker_control::memory::MemoryStore;
use broker_control::store::RbacAuthorizer;

#[tokio::test]
async fn memory_store_passes_credential_suite() {
    credential_store_suite(&MemoryStore::new()).await.unwrap();
}

#[tokio::test]
async fn memory_store_passes_policy_suite() {
    policy_store_suite(&MemoryStore::new()).await.unwrap();
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
