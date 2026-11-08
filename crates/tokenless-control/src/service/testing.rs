// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Control services on an in-memory store, for the services' tests.

use std::sync::Arc;

use tokenless_core::ids::{RuleId, VaultId};

use super::Caller;
use crate::cipher::AesGcmCipher;
use crate::envelope::Envelope;
use crate::memory::MemoryStore;
use crate::probe::DisabledProber;
use crate::store::RbacAuthorizer;
use crate::{ControlConfig, ControlServices, ServiceStores};

pub async fn services() -> (Arc<MemoryStore>, ControlServices) {
    let store = Arc::new(MemoryStore::new());
    let cipher = Arc::new(
        Envelope::open(&AesGcmCipher::generate_key(), store.clone())
            .await
            .unwrap(),
    );
    let cs = ControlServices::new(
        ServiceStores {
            credentials: store.clone(),
            policy: store.clone(),
            audit: store.clone(),
            nodes: store.clone(),
        },
        Arc::new(RbacAuthorizer),
        cipher,
        Arc::new(DisabledProber),
        ControlConfig::default(),
    )
    .await
    .unwrap();
    (store, cs)
}

/// A vault with one rule a host service may mint sessions for.
pub async fn vault_with_rule(cs: &ControlServices, host: &Caller) -> (VaultId, RuleId) {
    use crate::service::policy::{CreateCredential, CreateRule};
    let vault = cs.policy.create_vault(host, "v").await.unwrap();
    let credential = cs
        .policy
        .create_credential(
            host,
            &vault.id,
            CreateCredential {
                name: "api".into(),
                template_id: "generic-bearer".into(),
                template_version: None,
                host_override: vec!["api.example.com".into()],
                fields: [("token".to_string(), "t".to_string())].into(),
                custom_headers: vec![],
                substitutions: vec![],
                not_after: None,
            },
        )
        .await
        .unwrap();
    let rule = cs
        .policy
        .create_rule(
            host,
            &vault.id,
            CreateRule {
                name: "api".into(),
                credential_id: credential.id,
                hosts: None,
                paths: None,
                methods: None,
                mcp_tools: None,
            },
        )
        .await
        .unwrap();
    (vault.id, rule.id)
}
