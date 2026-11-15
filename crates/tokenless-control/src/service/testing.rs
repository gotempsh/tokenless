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
use crate::store::{CredentialStore, RbacAuthorizer};
use crate::{ControlConfig, ControlServices, ServiceStores};

pub async fn services() -> (Arc<MemoryStore>, ControlServices) {
    services_with(|store| store).await
}

/// [`services`] whose credential store is `credentials` wrapped around the
/// memory store, for tests that interpose on it.
pub async fn services_with<C: CredentialStore + 'static>(
    credentials: impl FnOnce(Arc<MemoryStore>) -> Arc<C>,
) -> (Arc<MemoryStore>, ControlServices) {
    let store = Arc::new(MemoryStore::new());
    let cipher = Arc::new(
        Envelope::open(&AesGcmCipher::generate_key(), store.clone())
            .await
            .unwrap(),
    );
    let cs = ControlServices::new(
        ServiceStores {
            credentials: credentials(store.clone()),
            policy: store.clone(),
            audit: store.clone(),
            nodes: store.clone(),
            alerts: store.clone(),
            tripwires: store.clone(),
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
                git: None,
            },
        )
        .await
        .unwrap();
    (vault.id, rule.id)
}

/// The id of the test person called `name`: the same for every call, so a
/// caller built without the store matches the account made with it.
pub fn person_id(name: &str) -> tokenless_core::ids::UserId {
    let n = name
        .bytes()
        .fold(0u64, |h, b| h.wrapping_mul(31).wrapping_add(u64::from(b)))
        & 0xffff_ffff_ffff;
    format!("00000000-0000-4000-8000-{n:012x}").parse().unwrap()
}

/// A person's caller, signed in with a fresh step-up. `role` is their
/// instance role; their vault roles come from [`enrol`] and [`join`].
pub fn person_caller(name: &str, role: tokenless_core::authz::Role) -> Caller {
    use tokenless_core::authz::{Principal, PrincipalKind};
    Caller {
        principal: Principal {
            kind: PrincipalKind::User,
            actor: format!("user:{}", person_id(name)),
            role,
            vault: None,
        },
        step_up_at: Some(chrono::Utc::now()),
        second_factor: true,
        launch: None,
        sign_in: Default::default(),
    }
}

/// Makes the account behind `caller`, named after its id.
pub async fn enrol(identity: &dyn crate::store::IdentityStore, caller: &Caller) {
    let id = caller.user_id().unwrap();
    identity
        .insert_user(
            crate::model::User {
                id,
                username: format!("person-{}", &id.to_string()[24..]),
                password_hash: String::new(),
                totp_secret_enc: None,
                totp_last_step: None,
                role: caller.principal.role,
                created_at: chrono::Utc::now(),
                disabled_at: None,
                sso: None,
            },
            &[],
        )
        .await
        .unwrap();
}

/// Gives the person behind `caller` `role` in the vault.
pub async fn join(
    members: &dyn crate::store::MembershipStore,
    caller: &Caller,
    vault: &VaultId,
    role: tokenless_core::authz::Role,
) {
    members
        .put_vault_member(
            crate::model::VaultMember {
                vault_id: *vault,
                user_id: caller.user_id().unwrap(),
                username: String::new(),
                role,
                added_by: "user:test".into(),
                added_at: chrono::Utc::now(),
            },
            &[],
        )
        .await
        .unwrap();
}
