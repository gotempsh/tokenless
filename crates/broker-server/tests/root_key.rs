// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The root key on a real server and database: kept outside the data
//! directory, a copy of the directory decrypts nothing; it can be replaced;
//! and data from before the key hierarchy moves into it.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use broker_server::launcher::account::{self, SignIn};
use broker_server::root_key::{write_new, LEGACY_FILE};
use broker_server::store::SqliteStore;
use broker_server::{RootKeyInput, Server, ServerConfig};
use chrono::Utc;
use tokenless_control::cipher::AesGcmCipher;
use tokenless_control::model::Page;
use tokenless_control::probe::DisabledProber;
use tokenless_control::service::policy::CreateCredential;
use tokenless_control::store::{NodeStore, RbacAuthorizer};
use tokenless_control::{Caller, ControlConfig, ControlPlane, Stores};
use tokenless_core::authz::{Principal, PrincipalKind, Role};

const TOKEN: &str = "ghp_rootKeyTestToken0123456789abcdefABCD";

fn config(data: &Path, key: Option<&Path>) -> ServerConfig {
    let mut config = ServerConfig::new(data);
    config.api_listen = "127.0.0.1:0".parse().unwrap();
    config.node_listen = "127.0.0.1:0".parse().unwrap();
    config.root_key = key.map(|k| RootKeyInput::File(k.to_path_buf()));
    config
}

fn contains(dir: &Path, needle: &[u8]) -> bool {
    std::fs::read_dir(dir).unwrap().any(|entry| {
        let path = entry.unwrap().path();
        if path.is_dir() {
            contains(&path, needle)
        } else {
            std::fs::read(&path)
                .unwrap()
                .windows(needle.len())
                .any(|w| w == needle)
        }
    })
}

fn admin() -> Caller {
    Caller {
        principal: Principal {
            kind: PrincipalKind::User,
            actor: "user:test-admin".into(),
            role: Role::Admin,
            vault: None,
        },
        step_up_at: Some(Utc::now()),
        second_factor: false,
    }
}

fn credential() -> CreateCredential {
    CreateCredential {
        name: "github".into(),
        template_id: "github".into(),
        template_version: None,
        host_override: vec![],
        fields: BTreeMap::from([("token".to_string(), TOKEN.to_string())]),
        custom_headers: vec![],
        substitutions: vec![],
        not_after: None,
    }
}

async fn credentials_in(control: &ControlPlane) -> u64 {
    let vaults: Page<_> = control
        .policy
        .list_vaults(&admin(), Default::default())
        .await
        .unwrap();
    let mut n = 0;
    for vault in vaults.items {
        n += control
            .policy
            .list_credentials(&admin(), &vault.id, Default::default())
            .await
            .unwrap()
            .total;
    }
    n
}

#[tokio::test]
async fn a_copy_of_the_data_directory_without_the_root_key_decrypts_nothing() {
    let data = tempfile::tempdir().unwrap();
    let keys = tempfile::tempdir().unwrap();
    let key = keys.path().join("root.key");
    write_new(&key, &AesGcmCipher::generate_key()).unwrap();

    let server = Server::start(config(data.path(), Some(&key)))
        .await
        .unwrap();
    assert!(server.root_key_in_data_dir.is_none());
    let vault = server
        .control
        .policy
        .create_vault(&admin(), "work")
        .await
        .unwrap();
    server
        .control
        .policy
        .create_credential(&admin(), &vault.id, credential())
        .await
        .unwrap();
    let password = server.initial_admin.as_ref().unwrap().password.clone();
    server.shutdown();

    // Neither the token nor the key is anywhere in the data directory.
    assert!(!contains(data.path(), TOKEN.as_bytes()));
    assert!(!contains(data.path(), &std::fs::read(&key).unwrap()));
    assert!(!data.path().join("root.key").exists());

    // Without the key the server refuses, and leaves no new key behind.
    let err = Server::start(config(data.path(), None))
        .await
        .err()
        .unwrap()
        .to_string();
    assert!(err.contains("root key that is not here"), "{err}");
    assert!(!data.path().join("root.key").exists());

    // With the wrong key it refuses too.
    let wrong = keys.path().join("wrong.key");
    write_new(&wrong, &AesGcmCipher::generate_key()).unwrap();
    let err = Server::start(config(data.path(), Some(&wrong)))
        .await
        .err()
        .unwrap()
        .to_string();
    assert!(err.contains("root key does not match"), "{err}");

    // Replacing the key: the old one stops working, the new one opens it all.
    let new_key = keys.path().join("root-2.key");
    broker_server::rotate_root_key(&config(data.path(), Some(&key)), &new_key)
        .await
        .unwrap();
    assert!(Server::start(config(data.path(), Some(&key)))
        .await
        .is_err());
    let server = Server::start(config(data.path(), Some(&new_key)))
        .await
        .unwrap();
    assert_eq!(credentials_in(&server.control).await, 1);
    let url = format!("http://{}", server.api_addr);
    assert!(matches!(
        account::sign_in(&url, "admin", &password, None)
            .await
            .unwrap(),
        SignIn::Done(_)
    ));
    server.shutdown();

    // Rotating to a file that exists is refused before anything changes.
    assert!(
        broker_server::rotate_root_key(&config(data.path(), Some(&new_key)), &key)
            .await
            .is_err()
    );
    assert!(Server::start(config(data.path(), Some(&new_key)))
        .await
        .map(|s| s.shutdown())
        .is_ok());
}

#[tokio::test]
async fn data_from_before_the_root_key_moves_under_it() {
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(data.path()).unwrap();
    // As an earlier version left it: master.key, and every secret
    // encrypted directly under it.
    let master = AesGcmCipher::generate_key();
    std::fs::write(data.path().join(LEGACY_FILE), master.as_ref()).unwrap();
    let url = format!("sqlite://{}", data.path().join("broker.db").display());
    let store = Arc::new(SqliteStore::connect(&url).await.unwrap());
    let stores = Stores {
        credentials: store.clone(),
        policy: store.clone(),
        audit: store.clone(),
        identity: store.clone(),
        sso: store.clone(),
        audit_export: store.clone(),
        nodes: store.clone(),
    };
    let old = ControlPlane::new(
        stores,
        Arc::new(RbacAuthorizer),
        Arc::new(AesGcmCipher::new(&master).unwrap()),
        Arc::new(DisabledProber),
        Arc::new(tokenless_control::service::sso::oidc::NoTransport),
        Arc::new(tokenless_control::service::audit_export::DisabledWebhookTransport),
        ControlConfig::default(),
    )
    .await
    .unwrap();
    let password = old
        .auth
        .create_initial_admin()
        .await
        .unwrap()
        .unwrap()
        .password;
    let vault = old.policy.create_vault(&admin(), "work").await.unwrap();
    old.policy
        .create_credential(&admin(), &vault.id, credential())
        .await
        .unwrap();
    drop(old);
    let legacy = store.list_ciphertexts().await.unwrap();
    assert!(!legacy.is_empty() && legacy.iter().all(|c| c.ciphertext[0] == 1));
    drop(store);

    let server = Server::start(config(data.path(), None)).await.unwrap();
    // master.key is now the root key, and still in the data directory.
    assert_eq!(
        server.root_key_in_data_dir.as_deref(),
        Some(data.path().join(LEGACY_FILE).as_path())
    );
    assert!(server.initial_admin.is_none());
    assert_eq!(credentials_in(&server.control).await, 1);
    let api = format!("http://{}", server.api_addr);
    assert!(matches!(
        account::sign_in(&api, "admin", &password, None)
            .await
            .unwrap(),
        SignIn::Done(_)
    ));
    server.shutdown();

    // Every secret moved under the hierarchy; only its wrapped keys remain
    // in the old format.
    let store = SqliteStore::connect(&url).await.unwrap();
    for stored in store.list_ciphertexts().await.unwrap() {
        let hierarchy = matches!(&stored.owner,
            tokenless_control::store::CiphertextOwner::KeyMaterial { name } if name.starts_with("envelope/"));
        assert!(
            hierarchy || stored.ciphertext[0] == 2,
            "{:?} not migrated",
            stored.owner
        );
    }
    assert!(!contains(data.path(), TOKEN.as_bytes()));
}
