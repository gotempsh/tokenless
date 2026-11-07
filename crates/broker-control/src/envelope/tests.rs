// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use crate::memory::MemoryStore;

fn store() -> Arc<MemoryStore> {
    Arc::new(MemoryStore::new())
}

#[tokio::test]
async fn secrets_round_trip_under_their_scope_key() {
    let store = store();
    let root = AesGcmCipher::generate_key();
    let envelope = Envelope::open(&root, store.clone()).await.unwrap();
    let vault = VaultId::new();

    let ct = envelope
        .encrypt(KeyScope::Vault(vault), b"vault-secret", b"aad")
        .await
        .unwrap();
    assert_eq!(ct[0], FORMAT_V2);
    assert!(!ct.windows(12).any(|w| w == b"vault-secret"));
    assert_eq!(
        envelope.decrypt(&ct, b"aad").await.unwrap().as_slice(),
        b"vault-secret"
    );
    assert!(envelope.decrypt(&ct, b"other").await.is_err());

    // Each vault and the instance get their own data key, stored wrapped.
    envelope
        .encrypt(KeyScope::Instance, b"x", b"")
        .await
        .unwrap();
    let names: Vec<String> = store
        .list_ciphertexts()
        .await
        .unwrap()
        .into_iter()
        .filter_map(|c| match c.owner {
            CiphertextOwner::KeyMaterial { name } => Some(name),
            _ => None,
        })
        .collect();
    assert!(names.contains(&INSTANCE_KEY.to_string()));
    assert!(names.contains(&data_key_name(KeyScope::Instance)));
    assert!(names.contains(&data_key_name(KeyScope::Vault(vault))));

    // Pointing a ciphertext at another vault's key does not decrypt it.
    let other = VaultId::new();
    envelope
        .encrypt(KeyScope::Vault(other), b"y", b"")
        .await
        .unwrap();
    let mut moved = ct.clone();
    moved[1..=SCOPE_LEN].copy_from_slice(other.0.as_bytes());
    assert!(envelope.decrypt(&moved, b"aad").await.is_err());
}

#[tokio::test]
async fn the_database_alone_needs_the_root_key() {
    let store = store();
    let root = AesGcmCipher::generate_key();
    let ct = Envelope::open(&root, store.clone())
        .await
        .unwrap()
        .encrypt(KeyScope::Instance, b"secret", b"")
        .await
        .unwrap();

    // Restarting with the same root key reads it.
    let again = Envelope::open(&root, store.clone()).await.unwrap();
    assert_eq!(again.decrypt(&ct, b"").await.unwrap().as_slice(), b"secret");

    // Another root key opens nothing, and says why.
    let err = Envelope::open(&AesGcmCipher::generate_key(), store.clone())
        .await
        .err()
        .unwrap()
        .to_string();
    assert!(err.contains("root key does not match"), "{err}");
}

#[tokio::test]
async fn rotating_the_root_key_rewraps_only_the_instance_key() {
    let store = store();
    let old_root = AesGcmCipher::generate_key();
    let new_root = AesGcmCipher::generate_key();
    let ct = Envelope::open(&old_root, store.clone())
        .await
        .unwrap()
        .encrypt(KeyScope::Vault(VaultId::new()), b"secret", b"")
        .await
        .unwrap();

    assert!(
        Envelope::rotate_root(store.as_ref(), &new_root, &old_root)
            .await
            .is_err(),
        "the current root key must be the right one"
    );
    Envelope::rotate_root(store.as_ref(), &old_root, &new_root)
        .await
        .unwrap();

    let rotated = Envelope::open(&new_root, store.clone()).await.unwrap();
    assert_eq!(
        rotated.decrypt(&ct, b"").await.unwrap().as_slice(),
        b"secret"
    );
    assert!(Envelope::open(&old_root, store.clone()).await.is_err());
}

#[tokio::test]
async fn rotating_before_the_first_start_says_so() {
    let err = Envelope::rotate_root(
        store().as_ref(),
        &AesGcmCipher::generate_key(),
        &AesGcmCipher::generate_key(),
    )
    .await
    .err()
    .unwrap()
    .to_string();
    assert!(err.contains("start the server once first"), "{err}");
}
