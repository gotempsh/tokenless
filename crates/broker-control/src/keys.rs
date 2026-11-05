// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Long-lived key material, created on first start and stored encrypted.

use broker_core::session::SessionSigner;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;
use tracing::info;
use zeroize::Zeroizing;

use crate::cipher::SecretCipher;
use crate::error::ControlError;
use crate::pki::{generate_ca, CaMaterial};
use crate::store::NodeStore;

const SNAPSHOT_KEY: &str = "snapshot-signing-key";
const SESSION_KEY: &str = "session-signing-key";
const NODE_CA: &str = "node-ca";
const INTERCEPTION_CA: &str = "interception-ca";
const CSRF_KEY: &str = "csrf-key";

pub struct KeyRing {
    pub snapshot_key: SigningKey,
    pub session_signer: SessionSigner,
    pub node_ca: CaMaterial,
    pub interception_ca: CaMaterial,
    pub csrf_key: Zeroizing<[u8; 32]>,
}

fn aad(name: &str) -> Vec<u8> {
    format!("key-material|{name}").into_bytes()
}

async fn load_or_create(
    store: &dyn NodeStore,
    cipher: &dyn SecretCipher,
    name: &str,
    generate: impl FnOnce() -> Result<Zeroizing<Vec<u8>>, ControlError>,
) -> Result<Zeroizing<Vec<u8>>, ControlError> {
    let stored = match store.get_key_material(name).await? {
        Some(ct) => ct,
        None => {
            let plaintext = generate()?;
            let ct = cipher.encrypt(&plaintext, &aad(name))?;
            info!(key = name, "generated new key material");
            store.put_key_material_if_absent(name, ct).await?
        }
    };
    cipher.decrypt(&stored, &aad(name)).map_err(|e| {
        ControlError::crypto(
            "keyring.load",
            format!("key '{name}' could not be decrypted with the master key: {e}"),
        )
    })
}

fn random_32() -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(vec![0u8; 32]);
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn to_array(name: &str, bytes: &[u8]) -> Result<[u8; 32], ControlError> {
    bytes
        .try_into()
        .map_err(|_| ControlError::crypto("keyring.load", format!("key '{name}' is not 32 bytes")))
}

impl KeyRing {
    pub async fn load_or_create(
        store: &dyn NodeStore,
        cipher: &dyn SecretCipher,
    ) -> Result<Self, ControlError> {
        let snapshot = load_or_create(store, cipher, SNAPSHOT_KEY, || Ok(random_32())).await?;
        let session = load_or_create(store, cipher, SESSION_KEY, || Ok(random_32())).await?;
        let csrf = load_or_create(store, cipher, CSRF_KEY, || Ok(random_32())).await?;
        let node_ca = load_or_create(store, cipher, NODE_CA, || {
            Ok(generate_ca("credential-broker node CA")?.to_bytes())
        })
        .await?;
        let interception_ca = load_or_create(store, cipher, INTERCEPTION_CA, || {
            Ok(generate_ca("credential-broker interception CA")?.to_bytes())
        })
        .await?;
        Ok(Self {
            snapshot_key: SigningKey::from_bytes(&to_array(SNAPSHOT_KEY, &snapshot)?),
            session_signer: SessionSigner::new(SigningKey::from_bytes(&to_array(
                SESSION_KEY,
                &session,
            )?)),
            node_ca: CaMaterial::from_bytes(&node_ca)?,
            interception_ca: CaMaterial::from_bytes(&interception_ca)?,
            csrf_key: Zeroizing::new(to_array(CSRF_KEY, &csrf)?),
        })
    }
}
