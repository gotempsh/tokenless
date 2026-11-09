// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Envelope encryption under a root key the operator supplies.
//!
//! ```text
//! root key            supplied at start (a file or TOKENLESS_ROOT_KEY), never stored here
//!  └ instance key     random, stored in the database wrapped by the root key
//!     └ data keys     random, stored wrapped by the instance key:
//!        ├ instance   signing and CA keys, authenticator secrets, variables
//!        └ vault/<id> that vault's credentials
//! ```
//!
//! A copy of the database alone decrypts nothing. Replacing the root key
//! re-wraps the instance key and touches no secret.
//!
//! Ciphertext layout: `0x02 || scope(16) || inner`, where `scope` is the
//! vault ID (all zeros for the instance scope) and `inner` is the data
//! key's [`AesGcmCipher`] output.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokenless_core::audit::{AuditEvent, AuditOutcome};
use tokenless_core::ids::VaultId;
use tracing::info;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::cipher::{AesGcmCipher, KeyScope, SecretCipher, FORMAT_V1};
use crate::error::ControlError;
use crate::store::{CiphertextOwner, NodeStore, StoredCiphertext};

const FORMAT_V2: u8 = 2;
const SCOPE_LEN: usize = 16;
/// Key material names under this prefix belong to the hierarchy itself.
const PREFIX: &str = "envelope/";
const INSTANCE_KEY: &str = "envelope/instance-key";

fn data_key_name(scope: KeyScope) -> String {
    match scope {
        KeyScope::Instance => format!("{PREFIX}data-key/instance"),
        KeyScope::Vault(id) => format!("{PREFIX}data-key/vault/{id}"),
    }
}

fn scope_bytes(scope: KeyScope) -> [u8; SCOPE_LEN] {
    match scope {
        KeyScope::Instance => [0; SCOPE_LEN],
        KeyScope::Vault(id) => *id.0.as_bytes(),
    }
}

fn scope_from_bytes(bytes: &[u8]) -> Result<KeyScope, ControlError> {
    let uuid = Uuid::from_slice(bytes)
        .map_err(|e| ControlError::crypto("envelope.decrypt", format!("bad scope: {e}")))?;
    Ok(if uuid.is_nil() {
        KeyScope::Instance
    } else {
        KeyScope::Vault(VaultId(uuid))
    })
}

fn to_key(name: &str, bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>, ControlError> {
    let key: [u8; 32] = bytes.try_into().map_err(|_| {
        ControlError::crypto("envelope.key", format!("key '{name}' is not 32 bytes"))
    })?;
    Ok(Zeroizing::new(key))
}

/// What a stored value was encrypted with before the hierarchy existed,
/// and the associated data it was bound to.
fn legacy_binding(owner: &CiphertextOwner) -> Option<(KeyScope, Vec<u8>)> {
    match owner {
        CiphertextOwner::Credential { id, vault_id } => Some((
            KeyScope::Vault(*vault_id),
            crate::service::policy::credential_aad(id, vault_id),
        )),
        CiphertextOwner::Variable { id } => {
            Some((KeyScope::Instance, crate::service::render::variable_aad(id)))
        }
        CiphertextOwner::UserTotp { id } => {
            Some((KeyScope::Instance, crate::service::auth::totp_aad(id)))
        }
        CiphertextOwner::KeyMaterial { name } if !name.starts_with(PREFIX) => {
            Some((KeyScope::Instance, crate::keys::aad(name)))
        }
        // Written only under the hierarchy, never by an older version.
        CiphertextOwner::KeyMaterial { .. } | CiphertextOwner::OidcClientSecret { .. } => None,
    }
}

/// The key hierarchy, opened with the root key.
pub struct Envelope {
    store: Arc<dyn NodeStore>,
    instance_key: AesGcmCipher,
    data_keys: Mutex<HashMap<KeyScope, Arc<AesGcmCipher>>>,
}

impl Envelope {
    /// Opens the hierarchy, creating it on first start. Secrets stored by a
    /// version without it (encrypted directly under what is now the root
    /// key) are re-encrypted under their data keys in one transaction.
    pub async fn open(
        root_key: &[u8; 32],
        store: Arc<dyn NodeStore>,
    ) -> Result<Self, ControlError> {
        let root = AesGcmCipher::new(root_key)?;
        let stored = store.list_ciphertexts().await?;
        let legacy: Vec<StoredCiphertext> = stored
            .into_iter()
            .filter(|c| {
                c.ciphertext.first() == Some(&FORMAT_V1) && legacy_binding(&c.owner).is_some()
            })
            .collect();
        // Check the root key opens the existing secrets before writing
        // anything under it: a mistyped key must not become the root.
        if let Some(first) = legacy.first() {
            if let Some((_, aad)) = legacy_binding(&first.owner) {
                root.open(&first.ciphertext, &aad).map_err(|_| {
                    ControlError::crypto(
                        "envelope.open",
                        "this root key does not decrypt the existing secrets; start with the master.key this data was created with",
                    )
                })?;
            }
        }
        let wrapped = match store.get_key_material(INSTANCE_KEY).await? {
            Some(wrapped) => wrapped,
            None => {
                let fresh = AesGcmCipher::generate_key();
                let wrapped = root.seal(fresh.as_ref(), INSTANCE_KEY.as_bytes())?;
                info!("created the instance key");
                store
                    .put_key_material_if_absent(INSTANCE_KEY, wrapped)
                    .await?
            }
        };
        let instance = root.open(&wrapped, INSTANCE_KEY.as_bytes()).map_err(|_| {
            ControlError::crypto(
                "envelope.open",
                "the root key does not match the one this data is encrypted with; start with the original root key (--root-key-file or TOKENLESS_ROOT_KEY)",
            )
        })?;
        let envelope = Self {
            store,
            instance_key: AesGcmCipher::new(&*to_key(INSTANCE_KEY, &instance)?)?,
            data_keys: Mutex::new(HashMap::new()),
        };
        envelope.migrate(&root, legacy).await?;
        Ok(envelope)
    }

    /// Whether the store holds no secret yet, so a new root key may be
    /// created for it.
    pub async fn is_empty(store: &dyn NodeStore) -> Result<bool, ControlError> {
        Ok(store.list_ciphertexts().await?.is_empty())
    }

    async fn migrate(
        &self,
        root: &AesGcmCipher,
        legacy: Vec<StoredCiphertext>,
    ) -> Result<(), ControlError> {
        if legacy.is_empty() {
            return Ok(());
        }
        let mut changes = Vec::with_capacity(legacy.len());
        for old in legacy {
            let Some((scope, aad)) = legacy_binding(&old.owner) else {
                continue;
            };
            let plaintext = root.open(&old.ciphertext, &aad).map_err(|e| {
                ControlError::crypto(
                    "envelope.migrate",
                    format!("{:?} could not be decrypted: {e}", old.owner),
                )
            })?;
            let new = self.encrypt(scope, &plaintext, &aad).await?;
            changes.push((old, new));
        }
        let event = AuditEvent::new("system", "keys.migrate", AuditOutcome::Success)
            .detail("count", changes.len().to_string());
        let replaced = self.store.replace_ciphertexts(&changes, &[event]).await?;
        info!(
            count = replaced,
            "re-encrypted stored secrets under the key hierarchy"
        );
        Ok(())
    }

    /// Re-wraps the instance key under `new_root`. No secret is touched.
    pub async fn rotate_root(
        store: &dyn NodeStore,
        old_root: &[u8; 32],
        new_root: &[u8; 32],
    ) -> Result<(), ControlError> {
        let wrapped = store.get_key_material(INSTANCE_KEY).await?.ok_or_else(|| {
            ControlError::crypto(
                "envelope.rotate",
                "there is no instance key yet; start the server once first",
            )
        })?;
        let instance = AesGcmCipher::new(old_root)?
            .open(&wrapped, INSTANCE_KEY.as_bytes())
            .map_err(|_| {
                ControlError::crypto(
                    "envelope.rotate",
                    "the current root key does not match the one this data is encrypted with",
                )
            })?;
        let rewrapped = AesGcmCipher::new(new_root)?.seal(&instance, INSTANCE_KEY.as_bytes())?;
        let event = AuditEvent::new("system", "keys.rotate_root", AuditOutcome::Success);
        store
            .replace_key_material(INSTANCE_KEY, rewrapped, &[event])
            .await?;
        Ok(())
    }

    fn cached(&self, scope: KeyScope) -> Result<Option<Arc<AesGcmCipher>>, ControlError> {
        Ok(self
            .data_keys
            .lock()
            .map_err(|_| ControlError::crypto("envelope.cache", "data key cache lock poisoned"))?
            .get(&scope)
            .cloned())
    }

    fn unwrap_data_key(
        &self,
        scope: KeyScope,
        wrapped: &[u8],
    ) -> Result<Arc<AesGcmCipher>, ControlError> {
        let name = data_key_name(scope);
        let key = self
            .instance_key
            .open(wrapped, name.as_bytes())
            .map_err(|e| ControlError::crypto("envelope.key", format!("data key '{name}': {e}")))?;
        let cipher = Arc::new(AesGcmCipher::new(&*to_key(&name, &key)?)?);
        self.data_keys
            .lock()
            .map_err(|_| ControlError::crypto("envelope.cache", "data key cache lock poisoned"))?
            .insert(scope, cipher.clone());
        Ok(cipher)
    }

    /// The scope's data key, created on first use when `create`.
    async fn data_key(
        &self,
        scope: KeyScope,
        create: bool,
    ) -> Result<Arc<AesGcmCipher>, ControlError> {
        if let Some(cipher) = self.cached(scope)? {
            return Ok(cipher);
        }
        let name = data_key_name(scope);
        let wrapped = match self.store.get_key_material(&name).await? {
            Some(wrapped) => wrapped,
            None if create => {
                let fresh = AesGcmCipher::generate_key();
                let wrapped = self.instance_key.seal(fresh.as_ref(), name.as_bytes())?;
                // Two first uses at once both insert; the first one stored wins.
                self.store
                    .put_key_material_if_absent(&name, wrapped)
                    .await?
            }
            None => {
                return Err(ControlError::crypto(
                    "envelope.decrypt",
                    format!("there is no data key '{name}' for this secret"),
                ))
            }
        };
        self.unwrap_data_key(scope, &wrapped)
    }
}

#[async_trait]
impl SecretCipher for Envelope {
    async fn encrypt(
        &self,
        scope: KeyScope,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, ControlError> {
        let inner = self.data_key(scope, true).await?.seal(plaintext, aad)?;
        let mut out = Vec::with_capacity(1 + SCOPE_LEN + inner.len());
        out.push(FORMAT_V2);
        out.extend_from_slice(&scope_bytes(scope));
        out.extend_from_slice(&inner);
        Ok(out)
    }

    async fn decrypt(
        &self,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ControlError> {
        if ciphertext.len() < 1 + SCOPE_LEN || ciphertext[0] != FORMAT_V2 {
            return Err(ControlError::crypto(
                "envelope.decrypt",
                "ciphertext is truncated or has an unknown format",
            ));
        }
        let scope = scope_from_bytes(&ciphertext[1..=SCOPE_LEN])?;
        self.data_key(scope, false)
            .await?
            .open(&ciphertext[1 + SCOPE_LEN..], aad)
    }
}

#[cfg(test)]
mod tests;
