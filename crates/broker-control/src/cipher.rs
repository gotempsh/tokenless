// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Encryption at rest. Stores only ever receive ciphertext produced here.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

use crate::error::ControlError;

const FORMAT_V1: u8 = 1;
const NONCE_LEN: usize = 12;

/// Encrypts secrets before they reach a store. An embedding platform can
/// supply its own implementation backed by its key management.
pub trait SecretCipher: Send + Sync {
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, ControlError>;
    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, ControlError>;
}

/// AES-256-GCM with a random 96-bit nonce per message.
/// Layout: `0x01 || nonce(12) || ciphertext+tag`.
pub struct AesGcmCipher {
    cipher: Aes256Gcm,
}

impl AesGcmCipher {
    pub fn new(key: &[u8; 32]) -> Result<Self, ControlError> {
        let cipher =
            Aes256Gcm::new_from_slice(key).map_err(|e| ControlError::crypto("cipher.init", e))?;
        Ok(Self { cipher })
    }

    pub fn generate_key() -> Zeroizing<[u8; 32]> {
        let mut key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(key.as_mut());
        key
    }
}

impl SecretCipher for AesGcmCipher {
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, ControlError> {
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let ct = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| ControlError::crypto("cipher.encrypt", "AES-GCM encryption failed"))?;
        let mut out = Vec::with_capacity(1 + NONCE_LEN + ct.len());
        out.push(FORMAT_V1);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, ControlError> {
        if ciphertext.len() < 1 + NONCE_LEN + 16 || ciphertext[0] != FORMAT_V1 {
            return Err(ControlError::crypto(
                "cipher.decrypt",
                "ciphertext is truncated or has an unknown format",
            ));
        }
        let (nonce, ct) = ciphertext[1..].split_at(NONCE_LEN);
        self.cipher
            .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
            .map(Zeroizing::new)
            .map_err(|_| {
                ControlError::crypto(
                    "cipher.decrypt",
                    "authentication failed (wrong master key or record moved)",
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_aad_binding() {
        let cipher = AesGcmCipher::new(&AesGcmCipher::generate_key()).unwrap();
        let ct = cipher.encrypt(b"secret", b"credential|1").unwrap();
        assert!(!ct.windows(6).any(|w| w == b"secret"));
        assert_eq!(
            cipher.decrypt(&ct, b"credential|1").unwrap().as_slice(),
            b"secret"
        );
        assert!(cipher.decrypt(&ct, b"credential|2").is_err());
    }

    #[test]
    fn wrong_key_and_truncation_fail() {
        let a = AesGcmCipher::new(&AesGcmCipher::generate_key()).unwrap();
        let b = AesGcmCipher::new(&AesGcmCipher::generate_key()).unwrap();
        let ct = a.encrypt(b"x", b"").unwrap();
        assert!(b.decrypt(&ct, b"").is_err());
        assert!(a.decrypt(&ct[..5], b"").is_err());
    }
}
