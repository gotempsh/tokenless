// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Sealed envelopes: X25519 ECDH with an ephemeral key, HKDF-SHA256 and
//! AES-256-GCM. Used to deliver credentials to one data plane node so only
//! that node's private key can open them.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::CoreError;

pub use x25519_dalek::{PublicKey as SealPublicKey, StaticSecret as SealSecretKey};

// Predates the rename to tokenless and is kept: changing it invalidates
// existing sealed secrets.
const INFO: &[u8] = b"credential-broker/seal/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    /// Ephemeral X25519 public key, base64.
    pub epk: String,
    /// AES-GCM nonce, base64.
    pub nonce: String,
    /// Ciphertext with tag, base64.
    pub ct: String,
}

fn derive_key(
    shared: &[u8; 32],
    epk: &PublicKey,
    recipient: &PublicKey,
) -> Result<Zeroizing<[u8; 32]>, CoreError> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(epk.as_bytes());
    salt[32..].copy_from_slice(recipient.as_bytes());
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(INFO, okm.as_mut())
        .map_err(|e| CoreError::crypto("seal.hkdf", e.to_string()))?;
    Ok(okm)
}

pub fn seal(recipient: &PublicKey, plaintext: &[u8], aad: &[u8]) -> Result<Sealed, CoreError> {
    let ephemeral = EphemeralSecret::random_from_rng(OsRng);
    let epk = PublicKey::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(recipient);
    if !shared.was_contributory() {
        return Err(CoreError::crypto(
            "seal",
            "recipient key is a low-order point",
        ));
    }
    let key = derive_key(shared.as_bytes(), &epk, recipient)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|e| CoreError::crypto("seal.aes", e.to_string()))?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CoreError::crypto("seal.encrypt", "AES-GCM encryption failed"))?;
    Ok(Sealed {
        epk: STANDARD.encode(epk.as_bytes()),
        nonce: STANDARD.encode(nonce),
        ct: STANDARD.encode(ct),
    })
}

fn decode_fixed<const N: usize>(field: &str, value: &str) -> Result<[u8; N], CoreError> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|e| CoreError::encoding(field, e))?;
    bytes
        .try_into()
        .map_err(|_| CoreError::encoding(field, format!("expected {N} bytes")))
}

pub fn open(
    secret: &StaticSecret,
    sealed: &Sealed,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    let epk = PublicKey::from(decode_fixed::<32>("sealed.epk", &sealed.epk)?);
    let nonce = decode_fixed::<12>("sealed.nonce", &sealed.nonce)?;
    let ct = STANDARD
        .decode(&sealed.ct)
        .map_err(|e| CoreError::encoding("sealed.ct", e))?;
    let shared = secret.diffie_hellman(&epk);
    if !shared.was_contributory() {
        return Err(CoreError::crypto(
            "open",
            "ephemeral key is a low-order point",
        ));
    }
    let recipient = PublicKey::from(secret);
    let key = derive_key(shared.as_bytes(), &epk, &recipient)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|e| CoreError::crypto("open.aes", e.to_string()))?;
    cipher
        .decrypt(Nonce::from_slice(&nonce), Payload { msg: &ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| CoreError::crypto("open.decrypt", "authentication failed (wrong key or AAD)"))
}

pub fn encode_public_key(key: &PublicKey) -> String {
    STANDARD.encode(key.as_bytes())
}

pub fn decode_public_key(value: &str) -> Result<PublicKey, CoreError> {
    Ok(PublicKey::from(decode_fixed::<32>(
        "x25519 public key",
        value,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let sealed = seal(&public, b"hello", b"aad").unwrap();
        assert_eq!(open(&secret, &sealed, b"aad").unwrap().as_slice(), b"hello");
    }

    #[test]
    fn wrong_aad_or_key_fails() {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let sealed = seal(&public, b"hello", b"node-1").unwrap();
        assert!(open(&secret, &sealed, b"node-2").is_err());
        let other = StaticSecret::random_from_rng(OsRng);
        assert!(open(&other, &sealed, b"node-1").is_err());
    }

    #[test]
    fn low_order_recipient_is_rejected() {
        let zero = PublicKey::from([0u8; 32]);
        assert!(seal(&zero, b"x", b"").is_err());
    }

    #[test]
    fn public_key_encoding_round_trips() {
        let public = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        assert_eq!(
            decode_public_key(&encode_public_key(&public))
                .unwrap()
                .as_bytes(),
            public.as_bytes()
        );
        assert!(decode_public_key("AAAA").is_err());
    }
}
