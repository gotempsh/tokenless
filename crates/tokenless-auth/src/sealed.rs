// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Small values sealed for the browser to carry and give back: encrypted
//! and authenticated (AES-256-GCM), so it can neither read nor change
//! them. A key is derived per purpose from an instance secret with HKDF,
//! so no two uses can open each other's values.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::hkdf::{Salt, HKDF_SHA256};
use zeroize::Zeroizing;

use crate::error::AuthError;

/// A key for one purpose, such as the single sign-on flow cookie.
pub struct SealKey {
    key: LessSafeKey,
}

impl std::fmt::Debug for SealKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SealKey(***)")
    }
}

impl SealKey {
    /// Derives the key for `purpose` from a 32-byte instance secret.
    pub fn derive(secret: &[u8; 32], purpose: &str) -> Result<Self, AuthError> {
        let failed = |_| AuthError::KeyDerivation {
            purpose: purpose.to_string(),
        };
        let mut bytes = Zeroizing::new([0u8; 32]);
        let info = [purpose.as_bytes()];
        Salt::new(HKDF_SHA256, b"tokenless-sealed-v1")
            .extract(secret)
            .expand(&info, &AES_256_GCM)
            .and_then(|okm| okm.fill(bytes.as_mut()))
            .map_err(failed)?;
        let key = UnboundKey::new(&AES_256_GCM, bytes.as_ref()).map_err(failed)?;
        Ok(Self {
            key: LessSafeKey::new(key),
        })
    }

    /// Encrypts `plaintext`, bound to `context`, as base64url.
    pub fn seal(&self, context: &[u8], plaintext: &[u8]) -> String {
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let mut out = Vec::with_capacity(NONCE_LEN + plaintext.len() + AES_256_GCM.tag_len());
        out.extend_from_slice(&nonce);
        let mut body = plaintext.to_vec();
        // Fails only for inputs over ~64 GiB.
        if self
            .key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(context),
                &mut body,
            )
            .is_err()
        {
            body.clear();
        }
        out.extend_from_slice(&body);
        URL_SAFE_NO_PAD.encode(out)
    }

    /// The plaintext, or `None` when `sealed` was not made by this key for
    /// this context, or was changed.
    pub fn open(&self, context: &[u8], sealed: &str) -> Option<Zeroizing<Vec<u8>>> {
        let raw = URL_SAFE_NO_PAD.decode(sealed).ok()?;
        if raw.len() < NONCE_LEN + AES_256_GCM.tag_len() {
            return None;
        }
        let (nonce, body) = raw.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce).ok()?;
        let mut body = Zeroizing::new(body.to_vec());
        let plain = self
            .key
            .open_in_place(nonce, Aad::from(context), body.as_mut_slice())
            .ok()?;
        Some(Zeroizing::new(plain.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn a_sealed_value_opens_only_with_its_key_and_context() {
        let key = SealKey::derive(&[7; 32], "sso-flow").unwrap();
        let sealed = key.seal(b"ctx", b"hello");
        assert!(!sealed.contains("hello"));
        assert_eq!(key.open(b"ctx", &sealed).unwrap().as_slice(), b"hello");
        assert!(key.open(b"other", &sealed).is_none());
        assert!(SealKey::derive(&[8; 32], "sso-flow")
            .unwrap()
            .open(b"ctx", &sealed)
            .is_none());
        assert!(SealKey::derive(&[7; 32], "another-purpose")
            .unwrap()
            .open(b"ctx", &sealed)
            .is_none());
        // Same plaintext, a fresh nonce each time.
        assert_ne!(sealed, key.seal(b"ctx", b"hello"));
    }

    #[test]
    fn a_changed_or_malformed_value_does_not_open() {
        let key = SealKey::derive(&[7; 32], "sso-flow").unwrap();
        let sealed = key.seal(b"ctx", b"hello");
        let mut raw = URL_SAFE_NO_PAD.decode(&sealed).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        assert!(key.open(b"ctx", &URL_SAFE_NO_PAD.encode(&raw)).is_none());
        assert!(key.open(b"ctx", "").is_none());
        assert!(key.open(b"ctx", "not base64 !").is_none());
        assert!(key.open(b"ctx", "AAAA").is_none());
        assert_eq!(
            key.open(b"ctx", &key.seal(b"ctx", b"")).unwrap().as_slice(),
            b""
        );
    }
}
