// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! CSRF tokens derived from the session: HMAC-SHA256(server key, session
//! token hash). Nothing extra to store, and a token is useless with any other
//! session.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

pub const CSRF_HEADER: &str = "x-csrf-token";

fn mac(key: &[u8; 32], session_token_hash: &str) -> Option<Hmac<Sha256>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).ok()?;
    // Predates the rename to tokenless and is kept: changing it invalidates
    // existing CSRF tokens.
    mac.update(b"credential-broker/csrf/v1\0");
    mac.update(session_token_hash.as_bytes());
    Some(mac)
}

pub fn derive(key: &[u8; 32], session_token_hash: &str) -> String {
    match mac(key, session_token_hash) {
        Some(m) => URL_SAFE_NO_PAD.encode(m.finalize().into_bytes()),
        None => String::new(),
    }
}

pub fn verify(key: &[u8; 32], session_token_hash: &str, presented: &str) -> bool {
    let expected = derive(key, session_token_hash);
    !expected.is_empty() && bool::from(expected.as_bytes().ct_eq(presented.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csrf_is_bound_to_session() {
        let key = [7u8; 32];
        let token = derive(&key, "hash-a");
        assert!(verify(&key, "hash-a", &token));
        assert!(!verify(&key, "hash-b", &token));
        assert!(!verify(&[8u8; 32], "hash-a", &token));
        assert!(!verify(&key, "hash-a", ""));
    }
}
