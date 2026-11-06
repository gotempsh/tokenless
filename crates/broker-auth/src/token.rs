// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! High-entropy bearer tokens. Only the SHA-256 hash is ever stored; the
//! plaintext is returned once to whoever minted it.
//!
//! SHA-256 (not argon2) is the right hash here: these tokens carry 256 bits
//! of randomness, so there is nothing for a slow hash to protect, and they
//! are checked on every API request.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::AuthError;

pub const SESSION_PREFIX: &str = "cbs";
pub const SETUP_PREFIX: &str = "cbsetup";
pub const API_KEY_PREFIX: &str = "cbk";

fn random_part(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    OsRng.fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

/// `<prefix>_<43 chars of base64url>` (256 bits).
pub fn new_token(prefix: &str) -> String {
    format!("{prefix}_{}", random_part(32))
}

pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

pub fn hashes_equal(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// An API key as shown to its owner once: `cbk_<lookup>_<secret>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKeyParts {
    /// Public lookup prefix (`cbk_<lookup>`), stored in clear and shown in lists.
    pub prefix: String,
    pub full: String,
}

const LOOKUP_LEN: usize = 12;
const SECRET_LEN: usize = 43;

pub fn new_api_key() -> ApiKeyParts {
    let lookup = random_part(9);
    let prefix = format!("{API_KEY_PREFIX}_{lookup}");
    let full = format!("{prefix}_{}", random_part(32));
    ApiKeyParts { prefix, full }
}

pub fn parse_api_key(value: &str) -> Result<ApiKeyParts, AuthError> {
    let malformed = || AuthError::MalformedToken {
        expected_prefix: API_KEY_PREFIX.to_string(),
    };
    let rest = value
        .strip_prefix(API_KEY_PREFIX)
        .and_then(|r| r.strip_prefix('_'))
        .ok_or_else(malformed)?;
    // Both parts are base64url, which itself may contain '_', so split by
    // position rather than by separator.
    let is_b64url = |s: &str| {
        s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    if rest.len() != LOOKUP_LEN + 1 + SECRET_LEN || !rest.is_char_boundary(LOOKUP_LEN) {
        return Err(malformed());
    }
    let (lookup, tail) = rest.split_at(LOOKUP_LEN);
    let secret = tail.strip_prefix('_').ok_or_else(malformed)?;
    if !is_b64url(lookup) || !is_b64url(secret) {
        return Err(malformed());
    }
    Ok(ApiKeyParts {
        prefix: format!("{API_KEY_PREFIX}_{lookup}"),
        full: value.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_unique_and_prefixed() {
        let a = new_token(SESSION_PREFIX);
        let b = new_token(SESSION_PREFIX);
        assert_ne!(a, b);
        assert!(a.starts_with("cbs_"));
        assert_eq!(a.len(), 4 + 43);
    }

    #[test]
    fn hashes_are_stable_and_compared_in_constant_time() {
        let t = new_token(SETUP_PREFIX);
        assert!(hashes_equal(&hash_token(&t), &hash_token(&t)));
        assert!(!hashes_equal(&hash_token(&t), &hash_token("other")));
        assert_eq!(hash_token(&t).len(), 64);
    }

    #[test]
    fn api_keys_with_underscores_in_the_lookup_round_trip() {
        // base64url output contains '_' often enough that a separator-based
        // parser rejects roughly one key in six.
        let mut saw_underscore = false;
        for _ in 0..2000 {
            let key = new_api_key();
            saw_underscore |= key.prefix[4..].contains('_');
            assert_eq!(parse_api_key(&key.full).unwrap(), key, "{}", key.full);
        }
        assert!(saw_underscore);
    }

    #[test]
    fn api_keys_round_trip() {
        let key = new_api_key();
        let parsed = parse_api_key(&key.full).unwrap();
        assert_eq!(parsed, key);
        assert!(key.full.starts_with(&key.prefix));
        assert!(parse_api_key("cbk_short_x").is_err());
        assert!(parse_api_key(&format!("{}!", &key.full[..key.full.len() - 1])).is_err());
        assert!(parse_api_key(&key.full.replacen('_', "-", 2)).is_err());
        assert!(parse_api_key("other_abcdefghijkl_x").is_err());
    }
}
