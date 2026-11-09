// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Signing outgoing webhooks the [Standard Webhooks] way, so a receiver can
//! check them with an existing library.
//!
//! The secret is `whsec_<base64 key>`. A request carries `webhook-id`,
//! `webhook-timestamp` (Unix seconds) and `webhook-signature`:
//! `v1,<base64 HMAC-SHA256(key, "{id}.{timestamp}.{body}")>`.
//!
//! [Standard Webhooks]: https://www.standardwebhooks.com/

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::AuthError;

pub const SECRET_PREFIX: &str = "whsec_";
pub const ID_HEADER: &str = "webhook-id";
pub const TIMESTAMP_HEADER: &str = "webhook-timestamp";
pub const SIGNATURE_HEADER: &str = "webhook-signature";

/// A new signing secret: `whsec_` and 32 random bytes in base64.
pub fn new_secret() -> String {
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(key.as_mut());
    format!("{SECRET_PREFIX}{}", STANDARD.encode(key.as_ref()))
}

fn key(secret: &str) -> Result<Zeroizing<Vec<u8>>, AuthError> {
    let malformed = || AuthError::MalformedToken {
        expected_prefix: SECRET_PREFIX.into(),
    };
    let encoded = secret.strip_prefix(SECRET_PREFIX).ok_or_else(malformed)?;
    let key = Zeroizing::new(STANDARD.decode(encoded).map_err(|_| malformed())?);
    if key.is_empty() {
        return Err(malformed());
    }
    Ok(key)
}

/// The `webhook-signature` value for one request.
pub fn sign(secret: &str, id: &str, timestamp: i64, body: &[u8]) -> Result<String, AuthError> {
    let key = key(secret)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).map_err(|_| AuthError::MalformedToken {
        expected_prefix: SECRET_PREFIX.into(),
    })?;
    mac.update(id.as_bytes());
    mac.update(b".");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    Ok(format!(
        "v1,{}",
        STANDARD.encode(mac.finalize().into_bytes())
    ))
}

/// Where a secret can be told apart without showing it: its last four
/// characters.
pub fn secret_hint(secret: &str) -> String {
    let tail: String = secret
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{SECRET_PREFIX}…{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The test vector the Standard Webhooks reference libraries use.
    #[test]
    fn matches_the_reference_vector() {
        let signature = sign(
            "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw",
            "msg_p5jXN8AQM9LWM0D4loKWxJek",
            1_614_265_330,
            br#"{"test": 2432232314}"#,
        )
        .unwrap();
        assert_eq!(signature, "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=");
    }

    #[test]
    fn a_new_secret_signs_and_differs_each_time() {
        let a = new_secret();
        let b = new_secret();
        assert!(a.starts_with(SECRET_PREFIX));
        assert_ne!(a, b);
        assert_eq!(key(&a).unwrap().len(), 32);
        let one = sign(&a, "id", 1, b"body").unwrap();
        assert_ne!(one, sign(&b, "id", 1, b"body").unwrap());
        assert_ne!(one, sign(&a, "id", 2, b"body").unwrap());
        assert_ne!(one, sign(&a, "id", 1, b"body!").unwrap());
    }

    #[test]
    fn a_malformed_secret_is_refused() {
        for bad in [
            "",
            "whsec_",
            "whsec_!!!",
            "MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw",
        ] {
            assert!(
                sign(bad, "id", 1, b"").is_err(),
                "{bad:?} should be refused"
            );
        }
    }

    #[test]
    fn the_hint_shows_only_the_end() {
        assert_eq!(secret_hint("whsec_abcdefgh"), "whsec_…efgh");
    }
}
