// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! argon2id password hashing (OWASP baseline: 19 MiB, t=2, p=1).

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};

use crate::error::AuthError;

pub const MIN_PASSWORD_LEN: usize = 12;
pub const MAX_PASSWORD_LEN: usize = 1024;

fn hasher() -> Result<Argon2<'static>, AuthError> {
    let params = Params::new(19 * 1024, 2, 1, None).map_err(|e| AuthError::Hashing {
        reason: format!("invalid argon2 parameters: {e}"),
    })?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

pub fn check_password_policy(password: &str) -> Result<(), AuthError> {
    let len = password.chars().count();
    if len < MIN_PASSWORD_LEN {
        return Err(AuthError::WeakPassword {
            reason: format!("must be at least {MIN_PASSWORD_LEN} characters (got {len})"),
        });
    }
    if password.len() > MAX_PASSWORD_LEN {
        return Err(AuthError::WeakPassword {
            reason: format!("must be at most {MAX_PASSWORD_LEN} bytes"),
        });
    }
    Ok(())
}

pub fn hash_password(password: &str) -> Result<String, AuthError> {
    check_password_policy(password)?;
    let salt = SaltString::generate(&mut OsRng);
    hasher()?
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| AuthError::Hashing {
            reason: e.to_string(),
        })
}

/// Returns `Ok(false)` for a wrong password and `Err` only for a corrupt hash.
pub fn verify_password(stored_hash: &str, password: &str) -> Result<bool, AuthError> {
    if password.len() > MAX_PASSWORD_LEN {
        return Ok(false);
    }
    let parsed = PasswordHash::new(stored_hash).map_err(|e| AuthError::MalformedHash {
        reason: e.to_string(),
    })?;
    Ok(hasher()?
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

/// A valid argon2id hash of a random password, used to keep login timing
/// identical whether or not the username exists.
pub fn dummy_hash() -> Result<String, AuthError> {
    hash_password("dummy-password-for-timing-equalisation")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify() {
        let hash = hash_password("correct horse battery").unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password(&hash, "correct horse battery").unwrap());
        assert!(!verify_password(&hash, "wrong horse battery").unwrap());
    }

    #[test]
    fn policy_rejects_short_passwords() {
        assert!(matches!(
            hash_password("short"),
            Err(AuthError::WeakPassword { .. })
        ));
    }

    #[test]
    fn corrupt_hash_is_an_error() {
        assert!(matches!(
            verify_password("not-a-hash", "whatever-password"),
            Err(AuthError::MalformedHash { .. })
        ));
    }
}
