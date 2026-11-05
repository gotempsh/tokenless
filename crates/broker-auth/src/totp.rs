// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 6238 TOTP (SHA-1, 6 digits, 30 s) with replay protection: a code is
//! accepted only for a time step later than the last one used.

use totp_rs::{Algorithm, Secret, TOTP};

use crate::error::AuthError;

pub const ISSUER: &str = "credential-broker";
const STEP_SECS: u64 = 30;
const DIGITS: usize = 6;

/// A new random 160-bit secret, base32-encoded.
pub fn generate_secret() -> String {
    match Secret::generate_secret().to_encoded() {
        Secret::Encoded(s) => s,
        Secret::Raw(bytes) => base32_fallback(&bytes),
    }
}

fn base32_fallback(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((buffer >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((buffer << (5 - bits)) & 31) as usize]));
    }
    out
}

fn build(secret_b32: &str, account: &str) -> Result<TOTP, AuthError> {
    let invalid = |reason: String| AuthError::InvalidTotpSecret {
        account: account.to_string(),
        reason,
    };
    let bytes = Secret::Encoded(secret_b32.trim().to_ascii_uppercase())
        .to_bytes()
        .map_err(|e| invalid(e.to_string()))?;
    TOTP::new(
        Algorithm::SHA1,
        DIGITS,
        1,
        STEP_SECS,
        bytes,
        Some(ISSUER.to_string()),
        account.replace(':', "_"),
    )
    .map_err(|e| invalid(e.to_string()))
}

/// The `otpauth://` URL to show as a QR code or paste into an authenticator.
pub fn otpauth_url(secret_b32: &str, account: &str) -> Result<String, AuthError> {
    Ok(build(secret_b32, account)?.get_url())
}

/// Code for a given UNIX time; used by tests and the CLI.
pub fn code_at(secret_b32: &str, unix_secs: u64) -> Result<String, AuthError> {
    Ok(build(secret_b32, "code")?.generate(unix_secs))
}

/// Checks `code` against the current step and one step either side. Returns
/// the matched step so the caller can store it and refuse its reuse.
pub fn verify_code(
    secret_b32: &str,
    account: &str,
    code: &str,
    unix_secs: u64,
    last_used_step: Option<u64>,
) -> Result<Option<u64>, AuthError> {
    let code = code.trim();
    if code.len() != DIGITS || !code.chars().all(|c| c.is_ascii_digit()) {
        return Ok(None);
    }
    let totp = build(secret_b32, account)?;
    let current = unix_secs / STEP_SECS;
    for step in [current.saturating_sub(1), current, current + 1] {
        if last_used_step.is_some_and(|last| step <= last) {
            continue;
        }
        let expected = totp.generate(step * STEP_SECS);
        if subtle::ConstantTimeEq::ct_eq(expected.as_bytes(), code.as_bytes()).into() {
            return Ok(Some(step));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_secret_verifies() {
        let secret = generate_secret();
        assert!(secret.len() >= 32);
        let now = 1_800_000_000;
        let code = code_at(&secret, now).unwrap();
        assert_eq!(
            verify_code(&secret, "admin", &code, now, None).unwrap(),
            Some(now / 30)
        );
        assert_eq!(verify_code(&secret, "admin", "000000x", now, None).unwrap(), None);
    }

    #[test]
    fn replay_is_refused() {
        let secret = generate_secret();
        let now = 1_800_000_000;
        let code = code_at(&secret, now).unwrap();
        let step = verify_code(&secret, "admin", &code, now, None).unwrap();
        assert_eq!(verify_code(&secret, "admin", &code, now, step).unwrap(), None);
    }

    #[test]
    fn skew_of_one_step_is_tolerated() {
        let secret = generate_secret();
        let now = 1_800_000_000;
        let previous = code_at(&secret, now - 30).unwrap();
        assert!(verify_code(&secret, "admin", &previous, now, None)
            .unwrap()
            .is_some());
        let old = code_at(&secret, now - 90).unwrap();
        assert!(verify_code(&secret, "admin", &old, now, None).unwrap().is_none());
    }

    #[test]
    fn url_contains_issuer() {
        let url = otpauth_url(&generate_secret(), "admin").unwrap();
        assert!(url.starts_with("otpauth://totp/"));
        assert!(url.contains("issuer=credential-broker"));
    }

    #[test]
    fn base32_fallback_matches_rfc4648() {
        assert_eq!(base32_fallback(b"foobar"), "MZXW6YTBOI");
    }
}
