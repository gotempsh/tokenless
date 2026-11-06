// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Proxy session tokens: PASETO `v4.public` (Ed25519) carrying
//! [`SessionClaims`]. The control plane signs them; every data plane node
//! verifies them locally with the public keys shipped in its snapshot.

use std::collections::{BTreeMap, HashMap};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::error::CoreError;
use crate::ids::{RuleId, SessionId};
use crate::scope::Scope;

pub const DEFAULT_SESSION_TTL_SECS: u64 = 15 * 60;
pub const MAX_SESSION_TTL_SECS: u64 = 60 * 60;
pub const MAX_RULES_PER_SESSION: usize = 64;
pub const MAX_LABELS: usize = 16;
pub const ISSUER: &str = "credential-broker";

const HEADER: &str = "v4.public.";
const IMPLICIT_ASSERTION: &[u8] = b"credential-broker/proxy-session/v1";
const MAX_TOKEN_LEN: usize = 16 * 1024;
const SIGNATURE_LEN: usize = 64;
/// Tolerated clock skew for `nbf`/`iat` only. Expiry is never extended.
const NOT_BEFORE_LEEWAY_SECS: i64 = 30;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionClaims {
    pub iss: String,
    pub jti: SessionId,
    pub scope: Scope,
    pub rules: Vec<RuleId>,
    pub iat: DateTime<Utc>,
    pub nbf: DateTime<Utc>,
    pub exp: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_limit: Option<u64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

pub fn validate_labels(labels: &BTreeMap<String, String>) -> Result<(), CoreError> {
    if labels.len() > MAX_LABELS {
        return Err(CoreError::InvalidLabel {
            key: format!("({} labels)", labels.len()),
            reason: format!("at most {MAX_LABELS} labels are allowed"),
        });
    }
    for (key, value) in labels {
        let key_ok = !key.is_empty()
            && key.len() <= 64
            && key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
        if !key_ok {
            return Err(CoreError::InvalidLabel {
                key: key.clone(),
                reason: "keys must be 1-64 characters of a-z, 0-9, '_', '-' or '.'".into(),
            });
        }
        if value.len() > 256 || value.chars().any(char::is_control) {
            return Err(CoreError::InvalidLabel {
                key: key.clone(),
                reason: "values must be at most 256 characters without control characters".into(),
            });
        }
    }
    Ok(())
}

impl SessionClaims {
    pub fn new(
        scope: Scope,
        rules: Vec<RuleId>,
        ttl_secs: u64,
        request_limit: Option<u64>,
        labels: BTreeMap<String, String>,
        now: DateTime<Utc>,
    ) -> Result<Self, CoreError> {
        if ttl_secs == 0 || ttl_secs > MAX_SESSION_TTL_SECS {
            return Err(CoreError::InvalidTtl {
                requested_secs: ttl_secs,
                max_secs: MAX_SESSION_TTL_SECS,
            });
        }
        if rules.is_empty() || rules.len() > MAX_RULES_PER_SESSION {
            return Err(CoreError::InvalidScope {
                input: scope.to_string(),
                reason: format!("a session needs 1-{MAX_RULES_PER_SESSION} rules"),
            });
        }
        if request_limit == Some(0) {
            return Err(CoreError::InvalidScope {
                input: scope.to_string(),
                reason: "request_limit must be at least 1 when set".into(),
            });
        }
        validate_labels(&labels)?;
        let ttl = Duration::seconds(i64::try_from(ttl_secs).unwrap_or(i64::MAX));
        Ok(Self {
            iss: ISSUER.to_string(),
            jti: SessionId::new(),
            scope,
            rules,
            iat: now,
            nbf: now,
            exp: now + ttl,
            request_limit,
            labels,
        })
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SessionError {
    #[error("session token is malformed: {reason}")]
    Malformed { reason: String },
    #[error("session token was signed by unknown key '{kid}'")]
    UnknownKey { kid: String },
    #[error("session token signature is invalid (key '{kid}')")]
    BadSignature { kid: String },
    #[error("session {session_id} expired at {expired_at}")]
    Expired {
        session_id: SessionId,
        expired_at: DateTime<Utc>,
    },
    #[error("session {session_id} is not valid before {not_before}")]
    NotYetValid {
        session_id: SessionId,
        not_before: DateTime<Utc>,
    },
    #[error("session token issuer '{issuer}' is not '{ISSUER}'")]
    WrongIssuer { issuer: String },
}

fn malformed(reason: impl Into<String>) -> SessionError {
    SessionError::Malformed {
        reason: reason.into(),
    }
}

/// Short, stable identifier for an Ed25519 public key.
pub fn key_id(key: &VerifyingKey) -> String {
    let digest = Sha256::digest(key.as_bytes());
    digest[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// PASETO pre-authentication encoding.
fn pae(pieces: &[&[u8]]) -> Vec<u8> {
    fn le64(n: usize) -> [u8; 8] {
        ((n as u64) & 0x7FFF_FFFF_FFFF_FFFF).to_le_bytes()
    }
    let mut out = Vec::with_capacity(8 + pieces.iter().map(|p| p.len() + 8).sum::<usize>());
    out.extend_from_slice(&le64(pieces.len()));
    for piece in pieces {
        out.extend_from_slice(&le64(piece.len()));
        out.extend_from_slice(piece);
    }
    out
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Footer {
    kid: String,
}

/// Signs `message` as a PASETO `v4.public` token. An empty footer is
/// omitted from the token, as the specification requires.
pub fn sign_v4_public(key: &SigningKey, message: &[u8], footer: &[u8], implicit: &[u8]) -> String {
    let signature = key.sign(&pae(&[HEADER.as_bytes(), message, footer, implicit]));
    let mut payload = Vec::with_capacity(message.len() + SIGNATURE_LEN);
    payload.extend_from_slice(message);
    payload.extend_from_slice(&signature.to_bytes());
    let mut token = format!("{HEADER}{}", URL_SAFE_NO_PAD.encode(payload));
    if !footer.is_empty() {
        token.push('.');
        token.push_str(&URL_SAFE_NO_PAD.encode(footer));
    }
    token
}

/// A decoded, not yet verified `v4.public` token.
pub struct UnverifiedV4Public {
    message: Vec<u8>,
    signature: Signature,
    /// Empty when the token carries no footer.
    pub footer: Vec<u8>,
}

impl UnverifiedV4Public {
    pub fn parse(token: &str) -> Result<Self, SessionError> {
        if token.len() > MAX_TOKEN_LEN {
            return Err(malformed(format!(
                "token is longer than {MAX_TOKEN_LEN} bytes"
            )));
        }
        let body = token
            .strip_prefix(HEADER)
            .ok_or_else(|| malformed("token is not a v4.public PASETO"))?;
        let (payload_b64, footer_b64) = match body.split_once('.') {
            Some((p, f)) => (p, Some(f)),
            None => (body, None),
        };
        let footer = match footer_b64 {
            Some(f) => URL_SAFE_NO_PAD
                .decode(f)
                .map_err(|e| malformed(format!("footer is not base64url: {e}")))?,
            None => Vec::new(),
        };
        let payload = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|e| malformed(format!("payload is not base64url: {e}")))?;
        if payload.len() < SIGNATURE_LEN {
            return Err(malformed("payload is shorter than a signature"));
        }
        let (message, sig_bytes) = payload.split_at(payload.len() - SIGNATURE_LEN);
        let signature = Signature::from_slice(sig_bytes)
            .map_err(|e| malformed(format!("signature has the wrong length: {e}")))?;
        Ok(Self {
            message: message.to_vec(),
            signature,
            footer,
        })
    }

    /// Verifies the signature (with the implicit assertion) and returns the
    /// message. `kid` only labels the error.
    pub fn verify(
        self,
        key: &VerifyingKey,
        implicit: &[u8],
        kid: &str,
    ) -> Result<Vec<u8>, SessionError> {
        key.verify_strict(
            &pae(&[HEADER.as_bytes(), &self.message, &self.footer, implicit]),
            &self.signature,
        )
        .map_err(|_| SessionError::BadSignature {
            kid: kid.to_string(),
        })?;
        Ok(self.message)
    }
}

pub struct SessionSigner {
    kid: String,
    key: SigningKey,
}

impl SessionSigner {
    pub fn new(key: SigningKey) -> Self {
        Self {
            kid: key_id(&key.verifying_key()),
            key,
        }
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    pub fn sign(&self, claims: &SessionClaims) -> Result<String, CoreError> {
        let message =
            serde_json::to_vec(claims).map_err(|e| CoreError::encoding("session claims", e))?;
        let footer = serde_json::to_vec(&Footer {
            kid: self.kid.clone(),
        })
        .map_err(|e| CoreError::encoding("session footer", e))?;
        Ok(sign_v4_public(
            &self.key,
            &message,
            &footer,
            IMPLICIT_ASSERTION,
        ))
    }
}

/// Verifies a token against a set of published keys (by key ID) and the
/// current time. Revocation and request limits are checked by the caller.
pub fn verify_session(
    token: &str,
    keys: &HashMap<String, VerifyingKey>,
    now: DateTime<Utc>,
) -> Result<SessionClaims, SessionError> {
    let parsed = UnverifiedV4Public::parse(token)?;
    if parsed.footer.is_empty() {
        return Err(malformed("token has no footer"));
    }
    let kid = serde_json::from_slice::<Footer>(&parsed.footer)
        .map_err(|e| malformed(format!("footer is not valid JSON: {e}")))?
        .kid;
    let key = keys
        .get(&kid)
        .ok_or_else(|| SessionError::UnknownKey { kid: kid.clone() })?;
    let message = parsed.verify(key, IMPLICIT_ASSERTION, &kid)?;
    let claims: SessionClaims = serde_json::from_slice(&message)
        .map_err(|e| malformed(format!("claims are not valid: {e}")))?;
    if claims.iss != ISSUER {
        return Err(SessionError::WrongIssuer { issuer: claims.iss });
    }
    if now >= claims.exp {
        return Err(SessionError::Expired {
            session_id: claims.jti,
            expired_at: claims.exp,
        });
    }
    if now + Duration::seconds(NOT_BEFORE_LEEWAY_SECS) < claims.nbf {
        return Err(SessionError::NotYetValid {
            session_id: claims.jti,
            not_before: claims.nbf,
        });
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;

    use super::*;
    use crate::ids::VaultId;

    fn setup() -> (SessionSigner, HashMap<String, VerifyingKey>, SessionClaims) {
        let signer = SessionSigner::new(SigningKey::generate(&mut OsRng));
        let keys = HashMap::from([(signer.kid().to_string(), signer.verifying_key())]);
        let claims = SessionClaims::new(
            Scope::for_vault(&VaultId::new()),
            vec![RuleId::new()],
            DEFAULT_SESSION_TTL_SECS,
            Some(10),
            BTreeMap::from([("agent".to_string(), "ci-bot".to_string())]),
            Utc::now(),
        )
        .unwrap();
        (signer, keys, claims)
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let (signer, keys, claims) = setup();
        let token = signer.sign(&claims).unwrap();
        assert!(token.starts_with("v4.public."));
        assert!(token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')));
        assert_eq!(verify_session(&token, &keys, Utc::now()).unwrap(), claims);
    }

    #[test]
    fn tampered_tokens_fail() {
        let (signer, keys, claims) = setup();
        let token = signer.sign(&claims).unwrap();
        let (payload, footer) = token.trim_start_matches(HEADER).split_once('.').unwrap();
        let mut bytes = URL_SAFE_NO_PAD.decode(payload).unwrap();
        bytes[5] ^= 0x01;
        let forged = format!("{HEADER}{}.{footer}", URL_SAFE_NO_PAD.encode(bytes));
        assert!(matches!(
            verify_session(&forged, &keys, Utc::now()),
            Err(SessionError::BadSignature { .. }) | Err(SessionError::Malformed { .. })
        ));
    }

    #[test]
    fn unknown_key_and_other_signer_fail() {
        let (_, keys, claims) = setup();
        let other = SessionSigner::new(SigningKey::generate(&mut OsRng));
        let token = other.sign(&claims).unwrap();
        assert!(matches!(
            verify_session(&token, &keys, Utc::now()),
            Err(SessionError::UnknownKey { .. })
        ));
    }

    #[test]
    fn expiry_is_enforced() {
        let (signer, keys, claims) = setup();
        let token = signer.sign(&claims).unwrap();
        let later = claims.exp + Duration::seconds(1);
        assert!(matches!(
            verify_session(&token, &keys, later),
            Err(SessionError::Expired { session_id, .. }) if session_id == claims.jti
        ));
        assert!(matches!(
            verify_session(&token, &keys, claims.exp),
            Err(SessionError::Expired { .. })
        ));
    }

    #[test]
    fn ttl_and_limits_are_bounded() {
        let scope = Scope::for_vault(&VaultId::new());
        let mk = |ttl, rules: Vec<RuleId>, limit| {
            SessionClaims::new(
                scope.clone(),
                rules,
                ttl,
                limit,
                BTreeMap::new(),
                Utc::now(),
            )
        };
        assert!(mk(0, vec![RuleId::new()], None).is_err());
        assert!(mk(MAX_SESSION_TTL_SECS + 1, vec![RuleId::new()], None).is_err());
        assert!(mk(MAX_SESSION_TTL_SECS, vec![RuleId::new()], None).is_ok());
        assert!(mk(60, vec![], None).is_err());
        assert!(mk(60, vec![RuleId::new()], Some(0)).is_err());
    }

    #[test]
    fn labels_are_validated() {
        assert!(validate_labels(&BTreeMap::from([("ok".into(), "v".into())])).is_ok());
        assert!(validate_labels(&BTreeMap::from([("bad key".into(), "v".into())])).is_err());
        assert!(validate_labels(&BTreeMap::from([("k".into(), "line\nbreak".into())])).is_err());
    }

    #[test]
    fn garbage_is_malformed() {
        let keys = HashMap::new();
        for bad in ["", "v4.local.abc.def", "v4.public.abc", "v4.public.!!!.e30"] {
            assert!(matches!(
                verify_session(bad, &keys, Utc::now()),
                Err(SessionError::Malformed { .. })
            ));
        }
    }

    // Official PASETO v4 test vectors, from
    // https://github.com/paseto-standard/test-vectors (v4.json).
    // Copyright (c) 2021 Paragon Initiative Enterprises, ISC License:
    // Permission to use, copy, modify, and/or distribute this software for
    // any purpose with or without fee is hereby granted, provided that the
    // above copyright notice and this permission notice appear in all copies.
    mod paseto_vectors {
        use super::super::*;

        const SEED: &str = "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774";
        const PUBLIC: &str = "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2";
        const PAYLOAD: &str =
            r#"{"data":"this is a signed message","exp":"2022-01-01T00:00:00+00:00"}"#;
        const KID_FOOTER: &str = r#"{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}"#;

        struct Vector {
            name: &'static str,
            token: &'static str,
            footer: &'static str,
            implicit: &'static str,
        }

        const VALID: [Vector; 3] = [
            Vector {
                name: "4-S-1",
                token: "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9bg_XBBzds8lTZShVlwwKSgeKpLT3yukTw6JUz3W4h_ExsQV-P0V54zemZDcAxFaSeef1QlXEFtkqxT1ciiQEDA",
                footer: "",
                implicit: "",
            },
            Vector {
                name: "4-S-2",
                token: "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9v3Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0DtwQxVrJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
                footer: KID_FOOTER,
                implicit: "",
            },
            Vector {
                name: "4-S-3",
                token: "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9NPWciuD3d0o5eXJXG5pJy-DiVEoyPYWs1YSTwWHNJq6DZD3je5gf-0M4JR9ipdUSJbIovzmBECeaWmaqcaP0DQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
                footer: KID_FOOTER,
                implicit: r#"{"test-vector":"4-S-3"}"#,
            },
        ];

        fn keys() -> (SigningKey, VerifyingKey) {
            let seed: [u8; 32] = hex::decode(SEED).unwrap().try_into().unwrap();
            let signing = SigningKey::from_bytes(&seed);
            let public: [u8; 32] = hex::decode(PUBLIC).unwrap().try_into().unwrap();
            let verifying = VerifyingKey::from_bytes(&public).unwrap();
            assert_eq!(signing.verifying_key(), verifying);
            (signing, verifying)
        }

        #[test]
        fn signing_reproduces_the_official_tokens() {
            let (signing, _) = keys();
            for v in &VALID {
                let token = sign_v4_public(
                    &signing,
                    PAYLOAD.as_bytes(),
                    v.footer.as_bytes(),
                    v.implicit.as_bytes(),
                );
                assert_eq!(token, v.token, "vector {}", v.name);
            }
        }

        #[test]
        fn verifying_accepts_the_official_tokens() {
            let (_, verifying) = keys();
            for v in &VALID {
                let parsed = UnverifiedV4Public::parse(v.token).unwrap();
                assert_eq!(parsed.footer, v.footer.as_bytes(), "vector {}", v.name);
                let message = parsed
                    .verify(&verifying, v.implicit.as_bytes(), "test")
                    .unwrap();
                assert_eq!(message, PAYLOAD.as_bytes(), "vector {}", v.name);
            }
        }

        #[test]
        fn wrong_implicit_assertion_is_rejected() {
            let (_, verifying) = keys();
            let v = &VALID[2];
            let parsed = UnverifiedV4Public::parse(v.token).unwrap();
            assert!(parsed.verify(&verifying, b"", "test").is_err());
        }

        #[test]
        fn official_failure_vectors_are_rejected() {
            let (_, verifying) = keys();
            // 4-F-2: a v4.public token that must not verify.
            let bad = "v4.public.eyJpbnZhbGlkIjoidGhpcyBzaG91bGQgbmV2ZXIgZGVjb2RlIn22Sp4gjCaUw0c7EH84ZSm_jN_Qr41MrgLNu5LIBCzUr1pn3Z-Wukg9h3ceplWigpoHaTLcwxj0NsI1vjTh67YB.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";
            let rejected = UnverifiedV4Public::parse(bad)
                .and_then(|p| p.verify(&verifying, br#"{"test-vector":"4-F-2"}"#, "test"));
            assert!(rejected.is_err());
            // 4-F-1, 4-F-3..5: other versions/purposes must not even parse.
            for other in ["v4.local.AAAA", "v3.local.AAAA", "v3.public.AAAA"] {
                assert!(UnverifiedV4Public::parse(other).is_err(), "{other}");
            }
        }
    }
}
