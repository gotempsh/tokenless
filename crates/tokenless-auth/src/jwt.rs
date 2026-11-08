// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Signed JSON Web Tokens checked against a JSON Web Key Set: the ID tokens
//! an OpenID Connect provider issues.
//!
//! Only asymmetric signatures are accepted (RSA PKCS#1 v1.5 and PSS, ECDSA
//! on P-256 and P-384, Ed25519). `none` and the HMAC algorithms are refused
//! whatever the caller allows: a provider's public keys must never double
//! as a shared secret. This checks the signature only; what the claims say
//! (issuer, audience, expiry, nonce) is for the caller to check.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::signature::{self, RsaPublicKeyComponents, UnparsedPublicKey, VerificationAlgorithm};
use serde::Deserialize;
use serde_json::{Map, Value};
use thiserror::Error;

/// Longest token accepted, in bytes.
pub const MAX_TOKEN_LEN: usize = 16 * 1024;

/// A signature algorithm this module verifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Rs256,
    Rs384,
    Rs512,
    Ps256,
    Ps384,
    Ps512,
    Es256,
    Es384,
    EdDsa,
}

impl Algorithm {
    pub const ALL: [Algorithm; 9] = [
        Algorithm::Rs256,
        Algorithm::Rs384,
        Algorithm::Rs512,
        Algorithm::Ps256,
        Algorithm::Ps384,
        Algorithm::Ps512,
        Algorithm::Es256,
        Algorithm::Es384,
        Algorithm::EdDsa,
    ];

    /// The JOSE name, as in a token's `alg` header.
    pub fn as_str(self) -> &'static str {
        match self {
            Algorithm::Rs256 => "RS256",
            Algorithm::Rs384 => "RS384",
            Algorithm::Rs512 => "RS512",
            Algorithm::Ps256 => "PS256",
            Algorithm::Ps384 => "PS384",
            Algorithm::Ps512 => "PS512",
            Algorithm::Es256 => "ES256",
            Algorithm::Es384 => "ES384",
            Algorithm::EdDsa => "EdDSA",
        }
    }

    /// `None` for anything not verified here, `none` and HS* included.
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.as_str() == name)
    }

    fn key_type(self) -> &'static str {
        match self {
            Algorithm::Rs256
            | Algorithm::Rs384
            | Algorithm::Rs512
            | Algorithm::Ps256
            | Algorithm::Ps384
            | Algorithm::Ps512 => "RSA",
            Algorithm::Es256 | Algorithm::Es384 => "EC",
            Algorithm::EdDsa => "OKP",
        }
    }
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum JwtError {
    #[error("token is malformed: {reason}")]
    Malformed { reason: String },

    #[error("token is signed with '{alg}', which is not accepted (accepted: {accepted})")]
    AlgorithmRefused { alg: String, accepted: String },

    #[error("no key in the provider's key set can check this token ({wanted})")]
    NoKey { wanted: String },

    #[error("token signature does not verify with the provider's key {kid}")]
    BadSignature { kid: String },
}

/// One public key, as a JWK. Fields this module does not use are ignored.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default, rename = "use")]
    pub use_: Option<String>,
    #[serde(default)]
    pub crv: Option<String>,
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub y: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

/// The header fields this module reads.
#[derive(Debug, Clone, Deserialize)]
struct Header {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
    /// Extensions the token says must be understood; none are.
    #[serde(default)]
    crit: Option<Value>,
}

/// A token whose signature verified.
#[derive(Debug, Clone)]
pub struct Verified {
    pub alg: Algorithm,
    pub kid: Option<String>,
    pub claims: Map<String, Value>,
}

fn malformed(reason: impl Into<String>) -> JwtError {
    JwtError::Malformed {
        reason: reason.into(),
    }
}

fn b64(part: &str, what: &str) -> Result<Vec<u8>, JwtError> {
    URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|e| malformed(format!("{what} is not base64url: {e}")))
}

/// Checks `token`'s signature with a key from `keys`, using one of
/// `accepted`. With a `kid` in the header only that key is tried.
pub fn verify(token: &str, keys: &JwkSet, accepted: &[Algorithm]) -> Result<Verified, JwtError> {
    if token.len() > MAX_TOKEN_LEN {
        return Err(malformed(format!(
            "{} bytes, more than the {MAX_TOKEN_LEN} accepted",
            token.len()
        )));
    }
    let mut parts = token.split('.');
    let (Some(header_b64), Some(payload_b64), Some(signature_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(malformed("expected three '.'-separated parts"));
    };
    let header: Header = serde_json::from_slice(&b64(header_b64, "header")?)
        .map_err(|e| malformed(format!("header is not JSON with an 'alg': {e}")))?;
    if header.crit.is_some() {
        return Err(malformed("the header marks extensions critical ('crit')"));
    }
    let refused = || JwtError::AlgorithmRefused {
        alg: header.alg.clone(),
        accepted: accepted
            .iter()
            .map(|a| a.as_str())
            .collect::<Vec<_>>()
            .join(", "),
    };
    let alg = Algorithm::parse(&header.alg).ok_or_else(refused)?;
    if !accepted.contains(&alg) {
        return Err(refused());
    }
    let signature = b64(signature_b64, "signature")?;
    let claims = match serde_json::from_slice(&b64(payload_b64, "payload")?) {
        Ok(Value::Object(claims)) => claims,
        _ => return Err(malformed("payload is not a JSON object")),
    };
    let signed = &token.as_bytes()[..header_b64.len() + 1 + payload_b64.len()];

    let candidates: Vec<&Jwk> = keys
        .keys
        .iter()
        .filter(|k| header.kid.is_none() || k.kid == header.kid)
        .filter(|k| k.kty == alg.key_type())
        .filter(|k| k.alg.as_deref().is_none_or(|a| a == alg.as_str()))
        .filter(|k| k.use_.as_deref().is_none_or(|u| u == "sig"))
        .collect();
    if candidates.is_empty() {
        return Err(JwtError::NoKey {
            wanted: match &header.kid {
                Some(kid) => format!("kid '{kid}', {alg}"),
                None => format!("{alg}, no kid"),
            },
        });
    }
    for key in &candidates {
        if verify_with(key, alg, signed, &signature)? {
            return Ok(Verified {
                alg,
                kid: key.kid.clone(),
                claims,
            });
        }
    }
    Err(JwtError::BadSignature {
        kid: header.kid.unwrap_or_else(|| "(none given)".into()),
    })
}

fn field<'a>(key: &'a Jwk, value: &'a Option<String>, name: &str) -> Result<Vec<u8>, JwtError> {
    let value = value.as_deref().ok_or_else(|| {
        malformed(format!(
            "{} key {} has no '{name}'",
            key.kty,
            key.kid.as_deref().unwrap_or("(no kid)")
        ))
    })?;
    b64(value, name)
}

fn verify_with(
    key: &Jwk,
    alg: Algorithm,
    message: &[u8],
    signature: &[u8],
) -> Result<bool, JwtError> {
    let rsa = |params: &'static signature::RsaParameters| -> Result<bool, JwtError> {
        let n = field(key, &key.n, "n")?;
        let e = field(key, &key.e, "e")?;
        Ok(RsaPublicKeyComponents { n: &n, e: &e }
            .verify(params, message, signature)
            .is_ok())
    };
    let ec = |crv: &str,
              len: usize,
              algorithm: &'static dyn VerificationAlgorithm|
     -> Result<bool, JwtError> {
        if key.crv.as_deref() != Some(crv) {
            return Ok(false);
        }
        let x = field(key, &key.x, "x")?;
        let y = field(key, &key.y, "y")?;
        if x.len() != len || y.len() != len {
            return Ok(false);
        }
        let point = [&[0x04][..], &x, &y].concat();
        Ok(UnparsedPublicKey::new(algorithm, point)
            .verify(message, signature)
            .is_ok())
    };
    match alg {
        Algorithm::Rs256 => rsa(&signature::RSA_PKCS1_2048_8192_SHA256),
        Algorithm::Rs384 => rsa(&signature::RSA_PKCS1_2048_8192_SHA384),
        Algorithm::Rs512 => rsa(&signature::RSA_PKCS1_2048_8192_SHA512),
        Algorithm::Ps256 => rsa(&signature::RSA_PSS_2048_8192_SHA256),
        Algorithm::Ps384 => rsa(&signature::RSA_PSS_2048_8192_SHA384),
        Algorithm::Ps512 => rsa(&signature::RSA_PSS_2048_8192_SHA512),
        Algorithm::Es256 => ec("P-256", 32, &signature::ECDSA_P256_SHA256_FIXED),
        Algorithm::Es384 => ec("P-384", 48, &signature::ECDSA_P384_SHA384_FIXED),
        Algorithm::EdDsa => {
            if key.crv.as_deref() != Some("Ed25519") {
                return Ok(false);
            }
            let x = field(key, &key.x, "x")?;
            Ok(UnparsedPublicKey::new(&signature::ED25519, x)
                .verify(message, signature)
                .is_ok())
        }
    }
}

/// Signing, for tests that stand in for a provider.
#[cfg(any(test, feature = "test-signing"))]
pub mod testing {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
    use serde_json::{json, Value};

    /// An ES256 key with its JWK.
    pub struct TestKey {
        pair: EcdsaKeyPair,
        pub kid: String,
    }

    impl TestKey {
        #[allow(clippy::expect_used, reason = "test helper; ring key generation")]
        pub fn generate(kid: &str) -> Self {
            let rng = SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .expect("generate a P-256 key");
            let pair =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                    .expect("load the generated key");
            Self {
                pair,
                kid: kid.into(),
            }
        }

        pub fn jwk(&self) -> Value {
            let point = self.pair.public_key().as_ref();
            json!({
                "kty": "EC",
                "crv": "P-256",
                "kid": self.kid,
                "use": "sig",
                "alg": "ES256",
                "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
                "y": URL_SAFE_NO_PAD.encode(&point[33..65]),
            })
        }

        /// A compact token with `header` fields over the defaults.
        #[allow(clippy::expect_used, reason = "test helper; signing with a valid key")]
        pub fn sign_with(&self, header: Value, claims: &Value) -> String {
            let mut h = json!({"alg": "ES256", "typ": "JWT", "kid": self.kid});
            // A null field removes the default.
            if let (Some(h), Value::Object(extra)) = (h.as_object_mut(), header) {
                for (name, value) in extra {
                    if value.is_null() {
                        h.remove(&name);
                    } else {
                        h.insert(name, value);
                    }
                }
            }
            let input = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(h.to_string()),
                URL_SAFE_NO_PAD.encode(claims.to_string())
            );
            let sig = self
                .pair
                .sign(&SystemRandom::new(), input.as_bytes())
                .expect("sign");
            format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()))
        }

        pub fn sign(&self, claims: &Value) -> String {
            self.sign_with(json!({}), claims)
        }
    }
}

#[cfg(test)]
mod vectors;

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::testing::TestKey;
    use super::*;

    fn set(keys: &[&TestKey]) -> JwkSet {
        serde_json::from_value(json!({"keys": keys.iter().map(|k| k.jwk()).collect::<Vec<_>>()}))
            .unwrap()
    }

    #[test]
    fn a_token_signed_by_a_key_in_the_set_verifies() {
        let key = TestKey::generate("k1");
        let other = TestKey::generate("k2");
        let token = key.sign(&json!({"sub": "abc", "n": 1}));
        let v = verify(&token, &set(&[&other, &key]), &Algorithm::ALL).unwrap();
        assert_eq!(v.alg, Algorithm::Es256);
        assert_eq!(v.kid.as_deref(), Some("k1"));
        assert_eq!(v.claims["sub"], "abc");
        // Without a kid every key of the type is tried.
        let no_kid = key.sign_with(json!({"kid": null}), &json!({"sub": "abc"}));
        let v = verify(&no_kid, &set(&[&other, &key]), &Algorithm::ALL).unwrap();
        assert_eq!(v.kid.as_deref(), Some("k1"));
    }

    #[test]
    fn tampering_another_key_or_a_refused_algorithm_fails() {
        let key = TestKey::generate("k1");
        let token = key.sign(&json!({"sub": "abc"}));
        let parts: Vec<&str> = token.split('.').collect();
        let forged = format!(
            "{}.{}.{}",
            parts[0],
            URL_SAFE_NO_PAD.encode(json!({"sub": "admin"}).to_string()),
            parts[2]
        );
        assert!(matches!(
            verify(&forged, &set(&[&key]), &Algorithm::ALL),
            Err(JwtError::BadSignature { .. })
        ));
        // Same kid, different key: the attacker's own key set is not ours.
        let impostor = TestKey::generate("k1");
        assert!(matches!(
            verify(&impostor.sign(&json!({})), &set(&[&key]), &Algorithm::ALL),
            Err(JwtError::BadSignature { .. })
        ));
        assert!(matches!(
            verify(&token, &set(&[&TestKey::generate("k9")]), &Algorithm::ALL),
            Err(JwtError::NoKey { .. })
        ));
        assert!(matches!(
            verify(&token, &set(&[&key]), &[Algorithm::Rs256]),
            Err(JwtError::AlgorithmRefused { .. })
        ));
        for alg in ["none", "HS256", "HS512", "es256"] {
            let t = key.sign_with(json!({ "alg": alg }), &json!({}));
            assert!(
                matches!(
                    verify(&t, &set(&[&key]), &Algorithm::ALL),
                    Err(JwtError::AlgorithmRefused { .. })
                ),
                "{alg}"
            );
        }
        let unsigned = format!("{}.{}.", parts[0], parts[1]);
        assert!(verify(&unsigned, &set(&[&key]), &Algorithm::ALL).is_err());
    }

    #[test]
    fn malformed_tokens_and_critical_extensions_are_refused() {
        let key = TestKey::generate("k1");
        for bad in [
            "",
            "a.b",
            "a.b.c.d",
            "!!.e30.e30",
            &"a".repeat(MAX_TOKEN_LEN + 1),
        ] {
            assert!(
                matches!(
                    verify(bad, &set(&[&key]), &Algorithm::ALL),
                    Err(JwtError::Malformed { .. })
                ),
                "{bad:.20}"
            );
        }
        let crit = key.sign_with(json!({"crit": ["exp"]}), &json!({}));
        assert!(matches!(
            verify(&crit, &set(&[&key]), &Algorithm::ALL),
            Err(JwtError::Malformed { .. })
        ));
        let array = key.sign(&json!([1, 2]));
        assert!(matches!(
            verify(&array, &set(&[&key]), &Algorithm::ALL),
            Err(JwtError::Malformed { .. })
        ));
    }

    #[test]
    fn a_key_marked_for_another_algorithm_or_use_is_not_tried() {
        let key = TestKey::generate("k1");
        let token = key.sign(&json!({}));
        let mut jwk = key.jwk();
        jwk["use"] = json!("enc");
        let enc: JwkSet = serde_json::from_value(json!({ "keys": [jwk] })).unwrap();
        assert!(matches!(
            verify(&token, &enc, &Algorithm::ALL),
            Err(JwtError::NoKey { .. })
        ));
        let mut jwk = key.jwk();
        jwk["alg"] = json!("ES384");
        let other: JwkSet = serde_json::from_value(json!({ "keys": [jwk] })).unwrap();
        assert!(verify(&token, &other, &Algorithm::ALL).is_err());
    }
}
