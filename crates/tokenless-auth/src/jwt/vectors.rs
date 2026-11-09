// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tokens signed outside this crate (with OpenSSL, by throwaway keys made
//! for these tests), so RSA and Ed25519 are checked against an independent
//! signer. Every token carries `{"sub":"test-subject","iss":"https://idp.example.test"}`
//! and the header `kid` "t1".

use serde_json::json;

use super::*;

const RSA_N: &str = "sopnC1HvngNmwQBMEVAup4Zk1FQmOUOwKaRwS8HL7SfV1iSyrCkHRw29FjVZ2Rbm3tHy6ZuPQLYCJuC2DmQUrZnZ9aFUzr4JCkUJm6gWR3ZIO0TFpWJarw9j3R6CBTcHqJ-8w_GRsXGkxqy2z6a-ozVyQFpR5oEMnck5LK2SggBrLONyHnAhGuooBWCR5y9mKXoYG8GaTq-MokihZA0BjlNvoP75IFOT2Hb_TnQAEFYbtd2K5c4q0xs4sdg_qzimPPUQgsNK8ShODW1VoNIXr9Fni7q_2UlLtTvS1h9S7Uw_04Tqml2DJ4sgaiRyQkPL1Vt91yO6KgjiRXyMrj6bgQ";
const RSA_E: &str = "AQAB";
const ED25519_X: &str = "23BcroiU0BQYJ2seBbbeF4Eh8lUbZYm43UjbrVYubk4";
const RS256: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6InQxIn0.eyJzdWIiOiJ0ZXN0LXN1YmplY3QiLCJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlLnRlc3QifQ.kRtih7U5l06vdTmS9TfNCfvutBf9n30QGBMP18DzP8HJ4OQop6eGW9Qkf4S1HB-fWu8EJjL4i4I1goPE3KCdxCEs5NYVmgBebUUdKuMXePi9h7M0cZL1WfNlTuYQdD-rFMT_zUsrkF4vy99NVCJb5kyX8X9Nh97fqQSXLSoVhyyMErR5pyBamhPjUte8kiNC3wNh3TMGpI8lHjrJHNMHub4i6YfKG7jAuxYqA5LtuOg5sUKI1WdXMuL3Ty3jLMjHzTC-e9__230eHArfSnTSWLqx8NlD5rLiKfCXwJlLcjLg0MtLVttWkvVGQRhB1kaQVv_ZJ8Y6AXhsFvsuVPvZfw";
const PS256: &str = "eyJhbGciOiJQUzI1NiIsImtpZCI6InQxIn0.eyJzdWIiOiJ0ZXN0LXN1YmplY3QiLCJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlLnRlc3QifQ.d8Rhx4zaudI5IOpAloUFo0QjqFyb7idL6AtmrdlrM9ssZ3UJn6duG9-FXJ1uVdr-3x8fwUBlkTKB3r6LOJLHh3AEzrFxCDI9mqtH5DCrR7n9fHH6BXL7W9bq8FA4vn8zuhi7yeb_nQiXHOdNAGXGn6IFdYn9jx7ze4VDtnlT1Ff1KB5LG5wMk7_DmDQjCOpcA9hYryXDZaDk4MwBL0NxuQiGC1lxxAgHJ-H4sgt2VZbOCp9xBBpY01CmcAaIN1HcMOwjhiBTNVew16aS0RkAlQR_-73WjKCvWB71kzZH6pkh_nnCpTmUGc58UPT-FcI1w9_3tHznCo9gTjPkzbeocA";
const EDDSA: &str = "eyJhbGciOiJFZERTQSIsImtpZCI6InQxIn0.eyJzdWIiOiJ0ZXN0LXN1YmplY3QiLCJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlLnRlc3QifQ.OODVYCZ9xlvdCWn_U6NW6vGvkMlDjTpvEO-ItCB2UnFtimNDLpTlp8R5hgzC80sUQch6xa53WdeeEPqRelLuDA";

fn keys() -> JwkSet {
    serde_json::from_value(json!({"keys": [
        {"kty": "RSA", "kid": "t1", "n": RSA_N, "e": RSA_E},
        {"kty": "OKP", "kid": "t1", "crv": "Ed25519", "x": ED25519_X},
    ]}))
    .unwrap()
}

#[test]
fn rsa_and_ed25519_tokens_from_another_signer_verify() {
    for (token, alg) in [
        (RS256, Algorithm::Rs256),
        (PS256, Algorithm::Ps256),
        (EDDSA, Algorithm::EdDsa),
    ] {
        let v = verify(token, &keys(), &Algorithm::ALL).unwrap_or_else(|e| panic!("{alg}: {e}"));
        assert_eq!(v.alg, alg);
        assert_eq!(v.claims["sub"], "test-subject");
    }
}

#[test]
fn an_rsa_signature_does_not_pass_as_another_rsa_scheme() {
    // The PKCS#1 v1.5 signature relabelled PS256, and the reverse.
    let relabel = |token: &str, alg: &str| {
        let (_, rest) = token.split_once('.').unwrap();
        let header = URL_SAFE_NO_PAD.encode(format!(r#"{{"alg":"{alg}","kid":"t1"}}"#));
        format!("{header}.{rest}")
    };
    for token in [relabel(RS256, "PS256"), relabel(PS256, "RS256")] {
        assert!(matches!(
            verify(&token, &keys(), &Algorithm::ALL),
            Err(JwtError::BadSignature { .. })
        ));
    }
}
