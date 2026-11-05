// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Policy snapshots sent from the control plane to a data plane node.
//!
//! A snapshot is JSON signed with Ed25519 over its exact bytes, so there is
//! no canonicalisation step to get wrong. It carries a strictly increasing
//! version (nodes reject anything not newer than what they hold) and a lease:
//! once the lease runs out without a newer snapshot the node fails closed.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::ids::{CredentialId, NodeId, RuleId, SessionId};
use crate::rule::RuleScope;
use crate::scope::Scope;
use crate::seal::Sealed;
use crate::session::key_id;

pub const SNAPSHOT_FORMAT: u32 = 1;
const SIGNATURE_CONTEXT: &[u8] = b"credential-broker/snapshot/v1\0";

/// What the data plane does with a CONNECT to a host no session rule covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnmatchedHostPolicy {
    /// Open a plain TCP tunnel; TLS is never intercepted and nothing is injected.
    #[default]
    Passthrough,
    /// Refuse the CONNECT with 403.
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedKey {
    pub kid: String,
    /// Ed25519 public key, base64.
    pub public_key: String,
}

impl PublishedKey {
    pub fn from_key(key: &VerifyingKey) -> Self {
        Self {
            kid: key_id(key),
            public_key: STANDARD.encode(key.as_bytes()),
        }
    }

    pub fn decode(&self) -> Result<VerifyingKey, CoreError> {
        decode_verifying_key(&self.public_key)
    }
}

pub fn decode_verifying_key(value: &str) -> Result<VerifyingKey, CoreError> {
    let bytes: [u8; 32] = STANDARD
        .decode(value)
        .map_err(|e| CoreError::encoding("ed25519 public key", e))?
        .try_into()
        .map_err(|_| CoreError::encoding("ed25519 public key", "expected 32 bytes"))?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| CoreError::crypto("ed25519.decode", e.to_string()))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionLimit {
    pub session_id: SessionId,
    pub limit: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterceptionCa {
    /// CA certificate, DER, base64. Public: agents are told to trust it.
    pub cert_der: String,
    /// PKCS#8 private key, sealed to the node.
    pub key: Sealed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotRule {
    pub rule_id: RuleId,
    pub scope: Scope,
    pub credential_id: CredentialId,
    pub allow: RuleScope,
    /// Lower-cased header names the client may not supply on matching hosts.
    pub strip_headers: Vec<String>,
    /// [`crate::injection::InjectedHeaders`] JSON, sealed to the node.
    pub headers: Sealed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotBody {
    pub format: u32,
    pub version: u64,
    pub node_id: NodeId,
    pub issued_at: DateTime<Utc>,
    pub lease_secs: u32,
    pub session_keys: Vec<PublishedKey>,
    pub revoked_sessions: Vec<SessionId>,
    pub limited_sessions: Vec<SessionLimit>,
    pub unmatched_host_policy: UnmatchedHostPolicy,
    pub interception_ca: InterceptionCa,
    pub rules: Vec<SnapshotRule>,
}

/// AAD binding a sealed rule credential to one node, snapshot and rule.
pub fn rule_aad(node_id: &NodeId, version: u64, rule_id: &RuleId) -> Vec<u8> {
    format!("rule|{node_id}|{version}|{rule_id}").into_bytes()
}

/// AAD binding the sealed interception CA key to one node and snapshot.
pub fn ca_aad(node_id: &NodeId, version: u64) -> Vec<u8> {
    format!("interception-ca|{node_id}|{version}").into_bytes()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedSnapshot {
    /// The exact JSON bytes that were signed.
    pub body: String,
    /// Ed25519 signature, base64.
    pub signature: String,
    pub kid: String,
}

fn signing_input(body: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(SIGNATURE_CONTEXT.len() + body.len());
    input.extend_from_slice(SIGNATURE_CONTEXT);
    input.extend_from_slice(body);
    input
}

impl SignedSnapshot {
    pub fn sign(body: &SnapshotBody, key: &SigningKey) -> Result<Self, CoreError> {
        let json = serde_json::to_string(body).map_err(|e| CoreError::encoding("snapshot", e))?;
        let signature = key.sign(&signing_input(json.as_bytes()));
        Ok(Self {
            body: json,
            signature: STANDARD.encode(signature.to_bytes()),
            kid: key_id(&key.verifying_key()),
        })
    }

    /// Verifies the signature, then parses the body. Version, node and lease
    /// checks are the receiver's job because they depend on its state.
    pub fn verify(&self, key: &VerifyingKey) -> Result<SnapshotBody, CoreError> {
        let sig_bytes = STANDARD
            .decode(&self.signature)
            .map_err(|e| CoreError::encoding("snapshot signature", e))?;
        let signature = Signature::from_slice(&sig_bytes)
            .map_err(|e| CoreError::crypto("snapshot.signature", e.to_string()))?;
        key.verify_strict(&signing_input(self.body.as_bytes()), &signature)
            .map_err(|_| {
                CoreError::crypto(
                    "snapshot.verify",
                    format!("signature does not verify with key '{}'", key_id(key)),
                )
            })?;
        let body: SnapshotBody = serde_json::from_str(&self.body)
            .map_err(|e| CoreError::encoding("snapshot body", e))?;
        if body.format != SNAPSHOT_FORMAT {
            return Err(CoreError::encoding(
                "snapshot body",
                format!("unsupported format {}", body.format),
            ));
        }
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    use super::*;
    use crate::seal::seal;

    fn body() -> SnapshotBody {
        let node_key = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        let node_id = NodeId::new();
        SnapshotBody {
            format: SNAPSHOT_FORMAT,
            version: 7,
            node_id,
            issued_at: Utc::now(),
            lease_secs: 60,
            session_keys: vec![],
            revoked_sessions: vec![SessionId::new()],
            limited_sessions: vec![],
            unmatched_host_policy: UnmatchedHostPolicy::Passthrough,
            interception_ca: InterceptionCa {
                cert_der: STANDARD.encode(b"cert"),
                key: seal(&node_key, b"key", &ca_aad(&node_id, 7)).unwrap(),
            },
            rules: vec![],
        }
    }

    #[test]
    fn sign_and_verify() {
        let key = SigningKey::generate(&mut OsRng);
        let b = body();
        let signed = SignedSnapshot::sign(&b, &key).unwrap();
        assert_eq!(signed.verify(&key.verifying_key()).unwrap(), b);
    }

    #[test]
    fn tampering_and_wrong_key_fail() {
        let key = SigningKey::generate(&mut OsRng);
        let mut signed = SignedSnapshot::sign(&body(), &key).unwrap();
        let other = SigningKey::generate(&mut OsRng);
        assert!(signed.verify(&other.verifying_key()).is_err());
        signed.body = signed.body.replace("\"version\":7", "\"version\":8");
        assert!(signed.verify(&key.verifying_key()).is_err());
    }

    #[test]
    fn published_key_round_trips() {
        let key = SigningKey::generate(&mut OsRng).verifying_key();
        let published = PublishedKey::from_key(&key);
        assert_eq!(published.decode().unwrap(), key);
        assert_eq!(published.kid, key_id(&key));
    }
}
