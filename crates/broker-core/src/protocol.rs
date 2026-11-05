// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wire types between a data plane node and the control plane's node API.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::audit::AuditEvent;
use crate::error::CoreError;
use crate::ids::NodeId;

pub const JOIN_TOKEN_PREFIX: &str = "cbj1";
pub const MAX_AUDIT_BATCH: usize = 1000;

/// A one-time join token: `cbj1.<token id>.<secret>.<CA SHA-256 hex>`.
/// The CA fingerprint lets a new node authenticate the control plane before
/// it has any other trust anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinToken {
    pub token_id: String,
    pub secret: String,
    pub ca_fingerprint: String,
}

impl JoinToken {
    pub fn encode(&self) -> String {
        format!(
            "{JOIN_TOKEN_PREFIX}.{}.{}.{}",
            self.token_id, self.secret, self.ca_fingerprint
        )
    }

    pub fn parse(value: &str) -> Result<Self, CoreError> {
        let bad = |reason: &str| CoreError::Encoding {
            context: "join token".into(),
            reason: reason.into(),
        };
        let mut parts = value.trim().split('.');
        if parts.next() != Some(JOIN_TOKEN_PREFIX) {
            return Err(bad("expected prefix 'cbj1.'"));
        }
        let (Some(token_id), Some(secret), Some(fp), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(bad("expected four '.'-separated parts"));
        };
        if token_id.is_empty() || secret.len() < 32 {
            return Err(bad("token id or secret is too short"));
        }
        if fp.len() != 64 || !fp.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(bad("CA fingerprint must be 64 hex characters"));
        }
        Ok(Self {
            token_id: token_id.to_string(),
            secret: secret.to_string(),
            ca_fingerprint: fp.to_ascii_lowercase(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollRequest {
    pub join_token: String,
    pub node_name: String,
    /// PKCS#10 CSR for the node's own TLS client key (PEM).
    pub csr_pem: String,
    /// The node's X25519 public key (base64) credentials are sealed to.
    pub seal_public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub node_id: NodeId,
    pub client_cert_pem: String,
    pub ca_cert_pem: String,
    /// Ed25519 key (base64) that signs this node's snapshots.
    pub snapshot_verify_key: String,
    pub cert_not_after: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenewRequest {
    pub csr_pem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewResponse {
    pub client_cert_pem: String,
    pub cert_not_after: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditBatch {
    pub events: Vec<AuditEvent>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_token_round_trip() {
        let token = JoinToken {
            token_id: "abc".into(),
            secret: "s".repeat(43),
            ca_fingerprint: "a".repeat(64),
        };
        assert_eq!(JoinToken::parse(&token.encode()).unwrap(), token);
    }

    #[test]
    fn join_token_rejects_garbage() {
        for bad in [
            "",
            "cbj1.a.b",
            "cbj2.a.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.ff",
            "cbj1.a.short.ff",
        ] {
            assert!(JoinToken::parse(bad).is_err(), "{bad}");
        }
    }
}
