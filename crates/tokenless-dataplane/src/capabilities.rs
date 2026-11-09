// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! What this data plane enforces, so a host can refuse to attach workloads
//! to one that would enforce less than it promises them:
//!
//! ```no_run
//! # use tokenless_dataplane::{capabilities::Capability, DataPlane};
//! # fn attach(dataplane: &DataPlane) -> Result<(), tokenless_dataplane::DataPlaneError> {
//! dataplane
//!     .capabilities()
//!     .require(&[Capability::StrictExpiry, Capability::RevocationAck])?;
//! # Ok(()) }
//! ```
//!
//! A remote node needs no handshake: it tells the control plane the
//! snapshot format it reads and is only sent rules it can enforce, and it
//! refuses a session token carrying fields it does not know.

use serde::Serialize;
use tokenless_core::snapshot::{MIN_SNAPSHOT_FORMAT, SNAPSHOT_FORMAT};

use crate::error::DataPlaneError;

/// One guarantee a data plane may give.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Capability {
    /// A session bound to one start of a workload binds to no other.
    BindingGenerations,
    /// [`Binding::update`](crate::Binding::update) replaces a binding's
    /// sessions, fenced on a version, cutting only the grants it removes.
    BindingUpdates,
    /// `strict` sessions: open traffic stops at its deadlines, with no
    /// grace period, on a clock setting the time back cannot rewind.
    StrictExpiry,
    /// A deadline per rule within one session.
    RuleDeadlines,
    /// A secret's own `not_after`: the proxy stops sending it then.
    CredentialExpiry,
    /// Rules limited to Git smart HTTP for named repositories.
    GitScope,
    /// [`DataPlane::session_cut`](crate::DataPlane::session_cut) and
    /// [`Binding::revoke_and_wait`](crate::Binding::revoke_and_wait)
    /// resolve once a revocation is enforced.
    RevocationAck,
}

impl Capability {
    pub fn as_str(self) -> &'static str {
        match self {
            Capability::BindingGenerations => "binding_generations",
            Capability::BindingUpdates => "binding_updates",
            Capability::StrictExpiry => "strict_expiry",
            Capability::RuleDeadlines => "rule_deadlines",
            Capability::CredentialExpiry => "credential_expiry",
            Capability::GitScope => "git_scope",
            Capability::RevocationAck => "revocation_ack",
        }
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Everything this build enforces.
pub const CAPABILITIES: &[Capability] = &[
    Capability::BindingGenerations,
    Capability::BindingUpdates,
    Capability::StrictExpiry,
    Capability::RuleDeadlines,
    Capability::CredentialExpiry,
    Capability::GitScope,
    Capability::RevocationAck,
];

/// What a data plane enforces and which snapshots it reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Capabilities {
    pub features: Vec<Capability>,
    /// The newest snapshot format it reads.
    pub snapshot_format: u32,
    /// The oldest snapshot format it still reads.
    pub min_snapshot_format: u32,
}

impl Capabilities {
    /// This build's.
    pub fn current() -> Self {
        Self {
            features: CAPABILITIES.to_vec(),
            snapshot_format: SNAPSHOT_FORMAT,
            min_snapshot_format: MIN_SNAPSHOT_FORMAT,
        }
    }

    pub fn supports(&self, capability: Capability) -> bool {
        self.features.contains(&capability)
    }

    /// Fails with [`DataPlaneError::Unsupported`], naming every missing
    /// capability, unless all of `needed` are supported.
    pub fn require(&self, needed: &[Capability]) -> Result<(), DataPlaneError> {
        let missing: Vec<&str> = needed
            .iter()
            .filter(|c| !self.supports(**c))
            .map(|c| c.as_str())
            .collect();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(DataPlaneError::Unsupported {
                missing: missing.join(", "),
                snapshot_format: self.snapshot_format,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requiring_what_is_missing_names_it() {
        let all = Capabilities::current();
        assert!(all.require(CAPABILITIES).is_ok());
        assert_eq!(all.snapshot_format, SNAPSHOT_FORMAT);
        let older = Capabilities {
            features: vec![Capability::BindingGenerations],
            ..Capabilities::current()
        };
        let err = older
            .require(&[
                Capability::BindingGenerations,
                Capability::StrictExpiry,
                Capability::GitScope,
            ])
            .unwrap_err();
        assert!(
            err.to_string().contains("strict_expiry, git_scope"),
            "{err}"
        );
        assert_eq!(
            serde_json::to_string(&Capability::RevocationAck).unwrap(),
            "\"revocation_ack\""
        );
    }
}
