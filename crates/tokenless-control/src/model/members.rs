// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Vault membership: who may do what inside each vault, and how much a
//! sign-in may do at all.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokenless_core::authz::Role;
use tokenless_core::ids::{UserId, VaultId};

/// A person's role in one vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultGrant {
    pub vault_id: VaultId,
    pub role: Role,
}

/// A member of a vault, as the vault's Members list shows them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultMember {
    pub vault_id: VaultId,
    pub user_id: UserId,
    /// Joined from the person's account, for display.
    pub username: String,
    pub role: Role,
    /// The audit actor who added them or last changed their role.
    pub added_by: String,
    pub added_at: DateTime<Utc>,
}

/// The vaults a list covers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum VaultScope {
    /// Every vault.
    #[default]
    All,
    /// Only these; nothing when empty.
    Only(Vec<VaultId>),
}

impl VaultScope {
    pub fn one(id: VaultId) -> Self {
        VaultScope::Only(vec![id])
    }

    /// `None` means every vault.
    pub fn from_option(id: Option<&VaultId>) -> Self {
        id.map_or(VaultScope::All, |v| VaultScope::one(*v))
    }

    pub fn contains(&self, id: &VaultId) -> bool {
        match self {
            VaultScope::All => true,
            VaultScope::Only(ids) => ids.contains(id),
        }
    }

    /// Whether `vault`, possibly none for instance-wide records, is in
    /// scope. An instance-wide record is only in [`VaultScope::All`].
    pub fn covers(&self, vault: Option<&VaultId>) -> bool {
        match (self, vault) {
            (VaultScope::All, _) => true,
            (VaultScope::Only(ids), Some(v)) => ids.contains(v),
            (VaultScope::Only(_), None) => false,
        }
    }

    /// The vault ids as a JSON array, for SQL's `json_each`; `None` for
    /// every vault.
    pub fn json_ids(&self) -> Option<String> {
        match self {
            VaultScope::All => None,
            VaultScope::Only(ids) => Some(
                serde_json::to_string(&ids.iter().map(ToString::to_string).collect::<Vec<_>>())
                    .unwrap_or_else(|_| "[]".to_string()),
            ),
        }
    }

    /// Narrowed to one vault, when it is in scope; `None` when it is not.
    pub fn narrow(&self, id: &VaultId) -> Option<VaultScope> {
        self.contains(id).then(|| VaultScope::one(*id))
    }
}

/// What a person's sign-in may do.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignInScope {
    /// Whatever the person's roles allow: the console, and
    /// `tokenless login --manage`.
    #[default]
    Full,
    /// Only finding bundles and starting sessions from them, whatever the
    /// person's roles: `tokenless login`, kept on machines that run agents.
    Launch,
}

impl SignInScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            SignInScope::Full => "full",
            SignInScope::Launch => "launch",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "full" => Some(SignInScope::Full),
            "launch" => Some(SignInScope::Launch),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_scope_covers_only_its_vaults_and_instance_records_only_when_unscoped() {
        let (a, b) = (VaultId::new(), VaultId::new());
        let only_a = VaultScope::one(a);
        assert!(only_a.contains(&a) && !only_a.contains(&b));
        assert!(only_a.covers(Some(&a)) && !only_a.covers(None));
        assert!(VaultScope::All.covers(None));
        assert_eq!(only_a.narrow(&b), None);
        assert_eq!(only_a.narrow(&a), Some(VaultScope::one(a)));
        assert_eq!(VaultScope::All.json_ids(), None);
        assert_eq!(VaultScope::Only(vec![]).json_ids().as_deref(), Some("[]"));
        assert_eq!(only_a.json_ids(), Some(format!("[\"{a}\"]")));
    }

    #[test]
    fn sign_in_scopes_round_trip() {
        for scope in [SignInScope::Full, SignInScope::Launch] {
            assert_eq!(SignInScope::parse(scope.as_str()), Some(scope));
        }
        assert_eq!(SignInScope::parse("admin"), None);
    }
}
