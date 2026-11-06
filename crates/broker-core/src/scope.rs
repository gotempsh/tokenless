// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Opaque scopes.
//!
//! The data plane never interprets a scope: it only compares the scope in a
//! session token with the scope attached to each rule. Standalone mode uses
//! `vault:<uuid>`; an embedding control plane is free to use its own shape
//! (for example `project:12/environment:3`).

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::ids::VaultId;

const MAX_SCOPE_LEN: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Scope(String);

impl Scope {
    pub fn parse(input: &str) -> Result<Self, CoreError> {
        if input.is_empty() {
            return Err(CoreError::InvalidScope {
                input: input.to_string(),
                reason: "scope cannot be empty".into(),
            });
        }
        if input.len() > MAX_SCOPE_LEN {
            return Err(CoreError::InvalidScope {
                input: input.chars().take(32).collect(),
                reason: format!("scope is longer than {MAX_SCOPE_LEN} bytes"),
            });
        }
        if let Some(bad) = input
            .chars()
            .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, ':' | '/' | '_' | '.' | '-')))
        {
            return Err(CoreError::InvalidScope {
                input: input.to_string(),
                reason: format!("character '{bad}' is not allowed"),
            });
        }
        Ok(Self(input.to_string()))
    }

    /// The scope used by standalone mode for a vault.
    pub fn for_vault(vault_id: &VaultId) -> Self {
        Self(format!("vault:{vault_id}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for Scope {
    type Error = CoreError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Scope::parse(&value)
    }
}

impl From<Scope> for String {
    fn from(value: Scope) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_scope_is_valid() {
        let vault = VaultId::new();
        let scope = Scope::for_vault(&vault);
        assert_eq!(Scope::parse(scope.as_str()).unwrap(), scope);
    }

    #[test]
    fn rejects_empty_and_odd_characters() {
        assert!(Scope::parse("").is_err());
        assert!(Scope::parse("vault 1").is_err());
        assert!(Scope::parse("vault\n1").is_err());
        assert!(Scope::parse(&"a".repeat(300)).is_err());
    }

    #[test]
    fn deserialisation_validates() {
        assert!(serde_json::from_str::<Scope>("\"bad scope\"").is_err());
        assert!(serde_json::from_str::<Scope>("\"project:1/env:2\"").is_ok());
    }
}
