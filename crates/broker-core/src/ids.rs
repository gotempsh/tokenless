// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strongly typed identifiers. Each is a UUID v4 serialised as a string so a
//! rule ID can never be passed where a session ID is expected.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

macro_rules! id_type {
    ($(#[$meta:meta])* $name:ident, $label:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            pub fn kind() -> &'static str {
                $label
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(s).map(Self)
            }
        }
    };
}

id_type!(
    /// A vault groups credentials, rules and sessions under one scope.
    VaultId,
    "vault"
);
id_type!(CredentialId, "credential");
id_type!(RuleId, "rule");
id_type!(SessionId, "session");
id_type!(NodeId, "node");
id_type!(UserId, "user");
id_type!(ApiKeyId, "api_key");
id_type!(InviteId, "invite");
id_type!(VariableId, "variable");
id_type!(AuditEventId, "audit_event");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_round_trip_through_strings_and_json() {
        let id = RuleId::new();
        let parsed: RuleId = id.to_string().parse().unwrap();
        assert_eq!(id, parsed);
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{id}\""));
    }

    #[test]
    fn invalid_id_is_rejected() {
        assert!("not-a-uuid".parse::<VaultId>().is_err());
    }
}
