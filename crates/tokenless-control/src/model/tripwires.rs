// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tripwires: decoy credentials planted on agents' machines. Any request
//! through a proxy that carries one cuts its session off and raises an
//! alert.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokenless_core::ids::{TripwireId, VaultId};
use tokenless_core::tripwire::TripwireKind;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tripwire {
    pub id: TripwireId,
    pub vault_id: VaultId,
    /// Where it is planted, such as the machine's name.
    pub name: String,
    pub kind: TripwireKind,
    /// The decoy. Shown once when it is created and sent to proxies sealed;
    /// never in a response after. It opens nothing, so it is stored as is.
    #[serde(skip)]
    pub value: String,
    /// Its first characters, to recognise it by.
    pub prefix: String,
    /// An audit actor.
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub last_tripped_at: Option<DateTime<Utc>>,
}

impl std::fmt::Debug for Tripwire {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tripwire")
            .field("id", &self.id)
            .field("vault_id", &self.vault_id)
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("prefix", &self.prefix)
            .field("created_at", &self.created_at)
            .field("last_tripped_at", &self.last_tripped_at)
            .finish_non_exhaustive()
    }
}
