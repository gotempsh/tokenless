// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tripwires: decoy credentials to plant on agents' machines. Every proxy
//! refuses a request that carries one and cuts its session off; the
//! control plane revokes the session and raises an alert.

use std::sync::Arc;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokenless_core::audit::{AuditEvent, AuditOutcome};
use tokenless_core::authz::Action;
use tokenless_core::ids::{TripwireId, VaultId};
use tokenless_core::tripwire::TripwireKind;
use tracing::info;

use super::{Caller, Guard};
use crate::error::ControlError;
use crate::model::{Page, PageRequest, Tripwire};
use crate::notify::PolicyNotifier;
use crate::store::{PolicyStore, TripwireStore};

/// A vault holds at most this many; proxies are sent every vault's.
pub const MAX_TRIPWIRES_PER_VAULT: u64 = 20;
pub const MAX_NAME_LEN: usize = 100;

/// One way to plant a decoy, as text to paste.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plant {
    /// Where it goes, such as `~/.aws/credentials`.
    pub place: String,
    pub text: String,
}

/// A new tripwire, its decoy and how to plant it. Shown once.
#[derive(Clone, Serialize, Deserialize)]
pub struct CreatedTripwire {
    pub tripwire: Tripwire,
    pub value: String,
    /// The secret half that goes with it (AWS).
    pub secret: Option<String>,
    pub plant: Vec<Plant>,
}

impl std::fmt::Debug for CreatedTripwire {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreatedTripwire")
            .field("tripwire", &self.tripwire)
            .finish_non_exhaustive()
    }
}

/// Where a decoy of `kind` goes, ready to paste.
pub fn plant(kind: TripwireKind, value: &str, secret: Option<&str>) -> Vec<Plant> {
    let (var, secret_var) = kind.env_names();
    let mut exports = format!("export {var}={value}");
    let mut dotenv = format!("{var}={value}");
    if let (Some(name), Some(secret)) = (secret_var, secret) {
        exports.push_str(&format!("\nexport {name}={secret}"));
        dotenv.push_str(&format!("\n{name}={secret}"));
    }
    let mut ways = Vec::new();
    if let (TripwireKind::Aws, Some(secret)) = (kind, secret) {
        ways.push(Plant {
            place: "~/.aws/credentials".into(),
            text: format!(
                "[default]\naws_access_key_id = {value}\naws_secret_access_key = {secret}"
            ),
        });
    }
    ways.push(Plant {
        place: "the agent user's shell profile (~/.bashrc, ~/.zshrc)".into(),
        text: exports,
    });
    ways.push(Plant {
        place: "a .env file the agent does not read".into(),
        text: dotenv,
    });
    ways
}

pub struct TripwireService {
    tripwires: Arc<dyn TripwireStore>,
    policy: Arc<dyn PolicyStore>,
    guard: Guard,
    notifier: Arc<PolicyNotifier>,
}

impl TripwireService {
    pub fn new(
        tripwires: Arc<dyn TripwireStore>,
        policy: Arc<dyn PolicyStore>,
        guard: Guard,
        notifier: Arc<PolicyNotifier>,
    ) -> Self {
        Self {
            tripwires,
            policy,
            guard,
            notifier,
        }
    }

    pub async fn create(
        &self,
        caller: &Caller,
        vault_id: &VaultId,
        name: &str,
        kind: TripwireKind,
    ) -> Result<CreatedTripwire, ControlError> {
        self.guard
            .check(caller, Action::RuleWrite, Some(vault_id))
            .await?;
        let name = name.trim();
        if name.is_empty() || name.chars().count() > MAX_NAME_LEN {
            return Err(ControlError::validation(format!(
                "a tripwire's name must be 1-{MAX_NAME_LEN} characters, such as the machine it is planted on"
            )));
        }
        if self.policy.get_vault(vault_id).await?.is_none() {
            return Err(ControlError::not_found("vault", vault_id));
        }
        let existing = self
            .tripwires
            .list_tripwires(vault_id, PageRequest::new(Some(1), Some(1)))
            .await?;
        if existing.total >= MAX_TRIPWIRES_PER_VAULT {
            return Err(ControlError::validation(format!(
                "vault {vault_id} already has {MAX_TRIPWIRES_PER_VAULT} tripwires, the most it can hold; delete one first"
            )));
        }
        let decoy = kind.generate();
        let tripwire = Tripwire {
            id: TripwireId::new(),
            vault_id: *vault_id,
            name: name.to_string(),
            kind,
            prefix: decoy.value.chars().take(8).collect(),
            value: decoy.value.clone(),
            created_by: caller.actor().to_string(),
            created_at: Utc::now(),
            last_tripped_at: None,
        };
        let event = AuditEvent::new(caller.actor(), "tripwire.create", AuditOutcome::Success)
            .vault(*vault_id)
            .target(format!("tripwire:{}", tripwire.id))
            .detail("name", tripwire.name.clone())
            .detail("kind", kind.as_str())
            .detail("prefix", tripwire.prefix.clone());
        self.tripwires
            .insert_tripwire(tripwire.clone(), &[event])
            .await?;
        self.notifier.bump_content();
        info!(tripwire_id = %tripwire.id, vault_id = %vault_id, kind = kind.as_str(), "tripwire created");
        Ok(CreatedTripwire {
            plant: plant(kind, &decoy.value, decoy.secret.as_deref()),
            tripwire,
            value: decoy.value,
            secret: decoy.secret,
        })
    }

    pub async fn list(
        &self,
        caller: &Caller,
        vault_id: &VaultId,
        page: PageRequest,
    ) -> Result<Page<Tripwire>, ControlError> {
        self.guard
            .check(caller, Action::RuleRead, Some(vault_id))
            .await?;
        Ok(self.tripwires.list_tripwires(vault_id, page).await?)
    }

    /// Stops proxies looking for it. Needs a step-up: it removes a way to
    /// notice someone on an agent's machine.
    pub async fn delete(&self, caller: &Caller, id: &TripwireId) -> Result<Tripwire, ControlError> {
        let tripwire = self
            .tripwires
            .get_tripwire(id)
            .await?
            .ok_or_else(|| ControlError::not_found("tripwire", id))?;
        if caller
            .principal
            .vault
            .is_some_and(|bound| bound != tripwire.vault_id)
        {
            return Err(ControlError::not_found("tripwire", id));
        }
        self.guard
            .check(caller, Action::RuleDelete, Some(&tripwire.vault_id))
            .await?;
        self.guard.require_step_up(caller, Action::RuleDelete)?;
        let event = AuditEvent::new(caller.actor(), "tripwire.delete", AuditOutcome::Success)
            .vault(tripwire.vault_id)
            .target(format!("tripwire:{id}"))
            .detail("name", tripwire.name.clone())
            .detail("kind", tripwire.kind.as_str());
        if !self.tripwires.delete_tripwire(id, &[event]).await? {
            return Err(ControlError::not_found("tripwire", id));
        }
        self.notifier.bump_content();
        Ok(tripwire)
    }
}

#[cfg(test)]
mod tests;
