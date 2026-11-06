// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Access bundles: named lists of a vault's rules, one per kind of job
//! (`code-review`, `support`), that sessions are minted from by name.
//!
//! A bundle is a convenience over picking rules by hand, not a grant of its
//! own: minting still needs `SessionMint` on the vault, and a session keeps
//! the rules it was minted with. Editing a bundle affects new sessions only;
//! to cut a running agent off, revoke its session or disable the rule.

use std::sync::Arc;

use broker_core::audit::{AuditEvent, AuditOutcome};
use broker_core::authz::Action;
use broker_core::ids::{BundleId, RuleId, VaultId};
use chrono::Utc;
use serde::Deserialize;

use super::{Caller, Guard};
use crate::error::ControlError;
use crate::model::{AccessBundle, Page, PageRequest};
use crate::store::PolicyStore;

pub const MAX_BUNDLE_NAME: usize = 64;
pub const MAX_BUNDLE_DESCRIPTION: usize = 500;
pub const MAX_BUNDLE_RULES: usize = 100;

#[derive(Debug, Clone, Deserialize)]
pub struct CreateBundle {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub rule_ids: Vec<RuleId>,
}

/// Fields left out are unchanged; `rule_ids` replaces the whole list.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct UpdateBundle {
    pub name: Option<String>,
    pub description: Option<String>,
    pub rule_ids: Option<Vec<RuleId>>,
}

/// Names are typed on command lines (`run --bundle code-review`), so they
/// are restricted to characters that never need quoting.
pub fn validate_bundle_name(name: &str) -> Result<String, ControlError> {
    let name = name.trim();
    let valid = !name.is_empty()
        && name.len() <= MAX_BUNDLE_NAME
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if !valid {
        return Err(ControlError::validation(format!(
            "access bundle name '{name}' must be 1-{MAX_BUNDLE_NAME} letters, digits, '-', '_' or '.', starting with a letter or digit"
        )));
    }
    Ok(name.to_string())
}

fn validate_description(description: &str) -> Result<String, ControlError> {
    let description = description.trim();
    if description.chars().count() > MAX_BUNDLE_DESCRIPTION
        || description.chars().any(|c| c.is_control() && c != '\n')
    {
        return Err(ControlError::validation(format!(
            "access bundle description must be at most {MAX_BUNDLE_DESCRIPTION} printable characters"
        )));
    }
    Ok(description.to_string())
}

pub struct BundleService {
    policy: Arc<dyn PolicyStore>,
    guard: Guard,
}

impl BundleService {
    pub fn new(policy: Arc<dyn PolicyStore>, guard: Guard) -> Self {
        Self { policy, guard }
    }

    /// Every rule must exist and belong to the bundle's vault. Disabled
    /// rules are allowed: they are skipped when a session is minted.
    async fn checked_rules(
        &self,
        vault_id: &VaultId,
        rule_ids: &[RuleId],
    ) -> Result<Vec<RuleId>, ControlError> {
        let mut ids = rule_ids.to_vec();
        ids.sort();
        ids.dedup();
        if ids.len() > MAX_BUNDLE_RULES {
            return Err(ControlError::validation(format!(
                "an access bundle holds at most {MAX_BUNDLE_RULES} rules, got {}",
                ids.len()
            )));
        }
        for id in &ids {
            let rule = self
                .policy
                .get_rule(id)
                .await?
                .ok_or_else(|| ControlError::not_found("rule", id))?;
            if &rule.vault_id != vault_id {
                return Err(ControlError::validation(format!(
                    "rule {id} belongs to vault {}, not {vault_id}",
                    rule.vault_id
                )));
            }
        }
        Ok(ids)
    }

    pub async fn create(
        &self,
        caller: &Caller,
        vault_id: &VaultId,
        req: CreateBundle,
    ) -> Result<AccessBundle, ControlError> {
        self.guard
            .check(caller, Action::RuleWrite, Some(vault_id))
            .await?;
        self.policy
            .get_vault(vault_id)
            .await?
            .ok_or_else(|| ControlError::not_found("vault", vault_id))?;
        let name = validate_bundle_name(&req.name)?;
        let description = validate_description(&req.description)?;
        let rule_ids = self.checked_rules(vault_id, &req.rule_ids).await?;
        let now = Utc::now();
        let bundle = AccessBundle {
            id: BundleId::new(),
            vault_id: *vault_id,
            name,
            description,
            rule_ids,
            created_by: caller.actor().to_string(),
            created_at: now,
            updated_at: now,
        };
        let event = AuditEvent::new(caller.actor(), "bundle.create", AuditOutcome::Success)
            .vault(*vault_id)
            .target(format!("access_bundle:{}", bundle.id))
            .detail("name", bundle.name.clone())
            .detail("rules", bundle.rule_ids.len().to_string());
        self.policy.insert_bundle(bundle.clone(), &[event]).await?;
        Ok(bundle)
    }

    pub async fn update(
        &self,
        caller: &Caller,
        id: &BundleId,
        req: UpdateBundle,
    ) -> Result<AccessBundle, ControlError> {
        let mut bundle = self.find(id).await?;
        self.guard
            .check(caller, Action::RuleWrite, Some(&bundle.vault_id))
            .await?;
        if let Some(name) = &req.name {
            bundle.name = validate_bundle_name(name)?;
        }
        if let Some(description) = &req.description {
            bundle.description = validate_description(description)?;
        }
        if let Some(rule_ids) = &req.rule_ids {
            bundle.rule_ids = self.checked_rules(&bundle.vault_id, rule_ids).await?;
        }
        bundle.updated_at = Utc::now();
        let event = AuditEvent::new(caller.actor(), "bundle.update", AuditOutcome::Success)
            .vault(bundle.vault_id)
            .target(format!("access_bundle:{id}"))
            .detail("name", bundle.name.clone())
            .detail("rules", bundle.rule_ids.len().to_string());
        self.policy.update_bundle(bundle.clone(), &[event]).await?;
        Ok(bundle)
    }

    pub async fn delete(&self, caller: &Caller, id: &BundleId) -> Result<(), ControlError> {
        let bundle = self.find(id).await?;
        self.guard
            .check(caller, Action::RuleDelete, Some(&bundle.vault_id))
            .await?;
        let event = AuditEvent::new(caller.actor(), "bundle.delete", AuditOutcome::Success)
            .vault(bundle.vault_id)
            .target(format!("access_bundle:{id}"))
            .detail("name", bundle.name.clone());
        self.policy.delete_bundle(id, &[event]).await?;
        Ok(())
    }

    pub async fn get(&self, caller: &Caller, id: &BundleId) -> Result<AccessBundle, ControlError> {
        let bundle = self.find(id).await?;
        self.guard
            .check(caller, Action::RuleRead, Some(&bundle.vault_id))
            .await?;
        Ok(bundle)
    }

    pub async fn list(
        &self,
        caller: &Caller,
        vault_id: &VaultId,
        page: PageRequest,
    ) -> Result<Page<AccessBundle>, ControlError> {
        self.guard
            .check(caller, Action::RuleRead, Some(vault_id))
            .await?;
        Ok(self.policy.list_bundles(vault_id, page).await?)
    }

    async fn find(&self, id: &BundleId) -> Result<AccessBundle, ControlError> {
        self.policy
            .get_bundle(id)
            .await?
            .ok_or_else(|| ControlError::not_found("access_bundle", id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_names_are_shell_safe() {
        for good in ["code-review", "support_v2", "a", "ops.daily", " trimmed "] {
            assert!(validate_bundle_name(good).is_ok(), "{good}");
        }
        for bad in [
            "",
            "-leading",
            "has space",
            "semi;colon",
            "naïve",
            &"x".repeat(65),
        ] {
            let err = validate_bundle_name(bad).unwrap_err().to_string();
            assert!(err.contains("access bundle name"), "{bad}: {err}");
        }
    }

    #[test]
    fn descriptions_are_bounded() {
        assert_eq!(
            validate_description("  for reviews \n").unwrap(),
            "for reviews"
        );
        assert!(validate_description(&"x".repeat(501)).is_err());
        assert!(validate_description("bell\u{7}").is_err());
    }
}
