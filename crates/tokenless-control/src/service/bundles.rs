// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Access bundles: named lists of a vault's rules, one per kind of job
//! (`code-review`, `support`), that sessions are minted from by name.
//!
//! A bundle is a convenience over picking rules by hand, not a grant of its
//! own: minting still needs `SessionMint` on the vault, and a session keeps
//! the rules it was minted with. Editing a bundle affects new sessions only;
//! to cut a running agent off, revoke its session or disable the rule.

use std::sync::Arc;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokenless_core::audit::{AuditEvent, AuditOutcome};
use tokenless_core::authz::Action;
use tokenless_core::ids::{BundleId, RuleId, VaultId};

use super::{Caller, Guard};
use crate::error::ControlError;
use crate::model::{AccessBundle, Page, PageRequest, VaultScope};
use crate::notify::PolicyNotifier;
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
    /// Requests each session minted from it may make; none for no limit.
    #[serde(default)]
    pub request_limit: Option<u64>,
}

/// Fields left out are unchanged; `rule_ids` replaces the whole list.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct UpdateBundle {
    pub name: Option<String>,
    pub description: Option<String>,
    pub rule_ids: Option<Vec<RuleId>>,
    /// `null` removes the limit; left out, it is unchanged.
    #[serde(default, deserialize_with = "some_or_null")]
    pub request_limit: Option<Option<u64>>,
}

fn some_or_null<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Option<u64>>, D::Error> {
    Option::<u64>::deserialize(d).map(Some)
}

/// The most requests a bundle may allow each session; past it, no limit
/// says the same.
pub const MAX_BUNDLE_REQUEST_LIMIT: u64 = 1_000_000_000;

fn validate_request_limit(limit: Option<u64>) -> Result<Option<u64>, ControlError> {
    match limit {
        Some(n) if n == 0 || n > MAX_BUNDLE_REQUEST_LIMIT => Err(ControlError::validation(format!(
            "an access bundle's request limit must be 1-{MAX_BUNDLE_REQUEST_LIMIT}, got {n}; leave it out for no limit"
        ))),
        other => Ok(other),
    }
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

fn limit_detail(limit: Option<u64>) -> String {
    limit.map_or_else(|| "none".to_string(), |n| n.to_string())
}

pub struct BundleService {
    policy: Arc<dyn PolicyStore>,
    guard: Guard,
    notifier: Arc<PolicyNotifier>,
}

/// What deleting a bundle did.
#[derive(Debug, Clone, Serialize)]
pub struct DeletedBundle {
    /// Live sessions minted from it, now ended.
    pub sessions_revoked: u64,
}

impl BundleService {
    pub fn new(policy: Arc<dyn PolicyStore>, guard: Guard, notifier: Arc<PolicyNotifier>) -> Self {
        Self {
            policy,
            guard,
            notifier,
        }
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
        let request_limit = validate_request_limit(req.request_limit)?;
        let now = Utc::now();
        let bundle = AccessBundle {
            id: BundleId::new(),
            vault_id: *vault_id,
            name,
            description,
            rule_ids,
            request_limit,
            created_by: caller.actor().to_string(),
            created_at: now,
            updated_at: now,
        };
        let event = AuditEvent::new(caller.actor(), "bundle.create", AuditOutcome::Success)
            .vault(*vault_id)
            .target(format!("access_bundle:{}", bundle.id))
            .detail("name", bundle.name.clone())
            .detail("rules", bundle.rule_ids.len().to_string())
            .detail("request_limit", limit_detail(bundle.request_limit));
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
        if let Some(limit) = req.request_limit {
            bundle.request_limit = validate_request_limit(limit)?;
        }
        bundle.updated_at = Utc::now();
        let event = AuditEvent::new(caller.actor(), "bundle.update", AuditOutcome::Success)
            .vault(bundle.vault_id)
            .target(format!("access_bundle:{id}"))
            .detail("name", bundle.name.clone())
            .detail("rules", bundle.rule_ids.len().to_string())
            .detail("request_limit", limit_detail(bundle.request_limit));
        self.policy.update_bundle(bundle.clone(), &[event]).await?;
        Ok(bundle)
    }

    /// Deletes the bundle and ends the live sessions minted from it, so
    /// removing a bundle cuts its agents off at the next policy refresh.
    pub async fn delete(
        &self,
        caller: &Caller,
        id: &BundleId,
    ) -> Result<DeletedBundle, ControlError> {
        let bundle = self.find(id).await?;
        self.guard
            .check(caller, Action::RuleDelete, Some(&bundle.vault_id))
            .await?;
        self.guard
            .check(caller, Action::SessionRevoke, Some(&bundle.vault_id))
            .await?;
        let event = AuditEvent::new(caller.actor(), "bundle.delete", AuditOutcome::Success)
            .vault(bundle.vault_id)
            .target(format!("access_bundle:{id}"))
            .detail("name", bundle.name.clone())
            .detail("ends_live_sessions", "true");
        let sessions_revoked = self.policy.delete_bundle(id, Utc::now(), &[event]).await?;
        if sessions_revoked > 0 {
            self.notifier.bump_sessions();
        }
        Ok(DeletedBundle { sessions_revoked })
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
        Ok(self
            .policy
            .list_bundles(&VaultScope::one(*vault_id), page)
            .await?)
    }

    /// Bundles across every vault the caller can see: a person's vaults,
    /// the bound vault's for an API key.
    pub async fn list_all(
        &self,
        caller: &Caller,
        page: PageRequest,
    ) -> Result<Page<AccessBundle>, ControlError> {
        self.guard.check_list(caller, Action::RuleRead).await?;
        let within = self.guard.vault_scope(caller, Action::RuleRead).await?;
        Ok(self.policy.list_bundles(&within, page).await?)
    }

    async fn find(&self, id: &BundleId) -> Result<AccessBundle, ControlError> {
        self.policy
            .get_bundle(id)
            .await?
            .ok_or_else(|| ControlError::not_found("access_bundle", id))
    }
}

/// `reference` is a bundle id or, failing that, a name in the vault.
pub(super) async fn find_bundle(
    policy: &dyn PolicyStore,
    vault_id: &VaultId,
    reference: &str,
) -> Result<AccessBundle, ControlError> {
    let reference = reference.trim();
    let by_id = match reference.parse::<BundleId>() {
        Ok(id) => policy.get_bundle(&id).await?,
        Err(_) => None,
    };
    let found = match by_id {
        Some(b) => Some(b),
        None => policy.get_bundle_by_name(vault_id, reference).await?,
    };
    match found {
        Some(b) if &b.vault_id == vault_id => Ok(b),
        _ => Err(ControlError::NotFound {
            entity: "access_bundle",
            id: format!("{reference}' in vault '{vault_id}"),
        }),
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

    #[tokio::test]
    async fn a_bundles_request_limit_caps_the_sessions_minted_from_it() {
        use tokenless_core::authz::{Principal, Role};

        use crate::model::{AuditQuery, PageRequest};
        use crate::service::sessions::MintSession;
        use crate::service::testing::{services, vault_with_rule};
        use crate::store::AuditSink;

        let (store, cs) = services().await;
        let host = Caller::service(Principal::service("host", Role::Admin, None));
        let (vault, rule) = vault_with_rule(&cs, &host).await;
        for bad in [0, MAX_BUNDLE_REQUEST_LIMIT + 1] {
            let err = cs
                .bundles
                .create(
                    &host,
                    &vault,
                    CreateBundle {
                        name: "bad".into(),
                        description: String::new(),
                        rule_ids: vec![rule],
                        request_limit: Some(bad),
                    },
                )
                .await
                .unwrap_err();
            assert!(
                matches!(&err, ControlError::Validation { .. })
                    && err.to_string().contains("request limit"),
                "{err:?}"
            );
        }
        let bundle = cs
            .bundles
            .create(
                &host,
                &vault,
                CreateBundle {
                    name: "review".into(),
                    description: String::new(),
                    rule_ids: vec![rule],
                    request_limit: Some(100),
                },
            )
            .await
            .unwrap();
        let mint = |asked: Option<u64>| MintSession {
            bundle: Some("review".into()),
            ttl_secs: Some(600),
            request_limit: asked,
            ..MintSession::default()
        };
        let limit_of = |asked| {
            let cs = &cs;
            let host = &host;
            async move {
                cs.sessions
                    .mint(host, &vault, mint(asked))
                    .await
                    .unwrap()
                    .session
                    .request_limit
            }
        };
        assert_eq!(limit_of(None).await, Some(100), "the bundle's by default");
        assert_eq!(limit_of(Some(10)).await, Some(10), "fewer when asked");
        assert_eq!(limit_of(Some(1000)).await, Some(100), "never more");

        // Left out, it stays; null removes it.
        let kept = cs
            .bundles
            .update(&host, &bundle.id, UpdateBundle::default())
            .await
            .unwrap();
        assert_eq!(kept.request_limit, Some(100));
        let update: UpdateBundle = serde_json::from_str(r#"{"request_limit": null}"#).unwrap();
        let removed = cs.bundles.update(&host, &bundle.id, update).await.unwrap();
        assert_eq!(removed.request_limit, None);
        assert_eq!(limit_of(Some(1000)).await, Some(1000));
        assert_eq!(limit_of(None).await, None);

        let audit = store
            .query(&AuditQuery {
                action_prefix: Some("bundle.".into()),
                page: PageRequest::new(Some(1), Some(10)),
                ..Default::default()
            })
            .await
            .unwrap();
        let limits: Vec<&str> = audit
            .items
            .iter()
            .map(|e| e.detail["request_limit"].as_str())
            .collect();
        assert_eq!(limits, ["none", "100", "100"], "newest first");
    }
}
