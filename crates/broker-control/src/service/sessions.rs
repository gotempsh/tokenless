// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Proxy sessions: signed tokens bound to a scope and a subset of rules.

use std::collections::BTreeMap;
use std::sync::Arc;

use broker_core::audit::{AuditEvent, AuditOutcome};
use broker_core::authz::Action;
use broker_core::ids::{BundleId, RuleId, SessionId, VaultId};
use broker_core::scope::Scope;
use broker_core::session::{
    key_id, verify_session, SessionClaims, SessionError, DEFAULT_SESSION_TTL_SECS,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use super::{Caller, Guard};
use crate::error::ControlError;
use crate::keys::KeyRing;
use crate::model::{AccessBundle, Page, PageRequest, ProxySession, SessionBundle};
use crate::notify::PolicyNotifier;
use crate::store::PolicyStore;

#[derive(Debug, Clone, Deserialize)]
pub struct MintSession {
    /// The rules to grant. Leave empty when minting from `bundle`.
    #[serde(default)]
    pub rule_ids: Vec<RuleId>,
    /// An access bundle of the vault, by name or id. Its enabled rules
    /// are granted; disabled ones are skipped.
    #[serde(default)]
    pub bundle: Option<String>,
    #[serde(default)]
    pub ttl_secs: Option<u64>,
    #[serde(default)]
    pub request_limit: Option<u64>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MintedSession {
    /// Returned exactly once. The broker keeps only the session record.
    pub token: String,
    pub session: ProxySession,
}

pub struct SessionService {
    policy: Arc<dyn PolicyStore>,
    keys: Arc<KeyRing>,
    guard: Guard,
    notifier: Arc<PolicyNotifier>,
}

impl SessionService {
    pub fn new(
        policy: Arc<dyn PolicyStore>,
        keys: Arc<KeyRing>,
        guard: Guard,
        notifier: Arc<PolicyNotifier>,
    ) -> Self {
        Self {
            policy,
            keys,
            guard,
            notifier,
        }
    }

    pub async fn mint(
        &self,
        caller: &Caller,
        vault_id: &VaultId,
        req: MintSession,
    ) -> Result<MintedSession, ControlError> {
        self.guard
            .check(caller, Action::SessionMint, Some(vault_id))
            .await?;
        let vault = self
            .policy
            .get_vault(vault_id)
            .await?
            .ok_or_else(|| ControlError::not_found("vault", vault_id))?;
        let (mut rule_ids, bundle, skipped) = match &req.bundle {
            Some(_) if !req.rule_ids.is_empty() => {
                return Err(ControlError::validation(
                    "give either rule_ids or a bundle, not both",
                ))
            }
            Some(reference) => {
                let bundle = self.find_bundle(vault_id, reference).await?;
                let (enabled, skipped) = self.enabled_rules_of(&bundle).await?;
                if enabled.is_empty() {
                    return Err(ControlError::validation(format!(
                        "access bundle '{}' in vault {vault_id} has no enabled rules; add a rule to it or enable one",
                        bundle.name
                    )));
                }
                let reference = SessionBundle {
                    id: bundle.id,
                    name: bundle.name,
                };
                (enabled, Some(reference), skipped)
            }
            None => (req.rule_ids.clone(), None, 0),
        };
        rule_ids.sort();
        rule_ids.dedup();
        for rule_id in &rule_ids {
            let rule = self
                .policy
                .get_rule(rule_id)
                .await?
                .ok_or_else(|| ControlError::not_found("rule", rule_id))?;
            if &rule.vault_id != vault_id {
                return Err(ControlError::validation(format!(
                    "rule {rule_id} does not belong to vault {vault_id}"
                )));
            }
            if !rule.enabled {
                return Err(ControlError::validation(format!(
                    "rule {rule_id} is disabled"
                )));
            }
        }
        let claims = SessionClaims::new(
            Scope::for_vault(&vault.id),
            rule_ids.clone(),
            req.ttl_secs.unwrap_or(DEFAULT_SESSION_TTL_SECS),
            req.request_limit,
            req.labels.clone(),
            Utc::now(),
        )?;
        let token = self.keys.session_signer.sign(&claims)?;
        let session = ProxySession {
            id: claims.jti,
            vault_id: *vault_id,
            rule_ids,
            bundle,
            labels: req.labels,
            request_limit: req.request_limit,
            created_by: caller.actor().to_string(),
            created_at: claims.iat,
            expires_at: claims.exp,
            revoked_at: None,
        };
        let mut event = AuditEvent::new(caller.actor(), "session.mint", AuditOutcome::Success)
            .vault(*vault_id)
            .target(format!("session:{}", session.id))
            .detail("expires_at", session.expires_at.to_rfc3339())
            .detail("rules", session.rule_ids.len().to_string());
        if let Some(b) = &session.bundle {
            event = event
                .detail("bundle", b.name.clone())
                .detail("bundle_id", b.id.to_string())
                .detail("disabled_rules_skipped", skipped.to_string());
        }
        for (k, v) in &session.labels {
            event = event.detail(&format!("label.{k}"), v.clone());
        }
        self.policy
            .insert_session(session.clone(), &[event])
            .await?;
        if session.request_limit.is_some() {
            self.notifier.bump_sessions();
        }
        Ok(MintedSession { token, session })
    }

    /// `reference` is a bundle id or, failing that, a name in the vault.
    async fn find_bundle(
        &self,
        vault_id: &VaultId,
        reference: &str,
    ) -> Result<AccessBundle, ControlError> {
        let reference = reference.trim();
        let by_id = match reference.parse::<BundleId>() {
            Ok(id) => self.policy.get_bundle(&id).await?,
            Err(_) => None,
        };
        let found = match by_id {
            Some(b) => Some(b),
            None => self.policy.get_bundle_by_name(vault_id, reference).await?,
        };
        match found {
            Some(b) if &b.vault_id == vault_id => Ok(b),
            _ => Err(ControlError::NotFound {
                entity: "access_bundle",
                id: format!("{reference}' in vault '{vault_id}"),
            }),
        }
    }

    /// The bundle's enabled rules, and how many disabled ones were skipped.
    async fn enabled_rules_of(
        &self,
        bundle: &AccessBundle,
    ) -> Result<(Vec<RuleId>, usize), ControlError> {
        let mut enabled = Vec::with_capacity(bundle.rule_ids.len());
        let mut skipped = 0;
        for id in &bundle.rule_ids {
            match self.policy.get_rule(id).await? {
                Some(rule) if rule.enabled => enabled.push(*id),
                Some(_) => skipped += 1,
                // Deleting a rule removes it from bundles; tolerate a race.
                None => skipped += 1,
            }
        }
        Ok((enabled, skipped))
    }

    pub async fn revoke(
        &self,
        caller: &Caller,
        id: &SessionId,
    ) -> Result<ProxySession, ControlError> {
        let session = self
            .policy
            .get_session(id)
            .await?
            .ok_or_else(|| ControlError::not_found("session", id))?;
        self.guard
            .check(caller, Action::SessionRevoke, Some(&session.vault_id))
            .await?;
        let event = AuditEvent::new(caller.actor(), "session.revoke", AuditOutcome::Success)
            .vault(session.vault_id)
            .target(format!("session:{id}"))
            .detail("already_revoked", session.revoked_at.is_some().to_string());
        if self.policy.revoke_session(id, Utc::now(), &[event]).await? {
            self.notifier.bump_sessions();
        }
        self.policy
            .get_session(id)
            .await?
            .ok_or_else(|| ControlError::not_found("session", id))
    }

    /// Ends the session the token belongs to. Holding a session's token is
    /// enough to end it, so a launcher can clean up after its agent with no
    /// more than what it handed the agent. An already expired session is
    /// left alone: there is nothing to end.
    pub async fn revoke_self(&self, token: &str) -> Result<ProxySession, ControlError> {
        let verifying = self.keys.session_signer.verifying_key();
        let keys = std::collections::HashMap::from([(key_id(&verifying), verifying)]);
        let id = match verify_session(token.trim(), &keys, Utc::now()) {
            Ok(claims) => claims.jti,
            Err(SessionError::Expired { session_id, .. }) => {
                return self
                    .policy
                    .get_session(&session_id)
                    .await?
                    .ok_or_else(|| ControlError::not_found("session", session_id));
            }
            Err(e) => {
                return Err(ControlError::Unauthenticated {
                    reason: format!("not a valid proxy session token: {e}"),
                })
            }
        };
        let session = self
            .policy
            .get_session(&id)
            .await?
            .ok_or_else(|| ControlError::not_found("session", id))?;
        let actor = format!("session:{id}");
        let event = AuditEvent::new(&actor, "session.revoke", AuditOutcome::Success)
            .vault(session.vault_id)
            .target(format!("session:{id}"))
            .detail("by", "session token".to_string())
            .detail("already_revoked", session.revoked_at.is_some().to_string());
        if self
            .policy
            .revoke_session(&id, Utc::now(), &[event])
            .await?
        {
            self.notifier.bump_sessions();
        }
        self.policy
            .get_session(&id)
            .await?
            .ok_or_else(|| ControlError::not_found("session", id))
    }

    pub async fn list(
        &self,
        caller: &Caller,
        vault_id: &VaultId,
        page: PageRequest,
    ) -> Result<Page<ProxySession>, ControlError> {
        self.guard
            .check(caller, Action::SessionRead, Some(vault_id))
            .await?;
        Ok(self.policy.list_sessions(Some(vault_id), page).await?)
    }

    /// Sessions in every vault the caller can see: all of them for an
    /// unbound principal, the bound vault's otherwise.
    pub async fn list_all(
        &self,
        caller: &Caller,
        page: PageRequest,
    ) -> Result<Page<ProxySession>, ControlError> {
        let vault = caller.principal.vault;
        self.guard
            .check(caller, Action::SessionRead, vault.as_ref())
            .await?;
        Ok(self.policy.list_sessions(vault.as_ref(), page).await?)
    }
}
