// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Proxy sessions: signed tokens bound to a scope and a subset of rules.

use std::collections::BTreeMap;
use std::sync::Arc;

use broker_core::audit::{AuditEvent, AuditOutcome};
use broker_core::authz::Action;
use broker_core::ids::{RuleId, SessionId, VaultId};
use broker_core::scope::Scope;
use broker_core::session::{SessionClaims, DEFAULT_SESSION_TTL_SECS};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use super::{Caller, Guard};
use crate::error::ControlError;
use crate::keys::KeyRing;
use crate::model::{Page, PageRequest, ProxySession};
use crate::notify::PolicyNotifier;
use crate::store::PolicyStore;

#[derive(Debug, Clone, Deserialize)]
pub struct MintSession {
    pub rule_ids: Vec<RuleId>,
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
        let mut rule_ids = req.rule_ids.clone();
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

    pub async fn list(
        &self,
        caller: &Caller,
        vault_id: &VaultId,
        page: PageRequest,
    ) -> Result<Page<ProxySession>, ControlError> {
        self.guard
            .check(caller, Action::SessionRead, Some(vault_id))
            .await?;
        Ok(self.policy.list_sessions(vault_id, page).await?)
    }
}
