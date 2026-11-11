// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Launcher keys: API keys that only start sessions from one access bundle.
//!
//! An agent machine that runs `tokenless run` needs something to start its
//! sessions with. A person's sign-in reaches every bundle of every vault
//! they can see, so whoever gets onto that machine could start sessions for
//! all of them. A launcher key reaches one bundle, and every session it
//! starts gets the key's limits (lifetime, request limit, proxy, labels)
//! whatever the request asks for; see `SessionService::mint`.
//!
//! Editors of the vault create them (with step-up, like any new access) and
//! revoke them (without, so access can be cut off at once).

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use tokenless_auth::token;
use tokenless_core::audit::{AuditEvent, AuditOutcome};
use tokenless_core::authz::{Action, Role};
use tokenless_core::ids::{ApiKeyId, BundleId, NodeId, VaultId};
use tokenless_core::session::{validate_labels, DEFAULT_SESSION_TTL_SECS};

use super::{Caller, Guard};
use crate::error::ControlError;
use crate::model::{ApiKey, LaunchScope, Page, PageRequest, SessionCursor, MAX_PAGE_SIZE};
use crate::notify::PolicyNotifier;
use crate::store::{IdentityStore, NodeStore, PolicyStore};

/// How long a launcher key works when the request names no lifetime.
pub const DEFAULT_LAUNCHER_KEY_DAYS: u32 = 90;
pub const MAX_LAUNCHER_KEY_DAYS: u32 = 365;

#[derive(Debug, Clone, Deserialize)]
pub struct CreateLauncherKey {
    pub name: String,
    /// The access bundle, by name or id.
    pub bundle: String,
    /// The longest session the key starts. Default: 15 minutes, or less if
    /// Settings allow less.
    #[serde(default)]
    pub max_ttl_secs: Option<u64>,
    #[serde(default)]
    pub request_limit: Option<u64>,
    /// Only this proxy accepts the key's sessions. Choosing where
    /// credentials go needs the right to manage proxies.
    #[serde(default)]
    pub node_id: Option<NodeId>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    #[serde(default)]
    pub expires_in_days: Option<u32>,
}

/// A launcher key as listed: never its secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LauncherKey {
    pub id: ApiKeyId,
    pub name: String,
    pub prefix: String,
    pub vault_id: VaultId,
    pub bundle_id: BundleId,
    pub max_ttl_secs: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_limit: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<NodeId>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    pub created_by: String,
    pub created_at: chrono::DateTime<Utc>,
    pub expires_at: chrono::DateTime<Utc>,
    pub revoked_at: Option<chrono::DateTime<Utc>>,
    pub last_used_at: Option<chrono::DateTime<Utc>>,
}

impl LauncherKey {
    /// `None` for an ordinary API key.
    pub fn from_api_key(key: &ApiKey) -> Option<Self> {
        let launch = key.launch.as_ref()?;
        Some(Self {
            id: key.id,
            name: key.name.clone(),
            prefix: key.prefix.clone(),
            vault_id: key.vault_id,
            bundle_id: launch.bundle_id,
            max_ttl_secs: launch.max_ttl_secs,
            request_limit: launch.request_limit,
            node_id: launch.node_id,
            labels: launch.labels.clone(),
            created_by: key.created_by.clone(),
            created_at: key.created_at,
            expires_at: key.expires_at,
            revoked_at: key.revoked_at,
            last_used_at: key.last_used_at,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokedLauncherKey {
    pub launcher_key: LauncherKey,
    /// Live sessions the key had started, now ended.
    pub sessions_revoked: u64,
}

/// A new launcher key. The key is returned exactly once.
#[derive(Clone, Serialize, Deserialize)]
pub struct CreatedLauncherKey {
    pub key: String,
    pub launcher_key: LauncherKey,
}

tokenless_core::redacted_debug!(CreatedLauncherKey { launcher_key; key });

pub struct LauncherKeyService {
    identity: Arc<dyn IdentityStore>,
    policy: Arc<dyn PolicyStore>,
    nodes: Arc<dyn NodeStore>,
    guard: Guard,
    notifier: Arc<PolicyNotifier>,
}

impl LauncherKeyService {
    pub fn new(
        identity: Arc<dyn IdentityStore>,
        policy: Arc<dyn PolicyStore>,
        nodes: Arc<dyn NodeStore>,
        guard: Guard,
        notifier: Arc<PolicyNotifier>,
    ) -> Self {
        Self {
            identity,
            policy,
            nodes,
            guard,
            notifier,
        }
    }

    pub async fn create(
        &self,
        caller: &Caller,
        vault_id: &VaultId,
        req: CreateLauncherKey,
    ) -> Result<CreatedLauncherKey, ControlError> {
        self.guard
            .check(caller, Action::LauncherKeyCreate, Some(vault_id))
            .await?;
        let name = req.name.trim();
        if name.is_empty() || name.len() > 100 {
            return Err(ControlError::validation(
                "launcher key name must be 1-100 characters",
            ));
        }
        let days = req.expires_in_days.unwrap_or(DEFAULT_LAUNCHER_KEY_DAYS);
        if days == 0 || days > MAX_LAUNCHER_KEY_DAYS {
            return Err(ControlError::validation(format!(
                "expires_in_days must be between 1 and {MAX_LAUNCHER_KEY_DAYS}"
            )));
        }
        let bundle =
            super::bundles::find_bundle(self.policy.as_ref(), vault_id, &req.bundle).await?;
        let max_allowed = self.policy.get_settings().await?.max_session_ttl_secs;
        let max_ttl_secs = req
            .max_ttl_secs
            .unwrap_or(DEFAULT_SESSION_TTL_SECS.min(max_allowed));
        if max_ttl_secs == 0 || max_ttl_secs > max_allowed {
            return Err(ControlError::validation(format!(
                "max_ttl_secs must be between 1 and {max_allowed} (Settings → Session lifetime)"
            )));
        }
        if req.request_limit == Some(0) {
            return Err(ControlError::validation(
                "request_limit must be at least 1; leave it out for no limit",
            ));
        }
        validate_labels(&req.labels)?;
        if let Some(node_id) = &req.node_id {
            self.guard.check(caller, Action::NodeManage, None).await?;
            let node = self
                .nodes
                .get_node(node_id)
                .await?
                .ok_or_else(|| ControlError::not_found("node", node_id))?;
            if node.revoked_at.is_some() {
                return Err(ControlError::validation(format!(
                    "node {node_id} ('{}') is revoked; a launcher key can't be pinned to it",
                    node.name
                )));
            }
        }
        let parts = token::new_api_key();
        let now = Utc::now();
        let key = ApiKey {
            id: ApiKeyId::new(),
            name: name.to_string(),
            prefix: parts.prefix.clone(),
            secret_hash: token::hash_token(&parts.full),
            vault_id: *vault_id,
            // Minting needs editor; the launch scope narrows it to one bundle.
            role: Role::Editor,
            created_by: caller.actor().to_string(),
            created_at: now,
            expires_at: now + Duration::days(i64::from(days)),
            revoked_at: None,
            last_used_at: None,
            launch: Some(LaunchScope {
                bundle_id: bundle.id,
                max_ttl_secs,
                request_limit: req.request_limit,
                node_id: req.node_id,
                labels: req.labels,
            }),
        };
        let mut event =
            AuditEvent::new(caller.actor(), "launcher_key.create", AuditOutcome::Success)
                .vault(*vault_id)
                .target(format!("api_key:{}", key.prefix))
                .detail("name", key.name.clone())
                .detail("bundle", bundle.name.clone())
                .detail("bundle_id", bundle.id.to_string())
                .detail("max_ttl_secs", max_ttl_secs.to_string())
                .detail("expires_at", key.expires_at.to_rfc3339());
        if let Some(limit) = req.request_limit {
            event = event.detail("request_limit", limit.to_string());
        }
        if let Some(node) = req.node_id {
            event = event.detail("node_id", node.to_string());
        }
        self.identity.insert_api_key(key.clone(), &[event]).await?;
        let launcher_key = LauncherKey::from_api_key(&key).ok_or_else(|| {
            ControlError::validation(format!("launcher key {} lost its scope", key.prefix))
        })?;
        Ok(CreatedLauncherKey {
            key: parts.full,
            launcher_key,
        })
    }

    pub async fn list(
        &self,
        caller: &Caller,
        vault_id: &VaultId,
        bundle: Option<&BundleId>,
        page: PageRequest,
    ) -> Result<Page<LauncherKey>, ControlError> {
        self.guard
            .check(caller, Action::LauncherKeyRead, Some(vault_id))
            .await?;
        let found = self
            .identity
            .list_launcher_keys(vault_id, bundle, page)
            .await?;
        Ok(Page {
            items: found
                .items
                .iter()
                .filter_map(LauncherKey::from_api_key)
                .collect(),
            total: found.total,
            page: found.page,
            page_size: found.page_size,
        })
    }

    /// Revokes the key and ends the live sessions it started, so whoever
    /// holds it is cut off at once. Revoking twice is not an error: the key
    /// stays revoked and any session still live is ended.
    pub async fn revoke(
        &self,
        caller: &Caller,
        vault_id: &VaultId,
        id: &ApiKeyId,
    ) -> Result<RevokedLauncherKey, ControlError> {
        self.guard
            .check(caller, Action::LauncherKeyRevoke, Some(vault_id))
            .await?;
        let key = self
            .identity
            .get_api_key(id)
            .await?
            .filter(|k| &k.vault_id == vault_id && k.launch.is_some())
            .ok_or_else(|| ControlError::NotFound {
                entity: "launcher_key",
                id: format!("{id}' in vault '{vault_id}"),
            })?;
        let event = AuditEvent::new(caller.actor(), "launcher_key.revoke", AuditOutcome::Success)
            .vault(*vault_id)
            .target(format!("api_key:{}", key.prefix))
            .detail("name", key.name.clone());
        let now = Utc::now();
        let revoked_now = self.identity.revoke_api_key(id, now, &[event]).await?;
        let key = ApiKey {
            revoked_at: if revoked_now {
                Some(now)
            } else {
                key.revoked_at
            },
            ..key
        };
        let launcher_key =
            LauncherKey::from_api_key(&key).ok_or_else(|| ControlError::NotFound {
                entity: "launcher_key",
                id: id.to_string(),
            })?;
        let sessions_revoked = self
            .end_sessions(caller, &key, &launcher_key.bundle_id)
            .await?;
        Ok(RevokedLauncherKey {
            launcher_key,
            sessions_revoked,
        })
    }

    /// Ends the live sessions `key` started from its bundle.
    async fn end_sessions(
        &self,
        caller: &Caller,
        key: &ApiKey,
        bundle_id: &BundleId,
    ) -> Result<u64, ControlError> {
        let actor = format!("api_key:{}", key.prefix);
        let now = Utc::now();
        let mut after: Option<SessionCursor> = None;
        let mut ended = 0;
        loop {
            let page = self
                .policy
                .list_sessions(
                    Some(&key.vault_id),
                    Some(bundle_id),
                    Some(now),
                    after.as_ref(),
                    PageRequest::new(Some(1), Some(MAX_PAGE_SIZE)),
                )
                .await?;
            for session in page.items.iter().filter(|s| s.created_by == actor) {
                let event =
                    AuditEvent::new(caller.actor(), "session.revoke", AuditOutcome::Success)
                        .vault(session.vault_id)
                        .target(format!("session:{}", session.id))
                        .detail("reason", "launcher key revoked")
                        .detail("launcher_key", key.prefix.clone());
                if self
                    .policy
                    .revoke_session(&session.id, now, &[event])
                    .await?
                {
                    ended += 1;
                }
            }
            match page.items.last() {
                Some(last) if page.total > page.items.len() as u64 => {
                    after = Some(SessionCursor::from(last));
                }
                _ => break,
            }
        }
        if ended > 0 {
            self.notifier.bump_sessions();
        }
        Ok(ended)
    }
}

#[cfg(test)]
mod tests;
