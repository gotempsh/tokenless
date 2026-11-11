// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Proxy sessions: signed tokens bound to a scope and a subset of rules.

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokenless_core::audit::{AuditEvent, AuditOutcome};
use tokenless_core::authz::Action;
use tokenless_core::ids::{BundleId, NodeId, RuleId, SessionId, VaultId};
use tokenless_core::scope::Scope;
use tokenless_core::session::{
    key_id, validate_labels, verify_session, SessionClaims, SessionError, DEFAULT_SESSION_TTL_SECS,
};
use tokenless_core::substitution::SubstitutionLocation;
use tokenless_core::template::{builtin_mcp_path, ServiceKind};

use super::{Caller, Guard};
use crate::error::ControlError;
use crate::keys::KeyRing;
use crate::model::{AccessBundle, Page, PageRequest, ProxySession, SessionBundle, SessionListing};
use crate::notify::PolicyNotifier;
use crate::store::{CredentialStore, NodeStore, PolicyStore};

#[derive(Debug, Clone, Default, Deserialize)]
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
    /// Ignore `ttl_secs` and last as long as Settings allow: for tokens
    /// that live in an MCP client's configuration.
    #[serde(default)]
    pub longest: bool,
    #[serde(default)]
    pub request_limit: Option<u64>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// Only this data plane node accepts the session.
    #[serde(default)]
    pub node_id: Option<NodeId>,
    /// The binding the session is for. It then works only through that
    /// binding (one start of one sandbox), never from a header.
    #[serde(default)]
    pub binding: Option<SessionBinding>,
    /// An absolute deadline: the session ends by then whatever its
    /// lifetime, and none is minted once it has passed. A caller that
    /// renews a grant passes the grant's deadline each time, so renewing
    /// never extends it.
    #[serde(default)]
    pub not_after: Option<DateTime<Utc>>,
    /// Earlier deadlines for some of the granted rules, so grants that end
    /// at different times share one session. Like `not_after`, a caller
    /// that renews passes the same deadlines each time; one that has
    /// passed refuses the mint.
    #[serde(default)]
    pub rule_not_after: BTreeMap<RuleId, DateTime<Utc>>,
    /// Cut open traffic at the deadlines themselves (the session's, each
    /// rule's, each credential's), not a grace period after the session
    /// expires. For access promised for a set time.
    #[serde(default)]
    pub strict: bool,
}

/// Which binding a session is minted for: the workload's id and which start
/// of it. A new start takes a new generation, so its old sessions stop
/// working there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionBinding {
    pub id: String,
    pub generation: u64,
}

#[derive(Clone, Serialize)]
pub struct MintedSession {
    /// Returned exactly once. The broker keeps only the session record.
    pub token: String,
    pub session: ProxySession,
}

tokenless_core::redacted_debug!(MintedSession { session; token });

/// How long a new session in a vault may last, for the forms that mint one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SessionLimits {
    /// The longest session Settings allow.
    pub max_ttl_secs: u64,
    /// What a session lasts when the request names no lifetime.
    pub default_ttl_secs: u64,
}

/// A placeholder the agent can send, without its value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredPlaceholder {
    pub placeholder: String,
    /// The secret field it stands for: a name, never the value.
    #[serde(default)]
    pub field: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
    pub locations: Vec<SubstitutionLocation>,
}

/// One service a session can reach: where, how, and which placeholders it
/// accepts. Never carries a secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredService {
    pub rule_id: RuleId,
    pub rule: String,
    pub credential: String,
    pub template_id: String,
    pub service: String,
    pub hosts: Vec<String>,
    pub paths: Vec<String>,
    pub methods: Vec<String>,
    /// Disabled rules stay in the session but get no credential.
    pub enabled: bool,
    pub placeholders: Vec<DiscoveredPlaceholder>,
    /// `mcp` for an MCP server, which clients reach through the gateway.
    #[serde(default)]
    pub kind: ServiceKind,
    /// Where an MCP server answers on its host, e.g. `/mcp`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_path: Option<String>,
}

/// What an agent may learn about its own session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionDiscovery {
    pub session: ProxySession,
    pub services: Vec<DiscoveredService>,
}

pub struct SessionService {
    policy: Arc<dyn PolicyStore>,
    credentials: Arc<dyn CredentialStore>,
    nodes: Arc<dyn NodeStore>,
    keys: Arc<KeyRing>,
    guard: Guard,
    notifier: Arc<PolicyNotifier>,
}

impl SessionService {
    pub fn new(
        policy: Arc<dyn PolicyStore>,
        credentials: Arc<dyn CredentialStore>,
        nodes: Arc<dyn NodeStore>,
        keys: Arc<KeyRing>,
        guard: Guard,
        notifier: Arc<PolicyNotifier>,
    ) -> Self {
        Self {
            policy,
            credentials,
            nodes,
            keys,
            guard,
            notifier,
        }
    }

    /// A session minted for a node puts its credentials on that node: a
    /// scoped node is sent the rules of the sessions minted for it. Only
    /// whoever may manage nodes chooses where credentials go, so being
    /// able to mint in a vault isn't enough. The node must exist and not
    /// be revoked.
    async fn check_node_target(
        &self,
        caller: &Caller,
        node_id: &NodeId,
    ) -> Result<(), ControlError> {
        self.guard.check(caller, Action::NodeManage, None).await?;
        let node = self
            .nodes
            .get_node(node_id)
            .await?
            .ok_or_else(|| ControlError::not_found("node", node_id))?;
        if node.revoked_at.is_some() {
            return Err(ControlError::validation(format!(
                "node {node_id} ('{}') is revoked; sessions can't be minted for it",
                node.name
            )));
        }
        Ok(())
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
        if let Some(node_id) = &req.node_id {
            self.check_node_target(caller, node_id).await?;
        }
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
        let max_ttl = self.policy.get_settings().await?.max_session_ttl_secs;
        let now = Utc::now();
        let ttl = if req.longest {
            max_ttl
        } else {
            req.ttl_secs
                .unwrap_or(DEFAULT_SESSION_TTL_SECS.min(max_ttl))
        };
        let ttl = match req.not_after {
            Some(not_after) => capped_ttl(ttl, not_after, now)?,
            None => ttl,
        };
        let claims = SessionClaims::new(
            Scope::for_vault(&vault.id),
            rule_ids.clone(),
            ttl,
            req.request_limit,
            req.labels.clone(),
            now,
            max_ttl,
        )?;
        let claims = claims.with_rule_deadlines(&req.rule_not_after, now)?;
        let claims = if req.strict { claims.strict() } else { claims };
        let claims = match req.node_id {
            Some(node) => claims.for_node(node),
            None => claims,
        };
        let claims = match &req.binding {
            Some(binding) => claims.for_binding(&binding.id, binding.generation)?,
            None => claims,
        };
        let token = self.keys.session_signer.sign(&claims)?;
        let session = ProxySession {
            id: claims.jti,
            vault_id: *vault_id,
            rule_ids,
            bundle,
            labels: req.labels,
            request_limit: req.request_limit,
            node_id: claims.aud,
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
        if let Some(node) = claims.aud {
            event = event.detail("node_id", node.to_string());
        }
        if let Some(sub) = &claims.sub {
            event = event.detail("binding", sub.clone());
        }
        if let Some(not_after) = req.not_after {
            event = event.detail("not_after", not_after.to_rfc3339());
        }
        if claims.strict {
            event = event.detail("strict", "true");
        }
        for (rule_id, deadline) in &claims.rule_exp {
            event = event.detail(&format!("rule_not_after.{rule_id}"), deadline.to_rfc3339());
        }
        self.policy
            .insert_session(session.clone(), &[event])
            .await?;
        // A limited session is announced to every node; one minted for a
        // node may need rules a scoped node does not hold yet.
        if session.request_limit.is_some() || session.node_id.is_some() {
            self.notifier.bump_sessions();
        }
        Ok(MintedSession { token, session })
    }

    /// The lifetimes a caller allowed to mint in the vault may choose from.
    /// Settings themselves stay admin-only.
    pub async fn limits(
        &self,
        caller: &Caller,
        vault_id: &VaultId,
    ) -> Result<SessionLimits, ControlError> {
        self.guard
            .check(caller, Action::SessionMint, Some(vault_id))
            .await?;
        let max_ttl_secs = self.policy.get_settings().await?.max_session_ttl_secs;
        Ok(SessionLimits {
            max_ttl_secs,
            default_ttl_secs: DEFAULT_SESSION_TTL_SECS.min(max_ttl_secs),
        })
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

    /// Replaces a session's labels. They describe the session record; the
    /// proxies' traffic records keep the labels it was minted with, which
    /// are signed into its token.
    pub async fn update_labels(
        &self,
        caller: &Caller,
        id: &SessionId,
        labels: BTreeMap<String, String>,
    ) -> Result<ProxySession, ControlError> {
        let session = self
            .policy
            .get_session(id)
            .await?
            .ok_or_else(|| ControlError::not_found("session", id))?;
        self.guard
            .check(caller, Action::SessionMint, Some(&session.vault_id))
            .await?;
        validate_labels(&labels)?;
        let mut event = AuditEvent::new(
            caller.actor(),
            "session.update_labels",
            AuditOutcome::Success,
        )
        .vault(session.vault_id)
        .target(format!("session:{id}"));
        for (k, v) in &labels {
            event = event.detail(&format!("label.{k}"), v.clone());
        }
        self.policy
            .update_session_labels(id, labels, &[event])
            .await?;
        self.policy
            .get_session(id)
            .await?
            .ok_or_else(|| ControlError::not_found("session", id))
    }

    /// One session record, for its page. Never the token: only its
    /// holder has that.
    pub async fn get(&self, caller: &Caller, id: &SessionId) -> Result<ProxySession, ControlError> {
        let session = self
            .policy
            .get_session(id)
            .await?
            .ok_or_else(|| ControlError::not_found("session", id))?;
        self.guard
            .check(caller, Action::SessionRead, Some(&session.vault_id))
            .await?;
        Ok(session)
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

    /// The services a live session can reach, for the agent holding its
    /// token. Hosts, paths, methods and placeholder names only: no secret,
    /// and nothing about rules outside the session.
    pub async fn discover_self(&self, token: &str) -> Result<SessionDiscovery, ControlError> {
        let verifying = self.keys.session_signer.verifying_key();
        let keys = std::collections::HashMap::from([(key_id(&verifying), verifying)]);
        let claims = verify_session(token.trim(), &keys, Utc::now()).map_err(|e| {
            ControlError::Unauthenticated {
                reason: format!("not a live proxy session token: {e}"),
            }
        })?;
        let id = claims.jti;
        let session = self
            .policy
            .get_session(&id)
            .await?
            .ok_or_else(|| ControlError::not_found("session", id))?;
        if session.revoked_at.is_some() {
            return Err(ControlError::Unauthenticated {
                reason: format!("proxy session {id} has been revoked"),
            });
        }
        let services = self.services_of(&session).await?;
        Ok(SessionDiscovery { session, services })
    }

    /// What the session reaches, for the people who manage it: the same
    /// list its own token gets from `discover_self`, revoked or not.
    pub async fn services(
        &self,
        caller: &Caller,
        id: &SessionId,
    ) -> Result<Vec<DiscoveredService>, ControlError> {
        let session = self.get(caller, id).await?;
        self.services_of(&session).await
    }

    /// The session's rules with their credentials and templates, in the
    /// session's rule order. Rules or credentials deleted since are left out.
    async fn services_of(
        &self,
        session: &ProxySession,
    ) -> Result<Vec<DiscoveredService>, ControlError> {
        // Bounded by the session's rule count (at most a bundle's 100).
        let mut services = Vec::with_capacity(session.rule_ids.len());
        for rule_id in &session.rule_ids {
            let Some(rule) = self.policy.get_rule(rule_id).await? else {
                continue;
            };
            let Some(credential) = self.credentials.get_credential(&rule.credential_id).await?
            else {
                continue;
            };
            let template = self
                .policy
                .get_template(&credential.template_id, credential.template_version)
                .await?
                .map(|t| t.template);
            let service = template
                .as_ref()
                .map(|t| t.name.clone())
                .unwrap_or_else(|| credential.template_id.clone());
            let kind = template.as_ref().map(|t| t.kind).unwrap_or_default();
            let mcp_path = (kind == ServiceKind::Mcp)
                .then(|| {
                    template
                        .as_ref()
                        .and_then(|t| t.mcp_path.clone())
                        .or_else(|| builtin_mcp_path(&credential.template_id).map(str::to_string))
                })
                .flatten();
            services.push(DiscoveredService {
                rule_id: rule.id,
                rule: rule.name,
                credential: credential.name,
                template_id: credential.template_id,
                service,
                hosts: rule.allow.hosts.iter().map(ToString::to_string).collect(),
                paths: rule.allow.paths.iter().map(ToString::to_string).collect(),
                methods: rule.allow.methods.iter().map(ToString::to_string).collect(),
                enabled: rule.enabled,
                placeholders: credential
                    .substitutions
                    .into_iter()
                    .map(|s| DiscoveredPlaceholder {
                        placeholder: s.placeholder,
                        field: s.field,
                        env: s.env,
                        locations: s.locations,
                    })
                    .collect(),
                kind,
                mcp_path,
            });
        }
        Ok(services)
    }

    /// Ends the session the token belongs to. Holding a session's token is
    /// enough to end it, so a launcher can clean up after its agent with no
    /// more than what it handed the agent. An expired session is revoked
    /// too: traffic it opened may still be running (see
    /// [`open_traffic_horizon`](tokenless_core::session::open_traffic_horizon)).
    /// The signature is checked before expiry, so the caller still proves
    /// it holds the token.
    pub async fn revoke_self(&self, token: &str) -> Result<ProxySession, ControlError> {
        let verifying = self.keys.session_signer.verifying_key();
        let keys = std::collections::HashMap::from([(key_id(&verifying), verifying)]);
        let id = match verify_session(token.trim(), &keys, Utc::now()) {
            Ok(claims) => claims.jti,
            Err(SessionError::Expired { session_id, .. }) => session_id,
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

    /// Newest first; only the live ones (neither revoked nor expired)
    /// when `active`.
    pub async fn list(
        &self,
        caller: &Caller,
        vault_id: &VaultId,
        listing: SessionListing,
        page: PageRequest,
    ) -> Result<Page<ProxySession>, ControlError> {
        self.guard
            .check(caller, Action::SessionRead, Some(vault_id))
            .await?;
        Ok(self
            .policy
            .list_sessions(
                Some(vault_id),
                None,
                listing.active.then(Utc::now),
                listing.after.as_ref(),
                page,
            )
            .await?)
    }

    /// Sessions in every vault the caller can see: all of them for an
    /// unbound principal, the bound vault's otherwise.
    pub async fn list_all(
        &self,
        caller: &Caller,
        listing: SessionListing,
        page: PageRequest,
    ) -> Result<Page<ProxySession>, ControlError> {
        let vault = caller.principal.vault;
        self.guard
            .check(caller, Action::SessionRead, vault.as_ref())
            .await?;
        Ok(self
            .policy
            .list_sessions(
                vault.as_ref(),
                None,
                listing.active.then(Utc::now),
                listing.after.as_ref(),
                page,
            )
            .await?)
    }

    /// Sessions minted from one access bundle, newest first. Sessions of a
    /// bundle that was since deleted are only reachable by vault.
    pub async fn list_for_bundle(
        &self,
        caller: &Caller,
        bundle_id: &BundleId,
        listing: SessionListing,
        page: PageRequest,
    ) -> Result<Page<ProxySession>, ControlError> {
        let bundle = self
            .policy
            .get_bundle(bundle_id)
            .await?
            .ok_or_else(|| ControlError::not_found("access bundle", bundle_id))?;
        self.guard
            .check(caller, Action::SessionRead, Some(&bundle.vault_id))
            .await?;
        Ok(self
            .policy
            .list_sessions(
                Some(&bundle.vault_id),
                Some(bundle_id),
                listing.active.then(Utc::now),
                listing.after.as_ref(),
                page,
            )
            .await?)
    }
}

/// `ttl_secs` shortened so the session ends by `not_after`. Whole seconds,
/// rounded down: a session never outlives its deadline.
fn capped_ttl(
    ttl_secs: u64,
    not_after: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<u64, ControlError> {
    match u64::try_from((not_after - now).num_seconds()) {
        Ok(left) if left > 0 => Ok(ttl_secs.min(left)),
        _ => Err(ControlError::validation(format!(
            "not_after {} has passed (or is under a second away); a session cannot be minted past its deadline",
            not_after.to_rfc3339()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, TimeDelta};
    use rand::rngs::OsRng;
    use tokenless_core::authz::{Principal, Role};
    use tokenless_core::seal::{encode_public_key, SealPublicKey, SealSecretKey};
    use tokenless_core::session::OPEN_TRAFFIC_GRACE_SECS;

    use super::*;
    use crate::memory::MemoryStore;
    use crate::service::testing::{services, vault_with_rule};

    /// A stored session of `vault` that expires at `expires_at`.
    async fn stored(
        store: &MemoryStore,
        vault: VaultId,
        expires_at: DateTime<Utc>,
    ) -> ProxySession {
        let session = ProxySession {
            id: SessionId::new(),
            vault_id: vault,
            rule_ids: vec![RuleId::new()],
            bundle: None,
            labels: BTreeMap::new(),
            request_limit: None,
            node_id: None,
            created_by: "test".into(),
            created_at: expires_at - TimeDelta::minutes(15),
            expires_at,
            revoked_at: None,
        };
        store.insert_session(session.clone(), &[]).await.unwrap();
        session
    }

    /// Traffic outlives its session by the grace period, so revoking a
    /// session that expired within it must still reach the data planes.
    #[tokio::test]
    async fn revoking_an_expired_session_reaches_snapshots_within_the_grace_period() {
        let (store, cs) = services().await;
        let host = Caller::service(Principal::service("host", Role::Admin, None));
        let vault = cs.policy.create_vault(&host, "v").await.unwrap();
        let grace = TimeDelta::seconds(OPEN_TRAFFIC_GRACE_SECS);
        let recent = stored(&store, vault.id, Utc::now() - TimeDelta::minutes(10)).await;
        let old = stored(&store, vault.id, Utc::now() - grace - TimeDelta::minutes(1)).await;
        for s in [&recent, &old] {
            let revoked = cs.sessions.revoke(&host, &s.id).await.unwrap();
            assert!(revoked.revoked_at.is_some());
        }

        let secret = SealSecretKey::random_from_rng(OsRng);
        let node = cs
            .nodes
            .register_embedded(
                &host,
                "n",
                &encode_public_key(&SealPublicKey::from(&secret)),
            )
            .await
            .unwrap();
        let body = cs
            .nodes
            .build_snapshot(&node.node)
            .await
            .unwrap()
            .verify(&node.snapshot_verify_key)
            .unwrap();
        assert_eq!(body.revoked_sessions, vec![recent.id]);
    }

    fn until(rule: RuleId, not_after: DateTime<Utc>) -> MintSession {
        MintSession {
            rule_ids: vec![rule],
            bundle: None,
            ttl_secs: Some(900),
            longest: false,
            request_limit: None,
            labels: BTreeMap::new(),
            node_id: None,
            binding: None,
            not_after: Some(not_after),
            rule_not_after: Default::default(),
            strict: false,
        }
    }

    /// A grant's deadline caps every session minted for it, renewals
    /// included, and none is minted once it has passed.
    #[tokio::test]
    async fn not_after_caps_a_session_and_a_late_renewal_is_refused() {
        let (_, cs) = services().await;
        let host = Caller::service(Principal::service("host", Role::Admin, None));
        let (vault, rule) = vault_with_rule(&cs, &host).await;
        let deadline = Utc::now() + TimeDelta::seconds(30);

        let minted = cs
            .sessions
            .mint(&host, &vault, until(rule, deadline))
            .await
            .unwrap();
        assert!(minted.session.expires_at <= deadline);
        assert!(minted.session.expires_at > deadline - TimeDelta::seconds(3));
        let keys = std::collections::HashMap::from([(
            key_id(&cs.keys.session_signer.verifying_key()),
            cs.keys.session_signer.verifying_key(),
        )]);
        // A data plane whose clock is behind still honours the deadline
        // once it reaches it; expiry is never extended for skew.
        let claims = verify_session(
            &minted.token,
            &keys,
            minted.session.created_at - TimeDelta::seconds(20),
        )
        .unwrap();
        assert_eq!(claims.exp, minted.session.expires_at);
        assert!(matches!(
            verify_session(&minted.token, &keys, deadline),
            Err(SessionError::Expired { .. })
        ));

        // Without not_after the same request gets its full lifetime.
        let mut uncapped = until(rule, deadline);
        uncapped.not_after = None;
        let full = cs.sessions.mint(&host, &vault, uncapped).await.unwrap();
        assert!(full.session.expires_at > deadline + TimeDelta::minutes(10));

        for past in [Utc::now(), Utc::now() - TimeDelta::hours(1)] {
            let err = cs
                .sessions
                .mint(&host, &vault, until(rule, past))
                .await
                .unwrap_err();
            assert!(matches!(err, ControlError::Validation { .. }), "{err}");
            assert!(err.to_string().contains("has passed"), "{err}");
        }
    }

    /// A strict session with an earlier deadline for one rule carries both
    /// in its signed claims and its mint record. A deadline already passed,
    /// as a late renewal would pass it, or for a rule the session does not
    /// grant, refuses the mint, so it cannot bring a grant back.
    #[tokio::test]
    async fn rule_deadlines_and_strict_are_signed_and_a_passed_one_is_refused() {
        let (_, cs) = services().await;
        let host = Caller::service(Principal::service("host", Role::Admin, None));
        let (vault, rule) = vault_with_rule(&cs, &host).await;
        let other = cs
            .policy
            .create_rule(
                &host,
                &vault,
                crate::service::policy::CreateRule {
                    name: "second".into(),
                    credential_id: cs
                        .policy
                        .get_rule(&host, &rule)
                        .await
                        .unwrap()
                        .credential_id,
                    hosts: None,
                    paths: None,
                    methods: None,
                    mcp_tools: None,
                    git: None,
                },
            )
            .await
            .unwrap()
            .id;
        let grant = Utc::now() + TimeDelta::minutes(5);
        let mint = |deadlines: BTreeMap<RuleId, DateTime<Utc>>| MintSession {
            rule_ids: vec![rule, other],
            ttl_secs: Some(3600),
            rule_not_after: deadlines,
            strict: true,
            ..MintSession::default()
        };
        let minted = cs
            .sessions
            .mint(&host, &vault, mint(BTreeMap::from([(rule, grant)])))
            .await
            .unwrap();
        let keys = std::collections::HashMap::from([(
            key_id(&cs.keys.session_signer.verifying_key()),
            cs.keys.session_signer.verifying_key(),
        )]);
        let claims = verify_session(&minted.token, &keys, Utc::now()).unwrap();
        assert!(claims.strict);
        assert_eq!(claims.rule_deadline(&rule), grant);
        assert_eq!(claims.rule_deadline(&other), claims.exp);

        let events = cs
            .audit
            .query(
                &host,
                Some(vault),
                Some("session.mint".into()),
                PageRequest::default(),
            )
            .await
            .unwrap();
        let detail = &events.items[0].detail;
        assert_eq!(detail.get("strict").map(String::as_str), Some("true"));
        assert_eq!(
            detail.get(&format!("rule_not_after.{rule}")),
            Some(&grant.to_rfc3339())
        );

        for (deadlines, says) in [
            (
                BTreeMap::from([(rule, Utc::now() - TimeDelta::seconds(1))]),
                "has already passed",
            ),
            (
                BTreeMap::from([(RuleId::new(), grant)]),
                "not one the session grants",
            ),
        ] {
            let err = cs
                .sessions
                .mint(&host, &vault, mint(deadlines))
                .await
                .unwrap_err();
            assert!(
                matches!(
                    err,
                    ControlError::Core(tokenless_core::CoreError::InvalidRuleDeadline { .. })
                ),
                "{err}"
            );
            assert!(err.to_string().contains(says), "{err}");
        }
    }

    /// `tokenless run` ends its session with the token when it exits, which
    /// may be after the session expired; that still revokes it.
    #[tokio::test]
    async fn an_expired_token_still_revokes_its_session() {
        let (store, cs) = services().await;
        let host = Caller::service(Principal::service("host", Role::Admin, None));
        let vault = cs.policy.create_vault(&host, "v").await.unwrap();
        let session = stored(&store, vault.id, Utc::now() - TimeDelta::minutes(5)).await;
        let mut claims = SessionClaims::new(
            Scope::for_vault(&vault.id),
            session.rule_ids.clone(),
            900,
            None,
            BTreeMap::new(),
            session.created_at,
            DEFAULT_SESSION_TTL_SECS,
        )
        .unwrap();
        claims.jti = session.id;
        let token = cs.keys.session_signer.sign(&claims).unwrap();

        let ended = cs.sessions.revoke_self(&token).await.unwrap();
        assert_eq!(ended.id, session.id);
        assert!(ended.revoked_at.is_some());
        let forged = cs.sessions.revoke_self("v4.public.forged").await;
        assert!(
            matches!(forged, Err(ControlError::Unauthenticated { .. })),
            "{forged:?}"
        );
    }
}
