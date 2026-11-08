// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Data plane nodes: join tokens, enrolment, certificate renewal, snapshot
//! building and audit ingestion.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use tokenless_auth::token;
use tokenless_core::audit::{AuditEvent, AuditOutcome};
use tokenless_core::authz::Action;
use tokenless_core::ids::{NodeId, RuleId, VaultId};
use tokenless_core::protocol::{
    AuditBatch, EnrollRequest, EnrollResponse, JoinToken, RenewRequest, RenewResponse,
    MAX_AUDIT_BATCH,
};
use tokenless_core::seal::{decode_public_key, seal};
use tokenless_core::session::open_traffic_horizon;
use tokenless_core::snapshot::{
    ca_aad, format_for, rule_aad, rules_readable_by, InterceptionCa, PublishedKey, SessionLimit,
    SignedSnapshot, SnapshotBody, SnapshotRule, MIN_SNAPSHOT_FORMAT, SNAPSHOT_FORMAT,
};
use tokio::sync::watch;
use tracing::{info, warn};
use zeroize::Zeroizing;

use super::render::render_credential;
use super::{AuditRecorder, Caller, ControlConfig, Guard};
use crate::cipher::SecretCipher;
use crate::error::ControlError;
use crate::keys::KeyRing;
use crate::model::{JoinTokenRecord, Node, Page, PageRequest, TemplateStatus};
use crate::notify::{Generation, PolicyNotifier};
use crate::pki::{self, pem_encode};
use crate::store::{AuditSink, CredentialStore, NodeStore, PolicyStore};

/// A registered embedded data plane: see [`NodeService::register_embedded`].
#[derive(Debug, Clone)]
pub struct EmbeddedNode {
    pub node: Node,
    pub snapshot_verify_key: ed25519_dalek::VerifyingKey,
}

#[derive(Clone, Serialize)]
pub struct JoinTokenIssued {
    /// Returned exactly once.
    pub token: String,
    pub token_id: String,
    pub expires_at: DateTime<Utc>,
}

tokenless_core::redacted_debug!(JoinTokenIssued { token_id, expires_at; token });

/// A node's snapshot, and how many rules it could not be sent because they
/// need a newer snapshot format than it reads.
#[derive(Debug, Clone)]
pub struct NodeSnapshot {
    pub snapshot: SignedSnapshot,
    pub withheld_rules: usize,
}

struct CachedContent {
    content_generation: u64,
    /// For a scoped node, the sessions generation its rules were chosen at.
    sessions_generation: Option<u64>,
    /// For a scoped node, when the first session its rules came from ends.
    valid_until: Option<DateTime<Utc>>,
    rules: Vec<SnapshotRule>,
    ca: InterceptionCa,
}

impl CachedContent {
    fn fresh(&self, generation: Generation, now: DateTime<Utc>) -> bool {
        self.content_generation == generation.content
            && self
                .sessions_generation
                .is_none_or(|g| g == generation.sessions)
            && self.valid_until.is_none_or(|at| now < at)
    }
}

pub struct NodeService {
    nodes: Arc<dyn NodeStore>,
    policy: Arc<dyn PolicyStore>,
    credentials: Arc<dyn CredentialStore>,
    audit_sink: Arc<dyn AuditSink>,
    cipher: Arc<dyn SecretCipher>,
    keys: Arc<KeyRing>,
    guard: Guard,
    audit: AuditRecorder,
    notifier: Arc<PolicyNotifier>,
    config: ControlConfig,
    cache: Mutex<HashMap<NodeId, Arc<CachedContent>>>,
}

fn vault_from_scope(scope: &str) -> Option<VaultId> {
    scope.strip_prefix("vault:").and_then(|id| id.parse().ok())
}

impl NodeService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        nodes: Arc<dyn NodeStore>,
        policy: Arc<dyn PolicyStore>,
        credentials: Arc<dyn CredentialStore>,
        audit_sink: Arc<dyn AuditSink>,
        cipher: Arc<dyn SecretCipher>,
        keys: Arc<KeyRing>,
        guard: Guard,
        audit: AuditRecorder,
        notifier: Arc<PolicyNotifier>,
        config: ControlConfig,
    ) -> Self {
        Self {
            nodes,
            policy,
            credentials,
            audit_sink,
            cipher,
            keys,
            guard,
            audit,
            notifier,
            config,
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn lease_secs(&self) -> u32 {
        self.config.lease_secs
    }

    pub fn subscribe(&self) -> watch::Receiver<Generation> {
        self.notifier.subscribe()
    }

    pub fn node_ca_pem(&self) -> String {
        self.keys.node_ca.cert_pem()
    }

    pub fn interception_ca_pem(&self) -> String {
        self.keys.interception_ca.cert_pem()
    }

    pub async fn create_join_token(
        &self,
        caller: &Caller,
        ttl_secs: Option<u64>,
    ) -> Result<JoinTokenIssued, ControlError> {
        self.guard.check(caller, Action::NodeManage, None).await?;
        let ttl = ttl_secs.unwrap_or(self.config.join_token_ttl_secs);
        if ttl == 0 || ttl > 7 * 24 * 3600 {
            return Err(ControlError::validation(
                "join token TTL must be between 1s and 7 days",
            ));
        }
        let token_id = uuid::Uuid::new_v4().simple().to_string();
        let secret = token::new_token("s");
        let now = Utc::now();
        let expires_at = now + Duration::seconds(i64::try_from(ttl).unwrap_or(3600));
        let event = AuditEvent::new(
            caller.actor(),
            "node.join_token.create",
            AuditOutcome::Success,
        )
        .target(format!("join_token:{token_id}"))
        .detail("expires_at", expires_at.to_rfc3339());
        self.nodes
            .insert_join_token(
                JoinTokenRecord {
                    id: token_id.clone(),
                    secret_hash: token::hash_token(&secret),
                    created_by: caller.actor().to_string(),
                    created_at: now,
                    expires_at,
                    consumed_at: None,
                },
                &[event],
            )
            .await?;
        let encoded = JoinToken {
            token_id: token_id.clone(),
            secret,
            ca_fingerprint: self.keys.node_ca.fingerprint(),
        }
        .encode();
        Ok(JoinTokenIssued {
            token: encoded,
            token_id,
            expires_at,
        })
    }

    pub async fn enroll(&self, req: EnrollRequest) -> Result<EnrollResponse, ControlError> {
        let join =
            JoinToken::parse(&req.join_token).map_err(|e| ControlError::Unauthenticated {
                reason: e.to_string(),
            })?;
        let name = req.node_name.trim();
        if name.is_empty() || name.len() > 100 || name.chars().any(char::is_control) {
            return Err(ControlError::validation(
                "node name must be 1-100 printable characters",
            ));
        }
        decode_public_key(&req.seal_public_key)?;
        let now = Utc::now();
        if !self
            .nodes
            .consume_join_token(&join.token_id, &token::hash_token(&join.secret), now)
            .await?
        {
            warn!(join_token = %join.token_id, "rejected enrolment with invalid join token");
            self.audit
                .record(
                    AuditEvent::new("anonymous", "node.enroll", AuditOutcome::Denied)
                        .target(format!("join_token:{}", join.token_id)),
                )
                .await;
            return Err(ControlError::Unauthenticated {
                reason: format!(
                    "join token {} is invalid, expired or already used",
                    join.token_id
                ),
            });
        }
        let node_id = NodeId::new();
        let signed = pki::sign_node_csr(
            &self.keys.node_ca,
            &req.csr_pem,
            &node_id,
            self.config.node_cert_ttl,
        )?;
        let event = AuditEvent::new(
            format!("node:{node_id}"),
            "node.enroll",
            AuditOutcome::Success,
        )
        .target(format!("node:{node_id}"))
        .detail("name", name.to_string())
        .detail("join_token", join.token_id.clone());
        self.nodes
            .insert_node(
                Node {
                    id: node_id,
                    name: name.to_string(),
                    seal_public_key: req.seal_public_key.clone(),
                    cert_serial: signed.serial.clone(),
                    cert_not_after: signed.not_after,
                    enrolled_at: now,
                    last_seen_at: None,
                    revoked_at: None,
                    scoped_rules: false,
                },
                &[event],
            )
            .await?;
        info!(node_id = %node_id, node_name = %name, "data plane node enrolled");
        Ok(EnrollResponse {
            node_id,
            client_cert_pem: signed.cert_pem,
            ca_cert_pem: self.node_ca_pem(),
            snapshot_verify_key: STANDARD.encode(self.keys.snapshot_key.verifying_key().as_bytes()),
            cert_not_after: signed.not_after,
        })
    }

    /// Registers a data plane embedded in the calling program, which hands
    /// it snapshots from [`NodeService::build_snapshot`] and its audit
    /// batches to [`NodeService::ingest_audit`] in-process. No join token
    /// and no client certificate: the node never calls the node API, so its
    /// record holds no certificate (`cert_serial` is empty and
    /// `cert_not_after` is the moment of registration). Returns the node and
    /// the key its snapshots are signed with.
    pub async fn register_embedded(
        &self,
        caller: &Caller,
        name: &str,
        seal_public_key: &str,
    ) -> Result<EmbeddedNode, ControlError> {
        self.guard.check(caller, Action::NodeManage, None).await?;
        let name = name.trim();
        if name.is_empty() || name.len() > 100 || name.chars().any(char::is_control) {
            return Err(ControlError::validation(
                "node name must be 1-100 printable characters",
            ));
        }
        decode_public_key(seal_public_key)?;
        let now = Utc::now();
        let node = Node {
            id: NodeId::new(),
            name: name.to_string(),
            seal_public_key: seal_public_key.to_string(),
            cert_serial: String::new(),
            cert_not_after: now,
            enrolled_at: now,
            last_seen_at: None,
            revoked_at: None,
            scoped_rules: true,
        };
        let event = AuditEvent::new(
            caller.actor(),
            "node.register_embedded",
            AuditOutcome::Success,
        )
        .target(format!("node:{}", node.id))
        .detail("name", node.name.clone());
        self.nodes.insert_node(node.clone(), &[event]).await?;
        info!(node_id = %node.id, node_name = %node.name, "embedded data plane registered");
        Ok(EmbeddedNode {
            node,
            snapshot_verify_key: self.keys.snapshot_key.verifying_key(),
        })
    }

    /// Resolves the node behind an mTLS client certificate.
    pub async fn authenticate(&self, node_id: &NodeId) -> Result<Node, ControlError> {
        let node =
            self.nodes
                .get_node(node_id)
                .await?
                .ok_or_else(|| ControlError::Unauthenticated {
                    reason: format!("node {node_id} is not enrolled"),
                })?;
        if node.revoked_at.is_some() {
            return Err(ControlError::Unauthenticated {
                reason: format!("node {node_id} has been revoked"),
            });
        }
        if let Err(e) = self.nodes.touch_node(node_id, Utc::now()).await {
            warn!(node_id = %node_id, error = %e, "failed to record node heartbeat");
        }
        Ok(node)
    }

    pub async fn renew(
        &self,
        node: &Node,
        req: RenewRequest,
    ) -> Result<RenewResponse, ControlError> {
        let signed = pki::sign_node_csr(
            &self.keys.node_ca,
            &req.csr_pem,
            &node.id,
            self.config.node_cert_ttl,
        )?;
        let event = AuditEvent::new(
            format!("node:{}", node.id),
            "node.renew",
            AuditOutcome::Success,
        )
        .target(format!("node:{}", node.id))
        .detail("cert_serial", signed.serial.clone())
        .detail("not_after", signed.not_after.to_rfc3339());
        self.nodes
            .update_node_cert(&node.id, &signed.serial, signed.not_after, &[event])
            .await?;
        info!(node_id = %node.id, not_after = %signed.not_after, "renewed node client certificate");
        Ok(RenewResponse {
            client_cert_pem: signed.cert_pem,
            cert_not_after: signed.not_after,
        })
    }

    async fn build_content(
        &self,
        node: &Node,
        generation: Generation,
    ) -> Result<CachedContent, ControlError> {
        // A scoped node holds only what its own live sessions use.
        let (hosted, valid_until) = if node.scoped_rules {
            let sessions = self
                .policy
                .list_live_sessions_for_node(&node.id, Utc::now())
                .await?;
            let rules: HashSet<RuleId> = sessions
                .iter()
                .flat_map(|s| s.rule_ids.iter().copied())
                .collect();
            (Some(rules), sessions.iter().map(|s| s.expires_at).min())
        } else {
            (None, None)
        };
        let recipient = decode_public_key(&node.seal_public_key)?;
        let ca_key = self.keys.interception_ca.key_pkcs8_der()?;
        let ca = InterceptionCa {
            cert_der: STANDARD.encode(&self.keys.interception_ca.cert_der),
            key: seal(&recipient, &ca_key, &ca_aad(&node.id))?,
        };
        let mut templates = HashMap::new();
        for t in self.policy.list_templates().await? {
            if t.status == TemplateStatus::Approved {
                templates.insert((t.template.id.clone(), t.template.version), t.template);
            }
        }
        let mut rules = Vec::new();
        for rule in self.policy.list_enabled_rules().await? {
            if hosted.as_ref().is_some_and(|ids| !ids.contains(&rule.id)) {
                continue;
            }
            let Some(meta) = self.credentials.get_credential(&rule.credential_id).await? else {
                warn!(rule_id = %rule.id, credential_id = %rule.credential_id, "rule references a missing credential; skipped");
                continue;
            };
            let Some(template) = templates.get(&(meta.template_id.clone(), meta.template_version))
            else {
                warn!(rule_id = %rule.id, template = %meta.template_id, "rule template is not approved; skipped");
                continue;
            };
            let max = template.max_scope(&meta.host_override)?;
            if let Err(e) = rule.allow.ensure_within(&max, &template.id) {
                warn!(rule_id = %rule.id, error = %e, "rule exceeds its template; skipped");
                continue;
            }
            let rendered = match render_credential(
                self.credentials.as_ref(),
                self.cipher.as_ref(),
                template,
                &meta,
            )
            .await
            {
                Ok(r) => r,
                Err(ControlError::NotFound { .. }) => continue,
                Err(ControlError::Core(e)) => {
                    // A deleted-then-missing variable or a value that cannot be
                    // sent as a header; the rest of the policy still ships.
                    warn!(rule_id = %rule.id, credential_id = %meta.id, error = %e, "credential headers could not be rendered; rule skipped");
                    continue;
                }
                Err(e) => return Err(e),
            };
            let headers = rendered.headers;
            let headers_json = Zeroizing::new(
                serde_json::to_vec(&headers)
                    .map_err(|e| ControlError::crypto("headers.encode", e))?,
            );
            rules.push(SnapshotRule {
                rule_id: rule.id,
                scope: tokenless_core::scope::Scope::for_vault(&rule.vault_id),
                credential_id: meta.id,
                allow: rule.allow.clone(),
                strip_headers: rendered.strip,
                headers: seal(
                    &recipient,
                    &headers_json,
                    &rule_aad(&node.id, &rule.id, &meta.id),
                )?,
                not_after: meta.not_after,
            });
        }
        Ok(CachedContent {
            content_generation: generation.content,
            sessions_generation: node.scoped_rules.then_some(generation.sessions),
            valid_until,
            rules,
            ca,
        })
    }

    async fn content_for(
        &self,
        node: &Node,
        generation: Generation,
    ) -> Result<Arc<CachedContent>, ControlError> {
        let now = Utc::now();
        let cached = self
            .cache
            .lock()
            .ok()
            .and_then(|c| c.get(&node.id).cloned())
            .filter(|c| c.fresh(generation, now));
        if let Some(c) = cached {
            return Ok(c);
        }
        let built = Arc::new(self.build_content(node, generation).await?);
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(node.id, built.clone());
        }
        Ok(built)
    }

    /// Builds and signs a fresh snapshot for `node`, which reads every
    /// format this build writes (an embedded data plane), with a new
    /// version.
    pub async fn build_snapshot(&self, node: &Node) -> Result<SignedSnapshot, ControlError> {
        Ok(self
            .build_snapshot_for(node, SNAPSHOT_FORMAT)
            .await?
            .snapshot)
    }

    /// Builds and signs a fresh snapshot for `node`, which reads formats up
    /// to `reads_format`, with a new version. Rules it could not enforce
    /// are left out and counted.
    pub async fn build_snapshot_for(
        &self,
        node: &Node,
        reads_format: u32,
    ) -> Result<NodeSnapshot, ControlError> {
        let generation = self.notifier.current();
        let content = self.content_for(node, generation).await?;
        let (rules, withheld_rules) = rules_readable_by(
            &content.rules,
            reads_format.clamp(MIN_SNAPSHOT_FORMAT, SNAPSHOT_FORMAT),
        );
        let now = Utc::now();
        let settings = self.policy.get_settings().await?;
        let body = SnapshotBody {
            format: format_for(&rules),
            version: self.nodes.next_snapshot_version().await?,
            node_id: node.id,
            issued_at: now,
            lease_secs: self.config.lease_secs,
            session_keys: vec![PublishedKey::from_key(
                &self.keys.session_signer.verifying_key(),
            )],
            revoked_sessions: self
                .policy
                .list_revoked_unexpired(open_traffic_horizon(now))
                .await?,
            limited_sessions: self
                .policy
                .list_limited_active(now)
                .await?
                .into_iter()
                .map(|(session_id, limit)| SessionLimit { session_id, limit })
                .collect(),
            unmatched_host_policy: settings.unmatched_host_policy,
            egress: settings.egress.clone(),
            passthrough_hosts: settings.passthrough_hosts.clone(),
            interception_ca: content.ca.clone(),
            rules,
        };
        Ok(NodeSnapshot {
            snapshot: SignedSnapshot::sign(&body, &self.keys.snapshot_key)?,
            withheld_rules,
        })
    }

    /// Records a batch from a node. The actor is always the authenticated
    /// node, and only `proxy.*` actions are accepted, so a node cannot forge
    /// control plane history.
    pub async fn ingest_audit(
        &self,
        node: &Node,
        batch: AuditBatch,
    ) -> Result<usize, ControlError> {
        if batch.events.len() > MAX_AUDIT_BATCH {
            return Err(ControlError::validation(format!(
                "audit batch has {} events; the maximum is {MAX_AUDIT_BATCH}",
                batch.events.len()
            )));
        }
        let mut events = Vec::with_capacity(batch.events.len());
        for mut event in batch.events {
            if !event.action.starts_with("proxy.") {
                return Err(ControlError::validation(format!(
                    "node {} may only report proxy.* actions, got '{}'",
                    node.id, event.action
                )));
            }
            event.actor = format!("node:{}", node.id);
            event.vault_id = event.detail.get("scope").and_then(|s| vault_from_scope(s));
            events.push(event);
        }
        self.audit_sink.record(&events).await?;
        Ok(events.len())
    }

    pub async fn list_nodes(
        &self,
        caller: &Caller,
        page: PageRequest,
    ) -> Result<Page<Node>, ControlError> {
        self.guard.check(caller, Action::NodeManage, None).await?;
        Ok(self.nodes.list_nodes(page).await?)
    }

    /// One proxy, for its detail page.
    pub async fn get_node(&self, caller: &Caller, id: &NodeId) -> Result<Node, ControlError> {
        self.guard.check(caller, Action::NodeManage, None).await?;
        self.nodes
            .get_node(id)
            .await?
            .ok_or_else(|| ControlError::not_found("proxy", id))
    }

    pub async fn revoke_node(&self, caller: &Caller, id: &NodeId) -> Result<(), ControlError> {
        self.guard.check(caller, Action::NodeManage, None).await?;
        let event = AuditEvent::new(caller.actor(), "node.revoke", AuditOutcome::Success)
            .target(format!("node:{id}"));
        self.nodes.revoke_node(id, Utc::now(), &[event]).await?;
        if let Ok(mut cache) = self.cache.lock() {
            cache.remove(id);
        }
        self.notifier.bump_sessions();
        Ok(())
    }

    /// PEM of the interception CA for agents to trust.
    pub fn interception_ca_cert_pem(&self) -> String {
        pem_encode("CERTIFICATE", &self.keys.interception_ca.cert_der)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::{TimeDelta, Utc};
    use rand::rngs::OsRng;
    use tokenless_core::authz::{Principal, Role};
    use tokenless_core::seal::{encode_public_key, SealPublicKey, SealSecretKey};
    use tokenless_core::snapshot::{SnapshotBody, MIN_SNAPSHOT_FORMAT};

    use tokenless_core::ids::{NodeId, RuleId, VaultId};

    use crate::model::Node;
    use crate::service::policy::{CreateCredential, CreateRule};
    use crate::service::sessions::MintSession;
    use crate::service::testing::{services, vault_with_rule};
    use crate::store::NodeStore;
    use crate::{Caller, ControlError, ControlServices};

    /// The snapshot of a new embedded node running one session for `rule`.
    async fn snapshot(
        cs: &ControlServices,
        host: &Caller,
        vault: VaultId,
        rule: RuleId,
    ) -> SnapshotBody {
        let secret = SealSecretKey::random_from_rng(OsRng);
        let node = cs
            .nodes
            .register_embedded(host, "n", &encode_public_key(&SealPublicKey::from(&secret)))
            .await
            .unwrap();
        cs.sessions
            .mint(host, &vault, mint(rule, Some(node.node.id), 600))
            .await
            .unwrap();
        cs.nodes
            .build_snapshot(&node.node)
            .await
            .unwrap()
            .verify(&node.snapshot_verify_key)
            .unwrap()
    }

    fn mint(rule: RuleId, node: Option<NodeId>, ttl_secs: u64) -> MintSession {
        MintSession {
            rule_ids: vec![rule],
            bundle: None,
            ttl_secs: Some(ttl_secs),
            longest: false,
            request_limit: None,
            labels: BTreeMap::new(),
            node_id: node,
            binding: None,
            not_after: None,
            rule_not_after: Default::default(),
            strict: false,
        }
    }

    /// A node that runs some workloads holds only the credentials their
    /// sessions use: not every rule, nor the rules of other nodes' or
    /// unbound sessions, and nothing once those sessions end.
    #[tokio::test]
    async fn a_scoped_node_holds_only_the_rules_of_its_own_live_sessions() {
        let (store, cs) = services().await;
        let host = Caller::service(Principal::service("host", Role::Admin, None));
        let (vault, rule_a) = vault_with_rule(&cs, &host).await;
        let credential_id = cs
            .policy
            .get_rule(&host, &rule_a)
            .await
            .unwrap()
            .credential_id;
        let rule_b = cs
            .policy
            .create_rule(
                &host,
                &vault,
                CreateRule {
                    name: "second".into(),
                    credential_id,
                    hosts: None,
                    paths: None,
                    methods: None,
                    mcp_tools: None,
                },
            )
            .await
            .unwrap()
            .id;
        let secret = SealSecretKey::random_from_rng(OsRng);
        let scoped = cs
            .nodes
            .register_embedded(
                &host,
                "n",
                &encode_public_key(&SealPublicKey::from(&secret)),
            )
            .await
            .unwrap();
        assert!(scoped.node.scoped_rules);
        let mut everything = scoped.node.clone();
        everything.id = NodeId::new();
        everything.scoped_rules = false;
        store.insert_node(everything.clone(), &[]).await.unwrap();
        let rules = |node: Node| {
            let cs = &cs;
            let key = scoped.snapshot_verify_key;
            async move {
                let body = cs
                    .nodes
                    .build_snapshot(&node)
                    .await
                    .unwrap()
                    .verify(&key)
                    .unwrap();
                let mut ids: Vec<_> = body.rules.iter().map(|r| r.rule_id).collect();
                ids.sort();
                ids
            }
        };
        let mut both = vec![rule_a, rule_b];
        both.sort();
        assert_eq!(rules(scoped.node.clone()).await, vec![]);
        assert_eq!(rules(everything.clone()).await, both);

        let mine = cs
            .sessions
            .mint(&host, &vault, mint(rule_a, Some(scoped.node.id), 600))
            .await
            .unwrap();
        cs.sessions
            .mint(&host, &vault, mint(rule_b, None, 600))
            .await
            .unwrap();
        // Minted for another node, so not this one's.
        cs.sessions
            .mint(&host, &vault, mint(rule_b, Some(everything.id), 600))
            .await
            .unwrap();
        assert_eq!(rules(scoped.node.clone()).await, vec![rule_a]);

        // A session that runs out takes its rules with it.
        cs.sessions
            .mint(&host, &vault, mint(rule_b, Some(scoped.node.id), 1))
            .await
            .unwrap();
        assert_eq!(rules(scoped.node.clone()).await, both);
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        assert_eq!(rules(scoped.node.clone()).await, vec![rule_a]);

        cs.sessions.revoke(&host, &mine.session.id).await.unwrap();
        assert_eq!(rules(scoped.node.clone()).await, vec![]);
        assert_eq!(rules(everything).await, both);
    }

    /// A secret that expires upstream ships with its deadline, in the
    /// format that carries it; replacing the secret replaces the deadline.
    /// A node too old to enforce a credential's deadline is not sent that
    /// rule, and keeps every other one, rather than refusing every
    /// snapshot.
    #[tokio::test]
    async fn an_older_node_is_not_sent_a_rule_it_cannot_enforce() {
        let (_, cs) = services().await;
        let host = Caller::service(Principal::service("host", Role::Admin, None));
        let (vault, expiring) = vault_with_rule(&cs, &host).await;
        let other = cs
            .policy
            .create_credential(
                &host,
                &vault,
                CreateCredential {
                    name: "other".into(),
                    template_id: "generic-bearer".into(),
                    template_version: None,
                    host_override: vec!["other.example.com".into()],
                    fields: [("token".to_string(), "o".to_string())].into(),
                    custom_headers: vec![],
                    substitutions: vec![],
                    not_after: None,
                },
            )
            .await
            .unwrap();
        let other = cs
            .policy
            .create_rule(
                &host,
                &vault,
                CreateRule {
                    name: "other".into(),
                    credential_id: other.id,
                    hosts: None,
                    paths: None,
                    methods: None,
                    mcp_tools: None,
                },
            )
            .await
            .unwrap()
            .id;
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
        for rule in [expiring, other] {
            cs.sessions
                .mint(&host, &vault, mint(rule, Some(node.node.id), 600))
                .await
                .unwrap();
        }
        let built = cs.nodes.build_snapshot_for(&node.node, 1).await.unwrap();
        let credential = built
            .snapshot
            .verify(&node.snapshot_verify_key)
            .unwrap()
            .rules
            .iter()
            .find(|r| r.rule_id == expiring)
            .unwrap()
            .credential_id;
        assert_eq!(built.withheld_rules, 0, "nothing needs format 2 yet");

        cs.policy
            .rotate_credential(
                &host,
                &credential,
                [("token".to_string(), "t2".to_string())].into(),
                Some(Utc::now() + TimeDelta::hours(1)),
            )
            .await
            .unwrap();
        let old = cs.nodes.build_snapshot_for(&node.node, 1).await.unwrap();
        assert_eq!(old.withheld_rules, 1);
        let body = old.snapshot.verify(&node.snapshot_verify_key).unwrap();
        assert_eq!(body.format, MIN_SNAPSHOT_FORMAT);
        assert_eq!(
            body.rules.iter().map(|r| r.rule_id).collect::<Vec<_>>(),
            vec![other]
        );

        let current = cs
            .nodes
            .build_snapshot_for(&node.node, tokenless_core::snapshot::SNAPSHOT_FORMAT)
            .await
            .unwrap();
        assert_eq!(current.withheld_rules, 0);
        let body = current.snapshot.verify(&node.snapshot_verify_key).unwrap();
        assert_eq!((body.format, body.rules.len()), (2, 2));
    }

    #[tokio::test]
    async fn a_credentials_deadline_reaches_snapshots_and_follows_its_secret() {
        let (_, cs) = services().await;
        let host = Caller::service(Principal::service("host", Role::Admin, None));
        let (vault, rule) = vault_with_rule(&cs, &host).await;
        let body = snapshot(&cs, &host, vault, rule).await;
        assert_eq!(body.format, MIN_SNAPSHOT_FORMAT);
        assert_eq!(body.rules[0].not_after, None);

        let credential = body.rules[0].credential_id;
        let deadline = Utc::now() + TimeDelta::hours(1);
        let fields = BTreeMap::from([("token".to_string(), "t2".to_string())]);
        let rotated = cs
            .policy
            .rotate_credential(&host, &credential, fields.clone(), Some(deadline))
            .await
            .unwrap();
        assert_eq!(rotated.not_after, Some(deadline));
        let body = snapshot(&cs, &host, vault, rule).await;
        assert_eq!(body.format, 2);
        assert_eq!(body.rules[0].not_after, Some(deadline));

        // A secret with no deadline clears the old one.
        cs.policy
            .rotate_credential(&host, &credential, fields.clone(), None)
            .await
            .unwrap();
        let body = snapshot(&cs, &host, vault, rule).await;
        assert_eq!(
            (body.format, body.rules[0].not_after),
            (MIN_SNAPSHOT_FORMAT, None)
        );

        let past = Utc::now() - TimeDelta::seconds(1);
        let err = cs
            .policy
            .rotate_credential(&host, &credential, fields, Some(past))
            .await
            .unwrap_err();
        assert!(matches!(err, ControlError::Validation { .. }), "{err}");
        let err = cs
            .policy
            .create_credential(
                &host,
                &vault,
                CreateCredential {
                    name: "late".into(),
                    template_id: "generic-bearer".into(),
                    template_version: None,
                    host_override: vec!["api.example.com".into()],
                    fields: [("token".to_string(), "t".to_string())].into(),
                    custom_headers: vec![],
                    substitutions: vec![],
                    not_after: Some(past),
                },
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("has already passed"), "{err}");
    }
}
