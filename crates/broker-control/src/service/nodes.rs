// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Data plane nodes: join tokens, enrolment, certificate renewal, snapshot
//! building and audit ingestion.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use broker_auth::token;
use broker_core::audit::{AuditEvent, AuditOutcome};
use broker_core::authz::Action;
use broker_core::ids::{NodeId, VaultId};
use broker_core::protocol::{
    AuditBatch, EnrollRequest, EnrollResponse, JoinToken, RenewRequest, RenewResponse,
    MAX_AUDIT_BATCH,
};
use broker_core::seal::{decode_public_key, seal};
use broker_core::snapshot::{
    ca_aad, rule_aad, InterceptionCa, PublishedKey, SessionLimit, SignedSnapshot, SnapshotBody,
    SnapshotRule, SNAPSHOT_FORMAT,
};
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
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

#[derive(Debug, Clone, Serialize)]
pub struct JoinTokenIssued {
    /// Returned exactly once.
    pub token: String,
    pub token_id: String,
    pub expires_at: DateTime<Utc>,
}

struct CachedContent {
    content_generation: u64,
    rules: Vec<SnapshotRule>,
    ca: InterceptionCa,
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
        generation: u64,
    ) -> Result<CachedContent, ControlError> {
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
                scope: broker_core::scope::Scope::for_vault(&rule.vault_id),
                credential_id: meta.id,
                allow: rule.allow.clone(),
                strip_headers: rendered.strip,
                headers: seal(
                    &recipient,
                    &headers_json,
                    &rule_aad(&node.id, &rule.id, &meta.id),
                )?,
            });
        }
        Ok(CachedContent {
            content_generation: generation,
            rules,
            ca,
        })
    }

    async fn content_for(
        &self,
        node: &Node,
        generation: u64,
    ) -> Result<Arc<CachedContent>, ControlError> {
        let cached = self
            .cache
            .lock()
            .ok()
            .and_then(|c| c.get(&node.id).cloned())
            .filter(|c| c.content_generation == generation);
        if let Some(c) = cached {
            return Ok(c);
        }
        let built = Arc::new(self.build_content(node, generation).await?);
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(node.id, built.clone());
        }
        Ok(built)
    }

    /// Builds and signs a fresh snapshot for `node` with a new version.
    pub async fn build_snapshot(&self, node: &Node) -> Result<SignedSnapshot, ControlError> {
        let generation = self.notifier.current();
        let content = self.content_for(node, generation.content).await?;
        let now = Utc::now();
        let settings = self.policy.get_settings().await?;
        let body = SnapshotBody {
            format: SNAPSHOT_FORMAT,
            version: self.nodes.next_snapshot_version().await?,
            node_id: node.id,
            issued_at: now,
            lease_secs: self.config.lease_secs,
            session_keys: vec![PublishedKey::from_key(
                &self.keys.session_signer.verifying_key(),
            )],
            revoked_sessions: self.policy.list_revoked_unexpired(now).await?,
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
            rules: content.rules.clone(),
        };
        Ok(SignedSnapshot::sign(&body, &self.keys.snapshot_key)?)
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
