// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! In-memory implementation of every store trait. It is the reference the
//! conformance suite is written against and is handy for tests; it is not
//! durable.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, MutexGuard};

use async_trait::async_trait;
use broker_core::audit::AuditEvent;
use broker_core::ids::{ApiKeyId, CredentialId, NodeId, RuleId, SessionId, UserId, VaultId};
use chrono::{DateTime, Utc};

use crate::error::StoreError;
use crate::model::{
    ApiKey, AuditQuery, CredentialMeta, JoinTokenRecord, Node, Page, PageRequest, ProxySession,
    Rule, Settings, StoredTemplate, UiSession, User, Vault,
};
use crate::store::{AuditSink, CredentialStore, IdentityStore, NodeStore, PolicyStore};

#[derive(Default)]
struct Inner {
    credentials: HashMap<CredentialId, (CredentialMeta, Vec<u8>)>,
    vaults: HashMap<VaultId, Vault>,
    templates: BTreeMap<(String, u32), StoredTemplate>,
    rules: HashMap<RuleId, Rule>,
    sessions: HashMap<SessionId, ProxySession>,
    settings: Option<Settings>,
    audit: Vec<AuditEvent>,
    users: HashMap<UserId, User>,
    ui_sessions: HashMap<String, UiSession>,
    setup_token: Option<String>,
    api_keys: HashMap<ApiKeyId, ApiKey>,
    join_tokens: HashMap<String, JoinTokenRecord>,
    nodes: HashMap<NodeId, Node>,
    key_material: HashMap<String, Vec<u8>>,
    snapshot_version: u64,
}

#[derive(Default)]
pub struct MemoryStore {
    inner: Mutex<Inner>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> Result<MutexGuard<'_, Inner>, StoreError> {
        self.inner
            .lock()
            .map_err(|_| StoreError::backend("memory.lock", "mutex poisoned"))
    }
}

fn newest_first<T: Clone>(mut items: Vec<T>, key: impl Fn(&T) -> DateTime<Utc>) -> Vec<T> {
    items.sort_by_key(|item| std::cmp::Reverse(key(item)));
    items
}

#[async_trait]
impl CredentialStore for MemoryStore {
    async fn insert_credential(&self, meta: CredentialMeta, ct: Vec<u8>) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        if inner.credentials.contains_key(&meta.id) {
            return Err(StoreError::Conflict {
                entity: "credential",
                detail: format!("id {} exists", meta.id),
            });
        }
        if inner
            .credentials
            .values()
            .any(|(m, _)| m.vault_id == meta.vault_id && m.name == meta.name)
        {
            return Err(StoreError::Conflict {
                entity: "credential",
                detail: format!("name '{}' exists in vault {}", meta.name, meta.vault_id),
            });
        }
        inner.credentials.insert(meta.id, (meta, ct));
        Ok(())
    }

    async fn get_credential(
        &self,
        id: &CredentialId,
    ) -> Result<Option<CredentialMeta>, StoreError> {
        Ok(self.lock()?.credentials.get(id).map(|(m, _)| m.clone()))
    }

    async fn list_credentials(
        &self,
        vault_id: &VaultId,
        page: PageRequest,
    ) -> Result<Page<CredentialMeta>, StoreError> {
        let items: Vec<_> = self
            .lock()?
            .credentials
            .values()
            .filter(|(m, _)| &m.vault_id == vault_id)
            .map(|(m, _)| m.clone())
            .collect();
        Ok(page.apply(&newest_first(items, |m| m.created_at)))
    }

    async fn replace_secret(
        &self,
        id: &CredentialId,
        ct: Vec<u8>,
        field_names: Vec<String>,
        updated_at: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        let (meta, stored) = inner
            .credentials
            .get_mut(id)
            .ok_or_else(|| StoreError::not_found("credential", id))?;
        meta.field_names = field_names;
        meta.updated_at = updated_at;
        *stored = ct;
        Ok(())
    }

    async fn delete_credential(&self, id: &CredentialId) -> Result<(), StoreError> {
        self.lock()?
            .credentials
            .remove(id)
            .map(|_| ())
            .ok_or_else(|| StoreError::not_found("credential", id))
    }

    async fn load_secret_ciphertext(
        &self,
        id: &CredentialId,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.lock()?.credentials.get(id).map(|(_, ct)| ct.clone()))
    }
}

#[async_trait]
impl PolicyStore for MemoryStore {
    async fn insert_vault(&self, vault: Vault) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        if inner.vaults.values().any(|v| v.name == vault.name) {
            return Err(StoreError::Conflict {
                entity: "vault",
                detail: format!("name '{}' exists", vault.name),
            });
        }
        inner.vaults.insert(vault.id, vault);
        Ok(())
    }

    async fn get_vault(&self, id: &VaultId) -> Result<Option<Vault>, StoreError> {
        Ok(self.lock()?.vaults.get(id).cloned())
    }

    async fn list_vaults(&self, page: PageRequest) -> Result<Page<Vault>, StoreError> {
        let items: Vec<_> = self.lock()?.vaults.values().cloned().collect();
        Ok(page.apply(&newest_first(items, |v| v.created_at)))
    }

    async fn insert_template(&self, template: StoredTemplate) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        let key = (template.template.id.clone(), template.template.version);
        if inner.templates.contains_key(&key) {
            return Err(StoreError::Conflict {
                entity: "template",
                detail: format!("{} version {} exists", key.0, key.1),
            });
        }
        inner.templates.insert(key, template);
        Ok(())
    }

    async fn get_template(
        &self,
        id: &str,
        version: u32,
    ) -> Result<Option<StoredTemplate>, StoreError> {
        Ok(self
            .lock()?
            .templates
            .get(&(id.to_string(), version))
            .cloned())
    }

    async fn list_templates(&self) -> Result<Vec<StoredTemplate>, StoreError> {
        Ok(self.lock()?.templates.values().cloned().collect())
    }

    async fn approve_template(&self, id: &str, version: u32, by: &str) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        let t = inner
            .templates
            .get_mut(&(id.to_string(), version))
            .ok_or_else(|| StoreError::not_found("template", format!("{id}@{version}")))?;
        t.status = crate::model::TemplateStatus::Approved;
        t.approved_by = Some(by.to_string());
        Ok(())
    }

    async fn insert_rule(&self, rule: Rule) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        if inner
            .rules
            .values()
            .any(|r| r.vault_id == rule.vault_id && r.name == rule.name)
        {
            return Err(StoreError::Conflict {
                entity: "rule",
                detail: format!("name '{}' exists in vault {}", rule.name, rule.vault_id),
            });
        }
        inner.rules.insert(rule.id, rule);
        Ok(())
    }

    async fn get_rule(&self, id: &RuleId) -> Result<Option<Rule>, StoreError> {
        Ok(self.lock()?.rules.get(id).cloned())
    }

    async fn list_rules(
        &self,
        vault_id: &VaultId,
        page: PageRequest,
    ) -> Result<Page<Rule>, StoreError> {
        let items: Vec<_> = self
            .lock()?
            .rules
            .values()
            .filter(|r| &r.vault_id == vault_id)
            .cloned()
            .collect();
        Ok(page.apply(&newest_first(items, |r| r.created_at)))
    }

    async fn list_enabled_rules(&self) -> Result<Vec<Rule>, StoreError> {
        let mut items: Vec<_> = self
            .lock()?
            .rules
            .values()
            .filter(|r| r.enabled)
            .cloned()
            .collect();
        items.sort_by_key(|r| r.id);
        Ok(items)
    }

    async fn count_rules_for_credential(&self, id: &CredentialId) -> Result<u64, StoreError> {
        Ok(self
            .lock()?
            .rules
            .values()
            .filter(|r| &r.credential_id == id)
            .count() as u64)
    }

    async fn update_rule(&self, rule: Rule) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        let slot = inner
            .rules
            .get_mut(&rule.id)
            .ok_or_else(|| StoreError::not_found("rule", rule.id))?;
        *slot = rule;
        Ok(())
    }

    async fn delete_rule(&self, id: &RuleId) -> Result<(), StoreError> {
        self.lock()?
            .rules
            .remove(id)
            .map(|_| ())
            .ok_or_else(|| StoreError::not_found("rule", id))
    }

    async fn insert_session(&self, session: ProxySession) -> Result<(), StoreError> {
        self.lock()?.sessions.insert(session.id, session);
        Ok(())
    }

    async fn get_session(&self, id: &SessionId) -> Result<Option<ProxySession>, StoreError> {
        Ok(self.lock()?.sessions.get(id).cloned())
    }

    async fn list_sessions(
        &self,
        vault_id: &VaultId,
        page: PageRequest,
    ) -> Result<Page<ProxySession>, StoreError> {
        let items: Vec<_> = self
            .lock()?
            .sessions
            .values()
            .filter(|s| &s.vault_id == vault_id)
            .cloned()
            .collect();
        Ok(page.apply(&newest_first(items, |s| s.created_at)))
    }

    async fn revoke_session(&self, id: &SessionId, at: DateTime<Utc>) -> Result<bool, StoreError> {
        let mut inner = self.lock()?;
        let s = inner
            .sessions
            .get_mut(id)
            .ok_or_else(|| StoreError::not_found("session", id))?;
        if s.revoked_at.is_some() {
            return Ok(false);
        }
        s.revoked_at = Some(at);
        Ok(true)
    }

    async fn list_revoked_unexpired(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Vec<SessionId>, StoreError> {
        let mut ids: Vec<_> = self
            .lock()?
            .sessions
            .values()
            .filter(|s| s.revoked_at.is_some() && s.expires_at > now)
            .map(|s| s.id)
            .collect();
        ids.sort();
        Ok(ids)
    }

    async fn list_limited_active(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Vec<(SessionId, u64)>, StoreError> {
        let mut out: Vec<_> = self
            .lock()?
            .sessions
            .values()
            .filter(|s| s.revoked_at.is_none() && s.expires_at > now)
            .filter_map(|s| s.request_limit.map(|l| (s.id, l)))
            .collect();
        out.sort();
        Ok(out)
    }

    async fn get_settings(&self) -> Result<Settings, StoreError> {
        Ok(self.lock()?.settings.clone().unwrap_or_default())
    }

    async fn put_settings(&self, settings: Settings) -> Result<(), StoreError> {
        self.lock()?.settings = Some(settings);
        Ok(())
    }
}

#[async_trait]
impl AuditSink for MemoryStore {
    async fn record(&self, events: &[AuditEvent]) -> Result<(), StoreError> {
        self.lock()?.audit.extend_from_slice(events);
        Ok(())
    }

    async fn query(&self, query: &AuditQuery) -> Result<Page<AuditEvent>, StoreError> {
        let items: Vec<_> = self
            .lock()?
            .audit
            .iter()
            .filter(|e| query.vault_id.is_none() || e.vault_id == query.vault_id)
            .filter(|e| {
                query
                    .action_prefix
                    .as_deref()
                    .is_none_or(|p| e.action.starts_with(p))
            })
            .cloned()
            .collect();
        Ok(query.page.apply(&newest_first(items, |e| e.at)))
    }
}

#[async_trait]
impl IdentityStore for MemoryStore {
    async fn count_users(&self) -> Result<u64, StoreError> {
        Ok(self.lock()?.users.len() as u64)
    }

    async fn insert_user(&self, user: User) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        if inner.users.values().any(|u| u.username == user.username) {
            return Err(StoreError::Conflict {
                entity: "user",
                detail: format!("username '{}' exists", user.username),
            });
        }
        inner.users.insert(user.id, user);
        Ok(())
    }

    async fn get_user(&self, id: &UserId) -> Result<Option<User>, StoreError> {
        Ok(self.lock()?.users.get(id).cloned())
    }

    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, StoreError> {
        Ok(self
            .lock()?
            .users
            .values()
            .find(|u| u.username == username)
            .cloned())
    }

    async fn advance_totp_step(&self, id: &UserId, step: u64) -> Result<bool, StoreError> {
        let mut inner = self.lock()?;
        let user = inner
            .users
            .get_mut(id)
            .ok_or_else(|| StoreError::not_found("user", id))?;
        if user.totp_last_step.is_some_and(|last| step <= last) {
            return Ok(false);
        }
        user.totp_last_step = Some(step);
        Ok(true)
    }

    async fn insert_ui_session(&self, session: UiSession) -> Result<(), StoreError> {
        self.lock()?
            .ui_sessions
            .insert(session.token_hash.clone(), session);
        Ok(())
    }

    async fn get_ui_session(&self, token_hash: &str) -> Result<Option<UiSession>, StoreError> {
        Ok(self.lock()?.ui_sessions.get(token_hash).cloned())
    }

    async fn set_ui_session_step_up(
        &self,
        token_hash: &str,
        at: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        let s = inner
            .ui_sessions
            .get_mut(token_hash)
            .ok_or_else(|| StoreError::not_found("ui_session", "<hash>"))?;
        s.step_up_at = Some(at);
        Ok(())
    }

    async fn delete_ui_session(&self, token_hash: &str) -> Result<(), StoreError> {
        self.lock()?.ui_sessions.remove(token_hash);
        Ok(())
    }

    async fn delete_expired_ui_sessions(&self, now: DateTime<Utc>) -> Result<u64, StoreError> {
        let mut inner = self.lock()?;
        let before = inner.ui_sessions.len();
        inner.ui_sessions.retain(|_, s| s.expires_at > now);
        Ok((before - inner.ui_sessions.len()) as u64)
    }

    async fn replace_setup_token(
        &self,
        token_hash: &str,
        _at: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        self.lock()?.setup_token = Some(token_hash.to_string());
        Ok(())
    }

    async fn consume_setup_token(&self, token_hash: &str) -> Result<bool, StoreError> {
        let mut inner = self.lock()?;
        match &inner.setup_token {
            Some(stored) if broker_auth::token::hashes_equal(stored, token_hash) => {
                inner.setup_token = None;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn insert_api_key(&self, key: ApiKey) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        if inner.api_keys.values().any(|k| k.prefix == key.prefix) {
            return Err(StoreError::Conflict {
                entity: "api_key",
                detail: format!("prefix '{}' exists", key.prefix),
            });
        }
        inner.api_keys.insert(key.id, key);
        Ok(())
    }

    async fn get_api_key_by_prefix(&self, prefix: &str) -> Result<Option<ApiKey>, StoreError> {
        Ok(self
            .lock()?
            .api_keys
            .values()
            .find(|k| k.prefix == prefix)
            .cloned())
    }

    async fn list_api_keys(&self, page: PageRequest) -> Result<Page<ApiKey>, StoreError> {
        let items: Vec<_> = self.lock()?.api_keys.values().cloned().collect();
        Ok(page.apply(&newest_first(items, |k| k.created_at)))
    }

    async fn revoke_api_key(&self, id: &ApiKeyId, at: DateTime<Utc>) -> Result<bool, StoreError> {
        let mut inner = self.lock()?;
        let k = inner
            .api_keys
            .get_mut(id)
            .ok_or_else(|| StoreError::not_found("api_key", id))?;
        if k.revoked_at.is_some() {
            return Ok(false);
        }
        k.revoked_at = Some(at);
        Ok(true)
    }

    async fn touch_api_key(&self, id: &ApiKeyId, at: DateTime<Utc>) -> Result<(), StoreError> {
        if let Some(k) = self.lock()?.api_keys.get_mut(id) {
            k.last_used_at = Some(at);
        }
        Ok(())
    }
}

#[async_trait]
impl NodeStore for MemoryStore {
    async fn insert_join_token(&self, token: JoinTokenRecord) -> Result<(), StoreError> {
        self.lock()?.join_tokens.insert(token.id.clone(), token);
        Ok(())
    }

    async fn consume_join_token(
        &self,
        id: &str,
        secret_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<bool, StoreError> {
        let mut inner = self.lock()?;
        let Some(token) = inner.join_tokens.get_mut(id) else {
            return Ok(false);
        };
        if token.consumed_at.is_some()
            || token.expires_at <= now
            || !broker_auth::token::hashes_equal(&token.secret_hash, secret_hash)
        {
            return Ok(false);
        }
        token.consumed_at = Some(now);
        Ok(true)
    }

    async fn insert_node(&self, node: Node) -> Result<(), StoreError> {
        self.lock()?.nodes.insert(node.id, node);
        Ok(())
    }

    async fn get_node(&self, id: &NodeId) -> Result<Option<Node>, StoreError> {
        Ok(self.lock()?.nodes.get(id).cloned())
    }

    async fn list_nodes(&self, page: PageRequest) -> Result<Page<Node>, StoreError> {
        let items: Vec<_> = self.lock()?.nodes.values().cloned().collect();
        Ok(page.apply(&newest_first(items, |n| n.enrolled_at)))
    }

    async fn update_node_cert(
        &self,
        id: &NodeId,
        serial: &str,
        not_after: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        let n = inner
            .nodes
            .get_mut(id)
            .ok_or_else(|| StoreError::not_found("node", id))?;
        n.cert_serial = serial.to_string();
        n.cert_not_after = not_after;
        Ok(())
    }

    async fn touch_node(&self, id: &NodeId, at: DateTime<Utc>) -> Result<(), StoreError> {
        if let Some(n) = self.lock()?.nodes.get_mut(id) {
            n.last_seen_at = Some(at);
        }
        Ok(())
    }

    async fn revoke_node(&self, id: &NodeId, at: DateTime<Utc>) -> Result<bool, StoreError> {
        let mut inner = self.lock()?;
        let n = inner
            .nodes
            .get_mut(id)
            .ok_or_else(|| StoreError::not_found("node", id))?;
        if n.revoked_at.is_some() {
            return Ok(false);
        }
        n.revoked_at = Some(at);
        Ok(true)
    }

    async fn get_key_material(&self, name: &str) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.lock()?.key_material.get(name).cloned())
    }

    async fn put_key_material_if_absent(
        &self,
        name: &str,
        value: Vec<u8>,
    ) -> Result<Vec<u8>, StoreError> {
        Ok(self
            .lock()?
            .key_material
            .entry(name.to_string())
            .or_insert(value)
            .clone())
    }

    async fn next_snapshot_version(&self) -> Result<u64, StoreError> {
        let mut inner = self.lock()?;
        inner.snapshot_version += 1;
        Ok(inner.snapshot_version)
    }
}
