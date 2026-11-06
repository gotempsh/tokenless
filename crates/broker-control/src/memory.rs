// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! In-memory implementation of every store trait. It is the reference the
//! conformance suite is written against and is handy for tests; it is not
//! durable.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, MutexGuard};

use async_trait::async_trait;
use broker_core::audit::AuditEvent;
use broker_core::authz::Role;
use broker_core::ids::{
    ApiKeyId, BundleId, CredentialId, InviteId, NodeId, RuleId, SessionId, UserId, VariableId,
    VaultId,
};
use broker_core::substitution::Substitution;
use broker_core::variables::CustomHeader;
use chrono::{DateTime, Utc};

use crate::error::StoreError;
use crate::model::{
    AccessBundle, ApiKey, AuditQuery, CredentialMeta, Invite, JoinTokenRecord, Node, Page,
    PageRequest, ProxySession, Rule, Settings, StoredTemplate, UiSession, User, Variable, Vault,
    VaultDeletion,
};
use crate::store::{AuditSink, CredentialStore, IdentityStore, NodeStore, PolicyStore};

#[derive(Default)]
struct Inner {
    credentials: HashMap<CredentialId, (CredentialMeta, Vec<u8>)>,
    variables: HashMap<VariableId, (Variable, Vec<u8>)>,
    vaults: HashMap<VaultId, Vault>,
    templates: BTreeMap<(String, u32), StoredTemplate>,
    rules: HashMap<RuleId, Rule>,
    bundles: HashMap<BundleId, AccessBundle>,
    sessions: HashMap<SessionId, ProxySession>,
    settings: Option<Settings>,
    audit: Vec<AuditEvent>,
    users: HashMap<UserId, User>,
    ui_sessions: HashMap<String, UiSession>,
    setup_token: Option<String>,
    api_keys: HashMap<ApiKeyId, ApiKey>,
    invites: HashMap<InviteId, Invite>,
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
    async fn insert_credential(
        &self,
        meta: CredentialMeta,
        ct: Vec<u8>,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
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
        inner.audit.extend_from_slice(audit);
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
        variable_refs: Vec<String>,
        updated_at: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        let (meta, stored) = inner
            .credentials
            .get_mut(id)
            .ok_or_else(|| StoreError::not_found("credential", id))?;
        meta.field_names = field_names;
        meta.variable_refs = variable_refs;
        meta.updated_at = updated_at;
        *stored = ct;
        inner.audit.extend_from_slice(audit);
        Ok(())
    }

    async fn update_custom_headers(
        &self,
        id: &CredentialId,
        custom_headers: Vec<CustomHeader>,
        variable_refs: Vec<String>,
        updated_at: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        let (meta, _) = inner
            .credentials
            .get_mut(id)
            .ok_or_else(|| StoreError::not_found("credential", id))?;
        meta.custom_headers = custom_headers;
        meta.variable_refs = variable_refs;
        meta.updated_at = updated_at;
        inner.audit.extend_from_slice(audit);
        Ok(())
    }

    async fn update_substitutions(
        &self,
        id: &CredentialId,
        substitutions: Vec<Substitution>,
        updated_at: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        let (meta, _) = inner
            .credentials
            .get_mut(id)
            .ok_or_else(|| StoreError::not_found("credential", id))?;
        meta.substitutions = substitutions;
        meta.updated_at = updated_at;
        inner.audit.extend_from_slice(audit);
        Ok(())
    }

    async fn list_credentials_with_variables(&self) -> Result<Vec<CredentialMeta>, StoreError> {
        let mut items: Vec<_> = self
            .lock()?
            .credentials
            .values()
            .filter(|(m, _)| !m.variable_refs.is_empty())
            .map(|(m, _)| m.clone())
            .collect();
        items.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(items)
    }

    async fn insert_variable(
        &self,
        variable: Variable,
        ct: Vec<u8>,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        if inner.variables.values().any(|(v, _)| v.key == variable.key) {
            return Err(StoreError::Conflict {
                entity: "variable",
                detail: format!("key '{}' exists", variable.key),
            });
        }
        inner.variables.insert(variable.id, (variable, ct));
        inner.audit.extend_from_slice(audit);
        Ok(())
    }

    async fn get_variable(&self, id: &VariableId) -> Result<Option<Variable>, StoreError> {
        Ok(self.lock()?.variables.get(id).map(|(v, _)| v.clone()))
    }

    async fn list_variables(&self, page: PageRequest) -> Result<Page<Variable>, StoreError> {
        let mut items: Vec<_> = self
            .lock()?
            .variables
            .values()
            .map(|(v, _)| v.clone())
            .collect();
        items.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(page.apply(&items))
    }

    async fn existing_variable_keys(&self, keys: &[String]) -> Result<Vec<String>, StoreError> {
        let inner = self.lock()?;
        Ok(keys
            .iter()
            .filter(|k| inner.variables.values().any(|(v, _)| &v.key == *k))
            .cloned()
            .collect())
    }

    async fn replace_variable_value(
        &self,
        id: &VariableId,
        ct: Vec<u8>,
        updated_by: &str,
        updated_at: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        let (variable, stored) = inner
            .variables
            .get_mut(id)
            .ok_or_else(|| StoreError::not_found("variable", id))?;
        variable.updated_by = updated_by.to_string();
        variable.updated_at = updated_at;
        *stored = ct;
        inner.audit.extend_from_slice(audit);
        Ok(())
    }

    async fn delete_variable(
        &self,
        id: &VariableId,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        let key = inner
            .variables
            .get(id)
            .map(|(v, _)| v.key.clone())
            .ok_or_else(|| StoreError::not_found("variable", id))?;
        let users = inner
            .credentials
            .values()
            .filter(|(m, _)| m.variable_refs.contains(&key))
            .count();
        if users > 0 {
            return Err(StoreError::Conflict {
                entity: "variable",
                detail: format!("variable '{key}' is referenced by {users} credential(s)"),
            });
        }
        inner.variables.remove(id);
        inner.audit.extend_from_slice(audit);
        Ok(())
    }

    async fn load_variable_ciphertexts(
        &self,
        keys: &[String],
    ) -> Result<Vec<(Variable, Vec<u8>)>, StoreError> {
        Ok(self
            .lock()?
            .variables
            .values()
            .filter(|(v, _)| keys.contains(&v.key))
            .cloned()
            .collect())
    }

    async fn delete_credential(
        &self,
        id: &CredentialId,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        inner
            .credentials
            .remove(id)
            .map(|_| ())
            .ok_or_else(|| StoreError::not_found("credential", id))?;
        inner.audit.extend_from_slice(audit);
        Ok(())
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
    async fn insert_vault(&self, vault: Vault, audit: &[AuditEvent]) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        if inner.vaults.values().any(|v| v.name == vault.name) {
            return Err(StoreError::Conflict {
                entity: "vault",
                detail: format!("name '{}' exists", vault.name),
            });
        }
        inner.vaults.insert(vault.id, vault);
        inner.audit.extend_from_slice(audit);
        Ok(())
    }

    async fn get_vault(&self, id: &VaultId) -> Result<Option<Vault>, StoreError> {
        Ok(self.lock()?.vaults.get(id).cloned())
    }

    async fn delete_vault(
        &self,
        id: &VaultId,
        at: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<VaultDeletion, StoreError> {
        let mut inner = self.lock()?;
        inner
            .vaults
            .remove(id)
            .ok_or_else(|| StoreError::not_found("vault", id))?;
        let count = |before: usize, after: usize| (before - after) as u64;
        let mut done = VaultDeletion::default();
        let before = inner.credentials.len();
        inner
            .credentials
            .retain(|_, (meta, _)| &meta.vault_id != id);
        done.credentials = count(before, inner.credentials.len());
        let before = inner.rules.len();
        inner.rules.retain(|_, rule| &rule.vault_id != id);
        done.rules = count(before, inner.rules.len());
        let before = inner.bundles.len();
        inner.bundles.retain(|_, bundle| &bundle.vault_id != id);
        done.bundles = count(before, inner.bundles.len());
        for session in inner.sessions.values_mut() {
            if &session.vault_id == id && session.revoked_at.is_none() && session.expires_at > at {
                session.revoked_at = Some(at);
                done.sessions_revoked += 1;
            }
        }
        for key in inner.api_keys.values_mut() {
            if &key.vault_id == id && key.revoked_at.is_none() {
                key.revoked_at = Some(at);
                done.api_keys_revoked += 1;
            }
        }
        inner.audit.extend_from_slice(audit);
        Ok(done)
    }

    async fn count_live_sessions(
        &self,
        vault_id: &VaultId,
        now: DateTime<Utc>,
    ) -> Result<u64, StoreError> {
        Ok(self
            .lock()?
            .sessions
            .values()
            .filter(|s| &s.vault_id == vault_id && s.revoked_at.is_none() && s.expires_at > now)
            .count() as u64)
    }

    async fn list_vaults(&self, page: PageRequest) -> Result<Page<Vault>, StoreError> {
        let items: Vec<_> = self.lock()?.vaults.values().cloned().collect();
        Ok(page.apply(&newest_first(items, |v| v.created_at)))
    }

    async fn insert_template(
        &self,
        template: StoredTemplate,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        let key = (template.template.id.clone(), template.template.version);
        if inner.templates.contains_key(&key) {
            return Err(StoreError::Conflict {
                entity: "template",
                detail: format!("{} version {} exists", key.0, key.1),
            });
        }
        inner.templates.insert(key, template);
        inner.audit.extend_from_slice(audit);
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

    async fn approve_template(
        &self,
        id: &str,
        version: u32,
        by: &str,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        let t = inner
            .templates
            .get_mut(&(id.to_string(), version))
            .ok_or_else(|| StoreError::not_found("template", format!("{id}@{version}")))?;
        t.status = crate::model::TemplateStatus::Approved;
        t.approved_by = Some(by.to_string());
        inner.audit.extend_from_slice(audit);
        Ok(())
    }

    async fn insert_rule(&self, rule: Rule, audit: &[AuditEvent]) -> Result<(), StoreError> {
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
        inner.audit.extend_from_slice(audit);
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

    async fn update_rule(&self, rule: Rule, audit: &[AuditEvent]) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        let slot = inner
            .rules
            .get_mut(&rule.id)
            .ok_or_else(|| StoreError::not_found("rule", rule.id))?;
        *slot = rule;
        inner.audit.extend_from_slice(audit);
        Ok(())
    }

    async fn delete_rule(&self, id: &RuleId, audit: &[AuditEvent]) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        inner
            .rules
            .remove(id)
            .map(|_| ())
            .ok_or_else(|| StoreError::not_found("rule", id))?;
        for bundle in inner.bundles.values_mut() {
            bundle.rule_ids.retain(|r| r != id);
        }
        inner.audit.extend_from_slice(audit);
        Ok(())
    }

    async fn insert_bundle(
        &self,
        bundle: AccessBundle,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        if inner
            .bundles
            .values()
            .any(|b| b.vault_id == bundle.vault_id && b.name == bundle.name)
        {
            return Err(StoreError::Conflict {
                entity: "access_bundle",
                detail: format!("name '{}' exists in vault {}", bundle.name, bundle.vault_id),
            });
        }
        inner.bundles.insert(bundle.id, bundle);
        inner.audit.extend_from_slice(audit);
        Ok(())
    }

    async fn get_bundle(&self, id: &BundleId) -> Result<Option<AccessBundle>, StoreError> {
        Ok(self.lock()?.bundles.get(id).cloned())
    }

    async fn get_bundle_by_name(
        &self,
        vault_id: &VaultId,
        name: &str,
    ) -> Result<Option<AccessBundle>, StoreError> {
        Ok(self
            .lock()?
            .bundles
            .values()
            .find(|b| &b.vault_id == vault_id && b.name == name)
            .cloned())
    }

    async fn list_bundles(
        &self,
        vault_id: Option<&VaultId>,
        page: PageRequest,
    ) -> Result<Page<AccessBundle>, StoreError> {
        let mut items: Vec<_> = self
            .lock()?
            .bundles
            .values()
            .filter(|b| vault_id.is_none_or(|v| &b.vault_id == v))
            .cloned()
            .collect();
        items.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then_with(|| a.vault_id.to_string().cmp(&b.vault_id.to_string()))
        });
        Ok(page.apply(&items))
    }

    async fn update_bundle(
        &self,
        bundle: AccessBundle,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        if inner
            .bundles
            .values()
            .any(|b| b.id != bundle.id && b.vault_id == bundle.vault_id && b.name == bundle.name)
        {
            return Err(StoreError::Conflict {
                entity: "access_bundle",
                detail: format!("name '{}' exists in vault {}", bundle.name, bundle.vault_id),
            });
        }
        let slot = inner
            .bundles
            .get_mut(&bundle.id)
            .ok_or_else(|| StoreError::not_found("access_bundle", bundle.id))?;
        *slot = bundle;
        inner.audit.extend_from_slice(audit);
        Ok(())
    }

    async fn delete_bundle(
        &self,
        id: &BundleId,
        at: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<u64, StoreError> {
        let mut inner = self.lock()?;
        inner
            .bundles
            .remove(id)
            .ok_or_else(|| StoreError::not_found("access_bundle", id))?;
        let mut revoked = 0;
        for session in inner.sessions.values_mut() {
            let live = session.revoked_at.is_none() && session.expires_at > at;
            if live && session.bundle.as_ref().is_some_and(|b| &b.id == id) {
                session.revoked_at = Some(at);
                revoked += 1;
            }
        }
        inner.audit.extend_from_slice(audit);
        Ok(revoked)
    }

    async fn insert_session(
        &self,
        session: ProxySession,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        inner.sessions.insert(session.id, session);
        inner.audit.extend_from_slice(audit);
        Ok(())
    }

    async fn get_session(&self, id: &SessionId) -> Result<Option<ProxySession>, StoreError> {
        Ok(self.lock()?.sessions.get(id).cloned())
    }

    async fn list_sessions(
        &self,
        vault_id: Option<&VaultId>,
        bundle_id: Option<&BundleId>,
        page: PageRequest,
    ) -> Result<Page<ProxySession>, StoreError> {
        let items: Vec<_> = self
            .lock()?
            .sessions
            .values()
            .filter(|s| vault_id.is_none_or(|v| &s.vault_id == v))
            .filter(|s| bundle_id.is_none_or(|b| s.bundle.as_ref().is_some_and(|sb| &sb.id == b)))
            .cloned()
            .collect();
        Ok(page.apply(&newest_first(items, |s| s.created_at)))
    }

    async fn revoke_session(
        &self,
        id: &SessionId,
        at: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<bool, StoreError> {
        let mut inner = self.lock()?;
        let s = inner
            .sessions
            .get_mut(id)
            .ok_or_else(|| StoreError::not_found("session", id))?;
        if s.revoked_at.is_some() {
            inner.audit.extend_from_slice(audit);
            return Ok(false);
        }
        s.revoked_at = Some(at);
        inner.audit.extend_from_slice(audit);
        Ok(true)
    }

    async fn update_session_labels(
        &self,
        id: &SessionId,
        labels: BTreeMap<String, String>,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        inner
            .sessions
            .get_mut(id)
            .ok_or_else(|| StoreError::not_found("session", id))?
            .labels = labels;
        inner.audit.extend_from_slice(audit);
        Ok(())
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

    async fn put_settings(
        &self,
        settings: Settings,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        inner.settings = Some(settings);
        inner.audit.extend_from_slice(audit);
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
            .filter(|e| {
                query.session_id.is_none_or(|id| {
                    e.detail.get("session_id").map(String::as_str) == Some(id.to_string().as_str())
                })
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

    async fn insert_user(&self, user: User, audit: &[AuditEvent]) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        if inner.users.values().any(|u| u.username == user.username) {
            return Err(StoreError::Conflict {
                entity: "user",
                detail: format!("username '{}' exists", user.username),
            });
        }
        inner.users.insert(user.id, user);
        inner.audit.extend_from_slice(audit);
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

    async fn list_users(&self, page: PageRequest) -> Result<Page<User>, StoreError> {
        let items: Vec<_> = self.lock()?.users.values().cloned().collect();
        Ok(page.apply(&newest_first(items, |u| u.created_at)))
    }

    async fn update_user_access(
        &self,
        id: &UserId,
        role: Role,
        disabled_at: Option<DateTime<Utc>>,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        if !inner.users.contains_key(id) {
            return Err(StoreError::not_found("user", id));
        }
        let admins_left = inner
            .users
            .values()
            .filter(|u| {
                let (r, d) = if u.id == *id {
                    (role, disabled_at)
                } else {
                    (u.role, u.disabled_at)
                };
                r == Role::Admin && d.is_none()
            })
            .count();
        if admins_left == 0 {
            return Err(StoreError::Conflict {
                entity: "user",
                detail: format!("changing user {id} would leave no enabled admin"),
            });
        }
        if let Some(user) = inner.users.get_mut(id) {
            user.role = role;
            user.disabled_at = disabled_at;
        }
        if disabled_at.is_some() {
            inner.ui_sessions.retain(|_, s| s.user_id != *id);
        }
        inner.audit.extend_from_slice(audit);
        Ok(())
    }

    async fn insert_invite(&self, invite: Invite, audit: &[AuditEvent]) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        if inner.invites.contains_key(&invite.id)
            || inner
                .invites
                .values()
                .any(|i| i.token_hash == invite.token_hash)
        {
            return Err(StoreError::Conflict {
                entity: "invite",
                detail: format!("invite {} exists", invite.id),
            });
        }
        inner.invites.insert(invite.id, invite);
        inner.audit.extend_from_slice(audit);
        Ok(())
    }

    async fn get_invite_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<Invite>, StoreError> {
        Ok(self
            .lock()?
            .invites
            .values()
            .find(|i| i.token_hash == token_hash)
            .cloned())
    }

    async fn list_invites(&self, page: PageRequest) -> Result<Page<Invite>, StoreError> {
        let items: Vec<_> = self.lock()?.invites.values().cloned().collect();
        Ok(page.apply(&newest_first(items, |i| i.created_at)))
    }

    async fn revoke_invite(
        &self,
        id: &InviteId,
        at: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<bool, StoreError> {
        let mut inner = self.lock()?;
        let invite = inner
            .invites
            .get_mut(id)
            .ok_or_else(|| StoreError::not_found("invite", id))?;
        let changed = invite.accepted_at.is_none() && invite.revoked_at.is_none();
        if changed {
            invite.revoked_at = Some(at);
        }
        inner.audit.extend_from_slice(audit);
        Ok(changed)
    }

    async fn accept_invite(
        &self,
        token_hash: &str,
        user: User,
        audit: &[AuditEvent],
    ) -> Result<bool, StoreError> {
        let mut inner = self.lock()?;
        let Some(invite_id) = inner
            .invites
            .values()
            .find(|i| {
                i.token_hash == token_hash && i.role == user.role && i.is_pending(user.created_at)
            })
            .map(|i| i.id)
        else {
            return Ok(false);
        };
        if inner.users.values().any(|u| u.username == user.username) {
            return Err(StoreError::Conflict {
                entity: "user",
                detail: format!("username '{}' exists", user.username),
            });
        }
        if let Some(invite) = inner.invites.get_mut(&invite_id) {
            invite.accepted_at = Some(user.created_at);
            invite.accepted_by = Some(user.id);
        }
        inner.users.insert(user.id, user);
        inner.audit.extend_from_slice(audit);
        Ok(true)
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

    async fn insert_ui_session(
        &self,
        session: UiSession,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        inner
            .ui_sessions
            .insert(session.token_hash.clone(), session);
        inner.audit.extend_from_slice(audit);
        Ok(())
    }

    async fn get_ui_session(&self, token_hash: &str) -> Result<Option<UiSession>, StoreError> {
        Ok(self.lock()?.ui_sessions.get(token_hash).cloned())
    }

    async fn set_ui_session_step_up(
        &self,
        token_hash: &str,
        at: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        let s = inner
            .ui_sessions
            .get_mut(token_hash)
            .ok_or_else(|| StoreError::not_found("ui_session", "<hash>"))?;
        s.step_up_at = Some(at);
        inner.audit.extend_from_slice(audit);
        Ok(())
    }

    async fn delete_ui_session(
        &self,
        token_hash: &str,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        inner.ui_sessions.remove(token_hash);
        inner.audit.extend_from_slice(audit);
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

    async fn insert_api_key(&self, key: ApiKey, audit: &[AuditEvent]) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        if inner.api_keys.values().any(|k| k.prefix == key.prefix) {
            return Err(StoreError::Conflict {
                entity: "api_key",
                detail: format!("prefix '{}' exists", key.prefix),
            });
        }
        inner.api_keys.insert(key.id, key);
        inner.audit.extend_from_slice(audit);
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

    async fn revoke_api_key(
        &self,
        id: &ApiKeyId,
        at: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<bool, StoreError> {
        let mut inner = self.lock()?;
        let k = inner
            .api_keys
            .get_mut(id)
            .ok_or_else(|| StoreError::not_found("api_key", id))?;
        if k.revoked_at.is_some() {
            inner.audit.extend_from_slice(audit);
            return Ok(false);
        }
        k.revoked_at = Some(at);
        inner.audit.extend_from_slice(audit);
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
    async fn insert_join_token(
        &self,
        token: JoinTokenRecord,
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        inner.join_tokens.insert(token.id.clone(), token);
        inner.audit.extend_from_slice(audit);
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

    async fn insert_node(&self, node: Node, audit: &[AuditEvent]) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        inner.nodes.insert(node.id, node);
        inner.audit.extend_from_slice(audit);
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
        audit: &[AuditEvent],
    ) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        let n = inner
            .nodes
            .get_mut(id)
            .ok_or_else(|| StoreError::not_found("node", id))?;
        n.cert_serial = serial.to_string();
        n.cert_not_after = not_after;
        inner.audit.extend_from_slice(audit);
        Ok(())
    }

    async fn touch_node(&self, id: &NodeId, at: DateTime<Utc>) -> Result<(), StoreError> {
        if let Some(n) = self.lock()?.nodes.get_mut(id) {
            n.last_seen_at = Some(at);
        }
        Ok(())
    }

    async fn revoke_node(
        &self,
        id: &NodeId,
        at: DateTime<Utc>,
        audit: &[AuditEvent],
    ) -> Result<bool, StoreError> {
        let mut inner = self.lock()?;
        let n = inner
            .nodes
            .get_mut(id)
            .ok_or_else(|| StoreError::not_found("node", id))?;
        if n.revoked_at.is_some() {
            inner.audit.extend_from_slice(audit);
            return Ok(false);
        }
        n.revoked_at = Some(at);
        inner.audit.extend_from_slice(audit);
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
