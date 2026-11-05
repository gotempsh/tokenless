// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Vaults, templates, credentials (write-only), rules and settings.

use std::collections::BTreeMap;
use std::sync::Arc;

use broker_core::audit::{AuditEvent, AuditOutcome};
use broker_core::authz::{Action, Role};
use broker_core::host::HostPattern;
use broker_core::ids::{CredentialId, RuleId, VaultId};
use broker_core::injection::SecretFields;
use broker_core::path::{HttpMethod, PathPattern};
use broker_core::rule::RuleScope;
use broker_core::scope::Scope;
use broker_core::template::{builtin_templates, ServiceTemplate};
use chrono::Utc;
use serde::Deserialize;
use tracing::info;

use super::{AuditRecorder, Caller, Guard};
use crate::cipher::SecretCipher;
use crate::error::ControlError;
use crate::model::{
    CredentialMeta, Page, PageRequest, Rule, Settings, StoredTemplate, TemplateSource,
    TemplateStatus, Vault,
};
use crate::notify::PolicyNotifier;
use crate::store::{CredentialStore, PolicyStore};

#[derive(Debug, Clone, Deserialize)]
pub struct CreateCredential {
    pub name: String,
    pub template_id: String,
    #[serde(default)]
    pub template_version: Option<u32>,
    /// Admin-only: replaces the template's hosts (e.g. a self-hosted base URL).
    #[serde(default)]
    pub host_override: Vec<String>,
    pub fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateRule {
    pub name: String,
    pub credential_id: CredentialId,
    #[serde(default)]
    pub hosts: Option<Vec<String>>,
    #[serde(default)]
    pub paths: Option<Vec<String>>,
    #[serde(default)]
    pub methods: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct UpdateRule {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub hosts: Option<Vec<String>>,
    #[serde(default)]
    pub paths: Option<Vec<String>>,
    #[serde(default)]
    pub methods: Option<Vec<String>>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

fn validate_name(kind: &str, name: &str) -> Result<String, ControlError> {
    let name = name.trim();
    if name.is_empty() || name.len() > 100 || name.chars().any(char::is_control) {
        return Err(ControlError::validation(format!(
            "{kind} name must be 1-100 printable characters"
        )));
    }
    Ok(name.to_string())
}

fn parse_hosts(values: &[String]) -> Result<Vec<HostPattern>, ControlError> {
    values
        .iter()
        .map(|v| {
            if v.contains("://") {
                HostPattern::from_https_base_url(v)
            } else {
                HostPattern::parse(v)
            }
        })
        .collect::<Result<_, _>>()
        .map_err(ControlError::from)
}

fn parse_paths(values: &[String]) -> Result<Vec<PathPattern>, ControlError> {
    values
        .iter()
        .map(|v| PathPattern::parse(v))
        .collect::<Result<_, _>>()
        .map_err(ControlError::from)
}

fn parse_methods(values: &[String]) -> Result<Vec<HttpMethod>, ControlError> {
    values
        .iter()
        .map(|v| HttpMethod::parse(v))
        .collect::<Result<_, _>>()
        .map_err(ControlError::from)
}

fn credential_aad(id: &CredentialId, vault: &VaultId) -> Vec<u8> {
    format!("credential|{id}|{vault}").into_bytes()
}

pub(crate) fn credential_aad_for(meta: &CredentialMeta) -> Vec<u8> {
    credential_aad(&meta.id, &meta.vault_id)
}

fn hosts_string(hosts: &[HostPattern]) -> String {
    hosts
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

pub struct PolicyService {
    policy: Arc<dyn PolicyStore>,
    credentials: Arc<dyn CredentialStore>,
    cipher: Arc<dyn SecretCipher>,
    guard: Guard,
    audit: AuditRecorder,
    notifier: Arc<PolicyNotifier>,
}

impl PolicyService {
    pub fn new(
        policy: Arc<dyn PolicyStore>,
        credentials: Arc<dyn CredentialStore>,
        cipher: Arc<dyn SecretCipher>,
        guard: Guard,
        audit: AuditRecorder,
        notifier: Arc<PolicyNotifier>,
    ) -> Self {
        Self {
            policy,
            credentials,
            cipher,
            guard,
            audit,
            notifier,
        }
    }

    /// Inserts built-in templates that are not yet stored. Existing versions
    /// are left untouched so a stored version never changes under a rule.
    pub async fn seed_builtin_templates(&self) -> Result<(), ControlError> {
        for (template, yaml) in builtin_templates()? {
            if self
                .policy
                .get_template(&template.id, template.version)
                .await?
                .is_some()
            {
                continue;
            }
            info!(template = %template.id, version = template.version, "seeding built-in template");
            self.policy
                .insert_template(StoredTemplate {
                    template,
                    yaml: yaml.to_string(),
                    source: TemplateSource::Builtin,
                    status: TemplateStatus::Approved,
                    imported_by: None,
                    approved_by: Some("system".into()),
                    created_at: Utc::now(),
                })
                .await?;
        }
        Ok(())
    }

    // ---- vaults -------------------------------------------------------

    pub async fn create_vault(&self, caller: &Caller, name: &str) -> Result<Vault, ControlError> {
        self.guard.check(caller, Action::VaultCreate, None).await?;
        let name = validate_name("vault", name)?;
        let id = VaultId::new();
        let vault = Vault {
            id,
            name,
            scope: Scope::for_vault(&id),
            created_at: Utc::now(),
        };
        self.policy.insert_vault(vault.clone()).await?;
        self.audit
            .record(
                AuditEvent::new(caller.actor(), "vault.create", AuditOutcome::Success)
                    .vault(id)
                    .target(format!("vault:{id}"))
                    .detail("name", vault.name.clone()),
            )
            .await;
        Ok(vault)
    }

    pub async fn list_vaults(
        &self,
        caller: &Caller,
        page: PageRequest,
    ) -> Result<Page<Vault>, ControlError> {
        if let Some(bound) = caller.principal.vault {
            let vault = self.get_vault(caller, &bound).await?;
            return Ok(Page {
                items: vec![vault],
                total: 1,
                page: 1,
                page_size: page.page_size,
            });
        }
        self.guard.check(caller, Action::VaultRead, None).await?;
        Ok(self.policy.list_vaults(page).await?)
    }

    pub async fn get_vault(&self, caller: &Caller, id: &VaultId) -> Result<Vault, ControlError> {
        self.guard
            .check(caller, Action::VaultRead, Some(id))
            .await?;
        self.policy
            .get_vault(id)
            .await?
            .ok_or_else(|| ControlError::not_found("vault", id))
    }

    // ---- templates ----------------------------------------------------

    pub async fn list_templates(
        &self,
        caller: &Caller,
    ) -> Result<Vec<StoredTemplate>, ControlError> {
        self.guard.check(caller, Action::TemplateRead, None).await?;
        let admin = caller.principal.role == Role::Admin;
        Ok(self
            .policy
            .list_templates()
            .await?
            .into_iter()
            .filter(|t| admin || t.status == TemplateStatus::Approved)
            .collect())
    }

    pub async fn get_template(
        &self,
        caller: &Caller,
        id: &str,
        version: u32,
    ) -> Result<StoredTemplate, ControlError> {
        self.guard.check(caller, Action::TemplateRead, None).await?;
        let t = self
            .policy
            .get_template(id, version)
            .await?
            .ok_or_else(|| ControlError::not_found("template", format!("{id}@{version}")))?;
        if t.status != TemplateStatus::Approved && caller.principal.role != Role::Admin {
            return Err(ControlError::not_found(
                "template",
                format!("{id}@{version}"),
            ));
        }
        Ok(t)
    }

    /// Imports a YAML template. It stays unusable until an admin approves it.
    pub async fn import_template(
        &self,
        caller: &Caller,
        yaml: &str,
    ) -> Result<StoredTemplate, ControlError> {
        self.guard
            .check(caller, Action::TemplateImport, None)
            .await?;
        let template = ServiceTemplate::from_yaml(yaml)?;
        if builtin_templates()?
            .iter()
            .any(|(b, _)| b.id == template.id)
        {
            return Err(ControlError::Conflict {
                message: format!(
                    "template id '{}' is reserved by a built-in template; choose another id",
                    template.id
                ),
            });
        }
        let stored = StoredTemplate {
            template,
            yaml: yaml.to_string(),
            source: TemplateSource::Imported,
            status: TemplateStatus::PendingApproval,
            imported_by: Some(caller.actor().to_string()),
            approved_by: None,
            created_at: Utc::now(),
        };
        self.policy.insert_template(stored.clone()).await?;
        self.audit
            .record(
                AuditEvent::new(caller.actor(), "template.import", AuditOutcome::Success)
                    .target(format!(
                        "template:{}@{}",
                        stored.template.id, stored.template.version
                    ))
                    .detail("hosts", hosts_string(&stored.template.hosts))
                    .detail(
                        "host_override_allowed",
                        stored.template.host_override.allowed.to_string(),
                    ),
            )
            .await;
        Ok(stored)
    }

    pub async fn approve_template(
        &self,
        caller: &Caller,
        id: &str,
        version: u32,
    ) -> Result<StoredTemplate, ControlError> {
        self.guard
            .check(caller, Action::TemplateApprove, None)
            .await?;
        let existing = self
            .policy
            .get_template(id, version)
            .await?
            .ok_or_else(|| ControlError::not_found("template", format!("{id}@{version}")))?;
        if existing.status == TemplateStatus::Approved {
            return Ok(existing);
        }
        self.policy
            .approve_template(id, version, caller.actor())
            .await?;
        self.audit
            .record(
                AuditEvent::new(caller.actor(), "template.approve", AuditOutcome::Success)
                    .target(format!("template:{id}@{version}"))
                    .detail("hosts", hosts_string(&existing.template.hosts))
                    .detail(
                        "host_override_allowed",
                        existing.template.host_override.allowed.to_string(),
                    ),
            )
            .await;
        self.notifier.bump_content();
        self.get_template(caller, id, version).await
    }

    async fn approved_template(
        &self,
        id: &str,
        version: Option<u32>,
    ) -> Result<StoredTemplate, ControlError> {
        let candidates = self.policy.list_templates().await?;
        let found = match version {
            Some(v) => candidates
                .into_iter()
                .find(|t| t.template.id == id && t.template.version == v),
            None => candidates
                .into_iter()
                .filter(|t| t.template.id == id && t.status == TemplateStatus::Approved)
                .max_by_key(|t| t.template.version),
        };
        let t = found.ok_or_else(|| ControlError::not_found("template", id))?;
        if t.status != TemplateStatus::Approved {
            return Err(ControlError::validation(format!(
                "template {id}@{} is waiting for admin approval",
                t.template.version
            )));
        }
        Ok(t)
    }

    // ---- credentials --------------------------------------------------

    pub async fn create_credential(
        &self,
        caller: &Caller,
        vault_id: &VaultId,
        req: CreateCredential,
    ) -> Result<CredentialMeta, ControlError> {
        self.guard
            .check(caller, Action::CredentialWrite, Some(vault_id))
            .await?;
        let host_override = parse_hosts(&req.host_override)?;
        if !host_override.is_empty() {
            self.guard
                .check(caller, Action::CredentialWiden, Some(vault_id))
                .await?;
        }
        self.get_vault(caller, vault_id).await?;
        let name = validate_name("credential", &req.name)?;
        let stored = self
            .approved_template(&req.template_id, req.template_version)
            .await?;
        let template = &stored.template;
        template.max_scope(&host_override)?;
        let fields = SecretFields::new(req.fields);
        template.validate_fields(&fields)?;
        let id = CredentialId::new();
        let now = Utc::now();
        let meta = CredentialMeta {
            id,
            vault_id: *vault_id,
            name,
            template_id: template.id.clone(),
            template_version: template.version,
            host_override: host_override.clone(),
            field_names: fields.names(),
            created_by: caller.actor().to_string(),
            created_at: now,
            updated_at: now,
        };
        let plaintext = zeroize::Zeroizing::new(
            serde_json::to_vec(&fields)
                .map_err(|e| ControlError::crypto("credential.encode", e))?,
        );
        let ciphertext = self
            .cipher
            .encrypt(&plaintext, &credential_aad(&id, vault_id))?;
        self.credentials
            .insert_credential(meta.clone(), ciphertext)
            .await?;
        let mut event = AuditEvent::new(caller.actor(), "credential.create", AuditOutcome::Success)
            .vault(*vault_id)
            .target(format!("credential:{id}"))
            .detail("name", meta.name.clone())
            .detail("template", format!("{}@{}", template.id, template.version));
        if !host_override.is_empty() {
            event = event
                .detail("widened", "true")
                .detail("host_override", hosts_string(&host_override));
        }
        self.audit.record(event).await;
        Ok(meta)
    }

    /// Replaces a credential's secret. The old value is never returned.
    pub async fn rotate_credential(
        &self,
        caller: &Caller,
        id: &CredentialId,
        fields: BTreeMap<String, String>,
    ) -> Result<CredentialMeta, ControlError> {
        let meta = self.credential_meta(id).await?;
        self.guard
            .check(caller, Action::CredentialWrite, Some(&meta.vault_id))
            .await?;
        let stored = self
            .approved_template(&meta.template_id, Some(meta.template_version))
            .await?;
        let fields = SecretFields::new(fields);
        stored.template.validate_fields(&fields)?;
        let plaintext = zeroize::Zeroizing::new(
            serde_json::to_vec(&fields)
                .map_err(|e| ControlError::crypto("credential.encode", e))?,
        );
        let ciphertext = self
            .cipher
            .encrypt(&plaintext, &credential_aad_for(&meta))?;
        self.credentials
            .replace_secret(id, ciphertext, fields.names(), Utc::now())
            .await?;
        self.audit
            .record(
                AuditEvent::new(caller.actor(), "credential.rotate", AuditOutcome::Success)
                    .vault(meta.vault_id)
                    .target(format!("credential:{id}")),
            )
            .await;
        self.notifier.bump_content();
        self.credential_meta(id).await
    }

    pub async fn delete_credential(
        &self,
        caller: &Caller,
        id: &CredentialId,
    ) -> Result<(), ControlError> {
        let meta = self.credential_meta(id).await?;
        self.guard
            .check(caller, Action::CredentialDelete, Some(&meta.vault_id))
            .await?;
        let rules = self.policy.count_rules_for_credential(id).await?;
        if rules > 0 {
            return Err(ControlError::Conflict {
                message: format!(
                    "credential {id} is still used by {rules} rule(s); delete them first"
                ),
            });
        }
        self.credentials.delete_credential(id).await?;
        self.audit
            .record(
                AuditEvent::new(caller.actor(), "credential.delete", AuditOutcome::Success)
                    .vault(meta.vault_id)
                    .target(format!("credential:{id}")),
            )
            .await;
        self.notifier.bump_content();
        Ok(())
    }

    async fn credential_meta(&self, id: &CredentialId) -> Result<CredentialMeta, ControlError> {
        self.credentials
            .get_credential(id)
            .await?
            .ok_or_else(|| ControlError::not_found("credential", id))
    }

    pub async fn get_credential(
        &self,
        caller: &Caller,
        id: &CredentialId,
    ) -> Result<CredentialMeta, ControlError> {
        let meta = self.credential_meta(id).await?;
        self.guard
            .check(caller, Action::CredentialRead, Some(&meta.vault_id))
            .await?;
        Ok(meta)
    }

    pub async fn list_credentials(
        &self,
        caller: &Caller,
        vault_id: &VaultId,
        page: PageRequest,
    ) -> Result<Page<CredentialMeta>, ControlError> {
        self.guard
            .check(caller, Action::CredentialRead, Some(vault_id))
            .await?;
        Ok(self.credentials.list_credentials(vault_id, page).await?)
    }

    // ---- rules --------------------------------------------------------

    async fn max_scope_for(
        &self,
        meta: &CredentialMeta,
    ) -> Result<(ServiceTemplate, RuleScope), ControlError> {
        let stored = self
            .approved_template(&meta.template_id, Some(meta.template_version))
            .await?;
        let max = stored.template.max_scope(&meta.host_override)?;
        Ok((stored.template, max))
    }

    /// Creating a rule grants new access, so it needs step-up like widening.
    pub async fn create_rule(
        &self,
        caller: &Caller,
        vault_id: &VaultId,
        req: CreateRule,
    ) -> Result<Rule, ControlError> {
        self.guard
            .check(caller, Action::RuleWrite, Some(vault_id))
            .await?;
        self.guard.require_step_up(caller, Action::RuleWrite)?;
        let name = validate_name("rule", &req.name)?;
        let meta = self.credential_meta(&req.credential_id).await?;
        if &meta.vault_id != vault_id {
            return Err(ControlError::validation(format!(
                "credential {} belongs to another vault",
                req.credential_id
            )));
        }
        let (template, max) = self.max_scope_for(&meta).await?;
        let allow = RuleScope {
            hosts: match &req.hosts {
                Some(h) => parse_hosts(h)?,
                None => max.hosts.clone(),
            },
            paths: match &req.paths {
                Some(p) => parse_paths(p)?,
                None => max.paths.clone(),
            },
            methods: match &req.methods {
                Some(m) => parse_methods(m)?,
                None => max.methods.clone(),
            },
        };
        allow.validate(&template.id)?;
        allow.ensure_within(&max, &template.id)?;
        let now = Utc::now();
        let rule = Rule {
            id: RuleId::new(),
            vault_id: *vault_id,
            credential_id: meta.id,
            name,
            allow,
            enabled: true,
            created_by: caller.actor().to_string(),
            created_at: now,
            updated_at: now,
        };
        self.policy.insert_rule(rule.clone()).await?;
        self.audit
            .record(
                AuditEvent::new(caller.actor(), "rule.create", AuditOutcome::Success)
                    .vault(*vault_id)
                    .target(format!("rule:{}", rule.id))
                    .detail("credential", meta.id.to_string())
                    .detail("hosts", hosts_string(&rule.allow.hosts)),
            )
            .await;
        self.notifier.bump_content();
        Ok(rule)
    }

    /// Narrowing needs only `RuleWrite`; widening or re-enabling also needs step-up.
    pub async fn update_rule(
        &self,
        caller: &Caller,
        id: &RuleId,
        req: UpdateRule,
    ) -> Result<Rule, ControlError> {
        let mut rule = self
            .policy
            .get_rule(id)
            .await?
            .ok_or_else(|| ControlError::not_found("rule", id))?;
        self.guard
            .check(caller, Action::RuleWrite, Some(&rule.vault_id))
            .await?;
        let meta = self.credential_meta(&rule.credential_id).await?;
        let (template, max) = self.max_scope_for(&meta).await?;
        let previous = rule.clone();
        if let Some(name) = &req.name {
            rule.name = validate_name("rule", name)?;
        }
        if let Some(h) = &req.hosts {
            rule.allow.hosts = parse_hosts(h)?;
        }
        if let Some(p) = &req.paths {
            rule.allow.paths = parse_paths(p)?;
        }
        if let Some(m) = &req.methods {
            rule.allow.methods = parse_methods(m)?;
        }
        if let Some(enabled) = req.enabled {
            rule.enabled = enabled;
        }
        rule.allow.validate(&template.id)?;
        rule.allow.ensure_within(&max, &template.id)?;
        let widened = rule.allow.widens(&previous.allow) || (rule.enabled && !previous.enabled);
        if widened {
            self.guard.require_step_up(caller, Action::RuleWrite)?;
        }
        rule.updated_at = Utc::now();
        self.policy.update_rule(rule.clone()).await?;
        self.audit
            .record(
                AuditEvent::new(caller.actor(), "rule.update", AuditOutcome::Success)
                    .vault(rule.vault_id)
                    .target(format!("rule:{id}"))
                    .detail("widened", widened.to_string())
                    .detail("enabled", rule.enabled.to_string())
                    .detail("hosts", hosts_string(&rule.allow.hosts)),
            )
            .await;
        self.notifier.bump_content();
        Ok(rule)
    }

    pub async fn delete_rule(&self, caller: &Caller, id: &RuleId) -> Result<(), ControlError> {
        let rule = self
            .policy
            .get_rule(id)
            .await?
            .ok_or_else(|| ControlError::not_found("rule", id))?;
        self.guard
            .check(caller, Action::RuleDelete, Some(&rule.vault_id))
            .await?;
        self.policy.delete_rule(id).await?;
        self.audit
            .record(
                AuditEvent::new(caller.actor(), "rule.delete", AuditOutcome::Success)
                    .vault(rule.vault_id)
                    .target(format!("rule:{id}")),
            )
            .await;
        self.notifier.bump_content();
        Ok(())
    }

    pub async fn get_rule(&self, caller: &Caller, id: &RuleId) -> Result<Rule, ControlError> {
        let rule = self
            .policy
            .get_rule(id)
            .await?
            .ok_or_else(|| ControlError::not_found("rule", id))?;
        self.guard
            .check(caller, Action::RuleRead, Some(&rule.vault_id))
            .await?;
        Ok(rule)
    }

    pub async fn list_rules(
        &self,
        caller: &Caller,
        vault_id: &VaultId,
        page: PageRequest,
    ) -> Result<Page<Rule>, ControlError> {
        self.guard
            .check(caller, Action::RuleRead, Some(vault_id))
            .await?;
        Ok(self.policy.list_rules(vault_id, page).await?)
    }

    // ---- settings -----------------------------------------------------

    pub async fn get_settings(&self, caller: &Caller) -> Result<Settings, ControlError> {
        self.guard
            .check(caller, Action::SettingsWrite, None)
            .await?;
        Ok(self.policy.get_settings().await?)
    }

    pub async fn put_settings(
        &self,
        caller: &Caller,
        settings: Settings,
    ) -> Result<Settings, ControlError> {
        self.guard
            .check(caller, Action::SettingsWrite, None)
            .await?;
        self.policy.put_settings(settings.clone()).await?;
        self.audit
            .record(
                AuditEvent::new(caller.actor(), "settings.update", AuditOutcome::Success).detail(
                    "unmatched_host_policy",
                    format!("{:?}", settings.unmatched_host_policy).to_ascii_lowercase(),
                ),
            )
            .await;
        self.notifier.bump_content();
        Ok(settings)
    }
}
