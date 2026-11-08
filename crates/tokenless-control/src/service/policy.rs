// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Vaults, templates, credentials (write-only), rules and settings.

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokenless_core::audit::{AuditEvent, AuditOutcome};
use tokenless_core::authz::{Action, Role};
use tokenless_core::git::GitScope;
use tokenless_core::host::HostPattern;
use tokenless_core::ids::{CredentialId, RuleId, VaultId};
use tokenless_core::injection::SecretFields;
use tokenless_core::path::{HttpMethod, PathPattern};
use tokenless_core::rule::{validate_mcp_tools, RuleScope};
use tokenless_core::scope::Scope;
use tokenless_core::snapshot::UnmatchedHostPolicy;
use tokenless_core::substitution::{validate_substitutions, Substitution};
use tokenless_core::template::{builtin_templates, ServiceTemplate};
use tokenless_core::variables::{validate_custom_headers, CustomHeader};
use tracing::{debug, info};

use super::render::render_credential;
use super::{AuditRecorder, Caller, Guard};
use crate::cipher::{KeyScope, SecretCipher};
use crate::error::{ControlError, StoreError};
use crate::model::{
    CredentialMeta, Page, PageRequest, Rule, Settings, StoredTemplate, TemplateSource,
    TemplateStatus, Vault, VaultDeletion,
};
use crate::notify::PolicyNotifier;
use crate::probe::{CredentialProber, ProbeRequest};
use crate::store::{CredentialStore, NewSecret, PolicyStore};

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
    /// Extra headers sent with every injected request; values may use
    /// `{{VARIABLE}}` references.
    #[serde(default)]
    pub custom_headers: Vec<CustomHeader>,
    /// Placeholders the proxy replaces with one of `fields`.
    #[serde(default)]
    pub substitutions: Vec<Substitution>,
    /// When the secret stops being valid upstream, if it does.
    #[serde(default)]
    pub not_after: Option<DateTime<Utc>>,
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
    /// MCP tools a `tools/call` may name; omit to allow every tool.
    #[serde(default)]
    pub mcp_tools: Option<Vec<String>>,
    /// Limits the rule to Git smart HTTP for these repositories; see
    /// [`tokenless_core::git`]. Omit for any request the rule's paths allow.
    #[serde(default)]
    pub git: Option<GitScope>,
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
    /// Replaces the MCP tool list. `{"mcp_tools": []}` allows none; send
    /// `"allow_all_tools": true` to drop the list.
    #[serde(default)]
    pub mcp_tools: Option<Vec<String>>,
    #[serde(default)]
    pub allow_all_tools: bool,
    /// Replaces the Git scope; send `"remove_git": true` to drop it.
    #[serde(default)]
    pub git: Option<GitScope>,
    #[serde(default)]
    pub remove_git: bool,
}

/// A Git scope as sent, normalised and checked.
fn normalise_git(git: GitScope) -> Result<GitScope, ControlError> {
    Ok(GitScope::new(git.repositories, git.push)?)
}

fn git_string(git: &Option<GitScope>) -> String {
    match git {
        None => "any".into(),
        Some(g) => format!(
            "{}{}",
            g.repositories.join(","),
            if g.push { " (push)" } else { "" }
        ),
    }
}

/// Always-reachable hosts are matched on every CONNECT, so keep the list short.
pub const MAX_PASSTHROUGH_HOSTS: usize = 100;

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

pub(crate) fn credential_aad(id: &CredentialId, vault: &VaultId) -> Vec<u8> {
    format!("credential|{id}|{vault}").into_bytes()
}

pub(crate) fn credential_aad_for(meta: &CredentialMeta) -> Vec<u8> {
    credential_aad(&meta.id, &meta.vault_id)
}

/// Header names only: values may be configuration an admin considers private.
fn header_names(headers: &[CustomHeader]) -> String {
    if headers.is_empty() {
        return "none".into();
    }
    headers
        .iter()
        .map(|h| h.name.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Placeholders only, for audit details.
fn placeholder_names(substitutions: &[Substitution]) -> String {
    if substitutions.is_empty() {
        return "none".into();
    }
    substitutions
        .iter()
        .map(|s| s.placeholder.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Substitutions may only name fields the credential actually has, so a
/// snapshot never has to render one from a missing value.
fn check_substitutions(
    substitutions: &[Substitution],
    field_names: &[String],
) -> Result<(), ControlError> {
    let names: Vec<&str> = field_names.iter().map(String::as_str).collect();
    validate_substitutions(substitutions, &names).map_err(ControlError::from)
}

fn tools_string(tools: &Option<Vec<String>>) -> String {
    match tools {
        None => "all".into(),
        Some(t) if t.is_empty() => "none".into(),
        Some(t) => t.join(","),
    }
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
    prober: Arc<dyn CredentialProber>,
}

/// Result of running a template's validation request. Only the status is
/// reported: the response body could echo the credential.
#[derive(Debug, Clone, Serialize)]
pub struct CredentialValidation {
    pub credential_id: CredentialId,
    pub ok: bool,
    pub host: String,
    pub method: String,
    pub path: String,
    pub status: Option<u16>,
    pub expected_status: Vec<u16>,
    pub detail: String,
}

impl PolicyService {
    pub fn new(
        policy: Arc<dyn PolicyStore>,
        credentials: Arc<dyn CredentialStore>,
        cipher: Arc<dyn SecretCipher>,
        guard: Guard,
        audit: AuditRecorder,
        notifier: Arc<PolicyNotifier>,
        prober: Arc<dyn CredentialProber>,
    ) -> Self {
        Self {
            policy,
            credentials,
            cipher,
            guard,
            audit,
            notifier,
            prober,
        }
    }

    /// Runs the template's declared validation request against one of the
    /// credential's own hosts, with its injected headers, under the
    /// instance egress policy. Sends the secret only where a rule could.
    pub async fn validate_credential(
        &self,
        caller: &Caller,
        id: &CredentialId,
    ) -> Result<CredentialValidation, ControlError> {
        let meta = self.credential_meta(id).await?;
        self.guard
            .check(caller, Action::CredentialWrite, Some(&meta.vault_id))
            .await?;
        let (template, max) = self.max_scope_for(&meta).await?;
        let validation = template.validation.clone().ok_or_else(|| {
            ControlError::validation(format!(
                "template '{}@{}' declares no validation request",
                template.id, template.version
            ))
        })?;
        let host = max
            .hosts
            .iter()
            .find(|h| !h.is_wildcard())
            .ok_or_else(|| {
                ControlError::validation(format!(
                    "credential {id} only has wildcard hosts; there is no concrete host to validate against"
                ))
            })?
            .clone();
        let method = validation.method.as_str().to_string();
        let path = validation.path.as_str().to_string();
        if validation.method.is_any() || path.ends_with('*') {
            return Err(ControlError::validation(format!(
                "template '{}' validation request must name one method and an exact path",
                template.id
            )));
        }
        if !max.allows(host.host(), host.port(), &method, &path) {
            return Err(ControlError::validation(format!(
                "template '{}' validation request {method} {path} is outside the template's own scope",
                template.id
            )));
        }
        let headers = render_credential(
            self.credentials.as_ref(),
            self.cipher.as_ref(),
            &template,
            &meta,
        )
        .await?
        .headers;
        let egress = self.policy.get_settings().await?.egress;
        let expected = validation.expect_status.clone();
        let result = self
            .prober
            .probe(
                ProbeRequest {
                    host: host.host().to_string(),
                    port: host.port(),
                    method: method.clone(),
                    path: path.clone(),
                    headers,
                },
                &egress,
            )
            .await;
        let (ok, status, detail) = match result {
            Ok(status) => {
                let ok = if expected.is_empty() {
                    (200..300).contains(&status)
                } else {
                    expected.contains(&status)
                };
                let detail = if ok {
                    format!("{host} answered {status}")
                } else {
                    format!("{host} answered {status}; the credential may be invalid or lack permissions")
                };
                (ok, Some(status), detail)
            }
            Err(e) => (false, None, e.to_string()),
        };
        self.audit
            .record(
                AuditEvent::new(
                    caller.actor(),
                    "credential.validate",
                    if ok {
                        AuditOutcome::Success
                    } else {
                        AuditOutcome::Failure
                    },
                )
                .vault(meta.vault_id)
                .target(format!("credential:{id}"))
                .detail("host", host.to_string())
                .detail("request", format!("{method} {path}"))
                .detail(
                    "status",
                    status
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "none".into()),
                )
                .detail("detail", detail.clone()),
            )
            .await;
        Ok(CredentialValidation {
            credential_id: *id,
            ok,
            host: host.to_string(),
            method,
            path,
            status,
            expected_status: expected,
            detail,
        })
    }

    /// Inserts built-in templates that are not yet stored and returns how
    /// many. Existing versions are left untouched so a stored version never
    /// changes under a rule.
    pub async fn seed_builtin_templates(&self) -> Result<usize, ControlError> {
        let mut seeded = 0;
        for (template, yaml) in builtin_templates()? {
            if self
                .policy
                .get_template(&template.id, template.version)
                .await?
                .is_some()
            {
                continue;
            }
            debug!(template = %template.id, version = template.version, "seeding built-in template");
            self.policy
                .insert_template(
                    StoredTemplate {
                        template,
                        yaml: yaml.to_string(),
                        source: TemplateSource::Builtin,
                        status: TemplateStatus::Approved,
                        imported_by: None,
                        approved_by: Some("system".into()),
                        created_at: Utc::now(),
                    },
                    &[],
                )
                .await?;
            seeded += 1;
        }
        if seeded > 0 {
            info!(count = seeded, "added built-in templates");
        }
        Ok(seeded)
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
        let event = AuditEvent::new(caller.actor(), "vault.create", AuditOutcome::Success)
            .vault(id)
            .target(format!("vault:{id}"))
            .detail("name", vault.name.clone());
        self.policy.insert_vault(vault.clone(), &[event]).await?;
        Ok(vault)
    }

    /// Deletes a vault with its services, rules and bundles, and ends its
    /// sessions and API keys. Refused while sessions are live unless
    /// `force`, so a running agent is never cut off by accident.
    pub async fn delete_vault(
        &self,
        caller: &Caller,
        id: &VaultId,
        force: bool,
    ) -> Result<VaultDeletion, ControlError> {
        self.guard
            .check(caller, Action::VaultDelete, Some(id))
            .await?;
        self.guard.require_step_up(caller, Action::VaultDelete)?;
        let vault = self
            .policy
            .get_vault(id)
            .await?
            .ok_or_else(|| ControlError::not_found("vault", id))?;
        let now = Utc::now();
        let live = self.policy.count_live_sessions(id, now).await?;
        if live > 0 && !force {
            return Err(ControlError::Conflict {
                message: format!(
                    "vault '{}' ({id}) has {live} live session(s); revoke them first, or delete with force to end them",
                    vault.name
                ),
            });
        }
        let event = AuditEvent::new(caller.actor(), "vault.delete", AuditOutcome::Success)
            .vault(*id)
            .target(format!("vault:{id}"))
            .detail("name", vault.name.clone())
            .detail("forced", force.to_string());
        let done = self.policy.delete_vault(id, now, &[event]).await?;
        info!(
            vault_id = %id,
            credentials = done.credentials,
            rules = done.rules,
            bundles = done.bundles,
            sessions_revoked = done.sessions_revoked,
            api_keys_revoked = done.api_keys_revoked,
            "vault deleted"
        );
        self.notifier.bump_content();
        self.notifier.bump_sessions();
        Ok(done)
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

    /// Sessions of the vault that are neither revoked nor expired.
    pub async fn live_sessions(&self, caller: &Caller, id: &VaultId) -> Result<u64, ControlError> {
        self.guard
            .check(caller, Action::VaultRead, Some(id))
            .await?;
        Ok(self.policy.count_live_sessions(id, Utc::now()).await?)
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
        let event = AuditEvent::new(caller.actor(), "template.import", AuditOutcome::Success)
            .target(format!(
                "template:{}@{}",
                stored.template.id, stored.template.version
            ))
            .detail("hosts", hosts_string(&stored.template.hosts))
            .detail(
                "host_override_allowed",
                stored.template.host_override.allowed.to_string(),
            );
        self.policy
            .insert_template(stored.clone(), &[event])
            .await?;
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
        let event = AuditEvent::new(caller.actor(), "template.approve", AuditOutcome::Success)
            .target(format!("template:{id}@{version}"))
            .detail("hosts", hosts_string(&existing.template.hosts))
            .detail(
                "host_override_allowed",
                existing.template.host_override.allowed.to_string(),
            );
        self.policy
            .approve_template(id, version, caller.actor(), &[event])
            .await?;
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

    /// Every variable `fields` and `custom_headers` reference, after checking
    /// the headers and that each variable exists.
    async fn variable_refs(
        &self,
        template: &ServiceTemplate,
        fields: &SecretFields,
        custom_headers: &[CustomHeader],
    ) -> Result<Vec<String>, ControlError> {
        let mut keys = fields.variable_references()?;
        for key in validate_custom_headers(custom_headers, &template.injection.header_names())? {
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
        let existing = self.credentials.existing_variable_keys(&keys).await?;
        let missing: Vec<&str> = keys
            .iter()
            .filter(|k| !existing.contains(k))
            .map(String::as_str)
            .collect();
        if !missing.is_empty() {
            return Err(ControlError::validation(format!(
                "unknown variable(s) {}; create them under Variables first",
                missing.join(", ")
            )));
        }
        Ok(keys)
    }

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
        let vault = self.get_vault(caller, vault_id).await?;
        let name = validate_name("credential", &req.name)?;
        let stored = self
            .approved_template(&req.template_id, req.template_version)
            .await?;
        let template = &stored.template;
        template.max_scope(&host_override)?;
        let fields = SecretFields::new(req.fields);
        template.validate_fields(&fields)?;
        let variable_refs = self
            .variable_refs(template, &fields, &req.custom_headers)
            .await?;
        check_substitutions(&req.substitutions, &fields.names())?;
        let id = CredentialId::new();
        let now = Utc::now();
        check_not_after(req.not_after, now)?;
        let meta = CredentialMeta {
            id,
            vault_id: *vault_id,
            name,
            template_id: template.id.clone(),
            template_version: template.version,
            host_override: host_override.clone(),
            field_names: fields.names(),
            custom_headers: req.custom_headers,
            variable_refs,
            substitutions: req.substitutions,
            not_after: req.not_after,
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
            .encrypt(
                KeyScope::Vault(*vault_id),
                &plaintext,
                &credential_aad(&id, vault_id),
            )
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
        if !meta.custom_headers.is_empty() {
            event = event.detail("custom_headers", header_names(&meta.custom_headers));
        }
        if !meta.substitutions.is_empty() {
            event = event.detail("substitutions", placeholder_names(&meta.substitutions));
        }
        if let Some(not_after) = meta.not_after {
            event = event.detail("not_after", not_after.to_rfc3339());
        }
        self.credentials
            .insert_credential(meta.clone(), ciphertext, &[event])
            .await
            .map_err(|e| match e {
                // Names are unique per vault; say so in words the form can show.
                StoreError::Conflict { .. } => ControlError::Conflict {
                    message: format!(
                        "a service named '{}' already exists in vault '{}'; choose another name",
                        meta.name, vault.name
                    ),
                },
                other => other.into(),
            })?;
        Ok(meta)
    }

    /// Replaces a credential's secret, with the new secret's deadline if it
    /// has one. The old value is never returned.
    pub async fn rotate_credential(
        &self,
        caller: &Caller,
        id: &CredentialId,
        fields: BTreeMap<String, String>,
        not_after: Option<DateTime<Utc>>,
    ) -> Result<CredentialMeta, ControlError> {
        check_not_after(not_after, Utc::now())?;
        let meta = self.credential_meta(id).await?;
        self.guard
            .check(caller, Action::CredentialWrite, Some(&meta.vault_id))
            .await?;
        let stored = self
            .approved_template(&meta.template_id, Some(meta.template_version))
            .await?;
        let fields = SecretFields::new(fields);
        stored.template.validate_fields(&fields)?;
        check_substitutions(&meta.substitutions, &fields.names()).map_err(|e| {
            ControlError::validation(format!(
                "{e}; remove or change the substitution before dropping the field"
            ))
        })?;
        let variable_refs = self
            .variable_refs(&stored.template, &fields, &meta.custom_headers)
            .await?;
        let plaintext = zeroize::Zeroizing::new(
            serde_json::to_vec(&fields)
                .map_err(|e| ControlError::crypto("credential.encode", e))?,
        );
        let ciphertext = self
            .cipher
            .encrypt(
                KeyScope::Vault(meta.vault_id),
                &plaintext,
                &credential_aad_for(&meta),
            )
            .await?;
        let mut event = AuditEvent::new(caller.actor(), "credential.rotate", AuditOutcome::Success)
            .vault(meta.vault_id)
            .target(format!("credential:{id}"));
        if let Some(not_after) = not_after {
            event = event.detail("not_after", not_after.to_rfc3339());
        }
        self.credentials
            .replace_secret(
                id,
                NewSecret {
                    ciphertext,
                    field_names: fields.names(),
                    variable_refs,
                    not_after,
                },
                Utc::now(),
                &[event],
            )
            .await?;
        self.notifier.bump_content();
        self.credential_meta(id).await
    }

    /// Replaces a credential's custom headers. The secret is unchanged; its
    /// own variable references are kept.
    pub async fn update_custom_headers(
        &self,
        caller: &Caller,
        id: &CredentialId,
        custom_headers: Vec<CustomHeader>,
    ) -> Result<CredentialMeta, ControlError> {
        let meta = self.credential_meta(id).await?;
        self.guard
            .check(caller, Action::CredentialWrite, Some(&meta.vault_id))
            .await?;
        let stored = self
            .approved_template(&meta.template_id, Some(meta.template_version))
            .await?;
        let ciphertext = self
            .credentials
            .load_secret_ciphertext(id)
            .await?
            .ok_or_else(|| ControlError::not_found("credential", id))?;
        let plaintext = self
            .cipher
            .decrypt(&ciphertext, &credential_aad_for(&meta))
            .await?;
        let fields: SecretFields = serde_json::from_slice(&plaintext)
            .map_err(|e| ControlError::crypto("credential.decode", format!("{id}: {e}")))?;
        let variable_refs = self
            .variable_refs(&stored.template, &fields, &custom_headers)
            .await?;
        drop(fields);
        let event = AuditEvent::new(
            caller.actor(),
            "credential.update_headers",
            AuditOutcome::Success,
        )
        .vault(meta.vault_id)
        .target(format!("credential:{id}"))
        .detail("custom_headers", header_names(&custom_headers));
        self.credentials
            .update_custom_headers(id, custom_headers, variable_refs, Utc::now(), &[event])
            .await?;
        self.notifier.bump_content();
        self.credential_meta(id).await
    }

    /// Replaces a credential's substitutions. The secret is unchanged.
    pub async fn update_substitutions(
        &self,
        caller: &Caller,
        id: &CredentialId,
        substitutions: Vec<Substitution>,
    ) -> Result<CredentialMeta, ControlError> {
        let meta = self.credential_meta(id).await?;
        self.guard
            .check(caller, Action::CredentialWrite, Some(&meta.vault_id))
            .await?;
        check_substitutions(&substitutions, &meta.field_names)?;
        let event = AuditEvent::new(
            caller.actor(),
            "credential.update_substitutions",
            AuditOutcome::Success,
        )
        .vault(meta.vault_id)
        .target(format!("credential:{id}"))
        .detail("substitutions", placeholder_names(&substitutions));
        self.credentials
            .update_substitutions(id, substitutions, Utc::now(), &[event])
            .await?;
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
        let event = AuditEvent::new(caller.actor(), "credential.delete", AuditOutcome::Success)
            .vault(meta.vault_id)
            .target(format!("credential:{id}"));
        self.credentials.delete_credential(id, &[event]).await?;
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
            mcp_tools: req.mcp_tools.clone().map(validate_mcp_tools).transpose()?,
            git: req.git.clone().map(normalise_git).transpose()?,
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
        let event = AuditEvent::new(caller.actor(), "rule.create", AuditOutcome::Success)
            .vault(*vault_id)
            .target(format!("rule:{}", rule.id))
            .detail("credential_id", meta.id.to_string())
            .detail("hosts", hosts_string(&rule.allow.hosts))
            .detail("mcp_tools", tools_string(&rule.allow.mcp_tools))
            .detail("git", git_string(&rule.allow.git));
        self.policy.insert_rule(rule.clone(), &[event]).await?;
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
        if req.allow_all_tools && req.mcp_tools.is_some() {
            return Err(ControlError::validation(
                "send either mcp_tools or allow_all_tools, not both",
            ));
        }
        if req.allow_all_tools {
            rule.allow.mcp_tools = None;
        } else if let Some(tools) = &req.mcp_tools {
            rule.allow.mcp_tools = Some(validate_mcp_tools(tools.clone())?);
        }
        if req.remove_git && req.git.is_some() {
            return Err(ControlError::validation(
                "send either git or remove_git, not both",
            ));
        }
        if req.remove_git {
            rule.allow.git = None;
        } else if let Some(git) = &req.git {
            rule.allow.git = Some(normalise_git(git.clone())?);
        }
        rule.allow.validate(&template.id)?;
        rule.allow.ensure_within(&max, &template.id)?;
        let widened = rule.allow.widens(&previous.allow) || (rule.enabled && !previous.enabled);
        if widened {
            self.guard.require_step_up(caller, Action::RuleWrite)?;
        }
        rule.updated_at = Utc::now();
        let event = AuditEvent::new(caller.actor(), "rule.update", AuditOutcome::Success)
            .vault(rule.vault_id)
            .target(format!("rule:{id}"))
            .detail("credential_id", rule.credential_id.to_string())
            .detail("widened", widened.to_string())
            .detail("enabled", rule.enabled.to_string())
            .detail("hosts", hosts_string(&rule.allow.hosts))
            .detail("mcp_tools", tools_string(&rule.allow.mcp_tools))
            .detail("git", git_string(&rule.allow.git));
        self.policy.update_rule(rule.clone(), &[event]).await?;
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
        let event = AuditEvent::new(caller.actor(), "rule.delete", AuditOutcome::Success)
            .vault(rule.vault_id)
            .target(format!("rule:{id}"))
            .detail("credential_id", rule.credential_id.to_string());
        self.policy.delete_rule(id, &[event]).await?;
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
        settings.egress.validate()?;
        let mut settings = settings;
        settings.passthrough_hosts.sort();
        settings.passthrough_hosts.dedup();
        if settings.passthrough_hosts.len() > MAX_PASSTHROUGH_HOSTS {
            return Err(ControlError::validation(format!(
                "at most {MAX_PASSTHROUGH_HOSTS} always-reachable hosts are allowed, got {}",
                settings.passthrough_hosts.len()
            )));
        }
        let ceiling = tokenless_core::session::SESSION_TTL_CEILING_SECS;
        if !(60..=ceiling).contains(&settings.max_session_ttl_secs) {
            return Err(ControlError::validation(format!(
                "the longest session must be between 60 seconds and {} days, got {}s",
                ceiling / 86_400,
                settings.max_session_ttl_secs
            )));
        }
        let previous = self.policy.get_settings().await?;
        let adds_exception = settings
            .passthrough_hosts
            .iter()
            .any(|h| !previous.passthrough_hosts.iter().any(|p| p.covers(h)));
        let widens = settings.egress.widens(&previous.egress)
            || (previous.unmatched_host_policy == UnmatchedHostPolicy::Deny
                && settings.unmatched_host_policy == UnmatchedHostPolicy::Passthrough)
            || adds_exception
            || settings.max_session_ttl_secs > previous.max_session_ttl_secs;
        if widens {
            // Opening egress is as sensitive as widening a rule.
            self.guard.require_step_up(caller, Action::SettingsWrite)?;
        }
        let event = AuditEvent::new(caller.actor(), "settings.update", AuditOutcome::Success)
            .detail(
                "unmatched_host_policy",
                format!("{:?}", settings.unmatched_host_policy).to_ascii_lowercase(),
            )
            .detail(
                "egress_block_private",
                settings.egress.block_private.to_string(),
            )
            .detail(
                "egress_allow",
                settings
                    .egress
                    .allow
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            )
            .detail(
                "max_session_ttl_secs",
                settings.max_session_ttl_secs.to_string(),
            )
            .detail(
                "passthrough_hosts",
                settings
                    .passthrough_hosts
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            );
        self.policy.put_settings(settings.clone(), &[event]).await?;
        self.notifier.bump_content();
        Ok(settings)
    }
}

/// A secret's deadline must still be ahead: a secret already past it would
/// only ever be refused.
fn check_not_after(
    not_after: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Result<(), ControlError> {
    match not_after {
        Some(at) if at <= now => Err(ControlError::validation(format!(
            "not_after {} has already passed; give the secret's real expiry, or none",
            at.to_rfc3339()
        ))),
        _ => Ok(()),
    }
}
