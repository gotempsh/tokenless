// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Variables: write-only secrets referenced as `{{KEY}}` from credential
//! fields and custom headers. A value can be replaced, never read back.

use std::collections::HashMap;
use std::sync::Arc;

use broker_core::audit::{AuditEvent, AuditOutcome};
use broker_core::authz::Action;
use broker_core::ids::{CredentialId, VariableId, VaultId};
use broker_core::variables::{validate_key, MAX_VALUE_LEN};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::render::variable_aad;
use super::{Caller, Guard};
use crate::cipher::SecretCipher;
use crate::error::ControlError;
use crate::model::{Page, PageRequest, Variable};
use crate::notify::PolicyNotifier;
use crate::store::{CredentialStore, PolicyStore};

/// A submitted value: zeroed on drop and never printed.
#[derive(Deserialize)]
#[serde(from = "String")]
pub struct SecretValue(Zeroizing<String>);

impl From<String> for SecretValue {
    fn from(value: String) -> Self {
        Self(Zeroizing::new(value))
    }
}

impl std::ops::Deref for SecretValue {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretValue(***)")
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateVariable {
    pub key: String,
    pub value: SecretValue,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplaceVariable {
    pub value: SecretValue,
}

/// A credential whose fields or custom headers reference a variable.
#[derive(Debug, Clone, Serialize)]
pub struct VariableUse {
    pub credential_id: CredentialId,
    pub credential_name: String,
    pub vault_id: VaultId,
    pub vault_name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct VariableView {
    pub id: VariableId,
    pub key: String,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_by: String,
    pub updated_at: DateTime<Utc>,
    pub used_by: Vec<VariableUse>,
}

fn validate_value(key: &str, value: &str) -> Result<(), ControlError> {
    if value.is_empty() {
        return Err(ControlError::validation(format!(
            "variable {key}: value cannot be empty"
        )));
    }
    if value.len() > MAX_VALUE_LEN {
        return Err(ControlError::validation(format!(
            "variable {key}: value is {} bytes; at most {MAX_VALUE_LEN} are allowed",
            value.len()
        )));
    }
    // Values end up in HTTP headers: no line breaks or other control bytes.
    if value.chars().any(|c| c.is_control() && c != '\t') {
        return Err(ControlError::validation(format!(
            "variable {key}: value contains a line break or control character and cannot be sent in a header"
        )));
    }
    Ok(())
}

pub struct VariableService {
    credentials: Arc<dyn CredentialStore>,
    policy: Arc<dyn PolicyStore>,
    cipher: Arc<dyn SecretCipher>,
    guard: Guard,
    notifier: Arc<PolicyNotifier>,
}

impl VariableService {
    pub fn new(
        credentials: Arc<dyn CredentialStore>,
        policy: Arc<dyn PolicyStore>,
        cipher: Arc<dyn SecretCipher>,
        guard: Guard,
        notifier: Arc<PolicyNotifier>,
    ) -> Self {
        Self {
            credentials,
            policy,
            cipher,
            guard,
            notifier,
        }
    }

    async fn variable(&self, id: &VariableId) -> Result<Variable, ControlError> {
        self.credentials
            .get_variable(id)
            .await?
            .ok_or_else(|| ControlError::not_found("variable", id))
    }

    /// Which credentials use each key, with their vault names.
    async fn usage(&self) -> Result<HashMap<String, Vec<VariableUse>>, ControlError> {
        let mut vault_names: HashMap<VaultId, String> = HashMap::new();
        let mut usage: HashMap<String, Vec<VariableUse>> = HashMap::new();
        for meta in self.credentials.list_credentials_with_variables().await? {
            let vault_name = match vault_names.get(&meta.vault_id) {
                Some(name) => name.clone(),
                None => {
                    let name = self
                        .policy
                        .get_vault(&meta.vault_id)
                        .await?
                        .map(|v| v.name)
                        .unwrap_or_else(|| meta.vault_id.to_string());
                    vault_names.insert(meta.vault_id, name.clone());
                    name
                }
            };
            for key in &meta.variable_refs {
                usage.entry(key.clone()).or_default().push(VariableUse {
                    credential_id: meta.id,
                    credential_name: meta.name.clone(),
                    vault_id: meta.vault_id,
                    vault_name: vault_name.clone(),
                });
            }
        }
        Ok(usage)
    }

    fn view(variable: Variable, usage: &HashMap<String, Vec<VariableUse>>) -> VariableView {
        VariableView {
            used_by: usage.get(&variable.key).cloned().unwrap_or_default(),
            id: variable.id,
            key: variable.key,
            created_by: variable.created_by,
            created_at: variable.created_at,
            updated_by: variable.updated_by,
            updated_at: variable.updated_at,
        }
    }

    pub async fn list(
        &self,
        caller: &Caller,
        page: PageRequest,
    ) -> Result<Page<VariableView>, ControlError> {
        self.guard.check(caller, Action::VariableRead, None).await?;
        let found = self.credentials.list_variables(page).await?;
        let usage = self.usage().await?;
        Ok(Page {
            items: found
                .items
                .into_iter()
                .map(|v| Self::view(v, &usage))
                .collect(),
            total: found.total,
            page: found.page,
            page_size: found.page_size,
        })
    }

    pub async fn create(
        &self,
        caller: &Caller,
        req: CreateVariable,
    ) -> Result<VariableView, ControlError> {
        self.guard
            .check(caller, Action::VariableManage, None)
            .await?;
        let key = req.key.trim().to_string();
        validate_key(&key)?;
        validate_value(&key, &req.value)?;
        let now = Utc::now();
        let variable = Variable {
            id: VariableId::new(),
            key: key.clone(),
            created_by: caller.actor().to_string(),
            created_at: now,
            updated_by: caller.actor().to_string(),
            updated_at: now,
        };
        let ciphertext = self
            .cipher
            .encrypt(req.value.as_bytes(), &variable_aad(&variable.id))?;
        let event = AuditEvent::new(caller.actor(), "variable.create", AuditOutcome::Success)
            .target(format!("variable:{}", variable.id))
            .detail("key", key.clone());
        self.credentials
            .insert_variable(variable.clone(), ciphertext, &[event])
            .await
            .map_err(|e| match e {
                crate::StoreError::Conflict { .. } => ControlError::Conflict {
                    message: format!("a variable named {key} already exists"),
                },
                other => other.into(),
            })?;
        Ok(Self::view(variable, &HashMap::new()))
    }

    /// Replaces the value. Every credential using it picks it up at the
    /// next snapshot.
    pub async fn replace_value(
        &self,
        caller: &Caller,
        id: &VariableId,
        value: SecretValue,
    ) -> Result<VariableView, ControlError> {
        self.guard
            .check(caller, Action::VariableManage, None)
            .await?;
        let variable = self.variable(id).await?;
        validate_value(&variable.key, &value)?;
        let ciphertext = self
            .cipher
            .encrypt(value.as_bytes(), &variable_aad(&variable.id))?;
        let event = AuditEvent::new(caller.actor(), "variable.update", AuditOutcome::Success)
            .target(format!("variable:{id}"))
            .detail("key", variable.key.clone());
        self.credentials
            .replace_variable_value(id, ciphertext, caller.actor(), Utc::now(), &[event])
            .await?;
        self.notifier.bump_content();
        let usage = self.usage().await?;
        Ok(Self::view(self.variable(id).await?, &usage))
    }

    /// Refused while any credential still references the key.
    pub async fn delete(&self, caller: &Caller, id: &VariableId) -> Result<(), ControlError> {
        self.guard
            .check(caller, Action::VariableManage, None)
            .await?;
        let variable = self.variable(id).await?;
        let event = AuditEvent::new(caller.actor(), "variable.delete", AuditOutcome::Success)
            .target(format!("variable:{id}"))
            .detail("key", variable.key.clone());
        self.credentials
            .delete_variable(id, &[event])
            .await
            .map_err(|e| match e {
                crate::StoreError::Conflict { detail, .. } => ControlError::Conflict {
                    message: format!("{detail}; remove the references before deleting it"),
                },
                other => other.into(),
            })?;
        self.notifier.bump_content();
        Ok(())
    }
}
