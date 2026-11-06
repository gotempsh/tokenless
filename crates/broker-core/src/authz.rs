// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Role-based authorisation decisions. Pure: the control plane's
//! `Authorizer` wraps this so an embedding system can substitute its own.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ids::VaultId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Full control of the instance. Only people (never API keys) can be admins.
    Admin,
    /// Manage rules and sessions in one vault.
    Editor,
    /// Read-only access to one vault.
    Viewer,
    /// Mint proxy sessions in one vault, nothing else.
    SessionIssuer,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Editor => "editor",
            Role::Viewer => "viewer",
            Role::SessionIssuer => "session_issuer",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "admin" => Some(Role::Admin),
            "editor" => Some(Role::Editor),
            "viewer" => Some(Role::Viewer),
            "session_issuer" => Some(Role::SessionIssuer),
            _ => None,
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    VaultCreate,
    VaultRead,
    TemplateRead,
    TemplateImport,
    TemplateApprove,
    CredentialRead,
    CredentialWrite,
    CredentialDelete,
    /// Override a template's hosts (e.g. a self-hosted base URL).
    CredentialWiden,
    RuleRead,
    RuleWrite,
    RuleDelete,
    SessionRead,
    SessionMint,
    SessionRevoke,
    ApiKeyManage,
    AuditRead,
    NodeManage,
    SettingsWrite,
    /// List people and invitations.
    UserRead,
    /// Invite people, change their role, disable them.
    UserManage,
    /// List variables and where they are used (never their values).
    VariableRead,
    /// Create, replace and delete variables.
    VariableManage,
}

impl Action {
    /// Actions that require a recent second factor even for an admin.
    pub fn requires_step_up(&self) -> bool {
        matches!(
            self,
            Action::CredentialWrite
                | Action::CredentialWiden
                | Action::ApiKeyManage
                | Action::TemplateImport
                | Action::TemplateApprove
                | Action::NodeManage
                | Action::UserManage
                | Action::VariableManage
        )
    }

    fn instance_level(&self) -> bool {
        matches!(
            self,
            Action::VaultCreate
                | Action::TemplateImport
                | Action::TemplateApprove
                | Action::CredentialWiden
                | Action::ApiKeyManage
                | Action::NodeManage
                | Action::SettingsWrite
                | Action::UserRead
                | Action::UserManage
                | Action::VariableRead
                | Action::VariableManage
        )
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_else(|| format!("{self:?}"));
        f.write_str(&s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    User,
    ApiKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    pub kind: PrincipalKind,
    /// `user:<id>` or `api_key:<prefix>`; used as the audit actor.
    pub actor: String,
    pub role: Role,
    /// API keys are bound to exactly one vault; people are not.
    pub vault: Option<VaultId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny { reason: String },
}

pub fn rbac_decide(principal: &Principal, action: Action, vault: Option<&VaultId>) -> Decision {
    let deny = |reason: String| Decision::Deny { reason };
    if principal.role == Role::Admin {
        if principal.kind == PrincipalKind::ApiKey {
            return deny("API keys cannot hold the admin role".into());
        }
        return Decision::Allow;
    }
    if action.instance_level() {
        return deny(format!("'{action}' requires the admin role"));
    }
    if let Some(bound) = &principal.vault {
        match vault {
            Some(target) if target == bound => {}
            Some(target) => {
                return deny(format!(
                    "{} is bound to vault {bound} and cannot act on vault {target}",
                    principal.actor
                ))
            }
            None if action == Action::TemplateRead => {}
            None => {
                return deny(format!(
                    "'{action}' needs a vault the principal is bound to"
                ))
            }
        }
    }
    let allowed = match principal.role {
        Role::Admin => true,
        Role::Editor => matches!(
            action,
            Action::VaultRead
                | Action::TemplateRead
                | Action::CredentialRead
                | Action::RuleRead
                | Action::RuleWrite
                | Action::RuleDelete
                | Action::SessionRead
                | Action::SessionMint
                | Action::SessionRevoke
                | Action::AuditRead
        ),
        Role::Viewer => matches!(
            action,
            Action::VaultRead
                | Action::TemplateRead
                | Action::CredentialRead
                | Action::RuleRead
                | Action::SessionRead
                | Action::AuditRead
        ),
        Role::SessionIssuer => matches!(
            action,
            Action::VaultRead | Action::TemplateRead | Action::RuleRead | Action::SessionMint
        ),
    };
    if allowed {
        Decision::Allow
    } else {
        deny(format!(
            "role '{}' may not perform '{action}'",
            principal.role
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(role: Role, vault: VaultId) -> Principal {
        Principal {
            kind: PrincipalKind::ApiKey,
            actor: "api_key:abc".into(),
            role,
            vault: Some(vault),
        }
    }

    #[test]
    fn admin_user_can_do_everything() {
        let admin = Principal {
            kind: PrincipalKind::User,
            actor: "user:1".into(),
            role: Role::Admin,
            vault: None,
        };
        assert_eq!(
            rbac_decide(&admin, Action::NodeManage, None),
            Decision::Allow
        );
    }

    #[test]
    fn api_keys_are_vault_bound() {
        let vault = VaultId::new();
        let issuer = key(Role::SessionIssuer, vault);
        assert_eq!(
            rbac_decide(&issuer, Action::SessionMint, Some(&vault)),
            Decision::Allow
        );
        assert!(matches!(
            rbac_decide(&issuer, Action::SessionMint, Some(&VaultId::new())),
            Decision::Deny { .. }
        ));
        assert!(matches!(
            rbac_decide(&issuer, Action::SessionRevoke, Some(&vault)),
            Decision::Deny { .. }
        ));
        assert!(matches!(
            rbac_decide(
                &key(Role::Editor, vault),
                Action::CredentialWrite,
                Some(&vault)
            ),
            Decision::Deny { .. }
        ));
        assert!(matches!(
            rbac_decide(
                &key(Role::Editor, vault),
                Action::ApiKeyManage,
                Some(&vault)
            ),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn api_key_admin_is_refused() {
        let vault = VaultId::new();
        assert!(matches!(
            rbac_decide(&key(Role::Admin, vault), Action::VaultRead, Some(&vault)),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn step_up_actions() {
        assert!(Action::CredentialWrite.requires_step_up());
        assert!(Action::ApiKeyManage.requires_step_up());
        assert!(!Action::SessionMint.requires_step_up());
        assert_eq!(Action::CredentialWiden.to_string(), "credential_widen");
    }
}
