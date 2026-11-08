// SPDX-FileCopyrightText: 2026 tokenless contributors
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
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Editor => "editor",
            Role::Viewer => "viewer",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "admin" => Some(Role::Admin),
            "editor" => Some(Role::Editor),
            "viewer" => Some(Role::Viewer),
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
    /// Delete a vault with everything in it. Admin only, with step-up.
    VaultDelete,
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
                | Action::VaultDelete
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
                | Action::VaultDelete
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
    /// A program that embeds the control services and calls them for its
    /// own, already authorised, users. Never created by sign-in.
    Service,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    pub kind: PrincipalKind,
    /// `user:<id>`, `api_key:<prefix>` or `service:<name>`; used as the
    /// audit actor.
    pub actor: String,
    pub role: Role,
    /// API keys are bound to exactly one vault and people to none; a
    /// service may be bound to one.
    pub vault: Option<VaultId>,
}

impl Principal {
    /// A service principal, audited as `service:<name>`.
    pub fn service(name: &str, role: Role, vault: Option<VaultId>) -> Self {
        Self {
            kind: PrincipalKind::Service,
            actor: format!("service:{name}"),
            role,
            vault,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny { reason: String },
}

pub fn rbac_decide(principal: &Principal, action: Action, vault: Option<&VaultId>) -> Decision {
    let deny = |reason: String| Decision::Deny { reason };
    if principal.role == Role::Admin {
        match principal.kind {
            PrincipalKind::ApiKey => {
                return deny("API keys cannot hold the admin role".into());
            }
            PrincipalKind::User => return Decision::Allow,
            // A vault-bound service administers its vault and nothing else.
            PrincipalKind::Service => {
                return match (&principal.vault, vault) {
                    (None, _) => Decision::Allow,
                    (Some(bound), Some(target)) if bound == target => Decision::Allow,
                    (Some(bound), Some(target)) => deny(format!(
                        "{} is bound to vault {bound} and cannot act on vault {target}",
                        principal.actor
                    )),
                    (Some(_), None) if action == Action::TemplateRead => Decision::Allow,
                    (Some(bound), None) => deny(format!(
                        "{} is bound to vault {bound}; '{action}' is instance-wide",
                        principal.actor
                    )),
                };
            }
        }
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
    fn a_service_is_held_to_its_vault_even_as_admin() {
        let (mine, other) = (VaultId::new(), VaultId::new());
        let bound = Principal::service("host", Role::Admin, Some(mine));
        assert_eq!(bound.actor, "service:host");
        for action in [
            Action::CredentialWrite,
            Action::CredentialWiden,
            Action::VaultDelete,
        ] {
            assert_eq!(
                rbac_decide(&bound, action, Some(&mine)),
                Decision::Allow,
                "{action}"
            );
        }
        assert_eq!(
            rbac_decide(&bound, Action::TemplateRead, None),
            Decision::Allow
        );
        for (action, vault) in [
            (Action::CredentialWrite, Some(&other)),
            (Action::SessionMint, Some(&other)),
            (Action::NodeManage, None),
            (Action::SettingsWrite, None),
        ] {
            assert!(
                matches!(rbac_decide(&bound, action, vault), Decision::Deny { .. }),
                "{action} on {vault:?}"
            );
        }
        let unbound = Principal::service("host", Role::Admin, None);
        assert_eq!(
            rbac_decide(&unbound, Action::NodeManage, None),
            Decision::Allow
        );
        let editor = Principal::service("host", Role::Editor, Some(mine));
        assert!(matches!(
            rbac_decide(&editor, Action::CredentialWrite, Some(&mine)),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn api_keys_are_vault_bound() {
        let vault = VaultId::new();
        let editor = key(Role::Editor, vault);
        assert_eq!(
            rbac_decide(&editor, Action::SessionMint, Some(&vault)),
            Decision::Allow
        );
        assert!(matches!(
            rbac_decide(&editor, Action::SessionMint, Some(&VaultId::new())),
            Decision::Deny { .. }
        ));
        assert!(matches!(
            rbac_decide(&key(Role::Viewer, vault), Action::SessionMint, Some(&vault)),
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
