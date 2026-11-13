// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Role-based authorisation decisions. Pure: the control plane's
//! `Authorizer` wraps this so an embedding system can substitute its own.
//!
//! Access has two independent levels. A person's *instance role*
//! ([`Role::Admin`] or [`Role::Member`]) decides who runs the instance:
//! people, settings, sign-in, proxies. Their *vault role*
//! ([`Role::Admin`], [`Role::Editor`], [`Role::Viewer`] or [`Role::Runner`],
//! one per vault they are a member of) decides what they may do inside
//! that vault. Being an instance admin gives no vault's contents: an admin
//! joins a vault first (see [`Action::VaultJoin`]). The control plane's
//! guard resolves the vault role before asking [`rbac_decide`].

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ids::VaultId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// As an instance role, runs the instance; as a vault role, has full
    /// control of the vault, its members included. Only people (never API
    /// keys) can be admins.
    Admin,
    /// Manage services, rules, bundles and sessions in one vault.
    Editor,
    /// Read-only access to one vault.
    Viewer,
    /// Starts sessions from one vault's access bundles and sees what they
    /// reach, nothing more: for the people (and keys) who only run agents.
    Runner,
    /// An instance role: signs in, and reaches only the vaults they are a
    /// member of, by their role in each.
    Member,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Editor => "editor",
            Role::Viewer => "viewer",
            Role::Runner => "runner",
            Role::Member => "member",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "admin" => Some(Role::Admin),
            "editor" => Some(Role::Editor),
            "viewer" => Some(Role::Viewer),
            "runner" => Some(Role::Runner),
            "member" => Some(Role::Member),
            _ => None,
        }
    }

    /// A role a person holds on the instance.
    pub fn is_instance_role(&self) -> bool {
        matches!(self, Role::Admin | Role::Member)
    }

    /// A role a person holds in a vault.
    pub fn is_vault_role(&self) -> bool {
        matches!(
            self,
            Role::Admin | Role::Editor | Role::Viewer | Role::Runner
        )
    }

    /// A role an API key may hold: a vault role short of admin.
    pub fn is_api_key_role(&self) -> bool {
        matches!(self, Role::Editor | Role::Viewer | Role::Runner)
    }

    /// Orders vault roles by how much they allow, for "at least" checks
    /// and for keeping the higher of two grants. A runner starts sessions
    /// a viewer may not, but sees less; neither contains the other, and a
    /// runner ranks lowest so a grant never turns a viewer into one.
    pub fn vault_rank(&self) -> u8 {
        match self {
            Role::Admin => 4,
            Role::Editor => 3,
            Role::Viewer => 2,
            Role::Runner => 1,
            Role::Member => 0,
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
    /// An instance admin makes themselves an admin of a vault they are not
    /// a member of, to reach its contents. With step-up, and recorded.
    VaultJoin,
    /// Add people to a vault, change their role in it, remove them.
    VaultMemberManage,
    TemplateRead,
    TemplateImport,
    TemplateApprove,
    CredentialRead,
    CredentialWrite,
    CredentialDelete,
    /// Override a template's hosts (e.g. a self-hosted base URL): send the
    /// secret somewhere the template does not. A vault's admins only.
    CredentialWiden,
    RuleRead,
    RuleWrite,
    RuleDelete,
    SessionRead,
    SessionMint,
    SessionRevoke,
    /// List API keys (never their secrets).
    ApiKeyRead,
    ApiKeyManage,
    /// List a vault's launcher keys (never their secrets).
    LauncherKeyRead,
    /// Create a launcher key: an API key that only starts sessions from one
    /// access bundle of the vault.
    LauncherKeyCreate,
    /// Revoke a launcher key. No step-up: cutting access off must be quick.
    LauncherKeyRevoke,
    AuditRead,
    /// Mark an alert as looked at. Seeing alerts takes `AuditRead`.
    AlertAcknowledge,
    /// List proxies and their status.
    NodeRead,
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
    /// Add, change and remove single sign-on providers and the sign-in
    /// settings.
    IdentityProviderManage,
    /// Add, change and remove the destinations audit events are sent to.
    AuditExportManage,
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
                | Action::LauncherKeyCreate
                | Action::TemplateImport
                | Action::TemplateApprove
                | Action::NodeManage
                | Action::UserManage
                | Action::VariableManage
                | Action::IdentityProviderManage
                | Action::AuditExportManage
                | Action::VaultJoin
                | Action::VaultMemberManage
        )
    }

    /// Actions on the instance rather than inside one vault: they take the
    /// instance role, never a vault role.
    pub fn instance_level(&self) -> bool {
        matches!(
            self,
            Action::VaultCreate
                | Action::VaultDelete
                | Action::VaultJoin
                | Action::TemplateImport
                | Action::TemplateApprove
                | Action::ApiKeyRead
                | Action::ApiKeyManage
                | Action::NodeRead
                | Action::NodeManage
                | Action::SettingsWrite
                | Action::UserRead
                | Action::UserManage
                | Action::VariableRead
                | Action::VariableManage
                | Action::IdentityProviderManage
                | Action::AuditExportManage
        )
    }
}

impl Action {
    /// What an instance admin may do in a vault without joining it: see
    /// that it exists, its sessions, launcher keys, audit log and alerts,
    /// and cut off its sessions and launcher keys. Watching and stopping,
    /// never reaching what the vault holds.
    pub fn admin_oversight(&self) -> bool {
        matches!(
            self,
            Action::VaultRead
                | Action::SessionRead
                | Action::LauncherKeyRead
                | Action::AuditRead
                | Action::AlertAcknowledge
                | Action::SessionRevoke
                | Action::LauncherKeyRevoke
        )
    }

    /// What a sign-in made for running agents (`tokenless login`, the
    /// default) may do: find the bundles it can start, start sessions from
    /// them and see what they reach.
    pub fn launch_only(&self) -> bool {
        matches!(
            self,
            Action::VaultRead
                | Action::TemplateRead
                | Action::CredentialRead
                | Action::RuleRead
                | Action::SessionMint
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
                | Action::LauncherKeyRead
                | Action::LauncherKeyCreate
                | Action::LauncherKeyRevoke
                | Action::AuditRead
                | Action::AlertAcknowledge
        ),
        Role::Viewer => matches!(
            action,
            Action::VaultRead
                | Action::TemplateRead
                | Action::CredentialRead
                | Action::RuleRead
                | Action::SessionRead
                | Action::LauncherKeyRead
                | Action::AuditRead
        ),
        // Starting sessions is the point; what they reach is shown so the
        // right bundle can be picked. No audit log, no other sessions.
        Role::Runner => matches!(
            action,
            Action::VaultRead
                | Action::TemplateRead
                | Action::CredentialRead
                | Action::RuleRead
                | Action::SessionMint
        ),
        // Everything a member does in a vault comes from their role there.
        Role::Member => action == Action::TemplateRead,
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
    fn roles_belong_to_the_instance_a_vault_or_a_key() {
        for role in [Role::Admin, Role::Member] {
            assert!(role.is_instance_role(), "{role}");
        }
        for role in [Role::Editor, Role::Viewer, Role::Runner] {
            assert!(!role.is_instance_role() && role.is_vault_role(), "{role}");
            assert!(role.is_api_key_role(), "{role}");
        }
        assert!(Role::Admin.is_vault_role() && !Role::Admin.is_api_key_role());
        assert!(!Role::Member.is_vault_role() && !Role::Member.is_api_key_role());
        for role in [Role::Runner, Role::Member] {
            assert_eq!(Role::parse(role.as_str()), Some(role));
        }
        assert!(Role::Admin.vault_rank() > Role::Editor.vault_rank());
        assert!(Role::Viewer.vault_rank() > Role::Runner.vault_rank());
        assert!(Role::Runner.vault_rank() > Role::Member.vault_rank());
    }

    #[test]
    fn a_runner_starts_sessions_and_reads_only_what_picking_a_bundle_needs() {
        let vault = VaultId::new();
        let runner = key(Role::Runner, vault);
        for action in [
            Action::VaultRead,
            Action::TemplateRead,
            Action::CredentialRead,
            Action::RuleRead,
            Action::SessionMint,
        ] {
            assert_eq!(
                rbac_decide(&runner, action, Some(&vault)),
                Decision::Allow,
                "{action}"
            );
            assert!(action.launch_only(), "{action}");
        }
        for action in [
            Action::SessionRead,
            Action::SessionRevoke,
            Action::AuditRead,
            Action::RuleWrite,
            Action::LauncherKeyCreate,
            Action::VaultMemberManage,
        ] {
            assert!(
                matches!(
                    rbac_decide(&runner, action, Some(&vault)),
                    Decision::Deny { .. }
                ),
                "{action}"
            );
            assert!(!action.launch_only(), "{action}");
        }
    }

    #[test]
    fn a_member_of_the_instance_does_nothing_in_a_vault_by_that_alone() {
        let member = Principal {
            kind: PrincipalKind::User,
            actor: "user:1".into(),
            role: Role::Member,
            vault: None,
        };
        assert_eq!(
            rbac_decide(&member, Action::TemplateRead, None),
            Decision::Allow
        );
        let vault = VaultId::new();
        for action in [Action::VaultRead, Action::SessionMint, Action::VaultJoin] {
            assert!(
                matches!(
                    rbac_decide(&member, action, Some(&vault)),
                    Decision::Deny { .. }
                ),
                "{action}"
            );
        }
    }

    #[test]
    fn oversight_reads_and_stops_but_never_writes_or_reads_contents() {
        for action in [
            Action::VaultRead,
            Action::SessionRead,
            Action::LauncherKeyRead,
            Action::AuditRead,
            Action::AlertAcknowledge,
            Action::SessionRevoke,
            Action::LauncherKeyRevoke,
        ] {
            assert!(action.admin_oversight(), "{action}");
        }
        for action in [
            Action::CredentialRead,
            Action::CredentialWrite,
            Action::RuleRead,
            Action::SessionMint,
            Action::LauncherKeyCreate,
            Action::VaultMemberManage,
        ] {
            assert!(!action.admin_oversight(), "{action}");
        }
        assert!(Action::VaultJoin.instance_level() && Action::VaultJoin.requires_step_up());
        assert!(!Action::VaultMemberManage.instance_level());
        assert!(Action::VaultMemberManage.requires_step_up());
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
    fn reading_never_needs_step_up() {
        // The console reads these in the background on every page: a
        // read that needed a recent second factor would ask an admin to
        // confirm while they were only looking.
        for action in [
            Action::VaultRead,
            Action::TemplateRead,
            Action::CredentialRead,
            Action::RuleRead,
            Action::SessionRead,
            Action::ApiKeyRead,
            Action::AuditRead,
            Action::NodeRead,
            Action::UserRead,
            Action::VariableRead,
        ] {
            assert!(!action.requires_step_up(), "{action}");
        }
        // Still admin only.
        let vault = VaultId::new();
        for action in [Action::NodeRead, Action::ApiKeyRead] {
            assert!(
                matches!(
                    rbac_decide(&key(Role::Editor, vault), action, None),
                    Decision::Deny { .. }
                ),
                "{action}"
            );
        }
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
