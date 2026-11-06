// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

pub mod audit;
pub mod auth;
pub mod bundles;
pub mod nodes;
pub mod policy;
mod render;
pub mod sessions;
pub mod users;
pub mod variables;

use std::sync::Arc;

use broker_core::audit::AuditEvent;
use broker_core::authz::{Action, Decision, Principal, PrincipalKind};
use broker_core::ids::VaultId;
use chrono::{DateTime, Utc};
use tracing::error;

use crate::cipher::SecretCipher;
use crate::error::ControlError;
use crate::keys::KeyRing;
use crate::notify::PolicyNotifier;
use crate::probe::CredentialProber;
use crate::store::{AuditSink, Authorizer, CredentialStore, IdentityStore, NodeStore, PolicyStore};

#[derive(Debug, Clone)]
pub struct ControlConfig {
    /// How long a node may keep serving without a newer snapshot.
    pub lease_secs: u32,
    pub node_cert_ttl: chrono::Duration,
    pub ui_session_ttl_secs: u64,
    pub step_up_window_secs: u64,
    pub join_token_ttl_secs: u64,
}

impl Default for ControlConfig {
    fn default() -> Self {
        Self {
            lease_secs: 60,
            node_cert_ttl: chrono::Duration::hours(24),
            ui_session_ttl_secs: 12 * 3600,
            step_up_window_secs: 300,
            join_token_ttl_secs: 3600,
        }
    }
}

/// The authenticated party behind a request.
#[derive(Debug, Clone)]
pub struct Caller {
    pub principal: Principal,
    /// When the caller last proved a second factor (people only).
    pub step_up_at: Option<DateTime<Utc>>,
    /// Whether the caller has a second factor to step up with. Only people
    /// with an authenticator enrolled are asked to step up: for a
    /// password-only account it would just ask for the same password again.
    pub second_factor: bool,
}

impl Caller {
    pub fn actor(&self) -> &str {
        &self.principal.actor
    }
}

#[derive(Clone)]
pub struct Stores {
    pub credentials: Arc<dyn CredentialStore>,
    pub policy: Arc<dyn PolicyStore>,
    pub audit: Arc<dyn AuditSink>,
    pub identity: Arc<dyn IdentityStore>,
    pub nodes: Arc<dyn NodeStore>,
}

/// Authorisation plus step-up enforcement, shared by every service.
#[derive(Clone)]
pub struct Guard {
    authorizer: Arc<dyn Authorizer>,
    step_up_window_secs: u64,
}

impl Guard {
    pub fn new(authorizer: Arc<dyn Authorizer>, step_up_window_secs: u64) -> Self {
        Self {
            authorizer,
            step_up_window_secs,
        }
    }

    pub async fn check(
        &self,
        caller: &Caller,
        action: Action,
        vault: Option<&VaultId>,
    ) -> Result<(), ControlError> {
        if let Decision::Deny { reason } = self
            .authorizer
            .authorize(&caller.principal, action, vault)
            .await
        {
            return Err(ControlError::Forbidden { reason });
        }
        if action.requires_step_up() {
            self.require_step_up(caller, action)?;
        }
        Ok(())
    }

    pub fn require_step_up(&self, caller: &Caller, action: Action) -> Result<(), ControlError> {
        if caller.principal.kind != PrincipalKind::User {
            return Err(ControlError::Forbidden {
                reason: format!(
                    "'{action}' needs a person with a second factor; {} is an API key",
                    caller.actor()
                ),
            });
        }
        if !caller.second_factor {
            return Ok(());
        }
        let window =
            chrono::Duration::seconds(i64::try_from(self.step_up_window_secs).unwrap_or(300));
        let fresh = caller
            .step_up_at
            .is_some_and(|at| Utc::now().signed_duration_since(at) <= window);
        if fresh {
            Ok(())
        } else {
            Err(ControlError::StepUpRequired {
                action: action.to_string(),
                window_secs: self.step_up_window_secs,
            })
        }
    }
}

/// Writes audit events that describe no stored change: denials and
/// validation requests. Events for a change are handed to the store method
/// that makes it and committed with it. A failed write here is logged at
/// error level.
#[derive(Clone)]
pub struct AuditRecorder {
    sink: Arc<dyn AuditSink>,
}

impl AuditRecorder {
    pub fn new(sink: Arc<dyn AuditSink>) -> Self {
        Self { sink }
    }

    pub async fn record(&self, event: AuditEvent) {
        if let Err(e) = self.sink.record(std::slice::from_ref(&event)).await {
            error!(
                action = %event.action,
                actor = %event.actor,
                target = ?event.target,
                error = %e,
                "failed to write audit event"
            );
        }
    }
}

/// Everything the HTTP layer needs, wired once at startup.
pub struct ControlPlane {
    pub auth: auth::AuthService,
    pub policy: policy::PolicyService,
    pub sessions: sessions::SessionService,
    pub bundles: bundles::BundleService,
    pub nodes: nodes::NodeService,
    pub users: users::UserService,
    pub variables: variables::VariableService,
    pub audit: audit::AuditService,
    pub keys: Arc<KeyRing>,
    pub notifier: Arc<PolicyNotifier>,
}

impl ControlPlane {
    pub async fn new(
        stores: Stores,
        authorizer: Arc<dyn Authorizer>,
        cipher: Arc<dyn SecretCipher>,
        prober: Arc<dyn CredentialProber>,
        config: ControlConfig,
    ) -> Result<Self, ControlError> {
        let keys = Arc::new(KeyRing::load_or_create(stores.nodes.as_ref(), cipher.as_ref()).await?);
        let notifier = Arc::new(PolicyNotifier::new());
        let guard = Guard::new(authorizer, config.step_up_window_secs);
        let recorder = AuditRecorder::new(stores.audit.clone());
        let users = users::UserService::new(stores.identity.clone(), cipher.clone(), guard.clone());
        let auth = auth::AuthService::new(
            stores.identity.clone(),
            cipher.clone(),
            keys.clone(),
            guard.clone(),
            recorder.clone(),
            config.clone(),
        )?;
        let policy = policy::PolicyService::new(
            stores.policy.clone(),
            stores.credentials.clone(),
            cipher.clone(),
            guard.clone(),
            recorder.clone(),
            notifier.clone(),
            prober,
        );
        policy.seed_builtin_templates().await?;
        let variables = variables::VariableService::new(
            stores.credentials.clone(),
            stores.policy.clone(),
            cipher.clone(),
            guard.clone(),
            notifier.clone(),
        );
        let bundles = bundles::BundleService::new(stores.policy.clone(), guard.clone());
        let sessions = sessions::SessionService::new(
            stores.policy.clone(),
            stores.credentials.clone(),
            keys.clone(),
            guard.clone(),
            notifier.clone(),
        );
        let nodes = nodes::NodeService::new(
            stores.nodes.clone(),
            stores.policy.clone(),
            stores.credentials.clone(),
            stores.audit.clone(),
            cipher,
            keys.clone(),
            guard.clone(),
            recorder,
            notifier.clone(),
            config,
        );
        let audit = audit::AuditService::new(stores.audit, guard);
        Ok(Self {
            auth,
            policy,
            sessions,
            bundles,
            nodes,
            users,
            variables,
            audit,
            keys,
            notifier,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use broker_auth::totp;
    use broker_core::authz::Role;
    use broker_core::injection::InjectedHeaders;
    use broker_core::protocol::{AuditBatch, EnrollRequest};
    use broker_core::seal::{encode_public_key, open, SealPublicKey, SealSecretKey};
    use broker_core::snapshot::{decode_verifying_key, rule_aad};
    use rand::rngs::OsRng;

    use super::auth::{CreateApiKey, LoginRequest, SetupRequest};
    use super::policy::{CreateCredential, CreateRule, UpdateRule};
    use super::sessions::MintSession;
    use super::*;
    use crate::cipher::AesGcmCipher;
    use crate::memory::MemoryStore;
    use crate::model::PageRequest;
    use crate::store::RbacAuthorizer;
    use crate::StoreError;

    async fn plane() -> ControlPlane {
        plane_with(Arc::new(crate::probe::DisabledProber)).await
    }

    async fn plane_with(prober: Arc<dyn CredentialProber>) -> ControlPlane {
        let store = Arc::new(MemoryStore::new());
        let stores = Stores {
            credentials: store.clone(),
            policy: store.clone(),
            audit: store.clone(),
            identity: store.clone(),
            nodes: store,
        };
        let cipher = Arc::new(AesGcmCipher::new(&AesGcmCipher::generate_key()).unwrap());
        ControlPlane::new(
            stores,
            Arc::new(RbacAuthorizer),
            cipher,
            prober,
            ControlConfig::default(),
        )
        .await
        .unwrap()
    }

    fn admin(step_up_age_secs: i64) -> Caller {
        Caller {
            principal: Principal {
                kind: PrincipalKind::User,
                actor: "user:test-admin".into(),
                role: Role::Admin,
                vault: None,
            },
            step_up_at: Some(Utc::now() - chrono::Duration::seconds(step_up_age_secs)),
            second_factor: true,
        }
    }

    fn now_secs() -> u64 {
        u64::try_from(Utc::now().timestamp()).unwrap()
    }

    fn bearer(fields: &[(&str, &str)], hosts: &[&str]) -> CreateCredential {
        CreateCredential {
            name: "api".into(),
            template_id: "generic-bearer".into(),
            template_version: None,
            host_override: hosts.iter().map(|h| h.to_string()).collect(),
            fields: fields
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            custom_headers: vec![],
            substitutions: vec![],
        }
    }

    #[tokio::test]
    async fn setup_login_and_csrf() {
        let cp = plane().await;
        assert!(cp.auth.setup_required().await.unwrap());
        let token = cp.auth.issue_setup_token().await.unwrap().unwrap();
        let enrol = cp.auth.new_totp_enrollment("admin").unwrap();
        let req = |code: String, tok: &str| SetupRequest {
            setup_token: tok.to_string(),
            username: "admin".into(),
            password: "correct horse battery".into(),
            totp_secret: Some(enrol.secret.clone()),
            totp_code: Some(code),
        };
        assert!(matches!(
            cp.auth.complete_setup(req("000000".into(), &token)).await,
            Err(ControlError::Validation { .. })
        ));
        let code = totp::code_at(&enrol.secret, now_secs()).unwrap();
        assert!(matches!(
            cp.auth
                .complete_setup(req(code.clone(), "cbsetup_wrong"))
                .await,
            Err(ControlError::Unauthenticated { .. })
        ));
        cp.auth
            .complete_setup(req(code.clone(), &token))
            .await
            .unwrap();
        assert!(matches!(
            cp.auth.complete_setup(req(code.clone(), &token)).await,
            Err(ControlError::Conflict { .. })
        ));
        assert!(cp.auth.issue_setup_token().await.unwrap().is_none());

        let login = |password: &str, code: String| LoginRequest {
            username: "admin".into(),
            password: password.into(),
            totp_code: Some(code),
        };
        // The setup code's time step is spent: replaying it must fail.
        assert!(cp
            .auth
            .login(login("correct horse battery", code))
            .await
            .is_err());
        assert!(cp
            .auth
            .login(login(
                "wrong password!!",
                totp::code_at(&enrol.secret, now_secs() + 30).unwrap()
            ))
            .await
            .is_err());
        let outcome = cp
            .auth
            .login(login(
                "correct horse battery",
                totp::code_at(&enrol.secret, now_secs() + 30).unwrap(),
            ))
            .await
            .unwrap();
        let auth = cp.auth.authenticate_session(&outcome.token).await.unwrap();
        assert_eq!(auth.user.username, "admin");
        assert!(cp.auth.verify_csrf(&auth.token_hash, &outcome.csrf_token));
        assert!(!cp.auth.verify_csrf(&auth.token_hash, "forged"));
        cp.auth.logout(&auth).await.unwrap();
        assert!(cp.auth.authenticate_session(&outcome.token).await.is_err());
    }

    /// Completes first-admin setup and returns a fresh-step-up caller for it.
    async fn setup_admin(cp: &ControlPlane) -> Caller {
        let token = cp.auth.issue_setup_token().await.unwrap().unwrap();
        let enrol = cp.auth.new_totp_enrollment("admin").unwrap();
        let admin = cp
            .auth
            .complete_setup(SetupRequest {
                setup_token: token,
                username: "admin".into(),
                password: "correct horse battery".into(),
                totp_secret: Some(enrol.secret.clone()),
                totp_code: Some(totp::code_at(&enrol.secret, now_secs()).unwrap()),
            })
            .await
            .unwrap();
        Caller {
            principal: Principal {
                kind: PrincipalKind::User,
                actor: format!("user:{}", admin.id),
                role: Role::Admin,
                vault: None,
            },
            step_up_at: Some(Utc::now()),
            second_factor: true,
        }
    }

    #[tokio::test]
    async fn invited_people_get_the_offered_role_and_can_be_disabled() {
        use super::users::{AcceptInviteRequest, CreateInvite, UpdateUser};

        let cp = plane().await;
        let admin = setup_admin(&cp).await;
        let invite = |role| CreateInvite {
            role,
            expires_in_hours: None,
        };
        let stale = Caller {
            step_up_at: Some(Utc::now() - chrono::Duration::seconds(3600)),
            ..admin.clone()
        };
        assert!(matches!(
            cp.users.create_invite(&stale, invite(Role::Editor)).await,
            Err(ControlError::StepUpRequired { .. })
        ));
        assert!(matches!(
            cp.users
                .create_invite(&admin, invite(Role::SessionIssuer))
                .await,
            Err(ControlError::Validation { .. })
        ));
        assert!(matches!(
            cp.users
                .create_invite(
                    &admin,
                    CreateInvite {
                        role: Role::Viewer,
                        expires_in_hours: Some(24 * 30),
                    }
                )
                .await,
            Err(ControlError::Validation { .. })
        ));

        let issued = cp
            .users
            .create_invite(&admin, invite(Role::Editor))
            .await
            .unwrap();
        assert!(issued.token.starts_with("cbinv_"));
        let info = cp.users.inspect_invite(&issued.token).await.unwrap();
        assert_eq!(info.role, Role::Editor);
        assert!(cp.users.inspect_invite("cbinv_unknown").await.is_err());

        let enrol = cp.users.invite_totp(&issued.token, "bob").await.unwrap();
        let accept = |code: String| AcceptInviteRequest {
            invite_token: issued.token.clone(),
            username: "bob".into(),
            password: "a different long password".into(),
            totp_secret: Some(enrol.secret.clone()),
            totp_code: Some(code),
        };
        assert!(matches!(
            cp.users.accept_invite(accept("000000".into())).await,
            Err(ControlError::Validation { .. })
        ));
        // The previous step is still accepted; using it leaves the current
        // and next steps for the logins below.
        let bob = cp
            .users
            .accept_invite(accept(
                totp::code_at(&enrol.secret, now_secs() - 30).unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(bob.role, Role::Editor);
        assert!(matches!(
            cp.users
                .accept_invite(accept(totp::code_at(&enrol.secret, now_secs()).unwrap()))
                .await,
            Err(ControlError::Unauthenticated { .. })
        ));

        let login = |offset: u64| LoginRequest {
            username: "bob".into(),
            password: "a different long password".into(),
            totp_code: Some(totp::code_at(&enrol.secret, now_secs() + offset).unwrap()),
        };
        let session = cp.auth.login(login(0)).await.unwrap();
        let bob_caller = cp
            .auth
            .authenticate_session(&session.token)
            .await
            .unwrap()
            .caller;
        assert_eq!(bob_caller.principal.role, Role::Editor);
        assert!(matches!(
            cp.users
                .list_users(&bob_caller, PageRequest::default())
                .await,
            Err(ControlError::Forbidden { .. })
        ));
        assert!(matches!(
            cp.users
                .create_invite(&bob_caller, invite(Role::Admin))
                .await,
            Err(ControlError::Forbidden { .. })
        ));

        let admin_id: broker_core::ids::UserId =
            admin.actor().trim_start_matches("user:").parse().unwrap();
        let disable = UpdateUser {
            role: None,
            disabled: Some(true),
        };
        assert!(matches!(
            cp.users
                .update_user(&admin, &admin_id, disable.clone())
                .await,
            Err(ControlError::Validation { .. })
        ));
        assert!(matches!(
            cp.users
                .update_user(
                    &admin,
                    &admin_id,
                    UpdateUser {
                        role: Some(Role::Viewer),
                        disabled: None,
                    }
                )
                .await,
            Err(ControlError::Conflict { .. })
        ));

        let updated = cp
            .users
            .update_user(&admin, &bob.id, disable)
            .await
            .unwrap();
        assert!(updated.disabled_at.is_some());
        assert!(cp.auth.authenticate_session(&session.token).await.is_err());
        // Refused before the TOTP code is checked, so the step stays unused.
        assert!(cp.auth.login(login(30)).await.is_err());
        cp.users
            .update_user(
                &admin,
                &bob.id,
                UpdateUser {
                    role: Some(Role::Viewer),
                    disabled: Some(false),
                },
            )
            .await
            .unwrap();
        let session = cp.auth.login(login(30)).await.unwrap();
        let auth = cp.auth.authenticate_session(&session.token).await.unwrap();
        assert_eq!(auth.user.role, Role::Viewer);

        let users = cp
            .users
            .list_users(&admin, PageRequest::default())
            .await
            .unwrap();
        assert_eq!(users.total, 2);
        let invites = cp
            .users
            .list_invites(&admin, PageRequest::default())
            .await
            .unwrap();
        assert_eq!(invites.items[0].accepted_by, Some(bob.id));

        let actions: Vec<String> = cp
            .audit
            .query(&admin, None, Some("user.".into()), PageRequest::default())
            .await
            .unwrap()
            .items
            .into_iter()
            .map(|e| e.action)
            .collect();
        for expected in ["user.invite", "user.invite.accept", "user.update"] {
            assert!(
                actions.iter().any(|a| a == expected),
                "missing audit action {expected} in {actions:?}"
            );
        }
    }

    #[tokio::test]
    async fn revoked_invites_cannot_be_accepted() {
        use super::users::CreateInvite;

        let cp = plane().await;
        let admin = setup_admin(&cp).await;
        let issued = cp
            .users
            .create_invite(
                &admin,
                CreateInvite {
                    role: Role::Viewer,
                    expires_in_hours: Some(1),
                },
            )
            .await
            .unwrap();
        cp.users
            .revoke_invite(&admin, &issued.invite.id)
            .await
            .unwrap();
        assert!(matches!(
            cp.users.inspect_invite(&issued.token).await,
            Err(ControlError::Unauthenticated { .. })
        ));
        assert!(cp.users.invite_totp(&issued.token, "carol").await.is_err());
    }

    #[tokio::test]
    async fn password_only_accounts_sign_in_and_step_up_with_the_password() {
        use super::auth::StepUpProof;

        let cp = plane().await;
        let token = cp.auth.issue_setup_token().await.unwrap().unwrap();
        let setup = |secret: Option<String>, code: Option<String>| SetupRequest {
            setup_token: token.clone(),
            username: "admin".into(),
            password: "correct horse battery".into(),
            totp_secret: secret,
            totp_code: code,
        };
        // Half an enrolment is refused rather than silently dropped.
        assert!(matches!(
            cp.auth
                .complete_setup(setup(Some(totp::generate_secret()), None))
                .await,
            Err(ControlError::Validation { .. })
        ));
        let admin = cp.auth.complete_setup(setup(None, None)).await.unwrap();
        assert!(!admin.totp_enrolled);

        let login = |password: &str| LoginRequest {
            username: "admin".into(),
            password: password.into(),
            totp_code: None,
        };
        assert!(cp.auth.login(login("not the password")).await.is_err());
        let outcome = cp.auth.login(login("correct horse battery")).await.unwrap();
        assert!(!outcome.user.totp_enrolled);
        let auth = cp.auth.authenticate_session(&outcome.token).await.unwrap();

        let proof = |code: Option<&str>, password: Option<&str>| StepUpProof {
            code: code.map(str::to_string),
            password: password.map(str::to_string),
        };
        assert!(cp
            .auth
            .step_up(&auth, &proof(None, Some("not the password")))
            .await
            .is_err());
        assert!(cp
            .auth
            .step_up(&auth, &proof(Some("123456"), None))
            .await
            .is_err());
        cp.auth
            .step_up(&auth, &proof(None, Some("correct horse battery")))
            .await
            .unwrap();

        // Sensitive actions are not gated on a step-up the account cannot
        // give with anything but the password it signed in with.
        assert!(!auth.caller.second_factor);
        let long_ago = Caller {
            step_up_at: Some(Utc::now() - chrono::Duration::seconds(3600)),
            ..auth.caller.clone()
        };
        cp.users
            .create_invite(
                &long_ago,
                super::users::CreateInvite {
                    role: Role::Editor,
                    expires_in_hours: None,
                },
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn enrolled_accounts_cannot_skip_the_code() {
        use super::auth::StepUpProof;

        let cp = plane().await;
        let token = cp.auth.issue_setup_token().await.unwrap().unwrap();
        let enrol = cp.auth.new_totp_enrollment("admin").unwrap();
        let admin = cp
            .auth
            .complete_setup(SetupRequest {
                setup_token: token,
                username: "admin".into(),
                password: "correct horse battery".into(),
                totp_secret: Some(enrol.secret.clone()),
                totp_code: Some(totp::code_at(&enrol.secret, now_secs()).unwrap()),
            })
            .await
            .unwrap();
        assert!(admin.totp_enrolled);
        let without_code = LoginRequest {
            username: "admin".into(),
            password: "correct horse battery".into(),
            totp_code: None,
        };
        assert!(cp.auth.login(without_code.clone()).await.is_err());
        let outcome = cp
            .auth
            .login(LoginRequest {
                totp_code: Some(totp::code_at(&enrol.secret, now_secs() + 30).unwrap()),
                ..without_code
            })
            .await
            .unwrap();
        let auth = cp.auth.authenticate_session(&outcome.token).await.unwrap();
        assert!(auth.caller.second_factor);
        let long_ago = Caller {
            step_up_at: Some(Utc::now() - chrono::Duration::seconds(3600)),
            ..auth.caller.clone()
        };
        assert!(matches!(
            cp.users
                .create_invite(
                    &long_ago,
                    super::users::CreateInvite {
                        role: Role::Editor,
                        expires_in_hours: None,
                    },
                )
                .await,
            Err(ControlError::StepUpRequired { .. })
        ));
        // The password must not stand in for the second factor.
        assert!(cp
            .auth
            .step_up(
                &auth,
                &StepUpProof {
                    code: None,
                    password: Some("correct horse battery".into()),
                }
            )
            .await
            .is_err());
    }

    #[tokio::test]
    async fn login_is_rate_limited() {
        let cp = plane().await;
        for _ in 0..5 {
            let _ = cp
                .auth
                .login(LoginRequest {
                    username: "nobody".into(),
                    password: "whatever-password".into(),
                    totp_code: Some("123456".into()),
                })
                .await;
        }
        let res = cp
            .auth
            .login(LoginRequest {
                username: "nobody".into(),
                password: "whatever-password".into(),
                totp_code: Some("123456".into()),
            })
            .await;
        assert!(matches!(res, Err(ControlError::RateLimited { .. })));
    }

    #[tokio::test]
    async fn credential_writes_need_fresh_step_up_and_stay_write_only() {
        let cp = plane().await;
        let vault = cp.policy.create_vault(&admin(0), "main").await.unwrap();
        let stale = admin(3600);
        let res = cp
            .policy
            .create_credential(
                &stale,
                &vault.id,
                bearer(&[("token", "s3cr3t-value")], &["api.example.com"]),
            )
            .await;
        assert!(matches!(res, Err(ControlError::StepUpRequired { .. })));

        let meta = cp
            .policy
            .create_credential(
                &admin(0),
                &vault.id,
                bearer(&[("token", "s3cr3t-value")], &["api.example.com"]),
            )
            .await
            .unwrap();
        let listed = cp
            .policy
            .list_credentials(&admin(0), &vault.id, PageRequest::default())
            .await
            .unwrap();
        for json in [
            serde_json::to_string(&meta).unwrap(),
            serde_json::to_string(&listed).unwrap(),
        ] {
            assert!(!json.contains("s3cr3t-value"));
        }
        let audit = cp
            .audit
            .query(&admin(0), None, None, PageRequest::default())
            .await
            .unwrap();
        assert!(!serde_json::to_string(&audit)
            .unwrap()
            .contains("s3cr3t-value"));
        assert!(audit.items.iter().any(|e| e.action == "credential.create"
            && e.detail.get("widened").map(String::as_str) == Some("true")));
    }

    #[tokio::test]
    async fn templates_cap_scope() {
        let cp = plane().await;
        let a = admin(0);
        let vault = cp.policy.create_vault(&a, "main").await.unwrap();
        let mut github = bearer(&[("token", "t")], &["api.example.com"]);
        github.template_id = "github".into();
        assert!(matches!(
            cp.policy
                .create_credential(&a, &vault.id, github.clone())
                .await,
            Err(ControlError::Core(broker_core::CoreError::Widening { .. }))
        ));
        github.host_override.clear();
        let cred = cp
            .policy
            .create_credential(&a, &vault.id, github)
            .await
            .unwrap();
        let rule = |hosts: Option<Vec<String>>, paths: Option<Vec<String>>| CreateRule {
            name: "r".into(),
            credential_id: cred.id,
            hosts,
            paths,
            methods: Some(vec!["GET".into()]),
        };
        assert!(cp
            .policy
            .create_rule(
                &a,
                &vault.id,
                rule(Some(vec!["evil.example.com".into()]), None)
            )
            .await
            .is_err());
        let created = cp
            .policy
            .create_rule(&a, &vault.id, rule(None, Some(vec!["/repos/*".into()])))
            .await
            .unwrap();
        assert_eq!(created.allow.hosts[0].host(), "api.github.com");

        let stale = admin(3600);
        let narrowed = cp
            .policy
            .update_rule(
                &stale,
                &created.id,
                UpdateRule {
                    paths: Some(vec!["/repos/a/*".into()]),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(narrowed.allow.paths[0].as_str(), "/repos/a/*");
        let widen = cp
            .policy
            .update_rule(
                &stale,
                &created.id,
                UpdateRule {
                    paths: Some(vec!["/*".into()]),
                    ..Default::default()
                },
            )
            .await;
        assert!(matches!(widen, Err(ControlError::StepUpRequired { .. })));
        assert!(matches!(
            cp.policy.delete_credential(&a, &cred.id).await,
            Err(ControlError::Conflict { .. })
        ));
    }

    #[tokio::test]
    async fn sessions_mint_from_an_access_bundle_by_name() {
        use crate::service::bundles::{CreateBundle, UpdateBundle};

        let cp = plane().await;
        let a = admin(0);
        let vault = cp.policy.create_vault(&a, "main").await.unwrap();
        let other = cp.policy.create_vault(&a, "other").await.unwrap();
        let cred = cp
            .policy
            .create_credential(
                &a,
                &vault.id,
                bearer(&[("token", "t")], &["api.example.com"]),
            )
            .await
            .unwrap();
        let mut rules = Vec::new();
        for name in ["read", "write"] {
            let rule = cp
                .policy
                .create_rule(
                    &a,
                    &vault.id,
                    CreateRule {
                        name: name.into(),
                        credential_id: cred.id,
                        hosts: None,
                        paths: None,
                        methods: None,
                    },
                )
                .await
                .unwrap();
            rules.push(rule);
        }
        let bundle = cp
            .bundles
            .create(
                &a,
                &vault.id,
                CreateBundle {
                    name: "code-review".into(),
                    description: "GitHub for reviews".into(),
                    rule_ids: vec![rules[1].id, rules[0].id, rules[0].id],
                },
            )
            .await
            .unwrap();
        let mut expected = vec![rules[0].id, rules[1].id];
        expected.sort();
        assert_eq!(bundle.rule_ids, expected, "sorted and deduplicated");

        // A session_issuer key mints by name without reading the bundle.
        let (plaintext, _) = cp
            .auth
            .create_api_key(
                &a,
                CreateApiKey {
                    name: "launcher".into(),
                    vault_id: vault.id,
                    role: Role::SessionIssuer,
                    expires_in_days: 30,
                },
            )
            .await
            .unwrap();
        let key = cp.auth.authenticate_api_key(&plaintext).await.unwrap();
        let by_bundle = |bundle: &str| MintSession {
            rule_ids: vec![],
            bundle: Some(bundle.into()),
            ttl_secs: Some(600),
            request_limit: None,
            labels: BTreeMap::new(),
        };
        let minted = cp
            .sessions
            .mint(&key, &vault.id, by_bundle("code-review"))
            .await
            .unwrap();
        assert_eq!(minted.session.rule_ids, expected);
        let reference = minted.session.bundle.clone().unwrap();
        assert_eq!(
            (reference.id, reference.name.as_str()),
            (bundle.id, "code-review")
        );
        // By id works too.
        cp.sessions
            .mint(&key, &vault.id, by_bundle(&bundle.id.to_string()))
            .await
            .unwrap();

        // Disabled rules are skipped, and a bundle with none left refuses.
        for (i, rule) in rules.iter().enumerate() {
            cp.policy
                .update_rule(
                    &a,
                    &rule.id,
                    UpdateRule {
                        enabled: Some(false),
                        ..UpdateRule::default()
                    },
                )
                .await
                .unwrap();
            let result = cp
                .sessions
                .mint(&key, &vault.id, by_bundle("code-review"))
                .await;
            if i == 0 {
                assert_eq!(result.unwrap().session.rule_ids, vec![rules[1].id]);
            } else {
                let err = result.unwrap_err().to_string();
                assert!(err.contains("has no enabled rules"), "{err}");
            }
        }

        let both = MintSession {
            rule_ids: vec![rules[0].id],
            ..by_bundle("code-review")
        };
        assert!(matches!(
            cp.sessions.mint(&a, &vault.id, both).await,
            Err(ControlError::Validation { .. })
        ));
        let err = cp
            .sessions
            .mint(&a, &vault.id, by_bundle("missing"))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("'missing' in vault"), "{err}");
        // A bundle id from another vault is not found there.
        assert!(matches!(
            cp.sessions
                .mint(&a, &other.id, by_bundle(&bundle.id.to_string()))
                .await,
            Err(ControlError::NotFound { .. })
        ));

        // Only editors and admins manage bundles.
        assert!(matches!(
            cp.bundles
                .create(
                    &key,
                    &vault.id,
                    CreateBundle {
                        name: "mine".into(),
                        description: String::new(),
                        rule_ids: vec![],
                    },
                )
                .await,
            Err(ControlError::Forbidden { .. })
        ));
        // Rules from another vault cannot be bundled.
        let foreign = cp
            .bundles
            .create(
                &a,
                &other.id,
                CreateBundle {
                    name: "x".into(),
                    description: String::new(),
                    rule_ids: vec![rules[0].id],
                },
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(foreign.contains("belongs to vault"), "{foreign}");
        // Names are unique per vault.
        assert!(matches!(
            cp.bundles
                .create(
                    &a,
                    &vault.id,
                    CreateBundle {
                        name: "code-review".into(),
                        description: String::new(),
                        rule_ids: vec![],
                    },
                )
                .await,
            Err(ControlError::Store(StoreError::Conflict { .. }))
        ));

        // Deleting a rule takes it out of the bundle.
        cp.policy.delete_rule(&a, &rules[0].id).await.unwrap();
        let after = cp.bundles.get(&a, &bundle.id).await.unwrap();
        assert_eq!(after.rule_ids, vec![rules[1].id]);
        let renamed = cp
            .bundles
            .update(
                &a,
                &bundle.id,
                UpdateBundle {
                    name: Some("review".into()),
                    ..UpdateBundle::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(renamed.rule_ids, vec![rules[1].id]);
        cp.bundles.delete(&a, &bundle.id).await.unwrap();
        assert!(cp
            .bundles
            .list(&a, &vault.id, PageRequest::new(None, None))
            .await
            .unwrap()
            .items
            .is_empty());
    }

    #[tokio::test]
    async fn api_keys_are_vault_bound_and_cannot_step_up() {
        let cp = plane().await;
        let a = admin(0);
        let vault = cp.policy.create_vault(&a, "main").await.unwrap();
        let other = cp.policy.create_vault(&a, "other").await.unwrap();
        let cred = cp
            .policy
            .create_credential(
                &a,
                &vault.id,
                bearer(&[("token", "t")], &["api.example.com"]),
            )
            .await
            .unwrap();
        let rule = cp
            .policy
            .create_rule(
                &a,
                &vault.id,
                CreateRule {
                    name: "r".into(),
                    credential_id: cred.id,
                    hosts: None,
                    paths: None,
                    methods: None,
                },
            )
            .await
            .unwrap();
        let (plaintext, record) = cp
            .auth
            .create_api_key(
                &a,
                CreateApiKey {
                    name: "ci".into(),
                    vault_id: vault.id,
                    role: Role::SessionIssuer,
                    expires_in_days: 30,
                },
            )
            .await
            .unwrap();
        assert!(plaintext.starts_with(&record.prefix));
        assert!(!serde_json::to_string(&record).unwrap().contains(&plaintext));
        let key = cp.auth.authenticate_api_key(&plaintext).await.unwrap();
        let minted = cp
            .sessions
            .mint(
                &key,
                &vault.id,
                MintSession {
                    rule_ids: vec![rule.id],
                    bundle: None,
                    ttl_secs: None,
                    request_limit: None,
                    labels: BTreeMap::new(),
                },
            )
            .await
            .unwrap();
        assert!(minted.token.starts_with("v4.public."));
        assert!(matches!(
            cp.sessions
                .mint(
                    &key,
                    &other.id,
                    MintSession {
                        rule_ids: vec![rule.id],
                        bundle: None,
                        ttl_secs: None,
                        request_limit: None,
                        labels: BTreeMap::new(),
                    },
                )
                .await,
            Err(ControlError::Forbidden { .. })
        ));
        assert!(matches!(
            cp.policy
                .create_credential(&key, &vault.id, bearer(&[("token", "t")], &[]))
                .await,
            Err(ControlError::Forbidden { .. })
        ));
        cp.auth.revoke_api_key(&a, &record.id).await.unwrap();
        assert!(cp.auth.authenticate_api_key(&plaintext).await.is_err());
    }

    #[tokio::test]
    async fn enrolment_and_sealed_snapshot() {
        let cp = plane().await;
        let a = admin(0);
        let vault = cp.policy.create_vault(&a, "main").await.unwrap();
        let cred = cp
            .policy
            .create_credential(
                &a,
                &vault.id,
                bearer(&[("token", "injected-secret")], &["localhost:8443"]),
            )
            .await
            .unwrap();
        let rule = cp
            .policy
            .create_rule(
                &a,
                &vault.id,
                CreateRule {
                    name: "r".into(),
                    credential_id: cred.id,
                    hosts: None,
                    paths: None,
                    methods: None,
                },
            )
            .await
            .unwrap();
        let join = cp.nodes.create_join_token(&a, None).await.unwrap();
        let tls_key = rcgen::KeyPair::generate().unwrap();
        let csr = rcgen::CertificateParams::new(Vec::<String>::new())
            .unwrap()
            .serialize_request(&tls_key)
            .unwrap()
            .pem()
            .unwrap();
        let seal_secret = SealSecretKey::random_from_rng(OsRng);
        let request = EnrollRequest {
            join_token: join.token.clone(),
            node_name: "node-a".into(),
            csr_pem: csr,
            seal_public_key: encode_public_key(&SealPublicKey::from(&seal_secret)),
        };
        let enrolled = cp.nodes.enroll(request.clone()).await.unwrap();
        assert!(matches!(
            cp.nodes.enroll(request).await,
            Err(ControlError::Unauthenticated { .. })
        ));
        let node = cp.nodes.authenticate(&enrolled.node_id).await.unwrap();
        let verify = decode_verifying_key(&enrolled.snapshot_verify_key).unwrap();

        let first = cp
            .nodes
            .build_snapshot(&node)
            .await
            .unwrap()
            .verify(&verify)
            .unwrap();
        assert_eq!(first.rules.len(), 1);
        let sealed = &first.rules[0];
        let plaintext = open(
            &seal_secret,
            &sealed.headers,
            &rule_aad(&node.id, &rule.id, &cred.id),
        )
        .unwrap();
        let headers: InjectedHeaders = serde_json::from_slice(&plaintext).unwrap();
        assert_eq!(headers.headers[0].value, "Bearer injected-secret");
        assert!(!first_contains(&first, "injected-secret"));

        let minted = cp
            .sessions
            .mint(
                &a,
                &vault.id,
                MintSession {
                    rule_ids: vec![rule.id],
                    bundle: None,
                    ttl_secs: Some(60),
                    request_limit: Some(3),
                    labels: BTreeMap::new(),
                },
            )
            .await
            .unwrap();
        cp.sessions.revoke(&a, &minted.session.id).await.unwrap();
        let second = cp
            .nodes
            .build_snapshot(&node)
            .await
            .unwrap()
            .verify(&verify)
            .unwrap();
        assert!(second.version > first.version);
        assert_eq!(second.revoked_sessions, vec![minted.session.id]);
        assert!(second.limited_sessions.is_empty());

        cp.nodes.revoke_node(&a, &node.id).await.unwrap();
        assert!(cp.nodes.authenticate(&node.id).await.is_err());
    }

    /// The plaintext (or its base64) must never appear in a snapshot body.
    fn first_contains(body: &broker_core::snapshot::SnapshotBody, needle: &str) -> bool {
        let json = serde_json::to_string(body).unwrap();
        json.contains(needle) || json.contains(&STANDARD.encode(needle))
    }

    #[tokio::test]
    async fn node_audit_cannot_forge_control_plane_events() {
        let cp = plane().await;
        let node = crate::model::Node {
            id: broker_core::ids::NodeId::new(),
            name: "n".into(),
            seal_public_key: String::new(),
            cert_serial: String::new(),
            cert_not_after: Utc::now(),
            enrolled_at: Utc::now(),
            last_seen_at: None,
            revoked_at: None,
        };
        let forged = AuditEvent::new(
            "user:someone",
            "credential.delete",
            broker_core::audit::AuditOutcome::Success,
        );
        assert!(cp
            .nodes
            .ingest_audit(
                &node,
                AuditBatch {
                    events: vec![forged]
                }
            )
            .await
            .is_err());
        let vault = broker_core::ids::VaultId::new();
        let ok = AuditEvent::new(
            "user:someone",
            "proxy.inject",
            broker_core::audit::AuditOutcome::Success,
        )
        .detail("scope", format!("vault:{vault}"));
        cp.nodes
            .ingest_audit(&node, AuditBatch { events: vec![ok] })
            .await
            .unwrap();
        let page = cp
            .audit
            .query(
                &admin(0),
                Some(vault),
                Some("proxy.".into()),
                PageRequest::default(),
            )
            .await
            .unwrap();
        assert_eq!(page.items[0].actor, format!("node:{}", node.id));
    }

    /// host, port, method, path, injected headers
    type SeenProbe = (String, u16, String, String, Vec<(String, String)>);

    /// Records what it was asked to send and answers with a fixed status.
    struct RecordingProber {
        status: u16,
        seen: std::sync::Mutex<Vec<SeenProbe>>,
    }

    #[async_trait::async_trait]
    impl CredentialProber for RecordingProber {
        async fn probe(
            &self,
            request: crate::probe::ProbeRequest,
            egress: &broker_core::egress::EgressPolicy,
        ) -> Result<u16, crate::probe::ProbeError> {
            assert!(
                egress.block_private,
                "default egress policy must be passed through"
            );
            self.seen.lock().unwrap().push((
                request.host,
                request.port,
                request.method,
                request.path,
                request
                    .headers
                    .headers
                    .iter()
                    .map(|h| (h.name.clone(), h.value.clone()))
                    .collect(),
            ));
            Ok(self.status)
        }
    }

    fn openai(key: &str) -> CreateCredential {
        CreateCredential {
            name: "models".into(),
            template_id: "openai".into(),
            template_version: None,
            host_override: vec![],
            fields: [("api_key".to_string(), key.to_string())].into(),
            custom_headers: vec![],
            substitutions: vec![],
        }
    }

    #[tokio::test]
    async fn substitutions_name_existing_fields_and_are_audited_by_placeholder() {
        use broker_core::substitution::{Substitution, SubstitutionLocation};
        let cp = plane().await;
        let a = admin(0);
        let vault = cp.policy.create_vault(&a, "main").await.unwrap();
        let sub = |field: &str| Substitution {
            placeholder: "__OPENAI_KEY__".into(),
            field: field.into(),
            env: Some("OPENAI_API_KEY".into()),
            locations: vec![SubstitutionLocation::Header],
        };
        let mut req = openai("sk-substituted");
        req.substitutions = vec![sub("password")];
        let err = cp
            .policy
            .create_credential(&a, &vault.id, req.clone())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("field 'password'"), "{err}");

        req.substitutions = vec![sub("api_key")];
        let meta = cp
            .policy
            .create_credential(&a, &vault.id, req)
            .await
            .unwrap();
        assert_eq!(meta.substitutions, vec![sub("api_key")]);
        assert!(!serde_json::to_string(&meta)
            .unwrap()
            .contains("sk-substituted"));

        let cleared = cp
            .policy
            .update_substitutions(&a, &meta.id, vec![])
            .await
            .unwrap();
        assert!(cleared.substitutions.is_empty());
        let missing = cp
            .policy
            .update_substitutions(&a, &broker_core::ids::CredentialId::new(), vec![])
            .await;
        assert!(matches!(missing, Err(ControlError::NotFound { .. })));

        let events = cp
            .audit
            .query(&a, Some(vault.id), None, PageRequest::default())
            .await
            .unwrap()
            .items;
        let update = events
            .iter()
            .find(|e| e.action == "credential.update_substitutions")
            .unwrap();
        assert_eq!(
            update.detail.get("substitutions").map(String::as_str),
            Some("none")
        );
        let create = events
            .iter()
            .find(|e| e.action == "credential.create")
            .unwrap();
        assert_eq!(
            create.detail.get("substitutions").map(String::as_str),
            Some("__OPENAI_KEY__")
        );
    }

    #[tokio::test]
    async fn validation_sends_the_declared_request_to_the_credential_host_only() {
        let prober = Arc::new(RecordingProber {
            status: 200,
            seen: Default::default(),
        });
        let cp = plane_with(prober.clone()).await;
        let vault = cp.policy.create_vault(&admin(0), "main").await.unwrap();
        let meta = cp
            .policy
            .create_credential(&admin(0), &vault.id, openai("sk-validate-me"))
            .await
            .unwrap();
        let result = cp
            .policy
            .validate_credential(&admin(0), &meta.id)
            .await
            .unwrap();
        assert!(result.ok, "{result:?}");
        assert_eq!(result.status, Some(200));
        assert!(!serde_json::to_string(&result)
            .unwrap()
            .contains("sk-validate-me"));
        let seen = prober.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        let (host, port, method, path, headers) = &seen[0];
        assert_eq!((host.as_str(), *port), ("api.openai.com", 443));
        assert_eq!((method.as_str(), path.as_str()), ("GET", "/v1/models"));
        assert_eq!(
            headers,
            &vec![(
                "authorization".to_string(),
                "Bearer sk-validate-me".to_string()
            )]
        );
        let audit = cp
            .audit
            .query(
                &admin(0),
                None,
                Some("credential.validate".into()),
                PageRequest::default(),
            )
            .await
            .unwrap();
        assert_eq!(audit.items.len(), 1);
        assert!(!serde_json::to_string(&audit)
            .unwrap()
            .contains("sk-validate-me"));

        // Validation exposes the secret to its own host, so it needs step-up.
        let stale = cp.policy.validate_credential(&admin(3600), &meta.id).await;
        assert!(matches!(stale, Err(ControlError::StepUpRequired { .. })));
    }

    #[tokio::test]
    async fn variables_fill_fields_and_custom_headers_and_stay_write_only() {
        use super::variables::{CreateVariable, SecretValue};
        use broker_core::variables::CustomHeader;
        let prober = Arc::new(RecordingProber {
            status: 200,
            seen: Default::default(),
        });
        let cp = plane_with(prober.clone()).await;
        let a = admin(0);
        let vault = cp.policy.create_vault(&a, "main").await.unwrap();
        let key = cp
            .variables
            .create(
                &a,
                CreateVariable {
                    key: "OPENAI_KEY".into(),
                    value: SecretValue::from("sk-from-variable".to_string()),
                },
            )
            .await
            .unwrap();
        cp.variables
            .create(
                &a,
                CreateVariable {
                    key: "ORG".into(),
                    value: SecretValue::from("acme-test".to_string()),
                },
            )
            .await
            .unwrap();
        let duplicate = cp
            .variables
            .create(
                &a,
                CreateVariable {
                    key: "ORG".into(),
                    value: SecretValue::from("x".to_string()),
                },
            )
            .await;
        assert!(matches!(duplicate, Err(ControlError::Conflict { .. })));

        let header = |name: &str, value: &str| CustomHeader {
            name: name.into(),
            value: value.into(),
        };
        let mut req = openai("{{OPENAI_KEY}}");
        req.custom_headers = vec![header("OpenAI-Organization", "org-{{ ORG }}")];
        let meta = cp
            .policy
            .create_credential(&a, &vault.id, req)
            .await
            .unwrap();
        assert_eq!(meta.variable_refs, ["OPENAI_KEY", "ORG"]);

        cp.policy.validate_credential(&a, &meta.id).await.unwrap();
        let sent = prober.seen.lock().unwrap()[0].4.clone();
        assert_eq!(
            sent,
            vec![
                ("authorization".into(), "Bearer sk-from-variable".into()),
                ("openai-organization".into(), "org-acme-test".into()),
            ]
        );

        // Replacing the value reaches every credential that uses it.
        cp.variables
            .replace_value(&a, &key.id, SecretValue::from("sk-rotated".to_string()))
            .await
            .unwrap();
        cp.policy.validate_credential(&a, &meta.id).await.unwrap();
        let sent = prober.seen.lock().unwrap()[1].4.clone();
        assert_eq!(sent[0].1, "Bearer sk-rotated");

        // The list shows where a variable is used, never its value.
        let listed = cp.variables.list(&a, PageRequest::default()).await.unwrap();
        let json = serde_json::to_string(&listed).unwrap();
        assert!(!json.contains("sk-rotated") && !json.contains("acme-test"));
        let used = &listed
            .items
            .iter()
            .find(|v| v.key == "OPENAI_KEY")
            .unwrap()
            .used_by;
        assert_eq!(used.len(), 1);
        assert_eq!(used[0].vault_name, "main");

        // In use: cannot be deleted until the reference goes.
        let in_use = cp.variables.delete(&a, &key.id).await;
        assert!(
            matches!(in_use, Err(ControlError::Conflict { .. })),
            "{in_use:?}"
        );

        // Unknown references and shadowing headers are refused up front.
        let unknown = cp
            .policy
            .create_credential(&a, &vault.id, openai("{{NOPE}}"))
            .await;
        assert!(
            matches!(&unknown, Err(ControlError::Validation { message }) if message.contains("NOPE")),
            "{unknown:?}"
        );
        let shadow = cp
            .policy
            .update_custom_headers(&a, &meta.id, vec![header("Authorization", "x")])
            .await;
        assert!(matches!(shadow, Err(ControlError::Core(_))), "{shadow:?}");

        let cleared = cp
            .policy
            .update_custom_headers(&a, &meta.id, vec![])
            .await
            .unwrap();
        assert_eq!(cleared.variable_refs, ["OPENAI_KEY"]);
        let org = listed.items.iter().find(|v| v.key == "ORG").unwrap();
        cp.variables.delete(&a, &org.id).await.unwrap();

        // Managing variables is an admin task.
        let mut viewer = admin(0);
        viewer.principal.role = Role::Viewer;
        assert!(matches!(
            cp.variables.list(&viewer, PageRequest::default()).await,
            Err(ControlError::Forbidden { .. })
        ));
    }

    #[tokio::test]
    async fn validation_reports_unexpected_status_and_missing_declarations() {
        let cp = plane_with(Arc::new(RecordingProber {
            status: 401,
            seen: Default::default(),
        }))
        .await;
        let vault = cp.policy.create_vault(&admin(0), "main").await.unwrap();
        let meta = cp
            .policy
            .create_credential(&admin(0), &vault.id, openai("sk-revoked"))
            .await
            .unwrap();
        let result = cp
            .policy
            .validate_credential(&admin(0), &meta.id)
            .await
            .unwrap();
        assert!(!result.ok);
        assert_eq!(result.status, Some(401));

        let generic = cp
            .policy
            .create_credential(
                &admin(0),
                &vault.id,
                bearer(&[("token", "t")], &["api.example.com"]),
            )
            .await
            .unwrap();
        let res = cp.policy.validate_credential(&admin(0), &generic.id).await;
        assert!(
            matches!(res, Err(ControlError::Validation { .. })),
            "{res:?}"
        );
    }

    #[tokio::test]
    async fn validation_without_a_prober_explains_itself() {
        let cp = plane().await;
        let vault = cp.policy.create_vault(&admin(0), "main").await.unwrap();
        let meta = cp
            .policy
            .create_credential(&admin(0), &vault.id, openai("sk-x"))
            .await
            .unwrap();
        let result = cp
            .policy
            .validate_credential(&admin(0), &meta.id)
            .await
            .unwrap();
        assert!(!result.ok);
        assert!(result.detail.contains("not available"), "{}", result.detail);
    }
}
