// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Least privilege end to end on the control plane: people act inside a
//! vault only with their role there, instance admins oversee vaults until
//! they join, `tokenless login` sign-ins only start sessions and runners
//! only start them from bundles.

use std::sync::Arc;

use chrono::{Duration, Utc};
use tokenless_core::authz::Role;
use tokenless_core::ids::VaultId;

use super::*;
use crate::cipher::AesGcmCipher;
use crate::envelope::Envelope;
use crate::memory::MemoryStore;
use crate::model::{AuditQuery, SessionListing, SignInScope};
use crate::service::auth::{CreateApiKey, LoginRequest};
use crate::service::bundles::CreateBundle;
use crate::service::policy::{CreateCredential, CreateRule};
use crate::service::sessions::MintSession;
use crate::service::testing::{enrol, join, person_caller};
use crate::service::users::{AcceptInviteRequest, CreateInvite};
use crate::store::RbacAuthorizer;
use crate::{ControlConfig, ControlPlane, Stores};

struct T {
    store: Arc<MemoryStore>,
    cp: ControlPlane,
    team: VaultId,
    private: VaultId,
}

fn admin() -> Caller {
    person_caller("admin", Role::Admin)
}

fn bob() -> Caller {
    person_caller("bob", Role::Member)
}

fn page() -> PageRequest {
    PageRequest::new(None, None)
}

/// Two vaults the admin created, so administers; bob is in neither.
async fn setup() -> T {
    let store = Arc::new(MemoryStore::new());
    let cipher = Arc::new(
        Envelope::open(&AesGcmCipher::generate_key(), store.clone())
            .await
            .unwrap(),
    );
    let cp = ControlPlane::new(
        Stores {
            credentials: store.clone(),
            policy: store.clone(),
            audit: store.clone(),
            identity: store.clone(),
            sso: store.clone(),
            audit_export: store.clone(),
            nodes: store.clone(),
            alerts: store.clone(),
            tripwires: store.clone(),
            members: store.clone(),
        },
        Arc::new(RbacAuthorizer),
        cipher,
        Arc::new(crate::probe::DisabledProber),
        Arc::new(crate::service::sso::oidc::NoTransport),
        Arc::new(crate::service::audit_export::DisabledWebhookTransport),
        ControlConfig::default(),
    )
    .await
    .unwrap();
    enrol(store.as_ref(), &admin()).await;
    enrol(store.as_ref(), &bob()).await;
    let team = cp.policy.create_vault(&admin(), "team").await.unwrap().id;
    let private = cp
        .policy
        .create_vault(&admin(), "private")
        .await
        .unwrap()
        .id;
    T {
        store,
        cp,
        team,
        private,
    }
}

impl T {
    /// A service, a rule and a bundle named "agents" in the vault.
    async fn bundle(&self, vault: &VaultId) {
        let credential = self
            .cp
            .policy
            .create_credential(
                &admin(),
                vault,
                CreateCredential {
                    name: "api".into(),
                    template_id: "generic-bearer".into(),
                    template_version: None,
                    host_override: vec!["api.example.com".into()],
                    fields: [("token".to_string(), "t".to_string())].into(),
                    custom_headers: vec![],
                    substitutions: vec![],
                    not_after: None,
                },
            )
            .await
            .unwrap();
        let rule = self
            .cp
            .policy
            .create_rule(
                &admin(),
                vault,
                CreateRule {
                    name: "api".into(),
                    credential_id: credential.id,
                    hosts: None,
                    paths: None,
                    methods: None,
                    mcp_tools: None,
                    git: None,
                },
            )
            .await
            .unwrap();
        self.cp
            .bundles
            .create(
                &admin(),
                vault,
                CreateBundle {
                    name: "agents".into(),
                    description: String::new(),
                    rule_ids: vec![rule.id],
                    request_limit: None,
                },
            )
            .await
            .unwrap();
    }

    async fn audit(&self, action: &str) -> Vec<tokenless_core::audit::AuditEvent> {
        crate::store::AuditSink::query(
            self.store.as_ref(),
            &AuditQuery {
                action_prefix: Some(action.into()),
                page: PageRequest::new(Some(1), Some(100)),
                ..AuditQuery::default()
            },
        )
        .await
        .unwrap()
        .items
    }
}

fn forbidden(result: Result<impl std::fmt::Debug, ControlError>) -> String {
    match result {
        Err(ControlError::Forbidden { reason }) => reason,
        other => panic!("expected Forbidden, got {other:?}"),
    }
}

#[tokio::test]
async fn a_person_works_only_in_the_vaults_they_belong_to() {
    let t = setup().await;
    t.bundle(&t.team).await;
    t.bundle(&t.private).await;
    // Nothing until someone adds them.
    let reason = forbidden(t.cp.policy.list_credentials(&bob(), &t.team, page()).await);
    assert!(reason.contains("not a member of vault"), "{reason}");
    assert_eq!(
        t.cp.policy.list_vaults(&bob(), page()).await.unwrap().total,
        0
    );

    t.cp.members
        .put(
            &admin(),
            &t.team,
            PutMember {
                username: "person-".to_string() + &person_id_tail("bob"),
                role: Role::Editor,
            },
        )
        .await
        .unwrap();
    t.cp.policy
        .list_credentials(&bob(), &t.team, page())
        .await
        .unwrap();
    forbidden(
        t.cp.policy
            .list_credentials(&bob(), &t.private, page())
            .await,
    );

    // Lists across vaults hold only theirs.
    let vaults = t.cp.vault_overviews(&bob(), page()).await.unwrap();
    assert_eq!(vaults.total, 1);
    assert_eq!(vaults.items[0].vault.id, t.team);
    assert_eq!(vaults.items[0].my_role, Some(Role::Editor));
    let bundles = t.cp.bundles.list_all(&bob(), page()).await.unwrap();
    assert!(bundles.items.iter().all(|b| b.vault_id == t.team) && bundles.total == 1);
    let events = t.cp.audit.query(&bob(), None, None, page()).await.unwrap();
    assert!(events.total > 0);
    assert!(
        events.items.iter().all(|e| e.vault_id == Some(t.team)),
        "only the team vault's events, and no instance-wide ones"
    );
    // The admin sees everything they oversee.
    let all =
        t.cp.audit
            .query(&admin(), None, None, page())
            .await
            .unwrap();
    assert!(all.items.iter().any(|e| e.vault_id == Some(t.private)));
    // Instance work stays with the instance's admins.
    forbidden(t.cp.users.list_users(&bob(), page()).await);
    forbidden(t.cp.policy.create_vault(&bob(), "mine").await);
}

/// The username `enrol` gives the test person `name`.
fn person_id_tail(name: &str) -> String {
    crate::service::testing::person_id(name).to_string()[24..].to_string()
}

#[tokio::test]
async fn an_instance_admin_oversees_a_vault_and_joins_it_to_do_more() {
    let t = setup().await;
    t.bundle(&t.team).await;
    join(t.store.as_ref(), &bob(), &t.team, Role::Admin).await;
    let admin_id = admin().user_id().unwrap();
    t.cp.members
        .remove(&admin(), &t.team, &admin_id)
        .await
        .unwrap();

    // Oversight: the vault, its sessions, its audit log; not its contents.
    let overview = t.cp.vault_overview_by_id(&admin(), &t.team).await.unwrap();
    assert_eq!(overview.my_role, None);
    assert!(overview.services.is_empty());
    let reason = forbidden(
        t.cp.policy
            .list_credentials(&admin(), &t.team, page())
            .await,
    );
    assert!(reason.contains("join the vault first"), "{reason}");
    forbidden(
        t.cp.sessions
            .mint(
                &admin(),
                &t.team,
                MintSession {
                    bundle: Some("agents".into()),
                    ..MintSession::default()
                },
            )
            .await,
    );
    t.cp.audit
        .query(&admin(), Some(t.team), None, page())
        .await
        .unwrap();
    // What to stop is visible, so it can be stopped.
    t.cp.sessions
        .list(&admin(), &t.team, SessionListing::default(), page())
        .await
        .unwrap();
    t.cp.launcher_keys
        .list(&admin(), &t.team, None, page())
        .await
        .unwrap();

    // Joining is a sensitive, audited step.
    let stale = Caller {
        step_up_at: Some(Utc::now() - Duration::hours(1)),
        ..admin()
    };
    assert!(matches!(
        t.cp.members.join(&stale, &t.team).await,
        Err(ControlError::StepUpRequired { .. })
    ));
    forbidden(t.cp.members.join(&bob(), &t.private).await);
    let joined = t.cp.members.join(&admin(), &t.team).await.unwrap();
    assert_eq!(joined.role, Role::Admin);
    t.cp.policy
        .list_credentials(&admin(), &t.team, page())
        .await
        .unwrap();
    let joins = t.audit("vault.join").await;
    assert_eq!(joins.len(), 1);
    assert_eq!(joins[0].vault_id, Some(t.team));
    assert!(matches!(
        t.cp.members.join(&admin(), &t.team).await,
        Err(ControlError::Conflict { .. })
    ));
}

#[tokio::test]
async fn a_vault_keeps_an_admin_and_only_its_admins_manage_members() {
    let t = setup().await;
    join(t.store.as_ref(), &bob(), &t.team, Role::Editor).await;
    let put = |username: &str, role| PutMember {
        username: username.into(),
        role,
    };
    let bob_name = format!("person-{}", person_id_tail("bob"));
    forbidden(
        t.cp.members
            .put(&bob(), &t.team, put(&bob_name, Role::Admin))
            .await,
    );
    let err =
        t.cp.members
            .put(&admin(), &t.team, put("nobody", Role::Viewer))
            .await;
    assert!(
        matches!(&err, Err(ControlError::Validation { message }) if message.contains("nobody is called 'nobody'")),
        "{err:?}"
    );
    let err =
        t.cp.members
            .put(&admin(), &t.team, put(&bob_name, Role::Member))
            .await;
    assert!(
        matches!(err, Err(ControlError::Validation { .. })),
        "{err:?}"
    );
    let stale = Caller {
        step_up_at: Some(Utc::now() - Duration::hours(1)),
        ..admin()
    };
    assert!(matches!(
        t.cp.members
            .put(&stale, &t.team, put(&bob_name, Role::Viewer))
            .await,
        Err(ControlError::StepUpRequired { .. })
    ));

    let admin_id = admin().user_id().unwrap();
    let err = t.cp.members.remove(&admin(), &t.team, &admin_id).await;
    assert!(
        matches!(&err, Err(ControlError::Conflict { message }) if message.contains("last admin of vault team")),
        "{err:?}"
    );
    let admin_name = format!("person-{}", person_id_tail("admin"));
    let err =
        t.cp.members
            .put(&admin(), &t.team, put(&admin_name, Role::Editor))
            .await;
    assert!(matches!(err, Err(ControlError::Conflict { .. })), "{err:?}");

    let changed =
        t.cp.members
            .put(&admin(), &t.team, put(&bob_name, Role::Viewer))
            .await
            .unwrap();
    assert_eq!(changed.role, Role::Viewer);
    let listed = t.cp.members.list(&bob(), &t.team, page()).await.unwrap();
    assert_eq!(listed.total, 2);
    let puts = t.audit("vault.member.put").await;
    assert_eq!(puts.len(), 1);
    assert_eq!(puts[0].detail["previous_role"], "editor");
    assert_eq!(puts[0].detail["role"], "viewer");

    // Anyone may leave; then they are no longer there to leave.
    let bob_id = bob().user_id().unwrap();
    t.cp.members.remove(&bob(), &t.team, &bob_id).await.unwrap();
    forbidden(t.cp.members.remove(&bob(), &t.team, &bob_id).await);
    assert!(matches!(
        t.cp.members.remove(&admin(), &t.team, &bob_id).await,
        Err(ControlError::NotFound { .. })
    ));
    assert_eq!(t.audit("vault.member.remove").await.len(), 1);
}

#[tokio::test]
async fn a_launch_sign_in_only_starts_sessions() {
    let t = setup().await;
    t.bundle(&t.team).await;
    join(t.store.as_ref(), &bob(), &t.team, Role::Editor).await;
    let launch = Caller {
        sign_in: SignInScope::Launch,
        ..bob()
    };
    t.cp.policy
        .list_credentials(&launch, &t.team, page())
        .await
        .unwrap();
    t.cp.bundles.list_all(&launch, page()).await.unwrap();
    t.cp.sessions
        .mint(
            &launch,
            &t.team,
            MintSession {
                bundle: Some("agents".into()),
                ..MintSession::default()
            },
        )
        .await
        .unwrap();
    let reason = forbidden(
        t.cp.bundles
            .create(
                &launch,
                &t.team,
                CreateBundle {
                    name: "more".into(),
                    description: String::new(),
                    rule_ids: vec![],
                    request_limit: None,
                },
            )
            .await,
    );
    assert!(reason.contains("tokenless login --manage"), "{reason}");
    forbidden(
        t.cp.sessions
            .list_all(&launch, Default::default(), page())
            .await,
    );
    forbidden(t.cp.audit.query(&launch, Some(t.team), None, page()).await);
    // An instance admin's `tokenless login` is no more than anyone's.
    let admin_launch = Caller {
        sign_in: SignInScope::Launch,
        ..admin()
    };
    forbidden(t.cp.users.list_users(&admin_launch, page()).await);
    forbidden(t.cp.members.join(&admin_launch, &t.private).await);
}

#[tokio::test]
async fn a_runner_starts_sessions_from_bundles_only() {
    let t = setup().await;
    t.bundle(&t.team).await;
    join(t.store.as_ref(), &bob(), &t.team, Role::Runner).await;
    let reason = forbidden(
        t.cp.sessions
            .mint(&bob(), &t.team, MintSession::default())
            .await,
    );
    assert!(reason.contains("access bundles only"), "{reason}");
    let mine =
        t.cp.sessions
            .mint(
                &bob(),
                &t.team,
                MintSession {
                    bundle: Some("agents".into()),
                    ..MintSession::default()
                },
            )
            .await
            .unwrap();
    let theirs =
        t.cp.sessions
            .mint(
                &admin(),
                &t.team,
                MintSession {
                    bundle: Some("agents".into()),
                    ..MintSession::default()
                },
            )
            .await
            .unwrap();
    let labels = [("task".to_string(), "review".to_string())].into();
    t.cp.sessions
        .update_labels(&bob(), &mine.session.id, labels)
        .await
        .unwrap();
    let reason = forbidden(
        t.cp.sessions
            .update_labels(&bob(), &theirs.session.id, Default::default())
            .await,
    );
    assert!(reason.contains("only the sessions it started"), "{reason}");
    // It sees no one's sessions and no audit log.
    forbidden(
        t.cp.sessions
            .list(&bob(), &t.team, Default::default(), page())
            .await,
    );
    forbidden(t.cp.audit.query(&bob(), Some(t.team), None, page()).await);

    // An API key may be a runner, never a member or an admin.
    let key = |role| CreateApiKey {
        name: "ci".into(),
        vault_id: t.team,
        role,
        expires_in_days: 30,
    };
    t.cp.auth
        .create_api_key(&admin(), key(Role::Runner))
        .await
        .unwrap();
    for role in [Role::Member, Role::Admin] {
        let err = t.cp.auth.create_api_key(&admin(), key(role)).await;
        assert!(
            matches!(err, Err(ControlError::Validation { .. })),
            "{role}: {err:?}"
        );
    }
}

#[tokio::test]
async fn a_sign_in_can_ask_for_less_never_more() {
    let t = setup().await;
    let issued =
        t.cp.users
            .create_invite(
                &admin(),
                CreateInvite {
                    role: Role::Member,
                    expires_in_hours: None,
                    vaults: vec![crate::model::VaultGrant {
                        vault_id: t.team,
                        role: Role::Runner,
                    }],
                },
            )
            .await
            .unwrap();
    t.cp.users
        .accept_invite(AcceptInviteRequest {
            invite_token: issued.token,
            username: "carol".into(),
            password: "a long enough password".into(),
            totp_secret: None,
            totp_code: None,
        })
        .await
        .unwrap();
    let login = |scope, ttl_secs| LoginRequest {
        username: "carol".into(),
        password: "a long enough password".into(),
        totp_code: None,
        scope,
        ttl_secs,
    };
    let err = t.cp.auth.login(login(SignInScope::Launch, Some(30))).await;
    assert!(
        matches!(err, Err(ControlError::Validation { .. })),
        "{err:?}"
    );
    let short =
        t.cp.auth
            .login(login(SignInScope::Launch, Some(600)))
            .await
            .unwrap();
    assert_eq!(short.max_age_secs, 600);
    assert_eq!(short.scope, SignInScope::Launch);
    let auth = t.cp.auth.authenticate_session(&short.token).await.unwrap();
    assert_eq!(auth.caller.sign_in, SignInScope::Launch);
    // Longer than the instance allows is cut to it.
    let long =
        t.cp.auth
            .login(login(SignInScope::Full, Some(10 * 365 * 24 * 3600)))
            .await
            .unwrap();
    assert_eq!(
        long.max_age_secs,
        ControlConfig::default().ui_session_ttl_secs
    );
    let logins = t.audit("auth.login").await;
    assert!(logins
        .iter()
        .any(|e| e.detail.get("scope").map(String::as_str) == Some("launch")));
}
