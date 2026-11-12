// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{Duration, Utc};

use super::*;
use crate::cipher::AesGcmCipher;
use crate::envelope::Envelope;
use crate::memory::MemoryStore;
use crate::model::{AuditQuery, Node, Settings};
use crate::service::auth::CreateApiKey;
use crate::service::bundles::CreateBundle;
use crate::service::policy::{CreateCredential, CreateRule};
use crate::service::sessions::MintSession;
use crate::store::{AuditSink, PolicyStore, RbacAuthorizer};
use crate::{ControlConfig, ControlPlane, Stores};

struct T {
    store: Arc<MemoryStore>,
    cp: ControlPlane,
    vault: VaultId,
    bundle: BundleId,
    other_bundle: BundleId,
}

fn person(role: Role) -> Caller {
    crate::service::testing::person_caller(&format!("test-{role}"), role)
}

fn admin() -> Caller {
    person(Role::Admin)
}

fn editor() -> Caller {
    person(Role::Editor)
}

fn create(bundle: &str) -> CreateLauncherKey {
    CreateLauncherKey {
        name: "build-runner".into(),
        bundle: bundle.into(),
        max_ttl_secs: None,
        request_limit: None,
        node_id: None,
        labels: BTreeMap::new(),
        expires_in_days: None,
    }
}

fn mint() -> MintSession {
    MintSession::default()
}

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
    let a = admin();
    for p in [&a, &editor(), &person(Role::Viewer)] {
        crate::service::testing::enrol(store.as_ref(), p).await;
    }
    let vault = cp.policy.create_vault(&a, "work").await.unwrap();
    crate::service::testing::join(store.as_ref(), &editor(), &vault.id, Role::Editor).await;
    crate::service::testing::join(
        store.as_ref(),
        &person(Role::Viewer),
        &vault.id,
        Role::Viewer,
    )
    .await;
    let credential = cp
        .policy
        .create_credential(
            &a,
            &vault.id,
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
    let rule = cp
        .policy
        .create_rule(
            &a,
            &vault.id,
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
    let mut bundles = Vec::new();
    for name in ["build", "deploy"] {
        let bundle = cp
            .bundles
            .create(
                &a,
                &vault.id,
                CreateBundle {
                    request_limit: None,
                    name: name.into(),
                    description: String::new(),
                    rule_ids: vec![rule.id],
                },
            )
            .await
            .unwrap();
        bundles.push(bundle.id);
    }
    T {
        store,
        cp,
        vault: vault.id,
        bundle: bundles[0],
        other_bundle: bundles[1],
    }
}

impl T {
    /// A launcher key for the `build` bundle, signed in.
    async fn key(&self, req: CreateLauncherKey) -> (CreatedLauncherKey, Caller) {
        let created = self
            .cp
            .launcher_keys
            .create(&editor(), &self.vault, req)
            .await
            .unwrap();
        let caller = self
            .cp
            .auth
            .authenticate_api_key(&created.key)
            .await
            .unwrap();
        (created, caller)
    }

    async fn audit(&self, action: &str) -> Vec<tokenless_core::audit::AuditEvent> {
        self.store
            .query(&AuditQuery {
                action_prefix: Some(action.into()),
                page: PageRequest::new(Some(1), Some(100)),
                ..Default::default()
            })
            .await
            .unwrap()
            .items
            .into_iter()
            .filter(|e| e.action == action)
            .collect()
    }

    async fn node(&self, name: &str) -> NodeId {
        let node = Node {
            id: NodeId::new(),
            name: name.into(),
            seal_public_key: String::new(),
            cert_serial: format!("serial-{name}"),
            cert_not_after: Utc::now() + Duration::days(30),
            enrolled_at: Utc::now(),
            last_seen_at: None,
            revoked_at: None,
            scoped_rules: false,
        };
        self.store.insert_node(node.clone(), &[]).await.unwrap();
        node.id
    }
}

#[tokio::test]
async fn a_key_starts_sessions_from_its_bundle_within_its_limits() {
    let t = setup().await;
    let (created, key) = t
        .key(CreateLauncherKey {
            max_ttl_secs: Some(300),
            request_limit: Some(40),
            labels: BTreeMap::from([("machine".to_string(), "ci-runner".to_string())]),
            ..create("build")
        })
        .await;
    assert_eq!(created.launcher_key.bundle_id, t.bundle);
    assert_eq!(created.launcher_key.max_ttl_secs, 300);

    // No bundle named: the key's own. Longer, unlimited asks are capped.
    let minted =
        t.cp.sessions
            .mint(
                &key,
                &t.vault,
                MintSession {
                    ttl_secs: Some(3600),
                    labels: BTreeMap::from([
                        ("machine".to_string(), "spoofed".to_string()),
                        ("name".to_string(), "nightly".to_string()),
                    ]),
                    ..mint()
                },
            )
            .await
            .unwrap();
    let s = &minted.session;
    assert_eq!(s.bundle.as_ref().map(|b| b.id), Some(t.bundle));
    assert_eq!((s.expires_at - s.created_at).num_seconds(), 300);
    assert_eq!(s.request_limit, Some(40));
    assert_eq!(
        s.labels.get("machine").map(String::as_str),
        Some("ci-runner")
    );
    assert_eq!(s.labels.get("name").map(String::as_str), Some("nightly"));
    assert_eq!(
        s.created_by,
        format!("api_key:{}", created.launcher_key.prefix)
    );

    // Shorter and fewer are allowed; "longest" is the key's longest.
    let shorter =
        t.cp.sessions
            .mint(
                &key,
                &t.vault,
                MintSession {
                    bundle: Some("build".into()),
                    ttl_secs: Some(60),
                    request_limit: Some(5),
                    ..mint()
                },
            )
            .await
            .unwrap()
            .session;
    assert_eq!((shorter.expires_at - shorter.created_at).num_seconds(), 60);
    assert_eq!(shorter.request_limit, Some(5));
    let longest =
        t.cp.sessions
            .mint(
                &key,
                &t.vault,
                MintSession {
                    longest: true,
                    ..mint()
                },
            )
            .await
            .unwrap()
            .session;
    assert_eq!((longest.expires_at - longest.created_at).num_seconds(), 300);
}

#[tokio::test]
async fn a_key_keeps_working_when_settings_allow_less_than_it_did() {
    let t = setup().await;
    let (_, key) = t
        .key(CreateLauncherKey {
            max_ttl_secs: Some(3600),
            ..create("build")
        })
        .await;
    let store = &t.store;
    let lower = |max| async move {
        let settings = store.get_settings().await.unwrap();
        store
            .put_settings(
                Settings {
                    max_session_ttl_secs: max,
                    ..settings
                },
                &[],
            )
            .await
            .unwrap();
    };
    let lasts = |req: MintSession| async {
        let s =
            t.cp.sessions
                .mint(&key, &t.vault, req)
                .await
                .unwrap()
                .session;
        (s.expires_at - s.created_at).num_seconds()
    };
    lower(1800).await;
    let longest = MintSession {
        longest: true,
        ..mint()
    };
    assert_eq!(lasts(longest.clone()).await, 1800);
    assert_eq!(lasts(mint()).await, 15 * 60);
    lower(300).await;
    assert_eq!(lasts(longest).await, 300);
    assert_eq!(lasts(mint()).await, 300, "the default too");
}

#[tokio::test]
async fn a_key_does_nothing_but_start_its_bundle_s_sessions() {
    let t = setup().await;
    let (created, key) = t.key(create("build")).await;
    let prefix = created.launcher_key.prefix;

    let other =
        t.cp.sessions
            .mint(
                &key,
                &t.vault,
                MintSession {
                    bundle: Some("deploy".into()),
                    ..mint()
                },
            )
            .await
            .unwrap_err();
    assert!(
        matches!(&other, ControlError::Forbidden { reason } if reason.contains("launcher key") && reason.contains("'deploy'")),
        "{other}"
    );
    let by_id =
        t.cp.sessions
            .mint(
                &key,
                &t.vault,
                MintSession {
                    bundle: Some(t.other_bundle.to_string()),
                    ..mint()
                },
            )
            .await
            .unwrap_err();
    assert!(matches!(by_id, ControlError::Forbidden { .. }), "{by_id}");
    let rules =
        t.cp.policy
            .list_rules(&admin(), &t.vault, PageRequest::new(None, None))
            .await
            .unwrap();
    let by_rule =
        t.cp.sessions
            .mint(
                &key,
                &t.vault,
                MintSession {
                    rule_ids: vec![rules.items[0].id],
                    ..mint()
                },
            )
            .await
            .unwrap_err();
    assert!(
        matches!(&by_rule, ControlError::Forbidden { reason } if reason.contains("not from rules")),
        "{by_rule}"
    );

    // Reading or changing anything else is refused, naming the key: even
    // the labels of a session it started itself.
    let own = t.cp.sessions.mint(&key, &t.vault, mint()).await.unwrap();
    let theirs =
        t.cp.sessions
            .mint(
                &editor(),
                &t.vault,
                MintSession {
                    bundle: Some("deploy".into()),
                    ..mint()
                },
            )
            .await
            .unwrap()
            .session
            .id;
    let reads = [
        t.cp.sessions
            .update_labels(&key, &own.session.id, BTreeMap::new())
            .await
            .map(|_| ()),
        t.cp.sessions
            .update_labels(&key, &theirs, BTreeMap::new())
            .await
            .map(|_| ()),
        t.cp.policy
            .list_rules(&key, &t.vault, PageRequest::new(None, None))
            .await
            .map(|_| ()),
        t.cp.policy
            .list_credentials(&key, &t.vault, PageRequest::new(None, None))
            .await
            .map(|_| ()),
        t.cp.sessions
            .list(
                &key,
                &t.vault,
                Default::default(),
                PageRequest::new(None, None),
            )
            .await
            .map(|_| ()),
        t.cp.launcher_keys
            .list(&key, &t.vault, None, PageRequest::new(None, None))
            .await
            .map(|_| ()),
        t.cp.launcher_keys
            .create(&key, &t.vault, create("build"))
            .await
            .map(|_| ()),
    ];
    for result in reads {
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ControlError::Forbidden { reason } if reason.contains(&prefix) && reason.contains("launcher key")),
            "{err}"
        );
    }
}

#[tokio::test]
async fn editors_create_keys_viewers_list_them_api_keys_do_neither() {
    let t = setup().await;
    let viewer = person(Role::Viewer);
    let err =
        t.cp.launcher_keys
            .create(&viewer, &t.vault, create("build"))
            .await
            .unwrap_err();
    assert!(matches!(err, ControlError::Forbidden { .. }), "{err}");
    t.key(create("build")).await;
    let listed =
        t.cp.launcher_keys
            .list(&viewer, &t.vault, None, PageRequest::new(None, None))
            .await
            .unwrap();
    assert_eq!(listed.total, 1);

    // An ordinary editor key can't make itself launcher keys: that takes a
    // person who can step up.
    let (plaintext, _) =
        t.cp.auth
            .create_api_key(
                &admin(),
                CreateApiKey {
                    name: "ci".into(),
                    vault_id: t.vault,
                    role: Role::Editor,
                    expires_in_days: 30,
                },
            )
            .await
            .unwrap();
    let api_key = t.cp.auth.authenticate_api_key(&plaintext).await.unwrap();
    let err =
        t.cp.launcher_keys
            .create(&api_key, &t.vault, create("build"))
            .await
            .unwrap_err();
    assert!(matches!(err, ControlError::Forbidden { .. }), "{err}");
    // Ordinary keys are not listed as launcher keys.
    let listed =
        t.cp.launcher_keys
            .list(&editor(), &t.vault, None, PageRequest::new(None, None))
            .await
            .unwrap();
    assert_eq!(listed.total, 1);

    // A person with a second factor steps up first.
    let stale = Caller {
        step_up_at: None,
        ..editor()
    };
    let err =
        t.cp.launcher_keys
            .create(&stale, &t.vault, create("build"))
            .await
            .unwrap_err();
    assert!(matches!(err, ControlError::StepUpRequired { .. }), "{err}");
}

#[tokio::test]
async fn revoking_a_key_ends_the_sessions_it_started() {
    let t = setup().await;
    let (created, key) = t.key(create("build")).await;
    let mut started = Vec::new();
    for _ in 0..3 {
        started.push(
            t.cp.sessions
                .mint(&key, &t.vault, mint())
                .await
                .unwrap()
                .session
                .id,
        );
    }
    let by_person =
        t.cp.sessions
            .mint(
                &editor(),
                &t.vault,
                MintSession {
                    bundle: Some("build".into()),
                    ..mint()
                },
            )
            .await
            .unwrap()
            .session
            .id;

    // Revoking needs no step-up: cutting access off must be quick.
    let quick = Caller {
        step_up_at: None,
        ..editor()
    };
    let revoked =
        t.cp.launcher_keys
            .revoke(&quick, &t.vault, &created.launcher_key.id)
            .await
            .unwrap();
    assert_eq!(revoked.sessions_revoked, 3);
    assert!(revoked.launcher_key.revoked_at.is_some());
    for id in &started {
        let s = t.cp.sessions.get(&admin(), id).await.unwrap();
        assert!(s.revoked_at.is_some(), "session {id} is still live");
    }
    let kept = t.cp.sessions.get(&admin(), &by_person).await.unwrap();
    assert!(
        kept.revoked_at.is_none(),
        "a person's session is not the key's"
    );

    let err =
        t.cp.auth
            .authenticate_api_key(&created.key)
            .await
            .unwrap_err();
    assert!(err.to_string().contains("revoked"), "{err}");
    let again =
        t.cp.launcher_keys
            .revoke(&editor(), &t.vault, &created.launcher_key.id)
            .await
            .unwrap();
    assert_eq!(again.sessions_revoked, 0);
    assert_eq!(
        again.launcher_key.revoked_at,
        revoked.launcher_key.revoked_at
    );

    let ended = t.audit("session.revoke").await;
    assert_eq!(ended.len(), 3);
    assert!(ended
        .iter()
        .all(|e| e.detail.get("launcher_key") == Some(&created.launcher_key.prefix)));
    assert_eq!(t.audit("launcher_key.revoke").await.len(), 2);
    let create_events = t.audit("launcher_key.create").await;
    assert_eq!(create_events.len(), 1);
    assert_eq!(
        create_events[0].detail.get("bundle").map(String::as_str),
        Some("build")
    );
}

#[tokio::test]
async fn a_mint_signed_in_before_the_key_was_revoked_does_not_outlive_it() {
    let t = setup().await;
    let (created, key) = t.key(create("build")).await;
    // Signed in, then revoked before its session is stored: the revoke
    // listed the key's sessions without this one.
    let revoked =
        t.cp.launcher_keys
            .revoke(&editor(), &t.vault, &created.launcher_key.id)
            .await
            .unwrap();
    assert_eq!(revoked.sessions_revoked, 0);
    let err =
        t.cp.sessions
            .mint(&key, &t.vault, mint())
            .await
            .unwrap_err();
    assert!(
        matches!(&err, ControlError::Unauthenticated { reason } if reason.contains("revoked")),
        "{err}"
    );
    let live =
        t.cp.sessions
            .list(
                &admin(),
                &t.vault,
                crate::model::SessionListing {
                    active: true,
                    after: None,
                },
                PageRequest::new(None, None),
            )
            .await
            .unwrap();
    assert_eq!(live.total, 0, "nothing the key started is live");
    let ended = t.audit("session.revoke").await;
    assert_eq!(ended.len(), 1);
    assert_eq!(ended[0].detail["reason"], "launcher key revoked");
}

#[tokio::test]
async fn revoking_it_from_the_api_keys_list_ends_its_sessions_too() {
    let t = setup().await;
    let (created, key) = t.key(create("build")).await;
    let started = t.cp.sessions.mint(&key, &t.vault, mint()).await.unwrap();
    let id = created.launcher_key.id;

    // The plain API-key revoke would leave the sessions running: refused.
    let err = t.cp.auth.revoke_api_key(&admin(), &id).await.unwrap_err();
    assert!(
        matches!(&err, ControlError::Validation { message } if message.contains("launcher key")),
        "{err}"
    );
    assert!(t.cp.auth.authenticate_api_key(&created.key).await.is_ok());

    let revoked =
        t.cp.launcher_keys
            .revoke_api_key(&admin(), &id)
            .await
            .unwrap()
            .expect("a launcher key");
    assert_eq!(revoked.sessions_revoked, 1);
    let s =
        t.cp.sessions
            .get(&admin(), &started.session.id)
            .await
            .unwrap();
    assert!(s.revoked_at.is_some());

    // An ordinary key is left to the API-key revoke.
    let (_, ordinary) =
        t.cp.auth
            .create_api_key(
                &admin(),
                CreateApiKey {
                    name: "ci".into(),
                    vault_id: t.vault,
                    role: Role::Viewer,
                    expires_in_days: 30,
                },
            )
            .await
            .unwrap();
    assert!(t
        .cp
        .launcher_keys
        .revoke_api_key(&admin(), &ordinary.id)
        .await
        .unwrap()
        .is_none());
    t.cp.auth
        .revoke_api_key(&admin(), &ordinary.id)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_revoked_session_is_not_renewed() {
    let t = setup().await;
    let (_, key) = t.key(create("build")).await;
    let first = t.cp.sessions.mint(&key, &t.vault, mint()).await.unwrap();
    let renewal = |previous| MintSession {
        renews: Some(previous),
        ..mint()
    };
    let next =
        t.cp.sessions
            .mint(&key, &t.vault, renewal(first.session.id))
            .await
            .unwrap();

    // Cut off by a proxy, or ended by a person: the launcher's timer does
    // not bring it back.
    t.store
        .revoke_session(&next.session.id, Utc::now(), &[])
        .await
        .unwrap();
    let err =
        t.cp.sessions
            .mint(&key, &t.vault, renewal(next.session.id))
            .await
            .unwrap_err();
    assert!(
        matches!(&err, ControlError::Conflict { message } if message.contains("revoked")),
        "{err}"
    );

    let other_vault = t.cp.policy.create_vault(&admin(), "other").await.unwrap();
    let elsewhere = MintSession {
        renews: Some(first.session.id),
        ..mint()
    };
    let err =
        t.cp.sessions
            .mint(&admin(), &other_vault.id, elsewhere)
            .await
            .unwrap_err();
    assert!(matches!(err, ControlError::Validation { .. }), "{err}");
}

#[tokio::test]
async fn revoking_finds_only_launcher_keys_of_the_vault() {
    let t = setup().await;
    let (plaintext, ordinary) =
        t.cp.auth
            .create_api_key(
                &admin(),
                CreateApiKey {
                    name: "ci".into(),
                    vault_id: t.vault,
                    role: Role::Editor,
                    expires_in_days: 30,
                },
            )
            .await
            .unwrap();
    let err =
        t.cp.launcher_keys
            .revoke(&editor(), &t.vault, &ordinary.id)
            .await
            .unwrap_err();
    assert!(
        matches!(&err, ControlError::NotFound { .. })
            && err.to_string().contains(&ordinary.id.to_string()),
        "{err}"
    );
    t.cp.auth.authenticate_api_key(&plaintext).await.unwrap();

    let (created, _) = t.key(create("build")).await;
    let elsewhere =
        t.cp.policy
            .create_vault(&admin(), "elsewhere")
            .await
            .unwrap();
    // An editor there too, so only the key's vault is wrong.
    crate::service::testing::join(t.store.as_ref(), &editor(), &elsewhere.id, Role::Editor).await;
    let err =
        t.cp.launcher_keys
            .revoke(&editor(), &elsewhere.id, &created.launcher_key.id)
            .await
            .unwrap_err();
    assert!(matches!(err, ControlError::NotFound { .. }), "{err}");
}

#[tokio::test]
async fn a_key_pinned_to_a_proxy_starts_sessions_only_for_it() {
    let t = setup().await;
    let laptop = t.node("laptop").await;
    let other = t.node("other").await;
    let err =
        t.cp.launcher_keys
            .create(
                &editor(),
                &t.vault,
                CreateLauncherKey {
                    node_id: Some(laptop),
                    ..create("build")
                },
            )
            .await
            .unwrap_err();
    assert!(
        matches!(err, ControlError::Forbidden { .. }),
        "choosing where credentials go needs the right to manage proxies: {err}"
    );
    let created =
        t.cp.launcher_keys
            .create(
                &admin(),
                &t.vault,
                CreateLauncherKey {
                    node_id: Some(laptop),
                    ..create("build")
                },
            )
            .await
            .unwrap();
    let key = t.cp.auth.authenticate_api_key(&created.key).await.unwrap();
    let session =
        t.cp.sessions
            .mint(&key, &t.vault, mint())
            .await
            .unwrap()
            .session;
    assert_eq!(session.node_id, Some(laptop));
    let err =
        t.cp.sessions
            .mint(
                &key,
                &t.vault,
                MintSession {
                    node_id: Some(other),
                    ..mint()
                },
            )
            .await
            .unwrap_err();
    assert!(
        matches!(&err, ControlError::Forbidden { reason } if reason.contains(&laptop.to_string())),
        "{err}"
    );

    // An unpinned key can't pick a proxy either.
    let (_, unpinned) = t.key(create("build")).await;
    let err =
        t.cp.sessions
            .mint(
                &unpinned,
                &t.vault,
                MintSession {
                    node_id: Some(laptop),
                    ..mint()
                },
            )
            .await
            .unwrap_err();
    assert!(matches!(err, ControlError::Forbidden { .. }), "{err}");
}

#[tokio::test]
async fn bad_requests_say_what_is_wrong() {
    let t = setup().await;
    let cases = [
        (
            CreateLauncherKey {
                name: " ".into(),
                ..create("build")
            },
            "name",
        ),
        (
            CreateLauncherKey {
                max_ttl_secs: Some(8 * 24 * 3600),
                ..create("build")
            },
            "max_ttl_secs",
        ),
        (
            CreateLauncherKey {
                max_ttl_secs: Some(0),
                ..create("build")
            },
            "max_ttl_secs",
        ),
        (
            CreateLauncherKey {
                request_limit: Some(0),
                ..create("build")
            },
            "request_limit",
        ),
        (
            CreateLauncherKey {
                expires_in_days: Some(0),
                ..create("build")
            },
            "expires_in_days",
        ),
        (
            CreateLauncherKey {
                expires_in_days: Some(MAX_LAUNCHER_KEY_DAYS + 1),
                ..create("build")
            },
            "expires_in_days",
        ),
    ];
    for (req, field) in cases {
        let err =
            t.cp.launcher_keys
                .create(&editor(), &t.vault, req)
                .await
                .unwrap_err();
        assert!(
            matches!(err, ControlError::Validation { .. }) && err.to_string().contains(field),
            "{field}: {err}"
        );
    }
    let err =
        t.cp.launcher_keys
            .create(&editor(), &t.vault, create("missing"))
            .await
            .unwrap_err();
    assert!(
        matches!(err, ControlError::NotFound { .. }) && err.to_string().contains("missing"),
        "{err}"
    );
}

#[tokio::test]
async fn defaults_and_the_secret_shown_once() {
    let t = setup().await;
    let (created, _) = t.key(create("build")).await;
    let key = &created.launcher_key;
    assert_eq!(key.max_ttl_secs, 15 * 60);
    assert_eq!(
        (key.expires_at - key.created_at).num_days(),
        i64::from(DEFAULT_LAUNCHER_KEY_DAYS)
    );
    assert!(created.key.starts_with(&key.prefix));
    let printed = format!("{created:?}");
    assert!(!printed.contains(&created.key), "{printed}");
    let listed = serde_json::to_string(
        &t.cp
            .launcher_keys
            .list(
                &editor(),
                &t.vault,
                Some(&t.bundle),
                PageRequest::new(None, None),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(
        !listed.contains(&created.key) && !listed.contains("hash"),
        "{listed}"
    );
}
