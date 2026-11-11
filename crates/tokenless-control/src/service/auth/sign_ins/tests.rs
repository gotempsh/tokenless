// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::Arc;

use tokenless_auth::{password, totp};
use tokenless_core::authz::{Principal, PrincipalKind, Role};

use super::*;
use crate::cipher::AesGcmCipher;
use crate::envelope::Envelope;
use crate::memory::MemoryStore;
use crate::model::{AuditQuery, SignInSettings, User};
use crate::service::auth::{ChangePassword, EnableAuthenticator, LoginRequest};
use crate::store::{AuditSink, IdentityStore, RbacAuthorizer};
use crate::{ControlConfig, ControlPlane, Stores};

const BROWSER: &str = "Mozilla/5.0 (Macintosh) Firefox/140.0";
const CLI: &str = "tokenless/0.4.0";
const PASSWORD: &str = "a long enough password";

struct T {
    store: Arc<MemoryStore>,
    cp: ControlPlane,
}

fn person(role: Role) -> Caller {
    Caller {
        principal: Principal {
            kind: PrincipalKind::User,
            actor: format!("user:test-{role}"),
            role,
            vault: None,
        },
        step_up_at: Some(Utc::now()),
        second_factor: true,
        launch: None,
    }
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
    T { store, cp }
}

impl T {
    async fn add_user(&self, username: &str) -> User {
        let user = User {
            id: UserId::new(),
            username: username.into(),
            password_hash: password::hash_password(PASSWORD).unwrap(),
            totp_secret_enc: None,
            totp_last_step: None,
            role: Role::Editor,
            created_at: Utc::now(),
            disabled_at: None,
            sso: None,
        };
        self.store.insert_user(user.clone(), &[]).await.unwrap();
        user
    }

    /// Signs `username` in from a client with `user_agent`; the token.
    async fn sign_in(&self, username: &str, user_agent: &str) -> String {
        self.cp
            .auth
            .login_from(
                LoginRequest {
                    username: username.into(),
                    password: PASSWORD.into(),
                    totp_code: None,
                },
                Some(user_agent),
            )
            .await
            .unwrap()
            .token
    }

    async fn session(&self, token: &str) -> SessionAuth {
        self.cp.auth.authenticate_session(token).await.unwrap()
    }

    async fn signed_in(&self, token: &str) -> bool {
        self.cp.auth.authenticate_session(token).await.is_ok()
    }

    async fn audit(&self, action: &str) -> Vec<AuditEvent> {
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
}

fn all() -> PageRequest {
    PageRequest::new(Some(1), Some(20))
}

#[test]
fn clients_are_told_apart_by_user_agent() {
    assert_eq!(SignInClient::of(Some(CLI)), SignInClient::Cli);
    assert_eq!(SignInClient::of(Some(BROWSER)), SignInClient::Browser);
    assert_eq!(SignInClient::of(None), SignInClient::Unknown);
}

#[test]
fn clients_get_a_short_name() {
    let cases = [
        (Some(CLI), "tokenless CLI 0.4.0"),
        (Some(BROWSER), "Firefox on macOS"),
        (
            Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36 Edg/141.0"),
            "Edge on Windows",
        ),
        (
            Some("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36"),
            "Chrome on Linux",
        ),
        (
            Some("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"),
            "Safari on iPhone",
        ),
        (Some("curl/8.7.1"), "curl/8.7.1"),
        (None, "unknown client"),
    ];
    for (ua, want) in cases {
        assert_eq!(describe_client(ua), want, "{ua:?}");
    }
}

#[test]
fn idle_timeouts_read_as_words() {
    assert_eq!(idle_words(7200), "2 hours");
    assert_eq!(idle_words(3600), "1 hour");
    assert_eq!(idle_words(300), "5 minutes");
    assert_eq!(idle_words(86_400 * 7), "7 days");
    assert_eq!(idle_words(90), "90 seconds");
}

#[test]
fn no_idle_timeout_has_no_cutoff() {
    let now = Utc::now();
    assert_eq!(idle_cutoff(None, now), None);
    assert_eq!(
        idle_cutoff(Some(60), now),
        Some(now - Duration::seconds(60))
    );
}

#[tokio::test]
async fn a_person_lists_and_revokes_their_own_sign_ins() {
    let t = setup().await;
    t.add_user("ada").await;
    t.add_user("bob").await;
    let browser = t.sign_in("ada", BROWSER).await;
    let cli = t.sign_in("ada", CLI).await;
    let bobs = t.sign_in("bob", BROWSER).await;
    let auth = t.session(&browser).await;

    let listed = t.cp.auth.sign_ins(&auth, all()).await.unwrap();
    assert_eq!(listed.total, 2, "{listed:?}");
    let current: Vec<_> = listed.items.iter().filter(|s| s.current).collect();
    assert_eq!(current.len(), 1);
    assert_eq!(current[0].id, auth.sign_in_id);
    assert_eq!(current[0].client, SignInClient::Browser);
    let other = listed.items.iter().find(|s| !s.current).unwrap();
    assert_eq!(other.client, SignInClient::Cli);
    assert_eq!(other.user_agent.as_deref(), Some(CLI));

    // Someone else's sign-in is not found, and nothing ends.
    let bob = t.session(&bobs).await;
    let err = t.cp.auth.revoke_sign_in(&bob, &other.id).await.unwrap_err();
    assert!(
        matches!(&err, ControlError::NotFound { id, .. } if *id == other.id.to_string()),
        "{err:?}"
    );
    assert!(t.signed_in(&cli).await);

    // Revoking one leaves the others.
    t.cp.auth.revoke_sign_in(&auth, &other.id).await.unwrap();
    assert!(!t.signed_in(&cli).await);
    assert!(t.signed_in(&browser).await);
    assert!(t.signed_in(&bobs).await);
    let events = t.audit("auth.sign_in_revoke").await;
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].detail.get("sign_in").map(String::as_str),
        Some(other.id.to_string().as_str())
    );
}

#[tokio::test]
async fn signing_out_elsewhere_keeps_this_sign_in() {
    let t = setup().await;
    t.add_user("ada").await;
    t.add_user("bob").await;
    let here = t.sign_in("ada", BROWSER).await;
    let laptop = t.sign_in("ada", BROWSER).await;
    let cli = t.sign_in("ada", CLI).await;
    let bobs = t.sign_in("bob", CLI).await;
    let auth = t.session(&here).await;

    let done = t.cp.auth.sign_out_elsewhere(&auth).await.unwrap();
    assert_eq!(done.revoked, 2);
    assert!(t.signed_in(&here).await);
    assert!(!t.signed_in(&laptop).await);
    assert!(!t.signed_in(&cli).await);
    assert!(t.signed_in(&bobs).await);
    assert_eq!(t.audit("auth.sign_out_elsewhere").await.len(), 1);
    let listed = t.cp.auth.sign_ins(&auth, all()).await.unwrap();
    assert_eq!(listed.total, 1);
}

#[tokio::test]
async fn an_unused_sign_in_ends_after_the_idle_timeout() {
    let t = setup().await;
    t.add_user("ada").await;
    t.cp.sso
        .put_sign_in_settings(
            &person(Role::Admin),
            SignInSettings {
                idle_timeout_secs: Some(300),
                ..SignInSettings::default()
            },
        )
        .await
        .unwrap();
    let idle = t.sign_in("ada", BROWSER).await;
    let busy = t.sign_in("ada", CLI).await;
    let stale = Utc::now() - Duration::seconds(301);
    t.store
        .touch_ui_session(&tokenless_auth::token::hash_token(&idle), stale)
        .await
        .unwrap();

    let auth = t.session(&busy).await;
    let listed = t.cp.auth.sign_ins(&auth, all()).await.unwrap();
    assert_eq!(listed.total, 1, "an idle sign-in is not listed: {listed:?}");

    let err = t.cp.auth.authenticate_session(&idle).await.unwrap_err();
    assert!(
        err.to_string().contains("after 5 minutes without use"),
        "{err}"
    );
    assert!(t.signed_in(&busy).await);

    // Off: an old sign-in still works until its absolute expiry.
    t.cp.sso
        .put_sign_in_settings(
            &person(Role::Admin),
            SignInSettings {
                idle_timeout_secs: None,
                ..SignInSettings::default()
            },
        )
        .await
        .unwrap();
    t.store
        .touch_ui_session(
            &tokenless_auth::token::hash_token(&busy),
            Utc::now() - Duration::days(2),
        )
        .await
        .unwrap();
    assert!(t.signed_in(&busy).await);
}

#[tokio::test]
async fn use_is_recorded_at_most_once_a_minute() {
    let t = setup().await;
    t.add_user("ada").await;
    let token = t.sign_in("ada", BROWSER).await;
    let hash = tokenless_auth::token::hash_token(&token);
    let recent = Utc::now() - Duration::seconds(10);
    t.store.touch_ui_session(&hash, recent).await.unwrap();
    t.session(&token).await;
    let s = t.store.get_ui_session(&hash).await.unwrap().unwrap();
    assert_eq!(s.last_used_at, recent, "used 10 s ago: not written again");

    let old = Utc::now() - Duration::seconds(120);
    t.store.touch_ui_session(&hash, old).await.unwrap();
    t.session(&token).await;
    let s = t.store.get_ui_session(&hash).await.unwrap().unwrap();
    assert!(s.last_used_at > old + Duration::seconds(100));
}

#[tokio::test]
async fn the_idle_timeout_has_bounds() {
    let t = setup().await;
    for secs in [0, 60, 31 * 86_400] {
        let err =
            t.cp.sso
                .put_sign_in_settings(
                    &person(Role::Admin),
                    SignInSettings {
                        idle_timeout_secs: Some(secs),
                        ..SignInSettings::default()
                    },
                )
                .await
                .unwrap_err();
        assert!(matches!(err, ControlError::Validation { .. }), "{err:?}");
        assert!(err.to_string().contains(&secs.to_string()), "{err}");
    }
}

#[tokio::test]
async fn changing_the_password_or_authenticator_ends_the_other_sign_ins() {
    let t = setup().await;
    t.add_user("ada").await;
    let here = t.sign_in("ada", BROWSER).await;
    let other = t.sign_in("ada", CLI).await;
    let auth = t.session(&here).await;
    t.cp.auth
        .change_password(
            &auth,
            &ChangePassword {
                current_password: PASSWORD.into(),
                new_password: "another long enough password".into(),
            },
        )
        .await
        .unwrap();
    assert!(t.signed_in(&here).await);
    assert!(!t.signed_in(&other).await);

    // A sign-in from before the authenticator was added ends with it.
    let other =
        t.cp.auth
            .login_from(
                LoginRequest {
                    username: "ada".into(),
                    password: "another long enough password".into(),
                    totp_code: None,
                },
                Some(CLI),
            )
            .await
            .unwrap()
            .token;
    let enrol = t.cp.auth.new_totp_enrollment("ada").unwrap();
    let now = u64::try_from(Utc::now().timestamp()).unwrap();
    t.cp.auth
        .enable_authenticator(
            &auth,
            &EnableAuthenticator {
                secret: enrol.secret.clone(),
                code: totp::code_at(&enrol.secret, now).unwrap(),
                password: "another long enough password".into(),
            },
        )
        .await
        .unwrap();
    assert!(t.signed_in(&here).await);
    assert!(!t.signed_in(&other).await);
}

#[tokio::test]
async fn an_admin_signs_someone_out_everywhere() {
    let t = setup().await;
    let ada = t.add_user("ada").await;
    let first = t.sign_in("ada", BROWSER).await;
    let second = t.sign_in("ada", CLI).await;

    let editor = person(Role::Editor);
    let err =
        t.cp.auth
            .revoke_user_sign_ins(&editor, &ada.id)
            .await
            .unwrap_err();
    assert!(matches!(err, ControlError::Forbidden { .. }), "{err:?}");
    assert!(t.signed_in(&first).await);

    let admin = person(Role::Admin);
    let listed =
        t.cp.auth
            .user_sign_ins(&admin, &ada.id, all())
            .await
            .unwrap();
    assert_eq!(listed.total, 2);
    assert!(listed.items.iter().all(|s| !s.current));

    let done =
        t.cp.auth
            .revoke_user_sign_ins(&admin, &ada.id)
            .await
            .unwrap();
    assert_eq!(done.revoked, 2);
    assert!(!t.signed_in(&first).await);
    assert!(!t.signed_in(&second).await);
    let events = t.audit("user.sign_ins_revoke").await;
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].target.as_deref(),
        Some(format!("user:{}", ada.id).as_str())
    );

    let missing = UserId::new();
    let err =
        t.cp.auth
            .revoke_user_sign_ins(&admin, &missing)
            .await
            .unwrap_err();
    assert!(
        matches!(&err, ControlError::NotFound { id, .. } if *id == missing.to_string()),
        "{err:?}"
    );
}
