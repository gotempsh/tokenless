// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Single sign-on against a provider simulated in memory: it issues codes
//! for the authorization URLs it is shown and signs ID tokens with its own
//! key, checking PKCE and client authentication as a real one would.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::Utc;
use serde_json::{json, Value};
use tokenless_auth::jwt::testing::TestKey;
use tokenless_core::authz::{Principal, PrincipalKind, Role};
use url::Url;

use super::oidc::{HttpReply, OidcTransport, TransportError};
use super::*;
use crate::cipher::AesGcmCipher;
use crate::envelope::Envelope;
use crate::memory::MemoryStore;
use crate::model::{OidcPurpose, PasswordSignIn, RoleMapping, SignInSettings};
use crate::service::auth::LoginRequest;
use crate::service::users::{AcceptInviteRequest, CreateInvite, UpdateUser};
use crate::store::{AuditSink, RbacAuthorizer};
use crate::{ControlConfig, ControlPlane, Stores};

const ISSUER: &str = "https://idp.example.test";
const REDIRECT: &str = "https://broker.example.test/api/v1/auth/oidc/callback";

/// Who the provider signs in, and how.
#[derive(Clone)]
struct Person {
    sub: String,
    username: String,
    groups: Vec<String>,
    /// Seconds before now that the person last entered their password.
    auth_age_secs: i64,
}

struct Issued {
    nonce: String,
    challenge: String,
    person: Person,
}

struct FakeIdp {
    key: TestKey,
    /// Signs with this instead, when set.
    impostor: Mutex<Option<TestKey>>,
    person: Mutex<Person>,
    codes: Mutex<HashMap<String, Issued>>,
    /// Claims put into the next ID tokens over the computed ones.
    overrides: Mutex<Value>,
    /// Leave groups out of the ID token; userinfo carries them.
    groups_in_userinfo: Mutex<bool>,
    basic_auth: Mutex<Option<String>>,
}

impl FakeIdp {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            key: TestKey::generate("idp-key-1"),
            impostor: Mutex::new(None),
            person: Mutex::new(Person {
                sub: "subject-ada".into(),
                username: "Ada".into(),
                groups: vec!["engineering".into()],
                auth_age_secs: 0,
            }),
            codes: Mutex::new(HashMap::new()),
            overrides: Mutex::new(json!({})),
            groups_in_userinfo: Mutex::new(false),
            basic_auth: Mutex::new(None),
        })
    }

    fn set_person(&self, f: impl FnOnce(&mut Person)) {
        f(&mut self.person.lock().unwrap());
    }

    /// The person signs in at the provider: returns the state and code
    /// the browser brings back, and the request's parameters.
    fn authorize(&self, authorization_url: &str) -> (String, String, HashMap<String, String>) {
        assert!(authorization_url.starts_with("https://idp.example.test/authorize?"));
        let url = Url::parse(authorization_url).unwrap();
        let q: HashMap<String, String> = url.query_pairs().into_owned().collect();
        assert_eq!(q["response_type"], "code");
        assert_eq!(q["client_id"], "tokenless");
        assert_eq!(q["redirect_uri"], REDIRECT);
        assert_eq!(q["code_challenge_method"], "S256");
        assert!(q["scope"].split(' ').any(|s| s == "openid"));
        let code = format!("code-{}", tokenless_auth::token::random_value());
        self.codes.lock().unwrap().insert(
            code.clone(),
            Issued {
                nonce: q["nonce"].clone(),
                challenge: q["code_challenge"].clone(),
                person: self.person.lock().unwrap().clone(),
            },
        );
        (q["state"].clone(), code, q)
    }

    fn reply(status: u16, body: Value) -> Result<HttpReply, TransportError> {
        Ok(HttpReply {
            status,
            body: body.to_string().into_bytes(),
        })
    }
}

#[async_trait]
impl OidcTransport for FakeIdp {
    async fn get(&self, url: &Url, bearer: Option<&str>) -> Result<HttpReply, TransportError> {
        match url.as_str() {
            "https://idp.example.test/.well-known/openid-configuration" => Self::reply(
                200,
                json!({
                    "issuer": ISSUER,
                    "authorization_endpoint": "https://idp.example.test/authorize",
                    "token_endpoint": "https://idp.example.test/token",
                    "jwks_uri": "https://idp.example.test/keys",
                    "userinfo_endpoint": "https://idp.example.test/userinfo",
                    "id_token_signing_alg_values_supported": ["ES256"],
                }),
            ),
            "https://idp.example.test/keys" => {
                Self::reply(200, json!({ "keys": [self.key.jwk()] }))
            }
            "https://idp.example.test/userinfo" => {
                if !bearer.is_some_and(|b| b.starts_with("at-")) {
                    return Self::reply(401, json!({}));
                }
                let person = self.person.lock().unwrap().clone();
                Self::reply(200, json!({ "sub": person.sub, "groups": person.groups }))
            }
            other => Err(TransportError {
                reason: format!("unexpected GET {other}"),
            }),
        }
    }

    async fn post_form(
        &self,
        url: &Url,
        form: &[(&str, &str)],
        basic: Option<(&str, &str)>,
    ) -> Result<HttpReply, TransportError> {
        assert_eq!(url.as_str(), "https://idp.example.test/token");
        *self.basic_auth.lock().unwrap() = basic.map(|(u, p)| STANDARD.encode(format!("{u}:{p}")));
        let f: HashMap<&str, &str> = form.iter().copied().collect();
        assert_eq!(f["grant_type"], "authorization_code");
        assert_eq!(f["redirect_uri"], REDIRECT);
        assert!(!f.contains_key("client_secret"), "the secret goes in Basic");
        let Some(issued) = self.codes.lock().unwrap().remove(f["code"]) else {
            return Self::reply(
                400,
                json!({"error": "invalid_grant", "error_description": "unknown code"}),
            );
        };
        if super::oidc::pkce_challenge(f["code_verifier"]) != issued.challenge {
            return Self::reply(
                400,
                json!({"error": "invalid_grant", "error_description": "PKCE verifier mismatch"}),
            );
        }
        let now = Utc::now().timestamp();
        let p = &issued.person;
        let mut claims = json!({
            "iss": ISSUER,
            "aud": "tokenless",
            "sub": p.sub,
            "exp": now + 300,
            "iat": now,
            "auth_time": now - p.auth_age_secs,
            "nonce": issued.nonce,
            "preferred_username": p.username,
        });
        if !*self.groups_in_userinfo.lock().unwrap() {
            claims["groups"] = json!(p.groups);
        }
        if let Value::Object(extra) = self.overrides.lock().unwrap().clone() {
            for (k, v) in extra {
                claims[k] = v;
            }
        }
        let impostor = self.impostor.lock().unwrap();
        let id_token = impostor.as_ref().unwrap_or(&self.key).sign(&claims);
        Self::reply(
            200,
            json!({"id_token": id_token, "access_token": format!("at-{}", f["code"]), "token_type": "Bearer"}),
        )
    }
}

struct T {
    store: Arc<MemoryStore>,
    cp: ControlPlane,
    idp: Arc<FakeIdp>,
}

fn admin() -> Caller {
    Caller {
        principal: Principal {
            kind: PrincipalKind::User,
            actor: "user:test-admin".into(),
            role: Role::Admin,
            vault: None,
        },
        step_up_at: Some(Utc::now()),
        second_factor: true,
        launch: None,
    }
}

fn input() -> OidcProviderInput {
    OidcProviderInput {
        slug: "corp".into(),
        name: "Corp SSO".into(),
        issuer: ISSUER.into(),
        client_id: "tokenless".into(),
        client_secret: Some("s3cret+/=".into()),
        clear_client_secret: false,
        redirect_uri: REDIRECT.into(),
        scopes: vec!["profile".into(), "groups".into()],
        groups_claim: default_groups_claim(),
        username_claim: default_username_claim(),
        role_mappings: vec![
            RoleMapping {
                group: "engineering".into(),
                role: Role::Editor,
            },
            RoleMapping {
                group: "auditors".into(),
                role: Role::Viewer,
            },
            RoleMapping {
                group: "platform-admins".into(),
                role: Role::Admin,
            },
        ],
        enabled: true,
    }
}

fn disabled() -> OidcProviderInput {
    OidcProviderInput {
        enabled: false,
        client_secret: None,
        ..input()
    }
}

async fn setup() -> T {
    let store = Arc::new(MemoryStore::new());
    let cipher = Arc::new(
        Envelope::open(&AesGcmCipher::generate_key(), store.clone())
            .await
            .unwrap(),
    );
    let idp = FakeIdp::new();
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
        },
        Arc::new(RbacAuthorizer),
        cipher,
        Arc::new(crate::probe::DisabledProber),
        idp.clone(),
        Arc::new(crate::service::audit_export::DisabledWebhookTransport),
        ControlConfig::default(),
    )
    .await
    .unwrap();
    T { store, cp, idp }
}

async fn with_provider() -> (T, OidcProviderView) {
    let t = setup().await;
    let p = t.cp.sso.create_provider(&admin(), input()).await.unwrap();
    (t, p)
}

impl T {
    async fn sign_in(&self) -> Result<SsoCompleted, SsoFailed> {
        let r = self
            .cp
            .sso
            .begin("corp", OidcPurpose::Login, Some("/vaults"), None)
            .await
            .unwrap();
        let (state, code, _) = self.idp.authorize(&r.authorization_url);
        self.complete(state, code, &r.browser_token).await
    }

    async fn complete(
        &self,
        state: String,
        code: String,
        browser: &str,
    ) -> Result<SsoCompleted, SsoFailed> {
        self.cp
            .sso
            .complete(
                SsoCallback {
                    state: Some(state),
                    code: Some(code),
                    ..Default::default()
                },
                Some(browser),
                Some("Mozilla/5.0 test"),
            )
            .await
    }

    /// Signs in and returns the session token and what it authenticates as.
    async fn signed_in(&self) -> (String, SessionAuth) {
        match self.sign_in().await.unwrap() {
            SsoCompleted::SignedIn { login, return_to } => {
                assert_eq!(return_to, "/vaults");
                let auth = self
                    .cp
                    .auth
                    .authenticate_session(&login.token)
                    .await
                    .unwrap();
                (login.token, auth)
            }
            other => panic!("{other:?}"),
        }
    }

    async fn session(&self) -> SessionAuth {
        self.signed_in().await.1
    }

    async fn audit(&self, action: &str) -> Vec<tokenless_core::audit::AuditEvent> {
        self.store
            .query(&crate::model::AuditQuery::default())
            .await
            .unwrap()
            .items
            .into_iter()
            .filter(|e| e.action == action)
            .collect()
    }
}

fn refused(r: Result<SsoCompleted, SsoFailed>) -> ControlError {
    match r {
        Ok(done) => panic!("signed in: {done:?}"),
        Err(f) => f.error,
    }
}

#[tokio::test]
async fn first_sign_in_creates_the_account_with_its_groups_role() {
    let (t, provider) = with_provider().await;
    assert!(provider.has_client_secret);
    let session = t.session().await;
    assert_eq!(session.user.username, "ada");
    assert_eq!(session.user.role, Role::Editor);
    assert_eq!(session.user.sso_provider_id, Some(provider.id));
    // It steps up at the provider, so it counts as having a second factor.
    assert!(session.caller.second_factor);
    assert!(session.caller.step_up_at.is_some());
    // The secret went in Basic, form-encoded first (RFC 6749 §2.3.1).
    assert_eq!(
        t.idp.basic_auth.lock().unwrap().as_deref(),
        Some(STANDARD.encode("tokenless:s3cret%2B%2F%3D").as_str())
    );
    assert!(t
        .audit("auth.login")
        .await
        .iter()
        .any(|e| e.outcome == AuditOutcome::Success
            && e.detail.get("method").map(String::as_str) == Some("sso")));
    assert_eq!(t.audit("user.create").await.len(), 1);
    // Signing in again finds the same account.
    assert_eq!(t.session().await.user.id, session.user.id);
    assert_eq!(t.audit("user.create").await.len(), 1);
}

#[tokio::test]
async fn the_role_follows_the_groups_at_every_sign_in() {
    let (t, _) = with_provider().await;
    // Someone else is an admin, so the person's role can change.
    t.cp.auth.create_initial_admin().await.unwrap();
    let (first_token, first) = t.signed_in().await;
    assert_eq!(first.user.role, Role::Editor);
    t.idp
        .set_person(|p| p.groups = vec!["auditors".into(), "platform-admins".into()]);
    let second = t.session().await;
    assert_eq!(second.user.role, Role::Admin);
    // A session from before carries the new role too.
    let before = t.cp.auth.authenticate_session(&first_token).await.unwrap();
    assert_eq!(before.caller.principal.role, Role::Admin);
    t.idp.set_person(|p| p.groups = vec!["auditors".into()]);
    assert_eq!(t.session().await.user.role, Role::Viewer);
    let updates = t.audit("user.update").await;
    assert_eq!(updates.len(), 2);
    assert!(updates
        .iter()
        .all(|u| u.detail.get("reason").map(String::as_str) == Some("groups at corp")));
    // An admin cannot set the role by hand: the next sign-in would undo it.
    let err =
        t.cp.users
            .update_user(
                &admin(),
                &second.user.id,
                UpdateUser {
                    role: Some(Role::Editor),
                    disabled: None,
                },
            )
            .await
            .unwrap_err();
    assert!(err.to_string().contains("group mappings"), "{err}");
}

#[tokio::test]
async fn groups_mapping_to_no_role_are_refused_and_named() {
    let (t, _) = with_provider().await;
    t.idp
        .set_person(|p| p.groups = vec!["marketing".into(), "everyone".into()]);
    let err = refused(t.sign_in().await);
    assert!(matches!(err, ControlError::SsoRefused { .. }), "{err}");
    let message = err.to_string();
    assert!(
        message.contains("groups seen: everyone, marketing"),
        "{message}"
    );
    let denied: Vec<_> = t
        .audit("auth.login")
        .await
        .into_iter()
        .filter(|e| e.outcome == AuditOutcome::Denied)
        .collect();
    assert_eq!(denied.len(), 1);
    assert!(denied[0].detail["reason"].contains("marketing"));
    assert!(t.audit("user.create").await.is_empty());
    t.idp.set_person(|p| p.groups = vec![]);
    let err = refused(t.sign_in().await).to_string();
    assert!(
        err.contains("the 'groups' claim is missing or empty"),
        "{err}"
    );
}

#[tokio::test]
async fn groups_only_in_userinfo_are_found_there() {
    let (t, _) = with_provider().await;
    *t.idp.groups_in_userinfo.lock().unwrap() = true;
    t.idp
        .set_person(|p| p.groups = vec!["platform-admins".into()]);
    assert_eq!(t.session().await.user.role, Role::Admin);
}

#[tokio::test]
async fn an_answer_counts_once_and_only_in_the_browser_that_asked() {
    let (t, _) = with_provider().await;
    let r =
        t.cp.sso
            .begin("corp", OidcPurpose::Login, None, None)
            .await
            .unwrap();
    let (state, code, _) = t.idp.authorize(&r.authorization_url);
    // Another browser brings the answer back: it has no sign-in in progress.
    let err = refused(
        t.complete(state.clone(), code.clone(), "another-browser")
            .await,
    );
    assert!(err.to_string().contains("another browser"), "{err}");
    let err =
        t.cp.sso
            .complete(
                SsoCallback {
                    state: Some(state.clone()),
                    code: Some(code.clone()),
                    ..Default::default()
                },
                None,
                None,
            )
            .await
            .unwrap_err();
    assert!(err.error.to_string().contains("another browser"));
    // An answer for another sign-in than this browser's.
    let err = refused(
        t.complete("forged".into(), code.clone(), &r.browser_token)
            .await,
    );
    assert!(err.to_string().contains("another sign-in"), "{err}");
    let err =
        t.cp.sso
            .complete(SsoCallback::default(), Some(&r.browser_token), None)
            .await
            .unwrap_err();
    assert!(err.error.to_string().contains("no state"));
    // The browser that asked signs in; the same answer again is refused.
    assert!(t
        .complete(state.clone(), code.clone(), &r.browser_token)
        .await
        .is_ok());
    let err = refused(t.complete(state, code, &r.browser_token).await);
    assert!(
        matches!(err, ControlError::IdentityProvider { .. }),
        "{err}"
    );
}

#[tokio::test]
async fn a_forged_or_misdirected_id_token_is_refused() {
    let (t, _) = with_provider().await;
    *t.idp.impostor.lock().unwrap() = Some(TestKey::generate("idp-key-1"));
    let err = refused(t.sign_in().await);
    assert!(err.to_string().contains("signature"), "{err}");
    *t.idp.impostor.lock().unwrap() = None;
    for (claim, value) in [
        ("nonce", json!("replayed")),
        ("aud", json!("another-client")),
        ("iss", json!("https://evil.example.test")),
        ("exp", json!(Utc::now().timestamp() - 3600)),
    ] {
        *t.idp.overrides.lock().unwrap() = json!({ claim: value });
        let err = refused(t.sign_in().await);
        assert!(
            matches!(err, ControlError::IdentityProvider { .. }),
            "{claim}: {err}"
        );
    }
    assert_eq!(
        crate::store::IdentityStore::count_users(t.store.as_ref())
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn a_provider_error_or_wrong_code_is_reported() {
    let (t, _) = with_provider().await;
    let r =
        t.cp.sso
            .begin("corp", OidcPurpose::Login, Some("/x"), None)
            .await
            .unwrap();
    let (state, _, _) = t.idp.authorize(&r.authorization_url);
    let err =
        t.cp.sso
            .complete(
                SsoCallback {
                    state: Some(state),
                    error: Some("access_denied".into()),
                    error_description: Some("the person declined".into()),
                    ..Default::default()
                },
                Some(&r.browser_token),
                None,
            )
            .await
            .unwrap_err();
    assert_eq!(err.purpose, OidcPurpose::Login);
    assert_eq!(err.return_to, "/x");
    assert!(err
        .error
        .to_string()
        .contains("access_denied: the person declined"));
    let r =
        t.cp.sso
            .begin("corp", OidcPurpose::Login, None, None)
            .await
            .unwrap();
    let (state, _, _) = t.idp.authorize(&r.authorization_url);
    let err = refused(
        t.complete(state, "not-issued".into(), &r.browser_token)
            .await,
    );
    assert!(err.to_string().contains("invalid_grant"), "{err}");
}

#[tokio::test]
async fn a_username_held_by_a_local_account_is_not_taken_over() {
    let (t, _) = with_provider().await;
    t.cp.auth.create_initial_admin().await.unwrap();
    t.idp.set_person(|p| p.username = "admin".into());
    let err = refused(t.sign_in().await);
    assert!(
        err.to_string().contains("belongs to another account"),
        "{err}"
    );
    t.idp.set_person(|p| p.username = "x".into());
    let err = refused(t.sign_in().await).to_string();
    assert!(err.contains("no usable 'preferred_username'"), "{err}");
}

#[tokio::test]
async fn an_sso_account_has_no_password_or_authenticator_here() {
    let (t, _) = with_provider().await;
    let session = t.session().await;
    let err =
        t.cp.auth
            .login(LoginRequest {
                username: "ada".into(),
                password: String::new(),
                totp_code: None,
            })
            .await
            .unwrap_err();
    assert!(matches!(err, ControlError::Unauthenticated { .. }), "{err}");
    let err =
        t.cp.auth
            .change_password(
                &session,
                &crate::service::auth::ChangePassword {
                    current_password: "x".into(),
                    new_password: "a much longer password".into(),
                },
            )
            .await
            .unwrap_err();
    assert!(err.to_string().contains("single sign-on"), "{err}");
    let err =
        t.cp.auth
            .step_up(&session, &Default::default())
            .await
            .unwrap_err();
    assert!(err.to_string().contains("purpose=step_up"), "{err}");
    assert!(t.cp.auth.reset_password("ada").await.is_err());
}

#[tokio::test]
async fn a_disabled_account_or_provider_cannot_sign_in() {
    let (t, provider) = with_provider().await;
    // Someone else is an admin, so the person's role can change.
    t.cp.auth.create_initial_admin().await.unwrap();
    let session = t.session().await;
    let set_disabled = |disabled: bool| UpdateUser {
        role: None,
        disabled: Some(disabled),
    };
    t.cp.users
        .update_user(&admin(), &session.user.id, set_disabled(true))
        .await
        .unwrap();
    let err = refused(t.sign_in().await).to_string();
    assert!(err.contains("has been disabled"), "{err}");
    t.cp.users
        .update_user(&admin(), &session.user.id, set_disabled(false))
        .await
        .unwrap();
    let (token, _) = t.signed_in().await;
    // Turning the provider off ends its people's sessions.
    t.cp.sso
        .update_provider(&admin(), &provider.id, disabled())
        .await
        .unwrap();
    let err = t.cp.auth.authenticate_session(&token).await.unwrap_err();
    assert!(err.to_string().contains("turned off"), "{err}");
    let err =
        t.cp.sso
            .begin("corp", OidcPurpose::Login, None, None)
            .await
            .unwrap_err();
    assert!(matches!(err, ControlError::NotFound { .. }), "{err}");
    // And it cannot be deleted while it has accounts.
    let err =
        t.cp.sso
            .delete_provider(&admin(), &provider.id)
            .await
            .unwrap_err();
    assert!(err.to_string().contains("turn it off instead"), "{err}");
}

#[tokio::test]
async fn step_up_needs_a_fresh_sign_in_at_the_provider() {
    let (t, _) = with_provider().await;
    let session = t.session().await;
    let r =
        t.cp.sso
            .begin(
                "corp",
                OidcPurpose::StepUp,
                Some("/settings"),
                Some(&session),
            )
            .await
            .unwrap();
    let (state, code, q) = t.idp.authorize(&r.authorization_url);
    assert_eq!(q["prompt"], "login");
    assert_eq!(q["max_age"], "0");
    match t.complete(state, code, &r.browser_token).await.unwrap() {
        SsoCompleted::SteppedUp { return_to, .. } => assert_eq!(return_to, "/settings"),
        other => panic!("{other:?}"),
    }
    assert_eq!(t.audit("auth.step_up").await[0].detail["method"], "sso");
    // A provider that reuses an old sign-in does not step anyone up.
    t.idp.set_person(|p| p.auth_age_secs = 3600);
    let r =
        t.cp.sso
            .begin("corp", OidcPurpose::StepUp, None, Some(&session))
            .await
            .unwrap();
    let (state, code, _) = t.idp.authorize(&r.authorization_url);
    let err = t.complete(state, code, &r.browser_token).await.unwrap_err();
    assert_eq!(err.purpose, OidcPurpose::StepUp);
    assert!(err.error.to_string().contains("max_age=0"), "{}", err.error);
    // Someone else signing in at the provider does not step this session up.
    t.idp.set_person(|p| {
        p.auth_age_secs = 0;
        p.sub = "subject-other".into();
    });
    let r =
        t.cp.sso
            .begin("corp", OidcPurpose::StepUp, None, Some(&session))
            .await
            .unwrap();
    let (state, code, _) = t.idp.authorize(&r.authorization_url);
    let err = t.complete(state, code, &r.browser_token).await.unwrap_err();
    assert!(
        err.error.to_string().contains("different person"),
        "{}",
        err.error
    );
    // Without a session there is nothing to step up.
    assert!(t
        .cp
        .sso
        .begin("corp", OidcPurpose::StepUp, None, None)
        .await
        .is_err());
}

#[tokio::test]
async fn return_to_stays_on_this_instance() {
    let (t, _) = with_provider().await;
    for bad in [
        "https://evil.example.test",
        "//evil.example.test",
        "/\\evil",
        "x",
    ] {
        let err =
            t.cp.sso
                .begin("corp", OidcPurpose::Login, Some(bad), None)
                .await
                .unwrap_err();
        assert!(matches!(err, ControlError::Validation { .. }), "{bad}");
    }
}

#[tokio::test]
async fn providers_are_checked_and_never_show_their_secret() {
    let t = setup().await;
    type Change = Box<dyn Fn(&mut OidcProviderInput)>;
    let bad: Vec<(&str, Change)> = vec![
        ("slug", Box::new(|i| i.slug = "Corp SSO".into())),
        (
            "issuer",
            Box::new(|i| i.issuer = "http://idp.example.test".into()),
        ),
        (
            "redirect_uri",
            Box::new(|i| i.redirect_uri = "https://broker.example.test/elsewhere".into()),
        ),
        ("mappings", Box::new(|i| i.role_mappings.clear())),
        (
            "duplicate group",
            Box::new(|i| {
                let first = i.role_mappings[0].clone();
                i.role_mappings.push(RoleMapping {
                    role: Role::Admin,
                    ..first
                })
            }),
        ),
        ("scope", Box::new(|i| i.scopes = vec!["bad scope".into()])),
        (
            "unknown issuer",
            Box::new(|i| i.issuer = "https://other.example.test".into()),
        ),
    ];
    for (what, change) in bad {
        let mut i = input();
        change(&mut i);
        let err = t.cp.sso.create_provider(&admin(), i).await.unwrap_err();
        assert!(
            matches!(err, ControlError::Validation { .. }),
            "{what}: {err}"
        );
    }
    let created = t.cp.sso.create_provider(&admin(), input()).await.unwrap();
    let json = serde_json::to_string(&created).unwrap();
    assert!(!json.contains("s3cret"), "{json}");
    assert!(json.contains("\"has_client_secret\":true"));
    assert!(format!("{:?}", input()).contains("***"));
    assert!(matches!(
        t.cp.sso.create_provider(&admin(), input()).await,
        Err(ControlError::Conflict { .. })
    ));
    // Replacing without a secret keeps it; clearing removes it.
    let mut keep = OidcProviderInput {
        client_secret: None,
        name: "Corp".into(),
        ..input()
    };
    let kept =
        t.cp.sso
            .update_provider(&admin(), &created.id, keep.clone())
            .await
            .unwrap();
    assert!(kept.has_client_secret);
    assert_eq!(kept.name, "Corp");
    keep.clear_client_secret = true;
    let cleared =
        t.cp.sso
            .update_provider(&admin(), &created.id, keep)
            .await
            .unwrap();
    assert!(!cleared.has_client_secret);
    // Admins only, and with a fresh step-up.
    let mut editor = admin();
    editor.principal.role = Role::Editor;
    assert!(matches!(
        t.cp.sso.create_provider(&editor, input()).await,
        Err(ControlError::Forbidden { .. })
    ));
    let mut stale = admin();
    stale.step_up_at = Some(Utc::now() - chrono::Duration::hours(1));
    assert!(matches!(
        t.cp.sso.delete_provider(&stale, &created.id).await,
        Err(ControlError::StepUpRequired { .. })
    ));
    t.cp.sso
        .delete_provider(&admin(), &created.id)
        .await
        .unwrap();
    assert!(t.cp.sso.list_providers(&admin()).await.unwrap().is_empty());
    assert_eq!(t.audit("identity_provider.delete").await.len(), 1);
}

#[tokio::test]
async fn password_sign_in_can_be_kept_for_admins_only() {
    let (t, provider) = with_provider().await;
    let creds = t.cp.auth.create_initial_admin().await.unwrap().unwrap();
    // A local editor, signed in before the switch.
    let invite =
        t.cp.users
            .create_invite(
                &admin(),
                CreateInvite {
                    role: Role::Editor,
                    expires_in_hours: None,
                },
            )
            .await
            .unwrap();
    t.cp.users
        .accept_invite(AcceptInviteRequest {
            invite_token: invite.token,
            username: "local-editor".into(),
            password: "a long enough password".into(),
            totp_secret: None,
            totp_code: None,
        })
        .await
        .unwrap();
    let login = |username: &str, password: &str| LoginRequest {
        username: username.into(),
        password: password.into(),
        totp_code: None,
    };
    let editor =
        t.cp.auth
            .login(login("local-editor", "a long enough password"))
            .await
            .unwrap();

    let admins_only = SignInSettings {
        password_sign_in: PasswordSignIn::AdminsOnly,
        ..SignInSettings::default()
    };
    t.cp.sso
        .put_sign_in_settings(&admin(), admins_only.clone())
        .await
        .unwrap();
    assert_eq!(
        t.cp.sso.sign_in_options().await.unwrap().password_sign_in,
        PasswordSignIn::AdminsOnly
    );
    let err =
        t.cp.auth
            .login(login("local-editor", "a long enough password"))
            .await
            .unwrap_err();
    assert!(matches!(err, ControlError::Forbidden { .. }), "{err}");
    assert!(t.cp.auth.authenticate_session(&editor.token).await.is_err());
    // The local admin still gets in, as break-glass.
    t.cp.auth
        .login(login(&creds.username, &creds.password))
        .await
        .unwrap();
    // A password invite for a non-admin could not sign in.
    assert!(t
        .cp
        .users
        .create_invite(
            &admin(),
            CreateInvite {
                role: Role::Viewer,
                expires_in_hours: None,
            },
        )
        .await
        .is_err());
    // The last enabled provider stays while it is everyone else's way in.
    let err =
        t.cp.sso
            .update_provider(&admin(), &provider.id, disabled())
            .await
            .unwrap_err();
    assert!(matches!(err, ControlError::Conflict { .. }), "{err}");
    t.cp.sso
        .put_sign_in_settings(&admin(), SignInSettings::default())
        .await
        .unwrap();
    t.cp.sso
        .update_provider(&admin(), &provider.id, disabled())
        .await
        .unwrap();
    // Admins-only needs an enabled provider to begin with.
    let err =
        t.cp.sso
            .put_sign_in_settings(&admin(), admins_only)
            .await
            .unwrap_err();
    assert!(matches!(err, ControlError::Validation { .. }), "{err}");
    assert_eq!(t.audit("settings.sign_in").await.len(), 2);
}

#[tokio::test]
async fn starting_sign_ins_stores_nothing_so_anonymous_starts_crowd_out_no_one() {
    let (t, _) = with_provider().await;
    // More than any table of pending sign-ins would hold.
    for _ in 0..12_000 {
        t.cp.sso
            .begin("corp", OidcPurpose::Login, None, None)
            .await
            .unwrap();
    }
    assert!(t.sign_in().await.is_ok());
}

#[tokio::test]
async fn a_changed_or_expired_flow_cookie_is_refused() {
    let (t, provider) = with_provider().await;
    let r =
        t.cp.sso
            .begin("corp", OidcPurpose::Login, Some("/vaults"), None)
            .await
            .unwrap();
    let (state, code, _) = t.idp.authorize(&r.authorization_url);
    assert!(!r.browser_token.contains(&state), "the cookie is sealed");
    let mut changed = r.browser_token.clone().into_bytes();
    let last = changed.len() - 1;
    changed[last] = if changed[last] == b'A' { b'B' } else { b'A' };
    let changed = String::from_utf8(changed).unwrap();
    let err = refused(t.complete(state.clone(), code.clone(), &changed).await);
    assert!(err.to_string().contains("no sign-in in progress"), "{err}");

    // A sign-in older than its lifetime, sealed as the server would.
    let then = Utc::now() - Duration::seconds(REQUEST_TTL_SECS as i64 + 1);
    let old = OidcRequest {
        state_hash: token::hash_token(&state),
        provider_id: provider.id,
        purpose: OidcPurpose::Login,
        nonce: "n".into(),
        pkce_verifier: "v".into(),
        ui_session_hash: None,
        user_id: None,
        return_to: "/vaults".into(),
        created_at: then,
        expires_at: then + Duration::seconds(REQUEST_TTL_SECS as i64),
    };
    let sealed =
        t.cp.sso
            .flow_key
            .seal(FLOW_CONTEXT, &serde_json::to_vec(&old).unwrap());
    let failed =
        t.cp.sso
            .complete(
                SsoCallback {
                    state: Some(state),
                    code: Some(code),
                    ..Default::default()
                },
                Some(&sealed),
                None,
            )
            .await
            .unwrap_err();
    assert!(
        failed.error.to_string().contains("expired"),
        "{}",
        failed.error
    );
    assert_eq!(failed.return_to, "/vaults");
}

#[tokio::test]
async fn a_disable_during_a_role_changing_sign_in_is_not_undone() {
    let (t, view) = with_provider().await;
    t.cp.auth.create_initial_admin().await.unwrap();
    let (_, session) = t.signed_in().await;
    let provider = t.store.get_oidc_provider(&view.id).await.unwrap().unwrap();
    // The sign-in reads the account while it is still enabled...
    let stale = t.store.get_user(&session.user.id).await.unwrap().unwrap();
    assert!(stale.disabled_at.is_none());
    // ...an admin disables it...
    t.store
        .update_user_access(&stale.id, stale.role, Some(Utc::now()), &[])
        .await
        .unwrap();
    // ...and the sign-in then applies a new role from the groups.
    let err =
        t.cp.sso
            .sync_role(&provider, stale.clone(), Role::Admin)
            .await
            .unwrap_err();
    assert!(err.to_string().contains("disabled"), "{err}");
    let now = t.store.get_user(&stale.id).await.unwrap().unwrap();
    assert!(now.disabled_at.is_some(), "still disabled");
    assert_eq!(now.role, stale.role, "role unchanged");
}

#[tokio::test]
async fn the_last_admin_is_not_demoted_by_its_groups() {
    let (t, _) = with_provider().await;
    t.idp
        .set_person(|p| p.groups = vec!["platform-admins".into()]);
    assert_eq!(t.session().await.user.role, Role::Admin);
    t.idp.set_person(|p| p.groups = vec!["auditors".into()]);
    let err = refused(t.sign_in().await);
    assert!(matches!(err, ControlError::SsoRefused { .. }), "{err}");
    assert!(err.to_string().contains("last enabled admin"), "{err}");
}
