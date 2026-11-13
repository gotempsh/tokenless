// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Single sign-on end to end: a real server, and an identity provider on
//! loopback that signs people in when the browser reaches its authorize
//! endpoint. The browser is played by an HTTP client that follows the
//! redirects by hand and keeps the cookies it is given.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use broker_server::{RunningServer, Server, ServerConfig};
use chrono::Utc;
use serde_json::{json, Value};
use tokenless_auth::jwt::testing::TestKey;

struct Idp {
    issuer: String,
    key: TestKey,
    groups: Mutex<Vec<String>>,
    /// code -> (nonce, PKCE challenge)
    codes: Mutex<HashMap<String, (String, String)>>,
}

async fn discovery(State(idp): State<Arc<Idp>>) -> Json<Value> {
    Json(json!({
        "issuer": idp.issuer,
        "authorization_endpoint": format!("{}/authorize", idp.issuer),
        "token_endpoint": format!("{}/token", idp.issuer),
        "jwks_uri": format!("{}/keys", idp.issuer),
        "id_token_signing_alg_values_supported": ["ES256"],
    }))
}

async fn keys(State(idp): State<Arc<Idp>>) -> Json<Value> {
    Json(json!({ "keys": [idp.key.jwk()] }))
}

/// The person is already signed in at the provider: it sends the browser
/// straight back with a code.
async fn authorize(
    State(idp): State<Arc<Idp>>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let code = format!("code-{}", tokenless_auth::token::random_value());
    idp.codes.lock().unwrap().insert(
        code.clone(),
        (q["nonce"].clone(), q["code_challenge"].clone()),
    );
    let back = format!(
        "{}?code={code}&state={}",
        q["redirect_uri"],
        url::form_urlencoded::byte_serialize(q["state"].as_bytes()).collect::<String>()
    );
    (StatusCode::FOUND, [(header::LOCATION, back)]).into_response()
}

async fn token(State(idp): State<Arc<Idp>>, headers: HeaderMap, body: String) -> Response {
    let form: HashMap<String, String> = url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect();
    use base64::Engine;
    let expected = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("tokenless:idp-client-secret")
    );
    if headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        != Some(&expected)
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid_client"})),
        )
            .into_response();
    }
    let Some((nonce, challenge)) = idp.codes.lock().unwrap().remove(&form["code"]) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_grant"})),
        )
            .into_response();
    };
    if tokenless_control::service::sso::oidc::pkce_challenge(&form["code_verifier"]) != challenge {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_grant"})),
        )
            .into_response();
    }
    let now = Utc::now().timestamp();
    let id_token = idp.key.sign(&json!({
        "iss": idp.issuer,
        "aud": "tokenless",
        "sub": "subject-grace",
        "exp": now + 300,
        "iat": now,
        "auth_time": now,
        "nonce": nonce,
        "preferred_username": "grace",
        "groups": *idp.groups.lock().unwrap(),
    }));
    Json(json!({ "id_token": id_token, "access_token": "at", "token_type": "Bearer" }))
        .into_response()
}

async fn start_idp() -> Arc<Idp> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let idp = Arc::new(Idp {
        issuer: format!("http://127.0.0.1:{}", addr.port()),
        key: TestKey::generate("loopback-key"),
        groups: Mutex::new(vec!["broker-editors".into()]),
        codes: Mutex::new(HashMap::new()),
    });
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/keys", get(keys))
        .route("/authorize", get(authorize))
        .route("/token", post(token))
        .with_state(idp.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    idp
}

/// A browser: no automatic redirects, and the cookies it was given.
struct Browser {
    http: reqwest::Client,
    cookies: HashMap<String, String>,
}

impl Browser {
    fn new() -> Self {
        Self {
            http: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            cookies: HashMap::new(),
        }
    }

    /// GETs `url` and returns the status and where it redirects to.
    async fn visit(&mut self, url: &str) -> (reqwest::StatusCode, String) {
        let cookie = self
            .cookies
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ");
        let mut request = self.http.get(url);
        if !cookie.is_empty() {
            request = request.header(header::COOKIE.as_str(), cookie);
        }
        let response = request.send().await.unwrap();
        for set in response.headers().get_all(header::SET_COOKIE.as_str()) {
            let set = set.to_str().unwrap();
            let pair = set.split(';').next().unwrap();
            let (name, value) = pair.split_once('=').unwrap();
            self.cookies.insert(name.to_string(), value.to_string());
        }
        let location = response
            .headers()
            .get(header::LOCATION.as_str())
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_default();
        (response.status(), location)
    }
}

async fn admin_session(server: &RunningServer) -> (reqwest::Client, String, String) {
    let generated = server.initial_admin.as_ref().unwrap();
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    let response = http
        .post(format!("http://{}/api/v1/auth/login", server.api_addr))
        .json(&json!({ "username": "admin", "password": generated.password.as_str() }))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let cookie = response.headers()[header::SET_COOKIE.as_str()]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let body: Value = response.json().await.unwrap();
    (
        http,
        cookie,
        body["csrf_token"].as_str().unwrap().to_string(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_person_signs_in_with_their_identity_provider() {
    let idp = start_idp().await;
    let data = tempfile::tempdir().unwrap();
    let mut config = ServerConfig::new(data.path());
    config.api_listen = "127.0.0.1:0".parse().unwrap();
    config.node_listen = "127.0.0.1:0".parse().unwrap();
    let server = Server::start(config).await.unwrap();
    let api = format!("http://{}/api/v1", server.api_addr);

    let (http, cookie, csrf) = admin_session(&server).await;
    let created = http
        .post(format!("{api}/identity-providers"))
        .header("cookie", &cookie)
        .header("x-csrf-token", &csrf)
        .json(&json!({
            "slug": "corp",
            "name": "Corp",
            "issuer": idp.issuer,
            "client_id": "tokenless",
            "client_secret": "idp-client-secret",
            "redirect_uri": format!("{api}/auth/oidc/callback"),
            "role_mappings": [{ "group": "broker-editors", "role": "member" }],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), reqwest::StatusCode::CREATED);
    let created: Value = created.json().await.unwrap();
    assert_eq!(created["has_client_secret"], true);
    // A provider the issuer does not give away gets the OpenID logo.
    assert_eq!(created["brand"], "openid");
    assert!(!created.to_string().contains("idp-client-secret"));

    let options: Value = reqwest::get(format!("{api}/auth/sign-in-options"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        options["providers"],
        json!([{ "slug": "corp", "name": "Corp", "brand": "openid" }])
    );
    assert_eq!(options["password_sign_in"], "everyone");

    // To the provider and back.
    let mut browser = Browser::new();
    let (status, to_idp) = browser
        .visit(&format!("{api}/auth/oidc/corp/start?return_to=/vaults"))
        .await;
    assert_eq!(status, reqwest::StatusCode::SEE_OTHER);
    assert!(
        to_idp.starts_with(&format!("{}/authorize?", idp.issuer)),
        "{to_idp}"
    );
    assert!(browser.cookies.contains_key("__Host-tokenless_sso"));
    let (status, callback) = browser.visit(&to_idp).await;
    assert_eq!(status, reqwest::StatusCode::FOUND);
    let (status, landed) = browser.visit(&callback).await;
    assert_eq!(status, reqwest::StatusCode::SEE_OTHER, "{landed}");
    assert_eq!(landed, "/vaults");
    assert_eq!(
        browser.cookies["__Host-tokenless_sso"], "",
        "the flow cookie is cleared"
    );
    let session = browser.cookies["__Host-broker_session"].clone();
    let me: Value = http
        .get(format!("{api}/auth/me"))
        .header("cookie", format!("__Host-broker_session={session}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me["user"]["username"], "grace");
    assert_eq!(me["user"]["role"], "member");
    assert_eq!(me["sso"]["slug"], "corp");

    // The same answer again, or in a browser that did not ask, is refused.
    let (_, replay) = browser.visit(&callback).await;
    assert!(replay.starts_with("/?sso_error="), "{replay}");
    let (_, to_idp) = Browser::new()
        .visit(&format!("{api}/auth/oidc/corp/start"))
        .await;
    let mut other = Browser::new();
    let (_, callback) = other.visit(&to_idp).await;
    let (_, refused) = other.visit(&callback).await;
    assert!(refused.contains("another+browser"), "{refused}");

    // Groups that map to no role are refused, saying which were seen, on
    // the console page the sign-in was headed for.
    *idp.groups.lock().unwrap() = vec!["marketing".into()];
    let mut browser = Browser::new();
    let (_, to_idp) = browser
        .visit(&format!(
            "{api}/auth/oidc/corp/start?return_to=%2F%23%2Fvaults"
        ))
        .await;
    let (_, callback) = browser.visit(&to_idp).await;
    let (_, refused) = browser.visit(&callback).await;
    assert!(refused.starts_with("/?sso_error="), "{refused}");
    assert!(refused.ends_with("#/vaults"), "{refused}");
    assert!(refused.contains("marketing"), "{refused}");
    assert!(!browser.cookies.contains_key("__Host-broker_session"));
}
