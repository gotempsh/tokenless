// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end: a real server, an enrolled data plane and a local TLS
//! upstream, driven only through the public HTTP APIs and the proxy.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use broker_control::ControlConfig;
use broker_dataplane::{enroll, DataPlane, DataPlaneConfig};
use broker_server::{RunningServer, Server, ServerConfig};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, SET_COOKIE};
use reqwest::{Certificate, StatusCode};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

const SECRET: &str = "upstream-secret-token-6d1f0c2b9e";
const CLIENT_SUPPLIED: &str = "Bearer client-supplied-value";
const PASSWORD: &str = "correct horse battery staple";

// ----- local TLS upstream that echoes the headers it received --------------

#[derive(Debug, Serialize, Deserialize)]
struct Echo {
    path: String,
    host: Option<String>,
    authorization: Option<String>,
    proxy_authorization: Option<String>,
    x_api_key: Option<String>,
    #[serde(default)]
    query: Option<String>,
    #[serde(default)]
    x_tool_key: Option<String>,
    #[serde(default)]
    body: String,
}

struct Upstream {
    addr: SocketAddr,
    ca_pem: String,
}

fn header<B>(req: &Request<B>, name: &str) -> Option<String> {
    req.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

async fn echo(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let (parts, incoming) = req.into_parts();
    let req = Request::from_parts(parts, ());
    let received = incoming
        .collect()
        .await
        .map(|b| String::from_utf8_lossy(&b.to_bytes()).into_owned())
        .unwrap_or_default();
    let body = Echo {
        path: req.uri().path().to_string(),
        host: header(&req, "host"),
        authorization: header(&req, "authorization"),
        proxy_authorization: header(&req, "proxy-authorization"),
        x_api_key: header(&req, "x-api-key"),
        query: req.uri().query().map(str::to_string),
        x_tool_key: header(&req, "x-tool-key"),
        body: received,
    };
    let bytes = serde_json::to_vec(&body).unwrap();
    Ok(Response::builder()
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(bytes)))
        .unwrap())
}

async fn start_upstream() -> Upstream {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
        .unwrap()
        .signed_by(&leaf_key, &issuer)
        .unwrap();
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from(leaf.der().to_vec())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
    )
    .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                continue;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), hyper::service::service_fn(echo))
                    .await;
            });
        }
    });
    Upstream {
        addr,
        ca_pem: ca_cert.pem(),
    }
}

// ----- management API client -------------------------------------------------

struct Api {
    base: String,
    http: reqwest::Client,
    cookie: Option<String>,
    csrf: Option<String>,
    api_key: Option<String>,
}

impl Api {
    fn new(server: &RunningServer) -> Self {
        Self {
            base: format!("http://{}/api/v1", server.api_addr),
            http: reqwest::Client::builder().no_proxy().build().unwrap(),
            cookie: None,
            csrf: None,
            api_key: None,
        }
    }

    fn headers(&self) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(key) = &self.api_key {
            h.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {key}")).unwrap(),
            );
        } else if let Some(cookie) = &self.cookie {
            h.insert("cookie", HeaderValue::from_str(cookie).unwrap());
            if let Some(csrf) = &self.csrf {
                h.insert("x-csrf-token", HeaderValue::from_str(csrf).unwrap());
            }
        }
        h
    }

    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, HeaderMap, Value) {
        let mut req = self
            .http
            .request(method, format!("{}{}", self.base, path))
            .headers(self.headers());
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let text = resp.text().await.unwrap();
        let value = serde_json::from_str(&text).unwrap_or(Value::String(text));
        (status, headers, value)
    }

    async fn get(&self, path: &str) -> Value {
        let (status, headers, body) = self.call(reqwest::Method::GET, path, None).await;
        assert_eq!(status, StatusCode::OK, "GET {path}: {body}");
        assert_eq!(headers.get("cache-control").unwrap(), "no-store");
        body
    }

    async fn post(&self, path: &str, body: Value) -> Value {
        let (status, headers, body) = self.call(reqwest::Method::POST, path, Some(body)).await;
        assert!(status.is_success(), "POST {path}: {status} {body}");
        assert_eq!(headers.get("cache-control").unwrap(), "no-store");
        body
    }
}

fn totp(secret: &str, offset_secs: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    broker_auth::totp::code_at(secret, now + offset_secs).unwrap()
}

/// Signs in as the admin created on first start, sets PASSWORD as its
/// password and turns on an authenticator; returns the session and the
/// authenticator's secret.
async fn bootstrap_admin(server: &RunningServer) -> (Api, String) {
    let generated = server
        .initial_admin
        .as_ref()
        .expect("the first start creates the admin");
    assert_eq!(generated.username, "admin");
    let mut api = Api::new(server);

    let (status, _, _) = api
        .call(
            reqwest::Method::POST,
            "/auth/login",
            Some(json!({ "username": "admin", "password": "not-the-generated-one" })),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, headers, body) = api
        .call(
            reqwest::Method::POST,
            "/auth/login",
            Some(json!({ "username": "admin", "password": generated.password.as_str() })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["user"]["totp_enrolled"], false);
    let set_cookie = headers
        .get(SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("Secure"));
    assert!(set_cookie.contains("SameSite=Strict"));
    api.cookie = Some(set_cookie.split(';').next().unwrap().to_string());
    api.csrf = Some(body["csrf_token"].as_str().unwrap().to_string());

    let (status, _, _) = api
        .call(
            reqwest::Method::POST,
            "/auth/password",
            Some(json!({
                "current_password": generated.password.as_str(),
                "new_password": PASSWORD,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let enrollment = api.post("/auth/authenticator/enrollment", json!({})).await;
    let secret = enrollment["secret"].as_str().unwrap().to_string();
    let enabled = api
        .post(
            "/auth/authenticator",
            json!({ "secret": secret, "code": totp(&secret, 0), "password": PASSWORD }),
        )
        .await;
    assert_eq!(enabled["totp_enrolled"], true);

    // From now on the password alone asks for the code.
    let (status, _, body) = Api::new(server)
        .call(
            reqwest::Method::POST,
            "/auth/login",
            Some(json!({ "username": "admin", "password": PASSWORD })),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "second_factor_required");
    (api, secret)
}

// ----- proxy helpers ---------------------------------------------------------

/// Sends a raw CONNECT and returns the proxy's status code.
async fn connect_status(proxy: SocketAddr, target: &str, token: Option<&str>) -> u16 {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some(t) = token {
        req.push_str(&format!("Proxy-Authorization: Bearer {t}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let head = String::from_utf8_lossy(&buf[..n]).to_string();
    head.split_whitespace().nth(1).unwrap().parse().unwrap()
}

fn proxied_client(proxy: SocketAddr, token: &str, roots: &[&str]) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .proxy(reqwest::Proxy::https(format!("http://{token}@{proxy}")).unwrap())
        .tls_built_in_root_certs(false)
        .timeout(Duration::from_secs(10));
    for pem in roots {
        builder = builder.add_root_certificate(Certificate::from_pem(pem.as_bytes()).unwrap());
    }
    builder.build().unwrap()
}

async fn eventually<F, Fut>(what: &str, timeout: Duration, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = Instant::now();
    while start.elapsed() < timeout {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for {what}");
}

/// The token behind a live session's `Proxy-Authorization: Basic` value.
fn current_token(live: &broker_server::launcher::session::LiveSession) -> String {
    let auth = live.auth.load();
    let encoded = auth.strip_prefix("Basic ").unwrap();
    let decoded = String::from_utf8(
        {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.decode(encoded)
        }
        .unwrap(),
    )
    .unwrap();
    decoded.trim_end_matches(':').to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn end_to_end() {
    let data = tempfile::tempdir().unwrap();
    let upstream = start_upstream().await;
    let upstream_port = upstream.addr.port();

    // --- server -----------------------------------------------------------
    let mut config = ServerConfig::new(data.path());
    config.api_listen = "127.0.0.1:0".parse().unwrap();
    config.node_listen = "127.0.0.1:0".parse().unwrap();
    config.control = ControlConfig {
        lease_secs: 3,
        ..ControlConfig::default()
    };
    config.validation_public_roots = false;
    config.validation_extra_roots =
        broker_dataplane::tls::certs_from_pem("upstream CA", &upstream.ca_pem).unwrap();
    let server = Server::start(config).await.unwrap();
    let (mut api, _totp_secret) = bootstrap_admin(&server).await;

    // CSRF: a cookie-authenticated write without the token is refused.
    let csrf = api.csrf.take();
    let (status, _, body) = api
        .call(
            reqwest::Method::POST,
            "/vaults",
            Some(json!({ "name": "nope" })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    api.csrf = csrf;

    // --- policy: vault, credential, rule -----------------------------------
    let vault = api.post("/vaults", json!({ "name": "agents" })).await;
    let vault_id = vault["id"].as_str().unwrap().to_string();
    let credential = api
        .post(
            &format!("/vaults/{vault_id}/credentials"),
            json!({
                "name": "local-upstream",
                "template_id": "generic-bearer",
                "host_override": [format!("https://localhost:{upstream_port}")],
                "fields": { "token": SECRET },
                "substitutions": [{
                    "placeholder": "__UPSTREAM_TOKEN__",
                    "field": "token",
                    "env": "UPSTREAM_TOKEN",
                    "locations": ["path", "query", "header", "body"],
                }],
            }),
        )
        .await;
    let credential_id = credential["id"].as_str().unwrap().to_string();
    assert_eq!(
        credential["substitutions"][0]["placeholder"],
        "__UPSTREAM_TOKEN__"
    );
    assert!(!credential.to_string().contains(SECRET));
    let rule = api
        .post(
            &format!("/vaults/{vault_id}/rules"),
            json!({ "name": "local-upstream", "credential_id": credential_id }),
        )
        .await;
    let rule_id = rule["id"].as_str().unwrap().to_string();

    // --- enrol and start the data plane --------------------------------------
    let join = api.post("/nodes/join-tokens", json!({})).await;
    let join_token = join["token"].as_str().unwrap().to_string();
    let control_url = format!("https://127.0.0.1:{}", server.node_addr.port());
    let identity = enroll(&control_url, &join_token, "e2e-node").await.unwrap();
    // The join token is one-time.
    assert!(enroll(&control_url, &join_token, "again").await.is_err());

    let upstream_roots =
        broker_dataplane::tls::certs_from_pem("upstream CA", &upstream.ca_pem).unwrap();
    let dp = DataPlane::start(
        DataPlaneConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            mcp_listen: Some("127.0.0.1:0".parse().unwrap()),
            use_public_roots: false,
            extra_upstream_roots: upstream_roots,
            audit_flush_interval: Duration::from_millis(100),
            ..DataPlaneConfig::default()
        },
        identity,
    )
    .await
    .unwrap();
    let proxy = dp.local_addr();
    eventually("first snapshot", Duration::from_secs(10), || async {
        dp.lease_valid()
    })
    .await;

    // --- mint a session (also via a vault-scoped API key) ---------------------
    let minted = api
        .post(
            &format!("/vaults/{vault_id}/sessions"),
            json!({ "rule_ids": [rule_id], "ttl_secs": 600, "labels": { "agent": "e2e" } }),
        )
        .await;
    let session_token = minted["token"].as_str().unwrap().to_string();
    let session_id = minted["session"]["id"].as_str().unwrap().to_string();
    assert!(session_token.starts_with("v4.public."));

    // Agents get sessions; the old key-for-agents role is gone.
    let (status, _, _) = api
        .call(
            reqwest::Method::POST,
            "/api-keys",
            Some(json!({ "name": "ci", "vault_id": vault_id, "role": "session_issuer", "expires_in_days": 1 })),
        )
        .await;
    assert!(
        status.is_client_error(),
        "session_issuer keys are refused, got {status}"
    );
    let created_key = api
        .post(
            "/api-keys",
            json!({ "name": "ci", "vault_id": vault_id, "role": "editor", "expires_in_days": 1 }),
        )
        .await;
    let raw_key = created_key["api_key"].as_str().unwrap().to_string();
    assert!(raw_key.starts_with("cbk_"));
    let keys_listing = api.get("/api-keys").await;
    assert!(!keys_listing.to_string().contains(&raw_key));
    let mut automation = Api::new(&server);
    automation.api_key = Some(raw_key);
    let minted_by_key = automation
        .post(
            &format!("/vaults/{vault_id}/sessions"),
            json!({ "rule_ids": [rule_id], "ttl_secs": 300 }),
        )
        .await;
    assert!(minted_by_key["token"]
        .as_str()
        .unwrap()
        .starts_with("v4.public."));
    // An editor key cannot add credentials.
    let (status, _, _) = automation
        .call(
            reqwest::Method::POST,
            &format!("/vaults/{vault_id}/credentials"),
            Some(json!({ "name": "x", "template_id": "openai", "fields": { "api_key": "x" } })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // --- injection through the proxy -------------------------------------------
    let ca_pem = reqwest::get(format!(
        "http://{}/api/v1/ca/interception.pem",
        server.api_addr
    ))
    .await
    .unwrap()
    .text()
    .await
    .unwrap();
    let client = proxied_client(proxy, &session_token, &[&ca_pem, &upstream.ca_pem]);
    let echo: Echo = client
        .get(format!("https://localhost:{upstream_port}/v1/things"))
        .header(AUTHORIZATION, CLIENT_SUPPLIED)
        .header("x-api-key", "client-api-key")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        echo.authorization.as_deref(),
        Some(format!("Bearer {SECRET}").as_str())
    );
    assert_eq!(
        echo.proxy_authorization, None,
        "Proxy-Authorization must be stripped"
    );
    assert_eq!(
        echo.x_api_key, None,
        "client credential headers must be stripped on ruled hosts"
    );
    assert_eq!(echo.path, "/v1/things");

    // --- the MCP gateway: plain HTTP, the session token as a bearer token ---
    let gateway = dp.mcp_addr().expect("MCP gateway listening");
    let direct = reqwest::Client::builder().no_proxy().build().unwrap();
    let gateway_url = |rest: &str| format!("http://{gateway}/mcp/{rest}");
    let response = direct
        .post(gateway_url(&format!("localhost:{upstream_port}/mcp?x=1")))
        .bearer_auth(&session_token)
        .header("mcp-session-id", "abc")
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let echo: Echo = response.json().await.unwrap();
    assert_eq!(
        echo.authorization.as_deref(),
        Some(format!("Bearer {SECRET}").as_str()),
        "the gateway swaps the session token for the credential"
    );
    assert_eq!(echo.path, "/mcp");
    assert_eq!(echo.query.as_deref(), Some("x=1"));
    assert_eq!(
        echo.host.as_deref(),
        Some(format!("localhost:{upstream_port}").as_str())
    );
    assert!(echo.body.contains("tools/list"), "{}", echo.body);
    assert!(!format!("{echo:?}").contains(&session_token));

    let status = |r: reqwest::Response| r.status();
    let no_token = direct
        .get(gateway_url(&format!("localhost:{upstream_port}/mcp")))
        .send()
        .await
        .unwrap();
    assert_eq!(no_token.status(), StatusCode::UNAUTHORIZED);
    assert!(no_token.headers().contains_key("www-authenticate"));
    let upstream_secret = direct
        .get(gateway_url(&format!("localhost:{upstream_port}/mcp")))
        .bearer_auth("not-a-session-token")
        .send()
        .await
        .unwrap();
    assert_eq!(status(upstream_secret), StatusCode::UNAUTHORIZED);
    let elsewhere = direct
        .get(gateway_url("other.example.com/mcp"))
        .bearer_auth(&session_token)
        .send()
        .await
        .unwrap();
    assert_eq!(
        status(elsewhere),
        StatusCode::FORBIDDEN,
        "the gateway only reaches the session's own hosts"
    );
    let off_prefix = direct
        .get(format!("http://{gateway}/localhost:{upstream_port}/mcp"))
        .bearer_auth(&session_token)
        .send()
        .await
        .unwrap();
    assert_eq!(status(off_prefix), StatusCode::NOT_FOUND);

    // --- substitutions: placeholders become the secret on the way out -------
    let echo: Echo = client
        .post(format!(
            "https://localhost:{upstream_port}/v1/keys/__UPSTREAM_TOKEN__?key=__UPSTREAM_TOKEN__"
        ))
        .header("x-tool-key", "Token __UPSTREAM_TOKEN__")
        .json(&json!({ "auth": "__UPSTREAM_TOKEN__" }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(echo.path, format!("/v1/keys/{SECRET}"));
    assert_eq!(
        echo.query.as_deref(),
        Some(format!("key={SECRET}").as_str())
    );
    assert_eq!(
        echo.x_tool_key.as_deref(),
        Some(format!("Token {SECRET}").as_str())
    );
    let sent: Value = serde_json::from_str(&echo.body).unwrap();
    assert_eq!(sent["auth"], SECRET);

    // --- MCP tool limits ----------------------------------------------------
    let (status, _, limited) = api
        .call(
            reqwest::Method::PATCH,
            &format!("/rules/{rule_id}"),
            Some(json!({ "mcp_tools": ["search", "search"] })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{limited}");
    assert_eq!(limited["allow"]["mcp_tools"], json!(["search"]));
    let call = |tool: &str| {
        json!({ "jsonrpc": "2.0", "id": 9, "method": "tools/call",
                "params": { "name": tool, "arguments": { "token": "__UPSTREAM_TOKEN__" } } })
    };
    let mcp_url = format!("https://localhost:{upstream_port}/mcp");
    eventually(
        "tool limits reach the proxy",
        Duration::from_secs(10),
        || async {
            let refused: Value = client
                .post(&mcp_url)
                .json(&call("delete_everything"))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap_or(Value::Null);
            refused["error"]["data"]["tool"] == "delete_everything"
        },
    )
    .await;
    // An allowed call is forwarded, with its placeholder filled in.
    let echo: Echo = client
        .post(&mcp_url)
        .json(&call("search"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let forwarded: Value = serde_json::from_str(&echo.body).unwrap();
    assert_eq!(forwarded["params"]["name"], "search");
    assert_eq!(forwarded["params"]["arguments"]["token"], SECRET);
    // A batch with one refused call is refused whole, one error per request.
    let refused: Value = client
        .post(&mcp_url)
        .json(&json!([
            { "jsonrpc": "2.0", "id": 1, "method": "tools/list" },
            { "jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": { "name": "drop" } },
        ]))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(refused.as_array().map(Vec::len), Some(2), "{refused}");
    assert_eq!(refused[1]["id"], 2);
    // Without a readable body the proxy cannot check, so it refuses.
    let unreadable = client
        .post(&mcp_url)
        .header("content-encoding", "gzip")
        .body("not really gzip")
        .send()
        .await
        .unwrap();
    assert_eq!(unreadable.status(), StatusCode::BAD_REQUEST);
    // GET (the SSE stream) is not a tool call and passes.
    assert!(client
        .get(&mcp_url)
        .send()
        .await
        .unwrap()
        .status()
        .is_success());
    let (status, _, restored) = api
        .call(
            reqwest::Method::PATCH,
            &format!("/rules/{rule_id}"),
            Some(json!({ "allow_all_tools": true })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{restored}");
    assert!(restored["allow"].get("mcp_tools").is_none(), "{restored}");

    // --- no session: 407 -------------------------------------------------------
    assert_eq!(
        connect_status(proxy, &format!("localhost:{upstream_port}"), None).await,
        407
    );
    assert_eq!(
        connect_status(
            proxy,
            &format!("localhost:{upstream_port}"),
            Some("v4.public.garbage")
        )
        .await,
        407
    );

    // --- access bundle + session port (what `run --bundle` does) ------------
    let bundle = api
        .post(
            &format!("/vaults/{vault_id}/bundles"),
            json!({ "name": "local-review", "description": "e2e", "rule_ids": [rule_id] }),
        )
        .await;
    assert_eq!(bundle["rule_ids"], json!([rule_id]));
    let listing = api.get(&format!("/vaults/{vault_id}/bundles")).await;
    assert_eq!(listing["total"], 1);
    {
        use broker_server::launcher::client::{ApiClient, Credentials, MintRequest};
        use broker_server::launcher::port::SessionPort;
        use broker_server::launcher::session::LiveSession;
        use broker_server::launcher::trust::placeholder_env;

        let launcher = Arc::new(
            ApiClient::new(
                &format!("http://{}", server.api_addr),
                automation
                    .api_key
                    .clone()
                    .map(|k| Credentials::ApiKey(zeroize::Zeroizing::new(k))),
            )
            .unwrap(),
        );
        // A vault-bound key needs no --vault.
        let resolved = launcher.resolve_vault(None).await.unwrap();
        assert_eq!(resolved.to_string(), vault_id);
        let missing = launcher
            .mint(
                &resolved,
                &MintRequest {
                    bundle: "no-such-bundle".into(),
                    ttl_secs: 60,
                    longest: false,
                    request_limit: None,
                    labels: Default::default(),
                },
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(
            missing.contains("404") && missing.contains("no-such-bundle"),
            "{missing}"
        );

        let live = LiveSession::start(
            launcher.clone(),
            resolved,
            MintRequest {
                bundle: "local-review".into(),
                ttl_secs: 120,
                longest: false,
                request_limit: None,
                labels: [("command".to_string(), "e2e".to_string())].into(),
            },
        )
        .await
        .unwrap();
        let session = live.current.load_full();
        assert_eq!(session.bundle.as_ref().unwrap().name, "local-review");
        assert_eq!(session.rule_ids.len(), 1);

        // The agent can ask what it may reach; nothing secret comes back.
        let first_token = current_token(&live);
        let discovery = launcher.discover(&first_token).await.unwrap();
        assert_eq!(discovery.session.id, session.id);
        assert_eq!(discovery.services.len(), 1);
        let reached = &discovery.services[0];
        assert_eq!(reached.credential, "local-upstream");
        assert_eq!(reached.hosts, [format!("localhost:{upstream_port}")]);
        assert_eq!(reached.placeholders[0].placeholder, "__UPSTREAM_TOKEN__");
        assert!(!serde_json::to_string(&discovery).unwrap().contains(SECRET));
        assert_eq!(
            placeholder_env(&live.services),
            [(
                "UPSTREAM_TOKEN".to_string(),
                "__UPSTREAM_TOKEN__".to_string()
            )]
        );
        let port = SessionPort::start(
            "127.0.0.1:0".parse().unwrap(),
            &proxy.to_string(),
            live.auth.clone(),
            live.listing(),
        )
        .await
        .unwrap();

        // The agent's client has a plain proxy URL: no token anywhere.
        let mut builder = reqwest::Client::builder()
            .proxy(reqwest::Proxy::https(format!("http://{}", port.addr)).unwrap())
            .tls_built_in_root_certs(false)
            .timeout(Duration::from_secs(10));
        for pem in [&ca_pem, &upstream.ca_pem] {
            builder = builder.add_root_certificate(Certificate::from_pem(pem.as_bytes()).unwrap());
        }
        let agent = builder.build().unwrap();
        let echo: Echo = agent
            .get(format!("https://localhost:{upstream_port}/via-port"))
            .header(AUTHORIZATION, CLIENT_SUPPLIED)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(
            echo.authorization.as_deref(),
            Some(format!("Bearer {SECRET}").as_str()),
            "the bundle's credential is injected through the session port"
        );
        assert_eq!(echo.proxy_authorization, None);

        // A service added to the bundle while the agent runs: the next
        // renewal mints a session that reaches it, and what the agent can
        // ask the session port about follows.
        let read_only = api
            .post(
                &format!("/vaults/{vault_id}/rules"),
                json!({ "name": "local-upstream-read", "credential_id": credential_id, "methods": ["GET"] }),
            )
            .await;
        let read_only_id = read_only["id"].as_str().unwrap().to_string();
        let (status, _, widened) = api
            .call(
                reqwest::Method::PATCH,
                &format!("/bundles/{}", bundle["id"].as_str().unwrap()),
                Some(json!({ "rule_ids": [rule_id, read_only_id] })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{widened}");
        let listed = |body: Value| -> Vec<String> {
            body["services"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s["rule"].as_str().unwrap().to_string())
                .collect()
        };
        let ask_port = || async {
            reqwest::get(format!("http://{}/services", port.addr))
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()
        };
        assert_eq!(listed(ask_port().await), ["local-upstream"]);
        live.renew_now().await.unwrap();
        assert_eq!(live.current.load().rule_ids.len(), 2);
        let mut after = listed(ask_port().await);
        after.sort();
        assert_eq!(after, ["local-upstream", "local-upstream-read"]);

        // Ending (with the tokens alone) ends both sessions it minted and
        // cuts the port off.
        assert_eq!(live.end().await, 2);
        let (status, _, _) = api
            .call(
                reqwest::Method::DELETE,
                &format!("/rules/{read_only_id}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let record = api.get(&format!("/vaults/{vault_id}/sessions")).await;
        let ended = record["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["id"] == session.id.to_string())
            .unwrap()
            .clone();
        assert!(ended["revoked_at"].is_string(), "{ended}");
        assert_eq!(ended["bundle"]["name"], "local-review");
        let port_addr = port.addr;
        eventually(
            "the ended session to be refused",
            Duration::from_secs(10),
            || async {
                connect_status(port_addr, &format!("localhost:{upstream_port}"), None).await == 407
            },
        )
        .await;
        port.stop();

        // Self-revocation needs a real session token.
        let bad = launcher
            .revoke_self("v4.public.garbage")
            .await
            .unwrap_err()
            .to_string();
        assert!(bad.contains("401"), "{bad}");
        let ended = launcher
            .discover(&first_token)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            ended.contains("401") && ended.contains("revoked"),
            "{ended}"
        );
    }

    // --- imported template with a validation request ---------------------
    let yaml = format!(
        "id: local-echo\nversion: 1\nname: Local echo\nhosts: [\"localhost:{upstream_port}\"]\n\
         allow:\n  paths: [\"/*\"]\n  methods: [GET]\n\
         credential_fields:\n  - name: token\n    label: Token\n\
         injection:\n  method: header\n  name: X-Service-Token\n  field: token\n\
         validation:\n  method: GET\n  path: /health\n  expect_status: [200]\n"
    );
    let imported = api.post("/templates/import", json!({ "yaml": yaml })).await;
    assert_eq!(imported["status"], "pending_approval");
    assert_eq!(
        imported["template"]["hosts"][0],
        format!("localhost:{upstream_port}")
    );
    let echo_credential = json!({
        "name": "echo",
        "template_id": "local-echo",
        "fields": { "token": SECRET },
    });
    let (status, _, _) = api
        .call(
            reqwest::Method::POST,
            &format!("/vaults/{vault_id}/credentials"),
            Some(echo_credential.clone()),
        )
        .await;
    assert!(
        status.is_client_error(),
        "a pending template must not back credentials"
    );
    api.post("/templates/local-echo/1/approve", json!({})).await;
    let echo = api
        .post(&format!("/vaults/{vault_id}/credentials"), echo_credential)
        .await;
    let echo_id = echo["id"].as_str().unwrap().to_string();
    let blocked = api
        .post(&format!("/credentials/{echo_id}/validate"), json!({}))
        .await;
    assert_eq!(blocked["ok"], false, "{blocked}");
    assert!(
        blocked["detail"].as_str().unwrap().contains("loopback"),
        "{blocked}"
    );

    // --- egress policy: private passthrough destinations are blocked -------
    let loopback_target = format!("127.0.0.1:{upstream_port}");
    assert_eq!(
        connect_status(proxy, &loopback_target, Some(&session_token)).await,
        403,
        "loopback passthrough must be refused by default"
    );
    api.call(
        reqwest::Method::PUT,
        "/settings",
        Some(json!({
            "unmatched_host_policy": "passthrough",
            "egress": { "block_private": true, "allow": ["127.0.0.0/8"] }
        })),
    )
    .await;
    eventually(
        "egress allowlist applied",
        Duration::from_secs(5),
        || async { connect_status(proxy, &loopback_target, Some(&session_token)).await == 200 },
    )
    .await;
    // A malformed range is rejected with a 400.
    let (status, _, _) = api
        .call(
            reqwest::Method::PUT,
            "/settings",
            Some(json!({
                "unmatched_host_policy": "passthrough",
                "egress": { "block_private": true, "allow": ["10.0.0.1/8"] }
            })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // With loopback allowed, the validation request reaches the upstream.
    let validated = api
        .post(&format!("/credentials/{echo_id}/validate"), json!({}))
        .await;
    assert_eq!(validated["ok"], true, "{validated}");
    assert_eq!(validated["status"], 200);
    assert!(!validated.to_string().contains(SECRET));

    // --- unmatched host: tunnelled untouched ----------------------------------
    // 127.0.0.1 has no rule, so the client must see the upstream's own
    // certificate (it only trusts the upstream CA here) and its own header.
    let direct = proxied_client(proxy, &session_token, &[&upstream.ca_pem]);
    let echo: Echo = direct
        .get(format!("https://127.0.0.1:{upstream_port}/passthrough"))
        .header(AUTHORIZATION, CLIENT_SUPPLIED)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(echo.authorization.as_deref(), Some(CLIENT_SUPPLIED));
    assert_eq!(echo.path, "/passthrough");

    // --- deny policy with an always-reachable host -----------------------------
    let deny = |hosts: Vec<String>| {
        json!({
            "unmatched_host_policy": "deny",
            "egress": { "block_private": true, "allow": ["127.0.0.0/8"] },
            "passthrough_hosts": hosts,
        })
    };
    api.call(reqwest::Method::PUT, "/settings", Some(deny(vec![])))
        .await;
    eventually("deny policy applied", Duration::from_secs(5), || async {
        connect_status(proxy, &loopback_target, Some(&session_token)).await == 403
    })
    .await;
    let (status, _, saved) = api
        .call(
            reqwest::Method::PUT,
            "/settings",
            Some(deny(vec![loopback_target.clone()])),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    assert_eq!(saved["passthrough_hosts"][0], loopback_target);
    eventually(
        "always-reachable host tunnelled under deny",
        Duration::from_secs(5),
        || async { connect_status(proxy, &loopback_target, Some(&session_token)).await == 200 },
    )
    .await;
    // Exceptions are tunnelled, never intercepted: the upstream's own
    // certificate and the agent's own header reach it.
    let echo: Echo = direct
        .get(format!("https://127.0.0.1:{upstream_port}/excepted"))
        .header(AUTHORIZATION, CLIENT_SUPPLIED)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(echo.authorization.as_deref(), Some(CLIENT_SUPPLIED));
    // They still obey the egress policy.
    api.call(
        reqwest::Method::PUT,
        "/settings",
        Some(json!({
            "unmatched_host_policy": "deny",
            "egress": { "block_private": true, "allow": [] },
            "passthrough_hosts": [loopback_target.clone()],
        })),
    )
    .await;
    eventually(
        "egress still applies to always-reachable hosts",
        Duration::from_secs(5),
        || async { connect_status(proxy, &loopback_target, Some(&session_token)).await == 403 },
    )
    .await;

    // --- audit records were shipped by the node ----------------------------
    eventually(
        "proxy.inject audit event",
        Duration::from_secs(10),
        || async {
            let page = api.get("/audit?action_prefix=proxy.inject").await;
            page["items"].as_array().is_some_and(|items| {
                items.iter().any(|e| {
                    e["action"] == "proxy.inject"
                        && e["vault_id"] == vault_id.as_str()
                        && e["actor"].as_str().is_some_and(|a| a.starts_with("node:"))
                })
            })
        },
    )
    .await;

    // Each injected request is paired with the API's answer, and tunnels
    // are logged too.
    eventually(
        "proxy.response paired with its proxy.inject",
        Duration::from_secs(10),
        || async {
            let page = api.get("/audit?action_prefix=proxy.&page_size=100").await;
            let items = page["items"].as_array().cloned().unwrap_or_default();
            let responded = items.iter().find(|e| {
                e["action"] == "proxy.response"
                    && e["detail"]["status"] == "200"
                    && e["detail"]["duration_ms"].is_string()
            });
            let paired = responded.is_some_and(|r| {
                items.iter().any(|e| {
                    e["action"] == "proxy.inject"
                        && e["detail"]["request_id"] == r["detail"]["request_id"]
                })
            });
            let tunnelled = items.iter().any(|e| {
                e["action"] == "proxy.tunnel"
                    && e["detail"]["reason"]
                        .as_str()
                        .is_some_and(|r| r.contains("always-reachable"))
            });
            paired && tunnelled
        },
    )
    .await;

    // A service's log: what was done to it and the requests that used it,
    // the API's answers included, and nothing about other services.
    let log = api
        .get(&format!(
            "/audit?vault_id={vault_id}&credential_id={credential_id}&page_size=100"
        ))
        .await;
    let items = log["items"].as_array().cloned().unwrap_or_default();
    let actions: Vec<&str> = items.iter().filter_map(|e| e["action"].as_str()).collect();
    for action in [
        "credential.create",
        "rule.create",
        "proxy.inject",
        "proxy.response",
    ] {
        assert!(
            actions.contains(&action),
            "{action} missing from the service's log: {actions:?}"
        );
    }
    let ours = format!("credential:{credential_id}");
    assert!(
        items.iter().all(|e| e["target"] == ours.as_str()
            || e["detail"]["credential_id"] == credential_id.as_str()),
        "the service's log holds another service's events: {items:?}"
    );

    // --- secrets are write-only ------------------------------------------------
    let mut bodies = Vec::new();
    for path in [
        format!("/vaults/{vault_id}/credentials"),
        format!("/credentials/{credential_id}"),
        format!("/vaults/{vault_id}/rules"),
        format!("/rules/{rule_id}"),
        format!("/vaults/{vault_id}/sessions"),
        format!("/sessions/{session_id}/services"),
        "/vaults/overview".to_string(),
        format!("/vaults/{vault_id}/overview"),
        "/templates".to_string(),
        "/audit?page_size=100".to_string(),
        format!("/audit?credential_id={credential_id}&page_size=100"),
        "/nodes".to_string(),
        "/settings".to_string(),
        "/api-keys".to_string(),
        "/auth/me".to_string(),
    ] {
        bodies.push(api.get(&path).await.to_string());
    }
    for body in &bodies {
        assert!(
            !body.contains(SECRET),
            "secret leaked through the API: {body}"
        );
    }
    let (status, _, _) = api
        .call(
            reqwest::Method::GET,
            &format!("/credentials/{credential_id}/secret"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    // Rotation is write-only too: the response carries metadata only.
    let rotated = api
        .call(
            reqwest::Method::PUT,
            &format!("/credentials/{credential_id}/secret"),
            Some(json!({ "fields": { "token": SECRET } })),
        )
        .await;
    assert_eq!(rotated.0, StatusCode::OK, "{}", rotated.2);
    assert!(!rotated.2.to_string().contains(SECRET));
    // And at rest the database holds ciphertext only.
    for entry in std::fs::read_dir(data.path()).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        assert!(
            !bytes.windows(SECRET.len()).any(|w| w == SECRET.as_bytes()),
            "plaintext secret found on disk"
        );
    }

    // --- revocation reaches the data plane within seconds ----------------------
    api.post(&format!("/sessions/{session_id}/revoke"), json!({}))
        .await;
    let target = format!("localhost:{upstream_port}");
    eventually(
        "revoked session rejected",
        Duration::from_secs(5),
        || async { connect_status(proxy, &target, Some(&session_token)).await == 407 },
    )
    .await;

    // --- step-up rejects a wrong code -----------------------------------------
    let (status, _, body) = api
        .call(
            reqwest::Method::POST,
            "/auth/step-up",
            Some(json!({ "code": "000000" })),
        )
        .await;
    assert!(status.is_client_error(), "{body}");

    // --- lease expiry: control plane gone, data plane fails closed ------------
    let other = minted_by_key["token"].as_str().unwrap().to_string();
    assert_eq!(connect_status(proxy, &target, Some(&other)).await, 200);
    let pooled = proxied_client(proxy, &other, &[&ca_pem, &upstream.ca_pem]);
    let ok = pooled
        .get(format!("https://localhost:{upstream_port}/before"))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
    server.shutdown();
    eventually("lease expiry", Duration::from_secs(10), || async {
        !dp.lease_valid()
    })
    .await;
    assert_eq!(connect_status(proxy, &target, Some(&other)).await, 503);
    // A tunnel opened before expiry refuses injection too.
    let after = pooled
        .get(format!("https://localhost:{upstream_port}/after"))
        .send()
        .await;
    // Either the pooled tunnel answers 503 itself, or the client opened a
    // fresh CONNECT that was refused; it must never reach the upstream.
    if let Ok(resp) = after {
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
    assert!(dp.metrics().render().contains("lease_refusals_total"));
    dp.shutdown();
}

/// Logs `username` in on a fresh client and returns it with its cookie.
async fn login_as(server: &RunningServer, username: &str, password: &str, code: &str) -> Api {
    let mut api = Api::new(server);
    let (status, headers, body) = api
        .call(
            reqwest::Method::POST,
            "/auth/login",
            Some(json!({ "username": username, "password": password, "totp_code": code })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "login {username}: {body}");
    let set_cookie = headers.get(SET_COOKIE).unwrap().to_str().unwrap();
    api.cookie = Some(set_cookie.split(';').next().unwrap().to_string());
    api.csrf = Some(body["csrf_token"].as_str().unwrap().to_string());
    api
}

#[tokio::test]
async fn people_are_invited_with_a_role_and_can_be_disabled() {
    let data = tempfile::tempdir().unwrap();
    let mut config = ServerConfig::new(data.path());
    config.api_listen = "127.0.0.1:0".parse().unwrap();
    config.node_listen = "127.0.0.1:0".parse().unwrap();
    let server = Server::start(config).await.unwrap();
    let (admin, _) = bootstrap_admin(&server).await;

    let issued = admin
        .post(
            "/invites",
            json!({ "role": "editor", "expires_in_hours": 24 }),
        )
        .await;
    let invite_token = issued["token"].as_str().unwrap().to_string();
    assert!(invite_token.starts_with("cbinv_"));
    assert!(
        issued["invite"].get("token_hash").is_none(),
        "the stored hash must never be returned"
    );
    let listed = admin.get("/invites").await;
    assert_eq!(listed["total"], 1);
    assert!(!listed.to_string().contains(&invite_token));

    // The invitee has no session: everything below is unauthenticated.
    let guest = Api::new(&server);
    let info = guest
        .post("/invites/inspect", json!({ "invite_token": invite_token }))
        .await;
    assert_eq!(info["role"], "editor");
    let (status, _, _) = guest
        .call(
            reqwest::Method::POST,
            "/invites/inspect",
            Some(json!({ "invite_token": "cbinv_forged" })),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let enrollment = guest
        .post(
            "/invites/totp",
            json!({ "invite_token": invite_token, "username": "editor-one" }),
        )
        .await;
    let secret = enrollment["secret"].as_str().unwrap().to_string();
    let accepted = guest
        .post(
            "/invites/accept",
            json!({
                "invite_token": invite_token,
                "username": "editor-one",
                "password": PASSWORD,
                "totp_secret": secret,
                "totp_code": totp(&secret, 0),
            }),
        )
        .await;
    assert_eq!(accepted["role"], "editor");
    let user_id = accepted["id"].as_str().unwrap().to_string();
    let (status, _, _) = guest
        .call(
            reqwest::Method::POST,
            "/invites/accept",
            Some(json!({
                "invite_token": invite_token,
                "username": "editor-two",
                "password": PASSWORD,
                "totp_secret": secret,
                "totp_code": totp(&secret, 30),
            })),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "invites are single use");

    let editor = login_as(&server, "editor-one", PASSWORD, &totp(&secret, 30)).await;
    let me = editor.get("/auth/me").await;
    assert_eq!(me["user"]["role"], "editor");
    let (status, _, _) = editor.call(reqwest::Method::GET, "/users", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _, _) = editor
        .call(
            reqwest::Method::POST,
            "/invites",
            Some(json!({ "role": "admin" })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // The only admin cannot demote themselves.
    let users = admin.get("/users").await;
    assert_eq!(users["total"], 2);
    let admin_id = users["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["username"] == "admin")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, _, body) = admin
        .call(
            reqwest::Method::PATCH,
            &format!("/users/{admin_id}"),
            Some(json!({ "role": "viewer" })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    // Disabling ends the editor's session at once.
    let (status, _, body) = admin
        .call(
            reqwest::Method::PATCH,
            &format!("/users/{user_id}"),
            Some(json!({ "disabled": true })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["disabled_at"].is_string());
    let (status, _, _) = editor.call(reqwest::Method::GET, "/auth/me", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let audit = admin.get("/audit?action_prefix=user.").await;
    let actions: Vec<&str> = audit["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    for expected in ["user.invite", "user.invite.accept", "user.update"] {
        assert!(
            actions.contains(&expected),
            "{expected} missing from {actions:?}"
        );
    }
    server.shutdown();
}
