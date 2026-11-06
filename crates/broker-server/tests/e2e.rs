// SPDX-FileCopyrightText: 2026 credential-broker contributors
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
use http_body_util::Full;
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
}

struct Upstream {
    addr: SocketAddr,
    ca_pem: String,
}

fn header(req: &Request<Incoming>, name: &str) -> Option<String> {
    req.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

async fn echo(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let body = Echo {
        path: req.uri().path().to_string(),
        host: header(&req, "host"),
        authorization: header(&req, "authorization"),
        proxy_authorization: header(&req, "proxy-authorization"),
        x_api_key: header(&req, "x-api-key"),
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

/// Creates the first admin from the setup token and logs in.
async fn bootstrap_admin(server: &RunningServer) -> (Api, String) {
    let mut api = Api::new(server);
    let status = api.get("/setup/status").await;
    assert_eq!(status["setup_required"], true);
    let enrollment = api
        .post("/setup/totp", json!({ "username": "admin" }))
        .await;
    let secret = enrollment["secret"].as_str().unwrap().to_string();

    // A wrong setup token is refused.
    let (status, _, _) = api
        .call(
            reqwest::Method::POST,
            "/setup",
            Some(json!({
                "setup_token": "cbsetup_wrong",
                "username": "admin",
                "password": PASSWORD,
                "totp_secret": secret,
                "totp_code": totp(&secret, 0),
            })),
        )
        .await;
    assert!(status.is_client_error());

    let token = server
        .setup_token
        .clone()
        .expect("setup token printed once");
    api.post(
        "/setup",
        json!({
            "setup_token": token,
            "username": "admin",
            "password": PASSWORD,
            "totp_secret": secret,
            "totp_code": totp(&secret, 0),
        }),
    )
    .await;

    // The setup token is single use.
    let (status, _, _) = api
        .call(
            reqwest::Method::POST,
            "/setup",
            Some(json!({
                "setup_token": token,
                "username": "second",
                "password": PASSWORD,
                "totp_secret": secret,
                "totp_code": totp(&secret, 0),
            })),
        )
        .await;
    assert!(status.is_client_error());

    // Setup consumed the current TOTP step, so log in with the next one.
    let (status, headers, body) = api
        .call(
            reqwest::Method::POST,
            "/auth/login",
            Some(json!({ "username": "admin", "password": PASSWORD, "totp_code": totp(&secret, 30) })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
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
            }),
        )
        .await;
    let credential_id = credential["id"].as_str().unwrap().to_string();
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

    let created_key = api
        .post(
            "/api-keys",
            json!({ "name": "ci", "vault_id": vault_id, "role": "session_issuer", "expires_in_days": 1 }),
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
    // A session issuer cannot add credentials.
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

    // --- secrets are write-only ------------------------------------------------
    let mut bodies = Vec::new();
    for path in [
        format!("/vaults/{vault_id}/credentials"),
        format!("/credentials/{credential_id}"),
        format!("/vaults/{vault_id}/rules"),
        format!("/rules/{rule_id}"),
        format!("/vaults/{vault_id}/sessions"),
        "/templates".to_string(),
        "/audit?page_size=100".to_string(),
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
