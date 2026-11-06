// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The management API can be served over TLS with operator-supplied files.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use broker_server::api_tls::ApiTlsFiles;
use broker_server::{Server, ServerConfig};

#[tokio::test]
async fn management_api_serves_https_with_the_configured_certificate() {
    let data = tempfile::tempdir().unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let files = ApiTlsFiles {
        cert: data.path().join("api.crt"),
        key: data.path().join("api.key"),
    };
    std::fs::write(&files.cert, cert.cert.pem()).unwrap();
    std::fs::write(&files.key, cert.signing_key.serialize_pem()).unwrap();

    let mut config = ServerConfig::new(data.path().join("state"));
    config.api_listen = "127.0.0.1:0".parse().unwrap();
    config.node_listen = "127.0.0.1:0".parse().unwrap();
    config.api_tls = Some(files);
    let server = Server::start(config).await.unwrap();
    assert!(server.api_tls);
    let port = server.api_addr.port();

    let client = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(reqwest::Certificate::from_pem(cert.cert.pem().as_bytes()).unwrap())
        .resolve("localhost", server.api_addr)
        .build()
        .unwrap();
    let resp = client
        .get(format!("https://localhost:{port}/api/v1/setup/status"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert_eq!(resp.headers().get("cache-control").unwrap(), "no-store");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["setup_required"], true);

    // Plain HTTP on the TLS port gets no answer.
    let plain = reqwest::Client::builder().no_proxy().build().unwrap();
    assert!(plain
        .get(format!("http://127.0.0.1:{port}/api/v1/setup/status"))
        .send()
        .await
        .is_err());

    // A client that does not trust the certificate is refused.
    let untrusting = reqwest::Client::builder()
        .no_proxy()
        .tls_built_in_root_certs(false)
        .resolve("localhost", server.api_addr)
        .build()
        .unwrap();
    assert!(untrusting
        .get(format!("https://localhost:{port}/api/v1/setup/status"))
        .send()
        .await
        .is_err());
    server.shutdown();
}
