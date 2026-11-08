// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A running embedded data plane with one rule and one session, for tests
//! that send real traffic through the proxy.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use rustls::pki_types::{CertificateDer, ServerName};
use tokenless_core::audit::AuditEvent;
use tokenless_core::egress::EgressPolicy;
use tokenless_core::ids::{RuleId, SessionId};
use tokenless_core::scope::Scope;
use tokenless_core::session::{SessionClaims, SessionSigner};
use tokenless_core::snapshot::SignedSnapshot;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::client::TlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::audit::AuditShipper;
use crate::error::DataPlaneError;
use crate::state::tests::Fixture;
use crate::state::NodeKeys;
use crate::tls::{leaf_server_config, upstream_client_config};
use crate::{Binding, BindingSpec, DataPlane, DataPlaneConfig, SnapshotInstaller};

struct Discard;

#[async_trait]
impl AuditShipper for Discard {
    async fn ship(&self, _: &[AuditEvent]) -> Result<(), DataPlaneError> {
        Ok(())
    }
}

pub struct Running {
    pub f: Fixture,
    pub dp: DataPlane,
    pub installer: SnapshotInstaller,
    pub rule: RuleId,
    /// The host pattern the rule covers.
    pub host: String,
    pub token: String,
    pub jti: SessionId,
}

/// A data plane whose rule covers `host` (injecting `Bearer t`), trusting
/// `upstream_roots` for upstream TLS, with a session for that rule.
pub async fn running(host: &str, upstream_roots: Vec<CertificateDer<'static>>) -> Running {
    running_for(host, upstream_roots, 600).await
}

/// [`running`] with a session that lasts `ttl_secs`.
pub async fn running_for(
    host: &str,
    upstream_roots: Vec<CertificateDer<'static>>,
    ttl_secs: u64,
) -> Running {
    running_with(host, upstream_roots, ttl_secs, Arc::new(Discard)).await
}

/// [`running_for`] shipping its audit batches to `shipper`.
pub async fn running_with(
    host: &str,
    upstream_roots: Vec<CertificateDer<'static>>,
    ttl_secs: u64,
    shipper: Arc<dyn AuditShipper>,
) -> Running {
    let f = Fixture::new();
    let keys = NodeKeys {
        node_id: f.keys.node_id,
        seal_secret: f.keys.seal_secret.clone(),
        snapshot_key: f.keys.snapshot_key,
    };
    let config = DataPlaneConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        mcp_listen: Some("127.0.0.1:0".parse().unwrap()),
        use_public_roots: false,
        extra_upstream_roots: upstream_roots,
        ..DataPlaneConfig::default()
    };
    let (dp, installer) = DataPlane::start_embedded(config, keys, shipper)
        .await
        .unwrap();
    let rule = RuleId::new();
    installer
        .install(&snapshot(&f, 1, rule, host, vec![]))
        .unwrap();
    let claims = SessionClaims::new(
        scope(),
        vec![rule],
        ttl_secs,
        None,
        BTreeMap::new(),
        Utc::now(),
        3600,
    )
    .unwrap();
    let token = SessionSigner::new(f.session_signer.clone())
        .sign(&claims)
        .unwrap();
    Running {
        f,
        dp,
        installer,
        rule,
        host: host.to_string(),
        token,
        jti: claims.jti,
    }
}

impl Running {
    /// A session for the rule, minted for one start of binding `id` on
    /// this node.
    pub fn bound_token(&self, id: &str, generation: u64, ttl_secs: u64) -> (String, SessionId) {
        let claims = SessionClaims::new(
            scope(),
            vec![self.rule],
            ttl_secs,
            None,
            BTreeMap::new(),
            Utc::now(),
            3600,
        )
        .unwrap()
        .for_node(self.f.keys.node_id)
        .for_binding(id, generation)
        .unwrap();
        let token = SessionSigner::new(self.f.session_signer.clone())
            .sign(&claims)
            .unwrap();
        (token, claims.jti)
    }

    /// Binds `id` (generation 1) to `sessions`.
    pub fn bind(&self, id: &str, sessions: Vec<String>) -> Arc<Binding> {
        Arc::new(
            self.dp
                .bind(BindingSpec {
                    binding_id: id.into(),
                    generation: 1,
                    sessions,
                    version: 0,
                    max_connections: 8,
                })
                .unwrap(),
        )
    }

    /// One request from a workload through `binding`: CONNECT, TLS with
    /// the interception CA, `GET /`. Returns the response's status line.
    pub async fn request_through(&self, binding: &Arc<Binding>, target: &str) -> String {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let serving = binding.clone();
        tokio::spawn(async move { serving.serve(server).await });
        client
            .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let head = read_head(&mut client).await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        let config =
            upstream_client_config(false, &[CertificateDer::from(self.f.ca_cert_der.clone())])
                .unwrap();
        let mut tls = TlsConnector::from(config)
            .connect(ServerName::try_from("localhost").unwrap(), client)
            .await
            .unwrap();
        tls.write_all(
            format!("GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
        read_head(&mut tls)
            .await
            .lines()
            .next()
            .unwrap_or_default()
            .to_string()
    }

    /// The next snapshot: the same rule, revoking `revoked`.
    pub fn snapshot(&self, version: u64, revoked: Vec<SessionId>) -> SignedSnapshot {
        snapshot(&self.f, version, self.rule, &self.host, revoked)
    }

    /// The next snapshot, its credential valid until `not_after`.
    pub fn snapshot_until(&self, version: u64, not_after: chrono::DateTime<Utc>) -> SignedSnapshot {
        let mut body = self
            .f
            .snapshot_body(version, vec![(self.rule, scope(), &self.host, "t")]);
        body.egress = EgressPolicy {
            block_private: false,
            allow: vec![],
        };
        body.rules[0].not_after = Some(not_after);
        body.format = 2;
        self.f.sign(&body)
    }

    /// Opens a CONNECT tunnel with the session and checks it was accepted.
    pub async fn tunnel(&self, target: &str) -> TcpStream {
        self.tunnel_with(target, &self.token).await
    }

    /// [`Running::tunnel`] with another session token.
    pub async fn tunnel_with(&self, target: &str, token: &str) -> TcpStream {
        let mut stream = TcpStream::connect(self.dp.local_addr()).await.unwrap();
        stream
            .write_all(
                format!(
                    "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Bearer {token}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            assert_eq!(
                stream.read(&mut byte).await.unwrap(),
                1,
                "proxy closed early"
            );
            head.push(byte[0]);
        }
        let head = String::from_utf8_lossy(&head);
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        stream
    }

    /// Opens an intercepted tunnel to `target` and completes TLS with the
    /// proxy, trusting the interception CA as an agent would.
    pub async fn intercepted(&self, target: &str, name: &str) -> TlsStream<TcpStream> {
        self.intercepted_with(target, name, &self.token).await
    }

    /// [`Running::intercepted`] with another session token.
    pub async fn intercepted_with(
        &self,
        target: &str,
        name: &str,
        token: &str,
    ) -> TlsStream<TcpStream> {
        let stream = self.tunnel_with(target, token).await;
        let client =
            upstream_client_config(false, &[CertificateDer::from(self.f.ca_cert_der.clone())])
                .unwrap();
        TlsConnector::from(client)
            .connect(ServerName::try_from(name.to_string()).unwrap(), stream)
            .await
            .unwrap()
    }
}

fn scope() -> Scope {
    Scope::parse("vault:test").unwrap()
}

/// One rule for `host`; loopback is reachable so tests can tunnel to a
/// local upstream.
fn snapshot(
    f: &Fixture,
    version: u64,
    rule: RuleId,
    host: &str,
    revoked: Vec<SessionId>,
) -> SignedSnapshot {
    let mut body = f.snapshot_body(version, vec![(rule, scope(), host, "t")]);
    body.egress = EgressPolicy {
        block_private: false,
        allow: vec![],
    };
    body.revoked_sessions = revoked;
    f.sign(&body)
}

async fn read_head(stream: &mut (impl AsyncRead + Unpin)) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).await.unwrap_or(0) == 0 {
            break;
        }
        head.push(byte[0]);
    }
    String::from_utf8_lossy(&head).into_owned()
}

/// A local HTTPS upstream for `localhost` that answers every request with
/// `answer` (a whole response). Returns its port and certificate.
pub async fn https_upstream(answer: &'static str) -> (u16, CertificateDer<'static>) {
    https_upstream_with(answer, false).await
}

/// [`https_upstream`] that keeps each connection open after `answer`, as
/// an event stream does.
pub async fn https_stream_upstream(answer: &'static str) -> (u16, CertificateDer<'static>) {
    https_upstream_with(answer, true).await
}

/// A local HTTPS upstream for `localhost` that answers each request with
/// the `Authorization` header it received as the body.
pub async fn https_echo_authorization_upstream() -> (u16, CertificateDer<'static>) {
    let (listener, server, root) = https_listener().await;
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = TlsAcceptor::from(server.clone());
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let head = read_head(&mut tls).await;
                let auth = head
                    .lines()
                    .find_map(|l| {
                        let (name, value) = l.split_once(':')?;
                        name.eq_ignore_ascii_case("authorization")
                            .then(|| value.trim().to_string())
                    })
                    .unwrap_or_default();
                let answer = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{auth}",
                    auth.len()
                );
                let _ = tls.write_all(answer.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    (port, root)
}

async fn https_listener() -> (
    TcpListener,
    Arc<rustls::ServerConfig>,
    CertificateDer<'static>,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let root = CertificateDer::from(cert.cert.der().to_vec());
    let server = leaf_server_config(
        "localhost",
        vec![root.clone()],
        cert.signing_key.serialize_der(),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    (listener, server, root)
}

async fn https_upstream_with(answer: &'static str, hold: bool) -> (u16, CertificateDer<'static>) {
    let (listener, server, root) = https_listener().await;
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = TlsAcceptor::from(server.clone());
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                read_head(&mut tls).await;
                let _ = tls.write_all(answer.as_bytes()).await;
                if hold {
                    let _ = tls.flush().await;
                    let mut rest = [0u8; 1];
                    // Until the proxy closes its side.
                    let _ = tls.read(&mut rest).await;
                }
                let _ = tls.shutdown().await;
            });
        }
    });
    (port, root)
}
