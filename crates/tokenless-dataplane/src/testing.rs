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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::audit::AuditShipper;
use crate::error::DataPlaneError;
use crate::state::tests::Fixture;
use crate::state::NodeKeys;
use crate::tls::upstream_client_config;
use crate::{DataPlane, DataPlaneConfig, SnapshotInstaller};

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
    let f = Fixture::new();
    let keys = NodeKeys {
        node_id: f.keys.node_id,
        seal_secret: f.keys.seal_secret.clone(),
        snapshot_key: f.keys.snapshot_key,
    };
    let config = DataPlaneConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        use_public_roots: false,
        extra_upstream_roots: upstream_roots,
        ..DataPlaneConfig::default()
    };
    let (dp, installer) = DataPlane::start_embedded(config, keys, Arc::new(Discard))
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
    /// The next snapshot: the same rule, revoking `revoked`.
    pub fn snapshot(&self, version: u64, revoked: Vec<SessionId>) -> SignedSnapshot {
        snapshot(&self.f, version, self.rule, &self.host, revoked)
    }

    /// Opens a CONNECT tunnel with the session and checks it was accepted.
    pub async fn tunnel(&self, target: &str) -> TcpStream {
        let mut stream = TcpStream::connect(self.dp.local_addr()).await.unwrap();
        stream
            .write_all(
                format!(
                    "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Bearer {}\r\n\r\n",
                    self.token
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
        let stream = self.tunnel(target).await;
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
