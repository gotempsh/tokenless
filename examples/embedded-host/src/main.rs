// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Embeds tokenless in one process, as a platform that runs untrusted
//! workloads would:
//!
//! 1. the control services on in-memory stores, called as a service;
//! 2. a data plane registered with them, fed snapshots in-process and
//!    shipping its audit batches back the same way;
//! 3. a workload bound to a session minted for it, whose proxy connection
//!    is a plain byte stream. It never sees the session token or the
//!    credential, and its request reaches the upstream with the credential
//!    injected.
//!
//! Exits non-zero if any step does not behave as described.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokenless_control::cipher::AesGcmCipher;
use tokenless_control::envelope::Envelope;
use tokenless_control::memory::MemoryStore;
use tokenless_control::model::{Node, PageRequest};
use tokenless_control::probe::DisabledProber;
use tokenless_control::service::policy::{CreateCredential, CreateRule};
use tokenless_control::service::sessions::{MintSession, SessionBinding};
use tokenless_control::store::RbacAuthorizer;
use tokenless_control::{Caller, ControlConfig, ControlServices, ServiceStores};
use tokenless_core::audit::AuditEvent;
use tokenless_core::authz::{Principal, Role};
use tokenless_core::protocol::AuditBatch;
use tokenless_core::seal::{encode_public_key, SealPublicKey, SealSecretKey};
use tokenless_dataplane::audit::AuditShipper;
use tokenless_dataplane::state::NodeKeys;
use tokenless_dataplane::{BindingSpec, DataPlane, DataPlaneConfig, DataPlaneError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor, TlsConnector};

type Error = Box<dyn std::error::Error + Send + Sync>;

/// The upstream credential. The workload never holds it.
const API_TOKEN: &str = "example-upstream-token";

#[tokio::main]
async fn main() -> Result<(), Error> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (upstream_port, upstream_root) = start_upstream().await?;
    let upstream = format!("localhost:{upstream_port}");

    // 1. Control services, no accounts. The host has authenticated its own
    //    user already and calls as itself.
    let store = Arc::new(MemoryStore::new());
    let cipher = Arc::new(Envelope::open(&AesGcmCipher::generate_key(), store.clone()).await?);
    let control = Arc::new(
        ControlServices::new(
            ServiceStores {
                credentials: store.clone(),
                policy: store.clone(),
                audit: store.clone(),
                nodes: store.clone(),
            },
            Arc::new(RbacAuthorizer),
            cipher,
            Arc::new(DisabledProber),
            ControlConfig {
                lease_secs: 30,
                ..ControlConfig::default()
            },
        )
        .await?,
    );
    let host = Caller::service(Principal::service("embedded-host", Role::Admin, None));
    let vault = control.policy.create_vault(&host, "project-a").await?;
    let credential = control
        .policy
        .create_credential(
            &host,
            &vault.id,
            CreateCredential {
                name: "example-api".into(),
                template_id: "generic-bearer".into(),
                template_version: None,
                host_override: vec![upstream.clone()],
                fields: [("token".to_string(), API_TOKEN.to_string())].into(),
                custom_headers: vec![],
                substitutions: vec![],
            },
        )
        .await?;
    let rule = control
        .policy
        .create_rule(
            &host,
            &vault.id,
            CreateRule {
                name: "example-api".into(),
                credential_id: credential.id,
                hosts: None,
                paths: None,
                methods: None,
                mcp_tools: None,
            },
        )
        .await?;

    // 2. The data plane, registered as a node of these services.
    let seal_secret = SealSecretKey::random_from_rng(rand::rngs::OsRng);
    let registered = control
        .nodes
        .register_embedded(
            &host,
            "embedded",
            &encode_public_key(&SealPublicKey::from(&seal_secret)),
        )
        .await?;
    let node = registered.node.clone();
    let (dataplane, installer) = DataPlane::start_embedded(
        DataPlaneConfig {
            listen: "127.0.0.1:0".parse()?,
            use_public_roots: false,
            extra_upstream_roots: vec![upstream_root],
            audit_flush_interval: Duration::from_millis(50),
            ..DataPlaneConfig::default()
        },
        NodeKeys {
            node_id: node.id,
            seal_secret,
            snapshot_key: registered.snapshot_verify_key,
        },
        Arc::new(ToControl {
            control: control.clone(),
            node: node.clone(),
        }),
    )
    .await?;
    let version = installer.install(&control.nodes.build_snapshot(&node).await?)?;
    println!("data plane running with snapshot {version}");

    // 3. A workload, bound to a session minted for it on this node.
    let minted = control
        .sessions
        .mint(
            &host,
            &vault.id,
            MintSession {
                rule_ids: vec![rule.id],
                bundle: None,
                ttl_secs: Some(600),
                longest: false,
                request_limit: None,
                labels: [("workload".to_string(), "workload-1".to_string())].into(),
                node_id: Some(node.id),
                binding: Some(SessionBinding {
                    id: "workload-1".into(),
                    generation: 1,
                }),
                not_after: None,
            },
        )
        .await?;
    let binding = Arc::new(dataplane.bind(BindingSpec {
        binding_id: "workload-1".into(),
        generation: 1,
        sessions: vec![minted.token],
        max_connections: 8,
    })?);

    // The workload's proxy connection: any byte stream will do.
    let (workload, proxy_side) = tokio::io::duplex(64 * 1024);
    let serving = binding.clone();
    tokio::spawn(async move { serving.serve(proxy_side).await });
    let seen = workload_request(
        workload,
        &upstream,
        CertificateDer::from(control.keys.interception_ca.cert_der.clone()),
    )
    .await?;
    if seen != format!("Bearer {API_TOKEN}") {
        return Err(format!("the upstream saw Authorization '{seen}'").into());
    }
    println!("the upstream received the injected credential; the workload never held it");

    // Its traffic is in the audit log, recorded by the node.
    let mut audited = Vec::new();
    for _ in 0..50 {
        audited = control
            .audit
            .query(
                &host,
                Some(vault.id),
                Some("proxy.".into()),
                PageRequest::default(),
            )
            .await?
            .items;
        if !audited.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let Some(event) = audited.first() else {
        return Err("no proxy event reached the audit log".into());
    };
    println!("audited: {} by {}", event.action, event.actor);

    binding.revoke();
    dataplane.shutdown();
    Ok(())
}

/// Ships the data plane's audit batches to the control services in-process.
struct ToControl {
    control: Arc<ControlServices>,
    node: Node,
}

#[async_trait]
impl AuditShipper for ToControl {
    async fn ship(&self, events: &[AuditEvent]) -> Result<(), DataPlaneError> {
        self.control
            .nodes
            .ingest_audit(
                &self.node,
                AuditBatch {
                    events: events.to_vec(),
                },
            )
            .await
            .map(|_| ())
            .map_err(|e| DataPlaneError::Control {
                method: "in-process".into(),
                path: "ingest_audit".into(),
                reason: e.to_string(),
            })
    }
}

/// What the workload does: CONNECT through its binding, TLS with the
/// interception CA it was given, one request. Returns what the upstream
/// says it received in `Authorization`.
async fn workload_request(
    mut stream: tokio::io::DuplexStream,
    upstream: &str,
    interception_ca: CertificateDer<'static>,
) -> Result<String, Error> {
    stream
        .write_all(format!("CONNECT {upstream} HTTP/1.1\r\nHost: {upstream}\r\n\r\n").as_bytes())
        .await?;
    let head = read_head(&mut stream).await?;
    if !head.starts_with("HTTP/1.1 200") {
        return Err(format!("the proxy refused the CONNECT: {head}").into());
    }
    let mut roots = rustls::RootCertStore::empty();
    roots.add(interception_ca)?;
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut tls = TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost")?, stream)
        .await?;
    tls.write_all(
        format!("GET /whoami HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await?;
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await?;
    let response = String::from_utf8_lossy(&response);
    let Some((head, body)) = response.split_once("\r\n\r\n") else {
        return Err(format!("unexpected response: {response}").into());
    };
    if !head.starts_with("HTTP/1.1 200") {
        return Err(format!("the request failed: {response}").into());
    }
    Ok(body.to_string())
}

async fn read_head(stream: &mut (impl AsyncReadExt + Unpin)) -> Result<String, Error> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).await? == 0 {
            break;
        }
        head.push(byte[0]);
    }
    Ok(String::from_utf8_lossy(&head).into_owned())
}

/// A local HTTPS service that answers each request with the
/// `Authorization` header it received. Returns its port and certificate.
async fn start_upstream() -> Result<(u16, CertificateDer<'static>), Error> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let der = CertificateDer::from(cert.cert.der().to_vec());
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![der.clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())),
        )?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let Ok(head) = read_head(&mut tls).await else {
                    return;
                };
                let seen = head
                    .lines()
                    .find_map(|l| {
                        let (name, value) = l.split_once(':')?;
                        name.eq_ignore_ascii_case("authorization")
                            .then(|| value.trim().to_string())
                    })
                    .unwrap_or_default();
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{seen}",
                    seen.len()
                );
                let _ = tls.write_all(reply.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    Ok((port, der))
}
