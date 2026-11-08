// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strict deadlines, binding updates and waiting for a revocation to be
//! enforced, with real traffic: streaming responses, slow uploads and idle
//! tunnels through the proxy to a local upstream, while fresh snapshots
//! keep arriving so the lease is never what ends them.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, TimeDelta, Utc};
use rustls::pki_types::{CertificateDer, ServerName};
use tokenless_core::egress::EgressPolicy;
use tokenless_core::ids::RuleId;
use tokenless_core::path::PathPattern;
use tokenless_core::scope::Scope;
use tokenless_core::session::{SessionClaims, SessionSigner};
use tokenless_core::snapshot::SnapshotBody;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::{timeout, Instant};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::audit::AuditShipper;
use crate::error::DataPlaneError;
use crate::state::tests::Fixture;
use crate::state::NodeKeys;
use crate::tls::{leaf_server_config, upstream_client_config};
use crate::{Binding, BindingSpec, BindingUpdate, DataPlane, DataPlaneConfig, SnapshotInstaller};

/// How late a cut may come after its deadline.
const LATE: Duration = Duration::from_millis(1500);
/// A grant's deadline in these tests, from when the session is minted.
const GRANT: Duration = Duration::from_secs(2);

struct Discard;

#[async_trait::async_trait]
impl AuditShipper for Discard {
    async fn ship(&self, _: &[tokenless_core::audit::AuditEvent]) -> Result<(), DataPlaneError> {
        Ok(())
    }
}

fn scope() -> Scope {
    Scope::parse("vault:test").unwrap()
}

/// A local HTTPS upstream for `localhost`. `GET` is answered with a
/// chunked response that starts with the `Authorization` it received and
/// never ends; `POST` bodies are read until the proxy closes the
/// connection, counting the bytes.
struct Upstream {
    port: u16,
    root: CertificateDer<'static>,
    uploaded: Arc<AtomicUsize>,
    /// When the upload connection was closed by the proxy.
    upload_closed: Arc<Mutex<Option<Instant>>>,
}

async fn upstream() -> Upstream {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let root = CertificateDer::from(cert.cert.der().to_vec());
    let server = leaf_server_config(
        "localhost",
        vec![root.clone()],
        cert.signing_key.serialize_der(),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let uploaded = Arc::new(AtomicUsize::new(0));
    let upload_closed = Arc::new(Mutex::new(None));
    let (counter, closed) = (uploaded.clone(), upload_closed.clone());
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = TlsAcceptor::from(server.clone());
            let (counter, closed) = (counter.clone(), closed.clone());
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let head = read_head(&mut tls).await;
                if head.starts_with("POST") {
                    let mut buf = [0u8; 4096];
                    while let Ok(n @ 1..) = tls.read(&mut buf).await {
                        counter.fetch_add(n, Ordering::SeqCst);
                    }
                    *closed.lock().unwrap() = Some(Instant::now());
                    return;
                }
                let auth = head
                    .lines()
                    .find_map(|l| {
                        let (name, value) = l.split_once(':')?;
                        name.eq_ignore_ascii_case("authorization")
                            .then(|| value.trim().to_string())
                    })
                    .unwrap_or_default();
                let answer = format!(
                    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{auth}\r\n",
                    auth.len()
                );
                let _ = tls.write_all(answer.as_bytes()).await;
                let _ = tls.flush().await;
                let mut rest = [0u8; 1];
                // Until the proxy closes its side.
                let _ = tls.read(&mut rest).await;
            });
        }
    });
    Upstream {
        port,
        root,
        uploaded,
        upload_closed,
    }
}

/// An embedded data plane with two rules on `localhost`: A for `/a/*`
/// sending `Bearer ta`, B for `/b/*` sending `Bearer tb`.
struct Plane {
    f: Fixture,
    dp: DataPlane,
    installer: SnapshotInstaller,
    rule_a: RuleId,
    rule_b: RuleId,
    /// `localhost:<upstream port>`, the rules' host.
    host: String,
    version: AtomicU64,
    /// A's credential's `not_after`, in every snapshot installed.
    a_not_after: Mutex<Option<DateTime<Utc>>>,
    /// A's paths, `/a/*` unless a test widens them.
    a_paths: Mutex<&'static str>,
}

impl Plane {
    async fn start(upstream: &Upstream) -> Arc<Self> {
        let f = Fixture::new();
        let keys = NodeKeys {
            node_id: f.keys.node_id,
            seal_secret: f.keys.seal_secret.clone(),
            snapshot_key: f.keys.snapshot_key,
        };
        let config = DataPlaneConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            use_public_roots: false,
            extra_upstream_roots: vec![upstream.root.clone()],
            ..DataPlaneConfig::default()
        };
        let (dp, installer) = DataPlane::start_embedded(config, keys, Arc::new(Discard))
            .await
            .unwrap();
        let plane = Arc::new(Self {
            f,
            dp,
            installer,
            rule_a: RuleId::new(),
            rule_b: RuleId::new(),
            host: format!("localhost:{}", upstream.port),
            version: AtomicU64::new(0),
            a_not_after: Mutex::new(None),
            a_paths: Mutex::new("/a/*"),
        });
        plane.install();
        plane
    }

    fn body(&self, version: u64) -> SnapshotBody {
        let mut body = self.f.snapshot_body(
            version,
            vec![
                (self.rule_a, scope(), &self.host, "ta"),
                (self.rule_b, scope(), &self.host, "tb"),
            ],
        );
        body.egress = EgressPolicy {
            block_private: false,
            allow: vec![],
        };
        body.rules[0].allow.paths =
            vec![PathPattern::parse(*self.a_paths.lock().unwrap()).unwrap()];
        body.rules[1].allow.paths = vec![PathPattern::parse("/b/*").unwrap()];
        if let Some(at) = *self.a_not_after.lock().unwrap() {
            body.rules[0].not_after = Some(at);
            body.format = 2;
        }
        body
    }

    fn install(&self) {
        let version = self.version.fetch_add(1, Ordering::SeqCst) + 1;
        self.installer
            .install(&self.f.sign(&self.body(version)))
            .unwrap();
    }

    /// Installs a fresh snapshot every 300ms until aborted.
    fn refresh(self: &Arc<Self>) -> JoinHandle<()> {
        let plane = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(300)).await;
                plane.install();
            }
        })
    }

    fn claims(&self, rules: Vec<RuleId>, ttl_secs: u64) -> SessionClaims {
        SessionClaims::new(
            scope(),
            rules,
            ttl_secs,
            None,
            BTreeMap::new(),
            Utc::now(),
            3600,
        )
        .unwrap()
    }

    fn sign(&self, claims: &SessionClaims) -> String {
        SessionSigner::new(self.f.session_signer.clone())
            .sign(claims)
            .unwrap()
    }

    /// A tunnel to the upstream with `token`, TLS done as an agent does.
    async fn tunnel(&self, port: u16, token: &str) -> impl AsyncRead + AsyncWrite + Unpin {
        let mut tcp = TcpStream::connect(self.dp.local_addr()).await.unwrap();
        let target = format!("localhost:{port}");
        tcp.write_all(
            format!(
                "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Bearer {token}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let head = read_head(&mut tcp).await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        self.tls(tcp).await
    }

    /// A tunnel to the upstream through `binding`.
    async fn bound_tunnel(
        &self,
        binding: &Arc<Binding>,
        port: u16,
    ) -> impl AsyncRead + AsyncWrite + Unpin {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let serving = binding.clone();
        tokio::spawn(async move { serving.serve(server).await });
        let target = format!("localhost:{port}");
        client
            .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let head = read_head(&mut client).await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        self.tls(client).await
    }

    async fn tls<S>(&self, stream: S) -> tokio_rustls::client::TlsStream<S>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let config =
            upstream_client_config(false, &[CertificateDer::from(self.f.ca_cert_der.clone())])
                .unwrap();
        TlsConnector::from(config)
            .connect(ServerName::try_from("localhost").unwrap(), stream)
            .await
            .unwrap()
    }
}

async fn read_head(stream: &mut (impl AsyncRead + Unpin)) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte).await {
            Ok(1) => head.push(byte[0]),
            _ => break,
        }
    }
    String::from_utf8_lossy(&head).into_owned()
}

/// Sends `GET path` and returns the status line and, for a 200, the first
/// chunk of the never-ending body.
async fn get(stream: &mut (impl AsyncRead + AsyncWrite + Unpin), path: &str, port: u16) -> String {
    stream
        .write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let head = timeout(Duration::from_secs(5), read_head(stream))
        .await
        .expect("an answer");
    let status = head.lines().next().unwrap_or_default().to_string();
    if !status.contains(" 200 ") {
        return status;
    }
    let mut chunk = vec![0u8; 256];
    let n = timeout(Duration::from_secs(5), stream.read(&mut chunk))
        .await
        .expect("the first chunk")
        .unwrap();
    format!("{status} {}", String::from_utf8_lossy(&chunk[..n]))
}

/// When `stream` ends (EOF or error), if it does by `by`.
async fn ends_by(stream: &mut (impl AsyncRead + Unpin), by: Instant) -> Option<Instant> {
    let mut buf = [0u8; 256];
    let read_to_end = async {
        while let Ok(1..) = stream.read(&mut buf).await {}
        Instant::now()
    };
    tokio::time::timeout_at(by, read_to_end).await.ok()
}

fn deadline_in(d: Duration) -> (DateTime<Utc>, Instant) {
    (
        Utc::now() + TimeDelta::from_std(d).unwrap(),
        Instant::now() + d,
    )
}

/// One session holds grants A and B on one host; A's grant ends first.
/// A's open stream and its new requests stop at A's deadline, not an hour
/// later, while B's stream and requests carry on.
#[tokio::test]
async fn a_strict_grant_ends_its_streams_and_requests_while_the_other_runs() {
    let up = upstream().await;
    let p = Plane::start(&up).await;
    let refresh = p.refresh();
    let (a_deadline, a_at) = deadline_in(GRANT);
    let claims = p
        .claims(vec![p.rule_a, p.rule_b], 600)
        .strict()
        .with_rule_deadlines(&[(p.rule_a, a_deadline)].into(), Utc::now())
        .unwrap();
    let token = p.sign(&claims);

    let mut a = p.tunnel(up.port, &token).await;
    let mut b = p.tunnel(up.port, &token).await;
    assert!(get(&mut a, "/a/stream", up.port)
        .await
        .contains("Bearer ta"));
    assert!(get(&mut b, "/b/stream", up.port)
        .await
        .contains("Bearer tb"));

    let ended = ends_by(&mut a, a_at + LATE)
        .await
        .expect("A's stream is cut");
    assert!(
        ended + Duration::from_millis(100) >= a_at,
        "cut before the deadline"
    );
    let still_open = ends_by(&mut b, Instant::now() + Duration::from_secs(1)).await;
    assert!(still_open.is_none(), "B's stream was cut with A's grant");

    let mut again = p.tunnel(up.port, &token).await;
    let refused = get(&mut again, "/a/next", up.port).await;
    assert!(refused.contains(" 403 "), "{refused}");
    let mut b2 = p.tunnel(up.port, &token).await;
    assert!(get(&mut b2, "/b/next", up.port).await.contains("Bearer tb"));
    refresh.abort();
}

/// A slow upload under a strict grant stops reaching the upstream at the
/// grant's deadline.
#[tokio::test]
async fn a_strict_upload_stops_at_its_deadline() {
    let up = upstream().await;
    let p = Plane::start(&up).await;
    let refresh = p.refresh();
    let (a_deadline, a_at) = deadline_in(GRANT);
    let claims = p
        .claims(vec![p.rule_a, p.rule_b], 600)
        .strict()
        .with_rule_deadlines(&[(p.rule_a, a_deadline)].into(), Utc::now())
        .unwrap();
    let token = p.sign(&claims);
    let mut tunnel = p.tunnel(up.port, &token).await;
    tunnel
        .write_all(
            format!(
                "POST /a/upload HTTP/1.1\r\nHost: localhost:{}\r\nTransfer-Encoding: chunked\r\n\r\n",
                up.port
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let writer = tokio::spawn(async move {
        while tunnel.write_all(b"400\r\n").await.is_ok()
            && tunnel.write_all(&[b'x'; 1024]).await.is_ok()
            && tunnel.write_all(b"\r\n").await.is_ok()
            && tunnel.flush().await.is_ok()
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });
    tokio::time::sleep_until(a_at + LATE).await;
    let closed = up
        .upload_closed
        .lock()
        .unwrap()
        .expect("the upload reached the upstream after its deadline");
    assert!(closed + Duration::from_millis(100) >= a_at, "cut early");
    assert!(
        up.uploaded.load(Ordering::SeqCst) > 0,
        "nothing was uploaded"
    );
    writer.abort();
    refresh.abort();
}

/// A strict session's stream stops when its credential's `not_after`
/// passes, even though the grant goes on; the other credential's does not.
#[tokio::test]
async fn a_credential_expiring_mid_stream_cuts_a_strict_stream() {
    let up = upstream().await;
    let p = Plane::start(&up).await;
    let (not_after, at) = deadline_in(GRANT);
    *p.a_not_after.lock().unwrap() = Some(not_after);
    p.install();
    let refresh = p.refresh();
    let token = p.sign(&p.claims(vec![p.rule_a, p.rule_b], 600).strict());
    let mut a = p.tunnel(up.port, &token).await;
    let mut b = p.tunnel(up.port, &token).await;
    assert!(get(&mut a, "/a/stream", up.port)
        .await
        .contains("Bearer ta"));
    assert!(get(&mut b, "/b/stream", up.port)
        .await
        .contains("Bearer tb"));
    let ended = ends_by(&mut a, at + LATE).await.expect("A's stream is cut");
    assert!(ended + Duration::from_millis(100) >= at, "cut early");
    assert!(
        ends_by(&mut b, Instant::now() + Duration::from_secs(1))
            .await
            .is_none(),
        "B's stream was cut with A's credential"
    );
    refresh.abort();
}

/// Without strict, a grant's deadline stops new requests, and the open
/// stream runs on within the grace period, as for a session's expiry.
#[tokio::test]
async fn without_strict_a_grant_deadline_refuses_new_requests_only() {
    let up = upstream().await;
    let p = Plane::start(&up).await;
    let refresh = p.refresh();
    let (a_deadline, a_at) = deadline_in(Duration::from_secs(1));
    let claims = p
        .claims(vec![p.rule_a, p.rule_b], 600)
        .with_rule_deadlines(&[(p.rule_a, a_deadline)].into(), Utc::now())
        .unwrap();
    let token = p.sign(&claims);
    let mut a = p.tunnel(up.port, &token).await;
    assert!(get(&mut a, "/a/stream", up.port)
        .await
        .contains("Bearer ta"));
    assert!(
        ends_by(&mut a, a_at + LATE).await.is_none(),
        "the stream was cut without strict"
    );
    let mut again = p.tunnel(up.port, &token).await;
    let refused = get(&mut again, "/a/next", up.port).await;
    assert!(refused.contains(" 403 "), "{refused}");
    refresh.abort();
}

/// Without strict, a grant ending stops new requests through a binding
/// too, but not the stream already flowing under it, however many fresh
/// snapshots wake its watch.
#[tokio::test]
async fn without_strict_a_bound_stream_outlives_its_grant_deadline() {
    let up = upstream().await;
    let p = Plane::start(&up).await;
    let refresh = p.refresh();
    let (a_deadline, a_at) = deadline_in(Duration::from_secs(1));
    let claims = p
        .claims(vec![p.rule_a, p.rule_b], 600)
        .for_node(p.f.keys.node_id)
        .for_binding("sandbox-2", 1)
        .unwrap()
        .with_rule_deadlines(&[(p.rule_a, a_deadline)].into(), Utc::now())
        .unwrap();
    let binding = Arc::new(
        p.dp.bind(BindingSpec {
            binding_id: "sandbox-2".into(),
            generation: 1,
            sessions: vec![p.sign(&claims)],
            version: 1,
            max_connections: 8,
        })
        .unwrap(),
    );
    let mut a = p.bound_tunnel(&binding, up.port).await;
    assert!(get(&mut a, "/a/stream", up.port)
        .await
        .contains("Bearer ta"));
    assert!(
        ends_by(&mut a, a_at + LATE).await.is_none(),
        "a bound stream was cut at its grant's deadline without strict"
    );
    let mut again = p.bound_tunnel(&binding, up.port).await;
    let refused = get(&mut again, "/a/next", up.port).await;
    assert!(refused.contains(" 403 "), "{refused}");
    refresh.abort();
}

/// A more specific rule whose grant has ended no longer takes the request
/// from a broader rule the session still holds.
#[tokio::test]
async fn an_ended_grant_leaves_its_requests_to_a_broader_rule_still_held() {
    let up = upstream().await;
    let p = Plane::start(&up).await;
    *p.a_paths.lock().unwrap() = "/*";
    p.install();
    let refresh = p.refresh();
    let (b_deadline, b_at) = deadline_in(Duration::from_secs(1));
    let claims = p
        .claims(vec![p.rule_a, p.rule_b], 600)
        .with_rule_deadlines(&[(p.rule_b, b_deadline)].into(), Utc::now())
        .unwrap();
    let token = p.sign(&claims);
    let mut before = p.tunnel(up.port, &token).await;
    let answer = get(&mut before, "/b/x", up.port).await;
    assert!(answer.contains("Bearer tb"), "{answer}");
    tokio::time::sleep_until(b_at + Duration::from_millis(200)).await;
    let mut after = p.tunnel(up.port, &token).await;
    let answer = get(&mut after, "/b/x", up.port).await;
    assert!(answer.contains("Bearer ta"), "{answer}");
    refresh.abort();
}

/// An idle strict tunnel to a host closes when the last grant covering it
/// ends, and a passthrough tunnel when the session expires.
#[tokio::test]
async fn strict_idle_tunnels_close_at_their_deadlines() {
    let up = upstream().await;
    let p = Plane::start(&up).await;
    let refresh = p.refresh();
    let (grant, grant_at) = deadline_in(GRANT);
    let both = p
        .claims(vec![p.rule_a, p.rule_b], 600)
        .strict()
        .with_rule_deadlines(&[(p.rule_a, grant), (p.rule_b, grant)].into(), Utc::now())
        .unwrap();
    let mut idle = p.tunnel(up.port, &p.sign(&both)).await;
    let ended = ends_by(&mut idle, grant_at + LATE)
        .await
        .expect("the idle tunnel stays open after its last grant");
    assert!(ended + Duration::from_millis(100) >= grant_at, "cut early");

    // Not covered by any rule: tunnelled untouched, until the session ends.
    let plain = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let plain_port = plain.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = plain.accept().await {
            tokio::spawn(async move {
                let mut b = [0u8; 1];
                let _ = tcp.read(&mut b).await;
            });
        }
    });
    let short = p.claims(vec![p.rule_a], 2).strict();
    let expires = Instant::now() + Duration::from_secs(2);
    let mut tcp = TcpStream::connect(p.dp.local_addr()).await.unwrap();
    let target = format!("127.0.0.1:{plain_port}");
    tcp.write_all(
        format!(
            "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Bearer {}\r\n\r\n",
            p.sign(&short)
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    assert!(read_head(&mut tcp).await.starts_with("HTTP/1.1 200"));
    assert!(
        ends_by(&mut tcp, expires + LATE).await.is_some(),
        "a strict passthrough tunnel outlived its session"
    );
    refresh.abort();
}

/// Updating a binding to sessions that no longer grant A cuts A's open
/// stream and leaves B's running; renewing B interrupts nothing; a stale
/// update is refused.
#[tokio::test]
async fn updating_a_binding_cuts_only_the_grant_it_removes() {
    let up = upstream().await;
    let p = Plane::start(&up).await;
    let refresh = p.refresh();
    let node = p.f.keys.node_id;
    let bound = |rules: Vec<RuleId>| {
        let claims = p
            .claims(rules, 600)
            .strict()
            .for_node(node)
            .for_binding("sandbox-1", 1)
            .unwrap();
        p.sign(&claims)
    };
    let binding = Arc::new(
        p.dp.bind(BindingSpec {
            binding_id: "sandbox-1".into(),
            generation: 1,
            sessions: vec![bound(vec![p.rule_a, p.rule_b])],
            version: 1,
            max_connections: 8,
        })
        .unwrap(),
    );
    let mut a = p.bound_tunnel(&binding, up.port).await;
    let mut b = p.bound_tunnel(&binding, up.port).await;
    assert!(get(&mut a, "/a/stream", up.port)
        .await
        .contains("Bearer ta"));
    assert!(get(&mut b, "/b/stream", up.port)
        .await
        .contains("Bearer tb"));

    binding
        .update(BindingUpdate {
            version: 2,
            sessions: vec![bound(vec![p.rule_b])],
        })
        .unwrap();
    assert!(
        ends_by(&mut a, Instant::now() + LATE).await.is_some(),
        "A's stream outlived the update that removed A"
    );
    assert!(
        ends_by(&mut b, Instant::now() + Duration::from_secs(1))
            .await
            .is_none(),
        "B's stream was cut by an update that kept B"
    );

    let stale = binding.update(BindingUpdate {
        version: 2,
        sessions: vec![bound(vec![p.rule_a, p.rule_b])],
    });
    assert!(
        matches!(
            stale,
            Err(DataPlaneError::StaleBindingUpdate {
                current: 2,
                offered: 2,
                ..
            })
        ),
        "{stale:?}"
    );
    binding
        .update(BindingUpdate {
            version: 3,
            sessions: vec![bound(vec![p.rule_b])],
        })
        .unwrap();
    assert!(
        ends_by(&mut b, Instant::now() + Duration::from_secs(1))
            .await
            .is_none(),
        "renewing B cut B's stream"
    );

    let mut a2 = p.bound_tunnel(&binding, up.port).await;
    let refused = get(&mut a2, "/a/next", up.port).await;
    assert!(refused.contains(" 403 "), "{refused}");
    let mut b2 = p.bound_tunnel(&binding, up.port).await;
    assert!(get(&mut b2, "/b/next", up.port).await.contains("Bearer tb"));
    assert_eq!(binding.version(), 3);
    refresh.abort();
}

/// Is `stream` at its end already (EOF or error within 100ms)?
async fn is_closed(stream: &mut (impl AsyncRead + Unpin)) -> bool {
    ends_by(stream, Instant::now() + Duration::from_millis(100))
        .await
        .is_some()
}

/// Revoking a binding and waiting returns only once its stream and its
/// idle tunnel are closed, and says how many there were.
#[tokio::test]
async fn revoke_and_wait_returns_once_the_bindings_traffic_has_stopped() {
    let up = upstream().await;
    let p = Plane::start(&up).await;
    let refresh = p.refresh();
    let claims = p
        .claims(vec![p.rule_a, p.rule_b], 600)
        .for_node(p.f.keys.node_id)
        .for_binding("sandbox-2", 1)
        .unwrap();
    let binding = Arc::new(
        p.dp.bind(BindingSpec {
            binding_id: "sandbox-2".into(),
            generation: 1,
            sessions: vec![p.sign(&claims)],
            version: 1,
            max_connections: 8,
        })
        .unwrap(),
    );
    let mut streaming = p.bound_tunnel(&binding, up.port).await;
    assert!(get(&mut streaming, "/a/stream", up.port)
        .await
        .contains("Bearer ta"));
    let mut idle = p.bound_tunnel(&binding, up.port).await;

    let report = binding
        .revoke_and_wait(Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(report.connections_closed, 2, "{report:?}");
    assert_eq!(
        binding.status().open_connections,
        0,
        "returned with traffic open"
    );
    assert!(report.snapshot_version.is_some());
    assert!(is_closed(&mut streaming).await, "the stream is still open");
    assert!(is_closed(&mut idle).await, "the idle tunnel is still open");
    // Nothing left: it returns at once.
    let again = binding
        .revoke_and_wait(Duration::from_millis(50))
        .await
        .unwrap();
    assert_eq!(again.connections_closed, 0);
    refresh.abort();
}

/// Waiting for a session's revocation fails, saying why, while the
/// revocation has not arrived, and succeeds only once it is installed and
/// the session's open traffic is gone.
/// A session that expired long ago is no longer listed as revoked, but
/// nothing can open under it: with nothing open it is cut.
#[tokio::test]
async fn session_cut_accepts_a_long_expired_session_with_nothing_open() {
    let up = upstream().await;
    let p = Plane::start(&up).await;
    let gone = tokenless_core::ids::SessionId::new();
    let long_ago = Utc::now() - TimeDelta::hours(2);
    let report =
        p.dp.session_cut(gone, long_ago, Duration::from_millis(300))
            .await
            .unwrap();
    assert_eq!(report.connections_closed, 0);
    // Still draining: it waits for that.
    let open = p.dp.shared.traffic.enter(gone);
    let err =
        p.dp.session_cut(gone, long_ago, Duration::from_millis(100))
            .await
            .unwrap_err();
    assert!(
        matches!(err, DataPlaneError::NotCut { open: 1, .. }),
        "{err}"
    );
    drop(open);
}

#[tokio::test]
async fn session_cut_waits_for_the_revocation_and_the_traffic() {
    let up = upstream().await;
    let p = Plane::start(&up).await;
    let claims = p.claims(vec![p.rule_a, p.rule_b], 600);
    let token = p.sign(&claims);
    let mut streaming = p.tunnel(up.port, &token).await;
    assert!(get(&mut streaming, "/b/stream", up.port)
        .await
        .contains("Bearer tb"));
    let mut idle = p.tunnel(up.port, &token).await;

    // Not delivered yet, as when the control plane cannot reach the node.
    let err =
        p.dp.session_cut(claims.jti, claims.exp, Duration::from_millis(300))
            .await
            .unwrap_err();
    match &err {
        DataPlaneError::NotCut {
            open,
            revocation_installed,
            lease_remaining_secs,
            ..
        } => {
            assert_eq!(*open, 2, "{err}");
            assert!(!revocation_installed, "{err}");
            assert!(*lease_remaining_secs > 0, "{err}");
        }
        other => panic!("{other}"),
    }
    assert!(err.to_string().contains("not installed yet"), "{err}");
    // No traffic is not enough: until the revocation is in force, a new
    // connection could still use the session.
    let unused = p.claims(vec![p.rule_a], 600);
    let err =
        p.dp.session_cut(unused.jti, unused.exp, Duration::from_millis(100))
            .await
            .unwrap_err();
    assert!(
        matches!(
            err,
            DataPlaneError::NotCut {
                open: 0,
                revocation_installed: false,
                ..
            }
        ),
        "{err}"
    );

    // Delivered late: the wait resolves once it is in force and the
    // traffic is gone, not before. `slow` stands for a connection still
    // being torn down after the revocation arrived.
    let slow = p.dp.shared.traffic.enter(claims.jti);
    let waiting = {
        let (dp_session, exp) = (claims.jti, claims.exp);
        let p = p.clone();
        tokio::spawn(async move {
            p.dp.session_cut(dp_session, exp, Duration::from_secs(5))
                .await
        })
    };
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(
        !waiting.is_finished(),
        "resolved before the revocation arrived"
    );
    let version = p.version.fetch_add(1, Ordering::SeqCst) + 1;
    let mut body = p.body(version);
    body.revoked_sessions = vec![claims.jti];
    p.installer.install(&p.f.sign(&body)).unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !waiting.is_finished(),
        "resolved while the session still had traffic open"
    );
    drop(slow);
    let report = timeout(Duration::from_secs(5), waiting)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(report.snapshot_version, Some(version));
    assert_eq!(report.connections_closed, 3);
    assert_eq!(
        p.dp.shared.traffic.count(&claims.jti),
        0,
        "returned with traffic open"
    );
    assert!(is_closed(&mut streaming).await, "the stream is still open");
    assert!(is_closed(&mut idle).await, "the idle tunnel is still open");
}
