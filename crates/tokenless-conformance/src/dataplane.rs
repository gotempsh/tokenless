// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! What an embedded data plane must do for the workloads it serves, run
//! against the embedder's own control services and stores.
//!
//! [`dataplane_suite`] starts an embedded data plane registered with
//! `control`, binds workloads to sessions minted the way an embedder mints
//! them, and drives their proxy connections over in-memory streams. Its
//! services' hosts don't resolve, so nothing reaches an upstream. It checks
//!
//! - **binding isolation:** a workload reaches only its own sessions'
//!   services, whatever `Proxy-Authorization` it sends;
//! - **generation fencing:** a session minted for an earlier start of a
//!   workload does not bind to a later one;
//! - **overlapping sessions refused:** two sessions covering one host are
//!   not bound together;
//! - **cutting open traffic:** revoking a session cuts its open connection,
//!   and an idle connection closes when its session expires, while fresh
//!   policy keeps the lease alive;
//! - **lease expiry:** with no new policy, traffic is refused once the lease
//!   runs out;
//! - **secrets never in diagnostics:** no token or secret appears in the
//!   status, errors, debug output, proxy answers or audit log, including
//!   the record of a request the credential was injected into.
//!
//! It uses real time, with sessions of a few seconds and the embedder's
//! lease, so `control` must be configured with `lease_secs` of at most
//! [`MAX_SUITE_LEASE_SECS`]. It takes about `lease_secs + 5` seconds.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rustls::pki_types::{CertificateDer, ServerName};
use tokenless_control::model::{Node, PageRequest};
use tokenless_control::service::policy::{CreateCredential, CreateRule};
use tokenless_control::service::sessions::{MintSession, MintedSession, SessionBinding};
use tokenless_control::{Caller, ControlServices};
use tokenless_core::audit::AuditEvent;
use tokenless_core::ids::{NodeId, RuleId, VaultId};
use tokenless_core::protocol::AuditBatch;
use tokenless_core::seal::{encode_public_key, SealPublicKey, SealSecretKey};
use tokenless_dataplane::audit::AuditShipper;
use tokenless_dataplane::state::NodeKeys;
use tokenless_dataplane::tls::upstream_client_config;
use tokenless_dataplane::{
    Binding, BindingSpec, DataPlane, DataPlaneConfig, DataPlaneError, NotReady, SnapshotInstaller,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::ConformanceFailure;

const SUITE: &str = "dataplane";

/// The longest lease the suite waits out.
pub const MAX_SUITE_LEASE_SECS: u32 = 10;

/// How long open traffic may take to be cut once its policy says so.
const CUT_BOUND: Duration = Duration::from_secs(3);

const HOST_A: &str = "svc-a.conformance.invalid";
const HOST_B: &str = "svc-b.conformance.invalid";
const SECRET_A: &str = "conformance-secret-a-0d8f";
const SECRET_B: &str = "conformance-secret-b-71c2";

macro_rules! check {
    ($check:expr, $cond:expr, $($fmt:tt)+) => {
        if !$cond {
            return Err(fail($check, format!($($fmt)+)));
        }
    };
}

fn fail(check: &'static str, detail: impl Into<String>) -> ConformanceFailure {
    ConformanceFailure {
        suite: SUITE,
        check,
        detail: detail.into(),
    }
}

/// Runs every data-plane check against `control`, acting as `host`: the
/// embedder's service principal, an admin not bound to a vault. It
/// creates one vault and registers one embedded node of its own, and at
/// the end, whether the checks pass or not, deletes the vault and revokes
/// the node.
pub async fn dataplane_suite(
    control: Arc<ControlServices>,
    host: &Caller,
) -> Result<(), ConformanceFailure> {
    let lease = control.nodes.lease_secs();
    check!(
        "setup",
        lease <= MAX_SUITE_LEASE_SECS,
        "the suite waits out the lease: configure lease_secs of at most {MAX_SUITE_LEASE_SECS}, not {lease}"
    );
    let _ = rustls::crypto::ring::default_provider().install_default();
    let vault = control
        .policy
        .create_vault(host, &format!("conformance-dataplane-{}", VaultId::new()))
        .await
        .map_err(|e| fail("setup", format!("creating the suite's vault: {e}")))?
        .id;
    let mut node = None;
    let result = match Harness::start(control.clone(), host, vault, &mut node).await {
        Ok(h) => {
            let result = h.run().await;
            h.dataplane.abort();
            result
        }
        Err(e) => Err(e),
    };
    let mut cleanup = Vec::new();
    if let Some(node) = node {
        if let Err(e) = control.nodes.revoke_node(host, &node).await {
            cleanup.push(format!("revoking node {node}: {e}"));
        }
    }
    if let Err(e) = control.policy.delete_vault(host, &vault, true).await {
        cleanup.push(format!("deleting vault {vault}: {e}"));
    }
    result?;
    check!(
        "cleanup",
        cleanup.is_empty(),
        "the suite could not remove what it created: {}",
        cleanup.join("; ")
    );
    Ok(())
}

struct Harness {
    control: Arc<ControlServices>,
    host: Caller,
    vault: VaultId,
    rule_a: RuleId,
    rule_a2: RuleId,
    rule_b: RuleId,
    node: Node,
    dataplane: DataPlane,
    installer: SnapshotInstaller,
    interception_ca: CertificateDer<'static>,
    /// Every token minted, to look for in diagnostics.
    tokens: std::sync::Mutex<Vec<String>>,
}

impl Harness {
    /// Sets up in `vault`, recording in `registered_node` the node it
    /// registers so the caller can revoke it even when a later step fails.
    async fn start(
        control: Arc<ControlServices>,
        host: &Caller,
        vault: VaultId,
        registered_node: &mut Option<NodeId>,
    ) -> Result<Self, ConformanceFailure> {
        let setup = |e: &dyn std::fmt::Display| fail("setup", e.to_string());
        let mut rules = Vec::new();
        for (name, target, secret) in [("svc-a", HOST_A, SECRET_A), ("svc-b", HOST_B, SECRET_B)] {
            let credential = control
                .policy
                .create_credential(
                    host,
                    &vault,
                    CreateCredential {
                        name: name.into(),
                        template_id: "generic-bearer".into(),
                        template_version: None,
                        host_override: vec![target.into()],
                        fields: [("token".to_string(), secret.to_string())].into(),
                        custom_headers: vec![],
                        substitutions: vec![],
                        not_after: None,
                    },
                )
                .await
                .map_err(|e| setup(&e))?;
            rules.push((credential.id, name));
        }
        let mut ids = Vec::new();
        for (credential_id, name) in [rules[0], rules[0], rules[1]] {
            let rule = control
                .policy
                .create_rule(
                    host,
                    &vault,
                    CreateRule {
                        name: format!("{name}-{}", ids.len()),
                        credential_id,
                        hosts: None,
                        paths: None,
                        methods: None,
                        mcp_tools: None,
                    },
                )
                .await
                .map_err(|e| setup(&e))?;
            ids.push(rule.id);
        }
        let seal_secret = SealSecretKey::random_from_rng(rand::rngs::OsRng);
        let registered = control
            .nodes
            .register_embedded(
                host,
                "conformance-dataplane",
                &encode_public_key(&SealPublicKey::from(&seal_secret)),
            )
            .await
            .map_err(|e| setup(&e))?;
        *registered_node = Some(registered.node.id);
        let node = registered.node.clone();
        let (dataplane, installer) = DataPlane::start_embedded(
            DataPlaneConfig {
                listen: "127.0.0.1:0".parse().map_err(|e| setup(&e))?,
                use_public_roots: false,
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
        .await
        .map_err(|e| setup(&e))?;
        Ok(Self {
            interception_ca: CertificateDer::from(control.keys.interception_ca.cert_der.clone()),
            control,
            host: host.clone(),
            vault,
            rule_a: ids[0],
            rule_a2: ids[1],
            rule_b: ids[2],
            node,
            dataplane,
            installer,
            tokens: std::sync::Mutex::new(Vec::new()),
        })
    }

    async fn run(&self) -> Result<(), ConformanceFailure> {
        self.binding_isolation().await?;
        self.generation_fencing().await?;
        self.overlapping_sessions_refused().await?;
        self.revoking_cuts_open_traffic().await?;
        self.expiry_closes_idle_traffic().await?;
        self.secrets_never_in_diagnostics().await?;
        // Last: it lets the lease run out.
        self.lease_expiry_refuses_traffic().await
    }

    /// Mints a session for `rule` bound to `binding`/`generation` on this
    /// node.
    async fn mint(
        &self,
        check: &'static str,
        rule: RuleId,
        binding: &str,
        generation: u64,
        ttl_secs: u64,
    ) -> Result<MintedSession, ConformanceFailure> {
        let minted = self
            .control
            .sessions
            .mint(
                &self.host,
                &self.vault,
                MintSession {
                    rule_ids: vec![rule],
                    bundle: None,
                    ttl_secs: Some(ttl_secs),
                    longest: false,
                    request_limit: None,
                    labels: Default::default(),
                    node_id: Some(self.node.id),
                    binding: Some(SessionBinding {
                        id: binding.into(),
                        generation,
                    }),
                    not_after: None,
                    rule_not_after: Default::default(),
                    strict: false,
                },
            )
            .await
            .map_err(|e| fail(check, format!("minting a session: {e}")))?;
        if let Ok(mut tokens) = self.tokens.lock() {
            tokens.push(minted.token.clone());
        }
        Ok(minted)
    }

    /// Builds the node's snapshot from the control services and installs
    /// it, as the embedder does after each mint and revocation.
    async fn install(&self, check: &'static str) -> Result<u64, ConformanceFailure> {
        let snapshot = self
            .control
            .nodes
            .build_snapshot(&self.node)
            .await
            .map_err(|e| fail(check, format!("building the snapshot: {e}")))?;
        self.installer
            .install(&snapshot)
            .map_err(|e| fail(check, format!("installing the snapshot: {e}")))
    }

    /// Whether `stream` is closed within `bound` while fresh policy is
    /// installed every half second, so a lease running out can't be what
    /// closes it.
    async fn closes_within_fresh_policy(
        &self,
        check: &'static str,
        stream: impl AsyncRead + AsyncWrite + Unpin,
        bound: Duration,
    ) -> Result<bool, ConformanceFailure> {
        let closed = closes_within(stream, bound);
        tokio::pin!(closed);
        loop {
            tokio::select! {
                closed = &mut closed => return Ok(closed),
                _ = tokio::time::sleep(Duration::from_millis(500)) => {
                    self.install(check).await?;
                }
            }
        }
    }

    fn bind(
        &self,
        id: &str,
        generation: u64,
        sessions: Vec<String>,
    ) -> Result<Arc<Binding>, DataPlaneError> {
        self.dataplane
            .bind(BindingSpec {
                binding_id: id.into(),
                generation,
                sessions,
                version: 0,
                max_connections: 8,
            })
            .map(Arc::new)
    }

    async fn bound(
        &self,
        check: &'static str,
        id: &str,
        generation: u64,
        sessions: Vec<String>,
    ) -> Result<Arc<Binding>, ConformanceFailure> {
        let version = self.install(check).await?;
        let binding = self
            .bind(id, generation, sessions)
            .map_err(|e| fail(check, format!("binding {id}: {e}")))?;
        binding
            .ready(version, Duration::from_secs(5))
            .await
            .map_err(|e| fail(check, format!("binding {id} never became ready: {e}")))?;
        Ok(binding)
    }

    async fn binding_isolation(&self) -> Result<(), ConformanceFailure> {
        const CHECK: &str = "binding_isolation";
        let a = self.mint(CHECK, self.rule_a, "iso-a", 1, 600).await?;
        let b = self.mint(CHECK, self.rule_b, "iso-b", 1, 600).await?;
        let binding_a = self.bound(CHECK, "iso-a", 1, vec![a.token.clone()]).await?;
        let binding_b = self.bound(CHECK, "iso-b", 1, vec![b.token]).await?;

        // Whatever the unmatched-host policy does with B's connection
        // (refuse it, or tunnel it untouched), it is never intercepted, so
        // A's credential is never injected into it.
        check!(
            CHECK,
            self.injects(&binding_a, None).await,
            "workload A's own service was not intercepted"
        );
        check!(
            CHECK,
            !self.injects(&binding_b, None).await,
            "workload B's connection to workload A's service was intercepted"
        );
        check!(
            CHECK,
            !self.injects(&binding_b, Some(&a.token)).await,
            "workload B's connection was intercepted when it sent workload A's token"
        );
        binding_a.revoke();
        binding_b.revoke();
        Ok(())
    }

    async fn generation_fencing(&self) -> Result<(), ConformanceFailure> {
        const CHECK: &str = "generation_fencing";
        let old = self.mint(CHECK, self.rule_a, "fence", 1, 600).await?;
        let new = self.mint(CHECK, self.rule_a, "fence", 2, 600).await?;
        self.install(CHECK).await?;
        check!(
            CHECK,
            self.bind("fence", 2, vec![old.token]).is_err(),
            "a session minted for start 1 bound to start 2"
        );
        let binding = self.bound(CHECK, "fence", 2, vec![new.token]).await?;
        let (status, _) = connect(&binding, HOST_A, None).await;
        check!(
            CHECK,
            status.contains(" 200 "),
            "start 2 with its own session: {status}"
        );
        binding.revoke();
        Ok(())
    }

    async fn overlapping_sessions_refused(&self) -> Result<(), ConformanceFailure> {
        const CHECK: &str = "overlapping_sessions_refused";
        let first = self.mint(CHECK, self.rule_a, "overlap", 1, 600).await?;
        let second = self.mint(CHECK, self.rule_a2, "overlap", 1, 600).await?;
        let version = self.install(CHECK).await?;
        match self.bind("overlap", 1, vec![first.token, second.token]) {
            Err(_) => Ok(()),
            // Bound before the policy showed the overlap: it must not
            // become ready, and the host must stay unreachable.
            Ok(binding) => {
                let ready = binding.ready(version, Duration::from_secs(5)).await;
                check!(
                    CHECK,
                    matches!(
                        ready,
                        Err(DataPlaneError::NotReady {
                            reason: NotReady::OverlappingSessions,
                            ..
                        })
                    ),
                    "two sessions covering {HOST_A} were bound and reported {ready:?}"
                );
                binding.revoke();
                Ok(())
            }
        }
    }

    async fn revoking_cuts_open_traffic(&self) -> Result<(), ConformanceFailure> {
        const CHECK: &str = "revoking_cuts_open_traffic";
        let minted = self.mint(CHECK, self.rule_a, "revoke", 1, 600).await?;
        let binding = self.bound(CHECK, "revoke", 1, vec![minted.token]).await?;
        let tls = self.intercepted(CHECK, &binding).await?;
        self.control
            .sessions
            .revoke(&self.host, &minted.session.id)
            .await
            .map_err(|e| fail(CHECK, format!("revoking the session: {e}")))?;
        self.install(CHECK).await?;
        check!(
            CHECK,
            self.closes_within_fresh_policy(CHECK, tls, CUT_BOUND)
                .await?,
            "an open connection outlived its session's revocation by more than {CUT_BOUND:?}"
        );
        binding.revoke();
        Ok(())
    }

    async fn expiry_closes_idle_traffic(&self) -> Result<(), ConformanceFailure> {
        const CHECK: &str = "expiry_closes_idle_traffic";
        let ttl = 2;
        let minted = self.mint(CHECK, self.rule_a, "expiry", 1, ttl).await?;
        let binding = self.bound(CHECK, "expiry", 1, vec![minted.token]).await?;
        let tls = self.intercepted(CHECK, &binding).await?;
        check!(
            CHECK,
            self.closes_within_fresh_policy(CHECK, tls, Duration::from_secs(ttl) + CUT_BOUND)
                .await?,
            "an idle connection stayed open after its session expired"
        );
        // With policy in force, the refusal is the session's, not the lease's.
        self.install(CHECK).await?;
        let (status, _) = connect(&binding, HOST_A, None).await;
        check!(
            CHECK,
            !status.contains(" 200 ") && !status.contains(" 503 "),
            "a new connection after the session expired, with fresh policy: {status}"
        );
        binding.revoke();
        Ok(())
    }

    async fn secrets_never_in_diagnostics(&self) -> Result<(), ConformanceFailure> {
        const CHECK: &str = "secrets_never_in_diagnostics";
        let minted = self.mint(CHECK, self.rule_b, "diag", 1, 600).await?;
        let binding = self
            .bound(CHECK, "diag", 1, vec![minted.token.clone()])
            .await?;
        // A request the credential is injected into, so the audit log holds
        // its record. The host doesn't resolve, so the proxy answers it.
        let mut tls = self.tls_to(CHECK, &binding, HOST_B).await?;
        let answer = timeout(Duration::from_secs(15), async {
            tls.write_all(
                format!("GET /conformance HTTP/1.1\r\nHost: {HOST_B}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .ok()?;
            let mut answer = Vec::new();
            let _ = tls.read_to_end(&mut answer).await;
            Some(String::from_utf8_lossy(&answer).into_owned())
        })
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
        check!(
            CHECK,
            answer.starts_with("HTTP/1.1 "),
            "no answer to a request through the diagnostics workload: {answer:?}"
        );
        let refused = self
            .bind("diag", 1, vec![minted.token.clone(), minted.token])
            .err()
            .map(|e| format!("{e} {e:?}"))
            .unwrap_or_default();
        // Let the audit batches reach the control services.
        let mut audit = Vec::new();
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            audit = self
                .control
                .audit
                .query(&self.host, Some(self.vault), None, PageRequest::default())
                .await
                .map_err(|e| fail(CHECK, format!("reading the audit log: {e}")))?
                .items;
            if audit.iter().any(|e| e.action == "proxy.inject") {
                break;
            }
        }
        check!(
            CHECK,
            audit.iter().any(|e| e.action == "proxy.inject"),
            "the request injected into never reached the vault's audit log"
        );
        let surfaces = [
            (
                "the data plane status",
                format!("{:?}", self.dataplane.status()),
            ),
            ("the binding status", format!("{:?}", binding.status())),
            ("the binding", format!("{binding:?}")),
            ("a bind error", refused),
            ("the proxy's answer", answer),
            ("the audit log", format!("{audit:?}")),
        ];
        let tokens = self.tokens.lock().map(|t| t.clone()).unwrap_or_default();
        for (surface, text) in &surfaces {
            for secret in [SECRET_A, SECRET_B] {
                check!(
                    CHECK,
                    !text.contains(secret),
                    "{surface} contains a stored secret"
                );
            }
            for token in &tokens {
                check!(
                    CHECK,
                    !text.contains(token.as_str()),
                    "{surface} contains a session token"
                );
            }
        }
        binding.revoke();
        Ok(())
    }

    async fn lease_expiry_refuses_traffic(&self) -> Result<(), ConformanceFailure> {
        const CHECK: &str = "lease_expiry_refuses_traffic";
        let minted = self.mint(CHECK, self.rule_a, "lease", 1, 600).await?;
        let binding = self.bound(CHECK, "lease", 1, vec![minted.token]).await?;
        let tls = self.intercepted(CHECK, &binding).await?;
        // No more snapshots: the control plane is unreachable from here on.
        let lease = Duration::from_secs(u64::from(self.control.nodes.lease_secs()));
        check!(
            CHECK,
            closes_within(tls, lease + CUT_BOUND).await,
            "an open connection outlived the policy lease"
        );
        let (status, _) = connect(&binding, HOST_A, None).await;
        check!(
            CHECK,
            status.contains(" 503 "),
            "a new connection after the lease ran out: {status}"
        );
        check!(
            CHECK,
            self.dataplane.status().problem == Some(NotReady::StalePolicy),
            "the status did not report the stale policy: {:?}",
            self.dataplane.status().problem
        );
        binding.revoke();
        Ok(())
    }

    /// Whether a connection through `binding` to service A is intercepted,
    /// the only way a credential is ever injected into it.
    async fn injects(&self, binding: &Arc<Binding>, token: Option<&str>) -> bool {
        let (status, stream) = connect(binding, HOST_A, token).await;
        if !status.contains(" 200 ") {
            return false;
        }
        let Ok(config) = upstream_client_config(false, std::slice::from_ref(&self.interception_ca))
        else {
            return false;
        };
        let Ok(name) = ServerName::try_from(HOST_A.to_string()) else {
            return false;
        };
        matches!(
            timeout(
                Duration::from_secs(5),
                TlsConnector::from(config).connect(name, stream)
            )
            .await,
            Ok(Ok(_))
        )
    }

    /// An intercepted connection to the workload's service, TLS done with
    /// the interception CA and nothing sent: an idle keep-alive.
    async fn intercepted(
        &self,
        check: &'static str,
        binding: &Arc<Binding>,
    ) -> Result<TlsStream<DuplexStream>, ConformanceFailure> {
        self.tls_to(check, binding, HOST_A).await
    }

    /// [`Harness::intercepted`] to `host`.
    async fn tls_to(
        &self,
        check: &'static str,
        binding: &Arc<Binding>,
        host: &str,
    ) -> Result<TlsStream<DuplexStream>, ConformanceFailure> {
        let (status, stream) = connect(binding, host, None).await;
        check!(
            check,
            status.contains(" 200 "),
            "opening the connection: {status}"
        );
        let config = upstream_client_config(false, std::slice::from_ref(&self.interception_ca))
            .map_err(|e| fail(check, format!("client TLS: {e}")))?;
        let name = ServerName::try_from(host.to_string())
            .map_err(|e| fail(check, format!("server name: {e}")))?;
        timeout(
            Duration::from_secs(5),
            TlsConnector::from(config).connect(name, stream),
        )
        .await
        .map_err(|_| fail(check, "the TLS handshake with the proxy timed out"))?
        .map_err(|e| fail(check, format!("the TLS handshake with the proxy: {e}")))
    }
}

/// Opens a proxy connection through `binding` and sends `CONNECT host:443`,
/// with `token` as `Proxy-Authorization` if given. Returns the status line
/// and the stream.
async fn connect(
    binding: &Arc<Binding>,
    host: &str,
    token: Option<&str>,
) -> (String, DuplexStream) {
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let serving = binding.clone();
    tokio::spawn(async move { serving.serve(server).await });
    let auth = token
        .map(|t| format!("Proxy-Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let request = format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n{auth}\r\n");
    if client.write_all(request.as_bytes()).await.is_err() {
        return ("connection refused".into(), client);
    }
    let head = timeout(Duration::from_secs(5), read_head(&mut client))
        .await
        .unwrap_or_else(|_| "no answer".into());
    let status = head.lines().next().unwrap_or("closed").to_string();
    (status, client)
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

/// Whether the other side closes `stream` within `bound`.
async fn closes_within(mut stream: impl AsyncRead + AsyncWrite + Unpin, bound: Duration) -> bool {
    let mut buf = [0u8; 1024];
    let read = async {
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    };
    timeout(bound, read).await.is_ok()
}

/// Ships audit batches to the control services in-process, as an
/// embedder does.
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
