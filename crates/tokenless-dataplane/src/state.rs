// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The node's in-memory view of policy, swapped atomically on each snapshot.
//!
//! The request path only ever does `ArcSwapOption::load` and reads immutable
//! data: no lock, no I/O. All verification, decryption and certificate
//! minting happens here, on the snapshot task, before the swap.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use http::{HeaderName, HeaderValue};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::CertificateDer;
use rustls::ServerConfig;
use tokenless_core::ids::{CredentialId, NodeId, RuleId, SessionId};
use tokenless_core::injection::InjectedHeaders;
use tokenless_core::rule::RuleScope;
use tokenless_core::scope::Scope;
use tokenless_core::seal::{open, SealSecretKey};
use tokenless_core::snapshot::{
    ca_aad, rule_aad, QuarantinePolicy, SignedSnapshot, UnmatchedHostPolicy,
};
use tokenless_core::substitution::RenderedSubstitution;
use zeroize::Zeroizing;

use tokio::sync::watch;
use tracing::debug;

use crate::error::DataPlaneError;
use crate::metrics::Metrics;
use crate::tls::{leaf_server_config, sha256_hex};

/// Maximum clock skew accepted for a snapshot's `issued_at` in the future.
const MAX_FUTURE_SKEW_SECS: i64 = 60;
const LEAF_VALIDITY_DAYS: i64 = 7;
const LEAF_REFRESH_AFTER: Duration = Duration::from_secs(24 * 3600);

/// Keys the node holds for verifying and opening snapshots.
pub struct NodeKeys {
    pub node_id: NodeId,
    pub seal_secret: SealSecretKey,
    pub snapshot_key: VerifyingKey,
}

#[derive(Clone)]
pub struct ActiveRule {
    pub id: RuleId,
    pub scope: Scope,
    pub credential_id: CredentialId,
    pub allow: RuleScope,
    pub strip: Vec<HeaderName>,
    pub inject: Vec<(HeaderName, HeaderValue)>,
    /// Placeholders swapped for secret values; empty for most rules.
    pub substitutions: Vec<RenderedSubstitution>,
    /// When the credential stops being valid upstream, if it does.
    pub not_after: Option<chrono::DateTime<chrono::Utc>>,
}

impl ActiveRule {
    /// Whether a request sent under `other` would leave the proxy exactly as
    /// under this rule.
    pub fn sends_same_as(&self, other: &ActiveRule) -> bool {
        self.credential_id == other.credential_id
            || (self.inject == other.inject
                && self.substitutions == other.substitutions
                && self.strip == other.strip
                && self.not_after == other.not_after)
    }
}

/// Interception certificates, one server config per rule host.
pub struct InterceptionTls {
    ca_fingerprint: String,
    created: Instant,
    configs: HashMap<String, Arc<ServerConfig>>,
}

impl InterceptionTls {
    pub fn config_for(&self, pattern_host: &str) -> Option<Arc<ServerConfig>> {
        self.configs.get(pattern_host).cloned()
    }
}

#[derive(Clone)]
pub struct ActiveSnapshot {
    pub version: u64,
    pub lease_deadline: Instant,
    /// The control plane's clock when it issued the snapshot, and when it
    /// was installed here: what deadlines are checked against (see
    /// `clock`).
    pub issued_at: DateTime<Utc>,
    pub installed_at: Instant,
    pub session_keys: HashMap<String, VerifyingKey>,
    pub revoked: HashSet<SessionId>,
    pub limits: HashMap<SessionId, Arc<AtomicU64>>,
    pub policy: UnmatchedHostPolicy,
    pub egress: tokenless_core::egress::EgressPolicy,
    pub passthrough_hosts: Vec<tokenless_core::host::HostPattern>,
    pub rules: Vec<ActiveRule>,
    pub tls: Arc<InterceptionTls>,
    /// When this node cuts off a session that keeps being refused.
    pub quarantine: Option<QuarantinePolicy>,
    /// Sessions this node cut off that the control plane has not listed as
    /// revoked yet, with their expiry; they are in `revoked` too, and
    /// carried into each new snapshot until the control plane lists them.
    pub quarantined: HashMap<SessionId, DateTime<Utc>>,
}

impl ActiveSnapshot {
    pub fn lease_valid(&self) -> bool {
        Instant::now() < self.lease_deadline
    }
}

pub type SnapshotHandle = Arc<ArcSwapOption<ActiveSnapshot>>;

fn leaf_configs(
    hosts: &HashSet<String>,
    ca_cert_der: &[u8],
    ca_key_der: &[u8],
    reuse: Option<&InterceptionTls>,
) -> Result<HashMap<String, Arc<ServerConfig>>, DataPlaneError> {
    let mut configs = HashMap::with_capacity(hosts.len());
    let mut missing = Vec::new();
    for host in hosts {
        match reuse.and_then(|r| r.configs.get(host)) {
            Some(existing) => {
                configs.insert(host.clone(), existing.clone());
            }
            None => missing.push(host.clone()),
        }
    }
    if missing.is_empty() {
        return Ok(configs);
    }
    let ca_key = KeyPair::try_from(ca_key_der).map_err(|e| DataPlaneError::Certificate {
        host: "interception CA".into(),
        reason: format!("CA key is unusable: {e}"),
    })?;
    let issuer = Issuer::from_ca_cert_der(&CertificateDer::from(ca_cert_der.to_vec()), ca_key)
        .map_err(|e| DataPlaneError::Certificate {
            host: "interception CA".into(),
            reason: format!("CA certificate is unusable: {e}"),
        })?;
    let leaf_key = KeyPair::generate().map_err(|e| DataPlaneError::Certificate {
        host: "leaf".into(),
        reason: e.to_string(),
    })?;
    let leaf_key_der = Zeroizing::new(leaf_key.serialize_der());
    let now = Utc::now();
    for host in missing {
        let cert_err = |reason: String| DataPlaneError::Certificate {
            host: host.clone(),
            reason,
        };
        let mut params =
            CertificateParams::new(vec![host.clone()]).map_err(|e| cert_err(e.to_string()))?;
        let to_offset = |dt: DateTime<Utc>| {
            time::OffsetDateTime::from_unix_timestamp(dt.timestamp())
                .map_err(|e| cert_err(e.to_string()))
        };
        params.not_before = to_offset(now - chrono::Duration::hours(1))?;
        params.not_after = to_offset(now + chrono::Duration::days(LEAF_VALIDITY_DAYS))?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host.as_str());
        params.distinguished_name = dn;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let cert = params
            .signed_by(&leaf_key, &issuer)
            .map_err(|e| cert_err(e.to_string()))?;
        let config = leaf_server_config(
            &host,
            vec![
                cert.der().clone(),
                CertificateDer::from(ca_cert_der.to_vec()),
            ],
            leaf_key_der.to_vec(),
        )?;
        configs.insert(host, config);
    }
    Ok(configs)
}

/// Verifies `signed` against the snapshot in force and swaps it in, counting
/// the outcome, and tells open tunnels through `changed` so they can see
/// whether their session was revoked. Returns the version now in force.
/// Callers that may run concurrently serialize around it, so an older
/// snapshot never replaces a newer one.
pub fn apply(
    signed: &SignedSnapshot,
    keys: &NodeKeys,
    handle: &SnapshotHandle,
    changed: &watch::Sender<u64>,
    metrics: &Metrics,
) -> Result<u64, DataPlaneError> {
    loop {
        let previous = handle.load_full();
        let active = match build_active(signed, keys, previous.as_deref(), Utc::now()) {
            Ok(active) => active,
            Err(e) => {
                Metrics::inc(&metrics.snapshots_rejected_total);
                return Err(e);
            }
        };
        let version = active.version;
        let rules = active.rules.len();
        // Swapped only over the snapshot it was built from: a session cut
        // off in between (see `quarantine`) is carried into a rebuild
        // rather than lost.
        let swapped = handle.compare_and_swap(&previous, Some(Arc::new(active)));
        let same = match (swapped.as_ref(), previous.as_ref()) {
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            (None, None) => true,
            _ => false,
        };
        if !same {
            continue;
        }
        debug!(version, rules, "applied snapshot");
        changed.send_replace(version);
        Metrics::inc(&metrics.snapshots_applied_total);
        return Ok(version);
    }
}

/// Verifies `signed` and builds the state to swap in. `previous` supplies
/// the version floor, request counters and reusable leaf certificates.
pub fn build_active(
    signed: &SignedSnapshot,
    keys: &NodeKeys,
    previous: Option<&ActiveSnapshot>,
    now: DateTime<Utc>,
) -> Result<ActiveSnapshot, DataPlaneError> {
    let body = signed.verify(&keys.snapshot_key)?;
    if body.node_id != keys.node_id {
        return Err(DataPlaneError::rejected(format!(
            "snapshot {} is for node {}, this node is {}",
            body.version, body.node_id, keys.node_id
        )));
    }
    if let Some(prev) = previous {
        if body.version <= prev.version {
            return Err(DataPlaneError::StaleSnapshot {
                received: body.version,
                current: prev.version,
            });
        }
    }
    let age = now.signed_duration_since(body.issued_at).num_seconds();
    if age < -MAX_FUTURE_SKEW_SECS {
        return Err(DataPlaneError::rejected(format!(
            "snapshot {} is issued {}s in the future; check clocks",
            body.version, -age
        )));
    }
    let lease = i64::from(body.lease_secs);
    if age >= lease {
        return Err(DataPlaneError::rejected(format!(
            "snapshot {} was issued {age}s ago and its {lease}s lease has already run out",
            body.version
        )));
    }
    let remaining = Duration::from_secs(u64::try_from(lease - age.max(0)).unwrap_or(0));

    let mut session_keys = HashMap::new();
    for key in &body.session_keys {
        session_keys.insert(key.kid.clone(), key.decode()?);
    }

    let mut revoked: HashSet<SessionId> = body.revoked_sessions.iter().copied().collect();
    let quarantined = crate::quarantine::still_quarantined(previous, &revoked, now);
    revoked.extend(quarantined.keys().copied());

    let mut limits = HashMap::new();
    for limit in &body.limited_sessions {
        let counter = previous
            .and_then(|p| p.limits.get(&limit.session_id).cloned())
            .unwrap_or_else(|| Arc::new(AtomicU64::new(0)));
        limits.insert(limit.session_id, counter);
    }

    let ca_cert_der = STANDARD
        .decode(&body.interception_ca.cert_der)
        .map_err(|e| DataPlaneError::rejected(format!("interception CA is not base64: {e}")))?;
    let ca_key_der = open(
        &keys.seal_secret,
        &body.interception_ca.key,
        &ca_aad(&keys.node_id),
    )?;

    let mut rules = Vec::with_capacity(body.rules.len());
    let mut hosts = HashSet::new();
    for rule in &body.rules {
        let plaintext = open(
            &keys.seal_secret,
            &rule.headers,
            &rule_aad(&keys.node_id, &rule.rule_id, &rule.credential_id),
        )?;
        let headers: InjectedHeaders = serde_json::from_slice(&plaintext).map_err(|e| {
            DataPlaneError::rejected(format!("rule {} headers are invalid: {e}", rule.rule_id))
        })?;
        let mut inject = Vec::with_capacity(headers.headers.len());
        for h in &headers.headers {
            let name = HeaderName::from_bytes(h.name.as_bytes()).map_err(|e| {
                DataPlaneError::rejected(format!(
                    "rule {} header name '{}': {e}",
                    rule.rule_id, h.name
                ))
            })?;
            let mut value = HeaderValue::from_str(&h.value).map_err(|_| {
                DataPlaneError::rejected(format!(
                    "rule {} header '{}' has an invalid value",
                    rule.rule_id, h.name
                ))
            })?;
            value.set_sensitive(true);
            inject.push((name, value));
        }
        let strip = rule
            .strip_headers
            .iter()
            .map(|n| {
                HeaderName::from_bytes(n.as_bytes()).map_err(|e| {
                    DataPlaneError::rejected(format!(
                        "rule {} strip header '{n}': {e}",
                        rule.rule_id
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        for host in &rule.allow.hosts {
            hosts.insert(host.certificate_name().to_string());
        }
        rules.push(ActiveRule {
            id: rule.rule_id,
            scope: rule.scope.clone(),
            credential_id: rule.credential_id,
            allow: rule.allow.clone(),
            strip,
            inject,
            substitutions: headers.substitutions.clone(),
            not_after: rule.not_after,
        });
    }

    let fingerprint = sha256_hex(&ca_cert_der);
    let reuse = previous
        .map(|p| p.tls.as_ref())
        .filter(|t| t.ca_fingerprint == fingerprint && t.created.elapsed() < LEAF_REFRESH_AFTER);
    let configs = leaf_configs(&hosts, &ca_cert_der, &ca_key_der, reuse)?;
    let tls = Arc::new(InterceptionTls {
        ca_fingerprint: fingerprint,
        created: reuse.map(|r| r.created).unwrap_or_else(Instant::now),
        configs,
    });

    Ok(ActiveSnapshot {
        version: body.version,
        lease_deadline: Instant::now() + remaining,
        issued_at: body.issued_at,
        installed_at: Instant::now(),
        session_keys,
        revoked,
        quarantined,
        quarantine: body.quarantine,
        limits,
        policy: body.unmatched_host_policy,
        egress: body.egress.clone(),
        passthrough_hosts: body.passthrough_hosts.clone(),
        rules,
        tls,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use tokenless_core::host::HostPattern;
    use tokenless_core::injection::InjectedHeader;
    use tokenless_core::path::{HttpMethod, PathPattern};
    use tokenless_core::seal::{seal, SealPublicKey};
    use tokenless_core::snapshot::{
        InterceptionCa, PublishedKey, SnapshotBody, SnapshotRule, SNAPSHOT_FORMAT,
    };

    use super::*;

    pub struct Fixture {
        pub keys: NodeKeys,
        pub signer: SigningKey,
        pub session_signer: SigningKey,
        pub ca_cert_der: Vec<u8>,
        ca_key_der: Vec<u8>,
    }

    impl Fixture {
        pub fn new() -> Self {
            let ca_key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::default();
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
            params.key_usages = vec![
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::DigitalSignature,
            ];
            let ca = params.self_signed(&ca_key).unwrap();
            let seal_secret = SealSecretKey::random_from_rng(OsRng);
            let signer = SigningKey::generate(&mut OsRng);
            Self {
                keys: NodeKeys {
                    node_id: NodeId::new(),
                    seal_secret,
                    snapshot_key: signer.verifying_key(),
                },
                signer,
                session_signer: SigningKey::generate(&mut OsRng),
                ca_cert_der: ca.der().to_vec(),
                ca_key_der: ca_key.serialize_der(),
            }
        }

        pub fn snapshot(
            &self,
            version: u64,
            rules: Vec<(RuleId, Scope, &str, &str)>,
        ) -> SignedSnapshot {
            self.sign(&self.snapshot_body(version, rules))
        }

        pub fn sign(&self, body: &SnapshotBody) -> SignedSnapshot {
            SignedSnapshot::sign(body, &self.signer).unwrap()
        }

        /// The body of [`Fixture::snapshot`], for tests that change a field.
        pub fn snapshot_body(
            &self,
            version: u64,
            rules: Vec<(RuleId, Scope, &str, &str)>,
        ) -> SnapshotBody {
            let public = SealPublicKey::from(&self.keys.seal_secret);
            let node = self.keys.node_id;
            SnapshotBody {
                format: SNAPSHOT_FORMAT,
                version,
                node_id: node,
                issued_at: Utc::now(),
                lease_secs: 60,
                session_keys: vec![PublishedKey::from_key(&self.session_signer.verifying_key())],
                revoked_sessions: vec![],
                limited_sessions: vec![],
                unmatched_host_policy: UnmatchedHostPolicy::Passthrough,
                egress: Default::default(),
                passthrough_hosts: vec![],
                interception_ca: InterceptionCa {
                    cert_der: STANDARD.encode(&self.ca_cert_der),
                    key: seal(&public, &self.ca_key_der, &ca_aad(&node)).unwrap(),
                },
                rules: rules
                    .into_iter()
                    .map(|(rule_id, scope, host, token)| {
                        let credential_id = CredentialId::new();
                        let headers = InjectedHeaders {
                            headers: vec![InjectedHeader {
                                name: "authorization".into(),
                                value: format!("Bearer {token}"),
                            }],
                            substitutions: vec![],
                        };
                        SnapshotRule {
                            rule_id,
                            scope,
                            credential_id,
                            allow: RuleScope {
                                hosts: vec![HostPattern::parse(host).unwrap()],
                                paths: vec![PathPattern::parse("/*").unwrap()],
                                methods: vec![HttpMethod::parse("*").unwrap()],
                                mcp_tools: None,
                                git: None,
                            },
                            strip_headers: vec![
                                "authorization".into(),
                                "proxy-authorization".into(),
                            ],
                            headers: seal(
                                &public,
                                &serde_json::to_vec(&headers).unwrap(),
                                &rule_aad(&node, &rule_id, &credential_id),
                            )
                            .unwrap(),
                            not_after: None,
                        }
                    })
                    .collect(),
                quarantine: None,
            }
        }
    }

    fn scope() -> Scope {
        Scope::parse("vault:test").unwrap()
    }

    #[test]
    fn builds_rules_and_leaf_certs() {
        let f = Fixture::new();
        let rule = RuleId::new();
        let active = build_active(
            &f.snapshot(1, vec![(rule, scope(), "api.example.com", "tok")]),
            &f.keys,
            None,
            Utc::now(),
        )
        .unwrap();
        assert_eq!(active.version, 1);
        assert!(active.lease_valid());
        assert_eq!(active.rules[0].inject[0].1.to_str().unwrap(), "Bearer tok");
        assert!(active.rules[0].inject[0].1.is_sensitive());
        assert!(active.tls.config_for("api.example.com").is_some());
    }

    #[test]
    fn rejects_stale_versions_wrong_node_and_bad_signatures() {
        let f = Fixture::new();
        let first = build_active(&f.snapshot(5, vec![]), &f.keys, None, Utc::now()).unwrap();
        assert!(matches!(
            build_active(&f.snapshot(5, vec![]), &f.keys, Some(&first), Utc::now()),
            Err(DataPlaneError::StaleSnapshot {
                received: 5,
                current: 5
            })
        ));
        assert!(build_active(&f.snapshot(6, vec![]), &f.keys, Some(&first), Utc::now()).is_ok());

        let other = Fixture::new();
        assert!(build_active(&other.snapshot(1, vec![]), &f.keys, None, Utc::now()).is_err());
        let mut tampered = f.snapshot(7, vec![]);
        tampered.body = tampered
            .body
            .replace("\"lease_secs\":60", "\"lease_secs\":6000");
        assert!(build_active(&tampered, &f.keys, None, Utc::now()).is_err());
    }

    #[test]
    fn rejects_snapshots_whose_lease_already_ran_out() {
        let f = Fixture::new();
        let later = Utc::now() + chrono::Duration::seconds(61);
        assert!(matches!(
            build_active(&f.snapshot(1, vec![]), &f.keys, None, later),
            Err(DataPlaneError::SnapshotRejected { .. })
        ));
    }

    #[test]
    fn leaf_certificates_are_reused_across_renewals() {
        let f = Fixture::new();
        let r = RuleId::new();
        let first = build_active(
            &f.snapshot(1, vec![(r, scope(), "api.example.com", "a")]),
            &f.keys,
            None,
            Utc::now(),
        )
        .unwrap();
        let second = build_active(
            &f.snapshot(2, vec![(r, scope(), "api.example.com", "b")]),
            &f.keys,
            Some(&first),
            Utc::now(),
        )
        .unwrap();
        assert!(Arc::ptr_eq(
            &first.tls.config_for("api.example.com").unwrap(),
            &second.tls.config_for("api.example.com").unwrap()
        ));
        assert_eq!(second.rules[0].inject[0].1.to_str().unwrap(), "Bearer b");
    }
}
