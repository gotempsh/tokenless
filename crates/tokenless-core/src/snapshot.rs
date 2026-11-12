// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Policy snapshots sent from the control plane to a data plane node.
//!
//! A snapshot is JSON signed with Ed25519 over its exact bytes, so there is
//! no canonicalisation step to get wrong. It carries a strictly increasing
//! version (nodes reject anything not newer than what they hold) and a lease:
//! once the lease runs out without a newer snapshot the node fails closed.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::host::HostPattern;
use crate::ids::{CredentialId, NodeId, RuleId, SessionId, TripwireId};
use crate::rule::RuleScope;
use crate::scope::Scope;
use crate::seal::Sealed;
use crate::session::key_id;

/// The newest format this build reads and writes. Format 2 adds a rule's
/// `not_after`, format 3 a rule's Git scope, format 4 the quarantine policy,
/// format 5 tripwires, format 6 the rate limit and turning response
/// redaction off. A snapshot is written in the oldest format that carries
/// everything in it, and a node says which format it reads when it opens
/// the snapshot stream ([`READS_FORMAT_PARAM`]): a rule it could not
/// enforce is left out of its snapshot, so an older node stops using that
/// one service instead of refusing every snapshot.
pub const SNAPSHOT_FORMAT: u32 = 6;
/// The format that carries [`SnapshotBody::quarantine`].
pub const QUARANTINE_FORMAT: u32 = 4;
/// The format that carries [`SnapshotBody::tripwires`].
pub const TRIPWIRE_FORMAT: u32 = 5;
/// The format that carries [`SnapshotBody::rate_limit`].
pub const RATE_LIMIT_FORMAT: u32 = 6;
/// The format that can turn [`SnapshotBody::scrub_responses`] off.
pub const SCRUB_FORMAT: u32 = 6;
/// What a node reports when it redacted a credential from a response.
pub const SCRUBBED_ACTION: &str = "proxy.response_scrubbed";
/// What a node reports, once per session per [`RATE_LIMIT_REPORT_SECS`],
/// when it refused a session's requests for going past the
/// [`RateLimit`], with how many.
pub const RATE_LIMITED_ACTION: &str = "proxy.rate_limited";
/// How often a node reports a session's rate-limited requests, so a
/// flood does not flood the audit log.
pub const RATE_LIMIT_REPORT_SECS: u64 = 10;
/// What a node reports when a request carries a tripwire's decoy; it has
/// already cut the session off, and the control plane revokes it.
pub const TRIPWIRE_ACTION: &str = "proxy.tripwire";
/// What a node reports when it closes a session's open traffic because the
/// session or its grant ended, the lease ran out or the node is stopping.
/// The node did the cutting, so it is never counted as a refusal.
pub const TUNNEL_CUT_ACTION: &str = "proxy.tunnel_cut";
/// What a node reports when it cuts a session off under its
/// [`QuarantinePolicy`]; the control plane then revokes the session.
pub const QUARANTINE_ACTION: &str = "proxy.quarantine";
/// The snapshot stream's query parameter with the newest format the node
/// reads. A node that sends none reads format 1.
pub const READS_FORMAT_PARAM: &str = "reads_format";
/// The oldest format this build still reads.
pub const MIN_SNAPSHOT_FORMAT: u32 = 1;
// Predates the rename to tokenless and is kept: changing it invalidates
// existing snapshot signatures.
const SIGNATURE_CONTEXT: &[u8] = b"credential-broker/snapshot/v1\0";

/// What the data plane does with a CONNECT to a host no session rule covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnmatchedHostPolicy {
    /// Open a plain TCP tunnel; TLS is never intercepted and nothing is injected.
    #[default]
    Passthrough,
    /// Refuse the CONNECT with 403.
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedKey {
    pub kid: String,
    /// Ed25519 public key, base64.
    pub public_key: String,
}

impl PublishedKey {
    pub fn from_key(key: &VerifyingKey) -> Self {
        Self {
            kid: key_id(key),
            public_key: STANDARD.encode(key.as_bytes()),
        }
    }

    pub fn decode(&self) -> Result<VerifyingKey, CoreError> {
        decode_verifying_key(&self.public_key)
    }
}

pub fn decode_verifying_key(value: &str) -> Result<VerifyingKey, CoreError> {
    let bytes: [u8; 32] = STANDARD
        .decode(value)
        .map_err(|e| CoreError::encoding("ed25519 public key", e))?
        .try_into()
        .map_err(|_| CoreError::encoding("ed25519 public key", "expected 32 bytes"))?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| CoreError::crypto("ed25519.decode", e.to_string()))
}

/// When a proxy cuts a session off on its own: after `refusals` refused
/// requests within `window_secs` of the first. A session that keeps
/// probing for what it may not reach is more likely an intruder than an
/// agent at work, and a person reviews it before anything runs again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuarantinePolicy {
    pub refusals: u32,
    pub window_secs: u32,
}

impl QuarantinePolicy {
    pub const MIN_REFUSALS: u32 = 3;
    pub const MAX_REFUSALS: u32 = 10_000;
    pub const MIN_WINDOW_SECS: u32 = 10;
    pub const MAX_WINDOW_SECS: u32 = 3600;
}

impl Default for QuarantinePolicy {
    /// 20 refusals in 5 minutes: an agent at work rarely comes near it,
    /// something trying host after host does within a minute.
    fn default() -> Self {
        Self {
            refusals: 20,
            window_secs: 300,
        }
    }
}

/// How fast one session may send requests through a node: `per_sec` on
/// average, with bursts of up to `burst` at once. Past it the node answers
/// 429 with `Retry-After` and forwards nothing; nothing is queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimit {
    pub per_sec: u32,
    pub burst: u32,
}

impl RateLimit {
    pub const MIN_PER_SEC: u32 = 1;
    pub const MAX_PER_SEC: u32 = 10_000;
    pub const MAX_BURST: u32 = 100_000;

    /// Whether going from `before` to `after` lets a session send more.
    pub fn loosened_by(before: Option<Self>, after: Option<Self>) -> bool {
        match (before, after) {
            (Some(_), None) => true,
            (None, _) => false,
            (Some(b), Some(a)) => a.per_sec > b.per_sec || a.burst > b.burst,
        }
    }
}

impl Default for RateLimit {
    /// 20 a second with bursts of 100: more than an agent at work sends,
    /// far less than a script emptying an API.
    fn default() -> Self {
        Self {
            per_sec: 20,
            burst: 100,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionLimit {
    pub session_id: SessionId,
    pub limit: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterceptionCa {
    /// CA certificate, DER, base64. Public: agents are told to trust it.
    pub cert_der: String,
    /// PKCS#8 private key, sealed to the node.
    pub key: Sealed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotRule {
    pub rule_id: RuleId,
    pub scope: Scope,
    pub credential_id: CredentialId,
    pub allow: RuleScope,
    /// Lower-cased header names the client may not supply on matching hosts.
    pub strip_headers: Vec<String>,
    /// [`crate::injection::InjectedHeaders`] JSON, sealed to the node.
    pub headers: Sealed,
    /// When the credential stops being valid upstream: the node injects it
    /// until then and refuses with a typed error after. Format 2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<DateTime<Utc>>,
}

/// The oldest format that carries `rule`.
pub fn rule_format(rule: &SnapshotRule) -> u32 {
    if rule.allow.git.is_some() {
        3
    } else if rule.not_after.is_some() {
        2
    } else {
        MIN_SNAPSHOT_FORMAT
    }
}

/// The format a snapshot with `rules` is written in: the oldest that
/// carries everything in it.
pub fn format_for(rules: &[SnapshotRule]) -> u32 {
    rules
        .iter()
        .map(rule_format)
        .max()
        .unwrap_or(MIN_SNAPSHOT_FORMAT)
}

/// The rules a node that reads formats up to `reads` can enforce, and how
/// many it cannot. Those are left out of its snapshot: an older node never
/// sends a credential whose limits it does not know, and still serves the
/// rest.
pub fn rules_readable_by(rules: &[SnapshotRule], reads: u32) -> (Vec<SnapshotRule>, usize) {
    let readable: Vec<SnapshotRule> = rules
        .iter()
        .filter(|r| rule_format(r) <= reads)
        .cloned()
        .collect();
    let withheld = rules.len() - readable.len();
    (readable, withheld)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotBody {
    pub format: u32,
    pub version: u64,
    pub node_id: NodeId,
    pub issued_at: DateTime<Utc>,
    pub lease_secs: u32,
    pub session_keys: Vec<PublishedKey>,
    pub revoked_sessions: Vec<SessionId>,
    pub limited_sessions: Vec<SessionLimit>,
    pub unmatched_host_policy: UnmatchedHostPolicy,
    /// Destinations passthrough tunnels may reach.
    #[serde(default)]
    pub egress: crate::egress::EgressPolicy,
    /// Hosts tunnelled untouched even under [`UnmatchedHostPolicy::Deny`].
    /// Omitted when empty so older nodes keep accepting snapshots.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub passthrough_hosts: Vec<crate::host::HostPattern>,
    pub interception_ca: InterceptionCa,
    pub rules: Vec<SnapshotRule>,
    /// When the node cuts a session off on its own; `None` for never.
    /// Format 4: left out for a node that reads older formats.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quarantine: Option<QuarantinePolicy>,
    /// `Vec<SnapshotTripwire>` JSON, sealed to the node, so the decoys are
    /// never readable from a captured snapshot. Format 5: left out for a
    /// node that reads older formats, and when there are none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tripwires: Option<Sealed>,
    /// How fast each session may send requests; `None` for no limit.
    /// Format 6: left out for a node that reads older formats.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimit>,
    /// Whether the node redacts a rule's credential from the responses to
    /// the requests it added it to. On unless an admin turned it off, and
    /// written only then, in format 6: a node that reads older formats is
    /// never told to stop.
    #[serde(default = "redacting", skip_serializing_if = "is_redacting")]
    pub scrub_responses: bool,
}

fn redacting() -> bool {
    true
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde passes a reference
fn is_redacting(on: &bool) -> bool {
    *on
}

/// A decoy the node refuses and cuts the session off for.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotTripwire {
    pub id: TripwireId,
    /// For the audit event; the value never goes in one.
    pub name: String,
    pub value: String,
    /// Hosts the node opens connections to under the deny policy, to look
    /// for the decoy where someone holding it would send it.
    pub hosts: Vec<HostPattern>,
}

impl std::fmt::Debug for SnapshotTripwire {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotTripwire")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("hosts", &self.hosts)
            .finish_non_exhaustive()
    }
}

/// The most tripwires one snapshot carries.
pub const MAX_SNAPSHOT_TRIPWIRES: usize = 500;

/// AAD binding the sealed tripwires to one node.
pub fn tripwires_aad(node_id: &NodeId) -> Vec<u8> {
    format!("tripwires|{node_id}").into_bytes()
}

/// AAD binding a sealed rule credential to one node, rule and credential.
/// The snapshot version is deliberately not part of it, so sealed rules can
/// be reused across lease renewals; the whole snapshot is signed anyway.
pub fn rule_aad(node_id: &NodeId, rule_id: &RuleId, credential_id: &CredentialId) -> Vec<u8> {
    format!("rule|{node_id}|{rule_id}|{credential_id}").into_bytes()
}

/// AAD binding the sealed interception CA key to one node.
pub fn ca_aad(node_id: &NodeId) -> Vec<u8> {
    format!("interception-ca|{node_id}").into_bytes()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedSnapshot {
    /// The exact JSON bytes that were signed.
    pub body: String,
    /// Ed25519 signature, base64.
    pub signature: String,
    pub kid: String,
}

fn signing_input(body: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(SIGNATURE_CONTEXT.len() + body.len());
    input.extend_from_slice(SIGNATURE_CONTEXT);
    input.extend_from_slice(body);
    input
}

impl SignedSnapshot {
    pub fn sign(body: &SnapshotBody, key: &SigningKey) -> Result<Self, CoreError> {
        let json = serde_json::to_string(body).map_err(|e| CoreError::encoding("snapshot", e))?;
        let signature = key.sign(&signing_input(json.as_bytes()));
        Ok(Self {
            body: json,
            signature: STANDARD.encode(signature.to_bytes()),
            kid: key_id(&key.verifying_key()),
        })
    }

    /// Verifies the signature, then parses the body. Version, node and lease
    /// checks are the receiver's job because they depend on its state.
    pub fn verify(&self, key: &VerifyingKey) -> Result<SnapshotBody, CoreError> {
        let sig_bytes = STANDARD
            .decode(&self.signature)
            .map_err(|e| CoreError::encoding("snapshot signature", e))?;
        let signature = Signature::from_slice(&sig_bytes)
            .map_err(|e| CoreError::crypto("snapshot.signature", e.to_string()))?;
        key.verify_strict(&signing_input(self.body.as_bytes()), &signature)
            .map_err(|_| {
                CoreError::crypto(
                    "snapshot.verify",
                    format!("signature does not verify with key '{}'", key_id(key)),
                )
            })?;
        let body: SnapshotBody = serde_json::from_str(&self.body)
            .map_err(|e| CoreError::encoding("snapshot body", e))?;
        if !(MIN_SNAPSHOT_FORMAT..=SNAPSHOT_FORMAT).contains(&body.format) {
            return Err(CoreError::encoding(
                "snapshot body",
                format!(
                    "unsupported format {} (this node reads {MIN_SNAPSHOT_FORMAT}-{SNAPSHOT_FORMAT}); upgrade the node",
                    body.format
                ),
            ));
        }
        if body.quarantine.is_some() && body.format < QUARANTINE_FORMAT {
            return Err(CoreError::encoding(
                "snapshot body",
                format!(
                    "format {} cannot carry a quarantine policy, which needs format {QUARANTINE_FORMAT}",
                    body.format
                ),
            ));
        }
        if body.tripwires.is_some() && body.format < TRIPWIRE_FORMAT {
            return Err(CoreError::encoding(
                "snapshot body",
                format!(
                    "format {} cannot carry tripwires, which need format {TRIPWIRE_FORMAT}",
                    body.format
                ),
            ));
        }
        if body.rate_limit.is_some() && body.format < RATE_LIMIT_FORMAT {
            return Err(CoreError::encoding(
                "snapshot body",
                format!(
                    "format {} cannot carry a rate limit, which needs format {RATE_LIMIT_FORMAT}",
                    body.format
                ),
            ));
        }
        if !body.scrub_responses && body.format < SCRUB_FORMAT {
            return Err(CoreError::encoding(
                "snapshot body",
                format!(
                    "format {} cannot turn response redaction off, which needs format {SCRUB_FORMAT}",
                    body.format
                ),
            ));
        }
        if let Some(rule) = body.rules.iter().find(|r| rule_format(r) > body.format) {
            let what = if rule.allow.git.is_some() {
                "a Git scope"
            } else {
                "a credential deadline"
            };
            return Err(CoreError::encoding(
                "snapshot body",
                format!(
                    "format {} cannot carry {what}, but rule {} has one",
                    body.format, rule.rule_id
                ),
            ));
        }
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    use super::*;
    use crate::seal::seal;

    fn body() -> SnapshotBody {
        let node_key = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        let node_id = NodeId::new();
        SnapshotBody {
            format: SNAPSHOT_FORMAT,
            version: 7,
            node_id,
            issued_at: Utc::now(),
            lease_secs: 60,
            session_keys: vec![],
            revoked_sessions: vec![SessionId::new()],
            limited_sessions: vec![],
            unmatched_host_policy: UnmatchedHostPolicy::Passthrough,
            egress: Default::default(),
            passthrough_hosts: vec![],
            interception_ca: InterceptionCa {
                cert_der: STANDARD.encode(b"cert"),
                key: seal(&node_key, b"key", &ca_aad(&node_id)).unwrap(),
            },
            rules: vec![],
            quarantine: None,
            tripwires: None,
            rate_limit: None,
            scrub_responses: true,
        }
    }

    #[test]
    fn redaction_is_on_unless_a_format_6_snapshot_turns_it_off() {
        let key = SigningKey::generate(&mut OsRng);
        let signed = |b: &SnapshotBody| SignedSnapshot::sign(b, &key).unwrap();
        let mut b = body();
        // On is the default and is not written, so any format carries it.
        assert!(!serde_json::to_string(&b).unwrap().contains("scrub"));
        assert!(
            signed(&b)
                .verify(&key.verifying_key())
                .unwrap()
                .scrub_responses
        );
        b.format = TRIPWIRE_FORMAT;
        b.scrub_responses = false;
        let err = signed(&b).verify(&key.verifying_key()).unwrap_err();
        assert!(
            err.to_string()
                .contains("cannot turn response redaction off"),
            "{err}"
        );
        b.format = SCRUB_FORMAT;
        assert!(
            !signed(&b)
                .verify(&key.verifying_key())
                .unwrap()
                .scrub_responses
        );
    }

    #[test]
    fn a_rate_limit_needs_format_6_and_is_left_out_when_off() {
        let key = SigningKey::generate(&mut OsRng);
        let signed = |b: &SnapshotBody| SignedSnapshot::sign(b, &key).unwrap();
        let mut b = body();
        b.format = TRIPWIRE_FORMAT;
        b.rate_limit = Some(RateLimit::default());
        let err = signed(&b).verify(&key.verifying_key()).unwrap_err();
        assert!(
            err.to_string().contains("cannot carry a rate limit"),
            "{err}"
        );
        b.format = RATE_LIMIT_FORMAT;
        let got = signed(&b).verify(&key.verifying_key()).unwrap();
        assert_eq!(
            got.rate_limit,
            Some(RateLimit {
                per_sec: 20,
                burst: 100
            })
        );
        b.rate_limit = None;
        assert!(!serde_json::to_string(&b).unwrap().contains("rate_limit"));
    }

    #[test]
    fn a_rate_limit_is_loosened_by_more_or_none() {
        let r = |per_sec, burst| Some(RateLimit { per_sec, burst });
        assert!(RateLimit::loosened_by(r(20, 100), None));
        assert!(RateLimit::loosened_by(r(20, 100), r(21, 100)));
        assert!(RateLimit::loosened_by(r(20, 100), r(20, 101)));
        assert!(!RateLimit::loosened_by(r(20, 100), r(10, 50)));
        assert!(!RateLimit::loosened_by(None, r(1, 1)));
    }

    #[test]
    fn a_quarantine_policy_needs_format_4_and_is_left_out_when_off() {
        let key = SigningKey::generate(&mut OsRng);
        let signed = |b: &SnapshotBody| SignedSnapshot::sign(b, &key).unwrap();
        let mut b = body();
        b.format = 3;
        b.quarantine = Some(QuarantinePolicy::default());
        let err = signed(&b).verify(&key.verifying_key()).unwrap_err();
        assert!(
            err.to_string().contains("cannot carry a quarantine policy"),
            "{err}"
        );
        b.format = QUARANTINE_FORMAT;
        let got = signed(&b).verify(&key.verifying_key()).unwrap();
        assert_eq!(
            got.quarantine,
            Some(QuarantinePolicy {
                refusals: 20,
                window_secs: 300
            })
        );
        // Off is not written at all, so older nodes keep reading it.
        b.quarantine = None;
        assert!(!serde_json::to_string(&b).unwrap().contains("quarantine"));
    }

    #[test]
    fn tripwires_need_format_5_and_are_left_out_when_none() {
        let key = SigningKey::generate(&mut OsRng);
        let signed = |b: &SnapshotBody| SignedSnapshot::sign(b, &key).unwrap();
        let mut b = body();
        b.format = QUARANTINE_FORMAT;
        b.tripwires = Some(b.interception_ca.key.clone());
        let err = signed(&b).verify(&key.verifying_key()).unwrap_err();
        assert!(err.to_string().contains("cannot carry tripwires"), "{err}");
        b.format = TRIPWIRE_FORMAT;
        assert!(signed(&b).verify(&key.verifying_key()).is_ok());
        b.tripwires = None;
        assert!(!serde_json::to_string(&b).unwrap().contains("tripwires"));
    }

    #[test]
    fn a_tripwire_s_decoy_is_never_in_debug() {
        let t = SnapshotTripwire {
            id: TripwireId::new(),
            name: "laptop".into(),
            value: "sk-decoy-value-0123456789".into(),
            hosts: vec![],
        };
        let shown = format!("{t:?}");
        assert!(
            shown.contains("laptop") && !shown.contains("sk-decoy"),
            "{shown}"
        );
    }

    #[test]
    fn sign_and_verify() {
        let key = SigningKey::generate(&mut OsRng);
        let b = body();
        let signed = SignedSnapshot::sign(&b, &key).unwrap();
        assert_eq!(signed.verify(&key.verifying_key()).unwrap(), b);
    }

    #[test]
    fn tampering_and_wrong_key_fail() {
        let key = SigningKey::generate(&mut OsRng);
        let mut signed = SignedSnapshot::sign(&body(), &key).unwrap();
        let other = SigningKey::generate(&mut OsRng);
        assert!(signed.verify(&other.verifying_key()).is_err());
        signed.body = signed.body.replace("\"version\":7", "\"version\":8");
        assert!(signed.verify(&key.verifying_key()).is_err());
    }

    #[test]
    fn published_key_round_trips() {
        let key = SigningKey::generate(&mut OsRng).verifying_key();
        let published = PublishedKey::from_key(&key);
        assert_eq!(published.decode().unwrap(), key);
        assert_eq!(published.kid, key_id(&key));
    }

    #[test]
    fn a_credential_deadline_needs_format_2_and_older_formats_still_read() {
        let key = SigningKey::generate(&mut OsRng);
        let signed = |b: &SnapshotBody| SignedSnapshot::sign(b, &key).unwrap();
        let mut b = body();
        let node_key = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        let (rule_id, credential_id) = (RuleId::new(), CredentialId::new());
        b.rules.push(SnapshotRule {
            rule_id,
            scope: Scope::parse("vault:test").unwrap(),
            credential_id,
            allow: RuleScope {
                hosts: vec![crate::host::HostPattern::parse("api.example.com").unwrap()],
                paths: vec![],
                methods: vec![],
                mcp_tools: None,
                git: None,
            },
            strip_headers: vec![],
            headers: seal(
                &node_key,
                b"{}",
                &rule_aad(&b.node_id, &rule_id, &credential_id),
            )
            .unwrap(),
            not_after: None,
        });
        b.format = format_for(&b.rules);
        assert_eq!(b.format, MIN_SNAPSHOT_FORMAT);
        assert!(signed(&b).verify(&key.verifying_key()).is_ok());

        b.rules[0].not_after = Some(Utc::now());
        assert_eq!(format_for(&b.rules), 2);
        // A node that reads only format 1 is sent the rule's absence.
        assert_eq!(rules_readable_by(&b.rules, 1), (vec![], 1));
        assert_eq!(rules_readable_by(&b.rules, 2), (b.rules.clone(), 0));
        // Format 1 cannot say it; a node must not read it as no deadline.
        let err = signed(&b).verify(&key.verifying_key()).unwrap_err();
        assert!(
            err.to_string()
                .contains("cannot carry a credential deadline"),
            "{err}"
        );
        b.format = 2;
        assert!(signed(&b).verify(&key.verifying_key()).is_ok());

        // A Git scope needs format 3; a node reading 2 is not sent it.
        b.rules[0].allow.git =
            Some(crate::git::GitScope::new(vec!["acme/widgets".into()], false).unwrap());
        assert_eq!(format_for(&b.rules), 3);
        assert_eq!(rules_readable_by(&b.rules, 2), (vec![], 1));
        let err = signed(&b).verify(&key.verifying_key()).unwrap_err();
        assert!(
            err.to_string().contains("cannot carry a Git scope"),
            "{err}"
        );
        b.format = 3;
        assert!(signed(&b).verify(&key.verifying_key()).is_ok());

        b.format = SNAPSHOT_FORMAT + 1;
        let err = signed(&b).verify(&key.verifying_key()).unwrap_err();
        assert!(err.to_string().contains("upgrade the node"), "{err}");
    }
}
