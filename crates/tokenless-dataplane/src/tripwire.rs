// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tripwires on the node: a request that carries a decoy planted on an
//! agent's machine is refused, its session cut off at once, and the
//! control plane told, which revokes it everywhere and raises an alert.
//!
//! The decoys are matched together in one pass over a request's headers
//! and URL (one Aho-Corasick automaton per snapshot), so the cost on the
//! request path does not grow with the number of tripwires.

use aho_corasick::AhoCorasick;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http::{HeaderMap, Uri};
use tokenless_core::audit::AuditOutcome;
use tokenless_core::host::HostPattern;
use tokenless_core::ids::TripwireId;
use tokenless_core::session::SessionClaims;
use tokenless_core::snapshot::{SnapshotTripwire, TRIPWIRE_ACTION};
use tracing::warn;

use crate::error::DataPlaneError;
use crate::metrics::Metrics;
use crate::proxy::ProxyShared;

/// The tripwires a snapshot carries, ready to match.
pub struct Tripwires {
    matcher: AhoCorasick,
    /// By pattern index: who each decoy is.
    names: Vec<(TripwireId, String)>,
    hosts: Vec<HostPattern>,
}

/// Where a decoy was found, for the audit event. Never the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub id: TripwireId,
    pub name: String,
    pub found_in: String,
}

impl Tripwires {
    pub fn build(list: Vec<SnapshotTripwire>) -> Result<Option<Self>, DataPlaneError> {
        if list.is_empty() {
            return Ok(None);
        }
        let matcher = AhoCorasick::new(list.iter().map(|t| t.value.as_bytes()))
            .map_err(|e| DataPlaneError::rejected(format!("tripwires cannot be matched: {e}")))?;
        let mut hosts: Vec<HostPattern> = list.iter().flat_map(|t| t.hosts.clone()).collect();
        hosts.sort();
        hosts.dedup();
        Ok(Some(Self {
            matcher,
            names: list.into_iter().map(|t| (t.id, t.name)).collect(),
            hosts,
        }))
    }

    /// Hosts someone holding a decoy would send it to.
    pub fn hosts(&self) -> &[HostPattern] {
        &self.hosts
    }

    pub fn covers_host(&self, host: &str, port: u16) -> bool {
        self.hosts.iter().any(|h| h.matches(host, port))
    }

    fn hit(&self, haystack: &[u8], found_in: impl FnOnce() -> String) -> Option<Hit> {
        let m = self.matcher.find(haystack)?;
        let (id, name) = self.names.get(m.pattern().as_usize())?;
        Some(Hit {
            id: *id,
            name: name.clone(),
            found_in: found_in(),
        })
    }

    /// `text` with every decoy in it replaced by `***`.
    pub fn redact(&self, text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        self.matcher.replace_all_with(text, &mut out, |_, _, dst| {
            dst.push_str("***");
            true
        });
        out
    }

    /// The first decoy in the request's URL or headers, including inside
    /// Basic credentials, where Git and other clients put a token.
    pub fn find(&self, headers: &HeaderMap, uri: &Uri) -> Option<Hit> {
        if let Some(pq) = uri.path_and_query() {
            if let Some(hit) = self.hit(pq.as_str().as_bytes(), || "url".into()) {
                return Some(hit);
            }
        }
        for (name, value) in headers {
            let bytes = value.as_bytes();
            if let Some(hit) = self.hit(bytes, || format!("header {name}")) {
                return Some(hit);
            }
            let basic = bytes
                .get(..6)
                .is_some_and(|p| p.eq_ignore_ascii_case(b"basic "));
            if basic {
                let decoded = STANDARD.decode(bytes[6..].trim_ascii()).unwrap_or_default();
                if let Some(hit) = self.hit(&decoded, || format!("header {name} (basic)")) {
                    return Some(hit);
                }
            }
        }
        None
    }
}

/// Cuts the session off and reports the hit. The caller refuses the request.
pub(crate) fn trip(
    shared: &ProxyShared,
    claims: &SessionClaims,
    tripwires: &Tripwires,
    hit: &Hit,
    host: &str,
    port: u16,
    request: (&str, &str),
) {
    Metrics::inc(&shared.metrics.tripwires_tripped_total);
    crate::quarantine::cut_off(shared, claims);
    warn!(
        session_id = %claims.jti,
        tripwire_id = %hit.id,
        host,
        found_in = %hit.found_in,
        "a request carried a tripwire's decoy; session cut off"
    );
    let event = crate::proxy::session_event(shared, claims, TRIPWIRE_ACTION, AuditOutcome::Denied)
        .detail("host", format!("{host}:{port}"))
        .detail("method", request.0.to_string())
        .detail(
            "path",
            // Redacted before it is cut, so no part of a decoy is left.
            tripwires
                .redact(request.1)
                .chars()
                .take(512)
                .collect::<String>(),
        )
        .detail("tripwire_id", hit.id.to_string())
        .detail("tripwire", hit.name.clone())
        .detail("found_in", hit.found_in.clone());
    // Best effort, as for any refusal: the session is already cut off here.
    let _ = shared.audit.try_record(event);
}

#[cfg(test)]
mod tests;
