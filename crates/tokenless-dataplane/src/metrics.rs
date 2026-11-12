// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Lock-free counters for the hot path, rendered in Prometheus text format.

use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};

macro_rules! metrics {
    ($($name:ident: $help:literal),* $(,)?) => {
        #[derive(Debug, Default)]
        pub struct Metrics {
            $(pub $name: AtomicU64,)*
        }

        impl Metrics {
            /// Every counter, in a fixed order, for exporters other than
            /// [`Metrics::render`].
            pub fn counters(&self) -> Vec<Counter<'_>> {
                vec![$(Counter { name: stringify!($name), help: $help, value: &self.$name },)*]
            }
        }
    };
}

metrics! {
    connections_total: "Client connections accepted",
    connections_rejected: "Connections dropped because the connection limit was reached",
    proxy_auth_failures_total: "CONNECTs refused with 407 (missing, invalid, expired or revoked session)",
    tunnels_passthrough_total: "CONNECTs tunnelled without interception",
    tunnels_intercepted_total: "CONNECTs intercepted for credential injection",
    tunnels_cut_total: "Open tunnels and streaming responses cut because their session was revoked or expired, or the lease ran out",
    connect_denied_total: "CONNECTs denied by policy",
    egress_blocked_total: "Passthrough CONNECTs refused because the destination is not a permitted address",
    requests_injected_total: "Requests forwarded with an injected credential",
    requests_denied_total: "Intercepted requests refused by policy",
    sessions_quarantined_total: "Sessions cut off for being refused too often",
    requests_rate_limited_total: "Intercepted requests refused with 429 because their session went past the rate limit",
    responses_scrubbed_total: "Intercepted responses in which an injected credential was redacted",
    tripwires_tripped_total: "Requests refused for carrying a tripwire's decoy; their session was cut off",
    lease_refusals_total: "Requests refused because the snapshot lease had expired",
    audit_dropped_total: "Audit events that could not be queued; the injection was refused",
    audit_shipped_total: "Audit events delivered to the control plane",
    audit_ship_failures_total: "Failed attempts to deliver an audit batch",
    snapshots_applied_total: "Policy snapshots verified and applied",
    snapshots_rejected_total: "Policy snapshots rejected",
    upstream_errors_total: "Upstream connection or request failures",
    credentials_redacted_total: "Occurrences of an injected credential redacted from an intercepted response",
    responses_withheld_total: "Intercepted responses withheld because they could not be scanned for the injected credential",
    gateway_requests_total: "Requests received by the MCP gateway",
    gateway_auth_failures_total: "MCP gateway requests refused with 401 (missing, invalid, expired or revoked session)",
}

/// One counter: its name (without the `broker_dataplane_` prefix the
/// Prometheus endpoint adds), what it counts, and its live value.
pub struct Counter<'a> {
    pub name: &'static str,
    pub help: &'static str,
    pub value: &'a AtomicU64,
}

impl Counter<'_> {
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

impl Metrics {
    pub fn render(&self) -> String {
        let mut out = String::new();
        for c in self.counters() {
            let _ = writeln!(out, "# HELP broker_dataplane_{} {}", c.name, c.help);
            let _ = writeln!(out, "# TYPE broker_dataplane_{} counter", c.name);
            let _ = writeln!(out, "broker_dataplane_{} {}", c.name, c.get());
        }
        out
    }

    pub fn inc(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add(counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_prometheus_text() {
        let m = Metrics::default();
        Metrics::inc(&m.audit_dropped_total);
        let text = m.render();
        assert!(text.contains("broker_dataplane_audit_dropped_total 1"));
        assert!(text.contains("# TYPE broker_dataplane_requests_injected_total counter"));
    }

    #[test]
    fn counters_list_every_counter_with_its_live_value() {
        let m = Metrics::default();
        Metrics::add(&m.requests_injected_total, 3);
        let counters = m.counters();
        assert_eq!(counters.len(), m.render().matches("# TYPE").count());
        let injected = counters
            .iter()
            .find(|c| c.name == "requests_injected_total")
            .unwrap();
        assert_eq!(injected.get(), 3);
        Metrics::inc(&m.requests_injected_total);
        assert_eq!(injected.get(), 4, "a counter reads the live value");
    }
}
