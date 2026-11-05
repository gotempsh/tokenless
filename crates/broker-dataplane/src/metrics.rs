// SPDX-FileCopyrightText: 2026 credential-broker contributors
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
            pub fn render(&self) -> String {
                let mut out = String::new();
                $(
                    let _ = writeln!(out, "# HELP broker_dataplane_{} {}", stringify!($name), $help);
                    let _ = writeln!(out, "# TYPE broker_dataplane_{} counter", stringify!($name));
                    let _ = writeln!(out, "broker_dataplane_{} {}", stringify!($name), self.$name.load(Ordering::Relaxed));
                )*
                out
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
    connect_denied_total: "CONNECTs denied by policy",
    requests_injected_total: "Requests forwarded with an injected credential",
    requests_denied_total: "Intercepted requests refused by policy",
    lease_refusals_total: "Requests refused because the snapshot lease had expired",
    audit_dropped_total: "Audit events that could not be queued; the injection was refused",
    audit_shipped_total: "Audit events delivered to the control plane",
    audit_ship_failures_total: "Failed attempts to deliver an audit batch",
    snapshots_applied_total: "Policy snapshots verified and applied",
    snapshots_rejected_total: "Policy snapshots rejected",
    upstream_errors_total: "Upstream connection or request failures",
}

impl Metrics {
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
}
