// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Resolving a destination under the egress policy. The proxy uses it for
//! passthrough tunnels, and the control plane's credential tests use the
//! same function, so both refuse exactly the same addresses.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokenless_core::egress::EgressPolicy;
use tokio::time::timeout;

/// Why a destination may not be reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Every address it resolves to is blocked; this is the first.
    Blocked { ip: IpAddr, reason: &'static str },
    /// It did not resolve (in time, or at all).
    Unresolvable { reason: String },
}

/// The addresses of `host` that `egress` allows, resolved within `limit`.
/// Addresses it blocks are dropped; when none is left, the first blocked
/// one is the refusal. Connect only to what this returns, so a second DNS
/// answer cannot redirect the connection.
pub async fn resolve_permitted(
    host: &str,
    port: u16,
    egress: &EgressPolicy,
    limit: Duration,
) -> Result<Vec<SocketAddr>, Refusal> {
    let resolved: Vec<SocketAddr> = timeout(limit, tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| Refusal::Unresolvable {
            reason: "DNS lookup timed out".into(),
        })?
        .map_err(|e| Refusal::Unresolvable {
            reason: e.to_string(),
        })?
        .collect();
    let mut first_block = None;
    let allowed: Vec<_> = resolved
        .iter()
        .copied()
        .filter(|addr| match egress.check(addr.ip()) {
            Ok(()) => true,
            Err(reason) => {
                first_block.get_or_insert((addr.ip(), reason));
                false
            }
        })
        .collect();
    if !allowed.is_empty() {
        return Ok(allowed);
    }
    Err(match first_block {
        Some((ip, reason)) => Refusal::Blocked { ip, reason },
        None => Refusal::Unresolvable {
            reason: "no addresses".into(),
        },
    })
}
