// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Egress address policy: which resolved IP addresses the broker may open
//! connections to on behalf of someone else (passthrough tunnels chosen by
//! an agent, and validation requests made by the control plane).
//!
//! By default every non-public address is refused (loopback, RFC 1918,
//! link-local and cloud metadata, CGNAT, unique-local, multicast and other
//! special-purpose ranges). Operators can allow specific ranges.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::CoreError;

pub const MAX_ALLOWED_CIDRS: usize = 64;

/// An IP network in CIDR notation. A bare address means a single host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct IpCidr {
    network: IpAddr,
    prefix: u8,
}

fn invalid(input: &str, reason: impl Into<String>) -> CoreError {
    CoreError::InvalidHost {
        input: input.to_string(),
        reason: reason.into(),
    }
}

fn mask_v4(addr: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let bits = u32::from(addr);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    Ipv4Addr::from(bits & mask)
}

fn mask_v6(addr: Ipv6Addr, prefix: u8) -> Ipv6Addr {
    let bits = u128::from(addr);
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    };
    Ipv6Addr::from(bits & mask)
}

impl IpCidr {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, canonical(ip)) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => mask_v4(ip, self.prefix) == net,
            (IpAddr::V6(net), IpAddr::V6(ip)) => mask_v6(ip, self.prefix) == net,
            _ => false,
        }
    }
}

impl FromStr for IpCidr {
    type Err = CoreError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let trimmed = input.trim();
        let (addr, prefix) = match trimmed.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (trimmed, None),
        };
        let addr: IpAddr = addr
            .parse()
            .map_err(|_| invalid(input, "expected an IP address or CIDR such as 10.0.0.0/8"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= max)
                .ok_or_else(|| invalid(input, format!("prefix must be 0-{max}")))?,
            None => max,
        };
        let network = match addr {
            IpAddr::V4(a) => IpAddr::V4(mask_v4(a, prefix)),
            IpAddr::V6(a) => IpAddr::V6(mask_v6(a, prefix)),
        };
        if network != addr {
            return Err(invalid(
                input,
                format!("host bits are set; did you mean {network}/{prefix}?"),
            ));
        }
        Ok(Self { network, prefix })
    }
}

impl TryFrom<String> for IpCidr {
    type Error = CoreError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<IpCidr> for String {
    fn from(value: IpCidr) -> Self {
        value.to_string()
    }
}

impl fmt::Display for IpCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

/// Unwraps IPv4 addresses embedded in IPv6 (mapped, NAT64, 6to4) so they
/// cannot be used to smuggle a private IPv4 destination past the check.
fn canonical(ip: IpAddr) -> IpAddr {
    let IpAddr::V6(v6) = ip else {
        return ip;
    };
    if let Some(v4) = v6.to_ipv4_mapped() {
        return IpAddr::V4(v4);
    }
    let seg = v6.segments();
    let embedded =
        |hi: u16, lo: u16| IpAddr::V4(Ipv4Addr::from((u32::from(hi) << 16) | u32::from(lo)));
    // 64:ff9b::/96 (NAT64)
    if seg[0] == 0x64 && seg[1] == 0xff9b && seg[2..6].iter().all(|s| *s == 0) {
        return embedded(seg[6], seg[7]);
    }
    // 2002::/16 (6to4)
    if seg[0] == 0x2002 {
        return embedded(seg[1], seg[2]);
    }
    ip
}

/// Why an address is not a public unicast destination, if it is not.
pub fn non_public_reason(ip: IpAddr) -> Option<&'static str> {
    match canonical(ip) {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            match o {
                [0, ..] => Some("unspecified (0.0.0.0/8)"),
                [127, ..] => Some("loopback"),
                [10, ..] => Some("private (10.0.0.0/8)"),
                [172, b, ..] if (16..=31).contains(&b) => Some("private (172.16.0.0/12)"),
                [192, 168, ..] => Some("private (192.168.0.0/16)"),
                [169, 254, ..] => Some("link-local / cloud metadata (169.254.0.0/16)"),
                [100, b, ..] if (64..=127).contains(&b) => {
                    Some("carrier-grade NAT (100.64.0.0/10)")
                }
                [192, 0, 0, _] => Some("IETF protocol assignments (192.0.0.0/24)"),
                [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _] => {
                    Some("documentation range")
                }
                [198, b, ..] if b == 18 || b == 19 => Some("benchmarking (198.18.0.0/15)"),
                [a, ..] if (224..=239).contains(&a) => Some("multicast"),
                [a, ..] if a >= 240 => Some("reserved or broadcast (240.0.0.0/4)"),
                _ => None,
            }
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            if v6.is_unspecified() {
                Some("unspecified (::)")
            } else if v6.is_loopback() {
                Some("loopback")
            } else if seg[0] & 0xfe00 == 0xfc00 {
                Some("unique local (fc00::/7)")
            } else if seg[0] & 0xffc0 == 0xfe80 {
                Some("link-local (fe80::/10)")
            } else if seg[0] & 0xff00 == 0xff00 {
                Some("multicast")
            } else if seg[0] == 0x2001 && seg[1] == 0x0db8 {
                Some("documentation range (2001:db8::/32)")
            } else {
                None
            }
        }
    }
}

/// Where the broker may connect on someone else's behalf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressPolicy {
    /// Refuse non-public destinations unless they are in `allow`.
    #[serde(default = "default_true")]
    pub block_private: bool,
    /// Ranges that are reachable even though they are not public.
    #[serde(default)]
    pub allow: Vec<IpCidr>,
}

fn default_true() -> bool {
    true
}

impl Default for EgressPolicy {
    fn default() -> Self {
        Self {
            block_private: true,
            allow: Vec::new(),
        }
    }
}

impl EgressPolicy {
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.allow.len() > MAX_ALLOWED_CIDRS {
            return Err(invalid(
                &format!("({} ranges)", self.allow.len()),
                format!("at most {MAX_ALLOWED_CIDRS} allowed ranges"),
            ));
        }
        Ok(())
    }

    /// True when `self` permits something `previous` did not.
    pub fn widens(&self, previous: &EgressPolicy) -> bool {
        (previous.block_private && !self.block_private)
            || self.allow.iter().any(|c| !previous.allow.contains(c))
    }

    /// `Err(reason)` when connecting to `ip` is not permitted.
    pub fn check(&self, ip: IpAddr) -> Result<(), &'static str> {
        if !self.block_private {
            return Ok(());
        }
        match non_public_reason(ip) {
            None => Ok(()),
            Some(_) if self.allow.iter().any(|c| c.contains(ip)) => Ok(()),
            Some(reason) => Err(reason),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn classifies_special_purpose_ranges() {
        for blocked in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fd00::1",
            "fe80::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::a9fe:a9fe",
            "2002:0a00:0001::1",
        ] {
            assert!(
                non_public_reason(ip(blocked)).is_some(),
                "{blocked} should be non-public"
            );
        }
        for public in [
            "1.1.1.1",
            "172.32.0.1",
            "100.128.0.1",
            "2606:4700::1111",
            "::ffff:8.8.8.8",
        ] {
            assert_eq!(
                non_public_reason(ip(public)),
                None,
                "{public} should be public"
            );
        }
    }

    #[test]
    fn default_policy_blocks_private_and_allows_public() {
        let p = EgressPolicy::default();
        assert!(p.check(ip("10.0.0.5")).is_err());
        assert!(p.check(ip("::ffff:192.168.0.1")).is_err());
        assert!(p.check(ip("93.184.216.34")).is_ok());
    }

    #[test]
    fn allow_list_opens_specific_ranges_only() {
        let p = EgressPolicy {
            block_private: true,
            allow: vec!["10.20.0.0/16".parse().unwrap(), "fd12::1".parse().unwrap()],
        };
        assert!(p.check(ip("10.20.3.4")).is_ok());
        assert!(p.check(ip("::ffff:10.20.3.4")).is_ok());
        assert!(p.check(ip("10.21.0.1")).is_err());
        assert!(p.check(ip("fd12::1")).is_ok());
        assert!(p.check(ip("fd12::2")).is_err());
        assert!(p.check(ip("127.0.0.1")).is_err());
    }

    #[test]
    fn widening_is_detected() {
        let base = EgressPolicy::default();
        let more = EgressPolicy {
            block_private: true,
            allow: vec!["10.0.0.0/8".parse().unwrap()],
        };
        assert!(more.widens(&base));
        assert!(!base.widens(&more));
        let off = EgressPolicy {
            block_private: false,
            allow: vec![],
        };
        assert!(off.widens(&base));
        assert!(!base.widens(&base));
    }

    #[test]
    fn disabled_policy_allows_everything() {
        let p = EgressPolicy {
            block_private: false,
            allow: vec![],
        };
        assert!(p.check(ip("127.0.0.1")).is_ok());
    }

    #[test]
    fn cidr_parsing_and_serde() {
        assert_eq!(
            "10.0.0.0/8".parse::<IpCidr>().unwrap().to_string(),
            "10.0.0.0/8"
        );
        assert_eq!(
            "192.168.1.7".parse::<IpCidr>().unwrap().to_string(),
            "192.168.1.7/32"
        );
        assert_eq!(
            "fd00::/8".parse::<IpCidr>().unwrap().to_string(),
            "fd00::/8"
        );
        assert!("10.0.0.1/8".parse::<IpCidr>().is_err(), "host bits set");
        assert!("10.0.0.0/33".parse::<IpCidr>().is_err());
        assert!("example.com".parse::<IpCidr>().is_err());
        let p: EgressPolicy = serde_json::from_str(r#"{"allow":["127.0.0.0/8"]}"#).unwrap();
        assert!(p.block_private);
        assert!(p.check(ip("127.0.0.1")).is_ok());
        assert!(serde_json::from_str::<EgressPolicy>(r#"{"allow":["nope"]}"#).is_err());
    }
}
