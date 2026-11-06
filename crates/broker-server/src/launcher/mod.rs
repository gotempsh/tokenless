// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The agent side of the broker: mint a proxy session from an access
//! bundle, open a local session port that adds the session to every
//! request, and run an agent behind it.
//!
//! The session port listens on loopback only. It rewrites the head of each
//! proxy request to carry the current session token and then relays bytes
//! to the data plane proxy, so the agent is configured with a plain
//! `HTTPS_PROXY=http://127.0.0.1:<port>` and never sees a token. Because
//! sessions are capped (an hour unless an admin changes it), the port renews its session before it
//! expires, and every session it minted is ended when it stops.

pub mod account;
pub mod client;
pub mod inject;
pub mod mcp;
pub mod port;
pub mod session;
pub mod skill;
pub mod trust;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum LauncherError {
    #[error("{message}")]
    Config { message: String },

    #[error("request to {url} while {operation} failed: {reason}")]
    Http {
        operation: &'static str,
        url: String,
        reason: String,
    },

    #[error("the broker refused {operation} ({status} {title}): {detail}")]
    Api {
        operation: &'static str,
        status: u16,
        title: String,
        detail: String,
    },

    #[error("the interception CA from {url} has fingerprint {actual}, not the pinned {expected}; refusing to start")]
    CaMismatch {
        url: String,
        expected: String,
        actual: String,
    },

    #[error("not signed in to {server}, or the session has ended; run: tokenless login --server {server}")]
    NotSignedIn { server: String },

    #[error("{operation} the session for {server} in the OS keychain failed: {reason}")]
    Keychain {
        operation: &'static str,
        server: String,
        reason: String,
    },

    #[error("I/O failure while {context}: {source}")]
    Io {
        context: String,
        source: std::io::Error,
    },
}

impl LauncherError {
    pub fn config(message: impl Into<String>) -> Self {
        LauncherError::Config {
            message: message.into(),
        }
    }

    pub fn io(context: impl Into<String>) -> impl FnOnce(std::io::Error) -> Self {
        let context = context.into();
        move |source| LauncherError::Io { context, source }
    }
}

/// Parses `90`, `90s`, `15m` or `1h` into seconds.
pub fn parse_duration_secs(raw: &str) -> Result<u64, LauncherError> {
    let raw = raw.trim();
    let (digits, unit) = match raw.find(|c: char| !c.is_ascii_digit()) {
        Some(i) => raw.split_at(i),
        None => (raw, "s"),
    };
    let value: u64 = digits.parse().map_err(|_| {
        LauncherError::config(format!("'{raw}' is not a duration like 90s, 15m or 1h"))
    })?;
    let factor = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        _ => {
            return Err(LauncherError::config(format!(
                "'{raw}' has unknown unit '{unit}'; use s, m or h"
            )))
        }
    };
    value
        .checked_mul(factor)
        .filter(|secs| *secs > 0)
        .ok_or_else(|| LauncherError::config(format!("'{raw}' must be a positive duration")))
}

/// Parses `key=value` labels.
pub fn parse_label(raw: &str) -> Result<(String, String), LauncherError> {
    raw.split_once('=')
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .filter(|(k, _)| !k.is_empty())
        .ok_or_else(|| LauncherError::config(format!("label '{raw}' must look like key=value")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration_secs("90").unwrap(), 90);
        assert_eq!(parse_duration_secs("90s").unwrap(), 90);
        assert_eq!(parse_duration_secs("15m").unwrap(), 900);
        assert_eq!(parse_duration_secs(" 1h ").unwrap(), 3600);
        for bad in ["", "0", "1d", "m", "-5m", "99999999999999999999h"] {
            assert!(parse_duration_secs(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn labels() {
        assert_eq!(
            parse_label("agent = reviewer").unwrap(),
            ("agent".into(), "reviewer".into())
        );
        assert_eq!(parse_label("k=").unwrap(), ("k".into(), String::new()));
        assert!(parse_label("novalue").is_err());
        assert!(parse_label("=v").is_err());
    }
}
