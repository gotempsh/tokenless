// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Outbound validation requests ("does this credential work?").
//!
//! The control plane decides *what* to send (the template's declared
//! validation request, to one of the credential's own hosts, with its
//! injected headers). A [`CredentialProber`] decides *how*, and must refuse
//! destinations that the [`EgressPolicy`] forbids. The response body is
//! never returned, only the status code.

use async_trait::async_trait;
use broker_core::egress::EgressPolicy;
use broker_core::injection::InjectedHeaders;
use thiserror::Error;

pub struct ProbeRequest {
    pub host: String,
    pub port: u16,
    pub method: String,
    pub path: String,
    pub headers: InjectedHeaders,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProbeError {
    #[error(
        "{host} resolves to {ip}, which is {reason}; allow the range in Settings to validate it"
    )]
    Blocked {
        host: String,
        ip: String,
        reason: String,
    },
    #[error("could not resolve {host}: {reason}")]
    Resolve { host: String, reason: String },
    #[error("validation request to {host} failed: {reason}")]
    Request { host: String, reason: String },
    #[error("outbound validation requests are not available in this deployment")]
    Unavailable,
}

#[async_trait]
pub trait CredentialProber: Send + Sync {
    /// Sends the request and returns the response status code.
    async fn probe(&self, request: ProbeRequest, egress: &EgressPolicy) -> Result<u16, ProbeError>;
}

/// A prober for deployments (and tests) that make no outbound calls.
#[derive(Debug, Default, Clone, Copy)]
pub struct DisabledProber;

#[async_trait]
impl CredentialProber for DisabledProber {
    async fn probe(&self, _: ProbeRequest, _: &EgressPolicy) -> Result<u16, ProbeError> {
        Err(ProbeError::Unavailable)
    }
}
