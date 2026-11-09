// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! HTTPS to the webhook receivers audit events are sent to.
//!
//! It trusts what credential validation trusts (the public web PKI unless
//! turned off, plus the extra CAs given), follows no redirects, gives up
//! after [`TIMEOUT`], and reads at most [`MAX_REPLY`] of a reply before
//! dropping the connection: only the status matters. Receivers are named by
//! an admin and are often on the internal network (a SIEM), so the egress
//! policy for agents' traffic does not apply here.

use std::time::Duration;

use async_trait::async_trait;
use rustls::pki_types::CertificateDer;
use tokenless_control::service::audit_export::{WebhookError, WebhookRequest, WebhookTransport};

use crate::error::ServerError;

pub const TIMEOUT: Duration = Duration::from_secs(10);
pub const MAX_REPLY: usize = 64 * 1024;

pub struct HttpWebhookTransport {
    http: reqwest::Client,
}

impl HttpWebhookTransport {
    pub fn new(
        use_public_roots: bool,
        extra_roots: &[CertificateDer<'static>],
    ) -> Result<Self, ServerError> {
        let fail = |reason: String| ServerError::Tls {
            listener: "audit webhook client".into(),
            reason,
        };
        let tls = tokenless_dataplane::tls::upstream_client_config(use_public_roots, extra_roots)
            .map_err(|e| fail(e.to_string()))?;
        let http = reqwest::Client::builder()
            .use_preconfigured_tls((*tls).clone())
            .timeout(TIMEOUT)
            .connect_timeout(TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .user_agent(concat!("tokenless/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| fail(e.to_string()))?;
        Ok(Self { http })
    }
}

fn describe(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        format!("no answer within {}s", TIMEOUT.as_secs())
    } else if e.is_connect() {
        format!("could not connect: {e}")
    } else {
        e.to_string()
    }
}

#[async_trait]
impl WebhookTransport for HttpWebhookTransport {
    async fn post(&self, request: WebhookRequest) -> Result<u16, WebhookError> {
        let fail = |reason: String| WebhookError { reason };
        let mut builder = self.http.post(&request.url).body(request.body);
        for (name, value) in &request.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let mut response = builder.send().await.map_err(|e| fail(describe(&e)))?;
        let status = response.status().as_u16();
        // Read a little of the reply so a keep-alive connection can be
        // reused, then stop: a receiver cannot make us buffer more.
        let mut read = 0usize;
        while read < MAX_REPLY {
            match response.chunk().await {
                Ok(Some(chunk)) => read += chunk.len(),
                Ok(None) | Err(_) => break,
            }
        }
        Ok(status)
    }
}
