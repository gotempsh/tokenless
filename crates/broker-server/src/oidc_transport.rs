// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! HTTPS to identity providers, for single sign-on.
//!
//! It trusts what credential validation trusts (the public web PKI unless
//! turned off, plus the extra CAs given), follows no redirects, gives up
//! after [`TIMEOUT`] and reads at most [`MAX_BODY`] of a reply. Providers
//! are named by an admin and are often on the internal network, so the
//! egress policy for agents' traffic does not apply here.

use std::time::Duration;

use async_trait::async_trait;
use rustls::pki_types::CertificateDer;
use tokenless_control::service::sso::oidc::{HttpReply, OidcTransport, TransportError};
use url::Url;

use crate::error::ServerError;

pub const TIMEOUT: Duration = Duration::from_secs(10);
pub const MAX_BODY: usize = 1024 * 1024;

pub struct HttpOidcTransport {
    http: reqwest::Client,
}

impl HttpOidcTransport {
    pub fn new(
        use_public_roots: bool,
        extra_roots: &[CertificateDer<'static>],
    ) -> Result<Self, ServerError> {
        let tls = tokenless_dataplane::tls::upstream_client_config(use_public_roots, extra_roots)
            .map_err(|e| ServerError::Tls {
            listener: "identity provider client".into(),
            reason: e.to_string(),
        })?;
        let http = reqwest::Client::builder()
            .use_preconfigured_tls((*tls).clone())
            .timeout(TIMEOUT)
            .connect_timeout(TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .user_agent(concat!("tokenless/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| ServerError::Tls {
                listener: "identity provider client".into(),
                reason: e.to_string(),
            })?;
        Ok(Self { http })
    }

    async fn send(&self, request: reqwest::RequestBuilder) -> Result<HttpReply, TransportError> {
        let fail = |reason: String| TransportError { reason };
        let mut response = request
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| fail(describe(&e)))?;
        let status = response.status().as_u16();
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| fail(describe(&e)))? {
            if body.len() + chunk.len() > MAX_BODY {
                return Err(fail(format!("the reply is larger than {MAX_BODY} bytes")));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(HttpReply { status, body })
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
impl OidcTransport for HttpOidcTransport {
    async fn get(&self, url: &Url, bearer: Option<&str>) -> Result<HttpReply, TransportError> {
        let mut request = self.http.get(url.as_str());
        if let Some(token) = bearer {
            request = request.bearer_auth(token);
        }
        self.send(request).await
    }

    async fn post_form(
        &self,
        url: &Url,
        form: &[(&str, &str)],
        basic: Option<(&str, &str)>,
    ) -> Result<HttpReply, TransportError> {
        let mut request = self.http.post(url.as_str()).form(form);
        if let Some((user, password)) = basic {
            request = request.basic_auth(user, Some(password));
        }
        self.send(request).await
    }
}
