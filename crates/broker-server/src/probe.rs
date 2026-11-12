// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! HTTPS prober for credential validation requests.
//!
//! The destination is resolved here and every address is checked against
//! the egress policy; the connection then goes to a checked address, so a
//! second DNS answer cannot redirect it. Redirects are not followed and the
//! response body is discarded unread.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use http::header::{HeaderName, HeaderValue, HOST, USER_AGENT};
use http::Request;
use http_body_util::Empty;
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::ClientConfig;
use tokenless_control::probe::{CredentialProber, ProbeError, ProbeRequest};
use tokenless_core::egress::EgressPolicy;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::debug;

use crate::error::ServerError;

const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

pub struct HttpProber {
    tls: Arc<ClientConfig>,
}

impl HttpProber {
    pub fn new(
        use_public_roots: bool,
        extra_roots: &[CertificateDer<'static>],
    ) -> Result<Self, ServerError> {
        let tls = tokenless_dataplane::tls::upstream_client_config(use_public_roots, extra_roots)
            .map_err(|e| ServerError::Tls {
            listener: "validation prober".into(),
            reason: e.to_string(),
        })?;
        Ok(Self { tls })
    }

    async fn resolve(
        &self,
        host: &str,
        port: u16,
        egress: &EgressPolicy,
    ) -> Result<Vec<SocketAddr>, ProbeError> {
        let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
            .await
            .map_err(|e| ProbeError::Resolve {
                host: host.to_string(),
                reason: e.to_string(),
            })?
            .collect();
        let mut blocked = None;
        let allowed: Vec<SocketAddr> = resolved
            .iter()
            .copied()
            .filter(|a| match egress.check(a.ip()) {
                Ok(()) => true,
                Err(reason) => {
                    blocked.get_or_insert((a.ip(), reason));
                    false
                }
            })
            .collect();
        if !allowed.is_empty() {
            return Ok(allowed);
        }
        Err(match blocked {
            Some((ip, reason)) => ProbeError::Blocked {
                host: host.to_string(),
                ip: ip.to_string(),
                reason: reason.to_string(),
            },
            None => ProbeError::Resolve {
                host: host.to_string(),
                reason: "no addresses".into(),
            },
        })
    }

    async fn run(&self, req: ProbeRequest, egress: &EgressPolicy) -> Result<u16, ProbeError> {
        let fail = |reason: String| ProbeError::Request {
            host: req.host.clone(),
            reason,
        };
        let addrs = self.resolve(&req.host, req.port, egress).await?;
        let tcp = TcpStream::connect(&addrs[..])
            .await
            .map_err(|e| fail(format!("connect failed: {e}")))?;
        let server_name = ServerName::try_from(req.host.clone())
            .map_err(|_| fail("host is not a valid TLS server name".into()))?;
        let tls = TlsConnector::from(self.tls.clone())
            .connect(server_name, tcp)
            .await
            .map_err(|e| fail(format!("TLS handshake failed: {e}")))?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|e| fail(format!("HTTP handshake failed: {e}")))?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!(error = %e, "validation connection closed");
            }
        });
        let authority = if req.port == 443 {
            req.host.clone()
        } else {
            format!("{}:{}", req.host, req.port)
        };
        let mut builder = Request::builder()
            .method(req.method.as_str())
            .uri(req.path.as_str())
            .header(HOST, authority)
            .header(USER_AGENT, "tokenless-validation/1");
        for h in &req.headers.headers {
            let name = HeaderName::from_bytes(h.name.as_bytes())
                .map_err(|e| fail(format!("invalid injected header name: {e}")))?;
            let mut value = HeaderValue::from_str(&h.value)
                .map_err(|_| fail(format!("invalid value for injected header '{name}'")))?;
            value.set_sensitive(true);
            builder = builder.header(name, value);
        }
        let request = builder
            .body(Empty::<Bytes>::new())
            .map_err(|e| fail(format!("building request: {e}")))?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|e| fail(format!("request failed: {e}")))?;
        Ok(response.status().as_u16())
    }
}

#[async_trait]
impl CredentialProber for HttpProber {
    async fn probe(&self, request: ProbeRequest, egress: &EgressPolicy) -> Result<u16, ProbeError> {
        let host = request.host.clone();
        tokio::time::timeout(PROBE_TIMEOUT, self.run(request, egress))
            .await
            .map_err(|_| ProbeError::Request {
                host,
                reason: format!("timed out after {}s", PROBE_TIMEOUT.as_secs()),
            })?
    }
}

#[cfg(test)]
mod tests {
    use tokenless_core::injection::InjectedHeaders;

    use super::*;

    fn request(host: &str) -> ProbeRequest {
        ProbeRequest {
            host: host.into(),
            port: 443,
            method: "GET".into(),
            path: "/".into(),
            headers: InjectedHeaders {
                headers: vec![],
                substitutions: vec![],
                secrets: vec![],
            },
        }
    }

    #[tokio::test]
    async fn private_destinations_are_refused_before_connecting() {
        let prober = HttpProber::new(false, &[]).unwrap();
        for host in ["localhost", "127.0.0.1"] {
            let err = prober
                .probe(request(host), &EgressPolicy::default())
                .await
                .unwrap_err();
            assert!(matches!(err, ProbeError::Blocked { .. }), "{host}: {err}");
        }
    }
}
