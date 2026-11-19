// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! HTTPS prober for credential tests.
//!
//! The destination is resolved with the proxy's own egress resolution
//! ([`tokenless_dataplane::egress::resolve_permitted`]), so a test refuses
//! exactly the addresses a passthrough tunnel would; the connection then
//! goes to a checked address, so a second DNS answer cannot redirect it.
//! Redirects are not followed and the response body is never read: only
//! the status line matters. The whole exchange has one deadline.

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
use tokenless_control::probe::{CredentialProber, ProbeError, ProbeRequest, PROBE_TIMEOUT};
use tokenless_core::egress::EgressPolicy;
use tokenless_dataplane::egress::{resolve_permitted, Refusal};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::debug;

use crate::error::ServerError;

pub struct HttpProber {
    tls: Arc<ClientConfig>,
    timeout: Duration,
}

impl HttpProber {
    pub fn new(
        use_public_roots: bool,
        extra_roots: &[CertificateDer<'static>],
    ) -> Result<Self, ServerError> {
        let tls = tokenless_dataplane::tls::upstream_client_config(use_public_roots, extra_roots)
            .map_err(|e| ServerError::Tls {
            listener: "credential test prober".into(),
            reason: e.to_string(),
        })?;
        Ok(Self {
            tls,
            timeout: PROBE_TIMEOUT,
        })
    }

    /// The same prober with a shorter deadline, never a longer one.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout.min(PROBE_TIMEOUT);
        self
    }

    async fn run(&self, req: ProbeRequest, egress: &EgressPolicy) -> Result<u16, ProbeError> {
        let fail = |reason: String| ProbeError::Request {
            host: req.host.clone(),
            reason,
        };
        let addrs = resolve_permitted(&req.host, req.port, egress, self.timeout)
            .await
            .map_err(|refusal| match refusal {
                Refusal::Blocked { ip, reason } => ProbeError::Blocked {
                    host: req.host.clone(),
                    ip: ip.to_string(),
                    reason: reason.to_string(),
                },
                Refusal::Unresolvable { reason } => ProbeError::Resolve {
                    host: req.host.clone(),
                    reason,
                },
            })?;
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
                debug!(error = %e, "credential test connection closed");
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
            .header(USER_AGENT, "tokenless-test/1");
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
        // Dropped unread, with the connection: a body could echo the key.
        Ok(response.status().as_u16())
    }
}

#[async_trait]
impl CredentialProber for HttpProber {
    async fn probe(&self, request: ProbeRequest, egress: &EgressPolicy) -> Result<u16, ProbeError> {
        let host = request.host.clone();
        tokio::time::timeout(self.timeout, self.run(request, egress))
            .await
            .map_err(|_| ProbeError::TimedOut {
                host,
                secs: self.timeout.as_secs().max(1),
            })?
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use rustls::pki_types::PrivateKeyDer;
    use tokenless_core::egress::IpCidr;
    use tokenless_core::injection::{InjectedHeader, InjectedHeaders};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use super::*;

    const DUMMY: &str = "Bearer tokenless-test-dummy-key";

    fn request(host: &str, port: u16) -> ProbeRequest {
        ProbeRequest {
            host: host.into(),
            port,
            method: "GET".into(),
            path: "/v1/models".into(),
            headers: InjectedHeaders {
                headers: vec![InjectedHeader {
                    name: "authorization".into(),
                    value: DUMMY.into(),
                    fixed: false,
                }],
                substitutions: vec![],
                secrets: vec![],
            },
        }
    }

    /// The egress policy of an instance that allows loopback, as one with
    /// a self-hosted service on this machine would.
    fn loopback_allowed() -> EgressPolicy {
        EgressPolicy {
            allow: vec!["127.0.0.0/8".parse::<IpCidr>().unwrap()],
            ..EgressPolicy::default()
        }
    }

    /// What a mock upstream does with each request.
    #[derive(Clone, Copy)]
    enum Upstream {
        Answer(&'static str),
        /// Accepts the request and never answers.
        Hang,
    }

    /// A local HTTPS service for `localhost`. Returns its port, its
    /// certificate and the request heads it received.
    async fn upstream(
        behaviour: Upstream,
    ) -> (u16, CertificateDer<'static>, Arc<Mutex<Vec<String>>>) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let root = CertificateDer::from(cert.cert.der().to_vec());
        let key = PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();
        let server = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![root.clone()], key)
        .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let heads = Arc::new(Mutex::new(Vec::new()));
        let seen = heads.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let seen = seen.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        if tls.read(&mut byte).await.unwrap_or(0) == 0 {
                            break;
                        }
                        head.push(byte[0]);
                    }
                    seen.lock()
                        .unwrap()
                        .push(String::from_utf8_lossy(&head).into_owned());
                    match behaviour {
                        Upstream::Answer(answer) => {
                            let _ = tls.write_all(answer.as_bytes()).await;
                            let _ = tls.shutdown().await;
                        }
                        Upstream::Hang => {
                            tokio::time::sleep(Duration::from_secs(60)).await;
                        }
                    }
                });
            }
        });
        (port, root, heads)
    }

    fn answer(status: &str, body: &str) -> &'static str {
        Box::leak(
            format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .into_boxed_str(),
        )
    }

    #[tokio::test]
    async fn sends_the_request_with_the_injected_header_and_reports_the_status() {
        // The body echoes the key, as some services do; it is never read.
        let (port, root, heads) = upstream(Upstream::Answer(answer(
            "200 OK",
            &format!("{{\"key\":\"{DUMMY}\"}}"),
        )))
        .await;
        let prober = HttpProber::new(false, &[root]).unwrap();
        let status = prober
            .probe(request("localhost", port), &loopback_allowed())
            .await
            .unwrap();
        assert_eq!(status, 200);
        let head = heads.lock().unwrap()[0].clone();
        assert!(head.starts_with("GET /v1/models HTTP/1.1\r\n"), "{head}");
        assert!(head
            .to_ascii_lowercase()
            .contains(&format!("authorization: {}", DUMMY.to_ascii_lowercase())));
        assert!(head.contains(&format!("host: localhost:{port}")), "{head}");
    }

    #[tokio::test]
    async fn refusals_and_odd_answers_are_statuses_and_redirects_are_not_followed() {
        for (line, code) in [
            ("401 Unauthorized", 401),
            ("403 Forbidden", 403),
            ("404 Not Found", 404),
            ("500 Internal Server Error", 500),
        ] {
            let (port, root, _) = upstream(Upstream::Answer(answer(line, ""))).await;
            let prober = HttpProber::new(false, &[root]).unwrap();
            let status = prober
                .probe(request("localhost", port), &loopback_allowed())
                .await
                .unwrap();
            assert_eq!(status, code);
        }
        let redirect = "HTTP/1.1 302 Found\r\nLocation: https://169.254.169.254/latest/meta-data/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let (port, root, heads) = upstream(Upstream::Answer(redirect)).await;
        let prober = HttpProber::new(false, &[root]).unwrap();
        let status = prober
            .probe(request("localhost", port), &loopback_allowed())
            .await
            .unwrap();
        assert_eq!(status, 302);
        assert_eq!(
            heads.lock().unwrap().len(),
            1,
            "the redirect is not followed"
        );
    }

    #[tokio::test]
    async fn private_and_metadata_destinations_are_refused_before_connecting() {
        let (port, root, heads) = upstream(Upstream::Answer(answer("200 OK", ""))).await;
        let prober = HttpProber::new(false, &[root]).unwrap();
        for host in ["localhost", "127.0.0.1", "169.254.169.254", "10.0.0.1"] {
            let err = prober
                .probe(request(host, port), &EgressPolicy::default())
                .await
                .unwrap_err();
            assert!(matches!(err, ProbeError::Blocked { .. }), "{host}: {err}");
            assert!(
                err.to_string().contains("allow the range in Settings"),
                "{err}"
            );
        }
        assert!(
            heads.lock().unwrap().is_empty(),
            "nothing reached the upstream"
        );
    }

    #[tokio::test]
    async fn an_upstream_that_does_not_answer_times_out() {
        let (port, root, _) = upstream(Upstream::Hang).await;
        let prober = HttpProber::new(false, &[root])
            .unwrap()
            .with_timeout(Duration::from_millis(300));
        let started = std::time::Instant::now();
        let err = prober
            .probe(request("localhost", port), &loopback_allowed())
            .await
            .unwrap_err();
        assert!(matches!(err, ProbeError::TimedOut { .. }), "{err}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn the_deadline_is_never_longer_than_the_limit() {
        let prober = HttpProber::new(false, &[])
            .unwrap()
            .with_timeout(Duration::from_secs(3600));
        assert_eq!(prober.timeout, PROBE_TIMEOUT);
    }

    #[tokio::test]
    async fn unreachable_hosts_and_bad_certificates_are_failures_to_reach() {
        // Nothing listens on the port.
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);
        let prober = HttpProber::new(false, &[]).unwrap();
        let err = prober
            .probe(request("localhost", port), &loopback_allowed())
            .await
            .unwrap_err();
        assert!(
            matches!(&err, ProbeError::Request { reason, .. } if reason.contains("connect failed")),
            "{err}"
        );

        // A certificate nobody trusts.
        let (port, _untrusted, heads) = upstream(Upstream::Answer(answer("200 OK", ""))).await;
        let err = prober
            .probe(request("localhost", port), &loopback_allowed())
            .await
            .unwrap_err();
        assert!(
            matches!(&err, ProbeError::Request { reason, .. } if reason.contains("TLS handshake failed")),
            "{err}"
        );
        assert!(heads.lock().unwrap().is_empty(), "no request without TLS");

        // A name that does not resolve.
        let err = prober
            .probe(request("tokenless-test.invalid", 443), &loopback_allowed())
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                ProbeError::Resolve { .. } | ProbeError::TimedOut { .. }
            ),
            "{err}"
        );
        assert!(!err.to_string().contains(DUMMY));
    }
}
