// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! rustls configuration. Every config is built with an explicit `ring`
//! provider so nothing depends on a process-wide default.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};
use rustls_pki_types::pem::PemObject;
use sha2::{Digest, Sha256};

use crate::error::DataPlaneError;

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn certs_from_pem(
    context: &str,
    pem: &str,
) -> Result<Vec<CertificateDer<'static>>, DataPlaneError> {
    let certs = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| DataPlaneError::tls(context, e))?;
    if certs.is_empty() {
        return Err(DataPlaneError::tls(context, "no certificate found in PEM"));
    }
    Ok(certs)
}

pub fn key_from_pem(context: &str, pem: &str) -> Result<PrivateKeyDer<'static>, DataPlaneError> {
    PrivateKeyDer::from_pem_slice(pem.as_bytes()).map_err(|e| DataPlaneError::tls(context, e))
}

/// Client config for connecting to real upstreams.
pub fn upstream_client_config(
    use_public_roots: bool,
    extra_roots: &[CertificateDer<'static>],
) -> Result<Arc<ClientConfig>, DataPlaneError> {
    let mut roots = RootCertStore::empty();
    if use_public_roots {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    for root in extra_roots {
        roots
            .add(root.clone())
            .map_err(|e| DataPlaneError::tls("upstream extra root", e))?;
    }
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| DataPlaneError::tls("upstream client", e))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// mTLS client config for the node API: trusts only the node CA.
pub fn mtls_client_config(
    ca_pem: &str,
    cert_pem: &str,
    key_pem: &str,
) -> Result<Arc<ClientConfig>, DataPlaneError> {
    let mut roots = RootCertStore::empty();
    for ca in certs_from_pem("node CA", ca_pem)? {
        roots
            .add(ca)
            .map_err(|e| DataPlaneError::tls("node CA", e))?;
    }
    let config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| DataPlaneError::tls("node client", e))?
        .with_root_certificates(roots)
        .with_client_auth_cert(
            certs_from_pem("node client certificate", cert_pem)?,
            key_from_pem("node client key", key_pem)?,
        )
        .map_err(|e| DataPlaneError::tls("node client certificate", e))?;
    Ok(Arc::new(config))
}

/// Client config used once, at enrolment: the server chain must contain a
/// CA whose SHA-256 matches the fingerprint embedded in the join token, and
/// the leaf must validate against that CA.
pub fn pinned_client_config(ca_fingerprint: &str) -> Result<Arc<ClientConfig>, DataPlaneError> {
    let provider = provider();
    let config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| DataPlaneError::tls("enrolment client", e))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedCaVerifier {
            fingerprint: ca_fingerprint.to_ascii_lowercase(),
            provider,
        }))
        .with_no_client_auth();
    Ok(Arc::new(config))
}

#[derive(Debug)]
struct PinnedCaVerifier {
    fingerprint: String,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedCaVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let ca = intermediates
            .iter()
            .find(|c| sha256_hex(c.as_ref()) == self.fingerprint)
            .ok_or_else(|| {
                rustls::Error::General(format!(
                    "control plane did not present the CA pinned by the join token ({})",
                    self.fingerprint
                ))
            })?;
        let mut roots = RootCertStore::empty();
        roots.add(ca.clone().into_owned())?;
        let inner =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), self.provider.clone())
                .build()
                .map_err(|e| rustls::Error::General(e.to_string()))?;
        inner.verify_server_cert(end_entity, &[], server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Server config presenting one interception leaf certificate.
pub fn leaf_server_config(
    host: &str,
    chain: Vec<CertificateDer<'static>>,
    key_der: Vec<u8>,
) -> Result<Arc<ServerConfig>, DataPlaneError> {
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| DataPlaneError::tls(host, e))?
        .with_no_client_auth()
        .with_single_cert(
            chain,
            PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(key_der)),
        )
        .map_err(|e| DataPlaneError::tls(host, e))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}
