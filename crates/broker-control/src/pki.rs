// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The control plane's internal certificate authorities.
//!
//! * The **node CA** issues the node API's server certificate and the
//!   short-lived mTLS client certificates nodes use to fetch snapshots.
//! * The **interception CA** is what data plane nodes use to mint leaf
//!   certificates for intercepted hosts; agents are configured to trust it.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use broker_core::ids::NodeId;
use chrono::{DateTime, TimeZone, Utc};
use rand::rngs::OsRng;
use rand::RngCore;
use rcgen::string::Ia5String;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType, SerialNumber,
};
use rustls_pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::ControlError;

// Predates the rename to tokenless and is kept: changing it invalidates
// existing node certificates.
pub const NODE_URI_PREFIX: &str = "urn:credential-broker:node:";
const CA_VALIDITY_DAYS: i64 = 3650;

/// A CA certificate and its private key (PKCS#8 PEM, zeroised on drop).
pub struct CaMaterial {
    pub cert_der: Vec<u8>,
    pub key_pem: Zeroizing<String>,
}

impl CaMaterial {
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.cert_der)
    }

    pub fn cert_pem(&self) -> String {
        pem_encode("CERTIFICATE", &self.cert_der)
    }

    fn issuer(&self) -> Result<Issuer<'static, KeyPair>, ControlError> {
        let key = KeyPair::from_pem(&self.key_pem).map_err(|e| ControlError::pki("ca.key", e))?;
        Issuer::from_ca_cert_der(&CertificateDer::from(self.cert_der.clone()), key)
            .map_err(|e| ControlError::pki("ca.issuer", e))
    }

    /// Serialised form for encrypted storage: `der_len(4) || der || key_pem`.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(
            4 + self.cert_der.len() + self.key_pem.len(),
        ));
        out.extend_from_slice(&(self.cert_der.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.cert_der);
        out.extend_from_slice(self.key_pem.as_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ControlError> {
        let bad = || ControlError::pki("ca.decode", "stored CA material is truncated");
        let len_bytes: [u8; 4] = bytes
            .get(..4)
            .ok_or_else(bad)?
            .try_into()
            .map_err(|_| bad())?;
        let len = u32::from_be_bytes(len_bytes) as usize;
        let der = bytes.get(4..4 + len).ok_or_else(bad)?.to_vec();
        let key = std::str::from_utf8(bytes.get(4 + len..).ok_or_else(bad)?)
            .map_err(|e| ControlError::pki("ca.decode", e))?;
        Ok(Self {
            cert_der: der,
            key_pem: Zeroizing::new(key.to_string()),
        })
    }

    /// PKCS#8 DER of the private key, for sealing to data plane nodes.
    pub fn key_pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>, ControlError> {
        let key = KeyPair::from_pem(&self.key_pem).map_err(|e| ControlError::pki("ca.key", e))?;
        Ok(Zeroizing::new(key.serialize_der()))
    }
}

pub fn fingerprint(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

pub fn pem_encode(label: &str, der: &[u8]) -> String {
    let b64 = STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(&String::from_utf8_lossy(chunk));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

fn to_offset(dt: DateTime<Utc>) -> Result<time::OffsetDateTime, ControlError> {
    time::OffsetDateTime::from_unix_timestamp(dt.timestamp())
        .map_err(|e| ControlError::pki("validity", e))
}

fn random_serial() -> (SerialNumber, String) {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes[0] &= 0x7f; // keep it positive
    (SerialNumber::from_slice(&bytes), hex::encode(bytes))
}

fn dn(common_name: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    dn.push(DnType::OrganizationName, "tokenless");
    dn
}

pub fn generate_ca(common_name: &str) -> Result<CaMaterial, ControlError> {
    let key = KeyPair::generate().map_err(|e| ControlError::pki("ca.keygen", e))?;
    let mut params = CertificateParams::default();
    let now = Utc::now();
    params.not_before = to_offset(now - chrono::Duration::minutes(5))?;
    params.not_after = to_offset(now + chrono::Duration::days(CA_VALIDITY_DAYS))?;
    params.distinguished_name = dn(common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.serial_number = Some(random_serial().0);
    let cert = params
        .self_signed(&key)
        .map_err(|e| ControlError::pki("ca.self_sign", format!("{common_name}: {e}")))?;
    Ok(CaMaterial {
        cert_der: cert.der().to_vec(),
        key_pem: Zeroizing::new(key.serialize_pem()),
    })
}

pub struct IssuedCert {
    pub cert_der: Vec<u8>,
    pub key_der: Zeroizing<Vec<u8>>,
}

/// Issues the node API's TLS server certificate.
pub fn issue_server_cert(
    ca: &CaMaterial,
    names: &[String],
    validity: chrono::Duration,
) -> Result<IssuedCert, ControlError> {
    let issuer = ca.issuer()?;
    let key = KeyPair::generate().map_err(|e| ControlError::pki("server.keygen", e))?;
    let mut params = CertificateParams::new(names.to_vec())
        .map_err(|e| ControlError::pki("server.params", format!("names {names:?}: {e}")))?;
    let now = Utc::now();
    params.not_before = to_offset(now - chrono::Duration::minutes(5))?;
    params.not_after = to_offset(now + validity)?;
    params.distinguished_name = dn("tokenless node API");
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.serial_number = Some(random_serial().0);
    let cert = params
        .signed_by(&key, &issuer)
        .map_err(|e| ControlError::pki("server.sign", e))?;
    Ok(IssuedCert {
        cert_der: cert.der().to_vec(),
        key_der: Zeroizing::new(key.serialize_der()),
    })
}

pub struct SignedNodeCert {
    pub cert_pem: String,
    pub serial: String,
    pub not_after: DateTime<Utc>,
}

/// Signs a node's CSR. Only the CSR's public key is used: names, usages and
/// validity are always chosen here, never by the requester.
pub fn sign_node_csr(
    ca: &CaMaterial,
    csr_pem: &str,
    node_id: &NodeId,
    validity: chrono::Duration,
) -> Result<SignedNodeCert, ControlError> {
    if csr_pem.len() > 16 * 1024 {
        return Err(ControlError::validation("CSR is larger than 16 KiB"));
    }
    let csr = CertificateSigningRequestParams::from_pem(csr_pem)
        .map_err(|e| ControlError::validation(format!("CSR for node {node_id} is invalid: {e}")))?;
    let issuer = ca.issuer()?;
    let mut params = CertificateParams::default();
    let now = Utc::now();
    let not_after = now + validity;
    params.not_before = to_offset(now - chrono::Duration::minutes(5))?;
    params.not_after = to_offset(not_after)?;
    params.distinguished_name = dn(&format!("node:{node_id}"));
    let uri = Ia5String::try_from(format!("{NODE_URI_PREFIX}{node_id}"))
        .map_err(|e| ControlError::pki("node.san", e))?;
    params.subject_alt_names = vec![SanType::URI(uri)];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let (serial, serial_hex) = random_serial();
    params.serial_number = Some(serial);
    let signer = CertificateSigningRequestParams {
        params,
        public_key: csr.public_key,
    };
    let cert = signer
        .signed_by(&issuer)
        .map_err(|e| ControlError::pki("node.sign", format!("node {node_id}: {e}")))?;
    Ok(SignedNodeCert {
        cert_pem: cert.pem(),
        serial: serial_hex,
        not_after: Utc
            .timestamp_opt(not_after.timestamp(), 0)
            .single()
            .unwrap_or(not_after),
    })
}

/// Reads the node ID from a client certificate's URI SAN.
pub fn node_id_from_cert(der: &[u8]) -> Option<NodeId> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let san = cert.subject_alternative_name().ok()??;
    san.value.general_names.iter().find_map(|name| match name {
        x509_parser::extensions::GeneralName::URI(uri) => uri
            .strip_prefix(NODE_URI_PREFIX)
            .and_then(|id| id.parse().ok()),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn csr() -> (String, KeyPair) {
        let key = KeyPair::generate().unwrap();
        let params = CertificateParams::new(vec!["attacker-chosen.example".to_string()]).unwrap();
        let csr = params.serialize_request(&key).unwrap();
        (csr.pem().unwrap(), key)
    }

    #[test]
    fn ca_round_trips_through_bytes() {
        let ca = generate_ca("test CA").unwrap();
        let restored = CaMaterial::from_bytes(&ca.to_bytes()).unwrap();
        assert_eq!(restored.cert_der, ca.cert_der);
        assert_eq!(restored.fingerprint(), ca.fingerprint());
        assert!(ca.cert_pem().starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(CaMaterial::from_bytes(&[0, 0]).is_err());
    }

    #[test]
    fn node_csr_is_signed_with_our_names_only() {
        let ca = generate_ca("node CA").unwrap();
        let (csr_pem, _) = csr();
        let node_id = NodeId::new();
        let signed = sign_node_csr(&ca, &csr_pem, &node_id, chrono::Duration::hours(1)).unwrap();
        let der = STANDARD
            .decode(
                signed
                    .cert_pem
                    .lines()
                    .filter(|l| !l.starts_with("-----"))
                    .collect::<String>(),
            )
            .unwrap();
        assert_eq!(node_id_from_cert(&der), Some(node_id));
        let (_, parsed) = x509_parser::parse_x509_certificate(&der).unwrap();
        let san = parsed.subject_alternative_name().unwrap().unwrap();
        assert_eq!(san.value.general_names.len(), 1);
        assert!(signed.not_after > Utc::now());
    }

    #[test]
    fn garbage_csr_is_a_validation_error() {
        let ca = generate_ca("node CA").unwrap();
        assert!(matches!(
            sign_node_csr(&ca, "not a csr", &NodeId::new(), chrono::Duration::hours(1)),
            Err(ControlError::Validation { .. })
        ));
    }

    #[test]
    fn server_cert_issues() {
        let ca = generate_ca("node CA").unwrap();
        let cert = issue_server_cert(
            &ca,
            &["localhost".into(), "127.0.0.1".into()],
            chrono::Duration::days(1),
        )
        .unwrap();
        assert!(!cert.cert_der.is_empty());
        assert!(node_id_from_cert(&cert.cert_der).is_none());
    }
}
