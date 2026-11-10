// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The certificates and environment an agent needs to use the proxy.
//!
//! Brokered hosts are intercepted with the broker's CA, while other hosts
//! are tunnelled untouched and present their real certificates. Most
//! runtimes take one trust file that *replaces* their roots, so the agent
//! gets a bundle of the system roots plus the broker CA. Node is the
//! exception: `NODE_EXTRA_CA_CERTS` adds to its own roots, so it gets the
//! broker CA alone.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use sha2::{Digest, Sha256};

use tokenless_control::service::sessions::DiscoveredService;
use tracing::warn;

use super::LauncherError;

/// System trust files, in the order they are looked for.
const SYSTEM_BUNDLES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt", // Debian, Ubuntu, Alpine, Arch
    "/etc/pki/tls/certs/ca-bundle.crt",   // Fedora, RHEL
    "/etc/ssl/ca-bundle.pem",             // openSUSE
    "/etc/ssl/cert.pem",                  // macOS, BSDs
];

/// SHA-256 of the first certificate in `pem`, as `AB:CD:...` (the form the
/// Proxies page shows).
pub fn fingerprint(pem: &str) -> Result<String, LauncherError> {
    let cert = CertificateDer::pem_slice_iter(pem.as_bytes())
        .next()
        .ok_or_else(|| LauncherError::config("the interception CA response holds no certificate"))?
        .map_err(|e| LauncherError::config(format!("the interception CA is not valid PEM: {e}")))?;
    let digest = Sha256::digest(cert.as_ref());
    Ok(digest
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":"))
}

/// Compares fingerprints ignoring case, colons and spaces.
pub fn fingerprints_match(a: &str, b: &str) -> bool {
    let norm = |s: &str| {
        s.chars()
            .filter(|c| c.is_ascii_hexdigit())
            .map(|c| c.to_ascii_uppercase())
            .collect::<String>()
    };
    let (a, b) = (norm(a), norm(b));
    a.len() == 64 && a == b
}

/// Trust files written for one agent run.
#[derive(Debug)]
pub struct TrustFiles {
    /// The broker CA alone.
    pub broker_ca: PathBuf,
    /// System roots followed by the broker CA.
    pub bundle: PathBuf,
    /// Where the system roots came from, if any were found.
    pub base: Option<PathBuf>,
}

fn find_base(explicit: Option<&Path>) -> Result<Option<PathBuf>, LauncherError> {
    if let Some(path) = explicit {
        if !path.is_file() {
            return Err(LauncherError::config(format!(
                "--trust-base {} is not a readable file",
                path.display()
            )));
        }
        return Ok(Some(path.to_path_buf()));
    }
    let from_env = std::env::var_os("SSL_CERT_FILE").map(PathBuf::from);
    Ok(from_env
        .into_iter()
        .chain(SYSTEM_BUNDLES.iter().map(PathBuf::from))
        .find(|p| p.is_file()))
}

/// Writes the trust files into `dir` (created by the caller, private).
pub fn write_trust_files(
    dir: &Path,
    broker_pem: &str,
    explicit_base: Option<&Path>,
) -> Result<TrustFiles, LauncherError> {
    let broker_ca = dir.join("broker-ca.pem");
    std::fs::write(&broker_ca, broker_pem).map_err(LauncherError::io(format!(
        "writing {}",
        broker_ca.display()
    )))?;
    let base = find_base(explicit_base)?;
    let mut bundle_pem = match &base {
        Some(path) => std::fs::read_to_string(path).map_err(LauncherError::io(format!(
            "reading system roots {}",
            path.display()
        )))?,
        None => String::new(),
    };
    if !bundle_pem.is_empty() && !bundle_pem.ends_with('\n') {
        bundle_pem.push('\n');
    }
    bundle_pem.push_str(broker_pem);
    let bundle = dir.join("trust-bundle.pem");
    std::fs::write(&bundle, bundle_pem)
        .map_err(LauncherError::io(format!("writing {}", bundle.display())))?;
    Ok(TrustFiles {
        broker_ca,
        bundle,
        base,
    })
}

/// Environment for an agent behind the session port at `port`.
pub fn agent_env(port: SocketAddr, trust: &TrustFiles) -> Vec<(String, String)> {
    let proxy = format!("http://{port}");
    let bundle = trust.bundle.display().to_string();
    let mut no_proxy = vec!["localhost".to_string(), "127.0.0.1".into(), "::1".into()];
    if let Ok(existing) = std::env::var("NO_PROXY").or_else(|_| std::env::var("no_proxy")) {
        no_proxy.extend(
            existing
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty() && !no_proxy.iter().any(|n| n == s))
                .map(str::to_string)
                .collect::<Vec<_>>(),
        );
    }
    let no_proxy = no_proxy.join(",");
    let mut env = Vec::new();
    for name in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
        env.push((name.to_string(), proxy.clone()));
    }
    for name in ["NO_PROXY", "no_proxy"] {
        env.push((name.to_string(), no_proxy.clone()));
    }
    for name in [
        "SSL_CERT_FILE",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "GIT_SSL_CAINFO",
        "AWS_CA_BUNDLE",
        "DENO_CERT",
    ] {
        env.push((name.to_string(), bundle.clone()));
    }
    env.push((
        "NODE_EXTRA_CA_CERTS".to_string(),
        trust.broker_ca.display().to_string(),
    ));
    // Node 24+ only sends its built-in fetch through HTTPS_PROXY with this.
    env.push(("NODE_USE_ENV_PROXY".to_string(), "1".to_string()));
    env.push(("TOKENLESS_PROXY".to_string(), proxy));
    env
}

/// `ENV=placeholder` for every enabled service's placeholders that name an
/// environment variable, so tools that insist on a key start with one the
/// proxy will swap. When two services claim the same variable the first
/// wins and the clash is reported.
pub fn placeholder_env(services: &[DiscoveredService]) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = Vec::new();
    for service in services.iter().filter(|s| s.enabled) {
        for p in &service.placeholders {
            let Some(name) = &p.env else { continue };
            match env.iter().find(|(n, _)| n == name) {
                Some((_, kept)) if kept != &p.placeholder => warn!(
                    variable = %name,
                    service = %service.service,
                    "two services set the same placeholder variable; keeping the first"
                ),
                Some(_) => {}
                None => env.push((name.clone(), p.placeholder.clone())),
            }
        }
    }
    env
}

/// Quotes a value for a POSIX shell `export` line.
pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// `value` as one shell word: as it is when nothing in it needs quoting
/// (`personal`, `my-agent`), quoted otherwise (`'Work stuff'`).
pub fn shell_word(value: &str) -> String {
    let plain = !value.is_empty()
        && value.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | ':' | '@' | '+' | ',')
        });
    if plain {
        value.to_string()
    } else {
        shell_quote(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ca() -> String {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["ca.test".to_string()]).unwrap();
        params.self_signed(&key).unwrap().pem()
    }

    #[test]
    fn fingerprints_are_colon_hex_and_compare_loosely() {
        let pem = test_ca();
        let fp = fingerprint(&pem).unwrap();
        assert_eq!(fp.len(), 32 * 3 - 1);
        assert!(fp
            .chars()
            .all(|c| c == ':' || c.is_ascii_hexdigit() && !c.is_ascii_lowercase()));
        assert!(fingerprints_match(&fp, &fp.replace(':', "").to_lowercase()));
        assert!(!fingerprints_match(&fp, "AB:CD"));
        assert!(fingerprint("not a pem").is_err());
    }

    #[test]
    fn bundle_has_base_roots_then_the_broker_ca() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("roots.pem");
        std::fs::write(&base, "ROOTS").unwrap();
        let files = write_trust_files(dir.path(), "BROKER\n", Some(&base)).unwrap();
        assert_eq!(
            std::fs::read_to_string(&files.bundle).unwrap(),
            "ROOTS\nBROKER\n"
        );
        assert_eq!(
            std::fs::read_to_string(&files.broker_ca).unwrap(),
            "BROKER\n"
        );
        let missing = dir.path().join("missing.pem");
        assert!(write_trust_files(dir.path(), "B", Some(&missing)).is_err());
    }

    #[test]
    fn env_points_every_runtime_at_the_port_and_bundle() {
        let files = TrustFiles {
            broker_ca: "/t/broker-ca.pem".into(),
            bundle: "/t/trust-bundle.pem".into(),
            base: None,
        };
        let env: std::collections::HashMap<_, _> =
            agent_env("127.0.0.1:41000".parse().unwrap(), &files)
                .into_iter()
                .collect();
        assert_eq!(env["HTTPS_PROXY"], "http://127.0.0.1:41000");
        assert_eq!(env["https_proxy"], "http://127.0.0.1:41000");
        assert_eq!(env["SSL_CERT_FILE"], "/t/trust-bundle.pem");
        assert_eq!(env["NODE_EXTRA_CA_CERTS"], "/t/broker-ca.pem");
        assert_eq!(env["NODE_USE_ENV_PROXY"], "1");
        assert!(env["NO_PROXY"].starts_with("localhost,127.0.0.1,::1"));
        assert!(
            env.values().all(|v| !v.contains("v4.public.")),
            "no token in the env"
        );
    }

    #[test]
    fn placeholders_of_enabled_services_become_env() {
        use tokenless_control::service::sessions::DiscoveredPlaceholder;
        use tokenless_core::ids::RuleId;
        let service = |name: &str, enabled: bool, env: &str, placeholder: &str| DiscoveredService {
            rule_id: RuleId::new(),
            rule: name.into(),
            credential: name.into(),
            template_id: name.into(),
            service: name.into(),
            hosts: vec![],
            paths: vec![],
            methods: vec![],
            enabled,
            placeholders: vec![
                DiscoveredPlaceholder {
                    placeholder: placeholder.into(),
                    field: "token".into(),
                    env: Some(env.into()),
                    locations: vec![],
                },
                DiscoveredPlaceholder {
                    placeholder: "__NO_ENV_HERE__".into(),
                    field: "user".into(),
                    env: None,
                    locations: vec![],
                },
            ],
            kind: Default::default(),
            mcp_path: None,
        };
        let env = placeholder_env(&[
            service("github", true, "GITHUB_TOKEN", "__GITHUB_TOKEN__"),
            service("stripe", false, "STRIPE_KEY", "__STRIPE_KEY__"),
            service("other", true, "GITHUB_TOKEN", "__OTHER__"),
        ]);
        assert_eq!(
            env,
            vec![("GITHUB_TOKEN".to_string(), "__GITHUB_TOKEN__".to_string())]
        );
    }

    #[test]
    fn shell_quoting() {
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(shell_word("my-agent"), "my-agent");
        assert_eq!(shell_word("Work stuff"), "'Work stuff'");
        assert_eq!(shell_word("$HOME"), "'$HOME'");
        assert_eq!(shell_word(""), "''");
    }
}
