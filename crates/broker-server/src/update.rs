// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `tokenless update`: replaces this binary with a release's, checked the
//! way `install.sh` checks it.
//!
//! The release is found by where `github.com/<repo>/releases/latest`
//! redirects, so no API token or rate limit is involved. Its archive is
//! checked against the release's `SHA256SUMS`, and when `cosign` is
//! installed, `SHA256SUMS`' keyless signature is verified against the
//! repository's release workflow. The new binary is unpacked next to this
//! one, asked for its `--version`, and only then renamed over it: a failure
//! at any step leaves the installed binary as it was. Processes already
//! running keep the old binary until they are restarted.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use crate::webhook_transport::describe;

pub const DEFAULT_REPO: &str = "gotempsh/tokenless";
/// This build's version. The release workflow gives a release build its
/// tag's version, suffix included (`0.3.0-rc.1`): the crate's version never
/// has one, so an rc built from it would pass for the final release.
pub const VERSION: &str = match option_env!("TOKENLESS_BUILD_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};
/// Set in the container image to its name: there, the image is updated,
/// not the binary inside it.
pub const CONTAINER_IMAGE_ENV: &str = "TOKENLESS_CONTAINER_IMAGE";

const GITHUB: &str = "https://github.com";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// A download that sends nothing for this long is given up on.
const READ_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_ARCHIVE: u64 = 256 * 1024 * 1024;
const MAX_BINARY: u64 = 512 * 1024 * 1024;
const MAX_SMALL_FILE: u64 = 1024 * 1024;
const VERSION_TIMEOUT: Duration = Duration::from_secs(20);
/// What the file staged next to the binary is called, before its random part.
const STAGED_PREFIX: &str = ".tokenless-update-";
/// A staged file this old belongs to no running update: one was killed
/// before it could remove it.
const STALE_STAGED: Duration = Duration::from_secs(60 * 60);

/// The release target this binary was built for, as in the archive names.
pub fn target() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some("x86_64-unknown-linux-musl"),
        ("linux", "aarch64") => Some("aarch64-unknown-linux-musl"),
        ("macos", "x86_64") => Some("x86_64-apple-darwin"),
        ("macos", "aarch64") => Some("aarch64-apple-darwin"),
        _ => None,
    }
}

/// Which release to install.
#[derive(Debug, Clone, PartialEq)]
pub enum Wanted {
    /// The newest release, installed only when it is newer than this one.
    Latest,
    /// This tag, installed whatever this binary's version: an explicit
    /// downgrade or reinstall.
    Release(String),
}

#[derive(Debug, Clone)]
pub struct Options {
    /// `owner/name` on GitHub.
    pub repo: String,
    /// A base URL holding the release files instead of GitHub's, for
    /// mirrors. The latest version is then known only once downloaded.
    pub mirror: Option<String>,
    pub wanted: Wanted,
    /// Only say whether a newer release exists.
    pub check_only: bool,
    /// `cosign`, when it is installed: `SHA256SUMS`' signature is then
    /// verified.
    pub cosign: Option<PathBuf>,
    /// Refuse to install without verifying the signature.
    pub require_signature: bool,
    /// A PEM file of CAs trusted for the downloads besides the public
    /// ones: a mirror's internal CA, or a TLS-inspecting proxy's.
    pub ca_file: Option<PathBuf>,
    /// `https://github.com`; tests point it at a local server.
    pub github: String,
}

impl Options {
    pub fn new(repo: String) -> Self {
        Self {
            repo,
            mirror: None,
            wanted: Wanted::Latest,
            check_only: false,
            cosign: None,
            require_signature: false,
            ca_file: None,
            github: GITHUB.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// Nothing newer: `latest` is no newer than `current`.
    UpToDate {
        current: semver::Version,
        latest: semver::Version,
    },
    /// `--check`: `latest` is newer than `current`.
    Available {
        current: semver::Version,
        latest: semver::Version,
    },
    Updated {
        path: PathBuf,
        from: semver::Version,
        to: semver::Version,
        signature_verified: bool,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("no release is built for {os} on {arch}; build tokenless from source instead")]
    UnsupportedPlatform {
        os: &'static str,
        arch: &'static str,
    },
    #[error(
        "this tokenless runs from the container image {image}; pull its new tag and recreate the container instead"
    )]
    Container { image: String },
    #[error("{dir} is not writable, so {binary} cannot be replaced ({source}); run the update as the user that installed it, or reinstall with install.sh")]
    NotWritable {
        dir: String,
        binary: String,
        source: std::io::Error,
    },
    #[error("reading the CA file {path}: {reason}")]
    Ca { path: String, reason: String },
    #[error("finding the latest release of {repo}: {reason}")]
    Latest { repo: String, reason: String },
    #[error("release tag {tag:?} is not a version such as v1.2.3")]
    BadTag { tag: String },
    #[error("downloading {url}: {reason}")]
    Download { url: String, reason: String },
    #[error("{url} is larger than {limit} bytes; not installing")]
    TooLarge { url: String, limit: u64 },
    #[error("{asset} is not listed in the release's SHA256SUMS; not installing")]
    NotInSums { asset: String },
    #[error("checksum mismatch for {asset}: SHA256SUMS says {expected}, the download is {actual}; not installing")]
    ChecksumMismatch {
        asset: String,
        expected: String,
        actual: String,
    },
    #[error("--require-signature was given but cosign is not installed; install cosign or leave the flag off")]
    NoCosign,
    #[error("the signature on {repo}'s SHA256SUMS did not verify; not installing: {reason}")]
    Signature { repo: String, reason: String },
    #[error("unpacking {asset}: {reason}")]
    Archive { asset: String, reason: String },
    #[error("stopped by {signal}; {binary} is unchanged")]
    Interrupted {
        signal: &'static str,
        binary: String,
    },
    #[error("the new binary does not run on this machine: {reason}; {binary} is unchanged")]
    NewBinary { binary: String, reason: String },
    #[error("release {tag} holds tokenless {found}, not {expected}; not installing")]
    VersionMismatch {
        tag: String,
        expected: semver::Version,
        found: semver::Version,
    },
    #[error("I/O failure while {context}: {source}")]
    Io {
        context: String,
        source: std::io::Error,
    },
}

fn io(context: impl Into<String>) -> impl FnOnce(std::io::Error) -> UpdateError {
    let context = context.into();
    move |source| UpdateError::Io { context, source }
}

/// `v1.2.3` or `1.2.3`.
pub fn parse_tag(tag: &str) -> Result<semver::Version, UpdateError> {
    let bad = || UpdateError::BadTag { tag: tag.into() };
    semver::Version::parse(tag.trim().trim_start_matches('v')).map_err(|_| bad())
}

/// `v1.2.3`, from what a user typed.
fn normalize_tag(tag: &str) -> String {
    let tag = tag.trim();
    if tag.starts_with('v') {
        tag.into()
    } else {
        format!("v{tag}")
    }
}

/// The tag out of a `.../releases/tag/<tag>` redirect.
fn tag_from_location(location: &str) -> Option<&str> {
    let (_, tag) = location
        .trim_end_matches('/')
        .rsplit_once("/releases/tag/")?;
    (!tag.is_empty() && !tag.contains('/')).then_some(tag)
}

/// The checksum `SHA256SUMS` lists for `asset`, as `sha256sum` writes it.
fn checksum_for<'a>(sums: &'a str, asset: &str) -> Option<&'a str> {
    sums.lines().find_map(|line| {
        let (hash, name) = line.trim().split_once(char::is_whitespace)?;
        let name = name.trim().trim_start_matches('*');
        (name == asset).then_some(hash)
    })
}

/// The version a `tokenless --version` line names.
fn version_from_output(output: &str) -> Option<semver::Version> {
    semver::Version::parse(output.split_whitespace().nth(1)?).ok()
}

/// Finds `name` in `PATH`.
pub fn find_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

/// Why a request failed; a timeout names the limit that ran out.
fn why(e: reqwest::Error) -> String {
    let limit = if e.is_connect() {
        CONNECT_TIMEOUT
    } else {
        READ_TIMEOUT
    };
    describe(e, limit)
}

struct Http {
    /// Follows redirects: release downloads are redirected to storage.
    follow: reqwest::Client,
    /// Does not: the latest release is read from the redirect itself.
    once: reqwest::Client,
}

impl Http {
    fn new(opts: &Options) -> Result<Self, UpdateError> {
        let plain_http = opts.github.starts_with("http://")
            || opts
                .mirror
                .as_deref()
                .is_some_and(|m| m.starts_with("http://"));
        let mut roots = Vec::new();
        if let Some(path) = &opts.ca_file {
            let shown = path.display().to_string();
            let fail = |reason: String| UpdateError::Ca {
                path: shown.clone(),
                reason,
            };
            let pem = std::fs::read_to_string(path).map_err(|e| fail(e.to_string()))?;
            roots = tokenless_dataplane::tls::certs_from_pem(&shown, &pem)
                .map_err(|e| fail(e.to_string()))?;
        }
        let tls = tokenless_dataplane::tls::upstream_client_config(true, &roots).map_err(|e| {
            UpdateError::Download {
                url: opts.github.clone(),
                reason: e.to_string(),
            }
        })?;
        let build = |redirect| {
            reqwest::Client::builder()
                .use_preconfigured_tls((*tls).clone())
                // Only an explicit mirror (or a test server) may be plain
                // HTTP; the checksums come from the same place.
                .https_only(!plain_http)
                .connect_timeout(CONNECT_TIMEOUT)
                .read_timeout(READ_TIMEOUT)
                .redirect(redirect)
                .user_agent(concat!("tokenless/", env!("CARGO_PKG_VERSION")))
                .build()
                .map_err(|e| UpdateError::Download {
                    url: opts.github.clone(),
                    reason: why(e),
                })
        };
        Ok(Self {
            follow: build(reqwest::redirect::Policy::limited(10))?,
            once: build(reqwest::redirect::Policy::none())?,
        })
    }

    async fn latest_tag(&self, opts: &Options) -> Result<String, UpdateError> {
        let url = format!(
            "{}/{}/releases/latest",
            opts.github.trim_end_matches('/'),
            opts.repo
        );
        let fail = |reason: String| UpdateError::Latest {
            repo: opts.repo.clone(),
            reason,
        };
        let response = self.once.get(&url).send().await.map_err(|e| fail(why(e)))?;
        let status = response.status();
        if !status.is_redirection() {
            return Err(fail(if status == reqwest::StatusCode::NOT_FOUND {
                "the repository has no published release".into()
            } else {
                format!("{url} answered {status}, not a redirect to the release")
            }));
        }
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        tag_from_location(location)
            .map(str::to_string)
            .ok_or_else(|| fail(format!("it redirected to {location:?}, not a release tag")))
    }

    async fn get(&self, url: &str) -> Result<reqwest::Response, UpdateError> {
        let fail = |reason: String| UpdateError::Download {
            url: url.into(),
            reason,
        };
        let response = self
            .follow
            .get(url)
            .send()
            .await
            .map_err(|e| fail(why(e)))?;
        if !response.status().is_success() {
            return Err(fail(format!("answered {}", response.status())));
        }
        Ok(response)
    }

    async fn small(&self, url: &str) -> Result<Vec<u8>, UpdateError> {
        let mut response = self.get(url).await?;
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| UpdateError::Download {
            url: url.into(),
            reason: why(e),
        })? {
            body.extend_from_slice(&chunk);
            if body.len() as u64 > MAX_SMALL_FILE {
                return Err(UpdateError::TooLarge {
                    url: url.into(),
                    limit: MAX_SMALL_FILE,
                });
            }
        }
        Ok(body)
    }

    /// Streams `url` into `to`, returning its SHA-256 in hex.
    async fn file(&self, url: &str, to: &Path) -> Result<String, UpdateError> {
        let mut response = self.get(url).await?;
        let mut file = tokio::fs::File::create(to)
            .await
            .map_err(io(format!("creating {}", to.display())))?;
        let mut hash = Sha256::new();
        let mut size = 0u64;
        while let Some(chunk) = response.chunk().await.map_err(|e| UpdateError::Download {
            url: url.into(),
            reason: why(e),
        })? {
            size += chunk.len() as u64;
            if size > MAX_ARCHIVE {
                return Err(UpdateError::TooLarge {
                    url: url.into(),
                    limit: MAX_ARCHIVE,
                });
            }
            hash.update(&chunk);
            file.write_all(&chunk)
                .await
                .map_err(io(format!("writing {}", to.display())))?;
        }
        file.flush()
            .await
            .map_err(io(format!("writing {}", to.display())))?;
        Ok(hex::encode(hash.finalize()))
    }
}

/// Updates the binary at `installed`, which is `current`, as `opts` asks.
pub async fn update(
    opts: &Options,
    installed: &Path,
    current: &semver::Version,
) -> Result<Outcome, UpdateError> {
    let target = target().ok_or(UpdateError::UnsupportedPlatform {
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
    })?;
    if opts.require_signature && opts.cosign.is_none() {
        return Err(UpdateError::NoCosign);
    }
    let http = Http::new(opts)?;

    // The tag, unless a mirror only holds "the latest" files.
    let tag = match (&opts.wanted, &opts.mirror) {
        (Wanted::Release(tag), _) => Some(normalize_tag(tag)),
        (Wanted::Latest, None) => Some(http.latest_tag(opts).await?),
        (Wanted::Latest, Some(_)) => None,
    };
    if let (Some(tag), Wanted::Latest) = (&tag, &opts.wanted) {
        let latest = parse_tag(tag)?;
        if latest <= *current {
            return Ok(Outcome::UpToDate {
                current: current.clone(),
                latest,
            });
        }
        if opts.check_only {
            return Ok(Outcome::Available {
                current: current.clone(),
                latest,
            });
        }
    }
    let expected = tag.as_deref().map(parse_tag).transpose()?;
    let work = tempfile::tempdir().map_err(io("creating a temporary directory"))?;

    // Written next to the binary, so the final rename is atomic; failing
    // here, before any download, is the cheapest place to find out. A
    // check (a mirror's latest is only known once it runs) installs
    // nothing, so without write access there it uses a temporary
    // directory instead.
    let beside = installed.parent().unwrap_or(Path::new("."));
    let stage = |dir: &Path| {
        tempfile::Builder::new()
            .prefix(STAGED_PREFIX)
            .tempfile_in(dir)
    };
    let (staged, staged_in) = match stage(beside) {
        Ok(staged) => {
            remove_stale(beside);
            (staged, beside)
        }
        Err(_) if opts.check_only => (
            stage(work.path()).map_err(io("staging the download"))?,
            work.path(),
        ),
        Err(source) => {
            return Err(UpdateError::NotWritable {
                dir: beside.display().to_string(),
                binary: installed.display().to_string(),
                source,
            })
        }
    };

    // Without a mirror the tag is always known.
    let base = match &opts.mirror {
        Some(mirror) => mirror.trim_end_matches('/').to_string(),
        None => format!(
            "{}/{}/releases/download/{}",
            opts.github.trim_end_matches('/'),
            opts.repo,
            tag.as_deref().unwrap_or_default()
        ),
    };
    let asset = format!("tokenless-{target}.tar.gz");

    let sums_bytes = http.small(&format!("{base}/SHA256SUMS")).await?;
    let sums = String::from_utf8_lossy(&sums_bytes).into_owned();
    let expected_hash = checksum_for(&sums, &asset)
        .ok_or_else(|| UpdateError::NotInSums {
            asset: asset.clone(),
        })?
        .to_ascii_lowercase();

    let signature_verified = match &opts.cosign {
        Some(cosign) => {
            let sums_path = work.path().join("SHA256SUMS");
            std::fs::write(&sums_path, &sums_bytes).map_err(io("writing SHA256SUMS"))?;
            let bundle = work.path().join("SHA256SUMS.sigstore.json");
            let bytes = http
                .small(&format!("{base}/SHA256SUMS.sigstore.json"))
                .await?;
            std::fs::write(&bundle, bytes).map_err(io("writing the signature bundle"))?;
            verify_signature(cosign, &opts.repo, &sums_path, &bundle).await?;
            true
        }
        None => false,
    };

    let archive = work.path().join(&asset);
    let actual = http.file(&format!("{base}/{asset}"), &archive).await?;
    if actual != expected_hash {
        return Err(UpdateError::ChecksumMismatch {
            asset,
            expected: expected_hash,
            actual,
        });
    }

    unpack(&archive, &asset, target, staged.path())?;
    // Closed first: Linux refuses to run a file open for writing ("Text
    // file busy").
    let staged = staged.into_temp_path();
    let found = run_version(&staged, installed)
        .await
        .map_err(|e| match e {
            UpdateError::NewBinary { binary, reason } if staged_in != beside => {
                UpdateError::NewBinary {
                    binary,
                    reason: format!(
                        "{reason} (run from {}; if it is mounted noexec, set TMPDIR to a directory that allows running programs)",
                        staged_in.display()
                    ),
                }
            }
            other => other,
        })?;
    match &expected {
        Some(expected) if found != *expected => {
            return Err(UpdateError::VersionMismatch {
                tag: tag.unwrap_or_default(),
                expected: expected.clone(),
                found,
            });
        }
        // A mirror's "latest": known only now.
        None if found <= *current => {
            return Ok(Outcome::UpToDate {
                current: current.clone(),
                latest: found,
            });
        }
        _ => {}
    }
    if opts.check_only {
        return Ok(Outcome::Available {
            current: current.clone(),
            latest: found,
        });
    }
    staged.persist(installed).map_err(|e| UpdateError::Io {
        context: format!("replacing {}", installed.display()),
        source: e.error,
    })?;
    Ok(Outcome::Updated {
        path: installed.to_path_buf(),
        from: current.clone(),
        to: found,
        signature_verified,
    })
}

/// Removes what earlier updates, killed before they could clean up, staged
/// in `dir`. Best effort: a file that cannot be removed stays.
fn remove_stale(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if !entry
            .file_name()
            .to_string_lossy()
            .starts_with(STAGED_PREFIX)
        {
            continue;
        }
        let stale = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .is_some_and(|age| age > STALE_STAGED);
        if stale {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

async fn verify_signature(
    cosign: &Path,
    repo: &str,
    sums: &Path,
    bundle: &Path,
) -> Result<(), UpdateError> {
    let fail = |reason: String| UpdateError::Signature {
        repo: repo.into(),
        reason,
    };
    let identity = format!(
        "^https://github\\.com/{}/\\.github/workflows/release\\.yml@refs/tags/",
        repo.replace('.', "\\.")
    );
    let output = tokio::process::Command::new(cosign)
        .arg("verify-blob")
        .arg(sums)
        .arg("--bundle")
        .arg(bundle)
        .args(["--certificate-identity-regexp", &identity])
        .args([
            "--certificate-oidc-issuer",
            "https://token.actions.githubusercontent.com",
        ])
        .kill_on_drop(true)
        .output()
        .await
        .map_err(|e| fail(format!("running {}: {e}", cosign.display())))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(fail(stderr.trim().lines().last().unwrap_or("").to_string()))
    }
}

/// Writes `tokenless-<target>/tokenless` from the archive to `to`, mode 0755.
fn unpack(archive: &Path, asset: &str, target: &str, to: &Path) -> Result<(), UpdateError> {
    let fail = |reason: String| UpdateError::Archive {
        asset: asset.into(),
        reason,
    };
    let wanted = format!("tokenless-{target}/tokenless");
    let file = std::fs::File::open(archive).map_err(io(format!("opening {asset}")))?;
    let mut tar = tar::Archive::new(GzDecoder::new(file));
    let entries = tar.entries().map_err(|e| fail(e.to_string()))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| fail(e.to_string()))?;
        let path = entry.path().map_err(|e| fail(e.to_string()))?;
        if path.to_str() != Some(wanted.as_str()) {
            continue;
        }
        if !entry.header().entry_type().is_file() {
            return Err(fail(format!("{wanted} is not a regular file")));
        }
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(to)
            .map_err(io(format!("writing {}", to.display())))?;
        let written = std::io::copy(&mut (&mut entry).take(MAX_BINARY + 1), &mut out)
            .map_err(|e| fail(e.to_string()))?;
        if written > MAX_BINARY {
            return Err(fail(format!("{wanted} is larger than {MAX_BINARY} bytes")));
        }
        out.sync_all()
            .map_err(io(format!("writing {}", to.display())))?;
        set_executable(to)?;
        return Ok(());
    }
    Err(fail(format!("it holds no {wanted}")))
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<(), UpdateError> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .map_err(io(format!("making {} executable", path.display())))
}

#[cfg(not(unix))]
fn set_executable(_: &Path) -> Result<(), UpdateError> {
    Ok(())
}

/// Runs `staged --version`: the new binary must start on this machine and
/// say which version it is.
async fn run_version(staged: &Path, installed: &Path) -> Result<semver::Version, UpdateError> {
    let fail = |reason: String| UpdateError::NewBinary {
        binary: installed.display().to_string(),
        reason,
    };
    let run = async {
        // Linux refuses to run a file some process has open for writing.
        // Ours is closed, but a process forked by another thread in the
        // meantime holds a copy of a descriptor until it runs its own
        // program, which takes moments: try again a few times.
        let mut busy_wait = Duration::from_millis(20);
        loop {
            let run = tokio::process::Command::new(staged)
                .arg("--version")
                .kill_on_drop(true)
                .output()
                .await;
            match run {
                Err(e)
                    if e.kind() == std::io::ErrorKind::ExecutableFileBusy
                        && busy_wait < Duration::from_secs(2) =>
                {
                    tokio::time::sleep(busy_wait).await;
                    busy_wait *= 2;
                }
                run => return run,
            }
        }
    };
    let output = tokio::time::timeout(VERSION_TIMEOUT, run)
        .await
        .map_err(|_| {
            fail(format!(
                "--version gave no answer in {}s",
                VERSION_TIMEOUT.as_secs()
            ))
        })?
        .map_err(|e| fail(e.to_string()))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() {
        return Err(fail(format!("--version exited with {}", output.status)));
    }
    version_from_output(&stdout)
        .ok_or_else(|| fail(format!("--version printed {:?}", stdout.trim())))
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use axum::extract::{Path as UrlPath, State};
    use axum::http::{header, StatusCode};
    use axum::response::{IntoResponse, Response};
    use flate2::write::GzEncoder;

    #[test]
    fn tags_versions_and_checksums_are_read_as_released() {
        assert_eq!(parse_tag("v0.3.0").unwrap(), semver::Version::new(0, 3, 0));
        assert_eq!(parse_tag("0.3.0").unwrap(), semver::Version::new(0, 3, 0));
        assert!(matches!(
            parse_tag("latest"),
            Err(UpdateError::BadTag { .. })
        ));
        assert_eq!(normalize_tag("0.3.0"), "v0.3.0");
        assert_eq!(normalize_tag(" v0.3.0 "), "v0.3.0");
        assert_eq!(
            tag_from_location("https://github.com/o/r/releases/tag/v0.3.0"),
            Some("v0.3.0")
        );
        assert_eq!(tag_from_location("https://github.com/o/r/releases"), None);
        let sums = "aa11  tokenless-x86_64-apple-darwin.tar.gz\nbb22 *tokenless-aarch64-apple-darwin.tar.gz\n";
        assert_eq!(
            checksum_for(sums, "tokenless-x86_64-apple-darwin.tar.gz"),
            Some("aa11")
        );
        assert_eq!(
            checksum_for(sums, "tokenless-aarch64-apple-darwin.tar.gz"),
            Some("bb22")
        );
        assert_eq!(checksum_for(sums, "tokenless-aarch64-apple-darwin"), None);
        assert_eq!(
            version_from_output("tokenless 0.3.0\n"),
            Some(semver::Version::new(0, 3, 0))
        );
        assert_eq!(version_from_output("garbage"), None);
        assert!(target().is_some(), "tests run on a released platform");
    }

    /// A release served the way GitHub serves one.
    #[derive(Default)]
    struct Release {
        latest: Mutex<String>,
        files: Mutex<HashMap<String, Vec<u8>>>,
        archive_downloads: AtomicUsize,
    }

    async fn latest(State(r): State<Arc<Release>>) -> Response {
        let tag = r.latest.lock().unwrap().clone();
        (
            StatusCode::FOUND,
            [(
                header::LOCATION,
                format!("https://github.com/o/r/releases/tag/{tag}"),
            )],
        )
            .into_response()
    }

    async fn file(State(r): State<Arc<Release>>, UrlPath(path): UrlPath<String>) -> Response {
        let name = path.rsplit('/').next().unwrap_or_default().to_string();
        if name.ends_with(".tar.gz") {
            r.archive_downloads.fetch_add(1, Ordering::SeqCst);
        }
        match r.files.lock().unwrap().get(&name) {
            Some(bytes) => bytes.clone().into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        }
    }

    async fn serve(release: Arc<Release>) -> String {
        let app = axum::Router::new()
            .route("/o/r/releases/latest", axum::routing::get(latest))
            .route("/o/r/releases/download/{*path}", axum::routing::get(file))
            .route("/mirror/{*path}", axum::routing::get(file))
            .with_state(release);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await });
        format!("http://{addr}")
    }

    /// A release archive whose "binary" says it is `version`.
    fn archive(version: &str) -> Vec<u8> {
        let script = format!("#!/bin/sh\necho 'tokenless {version}'\n");
        let mut tar = tar::Builder::new(GzEncoder::new(Vec::new(), flate2::Compression::fast()));
        let mut header = tar::Header::new_gnu();
        header.set_size(script.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        let path = format!("tokenless-{}/tokenless", target().unwrap());
        tar.append_data(&mut header, path, script.as_bytes())
            .unwrap();
        tar.into_inner().unwrap().finish().unwrap()
    }

    fn asset() -> String {
        format!("tokenless-{}.tar.gz", target().unwrap())
    }

    /// Publishes `tag`, holding a binary that says `binary_version`.
    fn publish(release: &Release, tag: &str, binary_version: &str) {
        let bytes = archive(binary_version);
        let sums = format!("{}  {}\n", hex::encode(Sha256::digest(&bytes)), asset());
        *release.latest.lock().unwrap() = tag.into();
        let mut files = release.files.lock().unwrap();
        files.insert(asset(), bytes);
        files.insert("SHA256SUMS".into(), sums.into_bytes());
        files.insert("SHA256SUMS.sigstore.json".into(), b"{}".to_vec());
    }

    struct Installed {
        _dir: tempfile::TempDir,
        path: PathBuf,
    }

    impl Installed {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("tokenless");
            std::fs::write(&path, "the installed binary").unwrap();
            Self { _dir: dir, path }
        }

        fn contents(&self) -> String {
            std::fs::read_to_string(&self.path).unwrap()
        }

        /// Nothing staged is left next to the binary.
        fn leftovers(&self) -> Vec<String> {
            std::fs::read_dir(self.path.parent().unwrap())
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .filter(|n| n != "tokenless")
                .collect()
        }
    }

    fn options(github: &str) -> Options {
        Options {
            github: github.into(),
            ..Options::new("o/r".into())
        }
    }

    fn v(s: &str) -> semver::Version {
        semver::Version::parse(s).unwrap()
    }

    #[tokio::test]
    async fn a_newer_release_replaces_the_binary_after_its_checks() {
        let release = Arc::new(Release::default());
        publish(&release, "v9.9.9", "9.9.9");
        let base = serve(release.clone()).await;
        let installed = Installed::new();

        let outcome = update(&options(&base), &installed.path, &v("0.2.0"))
            .await
            .unwrap();
        assert_eq!(
            outcome,
            Outcome::Updated {
                path: installed.path.clone(),
                from: v("0.2.0"),
                to: v("9.9.9"),
                signature_verified: false,
            }
        );
        assert!(installed.contents().contains("tokenless 9.9.9"));
        let mode = std::fs::metadata(&installed.path)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755);
        assert_eq!(installed.leftovers(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn the_latest_release_or_an_older_one_downloads_nothing() {
        let release = Arc::new(Release::default());
        publish(&release, "v0.2.0", "0.2.0");
        let base = serve(release.clone()).await;
        let installed = Installed::new();

        let outcome = update(&options(&base), &installed.path, &v("0.2.0"))
            .await
            .unwrap();
        assert_eq!(
            outcome,
            Outcome::UpToDate {
                current: v("0.2.0"),
                latest: v("0.2.0")
            }
        );
        let outcome = update(&options(&base), &installed.path, &v("0.3.0-dev"))
            .await
            .unwrap();
        assert_eq!(
            outcome,
            Outcome::UpToDate {
                current: v("0.3.0-dev"),
                latest: v("0.2.0")
            }
        );
        assert_eq!(release.archive_downloads.load(Ordering::SeqCst), 0);
        assert_eq!(installed.contents(), "the installed binary");
    }

    #[tokio::test]
    async fn check_only_says_what_is_available_and_changes_nothing() {
        let release = Arc::new(Release::default());
        publish(&release, "v9.9.9", "9.9.9");
        let base = serve(release.clone()).await;
        let installed = Installed::new();
        let opts = Options {
            check_only: true,
            ..options(&base)
        };

        let outcome = update(&opts, &installed.path, &v("0.2.0")).await.unwrap();
        assert_eq!(
            outcome,
            Outcome::Available {
                current: v("0.2.0"),
                latest: v("9.9.9")
            }
        );
        assert_eq!(release.archive_downloads.load(Ordering::SeqCst), 0);
        assert_eq!(installed.contents(), "the installed binary");
    }

    #[tokio::test]
    async fn a_checksum_mismatch_installs_nothing() {
        let release = Arc::new(Release::default());
        publish(&release, "v9.9.9", "9.9.9");
        release.files.lock().unwrap().insert(
            "SHA256SUMS".into(),
            format!("{}  {}\n", "0".repeat(64), asset()).into_bytes(),
        );
        let base = serve(release).await;
        let installed = Installed::new();

        let err = update(&options(&base), &installed.path, &v("0.2.0"))
            .await
            .unwrap_err();
        assert!(matches!(err, UpdateError::ChecksumMismatch { .. }), "{err}");
        assert_eq!(installed.contents(), "the installed binary");
        assert_eq!(installed.leftovers(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn a_binary_that_is_not_the_tagged_version_is_not_installed() {
        let release = Arc::new(Release::default());
        publish(&release, "v9.9.9", "9.9.8");
        let base = serve(release).await;
        let installed = Installed::new();

        let err = update(&options(&base), &installed.path, &v("0.2.0"))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, UpdateError::VersionMismatch { found, .. } if *found == v("9.9.8")),
            "{err}"
        );
        assert_eq!(installed.contents(), "the installed binary");
    }

    #[tokio::test]
    async fn an_explicit_release_installs_even_an_older_one() {
        let release = Arc::new(Release::default());
        publish(&release, "v0.1.0", "0.1.0");
        *release.latest.lock().unwrap() = "v9.9.9".into();
        let base = serve(release).await;
        let installed = Installed::new();
        let opts = Options {
            wanted: Wanted::Release("0.1.0".into()),
            ..options(&base)
        };

        let outcome = update(&opts, &installed.path, &v("0.2.0")).await.unwrap();
        assert!(
            matches!(&outcome, Outcome::Updated { to, .. } if *to == v("0.1.0")),
            "{outcome:?}"
        );
    }

    #[tokio::test]
    async fn a_mirror_s_latest_is_known_once_downloaded() {
        let release = Arc::new(Release::default());
        publish(&release, "unused", "9.9.9");
        let base = serve(release.clone()).await;
        let installed = Installed::new();
        let opts = Options {
            mirror: Some(format!("{base}/mirror")),
            ..options("https://github.invalid")
        };

        let outcome = update(&opts, &installed.path, &v("9.9.9")).await.unwrap();
        assert_eq!(
            outcome,
            Outcome::UpToDate {
                current: v("9.9.9"),
                latest: v("9.9.9")
            }
        );
        assert_eq!(installed.contents(), "the installed binary");
        assert_eq!(installed.leftovers(), Vec::<String>::new());

        let outcome = update(&opts, &installed.path, &v("0.2.0")).await.unwrap();
        assert!(matches!(outcome, Outcome::Updated { .. }), "{outcome:?}");
    }

    #[tokio::test]
    async fn a_prerelease_installs_and_is_replaced_by_its_final_release() {
        // A release build reports its tag's version, suffix included.
        let release = Arc::new(Release::default());
        let base = serve(release.clone()).await;
        let installed = Installed::new();
        publish(&release, "v0.3.0-rc.1", "0.3.0-rc.1");
        let rc = Options {
            wanted: Wanted::Release("v0.3.0-rc.1".into()),
            ..options(&base)
        };
        let outcome = update(&rc, &installed.path, &v("0.2.0")).await.unwrap();
        assert!(
            matches!(&outcome, Outcome::Updated { to, .. } if *to == v("0.3.0-rc.1")),
            "{outcome:?}"
        );

        publish(&release, "v0.3.0", "0.3.0");
        let outcome = update(&options(&base), &installed.path, &v("0.3.0-rc.1"))
            .await
            .unwrap();
        assert!(
            matches!(&outcome, Outcome::Updated { to, .. } if *to == v("0.3.0")),
            "{outcome:?}"
        );
    }

    #[tokio::test]
    async fn a_ca_file_that_cannot_be_read_fails_before_any_request() {
        let release = Arc::new(Release::default());
        publish(&release, "v9.9.9", "9.9.9");
        let base = serve(release.clone()).await;
        let installed = Installed::new();
        let dir = tempfile::tempdir().unwrap();
        let not_pem = dir.path().join("ca.pem");
        std::fs::write(&not_pem, "not a certificate").unwrap();
        for ca in [dir.path().join("missing.pem"), not_pem] {
            let opts = Options {
                ca_file: Some(ca.clone()),
                ..options(&base)
            };
            let err = update(&opts, &installed.path, &v("0.2.0"))
                .await
                .unwrap_err();
            assert!(
                matches!(&err, UpdateError::Ca { path, .. } if *path == ca.display().to_string()),
                "{err}"
            );
        }
        assert_eq!(release.archive_downloads.load(Ordering::SeqCst), 0);
        assert_eq!(installed.contents(), "the installed binary");
    }

    #[tokio::test]
    async fn what_a_killed_update_staged_is_removed_once_it_is_an_hour_old() {
        let release = Arc::new(Release::default());
        publish(&release, "v9.9.9", "9.9.9");
        let base = serve(release.clone()).await;
        let installed = Installed::new();
        let dir = installed.path.parent().unwrap();
        let stale = dir.join(format!("{STAGED_PREFIX}stale"));
        let recent = dir.join(format!("{STAGED_PREFIX}recent"));
        std::fs::write(&stale, "a killed update's").unwrap();
        std::fs::write(&recent, "a running update's").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&stale)
            .unwrap()
            .set_modified(std::time::SystemTime::now() - Duration::from_secs(2 * 60 * 60))
            .unwrap();

        update(&options(&base), &installed.path, &v("0.2.0"))
            .await
            .unwrap();
        assert!(!stale.exists());
        assert!(recent.exists());
    }

    #[tokio::test]
    async fn checking_a_mirror_needs_no_write_access_to_the_binary_s_directory() {
        let release = Arc::new(Release::default());
        publish(&release, "unused", "9.9.9");
        let base = serve(release.clone()).await;
        let installed = Installed::new();
        let dir = installed.path.parent().unwrap().to_path_buf();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        let opts = Options {
            mirror: Some(format!("{base}/mirror")),
            check_only: true,
            ..options("https://github.invalid")
        };

        let newer = update(&opts, &installed.path, &v("0.2.0")).await;
        let same = update(&opts, &installed.path, &v("9.9.9")).await;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            newer.unwrap(),
            Outcome::Available {
                current: v("0.2.0"),
                latest: v("9.9.9")
            }
        );
        assert_eq!(
            same.unwrap(),
            Outcome::UpToDate {
                current: v("9.9.9"),
                latest: v("9.9.9")
            }
        );
        assert_eq!(installed.contents(), "the installed binary");
        assert_eq!(installed.leftovers(), Vec::<String>::new());
    }

    /// A stand-in for cosign that exits with `code` and prints `stderr`.
    fn fake_cosign(dir: &Path, code: i32, stderr: &str) -> PathBuf {
        let path = dir.join("cosign");
        std::fs::write(
            &path,
            format!("#!/bin/sh\necho '{stderr}' >&2\nexit {code}\n"),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[tokio::test]
    async fn the_signature_is_verified_with_cosign_when_it_is_installed() {
        let release = Arc::new(Release::default());
        publish(&release, "v9.9.9", "9.9.9");
        let base = serve(release.clone()).await;
        let tools = tempfile::tempdir().unwrap();

        let installed = Installed::new();
        let opts = Options {
            cosign: Some(fake_cosign(
                tools.path(),
                1,
                "error: no matching signatures",
            )),
            ..options(&base)
        };
        let err = update(&opts, &installed.path, &v("0.2.0"))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, UpdateError::Signature { reason, .. } if reason.contains("no matching signatures")),
            "{err}"
        );
        assert_eq!(installed.contents(), "the installed binary");
        assert_eq!(
            release.archive_downloads.load(Ordering::SeqCst),
            0,
            "checked before the download"
        );

        let opts = Options {
            cosign: Some(fake_cosign(tools.path(), 0, "Verified OK")),
            ..options(&base)
        };
        let outcome = update(&opts, &installed.path, &v("0.2.0")).await.unwrap();
        assert!(
            matches!(
                outcome,
                Outcome::Updated {
                    signature_verified: true,
                    ..
                }
            ),
            "{outcome:?}"
        );
    }

    #[tokio::test]
    async fn requiring_a_signature_without_cosign_fails_before_any_request() {
        let opts = Options {
            require_signature: true,
            ..options("http://127.0.0.1:1")
        };
        let installed = Installed::new();
        let err = update(&opts, &installed.path, &v("0.2.0"))
            .await
            .unwrap_err();
        assert!(matches!(err, UpdateError::NoCosign), "{err}");
    }

    #[tokio::test]
    async fn a_directory_it_cannot_write_is_said_before_downloading() {
        let release = Arc::new(Release::default());
        publish(&release, "v9.9.9", "9.9.9");
        let base = serve(release.clone()).await;
        let installed = Installed::new();
        let dir = installed.path.parent().unwrap().to_path_buf();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        // Root writes anywhere; nothing to check then.
        let writable = tempfile::tempfile_in(&dir).is_ok();

        let result = update(&options(&base), &installed.path, &v("0.2.0")).await;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        if writable {
            return;
        }
        let err = result.unwrap_err();
        assert!(matches!(err, UpdateError::NotWritable { .. }), "{err}");
        assert_eq!(release.archive_downloads.load(Ordering::SeqCst), 0);
    }
}
