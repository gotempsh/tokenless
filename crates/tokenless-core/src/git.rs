// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Git over HTTPS for named repositories: which smart HTTP requests clone,
//! fetch or push them.
//!
//! A rule with a [`GitScope`] lets a credential reach only these requests
//! for its repositories, on top of its hosts, paths and methods:
//!
//! | Request | Allows |
//! |---|---|
//! | `GET /<repo>/info/refs?service=git-upload-pack` | clone, fetch |
//! | `POST /<repo>/git-upload-pack` | clone, fetch |
//! | `GET /<repo>/info/refs?service=git-receive-pack` | push |
//! | `POST /<repo>/git-receive-pack` | push |
//!
//! `<repo>` is the repository's path with or without a `.git` suffix, which
//! name the same repository on GitHub and GitLab; compared without regard
//! to ASCII case, as they do. Everything else is refused: the dumb HTTP
//! protocol, Git LFS (its objects come from other hosts, through actions a
//! credential must not follow), any other query, a repeated or encoded
//! `service` parameter, a query on the RPCs and any percent-encoding in the
//! path. Pushing is refused already at discovery, before the client sends a
//! pack.

use serde::{Deserialize, Serialize};

use crate::error::CoreError;

/// Repositories one rule may hold.
pub const MAX_GIT_REPOSITORIES: usize = 100;
const MAX_SEGMENTS: usize = 20;
const MAX_SEGMENT_LEN: usize = 100;

/// Git smart HTTP to named repositories.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitScope {
    /// Repository paths on the host, such as `acme/widgets` or
    /// `group/subgroup/project`: lower-cased, without `.git`, sorted.
    pub repositories: Vec<String>,
    /// Pushing as well as cloning and fetching.
    #[serde(default)]
    pub push: bool,
}

/// What a smart HTTP request does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Service {
    /// Clone or fetch.
    UploadPack,
    Push,
}

impl GitScope {
    /// Checks and normalises the repositories: trimmed, without leading or
    /// trailing `/` or one trailing `.git`, lower-cased, sorted, without
    /// duplicates.
    pub fn new(repositories: Vec<String>, push: bool) -> Result<Self, CoreError> {
        let mut normal = Vec::with_capacity(repositories.len());
        for repository in repositories {
            let trimmed = repository.trim().trim_matches('/');
            let path = trimmed.strip_suffix(".git").unwrap_or(trimmed);
            let path = path.to_ascii_lowercase();
            check_repository(&path).map_err(|reason| invalid(&repository, reason))?;
            normal.push(path);
        }
        normal.sort();
        normal.dedup();
        let scope = Self {
            repositories: normal,
            push,
        };
        scope.validate()?;
        Ok(scope)
    }

    /// What [`GitScope::new`] guarantees, for a scope read back.
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.repositories.is_empty() || self.repositories.len() > MAX_GIT_REPOSITORIES {
            return Err(CoreError::InvalidGitScope {
                repository: String::new(),
                reason: format!(
                    "a Git scope needs 1-{MAX_GIT_REPOSITORIES} repositories, got {}",
                    self.repositories.len()
                ),
            });
        }
        for repository in &self.repositories {
            if repository.to_ascii_lowercase() != *repository {
                return Err(invalid(repository, "must be lower-case".into()));
            }
            check_repository(repository).map_err(|reason| invalid(repository, reason))?;
        }
        Ok(())
    }

    /// Whether this smart HTTP request is allowed. `path` must already
    /// have passed [`crate::path::check_request_path`]; `query` is the raw
    /// query, `None` without a `?`.
    pub fn allows(&self, method: &str, path: &str, query: Option<&str>) -> bool {
        let Some((repository, service)) = parse(method, path, query) else {
            return false;
        };
        if service == Service::Push && !self.push {
            return false;
        }
        self.repositories
            .iter()
            .any(|r| r.eq_ignore_ascii_case(repository))
    }

    /// True when `self` allows something `previous` did not.
    pub fn widens(&self, previous: &GitScope) -> bool {
        (self.push && !previous.push)
            || self
                .repositories
                .iter()
                .any(|r| !previous.repositories.contains(r))
    }
}

fn invalid(repository: &str, reason: String) -> CoreError {
    CoreError::InvalidGitScope {
        repository: repository.chars().take(200).collect(),
        reason,
    }
}

fn check_repository(path: &str) -> Result<(), String> {
    let segments: Vec<&str> = path.split('/').collect();
    if path.is_empty() || segments.len() < 2 || segments.len() > MAX_SEGMENTS {
        return Err(format!(
            "a repository is 2-{MAX_SEGMENTS} '/'-separated parts, like owner/name"
        ));
    }
    for segment in segments {
        let valid = !segment.is_empty()
            && segment.len() <= MAX_SEGMENT_LEN
            && segment != "."
            && segment != ".."
            && !segment.ends_with(".git")
            && segment
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
        if !valid {
            return Err(format!(
                "'{segment}' must be 1-{MAX_SEGMENT_LEN} letters, digits, '.', '_' or '-', not '.' or '..' and not ending in .git"
            ));
        }
    }
    Ok(())
}

/// The repository a smart HTTP request is for and what it does, if it is
/// one exactly.
fn parse<'a>(method: &str, path: &'a str, query: Option<&str>) -> Option<(&'a str, Service)> {
    if path.contains('%') {
        return None;
    }
    let (repo, service) = if method.eq_ignore_ascii_case("GET") {
        let repo = path.strip_suffix("/info/refs")?;
        let service = match query? {
            "service=git-upload-pack" => Service::UploadPack,
            "service=git-receive-pack" => Service::Push,
            _ => return None,
        };
        (repo, service)
    } else if method.eq_ignore_ascii_case("POST") && query.is_none() {
        if let Some(repo) = path.strip_suffix("/git-upload-pack") {
            (repo, Service::UploadPack)
        } else {
            (path.strip_suffix("/git-receive-pack")?, Service::Push)
        }
    } else {
        return None;
    };
    let repo = repo.strip_prefix('/')?;
    let repo = repo.strip_suffix(".git").unwrap_or(repo);
    check_repository(&repo.to_ascii_lowercase()).ok()?;
    Some((repo, service))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read() -> GitScope {
        GitScope::new(vec!["Acme/Widgets.git".into()], false).unwrap()
    }

    #[test]
    fn repositories_are_normalised_and_checked() {
        let s = GitScope::new(
            vec![
                " /acme/widgets/ ".into(),
                "acme/widgets.git".into(),
                "group/sub/project".into(),
            ],
            true,
        )
        .unwrap();
        assert_eq!(s.repositories, ["acme/widgets", "group/sub/project"]);
        for bad in [
            "",
            "widgets",
            "acme//widgets",
            "acme/../widgets",
            "acme/./widgets",
            "acme/wid gets",
            "acme/widgets.git.git",
            "acme/%77idgets",
            "acme/x.git/y",
        ] {
            assert!(GitScope::new(vec![bad.into()], false).is_err(), "{bad}");
        }
        assert!(GitScope::new(vec![], false).is_err());
        let too_many = (0..=MAX_GIT_REPOSITORIES)
            .map(|i| format!("acme/r{i}"))
            .collect();
        assert!(GitScope::new(too_many, false).is_err());
        let mut upper = read();
        upper.repositories = vec!["Acme/widgets".into()];
        assert!(upper.validate().is_err());
    }

    #[test]
    fn read_access_clones_and_fetches_its_repository_only() {
        let s = read();
        for (method, path, query) in [
            (
                "GET",
                "/acme/widgets.git/info/refs",
                Some("service=git-upload-pack"),
            ),
            (
                "GET",
                "/acme/widgets/info/refs",
                Some("service=git-upload-pack"),
            ),
            ("POST", "/acme/widgets.git/git-upload-pack", None),
            ("POST", "/ACME/Widgets/git-upload-pack", None),
        ] {
            assert!(s.allows(method, path, query), "{method} {path} {query:?}");
        }
        for (method, path, query) in [
            // Pushing, at discovery and at the RPC.
            (
                "GET",
                "/acme/widgets.git/info/refs",
                Some("service=git-receive-pack"),
            ),
            ("POST", "/acme/widgets.git/git-receive-pack", None),
            // Another repository, or a lookalike.
            (
                "GET",
                "/acme/other.git/info/refs",
                Some("service=git-upload-pack"),
            ),
            (
                "GET",
                "/acme/widgets.git.git/info/refs",
                Some("service=git-upload-pack"),
            ),
            (
                "GET",
                "/acme/widgets-x/info/refs",
                Some("service=git-upload-pack"),
            ),
            (
                "GET",
                "/acme/widgets/extra/info/refs",
                Some("service=git-upload-pack"),
            ),
            (
                "GET",
                "/x/acme/widgets/info/refs",
                Some("service=git-upload-pack"),
            ),
            // Ambiguous or encoded discovery.
            ("GET", "/acme/widgets.git/info/refs", None),
            ("GET", "/acme/widgets.git/info/refs", Some("")),
            (
                "GET",
                "/acme/widgets.git/info/refs",
                Some("service=git-upload-pack&service=git-receive-pack"),
            ),
            (
                "GET",
                "/acme/widgets.git/info/refs",
                Some("service=git-receive-pack&service=git-upload-pack"),
            ),
            (
                "GET",
                "/acme/widgets.git/info/refs",
                Some("service=git%2Dupload-pack"),
            ),
            (
                "GET",
                "/acme/widgets.git/info/refs",
                Some("Service=git-upload-pack"),
            ),
            (
                "GET",
                "/acme/widgets.git/info/refs",
                Some("service=git-upload-pack&x=1"),
            ),
            (
                "GET",
                "/acme/%77idgets.git/info/refs",
                Some("service=git-upload-pack"),
            ),
            // RPCs take no query; discovery is not a POST.
            ("POST", "/acme/widgets.git/git-upload-pack", Some("")),
            ("POST", "/acme/widgets.git/git-upload-pack", Some("x=1")),
            (
                "POST",
                "/acme/widgets.git/info/refs",
                Some("service=git-upload-pack"),
            ),
            ("PUT", "/acme/widgets.git/git-upload-pack", None),
            // Dumb HTTP and Git LFS.
            ("GET", "/acme/widgets.git/HEAD", None),
            ("GET", "/acme/widgets.git/objects/info/packs", None),
            ("POST", "/acme/widgets.git/info/lfs/objects/batch", None),
            ("GET", "/acme/widgets.git", None),
        ] {
            assert!(!s.allows(method, path, query), "{method} {path} {query:?}");
        }
    }

    #[test]
    fn push_access_pushes_and_widening_is_noticed() {
        let push = GitScope::new(vec!["acme/widgets".into()], true).unwrap();
        assert!(push.allows(
            "GET",
            "/acme/widgets.git/info/refs",
            Some("service=git-receive-pack")
        ));
        assert!(push.allows("POST", "/acme/widgets.git/git-receive-pack", None));
        let more = GitScope::new(vec!["acme/widgets".into(), "acme/other".into()], false).unwrap();
        assert!(push.widens(&read()));
        assert!(more.widens(&read()));
        assert!(!read().widens(&push));
        assert!(!read().widens(&more));
    }
}
