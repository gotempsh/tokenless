// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `tokenless status`: what is set up on this machine and the one command
//! to run next. It is the first thing to run, by a person or an agent,
//! before anything else is: every check that cannot pass says how to fix
//! it, and `--json` gives an agent the same answer to act on.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokenless_control::model::Node;

use super::trust::shell_word;

/// A proxy not heard from for this long is not serving agents (proxies
/// poll every few seconds); the console uses the same cut-off.
pub const CONNECTED_WITHIN: chrono::Duration = chrono::Duration::minutes(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Ok,
    /// Not set up yet; `fix` says how.
    Missing,
    /// Set up but not working; `fix` says how.
    Failed,
    /// Could not be checked, because an earlier check did not pass or the
    /// person may not see it.
    Unknown,
}

#[derive(Debug, Serialize)]
pub struct Check {
    pub id: &'static str,
    pub label: &'static str,
    pub state: State,
    pub detail: String,
    /// The command that fixes it.
    pub fix: Option<String>,
    /// Whether tokenless can work without it.
    pub required: bool,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub version: String,
    pub server: String,
    /// Every required check passed: agents can be started behind tokenless.
    pub ready: bool,
    /// This shell already runs behind tokenless (`TOKENLESS_PROXY` is set).
    pub behind_tokenless: bool,
    pub checks: Vec<Check>,
    /// The one command to run next.
    pub next: Option<String>,
}

/// What `status` found, before it is judged.
#[derive(Debug)]
pub struct Observed {
    pub version: String,
    pub server: String,
    /// Whether `--server` was left at its default, so fixes need not repeat it.
    pub default_server: bool,
    /// `Err` says why nothing answers.
    pub control_plane: Result<(), String>,
    /// `None` when it was not checked. `Ok(None)`: no saved session.
    pub signed_in: Option<Result<Option<String>, String>>,
    /// Vaults with their service count and bundle names.
    pub vaults: Option<Result<Vec<VaultSummary>, String>>,
    /// `Ok(None)`: this person may not see proxies.
    pub proxies: Option<Result<Option<Vec<Node>>, String>>,
    pub skill: Skill,
    pub behind_tokenless: bool,
    /// Where `proxy add` should write, or where an enrolled proxy's file is.
    pub proxy_state: ProxyStateFile,
    pub now: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct VaultSummary {
    pub name: String,
    pub services: u64,
    pub bundles: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skill {
    Installed,
    Missing,
    /// Claude Code is not set up here; other agents install it with `npx skills`.
    NoClaudeCode,
}

/// The proxy identity file `proxy add` writes and `node run` reads.
#[derive(Debug, Clone)]
pub struct ProxyStateFile {
    pub path: PathBuf,
    pub exists: bool,
}

impl ProxyStateFile {
    /// `~/.tokenless/node.json`, or `./node.json` when only that one exists
    /// (a proxy enrolled with the default before `status` suggested a path).
    pub fn find(home: Option<&Path>, cwd: &Path) -> Self {
        let preferred = home.map(|h| h.join(".tokenless").join("node.json"));
        let legacy = cwd.join("node.json");
        match preferred {
            Some(p) if p.is_file() => ProxyStateFile {
                path: tilde(&p, home),
                exists: true,
            },
            _ if legacy.is_file() => ProxyStateFile {
                path: PathBuf::from("./node.json"),
                exists: true,
            },
            Some(p) => ProxyStateFile {
                path: tilde(&p, home),
                exists: false,
            },
            None => ProxyStateFile {
                path: PathBuf::from("./node.json"),
                exists: false,
            },
        }
    }
}

/// `path` with the home directory written `~`, as people type it.
fn tilde(path: &Path, home: Option<&Path>) -> PathBuf {
    match home.and_then(|h| path.strip_prefix(h).ok()) {
        Some(rest) => Path::new("~").join(rest),
        None => path.to_path_buf(),
    }
}

/// Whether `node` serves agents now.
pub fn connected(node: &Node, now: DateTime<Utc>) -> bool {
    node.revoked_at.is_none()
        && node.cert_not_after > now
        && node
            .last_seen_at
            .is_some_and(|seen| now - seen <= CONNECTED_WITHIN)
}

/// The vault and bundle to suggest: the first vault with a service and a
/// bundle, then any vault with a service.
fn suggested(vaults: &[VaultSummary]) -> (String, String) {
    let with_services = || vaults.iter().filter(|v| v.services > 0);
    let (vault, bundle) = with_services()
        .find_map(|v| v.bundles.first().map(|b| (v.name.as_str(), b.as_str())))
        .or_else(|| {
            with_services()
                .next()
                .map(|v| (v.name.as_str(), "my-agent"))
        })
        .unwrap_or(("personal", "my-agent"));
    // Both go into commands an agent runs as they are; a vault name may
    // hold a space.
    (shell_word(vault), shell_word(bundle))
}

pub fn assess(o: Observed) -> Report {
    let server_flag = if o.default_server {
        String::new()
    } else {
        format!(" --server {}", o.server)
    };
    let mut checks = Vec::new();

    let up = o.control_plane.is_ok();
    checks.push(match &o.control_plane {
        Ok(()) => Check {
            id: "control_plane",
            label: "Control plane",
            state: State::Ok,
            detail: format!("answers at {}", o.server),
            fix: None,
            required: true,
        },
        Err(why) => Check {
            id: "control_plane",
            label: "Control plane",
            state: State::Failed,
            detail: format!("none at {}: {why}", o.server),
            fix: Some(if o.default_server {
                "tokenless serve --data-dir ~/.tokenless".into()
            } else {
                format!("start the control plane at {}, or pass --server", o.server)
            }),
            required: true,
        },
    });

    let signed_in = matches!(o.signed_in, Some(Ok(Some(_))));
    checks.push(match &o.signed_in {
        Some(Ok(Some(user))) => ok("signed_in", "Signed in", format!("as {user}")),
        Some(Ok(None)) => Check {
            id: "signed_in",
            label: "Signed in",
            state: State::Missing,
            detail: "no saved session for this control plane".into(),
            fix: Some(format!("tokenless login{server_flag}")),
            required: true,
        },
        Some(Err(why)) => Check {
            id: "signed_in",
            label: "Signed in",
            state: State::Failed,
            detail: why.clone(),
            fix: Some(format!("tokenless login{server_flag}")),
            required: true,
        },
        None => unknown("signed_in", "Signed in", up, true),
    });

    let vaults = match &o.vaults {
        Some(Ok(v)) => v.clone(),
        _ => Vec::new(),
    };
    let (vault, bundle) = suggested(&vaults);
    checks.push(match &o.vaults {
        Some(Ok(v)) if v.iter().any(|v| v.services > 0) => {
            let services: u64 = v.iter().map(|v| v.services).sum();
            let in_vaults = v.iter().filter(|v| v.services > 0).count();
            ok(
                "services",
                "Services",
                format!(
                    "{services} {} in {in_vaults} {}",
                    plural(services, "service", "services"),
                    plural(in_vaults as u64, "vault", "vaults")
                ),
            )
        }
        Some(Ok(_)) => Check {
            id: "services",
            label: "Services",
            state: State::Missing,
            detail: "none yet; find the template with: tokenless service templates <name or variable>".into(),
            fix: Some(format!(
                "tokenless service add <template> --vault {vault} --bundle {bundle} --secret-file{server_flag}"
            )),
            required: true,
        },
        Some(Err(why)) => Check {
            id: "services",
            label: "Services",
            state: State::Unknown,
            detail: why.clone(),
            fix: None,
            required: true,
        },
        None => unknown("services", "Services", signed_in, true),
    });

    let state = o.proxy_state.path.display().to_string();
    checks.push(match &o.proxies {
        Some(Ok(Some(nodes))) => {
            let active: Vec<&Node> = nodes.iter().filter(|n| n.revoked_at.is_none()).collect();
            let live: Vec<&str> = active
                .iter()
                .filter(|n| connected(n, o.now))
                .map(|n| n.name.as_str())
                .collect();
            if !live.is_empty() {
                ok("proxy", "Proxy", format!("{} connected", live.join(", ")))
            } else if active.is_empty() {
                Check {
                    id: "proxy",
                    label: "Proxy",
                    state: State::Missing,
                    detail: "none enrolled".into(),
                    fix: Some(format!(
                        "tokenless proxy add --name <this machine> --state {state}{server_flag}"
                    )),
                    required: true,
                }
            } else {
                let names: Vec<&str> = active.iter().map(|n| n.name.as_str()).collect();
                Check {
                    id: "proxy",
                    label: "Proxy",
                    state: State::Failed,
                    detail: format!("{} enrolled, none connected", names.join(", ")),
                    fix: Some(if o.proxy_state.exists {
                        format!("tokenless node run --state {state}")
                    } else {
                        "tokenless node run --state <the file proxy add wrote>".into()
                    }),
                    required: true,
                }
            }
        }
        Some(Ok(None)) => Check {
            id: "proxy",
            label: "Proxy",
            state: State::Unknown,
            detail: "only an admin can see proxies".into(),
            fix: None,
            required: true,
        },
        // The list could not be read, so nothing says a proxy serves agents.
        Some(Err(why)) => Check {
            id: "proxy",
            label: "Proxy",
            state: State::Failed,
            detail: format!("could not list proxies: {why}"),
            fix: None,
            required: true,
        },
        None => unknown("proxy", "Proxy", signed_in, true),
    });

    checks.push(match o.skill {
        Skill::Installed => ok("skill", "Agent skill", "installed for Claude Code".into()),
        Skill::Missing => Check {
            id: "skill",
            label: "Agent skill",
            state: State::Missing,
            detail: "not installed for Claude Code".into(),
            fix: Some("tokenless skill --install".into()),
            required: false,
        },
        Skill::NoClaudeCode => Check {
            id: "skill",
            label: "Agent skill",
            state: State::Unknown,
            detail:
                "no Claude Code here; other agents get it with: npx skills add gotempsh/tokenless"
                    .into(),
            fix: None,
            required: false,
        },
    });

    // Only a check that could have passed counts against ready: the proxy
    // check is unknown when the person may not see proxies (a 403), and that
    // does not. A failure to list them is `Failed` and does.
    let ready = checks.iter().filter(|c| c.required).all(|c| {
        c.state == State::Ok || (c.state == State::Unknown && c.id == "proxy" && signed_in)
    });
    let next = checks
        .iter()
        .find(|c| c.required && c.fix.is_some())
        .or_else(|| checks.iter().find(|c| c.fix.is_some()))
        .and_then(|c| c.fix.clone())
        .or_else(|| {
            (ready && !o.behind_tokenless)
                .then(|| format!("tokenless run --vault {vault} --bundle {bundle} -- <command>"))
        });
    Report {
        version: o.version,
        server: o.server,
        ready,
        behind_tokenless: o.behind_tokenless,
        checks,
        next,
    }
}

fn ok(id: &'static str, label: &'static str, detail: String) -> Check {
    Check {
        id,
        label,
        state: State::Ok,
        detail,
        fix: None,
        required: true,
    }
}

fn unknown(id: &'static str, label: &'static str, earlier_passed: bool, required: bool) -> Check {
    Check {
        id,
        label,
        state: State::Unknown,
        detail: if earlier_passed {
            "not checked".into()
        } else {
            "not checked until the step above passes".into()
        },
        fix: None,
        required,
    }
}

fn plural(n: u64, one: &'static str, many: &'static str) -> &'static str {
    if n == 1 {
        one
    } else {
        many
    }
}

/// The report as `status` prints it for people.
pub fn render(report: &Report) -> String {
    let width = report
        .checks
        .iter()
        .map(|c| c.label.len())
        .max()
        .unwrap_or(0);
    let mut out = format!("tokenless {}\n\n", report.version);
    for check in &report.checks {
        let mark = match check.state {
            State::Ok => "ok",
            State::Missing => "--",
            State::Failed => "!!",
            State::Unknown => "??",
        };
        out.push_str(&format!(
            "  {mark}  {:width$}  {}\n",
            check.label, check.detail
        ));
    }
    out.push('\n');
    if report.behind_tokenless {
        out.push_str(
            "This shell runs behind tokenless: tokenless session info shows what it reaches.\n",
        );
    }
    match &report.next {
        Some(next) if report.ready => {
            out.push_str(&format!("Ready. Start an agent with:\n  {next}\n"))
        }
        Some(next) => out.push_str(&format!("Next:\n  {next}\n")),
        None if report.ready => out.push_str("Ready.\n"),
        None => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str, seen_ago: Option<i64>, now: DateTime<Utc>) -> Node {
        serde_json::from_value(serde_json::json!({
            "id": "00000000-0000-4000-8000-000000000001",
            "name": name,
            "seal_public_key": "",
            "cert_serial": "1",
            "cert_not_after": now + chrono::Duration::days(30),
            "enrolled_at": now - chrono::Duration::days(1),
            "last_seen_at": seen_ago.map(|s| now - chrono::Duration::seconds(s)),
            "revoked_at": null,
        }))
        .unwrap()
    }

    fn observed(now: DateTime<Utc>) -> Observed {
        Observed {
            version: "0.3.0".into(),
            server: "http://127.0.0.1:8080".into(),
            default_server: true,
            control_plane: Ok(()),
            signed_in: Some(Ok(Some("admin".into()))),
            vaults: Some(Ok(vec![VaultSummary {
                name: "work".into(),
                services: 2,
                bundles: vec!["code-review".into()],
            }])),
            proxies: Some(Ok(Some(vec![node("laptop", Some(5), now)]))),
            skill: Skill::Installed,
            behind_tokenless: false,
            proxy_state: ProxyStateFile {
                path: "~/.tokenless/node.json".into(),
                exists: true,
            },
            now,
        }
    }

    fn check<'a>(report: &'a Report, id: &str) -> &'a Check {
        report.checks.iter().find(|c| c.id == id).unwrap()
    }

    #[test]
    fn a_working_setup_is_ready_and_says_how_to_start_an_agent() {
        let now = Utc::now();
        let report = assess(observed(now));
        assert!(report.ready, "{report:#?}");
        assert!(
            report.checks.iter().all(|c| c.state == State::Ok),
            "{report:#?}"
        );
        assert_eq!(
            report.next.as_deref(),
            Some("tokenless run --vault work --bundle code-review -- <command>")
        );
        assert_eq!(check(&report, "services").detail, "2 services in 1 vault");
        let text = render(&report);
        assert!(
            text.contains("ok  Proxy          laptop connected"),
            "{text}"
        );
        assert!(text.contains("Ready. Start an agent with:"), "{text}");
    }

    #[test]
    fn nothing_running_says_to_start_the_control_plane_first() {
        let now = Utc::now();
        let report = assess(Observed {
            control_plane: Err("nothing is listening there".into()),
            signed_in: None,
            vaults: None,
            proxies: None,
            skill: Skill::Missing,
            ..observed(now)
        });
        assert!(!report.ready);
        assert_eq!(
            report.next.as_deref(),
            Some("tokenless serve --data-dir ~/.tokenless")
        );
        assert_eq!(check(&report, "signed_in").state, State::Unknown);
        assert_eq!(
            check(&report, "proxy").detail,
            "not checked until the step above passes"
        );
    }

    #[test]
    fn each_missing_step_names_its_command_in_order() {
        let now = Utc::now();
        let signed_out = assess(Observed {
            signed_in: Some(Ok(None)),
            vaults: None,
            proxies: None,
            default_server: false,
            server: "https://tokenless.internal".into(),
            ..observed(now)
        });
        assert_eq!(
            signed_out.next.as_deref(),
            Some("tokenless login --server https://tokenless.internal")
        );
        let empty = assess(Observed {
            vaults: Some(Ok(vec![])),
            proxies: Some(Ok(Some(vec![]))),
            ..observed(now)
        });
        assert_eq!(
            empty.next.as_deref(),
            Some(
                "tokenless service add <template> --vault personal --bundle my-agent --secret-file"
            )
        );
        assert_eq!(
            check(&empty, "proxy").fix.as_deref(),
            Some("tokenless proxy add --name <this machine> --state ~/.tokenless/node.json")
        );
    }

    #[test]
    fn an_enrolled_proxy_that_stopped_says_to_run_it() {
        let now = Utc::now();
        let report = assess(Observed {
            proxies: Some(Ok(Some(vec![
                node("laptop", Some(600), now),
                node("ci", None, now),
            ]))),
            ..observed(now)
        });
        assert!(!report.ready);
        let proxy = check(&report, "proxy");
        assert_eq!(proxy.state, State::Failed);
        assert_eq!(proxy.detail, "laptop, ci enrolled, none connected");
        assert_eq!(
            report.next.as_deref(),
            Some("tokenless node run --state ~/.tokenless/node.json")
        );
    }

    #[test]
    fn what_a_person_may_not_see_or_does_not_need_does_not_block_ready() {
        let now = Utc::now();
        let report = assess(Observed {
            proxies: Some(Ok(None)),
            skill: Skill::Missing,
            ..observed(now)
        });
        assert!(report.ready, "{report:#?}");
        // The missing skill is still the next thing to do.
        assert_eq!(report.next.as_deref(), Some("tokenless skill --install"));
        let behind = assess(Observed {
            behind_tokenless: true,
            ..observed(now)
        });
        assert!(behind.ready);
        assert_eq!(behind.next, None);
        assert!(render(&behind).contains("This shell runs behind tokenless"));
    }

    #[test]
    fn a_vault_name_with_a_space_is_quoted_in_the_next_command() {
        let now = Utc::now();
        let report = assess(Observed {
            vaults: Some(Ok(vec![VaultSummary {
                name: "Work stuff".into(),
                services: 1,
                bundles: vec!["code-review".into()],
            }])),
            ..observed(now)
        });
        assert_eq!(
            report.next.as_deref(),
            Some("tokenless run --vault 'Work stuff' --bundle code-review -- <command>")
        );
    }

    #[test]
    fn a_proxy_list_that_failed_is_not_ready() {
        let now = Utc::now();
        let report = assess(Observed {
            proxies: Some(Err(
                "request to /api/v1/nodes failed: connection reset".into()
            )),
            ..observed(now)
        });
        assert!(!report.ready, "{report:#?}");
        let proxy = check(&report, "proxy");
        assert_eq!(proxy.state, State::Failed);
        assert!(proxy.detail.contains("could not list proxies"), "{proxy:?}");
    }

    #[test]
    fn the_proxy_file_is_looked_for_in_home_then_here() {
        let home = tempfile::tempdir().unwrap();
        let here = tempfile::tempdir().unwrap();
        let fresh = ProxyStateFile::find(Some(home.path()), here.path());
        assert_eq!(fresh.path, PathBuf::from("~/.tokenless/node.json"));
        assert!(!fresh.exists);
        std::fs::write(here.path().join("node.json"), "{}").unwrap();
        let legacy = ProxyStateFile::find(Some(home.path()), here.path());
        assert_eq!(legacy.path, PathBuf::from("./node.json"));
        assert!(legacy.exists);
        std::fs::create_dir(home.path().join(".tokenless")).unwrap();
        std::fs::write(home.path().join(".tokenless/node.json"), "{}").unwrap();
        let preferred = ProxyStateFile::find(Some(home.path()), here.path());
        assert_eq!(preferred.path, PathBuf::from("~/.tokenless/node.json"));
        assert!(preferred.exists);
    }
}
