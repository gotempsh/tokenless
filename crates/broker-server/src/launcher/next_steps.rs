// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! What `service add` and `service test` say comes next: a short checklist
//! from "service added" to "an agent is using it", built from what is true
//! now. Each step is done or not, and one that is not names the command or
//! the console page that fixes it.

use serde::Serialize;
use tokenless_control::model::{CredentialTest, TestOutcome};
use tokenless_core::substitution::Substitution;

use super::trust::shell_word;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepState {
    Done,
    Pending,
    /// Could not be checked by this person (proxies are an admin's to see).
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct Step {
    pub id: &'static str,
    pub label: &'static str,
    pub state: StepState,
    pub detail: String,
    /// The command that does it, filled in.
    pub fix: Option<String>,
    /// The console page that does it.
    pub link: Option<String>,
}

/// Whether a proxy serves agents, as far as this person can see.
#[derive(Debug, Clone)]
pub enum ProxySeen {
    Connected(Vec<String>),
    /// Enrolled, none connected.
    Idle(Vec<String>),
    None,
    /// Not this person's to see, or the list could not be read.
    Unknown(String),
}

/// What the checklist is built from.
#[derive(Debug, Clone)]
pub struct Facts<'a> {
    /// The management API, for console links.
    pub server: &'a str,
    pub service: &'a str,
    pub credential_id: &'a str,
    pub vault: &'a str,
    pub vault_id: &'a str,
    pub bundle: Option<&'a str>,
    pub test: Option<&'a CredentialTest>,
    pub proxy: ProxySeen,
    /// Where `node run` finds this machine's proxy.
    pub proxy_state: &'a str,
    /// Whether that file is there: a proxy enrolled elsewhere is started
    /// on its own machine.
    pub proxy_state_exists: bool,
    /// ` --server <url>` for a control plane other than the default, so
    /// the commands act on the one that was used; empty otherwise.
    pub server_flag: &'a str,
    /// The variable tools read the key from, such as `OPENAI_API_KEY`.
    pub variable: Option<&'a str>,
    pub substitutions: &'a [Substitution],
}

#[derive(Debug, Clone, Serialize)]
pub struct NextSteps {
    pub steps: Vec<Step>,
    /// A command behind the bundle, when there is one.
    pub run: Option<String>,
    /// An agent behind the bundle.
    pub agent: Option<String>,
    /// What to give a tool that insists on a key.
    pub key: Option<String>,
}

/// The console page for one service.
pub fn service_link(server: &str, vault_id: &str, credential_id: &str) -> String {
    format!("{server}/#/vaults/{vault_id}/services/{credential_id}")
}

/// How a test went, in one line.
pub fn test_line(test: Option<&CredentialTest>) -> String {
    test.map_or_else(|| "not tested yet".into(), |t| t.detail.clone())
}

pub fn build(f: &Facts<'_>) -> NextSteps {
    let mut steps = Vec::new();
    let test_cmd = format!(
        "tokenless service test {} --vault {}{}",
        shell_word(f.service),
        shell_word(f.vault),
        f.server_flag
    );
    let service_page = service_link(f.server, f.vault_id, f.credential_id);
    steps.push(match f.test {
        Some(t) if t.outcome == TestOutcome::Accepted => Step {
            id: "tested",
            label: "Credential tested",
            state: StepState::Done,
            detail: t.detail.clone(),
            fix: None,
            link: None,
        },
        Some(t) => Step {
            id: "tested",
            label: "Credential tested",
            state: StepState::Pending,
            detail: t.detail.clone(),
            fix: match t.outcome {
                // Testing again would not change anything.
                TestOutcome::NoProbe | TestOutcome::Unavailable => None,
                _ => Some(test_cmd.clone()),
            },
            link: match t.outcome {
                TestOutcome::Rejected => Some(service_page.clone()),
                TestOutcome::Blocked => Some(format!("{}/#/settings", f.server)),
                _ => None,
            },
        },
        None => Step {
            id: "tested",
            label: "Credential tested",
            state: StepState::Pending,
            detail: "not tested yet".into(),
            fix: Some(test_cmd.clone()),
            link: None,
        },
    });
    steps.push(match f.bundle {
        Some(b) => Step {
            id: "bundle",
            label: "In an access bundle",
            state: StepState::Done,
            detail: format!("in {b}"),
            fix: None,
            link: None,
        },
        None => Step {
            id: "bundle",
            label: "In an access bundle",
            state: StepState::Pending,
            detail: "agents start from a bundle; tick this service in one".into(),
            fix: None,
            link: Some(format!(
                "{}/#/bundles/new?vault={}&back=vaults/{}/bundles",
                f.server, f.vault_id, f.vault_id
            )),
        },
    });
    steps.push(match &f.proxy {
        ProxySeen::Connected(names) => Step {
            id: "proxy",
            label: "Proxy connected",
            state: StepState::Done,
            detail: format!("{} connected", names.join(", ")),
            fix: None,
            link: None,
        },
        ProxySeen::Idle(names) if f.proxy_state_exists => Step {
            id: "proxy",
            label: "Proxy connected",
            state: StepState::Pending,
            detail: format!("{} enrolled, none connected", names.join(", ")),
            fix: Some(format!("tokenless node run --state {}", f.proxy_state)),
            link: None,
        },
        ProxySeen::Idle(names) => Step {
            id: "proxy",
            label: "Proxy connected",
            state: StepState::Pending,
            detail: format!(
                "{} enrolled, none connected; start it where it was enrolled: tokenless node run --state <its identity file>",
                names.join(", ")
            ),
            fix: None,
            link: None,
        },
        ProxySeen::None => Step {
            id: "proxy",
            label: "Proxy connected",
            state: StepState::Pending,
            detail: "no proxy enrolled".into(),
            fix: Some(format!(
                "tokenless proxy add --name <this machine> --state {state}{} && tokenless node run --state {state}",
                f.server_flag,
                state = f.proxy_state
            )),
            link: None,
        },
        ProxySeen::Unknown(why) => Step {
            id: "proxy",
            label: "Proxy connected",
            state: StepState::Unknown,
            detail: why.clone(),
            fix: Some(format!("tokenless status{}", f.server_flag)),
            link: None,
        },
    });
    let (run, agent) = match f.bundle {
        Some(b) => {
            let base = format!(
                "tokenless run --vault {} --bundle {}{}",
                shell_word(f.vault),
                shell_word(b),
                f.server_flag
            );
            (
                Some(format!("{base} -- <command>")),
                Some(format!("{base} -- claude")),
            )
        }
        None => (None, None),
    };
    let key = key_hint(f.variable, f.substitutions);
    // A test only tells; an untested key can still be used. What an agent
    // needs is the bundle and a proxy.
    let ready = steps
        .iter()
        .filter(|s| s.id != "tested")
        .all(|s| s.state == StepState::Done);
    steps.push(Step {
        id: "use",
        label: "Start an agent behind it",
        state: StepState::Pending,
        detail: match (&agent, ready) {
            (Some(_), true) => "ready".into(),
            (Some(_), false) => "once the steps above are done".into(),
            (None, _) => "once it is in an access bundle".into(),
        },
        fix: agent.clone(),
        link: None,
    });
    NextSteps {
        steps,
        run,
        agent,
        key,
    }
}

/// What to give a tool that will not start without the key: the
/// placeholder when the service has one with a variable, else any dummy.
fn key_hint(variable: Option<&str>, substitutions: &[Substitution]) -> Option<String> {
    if let Some(s) = substitutions.iter().find(|s| s.env.is_some()) {
        let env = s.env.as_deref().unwrap_or_default();
        return Some(format!(
            "{env} is set to {} for you; the proxy swaps in the key",
            s.placeholder
        ));
    }
    if let Some(s) = substitutions.first() {
        return Some(format!(
            "send {} where the key goes; the proxy swaps in the key",
            s.placeholder
        ));
    }
    variable.map(|v| {
        format!("a tool that insists on {v} gets any dummy value ({v}=tokenless); the proxy puts the key in")
    })
}

/// The checklist for people: one line per step, the fix under it.
pub fn render(steps: &NextSteps) -> String {
    let mut out = String::from("next steps:\n");
    for s in &steps.steps {
        let mark = match s.state {
            StepState::Done => "[x]",
            StepState::Pending => "[ ]",
            StepState::Unknown => "[?]",
        };
        out.push_str(&format!("  {mark} {}: {}\n", s.label, s.detail));
        if s.state != StepState::Done {
            if let Some(fix) = &s.fix {
                out.push_str(&format!("      {fix}\n"));
            }
            if let Some(link) = &s.link {
                out.push_str(&format!("      {link}\n"));
            }
        }
    }
    if let Some(run) = &steps.run {
        out.push_str(&format!("  a single command: {run}\n"));
    }
    if let Some(key) = &steps.key {
        out.push_str(&format!("  {key}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use tokenless_core::substitution::SubstitutionLocation;

    use super::*;

    fn test(outcome: TestOutcome, status: Option<u16>, detail: &str) -> CredentialTest {
        CredentialTest {
            outcome,
            ok: outcome == TestOutcome::Accepted,
            host: Some("api.openai.com".into()),
            method: Some("GET".into()),
            path: Some("/v1/models".into()),
            status,
            detail: detail.into(),
            retry_after_secs: None,
            tested_at: Utc::now(),
            tested_by: "user:someone".into(),
        }
    }

    fn facts<'a>(
        test: Option<&'a CredentialTest>,
        bundle: Option<&'a str>,
        proxy: ProxySeen,
    ) -> Facts<'a> {
        Facts {
            server: "http://127.0.0.1:8080",
            service: "openai",
            credential_id: "c1",
            vault: "personal",
            vault_id: "v1",
            bundle,
            test,
            proxy,
            proxy_state: "~/.tokenless/node.json",
            proxy_state_exists: true,
            server_flag: "",
            variable: Some("OPENAI_API_KEY"),
            substitutions: &[],
        }
    }

    fn state(steps: &NextSteps, id: &str) -> StepState {
        steps.steps.iter().find(|s| s.id == id).unwrap().state
    }

    #[test]
    fn everything_in_place_is_ticked_and_names_the_real_vault_and_bundle() {
        let t = test(
            TestOutcome::Accepted,
            Some(200),
            "api.openai.com accepted the credential (200)",
        );
        let steps = build(&facts(
            Some(&t),
            Some("my-agent"),
            ProxySeen::Connected(vec!["built-in".into()]),
        ));
        for id in ["tested", "bundle", "proxy"] {
            assert_eq!(state(&steps, id), StepState::Done, "{id}");
        }
        assert_eq!(
            steps.run.as_deref(),
            Some("tokenless run --vault personal --bundle my-agent -- <command>")
        );
        assert_eq!(
            steps.agent.as_deref(),
            Some("tokenless run --vault personal --bundle my-agent -- claude")
        );
        assert!(steps
            .key
            .as_deref()
            .unwrap()
            .contains("OPENAI_API_KEY=tokenless"));
        let text = render(&steps);
        assert!(text.lines().count() <= 8, "{text}");
        assert!(text.contains("[x] Credential tested"));
    }

    #[test]
    fn what_is_missing_links_to_its_fix() {
        let t = test(
            TestOutcome::Rejected,
            Some(401),
            "api.openai.com rejected the credential (401)",
        );
        let steps = build(&facts(
            Some(&t),
            None,
            ProxySeen::Idle(vec!["laptop".into()]),
        ));
        let tested = &steps.steps[0];
        assert_eq!(tested.state, StepState::Pending);
        assert_eq!(
            tested.fix.as_deref(),
            Some("tokenless service test openai --vault personal")
        );
        assert_eq!(
            tested.link.as_deref(),
            Some("http://127.0.0.1:8080/#/vaults/v1/services/c1")
        );
        let bundle = &steps.steps[1];
        assert_eq!(bundle.state, StepState::Pending);
        assert!(bundle
            .link
            .as_deref()
            .unwrap()
            .contains("#/bundles/new?vault=v1"));
        let proxy = &steps.steps[2];
        assert_eq!(
            proxy.fix.as_deref(),
            Some("tokenless node run --state ~/.tokenless/node.json")
        );
        assert!(steps.run.is_none() && steps.agent.is_none());
        assert_eq!(steps.steps[3].detail, "once it is in an access bundle");
    }

    #[test]
    fn a_service_with_no_test_is_never_ticked_and_not_retested() {
        let t = test(
            TestOutcome::NoProbe,
            None,
            "not tested: no test request defined for this service",
        );
        let steps = build(&facts(Some(&t), Some("b"), ProxySeen::None));
        assert_eq!(steps.steps[0].state, StepState::Pending);
        assert_eq!(steps.steps[0].fix, None);
        assert!(steps.steps[0].detail.starts_with("not tested"));
        assert!(steps.steps[2]
            .fix
            .as_deref()
            .unwrap()
            .starts_with("tokenless proxy add"));
        let blocked = test(TestOutcome::Blocked, None, "blocked");
        let steps = build(&facts(
            Some(&blocked),
            Some("b"),
            ProxySeen::Unknown("only an admin can see proxies".into()),
        ));
        assert_eq!(
            steps.steps[0].link.as_deref(),
            Some("http://127.0.0.1:8080/#/settings")
        );
        assert_eq!(steps.steps[2].state, StepState::Unknown);
    }

    /// An untested key can still be used: with a bundle and a proxy, the
    /// agent is ready to start whatever the test said.
    #[test]
    fn a_test_is_never_what_stands_between_a_service_and_an_agent() {
        let t = test(TestOutcome::NoProbe, None, "not tested: no test request");
        let connected = ProxySeen::Connected(vec!["laptop".into()]);
        let steps = build(&facts(Some(&t), Some("b"), connected.clone()));
        assert_eq!(steps.steps[3].detail, "ready");
        let steps = build(&facts(None, Some("b"), connected));
        assert_eq!(steps.steps[3].detail, "ready");
    }

    #[test]
    fn a_proxy_is_enrolled_and_started_where_its_identity_is() {
        let steps = build(&facts(None, Some("b"), ProxySeen::None));
        assert_eq!(
            steps.steps[2].fix.as_deref(),
            Some("tokenless proxy add --name <this machine> --state ~/.tokenless/node.json && tokenless node run --state ~/.tokenless/node.json")
        );
        // Enrolled on another machine: nothing to start here.
        let mut f = facts(None, Some("b"), ProxySeen::Idle(vec!["server-2".into()]));
        f.proxy_state_exists = false;
        let steps = build(&f);
        assert_eq!(steps.steps[2].fix, None);
        assert!(steps.steps[2].detail.contains("where it was enrolled"));
    }

    #[test]
    fn commands_name_a_control_plane_other_than_the_default() {
        let mut f = facts(None, Some("b"), ProxySeen::None);
        f.server_flag = " --server https://tokenless.example";
        let steps = build(&f);
        assert_eq!(
            steps.steps[0].fix.as_deref(),
            Some(
                "tokenless service test openai --vault personal --server https://tokenless.example"
            )
        );
        assert!(steps.steps[2].fix.as_deref().unwrap().contains(
            "--state ~/.tokenless/node.json --server https://tokenless.example && tokenless node run"
        ));
        assert_eq!(
            steps.agent.as_deref(),
            Some("tokenless run --vault personal --bundle b --server https://tokenless.example -- claude")
        );
    }

    #[test]
    fn a_placeholder_beats_a_dummy_value() {
        let subs = [Substitution {
            placeholder: "__OPENAI_API_KEY__".into(),
            field: "api_key".into(),
            env: Some("OPENAI_API_KEY".into()),
            locations: vec![SubstitutionLocation::Header],
        }];
        let mut f = facts(None, Some("b"), ProxySeen::None);
        f.substitutions = &subs;
        let steps = build(&f);
        assert_eq!(
            steps.key.as_deref(),
            Some("OPENAI_API_KEY is set to __OPENAI_API_KEY__ for you; the proxy swaps in the key")
        );
    }

    #[test]
    fn names_with_spaces_are_quoted_in_commands() {
        let mut f = facts(None, Some("code review"), ProxySeen::None);
        f.vault = "my vault";
        let steps = build(&f);
        assert_eq!(
            steps.run.as_deref(),
            Some("tokenless run --vault 'my vault' --bundle 'code review' -- <command>")
        );
    }
}
