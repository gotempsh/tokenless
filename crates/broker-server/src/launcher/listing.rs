// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! What the `list` commands print: a row per vault, service, bundle,
//! session or proxy, as a table for people and as JSON (the same rows)
//! for agents and scripts. Built from what the management API returns;
//! secrets never reach it, only their metadata.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokenless_control::model::{AccessBundle, CredentialMeta, Node, ProxySession, Rule, Vault};
use tokenless_core::ids::{BundleId, CredentialId, NodeId, SessionId, VaultId};
use tokenless_core::template::ServiceTemplate;

use super::status::connected;

/// Columns padded to their widest cell, two spaces apart; the last is not
/// padded, so lines carry no trailing spaces.
pub fn table(header: &[&str], rows: &[Vec<String>]) -> String {
    let cols = header.len();
    let width = |col: usize| {
        rows.iter()
            .map(|r| r.get(col).map_or(0, |c| c.chars().count()))
            .chain(std::iter::once(header[col].chars().count()))
            .max()
            .unwrap_or(0)
    };
    let widths: Vec<usize> = (0..cols).map(width).collect();
    let header: Vec<String> = header.iter().map(|h| h.to_string()).collect();
    let mut out = String::new();
    for row in std::iter::once(&header).chain(rows.iter()) {
        let mut line = String::new();
        for (col, cell) in row.iter().enumerate().take(cols) {
            if col + 1 == cols {
                line.push_str(cell);
            } else {
                line.push_str(&format!("{cell:w$}  ", w = widths[col]));
            }
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

/// `at` relative to `now`: "just now", "5 min ago", "in 3 h", "2 d ago".
pub fn relative(at: DateTime<Utc>, now: DateTime<Utc>) -> String {
    let secs = (at - now).num_seconds();
    let span = secs.unsigned_abs();
    if span < 60 {
        return "just now".into();
    }
    let amount = match span {
        s if s < 3_600 => format!("{} min", s / 60),
        s if s < 86_400 => format!("{} h", s / 3_600),
        s => format!("{} d", s / 86_400),
    };
    if secs < 0 {
        format!("{amount} ago")
    } else {
        format!("in {amount}")
    }
}

/// The first item and how many more: `api.github.com (+2)`.
fn first_and_more(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [only] => only.clone(),
        [first, rest @ ..] => format!("{first} (+{})", rest.len()),
    }
}

fn vault_names(vaults: &[Vault]) -> HashMap<VaultId, String> {
    vaults.iter().map(|v| (v.id, v.name.clone())).collect()
}

fn vault_name(names: &HashMap<VaultId, String>, id: &VaultId) -> String {
    names.get(id).cloned().unwrap_or_else(|| id.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VaultRow {
    pub id: VaultId,
    pub name: String,
    pub services: usize,
    pub bundles: usize,
    pub created_at: DateTime<Utc>,
}

/// A vault with how many services and bundles it holds.
pub fn vault_rows(
    vaults: &[Vault],
    services: &HashMap<VaultId, usize>,
    bundles: &HashMap<VaultId, usize>,
) -> Vec<VaultRow> {
    vaults
        .iter()
        .map(|v| VaultRow {
            id: v.id,
            name: v.name.clone(),
            services: services.get(&v.id).copied().unwrap_or(0),
            bundles: bundles.get(&v.id).copied().unwrap_or(0),
            created_at: v.created_at,
        })
        .collect()
}

pub fn vault_table(rows: &[VaultRow], now: DateTime<Utc>) -> String {
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            vec![
                r.name.clone(),
                r.services.to_string(),
                r.bundles.to_string(),
                relative(r.created_at, now),
            ]
        })
        .collect();
    table(&["NAME", "SERVICES", "BUNDLES", "CREATED"], &cells)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceRow {
    pub id: CredentialId,
    pub vault: String,
    pub name: String,
    pub template: String,
    /// The template version it was created on and is injected with.
    pub template_version: u32,
    /// Whether that version is approved. When it is not, proxies skip the
    /// service and `hosts` is empty.
    pub template_approved: bool,
    /// Where agents' requests get its credential.
    pub hosts: Vec<String>,
    /// When the secret stops being valid upstream, for one that expires.
    pub expires_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

/// A service with the hosts it reaches: its host override, or else the
/// hosts of the template version it is pinned to, as proxies resolve it.
/// `approved` is every approved template version, not just the newest.
pub fn service_rows(
    credentials: &[CredentialMeta],
    vaults: &[Vault],
    approved: &[ServiceTemplate],
) -> Vec<ServiceRow> {
    let names = vault_names(vaults);
    let approved: HashMap<(&str, u32), &ServiceTemplate> = approved
        .iter()
        .map(|t| ((t.id.as_str(), t.version), t))
        .collect();
    credentials
        .iter()
        .map(|c| {
            let template = approved.get(&(c.template_id.as_str(), c.template_version));
            let hosts = match template {
                None => vec![],
                Some(t) if c.host_override.is_empty() => {
                    t.hosts.iter().map(|h| h.to_string()).collect()
                }
                Some(_) => c.host_override.iter().map(|h| h.to_string()).collect(),
            };
            ServiceRow {
                id: c.id,
                vault: vault_name(&names, &c.vault_id),
                name: c.name.clone(),
                template: c.template_id.clone(),
                template_version: c.template_version,
                template_approved: template.is_some(),
                hosts,
                expires_at: c.not_after,
                updated_at: c.updated_at,
            }
        })
        .collect()
}

pub fn service_table(rows: &[ServiceRow], now: DateTime<Utc>) -> String {
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            vec![
                r.vault.clone(),
                r.name.clone(),
                if r.template_approved {
                    r.template.clone()
                } else {
                    format!("{} v{}", r.template, r.template_version)
                },
                match r.expires_at {
                    Some(at) if at <= now => "expired".into(),
                    Some(at) => relative(at, now),
                    None => "-".into(),
                },
                if r.template_approved {
                    first_and_more(&r.hosts)
                } else {
                    "none: this template version is not approved".into()
                },
            ]
        })
        .collect();
    table(&["VAULT", "NAME", "TEMPLATE", "EXPIRES", "HOSTS"], &cells)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BundleRow {
    pub id: BundleId,
    pub vault: String,
    pub name: String,
    pub description: String,
    /// The services its rules reach, by name.
    pub services: Vec<String>,
    /// Its rules that are turned off, so sessions skip them.
    pub rules_off: usize,
    pub updated_at: DateTime<Utc>,
}

/// A bundle with the services its rules reach. `rules` and `credentials`
/// are those of the bundles' vaults.
pub fn bundle_rows(
    bundles: &[AccessBundle],
    vaults: &[Vault],
    rules: &[Rule],
    credentials: &[CredentialMeta],
) -> Vec<BundleRow> {
    let names = vault_names(vaults);
    let rules: HashMap<_, &Rule> = rules.iter().map(|r| (r.id, r)).collect();
    let services: HashMap<CredentialId, &str> = credentials
        .iter()
        .map(|c| (c.id, c.name.as_str()))
        .collect();
    bundles
        .iter()
        .map(|b| {
            let mut reached = BTreeSet::new();
            let mut rules_off = 0;
            for rule in b.rule_ids.iter().filter_map(|id| rules.get(id)) {
                if !rule.enabled {
                    rules_off += 1;
                }
                if let Some(name) = services.get(&rule.credential_id) {
                    reached.insert(name.to_string());
                }
            }
            BundleRow {
                id: b.id,
                vault: vault_name(&names, &b.vault_id),
                name: b.name.clone(),
                description: b.description.clone(),
                services: reached.into_iter().collect(),
                rules_off,
                updated_at: b.updated_at,
            }
        })
        .collect()
}

pub fn bundle_table(rows: &[BundleRow], now: DateTime<Utc>) -> String {
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            let mut services = if r.services.is_empty() {
                "none yet".to_string()
            } else {
                r.services.join(", ")
            };
            if r.rules_off > 0 {
                services.push_str(&format!(
                    " ({} rule{} off)",
                    r.rules_off,
                    if r.rules_off == 1 { "" } else { "s" }
                ));
            }
            vec![
                r.vault.clone(),
                r.name.clone(),
                relative(r.updated_at, now),
                services,
            ]
        })
        .collect();
    table(&["VAULT", "NAME", "UPDATED", "SERVICES"], &cells)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Active,
    Expired,
    Revoked,
}

impl SessionState {
    pub fn of(session: &ProxySession, now: DateTime<Utc>) -> Self {
        if session.revoked_at.is_some() {
            SessionState::Revoked
        } else if session.expires_at <= now {
            SessionState::Expired
        } else {
            SessionState::Active
        }
    }

    fn label(self) -> &'static str {
        match self {
            SessionState::Active => "active",
            SessionState::Expired => "expired",
            SessionState::Revoked => "revoked",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionRow {
    pub id: SessionId,
    pub vault: String,
    /// The bundle it was minted from, as it was named then.
    pub bundle: Option<String>,
    pub state: SessionState,
    pub labels: BTreeMap<String, String>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

pub fn session_rows(
    sessions: &[ProxySession],
    vaults: &[Vault],
    now: DateTime<Utc>,
) -> Vec<SessionRow> {
    let names = vault_names(vaults);
    sessions
        .iter()
        .map(|s| SessionRow {
            id: s.id,
            vault: vault_name(&names, &s.vault_id),
            bundle: s.bundle.as_ref().map(|b| b.name.clone()),
            state: SessionState::of(s, now),
            labels: s.labels.clone(),
            created_by: s.created_by.clone(),
            created_at: s.created_at,
            expires_at: s.expires_at,
            revoked_at: s.revoked_at,
        })
        .collect()
}

pub fn session_table(rows: &[SessionRow], now: DateTime<Utc>) -> String {
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            let ends = match (r.state, r.revoked_at) {
                (SessionState::Revoked, Some(at)) => format!("revoked {}", relative(at, now)),
                (SessionState::Expired, _) => format!("expired {}", relative(r.expires_at, now)),
                _ => format!("expires {}", relative(r.expires_at, now)),
            };
            let labels: Vec<String> = r.labels.iter().map(|(k, v)| format!("{k}={v}")).collect();
            vec![
                r.id.to_string(),
                r.vault.clone(),
                r.bundle.clone().unwrap_or_else(|| "-".into()),
                r.state.label().into(),
                relative(r.created_at, now),
                ends,
                labels.join(","),
            ]
        })
        .collect();
    table(
        &[
            "ID", "VAULT", "BUNDLE", "STATE", "CREATED", "ENDS", "LABELS",
        ],
        &cells,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyState {
    /// Checked in recently: it serves agents.
    Connected,
    /// Enrolled, but has not checked in lately.
    NotConnected,
    /// Enrolled and never checked in.
    NeverConnected,
    /// Its certificate ran out; it has to enrol again.
    CertificateExpired,
    Revoked,
}

impl ProxyState {
    pub fn of(node: &Node, now: DateTime<Utc>) -> Self {
        if node.revoked_at.is_some() {
            ProxyState::Revoked
        } else if node.cert_not_after <= now {
            ProxyState::CertificateExpired
        } else if connected(node, now) {
            ProxyState::Connected
        } else if node.last_seen_at.is_none() {
            ProxyState::NeverConnected
        } else {
            ProxyState::NotConnected
        }
    }

    fn label(self) -> &'static str {
        match self {
            ProxyState::Connected => "connected",
            ProxyState::NotConnected => "not connected",
            ProxyState::NeverConnected => "never connected",
            ProxyState::CertificateExpired => "certificate expired",
            ProxyState::Revoked => "revoked",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProxyRow {
    pub id: NodeId,
    pub name: String,
    pub state: ProxyState,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub enrolled_at: DateTime<Utc>,
    pub cert_not_after: DateTime<Utc>,
}

pub fn proxy_rows(nodes: &[Node], now: DateTime<Utc>) -> Vec<ProxyRow> {
    nodes
        .iter()
        .map(|n| ProxyRow {
            id: n.id,
            name: n.name.clone(),
            state: ProxyState::of(n, now),
            last_seen_at: n.last_seen_at,
            enrolled_at: n.enrolled_at,
            cert_not_after: n.cert_not_after,
        })
        .collect()
}

pub fn proxy_table(rows: &[ProxyRow], now: DateTime<Utc>) -> String {
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            vec![
                r.name.clone(),
                r.state.label().into(),
                r.last_seen_at
                    .map_or_else(|| "-".into(), |at| relative(at, now)),
                relative(r.enrolled_at, now),
                r.id.to_string(),
            ]
        })
        .collect();
    table(&["NAME", "STATE", "LAST SEEN", "ENROLLED", "ID"], &cells)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use tokenless_control::model::SessionBundle;
    use tokenless_core::host::HostPattern;
    use tokenless_core::ids::RuleId;
    use tokenless_core::rule::RuleScope;
    use tokenless_core::scope::Scope;

    fn vault(name: &str, now: DateTime<Utc>) -> Vault {
        let id = VaultId::new();
        Vault {
            id,
            name: name.into(),
            scope: Scope::for_vault(&id),
            created_at: now - Duration::days(3),
        }
    }

    fn credential(vault: &Vault, name: &str, template: &str, now: DateTime<Utc>) -> CredentialMeta {
        CredentialMeta {
            id: CredentialId::new(),
            vault_id: vault.id,
            name: name.into(),
            template_id: template.into(),
            template_version: 1,
            host_override: vec![],
            field_names: vec!["token".into()],
            custom_headers: vec![],
            variable_refs: vec![],
            substitutions: vec![],
            not_after: None,
            secret_generation: 1,
            rotation_id: None,
            created_by: "user:a".into(),
            created_at: now,
            updated_at: now,
        }
    }

    fn rule(credential: &CredentialMeta, enabled: bool, now: DateTime<Utc>) -> Rule {
        Rule {
            id: RuleId::new(),
            vault_id: credential.vault_id,
            credential_id: credential.id,
            name: credential.name.clone(),
            allow: RuleScope {
                hosts: vec![],
                paths: vec![],
                methods: vec![],
                mcp_tools: None,
                git: None,
            },
            enabled,
            created_by: "user:a".into(),
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn tables_line_up_without_trailing_spaces() {
        let out = table(
            &["NAME", "STATE", "NOTE"],
            &[
                vec!["a".into(), "connected".into(), String::new()],
                vec!["longer-name".into(), "revoked".into(), "x".into()],
            ],
        );
        assert_eq!(
            out,
            "NAME         STATE      NOTE\na            connected\nlonger-name  revoked    x\n"
        );
    }

    #[test]
    fn times_read_relative_to_now() {
        let now = Utc::now();
        assert_eq!(relative(now - Duration::seconds(20), now), "just now");
        assert_eq!(relative(now - Duration::minutes(5), now), "5 min ago");
        assert_eq!(relative(now + Duration::hours(3), now), "in 3 h");
        assert_eq!(relative(now - Duration::days(2), now), "2 d ago");
    }

    #[test]
    fn a_service_reaches_its_override_or_else_its_template_hosts() {
        let now = Utc::now();
        let work = vault("work", now);
        let v1 = tokenless_core::template::builtin_templates()
            .unwrap()
            .into_iter()
            .map(|(t, _)| t)
            .find(|t| t.id == "github")
            .unwrap();
        // A newer version reaching other hosts: services stay on theirs.
        let mut v2 = v1.clone();
        v2.version = v1.version + 1;
        v2.hosts = vec![HostPattern::parse("api.v2.example.com").unwrap()];
        let mut github = credential(&work, "github", "github", now);
        github.template_version = v1.version;
        let mut mirror = credential(&work, "mirror", "github", now);
        mirror.template_version = v1.version;
        mirror.host_override = vec![HostPattern::parse("git.example.internal").unwrap()];
        mirror.not_after = Some(now - Duration::minutes(1));
        let mut newer = credential(&work, "newer", "github", now);
        newer.template_version = v2.version;
        let rows = service_rows(
            &[github.clone(), mirror.clone(), newer],
            std::slice::from_ref(&work),
            &[v2.clone(), v1.clone()],
        );
        assert_eq!(rows[0].vault, "work");
        assert!(
            rows[0].hosts.contains(&"api.github.com".to_string())
                && !rows[0].hosts.contains(&"api.v2.example.com".to_string()),
            "{:?}",
            rows[0].hosts
        );
        assert_eq!(rows[1].hosts, ["git.example.internal"]);
        assert_eq!(rows[2].hosts, ["api.v2.example.com"]);
        assert!(rows.iter().all(|r| r.template_approved));
        let shown = service_table(&rows, now);
        assert!(shown.lines().nth(2).unwrap().contains("expired"), "{shown}");

        // Its version no longer approved, proxies skip it: no hosts, and
        // the table says why.
        let rows = service_rows(&[github, mirror], &[work], &[v2]);
        assert!(
            rows.iter()
                .all(|r| !r.template_approved && r.hosts.is_empty()),
            "{rows:?}"
        );
        let shown = service_table(&rows, now);
        let line = shown.lines().nth(1).unwrap();
        assert!(
            line.contains(&format!("github v{}", v1.version))
                && line.contains("none: this template version is not approved"),
            "{shown}"
        );
    }

    #[test]
    fn a_bundle_names_the_services_its_rules_reach_and_counts_rules_off() {
        let now = Utc::now();
        let work = vault("work", now);
        let github = credential(&work, "github", "github", now);
        let notion = credential(&work, "notion", "notion", now);
        let on = rule(&github, true, now);
        let off = rule(&notion, false, now);
        let bundle = AccessBundle {
            id: BundleId::new(),
            vault_id: work.id,
            name: "code-review".into(),
            description: String::new(),
            rule_ids: vec![on.id, off.id],
            request_limit: None,
            created_by: "user:a".into(),
            created_at: now,
            updated_at: now,
        };
        let empty = AccessBundle {
            id: BundleId::new(),
            name: "empty".into(),
            rule_ids: vec![],
            ..bundle.clone()
        };
        let rows = bundle_rows(&[bundle, empty], &[work], &[on, off], &[github, notion]);
        assert_eq!(rows[0].services, ["github", "notion"]);
        assert_eq!(rows[0].rules_off, 1);
        let shown = bundle_table(&rows, now);
        assert!(shown.contains("github, notion (1 rule off)"), "{shown}");
        assert!(shown.contains("none yet"), "{shown}");
    }

    #[test]
    fn a_session_is_active_until_it_expires_or_is_revoked() {
        let now = Utc::now();
        let work = vault("work", now);
        let session = |expires: Duration, revoked: bool| ProxySession {
            id: SessionId::new(),
            vault_id: work.id,
            rule_ids: vec![],
            bundle: Some(SessionBundle {
                id: BundleId::new(),
                name: "code-review".into(),
            }),
            labels: BTreeMap::from([("agent".to_string(), "claude".to_string())]),
            request_limit: None,
            node_id: None,
            created_by: "user:a".into(),
            created_at: now - Duration::hours(1),
            expires_at: now + expires,
            revoked_at: revoked.then_some(now - Duration::minutes(2)),
        };
        let sessions = [
            session(Duration::hours(2), false),
            session(-Duration::minutes(5), false),
            session(Duration::hours(2), true),
        ];
        let rows = session_rows(&sessions, std::slice::from_ref(&work), now);
        let states: Vec<_> = rows.iter().map(|r| r.state).collect();
        assert_eq!(
            states,
            [
                SessionState::Active,
                SessionState::Expired,
                SessionState::Revoked
            ]
        );
        let shown = session_table(&rows, now);
        assert!(shown.contains("expires in 2 h"), "{shown}");
        assert!(shown.contains("expired 5 min ago"), "{shown}");
        assert!(shown.contains("revoked 2 min ago"), "{shown}");
        assert!(shown.contains("agent=claude"), "{shown}");
        assert!(
            shown.contains(&sessions[0].id.to_string()),
            "the id, for session revoke --id"
        );
        let json = serde_json::to_value(&rows[0]).unwrap();
        assert_eq!(json["state"], "active");
        assert_eq!(json["vault"], "work");
    }

    #[test]
    fn a_proxy_state_matches_what_status_calls_connected() {
        let now = Utc::now();
        let node = |seen: Option<Duration>, cert: Duration, revoked: bool| Node {
            id: NodeId::new(),
            name: "laptop".into(),
            seal_public_key: String::new(),
            cert_serial: String::new(),
            cert_not_after: now + cert,
            enrolled_at: now - Duration::days(1),
            last_seen_at: seen.map(|ago| now - ago),
            revoked_at: revoked.then_some(now),
            scoped_rules: false,
        };
        let day = Duration::days(1);
        let cases = [
            (
                node(Some(Duration::seconds(10)), day, false),
                ProxyState::Connected,
            ),
            (
                node(Some(Duration::hours(2)), day, false),
                ProxyState::NotConnected,
            ),
            (node(None, day, false), ProxyState::NeverConnected),
            (
                node(Some(Duration::seconds(10)), -day, false),
                ProxyState::CertificateExpired,
            ),
            (
                node(Some(Duration::seconds(10)), day, true),
                ProxyState::Revoked,
            ),
        ];
        for (n, want) in &cases {
            assert_eq!(ProxyState::of(n, now), *want, "{n:?}");
            assert_eq!(*want == ProxyState::Connected, connected(n, now));
        }
        let rows = proxy_rows(&[cases[2].0.clone()], now);
        let shown = proxy_table(&rows, now);
        assert!(shown.contains("never connected"), "{shown}");
    }
}
