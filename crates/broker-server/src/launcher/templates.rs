// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `tokenless service templates`: find the template for a service by its
//! ID, name, alias, host or the variable a tool reads its key from
//! (`OPENAI_API_KEY`), so neither a person nor an agent has to guess the ID
//! `service add` wants.

use serde::Serialize;
use tokenless_core::template::{ServiceKind, ServiceTemplate};

/// One template as `service templates --json` prints it.
#[derive(Debug, Serialize)]
pub struct TemplateRow {
    pub id: String,
    pub name: String,
    pub description: String,
    /// `http` or `mcp`.
    pub kind: &'static str,
    /// The variable tools read this service's key from, if there is a usual one.
    pub variable: Option<String>,
    pub hosts: Vec<String>,
    pub fields: Vec<FieldRow>,
}

#[derive(Debug, Serialize)]
pub struct FieldRow {
    pub name: String,
    pub label: String,
    pub required: bool,
}

impl From<&ServiceTemplate> for TemplateRow {
    fn from(t: &ServiceTemplate) -> Self {
        TemplateRow {
            id: t.id.clone(),
            name: t.name.clone(),
            description: t.description.clone(),
            kind: match t.kind {
                ServiceKind::Http => "http",
                ServiceKind::Mcp => "mcp",
            },
            variable: t.suggested_variable.clone(),
            hosts: t.hosts.iter().map(|h| h.to_string()).collect(),
            fields: t
                .credential_fields
                .iter()
                .map(|f| FieldRow {
                    name: f.name.clone(),
                    label: f.label.clone(),
                    required: f.required,
                })
                .collect(),
        }
    }
}

/// How well `t` matches `query` (already lowercase): `None` for no match,
/// lower is better. An exact ID, alias or variable comes before an exact
/// name or host, which come before a part of any of them.
fn rank(t: &ServiceTemplate, query: &str) -> Option<u8> {
    let variable = t.suggested_variable.as_deref().map(str::to_ascii_lowercase);
    let hosts: Vec<String> = t
        .hosts
        .iter()
        .map(|h| h.to_string().to_ascii_lowercase())
        .collect();
    let name = t.name.to_ascii_lowercase();
    let exact_key = t.id == query
        || t.aliases.iter().any(|a| a.eq_ignore_ascii_case(query))
        || variable.as_deref() == Some(query);
    if exact_key {
        return Some(0);
    }
    if name == query || hosts.iter().any(|h| h == query) {
        return Some(1);
    }
    let partly = t.id.contains(query)
        || name.contains(query)
        || t.aliases
            .iter()
            .any(|a| a.to_ascii_lowercase().contains(query))
        || variable.as_deref().is_some_and(|v| v.contains(query))
        || hosts.iter().any(|h| h.contains(query));
    partly.then_some(2)
}

/// The templates matching `query`, best first and otherwise in catalogue
/// order; every template when there is no query. A URL or `host/path` is
/// searched by its host, so `https://api.openai.com/v1` finds OpenAI.
pub fn search<'a>(
    templates: &'a [ServiceTemplate],
    query: Option<&str>,
) -> Vec<&'a ServiceTemplate> {
    let Some(query) = query.map(normalise).filter(|q| !q.is_empty()) else {
        return templates.iter().collect();
    };
    let mut found: Vec<(u8, usize, &ServiceTemplate)> = templates
        .iter()
        .enumerate()
        .filter_map(|(i, t)| rank(t, &query).map(|r| (r, i, t)))
        .collect();
    found.sort_by_key(|(r, i, _)| (*r, *i));
    found.into_iter().map(|(_, _, t)| t).collect()
}

fn normalise(query: &str) -> String {
    let q = query.trim().to_ascii_lowercase();
    let q = q
        .strip_prefix("https://")
        .or_else(|| q.strip_prefix("http://"))
        .unwrap_or(&q);
    // `$OPENAI_API_KEY` as someone copied it from a shell.
    let q = q.trim_start_matches('$');
    q.split('/').next().unwrap_or(q).to_string()
}

/// The newest version of each template, in the order given (the server lists
/// every version of an imported template).
pub fn newest(templates: impl IntoIterator<Item = ServiceTemplate>) -> Vec<ServiceTemplate> {
    let mut out: Vec<ServiceTemplate> = Vec::new();
    for t in templates {
        match out.iter_mut().find(|o| o.id == t.id) {
            Some(o) if o.version < t.version => *o = t,
            Some(_) => {}
            None => out.push(t),
        }
    }
    out
}

/// The table `service templates` prints for people.
pub fn table(templates: &[&ServiceTemplate]) -> String {
    let rows: Vec<[String; 4]> = templates
        .iter()
        .map(|t| {
            let mut hosts = t.hosts.iter().map(|h| h.to_string());
            let first = hosts.next().unwrap_or_default();
            let more = hosts.count();
            [
                t.id.clone(),
                t.name.clone(),
                t.suggested_variable.clone().unwrap_or_default(),
                if more > 0 {
                    format!("{first} (+{more})")
                } else {
                    first
                },
            ]
        })
        .collect();
    let header = ["ID", "NAME", "VARIABLE", "HOSTS"].map(String::from);
    let width = |col: usize| {
        rows.iter()
            .chain(std::iter::once(&header))
            .map(|r| r[col].chars().count())
            .max()
            .unwrap_or(0)
    };
    let widths = [width(0), width(1), width(2)];
    let mut out = String::new();
    for row in std::iter::once(&header).chain(rows.iter()) {
        let line = format!(
            "{:w0$}  {:w1$}  {:w2$}  {}",
            row[0],
            row[1],
            row[2],
            row[3],
            w0 = widths[0],
            w1 = widths[1],
            w2 = widths[2]
        );
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokenless_core::template::builtin_templates;

    fn catalogue() -> Vec<ServiceTemplate> {
        builtin_templates()
            .unwrap()
            .into_iter()
            .map(|(t, _)| t)
            .collect()
    }

    fn ids(found: &[&ServiceTemplate]) -> Vec<String> {
        found.iter().map(|t| t.id.clone()).collect()
    }

    #[test]
    fn a_tool_s_variable_finds_its_template_first() {
        let all = catalogue();
        for (query, id) in [
            ("OPENAI_API_KEY", "openai"),
            ("$ANTHROPIC_API_KEY", "anthropic"),
            ("github", "github"),
            ("GitHub", "github"),
            ("https://api.openai.com/v1/models", "openai"),
            ("api.anthropic.com", "anthropic"),
            ("chatgpt", "openai"),
        ] {
            let found = search(&all, Some(query));
            assert_eq!(
                found.first().map(|t| t.id.as_str()),
                Some(id),
                "{query}: {:?}",
                ids(&found)
            );
        }
    }

    #[test]
    fn a_part_of_a_name_finds_several_and_nothing_finds_none() {
        let all = catalogue();
        let git = ids(&search(&all, Some("git")));
        assert!(
            git.contains(&"github".to_string()) && git.contains(&"gitlab".to_string()),
            "{git:?}"
        );
        assert!(search(&all, Some("no-such-service-anywhere")).is_empty());
        assert_eq!(search(&all, None).len(), all.len());
        assert_eq!(search(&all, Some("  ")).len(), all.len());
    }

    #[test]
    fn rows_carry_what_service_add_needs() {
        let all = catalogue();
        let openai = search(&all, Some("openai"))[0];
        let row = TemplateRow::from(openai);
        assert_eq!(row.id, "openai");
        assert_eq!(row.variable.as_deref(), Some("OPENAI_API_KEY"));
        assert_eq!(row.kind, "http");
        assert_eq!(row.hosts, ["api.openai.com"]);
        assert_eq!(row.fields.len(), 1);
        assert_eq!(row.fields[0].name, "api_key");
        let text = table(&[openai]);
        assert!(text.starts_with("ID "), "{text}");
        assert!(
            text.contains("openai  OpenAI  OPENAI_API_KEY  api.openai.com"),
            "{text}"
        );
    }

    #[test]
    fn only_the_newest_version_of_a_template_is_listed() {
        let mut old = catalogue().remove(0);
        let mut new = old.clone();
        old.version = 1;
        new.version = 3;
        let newest = newest([old, new.clone()]);
        assert_eq!(newest.len(), 1);
        assert_eq!(newest[0].version, 3);
    }
}
