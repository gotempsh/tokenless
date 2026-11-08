// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The scope of a rule: which hosts, paths and methods may receive a
//! credential. A template defines the maximum scope; a rule instance may only
//! narrow it.

use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::host::HostPattern;
use crate::path::{HttpMethod, PathPattern};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleScope {
    pub hosts: Vec<HostPattern>,
    pub paths: Vec<PathPattern>,
    pub methods: Vec<HttpMethod>,
    /// MCP tools a `tools/call` may name. `None` allows every tool; an
    /// empty list allows none (other MCP methods still work).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_tools: Option<Vec<String>>,
}

pub const MAX_MCP_TOOLS: usize = 200;

/// Checks and normalises an MCP tool allowlist: sorted, without duplicates.
pub fn validate_mcp_tools(tools: Vec<String>) -> Result<Vec<String>, CoreError> {
    let mut tools: Vec<String> = tools.into_iter().map(|t| t.trim().to_string()).collect();
    tools.sort();
    tools.dedup();
    if tools.len() > MAX_MCP_TOOLS {
        return Err(CoreError::InvalidTemplate {
            template_id: "mcp tools".into(),
            reason: format!(
                "at most {MAX_MCP_TOOLS} tools may be listed, got {}",
                tools.len()
            ),
        });
    }
    for tool in &tools {
        let valid = !tool.is_empty()
            && tool.len() <= 128
            && tool
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "_-./".contains(c));
        if !valid {
            return Err(CoreError::InvalidTemplate {
                template_id: "mcp tools".into(),
                reason: format!(
                    "tool name '{tool}' must be 1-128 letters, digits, '_', '-', '.' or '/'"
                ),
            });
        }
    }
    Ok(tools)
}

impl RuleScope {
    pub fn validate(&self, context: &str) -> Result<(), CoreError> {
        let empty = |what: &str| CoreError::InvalidTemplate {
            template_id: context.to_string(),
            reason: format!("a rule needs at least one {what}"),
        };
        if self.hosts.is_empty() {
            return Err(empty("host"));
        }
        if self.paths.is_empty() {
            return Err(empty("path"));
        }
        if self.methods.is_empty() {
            return Err(empty("method"));
        }
        Ok(())
    }

    /// Fails with [`CoreError::Widening`] unless every host, path and method
    /// of `self` is covered by `max`.
    pub fn ensure_within(&self, max: &RuleScope, template_id: &str) -> Result<(), CoreError> {
        let widening = |detail: String| CoreError::Widening {
            template_id: template_id.to_string(),
            detail,
        };
        for host in &self.hosts {
            if !max.hosts.iter().any(|m| m.covers(host)) {
                return Err(widening(format!(
                    "host '{host}' is outside the allowed hosts"
                )));
            }
        }
        for path in &self.paths {
            if !max.paths.iter().any(|m| m.covers(path)) {
                return Err(widening(format!(
                    "path '{path}' is outside the allowed paths"
                )));
            }
        }
        for method in &self.methods {
            if !max.methods.iter().any(|m| m.covers(method)) {
                return Err(widening(format!(
                    "method '{method}' is outside the allowed methods"
                )));
            }
        }
        Ok(())
    }

    /// True when `self` allows something `previous` did not.
    pub fn widens(&self, previous: &RuleScope) -> bool {
        let more_tools = match (&self.mcp_tools, &previous.mcp_tools) {
            (_, None) => false,
            (None, Some(_)) => true,
            (Some(now), Some(before)) => now.iter().any(|t| !before.contains(t)),
        };
        more_tools || self.ensure_within(previous, "").is_err()
    }

    /// May a `tools/call` name `tool`?
    pub fn allows_tool(&self, tool: &str) -> bool {
        self.mcp_tools
            .as_ref()
            .is_none_or(|tools| tools.iter().any(|t| t == tool))
    }

    pub fn matches_host(&self, host: &str, port: u16) -> bool {
        self.hosts.iter().any(|h| h.matches(host, port))
    }

    /// `path` must already have passed [`crate::path::check_request_path`].
    pub fn allows(&self, host: &str, port: u16, method: &str, path: &str) -> bool {
        self.matches_host(host, port)
            && self.methods.iter().any(|m| m.matches(method))
            && self.paths.iter().any(|p| p.matches(path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(hosts: &[&str], paths: &[&str], methods: &[&str]) -> RuleScope {
        RuleScope {
            hosts: hosts
                .iter()
                .map(|h| HostPattern::parse(h).unwrap())
                .collect(),
            paths: paths
                .iter()
                .map(|p| PathPattern::parse(p).unwrap())
                .collect(),
            methods: methods
                .iter()
                .map(|m| HttpMethod::parse(m).unwrap())
                .collect(),
            mcp_tools: None,
        }
    }

    #[test]
    fn narrowing_is_accepted() {
        let max = scope(&["*.example.com"], &["/*"], &["*"]);
        let narrow = scope(&["api.example.com"], &["/v1/*"], &["GET"]);
        assert!(narrow.ensure_within(&max, "t").is_ok());
        assert!(!narrow.widens(&max));
    }

    #[test]
    fn widening_is_rejected_with_detail() {
        let max = scope(&["api.example.com"], &["/v1/*"], &["GET", "POST"]);
        let other_host = scope(&["evil.example.com"], &["/v1/*"], &["GET"]);
        let err = other_host.ensure_within(&max, "tmpl").unwrap_err();
        assert!(
            matches!(err, CoreError::Widening { ref template_id, .. } if template_id == "tmpl")
        );
        assert!(err.to_string().contains("evil.example.com"));
        assert!(scope(&["api.example.com"], &["/*"], &["GET"])
            .ensure_within(&max, "t")
            .is_err());
        assert!(scope(&["api.example.com"], &["/v1/*"], &["DELETE"])
            .ensure_within(&max, "t")
            .is_err());
    }

    #[test]
    fn allows_checks_all_dimensions() {
        let s = scope(&["api.example.com"], &["/v1/*"], &["GET"]);
        assert!(s.allows("api.example.com", 443, "GET", "/v1/models"));
        assert!(!s.allows("api.example.com", 443, "POST", "/v1/models"));
        assert!(!s.allows("api.example.com", 443, "GET", "/v2/models"));
        assert!(!s.allows("other.example.com", 443, "GET", "/v1/models"));
        assert!(!s.allows("api.example.com", 8443, "GET", "/v1/models"));
    }

    #[test]
    fn tool_lists_narrow_and_widen() {
        let all = scope(&["mcp.example.com"], &["/*"], &["*"]);
        let some = RuleScope {
            mcp_tools: Some(vec!["search".into()]),
            ..all.clone()
        };
        let more = RuleScope {
            mcp_tools: Some(vec!["search".into(), "delete".into()]),
            ..all.clone()
        };
        assert!(!some.widens(&all), "a list narrows 'every tool'");
        assert!(all.widens(&some), "dropping the list allows every tool");
        assert!(more.widens(&some));
        assert!(!some.widens(&more));
        assert!(all.allows_tool("anything"));
        assert!(some.allows_tool("search") && !some.allows_tool("delete"));
        assert_eq!(
            validate_mcp_tools(vec![" b".into(), "a".into(), "b".into()]).unwrap(),
            ["a", "b"]
        );
        assert!(validate_mcp_tools(vec!["has space".into()]).is_err());
        assert!(validate_mcp_tools(vec![String::new()]).is_err());
    }

    #[test]
    fn empty_dimensions_are_invalid() {
        assert!(scope(&[], &["/*"], &["*"]).validate("x").is_err());
        assert!(scope(&["a.example.com"], &[], &["*"])
            .validate("x")
            .is_err());
        assert!(scope(&["a.example.com"], &["/*"], &[])
            .validate("x")
            .is_err());
    }
}
