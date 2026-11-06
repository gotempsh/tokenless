// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `tokenless mcp`: the gateway URLs of a session's MCP services
//! and the commands that add them to an MCP client.
//!
//! A gateway URL is `<gateway>/mcp/<host[:port]><mcp_path>`. The client
//! sends the session token as a bearer token; the node checks it, drops
//! it and adds the service's credential (see `broker_dataplane::gateway`).

use broker_control::service::sessions::DiscoveredService;
use broker_core::template::ServiceKind;
use serde::Serialize;

/// Where `node run` serves the gateway unless told otherwise.
pub const DEFAULT_GATEWAY: &str = "http://127.0.0.1:3129";

/// One MCP server a client can be pointed at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct McpEndpoint {
    /// The name to give it in the client: the credential's, as a slug.
    pub name: String,
    pub service: String,
    pub credential: String,
    pub url: String,
}

fn slug(value: &str) -> String {
    let mut out = String::new();
    for c in value.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.ends_with('-') && !out.is_empty() {
            out.push('-');
        }
    }
    let out = out.trim_end_matches('-').to_string();
    if out.is_empty() {
        "mcp".to_string()
    } else {
        out
    }
}

/// The first host of `service` a URL can name (wildcards cannot).
fn concrete_host(service: &DiscoveredService) -> Option<&str> {
    service
        .hosts
        .iter()
        .map(String::as_str)
        .find(|h| !h.contains('*'))
}

/// The enabled MCP services of a session, with their gateway URLs. Names
/// are unique: a second "github" becomes "github-2".
pub fn endpoints(services: &[DiscoveredService], gateway: &str) -> Vec<McpEndpoint> {
    let gateway = gateway.trim().trim_end_matches('/');
    let mut out: Vec<McpEndpoint> = Vec::new();
    for s in services {
        if s.kind != ServiceKind::Mcp || !s.enabled {
            continue;
        }
        let Some(host) = concrete_host(s) else {
            continue;
        };
        let path = s.mcp_path.as_deref().unwrap_or("/");
        let base = slug(&s.credential);
        let mut name = base.clone();
        let mut n = 2;
        while out.iter().any(|e| e.name == name) {
            name = format!("{base}-{n}");
            n += 1;
        }
        out.push(McpEndpoint {
            name,
            service: s.service.clone(),
            credential: s.credential.clone(),
            url: format!("{gateway}/mcp/{host}{path}"),
        });
    }
    out
}

/// Quotes `value` for a POSIX shell when it needs it.
fn shell_quote(value: &str) -> String {
    if !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._/:=@%+,-".contains(c))
    {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', r"'\''"))
    }
}

/// `claude mcp add` for one endpoint.
pub fn claude_command(endpoint: &McpEndpoint, token: &str) -> String {
    format!(
        "claude mcp add --transport http {} {} --header {}",
        shell_quote(&endpoint.name),
        shell_quote(&endpoint.url),
        shell_quote(&format!("Authorization: Bearer {token}")),
    )
}

#[derive(Serialize)]
struct ServerEntry<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    url: &'a str,
    headers: std::collections::BTreeMap<&'static str, String>,
}

/// The `mcpServers` JSON most MCP clients read.
pub fn client_json(endpoints: &[McpEndpoint], token: &str) -> Result<String, serde_json::Error> {
    let servers: std::collections::BTreeMap<&str, ServerEntry> = endpoints
        .iter()
        .map(|e| {
            (
                e.name.as_str(),
                ServerEntry {
                    kind: "http",
                    url: &e.url,
                    headers: [("Authorization", format!("Bearer {token}"))].into(),
                },
            )
        })
        .collect();
    serde_json::to_string_pretty(&serde_json::json!({ "mcpServers": servers }))
}

#[cfg(test)]
mod tests {
    use broker_core::ids::RuleId;

    use super::*;

    fn service(
        credential: &str,
        kind: ServiceKind,
        host: &str,
        path: Option<&str>,
    ) -> DiscoveredService {
        DiscoveredService {
            rule_id: RuleId::new(),
            rule: credential.into(),
            credential: credential.into(),
            template_id: "github-mcp".into(),
            service: "GitHub MCP".into(),
            hosts: vec![host.into()],
            paths: vec!["/*".into()],
            methods: vec!["*".into()],
            enabled: true,
            placeholders: vec![],
            kind,
            mcp_path: path.map(str::to_string),
        }
    }

    #[test]
    fn builds_gateway_urls_for_mcp_services_only() {
        let mut disabled = service("Off", ServiceKind::Mcp, "mcp.example.com", None);
        disabled.enabled = false;
        let found = endpoints(
            &[
                service(
                    "Work GitHub",
                    ServiceKind::Mcp,
                    "api.githubcopilot.com",
                    Some("/mcp/"),
                ),
                service("Plain API", ServiceKind::Http, "api.example.com", None),
                service("Root", ServiceKind::Mcp, "mcp.example.com:8443", None),
                service("Wild", ServiceKind::Mcp, "*.example.com", None),
                disabled,
            ],
            "http://127.0.0.1:3129/",
        );
        assert_eq!(
            found
                .iter()
                .map(|e| (e.name.as_str(), e.url.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (
                    "work-github",
                    "http://127.0.0.1:3129/mcp/api.githubcopilot.com/mcp/"
                ),
                ("root", "http://127.0.0.1:3129/mcp/mcp.example.com:8443/"),
            ]
        );
    }

    #[test]
    fn names_are_unique_slugs() {
        let found = endpoints(
            &[
                service("GitHub", ServiceKind::Mcp, "a.example.com", None),
                service("github!", ServiceKind::Mcp, "b.example.com", None),
                service("***", ServiceKind::Mcp, "c.example.com", None),
            ],
            DEFAULT_GATEWAY,
        );
        let names: Vec<_> = found.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["github", "github-2", "mcp"]);
    }

    #[test]
    fn commands_carry_the_token_as_a_bearer_header() {
        let e = &endpoints(
            &[service(
                "GitHub",
                ServiceKind::Mcp,
                "api.githubcopilot.com",
                Some("/mcp/"),
            )],
            DEFAULT_GATEWAY,
        )[0];
        assert_eq!(
            claude_command(e, "v4.public.abc"),
            "claude mcp add --transport http github http://127.0.0.1:3129/mcp/api.githubcopilot.com/mcp/ --header 'Authorization: Bearer v4.public.abc'"
        );
        let json: serde_json::Value =
            serde_json::from_str(&client_json(std::slice::from_ref(e), "v4.public.abc").unwrap())
                .unwrap();
        assert_eq!(json["mcpServers"]["github"]["type"], "http");
        assert_eq!(
            json["mcpServers"]["github"]["headers"]["Authorization"],
            "Bearer v4.public.abc"
        );
    }
}
