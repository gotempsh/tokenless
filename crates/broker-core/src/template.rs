// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Versioned service templates.
//!
//! A template is YAML *data*: it names hosts, allowed paths and methods, the
//! credential fields a person must supply and one of the fixed injection
//! methods in [`crate::injection`]. It sets the maximum scope any rule built
//! from it may have.

use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::host::HostPattern;
use crate::injection::{InjectionSpec, SecretFields};
use crate::path::{HttpMethod, PathPattern};
use crate::rule::RuleScope;
use crate::variables::{validate_custom_headers, validate_key, CustomHeader};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceTemplate {
    pub id: String,
    pub version: u32,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub hosts: Vec<HostPattern>,
    pub allow: TemplateAllow,
    pub credential_fields: Vec<CredentialField>,
    pub injection: InjectionSpec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation: Option<ValidationRequest>,
    #[serde(default)]
    pub host_override: HostOverride,
    /// Reserved for phase 2. Parsed and validated, never acted upon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth: Option<OAuthSpec>,

    // ---- catalog presentation: never affects what is injected ----------
    #[serde(default)]
    pub category: TemplateCategory,
    #[serde(default)]
    pub kind: ServiceKind,
    /// Logo key the UI resolves to a bundled image; defaults to the id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo: Option<String>,
    /// Shown first in the catalog.
    #[serde(default)]
    pub popular: bool,
    /// Extra words the catalog search matches.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    /// Variable key the UI suggests for the main secret, e.g. `GITHUB_TOKEN`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggested_variable: Option<String>,
    /// Custom headers prefilled on new credentials, e.g. an API version.
    /// They are copied onto the credential, where they can be edited.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub default_headers: Vec<CustomHeader>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemplateCategory {
    LlmProviders,
    DeveloperTools,
    Infrastructure,
    Communication,
    Monitoring,
    Productivity,
    Payments,
    Commerce,
    Search,
    #[default]
    Custom,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceKind {
    /// A web API the agent calls directly.
    #[default]
    Http,
    /// A remote MCP server reached over streamable HTTP.
    Mcp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateAllow {
    pub paths: Vec<PathPattern>,
    pub methods: Vec<HttpMethod>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialField {
    pub name: String,
    pub label: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_true")]
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationRequest {
    pub method: HttpMethod,
    pub path: PathPattern,
    #[serde(default)]
    pub expect_status: Vec<u16>,
}

/// Whether an instance may replace the template's hosts (e.g. a self-hosted
/// base URL). Replacing hosts widens the template's scope, so the control
/// plane only lets administrators set it, behind step-up MFA, and audits it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostOverride {
    #[serde(default)]
    pub allowed: bool,
    #[serde(default)]
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// OAuth settings reserved for phase 2. Refresh will run only in the control
/// plane, one refresh at a time per credential, and only short-lived access
/// tokens will be sent to data plane nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorize_url: Option<String>,
    pub token_url: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Whether the provider rotates the refresh token on every use.
    #[serde(default)]
    pub refresh_token_single_use: bool,
    /// Whether the access token's `expires_in` is honoured when scheduling refresh.
    #[serde(default = "default_true")]
    pub honour_expires_in: bool,
}

const MAX_TEMPLATE_BYTES: usize = 64 * 1024;

fn is_slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

impl ServiceTemplate {
    pub fn from_yaml(yaml: &str) -> Result<Self, CoreError> {
        if yaml.len() > MAX_TEMPLATE_BYTES {
            return Err(CoreError::TemplateParse {
                reason: format!("template is larger than {MAX_TEMPLATE_BYTES} bytes"),
            });
        }
        let template: ServiceTemplate =
            serde_yaml::from_str(yaml).map_err(|e| CoreError::TemplateParse {
                reason: e.to_string(),
            })?;
        template.validate()?;
        Ok(template)
    }

    pub fn validate(&self) -> Result<(), CoreError> {
        let invalid = |reason: String| CoreError::InvalidTemplate {
            template_id: self.id.clone(),
            reason,
        };
        if !is_slug(&self.id) {
            return Err(invalid(
                "id must be 1-64 characters of a-z, 0-9, '-' or '_'".into(),
            ));
        }
        if self.version == 0 {
            return Err(invalid("version must be 1 or greater".into()));
        }
        if self.name.trim().is_empty() {
            return Err(invalid("name cannot be empty".into()));
        }
        if self.hosts.is_empty() && !self.host_override.required {
            return Err(invalid(
                "a template without hosts must set host_override.required".into(),
            ));
        }
        if self.host_override.required && !self.host_override.allowed {
            return Err(invalid(
                "host_override.required implies host_override.allowed".into(),
            ));
        }
        if self.allow.paths.is_empty() || self.allow.methods.is_empty() {
            return Err(invalid(
                "allow.paths and allow.methods cannot be empty".into(),
            ));
        }
        if self.credential_fields.is_empty() {
            return Err(invalid("at least one credential field is required".into()));
        }
        let mut seen = std::collections::BTreeSet::new();
        for field in &self.credential_fields {
            if !is_slug(&field.name) {
                return Err(invalid(format!(
                    "credential field name '{}' is invalid",
                    field.name
                )));
            }
            if !seen.insert(field.name.as_str()) {
                return Err(invalid(format!(
                    "credential field '{}' is declared twice",
                    field.name
                )));
            }
        }
        for used in self.injection.fields() {
            if !seen.contains(used) {
                return Err(invalid(format!(
                    "injection reads field '{used}' which is not declared in credential_fields"
                )));
            }
        }
        self.injection.validate(&self.id)?;
        if let Some(validation) = &self.validation {
            if !self.allow.paths.iter().any(|p| p.covers(&validation.path)) {
                return Err(invalid(format!(
                    "validation path '{}' is outside allow.paths",
                    validation.path
                )));
            }
        }
        if let Some(oauth) = &self.oauth {
            if !oauth.token_url.starts_with("https://") {
                return Err(invalid("oauth.token_url must be an https:// URL".into()));
            }
        }
        if let Some(logo) = &self.logo {
            if !is_slug(logo) {
                return Err(invalid(format!("logo '{logo}' must be a slug")));
            }
        }
        if let Some(key) = &self.suggested_variable {
            validate_key(key).map_err(|e| invalid(e.to_string()))?;
        }
        if self.aliases.len() > 16 || self.aliases.iter().any(|a| a.len() > 32) {
            return Err(invalid("at most 16 aliases of up to 32 characters".into()));
        }
        validate_custom_headers(&self.default_headers, &self.injection.header_names())
            .map_err(|e| invalid(e.to_string()))?;
        Ok(())
    }

    /// The maximum scope of a rule built from this template, after applying
    /// an optional host override.
    pub fn max_scope(&self, host_override: &[HostPattern]) -> Result<RuleScope, CoreError> {
        let hosts = if host_override.is_empty() {
            if self.host_override.required {
                return Err(CoreError::InvalidTemplate {
                    template_id: self.id.clone(),
                    reason: "this template requires a host override".into(),
                });
            }
            self.hosts.clone()
        } else {
            if !self.host_override.allowed {
                return Err(CoreError::Widening {
                    template_id: self.id.clone(),
                    detail: "this template does not allow overriding its hosts".into(),
                });
            }
            host_override.to_vec()
        };
        let scope = RuleScope {
            hosts,
            paths: self.allow.paths.clone(),
            methods: self.allow.methods.clone(),
        };
        scope.validate(&self.id)?;
        Ok(scope)
    }

    /// Checks that `fields` supplies exactly the declared fields, all required
    /// ones present and non-empty.
    pub fn validate_fields(&self, fields: &SecretFields) -> Result<(), CoreError> {
        for name in fields.names() {
            if !self.credential_fields.iter().any(|f| f.name == name) {
                return Err(CoreError::UnknownField {
                    template_id: self.id.clone(),
                    field: name,
                });
            }
        }
        for field in &self.credential_fields {
            let present = fields.get(&field.name).is_some_and(|v| !v.is_empty());
            if field.required && !present {
                return Err(CoreError::MissingField {
                    template_id: self.id.clone(),
                    field: field.name.clone(),
                });
            }
        }
        // Rendering catches values that cannot be sent as a header.
        self.injection.render(&self.id, fields).map(|_| ())
    }
}

const BUILTIN_YAML: &[(&str, &str)] = &[
    ("openai", include_str!("../templates/openai.yaml")),
    ("anthropic", include_str!("../templates/anthropic.yaml")),
    ("gemini", include_str!("../templates/gemini.yaml")),
    ("mistral", include_str!("../templates/mistral.yaml")),
    ("cohere", include_str!("../templates/cohere.yaml")),
    ("groq", include_str!("../templates/groq.yaml")),
    ("perplexity", include_str!("../templates/perplexity.yaml")),
    ("openrouter", include_str!("../templates/openrouter.yaml")),
    ("together", include_str!("../templates/together.yaml")),
    ("deepseek", include_str!("../templates/deepseek.yaml")),
    ("xai", include_str!("../templates/xai.yaml")),
    ("fireworks", include_str!("../templates/fireworks.yaml")),
    ("cerebras", include_str!("../templates/cerebras.yaml")),
    ("huggingface", include_str!("../templates/huggingface.yaml")),
    ("replicate", include_str!("../templates/replicate.yaml")),
    ("elevenlabs", include_str!("../templates/elevenlabs.yaml")),
    ("github", include_str!("../templates/github.yaml")),
    ("gitlab", include_str!("../templates/gitlab.yaml")),
    ("bitbucket", include_str!("../templates/bitbucket.yaml")),
    ("vercel", include_str!("../templates/vercel.yaml")),
    ("netlify", include_str!("../templates/netlify.yaml")),
    ("npm", include_str!("../templates/npm.yaml")),
    ("supabase", include_str!("../templates/supabase.yaml")),
    ("neon", include_str!("../templates/neon.yaml")),
    ("upstash", include_str!("../templates/upstash.yaml")),
    ("cloudflare", include_str!("../templates/cloudflare.yaml")),
    (
        "digitalocean",
        include_str!("../templates/digitalocean.yaml"),
    ),
    ("hetzner", include_str!("../templates/hetzner.yaml")),
    ("fly", include_str!("../templates/fly.yaml")),
    ("render", include_str!("../templates/render.yaml")),
    ("railway", include_str!("../templates/railway.yaml")),
    ("slack", include_str!("../templates/slack.yaml")),
    ("discord", include_str!("../templates/discord.yaml")),
    ("twilio", include_str!("../templates/twilio.yaml")),
    ("sendgrid", include_str!("../templates/sendgrid.yaml")),
    ("resend", include_str!("../templates/resend.yaml")),
    ("postmark", include_str!("../templates/postmark.yaml")),
    ("mailgun", include_str!("../templates/mailgun.yaml")),
    ("intercom", include_str!("../templates/intercom.yaml")),
    ("datadog", include_str!("../templates/datadog.yaml")),
    ("sentry", include_str!("../templates/sentry.yaml")),
    ("pagerduty", include_str!("../templates/pagerduty.yaml")),
    ("grafana", include_str!("../templates/grafana.yaml")),
    ("posthog", include_str!("../templates/posthog.yaml")),
    ("notion", include_str!("../templates/notion.yaml")),
    ("linear", include_str!("../templates/linear.yaml")),
    ("jira", include_str!("../templates/jira.yaml")),
    ("confluence", include_str!("../templates/confluence.yaml")),
    ("asana", include_str!("../templates/asana.yaml")),
    ("clickup", include_str!("../templates/clickup.yaml")),
    ("airtable", include_str!("../templates/airtable.yaml")),
    ("figma", include_str!("../templates/figma.yaml")),
    ("hubspot", include_str!("../templates/hubspot.yaml")),
    ("stripe", include_str!("../templates/stripe.yaml")),
    (
        "lemonsqueezy",
        include_str!("../templates/lemonsqueezy.yaml"),
    ),
    ("paddle", include_str!("../templates/paddle.yaml")),
    ("shopify", include_str!("../templates/shopify.yaml")),
    ("tavily", include_str!("../templates/tavily.yaml")),
    ("exa", include_str!("../templates/exa.yaml")),
    ("firecrawl", include_str!("../templates/firecrawl.yaml")),
    (
        "brave-search",
        include_str!("../templates/brave-search.yaml"),
    ),
    ("github-mcp", include_str!("../templates/github-mcp.yaml")),
    ("generic-mcp", include_str!("../templates/generic-mcp.yaml")),
    (
        "generic-bearer",
        include_str!("../templates/generic-bearer.yaml"),
    ),
    (
        "generic-api-key",
        include_str!("../templates/generic-api-key.yaml"),
    ),
    (
        "generic-basic",
        include_str!("../templates/generic-basic.yaml"),
    ),
];

/// The templates shipped with the broker, together with their YAML source.
pub fn builtin_templates() -> Result<Vec<(ServiceTemplate, &'static str)>, CoreError> {
    BUILTIN_YAML
        .iter()
        .map(|(id, yaml)| {
            let template = ServiceTemplate::from_yaml(yaml)?;
            if template.id != *id {
                return Err(CoreError::InvalidTemplate {
                    template_id: (*id).to_string(),
                    reason: format!("built-in file declares id '{}'", template.id),
                });
            }
            Ok((template, *yaml))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn all_builtins_parse_and_validate() {
        let builtins = builtin_templates().unwrap();
        assert!(
            builtins.len() >= 60,
            "the catalog ships {} templates",
            builtins.len()
        );
        let mut ids: Vec<_> = builtins.iter().map(|(t, _)| t.id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), builtins.len(), "template ids must be unique");
        for (t, _) in &builtins {
            if !t.host_override.required {
                assert!(!t.hosts.is_empty(), "{} has no hosts", t.id);
            }
            assert!(!t.description.is_empty(), "{} has no description", t.id);
        }
        // The popular templates lead the catalog.
        let popular: Vec<_> = builtins
            .iter()
            .filter(|(t, _)| t.popular)
            .map(|(t, _)| t.id.as_str())
            .collect();
        assert_eq!(
            popular,
            ["openai", "anthropic", "github", "slack", "notion", "stripe"]
        );
    }

    #[test]
    fn gitlab_allows_base_url_override_but_github_does_not() {
        let builtins = builtin_templates().unwrap();
        let find = |id: &str| builtins.iter().find(|(t, _)| t.id == id).unwrap().0.clone();
        let gitlab = find("gitlab");
        let custom = HostPattern::from_https_base_url("https://git.internal.example").unwrap();
        let scope = gitlab.max_scope(std::slice::from_ref(&custom)).unwrap();
        assert_eq!(scope.hosts, vec![custom.clone()]);
        assert_eq!(gitlab.max_scope(&[]).unwrap().hosts[0].host(), "gitlab.com");
        let github = find("github");
        assert!(matches!(
            github.max_scope(&[custom]),
            Err(CoreError::Widening { .. })
        ));
        assert!(find("generic-bearer").max_scope(&[]).is_err());
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let yaml = include_str!("../templates/github.yaml")
            .replace("version: 2", "version: 2\nscript: rm -rf /");
        assert!(matches!(
            ServiceTemplate::from_yaml(&yaml),
            Err(CoreError::TemplateParse { .. })
        ));
    }

    #[test]
    fn injection_must_reference_declared_field() {
        let yaml = include_str!("../templates/github.yaml").replace("field: token", "field: other");
        let err = ServiceTemplate::from_yaml(&yaml).unwrap_err();
        assert!(err.to_string().contains("other"));
    }

    #[test]
    fn oauth_fields_are_parsed_for_phase_two() {
        let yaml = format!(
            "{}\noauth:\n  token_url: https://auth.example.com/token\n  refresh_token_single_use: true\n  honour_expires_in: true\n",
            include_str!("../templates/github.yaml")
        );
        let t = ServiceTemplate::from_yaml(&yaml).unwrap();
        let oauth = t.oauth.unwrap();
        assert!(oauth.refresh_token_single_use);
        assert!(oauth.honour_expires_in);
    }

    #[test]
    fn field_validation() {
        let github = builtin_templates()
            .unwrap()
            .into_iter()
            .find(|(t, _)| t.id == "github")
            .unwrap()
            .0;
        let ok = SecretFields::new(BTreeMap::from([("token".to_string(), "t".to_string())]));
        assert!(github.validate_fields(&ok).is_ok());
        let missing = SecretFields::new(BTreeMap::new());
        assert!(matches!(
            github.validate_fields(&missing),
            Err(CoreError::MissingField { .. })
        ));
        let extra = SecretFields::new(BTreeMap::from([
            ("token".to_string(), "t".to_string()),
            ("other".to_string(), "x".to_string()),
        ]));
        assert!(matches!(
            github.validate_fields(&extra),
            Err(CoreError::UnknownField { .. })
        ));
    }
}
