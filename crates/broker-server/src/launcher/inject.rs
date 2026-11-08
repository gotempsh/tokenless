// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Environment variables an agent asks for by reference:
//! `tokenless exec GITHUB_TOKEN=cb://github/token -- ./deploy.sh`.
//!
//! A `cb://<service>/<field>` reference resolves to the placeholder the
//! proxy swaps for that secret field, never to the secret: stored
//! credentials are write-only, and the command only ever holds a value
//! that is useless outside the proxy. Anything else is passed through as
//! written, so `exec` also works as `env NAME=value`. References are
//! checked before the command starts; one that names nothing fails the
//! run instead of handing the command an empty variable.

use std::path::Path;

use tokenless_control::service::sessions::{DiscoveredPlaceholder, DiscoveredService};

use super::LauncherError;

/// The scheme of a secret reference.
pub const SCHEME: &str = "cb://";

/// Variables a command never inherits from the shell that started it: the
/// key that mints sessions and a session token would let it act beyond
/// its bundle.
pub const STRIPPED_ENV: &[&str] = &["TOKENLESS_API_KEY", "TOKENLESS_SESSION_TOKEN"];

/// `NAME=value` as given on the command line or in an env file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    pub name: String,
    pub value: String,
    /// Where it came from, for error messages.
    pub origin: String,
}

fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

fn assignment(name: &str, value: &str, origin: String) -> Result<Assignment, LauncherError> {
    let name = name.trim();
    if !valid_name(name) {
        return Err(LauncherError::config(format!(
            "{origin}: '{name}' is not an environment variable name (letters, digits and '_', not starting with a digit)"
        )));
    }
    Ok(Assignment {
        name: name.to_string(),
        value: value.to_string(),
        origin,
    })
}

/// Parses `NAME=value` from the command line.
pub fn parse_assignment(raw: &str) -> Result<Assignment, LauncherError> {
    let (name, value) = raw.split_once('=').ok_or_else(|| {
        LauncherError::config(format!(
            "'{raw}' must look like NAME=cb://<service>/<field> or NAME=value; put the command after --"
        ))
    })?;
    assignment(name, value, format!("argument '{name}='"))
}

/// Parses a dotenv-style file: `NAME=value` lines, optionally prefixed
/// with `export`, values optionally quoted, `#` comments. It is meant to
/// be committed: it holds references, not secrets.
pub fn parse_env_file(contents: &str, path: &Path) -> Result<Vec<Assignment>, LauncherError> {
    let mut out = Vec::new();
    for (i, line) in contents.lines().enumerate() {
        let origin = format!("{}:{}", path.display(), i + 1);
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let (name, value) = line.split_once('=').ok_or_else(|| {
            LauncherError::config(format!("{origin}: expected NAME=value, found '{line}'"))
        })?;
        out.push(assignment(name, &unquote(value.trim(), &origin)?, origin)?);
    }
    Ok(out)
}

fn unquote(value: &str, origin: &str) -> Result<String, LauncherError> {
    for quote in ['"', '\''] {
        if let Some(rest) = value.strip_prefix(quote) {
            return rest
                .strip_suffix(quote)
                .map(str::to_string)
                .ok_or_else(|| LauncherError::config(format!("{origin}: unterminated {quote}")));
        }
    }
    // Unquoted: a ` #` starts a comment, as in most dotenv readers.
    Ok(value
        .split_once(" #")
        .map_or(value, |(v, _)| v)
        .trim_end()
        .to_string())
}

/// The reference for one placeholder of `service`.
pub fn reference(service: &DiscoveredService, placeholder: &DiscoveredPlaceholder) -> String {
    format!("{SCHEME}{}/{}", service.credential, placeholder.field)
}

/// Every reference the session can resolve, for error messages and
/// `session info`.
pub fn references(services: &[DiscoveredService]) -> Vec<String> {
    services
        .iter()
        .filter(|s| s.enabled)
        .flat_map(|s| s.placeholders.iter().map(move |p| reference(s, p)))
        .collect()
}

fn available(services: &[DiscoveredService]) -> String {
    let refs = references(services);
    if refs.is_empty() {
        "this session has no placeholders; an admin adds them under Services → Placeholders"
            .to_string()
    } else {
        format!("this session resolves {}", refs.join(", "))
    }
}

/// The services `name` refers to: a credential, rule, template or service
/// name, exactly, or failing that ignoring case.
fn find_service<'a>(services: &'a [DiscoveredService], name: &str) -> Vec<&'a DiscoveredService> {
    let names = |s: &'a DiscoveredService| {
        [
            s.credential.as_str(),
            s.rule.as_str(),
            s.template_id.as_str(),
            s.service.as_str(),
        ]
    };
    let exact: Vec<_> = services
        .iter()
        .filter(|s| names(s).contains(&name))
        .collect();
    if !exact.is_empty() {
        return exact;
    }
    services
        .iter()
        .filter(|s| names(s).iter().any(|n| n.eq_ignore_ascii_case(name)))
        .collect()
}

fn resolve_reference(
    a: &Assignment,
    target: &str,
    services: &[DiscoveredService],
) -> Result<String, LauncherError> {
    let fail = |why: String| LauncherError::config(format!("{}: {why}", a.origin));
    let (name, field) = match target.rsplit_once('/') {
        Some((name, field)) if !field.is_empty() => (name, Some(field)),
        Some((name, _)) => (name, None),
        None => (target, None),
    };
    if name.is_empty() {
        return Err(fail(format!(
            "'{}' names no service; write {SCHEME}<service>/<field>",
            a.value
        )));
    }
    let service = match find_service(services, name).as_slice() {
        [] => {
            return Err(fail(format!(
                "no service in this session is called '{name}'; {}",
                available(services)
            )))
        }
        [one] => *one,
        many => {
            let names: Vec<&str> = many.iter().map(|s| s.credential.as_str()).collect();
            return Err(fail(format!(
                "'{name}' matches {}; use the service name instead",
                names.join(", ")
            )));
        }
    };
    if !service.enabled {
        return Err(fail(format!(
            "rule '{}' for '{}' is disabled, so the proxy would not add its secret",
            service.rule, service.credential
        )));
    }
    let fields = || {
        let f: Vec<&str> = service
            .placeholders
            .iter()
            .map(|p| p.field.as_str())
            .collect();
        if f.is_empty() {
            "it has none".to_string()
        } else {
            format!("it has {}", f.join(", "))
        }
    };
    let found = match field {
        Some(field) => service.placeholders.iter().find(|p| p.field == field),
        None if service.placeholders.len() == 1 => service.placeholders.first(),
        None if service.placeholders.is_empty() => None,
        None => {
            return Err(fail(format!(
                "'{}' has several placeholders, so name the field: {}",
                service.credential,
                service
                    .placeholders
                    .iter()
                    .map(|p| reference(service, p))
                    .collect::<Vec<_>>()
                    .join(", ")
            )))
        }
    };
    found.map(|p| p.placeholder.clone()).ok_or_else(|| {
        fail(format!(
            "'{}' has no placeholder for {}; an admin adds one under Services → Placeholders ({})",
            service.credential,
            field.map_or("its secret".to_string(), |f| format!("field '{f}'")),
            fields()
        ))
    })
}

/// Resolves assignments against the session's services. Later assignments
/// of a name replace earlier ones; `reserved` names (the proxy and trust
/// variables the launcher sets) cannot be assigned.
pub fn resolve(
    assignments: &[Assignment],
    services: &[DiscoveredService],
    reserved: &[String],
) -> Result<Vec<(String, String)>, LauncherError> {
    let mut env: Vec<(String, String)> = Vec::new();
    for a in assignments {
        if reserved.iter().any(|r| r == &a.name)
            || STRIPPED_ENV.contains(&a.name.as_str())
            || a.name.starts_with("TOKENLESS_")
        {
            return Err(LauncherError::config(format!(
                "{}: {} is set by tokenless itself and cannot be assigned",
                a.origin, a.name
            )));
        }
        let value = match a.value.strip_prefix(SCHEME) {
            Some(target) => resolve_reference(a, target, services)?,
            None => a.value.clone(),
        };
        match env.iter_mut().find(|(n, _)| n == &a.name) {
            Some(slot) => slot.1 = value,
            None => env.push((a.name.clone(), value)),
        }
    }
    Ok(env)
}

/// The command to start: the shell's environment minus [`STRIPPED_ENV`],
/// then `env` in order (later entries win).
pub fn agent_command(
    program: &str,
    args: &[String],
    env: &[(String, String)],
) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(program);
    command.args(args);
    for name in STRIPPED_ENV {
        command.env_remove(name);
    }
    command.envs(env.iter().map(|(k, v)| (k, v)));
    command
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokenless_core::ids::RuleId;

    fn placeholder(field: &str, placeholder: &str) -> DiscoveredPlaceholder {
        DiscoveredPlaceholder {
            placeholder: placeholder.into(),
            field: field.into(),
            env: None,
            locations: vec![],
        }
    }

    fn service(
        credential: &str,
        template: &str,
        placeholders: Vec<DiscoveredPlaceholder>,
    ) -> DiscoveredService {
        DiscoveredService {
            rule_id: RuleId::new(),
            rule: format!("{credential} rule"),
            credential: credential.into(),
            template_id: template.into(),
            service: template.to_uppercase(),
            hosts: vec![],
            paths: vec![],
            methods: vec![],
            enabled: true,
            placeholders,
            kind: Default::default(),
            mcp_path: None,
        }
    }

    fn session() -> Vec<DiscoveredService> {
        vec![
            service(
                "Work GitHub",
                "github",
                vec![placeholder("token", "__GITHUB_TOKEN__")],
            ),
            service(
                "Mail",
                "smtp",
                vec![
                    placeholder("user", "__SMTP_USER__"),
                    placeholder("password", "__SMTP_PASS__"),
                ],
            ),
            service("Bare", "bare", vec![]),
        ]
    }

    fn cli(raw: &[&str]) -> Vec<Assignment> {
        raw.iter().map(|r| parse_assignment(r).unwrap()).collect()
    }

    fn err(raw: &[&str]) -> String {
        resolve(&cli(raw), &session(), &[]).unwrap_err().to_string()
    }

    #[test]
    fn references_resolve_to_placeholders_and_literals_pass_through() {
        let env = resolve(
            &cli(&[
                "GH=cb://github/token",
                "GH2=cb://Work GitHub",
                "PASS=cb://mail/password",
                "REGION=eu-west-1",
                "EMPTY=",
                "URL=https://x.test/?a=b",
            ]),
            &session(),
            &[],
        )
        .unwrap();
        assert_eq!(
            env,
            [
                ("GH", "__GITHUB_TOKEN__"),
                ("GH2", "__GITHUB_TOKEN__"),
                ("PASS", "__SMTP_PASS__"),
                ("REGION", "eu-west-1"),
                ("EMPTY", ""),
                ("URL", "https://x.test/?a=b"),
            ]
            .map(|(k, v)| (k.to_string(), v.to_string()))
        );
    }

    #[test]
    fn a_later_assignment_replaces_an_earlier_one() {
        let env = resolve(&cli(&["A=1", "A=cb://github/token"]), &session(), &[]).unwrap();
        assert_eq!(env, vec![("A".to_string(), "__GITHUB_TOKEN__".to_string())]);
    }

    #[test]
    fn unresolvable_references_fail_with_what_is_available() {
        let unknown = err(&["X=cb://nope/token"]);
        assert!(
            unknown.contains("no service in this session is called 'nope'"),
            "{unknown}"
        );
        assert!(unknown.contains("cb://Work GitHub/token"), "{unknown}");
        let field = err(&["X=cb://github/password"]);
        assert!(
            field.contains("no placeholder for field 'password'"),
            "{field}"
        );
        assert!(field.contains("it has token"), "{field}");
        let several = err(&["X=cb://mail"]);
        assert!(
            several.contains("cb://Mail/user, cb://Mail/password"),
            "{several}"
        );
        let none = err(&["X=cb://bare"]);
        assert!(none.contains("it has none"), "{none}");
        assert!(err(&["X=cb://"]).contains("names no service"));
    }

    #[test]
    fn ambiguous_and_disabled_services_are_refused() {
        let mut services = session();
        services.push(service(
            "Personal GitHub",
            "github",
            vec![placeholder("token", "__GH2__")],
        ));
        let e = resolve(&cli(&["X=cb://github/token"]), &services, &[])
            .unwrap_err()
            .to_string();
        assert!(e.contains("matches Work GitHub, Personal GitHub"), "{e}");
        let ok = resolve(&cli(&["X=cb://Personal GitHub/token"]), &services, &[]).unwrap();
        assert_eq!(ok[0].1, "__GH2__");

        let mut services = session();
        services[0].enabled = false;
        let e = resolve(&cli(&["X=cb://github/token"]), &services, &[])
            .unwrap_err()
            .to_string();
        assert!(e.contains("is disabled"), "{e}");
    }

    #[test]
    fn launcher_variables_cannot_be_assigned() {
        let reserved = vec!["HTTPS_PROXY".to_string()];
        for raw in [
            "HTTPS_PROXY=http://elsewhere",
            "TOKENLESS_API_KEY=x",
            "TOKENLESS_PROXY=x",
        ] {
            let e = resolve(&cli(&[raw]), &session(), &reserved)
                .unwrap_err()
                .to_string();
            assert!(e.contains("set by tokenless itself"), "{e}");
        }
    }

    #[test]
    fn bad_arguments_name_the_problem() {
        assert!(parse_assignment("./deploy.sh")
            .unwrap_err()
            .to_string()
            .contains("put the command after --"));
        assert!(parse_assignment("1X=a")
            .unwrap_err()
            .to_string()
            .contains("not an environment variable name"));
        assert!(parse_assignment("A-B=a").is_err());
    }

    #[test]
    fn env_files_hold_references() {
        let path = Path::new(".env.broker");
        let parsed = parse_env_file(
            "# references only\n\nexport GH=cb://github/token\nPASS=\"cb://mail/password\"\nNOTE='a # b'\nREGION=eu-west-1 # comment\n",
            path,
        )
        .unwrap();
        let pairs: Vec<(&str, &str)> = parsed
            .iter()
            .map(|a| (a.name.as_str(), a.value.as_str()))
            .collect();
        assert_eq!(
            pairs,
            [
                ("GH", "cb://github/token"),
                ("PASS", "cb://mail/password"),
                ("NOTE", "a # b"),
                ("REGION", "eu-west-1"),
            ]
        );
        assert_eq!(parsed[0].origin, ".env.broker:3");
        let e = parse_env_file("A=1\nnot a line\n", path)
            .unwrap_err()
            .to_string();
        assert!(e.contains(".env.broker:2: expected NAME=value"), "{e}");
        assert!(parse_env_file("A=\"open\n", path)
            .unwrap_err()
            .to_string()
            .contains("unterminated"));
        let e = resolve(
            &parse_env_file("X=cb://nope\n", path).unwrap(),
            &session(),
            &[],
        )
        .unwrap_err()
        .to_string();
        assert!(e.starts_with(".env.broker:1:"), "{e}");
    }

    #[test]
    fn the_command_does_not_inherit_the_broker_key_or_a_session_token() {
        let command = agent_command("true", &[], &[("GH".into(), "__GITHUB_TOKEN__".into())]);
        let envs: Vec<_> = command.as_std().get_envs().collect();
        for name in STRIPPED_ENV {
            assert!(
                envs.contains(&(std::ffi::OsStr::new(name), None)),
                "{name} must be removed"
            );
        }
        assert!(envs.contains(&(
            std::ffi::OsStr::new("GH"),
            Some(std::ffi::OsStr::new("__GITHUB_TOKEN__"))
        )));
    }
}
