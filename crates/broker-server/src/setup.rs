// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The setup commands built for a first run and for agents: `status` says
//! what is missing and the command that fixes it, `service templates` finds
//! a template, and `service add --web` / `--secret-file` take a secret from
//! the person without it passing through whoever ran the command.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use broker_server::launcher::account::{self, AddService, ConsoleClient, SessionStore};
use broker_server::launcher::secret_file::{self, Fields, Prepared};
use broker_server::launcher::status::{self, Observed, ProxyStateFile, Skill, VaultSummary};
use broker_server::launcher::templates::{self, TemplateRow};
use broker_server::launcher::{skill, LauncherError};
use serde::Serialize;
use tokenless_control::model::StoredTemplate;
use tokenless_core::ids::CredentialId;
use tokenless_core::template::{builtin_templates, ServiceTemplate};

use super::messages::{self, say};
use super::{home_dir, read_fields, stop_signal, CliError, TerminalPrompter};

pub const DEFAULT_SERVER: &str = "http://127.0.0.1:8080";

/// How often `--web` looks for the new service, and `--secret-file` at the file.
const WEB_POLL: Duration = Duration::from_secs(3);
const FILE_POLL: Duration = Duration::from_millis(500);

pub async fn status_command(server: String, json: bool) -> Result<ExitCode, CliError> {
    let cwd = std::env::current_dir().map_err(|e| CliError::Io {
        context: "reading the current directory".into(),
        source: e,
    })?;
    let home = home_dir();
    let base = server.trim().trim_end_matches('/').to_string();
    let control_plane = account::probe(&base).await.map(|_| ());
    let mut observed = Observed {
        version: broker_server::update::VERSION.to_string(),
        default_server: base == DEFAULT_SERVER,
        server: base.clone(),
        control_plane: control_plane.clone(),
        signed_in: None,
        vaults: None,
        proxies: None,
        skill: skill_state(&cwd, home.as_deref()),
        behind_tokenless: std::env::var_os("TOKENLESS_PROXY").is_some_and(|v| !v.is_empty()),
        proxy_state: ProxyStateFile::find(home.as_deref(), &cwd),
        now: chrono::Utc::now(),
    };
    if control_plane.is_ok() {
        let prompter = TerminalPrompter;
        match ConsoleClient::open(&SessionStore::system(), &base, &prompter) {
            Err(LauncherError::NotSignedIn { .. }) => observed.signed_in = Some(Ok(None)),
            Err(e) => observed.signed_in = Some(Err(e.to_string())),
            Ok(client) => match client.me().await {
                Err(LauncherError::NotSignedIn { .. }) => {
                    observed.signed_in = Some(Err("the saved session has ended".into()))
                }
                Err(e) => observed.signed_in = Some(Err(e.to_string())),
                Ok(user) => {
                    observed.signed_in = Some(Ok(Some(user.username)));
                    observed.vaults =
                        Some(vault_summaries(&client).await.map_err(|e| e.to_string()));
                    observed.proxies = Some(match client.nodes().await {
                        Ok(nodes) => Ok(Some(nodes)),
                        Err(LauncherError::Api { status: 403, .. }) => Ok(None),
                        Err(e) => Err(e.to_string()),
                    });
                }
            },
        }
    }
    let report = status::assess(observed);
    if json {
        print_json(&report)?;
    } else {
        print!("{}", status::render(&report));
    }
    Ok(if report.ready {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn skill_state(cwd: &Path, home: Option<&Path>) -> Skill {
    if skill::installed_in(&skill::claude_dirs(cwd, home)) {
        Skill::Installed
    } else if home.is_some_and(|h| h.join(".claude").is_dir()) {
        Skill::Missing
    } else {
        Skill::NoClaudeCode
    }
}

async fn vault_summaries(client: &ConsoleClient<'_>) -> Result<Vec<VaultSummary>, LauncherError> {
    let mut out = Vec::new();
    for vault in client.vaults().await? {
        let services = client.credentials(&vault.id).await?.len() as u64;
        let bundles = if services > 0 {
            client
                .bundles(&vault.id)
                .await?
                .into_iter()
                .map(|b| b.name)
                .collect()
        } else {
            Vec::new()
        };
        out.push(VaultSummary {
            name: vault.name,
            services,
            bundles,
        });
    }
    Ok(out)
}

pub async fn templates_command(
    query: Option<String>,
    json: bool,
    server: String,
) -> Result<ExitCode, CliError> {
    let prompter = TerminalPrompter;
    // The control plane also lists templates an admin imported; without
    // one, the built-in catalogue is still worth searching.
    let from_server = match ConsoleClient::open(&SessionStore::system(), &server, &prompter) {
        Ok(client) => client.templates().await.ok(),
        Err(_) => None,
    };
    let all: Vec<ServiceTemplate> = match from_server {
        Some(stored) => templates::newest(
            stored
                .into_iter()
                .filter(|t| t.status == tokenless_control::model::TemplateStatus::Approved)
                .map(|t| t.template),
        ),
        None => {
            if !json {
                say("not signed in, so these are the built-in templates; tokenless login also lists ones imported on your control plane");
            }
            builtin_templates()
                .map_err(|e| LauncherError::config(format!("reading the built-in templates: {e}")))?
                .into_iter()
                .map(|(t, _)| t)
                .collect()
        }
    };
    let found = templates::search(&all, query.as_deref());
    if json {
        let rows: Vec<TemplateRow> = found.iter().map(|t| TemplateRow::from(*t)).collect();
        print_json(&rows)?;
    } else if !found.is_empty() {
        print!("{}", templates::table(&found));
    }
    if found.is_empty() {
        if !json {
            say(format_args!(
                "no template matches '{}'; any other HTTP API can be added as a custom service in the console (Add a service)",
                query.unwrap_or_default()
            ));
        }
        return Ok(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}

/// How `service add` gets the secret.
pub enum Source {
    /// Asked for in this terminal, or read from standard input.
    Terminal,
    /// Typed by the person in the console; this only waits for it.
    Web { open: bool },
    /// Saved by the person in this file, which is deleted afterwards.
    File { path: PathBuf, open: bool },
}

pub struct AddArgs {
    pub template: String,
    pub vault: String,
    pub bundle: Option<String>,
    pub name: Option<String>,
    pub read_only: bool,
    pub server: String,
    pub source: Source,
    /// How long `--web` and `--secret-file` wait for the person; `None`
    /// does not wait for `--web`.
    pub wait: Option<Duration>,
    pub json: bool,
}

/// What `service add --json` prints.
#[derive(Serialize)]
struct Added<'a> {
    service: &'a str,
    template: &'a str,
    vault: &'a str,
    vault_created: bool,
    bundle: Option<&'a str>,
    bundle_created: bool,
    /// How to start a command with it, when the bundle is known.
    run: Option<String>,
}

pub async fn add_service(args: AddArgs) -> Result<ExitCode, CliError> {
    let prompter = TerminalPrompter;
    let client = ConsoleClient::open(&SessionStore::system(), &args.server, &prompter)?;
    let template = account::pick_template(client.templates().await?, &args.template)?;
    let fields = match &args.source {
        Source::Web { open } => return add_from_web(&client, &template, &args, *open).await,
        Source::File { path, open } => from_file(&template, &args, path, *open).await?,
        Source::Terminal => {
            if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                say(messages::service_prompt(
                    &template.template.name,
                    args.vault.trim(),
                ));
            }
            read_fields(&template, &prompter)?
        }
    };
    let plan = AddService {
        template_id: template.template.id.clone(),
        name: args.name.clone(),
        vault: args.vault.clone(),
        bundle: args.bundle.clone(),
        read_only: args.read_only,
    };
    let added = client.add_service(&plan, &template, fields).await?;
    let bundle = added
        .bundle
        .as_ref()
        .map(|(b, created)| (b.name.as_str(), *created));
    if args.json {
        print_json(&Added {
            service: &added.credential.name,
            template: &template.template.id,
            vault: &added.vault.name,
            vault_created: added.vault_created,
            bundle: bundle.map(|(b, _)| b),
            bundle_created: bundle.is_some_and(|(_, c)| c),
            run: bundle.map(|(b, _)| run_command(&added.vault.name, b)),
        })?;
    } else {
        say(messages::added_service(&messages::AddedService {
            service: &added.credential.name,
            vault: &added.vault.name,
            vault_created: added.vault_created,
            bundle,
            rule: &added.rule.name,
        }));
    }
    Ok(ExitCode::SUCCESS)
}

fn run_command(vault: &str, bundle: &str) -> String {
    format!("tokenless run --vault {vault} --bundle {bundle} -- <command>")
}

/// Deletes the secret file however the command ends, unless the process is
/// killed outright.
struct RemoveOnDrop<'a>(&'a Path);

impl Drop for RemoveOnDrop<'_> {
    fn drop(&mut self) {
        if let Err(e) = secret_file::remove(self.0) {
            say(format_args!(
                "could not delete {}: {e}; delete it yourself",
                self.0.display()
            ));
        }
    }
}

async fn from_file(
    template: &StoredTemplate,
    args: &AddArgs,
    path: &Path,
    open: bool,
) -> Result<Fields, CliError> {
    let home = home_dir();
    let path = if path.as_os_str().is_empty() {
        let home = home.as_deref().ok_or_else(|| {
            LauncherError::config(
                "HOME is not set, so there is no default secret file; pass --secret-file <path>",
            )
        })?;
        secret_file::default_path(home, &template.template.id)
    } else {
        secret_file::expand(path, home.as_deref())
    };
    let fields = &template.template.credential_fields;
    let prepared = secret_file::prepare(&path, &template.template.name, args.vault.trim(), fields)?;
    let _remove = RemoveOnDrop(&path);
    let shown = path.display().to_string();
    if prepared == Prepared::Created || !secret_file::filled(&path, fields) {
        let what = match fields.as_slice() {
            [only] => format!("the {} {}", template.template.name, only.label),
            _ => format!("each {} credential after its =", template.template.name),
        };
        say(format_args!(
            "put {what} in {shown} and save it. tokenless then reads it, deletes the file and stores it encrypted; waiting up to {} minutes",
            args.wait.unwrap_or(Duration::ZERO).as_secs().div_ceil(60)
        ));
        if open {
            open_with_system(&shown, true);
        } else {
            say(format_args!("open it with: {}", editor_command(&shown)));
        }
    }
    let wait = secret_file::wait(
        path.as_path(),
        fields,
        args.wait.unwrap_or(Duration::ZERO),
        FILE_POLL,
    );
    let values = tokio::select! {
        values = wait => values?,
        signal = stop_signal() => {
            let signal = signal.unwrap_or("a stop signal");
            return Err(LauncherError::config(format!("stopped by {signal}; {shown} was deleted, nothing was stored")).into());
        }
    };
    Ok(values)
}

async fn add_from_web(
    client: &ConsoleClient<'_>,
    template: &StoredTemplate,
    args: &AddArgs,
    open: bool,
) -> Result<ExitCode, CliError> {
    let id = &template.template.id;
    let vaults = client.vaults().await?;
    let vault = vaults.iter().find(|v| v.name == args.vault.trim());
    let bundle = match (vault, args.bundle.as_deref()) {
        (Some(v), Some(name)) => client
            .bundles(&v.id)
            .await?
            .into_iter()
            .find(|b| b.name == name.trim()),
        _ => None,
    };
    let before = services_of(client, id).await?;
    let url = account::add_service_url(
        &args.server,
        id,
        vault.map(|v| &v.id),
        bundle.as_ref().map(|b| &b.id),
    )?;
    let choose = match (vault, args.bundle.as_deref(), &bundle) {
        (None, _, _) => format!(" Create vault '{}' there.", args.vault.trim()),
        (Some(_), Some(name), None) => format!(" Create access bundle '{name}' there."),
        _ => String::new(),
    };
    say(format_args!(
        "open this page, signed in to the console, and save the {} secret there; it never passes through this terminal.{choose}\n  {url}",
        template.template.name
    ));
    if open {
        open_with_system(&url, false);
    }
    let Some(timeout) = args.wait else {
        return Ok(ExitCode::SUCCESS);
    };
    let deadline = Instant::now() + timeout;
    let found = loop {
        tokio::select! {
            () = tokio::time::sleep(WEB_POLL) => {}
            signal = stop_signal() => {
                let signal = signal.unwrap_or("a stop signal");
                return Err(LauncherError::config(format!("stopped waiting by {signal}; a service saved on the page is still added")).into());
            }
        }
        let now = services_of(client, id).await?;
        if let Some(new) = now
            .into_iter()
            .find(|(c, _, _)| !before.iter().any(|(b, _, _)| b == c))
        {
            break new;
        }
        if Instant::now() >= deadline {
            return Err(LauncherError::config(format!(
                "no {} service was saved within {} minutes; run the command again to keep waiting",
                template.template.name,
                timeout.as_secs().div_ceil(60)
            ))
            .into());
        }
    };
    let (_, service, vault) = found;
    if args.json {
        print_json(&Added {
            service: &service,
            template: id,
            vault: &vault,
            vault_created: false,
            bundle: None,
            bundle_created: false,
            run: None,
        })?;
    } else {
        say(format_args!(
            "added {service} to vault '{vault}' in the console. Start a command with its bundle: tokenless run --vault {vault} --bundle <bundle> -- <command>"
        ));
    }
    Ok(ExitCode::SUCCESS)
}

/// Every service made from `template`, in every vault the person sees: its
/// ID, name and vault.
async fn services_of(
    client: &ConsoleClient<'_>,
    template: &str,
) -> Result<Vec<(CredentialId, String, String)>, LauncherError> {
    let mut out = Vec::new();
    for vault in client.vaults().await? {
        for c in client.credentials(&vault.id).await? {
            if c.template_id == template {
                out.push((c.id, c.name, vault.name.clone()));
            }
        }
    }
    Ok(out)
}

/// How to open `path` in a text editor here.
fn editor_command(path: &str) -> String {
    let quoted = broker_server::launcher::trust::shell_quote(path);
    if cfg!(target_os = "macos") {
        format!("open -t {quoted}")
    } else {
        format!("${{EDITOR:-nano}} {quoted}")
    }
}

/// Opens a URL in the browser, or a file in the text editor. A failure is
/// only a warning: the command already printed what to open.
fn open_with_system(target: &str, text_file: bool) {
    let mut command = if cfg!(target_os = "macos") {
        let mut c = std::process::Command::new("open");
        if text_file {
            c.arg("-t");
        }
        c
    } else {
        std::process::Command::new("xdg-open")
    };
    match command.arg(target).status() {
        Ok(s) if s.success() => {}
        Ok(s) => say(format_args!(
            "could not open {target} ({s}); open it yourself"
        )),
        Err(e) => say(format_args!(
            "could not open {target} ({e}); open it yourself"
        )),
    }
}

fn print_json(value: &impl Serialize) -> Result<(), CliError> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|e| LauncherError::config(format!("encoding the output as JSON: {e}")))?;
    println!("{text}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_editor_hint_quotes_the_path() {
        let hint = editor_command("/home/someone/My Keys/openai");
        assert!(hint.ends_with("'/home/someone/My Keys/openai'"), "{hint}");
    }
}
