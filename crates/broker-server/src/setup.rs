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
use broker_server::launcher::trust::shell_word;
use broker_server::launcher::{skill, LauncherError};
use serde::Serialize;
use tokenless_control::model::{AccessBundle, StoredTemplate};
use tokenless_core::ids::{BundleId, CredentialId, RuleId, VaultId};
use tokenless_core::template::{builtin_templates, ServiceTemplate};

use super::messages::{self, say};
use super::{home_dir, read_fields, CliError, TerminalPrompter};

pub const DEFAULT_SERVER: &str = "http://127.0.0.1:8080";

/// How often `--web` looks for the new service, and `--secret-file` at the file.
const WEB_POLL: Duration = Duration::from_secs(3);
const FILE_POLL: Duration = Duration::from_millis(500);
/// How long `--web` lets the page finish adding a new service to its bundle.
const WEB_SETTLE: Duration = Duration::from_secs(15);
const SETTLE_POLL: Duration = Duration::from_secs(1);

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
        manage: false,
        vaults: None,
        proxies: None,
        other_hosts: None,
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
                    observed.manage = client.session().manage;
                    observed.vaults =
                        Some(vault_summaries(&client).await.map_err(|e| e.to_string()));
                    observed.proxies = Some(match client.nodes().await {
                        Ok(nodes) => Ok(Some(nodes)),
                        Err(LauncherError::Api { status: 403, .. }) => Ok(None),
                        Err(e) => Err(e.to_string()),
                    });
                    observed.other_hosts = Some(match client.settings().await {
                        Ok(settings) => Ok(Some(settings.unmatched_host_policy)),
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
    let set_up: Vec<skill::Agent> = [skill::Agent::ClaudeCode, skill::Agent::Codex]
        .into_iter()
        .filter(|a| home.is_some_and(|h| a.set_up(h)))
        .collect();
    if set_up.is_empty() {
        return Skill::NoAgent;
    }
    let missing: Vec<&'static str> = set_up
        .iter()
        .filter(|a| !a.has_skill(cwd, home))
        .map(|a| a.name())
        .collect();
    if missing.is_empty() {
        Skill::Installed(set_up.iter().map(|a| a.name()).collect())
    } else {
        Skill::Missing(missing)
    }
}

async fn vault_summaries(client: &ConsoleClient<'_>) -> Result<Vec<VaultSummary>, LauncherError> {
    let mut out = Vec::new();
    for vault in client.vaults().await? {
        let services = client.credentials(&vault.id).await?.len() as u64;
        // Only a bundle with an enabled rule can start a session.
        let bundles = if services > 0 {
            let enabled: Vec<RuleId> = client
                .rules(&vault.id)
                .await?
                .into_iter()
                .filter(|r| r.enabled)
                .map(|r| r.id)
                .collect();
            client
                .bundles(&vault.id)
                .await?
                .into_iter()
                .filter(|b| b.rule_ids.iter().any(|r| enabled.contains(r)))
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
        Ok(client) => client.templates().await,
        Err(e) => Err(e),
    };
    let all: Vec<ServiceTemplate> = match from_server {
        Ok(stored) => templates::newest(
            stored
                .into_iter()
                .filter(|t| t.status == tokenless_control::model::TemplateStatus::Approved)
                .map(|t| t.template),
        ),
        Err(e) => {
            // On stderr even with --json, so a caller can tell the built-in
            // catalogue from the control plane's.
            say(builtin_because(&e));
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

/// Why `service templates` lists only the built-in templates.
fn builtin_because(e: &LauncherError) -> String {
    match e {
        LauncherError::NotSignedIn { .. } => "not signed in, so these are the built-in templates; tokenless login also lists ones imported on your control plane".into(),
        other => format!(
            "could not list the control plane's templates ({other}), so these are the built-in ones"
        ),
    }
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
    // Before anyone is asked for a key: a name the server refuses would
    // only fail after it was handed over.
    if let Some(bundle) = &args.bundle {
        tokenless_control::service::bundles::validate_bundle_name(bundle)
            .map_err(|e| LauncherError::config(e.to_string()))?;
    }
    let template = account::pick_template(client.templates().await?, &args.template)?;
    // The secret file, kept until the key is stored, and the signals that
    // end the waits (not listened for at a terminal prompt, which handles
    // Ctrl-C itself).
    let mut file = None;
    let fields = match &args.source {
        Source::Web { open } => {
            let mut stop = Stop::listen()?;
            return add_from_web(&client, &template, &args, *open, &mut stop).await;
        }
        Source::File { path, open } => {
            let mut stop = Stop::listen()?;
            let (fields, path) = from_file(&template, &args, path, *open, &mut stop).await?;
            file = Some((path, stop));
            fields
        }
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
    let stored = match &mut file {
        Some((path, stop)) => tokio::select! {
            stored = client.add_service(&plan, &template, fields) => stored,
            signal = stop.signalled() => {
                return Err(LauncherError::config(format!(
                    "stopped by {signal} while storing the key, so it may or may not be in vault '{}'; {} still holds it: if the vault's page in the console lists the service, delete the file, otherwise run the same command again",
                    args.vault.trim(),
                    path.display()
                ))
                .into());
            }
        },
        None => client.add_service(&plan, &template, fields).await,
    };
    let file = file.map(|(path, _)| path);
    let added = match stored {
        Ok(added) => added,
        Err(e) => {
            if let Some(path) = &file {
                if matches!(e, LauncherError::PartlyAdded { .. }) {
                    // The key is in the vault; another try would only
                    // collide with it.
                    discard(path);
                } else {
                    say(messages::kept_secret_file(&path.display().to_string()));
                }
            }
            return Err(e.into());
        }
    };
    if let Some(path) = &file {
        discard(path);
    }
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
    format!(
        "tokenless run --vault {} --bundle {} -- <command>",
        shell_word(vault),
        shell_word(bundle)
    )
}

/// Ctrl-C and, on Unix, SIGTERM, listened for from the moment this is made,
/// so a signal that comes while the command is busy (an HTTP call between
/// two waits) is kept for the next wait rather than lost.
struct Stop {
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
}

impl Stop {
    fn listen() -> Result<Self, CliError> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let listen = |kind: SignalKind, name: &str| {
                signal(kind).map_err(|e| CliError::Io {
                    context: format!("listening for {name}"),
                    source: e,
                })
            };
            Ok(Stop {
                interrupt: listen(SignalKind::interrupt(), "SIGINT")?,
                terminate: listen(SignalKind::terminate(), "SIGTERM")?,
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Stop {})
        }
    }

    /// Which signal came.
    async fn signalled(&mut self) -> &'static str {
        #[cfg(unix)]
        {
            tokio::select! {
                _ = self.interrupt.recv() => "SIGINT",
                _ = self.terminate.recv() => "SIGTERM",
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
            "Ctrl-C"
        }
    }
}

/// Deletes a stored key's secret file, or says it could not.
fn discard(path: &Path) {
    if let Err(e) = secret_file::remove(path) {
        say(format_args!(
            "the key is stored, but {} could not be deleted: {e}; delete it yourself",
            path.display()
        ));
    }
}

/// Deletes the secret file this command created when the wait for it ends
/// without a key (a stop signal, the deadline, an unreadable file), unless
/// the process is killed outright. Never armed for a file that was already
/// there, which may be the person's own. Disarmed once the key is read: the
/// file is then kept until the key is stored, so a failed store loses
/// nothing.
struct RemoveOnDrop<'a> {
    path: &'a Path,
    armed: bool,
}

impl Drop for RemoveOnDrop<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Err(e) = secret_file::remove(self.path) {
            say(format_args!(
                "could not delete {}: {e}; delete it yourself",
                self.path.display()
            ));
        }
    }
}

async fn from_file(
    template: &StoredTemplate,
    args: &AddArgs,
    path: &Path,
    open: bool,
    stop: &mut Stop,
) -> Result<(Fields, PathBuf), CliError> {
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
    let mut remove = RemoveOnDrop {
        path: &path,
        armed: prepared == Prepared::Created,
    };
    let shown = path.display().to_string();
    if prepared == Prepared::Created || !secret_file::filled(&path, fields) {
        let what = match fields.as_slice() {
            [only] => format!("the {} {}", template.template.name, only.label),
            _ => format!("each {} credential after its =", template.template.name),
        };
        say(format_args!(
            "put {what} in {shown} and save it. tokenless then stores it encrypted and deletes the file; waiting up to {} minutes",
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
        |problem| {
            say(format_args!(
                "{problem}; fix it in {shown} and save again, still waiting"
            ))
        },
    );
    let values = tokio::select! {
        values = wait => values?,
        signal = stop.signalled() => {
            let file = if remove.armed { "was deleted" } else { "was left as it was" };
            return Err(LauncherError::config(format!("stopped by {signal}; {shown} {file}, nothing was stored")).into());
        }
    };
    remove.armed = false;
    drop(remove);
    Ok((values, path))
}

async fn add_from_web(
    client: &ConsoleClient<'_>,
    template: &StoredTemplate,
    args: &AddArgs,
    open: bool,
    stop: &mut Stop,
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
    // What exists before the page opens, to tell what the page created.
    let mut bundles_before: Vec<BundleId> = Vec::new();
    for v in &vaults {
        bundles_before.extend(client.bundles(&v.id).await?.into_iter().map(|b| b.id));
    }
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
    let stopped = |signal: &str| -> CliError {
        LauncherError::config(format!(
            "stopped waiting by {signal}; a service saved on the page is still added"
        ))
        .into()
    };
    let found = loop {
        let poll = async {
            tokio::time::sleep(WEB_POLL).await;
            services_of(client, id).await
        };
        let now = tokio::select! {
            now = poll => now?,
            signal = stop.signalled() => return Err(stopped(signal)),
        };
        if let Some(new) = now
            .into_iter()
            .find(|(c, ..)| !before.iter().any(|(b, ..)| b == c))
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
    let (credential, service, vault_id, vault_name) = found;
    // The page saves the service, then its rule, then puts the rule in the
    // bundle, each its own request: give it a moment to finish before
    // saying the service is in no bundle.
    let settle = Instant::now() + WEB_SETTLE;
    let joined = loop {
        let joined = bundle_of(client, &vault_id, &credential, args.bundle.as_deref()).await?;
        if joined.is_some() || Instant::now() >= settle {
            break joined;
        }
        tokio::select! {
            () = tokio::time::sleep(SETTLE_POLL) => {}
            signal = stop.signalled() => return Err(stopped(signal)),
        }
    };
    // The page may have created the vault and the bundle; they are new when
    // they were not there before it opened.
    let vault_created = !vaults.iter().any(|v| v.id == vault_id);
    let bundle_created = joined
        .as_ref()
        .is_some_and(|b| !bundles_before.contains(&b.id));
    let joined = joined.map(|b| b.name);
    if args.json {
        print_json(&Added {
            service: &service,
            template: id,
            vault: &vault_name,
            vault_created,
            bundle: joined.as_deref(),
            bundle_created,
            run: joined.as_deref().map(|b| run_command(&vault_name, b)),
        })?;
    } else {
        match &joined {
            Some(b) => say(format_args!(
                "added {service} to vault '{vault_name}' and bundle '{b}' in the console. Start a command behind it: {}",
                run_command(&vault_name, b)
            )),
            None => say(format_args!(
                "added {service} to vault '{vault_name}' in the console, in no access bundle yet; add it to one on the vault's page, then: tokenless run --vault {} --bundle <bundle> -- <command>", shell_word(&vault_name)
            )),
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// The access bundle in `vault` holding a rule of `credential`: the one named
/// `wanted` when it does, else the first. `None` when no bundle holds it.
async fn bundle_of(
    client: &ConsoleClient<'_>,
    vault: &VaultId,
    credential: &CredentialId,
    wanted: Option<&str>,
) -> Result<Option<AccessBundle>, LauncherError> {
    let rules: Vec<RuleId> = client
        .rules(vault)
        .await?
        .into_iter()
        .filter(|r| &r.credential_id == credential)
        .map(|r| r.id)
        .collect();
    let holding: Vec<AccessBundle> = client
        .bundles(vault)
        .await?
        .into_iter()
        .filter(|b| b.rule_ids.iter().any(|r| rules.contains(r)))
        .collect();
    let preferred = wanted
        .map(str::trim)
        .and_then(|w| holding.iter().position(|b| b.name == w))
        .unwrap_or(0);
    Ok(holding.into_iter().nth(preferred))
}

/// Every service made from `template`, in every vault the person sees: its
/// ID, name, and its vault's ID and name.
async fn services_of(
    client: &ConsoleClient<'_>,
    template: &str,
) -> Result<Vec<(CredentialId, String, VaultId, String)>, LauncherError> {
    let mut out = Vec::new();
    for vault in client.vaults().await? {
        for c in client.credentials(&vault.id).await? {
            if c.template_id == template {
                out.push((c.id, c.name, vault.id, vault.name.clone()));
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

    /// A Ctrl-C or SIGTERM that comes while the command is busy with a
    /// request, when nothing waits for it, still ends the next wait.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_signal_while_busy_is_kept_for_the_next_wait() {
        let mut stop = Stop::listen().unwrap();
        assert!(std::process::Command::new("kill")
            .args(["-TERM", &std::process::id().to_string()])
            .status()
            .unwrap()
            .success());
        tokio::time::sleep(Duration::from_millis(200)).await;
        let signal = tokio::time::timeout(Duration::from_secs(5), stop.signalled())
            .await
            .expect("the signal sent before the wait ends it");
        assert_eq!(signal, "SIGTERM");
    }

    #[test]
    fn the_editor_hint_quotes_the_path() {
        let hint = editor_command("/home/someone/My Keys/openai");
        assert!(hint.ends_with("'/home/someone/My Keys/openai'"), "{hint}");
    }
}
