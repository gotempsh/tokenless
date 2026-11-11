// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The agent skill: instructions for an agent working behind the broker,
//! shipped inside the binary so it always matches the CLI that installs it.

use std::path::{Path, PathBuf};

use super::LauncherError;

/// `skills/tokenless/SKILL.md`.
pub const SKILL_MD: &str = include_str!("../../../../skills/tokenless/SKILL.md");

/// The skill's directory name, which is also its `name`.
pub const SKILL_NAME: &str = "tokenless";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Installed {
    Created,
    Unchanged,
    Replaced,
}

/// Where personal skills live: `~/.claude/skills`.
pub fn default_dir() -> Result<PathBuf, LauncherError> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(|home| PathBuf::from(home).join(".claude").join("skills"))
        .ok_or_else(|| {
            LauncherError::config("HOME is not set, so there is no default skills directory; pass --dir <skills directory>")
        })
}

/// Writes `<skills_dir>/tokenless/SKILL.md`. A different file
/// already there is only replaced with `force`, since it may hold local
/// edits.
pub fn install(skills_dir: &Path, force: bool) -> Result<(PathBuf, Installed), LauncherError> {
    let dir = skills_dir.join(SKILL_NAME);
    let path = dir.join("SKILL.md");
    let outcome = match std::fs::read_to_string(&path) {
        Ok(existing) if existing == SKILL_MD => return Ok((path, Installed::Unchanged)),
        Ok(_) if !force => {
            return Err(LauncherError::config(format!(
            "{} already exists and differs from this version's skill; pass --force to replace it",
            path.display()
        )))
        }
        Ok(_) => Installed::Replaced,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Installed::Created,
        Err(e) => {
            return Err(LauncherError::Io {
                context: format!("reading {}", path.display()),
                source: e,
            })
        }
    };
    std::fs::create_dir_all(&dir)
        .map_err(LauncherError::io(format!("creating {}", dir.display())))?;
    std::fs::write(&path, SKILL_MD)
        .map_err(LauncherError::io(format!("writing {}", path.display())))?;
    Ok((path, outcome))
}

/// Programs whose agent reads skills from `.claude/skills`.
const CLAUDE_CODE: &[&str] = &["claude"];

/// Whether `program` (its file name) is an agent that reads skills where
/// [`install`] puts them.
pub fn reads_claude_skills(program: &str) -> bool {
    CLAUDE_CODE.contains(&program)
}

/// The skills directories Claude Code reads from `cwd`: `.claude/skills`
/// in it and each folder above it, then `~/.claude/skills`.
pub fn claude_dirs(cwd: &Path, home: Option<&Path>) -> Vec<PathBuf> {
    cwd.ancestors()
        .map(|dir| dir.join(".claude").join("skills"))
        .chain(home.map(|h| h.join(".claude").join("skills")))
        .collect()
}

/// Whether any of `dirs` holds the skill: this version's or another (an
/// older one, a newer one from `npx skills`, or a copy with local edits,
/// all of which work).
pub fn installed_in(dirs: &[PathBuf]) -> bool {
    dirs.iter()
        .any(|dir| dir.join(SKILL_NAME).join("SKILL.md").is_file())
}

/// What to say before running `program` when it is an agent that would
/// read the skill and none is installed where it looks.
pub fn missing_hint(program: &str, cwd: &Path, home: Option<&Path>) -> Option<&'static str> {
    (reads_claude_skills(program) && !installed_in(&claude_dirs(cwd, home))).then_some(
        "the tokenless skill isn't installed for Claude Code, so it won't know how to use placeholders or read the proxy's errors. Install it with: tokenless skill --install",
    )
}

/// Where `tokenless login` offers to install the skill: `~/.claude/skills`,
/// when Claude Code is set up on this machine (`~/.claude` exists) and no
/// copy is installed where it would look from `cwd`.
pub fn install_offer(cwd: &Path, home: Option<&Path>) -> Option<PathBuf> {
    let home = home?;
    let claude = home.join(".claude");
    (claude.is_dir() && !installed_in(&claude_dirs(cwd, Some(home)))).then(|| claude.join("skills"))
}

/// Reads a yes/no answer to `question` from `input`, writing the question
/// to `output`. An empty answer is yes.
pub fn ask_yes(
    question: &str,
    input: &mut impl std::io::BufRead,
    output: &mut impl std::io::Write,
) -> std::io::Result<bool> {
    loop {
        write!(output, "{question} [Y/n] ")?;
        output.flush()?;
        let mut answer = String::new();
        if input.read_line(&mut answer)? == 0 {
            return Ok(false);
        }
        match answer.trim().to_ascii_lowercase().as_str() {
            "" | "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hint_shows_only_for_claude_code_without_the_skill() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let project = root.path().join("work").join("repo");
        let nested = project.join("src");
        std::fs::create_dir_all(&nested).unwrap();
        assert!(missing_hint("claude", &nested, Some(&home)).is_some());
        // Other programs never get it, so `run -- curl` stays quiet.
        assert!(missing_hint("curl", &nested, Some(&home)).is_none());

        // In the project, from a folder inside it.
        install(&project.join(".claude").join("skills"), false).unwrap();
        assert!(missing_hint("claude", &nested, Some(&home)).is_none());
        assert!(missing_hint("claude", &root.path().join("work"), Some(&home)).is_some());

        // Personal skills, in any version.
        let personal = home.join(".claude").join("skills").join(SKILL_NAME);
        std::fs::create_dir_all(&personal).unwrap();
        std::fs::write(personal.join("SKILL.md"), "an older version").unwrap();
        assert!(missing_hint("claude", &root.path().join("work"), Some(&home)).is_none());
    }

    #[test]
    fn login_offers_the_install_only_to_claude_code_users_without_it() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let cwd = root.path().join("work");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&cwd).unwrap();
        assert_eq!(
            install_offer(&cwd, Some(&home)),
            None,
            "no Claude Code here"
        );
        assert_eq!(install_offer(&cwd, None), None);
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        let offered = install_offer(&cwd, Some(&home)).unwrap();
        assert_eq!(offered, home.join(".claude").join("skills"));
        install(&offered, false).unwrap();
        assert_eq!(install_offer(&cwd, Some(&home)), None);
    }

    #[test]
    fn ask_yes_defaults_to_yes_and_asks_again_on_anything_else() {
        let ask = |typed: &str| {
            let mut out = Vec::new();
            let yes = ask_yes("Install?", &mut typed.as_bytes(), &mut out).unwrap();
            (yes, String::from_utf8(out).unwrap())
        };
        assert!(ask("\n").0);
        assert!(ask("Y\n").0);
        assert!(!ask("no\n").0);
        let (yes, out) = ask("maybe\nn\n");
        assert!(!yes);
        assert_eq!(out.matches("Install? [Y/n] ").count(), 2);
        // End of input is no.
        assert!(!ask("").0);
    }

    #[test]
    fn the_skill_has_frontmatter_naming_it() {
        let front = SKILL_MD
            .strip_prefix("---\n")
            .and_then(|rest| rest.split_once("\n---\n"))
            .map(|(front, _)| front)
            .expect("SKILL.md starts with a frontmatter block");
        assert!(
            front.lines().any(|l| l == format!("name: {SKILL_NAME}")),
            "{front}"
        );
        // `npx skills add gotempsh/tokenless` finds skills/<name>/SKILL.md
        // and only accepts lowercase names with hyphens.
        assert!(
            SKILL_NAME
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
            "{SKILL_NAME}"
        );
        let description = front
            .lines()
            .find_map(|l| l.strip_prefix("description: "))
            .expect("a description");
        assert!(
            description.len() <= 1024,
            "descriptions are capped at 1024 characters"
        );
        assert!(SKILL_MD.contains("cb://"));
    }

    #[test]
    fn the_skill_covers_services_without_placeholders() {
        // Templates create no placeholders, so the common case is a service
        // with none: the skill must say what to do then, quote the error a
        // `cb://` reference to it gets, and point at where an admin adds one.
        assert!(SKILL_MD.contains("lists none (the usual case)"));
        assert!(SKILL_MD.contains("has no placeholder for"));
        assert!(SKILL_MD.contains("Services → Placeholders"));
        assert!(SKILL_MD.contains("## 5. MCP servers through the gateway"));
    }

    #[test]
    fn the_skill_moves_keys_into_a_vault_without_seeing_them() {
        // Outside the broker the skill is what suggests tokenless when a key
        // comes up, so its description must say when, and the section must
        // keep the key away from the agent.
        let description = SKILL_MD
            .lines()
            .find_map(|l| l.strip_prefix("description: "))
            .expect("a description");
        assert!(
            description.contains("TOKENLESS_PROXY is not set"),
            "{description}"
        );
        assert!(SKILL_MD.contains("## 6. Not behind tokenless yet"));
        assert!(SKILL_MD
            .contains("Never ask for the key, read it from a file or an environment variable"));
        assert!(SKILL_MD.contains("suggest they revoke it"));
    }

    #[test]
    fn the_skill_connects_a_machine_to_a_teams_server() {
        // With a shared control plane the agent must not start another one,
        // must sign the person in as themselves rather than the default
        // admin, and must enrol a proxy on this machine even when a non-admin
        // can't use `proxy add`.
        let description = SKILL_MD
            .lines()
            .find_map(|l| l.strip_prefix("description: "))
            .expect("a description");
        assert!(
            description.contains("a team's tokenless server"),
            "{description}"
        );
        assert!(SKILL_MD.contains("### On a team's server"));
        assert!(SKILL_MD.contains("Then don't start another"));
        assert!(SKILL_MD.contains("tokenless login --username <their username>"));
        assert!(SKILL_MD.contains("only an admin can see proxies"));
        assert!(SKILL_MD.contains("tokenless node join --control-url"));
    }

    #[test]
    fn install_creates_then_keeps_local_edits_unless_forced() {
        let dir = tempfile::tempdir().unwrap();
        let (path, outcome) = install(dir.path(), false).unwrap();
        assert_eq!(outcome, Installed::Created);
        assert_eq!(path, dir.path().join("tokenless").join("SKILL.md"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), SKILL_MD);
        assert_eq!(install(dir.path(), false).unwrap().1, Installed::Unchanged);

        std::fs::write(&path, "local edits").unwrap();
        let e = install(dir.path(), false).unwrap_err().to_string();
        assert!(e.contains("pass --force"), "{e}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "local edits");
        assert_eq!(install(dir.path(), true).unwrap().1, Installed::Replaced);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), SKILL_MD);
    }
}
