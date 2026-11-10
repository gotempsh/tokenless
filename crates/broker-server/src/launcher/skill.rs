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
    /// A link to the shared copy was made.
    Linked,
    Unchanged,
    Replaced,
}

/// The agents whose skills folder differs, as `npx skills` lays them out:
/// Codex, like most other agents, reads `.agents/skills`, which holds the
/// one copy; Claude Code reads `.claude/skills`, which links to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Agent {
    ClaudeCode,
    Codex,
}

impl Agent {
    pub fn name(self) -> &'static str {
        match self {
            Agent::ClaudeCode => "Claude Code",
            Agent::Codex => "Codex",
        }
    }

    /// Its skills folder in `base`: a project, or the home directory.
    pub fn skills_dir(self, base: &Path) -> PathBuf {
        let folder = match self {
            Agent::ClaudeCode => ".claude",
            Agent::Codex => ".agents",
        };
        base.join(folder).join("skills")
    }

    /// The agent `program` (a file name) starts, if it reads skills.
    pub fn of_program(program: &str) -> Option<Agent> {
        match program {
            "claude" => Some(Agent::ClaudeCode),
            "codex" => Some(Agent::Codex),
            _ => None,
        }
    }

    /// Whether it is set up for this user: `~/.claude` for Claude Code,
    /// `~/.codex` (its settings) or `~/.agents` for Codex.
    pub fn set_up(self, home: &Path) -> bool {
        match self {
            Agent::ClaudeCode => home.join(".claude").is_dir(),
            Agent::Codex => home.join(".codex").is_dir() || home.join(".agents").is_dir(),
        }
    }

    /// The skills folders it reads from `cwd`: in it and each folder above
    /// it, then the home directory's.
    pub fn dirs(self, cwd: &Path, home: Option<&Path>) -> Vec<PathBuf> {
        cwd.ancestors()
            .chain(home)
            .map(|base| self.skills_dir(base))
            .collect()
    }

    /// Whether it finds the skill from `cwd`, in any version.
    pub fn has_skill(self, cwd: &Path, home: Option<&Path>) -> bool {
        installed_in(&self.dirs(cwd, home))
    }
}

/// The home directory, for installing the skill for every project.
pub fn home() -> Result<PathBuf, LauncherError> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| {
            LauncherError::config(
                "HOME is not set, so there is no skills directory to install into; pass --project or --dir <skills directory>",
            )
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

/// Where [`install_for_agents`] put the skill, and for whom.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placed {
    pub agents: &'static str,
    pub path: PathBuf,
    pub outcome: Installed,
}

/// Installs the skill in `base` (the home directory, or a project) as
/// `npx skills add` does: the copy in `<base>/.agents/skills/tokenless`,
/// which Codex and most other agents read, and for Claude Code
/// (`claude_code`) `<base>/.claude/skills/tokenless` linked to it. `copy`
/// writes a second copy there instead, as happens anyway where no link can
/// be made. Anything else already in either place is only replaced with
/// `force`.
pub fn install_for_agents(
    base: &Path,
    claude_code: bool,
    copy: bool,
    force: bool,
) -> Result<Vec<Placed>, LauncherError> {
    let (path, outcome) = install(&Agent::Codex.skills_dir(base), force)?;
    let mut placed = vec![Placed {
        agents: "Codex and other agents",
        path,
        outcome,
    }];
    if claude_code {
        placed.push(place_for_claude_code(base, copy, force)?);
    }
    Ok(placed)
}

/// What is at Claude Code's skill folder before installing.
enum Existing {
    Nothing,
    /// The link [`install_for_agents`] makes.
    OurLink,
    /// A copy of this version and nothing else, so replacing it loses nothing.
    SameCopy,
    Other,
}

fn existing(link: &Path, target: &Path) -> Result<Existing, LauncherError> {
    let meta = match std::fs::symlink_metadata(link) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Existing::Nothing),
        Err(e) => return Err(LauncherError::io(format!("checking {}", link.display()))(e)),
    };
    if meta.file_type().is_symlink() {
        let ours = std::fs::read_link(link).is_ok_and(|to| to == target);
        return Ok(if ours {
            Existing::OurLink
        } else {
            Existing::Other
        });
    }
    if !meta.is_dir() {
        return Ok(Existing::Other);
    }
    let entries: Vec<_> = std::fs::read_dir(link)
        .map_err(LauncherError::io(format!("reading {}", link.display())))?
        .filter_map(Result::ok)
        .map(|e| e.file_name())
        .collect();
    let same = entries.len() == 1
        && entries[0] == "SKILL.md"
        && std::fs::read_to_string(link.join("SKILL.md")).is_ok_and(|c| c == SKILL_MD);
    Ok(if same {
        Existing::SameCopy
    } else {
        Existing::Other
    })
}

fn place_for_claude_code(base: &Path, copy: bool, force: bool) -> Result<Placed, LauncherError> {
    let skills = Agent::ClaudeCode.skills_dir(base);
    let link = skills.join(SKILL_NAME);
    // Relative, as `npx skills` links it, so it holds if the folder moves.
    let target = Path::new("..")
        .join("..")
        .join(".agents")
        .join("skills")
        .join(SKILL_NAME);
    let placed = |path: PathBuf, outcome| Placed {
        agents: Agent::ClaudeCode.name(),
        path,
        outcome,
    };
    let found = existing(&link, &target)?;
    match (&found, copy) {
        (Existing::OurLink, false) => return Ok(placed(link, Installed::Unchanged)),
        (Existing::SameCopy, true) => {
            return Ok(placed(link.join("SKILL.md"), Installed::Unchanged))
        }
        (Existing::Other, _) if !force => {
            return Err(LauncherError::config(format!(
                "{} already exists and is not this version's skill; pass --force to replace it",
                link.display()
            )))
        }
        _ => {}
    }
    // Only what --force overwrote counts as replaced: an old copy of this
    // version, or the link swapped for a copy, loses nothing.
    let overwritten = matches!(found, Existing::Other);
    if !matches!(found, Existing::Nothing) {
        let removed = match std::fs::symlink_metadata(&link) {
            Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(&link),
            _ => std::fs::remove_file(&link),
        };
        removed.map_err(LauncherError::io(format!("replacing {}", link.display())))?;
    }
    if !copy {
        std::fs::create_dir_all(&skills)
            .map_err(LauncherError::io(format!("creating {}", skills.display())))?;
        if make_link(&target, &link).is_ok() {
            let outcome = if overwritten {
                Installed::Replaced
            } else {
                Installed::Linked
            };
            return Ok(placed(link, outcome));
        }
    }
    let (path, outcome) = install(&skills, true)?;
    let outcome = if overwritten {
        Installed::Replaced
    } else {
        outcome
    };
    Ok(placed(path, outcome))
}

#[cfg(unix)]
fn make_link(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

/// Windows needs a privilege for links, so the skill is copied there.
#[cfg(not(unix))]
fn make_link(_target: &Path, _link: &Path) -> std::io::Result<()> {
    Err(std::io::ErrorKind::Unsupported.into())
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
pub fn missing_hint(program: &str, cwd: &Path, home: Option<&Path>) -> Option<String> {
    let agent = Agent::of_program(program)?;
    (!agent.has_skill(cwd, home)).then(|| {
        format!(
            "the tokenless skill isn't installed for {}, so it won't know how to use placeholders or read the proxy's errors. Install it with: tokenless skill --install",
            agent.name()
        )
    })
}

/// The agents set up for this user that find no copy of the skill from
/// `cwd`, which `tokenless login` offers to install it for. Empty without a
/// home directory.
pub fn install_offer(cwd: &Path, home: Option<&Path>) -> Vec<Agent> {
    let Some(home) = home else {
        return Vec::new();
    };
    [Agent::ClaudeCode, Agent::Codex]
        .into_iter()
        .filter(|a| a.set_up(home) && !a.has_skill(cwd, Some(home)))
        .collect()
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
    fn the_hint_names_the_agent_that_would_miss_the_skill() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let project = root.path().join("work").join("repo");
        let nested = project.join("src");
        std::fs::create_dir_all(&nested).unwrap();
        let hint = missing_hint("claude", &nested, Some(&home)).unwrap();
        assert!(hint.contains("for Claude Code"), "{hint}");
        let hint = missing_hint("codex", &nested, Some(&home)).unwrap();
        assert!(hint.contains("for Codex"), "{hint}");
        // Other programs never get it, so `run -- curl` stays quiet.
        assert!(missing_hint("curl", &nested, Some(&home)).is_none());

        // In the project, from a folder inside it: each agent in its folder.
        install(&project.join(".agents").join("skills"), false).unwrap();
        assert!(missing_hint("codex", &nested, Some(&home)).is_none());
        assert!(missing_hint("claude", &nested, Some(&home)).is_some());
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
    fn login_offers_the_install_to_the_agents_set_up_without_it() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let cwd = root.path().join("work");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&cwd).unwrap();
        assert!(install_offer(&cwd, Some(&home)).is_empty(), "no agent here");
        assert!(install_offer(&cwd, None).is_empty());
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        assert_eq!(install_offer(&cwd, Some(&home)), [Agent::ClaudeCode]);
        std::fs::create_dir_all(home.join(".codex")).unwrap();
        assert_eq!(
            install_offer(&cwd, Some(&home)),
            [Agent::ClaudeCode, Agent::Codex]
        );
        install_for_agents(&home, true, false, false).unwrap();
        assert!(install_offer(&cwd, Some(&home)).is_empty());
    }

    #[test]
    fn it_is_installed_as_npx_skills_lays_it_out() {
        let home = tempfile::tempdir().unwrap();
        let home = home.path();
        let shared = home.join(".agents/skills/tokenless/SKILL.md");
        let link = home.join(".claude/skills/tokenless");

        let placed = install_for_agents(home, true, false, false).unwrap();
        assert_eq!(placed.len(), 2);
        assert_eq!(placed[0].path, shared);
        assert_eq!(placed[0].outcome, Installed::Created);
        assert_eq!(std::fs::read_to_string(&shared).unwrap(), SKILL_MD);
        // Claude Code reads it through the link, as `npx skills` makes it.
        assert_eq!(
            std::fs::read_to_string(link.join("SKILL.md")).unwrap(),
            SKILL_MD
        );
        #[cfg(unix)]
        {
            assert_eq!(placed[1].outcome, Installed::Linked);
            assert_eq!(
                std::fs::read_link(&link).unwrap(),
                Path::new("../../.agents/skills/tokenless")
            );
        }

        // Again: nothing to do.
        let again = install_for_agents(home, true, false, false).unwrap();
        assert!(
            again.iter().all(|p| p.outcome == Installed::Unchanged),
            "{again:?}"
        );

        // Without Claude Code, only the shared copy.
        let bare = tempfile::tempdir().unwrap();
        let placed = install_for_agents(bare.path(), false, false, false).unwrap();
        assert_eq!(placed.len(), 1);
        assert!(!bare.path().join(".claude").exists());
    }

    #[cfg(unix)]
    #[test]
    fn an_old_copy_for_claude_code_becomes_the_link_and_edits_need_force() {
        let home = tempfile::tempdir().unwrap();
        let home = home.path();
        let link = home.join(".claude/skills/tokenless");

        // A copy of this version, as `skill --install` used to write it,
        // is replaced by the link: nothing is lost.
        install(&home.join(".claude/skills"), false).unwrap();
        let placed = install_for_agents(home, true, false, false).unwrap();
        assert_eq!(placed[1].outcome, Installed::Linked);
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());

        // A copy with edits is only replaced with --force.
        std::fs::remove_file(&link).unwrap();
        std::fs::create_dir_all(&link).unwrap();
        std::fs::write(link.join("SKILL.md"), "my edits").unwrap();
        let e = install_for_agents(home, true, false, false)
            .unwrap_err()
            .to_string();
        assert!(e.contains("--force"), "{e}");
        assert_eq!(
            std::fs::read_to_string(link.join("SKILL.md")).unwrap(),
            "my edits"
        );
        let placed = install_for_agents(home, true, false, true).unwrap();
        assert_eq!(placed[1].outcome, Installed::Replaced);
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());

        // --copy turns the link into a copy, and is then up to date.
        let placed = install_for_agents(home, true, true, false).unwrap();
        assert_eq!(placed[1].outcome, Installed::Created);
        assert!(std::fs::symlink_metadata(&link).unwrap().is_dir());
        assert_eq!(
            std::fs::read_to_string(link.join("SKILL.md")).unwrap(),
            SKILL_MD
        );
        let placed = install_for_agents(home, true, true, false).unwrap();
        assert_eq!(placed[1].outcome, Installed::Unchanged);
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
