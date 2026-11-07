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

#[cfg(test)]
mod tests {
    use super::*;

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
