// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Packages that must never come back into the dependency graph. YAML is
//! parsed with `yaml_serde`, the YAML organization's maintained
//! continuation of `serde_yaml`, imported under the old name (see the root
//! `Cargo.toml`). `serde_yaml` itself and its `unsafe-libyaml` parser are
//! unmaintained (RUSTSEC-2024-0449), and platforms that embed tokenless
//! refuse them.
//!
//! Both lock files are checked: the workspace's, which Cargo resolves with
//! every feature of every crate on, so optional features are covered, and
//! the embedding example's, which is built outside the workspace.

const BANNED: &[&str] = &["serde_yaml", "unsafe-libyaml"];

const LOCKS: &[(&str, &str)] = &[
    ("Cargo.lock", include_str!("../../../Cargo.lock")),
    (
        "examples/embedded-host/Cargo.lock",
        include_str!("../../../examples/embedded-host/Cargo.lock"),
    ),
];

/// Each `[[package]]` of a lock file: its name and the names it depends on.
fn packages(lock: &str) -> Vec<(&str, Vec<&str>)> {
    lock.split("[[package]]")
        .skip(1)
        .filter_map(|entry| {
            let name = entry
                .lines()
                .find_map(|l| l.strip_prefix("name = \""))?
                .trim_end_matches('"');
            let deps = entry
                .split_once("dependencies = [")
                .map(|(_, rest)| rest.split(']').next().unwrap_or_default())
                .unwrap_or_default()
                .lines()
                .filter_map(|l| l.trim().strip_prefix('"'))
                // "name", or "name version" when two versions are locked.
                .filter_map(|d| d.trim_end_matches(['"', ',']).split(' ').next())
                .collect();
            Some((name, deps))
        })
        .collect()
}

/// For each banned package in `lock`, the packages that depend on it.
fn banned_in(lock: &str) -> Vec<(&'static str, Vec<&str>)> {
    let all = packages(lock);
    BANNED
        .iter()
        .filter(|banned| all.iter().any(|(name, _)| name == *banned))
        .map(|banned| {
            let dependents = all
                .iter()
                .filter(|(_, deps)| deps.contains(banned))
                .map(|(name, _)| *name)
                .collect();
            (*banned, dependents)
        })
        .collect()
}

#[test]
fn no_lock_file_holds_serde_yaml_or_unsafe_libyaml() {
    for (path, lock) in LOCKS {
        let found = banned_in(lock);
        assert!(
            found.is_empty(),
            "{path} holds unmaintained packages (RUSTSEC-2024-0449), \
             {found:?} as (package, depended on by). Depend on the workspace \
             `serde_yaml` entry, which is `yaml_serde` under that name."
        );
        assert!(
            packages(lock).iter().any(|(name, _)| *name == "yaml_serde"),
            "{path} has no yaml_serde: is the lock file read correctly?"
        );
    }
}

#[test]
fn a_banned_package_is_found_with_what_pulls_it_in() {
    let lock = r#"
[[package]]
name = "a"
version = "1.0.0"
dependencies = [
 "serde_yaml",
 "other 2.0.0",
]

[[package]]
name = "serde_yaml"
version = "0.9.34+deprecated"
dependencies = [
 "unsafe-libyaml",
]

[[package]]
name = "unsafe-libyaml"
version = "0.2.11"
"#;
    assert_eq!(
        banned_in(lock),
        vec![
            ("serde_yaml", vec!["a"]),
            ("unsafe-libyaml", vec!["serde_yaml"])
        ]
    );
    assert_eq!(packages(lock)[0].1, vec!["serde_yaml", "other"]);
    assert!(banned_in("[[package]]\nname = \"yaml_serde\"\n").is_empty());
}
