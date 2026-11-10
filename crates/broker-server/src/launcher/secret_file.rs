// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `service add --secret-file`: a credential handed over in a file, so an
//! agent can run the command for a person without the key passing through
//! it. The command creates the file (only its owner can read it), the person
//! puts the key in it with an editor, and the command reads it, wipes and
//! deletes the file, and stores the key. Neither the agent's conversation
//! nor a terminal ever shows it.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tokenless_core::template::CredentialField;
use zeroize::Zeroizing;

use super::LauncherError;

/// Bigger than any credential; a file this size is the wrong file.
const MAX_SIZE: u64 = 64 * 1024;

/// `~/.tokenless/incoming/<template>`: outside any project, so the file is
/// never one `git add .` away from a commit while it waits.
pub fn default_path(home: &Path, template: &str) -> PathBuf {
    home.join(".tokenless").join("incoming").join(template)
}

/// `path` with a leading `~/` made the home directory (a path given in
/// quotes, or by a program, arrives unexpanded).
pub fn expand(path: &Path, home: Option<&Path>) -> PathBuf {
    match (path.strip_prefix("~"), home) {
        (Ok(rest), Some(home)) => home.join(rest),
        _ => path.to_path_buf(),
    }
}

/// What `prepare` found.
#[derive(Debug, PartialEq, Eq)]
pub enum Prepared {
    /// It wrote the instructions; the person still has to add the key.
    Created,
    /// The file was already there; it may already hold the key.
    Existing,
}

/// Creates `path` with instructions for `fields`, readable only by its
/// owner, in a folder only they can open. An existing regular file is left
/// as it is. A symbolic link or anything but a regular file is refused,
/// because the file is deleted afterwards.
pub fn prepare(
    path: &Path,
    service: &str,
    vault: &str,
    fields: &[CredentialField],
) -> Result<Prepared, LauncherError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() => return Ok(Prepared::Existing),
        Ok(_) => {
            return Err(LauncherError::config(format!(
                "{} is not a regular file; pass --secret-file a path for a new file",
                path.display()
            )))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(LauncherError::io(format!("checking {}", path.display()))(e));
        }
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        if !parent.exists() {
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
            builder
                .create(parent)
                .map_err(LauncherError::io(format!("creating {}", parent.display())))?;
        }
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options
        .open(path)
        .map_err(LauncherError::io(format!("creating {}", path.display())))?;
    file.write_all(instructions(service, vault, fields).as_bytes())
        .map_err(LauncherError::io(format!("writing {}", path.display())))?;
    Ok(Prepared::Created)
}

/// What the new file says: comment lines, which are ignored, then where
/// each value goes.
pub fn instructions(service: &str, vault: &str, fields: &[CredentialField]) -> String {
    let mut out = String::new();
    if let [only] = fields {
        out.push_str(&format!(
            "# tokenless: the {service} {} for vault '{vault}'.\n\
             # Paste it below this line, save the file and close it. tokenless\n\
             # reads it, deletes this file and stores it encrypted.\n",
            only.label
        ));
        return out;
    }
    out.push_str(&format!(
        "# tokenless: the credentials of {service} for vault '{vault}'.\n\
         # Fill in each line after the =, save the file and close it. tokenless\n\
         # reads it, deletes this file and stores them encrypted.\n"
    ));
    for field in fields {
        let optional = if field.required { "" } else { " (optional)" };
        out.push_str(&format!("\n# {}{optional}\n{}=\n", field.label, field.name));
    }
    out
}

pub type Fields = BTreeMap<String, Zeroizing<String>>;

/// The values in `content`, or `None` while a required one is still empty.
///
/// Lines starting with `#` are comments. With one field, everything else is
/// its value (so a key pasted on its own line, or a multi-line private key,
/// both work), with an optional `<field>=` in front. With several, each
/// line is `<field>=<value>`.
pub fn parse(content: &str, fields: &[CredentialField]) -> Result<Option<Fields>, LauncherError> {
    let lines: Vec<&str> = content
        .lines()
        .map(|l| l.trim_end_matches('\r'))
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect();
    let mut out = Fields::new();
    if let [only] = fields {
        let prefix = format!("{}=", only.name);
        let joined = lines.join("\n");
        let value = joined.trim();
        let value = value.strip_prefix(&prefix).unwrap_or(value).trim();
        if value.is_empty() {
            return Ok(None);
        }
        out.insert(only.name.clone(), Zeroizing::new(value.to_string()));
        return Ok(Some(out));
    }
    for (number, line) in lines
        .iter()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
    {
        let known = || {
            fields
                .iter()
                .map(|f| f.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        };
        let Some((name, value)) = line.split_once('=') else {
            return Err(LauncherError::config(format!(
                "line {} of the secret file is not <field>=<value>; its fields are {}",
                number + 1,
                known()
            )));
        };
        let name = name.trim();
        if !fields.iter().any(|f| f.name == name) {
            // The text before `=` is not repeated: a key pasted on a line
            // of its own can hold an `=` (base64 padding).
            return Err(LauncherError::config(format!(
                "line {} of the secret file names a field this service does not have; its fields are {}",
                number + 1,
                known()
            )));
        }
        let value = value.trim();
        if !value.is_empty() {
            out.insert(name.to_string(), Zeroizing::new(value.to_string()));
        }
    }
    let filled = fields
        .iter()
        .filter(|f| f.required)
        .all(|f| out.contains_key(&f.name));
    Ok(filled.then_some(out))
}

/// The file's content; it never holds more than a credential.
fn read(path: &Path) -> Result<Zeroizing<String>, LauncherError> {
    let file = std::fs::File::open(path)
        .map_err(LauncherError::io(format!("reading {}", path.display())))?;
    let mut content = Zeroizing::new(String::new());
    file.take(MAX_SIZE + 1)
        .read_to_string(&mut content)
        .map_err(LauncherError::io(format!("reading {}", path.display())))?;
    if content.len() as u64 > MAX_SIZE {
        return Err(LauncherError::config(format!(
            "{} is larger than {MAX_SIZE} bytes, too big to be a credential",
            path.display()
        )));
    }
    Ok(content)
}

/// Whether the file already holds every required value (a person may have
/// filled it in before the command ran).
pub fn filled(path: &Path, fields: &[CredentialField]) -> bool {
    read(path).is_ok_and(|content| matches!(parse(&content, fields), Ok(Some(_))))
}

/// Waits until the file holds every required field and has stopped
/// changing (an editor may save in pieces), then returns the values. A file
/// that does not parse is not ready yet: `problem` is told once per distinct
/// error (which never quotes a value) and the wait goes on, so the person can
/// fix the line. At the deadline the last such error is returned.
pub async fn wait(
    path: &Path,
    fields: &[CredentialField],
    timeout: Duration,
    poll: Duration,
    mut problem: impl FnMut(&LauncherError),
) -> Result<Fields, LauncherError> {
    let deadline = Instant::now() + timeout;
    let mut last: Option<Zeroizing<String>> = None;
    let mut wrong: Option<LauncherError> = None;
    loop {
        match read(path) {
            Ok(content) => {
                let settled = last.as_ref().is_some_and(|l| **l == *content);
                if settled {
                    match parse(&content, fields) {
                        Ok(Some(values)) => return Ok(values),
                        Ok(None) => wrong = None,
                        Err(e) => {
                            if wrong.as_ref().map(ToString::to_string) != Some(e.to_string()) {
                                problem(&e);
                            }
                            wrong = Some(e);
                        }
                    }
                }
                last = Some(content);
            }
            // Editors that save by renaming leave a moment with no file.
            Err(LauncherError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        if Instant::now() >= deadline {
            return Err(wrong.unwrap_or_else(|| {
                LauncherError::config(format!(
                    "nothing was saved in {} within {} minutes; run the command again when you have the key",
                    path.display(),
                    timeout.as_secs().div_ceil(60)
                ))
            }));
        }
        tokio::time::sleep(poll).await;
    }
}

/// Overwrites the file with zeros and deletes it. A file that is already
/// gone is fine.
pub fn remove(path: &Path) -> Result<(), LauncherError> {
    let len = match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() => meta.len(),
        Ok(_) => return Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(LauncherError::io(format!("checking {}", path.display()))(e)),
    };
    if let Ok(mut file) = std::fs::OpenOptions::new().write(true).open(path) {
        let zeros = vec![0u8; usize::try_from(len.min(MAX_SIZE)).unwrap_or(0)];
        // Best effort: the delete below is what must happen.
        let _ = file.write_all(&zeros).and_then(|()| file.sync_all());
    }
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(LauncherError::io(format!("deleting {}", path.display()))(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(name: &str, required: bool) -> CredentialField {
        CredentialField {
            name: name.into(),
            label: format!("{name} label"),
            description: String::new(),
            required,
        }
    }

    fn value(fields: &Fields, name: &str) -> String {
        fields[name].as_str().to_string()
    }

    #[test]
    fn one_field_takes_whatever_is_pasted_below_the_comments() {
        let fields = [field("api_key", true)];
        let fresh = instructions("OpenAI", "personal", &fields);
        assert!(fresh.lines().all(|l| l.starts_with('#')), "{fresh}");
        assert_eq!(parse(&fresh, &fields).unwrap(), None);
        let got = parse(&format!("{fresh}\n  sk-abc123  \n"), &fields)
            .unwrap()
            .unwrap();
        assert_eq!(value(&got, "api_key"), "sk-abc123");
        let got = parse("api_key=sk-abc123\r\n", &fields).unwrap().unwrap();
        assert_eq!(value(&got, "api_key"), "sk-abc123");
        // A private key keeps its lines; a key ending in = keeps it.
        let pem = "-----BEGIN KEY-----\nabc\n-----END KEY-----";
        let got = parse(&format!("# c\n{pem}\n"), &fields).unwrap().unwrap();
        assert_eq!(value(&got, "api_key"), pem);
        let got = parse("c2VjcmV0==\n", &fields).unwrap().unwrap();
        assert_eq!(value(&got, "api_key"), "c2VjcmV0==");
    }

    #[test]
    fn several_fields_wait_for_every_required_one() {
        let fields = [
            field("client_id", true),
            field("client_secret", true),
            field("region", false),
        ];
        let fresh = instructions("Example", "work", &fields);
        assert!(
            fresh.contains("\nclient_id=\n") && fresh.contains("# region label (optional)"),
            "{fresh}"
        );
        assert_eq!(parse(&fresh, &fields).unwrap(), None);
        let half = fresh.replace("client_id=\n", "client_id=abc\n");
        assert_eq!(parse(&half, &fields).unwrap(), None);
        let full = half.replace("client_secret=\n", "client_secret = s=3 \n");
        let got = parse(&full, &fields).unwrap().unwrap();
        assert_eq!(value(&got, "client_id"), "abc");
        assert_eq!(value(&got, "client_secret"), "s=3");
        assert!(!got.contains_key("region"));
    }

    #[test]
    fn a_line_that_names_no_field_is_refused_with_the_fields_it_has() {
        let fields = [field("client_id", true), field("client_secret", true)];
        let e = parse("client_ID=abc\nclient_secret=x\n", &fields)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("line 1 ") && e.contains("client_id, client_secret"),
            "{e}"
        );
        // What comes before `=` may be part of a pasted key: never repeated.
        assert!(!e.contains("client_ID"), "{e}");
        let e = parse("just a value\n", &fields).unwrap_err().to_string();
        assert!(e.contains("line 1"), "{e}");
        // The refusal never repeats a value.
        assert!(!e.contains("just a value"), "{e}");
    }

    #[test]
    fn the_file_is_private_and_a_link_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = default_path(dir.path(), "openai");
        let fields = [field("api_key", true)];
        assert_eq!(
            prepare(&path, "OpenAI", "personal", &fields).unwrap(),
            Prepared::Created
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&path), 0o600);
            assert_eq!(mode(path.parent().unwrap()), 0o700);
        }
        assert!(
            !filled(&path, &fields),
            "the instructions alone are not a key"
        );
        // Run again, the file the person may have filled is left alone.
        std::fs::write(&path, "sk-abc").unwrap();
        assert!(filled(&path, &fields));
        assert_eq!(
            prepare(&path, "OpenAI", "personal", &fields).unwrap(),
            Prepared::Existing
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "sk-abc");
        #[cfg(unix)]
        {
            let link = dir.path().join("link");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(prepare(&link, "OpenAI", "personal", &fields).is_err());
            remove(&link).unwrap();
            assert!(path.exists(), "removing a link leaves what it points to");
        }
        remove(&path).unwrap();
        assert!(!path.exists());
        remove(&path).unwrap();
    }

    #[test]
    fn a_home_relative_path_is_expanded() {
        let home = Path::new("/home/someone");
        assert_eq!(
            expand(Path::new("~/.tokenless/k"), Some(home)),
            home.join(".tokenless/k")
        );
        assert_eq!(
            expand(Path::new("/tmp/k"), Some(home)),
            PathBuf::from("/tmp/k")
        );
        assert_eq!(expand(Path::new("~/k"), None), PathBuf::from("~/k"));
    }

    #[tokio::test]
    async fn waiting_returns_once_the_saved_key_stops_changing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        let fields = [field("api_key", true)];
        prepare(&path, "OpenAI", "personal", &fields).unwrap();
        let writer = {
            let path = path.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(50)).await;
                let fresh = std::fs::read_to_string(&path).unwrap();
                std::fs::write(&path, format!("{fresh}sk-")).unwrap();
                tokio::time::sleep(Duration::from_millis(30)).await;
                std::fs::write(&path, format!("{fresh}sk-abc123\n")).unwrap();
            })
        };
        let got = wait(
            &path,
            &fields,
            Duration::from_secs(5),
            Duration::from_millis(100),
            |_| {},
        )
        .await
        .unwrap();
        writer.await.unwrap();
        assert_eq!(value(&got, "api_key"), "sk-abc123");
    }

    #[tokio::test]
    async fn waiting_gives_up_at_the_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        let fields = [field("api_key", true)];
        prepare(&path, "OpenAI", "personal", &fields).unwrap();
        let e = wait(
            &path,
            &fields,
            Duration::from_millis(50),
            Duration::from_millis(10),
            |_| {},
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(e.contains("nothing was saved"), "{e}");
    }

    #[tokio::test]
    async fn a_wrong_line_is_reported_once_and_the_wait_goes_on_until_it_is_fixed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        let fields = [
            field("access_key_id", true),
            field("secret_access_key", true),
        ];
        prepare(&path, "AWS", "personal", &fields).unwrap();
        let fresh = std::fs::read_to_string(&path).unwrap();
        // A typo in a field name, with a value that must not be repeated.
        std::fs::write(
            &path,
            format!("{fresh}access_key=AKIAEXAMPLE\nsecret_access_key=s3cr3t==\n"),
        )
        .unwrap();
        let writer = {
            let (path, fresh) = (path.clone(), fresh.clone());
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(300)).await;
                std::fs::write(
                    &path,
                    format!("{fresh}access_key_id=AKIAEXAMPLE\nsecret_access_key=s3cr3t==\n"),
                )
                .unwrap();
            })
        };
        let mut problems = Vec::new();
        let got = wait(
            &path,
            &fields,
            Duration::from_secs(5),
            Duration::from_millis(20),
            |e| problems.push(e.to_string()),
        )
        .await
        .unwrap();
        writer.await.unwrap();
        assert_eq!(value(&got, "access_key_id"), "AKIAEXAMPLE");
        assert_eq!(value(&got, "secret_access_key"), "s3cr3t==");
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("line"), "{problems:?}");
        assert!(!problems[0].contains("AKIA") && !problems[0].contains("s3cr3t"));

        // Left wrong, the wait ends with that error, not "nothing was saved".
        std::fs::write(&path, format!("{fresh}s3cr3t==\n")).unwrap();
        let e = wait(
            &path,
            &fields,
            Duration::from_millis(200),
            Duration::from_millis(20),
            |_| {},
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(e.contains("does not have"), "{e}");
        assert!(!e.contains("s3cr3t"), "{e}");
    }
}
