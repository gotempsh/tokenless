// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The root key: the one secret the operator keeps outside the database.
//! It wraps the instance key, which wraps the data keys (see
//! [`tokenless_control::envelope`]), so whoever holds the data directory but
//! not the root key decrypts nothing.
//!
//! It comes from, in order:
//! 1. `--root-key-file <path>`: 32 raw bytes or base64 text;
//! 2. `TOKENLESS_ROOT_KEY`: base64 text;
//! 3. `<data-dir>/root.key`, or `<data-dir>/master.key` from earlier
//!    versions, generated on first start. The server then warns at every
//!    start that the key sits next to the data it protects.

use std::io::Write;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use tokenless_control::cipher::AesGcmCipher;
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::ServerError;

/// The file generated in the data directory when no root key is supplied.
pub const DATA_DIR_FILE: &str = "root.key";
/// What earlier versions called it; read when present.
pub const LEGACY_FILE: &str = "master.key";

/// A root key the operator supplies.
#[derive(Clone)]
pub enum RootKeyInput {
    File(PathBuf),
    /// Base64, from `TOKENLESS_ROOT_KEY`.
    Value(Zeroizing<String>),
}

impl std::fmt::Debug for RootKeyInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File(path) => f.debug_tuple("File").field(path).finish(),
            Self::Value(_) => f.write_str("Value(***)"),
        }
    }
}

/// The root key and where it came from.
pub struct RootKey {
    pub key: Zeroizing<[u8; 32]>,
    /// Set when the key was read from or created in the data directory.
    pub in_data_dir: Option<PathBuf>,
}

fn invalid(source: &str, reason: impl std::fmt::Display) -> ServerError {
    ServerError::Config {
        reason: format!("root key from {source}: {reason}"),
    }
}

/// 32 raw bytes, or base64 text of 32 bytes.
pub fn parse(source: &str, bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>, ServerError> {
    if let Ok(key) = <[u8; 32]>::try_from(bytes) {
        return Ok(Zeroizing::new(key));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| {
        invalid(
            source,
            format!(
                "expected 32 bytes or base64 text, found {} bytes",
                bytes.len()
            ),
        )
    })?;
    let decoded = Zeroizing::new(
        STANDARD
            .decode(text.trim())
            .map_err(|e| invalid(source, format!("not 32 bytes and not base64 ({e})")))?,
    );
    <[u8; 32]>::try_from(decoded.as_slice())
        .map(Zeroizing::new)
        .map_err(|_| {
            invalid(
                source,
                format!("base64 decodes to {} bytes, not 32", decoded.len()),
            )
        })
}

fn read(path: &Path) -> Result<Zeroizing<[u8; 32]>, ServerError> {
    let bytes = Zeroizing::new(
        std::fs::read(path)
            .map_err(|e| ServerError::io(format!("reading root key {}", path.display()), e))?,
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.permissions().mode() & 0o077 != 0 {
                warn!(path = %path.display(), "root key is readable by group or others; run chmod 600");
            }
        }
    }
    parse(&path.display().to_string(), &bytes)
}

/// Base64 text with a newline, as written to key files.
pub fn encode(key: &[u8; 32]) -> Zeroizing<String> {
    Zeroizing::new(format!("{}\n", STANDARD.encode(key)))
}

/// Writes a new key file (mode 0600); fails if `path` exists.
pub fn write_new(path: &Path, key: &[u8; 32]) -> Result<(), ServerError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|e| ServerError::io(format!("creating root key {}", path.display()), e))?;
    file.write_all(encode(key).as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|e| ServerError::io(format!("writing root key {}", path.display()), e))
}

/// Finds the root key. When none is supplied and none exists in
/// `data_dir`, one is generated there only for an `empty` database: data
/// encrypted under a key that isn't here must not get a new one.
pub fn resolve(
    input: Option<&RootKeyInput>,
    data_dir: &Path,
    empty: bool,
) -> Result<RootKey, ServerError> {
    let in_dir = [data_dir.join(DATA_DIR_FILE), data_dir.join(LEGACY_FILE)];
    let existing = in_dir.iter().find(|p| p.exists()).cloned();
    match input {
        Some(supplied) => {
            let key = match supplied {
                RootKeyInput::File(path) => read(path)?,
                RootKeyInput::Value(value) => parse("TOKENLESS_ROOT_KEY", value.as_bytes())?,
            };
            if let Some(copy) = existing {
                warn!(
                    path = %copy.display(),
                    "a root key file is still in the data directory; once this server starts with the supplied key, delete it, or a copy of the directory can be decrypted"
                );
            }
            Ok(RootKey {
                key,
                in_data_dir: None,
            })
        }
        None => match existing {
            Some(path) => Ok(RootKey {
                key: read(&path)?,
                in_data_dir: Some(path),
            }),
            None if !empty => Err(ServerError::Config {
                reason: format!(
                    "the secrets in {} are encrypted under a root key that is not here; start with --root-key-file <path> or TOKENLESS_ROOT_KEY",
                    data_dir.display()
                ),
            }),
            None => {
                let path = in_dir[0].clone();
                let key = AesGcmCipher::generate_key();
                write_new(&path, &key)?;
                info!(path = %path.display(), "generated the root key");
                Ok(RootKey {
                    key,
                    in_data_dir: Some(path),
                })
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_and_base64_keys_parse() {
        let key = [7u8; 32];
        assert_eq!(*parse("t", &key).unwrap(), key);
        assert_eq!(*parse("t", encode(&key).as_bytes()).unwrap(), key);
        let short = parse("t", STANDARD.encode([1u8; 16]).as_bytes())
            .err()
            .unwrap()
            .to_string();
        assert!(short.contains("16 bytes, not 32"), "{short}");
        assert!(parse("t", b"not a key").is_err());
    }

    #[test]
    fn a_supplied_key_wins_over_the_data_directory() {
        let dir = tempfile::tempdir().unwrap();
        let generated = resolve(None, dir.path(), true).unwrap();
        let path = dir.path().join(DATA_DIR_FILE);
        assert_eq!(generated.in_data_dir.as_deref(), Some(path.as_path()));
        // The next start reads the same one.
        let again = resolve(None, dir.path(), true).unwrap();
        assert_eq!(*again.key, *generated.key);

        let outside = tempfile::tempdir().unwrap();
        let file = outside.path().join("root.key");
        write_new(&file, &[9u8; 32]).unwrap();
        let supplied = resolve(Some(&RootKeyInput::File(file)), dir.path(), false).unwrap();
        assert_eq!(*supplied.key, [9u8; 32]);
        assert!(supplied.in_data_dir.is_none());

        let value = RootKeyInput::Value(Zeroizing::new(STANDARD.encode([4u8; 32])));
        assert_eq!(
            *resolve(Some(&value), dir.path(), false).unwrap().key,
            [4u8; 32]
        );
        assert_eq!(format!("{value:?}"), "Value(***)");
    }

    #[test]
    fn data_without_its_key_never_gets_a_new_one() {
        let dir = tempfile::tempdir().unwrap();
        let err = resolve(None, dir.path(), false).err().unwrap().to_string();
        assert!(err.contains("--root-key-file"), "{err}");
        assert!(!dir.path().join(DATA_DIR_FILE).exists());
    }

    #[test]
    fn the_master_key_of_earlier_versions_is_the_root_key() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(LEGACY_FILE), [3u8; 32]).unwrap();
        let found = resolve(None, dir.path(), true).unwrap();
        assert_eq!(*found.key, [3u8; 32]);
        assert!(!dir.path().join(DATA_DIR_FILE).exists());
    }

    #[cfg(unix)]
    #[test]
    fn generated_keys_are_private_and_never_overwritten() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k");
        write_new(&path, &[1u8; 32]).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(write_new(&path, &[2u8; 32]).is_err());
        assert_eq!(*read(&path).unwrap(), [1u8; 32]);
    }
}
