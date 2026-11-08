// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Authentication primitives: argon2id password hashing, TOTP, random
//! bearer tokens stored only as hashes, CSRF tokens and cookie formatting.
//! No storage and no I/O; the control plane composes these.

pub mod cookie;
pub mod csrf;
pub mod error;
pub mod password;
pub mod token;
pub mod totp;

pub use error::AuthError;
