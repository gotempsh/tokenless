// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AuthError {
    #[error("password rejected: {reason}")]
    WeakPassword { reason: String },

    #[error("password hashing failed: {reason}")]
    Hashing { reason: String },

    #[error("stored password hash is malformed: {reason}")]
    MalformedHash { reason: String },

    #[error("TOTP secret for account '{account}' is invalid: {reason}")]
    InvalidTotpSecret { account: String, reason: String },

    #[error("token is malformed: expected prefix '{expected_prefix}'")]
    MalformedToken { expected_prefix: String },
}
