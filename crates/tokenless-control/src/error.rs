// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;
use tokenless_auth::AuthError;
use tokenless_core::CoreError;

/// Errors returned by store trait implementations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StoreError {
    #[error("{entity} '{id}' not found")]
    NotFound { entity: &'static str, id: String },

    #[error("{entity} conflict: {detail}")]
    Conflict {
        entity: &'static str,
        detail: String,
    },

    #[error("credential '{id}' is at secret generation {current}, not {expected}: another rotation replaced the secret first; read the credential again and decide whether yours is still needed")]
    StaleGeneration {
        id: String,
        expected: u64,
        current: u64,
    },

    #[error("store backend failed during '{operation}': {reason}")]
    Backend { operation: String, reason: String },
}

impl StoreError {
    pub fn backend(operation: &str, reason: impl std::fmt::Display) -> Self {
        StoreError::Backend {
            operation: operation.to_string(),
            reason: reason.to_string(),
        }
    }

    pub fn not_found(entity: &'static str, id: impl std::fmt::Display) -> Self {
        StoreError::NotFound {
            entity,
            id: id.to_string(),
        }
    }
}

/// Errors returned by control plane services.
#[derive(Debug, Error)]
pub enum ControlError {
    #[error("{entity} '{id}' not found")]
    NotFound { entity: &'static str, id: String },

    #[error("validation failed: {message}")]
    Validation { message: String },

    #[error("conflict: {message}")]
    Conflict { message: String },

    #[error("authentication failed: {reason}")]
    Unauthenticated { reason: String },

    #[error("forbidden: {reason}")]
    Forbidden { reason: String },

    /// The password was right and the account has an authenticator: sign-in
    /// continues once the code is sent with the same username and password.
    #[error("account '{username}' needs a code from its authenticator to sign in")]
    SecondFactorRequired { username: String },

    #[error(
        "'{action}' requires a fresh second factor (step-up MFA within the last {window_secs}s)"
    )]
    StepUpRequired { action: String, window_secs: u64 },

    #[error("too many attempts for '{subject}'; retry in {retry_after_secs}s")]
    RateLimited {
        subject: String,
        retry_after_secs: u64,
    },

    #[error("cryptographic operation '{operation}' failed: {reason}")]
    Crypto { operation: String, reason: String },

    #[error("certificate operation '{operation}' failed: {reason}")]
    Pki { operation: String, reason: String },

    #[error(transparent)]
    Store(#[from] StoreError),

    #[error(transparent)]
    Core(#[from] CoreError),

    #[error(transparent)]
    Auth(#[from] AuthError),
}

impl ControlError {
    pub fn validation(message: impl Into<String>) -> Self {
        ControlError::Validation {
            message: message.into(),
        }
    }

    pub fn not_found(entity: &'static str, id: impl std::fmt::Display) -> Self {
        ControlError::NotFound {
            entity,
            id: id.to_string(),
        }
    }

    pub fn crypto(operation: &str, reason: impl std::fmt::Display) -> Self {
        ControlError::Crypto {
            operation: operation.to_string(),
            reason: reason.to_string(),
        }
    }

    pub fn pki(operation: &str, reason: impl std::fmt::Display) -> Self {
        ControlError::Pki {
            operation: operation.to_string(),
            reason: reason.to_string(),
        }
    }
}
