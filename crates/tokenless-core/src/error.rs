// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

/// Errors produced by the pure policy layer. Every variant names the value
/// that was rejected so a log line is enough to find the offending input.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CoreError {
    #[error("invalid host pattern '{input}': {reason}")]
    InvalidHost { input: String, reason: String },

    #[error("invalid path pattern '{input}': {reason}")]
    InvalidPath { input: String, reason: String },

    #[error("invalid HTTP method '{input}'")]
    InvalidMethod { input: String },

    #[error("invalid scope '{input}': {reason}")]
    InvalidScope { input: String, reason: String },

    #[error("invalid template '{template_id}': {reason}")]
    InvalidTemplate { template_id: String, reason: String },

    #[error("template YAML could not be parsed: {reason}")]
    TemplateParse { reason: String },

    #[error("rule widens the maximum scope of template '{template_id}': {detail}")]
    Widening { template_id: String, detail: String },

    #[error("credential field '{field}' is missing for template '{template_id}'")]
    MissingField { template_id: String, field: String },

    #[error(
        "credential field '{field}' for template '{template_id}' is not declared by the template"
    )]
    UnknownField { template_id: String, field: String },

    #[error("value for credential field '{field}' is not a valid HTTP header value: {reason}")]
    InvalidFieldValue { field: String, reason: String },

    #[error("invalid header name '{name}': {reason}")]
    InvalidHeaderName { name: String, reason: String },

    #[error("invalid variable key '{key}': {reason}")]
    InvalidVariableKey { key: String, reason: String },

    #[error("invalid variable reference in {context}: {reason}")]
    InvalidVariableReference { context: String, reason: String },

    #[error("{context} references variable '{key}', which does not exist")]
    UnknownVariable { context: String, key: String },

    #[error("invalid custom header '{name}': {reason}")]
    InvalidCustomHeader { name: String, reason: String },

    #[error("invalid substitution '{placeholder}': {reason}")]
    InvalidSubstitution { placeholder: String, reason: String },

    #[error("invalid session label '{key}': {reason}")]
    InvalidLabel { key: String, reason: String },

    #[error("invalid binding '{binding_id}': {reason}")]
    InvalidBinding { binding_id: String, reason: String },

    #[error("invalid Git repository '{repository}': {reason}")]
    InvalidGitScope { repository: String, reason: String },

    #[error("invalid deadline for rule {rule_id} in a session: {reason}")]
    InvalidRuleDeadline { rule_id: String, reason: String },

    #[error("invalid session TTL {requested_secs}s: must be between 1s and {max_secs}s")]
    InvalidTtl { requested_secs: u64, max_secs: u64 },

    #[error("cryptographic operation '{operation}' failed: {reason}")]
    Crypto { operation: String, reason: String },

    #[error("encoding error in {context}: {reason}")]
    Encoding { context: String, reason: String },
}

impl CoreError {
    pub(crate) fn crypto(operation: &str, reason: impl Into<String>) -> Self {
        CoreError::Crypto {
            operation: operation.to_string(),
            reason: reason.into(),
        }
    }

    pub(crate) fn encoding(context: &str, reason: impl std::fmt::Display) -> Self {
        CoreError::Encoding {
            context: context.to_string(),
            reason: reason.to_string(),
        }
    }
}
