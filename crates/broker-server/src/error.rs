// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Server errors and their RFC 7807 problem+json rendering.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use thiserror::Error;
use tokenless_auth::AuthError;
use tokenless_control::{ControlError, StoreError};
use tokenless_core::CoreError;
use tracing::error;

/// Startup and runtime failures of the server process itself.
#[derive(Debug, Error)]
pub enum ServerError {
    #[error("I/O failure while {context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },

    #[error("invalid configuration: {reason}")]
    Config { reason: String },

    #[error("TLS setup for {listener} failed: {reason}")]
    Tls { listener: String, reason: String },

    #[error(transparent)]
    Store(#[from] StoreError),

    #[error(transparent)]
    Control(#[from] ControlError),
}

impl ServerError {
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        ServerError::Io {
            context: context.into(),
            source,
        }
    }
}

/// An error returned by an HTTP handler.
#[derive(Debug, Error)]
pub enum ApiError {
    #[error(transparent)]
    Control(#[from] ControlError),

    #[error("bad request: {message}")]
    BadRequest { message: String },

    #[error("authentication required: {reason}")]
    Unauthenticated { reason: String },

    #[error("forbidden: {reason}")]
    Forbidden { reason: String },
}

impl ApiError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        ApiError::BadRequest {
            message: message.into(),
        }
    }
}

impl From<StoreError> for ApiError {
    fn from(e: StoreError) -> Self {
        ApiError::Control(ControlError::Store(e))
    }
}

#[derive(Debug, Serialize)]
pub struct Problem {
    #[serde(rename = "type")]
    pub type_: &'static str,
    pub title: &'static str,
    pub status: u16,
    pub detail: String,
    /// Stable machine-readable code for the UI (e.g. `step_up_required`).
    pub code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_secs: Option<u64>,
}

struct Mapped {
    status: StatusCode,
    title: &'static str,
    code: &'static str,
    retry_after: Option<u64>,
    internal: bool,
}

fn mapped(status: StatusCode, title: &'static str, code: &'static str) -> Mapped {
    Mapped {
        status,
        title,
        code,
        retry_after: None,
        internal: status.is_server_error(),
    }
}

fn map_store(e: &StoreError) -> Mapped {
    match e {
        StoreError::NotFound { .. } => mapped(StatusCode::NOT_FOUND, "Not Found", "not_found"),
        StoreError::Conflict { .. } => mapped(StatusCode::CONFLICT, "Conflict", "conflict"),
        StoreError::Backend { .. } => mapped(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Storage Error",
            "storage_error",
        ),
    }
}

fn map_core(e: &CoreError) -> Mapped {
    let invalid = || mapped(StatusCode::BAD_REQUEST, "Validation Error", "validation");
    match e {
        CoreError::InvalidHost { .. }
        | CoreError::InvalidPath { .. }
        | CoreError::InvalidMethod { .. }
        | CoreError::InvalidScope { .. }
        | CoreError::InvalidTemplate { .. }
        | CoreError::TemplateParse { .. }
        | CoreError::MissingField { .. }
        | CoreError::UnknownField { .. }
        | CoreError::InvalidFieldValue { .. }
        | CoreError::InvalidHeaderName { .. }
        | CoreError::InvalidLabel { .. }
        | CoreError::InvalidBinding { .. }
        | CoreError::InvalidTtl { .. }
        | CoreError::InvalidRuleDeadline { .. }
        | CoreError::InvalidVariableKey { .. }
        | CoreError::InvalidVariableReference { .. }
        | CoreError::UnknownVariable { .. }
        | CoreError::InvalidCustomHeader { .. }
        | CoreError::InvalidSubstitution { .. } => invalid(),
        CoreError::Widening { .. } => mapped(
            StatusCode::FORBIDDEN,
            "Scope Widening Not Allowed",
            "widening_forbidden",
        ),
        CoreError::Crypto { .. } | CoreError::Encoding { .. } => mapped(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal Error",
            "internal",
        ),
    }
}

fn map_auth(e: &AuthError) -> Mapped {
    match e {
        AuthError::WeakPassword { .. } | AuthError::InvalidTotpSecret { .. } => {
            mapped(StatusCode::BAD_REQUEST, "Validation Error", "validation")
        }
        AuthError::MalformedToken { .. } => mapped(
            StatusCode::UNAUTHORIZED,
            "Authentication Required",
            "unauthenticated",
        ),
        AuthError::Hashing { .. } | AuthError::MalformedHash { .. } => mapped(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal Error",
            "internal",
        ),
    }
}

fn map_control(e: &ControlError) -> Mapped {
    match e {
        ControlError::NotFound { .. } => mapped(StatusCode::NOT_FOUND, "Not Found", "not_found"),
        ControlError::Validation { .. } => {
            mapped(StatusCode::BAD_REQUEST, "Validation Error", "validation")
        }
        ControlError::Conflict { .. } => mapped(StatusCode::CONFLICT, "Conflict", "conflict"),
        ControlError::Unauthenticated { .. } => mapped(
            StatusCode::UNAUTHORIZED,
            "Authentication Required",
            "unauthenticated",
        ),
        ControlError::Forbidden { .. } => mapped(StatusCode::FORBIDDEN, "Forbidden", "forbidden"),
        ControlError::SecondFactorRequired { .. } => mapped(
            StatusCode::UNAUTHORIZED,
            "Authenticator Code Required",
            "second_factor_required",
        ),
        ControlError::StepUpRequired { .. } => mapped(
            StatusCode::FORBIDDEN,
            "Step-Up Authentication Required",
            "step_up_required",
        ),
        ControlError::RateLimited {
            retry_after_secs, ..
        } => Mapped {
            retry_after: Some(*retry_after_secs),
            ..mapped(
                StatusCode::TOO_MANY_REQUESTS,
                "Too Many Attempts",
                "rate_limited",
            )
        },
        ControlError::Crypto { .. } => mapped(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Cryptographic Error",
            "internal",
        ),
        ControlError::Pki { .. } => mapped(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Certificate Error",
            "internal",
        ),
        ControlError::Store(s) => map_store(s),
        ControlError::Core(c) => map_core(c),
        ControlError::Auth(a) => map_auth(a),
    }
}

impl ApiError {
    fn mapping(&self) -> Mapped {
        match self {
            ApiError::Control(e) => map_control(e),
            ApiError::BadRequest { .. } => {
                mapped(StatusCode::BAD_REQUEST, "Bad Request", "bad_request")
            }
            ApiError::Unauthenticated { .. } => mapped(
                StatusCode::UNAUTHORIZED,
                "Authentication Required",
                "unauthenticated",
            ),
            ApiError::Forbidden { .. } => mapped(StatusCode::FORBIDDEN, "Forbidden", "forbidden"),
        }
    }

    pub fn problem(&self) -> Problem {
        let m = self.mapping();
        let detail = if m.internal {
            // The full error is logged; clients get the category only so
            // storage or crypto internals never leak into responses.
            error!(error = %self, status = m.status.as_u16(), "request failed with an internal error");
            format!("{} (see server log)", m.title)
        } else {
            self.to_string()
        };
        Problem {
            type_: "about:blank",
            title: m.title,
            status: m.status.as_u16(),
            detail,
            code: m.code,
            retry_after_secs: m.retry_after,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let problem = self.problem();
        let status =
            StatusCode::from_u16(problem.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let body = serde_json::to_vec(&problem).unwrap_or_default();
        let mut response = (status, body).into_response();
        let headers = response.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        if let Some(secs) = problem.retry_after_secs {
            if let Ok(v) = HeaderValue::from_str(&secs.to_string()) {
                headers.insert(header::RETRY_AFTER, v);
            }
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn step_up_maps_to_403_with_code() {
        let p = ApiError::Control(ControlError::StepUpRequired {
            action: "credential.create".into(),
            window_secs: 300,
        })
        .problem();
        assert_eq!(p.status, 403);
        assert_eq!(p.code, "step_up_required");
        assert!(p.detail.contains("credential.create"));
    }

    #[test]
    fn missing_authenticator_code_maps_to_401_with_code() {
        let p = ApiError::Control(ControlError::SecondFactorRequired {
            username: "operator".into(),
        })
        .problem();
        assert_eq!(p.status, 401);
        assert_eq!(p.code, "second_factor_required");
        assert!(p.detail.contains("operator"));
    }

    #[test]
    fn rate_limit_carries_retry_after() {
        let response = ApiError::Control(ControlError::RateLimited {
            subject: "login:operator".into(),
            retry_after_secs: 42,
        })
        .into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response
                .headers()
                .get(header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            Some("42")
        );
    }

    #[test]
    fn internal_errors_do_not_leak_detail() {
        let p = ApiError::from(StoreError::backend(
            "insert credential",
            "disk I/O error at page 7",
        ))
        .problem();
        assert_eq!(p.status, 500);
        assert!(!p.detail.contains("page 7"));
    }

    #[test]
    fn store_not_found_is_404() {
        let p = ApiError::from(StoreError::not_found("rule", "abc")).problem();
        assert_eq!(p.status, 404);
        assert!(p.detail.contains("abc"));
    }
}
