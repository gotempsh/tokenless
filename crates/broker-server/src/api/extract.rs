// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Request extractors: authentication and problem+json body/query errors.

use std::sync::Arc;

use axum::extract::{FromRequest, FromRequestParts, Query, Request};
use axum::http::request::Parts;
use axum::http::{header, Method};
use axum::Json;
use serde::de::DeserializeOwned;
use tokenless_auth::cookie::session_from_cookie_header;
use tokenless_auth::csrf::CSRF_HEADER;
use tokenless_auth::token::API_KEY_PREFIX;
use tokenless_control::service::auth::SessionAuth;
use tokenless_control::Caller;

use super::AppState;
use crate::error::ApiError;

/// An authenticated caller: a UI session (cookie + CSRF) or an API key.
pub struct Authed {
    pub caller: Caller,
    /// Present for cookie sessions only.
    pub session: Option<SessionAuth>,
}

fn is_safe(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

impl FromRequestParts<Arc<AppState>> for Authed {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let auth = &state.control.auth;
        if let Some(value) = parts.headers.get(header::AUTHORIZATION) {
            let value = value.to_str().map_err(|_| ApiError::Unauthenticated {
                reason: "Authorization header is not valid ASCII".into(),
            })?;
            let key = value
                .strip_prefix("Bearer ")
                .filter(|k| k.starts_with(API_KEY_PREFIX))
                .ok_or_else(|| ApiError::Unauthenticated {
                    reason: format!("Authorization must be 'Bearer {API_KEY_PREFIX}_...'"),
                })?;
            let caller = auth.authenticate_api_key(key.trim()).await?;
            return Ok(Self {
                caller,
                session: None,
            });
        }
        let token = parts
            .headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find_map(session_from_cookie_header)
            .ok_or_else(|| ApiError::Unauthenticated {
                reason: "no session cookie or API key presented".into(),
            })?;
        let session = auth.authenticate_session(token).await?;
        if !is_safe(&parts.method) {
            let presented = parts
                .headers
                .get(CSRF_HEADER)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            if !auth.verify_csrf(&session.token_hash, presented) {
                return Err(ApiError::Forbidden {
                    reason: format!("missing or invalid {CSRF_HEADER} header"),
                });
            }
        }
        Ok(Self {
            caller: session.caller.clone(),
            session: Some(session),
        })
    }
}

/// `Json` whose rejection is a problem+json 400.
pub struct ApiJson<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        Json::<T>::from_request(req, state)
            .await
            .map(|Json(v)| ApiJson(v))
            .map_err(|e| ApiError::bad_request(format!("invalid JSON body: {}", e.body_text())))
    }
}

/// `Query` whose rejection is a problem+json 400.
pub struct ApiQuery<T>(pub T);

impl<S, T> FromRequestParts<S> for ApiQuery<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Query::<T>::from_request_parts(parts, state)
            .await
            .map(|Query(v)| ApiQuery(v))
            .map_err(|e| ApiError::bad_request(format!("invalid query string: {}", e.body_text())))
    }
}
