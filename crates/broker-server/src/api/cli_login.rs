// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
use super::{ApiJson, ApiQuery, AppState, Authed};
use crate::error::ApiError;
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokenless_control::service::auth::{CliLoginDetails, CliLoginStarted};

#[derive(Deserialize)]
pub struct Start {
    provider: String,
    #[serde(default)]
    manage: bool,
}
#[derive(Deserialize)]
pub struct Code {
    code: String,
}
#[derive(Deserialize)]
pub struct Poll {
    device_code: String,
}
#[derive(Serialize)]
struct Ready {
    token: String,
    csrf_token: String,
    user: tokenless_control::service::auth::UserSummary,
    expires_at: chrono::DateTime<chrono::Utc>,
}
fn private(body: impl IntoResponse) -> Response {
    ([(header::CACHE_CONTROL, "no-store")], body).into_response()
}
pub async fn start(
    State(s): State<Arc<AppState>>,
    ApiJson(req): ApiJson<Start>,
) -> Result<Response, ApiError> {
    let started: CliLoginStarted = s
        .control
        .auth
        .begin_cli_login(&req.provider, req.manage)
        .await?;
    Ok(private(Json(started)))
}
pub async fn details(
    State(s): State<Arc<AppState>>,
    _auth: Authed,
    ApiQuery(req): ApiQuery<Code>,
) -> Result<Response, ApiError> {
    let details: CliLoginDetails = s.control.auth.cli_login_details(&req.code)?;
    Ok(private(Json(details)))
}
pub async fn approve(
    State(s): State<Arc<AppState>>,
    auth: Authed,
    ApiJson(req): ApiJson<Code>,
) -> Result<Response, ApiError> {
    let session = auth.session.as_ref().ok_or_else(|| ApiError::Forbidden {
        reason: "CLI approval requires a browser sign-in".into(),
    })?;
    s.control.auth.approve_cli_login(session, &req.code).await?;
    Ok(private(StatusCode::NO_CONTENT))
}
pub async fn poll(
    State(s): State<Arc<AppState>>,
    ApiJson(req): ApiJson<Poll>,
) -> Result<Response, ApiError> {
    match s.control.auth.poll_cli_login(&req.device_code).await? {
        None => Ok(private(StatusCode::ACCEPTED)),
        Some(login) => Ok(private(Json(Ready {
            token: login.token,
            csrf_token: login.csrf_token,
            user: login.user,
            expires_at: login.expires_at,
        }))),
    }
}
