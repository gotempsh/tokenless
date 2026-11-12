// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Sign-ins: the console tabs and CLI logins holding someone's session.
//! People list and end their own; admins sign someone out everywhere.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use tokenless_control::model::{Page, PageRequest};
use tokenless_control::service::auth::{SessionAuth, SignIn, SignInsRevoked};
use tokenless_core::ids::{SignInId, UserId};

use super::{ApiQuery, AppState, Authed};
use crate::error::ApiError;

type ApiResult<T> = Result<T, ApiError>;
type St = State<Arc<AppState>>;

fn parse<T: std::str::FromStr>(kind: &str, raw: &str) -> ApiResult<T> {
    raw.parse()
        .map_err(|_| ApiError::bad_request(format!("'{raw}' is not a valid {kind} id")))
}

fn session(authed: &Authed) -> ApiResult<&SessionAuth> {
    authed.session.as_ref().ok_or_else(|| ApiError::Forbidden {
        reason: "sign-ins belong to people: an API key has none; sign in to see yours".into(),
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListQuery {
    page: Option<u64>,
    page_size: Option<u64>,
}

impl ListQuery {
    fn request(&self) -> PageRequest {
        PageRequest::new(self.page, self.page_size)
    }
}

/// `GET /auth/sign-ins`: the caller's sign-ins, newest first, the one
/// asking marked `current`.
pub async fn list_own(
    State(s): St,
    authed: Authed,
    ApiQuery(q): ApiQuery<ListQuery>,
) -> ApiResult<Json<Page<SignIn>>> {
    let auth = session(&authed)?;
    Ok(Json(s.control.auth.sign_ins(auth, q.request()).await?))
}

/// `POST /auth/sign-ins/{sign_in_id}/revoke`: ends one of the caller's
/// sign-ins.
pub async fn revoke_own(
    State(s): St,
    authed: Authed,
    Path(sign_in_id): Path<String>,
) -> ApiResult<StatusCode> {
    let auth = session(&authed)?;
    let id: SignInId = parse("sign-in", &sign_in_id)?;
    s.control.auth.revoke_sign_in(auth, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /auth/sign-ins/revoke-others`: ends every sign-in of the caller
/// but this one.
pub async fn revoke_others(State(s): St, authed: Authed) -> ApiResult<Json<SignInsRevoked>> {
    let auth = session(&authed)?;
    Ok(Json(s.control.auth.sign_out_elsewhere(auth).await?))
}

/// `GET /users/{user_id}/sign-ins`: someone's sign-ins, for an admin.
pub async fn list_user(
    State(s): St,
    authed: Authed,
    Path(user_id): Path<String>,
    ApiQuery(q): ApiQuery<ListQuery>,
) -> ApiResult<Json<Page<SignIn>>> {
    let id: UserId = parse("user", &user_id)?;
    Ok(Json(
        s.control
            .auth
            .user_sign_ins(&authed.caller, &id, q.request())
            .await?,
    ))
}

/// `POST /users/{user_id}/sign-ins/revoke`: signs someone out everywhere.
pub async fn revoke_user(
    State(s): St,
    authed: Authed,
    Path(user_id): Path<String>,
) -> ApiResult<Json<SignInsRevoked>> {
    let id: UserId = parse("user", &user_id)?;
    Ok(Json(
        s.control
            .auth
            .revoke_user_sign_ins(&authed.caller, &id)
            .await?,
    ))
}
