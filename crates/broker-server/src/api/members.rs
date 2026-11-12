// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A vault's members: who works in it, with which role.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use tokenless_control::model::{Page, PageRequest, VaultMember};
use tokenless_control::service::members::PutMember;
use tokenless_core::ids::{UserId, VaultId};

use super::{ApiJson, ApiQuery, AppState, Authed};
use crate::error::ApiError;

type ApiResult<T> = Result<T, ApiError>;
type St = State<Arc<AppState>>;

fn parse<T: std::str::FromStr>(kind: &str, raw: &str) -> ApiResult<T> {
    raw.parse()
        .map_err(|_| ApiError::bad_request(format!("'{raw}' is not a valid {kind} id")))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListQuery {
    page: Option<u64>,
    page_size: Option<u64>,
}

pub async fn list(
    State(s): St,
    authed: Authed,
    Path(vault_id): Path<String>,
    ApiQuery(q): ApiQuery<ListQuery>,
) -> ApiResult<Json<Page<VaultMember>>> {
    let vault: VaultId = parse("vault", &vault_id)?;
    Ok(Json(
        s.control
            .members
            .list(
                &authed.caller,
                &vault,
                PageRequest::new(q.page, q.page_size),
            )
            .await?,
    ))
}

/// Adds a person to the vault by username, or changes their role there.
pub async fn put(
    State(s): St,
    authed: Authed,
    Path(vault_id): Path<String>,
    ApiJson(req): ApiJson<PutMember>,
) -> ApiResult<Json<VaultMember>> {
    let vault: VaultId = parse("vault", &vault_id)?;
    Ok(Json(
        s.control.members.put(&authed.caller, &vault, req).await?,
    ))
}

pub async fn remove(
    State(s): St,
    authed: Authed,
    Path((vault_id, user_id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let vault: VaultId = parse("vault", &vault_id)?;
    let user: UserId = parse("user", &user_id)?;
    s.control
        .members
        .remove(&authed.caller, &vault, &user)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// An instance admin joins the vault as one of its admins.
pub async fn join(
    State(s): St,
    authed: Authed,
    Path(vault_id): Path<String>,
) -> ApiResult<Json<VaultMember>> {
    let vault: VaultId = parse("vault", &vault_id)?;
    Ok(Json(s.control.members.join(&authed.caller, &vault).await?))
}
