// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Launcher keys: API keys that only start sessions from one access bundle,
//! for agent machines.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use tokenless_control::model::{Page, PageRequest};
use tokenless_control::service::launcher_keys::{
    CreateLauncherKey, CreatedLauncherKey, LauncherKey, RevokedLauncherKey,
};
use tokenless_core::ids::{ApiKeyId, BundleId, VaultId};

use super::{ApiJson, ApiQuery, AppState, Authed};
use crate::error::ApiError;

type ApiResult<T> = Result<T, ApiError>;
type St = State<Arc<AppState>>;

fn vault_id(raw: &str) -> ApiResult<VaultId> {
    raw.parse()
        .map_err(|_| ApiError::bad_request(format!("'{raw}' is not a valid vault id")))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListQuery {
    page: Option<u64>,
    page_size: Option<u64>,
    /// Only this bundle's keys.
    bundle_id: Option<String>,
}

/// `GET /vaults/{vault_id}/launcher-keys`: newest first, revoked and expired
/// ones included, never their secrets.
pub async fn list(
    State(s): St,
    authed: Authed,
    Path(vault): Path<String>,
    ApiQuery(q): ApiQuery<ListQuery>,
) -> ApiResult<Json<Page<LauncherKey>>> {
    let bundle = q
        .bundle_id
        .as_deref()
        .map(|raw| {
            raw.parse::<BundleId>().map_err(|_| {
                ApiError::bad_request(format!("'{raw}' is not a valid access bundle id"))
            })
        })
        .transpose()?;
    Ok(Json(
        s.control
            .launcher_keys
            .list(
                &authed.caller,
                &vault_id(&vault)?,
                bundle.as_ref(),
                PageRequest::new(q.page, q.page_size),
            )
            .await?,
    ))
}

/// `POST /vaults/{vault_id}/launcher-keys`: the key is in this response and
/// nowhere else, ever.
pub async fn create(
    State(s): St,
    authed: Authed,
    Path(vault): Path<String>,
    ApiJson(req): ApiJson<CreateLauncherKey>,
) -> ApiResult<(StatusCode, Json<CreatedLauncherKey>)> {
    Ok((
        StatusCode::CREATED,
        Json(
            s.control
                .launcher_keys
                .create(&authed.caller, &vault_id(&vault)?, req)
                .await?,
        ),
    ))
}

/// `POST /vaults/{vault_id}/launcher-keys/{id}/revoke`: also ends the live
/// sessions the key started.
pub async fn revoke(
    State(s): St,
    authed: Authed,
    Path((vault, id)): Path<(String, String)>,
) -> ApiResult<Json<RevokedLauncherKey>> {
    let id: ApiKeyId = id
        .parse()
        .map_err(|_| ApiError::bad_request(format!("'{id}' is not a valid launcher key id")))?;
    Ok(Json(
        s.control
            .launcher_keys
            .revoke(&authed.caller, &vault_id(&vault)?, &id)
            .await?,
    ))
}
