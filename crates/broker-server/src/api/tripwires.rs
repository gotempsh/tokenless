// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tripwires: decoy credentials to plant on agents' machines.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use tokenless_control::model::{Page, PageRequest, Tripwire};
use tokenless_control::service::tripwires::CreatedTripwire;
use tokenless_core::ids::{TripwireId, VaultId};
use tokenless_core::tripwire::TripwireKind;

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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateTripwire {
    /// Where it is planted, such as the machine's name.
    name: String,
    kind: TripwireKind,
}

/// `GET /vaults/{vault_id}/tripwires`: newest first, never their decoys.
pub async fn list(
    State(s): St,
    authed: Authed,
    Path(vault): Path<String>,
    ApiQuery(q): ApiQuery<ListQuery>,
) -> ApiResult<Json<Page<Tripwire>>> {
    let vault: VaultId = parse("vault", &vault)?;
    Ok(Json(
        s.control
            .tripwires
            .list(
                &authed.caller,
                &vault,
                PageRequest::new(q.page, q.page_size),
            )
            .await?,
    ))
}

/// `POST /vaults/{vault_id}/tripwires`: the decoy and how to plant it are in
/// this response and nowhere else.
pub async fn create(
    State(s): St,
    authed: Authed,
    Path(vault): Path<String>,
    ApiJson(req): ApiJson<CreateTripwire>,
) -> ApiResult<(StatusCode, Json<CreatedTripwire>)> {
    let vault: VaultId = parse("vault", &vault)?;
    Ok((
        StatusCode::CREATED,
        Json(
            s.control
                .tripwires
                .create(&authed.caller, &vault, &req.name, req.kind)
                .await?,
        ),
    ))
}

/// `DELETE /tripwires/{tripwire_id}`: proxies stop looking for it.
pub async fn delete(
    State(s): St,
    authed: Authed,
    Path(id): Path<String>,
) -> ApiResult<Json<Tripwire>> {
    let id: TripwireId = parse("tripwire", &id)?;
    Ok(Json(s.control.tripwires.delete(&authed.caller, &id).await?))
}
