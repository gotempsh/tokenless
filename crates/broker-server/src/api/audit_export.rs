// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Audit export: the webhook receivers audit events are sent to.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use tokenless_control::service::audit_export::{
    AuditDestinationInput, AuditDestinationView, CreateAuditDestination, CreatedAuditDestination,
    DeliveryTest, RotatedSigningSecret, SkippedEvents,
};
use tokenless_core::ids::AuditDestinationId;

use super::{ApiJson, AppState, Authed};
use crate::error::ApiError;

type ApiResult<T> = Result<T, ApiError>;
type St = State<Arc<AppState>>;

fn destination_id(raw: &str) -> ApiResult<AuditDestinationId> {
    raw.parse()
        .map_err(|_| ApiError::bad_request(format!("'{raw}' is not a valid audit destination id")))
}

pub async fn list(State(s): St, authed: Authed) -> ApiResult<Json<Vec<AuditDestinationView>>> {
    Ok(Json(s.control.audit_export.list(&authed.caller).await?))
}

/// The signing secret is in this response and nowhere else, ever.
pub async fn create(
    State(s): St,
    authed: Authed,
    ApiJson(req): ApiJson<CreateAuditDestination>,
) -> ApiResult<(StatusCode, Json<CreatedAuditDestination>)> {
    Ok((
        StatusCode::CREATED,
        Json(s.control.audit_export.create(&authed.caller, req).await?),
    ))
}

pub async fn get(
    State(s): St,
    authed: Authed,
    Path(id): Path<String>,
) -> ApiResult<Json<AuditDestinationView>> {
    Ok(Json(
        s.control
            .audit_export
            .get(&authed.caller, &destination_id(&id)?)
            .await?,
    ))
}

pub async fn update(
    State(s): St,
    authed: Authed,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<AuditDestinationInput>,
) -> ApiResult<Json<AuditDestinationView>> {
    Ok(Json(
        s.control
            .audit_export
            .update(&authed.caller, &destination_id(&id)?, req)
            .await?,
    ))
}

pub async fn delete(State(s): St, authed: Authed, Path(id): Path<String>) -> ApiResult<StatusCode> {
    s.control
        .audit_export
        .delete(&authed.caller, &destination_id(&id)?)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn test(
    State(s): St,
    authed: Authed,
    Path(id): Path<String>,
) -> ApiResult<Json<DeliveryTest>> {
    Ok(Json(
        s.control
            .audit_export
            .test(&authed.caller, &destination_id(&id)?)
            .await?,
    ))
}

pub async fn rotate_secret(
    State(s): St,
    authed: Authed,
    Path(id): Path<String>,
) -> ApiResult<Json<RotatedSigningSecret>> {
    Ok(Json(
        s.control
            .audit_export
            .rotate_secret(&authed.caller, &destination_id(&id)?)
            .await?,
    ))
}

pub async fn pause(
    State(s): St,
    authed: Authed,
    Path(id): Path<String>,
) -> ApiResult<Json<AuditDestinationView>> {
    Ok(Json(
        s.control
            .audit_export
            .set_paused(&authed.caller, &destination_id(&id)?, true)
            .await?,
    ))
}

pub async fn resume(
    State(s): St,
    authed: Authed,
    Path(id): Path<String>,
) -> ApiResult<Json<AuditDestinationView>> {
    Ok(Json(
        s.control
            .audit_export
            .set_paused(&authed.caller, &destination_id(&id)?, false)
            .await?,
    ))
}

pub async fn skip(
    State(s): St,
    authed: Authed,
    Path(id): Path<String>,
) -> ApiResult<Json<SkippedEvents>> {
    Ok(Json(
        s.control
            .audit_export
            .skip_to_now(&authed.caller, &destination_id(&id)?)
            .await?,
    ))
}
