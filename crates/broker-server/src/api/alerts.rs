// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Alerts: what the proxies reported that someone should look at now.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;
use tokenless_control::model::{Alert, AlertFilter, AlertKind, Page, PageRequest};
use tokenless_control::service::alerts::AlertSummary;
use tokenless_core::ids::AlertId;

use super::{ApiQuery, AppState, Authed};
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
    /// Only those nobody has acknowledged.
    #[serde(default)]
    open: bool,
    vault_id: Option<String>,
    session_id: Option<String>,
    kind: Option<String>,
    page: Option<u64>,
    page_size: Option<u64>,
}

/// `GET /alerts`: newest first; `?open=true` for those not acknowledged.
pub async fn list(
    State(s): St,
    authed: Authed,
    ApiQuery(q): ApiQuery<ListQuery>,
) -> ApiResult<Json<Page<Alert>>> {
    let filter = AlertFilter {
        open_only: q.open,
        vault_id: q
            .vault_id
            .as_deref()
            .map(|v| parse("vault", v))
            .transpose()?,
        session_id: q
            .session_id
            .as_deref()
            .map(|v| parse("session", v))
            .transpose()?,
        kind: q
            .kind
            .as_deref()
            .map(|k| {
                AlertKind::parse(k).ok_or_else(|| {
                    ApiError::bad_request(format!(
                        "'{k}' is not an alert kind; one of quarantine, tripwire, refusals, new_proxy"
                    ))
                })
            })
            .transpose()?,
    };
    Ok(Json(
        s.control
            .alerts
            .list(
                &authed.caller,
                filter,
                PageRequest::new(q.page, q.page_size),
            )
            .await?,
    ))
}

/// `GET /alerts/summary`: how many are open, and the newest of them.
pub async fn summary(State(s): St, authed: Authed) -> ApiResult<Json<AlertSummary>> {
    Ok(Json(s.control.alerts.summary(&authed.caller).await?))
}

/// `POST /alerts/{alert_id}/acknowledge`: marks it looked at.
pub async fn acknowledge(
    State(s): St,
    authed: Authed,
    Path(alert_id): Path<String>,
) -> ApiResult<Json<Alert>> {
    let id: AlertId = parse("alert", &alert_id)?;
    Ok(Json(
        s.control.alerts.acknowledge(&authed.caller, &id).await?,
    ))
}
