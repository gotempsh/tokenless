// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Single sign-on: the browser redirects to and from identity providers,
//! the public sign-in options, and provider administration.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use tokenless_auth::cookie::{
    clear_sso_flow_cookie, session_cookie, session_from_cookie_header, sso_flow_cookie,
    sso_flow_from_cookie_header,
};
use tokenless_control::model::{OidcPurpose, SignInSettings};
use tokenless_control::service::auth::SessionAuth;
use tokenless_control::service::sso::{
    OidcProviderInput, OidcProviderView, SignInOptions, SsoCallback, SsoCompleted, SsoFailed,
};
use tokenless_core::ids::OidcProviderId;
use tracing::debug;

use super::{ApiJson, ApiQuery, AppState, Authed};
use crate::error::ApiError;

type ApiResult<T> = Result<T, ApiError>;
type St = State<Arc<AppState>>;

/// How the sign-in page offers single sign-on and passwords.
pub async fn sign_in_options(State(s): St) -> ApiResult<Json<SignInOptions>> {
    Ok(Json(s.control.sso.sign_in_options().await?))
}

#[derive(Debug, Deserialize)]
pub struct StartQuery {
    #[serde(default)]
    purpose: Option<String>,
    #[serde(default)]
    return_to: Option<String>,
}

fn cookie_value(headers: &HeaderMap, find: fn(&str) -> Option<&str>) -> Option<&str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(find)
}

/// The signed-in session behind a browser navigation, if any. A GET, so no
/// CSRF token: starting a step-up only sends the person to their provider.
async fn browser_session(s: &AppState, headers: &HeaderMap) -> Option<SessionAuth> {
    let token = cookie_value(headers, session_from_cookie_header)?;
    match s.control.auth.authenticate_session(token).await {
        Ok(session) => Some(session),
        Err(e) => {
            debug!(error = %e, "single sign-on start without a valid session");
            None
        }
    }
}

fn redirect(location: &str, cookies: &[String]) -> ApiResult<Response> {
    let mut response = StatusCode::SEE_OTHER.into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::LOCATION,
        HeaderValue::from_str(location)
            .map_err(|_| ApiError::bad_request("the redirect target cannot be sent as a header"))?,
    );
    for cookie in cookies {
        headers.append(
            header::SET_COOKIE,
            HeaderValue::from_str(cookie)
                .map_err(|_| ApiError::bad_request("could not encode a cookie"))?,
        );
    }
    Ok(response)
}

/// Sends the browser to the provider to sign in (`purpose=login`, the
/// default) or, signed in already, to prove it is them again
/// (`purpose=step_up`).
pub async fn start(
    State(s): St,
    Path(slug): Path<String>,
    ApiQuery(query): ApiQuery<StartQuery>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let purpose = match query.purpose.as_deref() {
        None => OidcPurpose::Login,
        Some(p) => OidcPurpose::parse(p).ok_or_else(|| {
            ApiError::bad_request(format!("purpose '{p}' must be 'login' or 'step_up'"))
        })?,
    };
    let session = match purpose {
        OidcPurpose::StepUp => browser_session(&s, &headers).await,
        OidcPurpose::Login => None,
    };
    let to = s
        .control
        .sso
        .begin(&slug, purpose, query.return_to.as_deref(), session.as_ref())
        .await?;
    redirect(
        &to.authorization_url,
        &[sso_flow_cookie(&to.browser_token, to.max_age_secs)],
    )
}

/// Adds `sso_error` to a path on this instance, before any `#fragment`:
/// the console routes with the fragment and reads the error from the query.
fn with_error(path: &str, message: &str) -> String {
    let message: String = message.chars().take(400).collect();
    let encoded: String = url::form_urlencoded::byte_serialize(message.as_bytes()).collect();
    let (before, fragment) = match path.split_once('#') {
        Some((before, fragment)) => (before, Some(fragment)),
        None => (path, None),
    };
    let sep = if before.contains('?') { '&' } else { '?' };
    match fragment {
        Some(f) => format!("{before}{sep}sso_error={encoded}#{f}"),
        None => format!("{before}{sep}sso_error={encoded}"),
    }
}

/// Where the provider sends the browser back. Signs in or records the
/// step-up, then goes to the page the sign-in started from; a failure
/// goes there too, with the reason in `sso_error`.
pub async fn callback(
    State(s): St,
    ApiQuery(query): ApiQuery<SsoCallback>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let flow = cookie_value(&headers, sso_flow_from_cookie_header);
    let user_agent = super::user_agent(&headers);
    match s.control.sso.complete(query, flow, user_agent).await {
        Ok(SsoCompleted::SignedIn { login, return_to }) => redirect(
            &return_to,
            &[
                session_cookie(&login.token, login.max_age_secs),
                clear_sso_flow_cookie(),
            ],
        ),
        Ok(SsoCompleted::SteppedUp { return_to, .. }) => {
            redirect(&return_to, &[clear_sso_flow_cookie()])
        }
        // Signed out, the console shows the sign-in page wherever it lands,
        // so a failed sign-in keeps the page it was headed for.
        Err(SsoFailed {
            return_to, error, ..
        }) => redirect(
            &with_error(&return_to, &error.to_string()),
            &[clear_sso_flow_cookie()],
        ),
    }
}

// ----- administration ----------------------------------------------------

fn provider_id(raw: &str) -> ApiResult<OidcProviderId> {
    raw.parse()
        .map_err(|_| ApiError::bad_request(format!("'{raw}' is not a valid identity provider id")))
}

pub async fn list_providers(
    State(s): St,
    authed: Authed,
) -> ApiResult<Json<Vec<OidcProviderView>>> {
    Ok(Json(s.control.sso.list_providers(&authed.caller).await?))
}

pub async fn create_provider(
    State(s): St,
    authed: Authed,
    ApiJson(req): ApiJson<OidcProviderInput>,
) -> ApiResult<(StatusCode, Json<OidcProviderView>)> {
    Ok((
        StatusCode::CREATED,
        Json(s.control.sso.create_provider(&authed.caller, req).await?),
    ))
}

pub async fn get_provider(
    State(s): St,
    authed: Authed,
    Path(id): Path<String>,
) -> ApiResult<Json<OidcProviderView>> {
    Ok(Json(
        s.control
            .sso
            .get_provider(&authed.caller, &provider_id(&id)?)
            .await?,
    ))
}

pub async fn update_provider(
    State(s): St,
    authed: Authed,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<OidcProviderInput>,
) -> ApiResult<Json<OidcProviderView>> {
    Ok(Json(
        s.control
            .sso
            .update_provider(&authed.caller, &provider_id(&id)?, req)
            .await?,
    ))
}

pub async fn delete_provider(
    State(s): St,
    authed: Authed,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    s.control
        .sso
        .delete_provider(&authed.caller, &provider_id(&id)?)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_sign_in_settings(State(s): St, authed: Authed) -> ApiResult<Json<SignInSettings>> {
    Ok(Json(
        s.control.sso.get_sign_in_settings(&authed.caller).await?,
    ))
}

pub async fn put_sign_in_settings(
    State(s): St,
    authed: Authed,
    ApiJson(req): ApiJson<SignInSettings>,
) -> ApiResult<Json<SignInSettings>> {
    Ok(Json(
        s.control
            .sso
            .put_sign_in_settings(&authed.caller, req)
            .await?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_are_added_to_the_page_as_a_query_parameter() {
        assert_eq!(
            with_error("/login", "no group & no role"),
            "/login?sso_error=no+group+%26+no+role"
        );
        assert_eq!(
            with_error("/settings?tab=a", "x"),
            "/settings?tab=a&sso_error=x"
        );
        assert_eq!(
            with_error("/#/settings/sign-in", "x"),
            "/?sso_error=x#/settings/sign-in"
        );
    }
}
