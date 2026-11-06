// SPDX-FileCopyrightText: 2026 credential-broker contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The management HTTP API (`/api/v1`) used by the UI and automation.

mod extract;
mod handlers;

use std::path::PathBuf;
use std::sync::Arc;

use axum::http::{header, HeaderName, HeaderValue};
use axum::routing::{get, post, put};
use axum::Router;
use broker_control::ControlPlane;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;

pub use extract::{ApiJson, ApiQuery, Authed};

pub struct AppState {
    pub control: Arc<ControlPlane>,
}

fn api_routes() -> Router<Arc<AppState>> {
    use handlers::*;
    Router::new()
        .route("/setup/status", get(setup_status))
        .route("/setup/totp", post(setup_totp))
        .route("/setup", post(setup_complete))
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
        .route("/auth/me", get(me))
        .route("/auth/step-up", post(step_up))
        .route("/vaults", get(list_vaults).post(create_vault))
        .route("/vaults/{vault_id}", get(get_vault))
        .route(
            "/vaults/{vault_id}/credentials",
            get(list_credentials).post(create_credential),
        )
        .route(
            "/vaults/{vault_id}/rules",
            get(list_rules).post(create_rule),
        )
        .route(
            "/vaults/{vault_id}/sessions",
            get(list_sessions).post(mint_session),
        )
        .route("/templates", get(list_templates))
        .route("/templates/import", post(import_template))
        .route("/templates/{template_id}/{version}", get(get_template))
        .route(
            "/templates/{template_id}/{version}/approve",
            post(approve_template),
        )
        .route(
            "/credentials/{credential_id}",
            get(get_credential).delete(delete_credential),
        )
        .route(
            "/credentials/{credential_id}/secret",
            put(rotate_credential),
        )
        .route(
            "/credentials/{credential_id}/validate",
            post(validate_credential),
        )
        .route(
            "/rules/{rule_id}",
            get(get_rule).patch(update_rule).delete(delete_rule),
        )
        .route("/sessions/{session_id}/revoke", post(revoke_session))
        .route("/api-keys", get(list_api_keys).post(create_api_key))
        .route(
            "/api-keys/{api_key_id}",
            axum::routing::delete(revoke_api_key),
        )
        .route("/audit", get(query_audit))
        .route("/nodes", get(list_nodes))
        .route("/nodes/join-tokens", post(create_join_token))
        .route("/nodes/{node_id}/revoke", post(revoke_node))
        .route("/settings", get(get_settings).put(put_settings))
        .route("/ca/interception.pem", get(interception_ca))
        .fallback(not_found)
        // Nothing the API returns may be cached: several responses carry
        // one-time credentials and the rest describe security state.
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
}

const UI_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

/// Builds the full router: `/api/v1`, plus the UI bundle when `ui_dir` is set.
pub fn router(state: Arc<AppState>, ui_dir: Option<PathBuf>) -> Router {
    let mut app = Router::new().nest("/api/v1", api_routes());
    if let Some(dir) = ui_dir {
        let index = dir.join("index.html");
        app = app.fallback_service(ServeDir::new(dir).fallback(ServeFile::new(index)));
    }
    app.layer(SetResponseHeaderLayer::overriding(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    ))
    .layer(SetResponseHeaderLayer::overriding(
        header::X_FRAME_OPTIONS,
        HeaderValue::from_static("DENY"),
    ))
    .layer(SetResponseHeaderLayer::overriding(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    ))
    .layer(SetResponseHeaderLayer::if_not_present(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(UI_CSP),
    ))
    .layer(SetResponseHeaderLayer::overriding(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    ))
    .with_state(state)
}
