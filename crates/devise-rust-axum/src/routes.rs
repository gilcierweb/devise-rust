//! Session route registration — tracer shell for the 09-01 slice
//! (`POST sign_in` + `DELETE sign_out`), grown into the full
//! `devise_for`-equivalent router in 09-02 (D-03).
//!
//! ## Session writes
//!
//! Handlers run the proxy for hooks and memoization and hand every
//! physical session write to the cycle-before-write bridge helpers:
//!
//! - sign-in: `AuthProxy::set_user` with `store: false` (Authentication
//!   hooks + memoization + `expire_devise_keys`), then
//!   [`insert_session_and_renew`](crate::bridge::insert_session_and_renew)
//!   cycles the id BEFORE inserting the `[key, salt]` payload;
//! - sign-out: `AuthProxy::sign_out` (logout hooks + warden key removal +
//!   memo clear), then
//!   [`sign_out_and_renew`](crate::bridge::sign_out_and_renew) rotates the
//!   id on the sign-out path.
//!
//! Failed cycles fail the transition (500), never a fake success.

#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Extension, Form, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::delete;
use axum::routing::post;
use devise_rust::adapter::Conditions;
use devise_rust::config::DeviseConfig;
use devise_rust::failure::{FailureReason, FailureRenderer, build_failure, is_navigational_format};
use devise_rust::helpers::after_sign_in_path_for;
use devise_rust::model::ModelFinder;
use devise_rust::proxy::{SetUserEvent, SetUserOpts};
use devise_rust::request::AuthRequest;
use devise_rust::scope::Mapping;
use tower_sessions::Session;

use crate::bridge;
use crate::callbacks::rotate_csrf_token;
use crate::failure::AxumFailureRenderer;
use crate::layer::AuthProxyHandle;

/// Shared state for the devise route handlers.
///
/// `mapping` carries the route paths and scope name; `finders` backs the
/// credential lookup and the proxy registration done by
/// [`DeviseLayer`](crate::layer::DeviseLayer).
#[derive(Clone)]
pub struct DeviseRouterState {
    /// Devise configuration (stretches drive password checks).
    pub config: Arc<DeviseConfig>,
    /// The scope mapping these routes serve.
    pub mapping: Mapping,
    /// Per-scope model finders.
    pub finders: HashMap<String, Arc<dyn ModelFinder>>,
}

/// Register the tracer session routes for one mapping: `POST {sign_in}`
/// and `DELETE {sign_out}` at the mapping's paths.
///
/// ## Examples
///
/// ```rust,ignore
/// let router = sessions_router(DeviseRouterState {
///     config,
///     mapping,
///     finders,
/// });
/// let app = Router::new().merge(router);
/// ```
pub fn sessions_router(state: DeviseRouterState) -> Router {
    let sign_in = state.mapping.sign_in_path();
    let sign_out = state.mapping.sign_out_path();
    Router::new()
        .route(&sign_in, post(sessions_create))
        .route(&sign_out, delete(sessions_destroy))
        .with_state(state)
}

/// `SessionsController#create`: authenticate the params, sign the user in
/// through the proxy, then persist with cycle-before-insert.
async fn sessions_create(
    State(st): State<DeviseRouterState>,
    Extension(session): Extension<Session>,
    Extension(handle): Extension<AuthProxyHandle>,
    Extension(auth_request): Extension<AuthRequest>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let scope = st.mapping.name.clone();
    let email = form.get("user_email").cloned().unwrap_or_default();
    let password = form.get("user_password").cloned().unwrap_or_default();

    let Some(finder) = st.finders.get(&scope) else {
        return internal_error();
    };
    let mut conditions = Conditions::new();
    conditions.insert("email", email);
    let Ok(found) = finder.find_first_boxed(&conditions).await else {
        return internal_error();
    };

    let Some(user) = found else {
        return invalid_credentials(&auth_request, &st);
    };

    // DatabaseAuthenticatable password check through the object-safe
    // facet (paranoid dummy-hash timing parity lives in core strategies).
    let password_ok = user
        .as_password_verifiable()
        .is_some_and(|verifiable| verifiable.valid_password(&password, &st.config));
    if !password_ok {
        return invalid_credentials(&auth_request, &st);
    }

    let (key, salt) = user.session_pair();

    // Sign in through AuthProxy set_user: Authentication hooks +
    // memoization + expire_devise_keys. `store: false` — the physical
    // write belongs to the cycle-before-insert bridge helper below.
    let mut proxy = handle.lock().await;
    let opts = SetUserOpts {
        event: SetUserEvent::Authentication,
        store: false,
        run_callbacks: true,
        force: false,
    };
    if proxy.set_user(&scope, Some(user), opts).await.is_err() {
        drop(proxy);
        return internal_error();
    }
    let target = after_sign_in_path_for(&scope, &proxy, &auth_request).await;
    drop(proxy);

    // D-04: cycle BEFORE the insert; a failed cycle fails the sign-in.
    if bridge::insert_session_and_renew(&session, &scope, &key, &salt)
        .await
        .is_err()
    {
        return internal_error();
    }
    // D-07: rotate the app-owned CSRF token on the transition.
    rotate_csrf_token(&session, &scope, &st.config).await;

    if is_navigational_format(&auth_request, &st.config) {
        flash_redirect(&target, "signed_in")
    } else {
        axum::Json(serde_json::json!({ "signed_in": true })).into_response()
    }
}

/// `SessionsController#destroy`: logout hooks + warden key removal through
/// the proxy, then rotate the id on the sign-out path.
async fn sessions_destroy(
    State(st): State<DeviseRouterState>,
    Extension(session): Extension<Session>,
    Extension(handle): Extension<AuthProxyHandle>,
    Extension(auth_request): Extension<AuthRequest>,
) -> Response {
    let scope = st.mapping.name.clone();

    // Warden logout: before_logout hooks + session key removal + memo clear.
    {
        let mut proxy = handle.lock().await;
        proxy.sign_out(&scope).await;
    }

    // D-04: rotate on the sign-out transition; failure fails the response.
    if bridge::sign_out_and_renew(&session, &scope).await.is_err() {
        return internal_error();
    }
    // D-07: rotate the app-owned CSRF token on the transition.
    rotate_csrf_token(&session, &scope, &st.config).await;

    if is_navigational_format(&auth_request, &st.config) {
        flash_redirect("/", "signed_out")
    } else {
        StatusCode::NO_CONTENT.into_response()
    }
}

/// Invalid credentials: the core failure decision for `FailureReason::Invalid`,
/// rendered through the shared renderer (302 + flash for navigational
/// requests, 401 otherwise).
fn invalid_credentials(auth_request: &AuthRequest, st: &DeviseRouterState) -> Response {
    let failure = build_failure(
        auth_request,
        &st.mapping,
        &st.config,
        FailureReason::Invalid,
    );
    AxumFailureRenderer::new().render(&failure, &st.mapping)
}

/// 302 + devise flash cookie (actix `flash_redirect` parity).
fn flash_redirect(target: &str, flash_key: &str) -> Response {
    let mut response = StatusCode::FOUND.into_response();
    let location = HeaderValue::from_str(target).unwrap_or_else(|_| HeaderValue::from_static("/"));
    response.headers_mut().insert(header::LOCATION, location);
    if let Some(flash) = crate::failure::flash_cookie_header(flash_key) {
        response.headers_mut().append(header::SET_COOKIE, flash);
    }
    response
}

fn internal_error() -> Response {
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}
