//! Test helpers — `sign_in` / `sign_out` bypass helpers for the axum
//! oneshot harness, mirroring Devise's `IntegrationHelpers`
//! (`login_as` / `logout` session-store bypass, D-17 semantics mirrored
//! from the actix crate).
//!
//! ## Bypass + renewal
//!
//! Every helper delegates to the [`crate::bridge`] transition fns, so the
//! D-04 `cycle_id`-before-write rotation fires on each path and a failed
//! rotation fails the transition. The helpers never re-run authentication
//! callbacks and never hash a password — the Devise `login_as` shape.
//!
//! ## Cookie replay
//!
//! The oneshot harness is stateless between requests, so tests capture
//! `Set-Cookie` pairs with [`set_cookie_pairs`] and replay them through
//! the `Cookie` request header with [`cookie_header`] on later oneshot
//! calls (the AXUM-04 pattern).
//!
//! Call sites live in test handlers (the middleware lifecycle owns the
//! `save()` flush), exactly like the actix crate's flows tests.

#![allow(clippy::missing_errors_doc)]

use devise_rust::config::DeviseConfig;

/// Test configuration with fast `stretches` (4) and a fixed 32-byte secret.
///
/// Not safe for production: holds a fixed secret so tests run fast.
#[must_use]
pub fn test_config() -> DeviseConfig {
    DeviseConfig {
        secret_key: "test-secret-key-for-testing-only-32-bytes-min".to_string(),
        stretches: 4,
        ..DeviseConfig::default()
    }
}

/// Sign-in bypass path for tests.
///
/// Equivalent Devise path: `login_as` — insert the session payload
/// without re-running callbacks, but always renew the session first
/// (D-04: bypass skips callbacks, not renewal).
///
/// Returns the key the payload was inserted under for test-side
/// roundtrip assertions.
///
/// # Errors
///
/// Returns `DeviseError::Internal` when the cycle or the insert fails —
/// the transition fails instead of persisting under the old id.
pub async fn sign_in(
    session: &tower_sessions::Session,
    scope: &str,
    key: &devise_rust::adapter::DeviseKey,
    salt: &str,
) -> Result<String, devise_rust::error::DeviseError> {
    crate::bridge::insert_session_and_renew(session, scope, key, salt).await?;
    Ok(devise_rust::session::keys::scope_session_key(scope))
}

/// Sign out a scope via the session-store bypass (D-04 renew-before-clear).
///
/// # Errors
///
/// Returns `DeviseError::Internal` when the cycle fails.
pub async fn sign_out(
    session: &tower_sessions::Session,
    scope: &str,
) -> Result<(), devise_rust::error::DeviseError> {
    crate::bridge::sign_out_and_renew(session, scope).await
}

/// IntegrationHelpers-parity sign-out: bridge sign-out plus the core
/// `forget` remember-cookie op so a test can drain it through the signed
/// tombstone (T-09-07: logout never leaves a live remember login).
///
/// Returns the [`RememberCookieOp::Clear`] to apply to the response jar.
///
/// # Errors
///
/// Returns `DeviseError::Internal` when the cycle fails.
pub async fn sign_out_with_forget(
    session: &tower_sessions::Session,
    scope: &str,
    config: &DeviseConfig,
) -> Result<devise_rust::rememberable::RememberCookieOp, devise_rust::error::DeviseError> {
    crate::bridge::sign_out_and_renew(session, scope).await?;
    Ok(crate::remember::forget_op(scope, config))
}

/// `bypass_sign_in` parity (Devise `IntegrationHelpers#sign_in` with a
/// record): store the session payload WITHOUT re-running callbacks but
/// WITH the D-04 renew-before-insert. The model is never re-hashed — the
/// session pair comes from the record directly.
///
/// Returns the session key the payload was inserted under.
///
/// # Errors
///
/// Returns `DeviseError::Internal` when the cycle or the insert fails.
pub async fn bypass_sign_in<M>(
    session: &tower_sessions::Session,
    scope: &str,
    user: &M,
) -> Result<String, devise_rust::error::DeviseError>
where
    M: devise_rust::failure::AnyDeviseModel + Send + Sync,
{
    let (key, salt) = user.session_pair();
    crate::bridge::bypass_sign_in_and_renew(session, scope, &key, &salt).await?;
    Ok(devise_rust::session::keys::scope_session_key(scope))
}

/// Sign out multiple scopes via bypass (D-04 renew-before-clear-each).
///
/// # Errors
///
/// Returns `DeviseError::Internal` when the cycle fails.
pub async fn sign_out_all_scopes(
    session: &tower_sessions::Session,
    scopes: &[String],
) -> Result<(), devise_rust::error::DeviseError> {
    crate::bridge::sign_out_all_scopes_and_renew(session, scopes).await
}

/// Capture the `name=value` pairs of every `Set-Cookie` header on a test
/// response — the replay jar for later `Request::builder().header(COOKIE,
/// ...)` oneshot calls.
#[must_use]
pub fn set_cookie_pairs(response: &axum::http::Response<axum::body::Body>) -> Vec<String> {
    response
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|v| v.split(';').next())
        .map(str::to_string)
        .collect()
}

/// Render cookie pairs as a `Cookie` request header value for replay.
#[must_use]
pub fn cookie_header(pairs: &[String]) -> String {
    pairs.join("; ")
}

/// Construct an [`AuthRequest`] for use in test-side proxy calls.
#[must_use]
pub fn sign_in_request(
    scope: &str,
    email: &str,
    password: &str,
) -> devise_rust::request::AuthRequest {
    let mut request = devise_rust::request::AuthRequest::new(
        devise_rust::request::HttpMethod::Post,
        format!("/{scope}/sign_in"),
    );
    request
        .params
        .insert(format!("{scope}_email"), email.to_string());
    request
        .params
        .insert(format!("{scope}_password"), password.to_string());
    request.flags.allow_params_authentication = true;
    request
}
