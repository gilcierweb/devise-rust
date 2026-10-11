//! Test helpers — `sign_in` / `sign_out` bypass helpers for `actix_web::test`,
//! mirroring Devise's `IntegrationHelpers`.

#![allow(clippy::missing_errors_doc)]

use devise_rust::config::DeviseConfig;

/// Test configuration with fast `stretches` (4) and a fixed secret key.
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
/// Equivalent Devise path: `bypass_sign_in (proxy.sign_in)` — insert the
/// session payload without re-running callbacks, but always renew the
/// session first (D-03).
///
/// Returns the key the payload was inserted under for test-side
/// roundtrip assertions.
///
/// # Errors
///
/// Returns `DeviseError::Internal` when the session insert fails.
#[allow(clippy::unused_async)] // async boundary matches Devise's sign_in contract
pub async fn sign_in(
    session: &actix_session::Session,
    scope: &str,
    key: &devise_rust::adapter::DeviseKey,
    salt: &str,
) -> Result<String, devise_rust::error::DeviseError> {
    crate::bridge::insert_session_and_renew_sync(session, scope, key, salt)?;
    Ok(devise_rust::session::keys::scope_session_key(scope))
}

/// Sign out a scope via the session-store bypass (D-03 renew-before-clear).
///
/// # Errors
///
/// Infallible: session remove cannot fail independently.
#[allow(clippy::unused_async)] // async boundary matches Devise's sign_out contract
pub async fn sign_out(
    session: &actix_session::Session,
    scope: &str,
) -> Result<(), devise_rust::error::DeviseError> {
    crate::bridge::sign_out_and_renew(session, scope)?;
    Ok(())
}

/// IntegrationHelpers-parity sign-out: bridge sign-out plus the core
/// `forget` remember-cookie op so a test can drain it through the
/// `SignedJar` tombstone (T-08-07: logout never leaves a live remember
/// login).
///
/// Returns the [`RememberCookieOp::Clear`](devise_rust::rememberable::RememberCookieOp::Clear) to apply to the response jar.
///
/// # Errors
///
/// Infallible: see [`sign_out`].
#[allow(clippy::unused_async)]
pub async fn sign_out_with_forget(
    session: &actix_session::Session,
    scope: &str,
    config: &DeviseConfig,
) -> Result<devise_rust::rememberable::RememberCookieOp, devise_rust::error::DeviseError> {
    crate::bridge::sign_out_and_renew(session, scope)?;
    Ok(crate::remember::forget_op(scope, config))
}

/// `bypass_sign_in` parity (Devise `IntegrationHelpers#sign_in`): store the
/// session payload WITHOUT re-running callbacks but WITH the D-03
/// renew-before-insert. The model is never re-hashed — the session pair
/// comes from the record directly.
///
/// Returns the session key the payload was inserted under.
///
/// # Errors
///
/// Returns `DeviseError::Internal` when the session insert fails.
#[allow(clippy::unused_async)]
pub async fn bypass_sign_in<M>(
    session: &actix_session::Session,
    scope: &str,
    user: &M,
) -> Result<String, devise_rust::error::DeviseError>
where
    M: devise_rust::failure::AnyDeviseModel + Send + Sync,
{
    let (key, salt) = user.session_pair();
    crate::bridge::bypass_sign_in_and_renew_sync(session, scope, &key, &salt)?;
    Ok(devise_rust::session::keys::scope_session_key(scope))
}

/// Capture the `name=value` pairs of every `Set-Cookie` header on a test
/// response — the replay jar for later `TestRequest::insert_header(COOKIE,
/// ...)` calls (D-17).
#[must_use]
pub fn set_cookie_pairs<B>(resp: &actix_web::dev::ServiceResponse<B>) -> Vec<String> {
    resp.headers()
        .get_all(actix_web::http::header::SET_COOKIE)
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

/// Sign out multiple scopes via bypass (D-03 renew-before-clear-each).
///
/// # Errors
///
/// Infallible: see [`sign_out`].
#[allow(clippy::unused_async)]
pub async fn sign_out_all_scopes(
    session: &actix_session::Session,
    scopes: &[String],
) -> Result<(), devise_rust::error::DeviseError> {
    crate::bridge::sign_out_all_scopes_and_renew_sync(session, scopes)?;
    Ok(())
}

/// Construct an [`AuthRequest`](devise_rust::request::AuthRequest) for use in test-side proxy calls.
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
