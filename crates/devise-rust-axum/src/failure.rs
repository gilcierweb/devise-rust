//! Failure renderer — maps core `Failure` decisions onto axum responses.
//!
//! This module never re-implements Devise's decision logic. The core
//! [`build_failure`](devise_rust::failure::build_failure) function owns the
//! recall / http-auth / navigational / API priority matrix; the renderer
//! only translates the variant it receives into an HTTP response.
//!
//! ## Mapping table
//!
//! | Core variant           | Axum response                                        |
//! |------------------------|------------------------------------------------------|
//! | `NavigationalRedirect` | 302 toward `mapping.sign_in_path()` + flash cookie   |
//! | `ApiUnauthorized`      | 401 with `WWW-Authenticate` when present             |
//! | `Recall`               | 302 toward the recall target (documented gap: Devise re-dispatches to the controller action; 09-02 wires per-controller rendering) |
//! | everything else        | 401                                                  |

#![allow(clippy::missing_errors_doc)] // failure shapes documented upstream

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use devise_rust::failure::{Failure, FailureReason, FailureRenderer};
use devise_rust::scope::Mapping;
use tower_sessions::cookie::{Cookie, SameSite};

/// Flash cookie name carrying the failure's I18n key (actix parity; the
/// value travels client-side and is fully derived from the flash key).
pub const FLASH_COOKIE: &str = "devise.flash";

/// Failure renderer for axum: delegates classification to core
/// `build_failure`, renders the resulting `Failure` as an axum `Response`.
///
/// ## Examples
///
/// ```rust,ignore
/// let failure = build_failure(&request, &mapping, &config, FailureReason::Unauthenticated);
/// let response = AxumFailureRenderer.render(&failure, &mapping);
/// assert_eq!(response.status(), StatusCode::FOUND);
/// ```
#[derive(Debug, Clone, Default)]
pub struct AxumFailureRenderer;

impl AxumFailureRenderer {
    /// Create a renderer instance.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl FailureRenderer for AxumFailureRenderer {
    type Response = Response;

    fn render(&self, failure: &Failure, mapping: &Mapping) -> Self::Response {
        match failure {
            Failure::NavigationalRedirect {
                location,
                flash_key,
                ..
            } => {
                // Navigational: 302 toward the mapping's sign-in path (the
                // `location` the core computed from `mapping.sign_in_path()`),
                // plus the flash key in a cookie.
                let target = if location.is_empty() {
                    mapping.sign_in_path()
                } else {
                    location.clone()
                };
                let mut response = redirect_found(&target);
                if let Some(flash) = flash_cookie_header(flash_key) {
                    response.headers_mut().append(header::SET_COOKIE, flash);
                }
                response
            }
            Failure::ApiUnauthorized {
                status,
                www_authenticate,
            } => {
                // API: 401 (+ optional WWW-Authenticate for HTTP Basic).
                let status = StatusCode::from_u16(*status).unwrap_or(StatusCode::UNAUTHORIZED);
                let mut response = status.into_response();
                if let Some(challenge) = www_authenticate {
                    if let Ok(value) = HeaderValue::from_str(challenge) {
                        response
                            .headers_mut()
                            .insert(header::WWW_AUTHENTICATE, value);
                    }
                }
                response
            }
            Failure::Recall { controller, action } => {
                // Recall: Devise re-dispatches to the controller/action with
                // the original params. Until per-controller wiring (09-02),
                // respond with a 302 toward the recall target — the same
                // documented gap the actix renderer carries.
                redirect_found(&format!("/{controller}/{action}"))
            }
            // Catch-all for the raw strategy/hook variants (Timeout,
            // InvalidCredentials, Locked, Unconfirmed, NotFound, Config,
            // Internal): generic 401, classified upstream when rendered.
            _ => StatusCode::UNAUTHORIZED.into_response(),
        }
    }
}

/// Extract the Devise flash-key reason for a raw `Failure`.
///
/// Strategy and hook failures carry Devise's thrown message; the renderer
/// needs the matching `FailureReason` flash key when re-classifying
/// through core `build_failure` (`:timeout`, `:locked`, `:unconfirmed`,
/// `:invalid`, else unauthenticated).
#[must_use]
pub fn failure_reason(failure: &Failure) -> FailureReason {
    match failure {
        Failure::Timeout => FailureReason::Timeout,
        Failure::Locked { .. } => FailureReason::Locked,
        Failure::Unconfirmed { .. } => FailureReason::Unconfirmed,
        Failure::InvalidCredentials { .. } => FailureReason::Invalid,
        _ => FailureReason::Unauthenticated,
    }
}

/// Render a 302 response toward `target`.
fn redirect_found(target: &str) -> Response {
    let mut response = StatusCode::FOUND.into_response();
    let location = HeaderValue::from_str(target).unwrap_or_else(|_| HeaderValue::from_static("/"));
    response.headers_mut().insert(header::LOCATION, location);
    response
}

/// Render the flash cookie header value carrying the flash key.
///
/// `HttpOnly` + `SameSite=Lax` + `Path=/`: the value is an I18n key, never
/// user data, so the jar round-trip carries no secrets. Shared with the
/// route handlers' `flash_redirect`.
pub(crate) fn flash_cookie_header(flash_key: &str) -> Option<HeaderValue> {
    if flash_key.is_empty() {
        return None;
    }
    let mut cookie = Cookie::new(FLASH_COOKIE, flash_key.to_string());
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    HeaderValue::from_str(&cookie.to_string()).ok()
}
