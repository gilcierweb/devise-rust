//! Failure renderer — maps core `Failure` decisions onto axum responses.
//!
//! This module never re-implements Devise's decision logic. The core
//! [`build_failure`](devise_rust::failure::build_failure) function owns the
//! recall / http-auth / navigational / API priority matrix; the renderer
//! only translates the variant it receives into an HTTP response.
//!
//! ## Flash transport (S11)
//!
//! The navigational redirect carries the failure's flash key in the
//! `devise.flash` cookie as a **signed envelope** (cookie 0.18 signed jar
//! over the Devise-derived `Key` — the same lineage the session cookie
//! signs with) dressed in `HttpOnly` + `SameSite=Lax` + `Path=/` +
//! `Secure`. The bare key inside is an I18n key, never user data — and
//! the signature means a client can no longer forge flash payloads.
//! [`take_flash`] is the read-once consumer: it verifies the envelope and
//! hands back the key plus the clearing tombstone the caller must attach
//! to the response.
//!
//! ## Mapping table
//!
//! | Core variant           | Axum response                                        |
//! |------------------------|------------------------------------------------------|
//! | `NavigationalRedirect` | 302 toward `mapping.sign_in_path()` + signed flash  |
//! | `ApiUnauthorized`      | 401 with `WWW-Authenticate` when present             |
//! | `Recall`               | 302 toward the scope's sign-in path (Devise's recall re-render, scope-mounted) |
//! | everything else        | 401                                                  |

#![allow(clippy::missing_errors_doc)] // failure shapes documented upstream

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use cookie::{Cookie, CookieJar, Key, SameSite};
use devise_rust::config::DeviseConfig;
use devise_rust::failure::{Failure, FailureReason, FailureRenderer};
use devise_rust::request::AuthRequest;
use devise_rust::scope::Mapping;

/// Flash cookie name carrying the failure's I18n key (actix parity; the
/// signed value derives from the flash key, never user data).
pub const FLASH_COOKIE: &str = "devise.flash";

/// Failure renderer for axum: delegates classification to core
/// `build_failure`, renders the resulting `Failure` as an axum `Response`.
///
/// Construct with [`AxumFailureRenderer::for_config`] so the flash rides
/// the signed transport: the renderer carries the cookie-signing `Key`
/// derived from the Devise `secret_key`. [`AxumFailureRenderer::new`]
/// (and `Default`) build a keyless renderer that redirects WITHOUT any
/// flash cookie — the fail-closed default, never an unsigned one.
///
/// ## Examples
///
/// ```rust,ignore
/// let renderer = AxumFailureRenderer::for_config(&config);
/// let failure = build_failure(&request, &mapping, &config, FailureReason::Unauthenticated);
/// let response = renderer.render(&failure, &mapping);
/// assert_eq!(response.status(), StatusCode::FOUND);
/// ```
#[derive(Debug, Clone, Default)]
pub struct AxumFailureRenderer {
    key: Option<Key>,
}

impl AxumFailureRenderer {
    /// Create a keyless renderer: redirects carry NO flash cookie (the
    /// fail-closed default — flash transport requires the signing key).
    #[must_use]
    pub fn new() -> Self {
        Self { key: None }
    }

    /// Create the renderer with the cookie-signing key derived from the
    /// Devise `secret_key` (the single-secret story: one secret rotates
    /// every cookie consumer). A secret too short for derivation yields
    /// the keyless renderer — callers that validated at boot never hit
    /// this branch, and an invalid secret must never degrade to an
    /// unsigned flash.
    #[must_use]
    pub fn for_config(config: &DeviseConfig) -> Self {
        Self {
            key: crate::remember::derive_remember_key(config).ok(),
        }
    }

    /// Create the renderer with an explicit cookie-signing key.
    #[must_use]
    pub fn with_key(key: Key) -> Self {
        Self { key: Some(key) }
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
                // plus the SIGNED flash cookie (S11).
                let target = if location.is_empty() {
                    mapping.sign_in_path()
                } else {
                    location.clone()
                };
                let mut response = redirect_found(&target);
                if let Some(key) = &self.key {
                    if let Some(flash) = flash_cookie_header(key, flash_key) {
                        response.headers_mut().append(header::SET_COOKIE, flash);
                    }
                }
                response
            }
            Failure::ApiUnauthorized {
                status,
                www_authenticate,
            } => {
                // API: 401 (+ optional WWW-Authenticate for HTTP Basic)
                // with a JSON body.
                let status = StatusCode::from_u16(*status).unwrap_or(StatusCode::UNAUTHORIZED);
                let mut response = (
                    status,
                    axum::Json(serde_json::json!({ "error": "unauthorized" })),
                )
                    .into_response();
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
                // Recall (Devise's failure_app `recall` branch): re-render the
                // scope's sign-in form. Devise re-dispatches `sessions#new`
                // with the posted params; the port redirects to the mapping's
                // sign-in path (the scope-mounted equivalent of
                // `/{controller}/{action}`), so the user lands on the real
                // form instead of an unmounted bare path.
                let _ = (controller, action);
                redirect_found(&mapping.sign_in_path())
            }
            // Catch-all for the raw strategy/hook variants (Timeout,
            // InvalidCredentials, Locked, Unconfirmed, NotFound, Config,
            // Internal): 401 JSON, classified upstream when rendered.
            _ => (
                StatusCode::UNAUTHORIZED,
                axum::Json(serde_json::json!({ "error": "unauthorized" })),
            )
                .into_response(),
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

/// Render the SIGNED flash cookie header value carrying the flash key.
///
/// `HttpOnly` + `SameSite=Lax` + `Path=/` + `Secure`: the cookie 0.18
/// signed jar seals the bare I18n key (MAC-prefixed envelope), so the
/// value cannot be forged or read over plain http (S11). Shared with the
/// route handlers' `flash_redirect`.
pub(crate) fn flash_cookie_header(key: &Key, flash_key: &str) -> Option<HeaderValue> {
    if flash_key.is_empty() {
        return None;
    }
    let cookie = Cookie::build((FLASH_COOKIE, flash_key.to_string()))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(true)
        .build();
    let mut jar = CookieJar::new();
    jar.signed_mut(key).add(cookie);
    jar.delta()
        .next()
        .and_then(|header| HeaderValue::from_str(&header.to_string()).ok())
}

/// Verify one raw `devise.flash` cookie value, yielding the bare flash key.
///
/// `None` means the signature did not verify (a tampered or foreign
/// value) — the caller treats it as no flash and still clears the cookie.
#[must_use]
pub fn verified_flash_value(key: &Key, raw_value: &str) -> Option<String> {
    let mut jar = CookieJar::new();
    jar.add_original(Cookie::new(FLASH_COOKIE, raw_value.to_string()));
    jar.signed(key)
        .get(FLASH_COOKIE)
        .map(|cookie| cookie.value().to_string())
}

/// Outcome of the read-once flash consume ([`take_flash`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlashRead {
    /// The verified bare flash key, when a signed flash cookie was present.
    pub key: Option<String>,
    /// The clearing tombstone the caller MUST attach to the response
    /// (`Set-Cookie`), so the flash is consumed exactly once. Present
    /// whenever a flash cookie was seen — even a tampered one.
    pub clear: Option<HeaderValue>,
}

/// Read-once Devise flash: verify the inbound signed `devise.flash`
/// cookie and hand back the bare key plus the clearing tombstone (S11).
///
/// Devise's flash is consumed on first render (Rails flash semantics);
/// the cookie transport mirrors that by pairing every read with a removal
/// cookie. A tampered value yields `key: None` AND the tombstone — a
/// forged flash never renders and never survives either.
#[must_use]
pub fn take_flash(request: &AuthRequest, config: &DeviseConfig) -> FlashRead {
    let Some(raw) = request.cookies.get(FLASH_COOKIE) else {
        return FlashRead {
            key: None,
            clear: None,
        };
    };
    let clear = removal_flash_header();
    let key = crate::remember::derive_remember_key(config)
        .ok()
        .and_then(|key| verified_flash_value(&key, raw));
    FlashRead {
        key,
        clear: Some(clear),
    }
}

/// The `devise.flash` removal cookie header (read-once consumption).
fn removal_flash_header() -> HeaderValue {
    let mut cookie = Cookie::build((FLASH_COOKIE, String::new()))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .build();
    cookie.make_removal();
    HeaderValue::from_str(&cookie.to_string()).unwrap_or_else(|_| HeaderValue::from_static(""))
}
