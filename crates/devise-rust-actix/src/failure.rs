//! Failure renderer — maps core `Failure` decisions onto `actix_web::HttpResponse`.
//!
//! This module never re-implements Devise's decision logic. The core
//! [`build_failure`](devise_rust::failure::build_failure) function owns the
//! recall / http-auth / navigational / API priority matrix; the renderer
//! only translates the variant it receives into an HTTP response.
//!
//! ## Mapping table (D-09)
//!
//! | Core variant                | Actix response                                          |
//! |-----------------------------|---------------------------------------------------------|
//! | `NavigationalRedirect`      | 302 toward `mapping.sign_in_path()`, including flash    |
//! | `ApiUnauthorized`           | 401 with `WWW-Authenticate` when present                |
//! | `Recall { .. }`             | 302 toward the scope's sign-in path (recall re-render)   |

#![allow(clippy::missing_errors_doc)] // failure shapes documented upstream

use actix_web::HttpResponse;
use actix_web::http::header;
use devise_rust::failure::{Failure, FailureRenderer};
use devise_rust::scope::Mapping;

/// Failure renderer for actix-web: delegates classification to core
/// `build_failure`, renders the resulting `Failure` as `HttpResponse`.
#[derive(Debug, Clone, Default)]
pub struct ActixFailureRenderer;

impl ActixFailureRenderer {
    /// Create a new renderer instance.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl FailureRenderer for ActixFailureRenderer {
    type Response = HttpResponse;

    fn render(&self, failure: &Failure, mapping: &Mapping) -> Self::Response {
        match failure {
            Failure::NavigationalRedirect {
                location,
                flash_key,
                stored_location: _stored_location,
            } => {
                // Navigational → 302 toward the mapping's sign-in path (the
                // `location` field, which the core already computed from
                // `mapping.sign_in_path()`), plus a flash cookie carrying
                // `flash_key`.
                let target = if location.is_empty() {
                    mapping.sign_in_path()
                } else {
                    location.clone()
                };
                let mut response = HttpResponse::Found()
                    .insert_header((header::LOCATION, target))
                    .finish();
                if let Some(flash_cookie) = render_flash_cookie(flash_key) {
                    response.add_cookie(&flash_cookie).ok();
                }
                // `stored_location` is written to the session jar by the
                // controller layer in Task 2; it does not alter the redirect.
                response
            }
            Failure::ApiUnauthorized {
                status,
                www_authenticate,
            } => {
                // API → 401 (+ optional WWW-Authenticate for HTTP Basic).
                let status_code = actix_web::http::StatusCode::from_u16(*status)
                    .unwrap_or(actix_web::http::StatusCode::UNAUTHORIZED);
                let mut builder = HttpResponse::build(status_code);
                if let Some(header_value) = www_authenticate {
                    builder.insert_header((header::WWW_AUTHENTICATE, header_value.clone()));
                }
                builder.finish()
            }
            Failure::Recall { controller, action } => {
                // Recall (Devise's failure_app `recall` branch): re-render the
                // scope's sign-in form. Devise re-dispatches `sessions#new`
                // with the posted params; the port redirects to the mapping's
                // sign-in path (the scope-mounted equivalent of
                // `/{controller}/{action}`), so the user lands on the real
                // form instead of an unmounted bare path.
                let target = mapping.sign_in_path();
                let _ = (controller, action);
                HttpResponse::Found()
                    .insert_header((header::LOCATION, target))
                    .finish()
            }
            // Catch-all for core failure variants the actix renderer does
            // not yet target: Timeout, InvalidCredentials, Locked,
            // Unconfirmed, NotFound, Config, ...
            other => {
                let _ = other; // Rendered as generic 401
                HttpResponse::Unauthorized().finish()
            }
        }
    }
}

/// Render a flash cookie carrying the failure's `flash_key`.
///
/// Cookie contents are HMAC-less at this stage: the `SessionMiddleware`'s
/// `CookieSessionStore` rounds them through the derived `Key`, so the flash
/// value travels client-side in the session jar.
fn render_flash_cookie(flash_key: &str) -> Option<actix_web::cookie::Cookie<'static>> {
    if flash_key.is_empty() {
        return None;
    }
    let mut cookie =
        actix_web::cookie::Cookie::new("devise.flash".to_string(), flash_key.to_string());
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_same_site(actix_web::cookie::SameSite::Lax);
    Some(cookie)
}
