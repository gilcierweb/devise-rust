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
                // `mapping.sign_in_path()`). The flash does NOT ride this
                // response: the core renderer contract has no session
                // access, and Devise's flash is session state — the actix
                // callers (extractors) stage `flash_key` into the signed
                // session before rendering through here (S11).
                let target = if location.is_empty() {
                    mapping.sign_in_path()
                } else {
                    location.clone()
                };
                let _ = flash_key;
                HttpResponse::Found()
                    .insert_header((header::LOCATION, target))
                    .finish()
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

// (S11 removed the standalone flash cookie: Devise's flash is session
// state, staged by the callers through `bridge::set_flash` and read once
// via `bridge::take_flash` — never an unsigned client-forgeable cookie.)
