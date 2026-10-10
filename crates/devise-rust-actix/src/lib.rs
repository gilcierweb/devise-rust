//! devise-rust-actix — Actix Web integration for devise-rust
//!
//! This crate provides the Actix Web session bridge, middleware, extractors,
//! failure renderer, route registration, and test helpers that map devise-rust
//! core's framework-neutral auth surface onto actix-web's request pipeline.
//!
//! ## Modules
//!
//! - [`bridge`] — `ActixSessionStore` implementing the core `SessionStore`
//!   trait over `actix_session::Session` (D-04 owned-extract).
//! - [`middleware`] — `DeviseMiddleware` Transform/Service pair: scope
//!   resolution, owned snapshot of session values, remember-cookie drain.
//! - [`failure`] — actix `FailureRenderer` mapping core `Failure` decisions
//!   to `HttpResponse` (302 navigational / 401 API).
//! - [`callbacks`] — `derive_actix_key` (`Key::derive_from` bridge) and the
//!   CSRF-rotation hook for `clean_up_csrf_token_on_authentication`.
//! - [`extractors`] — `Auth<M>` / `RequireAuth` / per-scope helper fns.
//! - [`routes`] — `devise_for` route spec → actix `Scope` translator.
//! - [`test_helpers`] — `sign_in`/`sign_out`/bypass helpers for
//!   `actix_web::test`, mirroring Devise's `IntegrationHelpers`.

#![warn(clippy::all, clippy::pedantic, unsafe_code)]

pub mod bridge;
pub mod callbacks;
pub mod extractors;
pub mod failure;
pub mod middleware;
pub mod routes;
pub mod test_helpers;

pub use bridge::ActixSessionStore;
pub use callbacks::{derive_actix_key, rotate_csrf_token};
pub use extractors::{Auth, RequireAuth};
pub use failure::ActixFailureRenderer;
pub use middleware::{DeviseMiddleware, DeviseMiddlewareConfig};
pub use routes::{DeviseRouteConfig, devise_for, route_specs_for_mapping};
