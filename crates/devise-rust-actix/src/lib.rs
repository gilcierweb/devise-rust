//! devise-rust-actix — Actix Web integration for devise-rust
//!
//! This crate provides the Actix Web session bridge, middleware, extractors,
//! failure renderer, route registration, and test helpers that map devise-rust
//! core's framework-neutral auth surface onto actix-web's request pipeline.
//!
//! ## CSRF — the port's contract (read this before shipping)
//!
//! **This crate does not verify request origins.** Devise runs inside
//! Rails, where `protect_from_forgery` guards every POST/PATCH/PUT/DELETE
//! before any controller action runs; the port leaves that layer to the
//! framework, because actix-web ships no built-in CSRF middleware.
//!
//! You MUST:
//!
//! 1. mount your framework's CSRF protection (an origin/token-check
//!    middleware) AROUND every mutating devise route — `sign_in`, `sign_up`,
//!    account `update`/`destroy`, and the passwords/confirmations/unlocks
//!    forms — and
//! 2. call [`bridge::handle_unverified_request`] from that middleware's
//!    failure path. Devise's override (`controllers/helpers.rb:254-260`)
//!    signs out EVERY scope, clears the devise session data, and renews the
//!    session id, so nothing signed-in survives a forged request; the
//!    bridge helper performs exactly that sweep against the live
//!    `actix_session::Session`.
//!
//! Without both pieces, a cross-site form post can drive any signed-in
//! session through the sign-in/sign-out/registration actions.
//!
//! ## Modules
//!
//! - [`bridge`] — the synchronous session I/O helpers over
//!   `actix_session::Session` (D-04 owned-extract), plus the S11
//!   session-backed flash (`set_flash` / `take_flash`).
//! - [`middleware`] — `DeviseMiddleware` Transform/Service pair: scope
//!   resolution, owned snapshot of session values, remember-cookie drain.
//! - [`failure`] — actix `FailureRenderer` mapping core `Failure` decisions
//!   to `HttpResponse` (302 navigational / 401 API).
//! - [`callbacks`] — `derive_actix_key` (`Key::derive_from` bridge) and the
//!   CSRF-rotation hook for `clean_up_csrf_token_on_authentication`.
//! - [`extractors`] — `Auth<M>` / `RequireAuth` / per-scope helper fns.
//! - [`routes`] — `devise_for` route spec → actix `Scope` translator.
//! - [`omniauth`] — the authorize + callback pair rendering the 09-03
//!   core omniauth policy over the shared route spec data (POST-only
//!   authorize, GET-or-POST callback, PKCE-state always-on).
//! - [`test_helpers`] — `sign_in`/`sign_out`/bypass helpers for
//!   `actix_web::test`, mirroring Devise's `IntegrationHelpers`.

#![warn(clippy::all, clippy::pedantic, unsafe_code)]

pub mod bridge;
pub mod callbacks;
pub mod extractors;
pub mod failure;
pub mod middleware;
pub mod omniauth;
pub mod remember;
pub mod routes;
pub mod schema;
pub mod test_helpers;

pub use callbacks::{derive_actix_key, rotate_csrf_token};
pub use extractors::{
    Auth, AuthGroup, RequireAuth, admin_session, admin_signed_in, authenticate_admin,
    authenticate_group, authenticate_scope, authenticate_user, current_admin, current_scope_record,
    current_user, group_signed_in, require_no_authentication, scope_session, scope_signed_in,
    user_session, user_signed_in,
};
pub use failure::ActixFailureRenderer;
pub use middleware::{DeviseMiddleware, DeviseMiddlewareConfig, ResolvedAuth, ResolvedAuthHandle};
pub use omniauth::{OmniauthWebState, devise_omniauth_scope};
pub use remember::{
    RememberRead, apply_op, apply_ops, attrs_for_scope, clear_op, cookie_for_set,
    derive_remember_key, forget_op, read_cookie, removal_cookie, resolve_inbound,
};
pub use routes::{DeviseWebState, FullDeviseModel, devise_for_users, route_specs_for_mapping};
