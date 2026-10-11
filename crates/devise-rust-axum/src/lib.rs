//! devise-rust-axum — Axum integration for devise-rust
//!
//! Tower-sessions bridge, tower layer, extractors, failure renderer, and
//! route registration mapping devise-rust core's framework-neutral auth
//! surface onto axum 0.8's request pipeline.
//!
//! Unlike the actix crate, `tower_sessions::Session` is `Clone + Send +
//! Sync`, so the bridge holds a cloned session handle and awaits freely —
//! there is no `!Send` owned-extract dance. `Session::cycle_id()` is async
//! and fallible, so every renewal call site propagates the error: a failed
//! rotation fails the privilege transition instead of persisting the old
//! session id (D-04).
//!
//! ## Modules
//!
//! - [`bridge`] — `TowerSessionStore` implementing the core
//!   [`SessionStore`](devise_rust::session::SessionStore) trait over a
//!   cloned `tower_sessions::Session`, plus the cycle-before-write
//!   transition helpers for every privilege path.
//! - [`layer`] — `DeviseLayer` tower `Layer`/`Service` pair: scope
//!   resolution, `AuthRequest` snapshot, `AuthProxy` construction, and the
//!   [`session_manager_layer`] builder (`SameSite` `Lax`, signed cookie).
//! - [`extractors`] — `Auth<M>` / `RequireAuth` `FromRequestParts`
//!   extractors reading only the layer-staged extensions (D-02 names).
//! - [`failure`] — `AxumFailureRenderer` delegating classification to core
//!   `build_failure` and rendering `NavigationalRedirect` as 302 + flash
//!   and `ApiUnauthorized` as 401.
//! - [`remember`] — signed remember-cookie transport: core codec values
//!   through the cookie 0.18 signed jar with the D-16 hardened attrs
//!   (the layer drains the proxy outbox; handlers never hold a jar).
//! - [`callbacks`] — session-signing `Key` derivation from the Devise
//!   `secret_key` (variable-length-safe `derive_from`, never `Key::from`).
//! - [`routes`] — the `devise_for`-equivalent router fn
//!   ([`devise_for_router`]) translating core `RouteSpec` data into an
//!   axum `Router`, plus all five controller groups (D-03/D-14), plus the
//!   09-01 tracer session routes.
//! - [`omniauth`] — the authorize + callback pair rendering the 09-03
//!   core omniauth policy over the shared route spec data (POST-only
//!   authorize, GET-or-POST callback, PKCE-state always-on).
//! - `stub_provider` — (feature `test-support` only) the generic
//!   `OAuth2` stub provider for the omniauth flow tests (D-06), shared
//!   with the actix crate's suite; never compiled into non-test builds.
//! - [`test_helpers`] — `sign_in` / `sign_out` bypass helpers with
//!   `Set-Cookie` capture and replay, mirroring Devise's
//!   `IntegrationHelpers` (test-only surface, shipped like the actix
//!   crate's).
//!
//! ## Options
//!
//! - Session store default: tower-sessions `MemoryStore` (D-01);
//!   `MokaStore`/Redis stay documented-only for multi-node deployments.
//! - Session cookie: `SameSite=Lax` (tower-sessions defaults to `Strict`,
//!   which withholds the cookie on the cross-site OAuth callback
//!   navigation), signed over the Devise-derived `Key`, `HttpOnly`, and
//!   `Secure` (plain-HTTP opt-out is example-config-only, 09-02).
//! - `cycle_id()` fires on every privilege transition: sign-in, sign-out,
//!   sign-out-all-scopes, bypass sign-in, and account update (D-04).
//!
//! ## Examples
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use devise_rust::config::DeviseConfig;
//! use devise_rust_axum::{DeviseLayer, session_manager_layer};
//!
//! let config = Arc::new(DeviseConfig {
//!     secret_key: "a-32-byte-devise-secret-key........".to_string(),
//!     ..DeviseConfig::default()
//! });
//! let session_layer = session_manager_layer(&config)?;
//! let app = axum::Router::new()
//!     .layer(DeviseLayer::new(registry, config))
//!     .layer(session_layer); // SessionManagerLayer stays OUTERMOST
//! ```

#![warn(clippy::all, clippy::pedantic, unsafe_code)]

pub mod bridge;
pub mod callbacks;
pub mod extractors;
pub mod failure;
pub mod layer;
pub mod omniauth;
pub mod remember;
pub mod routes;
/// Generic `OAuth2` stub provider — test support only (D-06). Gated
/// behind the `test-support` cargo feature: never compiled into
/// non-test builds; consumed by this crate's omniauth flow tests and
/// the actix crate's via its dev-dependency.
#[cfg(feature = "test-support")]
pub mod stub_provider;
pub mod test_helpers;

pub use bridge::{
    TowerSessionStore, account_update_and_renew, bypass_sign_in_and_renew,
    insert_session_and_renew, read_last_request_at, sign_out_all_scopes_and_renew,
    sign_out_and_renew, tick_last_request_at,
};
pub use callbacks::{csrf_token_key, derive_session_key, rotate_csrf_token};
pub use extractors::{
    Auth, AuthGroup, AuthRejection, RequireAuth, admin_session, admin_signed_in,
    authenticate_admin, authenticate_group, authenticate_scope, authenticate_user, current_admin,
    current_scope_record, current_user, group_signed_in, require_no_authentication, scope_session,
    scope_signed_in, user_session, user_signed_in,
};
pub use failure::AxumFailureRenderer;
pub use layer::{
    AuthProxyHandle, DeviseLayer, session_manager_layer, session_manager_layer_with_secure,
};
pub use omniauth::{OmniauthWebState, omniauth_router};
pub use remember::{
    RememberRead, apply_op, apply_ops, attrs_for_scope, clear_op, cookie_for_set,
    derive_remember_key, forget_op, ops_as_set_cookie_headers, read_cookie, removal_cookie,
    resolve_inbound, verified_cookie_value,
};
pub use routes::{
    DeviseRouterState, DeviseWebState, FullDeviseModel, devise_for_router, route_specs_for_mapping,
    sessions_router,
};
