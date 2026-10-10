//! Route registration — `devise_for` config fn translating core
//! [`RouteSpec`](devise_rust::scope::RouteSpec) data into actix-web
//! routes.
//!
//! ## Ordering
//!
//! `devise_for` is a helper that registers the scope's routes through a
//! closure; the actual HTTP route table lives in `actix_web::Scope` and is
//! wired by the full Task 3 work. This file exposes the translator plus a
//! minimal tracer path for Task 1.

use actix_web::{HttpResponse, Scope, web};
use devise_rust::scope::{Mapping, RouteSpec};

/// Configuration for a `devise_for` invocation.
#[derive(Debug, Clone)]
pub struct DeviseRouteConfig {
    /// The scope `Mapping` this block registers.
    pub mapping: Mapping,
}

/// Translate a core [`RouteSpec`] into an actix-web handler registration
/// closure. Returning a closure keeps `devise_for` agnostic of the
/// concrete `Scope` instance.
#[must_use]
pub fn route_specs_for_mapping(mapping: &Mapping) -> Vec<RouteSpec> {
    mapping.route_specs()
}

/// Minimal tracer block: registers the scope's sign-in / sign-out routes
/// on an actix `Scope` and returns it for chaining.
///
/// The full controller surface arrives in Task 3 (08-03); the tracer slice
/// only wires `POST sign_in` and `DELETE sign_out` to prove the
/// end-to-end session renewal path in `session_bridge.rs`.
pub fn devise_for<F>(scope: Scope, _config: &DeviseRouteConfig, configure: F) -> Scope
where
    F: FnOnce(&mut Scope) + Send + 'static,
{
    // Task 1 tracer: register sign_in POST and sign_out DELETE. The
    // configure callback is unused here but reserved for Task 3's full
    // route wiring.
    let _ = configure;
    scope
        .route("/sign_in", web::post().to(HttpResponse::Ok))
        .route("/sign_out", web::delete().to(HttpResponse::Ok))
}
