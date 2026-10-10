//! `DeviseMiddleware` — actix-web Transform/Service pair that owns the
//! request pipeline: scope resolution, owned session snapshot, `AuthProxy`
//! construction, hook dispatch (D-04 / D-06 / D-09).
//!
//! ## Pipeline ordering (D-01)
//!
//! `DeviseMiddleware` must be registered on the *outer* side of
//! `actix_session::SessionMiddleware` — actix visits middlewares in reverse
//! registration order, so wrapping `DeviseMiddleware` *before* wrapping
//! `SessionMiddleware` puts the Devise pipeline inside the session one.
//!
//! ## Behavior
//!
//! 1. Longest-prefix scope resolution against [`ScopeRegistry::find_by_path`].
//! 2. Owned snapshot of cookie/header/params into `AuthRequest` (D-04).
//! 3. Insertion of `AuthRequest` into request extensions for the extractor
//!    layer (extensions are the actix-web mailbox).
//! 4. Hooks fire later, from the controller/extractor side where the
//!    `Session` handle is reachable synchronously.

#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::future_not_send)]
#![allow(clippy::redundant_async_block)]
// The async block around `fut.await` is required to coerce S::Future into
// the boxed Future type the `Service` impl declares; without the async
// wrapper the trait associated-type bound cannot be satisfied.

use std::{
    collections::HashMap,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use actix_web::{
    Error, HttpMessage,
    body::MessageBody,
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
};
use devise_rust::{
    config::DeviseConfig,
    request::{AuthRequest, HttpMethod, RequestFlags},
    scope::ScopeRegistry,
    session::SessionStore,
};

/// Shared configuration for the middleware.
#[derive(Clone)]
pub struct DeviseMiddlewareConfig {
    /// Session store implementation (`ActixSessionStore`).
    pub session_store: Arc<dyn SessionStore>,
    /// Scope registry for mapping paths to scopes.
    pub scope_registry: Arc<ScopeRegistry>,
    /// Devise configuration.
    pub config: Arc<DeviseConfig>,
}

/// `DeviseMiddleware` — outer [`Transform`] producing the per-request service.
#[derive(Clone)]
pub struct DeviseMiddleware {
    config: DeviseMiddlewareConfig,
}

impl DeviseMiddleware {
    /// Construct the middleware from its shared configuration pieces.
    #[must_use]
    pub fn new(
        session_store: Arc<dyn SessionStore>,
        scope_registry: Arc<ScopeRegistry>,
        config: Arc<DeviseConfig>,
    ) -> Self {
        Self {
            config: DeviseMiddlewareConfig {
                session_store,
                scope_registry,
                config,
            },
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for DeviseMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: Send + 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = DeviseMiddlewareService<S>;
    type InitError = ();
    type Future = Pin<Box<dyn Future<Output = Result<Self::Transform, Self::InitError>>>>;

    fn new_transform(&self, service: S) -> Self::Future {
        let config = self.config.clone();
        Box::pin(async move { Ok(DeviseMiddlewareService { service, config }) })
    }
}

/// Per-request service produced by `DeviseMiddleware`.
pub struct DeviseMiddlewareService<S> {
    service: S,
    config: DeviseMiddlewareConfig,
}

impl<S, B> Service<ServiceRequest> for DeviseMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: Send + 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let config = self.config.clone();

        // Resolve scope longest-prefix before touching the request further.
        let scope = config
            .scope_registry
            .find_by_path(req.path())
            .map(|m| m.name.clone());

        // D-04 owned snapshot: the raw cookie/header/params data is cloned
        // synchronously; the remainder of the pipeline owns plain Rust values.
        let auth_request = build_auth_request(&req, &config.config, scope.as_deref());

        // Attach to request extensions for downstream handlers/extractors.
        req.extensions_mut().insert(auth_request);

        let fut = self.service.call(req);
        Box::pin(async move { fut.await })
    }
}

/// Build an owned [`AuthRequest`] snapshot of an actix request.
fn build_auth_request(
    req: &ServiceRequest,
    config: &DeviseConfig,
    scope: Option<&str>,
) -> AuthRequest {
    let mut cookies = HashMap::new();
    if let Some(scope_name) = scope {
        let session_key = devise_rust::session::keys::scope_session_key(scope_name);
        let remember_key = devise_rust::session::keys::remember_token_key(scope_name);
        let stored_key = devise_rust::session::keys::stored_location_key(scope_name);
        for name in [session_key, remember_key, stored_key] {
            if let Some(cookie) = req.cookie(&name) {
                cookies.insert(name, cookie.value().to_string());
            }
        }
    }

    let mut headers = HashMap::new();
    for (name, value) in req.headers() {
        if let Ok(v) = value.to_str() {
            headers.insert(name.as_str().to_lowercase(), v.to_string());
        }
    }

    let mut params = HashMap::new();
    let query_str = req.query_string();
    if !query_str.is_empty() {
        for pair in query_str.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                params.insert(k.to_string(), v.to_string());
            }
        }
    }

    let method = HttpMethod::from_str(req.method().as_str()).unwrap_or(HttpMethod::Get);

    let flags = RequestFlags {
        skip_storage: false,
        skip_timeout: false,
        skip_timeoutable: false,
        skip_trackable: false,
        allow_params_authentication: config.params_authenticatable,
    };

    // D-11: read peer_addr from the socket connection only, never
    // X-Forwarded-For.
    let peer_addr = req.connection_info().peer_addr().map(str::to_string);

    AuthRequest {
        method,
        path: req.path().to_string(),
        headers,
        cookies,
        params: params.clone(),
        query: params,
        flags,
        peer_addr,
    }
}
