//! `DeviseLayer` — tower `Layer`/`Service` pair owning the request pipeline:
//! scope resolution, `AuthRequest` snapshot, and `AuthProxy` construction.
//!
//! ## Pipeline ordering (session layer stays outermost)
//!
//! `DeviseLayer` must run INSIDE `SessionManagerLayer`: axum applies the
//! LAST `.layer()` call as the outermost, so applications wire
//!
//! ```text
//! Router::new()
//!     .layer(devise_layer)     // runs after the session layer
//!     .layer(session_layer);   // OUTERMOST — observes the request first
//! ```
//!
//! and [`session_manager_layer`] builds that session layer with the
//! `SameSite=Lax` override tower-sessions needs (its default `Strict`
//! withholds the cookie on the cross-site OAuth callback navigation,
//! orphaning PKCE/state), a signed cookie over the Devise-derived key,
//! `HttpOnly`, and `Secure` (the plain-HTTP opt-out belongs to the
//! example config, 09-02).
//!
//! ## Behavior
//!
//! 1. Fail closed (500) when no `tower_sessions::Session` is present in
//!    the request extensions — a router missing the session layer must
//!    never proceed as if anonymous.
//! 2. Longest-prefix scope resolution against
//!    [`ScopeRegistry::find_by_path`]; a miss continues unauthenticated.
//! 3. Owned `AuthRequest` snapshot: headers, cookies, query, method, path,
//!    `RequestFlags`, and the socket peer from `ConnectInfo<SocketAddr>`
//!    only — proxy forwarding headers are never consulted (D-20).
//! 4. `TowerSessionStore` over the cloned session plus a per-request
//!    `AuthProxy` with the configured finders, staged in extensions as
//!    [`AuthProxyHandle`] for extractors and handlers.
//!
//! ## Options
//!
//! - Session store: tower-sessions `MemoryStore` (D-01 default).
//! - `with_finder` registers the per-scope [`ModelFinder`] backing the
//!   proxy's fetch and strategy chain.
//! - `with_hooks` overrides the hook registry (defaults to empty; apps
//!   wire `register_devise_hooks` themselves).

#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::extract::ConnectInfo;
use axum::http::{Request, Response, StatusCode, header};
use devise_rust::config::DeviseConfig;
use devise_rust::error::DeviseError;
use devise_rust::hooks::HookRegistry;
use devise_rust::model::ModelFinder;
use devise_rust::proxy::AuthProxy;
use devise_rust::request::{AuthRequest, HttpMethod, RequestFlags, build_auth_request_with_peer};
use devise_rust::scope::{Mapping, ScopeRegistry};
use tower::{Layer, Service};
use tower_sessions::MemoryStore;
use tower_sessions::Session;
use tower_sessions::cookie::SameSite;
use tower_sessions::service::{SessionManagerLayer, SignedCookie};

use crate::bridge::TowerSessionStore;

/// Request-scoped `AuthProxy` staged in extensions.
///
/// `tokio::sync::Mutex` (not `std`) so the guard may live across `.await`:
/// extractors and handlers lock, run `authenticate_strict` /
/// `set_user`, and release, while handler futures stay `Send`.
pub type AuthProxyHandle = Arc<tokio::sync::Mutex<AuthProxy>>;

/// Tower layer producing the per-request Devise service.
///
/// ## Examples
///
/// ```rust,ignore
/// let layer = DeviseLayer::new(registry, config).with_finder("user", finder);
/// let app = Router::new()
///     .merge(sessions_router(mapping, state))
///     .layer(layer)
///     .layer(session_manager_layer(&config)?);
/// ```
#[derive(Clone)]
pub struct DeviseLayer {
    registry: Arc<ScopeRegistry>,
    config: Arc<DeviseConfig>,
    hooks: Arc<HookRegistry>,
    finders: HashMap<String, Arc<dyn ModelFinder>>,
}

impl DeviseLayer {
    /// Construct the layer over the shared registry and config.
    #[must_use]
    pub fn new(registry: Arc<ScopeRegistry>, config: Arc<DeviseConfig>) -> Self {
        Self {
            registry,
            config,
            hooks: Arc::new(HookRegistry::new()),
            finders: HashMap::new(),
        }
    }

    /// Register the [`ModelFinder`] backing one scope (session fetch and
    /// strategy chain).
    #[must_use]
    pub fn with_finder(mut self, scope: &str, finder: Arc<dyn ModelFinder>) -> Self {
        self.finders.insert(scope.to_string(), finder);
        self
    }

    /// Override the hook registry (apps wire
    /// [`register_devise_hooks`](devise_rust::hooks::register_devise_hooks)
    /// themselves).
    #[must_use]
    pub fn with_hooks(mut self, hooks: Arc<HookRegistry>) -> Self {
        self.hooks = hooks;
        self
    }
}

impl<S> Layer<S> for DeviseLayer {
    type Service = DeviseService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DeviseService {
            inner,
            layer: self.clone(),
        }
    }
}

/// Per-request service produced by [`DeviseLayer`].
#[derive(Clone)]
pub struct DeviseService<S> {
    inner: S,
    layer: DeviseLayer,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for DeviseService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: Default,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        // Tower contract: use the ready service; clone-and-replace keeps a
        // fresh clone for the next call (axum middleware pattern).
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let layer = self.layer.clone();

        Box::pin(async move {
            let mut req = req;
            // Fail closed when the session layer is missing or mis-ordered:
            // an anonymous fall-through here would silently disable every
            // session-backed guarantee (A2 probe).
            let Some(session) = req.extensions().get::<Session>().cloned() else {
                let mut response = Response::default();
                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                return Ok(response);
            };

            // Scope resolution: longest prefix over the registry; a miss
            // continues unauthenticated (unknown paths stay public).
            let path = req.uri().path().to_string();
            let mapping: Option<Mapping> = layer.registry.find_by_path(&path).cloned();

            // Owned snapshot of the request for core decisions.
            let auth_request = build_auth_request(&req, &layer.config);

            // Bridge store over the cloned session (Clone + Send + Sync —
            // no owned-extract dance) plus the per-request proxy.
            let store = Arc::new(TowerSessionStore::new(session));
            let mut proxy = AuthProxy::new(
                store,
                layer.registry.clone(),
                layer.hooks.clone(),
                layer.config.clone(),
            );
            for (scope, finder) in &layer.finders {
                proxy.register_finder(scope, finder.clone());
            }
            let handle: AuthProxyHandle = Arc::new(tokio::sync::Mutex::new(proxy));

            req.extensions_mut().insert(auth_request);
            req.extensions_mut().insert(layer.config.clone());
            req.extensions_mut().insert(handle);
            if let Some(mapping) = mapping {
                req.extensions_mut().insert(mapping);
            }

            inner.call(req).await
        })
    }
}

/// Build the session layer over the D-01 `MemoryStore` default with the
/// security posture the phase contract pins:
///
/// - `SameSite=Lax` — tower-sessions defaults to `Strict`, which withholds
///   the session cookie on the cross-site OAuth provider→app callback and
///   breaks the PKCE/state round-trip (Pitfall 6);
/// - signed cookie over the Devise-derived [`Key`](tower_sessions::cookie::Key)
///   (id-forgery probing hits an HMAC, not the store);
/// - `HttpOnly` and `Secure` on (the plain-HTTP `Secure` opt-out is
///   example-config-only, 09-02).
///
/// # Errors
///
/// Returns [`DeviseError::Config`] when the Devise `secret_key` is empty
/// (key derivation refuses empty secrets).
///
/// ## Examples
///
/// ```rust,ignore
/// let session_layer = session_manager_layer(&config)?;
/// let app = Router::new().layer(devise_layer).layer(session_layer);
/// ```
pub fn session_manager_layer(
    config: &DeviseConfig,
) -> Result<SessionManagerLayer<MemoryStore, SignedCookie>, DeviseError> {
    let key = crate::callbacks::derive_session_key(&config.secret_key)?;
    Ok(SessionManagerLayer::new(MemoryStore::default())
        .with_same_site(SameSite::Lax)
        .with_http_only(true)
        .with_secure(true)
        .with_signed(key))
}

/// Snapshot an incoming request into the core `AuthRequest`.
///
/// Headers land with lowercase names, cookies are parsed from every
/// `Cookie` header, and the query string feeds both `params` and `query`
/// (matching the actix bridge). The peer address comes from
/// `ConnectInfo<SocketAddr>` only — never a proxy header (D-20).
fn build_auth_request<ReqBody>(req: &Request<ReqBody>, config: &DeviseConfig) -> AuthRequest {
    let method = HttpMethod::from_str(req.method().as_str()).unwrap_or(HttpMethod::Get);
    let path = req.uri().path().to_string();

    let mut headers = HashMap::with_capacity(req.headers().len());
    for (name, value) in req.headers() {
        if let Ok(v) = value.to_str() {
            headers.insert(name.as_str().to_lowercase(), v.to_string());
        }
    }

    let mut cookies = HashMap::new();
    for value in req.headers().get_all(header::COOKIE) {
        if let Ok(raw) = value.to_str() {
            for pair in raw.split(';') {
                if let Some((name, value)) = pair.split_once('=') {
                    cookies.insert(name.trim().to_string(), value.trim().to_string());
                }
            }
        }
    }

    let mut params = HashMap::new();
    if let Some(query) = req.uri().query() {
        for pair in query.split('&') {
            if let Some((name, value)) = pair.split_once('=') {
                params.insert(name.to_string(), value.to_string());
            }
        }
    }
    let query = params.clone();

    let flags = RequestFlags {
        allow_params_authentication: config.params_authenticatable,
        ..RequestFlags::default()
    };

    let peer_addr = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip().to_string());

    build_auth_request_with_peer(
        method, path, headers, params, cookies, query, flags, peer_addr,
    )
}
