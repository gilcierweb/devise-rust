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
//! 4. Non-strict `AuthProxy` fetch for the resolved scope: the warden
//!    payload through the bridge store, salt validation via the scope's
//!    finder (mismatch deletes the key), then `Event::Request` hook
//!    dispatch with the live record — the core hook bodies own the
//!    timeout check, the live remember-me exemption, and the
//!    integer-epoch `last_request_at` tick, honoring the
//!    `skip_timeoutable` / `skip_timeout` / `skip_trackable` flags carried
//!    on the `AuthRequest`.
//! 5. `TowerSessionStore` over the cloned session plus the per-request
//!    `AuthProxy` with the configured finders, staged in extensions as
//!    [`AuthProxyHandle`] for extractors and handlers.
//! 6. After the inner service responds, the remember-cookie outbox
//!    drains into signed `Set-Cookie` headers (the 09-02 transport):
//!    `Set` ops carry the core codec value through the cookie 0.18
//!    signed jar — the same lineage the session cookie signs with —
//!    dressed in the hardened attributes; `Clear` ops render signed
//!    tombstones. Inbound, the resolved scope's remember cookie is
//!    signature-verified so the core strategy reads the plaintext
//!    triple (a failed verify keeps the raw value, which the strategy
//!    classifies as stale — delete and pass through).
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
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::extract::ConnectInfo;
use axum::http::{HeaderValue, Request, Response, StatusCode, header};
use devise_rust::adapter::DeviseKey;
use devise_rust::config::DeviseConfig;
use devise_rust::error::DeviseError;
use devise_rust::failure::AnyDeviseModel;
use devise_rust::hooks::{Event, HookContext, HookProxy, HookRegistry};
use devise_rust::model::ModelFinder;
use devise_rust::proxy::{AuthProxy, SetUserEvent, SetUserOpts};
use devise_rust::rememberable::RememberCookieOp;
use devise_rust::request::{AuthRequest, HttpMethod, RequestFlags, build_auth_request_with_peer};
use devise_rust::scope::{Mapping, ScopeRegistry};
use devise_rust::session::keys;
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
    ResBody: Default + Send,
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
            let mut auth_request = build_auth_request(&req, &layer.config);

            // Inbound remember transport (09-02): unwrap the signature on
            // the resolved scope's remember cookie so the core strategy
            // reads the plaintext triple. A failed verify KEEPS the raw
            // value — the strategy then classifies it as stale and the
            // response pipeline renders the delete tombstone (unsigned
            // 09-01-era cookies still parse, backward compatible).
            if let Some(mapping) = &mapping {
                if mapping.has_module(devise_rust::scope::Module::Rememberable) {
                    verify_inbound_remember_cookie(&mut auth_request, &layer.config, &mapping.name);
                }
            }

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

            // Non-strict fetch + Event::Request hooks for the resolved
            // scope (timeout tick, remember exemption — core hook bodies).
            if let Some(mapping) = &mapping {
                fetch_and_dispatch_request_hooks(
                    &mut proxy,
                    &layer.finders,
                    &layer.hooks,
                    mapping,
                    &auth_request,
                )
                .await;
            }

            let handle: AuthProxyHandle = Arc::new(tokio::sync::Mutex::new(proxy));

            req.extensions_mut().insert(auth_request);
            req.extensions_mut().insert(layer.config.clone());
            req.extensions_mut().insert(handle.clone());
            if let Some(mapping) = mapping {
                req.extensions_mut().insert(mapping);
            }

            let mut response = inner.call(req).await?;

            // Drain the remember-cookie outbox into signed Set-Cookie
            // headers (the 09-02 transport; codec validation stays core).
            let ops = handle.lock().await.take_remember_cookie_ops();
            apply_remember_ops(&mut response, &layer.config, &ops);
            Ok(response)
        })
    }
}

/// Non-strict warden fetch plus `Event::Request` hook dispatch for the
/// resolved scope.
///
/// The fetch mirrors core `AuthProxy::fetch_from_session` semantics over
/// the erased finder (the proxy's own fetch stays strategy-coupled for the
/// strict path): read the `[key, salt]` payload, fetch the record, compare
/// salts constant-time, and on mismatch DELETE the session key and yield
/// nothing (T-09-02).
///
/// Request hooks run with the local record BEFORE memoization — the same
/// borrow shape core uses — so the core `timeoutable_tick_hook` body can
/// sign the user out on expiry; a hook failure leaves the request
/// anonymous instead of resurrecting a timed-out record.
async fn fetch_and_dispatch_request_hooks(
    proxy: &mut AuthProxy,
    finders: &HashMap<String, Arc<dyn ModelFinder>>,
    hooks: &Arc<HookRegistry>,
    mapping: &Mapping,
    request: &AuthRequest,
) {
    let scope = mapping.name.as_str();
    let Some(finder) = finders.get(scope) else {
        return;
    };

    let Some(record) = fetch_session_record(proxy, finder.as_ref(), scope).await else {
        return;
    };

    // Event::Request hooks with the live record: core bodies own the
    // timeout check (skip flags honored through `request.flags`), the
    // live remember-me exemption, and the integer-epoch tick.
    let mut ctx = HookContext {
        proxy: proxy as &mut dyn HookProxy,
        scope,
        event: Event::Request,
        request: Some(request),
        record: Some(record.as_ref()),
    };
    let hook_result = hooks.run_hooks(&mut ctx).await;

    if hook_result.is_ok() {
        // Memoize (Fetch event: no hooks, no session write).
        let opts = SetUserOpts {
            event: SetUserEvent::Fetch,
            store: false,
            run_callbacks: false,
            force: false,
        };
        let _ = proxy.set_user(scope, Some(record), opts).await;
    }
}

/// Non-strict warden fetch over the erased finder.
///
/// Mirrors core `AuthProxy::fetch_from_session` semantics: read the
/// `[key, salt]` payload, load the record, compare salts constant-time; a
/// mismatch DELETES the session key and yields nothing (T-09-02), and a
/// salt-less record fails closed the same way core does.
async fn fetch_session_record(
    proxy: &mut AuthProxy,
    finder: &dyn ModelFinder,
    scope: &str,
) -> Option<Box<dyn AnyDeviseModel>> {
    let session_key = keys::scope_session_key(scope);
    let payload = proxy.session_store().get_value(&session_key).await?;
    let arr = payload.as_array()?;
    if arr.len() < 2 {
        return None;
    }
    let key_str = arr.first()?.as_str()?;
    let stored_salt = arr.get(1)?.as_str()?;
    let key = DeviseKey::from_str(key_str).ok()?;
    let record = finder.get_boxed(&key).await.ok()??;
    let current_salt = record.authenticatable_salt()?;
    if !devise_rust::crypto::secure_compare(&current_salt, stored_salt) {
        proxy.session_store().remove(&session_key).await;
        return None;
    }
    Some(record)
}

/// Render the drained remember-cookie intents onto the response as
/// SIGNED `Set-Cookie` headers (the 09-02 transport).
///
/// `Set` ops carry the core codec value signed with the Devise-derived
/// key (cookie 0.18 `SignedJar`, the session cookie's own lineage) plus
/// the core-rendered hardened attributes; `Clear` ops render signed
/// tombstones. The 5-condition check and the strict integer-epoch parse
/// live in core; this is transport only.
///
/// A `Config` secret too short for derivation skips the ops — unreachable
/// for a correctly wired app, whose session layer already failed closed
/// on the same secret at construction.
fn apply_remember_ops<ResBody>(
    response: &mut Response<ResBody>,
    config: &DeviseConfig,
    ops: &[RememberCookieOp],
) {
    if ops.is_empty() {
        return;
    }
    let Ok(key) = crate::remember::derive_remember_key(config) else {
        return;
    };
    for header in crate::remember::ops_as_set_cookie_headers(&key, ops) {
        if let Ok(value) = HeaderValue::from_str(&header) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
}

/// Signature-verify the resolved scope's inbound remember cookie, swapping
/// the raw value for the verified plaintext when the signature holds.
///
/// A failed verify keeps the raw value: the core rememberable strategy
/// then cannot decode it and reports a stale cookie, which the response
/// pipeline deletes (delete-and-pass-through, never `Failure`).
fn verify_inbound_remember_cookie(
    auth_request: &mut AuthRequest,
    config: &DeviseConfig,
    scope: &str,
) {
    let name = devise_rust::rememberable::remember_cookie_key(scope, config);
    let Some(raw) = auth_request.cookies.get(&name) else {
        return;
    };
    let Ok(key) = crate::remember::derive_remember_key(config) else {
        return;
    };
    if let Some(verified) = crate::remember::verified_cookie_value(&key, &name, raw) {
        auth_request.cookies.insert(name, verified);
    }
}

/// Build the session layer over the D-01 `MemoryStore` default with the
/// security posture the phase contract pins (production default:
/// `Secure` on).
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
    session_manager_layer_with_secure(config, true)
}

/// [`session_manager_layer`] with an explicit `Secure` attribute.
///
/// The ONLY sanctioned opt-out surface for plain-HTTP local development
/// (the browser-parity example runs `secure(false)` behind a loud
/// comment; production apps keep the `session_manager_layer` default).
/// Everything else keeps the phase posture: `SameSite=Lax`, signed
/// cookie over the Devise-derived key, `HttpOnly`.
///
/// # Errors
///
/// Returns [`DeviseError::Config`] when the Devise `secret_key` is empty
/// (key derivation refuses empty secrets).
pub fn session_manager_layer_with_secure(
    config: &DeviseConfig,
    secure: bool,
) -> Result<SessionManagerLayer<MemoryStore, SignedCookie>, DeviseError> {
    let key = crate::callbacks::derive_session_key(&config.secret_key)?;
    Ok(SessionManagerLayer::new(MemoryStore::default())
        .with_same_site(SameSite::Lax)
        .with_http_only(true)
        .with_secure(secure)
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
