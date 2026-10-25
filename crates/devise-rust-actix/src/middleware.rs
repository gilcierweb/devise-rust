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
    adapter::DeviseKey,
    config::DeviseConfig,
    failure::AnyDeviseModel,
    hooks::HookRegistry,
    model::ModelFinder,
    request::{AuthRequest, HttpMethod, RequestFlags},
    scope::{Mapping, ScopeRegistry},
    session::{SessionStore, keys},
};
use serde_json::Value;
use std::str::FromStr;

use actix_session::SessionExt;

/// Shared configuration for the middleware.
#[derive(Clone)]
pub struct DeviseMiddlewareConfig {
    /// Session store implementation (`ActixSessionStore`).
    pub session_store: Arc<dyn SessionStore>,
    /// Scope registry for mapping paths to scopes.
    pub scope_registry: Arc<ScopeRegistry>,
    /// Devise configuration.
    pub config: Arc<DeviseConfig>,
    /// Per-scope model finders used to resolve session users (08-02).
    pub finders: HashMap<String, Arc<dyn ModelFinder>>,
    /// Hook registry (reserved for hook dispatch in later plans).
    pub hooks: Arc<HookRegistry>,
}

/// Per-request resolved authentication state staged in request extensions.
///
/// The middleware fills this **before** the inner service is polled:
/// `AuthRequest` construction and the session-payload snapshot are
/// synchronous, record resolution happens while the handler future is
/// created but unpolled. Extractors read the staged values and never touch
/// `actix_session::Session` (D-04 / ACTIX-02 prohibition).
#[derive(Clone, Default)]
pub struct ResolvedAuth {
    /// Longest-prefix scope resolved from the request path (`find_by_path`).
    pub scope: Option<String>,
    /// Mapping for the resolved scope, if any.
    pub mapping: Option<Mapping>,
    /// Records resolved from session payloads, keyed by scope.
    pub users: HashMap<String, Arc<dyn AnyDeviseModel>>,
    /// Session payloads `[key, salt]` per scope (for `<scope>_session`).
    pub payloads: HashMap<String, Value>,
    /// Devise configuration shared with the failure renderer path.
    pub config: Option<Arc<DeviseConfig>>,
}

/// Handle staged in request extensions: `Arc<Mutex<_>>` so the middleware
/// future stays `Send` (the guard is taken and released synchronously,
/// never held across an `await`). Extractors lock briefly and clone the
/// snapshot; the `Send` contract of handler futures is preserved.
pub type ResolvedAuthHandle = Arc<std::sync::Mutex<ResolvedAuth>>;

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
                finders: HashMap::new(),
                hooks: Arc::new(HookRegistry::new()),
            },
        }
    }

    /// Register a per-scope model finder (used to resolve session users).
    #[must_use]
    pub fn with_finder(mut self, scope: &str, finder: Arc<dyn ModelFinder>) -> Self {
        self.config.finders.insert(scope.to_string(), finder);
        self
    }

    /// Override the hook registry used for future hook dispatch.
    #[must_use]
    pub fn with_hooks(mut self, hooks: Arc<HookRegistry>) -> Self {
        self.config.hooks = hooks;
        self
    }
}

impl<S, B> Transform<S, ServiceRequest> for DeviseMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
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
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

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
        let auth_request_for_resolution = auth_request.clone();

        // Session payload snapshot (synchronous, D-04): the `Session` handle
        // is read and dropped BEFORE any `.await`. Resolution of boxed
        // records happens inside the service future (below), where no
        // `Session` handle is alive.
        let session = req.get_session();
        let mut payloads = HashMap::new();
        for finder_scope in config.finders.keys() {
            let session_key = keys::scope_session_key(finder_scope);
            if let Some(value) = session.get::<Value>(&session_key).ok().flatten() {
                payloads.insert(finder_scope.clone(), value);
            }
        }
        drop(session);

        // Attach the AuthRequest and the shared resolved-auth handle. The
        // handle is filled inside the future below BEFORE the inner service
        // future is polled (actix services do not start work until poll),
        // so handlers and extractors observe the resolved state.
        let handle: ResolvedAuthHandle = Arc::new(std::sync::Mutex::new(ResolvedAuth {
            scope: scope.clone(),
            mapping: scope
                .as_deref()
                .and_then(|s| config.scope_registry.get(s).cloned()),
            users: HashMap::new(),
            payloads: payloads.clone(),
            config: Some(config.config.clone()),
        }));
        req.extensions_mut().insert(auth_request);
        req.extensions_mut().insert(handle.clone());

        let remember_clears: RememberClearHandle = Arc::new(std::sync::Mutex::new(Vec::new()));
        req.extensions_mut().insert(remember_clears.clone());

        let fut = self.service.call(req);
        Box::pin(async move {
            // Record resolution: adapter `.await`s happen here with no
            // `Session` handle alive (owned-extract, D-04).
            let users = resolve_users(&config, &payloads).await;
            // Remember-me arm (CONCERNS #7 / RMB parity): when the session
            // holds no user for the scope, the strategy chain's rememberable
            // arm runs over the signature-verified cookie, so a
            // remember-only request authenticates in actix like axum does.
            // Stale cookies are tombstoned on the response below.
            let (users, clears) = resolve_remember_users(
                &config,
                scope.as_deref(),
                users,
                &auth_request_for_resolution,
            )
            .await;
            if let Ok(mut guard) = remember_clears.lock() {
                *guard = clears;
            }
            if let Ok(mut guard) = handle.lock() {
                guard.users = users;
            }
            let response = fut.await;
            match response {
                Ok(service_response) => {
                    Ok(drain_remember_clears(service_response, &remember_clears))
                }
                Err(err) => Err(err),
            }
        })
    }
}

/// Staged remember-cookie tombstones for the response phase (the strategy
/// chain's `ClearCookieAndPass` outcomes in actix).
pub type RememberClearHandle = Arc<std::sync::Mutex<Vec<String>>>;

/// Apply the staged remember-cookie tombstones to the response
/// (`ClearCookieAndPass` → `cookies.delete`, Devise jar semantics).
fn drain_remember_clears<B>(
    mut response: actix_web::dev::ServiceResponse<B>,
    clears: &RememberClearHandle,
) -> actix_web::dev::ServiceResponse<B> {
    let Ok(guard) = clears.lock() else {
        return response;
    };
    let names: Vec<String> = guard.clone();
    drop(guard);
    for name in names {
        let _ = response
            .response_mut()
            .add_removal_cookie(&crate::remember::removal_cookie(&name));
    }
    response
}

/// Remember-me arm of the resolution (CONCERNS #7 / RMB-04).
///
/// For every scope that has NO session-resolved user but a registered
/// finder, a rememberable mapping, and a staged (signature-verified)
/// remember cookie, the core strategy chain runs and:
///
/// - on success, the record joins the resolved users (the 5-condition
///   check in `rememberable.rs` owns validity);
/// - on `ClearCookieAndPass`, the cookie name is returned so the response
///   phase tombstones it (Devise `cookies.delete`, never a Failure).
///
/// Signature verification happens here (the staged snapshot carries the
/// raw signed cookie); the core strategy sees only the plaintext triple,
/// exactly like the axum layer's inbound path.
async fn resolve_remember_users(
    config: &DeviseMiddlewareConfig,
    scope: Option<&str>,
    mut users: HashMap<String, Arc<dyn AnyDeviseModel>>,
    request: &AuthRequest,
) -> (HashMap<String, Arc<dyn AnyDeviseModel>>, Vec<String>) {
    let mut clears: Vec<String> = Vec::new();
    let Ok(jar_key) = crate::remember::derive_remember_key(&config.config) else {
        return (users, clears);
    };
    let Some(scope) = scope else {
        return (users, clears);
    };
    if users.contains_key(scope) {
        return (users, clears);
    }
    let Some(finder) = config.finders.get(scope) else {
        return (users, clears);
    };
    let Some(mapping) = config.scope_registry.get(scope) else {
        return (users, clears);
    };
    if !mapping.has_module(devise_rust::scope::Module::Rememberable) {
        return (users, clears);
    }
    let cookie_name = devise_rust::rememberable::remember_cookie_key(scope, &config.config);
    let Some(staged) = request.cookies.get(&cookie_name).cloned() else {
        return (users, clears);
    };
    // Signature-verified plaintext; a failed verify keeps the raw value,
    // which the core strategy classifies as stale (delete + pass through).
    let plaintext =
        crate::remember::verified_cookie_value(&jar_key, &cookie_name, &staged).unwrap_or(staged);
    let mut verified_request = request.clone();
    verified_request
        .cookies
        .insert(cookie_name.clone(), plaintext);

    let strategies = devise_rust::strategy::strategies_for(mapping, &config.config);
    for strategy in &strategies {
        if strategy.no_input() {
            match strategy
                .authenticate(&verified_request, mapping, finder.as_ref(), &config.config)
                .await
            {
                Ok(devise_rust::failure::AuthOutcome::Success(record)) => {
                    users.insert(scope.to_string(), Arc::from(record));
                }
                Ok(devise_rust::failure::AuthOutcome::ClearCookieAndPass { cookie_key }) => {
                    clears.push(cookie_key);
                }
                _ => {}
            }
            break;
        }
    }
    (users, clears)
}

/// Resolve session users for every scope that has a payload and a
/// registered finder, validating the stored salt (warden fetch semantics).
///
/// Salt mismatches fail closed to "no user"; the session-key deletion side
/// effect remains the bridge's job on its next synchronous fetch.
async fn resolve_users(
    config: &DeviseMiddlewareConfig,
    payloads: &HashMap<String, Value>,
) -> HashMap<String, Arc<dyn AnyDeviseModel>> {
    let mut users = HashMap::new();
    for (scope, value) in payloads {
        let Some(finder) = config.finders.get(scope) else {
            continue;
        };
        let Some(arr) = value.as_array() else {
            continue;
        };
        let (Some(key_str), Some(stored_salt)) = (
            arr.first().and_then(Value::as_str),
            arr.get(1).and_then(Value::as_str),
        ) else {
            continue;
        };
        let Ok(key) = DeviseKey::from_str(key_str) else {
            continue;
        };
        let Ok(Some(record)) = finder.get_boxed(&key).await else {
            continue;
        };
        let Some(current_salt) = record.authenticatable_salt() else {
            continue;
        };
        if !devise_rust::crypto::secure_compare(&current_salt, stored_salt) {
            continue;
        }
        users.insert(scope.clone(), Arc::from(record));
    }
    users
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
    // any proxy-supplied header.
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
