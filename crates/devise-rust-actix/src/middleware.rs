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
    session::keys,
};
use serde_json::Value;
use std::str::FromStr;

use actix_session::SessionExt;

/// Shared configuration for the middleware.
#[derive(Clone)]
pub struct DeviseMiddlewareConfig {
    /// Scope registry for mapping paths to scopes.
    pub scope_registry: Arc<ScopeRegistry>,
    /// Devise configuration.
    pub config: Arc<DeviseConfig>,
    /// Per-scope model finders used to resolve session users (08-02).
    pub finders: HashMap<String, Arc<dyn ModelFinder>>,
    /// Hook registry (reserved for hook dispatch in later plans).
    pub hooks: Arc<HookRegistry>,
}

/// A scope the activatable gate rejected this request.
///
/// Devise's `hooks/activatable.rb` runs on every `after_set_user` action,
/// the fetch included: a record that fails `active_for_authentication?` is
/// logged out and the request fails with its `inactive_message`. The
/// middleware stages the rejection here (it owns no hook registry), and the
/// response phase deletes the scope's session key.
#[derive(Clone, Debug)]
pub struct InactiveGate {
    /// Scope whose record the gate rejected.
    pub scope: String,
    /// The record's `inactive_message` stem (`locked` / `unconfirmed`).
    pub message: &'static str,
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
    /// Scope whose session expired this request (Devise `:timeout`), staged
    /// by the synchronous fetch-path timeout pass; extractors render the
    /// Devise timeout failure for it instead of the plain unauthenticated
    /// one.
    pub timed_out: Option<String>,
    /// Scope the activatable fetch gate rejected this request (Devise
    /// `:locked` / `:unconfirmed`), staged by the resolution pass;
    /// extractors render the matching Devise failure key for it instead of
    /// the plain unauthenticated one.
    pub inactive: Option<InactiveGate>,
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
    ///
    /// # Panics
    ///
    /// Panics when `config.validate()` fails — Devise's
    /// `raise_no_secret_key` boot contract (`routes.rb:228`): an empty
    /// `secret_key` makes every HMAC token digest forgeable, so the
    /// middleware refuses to construct (a Rust panic at boot time is the
    /// port's `raise`).
    #[must_use]
    pub fn new(scope_registry: Arc<ScopeRegistry>, config: Arc<DeviseConfig>) -> Self {
        if let Err(error) = config.validate() {
            panic!("{error}");
        }
        Self {
            config: DeviseMiddlewareConfig {
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
        let auth_request = build_auth_request(&req, scope.as_deref());
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
        // Timeoutable parity for the actix fetch path (Devise
        // `hooks/timeoutable.rb`). The axum layer dispatches the same core
        // rule through the async hook registry over a live tower store; the
        // actix `Session` is `!Send` (D-04: read once, drop before any
        // await), so the decision runs HERE, synchronously, over the live
        // handle. Core owns the rule (`check_timeout`); this pass is only
        // the session I/O: tick on Live, or drop the expired scope's payload
        // so the request resolves anonymous and the remember arm below
        // provides Devise's remember-me exemption.
        let mut timed_out: Option<String> = None;
        if let Some(scope_name) = scope.as_deref() {
            if payloads.contains_key(scope_name) {
                let flags = &auth_request_for_resolution.flags;
                let stored = crate::bridge::read_last_request_at_value(&session, scope_name);
                match devise_rust::timeoutable::check_timeout(
                    stored.as_ref(),
                    flags,
                    config.config.timeout_in,
                    &devise_rust::time::SystemClock,
                ) {
                    devise_rust::timeoutable::TimeoutDecision::Live => {
                        if !flags.skip_trackable {
                            crate::bridge::tick_last_request_at(
                                &session,
                                scope_name,
                                &devise_rust::time::SystemClock,
                            );
                        }
                    }
                    devise_rust::timeoutable::TimeoutDecision::Expired => {
                        payloads.remove(scope_name);
                        timed_out = Some(scope_name.to_string());
                    }
                    devise_rust::timeoutable::TimeoutDecision::Skipped => {}
                }
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
            timed_out,
            inactive: None,
        }));
        req.extensions_mut().insert(auth_request);
        req.extensions_mut().insert(handle.clone());

        let remember_clears: RememberClearHandle = Arc::new(std::sync::Mutex::new(Vec::new()));
        req.extensions_mut().insert(remember_clears.clone());

        let fut = self.service.call(req);
        Box::pin(async move {
            // Record resolution: adapter `.await`s happen here with no
            // `Session` handle alive (owned-extract, D-04).
            let (users, inactive) = resolve_users(&config, &payloads).await;
            // Remember-me arm (CONCERNS #7 / RMB parity): when the session
            // holds no user for the scope, the strategy chain's rememberable
            // arm runs over the signature-verified cookie, so a
            // remember-only request authenticates in actix like axum does.
            // Stale cookies are tombstoned on the response below.
            let (users, clears, remember_inactive) = resolve_remember_users(
                &config,
                scope.as_deref(),
                users,
                &auth_request_for_resolution,
            )
            .await;
            let mut inactive = inactive;
            inactive.extend(remember_inactive);
            if let Ok(mut guard) = remember_clears.lock() {
                *guard = clears;
            }
            if let Ok(mut guard) = handle.lock() {
                guard.users = users;
                // The request scope's gate wins so the extractor reads it.
                guard.inactive = inactive
                    .iter()
                    .find(|gate| Some(gate.scope.as_str()) == scope.as_deref())
                    .or_else(|| inactive.first())
                    .cloned();
            }
            let response = fut.await;
            match response {
                // Devise `warden.logout(scope)` in `hooks/activatable.rb`:
                // the rejected record's session key dies on the request that
                // rejected it, so an unlocked account cannot resurrect it
                // (T-261026-ghb-02). `Session::remove` is synchronous over
                // the Rc-backed handle, so no await crosses it.
                Ok(service_response) => Ok(drain_inactive_session_keys(
                    drain_remember_clears(
                        service_response,
                        &remember_clears,
                        &config.config,
                        &devise_rust::time::SystemClock,
                    ),
                    &inactive,
                )),
                Err(err) => Err(err),
            }
        })
    }
}

/// Delete the scope session key of every gated scope (Devise
/// `warden.logout(scope)`, `hooks/activatable.rb`).
///
/// actix-session's [`SessionExt::get_session`] on a `ServiceResponse`
/// delegates to the request's Rc-backed handle, and [`Session::remove`] is
/// synchronous, so the response-phase deletion never crosses an `await`.
fn drain_inactive_session_keys<B>(
    response: actix_web::dev::ServiceResponse<B>,
    gates: &[InactiveGate],
) -> actix_web::dev::ServiceResponse<B> {
    if gates.is_empty() {
        return response;
    }
    // The request-side handle reaches the same Rc-backed session the
    // `ServiceResponse` impl would (and is generic over the body type).
    let session = response.request().get_session();
    for gate in gates {
        session.remove(&keys::scope_session_key(&gate.scope));
    }
    response
}

/// Staged remember-cookie tombstones for the response phase (the strategy
/// chain's `ClearCookieAndPass` outcomes in actix).
///
/// Each entry is `(scope, cookie name)`: the scope is required to derive the
/// tombstone's `path`/`domain`/`secure` attributes, because a browser only
/// drops a cookie whose name **and** path **and** domain all match (S9).
pub type RememberClearHandle = Arc<std::sync::Mutex<Vec<(String, String)>>>;

/// Apply the staged remember-cookie tombstones to the response
/// (`ClearCookieAndPass` → `cookies.delete`, Devise jar semantics).
fn drain_remember_clears<B>(
    mut response: actix_web::dev::ServiceResponse<B>,
    clears: &RememberClearHandle,
    config: &DeviseConfig,
    clock: &dyn devise_rust::time::Clock,
) -> actix_web::dev::ServiceResponse<B> {
    let Ok(guard) = clears.lock() else {
        return response;
    };
    let staged: Vec<(String, String)> = guard.clone();
    drop(guard);
    for (scope, name) in staged {
        let attrs =
            devise_rust::rememberable::RememberableCookieAttrs::for_scope(&scope, config, clock);
        let _ = response
            .response_mut()
            .add_removal_cookie(&crate::remember::removal_cookie(&name, &attrs));
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
///
/// The activatable gate closes the arm (T-261026-ghb-01): a remember success
/// bypasses `set_user`, so the hook registry never sees it. An inactive
/// record is therefore NOT inserted into `users` and is returned as a
/// staged [`InactiveGate`] for the request scope instead. There is no
/// session key to delete here, and the remember cookie itself is left alone,
/// matching Devise's failure app which does not clear it.
async fn resolve_remember_users(
    config: &DeviseMiddlewareConfig,
    scope: Option<&str>,
    mut users: HashMap<String, Arc<dyn AnyDeviseModel>>,
    request: &AuthRequest,
) -> (
    HashMap<String, Arc<dyn AnyDeviseModel>>,
    Vec<(String, String)>,
    Vec<InactiveGate>,
) {
    let mut clears: Vec<(String, String)> = Vec::new();
    let mut inactive: Vec<InactiveGate> = Vec::new();
    let Ok(jar_key) = crate::remember::derive_remember_key(&config.config) else {
        return (users, clears, inactive);
    };
    let Some(scope) = scope else {
        return (users, clears, inactive);
    };
    if users.contains_key(scope) {
        return (users, clears, inactive);
    }
    let Some(finder) = config.finders.get(scope) else {
        return (users, clears, inactive);
    };
    let Some(mapping) = config.scope_registry.get(scope) else {
        return (users, clears, inactive);
    };
    if !mapping.has_module(devise_rust::scope::Module::Rememberable) {
        return (users, clears, inactive);
    }
    let cookie_name = devise_rust::rememberable::remember_cookie_key(scope, &config.config);
    let Some(staged) = request.cookies.get(&cookie_name).cloned() else {
        return (users, clears, inactive);
    };
    let staged_scope = scope.to_string();
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
                    // Activatable gate on the remember arm: the record joined
                    // the request without `set_user`, so the hooks never ran
                    // (T-261026-ghb-01). No session key exists to delete on
                    // this arm; the cookie is left for Devise's failure app.
                    if let Some(gate) = record.as_activatable() {
                        if !gate.active_for_authentication() {
                            inactive.push(InactiveGate {
                                scope: staged_scope.clone(),
                                message: gate.inactive_message(),
                            });
                            break;
                        }
                    }
                    users.insert(scope.to_string(), Arc::from(record));
                }
                Ok(devise_rust::failure::AuthOutcome::ClearCookieAndPass { cookie_key }) => {
                    clears.push((staged_scope.clone(), cookie_key));
                }
                _ => {}
            }
            break;
        }
    }
    (users, clears, inactive)
}

/// Resolve session users for every scope that has a payload and a
/// registered finder, validating the stored salt (warden fetch semantics).
///
/// Salt mismatches fail closed to "no user"; the session-key deletion side
/// effect remains the bridge's job on its next synchronous fetch.
///
/// Every resolved record is then run through the activatable gate
/// (`hooks/activatable.rb`, which validates the user activity on each
/// request): a record failing `active_for_authentication?` is NOT inserted
/// into `users`, and is returned as a staged [`InactiveGate`] instead. Core
/// owns the rule through the object-safe `Activatable` view; this pass only
/// performs the session I/O and the staging, mirroring the timeout pass's
/// split. The response phase deletes the gated scope's session key.
async fn resolve_users(
    config: &DeviseMiddlewareConfig,
    payloads: &HashMap<String, Value>,
) -> (HashMap<String, Arc<dyn AnyDeviseModel>>, Vec<InactiveGate>) {
    let mut users = HashMap::new();
    let mut inactive: Vec<InactiveGate> = Vec::new();
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
        // S6: models without an `encrypted_password` (omniauth-only rows)
        // have NO salt — the serializer writes "" and the fetch must compare
        // "" against "" the same way, or every such session dies on every
        // request. The writer (`session_pair`) already defaults to "".
        let current_salt = record.authenticatable_salt().unwrap_or_default();
        if !devise_rust::crypto::secure_compare(&current_salt, stored_salt) {
            continue;
        }
        // Activatable gate on the fetch (T-261026-ghb-01).
        if let Some(gate) = record.as_activatable() {
            if !gate.active_for_authentication() {
                inactive.push(InactiveGate {
                    scope: scope.clone(),
                    message: gate.inactive_message(),
                });
                continue;
            }
        }
        users.insert(scope.clone(), Arc::from(record));
    }
    (users, inactive)
}

/// Build an owned [`AuthRequest`] snapshot of an actix request.
fn build_auth_request(req: &ServiceRequest, scope: Option<&str>) -> AuthRequest {
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
        // Devise `allow_params_authentication!` (sessions_controller.rb:5)
        // enables the params strategy ONLY inside sessions#create — the
        // warden env flag starts false on every request (S4). Enabling it
        // from `config.params_authenticatable` here would let ANY guarded
        // route authenticate `?user_email=…&user_password=…` query
        // credentials (credentials in URLs/logs). The controller sets the
        // flag on this staged snapshot when it runs its sign-in pass.
        allow_params_authentication: false,
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
