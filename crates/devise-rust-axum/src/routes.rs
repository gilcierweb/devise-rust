//! Route registration — the `devise_for`-equivalent router fn (D-03)
//! translating core [`RouteSpec`] data
//! into an axum `Router`, plus the five controller groups (sessions,
//! registrations, passwords, confirmations, unlocks) per D-14, and the
//! 09-01 tracer session routes.
//!
//! ## Ordering / filtering (D-03 / D-13)
//!
//! [`devise_for_router`] iterates [`Mapping::route_specs`] verbatim —
//! `only` / `skip` / `path_names` / `sign_out_via` are all already baked
//! into the core table and are NEVER re-filtered here (the single
//! dispatch-time gate mirrors Devise's `routes.rb` unlock guard: unlock
//! routes vanish when the configured unlock strategy excludes `email`).
//! PATCH and PUT both reach the update handlers; sign-out honors
//! `sign_out_via` (DELETE default); axum 0.8 `{param}` captures pass
//! through untouched because core specs already emit them.
//!
//! ## Session writes (D-04)
//!
//! Handlers run the proxy for hooks and memoization and hand every
//! physical session write to the cycle-before-write bridge helpers.
//! Failed cycles fail the transition (500), never a fake success.
//!
//! ## Response split (D-15)
//!
//! Navigational (HTML-accepting) requests get Devise's 302 + flash cookie
//! semantics; JSON callers get status codes (`200`/`201`/`204`/`401`) plus
//! the configured [`DeviseConfig::error_status`] (200 by default) on the
//! validation-failure renders, with symbolic error keys unchanged in the
//! body (en.yml symbols, never values).

#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::too_many_lines)]

use std::collections::{BTreeMap, HashMap};
use std::convert::Infallible;
use std::str::FromStr;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Extension, Form, FromRequest, Query, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, delete, post};
use devise_rust::adapter::{Conditions, DeviseKey, OrmAdapter, Value as AdapterValue};
use devise_rust::config::DeviseConfig;
use devise_rust::confirmable::Confirmable;
use devise_rust::error::{DeviseError, ValidationErrors, errors_json};
use devise_rust::failure::{
    AnyDeviseModel, FailureReason, FailureRenderer, build_failure, flash_keys,
    is_navigational_format, successfully_sent_key,
};
use devise_rust::helpers::after_sign_in_path_for;
use devise_rust::hooks::HookProxy;
use devise_rust::lockable::{self, LockAttemptOutcome, Lockable};
use devise_rust::mailer::Mailer;
use devise_rust::model::{ModelFinder, Recoverable, Registerable, Validatable};
use devise_rust::proxy::{SetUserEvent, SetUserOpts};
use devise_rust::rememberable::{Rememberable, remember_cookie_key};
use devise_rust::request::AuthRequest;
use devise_rust::scope::{Mapping, RouteSpec, ScopeRegistry};
use devise_rust::time::Clock;
use serde_json::{Map, Value as JsonValue};
use tower_sessions::Session;

use crate::bridge;
use crate::callbacks::rotate_csrf_token;
use crate::failure::AxumFailureRenderer;
use crate::layer::AuthProxyHandle;

/// Shared state for the devise route handlers.
///
/// `mapping` carries the route paths and scope name; `finders` backs the
/// credential lookup and the proxy registration done by
/// [`DeviseLayer`](crate::layer::DeviseLayer).
#[derive(Clone)]
pub struct DeviseRouterState {
    /// Devise configuration (stretches drive password checks).
    pub config: Arc<DeviseConfig>,
    /// The scope mapping these routes serve.
    pub mapping: Mapping,
    /// Per-scope model finders.
    pub finders: HashMap<String, Arc<dyn ModelFinder>>,
}

/// Register the tracer session routes for one mapping: `POST {sign_in}`
/// and `DELETE {sign_out}` at the mapping's paths.
///
/// The 09-01 tracer slice, kept for the bridge suite; the full table
/// lives in [`devise_for_router`] (D-03).
///
/// ## Examples
///
/// ```rust,ignore
/// let router = sessions_router(DeviseRouterState {
///     config,
///     mapping,
///     finders,
/// });
/// let app = Router::new().merge(router);
/// ```
pub fn sessions_router(state: DeviseRouterState) -> Router {
    let sign_in = state.mapping.sign_in_path();
    let sign_out = state.mapping.sign_out_path();
    Router::new()
        .route(&sign_in, post(tracer_sessions_create))
        .route(&sign_out, delete(tracer_sessions_destroy))
        .with_state(state)
}

/// `SessionsController#create`: authenticate the params, sign the user in
/// through the proxy, then persist with cycle-before-insert.
async fn tracer_sessions_create(
    State(st): State<DeviseRouterState>,
    Extension(session): Extension<Session>,
    Extension(handle): Extension<AuthProxyHandle>,
    Extension(mut auth_request): Extension<AuthRequest>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let scope = st.mapping.name.clone();
    let email = form.get("user_email").cloned().unwrap_or_default();
    let password = form.get("user_password").cloned().unwrap_or_default();

    // Devise `allow_params_authentication!` (sessions_controller.rb:5):
    // sessions#create is the ONLY params-auth action (S4).
    auth_request.flags.allow_params_authentication = st.config.params_authenticatable;

    let Some(finder) = st.finders.get(&scope) else {
        return internal_error();
    };
    let mut conditions = Conditions::new();
    conditions.insert("email", email);
    let Ok(found) = finder.find_first_boxed(&conditions).await else {
        return internal_error();
    };

    let Some(user) = found else {
        return invalid_credentials(&auth_request, &st);
    };

    // DatabaseAuthenticatable password check through the object-safe
    // facet (paranoid dummy-hash timing parity lives in core strategies).
    let password_ok = user
        .as_password_verifiable()
        .is_some_and(|verifiable| verifiable.valid_password(&password, &st.config));
    if !password_ok {
        return invalid_credentials(&auth_request, &st);
    }
    // DBAU-07: fire `after_database_authentication` right after the
    // successful password check, exactly where Devise's strategy does.
    user.after_database_authentication();

    let (key, salt) = user.session_pair();

    // Sign in through AuthProxy set_user: Authentication hooks +
    // memoization + expire_devise_keys. `store: false` — the physical
    // write belongs to the cycle-before-insert bridge helper below.
    let mut proxy = handle.lock().await;
    let opts = SetUserOpts {
        event: SetUserEvent::Authentication,
        store: false,
        run_callbacks: true,
        force: false,
    };
    if proxy.set_user(&scope, Some(user), opts).await.is_err() {
        drop(proxy);
        return internal_error();
    }
    let target = after_sign_in_path_for(&scope, &proxy, &auth_request).await;
    drop(proxy);

    // D-04: cycle BEFORE the insert; a failed cycle fails the sign-in.
    if bridge::insert_session_and_renew(&session, &scope, &key, &salt)
        .await
        .is_err()
    {
        return internal_error();
    }
    // D-07: rotate the app-owned CSRF token on the transition.
    rotate_csrf_token(&session, &scope, &st.config).await;

    if is_navigational_format(&auth_request, &st.config) {
        flash_redirect(&st.config, &target, "signed_in")
    } else {
        axum::Json(serde_json::json!({ "signed_in": true })).into_response()
    }
}

/// `SessionsController#destroy`: logout hooks + warden key removal through
/// the proxy, then rotate the id on the sign-out path.
async fn tracer_sessions_destroy(
    State(st): State<DeviseRouterState>,
    Extension(session): Extension<Session>,
    Extension(handle): Extension<AuthProxyHandle>,
    Extension(auth_request): Extension<AuthRequest>,
) -> Response {
    let scope = st.mapping.name.clone();

    // Warden logout: before_logout hooks + session key removal + memo clear.
    {
        let mut proxy = handle.lock().await;
        proxy.sign_out(&scope).await;
    }

    // D-04: rotate on the sign-out transition; failure fails the response.
    if bridge::sign_out_and_renew(&session, &scope).await.is_err() {
        return internal_error();
    }
    // D-07: rotate the app-owned CSRF token on the transition.
    rotate_csrf_token(&session, &scope, &st.config).await;

    if is_navigational_format(&auth_request, &st.config) {
        flash_redirect(&st.config, "/", "signed_out")
    } else {
        StatusCode::NO_CONTENT.into_response()
    }
}

/// Invalid credentials: the core failure decision for `FailureReason::Invalid`,
/// rendered through the shared renderer (302 + flash for navigational
/// requests, 401 otherwise).
fn invalid_credentials(auth_request: &AuthRequest, st: &DeviseRouterState) -> Response {
    let failure = build_failure(
        auth_request,
        &st.mapping,
        &st.config,
        FailureReason::Invalid,
    );
    AxumFailureRenderer::for_config(&st.config).render(&failure, &st.mapping)
}

/// 302 + the SIGNED devise flash cookie carrying the bare I18n key
/// (actix `flash_redirect` parity; the one flash helper every controller
/// and the omniauth renderer share — M-flash: one format everywhere).
pub(crate) fn flash_redirect(config: &DeviseConfig, target: &str, flash_key: &str) -> Response {
    let mut response = StatusCode::FOUND.into_response();
    let location = HeaderValue::from_str(target).unwrap_or_else(|_| HeaderValue::from_static("/"));
    response.headers_mut().insert(header::LOCATION, location);
    if let Ok(key) = crate::remember::derive_remember_key(config) {
        if let Some(flash) = crate::failure::flash_cookie_header(&key, flash_key) {
            response.headers_mut().append(header::SET_COOKIE, flash);
        }
    }
    response
}

fn internal_error() -> Response {
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

// ============================================================================
// The full devise_for-equivalent router (D-03 / D-14) — typed state over
// one concrete model, adapter, and mailer per mapping, mirroring the actix
// crate's DeviseWebState shape so one doc page serves both frameworks.
// ============================================================================

/// The full model trait bundle the controller matrix needs (D-14).
///
/// Implemented once per concrete application model; the blanket impl keeps
/// call sites terse.
pub trait FullDeviseModel:
    Registerable
    + Recoverable
    + Validatable
    + Confirmable
    + Lockable
    + Rememberable
    + devise_rust::trackable::Trackable
    + Default
    + Clone
    + Send
    + Sync
    + 'static
{
}

impl<T> FullDeviseModel for T where
    T: Registerable
        + Recoverable
        + Validatable
        + Confirmable
        + Lockable
        + Rememberable
        + devise_rust::trackable::Trackable
        + Default
        + Clone
        + Send
        + Sync
        + 'static
{
}

/// Shared application state for one `devise_for_router` mount.
pub struct DeviseWebState<M, A, L> {
    /// Route mapping the mount was built from.
    pub mapping: Mapping,
    /// The FULL scope registry behind the middleware run (S2): sign-out-all
    /// and `verify_signed_out_user` iterate every registered scope, like
    /// Devise iterates `Devise.mappings.keys` — never only this mapping.
    pub registry: Arc<ScopeRegistry>,
    /// Devise configuration (shared `Arc` with the layer).
    pub config: Arc<DeviseConfig>,
    /// ORM adapter for the scope's model.
    pub adapter: Arc<A>,
    /// Mailer for confirmation/reset/unlock instructions.
    pub mailer: Arc<L>,
    /// Clock for windows/ticks.
    pub clock: Arc<dyn Clock>,
    /// Phantom marker: `M` pins the controller monomorphizations.
    pub marker: std::marker::PhantomData<fn() -> M>,
}

// Manual Clone: `A` and `L` sit behind `Arc`s, so the state clones
// regardless of whether the adapter or mailer types are themselves `Clone`
// (the derive would impose bounds the generic contract never needs).
impl<M, A, L> Clone for DeviseWebState<M, A, L> {
    fn clone(&self) -> Self {
        Self {
            mapping: self.mapping.clone(),
            registry: self.registry.clone(),
            config: self.config.clone(),
            adapter: self.adapter.clone(),
            mailer: self.mailer.clone(),
            clock: self.clock.clone(),
            marker: std::marker::PhantomData,
        }
    }
}

impl<M, A, L> DeviseWebState<M, A, L> {
    /// Build the state for one mapping.
    ///
    /// # Errors
    ///
    /// Returns [`DeviseError::Config`] when the Devise `secret_key` is
    /// missing (the core [`DeviseConfig::validate`] boot contract) or too
    /// short for the cookie-jar derivation.
    pub fn new(
        mapping: Mapping,
        registry: Arc<ScopeRegistry>,
        config: Arc<DeviseConfig>,
        adapter: Arc<A>,
        mailer: Arc<L>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, DeviseError> {
        // Fail closed on unusable secrets here so a misconfigured app never
        // boots: every token HMAC and remember-cookie write would silently
        // skip otherwise (Devise's `raise_no_secret_key`).
        config.validate()?;
        crate::remember::derive_remember_key(&config)?;
        Ok(Self {
            mapping,
            registry,
            config,
            adapter,
            mailer,
            clock,
            marker: std::marker::PhantomData,
        })
    }
}

/// Translate a core [`RouteSpec`] table out of a [`Mapping`].
#[must_use]
pub fn route_specs_for_mapping(mapping: &Mapping) -> Vec<RouteSpec> {
    mapping.route_specs()
}

/// Register the mapping's full Devise route table as an axum `Router`
/// (D-03: plain config fn returning a `Router`, merged via
/// `Router::merge`).
///
/// The route table is the core `RouteSpec` data with `only`/`skip`/
/// `path_names`/`sign_out_via` already honored — never re-filtered here
/// beyond Devise's own unlock-strategy guard. Both PATCH and PUT reach
/// the update handlers; `sign_out_via` picks the sign-out method.
///
/// ## Examples
///
/// ```rust,ignore
/// let router = devise_for_router(state);
/// let app = Router::new().merge(router);
/// ```
pub fn devise_for_router<M, A, L>(state: DeviseWebState<M, A, L>) -> Router
where
    M: FullDeviseModel,
    A: OrmAdapter<M, New = M> + Send + Sync + 'static,
    L: Mailer<M> + 'static,
{
    // Group specs by path so multi-method resources (PATCH+PUT updates,
    // GET+POST sign-in, the registration root verbs) share one route.
    let mut by_path: BTreeMap<String, Vec<RouteSpec>> = BTreeMap::new();
    for spec in state.mapping.route_specs() {
        // Omniauth legs mount through [`crate::omniauth::omniauth_router`]
        // (the omniauthable seam is a per-mount opt-in over the SAME
        // shared spec data); claiming the paths here would collide with
        // that mount.
        if spec.name.contains("omniauth") {
            continue;
        }
        if spec.name.contains("unlock")
            && !lockable::unlock_strategy_enabled_for("email", &state.config)
        {
            continue;
        }
        by_path.entry(spec.path.clone()).or_default().push(spec);
    }

    let mut router = Router::new();
    for (path, specs) in by_path {
        let mut method_router = MethodRouter::new();
        for spec in specs {
            method_router = attach_spec::<M, A, L>(method_router, &spec);
        }
        router = router.route(&path, method_router);
    }
    router.with_state(state)
}

/// Controller family a spec belongs to, from Devise's route-name stems.
fn spec_family(spec: &RouteSpec) -> &'static str {
    if spec.name.contains("session") {
        "session"
    } else if spec.name.contains("password") {
        "password"
    } else if spec.name.contains("confirmation") {
        "confirmation"
    } else if spec.name.contains("unlock") {
        "unlock"
    } else {
        "registration"
    }
}

/// Attach one spec's handler to the method router.
fn attach_spec<M, A, L>(
    mr: MethodRouter<DeviseWebState<M, A, L>>,
    spec: &RouteSpec,
) -> MethodRouter<DeviseWebState<M, A, L>>
where
    M: FullDeviseModel,
    A: OrmAdapter<M, New = M> + Send + Sync + 'static,
    L: Mailer<M> + 'static,
{
    let family = spec_family(spec);
    let action = spec.action.as_str();
    match spec.method.as_str() {
        "GET" => attach_get::<M, A, L>(mr, family, action),
        "POST" => attach_post::<M, A, L>(mr, family, action),
        // PATCH and PUT are SEPARATE specs for the same update handler:
        // each iteration attaches its own verb (D-13).
        "PATCH" => attach_patch::<M, A, L>(mr, family, action),
        "PUT" => attach_put::<M, A, L>(mr, family, action),
        // DELETE (sign_out_via default) and any other method: the
        // destroy-shaped verbs.
        _ => attach_delete::<M, A, L>(mr, family, action),
    }
}

fn attach_get<M, A, L>(
    mr: MethodRouter<DeviseWebState<M, A, L>>,
    family: &str,
    action: &str,
) -> MethodRouter<DeviseWebState<M, A, L>>
where
    M: FullDeviseModel,
    A: OrmAdapter<M> + Send + Sync + 'static,
    L: Mailer<M> + 'static,
{
    match (family, action) {
        ("registration", "new") => mr.get(registrations_new::<M, A, L>),
        (_, "new") => mr.get(new_handler::<M, A, L>),
        ("password", "edit") => mr.get(passwords_edit::<M, A, L>),
        ("registration", "edit") => mr.get(registrations_edit::<M, A, L>),
        ("registration", "cancel") => mr.get(registrations_cancel::<M, A, L>),
        ("confirmation", "show") => mr.get(confirmations_show::<M, A, L>),
        ("unlock", "show") => mr.get(unlocks_show::<M, A, L>),
        ("session", "destroy") => mr.get(sessions_destroy::<M, A, L>),
        ("registration", "destroy") => mr.get(registrations_destroy::<M, A, L>),
        _ => mr,
    }
}

fn attach_post<M, A, L>(
    mr: MethodRouter<DeviseWebState<M, A, L>>,
    family: &str,
    action: &str,
) -> MethodRouter<DeviseWebState<M, A, L>>
where
    M: FullDeviseModel,
    A: OrmAdapter<M, New = M> + Send + Sync + 'static,
    L: Mailer<M> + 'static,
{
    match (family, action) {
        ("session", "create") => mr.post(sessions_create::<M, A, L>),
        ("password", "create") => mr.post(passwords_create::<M, A, L>),
        ("confirmation", "create") => mr.post(confirmations_create::<M, A, L>),
        ("unlock", "create") => mr.post(unlocks_create::<M, A, L>),
        (_, "create") => mr.post(registrations_create::<M, A, L>),
        ("session", "destroy") => mr.post(sessions_destroy::<M, A, L>),
        ("registration", "destroy") => mr.post(registrations_destroy::<M, A, L>),
        _ => mr,
    }
}

fn attach_patch<M, A, L>(
    mr: MethodRouter<DeviseWebState<M, A, L>>,
    family: &str,
    action: &str,
) -> MethodRouter<DeviseWebState<M, A, L>>
where
    M: FullDeviseModel,
    A: OrmAdapter<M, New = M> + Send + Sync + 'static,
    L: Mailer<M> + 'static,
{
    match (family, action) {
        ("password", "update") => mr.patch(passwords_update::<M, A, L>),
        ("registration", "update") => mr.patch(registrations_update::<M, A, L>),
        _ => mr,
    }
}

fn attach_put<M, A, L>(
    mr: MethodRouter<DeviseWebState<M, A, L>>,
    family: &str,
    action: &str,
) -> MethodRouter<DeviseWebState<M, A, L>>
where
    M: FullDeviseModel,
    A: OrmAdapter<M, New = M> + Send + Sync + 'static,
    L: Mailer<M> + 'static,
{
    match (family, action) {
        ("password", "update") => mr.put(passwords_update::<M, A, L>),
        ("registration", "update") => mr.put(registrations_update::<M, A, L>),
        _ => mr,
    }
}

fn attach_delete<M, A, L>(
    mr: MethodRouter<DeviseWebState<M, A, L>>,
    family: &str,
    action: &str,
) -> MethodRouter<DeviseWebState<M, A, L>>
where
    M: FullDeviseModel,
    A: OrmAdapter<M> + Send + Sync + 'static,
    L: Mailer<M> + 'static,
{
    match (family, action) {
        ("session", "destroy") => mr.delete(sessions_destroy::<M, A, L>),
        ("registration", "destroy") => mr.delete(registrations_destroy::<M, A, L>),
        _ => mr,
    }
}

// ============================================================================
// Controller support (D-15 response split + shared body normalization)
// ============================================================================

/// Request body normalized into one flat params map (infallible: parse
/// misses yield an empty map so handlers own the error responses).
///
/// Devise sign-in params arrive scoped (`user[email]=…` form-encoding or
/// a nested JSON object under the scope singular); both collapse to flat
/// keys here, mirroring the actix `body_map`.
pub struct DeviseParams(pub(crate) Map<String, JsonValue>);

impl<S> FromRequest<S> for DeviseParams
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let is_json = req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|content_type| content_type.contains("application/json"));
        let map = if is_json {
            axum::Json::<JsonValue>::from_request(req, state)
                .await
                .ok()
                .and_then(|json| json.0.as_object().cloned())
                .unwrap_or_default()
        } else {
            Form::<HashMap<String, String>>::from_request(req, state)
                .await
                .map(|form| {
                    form.0
                        .into_iter()
                        .map(|(key, value)| (key, JsonValue::String(value)))
                        .collect()
                })
                .unwrap_or_default()
        };
        Ok(DeviseParams(map))
    }
}

/// Normalize the request body into one flat params map. Devise-sign-in
/// params arrive scoped (`user[email]=…` form-encoding or a nested JSON
/// object under the scope singular); both collapse to flat keys here.
fn body_map(raw: Map<String, JsonValue>, singular: &str) -> Map<String, JsonValue> {
    if let Some(scoped) = raw.get(singular).and_then(JsonValue::as_object) {
        return scoped.clone();
    }
    let prefix = format!("{singular}[");
    let mut merged = Map::new();
    for (key, value) in raw {
        if let Some(inner) = key
            .strip_prefix(&prefix)
            .and_then(|rest| rest.strip_suffix(']'))
        {
            merged.insert(inner.to_string(), value);
        } else {
            merged.insert(key, value);
        }
    }
    merged
}

fn param_str<'m>(map: &'m Map<String, JsonValue>, key: &str) -> &'m str {
    map.get(key).and_then(JsonValue::as_str).unwrap_or("")
}

/// Devise `devise_parameter_sanitizer.sanitize(action)`
/// (`parameter_sanitizer.rb`): keep ONLY the action's permitted keys before
/// a record is built from the params (S7 — mass-assignment guard).
///
/// The three actions used here are always registered by
/// [`ParameterSanitizer::new`], so the unknown-action `Err` (Devise's
/// `unknown_action!` raise) is unreachable; failing closed to a 500
/// (never a silent empty-map pass-through) keeps a future typo loud
/// instead of quietly widening the permitted set.
///
/// # Errors
///
/// [`devise_rust::error::DeviseError::Config`] when `action` has not been
/// registered; the caller renders it as the framework's internal error.
fn sanitized_params(
    config: &DeviseConfig,
    action: &str,
    params: &Map<String, JsonValue>,
) -> Result<Map<String, JsonValue>, devise_rust::error::DeviseError> {
    devise_rust::parameter::ParameterSanitizer::new(config).sanitize(action, params)
}

/// JSON vs HTML split (D-15): JSON when the request content-type or Accept
/// header names JSON; everything else follows Devise's navigational path.
fn wants_json(auth_request: &AuthRequest) -> bool {
    let accept = auth_request
        .headers
        .get("accept")
        .map(String::as_str)
        .unwrap_or_default();
    let content_type = auth_request
        .headers
        .get("content-type")
        .map(String::as_str)
        .unwrap_or_default();
    content_type.contains("application/json") || accept.contains("application/json")
}

/// Fail an authentication post: navigational → 302 to sign-in + flash;
/// JSON → 401 with the symbolic key (never values).
fn auth_fail<M, A, L>(
    auth_request: &AuthRequest,
    st: &DeviseWebState<M, A, L>,
    key: &str,
) -> Response {
    if wants_json(auth_request) {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({ "error": key })),
        )
            .into_response();
    }
    flash_redirect(&st.config, &st.mapping.sign_in_path(), key)
}

/// Unauthenticated gate for owner-only controller actions (Devise
/// `authenticate_<scope>!` semantics).
fn unauthenticated_response<M, A, L>(
    auth_request: &AuthRequest,
    st: &DeviseWebState<M, A, L>,
) -> Response {
    auth_fail(auth_request, st, "unauthenticated")
}

/// The responder `error_status` (`devise/lib/devise/controllers/responder.rb:9`)
/// for a config: [`DeviseConfig::validate`] rejects out-of-range codes at
/// boot, and this `unwrap_or` is defense-in-depth for configs that never
/// validated (never panic on the render path).
fn error_status_of(config: &DeviseConfig) -> StatusCode {
    StatusCode::from_u16(config.error_status).unwrap_or(StatusCode::OK)
}

/// Validation failure: HTML re-render and JSON both answer the configured
/// responder `error_status`, exactly as Devise's `respond_with` error
/// renders do for every format (`error_status` is applied to the HTML
/// re-render AND the JSON body). The keyed error body is unchanged; only
/// the status moves. The JSON body carries the entries' interpolation
/// options as a sibling `options` map
/// ([`errors_options_json`](devise_rust::error::errors_options_json),
/// M-8: Devise's `errors.add(attr, :key, period: ...)` payload) so the
/// renderer can interpolate `%{period}` and friends from the symbolic
/// keys; empty when no entry carries options. The
/// `confirmations#show` / `unlocks#show` call sites pass Devise's
/// hardcoded 422 instead (their TODO carve-out).
fn invalid_response(
    auth_request: &AuthRequest,
    errors: &ValidationErrors,
    status: StatusCode,
) -> Response {
    if wants_json(auth_request) {
        return (
            status,
            axum::Json(serde_json::json!({
                "errors": errors_json(errors),
                "options": devise_rust::error::errors_options_json(errors),
            })),
        )
            .into_response();
    }
    (
        status,
        [("content-type", "text/html; charset=utf-8")],
        format!(
            "Form errors: {}",
            serde_json::to_string(&errors_json(errors)).unwrap_or_else(|_| "{}".to_string())
        ),
    )
        .into_response()
}

/// Scopes that share this middleware run: EVERY registered scope, like
/// Devise's `Devise.mappings.keys` (`controllers/sign_in_out.rb:86-95`) —
/// never only the request's own mapping (S2).
fn all_scope_names<M, A, L>(st: &DeviseWebState<M, A, L>) -> Vec<String> {
    st.registry.scope_names()
}

/// Cheap scope-session probe for `require_no_authentication` /
/// `verify_signed_out_user`: no adapter round-trip, just the session payload's
/// presence (the salt check happens later, where the record is needed).
async fn scope_session_present(session: &Session, scope: &str) -> bool {
    session
        .get_value(&devise_rust::session::keys::scope_session_key(scope))
        .await
        .ok()
        .flatten()
        .is_some()
}

/// Load the currently-signed-in record for `scope` — the memoized
/// layer-resolved fetch (never a re-authentication).
async fn current_record<M>(handle: &AuthProxyHandle, scope: &str) -> Option<M>
where
    M: FullDeviseModel,
{
    let proxy = handle.lock().await;
    proxy.user::<M>(scope).cloned()
}

/// Durable sign-in bookkeeping shared by the password sign-in, the
/// sign-up pipeline, and the omniauth callback sign-in paths: the trackable
/// shift (current→last, now + socket peer) persisted through
/// `update_columns`, built from the single core definition
/// ([`tracked_fields_changeset`](devise_rust::trackable::tracked_fields_changeset)
/// with the named column constants).
///
/// The warden `after_set_user` Authentication hooks are memo-only by the
/// Phase 5 hook design, and `AuthProxy::set_user` dispatches them
/// request-less so the trackable hook body cannot run there — the
/// controller therefore owns BOTH the durable write AND the single
/// in-memory shift below (verified: exactly one application per sign-in;
/// the flow tests pin the record copy and the DB row at one increment).
///
/// The #4673 new-record guard (D-21) is restored on this path: the
/// adapter is probed first and an absent record performs zero writes and
/// no in-memory shift.
pub(crate) async fn sign_in_bookkeeping<M, A>(
    record: &mut M,
    adapter: &A,
    peer_addr: Option<&str>,
    clock: &dyn Clock,
) where
    M: FullDeviseModel,
    A: OrmAdapter<M> + Send + Sync,
{
    // Trackable: shift current→last, stamp now + socket peer (D-11), and
    // persist durably (the hook owns only the memo copy).
    if adapter.get(&record.to_key()).await.ok().flatten().is_none() {
        return;
    }
    let now = clock.now();
    // The durable map comes from the PRE-shift state through the one
    // core builder; the shift below then applies the same values to the
    // in-memory record copy.
    let fields = devise_rust::trackable::tracked_fields_changeset(record, now, peer_addr);
    record.update_tracked_fields(now, peer_addr);
    drop(adapter.update_columns(&record.to_key(), &fields).await);
}

// ============================================================================
// Controllers (D-14)
// ============================================================================

async fn new_handler<M, A, L>(
    State(st): State<DeviseWebState<M, A, L>>,
    Extension(session): Extension<Session>,
    Extension(handle): Extension<AuthProxyHandle>,
    Extension(auth_request): Extension<AuthRequest>,
) -> Response
where
    M: FullDeviseModel,
    A: OrmAdapter<M> + Send + Sync + 'static,
    L: Mailer<M> + 'static,
{
    // Devise mounts `require_no_authentication` on sessions#new and on
    // EVERY passwords and unlocks action (`sessions_controller.rb:4`,
    // `passwords_controller.rb:4`, `unlocks_controller.rb:4`): the generic
    // new-form handler serves all three families, so the guard runs here
    // too (registrations#new carries it inside its own handler).
    if let Some(redirect) = require_no_authentication(&session, &handle, &auth_request, &st).await {
        return redirect;
    }
    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        "form",
    )
        .into_response()
}

/// `require_no_authentication` (devise_controller.rb:116-132): a request
/// authenticated by SESSION OR by a live remember cookie is redirected
/// home with the `already_authenticated` flash instead of reaching the
/// guarded action. Devise's guard consults `warden.authenticate?` with
/// the mapping's NO-INPUT strategies (the rememberable strategy runs),
/// so a remembered visitor (session dropped, remember cookie kept) is
/// authenticated; the core
/// [`no_authentication_guard_passes`](devise_rust::helpers::no_authentication_guard_passes)
/// decision owns the rule and the five-condition cookie validation.
///
/// Mounted on sessions new/create (`sessions_controller.rb:4`), every
/// passwords action (`passwords_controller.rb:4`), every unlocks action
/// (`unlocks_controller.rb:4`), and registrations new/create/cancel
/// (`registrations_controller.rb:4`).
///
/// Returns `Some(redirect)` when the guard fires.
#[allow(clippy::too_many_lines)]
async fn require_no_authentication<M, A, L>(
    session: &Session,
    handle: &AuthProxyHandle,
    auth_request: &AuthRequest,
    st: &DeviseWebState<M, A, L>,
) -> Option<Response>
where
    M: FullDeviseModel,
    A: OrmAdapter<M> + Send + Sync + 'static,
    L: Mailer<M> + 'static,
{
    // Devise returns early for non-navigational formats; the flash-based
    // redirect is a navigational behavior (same shape as sessions#create).
    if wants_json(auth_request) {
        return None;
    }
    let scope = st.mapping.name.as_str();
    let session_present = scope_session_present(session, scope).await;
    // The remember cookie: the layer already signature-verified the
    // inbound cookie into `auth_request.cookies` for the resolved scope,
    // so the decode here reads the verified triple (a failed verify kept
    // the raw value, which decodes to nothing: anonymous, never a
    // failure).
    let remember_triple = auth_request
        .cookies
        .get(&remember_cookie_key(scope, &st.config))
        .and_then(|raw| {
            let (key, value, generated_at) = devise_rust::rememberable::decode_cookie_value(raw)?;
            devise_rust::rememberable::parse_generated_at(&generated_at)
                .map(|_| (key, value, generated_at))
        });
    let adapter = st.adapter.clone();
    let authenticated = devise_rust::helpers::no_authentication_guard_passes(
        session_present,
        remember_triple,
        &st.config,
        st.clock.as_ref(),
        |key: String| async move {
            let key = DeviseKey::from_str(&key).ok()?;
            let record = adapter.get(&key).await.ok()??;
            Some((
                record.rememberable_value().ok()?,
                record.remember_created_at(),
            ))
        },
    )
    .await;
    if !authenticated {
        return None;
    }
    let proxy = handle.lock().await;
    let target = after_sign_in_path_for(scope, &proxy, auth_request).await;
    drop(proxy);
    Some(flash_redirect(
        &st.config,
        &target,
        flash_keys::ALREADY_AUTHENTICATED,
    ))
}

/// `RegistrationsController#new` (`registrations_controller.rb:9-14`):
/// the sign-up form, behind `require_no_authentication` (S13).
async fn registrations_new<M, A, L>(
    State(st): State<DeviseWebState<M, A, L>>,
    Extension(session): Extension<Session>,
    Extension(handle): Extension<AuthProxyHandle>,
    Extension(auth_request): Extension<AuthRequest>,
) -> Response
where
    M: FullDeviseModel,
    A: OrmAdapter<M> + Send + Sync + 'static,
    L: Mailer<M> + 'static,
{
    if let Some(redirect) = require_no_authentication(&session, &handle, &auth_request, &st).await {
        return redirect;
    }
    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        "form",
    )
        .into_response()
}

/// SessionsController#create: authenticate the params, run the lockable
/// failed-attempt gate and the trackable durable shift, then sign the
/// user in through the proxy with a cycle-before-insert physical write.
#[allow(clippy::too_many_lines)]
async fn sessions_create<M, A, L>(
    State(st): State<DeviseWebState<M, A, L>>,
    Extension(session): Extension<Session>,
    Extension(handle): Extension<AuthProxyHandle>,
    Extension(mut auth_request): Extension<AuthRequest>,
    params: DeviseParams,
) -> Response
where
    M: FullDeviseModel,
    A: OrmAdapter<M> + Send + Sync + 'static,
    L: Mailer<M> + 'static,
{
    let singular = st.mapping.singular.clone();
    let scope = st.mapping.name.clone();
    // Devise `require_no_authentication` (sessions_controller.rb:4): an
    // already authenticated request (session OR live remember cookie,
    // devise_controller.rb:116-132) is redirected home with
    // `already_authenticated` instead of re-authenticating (navigational
    // formats only, as in Devise).
    if let Some(redirect) = require_no_authentication(&session, &handle, &auth_request, &st).await {
        return redirect;
    }
    // Devise `allow_params_authentication!` (sessions_controller.rb:5):
    // the ONLY action that opts into params authentication — the layer
    // leaves the request flag down everywhere else (S4).
    auth_request.flags.allow_params_authentication = st.config.params_authenticatable;
    // S7: `sign_in_params` — the `:sign_in` sanitizer decides what the
    // controller may read (`sessions_controller.rb:34-36`).
    // Devise's `unknown_action!` raise renders as the framework's 500.
    let raw_params = body_map(params.0, &singular);
    let Ok(params) = sanitized_params(&st.config, "sign_in", &raw_params) else {
        return internal_error();
    };
    let password = param_str(&params, "password").to_string();
    // Devise's sign-in form posts "1" (`TRUE_VALUES`,
    // `strategies/authenticatable.rb:56-57`); JSON clients send a real
    // boolean - the core helper honors both shapes (the axum leg
    // previously dropped the boolean).
    let remember = devise_rust::parameter::remember_me_from(&params);

    // M-fix: Devise builds the authentication conditions from
    // `Devise.authentication_keys` — never a hardcoded `email` column —
    // normalized through the same case/whitespace rules the params strategy
    // applies (`strategies/database_authenticatable.rb:8-14`).
    let mut conditions = Conditions::new();
    for key in &st.config.authentication_keys {
        // The lookup reads the RAW body map through the core `param_for`
        // precedence (scoped bracket, bridge flat, bare): the sign_in
        // sanitizer retains the bare spellings of the SAME permitted
        // credential, and the bridge flat spelling `{singular}_{key}` is
        // the port's own param dialect (the tracer routes and the core
        // strategy chain already accept it), so every spelling of the
        // CONFIGURED keys reaches the lookup while nothing unconfigured
        // can flow into the conditions.
        let raw = devise_rust::parameter::param_for(&raw_params, &singular, key);
        let value = devise_rust::model::normalize_credential_value(
            &raw,
            key,
            &st.config.case_insensitive_keys,
            &st.config.strip_whitespace_keys,
        );
        conditions.insert(key.clone(), AdapterValue::String(value));
    }
    // Devise's second `parse_authentication_key_values` pass over the request
    // object's values (`strategies/authenticatable.rb:147-167`): the layer's
    // staged snapshot carries them, a same-named request value overwrites the
    // param condition, and a missing or blank required key fails the parse.
    // On failure the generic `invalid` failure is reported (not
    // `not_found_in_database`): no lookup ran, so nothing is known about the
    // account either way.
    if !devise_rust::strategy::merge_request_keys(&mut conditions, &auth_request, &st.config) {
        return auth_fail(&auth_request, &st, "invalid");
    }
    // Devise `password.present? && find_for_database_authentication`
    // (`strategies/database_authenticatable.rb:10`): a blank password
    // short-circuits the lookup, fails with the unknown-account key
    // (invalid under paranoid after the dummy hash, which
    // `unknown_account_failure` performs), and never counts an attempt -
    // otherwise a blank POST on a known email would be a lockout-DoS
    // vector. The gate sits AFTER the request-keys parse (which Devise
    // runs inside `valid?`) and immediately BEFORE the find.
    if password.trim().is_empty() {
        return auth_fail(
            &auth_request,
            &st,
            devise_rust::strategy::unknown_account_failure(&st.config),
        );
    }
    let Some(mut record) =
        M::find_for_authentication(&conditions, st.adapter.as_ref(), &st.config).await
    else {
        // Devise paranoid mitigation + the non-paranoid `:not_found_in_database`
        // branch (`strategies/database_authenticatable.rb:22-25`): the dummy
        // hash and the key rule live in core so both frameworks and the
        // strategy chain share one implementation.
        return auth_fail(
            &auth_request,
            &st,
            devise_rust::strategy::unknown_account_failure(&st.config),
        );
    };

    let password_ok = record
        .as_password_verifiable()
        .is_some_and(|verifiable| verifiable.valid_password(&password, &st.config));

    let Ok(outcome) = record
        .apply_failed_attempt(
            password_ok,
            st.adapter.as_ref(),
            st.mailer.as_ref(),
            &st.config,
            st.clock.as_ref(),
        )
        .await
    else {
        return internal_error();
    };
    match outcome {
        LockAttemptOutcome::Locked => {
            // Same core rule as the incremented arm: under paranoid Devise
            // reports :invalid for a lock this attempt just triggered, so the
            // lock state cannot signal account existence
            // (`lockable.rb:127-131`).
            let key = record.lock_unauthenticated_message(&st.config, st.clock.as_ref());
            return auth_fail(&auth_request, &st, key);
        }
        LockAttemptOutcome::FailedIncremented => {
            // Devise's `unauthenticated_message` (lockable branch,
            // `lockable.rb:127-139`): paranoid-first, then locked, then
            // last-attempt warning. Core owns the rule; the controller just
            // renders its key (no hand-rolled duplicate here).
            let key = record.lock_unauthenticated_message(&st.config, st.clock.as_ref());
            return auth_fail(&auth_request, &st, key);
        }
        LockAttemptOutcome::Authenticated => {}
    }

    // DBAU-07: Devise's DatabaseAuthenticatable strategy fires
    // `after_database_authentication` immediately after the successful
    // password check (`strategies/database_authenticatable.rb:40`), before
    // warden's active-for-authentication gate — the controller mirrors
    // that order.
    devise_rust::failure::AnyDeviseModel::after_database_authentication(&record);

    // Devise `hooks/activatable.rb` include order (`models.rb`): the
    // activatable hook registers BEFORE the lockable hook, and its
    // `throw :warden` aborts the request before the lockable
    // `after_set_user` hook can run. A sign-in the activatable gate
    // rejects must therefore NOT persist the counter reset, or a failed
    // attempt on an inactive account would erase the brute-force history
    // (IN-04).
    if !record.active_for_authentication() {
        return auth_fail(&auth_request, &st, record.inactive_message());
    }

    // Devise warden `after_set_user` lockable hook: zero the counter on a
    // successful sign-in (durable; the hook owns only the memo copy).
    drop(record.reset_failed_attempts(st.adapter.as_ref()).await);

    // Trackable: the shared durable sign-in bookkeeping (current→last
    // shift + persist; the Authentication hooks are memo-only by the
    // Phase 5 hook design).
    sign_in_bookkeeping(
        &mut record,
        st.adapter.as_ref(),
        auth_request.peer_addr.as_deref(),
        st.clock.as_ref(),
    )
    .await;

    // Rememberable: durable `remember_me` BEFORE set_user (the core
    // rememberable-set hook owns the cookie intent and reads the flag).
    if remember {
        record.set_remember_me_flag(true);
        drop(
            record
                .remember_me(st.adapter.as_ref(), st.clock.as_ref())
                .await,
        );
    }

    let (key, salt) = record.session_pair();

    // Sign in through AuthProxy set_user: Authentication hooks +
    // memoization + expire_devise_keys. `store: false` — the physical
    // write belongs to the cycle-before-insert bridge helper below.
    let target = {
        let mut proxy = handle.lock().await;
        let opts = SetUserOpts {
            event: SetUserEvent::Authentication,
            store: false,
            run_callbacks: true,
            force: false,
        };
        if proxy
            .set_user(&scope, Some(Box::new(record)), opts)
            .await
            .is_err()
        {
            return internal_error();
        }
        after_sign_in_path_for(&scope, &proxy, &auth_request).await
    };

    // D-04: cycle BEFORE the insert; a failed cycle fails the sign-in.
    if bridge::insert_session_and_renew(&session, &scope, &key, &salt)
        .await
        .is_err()
    {
        return internal_error();
    }
    // D-07: rotate the app-owned CSRF token on the transition.
    rotate_csrf_token(&session, &scope, &st.config).await;

    if wants_json(&auth_request) {
        axum::Json(serde_json::json!({ "signed_in": true })).into_response()
    } else {
        flash_redirect(&st.config, &target, flash_keys::SIGNED_IN)
    }
}

/// SessionsController#destroy: `forget_me` on the current record, logout
/// hooks through the proxy, then rotate the id on the sign-out path. The
/// remember tombstone rides the proxy outbox so the layer drain renders
/// it signed (T-09-07: logout never leaves a live remember login).
async fn sessions_destroy<M, A, L>(
    State(st): State<DeviseWebState<M, A, L>>,
    Extension(session): Extension<Session>,
    Extension(handle): Extension<AuthProxyHandle>,
    Extension(auth_request): Extension<AuthRequest>,
) -> Response
where
    M: FullDeviseModel,
    A: OrmAdapter<M> + Send + Sync + 'static,
    L: Mailer<M> + 'static,
{
    let scope = st.mapping.name.clone();

    // Devise `verify_signed_out_user` → `all_signed_out?`
    // (`sessions_controller.rb:61-73`): iterate EVERY registered mapping's
    // session payload, not only this scope's — a sibling scope's active
    // session means the caller IS signed in somewhere, so the sign-out
    // proceeds and reports `signed_out` (M-fix).
    let mut any_scope_signed_in = current_record::<M>(&handle, &scope).await.is_some();
    if !any_scope_signed_in {
        for probe in all_scope_names(&st) {
            if scope_session_present(&session, &probe).await {
                any_scope_signed_in = true;
                break;
            }
        }
    }
    if !any_scope_signed_in {
        return if wants_json(&auth_request) {
            (
                StatusCode::UNAUTHORIZED,
                axum::Json(serde_json::json!({"error": "already_signed_out"})),
            )
                .into_response()
        } else {
            flash_redirect(&st.config, "/", "already_signed_out")
        };
    }

    // forget_me on the current record (durable), then the proxy sign-out
    // (logout hooks — incl. the forgetable Clear op when hooks are
    // registered). The explicit tombstone guarantees the delete even
    // without the hook registry.
    {
        let mut proxy = handle.lock().await;
        if let Some(mut record) = proxy.user::<M>(&scope).cloned() {
            if record
                .forget_me(st.adapter.as_ref(), &st.config)
                .await
                .is_ok()
            {
                proxy.push_remember_cookie_op(crate::remember::forget_op(&scope, &st.config));
            }
        }
        proxy.sign_out(&scope).await;
    }

    let sign_out = if st.config.sign_out_all_scopes {
        bridge::sign_out_all_scopes_and_renew(&session, &all_scope_names(&st)).await
    } else {
        bridge::sign_out_and_renew(&session, &scope).await
    };
    if sign_out.is_err() {
        return internal_error();
    }
    rotate_csrf_token(&session, &scope, &st.config).await;

    if wants_json(&auth_request) {
        StatusCode::NO_CONTENT.into_response()
    } else {
        flash_redirect(&st.config, "/", flash_keys::SIGNED_OUT)
    }
}

// ============================================================================
// Registrations controller (REGS / RegistrationsController)
// ============================================================================

async fn registrations_edit<M, A, L>(
    State(st): State<DeviseWebState<M, A, L>>,
    Extension(handle): Extension<AuthProxyHandle>,
    Extension(auth_request): Extension<AuthRequest>,
) -> Response
where
    M: FullDeviseModel,
    A: OrmAdapter<M> + Send + Sync + 'static,
    L: Mailer<M> + 'static,
{
    if current_record::<M>(&handle, &st.mapping.name)
        .await
        .is_none()
    {
        return unauthenticated_response(&auth_request, &st);
    }
    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        "edit",
    )
        .into_response()
}

#[allow(clippy::too_many_lines)]
async fn registrations_create<M, A, L>(
    State(st): State<DeviseWebState<M, A, L>>,
    Extension(session): Extension<Session>,
    Extension(handle): Extension<AuthProxyHandle>,
    Extension(auth_request): Extension<AuthRequest>,
    params: DeviseParams,
) -> Response
where
    M: FullDeviseModel,
    A: OrmAdapter<M, New = M> + Send + Sync + 'static,
    L: Mailer<M> + 'static,
{
    // Devise `require_no_authentication, only: [:new, :create, :cancel]`
    // (`registrations_controller.rb:4`): a signed-in session never reaches
    // the create action (S13).
    if let Some(redirect) = require_no_authentication(&session, &handle, &auth_request, &st).await {
        return redirect;
    }
    let singular = st.mapping.singular.clone();
    // S7: `sign_up_params` — the `:sign_up` sanitizer decides which params
    // may build a record (`registrations_controller.rb:113-115`); the raw
    // body map never reaches `new_with_session`.
    // Devise's `unknown_action!` raise renders as the framework's 500.
    let Ok(params) = sanitized_params(&st.config, "sign_up", &body_map(params.0, &singular)) else {
        return internal_error();
    };
    let mut record = M::new_with_session(&params, &JsonValue::Null, &st.config);

    let mut errors = record.validate(&st.config);
    record
        .validate_email_uniqueness(st.adapter.as_ref(), &mut errors)
        .await;
    if !errors.is_empty() {
        record.clean_up_passwords();
        return invalid_response(&auth_request, &errors, error_status_of(&st.config));
    }
    let Ok(mut saved) = st.adapter.create(record).await else {
        return internal_error();
    };
    // Devise confirmable `after_commit :send_on_create_confirmation_instructions`.
    // The GATED core path owns the decision (CNF-01:
    // `send_confirmation_notification?`, confirmable.rb:286-288): the
    // `skip_confirmation_notification!` flag is honored and a blank
    // address sends nothing (T-261026-ghk-02). Devise propagates a failed
    // delivery (Rails renders the raised delivery error as 500): the user
    // MUST learn the instructions never went out; swallowing it behind an
    // eprintln turns a broken mailer into silent "check your inbox" dead
    // air.
    if let Err(error) = saved
        .send_on_create_confirmation_instructions(
            st.adapter.as_ref(),
            st.mailer.as_ref(),
            &st.config,
            st.clock.as_ref(),
        )
        .await
    {
        let _ = error;
        return internal_error();
    }
    if let Some(message) = saved.post_sign_up_message() {
        let key = format!("signed_up_but_{message}");
        // Devise `expire_data_after_sign_in!`: the inactive branch must not
        // leave any signed-in state behind (registrations_controller.rb:26-29).
        let _ = bridge::expire_devise_data(&session, &all_scope_names(&st)).await;
        if wants_json(&auth_request) {
            (
                StatusCode::CREATED,
                axum::Json(serde_json::json!({ "signed_up": true, "inactive": message })),
            )
                .into_response()
        } else {
            flash_redirect(&st.config, &st.mapping.sign_in_path(), &key)
        }
    } else {
        // Devise `sign_up(resource_name, resource)` ->
        // `sign_in(resource_name, resource)` (`registrations_controller.rb:99-101`):
        // the sign-up IS an interactive sign-in, so the active branch runs the
        // same pipeline `sessions#create` runs: the trackable bookkeeping, the
        // Authentication hooks plus the devise key sweep through
        // `AuthProxy::set_user`, then the physical session write. The port
        // previously only inserted the payload, which left `sign_in_count`
        // at 0 and never swept the stale keys (IN-03).
        sign_in_bookkeeping(
            &mut saved,
            st.adapter.as_ref(),
            auth_request.peer_addr.as_deref(),
            st.clock.as_ref(),
        )
        .await;
        let (key, salt) = saved.session_pair();
        let scope = st.mapping.name.clone();
        {
            let mut proxy = handle.lock().await;
            let opts = SetUserOpts {
                event: SetUserEvent::Authentication,
                store: false,
                run_callbacks: true,
                force: false,
            };
            if proxy
                .set_user(&scope, Some(Box::new(saved)), opts)
                .await
                .is_err()
            {
                return internal_error();
            }
        }
        if bridge::insert_session_and_renew(&session, &scope, &key, &salt)
            .await
            .is_err()
        {
            return internal_error();
        }
        rotate_csrf_token(&session, &scope, &st.config).await;
        if wants_json(&auth_request) {
            (
                StatusCode::CREATED,
                axum::Json(serde_json::json!({ "signed_up": true })),
            )
                .into_response()
        } else {
            flash_redirect(&st.config, "/", flash_keys::SIGNED_UP)
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn registrations_update<M, A, L>(
    State(st): State<DeviseWebState<M, A, L>>,
    Extension(session): Extension<Session>,
    Extension(handle): Extension<AuthProxyHandle>,
    Extension(auth_request): Extension<AuthRequest>,
    params: DeviseParams,
) -> Response
where
    M: FullDeviseModel,
    A: OrmAdapter<M> + Send + Sync + 'static,
    L: Mailer<M> + 'static,
{
    let scope = st.mapping.name.clone();
    let Some(mut record) = current_record::<M>(&handle, &scope).await else {
        return unauthenticated_response(&auth_request, &st);
    };
    let singular = st.mapping.singular.clone();
    // S7: `account_update_params` — the `:account_update` sanitizer decides
    // which params reach `update_with_password`
    // (`registrations_controller.rb:139-141`); the raw body map never
    // touches the record.
    // Devise's `unknown_action!` raise renders as the framework's 500.
    let Ok(mut params) =
        sanitized_params(&st.config, "account_update", &body_map(params.0, &singular))
    else {
        return internal_error();
    };

    // Capture the pre-update state Devise's `before_update` callbacks and
    // `set_flash_message_for_update` read after the fact.
    let original_email = record.email_value().map(str::to_string);
    let password_changed = params
        .get("password")
        .and_then(JsonValue::as_str)
        .is_some_and(|pw| !pw.trim().is_empty());
    // Devise `sign_in_after_change_password?` (`registrations_controller.rb:131-135`):
    // a blank submitted `:password` returns true IMMEDIATELY (the salt never
    // moved, so re-signing in is safe), and only a real password change
    // consults the per-model config. `update_with_password` may delete the
    // blank password fields from the params map, so the blankness is read
    // here from the same map the action already parsed (never re-parsed).
    let password_blank = params
        .get("password")
        .and_then(JsonValue::as_str)
        .is_none_or(|pw| pw.trim().is_empty());
    let sign_in_after_change_password =
        password_blank || record.sign_in_after_change_password(&st.config);

    if let Err(errors) = record.update_with_password(&mut params, &st.config) {
        record.clean_up_passwords();
        return invalid_response(&auth_request, &errors, error_status_of(&st.config));
    }

    let mut errors = record.validate(&st.config);
    record
        .validate_email_uniqueness(st.adapter.as_ref(), &mut errors)
        .await;
    if !errors.is_empty() {
        record.clean_up_passwords();
        return invalid_response(&auth_request, &errors, error_status_of(&st.config));
    }

    // Devise `before_update` on recoverable (`clear_reset_password_token`,
    // `recoverable.rb:32`): a password change invalidates outstanding reset
    // links. Devise `postpone_email_change...` (confirmable #5783): an email
    // change is postponed behind a confirmation instead of being applied.
    let email_changed = matches!(
        (original_email.as_deref(), record.email_value()),
        (Some(old), Some(new)) if old != new
    );
    let mut reconfirmation_pending = false;
    if email_changed {
        let new_email = record.email_value().unwrap_or_default().to_string();
        // `update_with_password` already assigned the new address in memory;
        // `change_email_with_reconfirmation` reads the record's address as
        // the pre-change value (Devise's `devise_will_save_change_to_email?`
        // compares against the persisted row), so restore it first.
        record.set_email_address(original_email.clone().unwrap_or_default());
        match record
            .change_email_with_reconfirmation(
                &new_email,
                st.adapter.as_ref(),
                st.mailer.as_ref(),
                &st.config,
                st.clock.as_ref(),
            )
            .await
        {
            Ok(Some(_raw)) => reconfirmation_pending = true,
            Ok(None) => {}
            Err(_) => return internal_error(),
        }
    }

    let mut fields = HashMap::new();
    fields.insert(
        "encrypted_password".to_string(),
        AdapterValue::String(record.encrypted_password().unwrap_or_default().to_string()),
    );
    // After a postponed reconfirmation the DB keeps the ORIGINAL address
    // (core wrote it); the in-memory record carries the new one.
    if email_changed && !reconfirmation_pending {
        fields.insert(
            "email".to_string(),
            AdapterValue::String(record.email_value().unwrap_or_default().to_string()),
        );
    }
    if password_changed {
        record.clear_reset_password_token();
        fields.insert("reset_password_token".to_string(), AdapterValue::Null);
        fields.insert("reset_password_sent_at".to_string(), AdapterValue::Null);
    }
    let Ok(persisted) = st.adapter.update_columns(&record.to_key(), &fields).await else {
        return internal_error();
    };

    // D-03/T-08-09: account-update renewal: Devise runs
    // `bypass_sign_in resource, scope: resource_name if sign_in_after_change_password?`
    // (`registrations_controller.rb:54`), the same predicate the flash reads,
    // so the re-sign-in and the flash can never disagree.
    if sign_in_after_change_password {
        let (key, salt) = AnyDeviseModel::session_pair(&persisted);
        if bridge::bypass_sign_in_and_renew(&session, &scope, &key, &salt)
            .await
            .is_err()
        {
            return internal_error();
        }
        rotate_csrf_token(&session, &scope, &st.config).await;
    }
    // Devise `set_flash_message_for_update` (`registrations_controller.rb:151-162`):
    // the branch order is pending reconfirmation first, then
    // `sign_in_after_change_password?`, and NOTHING consults
    // `active_for_authentication?`; the reference never lets account
    // activity pick the flash key (M-4).
    let flash_key = if reconfirmation_pending {
        flash_keys::UPDATE_NEEDS_CONFIRMATION
    } else if sign_in_after_change_password {
        flash_keys::UPDATED
    } else {
        flash_keys::UPDATED_BUT_NOT_SIGNED_IN
    };
    if wants_json(&auth_request) {
        axum::Json(serde_json::json!({ "updated": true })).into_response()
    } else {
        flash_redirect(&st.config, "/", flash_key)
    }
}

async fn registrations_destroy<M, A, L>(
    State(st): State<DeviseWebState<M, A, L>>,
    Extension(session): Extension<Session>,
    Extension(handle): Extension<AuthProxyHandle>,
    Extension(auth_request): Extension<AuthRequest>,
) -> Response
where
    M: FullDeviseModel,
    A: OrmAdapter<M> + Send + Sync + 'static,
    L: Mailer<M> + 'static,
{
    let scope = st.mapping.name.clone();
    let Some(record) = current_record::<M>(&handle, &scope).await else {
        return unauthenticated_response(&auth_request, &st);
    };
    drop(st.adapter.delete(&record.to_key()).await);
    // Devise registrations#destroy honors `sign_out_all_scopes` like
    // sessions#destroy does (registrations_controller.rb:69-71).
    let sign_out = if st.config.sign_out_all_scopes {
        bridge::sign_out_all_scopes_and_renew(&session, &all_scope_names(&st)).await
    } else {
        bridge::sign_out_and_renew(&session, &scope).await
    };
    if sign_out.is_err() {
        return internal_error();
    }
    rotate_csrf_token(&session, &scope, &st.config).await;
    if wants_json(&auth_request) {
        StatusCode::NO_CONTENT.into_response()
    } else {
        flash_redirect(&st.config, "/", flash_keys::DESTROYED)
    }
}

async fn registrations_cancel<M, A, L>(
    State(st): State<DeviseWebState<M, A, L>>,
    Extension(session): Extension<Session>,
    Extension(handle): Extension<AuthProxyHandle>,
    Extension(auth_request): Extension<AuthRequest>,
) -> Response
where
    M: FullDeviseModel,
    A: OrmAdapter<M> + Send + Sync + 'static,
    L: Mailer<M> + 'static,
{
    // Devise `require_no_authentication, only: [:new, :create, :cancel]`
    // (`registrations_controller.rb:4`): a signed-in session never reaches
    // the cancel action (S13).
    if let Some(redirect) = require_no_authentication(&session, &handle, &auth_request, &st).await {
        return redirect;
    }
    // Devise registrations#cancel (`registrations_controller.rb:78-81`):
    // expire the session data, then redirect to the sign-up path (no flash).
    let _ = bridge::expire_devise_data(&session, &all_scope_names(&st)).await;
    (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, st.mapping.sign_up_path())],
    )
        .into_response()
}

// ============================================================================
// Passwords controller (RCV / PasswordsController)
// ============================================================================

async fn passwords_create<M, A, L>(
    State(st): State<DeviseWebState<M, A, L>>,
    Extension(session): Extension<Session>,
    Extension(handle): Extension<AuthProxyHandle>,
    Extension(auth_request): Extension<AuthRequest>,
    params: DeviseParams,
) -> Response
where
    M: FullDeviseModel,
    A: OrmAdapter<M, New = M> + Send + Sync + 'static,
    L: Mailer<M> + 'static,
{
    // Devise `require_no_authentication` (passwords_controller.rb:4): every
    // passwords action is guarded.
    if let Some(redirect) = require_no_authentication(&session, &handle, &auth_request, &st).await {
        return redirect;
    }
    let singular = st.mapping.singular.clone();
    let attrs = body_map(params.0, &singular);
    let outcome = M::send_reset_password_instructions_for(
        &attrs,
        st.adapter.as_ref(),
        st.mailer.as_ref(),
        &st.config,
        st.clock.as_ref(),
    )
    .await;
    let Ok(resource) = outcome else {
        return internal_error();
    };
    if resource.is_valid() || st.config.paranoid {
        if wants_json(&auth_request) {
            return (
                StatusCode::CREATED,
                axum::Json(serde_json::json!({ "sent": true })),
            )
                .into_response();
        }
        let key = successfully_sent_key(resource.is_valid(), st.config.paranoid);
        return flash_redirect(&st.config, &st.mapping.sign_in_path(), key);
    }
    invalid_response(&auth_request, &resource.errors, error_status_of(&st.config))
}

async fn passwords_edit<M, A, L>(
    State(st): State<DeviseWebState<M, A, L>>,
    Extension(session): Extension<Session>,
    Extension(handle): Extension<AuthProxyHandle>,
    Extension(auth_request): Extension<AuthRequest>,
    Query(query): Query<HashMap<String, String>>,
) -> Response
where
    M: FullDeviseModel,
    A: OrmAdapter<M> + Send + Sync + 'static,
    L: Mailer<M> + 'static,
{
    // Devise `require_no_authentication` (passwords_controller.rb:4): every
    // passwords action is guarded.
    if let Some(redirect) = require_no_authentication(&session, &handle, &auth_request, &st).await {
        return redirect;
    }
    // Devise `assert_reset_token_passed` (`passwords_controller.rb:65-70`):
    // the blank-token redirect goes to `new_session_path`, NOT the site
    // root: the user must land on the sign-in form to start over.
    let token = query.get("reset_password_token").map_or("", String::as_str);
    if token.trim().is_empty() {
        return flash_redirect(&st.config, &st.mapping.sign_in_path(), flash_keys::NO_TOKEN);
    }
    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        "edit",
    )
        .into_response()
}

/// The record's password digest BEFORE a token reset, resolved through the
/// SAME token lookup `reset_password_by_token` runs, so the controller can
/// compare the persisted value against the new one exactly like Devise's
/// `after_update` callback does (`database_authenticatable.rb:163-168`).
/// A blank or unknown token resolves to `None`; the reset then fails and no
/// notification can be pending anyway.
async fn digest_before_reset<M, A>(
    attrs: &serde_json::Map<String, JsonValue>,
    adapter: &A,
    config: &DeviseConfig,
) -> Option<String>
where
    M: Recoverable,
    A: OrmAdapter<M> + Send + Sync,
{
    let token = attrs
        .get("reset_password_token")
        .and_then(JsonValue::as_str)
        .unwrap_or("");
    if token.is_empty() {
        return None;
    }
    let Ok(Some(record)) = M::with_reset_password_token(token, adapter, config).await else {
        return None;
    };
    record.encrypted_password().map(str::to_string)
}

#[allow(clippy::too_many_lines)]
async fn passwords_update<M, A, L>(
    State(st): State<DeviseWebState<M, A, L>>,
    Extension(session): Extension<Session>,
    Extension(handle): Extension<AuthProxyHandle>,
    Extension(auth_request): Extension<AuthRequest>,
    params: DeviseParams,
) -> Response
where
    M: FullDeviseModel,
    A: OrmAdapter<M, New = M> + Send + Sync + 'static,
    L: Mailer<M> + 'static,
{
    // Devise `require_no_authentication` (passwords_controller.rb:4): every
    // passwords action is guarded.
    if let Some(redirect) = require_no_authentication(&session, &handle, &auth_request, &st).await {
        return redirect;
    }
    let singular = st.mapping.singular.clone();
    let attrs = body_map(params.0, &singular);
    // Devise `after_update :send_password_change_notification`
    // (`database_authenticatable.rb:163-168`): the callback fires on any
    // `encrypted_password` change, so the pre-reset digest has to be read
    // BEFORE the reset writes the new one. Devise fires it from a callback;
    // this controller path owns the decision (the model's own helper reads
    // config plus the skip flag, so the two paths cannot drift).
    let before_digest = digest_before_reset::<M, A>(&attrs, st.adapter.as_ref(), &st.config).await;
    let outcome =
        M::reset_password_by_token(&attrs, st.adapter.as_ref(), &st.config, st.clock.as_ref())
            .await;
    let Ok(mut resource) = outcome else {
        return internal_error();
    };
    if !resource.is_valid() {
        return invalid_response(&auth_request, &resource.errors, error_status_of(&st.config));
    }

    // Mirror the `after_update` decision on the reset path: mail the notice
    // when the digest moved and the config enables it. A mailer failure
    // fails the request like every other framework notification send.
    let mut changes = HashMap::new();
    changes.insert(
        "encrypted_password".to_string(),
        AdapterValue::String(
            resource
                .record
                .encrypted_password()
                .unwrap_or_default()
                .to_string(),
        ),
    );
    let previous = before_digest.map_or_else(HashMap::new, |digest| {
        HashMap::from([(
            "encrypted_password".to_string(),
            AdapterValue::String(digest),
        )])
    });
    if devise_rust::model::DatabaseAuthenticatable::send_password_change_notification(
        &resource.record,
        &devise_rust::adapter::ChangeSet::new(previous, changes),
        st.mailer.as_ref(),
        &st.config,
    )
    .is_err()
    {
        return internal_error();
    }

    // Devise `unlockable?` (`passwords_controller.rb:79-83`): the unlock
    // only runs when the configured unlock strategy includes :email AND the
    // account is actually locked, so a :time (or :none) penalty survives a
    // password reset (T-261026-ghf-01).
    if resource.record.unlock_strategy_enabled("email", &st.config)
        && resource.record.access_locked(&st.config, st.clock.as_ref())
    {
        drop(resource.record.unlock_access(st.adapter.as_ref()).await);
    }

    // Devise `passwords_controller.rb:40-45`: the sign-in after a reset is
    // UNCONDITIONAL under `sign_in_after_reset_password` (the reference
    // never gates it on `active_for_authentication?`), the flash splits on
    // activity, and `after_database_authentication` fires before the sign-in
    // (T-261026-ghf-02).
    let active = resource.record.active_for_authentication();
    if st.config.sign_in_after_reset_password {
        AnyDeviseModel::after_database_authentication(&resource.record);
        let scope = st.mapping.name.clone();
        let (key, salt) = AnyDeviseModel::session_pair(&resource.record);
        if bridge::insert_session_and_renew(&session, &scope, &key, &salt)
            .await
            .is_err()
        {
            return internal_error();
        }
        rotate_csrf_token(&session, &scope, &st.config).await;
    }

    let key = if st.config.sign_in_after_reset_password && active {
        flash_keys::UPDATED
    } else {
        flash_keys::UPDATED_NOT_ACTIVE
    };
    if wants_json(&auth_request) {
        (
            StatusCode::OK,
            axum::Json(serde_json::json!({ "reset": true, "key": key })),
        )
            .into_response()
    } else {
        flash_redirect(&st.config, "/", key)
    }
}

// ============================================================================
// Confirmations controller (CNF / ConfirmationsController)
// ============================================================================

async fn confirmations_show<M, A, L>(
    State(st): State<DeviseWebState<M, A, L>>,
    Extension(auth_request): Extension<AuthRequest>,
    Query(query): Query<HashMap<String, String>>,
) -> Response
where
    M: FullDeviseModel,
    A: OrmAdapter<M> + Send + Sync + 'static,
    L: Mailer<M> + 'static,
{
    let token = query.get("confirmation_token").map_or("", String::as_str);
    let config_snapshot = st.config.clone();
    let validate = move |record: &M| record.validate(&config_snapshot);
    let outcome = M::confirm_by_token(
        Some(token),
        st.adapter.as_ref(),
        &st.config,
        st.clock.as_ref(),
        &validate,
    )
    .await;
    let Ok(resource) = outcome else {
        return internal_error();
    };
    if resource.is_valid() {
        if wants_json(&auth_request) {
            return (
                StatusCode::OK,
                axum::Json(serde_json::json!({ "confirmed": true })),
            )
                .into_response();
        }
        return flash_redirect(
            &st.config,
            &st.mapping.sign_in_path(),
            flash_keys::CONFIRMED,
        );
    }
    // Devise carves `confirmations#show` out of the configurable
    // `error_status` with a TODO to adopt it only when the default changes
    // (`confirmations_controller.rb:30-31`); the port mirrors the hardcode.
    invalid_response(
        &auth_request,
        &resource.errors,
        StatusCode::UNPROCESSABLE_ENTITY,
    )
}

async fn confirmations_create<M, A, L>(
    State(st): State<DeviseWebState<M, A, L>>,
    Extension(auth_request): Extension<AuthRequest>,
    params: DeviseParams,
) -> Response
where
    M: FullDeviseModel,
    A: OrmAdapter<M, New = M> + Send + Sync + 'static,
    L: Mailer<M> + 'static,
{
    let singular = st.mapping.singular.clone();
    let attrs = body_map(params.0, &singular);
    let outcome = M::send_confirmation_instructions_for(
        &attrs,
        st.adapter.as_ref(),
        st.mailer.as_ref(),
        &st.config,
        st.clock.as_ref(),
    )
    .await;
    let Ok(resource) = outcome else {
        return internal_error();
    };
    // Devise `successfully_sent?` (devise_controller.rb:135-147): paranoid
    // mode clears the errors and reports a uniform
    // `send_paranoid_instructions`, so known and unknown addresses get the
    // same response.
    if resource.is_valid() || st.config.paranoid {
        let key = successfully_sent_key(resource.is_valid(), st.config.paranoid);
        if wants_json(&auth_request) {
            return (
                StatusCode::CREATED,
                axum::Json(serde_json::json!({ "sent": true })),
            )
                .into_response();
        }
        return flash_redirect(&st.config, &st.mapping.sign_in_path(), key);
    }
    invalid_response(&auth_request, &resource.errors, error_status_of(&st.config))
}

// ============================================================================
// Unlocks controller (LCK / UnlocksController) — registered only when the
// unlock strategy includes email (the dispatch-time gate in
// `devise_for_router`).
// ============================================================================

async fn unlocks_show<M, A, L>(
    State(st): State<DeviseWebState<M, A, L>>,
    Extension(session): Extension<Session>,
    Extension(handle): Extension<AuthProxyHandle>,
    Extension(auth_request): Extension<AuthRequest>,
    Query(query): Query<HashMap<String, String>>,
) -> Response
where
    M: FullDeviseModel,
    A: OrmAdapter<M> + Send + Sync + 'static,
    L: Mailer<M> + 'static,
{
    // Devise `require_no_authentication` (unlocks_controller.rb:4): every
    // unlocks action is guarded.
    if let Some(redirect) = require_no_authentication(&session, &handle, &auth_request, &st).await {
        return redirect;
    }
    let token = query.get("unlock_token").map_or("", String::as_str);
    let outcome = M::unlock_access_by_token(Some(token), st.adapter.as_ref(), &st.config).await;
    let Ok(resource) = outcome else {
        return internal_error();
    };
    if resource.is_valid() {
        if wants_json(&auth_request) {
            return (
                StatusCode::OK,
                axum::Json(serde_json::json!({ "unlocked": true })),
            )
                .into_response();
        }
        return flash_redirect(&st.config, &st.mapping.sign_in_path(), flash_keys::UNLOCKED);
    }
    // Devise carves `unlocks#show` out of the configurable `error_status`
    // with a TODO to adopt it only when the default changes
    // (`unlocks_controller.rb:32-33`); the port mirrors the hardcode.
    invalid_response(
        &auth_request,
        &resource.errors,
        StatusCode::UNPROCESSABLE_ENTITY,
    )
}

async fn unlocks_create<M, A, L>(
    State(st): State<DeviseWebState<M, A, L>>,
    Extension(session): Extension<Session>,
    Extension(handle): Extension<AuthProxyHandle>,
    Extension(auth_request): Extension<AuthRequest>,
    params: DeviseParams,
) -> Response
where
    M: FullDeviseModel,
    A: OrmAdapter<M, New = M> + Send + Sync + 'static,
    L: Mailer<M> + 'static,
{
    // Devise `require_no_authentication` (unlocks_controller.rb:4): every
    // unlocks action is guarded.
    if let Some(redirect) = require_no_authentication(&session, &handle, &auth_request, &st).await {
        return redirect;
    }
    let singular = st.mapping.singular.clone();
    let attrs = body_map(params.0, &singular);
    let outcome = M::send_unlock_instructions_for(
        &attrs,
        st.adapter.as_ref(),
        st.mailer.as_ref(),
        &st.config,
        st.clock.as_ref(),
    )
    .await;
    let Ok(resource) = outcome else {
        return internal_error();
    };
    // Devise `successfully_sent?` (devise_controller.rb:135-147): paranoid
    // mode clears the errors and reports a uniform
    // `send_paranoid_instructions`, so known and unknown addresses get the
    // same response.
    if resource.is_valid() || st.config.paranoid {
        let key = successfully_sent_key(resource.is_valid(), st.config.paranoid);
        if wants_json(&auth_request) {
            return (
                StatusCode::CREATED,
                axum::Json(serde_json::json!({ "sent": true })),
            )
                .into_response();
        }
        return flash_redirect(&st.config, &st.mapping.sign_in_path(), key);
    }
    invalid_response(&auth_request, &resource.errors, error_status_of(&st.config))
}
