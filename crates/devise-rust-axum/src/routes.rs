//! Route registration — the `devise_for`-equivalent router fn (D-03)
//! translating core [`RouteSpec`](devise_rust::scope::RouteSpec) data
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
//! semantics; JSON callers get status codes (`200`/`201`/`204`/`401`/`422`)
//! with symbolic error keys in the body (en.yml symbols, never values).

#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::too_many_lines)]

use std::collections::{BTreeMap, HashMap};
use std::convert::Infallible;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Extension, Form, FromRequest, Query, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, delete, post};
use devise_rust::adapter::{Conditions, OrmAdapter, Value as AdapterValue};
use devise_rust::config::DeviseConfig;
use devise_rust::confirmable::Confirmable;
use devise_rust::error::{DeviseError, ValidationErrors};
use devise_rust::failure::{
    AnyDeviseModel, FailureReason, FailureRenderer, build_failure, is_navigational_format,
};
use devise_rust::helpers::after_sign_in_path_for;
use devise_rust::hooks::HookProxy;
use devise_rust::lockable::{self, LockAttemptOutcome, Lockable};
use devise_rust::mailer::Mailer;
use devise_rust::model::{ModelFinder, Recoverable, Registerable, Validatable};
use devise_rust::proxy::{SetUserEvent, SetUserOpts};
use devise_rust::rememberable::{self, Rememberable};
use devise_rust::request::AuthRequest;
use devise_rust::scope::{Mapping, RouteSpec};
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
    Extension(auth_request): Extension<AuthRequest>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let scope = st.mapping.name.clone();
    let email = form.get("user_email").cloned().unwrap_or_default();
    let password = form.get("user_password").cloned().unwrap_or_default();

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
        flash_redirect(&target, "signed_in")
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
        flash_redirect("/", "signed_out")
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
    AxumFailureRenderer::new().render(&failure, &st.mapping)
}

/// 302 + devise flash cookie (actix `flash_redirect` parity).
fn flash_redirect(target: &str, flash_key: &str) -> Response {
    let mut response = StatusCode::FOUND.into_response();
    let location = HeaderValue::from_str(target).unwrap_or_else(|_| HeaderValue::from_static("/"));
    response.headers_mut().insert(header::LOCATION, location);
    if let Some(flash) = crate::failure::flash_cookie_header(flash_key) {
        response.headers_mut().append(header::SET_COOKIE, flash);
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
    /// Devise configuration (shared `Arc` with the layer).
    pub config: Arc<DeviseConfig>,
    /// ORM adapter for the scope's model.
    pub adapter: Arc<A>,
    /// Mailer for confirmation/reset/unlock instructions.
    pub mailer: Arc<L>,
    /// Clock for windows/ticks.
    pub clock: Arc<dyn Clock>,
    /// All scope names sharing the middleware run (used when
    /// `sign_out_all_scopes` holds); empty falls back to this scope only.
    pub all_scopes: Vec<String>,
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
            config: self.config.clone(),
            adapter: self.adapter.clone(),
            mailer: self.mailer.clone(),
            clock: self.clock.clone(),
            all_scopes: self.all_scopes.clone(),
            marker: std::marker::PhantomData,
        }
    }
}

impl<M, A, L> DeviseWebState<M, A, L> {
    /// Build the state for one mapping.
    ///
    /// # Errors
    ///
    /// Returns [`DeviseError::Config`] when the Devise `secret_key` is too
    /// short for the cookie-jar derivation.
    pub fn new(
        mapping: Mapping,
        config: Arc<DeviseConfig>,
        adapter: Arc<A>,
        mailer: Arc<L>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, DeviseError> {
        // Fail closed on unusable secrets here so a misconfigured app never
        // boots: every remember-cookie write would silently skip otherwise.
        crate::remember::derive_remember_key(&config)?;
        let all_scopes = vec![mapping.name.clone()];
        Ok(Self {
            mapping,
            config,
            adapter,
            mailer,
            clock,
            all_scopes,
            marker: std::marker::PhantomData,
        })
    }

    /// Override the sibling scopes sharing the sign-out-all behavior.
    #[must_use]
    pub fn with_all_scopes(mut self, scopes: Vec<String>) -> Self {
        self.all_scopes = scopes;
        self
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
        (_, "new") => mr.get(new_handler),
        ("password", "edit") => mr.get(passwords_edit),
        ("registration", "edit") => mr.get(registrations_edit::<M, A, L>),
        ("registration", "cancel") => mr.get(registrations_cancel),
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
pub struct DeviseParams(Map<String, JsonValue>);

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

fn errors_json(errors: &ValidationErrors) -> JsonValue {
    let mut map = Map::new();
    for (field, message) in errors.full_messages() {
        if let Some(list) = map
            .entry(field)
            .or_insert_with(|| JsonValue::Array(Vec::new()))
            .as_array_mut()
        {
            list.push(JsonValue::String(message));
        }
    }
    JsonValue::Object(map)
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
    flash_redirect(&st.mapping.sign_in_path(), key)
}

/// Unauthenticated gate for owner-only controller actions (Devise
/// `authenticate_<scope>!` semantics).
fn unauthenticated_response<M, A, L>(
    auth_request: &AuthRequest,
    st: &DeviseWebState<M, A, L>,
) -> Response {
    auth_fail(auth_request, st, "unauthenticated")
}

/// Validation failure: HTML re-render 422 / JSON 422 with keyed errors.
fn invalid_response(auth_request: &AuthRequest, errors: &ValidationErrors) -> Response {
    if wants_json(auth_request) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            axum::Json(serde_json::json!({ "errors": errors_json(errors) })),
        )
            .into_response();
    }
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        [("content-type", "text/html; charset=utf-8")],
        format!(
            "Form errors: {}",
            serde_json::to_string(&errors_json(errors)).unwrap_or_else(|_| "{}".to_string())
        ),
    )
        .into_response()
}

/// Scopes that share this middleware run: the state's own scope plus the
/// declared siblings (tests wire one scope; multi-scope apps pass the full
/// list through [`DeviseWebState::with_all_scopes`]).
fn all_scope_names<M, A, L>(st: &DeviseWebState<M, A, L>) -> Vec<String> {
    if st.all_scopes.is_empty() {
        vec![st.mapping.name.clone()]
    } else {
        st.all_scopes.clone()
    }
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

// ============================================================================
// Controllers (D-14)
// ============================================================================

async fn new_handler() -> Response {
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
    Extension(auth_request): Extension<AuthRequest>,
    params: DeviseParams,
) -> Response
where
    M: FullDeviseModel,
    A: OrmAdapter<M> + Send + Sync + 'static,
    L: Mailer<M> + 'static,
{
    let singular = st.mapping.singular.clone();
    let scope = st.mapping.name.clone();
    let params = body_map(params.0, &singular);
    let email = param_str(&params, "email").to_string();
    let password = param_str(&params, "password").to_string();
    let remember = params
        .get("remember_me")
        .and_then(JsonValue::as_str)
        .is_some_and(rememberable::is_true_value);

    let mut conditions = Conditions::new();
    conditions.insert("email", AdapterValue::String(email));
    let Some(mut record) =
        M::find_for_authentication(&conditions, st.adapter.as_ref(), &st.config).await
    else {
        return auth_fail(&auth_request, &st, "invalid");
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
            return auth_fail(&auth_request, &st, "locked");
        }
        LockAttemptOutcome::FailedIncremented => {
            let key = if record.last_attempt(&st.config) && st.config.last_attempt_warning {
                "last_attempt"
            } else {
                "invalid"
            };
            return auth_fail(&auth_request, &st, key);
        }
        LockAttemptOutcome::Authenticated => {}
    }

    // Devise warden `after_set_user` lockable hook: zero the counter on a
    // successful sign-in (durable; the hook owns only the memo copy).
    drop(record.reset_failed_attempts(st.adapter.as_ref()).await);

    if !record.active_for_authentication() {
        return auth_fail(&auth_request, &st, record.inactive_message());
    }

    // Trackable: shift current→last, stamp now + socket peer (D-11), and
    // persist durably (the hook owns only the memo copy).
    record.update_tracked_fields(
        st.clock.now(),
        &auth_request.peer_addr.clone().unwrap_or_default(),
    );
    let fields = HashMap::from([
        (
            "sign_in_count".to_string(),
            AdapterValue::Integer(i64::try_from(record.sign_in_count()).unwrap_or(i64::MAX)),
        ),
        (
            "current_sign_in_at".to_string(),
            record
                .current_sign_in_at()
                .map_or(AdapterValue::Null, |at| {
                    AdapterValue::String(at.to_rfc3339())
                }),
        ),
        (
            "last_sign_in_at".to_string(),
            record.last_sign_in_at().map_or(AdapterValue::Null, |at| {
                AdapterValue::String(at.to_rfc3339())
            }),
        ),
        (
            "current_sign_in_ip".to_string(),
            record
                .current_sign_in_ip()
                .map_or(AdapterValue::Null, |ip| {
                    AdapterValue::String(ip.to_string())
                }),
        ),
        (
            "last_sign_in_ip".to_string(),
            record.last_sign_in_ip().map_or(AdapterValue::Null, |ip| {
                AdapterValue::String(ip.to_string())
            }),
        ),
    ]);
    drop(st.adapter.update_columns(&record.to_key(), &fields).await);

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
        flash_redirect(&target, "signed_in")
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
        flash_redirect("/", "signed_out")
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
    Extension(auth_request): Extension<AuthRequest>,
    params: DeviseParams,
) -> Response
where
    M: FullDeviseModel,
    A: OrmAdapter<M, New = M> + Send + Sync + 'static,
    L: Mailer<M> + 'static,
{
    let singular = st.mapping.singular.clone();
    let params = body_map(params.0, &singular);
    let mut record = M::new_with_session(&params, &JsonValue::Null, &st.config);

    let mut errors = record.validate(&st.config);
    record
        .validate_email_uniqueness(st.adapter.as_ref(), &mut errors)
        .await;
    if !errors.is_empty() {
        record.clean_up_passwords();
        return invalid_response(&auth_request, &errors);
    }
    let Ok(mut saved) = st.adapter.create(record).await else {
        return internal_error();
    };
    // Devise confirmable `after_commit :send_on_create_confirmation_instructions`.
    if saved.confirmation_required() {
        if let Err(e) = saved
            .send_confirmation_instructions(
                st.adapter.as_ref(),
                st.mailer.as_ref(),
                &st.config,
                st.clock.as_ref(),
            )
            .await
        {
            eprintln!("send_confirmation_instructions: {e:?}");
        }
    }
    if let Some(message) = saved.post_sign_up_message() {
        let key = format!("signed_up_but_{message}");
        if wants_json(&auth_request) {
            (
                StatusCode::CREATED,
                axum::Json(serde_json::json!({ "signed_up": true, "inactive": message })),
            )
                .into_response()
        } else {
            flash_redirect(&st.mapping.sign_in_path(), &key)
        }
    } else {
        let (key, salt) = saved.session_pair();
        let scope = st.mapping.name.clone();
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
            flash_redirect("/", "signed_up")
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
    let mut params = body_map(params.0, &singular);

    if let Err(errors) = record.update_with_password(&mut params, &st.config) {
        record.clean_up_passwords();
        return invalid_response(&auth_request, &errors);
    }

    let mut errors = record.validate(&st.config);
    record
        .validate_email_uniqueness(st.adapter.as_ref(), &mut errors)
        .await;
    if !errors.is_empty() {
        record.clean_up_passwords();
        return invalid_response(&auth_request, &errors);
    }

    let fields = HashMap::from([
        (
            "email".to_string(),
            AdapterValue::String(record.email_value().unwrap_or_default().to_string()),
        ),
        (
            "encrypted_password".to_string(),
            AdapterValue::String(record.encrypted_password().unwrap_or_default().to_string()),
        ),
    ]);
    let Ok(persisted) = st.adapter.update_columns(&record.to_key(), &fields).await else {
        return internal_error();
    };

    // D-03/T-08-09: account-update renewal — bypass re-sign-in with the
    // fresh record (salt now tracks the new password).
    if record.sign_in_after_change_password(&st.config) {
        let (key, salt) = AnyDeviseModel::session_pair(&persisted);
        drop(bridge::bypass_sign_in_and_renew(&session, &scope, &key, &salt).await);
        rotate_csrf_token(&session, &scope, &st.config).await;
    }
    if wants_json(&auth_request) {
        axum::Json(serde_json::json!({ "updated": true })).into_response()
    } else {
        flash_redirect("/", "updated")
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
    drop(bridge::sign_out_and_renew(&session, &scope).await);
    rotate_csrf_token(&session, &scope, &st.config).await;
    if wants_json(&auth_request) {
        StatusCode::NO_CONTENT.into_response()
    } else {
        flash_redirect("/", "destroyed")
    }
}

async fn registrations_cancel() -> Response {
    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        "cancel",
    )
        .into_response()
}

// ============================================================================
// Passwords controller (RCV / PasswordsController)
// ============================================================================

async fn passwords_create<M, A, L>(
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
        let key = if st.config.paranoid && !resource.is_valid() {
            "send_paranoid_instructions"
        } else {
            "send_instructions"
        };
        return flash_redirect(&st.mapping.sign_in_path(), key);
    }
    invalid_response(&auth_request, &resource.errors)
}

async fn passwords_edit(Query(query): Query<HashMap<String, String>>) -> Response {
    // Devise `assert_reset_token_passed`.
    let token = query.get("reset_password_token").map_or("", String::as_str);
    if token.trim().is_empty() {
        return flash_redirect("/", "no_token");
    }
    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        "edit",
    )
        .into_response()
}

#[allow(clippy::too_many_lines)]
async fn passwords_update<M, A, L>(
    State(st): State<DeviseWebState<M, A, L>>,
    Extension(session): Extension<Session>,
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
    let outcome =
        M::reset_password_by_token(&attrs, st.adapter.as_ref(), &st.config, st.clock.as_ref())
            .await;
    let Ok(mut resource) = outcome else {
        return internal_error();
    };
    if !resource.is_valid() {
        return invalid_response(&auth_request, &resource.errors);
    }

    // Devise: unlock locked accounts on email-unlockable models.
    if resource.record.access_locked(&st.config, st.clock.as_ref()) {
        drop(resource.record.unlock_access(st.adapter.as_ref()).await);
    }

    if st.config.sign_in_after_reset_password && resource.record.active_for_authentication() {
        let scope = st.mapping.name.clone();
        let (key, salt) = AnyDeviseModel::session_pair(&resource.record);
        drop(bridge::insert_session_and_renew(&session, &scope, &key, &salt).await);
        rotate_csrf_token(&session, &scope, &st.config).await;
    }

    let key = if resource.record.active_for_authentication() {
        "updated"
    } else {
        "updated_not_active"
    };
    if wants_json(&auth_request) {
        (
            StatusCode::OK,
            axum::Json(serde_json::json!({ "reset": true, "key": key })),
        )
            .into_response()
    } else {
        flash_redirect("/", key)
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
        return flash_redirect(&st.mapping.sign_in_path(), "confirmed");
    }
    invalid_response(&auth_request, &resource.errors)
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
    if resource.is_valid() {
        if wants_json(&auth_request) {
            return (
                StatusCode::CREATED,
                axum::Json(serde_json::json!({ "sent": true })),
            )
                .into_response();
        }
        return flash_redirect(&st.mapping.sign_in_path(), "send_instructions");
    }
    invalid_response(&auth_request, &resource.errors)
}

// ============================================================================
// Unlocks controller (LCK / UnlocksController) — registered only when the
// unlock strategy includes email (the dispatch-time gate in
// `devise_for_router`).
// ============================================================================

async fn unlocks_show<M, A, L>(
    State(st): State<DeviseWebState<M, A, L>>,
    Extension(auth_request): Extension<AuthRequest>,
    Query(query): Query<HashMap<String, String>>,
) -> Response
where
    M: FullDeviseModel,
    A: OrmAdapter<M> + Send + Sync + 'static,
    L: Mailer<M> + 'static,
{
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
        return flash_redirect(&st.mapping.sign_in_path(), "unlocked");
    }
    invalid_response(&auth_request, &resource.errors)
}

async fn unlocks_create<M, A, L>(
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
    if resource.is_valid() {
        if wants_json(&auth_request) {
            return (
                StatusCode::CREATED,
                axum::Json(serde_json::json!({ "sent": true })),
            )
                .into_response();
        }
        return flash_redirect(&st.mapping.sign_in_path(), "send_instructions");
    }
    invalid_response(&auth_request, &resource.errors)
}
