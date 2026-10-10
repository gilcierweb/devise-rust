//! Route registration — `devise_for_users` config fn translating core
//! [`RouteSpec`](devise_rust::scope::RouteSpec) data into an actix-web
//! [`Scope`] plus the five controller groups (sessions, registrations,
//! passwords, confirmations, unlocks) per D-14.
//!
//! ## Ordering / filtering (D-12 / D-13)
//!
//! The actix scope iterates [`Mapping::route_specs`] verbatim — `only` /
//! `skip` / `path_names` / `sign_out_via` are all already baked into the
//! core table and are NEVER re-filtered here. The single dispatch-time gate
//! mirrors Devise's `routes.rb` unlock guard: unlock routes vanish when the
//! configured unlock strategy excludes `email`.
//!
//! ## Response split (D-15)
//!
//! Navigational (HTML-accepting) requests get Devise's 302 + flash cookie
//! semantics; JSON callers get status codes (`200`/`201`/`204`/`401`/`422`)
//! with symbolic error keys in the body (en.yml symbols, never values —
//! T-08-10).

#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::future_not_send)]
#![allow(clippy::missing_panics_doc)]

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use actix_session::Session;
use actix_web::cookie::{CookieJar, Key};
use actix_web::{Either, HttpMessage, HttpRequest, HttpResponse, Scope, web};
use devise_rust::adapter::{Conditions, OrmAdapter, Value as AdapterValue};
use devise_rust::config::DeviseConfig;
use devise_rust::confirmable::Confirmable;
use devise_rust::error::ValidationErrors;
use devise_rust::lockable::{self, LockAttemptOutcome, Lockable};
use devise_rust::mailer::Mailer;
use devise_rust::model::{Recoverable, Registerable, Validatable};
use devise_rust::rememberable::{self, RememberCookieOp, Rememberable, remember_cookie_key};
use devise_rust::scope::{Mapping, RouteSpec};
use devise_rust::time::Clock;
use serde_json::{Map, Value as JsonValue};

use crate::bridge::{
    bypass_sign_in_and_renew_sync, fetch_session_with_salt, insert_session_and_renew_sync,
    sign_out_all_scopes_and_renew_sync, sign_out_and_renew,
};
use crate::callbacks::rotate_csrf_token;

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

/// Shared application state for a `devise_for_users` scope.
pub struct DeviseWebState<M, A, L> {
    /// Route mapping the scope was built from.
    pub mapping: Mapping,
    /// Devise configuration (shared `Arc` with the middleware).
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

/// Translate a core [`RouteSpec`] table out of a [`Mapping`].
#[must_use]
pub fn route_specs_for_mapping(mapping: &Mapping) -> Vec<RouteSpec> {
    mapping.route_specs()
}

/// Register the scope's full Devise route table as an actix [`Scope`]
/// mounted at `mapping.full_path()`.
///
/// Plain config fn shape per D-12: consumers add it via
/// `.service(routes::devise_for_users(state))`. The route table is the core
/// `RouteSpec` data with `only`/`skip`/`path_names`/`sign_out_via` already
/// honored; PATCH and PUT both reach the update handlers (D-13).
pub fn devise_for_users<M, A, L>(state: web::Data<DeviseWebState<M, A, L>>) -> Scope
where
    M: FullDeviseModel,
    A: OrmAdapter<M, New = M> + Send + Sync + 'static,
    L: Mailer<M> + 'static,
{
    let mapping = &state.mapping;
    let full_path = mapping.full_path();
    let mut scope = web::scope(&full_path);

    // Group specs by path so PATCH+PUT updates (and registration root verbs)
    // share one `Resource` — actix rejects duplicate resource patterns.
    let mut by_path: BTreeMap<String, Vec<RouteSpec>> = BTreeMap::new();
    for spec in mapping.route_specs() {
        if spec.name.contains("unlock")
            && !lockable::unlock_strategy_enabled_for("email", &state.config)
        {
            continue;
        }
        let rel = spec
            .path
            .strip_prefix(&full_path)
            .map_or_else(|| spec.path.clone(), str::to_string);
        by_path.entry(rel).or_default().push(spec);
    }

    for (rel, specs) in by_path {
        let mut resource = web::resource(rel.clone());
        for spec in specs {
            resource = match (spec.method.as_str(), spec.action.as_str()) {
                (_, "new") => resource.route(method_guard(&spec.method).to(new_handler::<M, A, L>)),
                (_, "create") => {
                    if spec.name.contains("session") {
                        resource.route(method_guard(&spec.method).to(sessions_create::<M, A, L>))
                    } else if spec.name.contains("password") {
                        resource.route(method_guard(&spec.method).to(passwords_create::<M, A, L>))
                    } else if spec.name.contains("confirmation") {
                        resource
                            .route(method_guard(&spec.method).to(confirmations_create::<M, A, L>))
                    } else if spec.name.contains("unlock") {
                        resource.route(method_guard(&spec.method).to(unlocks_create::<M, A, L>))
                    } else {
                        resource
                            .route(method_guard(&spec.method).to(registrations_create::<M, A, L>))
                    }
                }
                (_, "destroy") => {
                    if spec.name.contains("session") {
                        resource.route(method_guard(&spec.method).to(sessions_destroy::<M, A, L>))
                    } else {
                        resource.route(method_guard(&spec.method).to(registrations_destroy::<
                            M,
                            A,
                            L,
                        >))
                    }
                }
                (_, "edit") => {
                    if spec.name.contains("password") {
                        resource.route(method_guard(&spec.method).to(passwords_edit::<M, A, L>))
                    } else {
                        resource.route(method_guard(&spec.method).to(registrations_edit::<M, A, L>))
                    }
                }
                (_, "update") => {
                    if spec.name.contains("password") {
                        resource.route(method_guard(&spec.method).to(passwords_update::<M, A, L>))
                    } else {
                        resource
                            .route(method_guard(&spec.method).to(registrations_update::<M, A, L>))
                    }
                }
                (_, "cancel") => {
                    resource.route(method_guard(&spec.method).to(registrations_cancel::<M, A, L>))
                }
                (_, "show") => {
                    if spec.name.contains("confirmation") {
                        resource.route(method_guard(&spec.method).to(confirmations_show::<M, A, L>))
                    } else {
                        resource.route(method_guard(&spec.method).to(unlocks_show::<M, A, L>))
                    }
                }
                _ => resource,
            };
        }
        scope = scope.service(resource);
    }
    scope.app_data(state)
}

/// HTTP method guard for a core spec method string (never hand-built paths).
fn method_guard(method: &str) -> actix_web::Route {
    match method {
        "GET" => web::get(),
        "POST" => web::post(),
        "PATCH" => web::patch(),
        "PUT" => web::put(),
        _ => web::delete(),
    }
}

// ============================================================================
// Controller support
// ============================================================================

type FormOrJson = Either<web::Form<HashMap<String, String>>, web::Json<JsonValue>>;

/// Normalize the request body into one flat params map. Devise-sign-in
/// params arrive scoped (`user[email]=…` form-encoding or a nested JSON
/// object under the scope singular); both collapse to flat keys here.
fn body_map(body: Option<FormOrJson>, singular: &str) -> Map<String, JsonValue> {
    let raw: Map<String, JsonValue> = match body {
        Some(Either::Left(form)) => form
            .into_inner()
            .into_iter()
            .map(|(k, v)| (k, JsonValue::String(v)))
            .collect(),
        Some(Either::Right(json)) => json.into_inner().as_object().cloned().unwrap_or_default(),
        None => Map::new(),
    };
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
fn wants_json(req: &HttpRequest) -> bool {
    let accept_is_json = req
        .headers()
        .get(actix_web::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("application/json"));
    req.content_type().contains("application/json") || accept_is_json
}

/// Devise flash: delivered as a `devise.flash` cookie (the session jar
/// rounds it through the derived key on the next request).
fn flash_redirect(location: &str, flash_key: &str) -> HttpResponse {
    let mut response = HttpResponse::Found()
        .insert_header((actix_web::http::header::LOCATION, location))
        .finish();
    let mut cookie =
        actix_web::cookie::Cookie::new("devise.flash".to_string(), flash_key.to_string());
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_same_site(actix_web::cookie::SameSite::Lax);
    response.add_cookie(&cookie).ok();
    response
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
/// JSON → 401 with the symbolic key (never values, T-08-10).
fn auth_fail(req: &HttpRequest, mapping: &Mapping, key: &str) -> HttpResponse {
    if wants_json(req) {
        return HttpResponse::Unauthorized().json(serde_json::json!({ "error": key }));
    }
    flash_redirect(&mapping.sign_in_path(), key)
}

/// Unauthenticated gate for owner-only controller actions (edit/update/
/// destroy registration): Devise `authenticate_<scope>!` semantics.
fn unauthenticated_response(req: &HttpRequest, mapping: &Mapping) -> HttpResponse {
    auth_fail(req, mapping, "unauthenticated")
}

/// Validation failure: HTML re-render 422 / JSON 422 with keyed errors.
fn invalid_response(req: &HttpRequest, errors: &ValidationErrors) -> HttpResponse {
    if wants_json(req) {
        return HttpResponse::UnprocessableEntity()
            .json(serde_json::json!({ "errors": errors_json(errors) }));
    }
    HttpResponse::UnprocessableEntity()
        .content_type("text/html; charset=utf-8")
        .body(format!(
            "Form errors: {}",
            serde_json::to_string(&errors_json(errors)).unwrap_or_else(|_| "{}".to_string())
        ))
}

/// Drain a [`RememberCookieOp`] onto the response through the signed jar
/// (D-05 transport, single derived key — D-02).
fn drain_remember_op(response: &mut HttpResponse, key: &Key, op: &RememberCookieOp) {
    let mut jar = CookieJar::new();
    crate::remember::apply_op(&mut jar.signed_mut(key), op);
    let drained: Vec<_> = jar.delta().cloned().collect();
    for cookie in drained {
        let owned: actix_web::cookie::Cookie<'static> = cookie.into_owned();
        response.add_cookie(&owned).ok();
    }
}

/// Success redirect target after sign-in: stored location (same-host
/// parsed via core validator) or the app root.
fn after_sign_in_target(session: &Session, scope: &str) -> String {
    let key = devise_rust::failure::stored_location_key(scope);
    if let Some(raw) = session.get::<String>(&key).ok().flatten() {
        session.remove(&key);
        if let Some(target) = devise_rust::request::AuthRequest::parse_stored_uri(&raw) {
            return target;
        }
    }
    "/".to_string()
}

// ============================================================================
// Controllers (D-14)
// ============================================================================

#[allow(clippy::extra_unused_type_parameters)] // monomorphized per route bundle
async fn new_handler<M, A, L>() -> HttpResponse
where
    M: FullDeviseModel,
    A: OrmAdapter<M> + Send + Sync,
    L: Mailer<M>,
{
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body("form")
}

#[allow(clippy::too_many_lines)]
async fn sessions_create<M, A, L>(
    req: HttpRequest,
    session: Session,
    state: web::Data<DeviseWebState<M, A, L>>,
    body: Option<FormOrJson>,
) -> HttpResponse
where
    M: FullDeviseModel,
    A: OrmAdapter<M> + Send + Sync,
    L: Mailer<M>,
{
    let singular = state.mapping.singular.clone();
    let scope = state.mapping.name.clone();
    let params = body_map(body, &singular);
    let email = param_str(&params, "email").to_string();
    let password = param_str(&params, "password").to_string();
    let remember = params
        .get("remember_me")
        .and_then(JsonValue::as_str)
        .is_some_and(rememberable::is_true_value);

    let mut conditions = Conditions::new();
    conditions.insert("email", AdapterValue::String(email));
    let Some(mut record) =
        M::find_for_authentication(&conditions, state.adapter.as_ref(), &state.config).await
    else {
        return auth_fail(&req, &state.mapping, "invalid");
    };

    let password_ok = record
        .as_password_verifiable()
        .is_some_and(|v| v.valid_password(&password, &state.config));

    let Ok(outcome) = record
        .apply_failed_attempt(
            password_ok,
            state.adapter.as_ref(),
            state.mailer.as_ref(),
            &state.config,
            state.clock.as_ref(),
        )
        .await
    else {
        return HttpResponse::InternalServerError().finish();
    };
    match outcome {
        LockAttemptOutcome::Locked => {
            return auth_fail(&req, &state.mapping, "locked");
        }
        LockAttemptOutcome::FailedIncremented => {
            let key = if record.last_attempt(&state.config) && state.config.last_attempt_warning {
                "last_attempt"
            } else {
                "invalid"
            };
            return auth_fail(&req, &state.mapping, key);
        }
        LockAttemptOutcome::Authenticated => {}
    }

    // Devise warden `after_set_user` lockable hook: zero the counter on a
    // successful sign-in.
    drop(record.reset_failed_attempts(state.adapter.as_ref()).await);

    if !record.active_for_authentication() {
        return auth_fail(&req, &state.mapping, record.inactive_message());
    }

    // Trackable: shift current→last, stamp now + peer IP (D-11: socket only).
    {
        let now = state.clock.now();
        let peer = req
            .connection_info()
            .peer_addr()
            .map(str::to_string)
            .unwrap_or_default();
        record.update_tracked_fields(now, &peer);
        let fields = HashMap::from([
            (
                "sign_in_count".to_string(),
                AdapterValue::Integer(i64::try_from(record.sign_in_count()).unwrap_or(i64::MAX)),
            ),
            (
                "current_sign_in_at".to_string(),
                record
                    .current_sign_in_at()
                    .map_or(AdapterValue::Null, |t| AdapterValue::String(t.to_rfc3339())),
            ),
            (
                "last_sign_in_at".to_string(),
                record
                    .last_sign_in_at()
                    .map_or(AdapterValue::Null, |t| AdapterValue::String(t.to_rfc3339())),
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
        drop(
            state
                .adapter
                .update_columns(&record.to_key(), &fields)
                .await,
        );
    }

    let (key, salt) = record.session_pair();
    if insert_session_and_renew_sync(&session, &scope, &key, &salt).is_err() {
        return HttpResponse::InternalServerError().finish();
    }
    rotate_csrf_token(&session, &scope, &state.config);

    let mut response = if wants_json(&req) {
        HttpResponse::Ok().json(serde_json::json!({ "signed_in": true }))
    } else {
        let target = after_sign_in_target(&session, &scope);
        flash_redirect(&target, "signed_in")
    };

    if remember
        && record
            .remember_me(state.adapter.as_ref(), state.clock.as_ref())
            .await
            .is_ok()
    {
        let value = record
            .rememberable_value()
            .unwrap_or_else(|_| record.authenticatable_salt().unwrap_or_default());
        let (cookie_key, cookie_value, generated_at) = rememberable::build_cookie_triple(
            &record.to_key().to_string(),
            &value,
            state.clock.as_ref(),
        );
        let op = RememberCookieOp::Set {
            scope: scope.clone(),
            key: remember_cookie_key(&scope, &state.config),
            value: rememberable::encode_cookie_value(&cookie_key, &cookie_value, &generated_at),
            attrs: crate::remember::attrs_for_scope(&scope, &state.config, state.clock.as_ref()),
        };
        if let Ok(jar_key) = crate::remember::derive_remember_key(&state.config) {
            drain_remember_op(&mut response, &jar_key, &op);
        }
    }
    response
}

async fn sessions_destroy<M, A, L>(
    req: HttpRequest,
    session: Session,
    state: web::Data<DeviseWebState<M, A, L>>,
) -> HttpResponse
where
    M: FullDeviseModel,
    A: OrmAdapter<M> + Send + Sync,
    L: Mailer<M>,
{
    let scope = state.mapping.name.clone();

    // forget_me on the current record (T-08-07), then sign out.
    let mut clear_op = None;
    if let Some(key) =
        fetch_session_with_salt::<A, M>(&session, &scope, state.adapter.as_ref()).await
    {
        if let Ok(Some(mut record)) = state.adapter.get(&key).await {
            if record
                .forget_me(state.adapter.as_ref(), &state.config)
                .await
                .is_ok()
            {
                clear_op = Some(crate::remember::forget_op(&scope, &state.config));
            }
        }
    }

    let sign_out = if state.config.sign_out_all_scopes {
        let scopes = all_scope_names(&state);
        sign_out_all_scopes_and_renew_sync(&session, &scopes)
    } else {
        sign_out_and_renew(&session, &scope)
    };
    if sign_out.is_err() {
        return HttpResponse::InternalServerError().finish();
    }
    rotate_csrf_token(&session, &scope, &state.config);

    let mut response = if wants_json(&req) {
        HttpResponse::NoContent().finish()
    } else {
        flash_redirect("/", "signed_out")
    };
    if let (Some(op), Ok(jar_key)) = (
        clear_op,
        crate::remember::derive_remember_key(&state.config),
    ) {
        drain_remember_op(&mut response, &jar_key, &op);
    }
    response
}

/// Scopes that share this middleware run: the state's own scope plus the
/// middleware registry (tests wire one scope; multi-scope apps pass the
/// full list through [`DeviseWebState::all_scopes`]).
fn all_scope_names<M, A, L>(state: &DeviseWebState<M, A, L>) -> Vec<String> {
    if state.all_scopes.is_empty() {
        vec![state.mapping.name.clone()]
    } else {
        state.all_scopes.clone()
    }
}

// ============================================================================
// Registrations controller (REGS / RegistrationsController)
// ============================================================================

/// Load the currently-signed-in record for `scope` (warden fetch semantics
/// via the bridge salt check).
async fn current_record<M, A, L>(
    session: &Session,
    state: &DeviseWebState<M, A, L>,
    scope: &str,
) -> Option<M>
where
    M: FullDeviseModel,
    A: OrmAdapter<M> + Send + Sync,
    L: Mailer<M>,
{
    let key = fetch_session_with_salt::<A, M>(session, scope, state.adapter.as_ref()).await?;
    state.adapter.get(&key).await.ok().flatten()
}

async fn registrations_edit<M, A, L>(
    req: HttpRequest,
    session: Session,
    state: web::Data<DeviseWebState<M, A, L>>,
) -> HttpResponse
where
    M: FullDeviseModel,
    A: OrmAdapter<M> + Send + Sync,
    L: Mailer<M>,
{
    if current_record(&session, &state, &state.mapping.name)
        .await
        .is_none()
    {
        return unauthenticated_response(&req, &state.mapping);
    }
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body("edit")
}

async fn registrations_create<M, A, L>(
    req: HttpRequest,
    session: Session,
    state: web::Data<DeviseWebState<M, A, L>>,
    body: Option<FormOrJson>,
) -> HttpResponse
where
    M: FullDeviseModel,
    A: OrmAdapter<M, New = M> + Send + Sync,
    L: Mailer<M>,
{
    let singular = state.mapping.singular.clone();
    let params = body_map(body, &singular);
    let mut record = M::new_with_session(&params, &JsonValue::Null, &state.config);

    let mut errors = record.validate(&state.config);
    record
        .validate_email_uniqueness(state.adapter.as_ref(), &mut errors)
        .await;
    if !errors.is_empty() {
        record.clean_up_passwords();
        return invalid_response(&req, &errors);
    }
    let Ok(mut saved) = state.adapter.create(record).await else {
        return HttpResponse::InternalServerError().finish();
    };
    // Devise confirmable `after_commit :send_on_create_confirmation_instructions`.
    if saved.confirmation_required() {
        if let Err(e) = saved
            .send_confirmation_instructions(
                state.adapter.as_ref(),
                state.mailer.as_ref(),
                &state.config,
                state.clock.as_ref(),
            )
            .await
        {
            eprintln!("send_confirmation_instructions: {e:?}");
        }
    }
    if let Some(message) = saved.post_sign_up_message() {
        let key = format!("signed_up_but_{message}");
        if wants_json(&req) {
            HttpResponse::Created()
                .json(serde_json::json!({ "signed_up": true, "inactive": message }))
        } else {
            flash_redirect(&state.mapping.sign_in_path(), &key)
        }
    } else {
        let (key, salt) = saved.session_pair();
        let scope = state.mapping.name.clone();
        if insert_session_and_renew_sync(&session, &scope, &key, &salt).is_err() {
            return HttpResponse::InternalServerError().finish();
        }
        rotate_csrf_token(&session, &scope, &state.config);
        if wants_json(&req) {
            HttpResponse::Created().json(serde_json::json!({ "signed_up": true }))
        } else {
            flash_redirect("/", "signed_up")
        }
    }
}

async fn registrations_update<M, A, L>(
    req: HttpRequest,
    session: Session,
    state: web::Data<DeviseWebState<M, A, L>>,
    body: Option<FormOrJson>,
) -> HttpResponse
where
    M: FullDeviseModel,
    A: OrmAdapter<M> + Send + Sync,
    L: Mailer<M>,
{
    let scope = state.mapping.name.clone();
    let Some(mut record) = current_record(&session, &state, &scope).await else {
        return unauthenticated_response(&req, &state.mapping);
    };
    let singular = state.mapping.singular.clone();
    let mut params = body_map(body, &singular);

    if let Err(errors) = record.update_with_password(&mut params, &state.config) {
        record.clean_up_passwords();
        return invalid_response(&req, &errors);
    }

    let mut errors = record.validate(&state.config);
    record
        .validate_email_uniqueness(state.adapter.as_ref(), &mut errors)
        .await;
    if !errors.is_empty() {
        record.clean_up_passwords();
        return invalid_response(&req, &errors);
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
    let Ok(persisted) = state
        .adapter
        .update_columns(&record.to_key(), &fields)
        .await
    else {
        return HttpResponse::InternalServerError().finish();
    };

    // D-03/T-08-09: account-update renewal — bypass re-sign-in with the
    // fresh record (salt now tracks the new password).
    if record.sign_in_after_change_password(&state.config) {
        let (key, salt) = devise_rust::failure::AnyDeviseModel::session_pair(&persisted);
        drop(bypass_sign_in_and_renew_sync(&session, &scope, &key, &salt));
        rotate_csrf_token(&session, &scope, &state.config);
    }
    if wants_json(&req) {
        HttpResponse::Ok().json(serde_json::json!({ "updated": true }))
    } else {
        flash_redirect("/", "updated")
    }
}

async fn registrations_destroy<M, A, L>(
    req: HttpRequest,
    session: Session,
    state: web::Data<DeviseWebState<M, A, L>>,
) -> HttpResponse
where
    M: FullDeviseModel,
    A: OrmAdapter<M> + Send + Sync,
    L: Mailer<M>,
{
    let scope = state.mapping.name.clone();
    let Some(record) = current_record(&session, &state, &scope).await else {
        return unauthenticated_response(&req, &state.mapping);
    };
    drop(state.adapter.delete(&record.to_key()).await);
    drop(sign_out_and_renew(&session, &scope));
    rotate_csrf_token(&session, &scope, &state.config);
    if wants_json(&req) {
        HttpResponse::NoContent().finish()
    } else {
        flash_redirect("/", "destroyed")
    }
}

async fn registrations_cancel<M, A, L>(
    _req: HttpRequest,
    _state: web::Data<DeviseWebState<M, A, L>>,
) -> HttpResponse
where
    M: FullDeviseModel,
    A: OrmAdapter<M> + Send + Sync,
    L: Mailer<M>,
{
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body("cancel")
}

// ============================================================================
// Passwords controller (RCV / PasswordsController)
// ============================================================================

async fn passwords_create<M, A, L>(
    req: HttpRequest,
    state: web::Data<DeviseWebState<M, A, L>>,
    body: Option<FormOrJson>,
) -> HttpResponse
where
    M: FullDeviseModel,
    A: OrmAdapter<M, New = M> + Send + Sync,
    L: Mailer<M>,
{
    let singular = state.mapping.singular.clone();
    let attrs = body_map(body, &singular);
    let outcome = M::send_reset_password_instructions_for(
        &attrs,
        state.adapter.as_ref(),
        state.mailer.as_ref(),
        &state.config,
        state.clock.as_ref(),
    )
    .await;
    let Ok(resource) = outcome else {
        return HttpResponse::InternalServerError().finish();
    };
    if resource.is_valid() || state.config.paranoid {
        if wants_json(&req) {
            return HttpResponse::Created().json(serde_json::json!({ "sent": true }));
        }
        let key = if state.config.paranoid && !resource.is_valid() {
            "send_paranoid_instructions"
        } else {
            "send_instructions"
        };
        return flash_redirect(&state.mapping.sign_in_path(), key);
    }
    invalid_response(&req, &resource.errors)
}

async fn passwords_edit<M, A, L>(
    _req: HttpRequest,
    _state: web::Data<DeviseWebState<M, A, L>>,
    query: web::Query<HashMap<String, String>>,
) -> HttpResponse
where
    M: FullDeviseModel,
    A: OrmAdapter<M> + Send + Sync,
    L: Mailer<M>,
{
    // Devise `assert_reset_token_passed`.
    let token = query.get("reset_password_token");
    let token_str = token.map_or("", String::as_str);
    if token_str.trim().is_empty() {
        return flash_redirect("/", "no_token");
    }
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body("edit")
}

async fn passwords_update<M, A, L>(
    req: HttpRequest,
    session: Session,
    state: web::Data<DeviseWebState<M, A, L>>,
    body: Option<FormOrJson>,
) -> HttpResponse
where
    M: FullDeviseModel,
    A: OrmAdapter<M, New = M> + Send + Sync,
    L: Mailer<M>,
{
    let singular = state.mapping.singular.clone();
    let attrs = body_map(body, &singular);
    let outcome = M::reset_password_by_token(
        &attrs,
        state.adapter.as_ref(),
        &state.config,
        state.clock.as_ref(),
    )
    .await;
    let Ok(mut resource) = outcome else {
        return HttpResponse::InternalServerError().finish();
    };
    if !resource.is_valid() {
        return invalid_response(&req, &resource.errors);
    }

    // Devise: unlock locked accounts on email-unlockable models.
    if resource
        .record
        .access_locked(&state.config, state.clock.as_ref())
    {
        drop(resource.record.unlock_access(state.adapter.as_ref()).await);
    }

    if state.config.sign_in_after_reset_password && resource.record.active_for_authentication() {
        let scope = state.mapping.name.clone();
        let (key, salt) = devise_rust::failure::AnyDeviseModel::session_pair(&resource.record);
        drop(insert_session_and_renew_sync(&session, &scope, &key, &salt));
        rotate_csrf_token(&session, &scope, &state.config);
    }

    let key = if resource.record.active_for_authentication() {
        "updated"
    } else {
        "updated_not_active"
    };
    if wants_json(&req) {
        HttpResponse::Ok().json(serde_json::json!({ "reset": true, "key": key }))
    } else {
        flash_redirect("/", key)
    }
}

// ============================================================================
// Confirmations controller (CNF / ConfirmationsController)
// ============================================================================

async fn confirmations_show<M, A, L>(
    req: HttpRequest,
    state: web::Data<DeviseWebState<M, A, L>>,
    query: web::Query<HashMap<String, String>>,
) -> HttpResponse
where
    M: FullDeviseModel,
    A: OrmAdapter<M> + Send + Sync,
    L: Mailer<M>,
{
    let token = query.get("confirmation_token");
    let token_str = token.map_or("", String::as_str);
    let config_snapshot = state.config.clone();
    let validate = move |record: &M| record.validate(&config_snapshot);
    let outcome = M::confirm_by_token(
        Some(token_str),
        state.adapter.as_ref(),
        &state.config,
        state.clock.as_ref(),
        &validate,
    )
    .await;
    let Ok(resource) = outcome else {
        return HttpResponse::InternalServerError().finish();
    };
    if resource.is_valid() {
        if wants_json(&req) {
            return HttpResponse::Ok().json(serde_json::json!({ "confirmed": true }));
        }
        return flash_redirect(&state.mapping.sign_in_path(), "confirmed");
    }
    invalid_response(&req, &resource.errors)
}

async fn confirmations_create<M, A, L>(
    req: HttpRequest,
    state: web::Data<DeviseWebState<M, A, L>>,
    body: Option<FormOrJson>,
) -> HttpResponse
where
    M: FullDeviseModel,
    A: OrmAdapter<M, New = M> + Send + Sync,
    L: Mailer<M>,
{
    let singular = state.mapping.singular.clone();
    let attrs = body_map(body, &singular);
    let outcome = M::send_confirmation_instructions_for(
        &attrs,
        state.adapter.as_ref(),
        state.mailer.as_ref(),
        &state.config,
        state.clock.as_ref(),
    )
    .await;
    let Ok(resource) = outcome else {
        return HttpResponse::InternalServerError().finish();
    };
    if resource.is_valid() {
        if wants_json(&req) {
            return HttpResponse::Created().json(serde_json::json!({ "sent": true }));
        }
        return flash_redirect(&state.mapping.sign_in_path(), "send_instructions");
    }
    invalid_response(&req, &resource.errors)
}

// ============================================================================
// Unlocks controller (LCK / UnlocksController)
// ============================================================================

async fn unlocks_show<M, A, L>(
    req: HttpRequest,
    state: web::Data<DeviseWebState<M, A, L>>,
    query: web::Query<HashMap<String, String>>,
) -> HttpResponse
where
    M: FullDeviseModel,
    A: OrmAdapter<M> + Send + Sync,
    L: Mailer<M>,
{
    let token = query.get("unlock_token");
    let token_str = token.map_or("", String::as_str);
    let outcome =
        M::unlock_access_by_token(Some(token_str), state.adapter.as_ref(), &state.config).await;
    let Ok(resource) = outcome else {
        return HttpResponse::InternalServerError().finish();
    };
    if resource.is_valid() {
        if wants_json(&req) {
            return HttpResponse::Ok().json(serde_json::json!({ "unlocked": true }));
        }
        return flash_redirect(&state.mapping.sign_in_path(), "unlocked");
    }
    invalid_response(&req, &resource.errors)
}

async fn unlocks_create<M, A, L>(
    req: HttpRequest,
    state: web::Data<DeviseWebState<M, A, L>>,
    body: Option<FormOrJson>,
) -> HttpResponse
where
    M: FullDeviseModel,
    A: OrmAdapter<M> + Send + Sync,
    L: Mailer<M>,
{
    let singular = state.mapping.singular.clone();
    let attrs = body_map(body, &singular);
    let outcome = M::send_unlock_instructions_for(
        &attrs,
        state.adapter.as_ref(),
        state.mailer.as_ref(),
        &state.config,
        state.clock.as_ref(),
    )
    .await;
    let Ok(resource) = outcome else {
        return HttpResponse::InternalServerError().finish();
    };
    if resource.is_valid() {
        if wants_json(&req) {
            return HttpResponse::Created().json(serde_json::json!({ "sent": true }));
        }
        return flash_redirect(&state.mapping.sign_in_path(), "send_instructions");
    }
    invalid_response(&req, &resource.errors)
}
