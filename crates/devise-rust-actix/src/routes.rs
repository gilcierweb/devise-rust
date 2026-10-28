//! Route registration — `devise_for_users` config fn translating core
//! [`RouteSpec`] data into an actix-web
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
//! semantics; JSON callers get status codes (`200`/`201`/`204`/`401`) plus
//! the configured [`DeviseConfig::error_status`] (200 by default) on the
//! validation-failure renders, with symbolic error keys unchanged in the
//! body (en.yml symbols, never values — T-08-10).

#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::future_not_send)]
#![allow(clippy::missing_panics_doc)]

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use actix_session::Session;
use actix_web::cookie::{CookieJar, Key};
use actix_web::http::StatusCode;
use actix_web::{Either, HttpMessage, HttpRequest, HttpResponse, Scope, web};
use devise_rust::adapter::{Conditions, DeviseKey, OrmAdapter, Value as AdapterValue};
use devise_rust::config::DeviseConfig;
use devise_rust::confirmable::Confirmable;
use devise_rust::error::{ValidationErrors, errors_json};
use devise_rust::failure::{Failure, FailureRenderer, flash_keys, successfully_sent_key};
use devise_rust::lockable::{LockAttemptOutcome, Lockable};
use devise_rust::mailer::Mailer;
use devise_rust::model::{Recoverable, Registerable, Validatable};
use devise_rust::rememberable::{self, RememberCookieOp, Rememberable, remember_cookie_key};
use devise_rust::scope::{Mapping, RouteSpec, ScopeRegistry};
use devise_rust::time::Clock;
use serde_json::{Map, Value as JsonValue};
use std::str::FromStr;

use crate::bridge::{
    bypass_sign_in_and_renew_sync, expire_devise_data_sync, fetch_session_with_salt,
    insert_session_and_renew_sync, sign_out_all_scopes_and_renew_sync, sign_out_and_renew,
};
use crate::callbacks::rotate_csrf_token;
use crate::failure::ActixFailureRenderer;

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
    /// The scope registry the middleware runs with — the source
    /// `sign_out_all_scopes` iterates (Devise walks `Devise.mappings`,
    /// not the routes of the scope that happened to mount the action).
    pub scope_registry: Arc<ScopeRegistry>,
    /// ORM adapter for the scope's model.
    pub adapter: Arc<A>,
    /// Mailer for confirmation/reset/unlock instructions.
    pub mailer: Arc<L>,
    /// Clock for windows/ticks.
    pub clock: Arc<dyn Clock>,
    /// All scope names sharing the middleware run (legacy override; the
    /// registry above is the authoritative source — kept for callers that
    /// hand-roll a state without one).
    pub all_scopes: Vec<String>,
    /// Phantom marker: `M` pins the controller monomorphizations.
    pub marker: std::marker::PhantomData<fn() -> M>,
}

impl<M, A, L> Clone for DeviseWebState<M, A, L> {
    fn clone(&self) -> Self {
        Self {
            mapping: self.mapping.clone(),
            config: self.config.clone(),
            scope_registry: self.scope_registry.clone(),
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
    // Boot contract: Devise raises `raise_no_secret_key` at route
    // registration when the secret is missing — the same hard error here
    // (the route scope is built once, at `App` construction time).
    if let Err(error) = state.config.validate() {
        panic!("{error}");
    }
    let mapping = &state.mapping;
    let full_path = mapping.full_path();
    let mut scope = web::scope(&full_path);

    // Group specs by path so PATCH+PUT updates (and registration root verbs)
    // share one `Resource` — actix rejects duplicate resource patterns.
    // The table IS the core config-aware spec set
    // (`Mapping::route_specs_for`): `only` / `skip` / `path_names` /
    // `sign_out_via` and the unlock-strategy guard all live in core
    // (`routes.rb:394-399`), never re-filtered here (L). The omniauth legs
    // are excluded — they are mounted by `devise_omniauth_scope`, whose
    // `{provider}` captures need the dedicated mount order.
    let mut by_path: BTreeMap<String, Vec<RouteSpec>> = BTreeMap::new();
    for spec in mapping.route_specs_for(&state.config) {
        if spec.name.contains("omniauth") {
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
                (_, "new") => {
                    if spec.name.contains("registration") {
                        resource.route(method_guard(&spec.method).to(registrations_new::<M, A, L>))
                    } else {
                        resource.route(method_guard(&spec.method).to(new_handler::<M, A, L>))
                    }
                }
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

/// Devise `devise_parameter_sanitizer.sanitize(action)`
/// (`parameter_sanitizer.rb`): reduce the request's flat params map to the
/// action's permitted keys before any record is built from it (S7).
///
/// The defaults mirror Devise's initializer: `sign_in` =
/// `authentication_keys` + password + `remember_me`; `sign_up` =
/// `authentication_keys` + password + `password_confirmation`;
/// `account_update` = the same plus `current_password`. An unregistered
/// action is a `Config` error rendered as 500 (Devise's
/// `unknown_action!` raise), never a silent pass-through.
fn sanitized_body(
    config: &DeviseConfig,
    action: &str,
    body: Option<FormOrJson>,
    singular: &str,
) -> Result<Map<String, JsonValue>, HttpResponse> {
    let raw = body_map(body, singular);
    devise_rust::parameter::ParameterSanitizer::new(config)
        .sanitize(action, &raw)
        .map_err(|error| {
            // Devise raises NotImplementedError into Rails' 500 handler.
            let _ = error;
            HttpResponse::InternalServerError().finish()
        })
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

/// Devise flash: SESSION state, not a cookie (S11). The key rides the
/// signed actix-session jar for exactly one subsequent read
/// ([`bridge::take_flash`]) — the same lifetime Rails' flash hash has.
///
/// One flash helper for the whole crate (M): the controllers AND the
/// omniauth callbacks stage the bare I18n key through this fn.
pub(crate) fn flash_redirect(session: &Session, location: &str, flash_key: &str) -> HttpResponse {
    crate::bridge::set_flash(session, flash_key);
    HttpResponse::Found()
        .insert_header((actix_web::http::header::LOCATION, location))
        .finish()
}

/// Fail an authentication post through the typed failure renderer:
/// navigational requests stage the Devise flash key in the signed session
/// and render the redirect through [`ActixFailureRenderer`] (the same
/// renderer the extractors already use, replacing the hand-rolled 302);
/// JSON requests keep the symbolic-keyed 401 body (never values,
/// T-08-10). The flash key set is byte-identical to the old helper's.
///
/// The core [`Failure::NavigationalRedirect`] carries the raw key
/// directly because the lockable `last_attempt` warning lives outside
/// the [`devise_rust::failure::FailureReason`] vocabulary; the staged
/// key reaches the session unchanged either way.
fn auth_fail(
    req: &HttpRequest,
    session: &Session,
    mapping: &Mapping,
    key: &'static str,
) -> HttpResponse {
    if wants_json(req) {
        return HttpResponse::Unauthorized().json(serde_json::json!({ "error": key }));
    }
    // Stage the flash (session state, S11) BEFORE the render - the
    // renderer contract carries no session access, exactly like the
    // extractor call sites.
    crate::bridge::set_flash(session, key);
    let failure = Failure::NavigationalRedirect {
        location: mapping.sign_in_path(),
        flash_key: key,
        stored_location: None,
    };
    ActixFailureRenderer::new().render(&failure, mapping)
}

/// Unauthenticated gate for owner-only controller actions (edit/update/
/// destroy registration): Devise `authenticate_<scope>!` semantics.
fn unauthenticated_response(
    req: &HttpRequest,
    session: &Session,
    mapping: &Mapping,
) -> HttpResponse {
    auth_fail(req, session, mapping, "unauthenticated")
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
    req: &HttpRequest,
    errors: &ValidationErrors,
    status: StatusCode,
) -> HttpResponse {
    if wants_json(req) {
        return HttpResponse::build(status).json(serde_json::json!({
            "errors": errors_json(errors),
            "options": devise_rust::error::errors_options_json(errors),
        }));
    }
    HttpResponse::build(status)
        .content_type("text/html; charset=utf-8")
        .body(format!(
            "Form errors: {}",
            serde_json::to_string(&errors_json(errors)).unwrap_or_else(|_| "{}".to_string())
        ))
}

/// Drain a [`RememberCookieOp`] onto the response through the signed jar
/// (D-05 transport, single derived key — D-02).
fn drain_remember_op(
    response: &mut HttpResponse,
    key: &Key,
    op: &RememberCookieOp,
    config: &DeviseConfig,
    clock: &dyn Clock,
) {
    let mut jar = CookieJar::new();
    crate::remember::apply_op(&mut jar.signed_mut(key), op, config, clock);
    let drained: Vec<_> = jar.delta().cloned().collect();
    for cookie in drained {
        let owned: actix_web::cookie::Cookie<'static> = cookie.into_owned();
        response.add_cookie(&owned).ok();
    }
}

/// Devise `after_sign_in_path_for` (`controllers/helpers.rb`): stored
/// location (validated same-host path, consumed on read) → scope root
/// (`signed_in_root_path` — the mapping's full path) → `/`.
///
/// One home for the whole crate: the sessions controller, the
/// `require_no_authentication` guards, and the omniauth callback all
/// redirect through this precedence (the omniauth twin previously carried
/// its own reduced copy that fell back to `/` directly).
pub(crate) fn after_sign_in_target(session: &Session, mapping: &Mapping) -> String {
    let key = devise_rust::failure::stored_location_key(&mapping.name);
    if let Some(raw) = session.get::<String>(&key).ok().flatten() {
        session.remove(&key);
        if let Some(target) = devise_rust::request::AuthRequest::parse_stored_uri(&raw) {
            return target;
        }
    }
    // `signed_in_root_path`: the scope's root; `/` only for unmapped scopes.
    mapping.full_path()
}

/// Plain 303 redirect with no flash (Devise's `redirect_to` for actions like
/// registrations#cancel that carry no message).
fn redirect_to(location: &str) -> HttpResponse {
    HttpResponse::SeeOther()
        .insert_header(("location", location))
        .finish()
}

// ============================================================================
// Controllers (D-14)
// ============================================================================

/// Devise `require_no_authentication` (devise_controller.rb:116-132):
/// navigational requests authenticated by SESSION OR by a live remember
/// cookie are redirected home with the `already_authenticated` flash;
/// non-navigational (API) requests pass through, exactly like Devise's
/// `return unless is_navigational_format?`.
///
/// Devise's guard consults `warden.authenticate?` with the mapping's
/// NO-INPUT strategies (the rememberable strategy runs,
/// `strategies/rememberable.rb`) so a remembered visitor (session
/// dropped, remember cookie kept) is authenticated; the core
/// [`no_authentication_guard_passes`](devise_rust::helpers::no_authentication_guard_passes)
/// decision owns the rule and the five-condition cookie validation.
///
/// Mounted on sessions new/create (`sessions_controller.rb:4`), every
/// passwords action (`passwords_controller.rb:4`), every unlocks action
/// (`unlocks_controller.rb:4`), and registrations new/create/cancel
/// (`registrations_controller.rb:4`).
async fn require_no_authentication_response<M, A, L>(
    req: &HttpRequest,
    session: &Session,
    state: &DeviseWebState<M, A, L>,
) -> Option<HttpResponse>
where
    M: FullDeviseModel,
    A: OrmAdapter<M> + Send + Sync,
    L: Mailer<M>,
{
    if wants_json(req) {
        return None;
    }
    let scope = state.mapping.name.as_str();
    let session_present = scope_session_present(session, scope);
    let remember_triple = remember_triple_from(req, &state.config, scope);
    let adapter = state.adapter.clone();
    let authenticated = devise_rust::helpers::no_authentication_guard_passes(
        session_present,
        remember_triple,
        &state.config,
        state.clock.as_ref(),
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
    Some(flash_redirect(
        session,
        &after_sign_in_target(session, &state.mapping),
        flash_keys::ALREADY_AUTHENTICATED,
    ))
}

/// Read the signed remember cookie through the actix remember helper
/// (`read_cookie` over a `SignedJar` keyed by the Devise secret): yields
/// the verified `[key, value, generated_at]` triple only: a missing,
/// tampered, or stale cookie reads as `None` (anonymous, never a
/// failure). The cookie name is the `rememberable_options`-override-aware
/// [`remember_cookie_key`].
fn remember_triple_from(
    req: &HttpRequest,
    config: &DeviseConfig,
    scope: &str,
) -> Option<(String, String, String)> {
    let name = rememberable::remember_cookie_key(scope, config);
    let raw = req.cookie(&name)?.value().to_string();
    let key = crate::remember::derive_remember_key(config).ok()?;
    let mut jar = actix_web::cookie::CookieJar::new();
    jar.add_original(actix_web::cookie::Cookie::new(name.clone(), raw));
    match crate::remember::read_cookie(&jar.signed(&key), &name) {
        crate::remember::RememberRead::Valid {
            key,
            value,
            generated_at,
        } => Some((key, value, generated_at)),
        _ => None,
    }
}

/// The generic `new`-form handler: sessions#new, passwords#new, and
/// unlocks#new all render through here, and Devise guards ALL of them
/// (`sessions_controller.rb:4`, `passwords_controller.rb:4`,
/// `unlocks_controller.rb:4`): the guard runs before the form renders
/// (registrations#new carries it inside its own handler).
async fn new_handler<M, A, L>(
    req: HttpRequest,
    session: Session,
    state: web::Data<DeviseWebState<M, A, L>>,
) -> HttpResponse
where
    M: FullDeviseModel,
    A: OrmAdapter<M> + Send + Sync,
    L: Mailer<M>,
{
    if let Some(response) = require_no_authentication_response(&req, &session, &state).await {
        return response;
    }
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body("form")
}

/// `GET /{scope}/sign_up` — registrations#new carries Devise's
/// `require_no_authentication` guard (S13): a signed-in visitor is
/// redirected home instead of seeing a second sign-up form.
async fn registrations_new<M, A, L>(
    req: HttpRequest,
    session: Session,
    state: web::Data<DeviseWebState<M, A, L>>,
) -> HttpResponse
where
    M: FullDeviseModel,
    A: OrmAdapter<M> + Send + Sync,
    L: Mailer<M>,
{
    if let Some(response) = require_no_authentication_response(&req, &session, &state).await {
        return response;
    }
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
    // Devise `allow_params_authentication!` (sessions_controller.rb:5): the
    // ONLY request in the pipeline whose staged snapshot carries
    // `devise.allow_params_authentication = true`. The middleware defaults
    // the flag to false on every request (S4); the controller flips it for
    // its own sign-in run, exactly where Devise's prepend_before_action does.
    if let Some(staged) = req
        .extensions_mut()
        .get_mut::<devise_rust::request::AuthRequest>()
    {
        staged.flags.allow_params_authentication = true;
    }
    // Devise `require_no_authentication` (sessions_controller.rb:4): an
    // already authenticated request (session OR live remember cookie,
    // devise_controller.rb:116-132) is redirected home with
    // `already_authenticated` instead of re-authenticating (navigational
    // formats only, as in Devise).
    if let Some(response) = require_no_authentication_response(&req, &session, &state).await {
        return response;
    }
    // S7: `sign_in_params`: the `:sign_in` sanitizer decides what the
    // controller may read (`sessions_controller.rb:34-36`); the raw body
    // map stays available for the authentication-key lookup below (the
    // bridge flat spelling of the SAME permitted keys).
    // Devise's `unknown_action!` raise renders as the framework's 500.
    let raw_params = body_map(body, &singular);
    let Ok(params) = devise_rust::parameter::ParameterSanitizer::new(&state.config)
        .sanitize("sign_in", &raw_params)
    else {
        return HttpResponse::InternalServerError().finish();
    };
    let password = param_str(&params, "password").to_string();
    // Devise's sign-in form posts "1" (`TRUE_VALUES`); JSON clients send a
    // real boolean - the core helper accepts both shapes, the same rule
    // both frameworks now share.
    let remember = devise_rust::parameter::remember_me_from(&params);

    let mut conditions = Conditions::new();
    // Devise `find_for_database_authentication` looks the record up
    // through `config.authentication_keys` — email is only the DEFAULT key
    // (`database_authenticatable.rb`). Each value passes the single
    // normalization home the params filter and the write path share, and
    // arrives through the core `param_for` precedence (scoped bracket,
    // bridge flat, bare key) over the RAW body map, so the `user_email`
    // bridge form reaches the lookup here exactly like it does on axum:
    // every spelling of the CONFIGURED keys, nothing unconfigured.
    for key in &state.config.authentication_keys {
        let raw = devise_rust::parameter::param_for(&raw_params, &singular, key);
        let value = devise_rust::model::normalize_credential_value(
            &raw,
            key,
            &state.config.case_insensitive_keys,
            &state.config.strip_whitespace_keys,
        );
        conditions.insert(key.clone(), AdapterValue::String(value));
    }
    // Devise's second `parse_authentication_key_values` pass over the request
    // object's values (`strategies/authenticatable.rb:147-167`): the staged
    // snapshot the middleware built carries them, a same-named request value
    // overwrites the param condition, and a missing or blank required key
    // fails the parse. On failure the generic `invalid` failure is reported
    // (not `not_found_in_database`): no lookup ran, so nothing is known
    // about the account either way.
    let staged_snapshot = req
        .extensions()
        .get::<devise_rust::request::AuthRequest>()
        .cloned()
        .unwrap_or_else(|| {
            devise_rust::request::AuthRequest::new(
                devise_rust::request::HttpMethod::Post,
                req.path().to_string(),
            )
        });
    if !devise_rust::strategy::merge_request_keys(&mut conditions, &staged_snapshot, &state.config)
    {
        return auth_fail(&req, &session, &state.mapping, "invalid");
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
            &req,
            &session,
            &state.mapping,
            devise_rust::strategy::unknown_account_failure(&state.config),
        );
    }
    let Some(mut record) =
        M::find_for_authentication(&conditions, state.adapter.as_ref(), &state.config).await
    else {
        // Devise paranoid mitigation + the non-paranoid `:not_found_in_database`
        // branch (`strategies/database_authenticatable.rb:22-25`): the dummy
        // hash and the key rule live in core so both frameworks and the
        // strategy chain share one implementation.
        return auth_fail(
            &req,
            &session,
            &state.mapping,
            devise_rust::strategy::unknown_account_failure(&state.config),
        );
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
            // Same core rule as the incremented arm: under paranoid Devise
            // reports :invalid for a lock this attempt just triggered, so the
            // lock state cannot signal account existence
            // (`lockable.rb:127-131`).
            let key = record.lock_unauthenticated_message(&state.config, state.clock.as_ref());
            return auth_fail(&req, &session, &state.mapping, key);
        }
        LockAttemptOutcome::FailedIncremented => {
            // Devise's `unauthenticated_message` (lockable branch,
            // `lockable.rb:127-139`): paranoid-first, then locked, then
            // last-attempt warning. Core owns the rule; the controller just
            // renders its key (no hand-rolled duplicate here).
            let key = record.lock_unauthenticated_message(&state.config, state.clock.as_ref());
            return auth_fail(&req, &session, &state.mapping, key);
        }
        LockAttemptOutcome::Authenticated => {
            // Devise's database_authenticatable strategy fires
            // `after_database_authentication` immediately after the
            // successful password check (`strategies/database_authenticatable.rb`,
            // DBAU-07) — before any session work. The erased
            // `AnyDeviseModel` seam is the one apps override.
            devise_rust::failure::AnyDeviseModel::after_database_authentication(&record);
        }
    }

    // Devise `hooks/activatable.rb` include order (`models.rb`): the
    // activatable hook registers BEFORE the lockable hook, and its
    // `throw :warden` aborts the request before the lockable
    // `after_set_user` hook can run. A sign-in the activatable gate rejects
    // must therefore NOT persist the counter reset, or a failed attempt on an
    // inactive account would erase the brute-force history (IN-04).
    if !record.active_for_authentication() {
        return auth_fail(&req, &session, &state.mapping, record.inactive_message());
    }

    // Devise warden `after_set_user` lockable hook: zero the counter on a
    // successful sign-in.
    drop(record.reset_failed_attempts(state.adapter.as_ref()).await);

    // Trackable: shift current to last, stamp now + peer IP (D-11: socket
    // only) and persist the five columns. The peer is copied out first:
    // `connection_info()` hands back a RefCell borrow that may not live
    // across the helper's await (clippy `await_holding_refcell_ref`).
    let peer_ip = req.connection_info().peer_addr().map(str::to_string);
    sign_in_bookkeeping(
        &mut record,
        state.adapter.as_ref(),
        peer_ip.as_deref(),
        state.clock.as_ref(),
    )
    .await;

    let (key, salt) = record.session_pair();
    if insert_session_and_renew_sync(&session, &scope, &key, &salt).is_err() {
        return HttpResponse::InternalServerError().finish();
    }
    rotate_csrf_token(&session, &scope, &state.config);

    let mut response = if wants_json(&req) {
        HttpResponse::Ok().json(serde_json::json!({ "signed_in": true }))
    } else {
        let target = after_sign_in_target(&session, &state.mapping);
        flash_redirect(&session, &target, flash_keys::SIGNED_IN)
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
        let (cookie_key, cookie_value, generated_at) =
            rememberable::build_cookie_triple_after_created_at(
                &record.to_key().to_string(),
                &value,
                state.clock.as_ref(),
                record.remember_created_at(),
            );
        let op = RememberCookieOp::Set {
            scope: scope.clone(),
            key: remember_cookie_key(&scope, &state.config),
            value: rememberable::encode_cookie_value(&cookie_key, &cookie_value, &generated_at),
            attrs: crate::remember::attrs_for_scope(&scope, &state.config, state.clock.as_ref()),
        };
        if let Ok(jar_key) = crate::remember::derive_remember_key(&state.config) {
            drain_remember_op(
                &mut response,
                &jar_key,
                &op,
                &state.config,
                state.clock.as_ref(),
            );
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

    // Devise `verify_signed_out_user` → `all_signed_out?`
    // (sessions_controller.rb:67-69): the check iterates EVERY mapping in
    // the registry — `already_signed_out` only fires when NO scope is
    // signed in; a session holding ANY scope proceeds with the sign-out.
    let scopes = all_scope_names(&state);
    if scopes
        .iter()
        .all(|probe| !scope_session_present(&session, probe))
    {
        return if wants_json(&req) {
            HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "already_signed_out"
            }))
        } else {
            flash_redirect(&session, "/", "already_signed_out")
        };
    }

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
        sign_out_all_scopes_and_renew_sync(&session, &scopes, &state.config)
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
        flash_redirect(&session, "/", flash_keys::SIGNED_OUT)
    };
    if let (Some(op), Ok(jar_key)) = (
        clear_op,
        crate::remember::derive_remember_key(&state.config),
    ) {
        drain_remember_op(
            &mut response,
            &jar_key,
            &op,
            &state.config,
            state.clock.as_ref(),
        );
    }
    response
}

/// Scopes that share this middleware run: the scope registry — Devise's
/// `sign_out_all_scopes` walks `Devise.mappings` (every registered
/// mapping), never just the scope that mounted the action (S2). The
/// legacy `all_scopes` list stays as the fallback for callers that
/// hand-roll a state without a registry.
fn all_scope_names<M, A, L>(state: &DeviseWebState<M, A, L>) -> Vec<String> {
    let registry_scopes = state.scope_registry.scope_names();
    if registry_scopes.is_empty() {
        if state.all_scopes.is_empty() {
            vec![state.mapping.name.clone()]
        } else {
            state.all_scopes.clone()
        }
    } else {
        registry_scopes
    }
}

/// Cheap scope-session probe for `require_no_authentication` /
/// `verify_signed_out_user`: no adapter round-trip, just the session payload's
/// presence (the salt check happens later, where the record is needed).
fn scope_session_present(session: &Session, scope: &str) -> bool {
    session
        .get::<serde_json::Value>(&devise_rust::session::keys::scope_session_key(scope))
        .ok()
        .flatten()
        .is_some()
}

/// Trackable: the durable sign-in bookkeeping (current -> last shift + the
/// five column writes; the `Authentication` hooks own only the memo copy by
/// the Phase 5 hook design).
///
/// The durable map is built by the single core definition
/// ([`tracked_fields_changeset`](devise_rust::trackable::tracked_fields_changeset),
/// named column constants) from the record's PRE-shift state, then the one
/// in-memory shift applies the same values to the record copy: exactly one
/// increment in memory and one in the DB per sign-in.
///
/// The #4673 new-record guard (D-21) is restored on this path: the adapter
/// is probed first and an absent record performs zero writes and no
/// in-memory shift.
///
/// The single home `sessions#create`, `registrations#create`, and the
/// omniauth callback share (IN-03: Devise's `sign_up` delegates to
/// `sign_in`, and `hooks/trackable.rb` runs on that `after_set_user`).
/// Mirrors the same-named helper in the axum crate (framework parity,
/// D-19).
pub(crate) async fn sign_in_bookkeeping<M, A>(
    record: &mut M,
    adapter: &A,
    peer_addr: Option<&str>,
    clock: &dyn Clock,
) where
    M: FullDeviseModel,
    A: OrmAdapter<M> + Send + Sync,
{
    if adapter.get(&record.to_key()).await.ok().flatten().is_none() {
        return;
    }
    let now = clock.now();
    let fields = devise_rust::trackable::tracked_fields_changeset(record, now, peer_addr);
    record.update_tracked_fields(now, peer_addr);
    drop(adapter.update_columns(&record.to_key(), &fields).await);
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
        return unauthenticated_response(&req, &session, &state.mapping);
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
    // Devise `require_no_authentication` (registrations_controller.rb:4):
    // a signed-in visitor never reaches the create action — the second
    // account cannot be created (S13).
    if let Some(response) = require_no_authentication_response(&req, &session, &state).await {
        return response;
    }
    let singular = state.mapping.singular.clone();
    let params = match sanitized_body(&state.config, "sign_up", body, &singular) {
        Ok(params) => params,
        Err(response) => return response,
    };
    let mut record = M::new_with_session(&params, &JsonValue::Null, &state.config);

    let mut errors = record.validate(&state.config);
    record
        .validate_email_uniqueness(state.adapter.as_ref(), &mut errors)
        .await;
    if !errors.is_empty() {
        record.clean_up_passwords();
        return invalid_response(&req, &errors, error_status_of(&state.config));
    }
    let Ok(mut saved) = state.adapter.create(record).await else {
        return HttpResponse::InternalServerError().finish();
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
            state.adapter.as_ref(),
            state.mailer.as_ref(),
            &state.config,
            state.clock.as_ref(),
        )
        .await
    {
        let _ = error;
        return HttpResponse::InternalServerError().finish();
    }
    if let Some(message) = saved.post_sign_up_message() {
        let key = format!("signed_up_but_{message}");
        // Devise `expire_data_after_sign_in!`: the inactive branch must not
        // leave any signed-in state behind (registrations_controller.rb:26-29).
        drop(expire_devise_data_sync(
            &session,
            &all_scope_names(&state),
            &state.config,
        ));
        if wants_json(&req) {
            HttpResponse::Created()
                .json(serde_json::json!({ "signed_up": true, "inactive": message }))
        } else {
            flash_redirect(&session, &state.mapping.sign_in_path(), &key)
        }
    } else {
        // Devise `sign_up(resource_name, resource)` ->
        // `sign_in(resource_name, resource)` (`registrations_controller.rb:99-101`):
        // the sign-up IS an interactive sign-in, so the active branch sweeps
        // the stale devise keys and runs the trackable bookkeeping the way
        // `sessions#create` does, then writes the session. The port previously
        // only inserted the payload, which left `sign_in_count` at 0 and never
        // swept the keys (IN-03).
        drop(expire_devise_data_sync(
            &session,
            &all_scope_names(&state),
            &state.config,
        ));
        let peer_ip = req.connection_info().peer_addr().map(str::to_string);
        sign_in_bookkeeping(
            &mut saved,
            state.adapter.as_ref(),
            peer_ip.as_deref(),
            state.clock.as_ref(),
        )
        .await;
        let (key, salt) = saved.session_pair();
        let scope = state.mapping.name.clone();
        if insert_session_and_renew_sync(&session, &scope, &key, &salt).is_err() {
            return HttpResponse::InternalServerError().finish();
        }
        rotate_csrf_token(&session, &scope, &state.config);
        if wants_json(&req) {
            HttpResponse::Created().json(serde_json::json!({ "signed_up": true }))
        } else {
            flash_redirect(&session, "/", flash_keys::SIGNED_UP)
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
        return unauthenticated_response(&req, &session, &state.mapping);
    };
    let singular = state.mapping.singular.clone();
    let mut params = match sanitized_body(&state.config, "account_update", body, &singular) {
        Ok(params) => params,
        Err(response) => return response,
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
        password_blank || record.sign_in_after_change_password(&state.config);

    if let Err(errors) = record.update_with_password(&mut params, &state.config) {
        record.clean_up_passwords();
        return invalid_response(&req, &errors, error_status_of(&state.config));
    }

    let mut errors = record.validate(&state.config);
    record
        .validate_email_uniqueness(state.adapter.as_ref(), &mut errors)
        .await;
    if !errors.is_empty() {
        record.clean_up_passwords();
        return invalid_response(&req, &errors, error_status_of(&state.config));
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
                state.adapter.as_ref(),
                state.mailer.as_ref(),
                &state.config,
                state.clock.as_ref(),
            )
            .await
        {
            Ok(Some(_raw)) => reconfirmation_pending = true,
            Ok(None) => {}
            Err(_) => return HttpResponse::InternalServerError().finish(),
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
    let Ok(persisted) = state
        .adapter
        .update_columns(&record.to_key(), &fields)
        .await
    else {
        return HttpResponse::InternalServerError().finish();
    };

    // D-03/T-08-09: account-update renewal: Devise runs
    // `bypass_sign_in resource, scope: resource_name if sign_in_after_change_password?`
    // (`registrations_controller.rb:54`), the same predicate the flash reads,
    // so the re-sign-in and the flash can never disagree.
    if sign_in_after_change_password {
        let (key, salt) = devise_rust::failure::AnyDeviseModel::session_pair(&persisted);
        if bypass_sign_in_and_renew_sync(&session, &scope, &key, &salt).is_err() {
            return HttpResponse::InternalServerError().finish();
        }
        rotate_csrf_token(&session, &scope, &state.config);
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
    if wants_json(&req) {
        HttpResponse::Ok().json(serde_json::json!({ "updated": true }))
    } else {
        flash_redirect(&session, "/", flash_key)
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
        return unauthenticated_response(&req, &session, &state.mapping);
    };
    drop(state.adapter.delete(&record.to_key()).await);
    // Devise registrations#destroy honors `sign_out_all_scopes` like
    // sessions#destroy does (registrations_controller.rb:69-71).
    let sign_out = if state.config.sign_out_all_scopes {
        sign_out_all_scopes_and_renew_sync(&session, &all_scope_names(&state), &state.config)
    } else {
        sign_out_and_renew(&session, &scope)
    };
    if sign_out.is_err() {
        return HttpResponse::InternalServerError().finish();
    }
    rotate_csrf_token(&session, &scope, &state.config);
    if wants_json(&req) {
        HttpResponse::NoContent().finish()
    } else {
        flash_redirect(&session, "/", flash_keys::DESTROYED)
    }
}

/// Devise registrations#cancel (`registrations_controller.rb:78-81`):
/// expire the OAuth session data, then redirect to the sign-up path
/// (no flash — the action only abandons the pending flow). The action is
/// guarded by `require_no_authentication` (`registrations_controller.rb:4`).
async fn registrations_cancel<M, A, L>(
    req: HttpRequest,
    session: Session,
    state: web::Data<DeviseWebState<M, A, L>>,
) -> HttpResponse
where
    M: FullDeviseModel,
    A: OrmAdapter<M> + Send + Sync,
    L: Mailer<M>,
{
    if let Some(response) = require_no_authentication_response(&req, &session, &state).await {
        return response;
    }
    drop(expire_devise_data_sync(
        &session,
        &all_scope_names(&state),
        &state.config,
    ));
    redirect_to(&state.mapping.sign_up_path())
}

// ============================================================================
// Passwords controller (RCV / PasswordsController)
// ============================================================================

async fn passwords_create<M, A, L>(
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
    // Devise `require_no_authentication` (passwords_controller.rb:4): every
    // passwords action is guarded.
    if let Some(response) = require_no_authentication_response(&req, &session, &state).await {
        return response;
    }
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
        let key = successfully_sent_key(resource.is_valid(), state.config.paranoid);
        return flash_redirect(&session, &state.mapping.sign_in_path(), key);
    }
    invalid_response(&req, &resource.errors, error_status_of(&state.config))
}

async fn passwords_edit<M, A, L>(
    req: HttpRequest,
    session: Session,
    state: web::Data<DeviseWebState<M, A, L>>,
    query: web::Query<HashMap<String, String>>,
) -> HttpResponse
where
    M: FullDeviseModel,
    A: OrmAdapter<M> + Send + Sync,
    L: Mailer<M>,
{
    // Devise `require_no_authentication` (passwords_controller.rb:4): every
    // passwords action is guarded.
    if let Some(response) = require_no_authentication_response(&req, &session, &state).await {
        return response;
    }
    // Devise `assert_reset_token_passed` (`passwords_controller.rb:65-70`):
    // the blank-token redirect goes to `new_session_path`, NOT the site
    // root: the user must land on the sign-in form to start over.
    let token = query.get("reset_password_token");
    let token_str = token.map_or("", String::as_str);
    if token_str.trim().is_empty() {
        return flash_redirect(
            &session,
            &state.mapping.sign_in_path(),
            flash_keys::NO_TOKEN,
        );
    }
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body("edit")
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
    // Devise `require_no_authentication` (passwords_controller.rb:4): every
    // passwords action is guarded.
    if let Some(response) = require_no_authentication_response(&req, &session, &state).await {
        return response;
    }
    let singular = state.mapping.singular.clone();
    let attrs = body_map(body, &singular);
    // Devise `after_update :send_password_change_notification`
    // (`database_authenticatable.rb:163-168`): the callback fires on any
    // `encrypted_password` change, so the pre-reset digest has to be read
    // BEFORE the reset writes the new one. Devise fires it from a callback;
    // this controller path owns the decision (the model's own helper reads
    // config plus the skip flag, so the two paths cannot drift).
    let before_digest =
        digest_before_reset::<M, A>(&attrs, state.adapter.as_ref(), &state.config).await;
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
        return invalid_response(&req, &resource.errors, error_status_of(&state.config));
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
        state.mailer.as_ref(),
        &state.config,
    )
    .is_err()
    {
        return HttpResponse::InternalServerError().finish();
    }

    // Devise `unlockable?` (`passwords_controller.rb:79-83`): the unlock
    // only runs when the configured unlock strategy includes :email AND the
    // account is actually locked, so a :time (or :none) penalty survives a
    // password reset (T-261026-ghf-01).
    if resource
        .record
        .unlock_strategy_enabled("email", &state.config)
        && resource
            .record
            .access_locked(&state.config, state.clock.as_ref())
    {
        drop(resource.record.unlock_access(state.adapter.as_ref()).await);
    }

    // Devise `passwords_controller.rb:40-45`: the sign-in after a reset is
    // UNCONDITIONAL under `sign_in_after_reset_password` (the reference
    // never gates it on `active_for_authentication?`), the flash splits on
    // activity, and `after_database_authentication` fires before the sign-in
    // (T-261026-ghf-02).
    let active = resource.record.active_for_authentication();
    if state.config.sign_in_after_reset_password {
        devise_rust::failure::AnyDeviseModel::after_database_authentication(&resource.record);
        let scope = state.mapping.name.clone();
        let (key, salt) = devise_rust::failure::AnyDeviseModel::session_pair(&resource.record);
        if insert_session_and_renew_sync(&session, &scope, &key, &salt).is_err() {
            return HttpResponse::InternalServerError().finish();
        }
        rotate_csrf_token(&session, &scope, &state.config);
    }

    let key = if state.config.sign_in_after_reset_password && active {
        flash_keys::UPDATED
    } else {
        flash_keys::UPDATED_NOT_ACTIVE
    };
    if wants_json(&req) {
        HttpResponse::Ok().json(serde_json::json!({ "reset": true, "key": key }))
    } else {
        flash_redirect(&session, "/", key)
    }
}

// ============================================================================
// Confirmations controller (CNF / ConfirmationsController)
// ============================================================================

async fn confirmations_show<M, A, L>(
    req: HttpRequest,
    session: Session,
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
        return flash_redirect(
            &session,
            &state.mapping.sign_in_path(),
            flash_keys::CONFIRMED,
        );
    }
    // Devise carves `confirmations#show` out of the configurable
    // `error_status` with a TODO to adopt it only when the default changes
    // (`confirmations_controller.rb:30-31`); the port mirrors the hardcode.
    invalid_response(&req, &resource.errors, StatusCode::UNPROCESSABLE_ENTITY)
}

async fn confirmations_create<M, A, L>(
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
    // Devise `successfully_sent?` (devise_controller.rb:135-147): paranoid
    // mode clears the errors and reports `send_paranoid_instructions` so the
    // response is uniform for known and unknown addresses.
    if resource.is_valid() || state.config.paranoid {
        let key = successfully_sent_key(resource.is_valid(), state.config.paranoid);
        if wants_json(&req) {
            return HttpResponse::Created().json(serde_json::json!({ "sent": true }));
        }
        return flash_redirect(&session, &state.mapping.sign_in_path(), key);
    }
    invalid_response(&req, &resource.errors, error_status_of(&state.config))
}

// ============================================================================
// Unlocks controller (LCK / UnlocksController)
// ============================================================================

async fn unlocks_show<M, A, L>(
    req: HttpRequest,
    session: Session,
    state: web::Data<DeviseWebState<M, A, L>>,
    query: web::Query<HashMap<String, String>>,
) -> HttpResponse
where
    M: FullDeviseModel,
    A: OrmAdapter<M> + Send + Sync,
    L: Mailer<M>,
{
    // Devise `require_no_authentication` (unlocks_controller.rb:4): every
    // unlocks action is guarded.
    if let Some(response) = require_no_authentication_response(&req, &session, &state).await {
        return response;
    }
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
        return flash_redirect(
            &session,
            &state.mapping.sign_in_path(),
            flash_keys::UNLOCKED,
        );
    }
    // Devise carves `unlocks#show` out of the configurable `error_status`
    // with a TODO to adopt it only when the default changes
    // (`unlocks_controller.rb:32-33`); the port mirrors the hardcode.
    invalid_response(&req, &resource.errors, StatusCode::UNPROCESSABLE_ENTITY)
}

async fn unlocks_create<M, A, L>(
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
    // Devise `require_no_authentication` (unlocks_controller.rb:4): every
    // unlocks action is guarded.
    if let Some(response) = require_no_authentication_response(&req, &session, &state).await {
        return response;
    }
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
    // Devise `successfully_sent?` (devise_controller.rb:135-147): paranoid
    // mode clears the errors and reports a uniform
    // `send_paranoid_instructions`, so known and unknown addresses get the
    // same response (the unlocks section ships that key in the catalog).
    if resource.is_valid() || state.config.paranoid {
        let key = successfully_sent_key(resource.is_valid(), state.config.paranoid);
        if wants_json(&req) {
            return HttpResponse::Created().json(serde_json::json!({ "sent": true }));
        }
        return flash_redirect(&session, &state.mapping.sign_in_path(), key);
    }
    invalid_response(&req, &resource.errors, error_status_of(&state.config))
}
