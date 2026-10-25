//! Actix extractors — `Auth<M>` / `RequireAuth<M>` plus per-scope helpers
//! and the `devise_group` equivalent (D-08 / D-10).
//!
//! Extractors read ONLY the request extensions staged by
//! [`crate::middleware::DeviseMiddleware`]:
//!
//! - [`crate::middleware::ResolvedAuthHandle`] — resolved records, session
//!   payloads, mapping, config (filled before the handler future is polled)
//! - [`devise_rust::request::AuthRequest`] — the owned request snapshot
//!
//! No extractor future ever holds `actix_session::Session`, so the `Send`
//! contract of handler futures is intact (D-04 / ACTIX-02 prohibition).
//!
//! ## Failure rendering (D-09)
//!
//! `RequireAuth` and the `authenticate_*` helpers never invent response
//! envelopes: they call core
//! [`build_failure`] (`FailureReason::Unauthenticated`)
//! and render through the 08-01
//! [`ActixFailureRenderer`] — 302 +
//! flash + `stored_location` for navigational formats, 401 otherwise.
//!
//! ## Options
//!
//! - Per-scope helper fns delegate to core helpers semantics with the scope
//!   name fixed (`user` + `admin` built in; arbitrary scopes via the
//!   `*_scope_*` variants).

#![allow(clippy::module_name_repetitions)]

use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;

use actix_web::http::header;
use actix_web::{Error, FromRequest, HttpMessage, HttpRequest, HttpResponse, error};
use devise_rust::config::DeviseConfig;
use devise_rust::failure::{AnyDeviseModel, FailureReason, FailureRenderer, build_failure};
use devise_rust::request::{AuthRequest, HttpMethod};
use devise_rust::scope::Mapping;
use serde_json::Value;

use crate::failure::ActixFailureRenderer;
use crate::middleware::{ResolvedAuth, ResolvedAuthHandle};

/// Read the staged [`ResolvedAuth`] snapshot out of request extensions.
///
/// Returns `None` when the Devise middleware is not in the stack (fail
/// closed to unauthenticated).
fn resolved_auth(req: &HttpRequest) -> Option<ResolvedAuth> {
    let handle = {
        let extensions = req.extensions();
        extensions.get::<ResolvedAuthHandle>().cloned()
    }?;
    handle.lock().ok().map(|guard| guard.clone())
}

/// Read the staged [`AuthRequest`] snapshot, or rebuild a minimal one from
/// the live request when the middleware never ran.
fn staged_request(req: &HttpRequest) -> AuthRequest {
    {
        let extensions = req.extensions();
        if let Some(snapshot) = extensions.get::<AuthRequest>() {
            return snapshot.clone();
        }
    }
    let mut request = AuthRequest::new(
        HttpMethod::from_str(req.method().as_str()).unwrap_or(HttpMethod::Get),
        req.path().to_string(),
    );
    for (name, value) in req.headers() {
        if let Ok(v) = value.to_str() {
            request
                .headers
                .insert(name.as_str().to_lowercase(), v.to_string());
        }
    }
    request
}

/// Build the unauthenticated failure response: core
/// [`build_failure`], rendered through the 08-01 renderer.
fn unauthenticated_response(
    request: &AuthRequest,
    mapping: Option<&Mapping>,
    config: Option<&DeviseConfig>,
) -> HttpResponse {
    let (Some(mapping), Some(config)) = (mapping, config) else {
        // No mapping resolved: fail closed with a bare 401.
        return HttpResponse::Unauthorized().finish();
    };
    let failure = build_failure(request, mapping, config, FailureReason::Unauthenticated);
    ActixFailureRenderer::new().render(&failure, mapping)
}

/// Extractor state resolved out of the request extensions in one
/// synchronous pass (no `await` while extension borrows are alive).
fn extract_state<M>(req: &HttpRequest) -> (String, Option<std::sync::Arc<dyn AnyDeviseModel>>, bool)
where
    M: AnyDeviseModel + Send + Sync + 'static,
{
    let Some(resolved) = resolved_auth(req) else {
        return (String::new(), None, false);
    };
    let Some(scope) = resolved.scope.clone() else {
        return (String::new(), None, false);
    };
    let record = resolved.users.get(&scope).cloned();
    // Typed sanity: a record that does not downcast to `M` is treated as
    // unauthenticated for this extractor (multi-scope isolation).
    let typed = record.as_ref().is_some_and(|r| r.as_any().is::<M>());
    (scope, record, typed)
}

/// Base extractor for an authenticated (or not) scope.
///
/// Yields the user the middleware resolved from the session store for the
/// request's path-derived scope, when present. Registration-free routes
/// resolve through the staged [`ResolvedAuth`] and never run strategies in
/// the extractor (D-08).
#[derive(Debug, Clone)]
pub struct Auth<M: AnyDeviseModel + Send + Sync + 'static> {
    record: Option<Arc<dyn AnyDeviseModel>>,
    scope: String,
    _phantom: PhantomData<fn() -> M>,
}

impl<M: AnyDeviseModel + Send + Sync + 'static> Auth<M> {
    /// Borrow the typed record when this request is authenticated.
    #[must_use]
    pub fn user(&self) -> Option<&M> {
        self.record.as_deref()?.as_any().downcast_ref::<M>()
    }

    /// Whether the request is authenticated for this scope.
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        self.user().is_some()
    }

    /// The scope this extractor resolved against.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }
}

impl<M: AnyDeviseModel + Send + Sync + 'static> FromRequest for Auth<M> {
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>> + Send>>;

    fn from_request(req: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        let (scope, record, typed) = extract_state::<M>(req);
        let record = if typed { record } else { None };
        Box::pin(async move {
            Ok(Auth {
                record,
                scope,
                _phantom: PhantomData,
            })
        })
    }
}

/// Strict extractor variant: fails closed when the request has no
/// authenticated record for its scope.
///
/// Anonymous navigational requests render the core 302 + flash through
/// [`ActixFailureRenderer`]; anonymous API requests render 401 (D-09).
#[derive(Debug, Clone)]
pub struct RequireAuth<M: AnyDeviseModel + Send + Sync + 'static> {
    inner: Auth<M>,
}

impl<M: AnyDeviseModel + Send + Sync + 'static> std::ops::Deref for RequireAuth<M> {
    type Target = Auth<M>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<M: AnyDeviseModel + Send + Sync + 'static> FromRequest for RequireAuth<M> {
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>> + Send>>;

    fn from_request(req: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        let (scope, record, typed) = extract_state::<M>(req);
        if typed {
            return Box::pin(async move {
                Ok(RequireAuth {
                    inner: Auth {
                        record,
                        scope,
                        _phantom: PhantomData,
                    },
                })
            });
        }
        // Fail closed through the core failure path (D-09, ACTIX-02).
        // `HttpResponse` is `!Send` (it carries `Extensions`), so the
        // response is constructed INSIDE the async block from `Send`
        // inputs: the future's own state stays `Send` (D-04 gate).
        let request = staged_request(req);
        let resolved = resolved_auth(req);
        let mapping = resolved.as_ref().and_then(|r| r.mapping.clone());
        let config = resolved.as_ref().and_then(|r| r.config.clone());
        // Devise `devise.failure.timeout`: a session the fetch-path timeout
        // pass expired fails closed with the timeout reason (the redirect
        // keeps the `timedout` flash), not the plain unauthenticated key.
        let timed_out = resolved
            .as_ref()
            .and_then(|r| r.timed_out.clone())
            .filter(|timed| timed == &scope);
        // Devise `store_location!`: GET navigational non-XHR requests are
        // remembered in the session so post-sign-in can return here
        // (T-08-08: same-host-only parse; POST/absolute/relative-foreign
        // targets are rejected by the core validator).
        if let (Some(mapping), Some(config)) = (&mapping, &config) {
            let navigational = request.is_navigational_format(config)
                && matches!(request.method, HttpMethod::Get)
                && !request.is_xhr();
            if navigational {
                if let Some(target) =
                    devise_rust::request::AuthRequest::parse_stored_uri(&request.path)
                {
                    use actix_session::SessionExt as _;
                    let session = req.get_session();
                    let key = devise_rust::failure::stored_location_key(&mapping.name);
                    drop(session.insert(&key, target));
                }
            }
        }
        Box::pin(async move {
            let response = if timed_out.is_some() {
                build_timeout_send_safe(&request, mapping, config)
            } else {
                build_unauthenticated_send_safe(&request, mapping, config)
            };
            Err(error::InternalError::from_response("", response).into())
        })
    }
}

/// Construct the timeout failure response inside the extractor future -
/// the same send-safe shape as [`build_unauthenticated_send_safe`] with the
/// Devise `:timeout` reason.
fn build_timeout_send_safe(
    request: &AuthRequest,
    mapping: Option<Mapping>,
    config: Option<Arc<DeviseConfig>>,
) -> HttpResponse {
    match (mapping, config) {
        (Some(mapping), Some(config)) => {
            let failure = build_failure(request, &mapping, &config, FailureReason::Timeout);
            ActixFailureRenderer::new().render(&failure, &mapping)
        }
        _ => HttpResponse::Unauthorized().finish(),
    }
}

/// Construct the unauthenticated failure response inside the extractor
/// future — inputs are all `Send`, the `!Send` `HttpResponse` never lives
/// in future state across await points.
fn build_unauthenticated_send_safe(
    request: &AuthRequest,
    mapping: Option<Mapping>,
    config: Option<Arc<DeviseConfig>>,
) -> HttpResponse {
    match (mapping, config) {
        (Some(mapping), Some(config)) => {
            let failure = build_failure(request, &mapping, &config, FailureReason::Unauthenticated);
            ActixFailureRenderer::new().render(&failure, &mapping)
        }
        _ => HttpResponse::Unauthorized().finish(),
    }
}

/// Typed current record for `scope` (owned clone; test models are `Clone`).
#[must_use]
pub fn current_scope_record<M>(req: &HttpRequest, scope: &str) -> Option<M>
where
    M: AnyDeviseModel + Clone + Send + Sync + 'static,
{
    resolved_auth(req)?
        .users
        .get(scope)?
        .as_any()
        .downcast_ref::<M>()
        .cloned()
}

/// Typed `current_<scope>` for the `user` scope.
#[must_use]
pub fn current_user<M>(req: &HttpRequest) -> Option<M>
where
    M: AnyDeviseModel + Clone + Send + Sync + 'static,
{
    current_scope_record(req, "user")
}

/// Typed `current_<scope>` for the `admin` scope.
#[must_use]
pub fn current_admin<M>(req: &HttpRequest) -> Option<M>
where
    M: AnyDeviseModel + Clone + Send + Sync + 'static,
{
    current_scope_record(req, "admin")
}

/// Whether `scope` is signed in (core `signed_in` semantics).
#[must_use]
pub fn scope_signed_in(req: &HttpRequest, scope: &str) -> bool {
    resolved_auth(req).is_some_and(|r| r.users.contains_key(scope))
}

/// `user_signed_in` helper (D-10).
#[must_use]
pub fn user_signed_in(req: &HttpRequest) -> bool {
    scope_signed_in(req, "user")
}

/// `admin_signed_in` helper (D-10).
#[must_use]
pub fn admin_signed_in(req: &HttpRequest) -> bool {
    scope_signed_in(req, "admin")
}

/// Raw session payload `[key, salt]` for `scope` (core `session_data`).
#[must_use]
pub fn scope_session(req: &HttpRequest, scope: &str) -> Option<Value> {
    resolved_auth(req)?.payloads.get(scope).cloned()
}

/// `user_session` helper (D-10).
#[must_use]
pub fn user_session(req: &HttpRequest) -> Option<Value> {
    scope_session(req, "user")
}

/// `admin_session` helper (D-10).
#[must_use]
pub fn admin_session(req: &HttpRequest) -> Option<Value> {
    scope_session(req, "admin")
}

/// `authenticate_<scope>!` helper: returns the typed record or the rendered
/// core `Failure` (302 navigational / 401 API, D-09).
///
/// # Errors
///
/// Returns the rendered failure response when `scope` is not authenticated.
pub fn authenticate_scope<M>(req: &HttpRequest, scope: &str) -> Result<M, HttpResponse>
where
    M: AnyDeviseModel + Clone + Send + Sync + 'static,
{
    if let Some(record) = current_scope_record::<M>(req, scope) {
        return Ok(record);
    }
    let request = staged_request(req);
    let resolved = resolved_auth(req);
    Err(unauthenticated_response(
        &request,
        resolved.as_ref().and_then(|r| r.mapping.as_ref()),
        resolved.as_ref().and_then(|r| r.config.as_deref()),
    ))
}

/// `authenticate_user!` helper (D-10).
///
/// # Errors
///
/// See [`authenticate_scope`].
pub fn authenticate_user<M>(req: &HttpRequest) -> Result<M, HttpResponse>
where
    M: AnyDeviseModel + Clone + Send + Sync + 'static,
{
    authenticate_scope(req, "user")
}

/// `authenticate_admin!` helper (D-10).
///
/// # Errors
///
/// See [`authenticate_scope`].
pub fn authenticate_admin<M>(req: &HttpRequest) -> Result<M, HttpResponse>
where
    M: AnyDeviseModel + Clone + Send + Sync + 'static,
{
    authenticate_scope(req, "admin")
}

/// `devise_group` equivalent: a named bundle of scopes tried in order
/// (mirrors core `Group` in `devise_rust::helpers`).
#[derive(Debug, Clone)]
pub struct AuthGroup {
    /// Group name (e.g. `"blogger"`).
    pub name: String,
    /// Scopes tried in order.
    pub scopes: Vec<String>,
}

impl AuthGroup {
    /// Create a group from a name and scope list.
    #[must_use]
    pub fn new(name: impl Into<String>, scopes: &[&str]) -> Self {
        Self {
            name: name.into(),
            scopes: scopes.iter().map(ToString::to_string).collect(),
        }
    }
}

/// Whether ANY scope in the group is signed in (core `group_signed_in`).
#[must_use]
pub fn group_signed_in(req: &HttpRequest, group: &AuthGroup) -> bool {
    group.scopes.iter().any(|scope| scope_signed_in(req, scope))
}

/// Authenticate the group: returns every scope that is signed in, in the
/// group's configured order. Fails closed with the core unauthenticated
/// response when no scope resolves (D-09).
///
/// # Errors
///
/// Returns the rendered failure response when no group scope is signed in.
pub fn authenticate_group(
    req: &HttpRequest,
    group: &AuthGroup,
) -> Result<Vec<String>, HttpResponse> {
    let signed: Vec<String> = group
        .scopes
        .iter()
        .filter(|scope| scope_signed_in(req, scope))
        .cloned()
        .collect();
    if !signed.is_empty() {
        return Ok(signed);
    }
    let request = staged_request(req);
    let resolved = resolved_auth(req);
    Err(unauthenticated_response(
        &request,
        resolved.as_ref().and_then(|r| r.mapping.as_ref()),
        resolved.as_ref().and_then(|r| r.config.as_deref()),
    ))
}

/// Reject already-signed-in visitors from sign-in pages (SESS-08 /
/// core `require_no_authentication`): navigational requests redirect to the
/// scope root with the `already_authenticated` flash; API requests 401.
///
/// # Errors
///
/// Returns the redirect/401 response when the request's scope is signed in.
pub fn require_no_authentication(req: &HttpRequest) -> Result<(), HttpResponse> {
    let Some(resolved) = resolved_auth(req) else {
        return Ok(());
    };
    let Some(scope) = resolved.scope.clone() else {
        return Ok(());
    };
    if !resolved.users.contains_key(&scope) {
        return Ok(());
    }
    let target = resolved
        .mapping
        .as_ref()
        .map_or_else(|| "/".to_string(), Mapping::full_path);
    let mut response = HttpResponse::Found()
        .insert_header((header::LOCATION, target))
        .finish();
    let mut flash = actix_web::cookie::Cookie::new(
        "devise.flash".to_string(),
        FailureReason::AlreadyAuthenticated.flash_key().to_string(),
    );
    flash.set_path("/");
    flash.set_http_only(true);
    flash.set_same_site(actix_web::cookie::SameSite::Lax);
    response.add_cookie(&flash).ok();
    Err(response)
}
