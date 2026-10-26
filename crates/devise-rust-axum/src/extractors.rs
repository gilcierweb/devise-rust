//! Axum extractors — `Auth<M>` / `RequireAuth<M>` plus per-scope helpers
//! and the `devise_group` equivalent (D-02 / D-10).
//!
//! Extractors read ONLY the extensions staged by
//! [`DeviseLayer`](crate::layer::DeviseLayer):
//!
//! - [`AuthProxyHandle`] — the per-request
//!   `AuthProxy` over the tower-sessions bridge;
//! - [`AuthRequest`] — the owned
//!   request snapshot;
//! - `Mapping` + `Arc<DeviseConfig>` — resolved scope and configuration.
//!
//! `Auth<M>` is the lazy `current_user` shape: it authenticates on demand
//! (session fetch, then strategies) and never rejects. `RequireAuth<M>`
//! is the `authenticate_<scope>!` shape: it fails closed, rendering the
//! core `Failure` through [`AxumFailureRenderer`]
//! — 302 + flash for navigational formats, 401 for API.
//!
//! Extractors never touch `tower_sessions::Session`: all session I/O
//! (including the `store_location!` write on a strict failure) flows
//! through the staged proxy's bridge store.
//!
//! ## Options
//!
//! Per-scope helper fns delegate to the core
//! [`helpers`](devise_rust::helpers) semantics with the scope name fixed
//! (`user` + `admin` built in; arbitrary scopes via the `*_scope_*`
//! variants), following the `devise_helpers!` macro template without
//! introducing a new macro (D-10).

#![allow(clippy::module_name_repetitions)]

use std::marker::PhantomData;
use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use devise_rust::config::DeviseConfig;
use devise_rust::failure::{AnyDeviseModel, Failure, FailureRenderer, build_failure};
use devise_rust::helpers::{AuthenticateOpts, Group};
use devise_rust::proxy::AuthProxy;
use devise_rust::request::AuthRequest;
use devise_rust::scope::Mapping;

use crate::failure::{AxumFailureRenderer, failure_reason};
use crate::layer::AuthProxyHandle;

/// Base extractor: the current user for the request's scope, when
/// authenticated.
///
/// Yields the user the proxy resolved (session fetch, then strategies on
/// demand); anonymous requests extract successfully with
/// [`user`](Self::user) returning `None`.
///
/// ## Examples
///
/// ```rust,ignore
/// async fn dashboard(auth: Auth<TracerUser>) -> &'static str {
///     match auth.user() {
///         Some(user) => "authenticated",
///         None => "anonymous",
///     }
/// }
/// ```
pub struct Auth<M: AnyDeviseModel + Clone + Send + Sync + 'static> {
    user: Option<M>,
    scope: String,
    _phantom: PhantomData<fn() -> M>,
}

impl<M: AnyDeviseModel + Clone + Send + Sync + 'static> Auth<M> {
    /// The typed record when this request is authenticated.
    #[must_use]
    pub fn user(&self) -> Option<&M> {
        self.user.as_ref()
    }

    /// Whether the request is authenticated for this scope.
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        self.user.is_some()
    }

    /// The scope this extractor resolved against.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }
}

impl<M, S> FromRequestParts<S> for Auth<M>
where
    M: AnyDeviseModel + Clone + Send + Sync + 'static,
    S: Send + Sync,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let Some((handle, request, mapping)) = staged_state(parts) else {
            return Ok(Auth {
                user: None,
                scope: String::new(),
                _phantom: PhantomData,
            });
        };
        let Some(mapping) = mapping else {
            return Ok(Auth {
                user: None,
                scope: String::new(),
                _phantom: PhantomData,
            });
        };
        let scope = mapping.name.clone();
        let mut proxy = handle.lock().await;
        let resolved = proxy.authenticate(&scope, &request).await;
        let typed = resolved.and_then(|user| user.as_any().downcast_ref::<M>().cloned());
        Ok(Auth {
            user: typed,
            scope,
            _phantom: PhantomData,
        })
    }
}

/// Strict extractor: fails closed when the request has no authenticated
/// record for its scope.
///
/// Anonymous navigational requests render the core 302 + flash; anonymous
/// API requests render 401 (the core `build_failure` decides which).
///
/// ## Examples
///
/// ```rust,ignore
/// async fn dashboard(user: RequireAuth<TracerUser>) -> String {
///     format!("hello {}", user.user().email)
/// }
/// ```
pub struct RequireAuth<M: AnyDeviseModel + Clone + Send + Sync + 'static> {
    inner: Auth<M>,
}

impl<M: AnyDeviseModel + Clone + Send + Sync + 'static> std::ops::Deref for RequireAuth<M> {
    type Target = Auth<M>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<M, S> FromRequestParts<S> for RequireAuth<M>
where
    M: AnyDeviseModel + Clone + Send + Sync + 'static,
    S: Send + Sync,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let Some((handle, request, mapping)) = staged_state(parts) else {
            return Err(AuthRejection::missing_layer());
        };
        let Some(mapping) = mapping else {
            // No scope resolved for this path: fail closed with a bare 401.
            return Err(AuthRejection::missing_layer());
        };
        let scope = mapping.name.clone();
        let config = parts.extensions.get::<Arc<DeviseConfig>>().cloned();
        let mut proxy = handle.lock().await;
        match proxy.authenticate_strict(&scope, &request).await {
            Ok(user) => {
                // Typed sanity: a record that does not downcast to `M` is
                // treated as unauthenticated for this extractor
                // (multi-scope isolation, actix parity).
                let Some(typed) = user.as_any().downcast_ref::<M>().cloned() else {
                    drop(proxy);
                    let response = render_failure(
                        &devise_rust::failure::Failure::Unauthenticated { message: "invalid" },
                        &request,
                        &mapping,
                        config.as_deref(),
                    );
                    return Err(AuthRejection(response));
                };
                Ok(RequireAuth {
                    inner: Auth {
                        user: Some(typed),
                        scope,
                        _phantom: PhantomData,
                    },
                })
            }
            Err(failure) => {
                // Devise `store_location!`: GET navigational non-XHR
                // requests are remembered in the session so post-sign-in
                // can return here (same-host-only via the core validator;
                // POST and absolute-URL targets store nothing). The write
                // rides the proxy's bridge store — the extractor never
                // touches the tower `Session` type.
                if let Some(config) = config.as_deref() {
                    devise_rust::failure::store_location(
                        &request,
                        &mapping.name,
                        config,
                        proxy.session_store(),
                    )
                    .await;
                }
                drop(proxy);
                let response = render_failure(&failure, &request, &mapping, config.as_deref());
                Err(AuthRejection(response))
            }
        }
    }
}

/// Rejection carrying the rendered failure response.
pub struct AuthRejection(Response);

impl AuthRejection {
    /// Bare 401 used when the Devise layer never staged state.
    #[must_use]
    pub fn missing_layer() -> Self {
        Self(axum::http::StatusCode::UNAUTHORIZED.into_response())
    }

    /// The rendered response.
    #[must_use]
    pub fn into_inner(self) -> Response {
        self.0
    }
}

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        self.0
    }
}

/// Read the layer-staged pieces in one synchronous pass.
type StagedState = (
    AuthProxyHandle,
    devise_rust::request::AuthRequest,
    Option<Mapping>,
);

fn staged_state(parts: &Parts) -> Option<StagedState> {
    let handle = parts.extensions.get::<AuthProxyHandle>().cloned()?;
    let request = parts
        .extensions
        .get::<devise_rust::request::AuthRequest>()
        .cloned()?;
    let mapping = parts.extensions.get::<Mapping>().cloned();
    Some((handle, request, mapping))
}

/// Classify a raw proxy failure through core `build_failure` and render it.
fn render_failure(
    failure: &devise_rust::failure::Failure,
    request: &devise_rust::request::AuthRequest,
    mapping: &Mapping,
    config: Option<&DeviseConfig>,
) -> Response {
    let Some(config) = config else {
        return AuthRejection::missing_layer().into_inner();
    };
    let reason = failure_reason(failure);
    let classified = build_failure(request, mapping, config, reason);
    // S11: the flash rides the SIGNED transport — the renderer carries the
    // config-derived cookie key, never an unsigned cookie.
    AxumFailureRenderer::for_config(config).render(&classified, mapping)
}

// ============================================================================
// Per-scope helpers (D-10) — thin monomorphizations of the core
// `devise_rust::helpers` surface with the scope name fixed. Handlers obtain
// the proxy by locking the staged [`AuthProxyHandle`] extension; every
// helper then delegates to core with no new decision logic.
// ============================================================================

/// Typed `current_<scope>` for an arbitrary scope (core
/// [`current_user`](devise_rust::helpers::current_user) semantics).
#[must_use]
pub fn current_scope_record<'a, M: 'static>(scope: &str, proxy: &'a AuthProxy) -> Option<&'a M> {
    devise_rust::helpers::current_user::<M>(scope, proxy)
}

/// Typed `current_user` for the `user` scope.
///
/// ## Examples
///
/// ```rust,ignore
/// let proxy = handle.lock().await;
/// if let Some(user) = current_user::<User>(&proxy) { /* ... */ }
/// ```
#[must_use]
pub fn current_user<M: 'static>(proxy: &AuthProxy) -> Option<&M> {
    current_scope_record::<M>("user", proxy)
}

/// Typed `current_admin` for the `admin` scope.
#[must_use]
pub fn current_admin<M: 'static>(proxy: &AuthProxy) -> Option<&M> {
    current_scope_record::<M>("admin", proxy)
}

/// Whether an arbitrary scope is signed in (core `signed_in` semantics:
/// memo presence, no strategy run).
#[must_use]
pub fn scope_signed_in(proxy: &AuthProxy, scope: &str) -> bool {
    devise_rust::helpers::signed_in(scope, proxy)
}

/// `user_signed_in` helper (D-10).
#[must_use]
pub fn user_signed_in(proxy: &AuthProxy) -> bool {
    scope_signed_in(proxy, "user")
}

/// `admin_signed_in` helper (D-10).
#[must_use]
pub fn admin_signed_in(proxy: &AuthProxy) -> bool {
    scope_signed_in(proxy, "admin")
}

/// Raw session payload `[key, salt]` for an arbitrary scope (core
/// `session_data` semantics over the proxy's bridge store).
pub async fn scope_session(proxy: &AuthProxy, scope: &str) -> Option<serde_json::Value> {
    devise_rust::helpers::session_data(scope, proxy).await
}

/// `user_session` helper (D-10).
pub async fn user_session(proxy: &AuthProxy) -> Option<serde_json::Value> {
    scope_session(proxy, "user").await
}

/// `admin_session` helper (D-10).
pub async fn admin_session(proxy: &AuthProxy) -> Option<serde_json::Value> {
    scope_session(proxy, "admin").await
}

/// `authenticate_<scope>!` for an arbitrary scope: strict authentication
/// through the real strategy chain, propagating the core `Failure` for the
/// renderer (302 navigational / 401 API, D-09).
///
/// # Errors
///
/// Returns the strategy or hook `Failure` when authentication fails.
pub async fn authenticate_scope<'a>(
    scope: &str,
    proxy: &'a mut AuthProxy,
    request: &AuthRequest,
    opts: &AuthenticateOpts,
) -> Result<&'a dyn AnyDeviseModel, Failure> {
    devise_rust::helpers::authenticate_strict(scope, proxy, request, opts).await
}

/// `authenticate_user!` helper (D-10).
///
/// # Errors
///
/// See [`authenticate_scope`].
pub async fn authenticate_user<'a>(
    proxy: &'a mut AuthProxy,
    request: &AuthRequest,
    opts: &AuthenticateOpts,
) -> Result<&'a dyn AnyDeviseModel, Failure> {
    authenticate_scope("user", proxy, request, opts).await
}

/// `authenticate_admin!` helper (D-10).
///
/// # Errors
///
/// See [`authenticate_scope`].
pub async fn authenticate_admin<'a>(
    proxy: &'a mut AuthProxy,
    request: &AuthRequest,
    opts: &AuthenticateOpts,
) -> Result<&'a dyn AnyDeviseModel, Failure> {
    authenticate_scope("admin", proxy, request, opts).await
}

/// `devise_group` equivalent: a named bundle of scopes tried in order.
///
/// An alias of core [`Group`] — the axum
/// crate never re-implements group semantics; the name matches the actix
/// crate's so one doc page serves both frameworks (D-02).
pub type AuthGroup = Group;

/// Authenticate every scope in the group, returning the ones that
/// succeeded (core [`authenticate_group`](devise_rust::helpers::authenticate_group)).
pub async fn authenticate_group(
    group: &AuthGroup,
    proxy: &mut AuthProxy,
    request: &AuthRequest,
    opts: &AuthenticateOpts,
) -> Vec<String> {
    devise_rust::helpers::authenticate_group(group, proxy, request, opts).await
}

/// Whether ANY scope in the group is signed in (core
/// [`group_signed_in`](devise_rust::helpers::group_signed_in)).
#[must_use]
pub fn group_signed_in(group: &AuthGroup, proxy: &AuthProxy) -> bool {
    devise_rust::helpers::group_signed_in(group, proxy)
}

/// Reject already-signed-in visitors from sign-in pages (SESS-08): a
/// signed-in scope yields the `already_authenticated` redirect rewritten
/// toward [`after_sign_in_path_for`](devise_rust::helpers::after_sign_in_path_for).
///
/// Re-exported from core — the redirect-rewrite toward the post-sign-in
/// path is core behavior the renderer consumes unchanged.
///
/// # Errors
///
/// Returns the navigational redirect when `scope` is signed in.
pub use devise_rust::helpers::require_no_authentication;
