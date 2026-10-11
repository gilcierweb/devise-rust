//! Axum extractors — `Auth<M>` / `RequireAuth<M>` (D-02: names identical
//! across the actix and axum crates; one doc page serves both frameworks).
//!
//! Extractors read ONLY the extensions staged by
//! [`DeviseLayer`](crate::layer::DeviseLayer):
//!
//! - [`AuthProxyHandle`](crate::layer::AuthProxyHandle) — the per-request
//!   `AuthProxy` over the tower-sessions bridge;
//! - [`AuthRequest`](devise_rust::request::AuthRequest) — the owned
//!   request snapshot;
//! - `Mapping` + `Arc<DeviseConfig>` — resolved scope and configuration.
//!
//! `Auth<M>` is the lazy `current_user` shape: it authenticates on demand
//! (session fetch, then strategies) and never rejects. `RequireAuth<M>`
//! is the `authenticate_<scope>!` shape: it fails closed, rendering the
//! core `Failure` through [`AxumFailureRenderer`](crate::failure::AxumFailureRenderer)
//! — 302 + flash for navigational formats, 401 for API.
//!
//! Extractors never touch `tower_sessions::Session` directly: all session
//! I/O flows through the proxy's bridge store.

#![allow(clippy::module_name_repetitions)]

use std::marker::PhantomData;
use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use devise_rust::config::DeviseConfig;
use devise_rust::failure::{AnyDeviseModel, FailureRenderer, build_failure};
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
                drop(proxy);
                // Devise `store_location!`: GET navigational non-XHR
                // requests are remembered in the session so post-sign-in
                // can return here (same-host-only via the core validator;
                // POST and absolute-URL targets store nothing).
                if let Some(session) = parts.extensions.get::<tower_sessions::Session>().cloned() {
                    if let Some(config) = config.as_deref() {
                        devise_rust::failure::store_location(
                            &request,
                            &mapping.name,
                            config,
                            &crate::bridge::TowerSessionStore::new(session),
                        )
                        .await;
                    }
                }
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
    AxumFailureRenderer::new().render(&classified, mapping)
}
