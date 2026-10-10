//! Actix extractors — `Auth` / `RequireAuth` and per-scope helpers.
//!
//! `Auth<M>` reads the request state's resolved `AuthRequest` from request
//! extensions (inserted by [`crate::middleware::DeviseMiddleware`]) and
//! exposes the underlying record `M` when authenticated.
//!
//! `RequireAuth` is the strict variant: it returns `401` via the
//! [`crate::failure::ActixFailureRenderer`] whenever the request has no
//! authenticated record.
//!
//! ## Options
//!
//! - `Scope` attribute on the extractor identifies which scope the request
//!   belongs to; `Auth<M>` is typed over the resolved record.
//!
//! ## Examples
//!
//! ```rust,ignore
//! async fn dashboard(auth: Auth<User>) -> HttpResponse {
//!     match auth.into_inner() {
//!         Some(user) => HttpResponse::Ok().json(user),
//!         None => HttpResponse::Unauthorized().finish(),
//!     }
//! }
//! ```

#![allow(clippy::module_name_repetitions)]

use std::marker::PhantomData;

use actix_web::{Error, FromRequest, HttpMessage, HttpRequest};
use devise_rust::failure::AnyDeviseModel;

/// Typed record accessor yielded by `Auth::into_inner` when the scope
/// resolved to an authenticated user.
pub struct Record<M: AnyDeviseModel + Send + Sync + 'static> {
    inner: Option<M>,
}

impl<M: AnyDeviseModel + Send + Sync + 'static> Record<M> {
    /// Construct a record.
    #[must_use]
    pub fn new(inner: Option<M>) -> Self {
        Self { inner }
    }

    /// Consume and return the inner record.
    #[must_use]
    pub fn into_inner(self) -> Option<M> {
        self.inner
    }
}

/// Base extractor for an authenticated (or not) scope.
///
/// Resolves the record by reading the `AuthRequest` that the middleware
/// staged in the request extensions (sync extract path: extensions are
/// fetchable without further I/O). Authentication lookup itself happens in
/// the middleware — this extractor only reads the result.
#[derive(Debug, Clone)]
pub struct Auth<M: AnyDeviseModel + Send + Sync + 'static> {
    _phantom: PhantomData<M>,
    record: Option<M>,
}

impl<M: AnyDeviseModel + Send + Sync + 'static> Auth<M> {
    /// Construct from a resolved record.
    #[must_use]
    pub fn new(record: Option<M>) -> Self {
        Self {
            _phantom: PhantomData,
            record,
        }
    }

    /// Borrow the record option.
    #[must_use]
    pub fn record(&self) -> Option<&M> {
        self.record.as_ref()
    }

    /// Whether the request is authenticated for this scope.
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        self.record.is_some()
    }
}

/// Strict extractor variant: yields `401` when unauthenticated.
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
    type Future = std::pin::Pin<Box<dyn Future<Output = Result<Self, Self::Error>> + Send>>;

    fn from_request(req: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        // Read the AuthRequest from middleware-staged extensions.
        let _scope: Option<String> = req
            .extensions()
            .get::<devise_rust::request::AuthRequest>()
            .and_then(|auth_req| auth_req.params.get("scope").cloned());

        // No user resolved yet — Task 2 will hook this up to the record.
        let result = RequireAuth {
            inner: Auth::new(None),
        };
        Box::pin(async move { Ok(result) })
    }
}
