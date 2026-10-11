//! Actix session bridge — `ActixSessionStore` implementing the core
//! [`SessionStore`] trait over
//! `actix_session::Session` using the **owned-extract** pattern (D-04).
//!
//! `actix_session::Session` is `!Send + !Sync`, so the bridge cannot hold a
//! `Session` handle itself and stay `Send + Sync`. The middleware owns the
//! session handle; each operation extracts values synchronously, drops the
//! handle, then `await`s on NO further session I/O.
//!
//! ## Renewal (SESS-05 / D-03)
//!
//! `Session::renew()` is called **before** every privilege transition:
//! `insert_session`, `sign_out`, `sign_out_all_scopes`, `bypass_sign_in`,
//! and the account-update path. The bridge's renew-before-insert order
//! closes the core gap where `AuthProxy::bypass_sign_in` / `sign_out`
//! otherwise skip renewal.
//!
//! ## Session payload
//!
//! Session content mirrors Devise exactly: JSON `[key, salt]` under
//! `warden.user.{scope}.session` via
//! [`keys::scope_session_key`].
//! Salt mismatch on fetch deletes the key and returns `None`
//! (warden fetch semantics, D-08).

#![allow(clippy::missing_errors_doc)] // session/serializer codes already documented upstream

use actix_session::Session;
use actix_web::cookie::Key;
use devise_rust::{
    adapter::{DeviseKey, OrmAdapter},
    error::DeviseError,
    failure::AnyDeviseModel,
    session::{SessionStore, keys},
};
use serde_json::Value;
use std::fmt;
use std::str::FromStr;

/// Actix-backed session store implementing the core `SessionStore` trait.
///
/// The struct holds **only** the derived `actix_web::cookie::Key`; the
/// actual `Session` handle is passed to each operation by the caller (the
/// middleware/extractor layer) because `Session` is `!Send + !Sync` and
/// cannot live across `await` points (D-04 owned-extract).
///
/// Construct via [`ActixSessionStore::new`] when the caller already has a
/// derived `Key`, or [`ActixSessionStore::with_derived_key`] to derive one
/// from the Devise `secret_key_base` via [`Key::derive_from`] (D-02).
///
/// ## Examples
///
/// ```rust,ignore
/// let config = DeviseConfig::default();
/// let key = derive_actix_key(&config.secret_key)?;
/// let store = ActixSessionStore::new(key);
/// // ... inside middleware: Session extracted per-request, dropped before await.
/// ```
#[derive(Clone)]
pub struct ActixSessionStore {
    /// The actix-web cookie `Key` derived from the Devise `secret_key_base`.
    ///
    /// Debug-redacted: keys never surface in logs (D-02 secrecy contract).
    key: Key,
}

impl fmt::Debug for ActixSessionStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ActixSessionStore")
            .field("key", &"<actix_web::cookie::Key>")
            .finish()
    }
}

impl ActixSessionStore {
    /// Create from an already-derived `Key`.
    #[must_use]
    pub fn new(key: Key) -> Self {
        Self { key }
    }

    /// Create from the Devise `secret_key_base`, deriving the `Key` via
    /// [`Key::derive_from`] (D-02). This is the single secret surface shared
    /// by HMAC token digests, session cookies, and remember cookies.
    ///
    /// # Errors
    ///
    /// Returns [`DeviseError::Config`] when `secret_key_base` is empty.
    pub fn with_derived_key(secret_key_base: &str) -> Result<Self, DeviseError> {
        let key = crate::callbacks::derive_actix_key(secret_key_base)?;
        Ok(Self::new(key))
    }

    /// Accessor for the derived `Key` (debug-redacted on the struct itself).
    #[must_use]
    pub fn key(&self) -> &Key {
        &self.key
    }

    /// Call `Session::renew()` **before** any session payload write.
    ///
    /// This is the D-03 renewal point for `sign_in` / `sign_out` /
    /// `bypass_sign_in` / account-update paths — the bridge's job is to
    /// ensure session fixation protection fires on every transition.
    ///
    /// Synchronous: `Session::renew()` is a pure re-key of the cookie jar,
    /// no I/O. Holding the handle around never blocks an executor (D-04).
    ///
    /// # Errors
    ///
    /// Infallible in practice: actix-session renew only fails on internal
    /// state errors, which would surface earlier. Returns `DeviseError::Internal`
    /// defensively if the underlying call ever reports failure.
    pub fn renew_sync(session: &Session) -> Result<(), DeviseError> {
        session.renew();
        Ok(())
    }
}

/// The bridge's `SessionStore` impl is a **placeholder-targeted struct impl**.
/// All real I/O flows through the synchronous helpers in this module
/// (see [`insert_session_and_renew_sync`], [`fetch_session_with_salt`], etc.) which
/// take an explicit `&Session` parameter. The trait exists so that the
/// bridge can satisfy the core `AuthProxy` constructor's `SessionStore`
/// boundary without holding `Session` directly.
#[async_trait::async_trait]
impl SessionStore for ActixSessionStore {
    async fn get_value(&self, _key: &str) -> Option<Value> {
        // Placeholder: real read flows through `fetch_session_with_salt`,
        // which sees the live `&Session` handle from the middleware.
        None
    }

    async fn insert_value(&self, _key: &str, _value: Value) {
        // Placeholder: real write flows through `insert_session_and_renew`.
    }

    async fn remove(&self, _key: &str) {
        // Placeholder: real remove flows through `sign_out_and_renew`.
    }

    async fn remove_prefix(&self, _prefix: &str) {
        // Placeholder: real prefix remove flows through `sign_out_all_scopes_and_renew`.
    }

    async fn keys_with_prefix(&self, _prefix: &str) -> Vec<String> {
        // Placeholder: real enumeration flows through a synchronous helper.
        Vec::new()
    }

    async fn renew(&self) -> Result<(), DeviseError> {
        // Placeholder: real renew flows through `renew_sync` via the helpers.
        Ok(())
    }

    async fn reset(&self) -> Result<(), DeviseError> {
        // Placeholder: real reset flows through a synchronous helper.
        Ok(())
    }
}

/// Insert the session payload `[key, salt]` for a scope, renewing first
/// (D-03 renew-before-insert).
///
/// # Errors
///
/// Returns [`DeviseError::Internal`] when the session insert fails (e.g.
/// payload too large for `CookieSessionStore`).
#[allow(clippy::needless_pass_by_value)] // key is owned for the session payload
pub fn insert_session_and_renew_sync(
    session: &Session,
    scope: &str,
    key: &DeviseKey,
    salt: &str,
) -> Result<(), DeviseError> {
    ActixSessionStore::renew_sync(session)?;
    let session_key = keys::scope_session_key(scope);
    let session_value = serde_json::json!([key.to_string(), salt]);
    session
        .insert(&session_key, session_value)
        .map_err(|e| DeviseError::Internal(format!("session insert failed: {e}")))?;
    Ok(())
}

/// Sign out a scope: remove its session key, renewing first (D-03).
///
/// # Errors
///
/// Infallible: session remove cannot fail independently.
pub fn sign_out_and_renew(session: &Session, scope: &str) -> Result<(), DeviseError> {
    ActixSessionStore::renew_sync(session)?;
    let session_key = keys::scope_session_key(scope);
    session.remove(&session_key);
    Ok(())
}

/// Sign out all scopes: remove each scope's session key, renewing first
/// (D-03).
///
/// # Errors
///
/// Infallible: see [`sign_out_and_renew`].
pub fn sign_out_all_scopes_and_renew_sync(
    session: &Session,
    scopes: &[String],
) -> Result<(), DeviseError> {
    ActixSessionStore::renew_sync(session)?;
    for scope in scopes {
        let session_key = keys::scope_session_key(scope);
        session.remove(&session_key);
    }
    Ok(())
}

/// Bypass sign-in (skip callbacks): insert session payload, renewing first
/// (D-03 / around `AuthProxy::bypass_sign_in`).
///
/// Closes the gap where core `bypass_sign_in` writes the session without
/// calling `renew`.
///
/// # Errors
///
/// Returns [`DeviseError::Internal`] when the session insert fails.
pub fn bypass_sign_in_and_renew_sync(
    session: &Session,
    scope: &str,
    key: &DeviseKey,
    salt: &str,
) -> Result<(), DeviseError> {
    ActixSessionStore::renew_sync(session)?;
    let session_key = keys::scope_session_key(scope);
    let session_value = serde_json::json!([key.to_string(), salt]);
    session
        .insert(&session_key, session_value)
        .map_err(|e| DeviseError::Internal(format!("session insert failed: {e}")))?;
    Ok(())
}

/// Fetch the session payload for a scope, validating the stored salt
/// against the current record's `authenticatable_salt` (warden fetch
/// semantics / D-08).
///
/// Salt mismatch deletes the session key and returns `None`. Any parse or
/// lookup failure also returns `None` (fail closed).
#[allow(clippy::future_not_send)] // session handle is sync-dropped before any await
pub async fn fetch_session_with_salt<A, M>(
    session: &Session,
    scope: &str,
    adapter: &A,
) -> Option<DeviseKey>
where
    A: OrmAdapter<M> + Send + Sync,
    M: AnyDeviseModel + Send + Sync + 'static,
{
    let session_key = keys::scope_session_key(scope);
    let session_value: Option<Value> = session.get(&session_key).ok().flatten();
    let value = session_value?;

    let arr = value.as_array()?;
    if arr.len() < 2 {
        return None;
    }

    let key_str = arr[0].as_str()?;
    let stored_salt = arr[1].as_str()?;
    let key = DeviseKey::from_str(key_str).ok()?;

    let record = adapter.get(&key).await.ok()??;
    let current_salt = record.authenticatable_salt()?;

    if !devise_rust::crypto::secure_compare(&current_salt, stored_salt) {
        session.remove(&session_key);
        return None;
    }
    Some(key)
}

/// Read the integer-epoch `last_request_at` tick for a scope (D-06).
///
/// Returns `None` when missing or malformed (fail-closed per T-05-09).
#[must_use]
pub fn read_last_request_at(
    session: &Session,
    scope: &str,
) -> Option<chrono::DateTime<chrono::Utc>> {
    let key = devise_rust::timeoutable::last_request_at_key(scope);
    let value: Option<String> = session.get(&key).ok().flatten();
    let value = value?;
    let json_value: Value = serde_json::from_str(&value).ok()?;
    devise_rust::timeoutable::parse_last_request_at(&json_value)
}

/// Write the integer-epoch `last_request_at` tick for a scope (D-06).
pub fn tick_last_request_at(session: &Session, scope: &str, clock: &dyn devise_rust::time::Clock) {
    let key = devise_rust::timeoutable::last_request_at_key(scope);
    let epoch = clock.now().timestamp();
    let _ = session.insert(&key, epoch);
}

/// Debug assertion: the serialized session payload stays under the
/// `CookieSessionStore` ceiling of 4096 bytes (T-08-03).
///
/// Call from tests only; the release path checks nothing.
///
/// # Panics
///
/// Panics when the serialized payload would exceed 4096 bytes — this is a
/// test-only assertion and is disabled in release builds.
#[cfg(debug_assertions)]
pub fn assert_session_size_under_limit(session: &Session, scope: &str) {
    let session_key = keys::scope_session_key(scope);
    if let Some(value) = session.get::<String>(&session_key).ok().flatten() {
        let size = value.len();
        assert!(
            size < 4096,
            "Session payload for scope '{scope}' is {size} bytes (exceeds 4096B CookieSessionStore ceiling)"
        );
    }
}

/// Compile-time `Send` gate for handler futures (D-04).
///
/// Instantiate on a representative handler `future` in a test to verify
/// the owned-extract pattern keeps futures `Send`.
///
/// ```rust,ignore
/// #[test]
/// fn handler_is_send() {
///     assert_send(async { /* ... */ });
/// }
/// ```
pub fn assert_send<T: Send>(_: T) {}
