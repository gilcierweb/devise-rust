//! Tower-sessions bridge — `TowerSessionStore` implementing the core
//! [`SessionStore`] trait over a cloned
//! `tower_sessions::Session`.
//!
//! Unlike the actix crate, `tower_sessions::Session` is `Clone + Send +
//! Sync`, so the bridge holds a cloned session handle and awaits freely —
//! there is no `!Send` owned-extract dance. The one tower divergence that
//! matters: `Session::cycle_id()` is `async` AND fallible, so every renewal
//! call site propagates the error — a failed rotation fails the privilege
//! transition instead of persisting the old session id (D-04).
//!
//! ## Renewal (SESS-05 / D-04, renew-before-insert)
//!
//! The transition helpers in this module call `session.cycle_id().await?`
//! BEFORE the session write on every privilege path — sign-in, sign-out,
//! sign-out-all-scopes, bypass sign-in, and account update. The order is
//! the Devise `reset_session`-then-store shape: cycle first, then write,
//! so a store swap can never orphan state written under the old id
//! (09-RESEARCH Pitfall 2). On the default `MemoryStore` both orders
//! converge (the cycle retains data); the flagged assumption is proven by
//! the per-path rotation tests, which assert the id changed AND the
//! payload survived.
//!
//! Core `AuthProxy::set_user` itself persists with insert-then-renew and
//! `bypass_sign_in` / `sign_out` skip renewal entirely (proxy.rs gap) —
//! which is why the bridge owns the physical writes on every transition:
//! handlers run the proxy for hooks and memoization with `store: false`
//! and hand the write to the cycle-before-insert helpers here.
//!
//! ## Session payload
//!
//! Session content mirrors Devise exactly: JSON `[key, salt]` under
//! `warden.user.{scope}.session` via
//! [`keys::scope_session_key`].
//! Salt mismatch on fetch deletes the key and yields `None` (warden fetch
//! semantics); the fetch lives in core `AuthProxy`, exercised through
//! this store.
//!
//! ## Key enumeration
//!
//! `tower_sessions::Session` does not expose record-key enumeration, so
//! the bridge maintains a session-resident index of the keys it inserted
//! (under [`KEY_INDEX`]). The index rides the session record: it survives
//! `cycle_id` (data is retained) and server-side store round-trips, and
//! it is removed as soon as it empties so a fully signed-out session
//! still qualifies for cookie removal.
//!
//! ## Epoch ticks
//!
//! [`read_last_request_at`] / [`tick_last_request_at`] carry the
//! `last_request_at` Integer-epoch semantics (D-06): strict integer
//! parsing only — float strings and other malformed shapes read back as
//! `None` so timeout checks fail closed to expired.

#![allow(clippy::missing_errors_doc)] // session/serializer codes documented upstream

use devise_rust::{
    adapter::DeviseKey,
    error::DeviseError,
    session::{SessionStore, keys},
};
use serde_json::Value;
use std::fmt;
use tower_sessions::Session;

/// Session-resident index of bridge-inserted keys, enabling
/// `keys_with_prefix` / `remove_prefix` over tower-sessions (whose
/// `Session` type does not expose record enumeration).
///
/// The leading underscore keeps the name out of the `warden.*` and
/// `devise.*` namespaces.
pub const KEY_INDEX: &str = "_devise_rust_session_keys";

/// Tower-sessions-backed session store implementing the core
/// `SessionStore` trait.
///
/// The struct holds a cloned `tower_sessions::Session` handle — `Clone +
/// Send + Sync` — so the core `AuthProxy` can drive the full trait surface
/// directly, including the salt-validating fetch. One store instance belongs
/// to one request (the [`DeviseLayer`](crate::layer::DeviseLayer) creates it
/// per request); the session handle is shared, so writes through the store
/// reach the same in-flight session the response pipeline saves.
///
/// ## Examples
///
/// ```rust,ignore
/// // Inside a request with a tower Session in extensions:
/// let store = TowerSessionStore::new(session.clone());
/// let store = Arc::new(store);
/// let mut proxy = AuthProxy::new(store, registry, hooks, config);
/// ```
#[derive(Clone)]
pub struct TowerSessionStore {
    session: Session,
}

impl fmt::Debug for TowerSessionStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never surface the session handle's Debug: it includes the record
        // data (payloads, salts). Redact unconditionally (secrets contract).
        f.debug_struct("TowerSessionStore")
            .field("session", &"<tower_sessions::Session>")
            .finish()
    }
}

impl TowerSessionStore {
    /// Create a bridge over a cloned tower-sessions session handle.
    #[must_use]
    pub fn new(session: Session) -> Self {
        Self { session }
    }

    /// The underlying tower-sessions handle.
    #[must_use]
    pub fn session(&self) -> &Session {
        &self.session
    }
}

#[async_trait::async_trait]
impl SessionStore for TowerSessionStore {
    /// Read a value by key. Fails closed to `None` on store errors
    /// (a session the store cannot produce is no session).
    async fn get_value(&self, key: &str) -> Option<Value> {
        self.session.get_value(key).await.ok().flatten()
    }

    /// Insert a value by key, tracking the key in the session-resident
    /// index for later prefix enumeration.
    async fn insert_value(&self, key: &str, value: Value) {
        if self.session.insert_value(key, value).await.is_err() {
            // Store hydration failed. The transition still fails closed at
            // the session layer: `SessionManager` turns a failed end-of-
            // request save into a 500, so a silent error here never becomes
            // a fake success response.
            return;
        }
        index_insert(&self.session, key).await;
    }

    /// Remove a key, dropping it from the index.
    async fn remove(&self, key: &str) {
        let _ = self.session.remove_value(key).await;
        index_remove(&self.session, key).await;
    }

    /// Remove every indexed key with the prefix.
    async fn remove_prefix(&self, prefix: &str) {
        for key in self.keys_with_prefix(prefix).await {
            self.remove(&key).await;
        }
    }

    /// List indexed keys with the prefix.
    async fn keys_with_prefix(&self, prefix: &str) -> Vec<String> {
        index_keys(&self.session)
            .await
            .into_iter()
            .filter(|key| key.starts_with(prefix))
            .collect()
    }

    /// Renew the session: rotate the id while retaining data (SESS-05).
    ///
    /// Errors propagate so a failed rotation fails the transition.
    async fn renew(&self) -> Result<(), DeviseError> {
        self.session
            .cycle_id()
            .await
            .map_err(|e| DeviseError::Internal(format!("session cycle_id failed: {e}")))
    }

    /// Reset the session: clear all data (Devise `reset_session`
    /// semantics — the whole record goes, including app-owned keys).
    async fn reset(&self) -> Result<(), DeviseError> {
        self.session.clear().await;
        Ok(())
    }
}

/// Map a tower-sessions cycle error into the Devise error taxonomy.
///
/// Only the error category crosses (store/UUID failures); session payloads
/// and salts never enter the message. By value: `map_err` hands over
/// ownership at every call site.
#[allow(clippy::needless_pass_by_value)] // display-only use of an owned map_err argument
fn cycle_error(e: tower_sessions::session::Error) -> DeviseError {
    DeviseError::Internal(format!("session cycle_id failed: {e}"))
}

/// Insert the warden `[key, salt]` payload for a scope (shared by every
/// insert-shaped transition; the cycle call sites stay literal in each
/// public helper so the D-04 paths grep cleanly).
async fn insert_warden_payload(
    session: &Session,
    scope: &str,
    key: &DeviseKey,
    salt: &str,
) -> Result<(), DeviseError> {
    let session_key = keys::scope_session_key(scope);
    let session_value = serde_json::json!([key.to_string(), salt]);
    session
        .insert_value(&session_key, session_value)
        .await
        .map_err(|e| DeviseError::Internal(format!("session insert failed: {e}")))?;
    Ok(())
}

/// Insert the warden session payload `[key, salt]` for a scope on the
/// SIGN-IN path, cycling the session id first (D-04 renew-before-insert).
///
/// The caller runs `AuthProxy::set_user` with `store: false` for hooks and
/// memoization, then hands the physical write to this helper so the cycle
/// precedes the insert.
///
/// # Errors
///
/// Returns [`DeviseError::Internal`] when the cycle or the insert fails —
/// the transition fails instead of persisting the payload under the old id.
pub async fn insert_session_and_renew(
    session: &Session,
    scope: &str,
    key: &DeviseKey,
    salt: &str,
) -> Result<(), DeviseError> {
    // D-04 sign-in cycle call site: fires BEFORE the payload insert.
    session.cycle_id().await.map_err(cycle_error)?;
    insert_warden_payload(session, scope, key, salt).await
}

/// Insert the warden session payload on the BYPASS-SIGN-IN path (password
/// change re-sign-in without callbacks), cycling the session id first.
///
/// Closes the core gap where `AuthProxy::bypass_sign_in` writes the
/// session without any renewal (proxy.rs bypass path).
///
/// # Errors
///
/// Returns [`DeviseError::Internal`] when the cycle or the insert fails —
/// the transition fails instead of persisting the payload under the old id.
pub async fn bypass_sign_in_and_renew(
    session: &Session,
    scope: &str,
    key: &DeviseKey,
    salt: &str,
) -> Result<(), DeviseError> {
    // D-04 bypass cycle call site: fires BEFORE the payload insert.
    session.cycle_id().await.map_err(cycle_error)?;
    insert_warden_payload(session, scope, key, salt).await
}

/// Insert the warden session payload on the ACCOUNT-UPDATE path
/// (`update_with_password` → re-sign-in), cycling the session id first.
///
/// Same shape as the bypass path — the account update IS a privilege
/// transition and must never keep the pre-update id.
///
/// # Errors
///
/// Returns [`DeviseError::Internal`] when the cycle or the insert fails —
/// the transition fails instead of persisting the payload under the old id.
pub async fn account_update_and_renew(
    session: &Session,
    scope: &str,
    key: &DeviseKey,
    salt: &str,
) -> Result<(), DeviseError> {
    // D-04 account-update cycle call site: fires BEFORE the payload insert.
    session.cycle_id().await.map_err(cycle_error)?;
    insert_warden_payload(session, scope, key, salt).await
}

/// Remove the warden session payload for a scope on the SIGN-OUT path,
/// cycling the session id first (D-04).
///
/// # Errors
///
/// Returns [`DeviseError::Internal`] when the cycle fails — the transition
/// fails instead of leaving the pre-sign-out id in place.
pub async fn sign_out_and_renew(session: &Session, scope: &str) -> Result<(), DeviseError> {
    // D-04 sign-out cycle call site: fires BEFORE the key removal.
    session.cycle_id().await.map_err(cycle_error)?;
    let session_key = keys::scope_session_key(scope);
    let _ = session.remove_value(&session_key).await;
    Ok(())
}

/// Remove the warden session payload for every scope on the
/// SIGN-OUT-ALL-SCOPES path, cycling the session id first (D-04).
///
/// Closes the core gap where `AuthProxy::sign_out_all_scopes` removes
/// without renewal (proxy.rs sign-out-all path).
///
/// # Errors
///
/// Returns [`DeviseError::Internal`] when the cycle fails — the transition
/// fails instead of leaving the pre-sign-out id in place.
pub async fn sign_out_all_scopes_and_renew(
    session: &Session,
    scopes: &[String],
) -> Result<(), DeviseError> {
    // D-04 sign-out-all cycle call site: fires BEFORE the removals.
    session.cycle_id().await.map_err(cycle_error)?;
    for scope in scopes {
        let session_key = keys::scope_session_key(scope);
        let _ = session.remove_value(&session_key).await;
    }
    Ok(())
}

/// Read the integer-epoch `last_request_at` tick for a scope (D-06).
///
/// Strict integer epochs only (core
/// [`parse_last_request_at`](devise_rust::timeoutable::parse_last_request_at)):
/// float strings and every other malformed shape return `None`, so callers
/// fail closed to expired — never rescued toward valid.
pub async fn read_last_request_at(
    session: &Session,
    scope: &str,
) -> Option<chrono::DateTime<chrono::Utc>> {
    let raw = session
        .get_value(&devise_rust::timeoutable::last_request_at_key(scope))
        .await
        .ok()
        .flatten()?;
    devise_rust::timeoutable::parse_last_request_at(&raw)
}

/// Write the integer-epoch `last_request_at` tick for a scope (D-06).
pub async fn tick_last_request_at(
    session: &Session,
    scope: &str,
    clock: &dyn devise_rust::time::Clock,
) {
    let epoch = clock.now().timestamp();
    let _ = session
        .insert_value(
            &devise_rust::timeoutable::last_request_at_key(scope),
            serde_json::Value::Number(serde_json::Number::from(epoch)),
        )
        .await;
}

/// Read the bridge's key index out of the session record.
async fn index_keys(session: &Session) -> Vec<String> {
    session
        .get_value(KEY_INDEX)
        .await
        .ok()
        .flatten()
        .and_then(|value| serde_json::from_value(value).ok())
        .unwrap_or_default()
}

/// Track `key` in the session-resident index.
async fn index_insert(session: &Session, key: &str) {
    let mut known = index_keys(session).await;
    if known.iter().any(|known| known == key) {
        return;
    }
    known.push(key.to_string());
    let _ = session
        .insert_value(KEY_INDEX, serde_json::json!(known))
        .await;
}

/// Drop `key` from the index, removing the index entirely once empty so a
/// signed-out session stays record-clean.
async fn index_remove(session: &Session, key: &str) {
    let mut known = index_keys(session).await;
    let before = known.len();
    known.retain(|known| known != key);
    if known.len() == before {
        return;
    }
    if known.is_empty() {
        let _ = session.remove_value(KEY_INDEX).await;
    } else {
        let _ = session
            .insert_value(KEY_INDEX, serde_json::json!(known))
            .await;
    }
}
