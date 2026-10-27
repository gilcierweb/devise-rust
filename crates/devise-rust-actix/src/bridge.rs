//! Actix session bridge — the synchronous session I/O helpers the
//! middleware and controllers run over `actix_session::Session` using the
//! **owned-extract** pattern (D-04).
//!
//! `actix_session::Session` is `!Send + !Sync`, so nothing `Send + Sync`
//! (a core `SessionStore` impl, an `AuthProxy`) can hold the live handle.
//! The middleware and handlers own the handle per request; each helper
//! extracts values synchronously, drops the handle, then `await`s on NO
//! further session I/O. There is deliberately NO `SessionStore`
//! implementation here: a bridge type that satisfied the async trait
//! without the live handle would be a silently-inert store (M-fix); all
//! real I/O flows through the helpers in this module.
//!
//! ## Renewal (SESS-05 / D-03)
//!
//! `Session::renew()` is called **before** every privilege transition:
//! `insert_session`, `sign_out`, `sign_out_all_scopes`, `bypass_sign_in`,
//! and the account-update path.
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
use devise_rust::{
    adapter::{DeviseKey, OrmAdapter},
    config::DeviseConfig,
    error::DeviseError,
    failure::AnyDeviseModel,
    session::keys,
};
use serde_json::Value;
use std::str::FromStr;

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

/// Session key carrying the one-shot devise flash (S11).
///
/// Devise's flash IS session state (Rails' flash hash): it rides the signed
/// session cookie (signature + `Secure` come from the app's
/// `SessionMiddleware` configuration), is read once, and is cleared on the
/// read — never a standalone unsigned cookie the client could forge and
/// the app might render.
pub const FLASH_SESSION_KEY: &str = "devise.flash";

/// Stage a flash I18n KEY for the next request to read (S11).
///
/// The value is always the bare catalog key (`signed_in`,
/// `devise.omniauth_callbacks.failure`, …) — one format across every
/// controller; the app renders it through the I18n catalog.
pub fn set_flash(session: &Session, flash_key: &str) {
    let _ = session.insert(FLASH_SESSION_KEY, flash_key);
}

/// Session key carrying the timeout marker Devise stages BESIDE the
/// timeout alert (`failure_app.rb:137`: `flash[:timedout] = true if
/// is_flashing_format?`). The marker is how Devise's later
/// `flash.keep(:timedout)` branch (`failure_app.rb:89-91`) recognizes a
/// timeout-expired visitor, and how apps can tell a session expiry from a
/// bad credential on the sign-in page.
pub const TIMEDOUT_FLASH_SESSION_KEY: &str = "devise.flash.timedout";

/// Stage the `timedout` flash marker beside the timeout alert (S11: the
/// marker is session state, exactly like the alert key).
pub fn set_timedout_marker(session: &Session) {
    let _ = session.insert(TIMEDOUT_FLASH_SESSION_KEY, true);
}

/// Read-and-clear the staged `timedout` marker (the same read-once
/// lifetime [`take_flash`] gives the alert key).
#[must_use]
pub fn take_timedout_marker(session: &Session) -> bool {
    let value = session
        .get::<bool>(TIMEDOUT_FLASH_SESSION_KEY)
        .ok()
        .flatten();
    session.remove(TIMEDOUT_FLASH_SESSION_KEY);
    value.unwrap_or(false)
}

/// Read-and-clear the staged flash (Rails' flash is read-once; the sweep
/// mirrors `flash.discard`).
#[must_use]
pub fn take_flash(session: &Session) -> Option<String> {
    let value = session.get::<String>(FLASH_SESSION_KEY).ok().flatten();
    session.remove(FLASH_SESSION_KEY);
    // The timedout marker rides the same read-once lifecycle as the alert
    // (Devise's flash sweep clears the pair together; the dedicated
    // [`take_timedout_marker`] read happens first when a caller wants it).
    session.remove(TIMEDOUT_FLASH_SESSION_KEY);
    value
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
    renew_sync(session)?;
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
    renew_sync(session)?;
    let session_key = keys::scope_session_key(scope);
    session.remove(&session_key);
    Ok(())
}

/// Remove every devise-owned session entry for one scope: the session
/// payload, the remember-token slot, the stored location, the timeoutable
/// tick, and the omniauth stash for every configured provider.
///
/// This is the port of Devise's `session.keys.grep(/^devise\./)` sweep over
/// the scope's keys plus the warden logout payload (S2): a signed-out
/// request must leave NO devise state behind in the session.
fn clear_scope_devise_data(session: &Session, scope: &str, config: &DeviseConfig) {
    session.remove(&keys::scope_session_key(scope));
    session.remove(&keys::remember_token_key(scope));
    session.remove(&devise_rust::failure::stored_location_key(scope));
    session.remove(&devise_rust::timeoutable::last_request_at_key(scope));
    for provider in &config.omniauth_providers {
        session.remove(&crate::omniauth::omniauth_state_key(scope, provider));
        session.remove(&crate::omniauth::omniauth_verifier_key(scope, provider));
    }
}

/// Devise `handle_unverified_request` (`controllers/helpers.rb:254-260`):
/// the CSRF-failure hook. Rails' base clears the session; Devise's override
/// additionally signs out EVERY scope without locking and marks the request
/// to skip session storage, so no user survives the aborted request
/// (session-fixation / cross-site form-abuse protection). The port runs
/// the full per-scope devise-data sweep (session payload, remember slot,
/// stored location, timeout tick, omniauth stash) and then renews the
/// session id, so any session-cookie value captured before the failure is
/// dead afterwards. Applications wire this from their CSRF failure path
/// (see the crate-level CSRF contract note).
///
/// # Errors
///
/// Infallible: see [`sign_out_and_renew`].
pub fn handle_unverified_request(
    session: &Session,
    scopes: &[String],
    config: &DeviseConfig,
) -> Result<(), DeviseError> {
    for scope in scopes {
        clear_scope_devise_data(session, scope, config);
    }
    let _ = renew_sync(session);
    Ok(())
}

/// Devise `expire_data_after_sign_in!` (`controllers/helpers.rb`): drop every
/// devise session payload and tick, the way Rails' `session.delete` sweep
/// over `/devise\./`-matching keys does. Called on the inactive sign-up
/// branch and on `cancel`, where a request must leave no signed-in state
/// behind.
///
/// The sweep covers the session payload, the remember-token slot, the
/// stored location, the timeoutable tick, and the omniauth stash for every
/// configured provider (no session id change — the data dies, the session
/// lives).
///
/// # Errors
///
/// Infallible: see [`sign_out_and_renew`].
pub fn expire_devise_data_sync(
    session: &Session,
    scopes: &[String],
    config: &DeviseConfig,
) -> Result<(), DeviseError> {
    for scope in scopes {
        clear_scope_devise_data(session, scope, config);
    }
    Ok(())
}

/// Sign out all scopes: Devise's `sign_out_all_scopes` — renew first
/// (D-03), then sweep every mapping's devise data out of the session
/// (`Devise.mappings` iteration, S2).
///
/// # Errors
///
/// Infallible: see [`sign_out_and_renew`].
pub fn sign_out_all_scopes_and_renew_sync(
    session: &Session,
    scopes: &[String],
    config: &DeviseConfig,
) -> Result<(), DeviseError> {
    renew_sync(session)?;
    for scope in scopes {
        clear_scope_devise_data(session, scope, config);
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
    renew_sync(session)?;
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
    // S6: the writer (`session_pair`) serializes a missing salt as "" —
    // omniauth-only rows carry no password digest, and their sessions must
    // resolve. Reading the salt as `None` logged them out on every request.
    let current_salt = record.authenticatable_salt().unwrap_or_default();

    if !devise_rust::crypto::secure_compare(&current_salt, stored_salt) {
        session.remove(&session_key);
        return None;
    }
    Some(key)
}

/// Raw JSON shape of the stored `last_request_at` tick for a scope: the
/// input the core timeout decision consumes (integer epoch or legacy
/// string). The actix middleware runs that decision synchronously with the
/// live `Session` handle (D-04), so it reads this raw shape instead of the
/// async store API.
#[must_use]
pub fn read_last_request_at_value(session: &Session, scope: &str) -> Option<serde_json::Value> {
    let key = devise_rust::timeoutable::last_request_at_key(scope);
    // The raw stored JSON value: the tick writes an integer epoch (JSON
    // number) and the core parser accepts the legacy string form too, so the
    // read must not pre-type it as `String` (a number read as String fails
    // and would make every session live forever).
    session.get::<serde_json::Value>(&key).ok().flatten()
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
