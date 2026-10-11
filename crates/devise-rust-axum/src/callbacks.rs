//! Bridge callbacks — session-signing key derivation (CSRF rotation joins
//! in 09-02 wiring).
//!
//! These are the small helpers at the intersection of framework session
//! crypto and Devise configuration, kept separate from [`crate::bridge`]
//! so the bridge itself stays purely session I/O.

use devise_rust::error::DeviseError;
use tower_sessions::cookie::Key;

/// Minimum master-key length `Key::derive_from` accepts (HKDF input).
///
/// cookie 0.18's derivation panics below this length; the bridge fails
/// closed with a `Config` error instead of ever panicking on app input.
const MIN_SECRET_LEN: usize = 32;

/// Derive the tower-sessions signing `Key` from the Devise `secret_key`.
///
/// This is the single-secret story: the same Devise `secret_key` drives
/// HMAC token digests, session-cookie signing, and (later) remember-cookie
/// signing, so rotating one secret rotates every consumer.
///
/// `Key::derive_from` is the **only** allowed constructor: it HKDF-expands
/// any master key of at least 32 bytes, whereas the fixed-length
/// `Key::from` constructor panics unless handed exactly 64 bytes — a trap
/// for variable-length Devise secrets. The phase prohibitions forbid
/// `Key::from` entirely for Devise secrets.
///
/// # Errors
///
/// Returns [`DeviseError::Config`] when `secret_key` is shorter than 32
/// bytes — the derivation panics below that length, and app-supplied
/// secrets must fail closed, never panic.
///
/// ## Examples
///
/// ```
/// use devise_rust_axum::callbacks::derive_session_key;
///
/// assert!(derive_session_key("short").is_err());
/// assert!(derive_session_key("a-32-byte-devise-secret-key........").is_ok());
/// ```
pub fn derive_session_key(secret_key: &str) -> Result<Key, DeviseError> {
    if secret_key.len() < MIN_SECRET_LEN {
        return Err(DeviseError::Config(format!(
            "secret_key must be at least {MIN_SECRET_LEN} bytes for tower-sessions Key derivation"
        )));
    }
    Ok(Key::derive_from(secret_key.as_bytes()))
}
