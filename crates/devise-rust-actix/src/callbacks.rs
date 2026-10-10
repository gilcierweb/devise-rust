//! Bridge callbacks — key derivation and CSRF rotation.
//!
//! These are the small helpers at the intersection of framework session
//! crypto and Devise configuration, kept separate from `bridge.rs` so that
//! the bridge itself is purely about session I/O.

use actix_session::Session;
use actix_web::cookie::Key;
use devise_rust::config::DeviseConfig;
use devise_rust::error::DeviseError;

/// Derive the actix-web `Key` from the Devise `secret_key_base` via
/// [`Key::derive_from`] (D-02).
///
/// `Key::derive_from` is the **only** allowed constructor: `Key::from` accepts
/// variable-length input and can panic / weak-key; the Devise contract calls
/// for HMAC-strength derivation.
///
/// # Errors
///
/// Returns [`DeviseError::Config`] when `secret_key_base` is empty.
pub fn derive_actix_key(secret_key_base: &str) -> Result<Key, DeviseError> {
    if secret_key_base.is_empty() {
        return Err(DeviseError::Config(
            "secret_key_base must not be empty for actix-session Key derivation".to_string(),
        ));
    }
    Ok(Key::derive_from(secret_key_base.as_bytes()))
}

/// Rotate the CSRF token stored in the session for a scope when
/// `config.clean_up_csrf_token_on_authentication` is true (D-07).
///
/// The app owns the token; this bridge callback owns the rotation trigger.
/// No framework-CSRF dependency: the token lives in the session under a key
/// derived from the scope's session key (`{scope}_csrf_token`).
///
/// Silent no-op when the flag is off so callers may invoke unconditionally
/// on privilege transitions.
pub fn rotate_csrf_token(session: &Session, scope: &str, config: &DeviseConfig) {
    if !config.clean_up_csrf_token_on_authentication {
        return;
    }
    let csrf_key = format!(
        "{}_csrf_token",
        devise_rust::session::keys::scope_session_key(scope).replace(".session", "")
    );
    let token = devise_rust::crypto::friendly_token(32);
    let _ = session.insert(&csrf_key, token);
}
