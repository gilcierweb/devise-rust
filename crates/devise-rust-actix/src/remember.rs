//! Remember-cookie transport — `SignedJar` wiring for the CORE codec (D-05).
//!
//! The codec triple `[key, value, generated_at]` is minted and parsed ONLY
//! by core functions
//! ([`encode_cookie_value`](devise_rust::rememberable::encode_cookie_value),
//! [`decode_cookie_value`](devise_rust::rememberable::decode_cookie_value),
//! [`parse_generated_at`](devise_rust::rememberable::parse_generated_at),
//! [`remember_cookie_valid`](devise_rust::rememberable::remember_cookie_valid)).
//! This module only moves the value through actix-web's `SignedJar`, signed
//! with the single shared secret surface (`Key::derive_from` on
//! `DeviseConfig.secret_key_base`, D-02) and dressed in the D-16 hardened
//! attributes from
//! [`RememberableCookieAttrs`].
//!
//! Every decode miss is a **stale cookie**: produce a `Clear` op and pass
//! through — never a `Failure` (Pitfall 12).
//!
//! ## Options
//!
//! The jar key derives from the Devise secret; the cookie name and the
//! `Secure` opt-out come from `rememberable_options` via
//! [`RememberableCookieAttrs::for_scope`].

use actix_web::cookie::time::OffsetDateTime;
use actix_web::cookie::{Cookie, CookieJar, Key, SameSite as ActixSameSite, SignedJar};
use devise_rust::config::DeviseConfig;
use devise_rust::error::DeviseError;
use devise_rust::rememberable::{
    RememberCookieOp, RememberableCookieAttrs, SameSite, remember_cookie_key,
};
use devise_rust::time::Clock;
use std::borrow::{Borrow, BorrowMut};

/// Derive the `SignedJar` key from the Devise secret (D-02): the same
/// `Key::derive_from` surface the session jar already uses.
///
/// # Errors
///
/// Returns [`DeviseError::Config`] when the secret is empty.
pub fn derive_remember_key(config: &DeviseConfig) -> Result<Key, DeviseError> {
    crate::callbacks::derive_actix_key(&config.secret_key)
}

/// Build the hardened `Set-Cookie` for a remember `Set` op from the core
/// attrs: `HttpOnly` always, `Secure` unless the plain-HTTP opt-out,
/// `SameSite=Lax`, `Expires = now + remember_for`, optional path/domain
/// (D-16 / Phase 5).
#[must_use]
pub fn cookie_for_set(value: &str, attrs: &RememberableCookieAttrs) -> Cookie<'static> {
    let mut builder = Cookie::build(attrs.key.clone(), value.to_string())
        .http_only(attrs.httponly)
        .same_site(match attrs.same_site {
            SameSite::Strict => ActixSameSite::Strict,
            SameSite::Lax => ActixSameSite::Lax,
            SameSite::None => ActixSameSite::None,
        })
        .path(attrs.path.clone().unwrap_or_else(|| "/".to_string()));
    if attrs.secure {
        builder = builder.secure(true);
    }
    if let Ok(expires) = OffsetDateTime::from_unix_timestamp(attrs.expires.timestamp()) {
        builder = builder.expires(expires);
    }
    if let Some(domain) = &attrs.domain {
        builder = builder.domain(domain.clone());
    }
    builder.finish()
}

/// Build the tombstone cookie for a `Clear` op (Devise `cookies.delete`).
#[must_use]
pub fn removal_cookie(name: &str) -> Cookie<'static> {
    let mut cookie = Cookie::build(name.to_string(), String::new())
        .path("/".to_string())
        .finish();
    cookie.make_removal();
    cookie
}

/// Execute one core [`RememberCookieOp`] against the signed jar: `Set`
/// signs the hardened cookie, `Clear` signs the tombstone.
pub fn apply_op<J: BorrowMut<CookieJar>>(jar: &mut SignedJar<J>, op: &RememberCookieOp) {
    match op {
        RememberCookieOp::Set { value, attrs, .. } => {
            jar.add(cookie_for_set(value, attrs));
        }
        RememberCookieOp::Clear { key, .. } => {
            jar.add(removal_cookie(key));
        }
    }
}

/// Execute every op in order against the signed jar.
pub fn apply_ops<J: BorrowMut<CookieJar>>(jar: &mut SignedJar<J>, ops: &[RememberCookieOp]) {
    for op in ops {
        apply_op(jar, op);
    }
}

/// Read outcome for a remember cookie handed in by the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RememberRead {
    /// Signature verified AND the core codec parsed the full triple with a
    /// strict integer-epoch timestamp.
    Valid {
        /// Model key from the triple.
        key: String,
        /// Remember token value from the triple.
        value: String,
        /// Integer-epoch generation timestamp from the triple.
        generated_at: String,
    },
    /// The cookie is present but its triple is malformed or its timestamp
    /// does not parse as strict integer epoch — the caller must clear the
    /// cookie and pass through (never a `Failure`).
    Stale,
    /// No such (verifiable) cookie.
    Absent,
}

/// Read-and-verify a remember cookie from the signed jar: signature check
/// via `SignedJar::get`, then the core codec via
/// [`devise_rust::rememberable::decode_cookie_value`] plus
/// [`devise_rust::rememberable::parse_generated_at`].
#[must_use]
pub fn read_cookie<J: Borrow<CookieJar>>(jar: &SignedJar<J>, name: &str) -> RememberRead {
    let Some(cookie) = jar.get(name) else {
        return RememberRead::Absent;
    };
    match devise_rust::rememberable::decode_cookie_value(cookie.value()) {
        Some((key, value, generated_at))
            if devise_rust::rememberable::parse_generated_at(&generated_at).is_some() =>
        {
            RememberRead::Valid {
                key,
                value,
                generated_at,
            }
        }
        _ => RememberRead::Stale,
    }
}

/// Build the `Clear` op for a stale/missing remember cookie (scope-aware,
/// key-override-aware via `rememberable_options`).
#[must_use]
pub fn clear_op(scope: &str, config: &DeviseConfig) -> RememberCookieOp {
    RememberCookieOp::Clear {
        scope: scope.to_string(),
        key: remember_cookie_key(scope, config),
    }
}

/// Resolve a client-presented remember cookie into either a valid triple
/// or a self-describing `Clear` op (stale or absent → `Clear`).
///
/// # Errors
///
/// Returns the boxed [`RememberCookieOp::Clear`] the caller must drain
/// through the jar whenever the inbound cookie is stale or absent (never a
/// `Failure` — stale cookies pass through after deletion).
pub fn resolve_inbound<J: Borrow<CookieJar>>(
    jar: &SignedJar<J>,
    scope: &str,
    config: &DeviseConfig,
) -> Result<(String, String, String), Box<RememberCookieOp>> {
    let name = remember_cookie_key(scope, config);
    match read_cookie(jar, &name) {
        RememberRead::Valid {
            key,
            value,
            generated_at,
        } => Ok((key, value, generated_at)),
        RememberRead::Stale | RememberRead::Absent => Err(Box::new(clear_op(scope, config))),
    }
}

/// The `Clear` op Devise `forget_me` produces: tombstone named per the
/// scope's cookie key (for test helpers and sign-out drains, D-17).
#[must_use]
pub fn forget_op(scope: &str, config: &DeviseConfig) -> RememberCookieOp {
    clear_op(scope, config)
}

/// Convenience: build the hardened attrs for `scope` at `clock.now()`.
///
/// Thin re-export surface so actix callers never need to assemble core
/// types themselves.
#[must_use]
pub fn attrs_for_scope(
    scope: &str,
    config: &DeviseConfig,
    clock: &dyn Clock,
) -> RememberableCookieAttrs {
    RememberableCookieAttrs::for_scope(scope, config, clock)
}
