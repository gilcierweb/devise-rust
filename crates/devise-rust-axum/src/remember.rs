//! Remember-cookie transport — signed-jar wiring for the CORE codec (D-16).
//!
//! The codec triple `[key, value, generated_at]` is minted and parsed ONLY
//! by core functions
//! ([`encode_cookie_value`](devise_rust::rememberable::encode_cookie_value),
//! [`decode_cookie_value`](devise_rust::rememberable::decode_cookie_value),
//! [`parse_generated_at`](devise_rust::rememberable::parse_generated_at),
//! [`remember_cookie_valid`](devise_rust::rememberable::remember_cookie_valid)).
//! This module only moves the value through the cookie 0.18 signed jar —
//! the same cookie lineage `tower-sessions` and `axum-extra` already use,
//! so a value signed here verifies in their jars with no version skew —
//! and dresses it in the D-16 hardened attributes from
//! [`RememberableCookieAttrs`].
//!
//! Every decode miss is a **stale cookie**: produce a `Clear` op and pass
//! through — never a `Failure` (Pitfall 12).
//!
//! ## Transport ownership (no droppable jar)
//!
//! The [`DeviseLayer`](crate::layer::DeviseLayer) drains the proxy
//! remember-cookie outbox AFTER the inner service responds
//! ([`ops_as_set_cookie_headers`](fn@ops_as_set_cookie_headers)), so no
//! handler ever holds a `SignedCookieJar` it could forget to return — the
//! consume-and-return trap (09-RESEARCH anti-pattern) is designed out:
//! there is exactly one transport, and it lives in the layer response
//! pipeline. Inbound, [`verified_cookie_value`] unwraps the signature so
//! the core rememberable strategy sees the plaintext triple through
//! `AuthRequest.cookies`.
//!
//! ## Options
//!
//! The jar key derives from the Devise secret (single-secret story,
//! `Key::derive_from` — never the fixed-length `Key::from`); the cookie
//! name and the `Secure` opt-out come from `rememberable_options` via
//! [`RememberableCookieAttrs::for_scope`].

use cookie::time::OffsetDateTime;
use cookie::{Cookie, CookieJar, Key, SameSite as CookieSameSite, SignedJar};
use devise_rust::config::DeviseConfig;
use devise_rust::error::DeviseError;
use devise_rust::rememberable::{
    RememberCookieOp, RememberableCookieAttrs, SameSite, remember_cookie_key,
};
use devise_rust::time::Clock;
use std::borrow::{Borrow, BorrowMut};

/// Derive the remember-jar signing `Key` from the Devise `secret_key`.
///
/// The same variable-length-safe derivation the session cookie uses
/// ([`derive_session_key`](crate::callbacks::derive_session_key)): one
/// secret rotates every consumer, and the ≥32-byte guard fails closed
/// with a `Config` error instead of the cookie-crate panic.
///
/// # Errors
///
/// Returns [`DeviseError::Config`] when the secret is shorter than 32
/// bytes.
pub fn derive_remember_key(config: &DeviseConfig) -> Result<Key, DeviseError> {
    crate::callbacks::derive_session_key(&config.secret_key)
}

/// Build the hardened `Set-Cookie` for a remember `Set` op from the core
/// attrs: `HttpOnly` always, `Secure` unless the plain-HTTP opt-out,
/// `SameSite=Lax`, `Expires = now + remember_for`, optional path/domain
/// (D-16 / Phase 5).
#[must_use]
pub fn cookie_for_set(value: &str, attrs: &RememberableCookieAttrs) -> Cookie<'static> {
    let mut builder = Cookie::build((attrs.key.clone(), value.to_string()))
        .http_only(attrs.httponly)
        .same_site(match attrs.same_site {
            SameSite::Strict => CookieSameSite::Strict,
            SameSite::Lax => CookieSameSite::Lax,
            SameSite::None => CookieSameSite::None,
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
    builder.build()
}

/// Build the tombstone cookie for a `Clear` op (Devise `cookies.delete`).
///
/// S9: the tombstone carries the SAME path/domain/secure attributes the
/// Set rendered from `rememberable_options` — a `Path=/` tombstone never
/// deletes a cookie scoped to `/app`, which would leave a live remember
/// login in the browser after sign-out.
#[must_use]
pub fn removal_cookie(name: &str, config: &DeviseConfig) -> Cookie<'static> {
    let path = config
        .rememberable_options
        .get("path")
        .cloned()
        .unwrap_or_else(|| "/".to_string());
    let mut cookie = Cookie::build((name.to_string(), String::new()))
        .path(path)
        .build();
    if let Some(domain) = config.rememberable_options.get("domain") {
        cookie.set_domain(domain.clone());
    }
    if devise_rust::rememberable::cookie_secure_flag(config) {
        cookie.set_secure(true);
    }
    cookie.make_removal();
    cookie
}

/// Execute one core [`RememberCookieOp`] against the signed jar: `Set`
/// signs the hardened cookie, `Clear` signs the tombstone (S9: the
/// tombstone carries the config's path/domain/secure attributes).
pub fn apply_op<J: BorrowMut<CookieJar>>(
    jar: &mut SignedJar<J>,
    op: &RememberCookieOp,
    config: &DeviseConfig,
) {
    match op {
        RememberCookieOp::Set { value, attrs, .. } => {
            jar.add(cookie_for_set(value, attrs));
        }
        RememberCookieOp::Clear { key, .. } => {
            jar.add(removal_cookie(key, config));
        }
    }
}

/// Execute every op in order against the signed jar.
pub fn apply_ops<J: BorrowMut<CookieJar>>(
    jar: &mut SignedJar<J>,
    ops: &[RememberCookieOp],
    config: &DeviseConfig,
) {
    for op in ops {
        apply_op(jar, op, config);
    }
}

/// Render drained [`RememberCookieOp`]s as signed `Set-Cookie` header
/// values — the layer response-pipeline transport.
///
/// One fresh `CookieJar` per call: each op signs onto the jar, and the
/// delta renders as the header strings the response carries. The Key is
/// handed in already derived (the layer derives once per response that has
/// ops); the secret only ever crosses module boundaries as bytes. The
/// config drives the `Clear` tombstone's path/domain/secure (S9).
#[must_use]
pub fn ops_as_set_cookie_headers(
    key: &Key,
    config: &DeviseConfig,
    ops: &[RememberCookieOp],
) -> Vec<String> {
    let mut jar = CookieJar::new();
    apply_ops(&mut jar.signed_mut(key), ops, config);
    jar.delta().map(ToString::to_string).collect()
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
/// via the jar, then the core codec via
/// [`decode_cookie_value`](devise_rust::rememberable::decode_cookie_value)
/// plus [`parse_generated_at`](devise_rust::rememberable::parse_generated_at).
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

/// Verify one inbound cookie value's signature, yielding the plaintext.
///
/// The layer uses this on the request path: the core rememberable strategy
/// is signer-agnostic and reads `AuthRequest.cookies`, so the verified
/// (unwrapped) value replaces the raw signed envelope there. `None` means
/// the signature did not verify — the caller keeps the raw value so the
/// strategy classifies it as stale and the response pipeline renders the
/// delete tombstone (unsigned 09-01-era cookies still parse for backward
/// compatibility).
#[must_use]
pub fn verified_cookie_value(key: &Key, name: &str, raw_value: &str) -> Option<String> {
    let jar = CookieJar::new();
    let mut owned = jar;
    owned.add_original(Cookie::new(name.to_string(), raw_value.to_string()));
    owned
        .signed(key)
        .get(name)
        .map(|cookie| cookie.value().to_string())
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
/// through the response pipeline whenever the inbound cookie is stale or
/// absent (never a `Failure` — stale cookies pass through after
/// deletion).
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
/// scope's cookie key (for test helpers and sign-out drains, T-09-07).
#[must_use]
pub fn forget_op(scope: &str, config: &DeviseConfig) -> RememberCookieOp {
    clear_op(scope, config)
}

/// Convenience: build the hardened attrs for `scope` at `clock.now()`.
///
/// Thin re-export surface so axum callers never need to assemble core
/// types themselves.
#[must_use]
pub fn attrs_for_scope(
    scope: &str,
    config: &DeviseConfig,
    clock: &dyn Clock,
) -> RememberableCookieAttrs {
    RememberableCookieAttrs::for_scope(scope, config, clock)
}
