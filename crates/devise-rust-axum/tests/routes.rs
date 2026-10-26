//! Route-registration parity tests (AXUM-03).
//!
//! - Route table equality: the registered router answers every
//!   `RouteSpec` from `Mapping::route_specs` — default mapping plus
//!   customization variants (`only`, `skip`, `path_names`, `sign_out_via`).
//! - Controllers: all five groups answer happy paths (+ flash-split for
//!   HTML vs JSON).
//! - Unlock routes vanish when `unlock_strategy` excludes `email`.
//! - Remember transport: the signed `Set-Cookie` carries the hardened
//!   attributes and the core codec triple (round-trip verified), stale
//!   cookies decode to delete-plus-pass-through, and the plain-HTTP
//!   `Secure` opt-out renders no `Secure` attribute.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]

mod common;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use common::{FixtureUser, SystemClock, default_mapping, test_config};
use devise_rust::adapter::OrmAdapter;
use devise_rust::config::DeviseConfig;

use devise_rust::failure::AnyDeviseModel;
use devise_rust::rememberable::{RememberCookieOp, encode_cookie_value};
use devise_rust::scope::{Mapping, Module, PathNames, SignOutVia};
use devise_rust::time::Clock as _;
use devise_rust_axum::remember as axum_remember;
use devise_rust_axum::{DeviseWebState, take_flash};
use http_body_util::BodyExt;
use tower::ServiceExt;

fn mapping_with(f: impl FnOnce(&mut Mapping)) -> Mapping {
    let mut mapping = default_mapping();
    f(&mut mapping);
    mapping
}

fn request(method: Method, uri: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .expect("request")
}

fn form_request(method: Method, uri: &str, accept: Option<&str>, payload: &str) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(accept) = accept {
        builder = builder.header(header::ACCEPT, accept);
    }
    builder
        .body(Body::from(payload.to_string()))
        .expect("request")
}

fn json_request(method: Method, uri: &str, payload: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json")
        .body(Body::from(payload.to_string()))
        .expect("request")
}

/// Extract `name=value` pairs from a response's `Set-Cookie` headers.
fn set_cookie_pairs(response: &axum::response::Response) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|v| v.split(';').next())
        .map(str::to_string)
        .collect()
}

async fn body_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body collects")
        .to_bytes();
    serde_json::from_slice(&bytes).expect("json body")
}

fn method_of(spec_method: &str) -> Method {
    spec_method.parse().expect("method parses")
}

/// Route table equality (default mapping): every core spec answers
/// (non-404) — the mounted router equals `Mapping::route_specs`.
#[tokio::test]
async fn route_table_matches_core_specs_default() {
    let mapping = default_mapping();
    let expected: Vec<(String, String)> = mapping
        .route_specs()
        .iter()
        .map(|s| (s.method.clone(), s.path.clone()))
        .collect();
    let (_state, app) = common::build_app(common::test_state(mapping));

    let mut probed = 0usize;
    for (method, path) in &expected {
        let response = app
            .clone()
            .oneshot(request(method_of(method), path))
            .await
            .expect("oneshot");
        assert_ne!(
            response.status(),
            StatusCode::NOT_FOUND,
            "spec {method} {path} must be registered, got {}",
            response.status()
        );
        probed += 1;
    }
    assert_eq!(probed, expected.len());
}

#[tokio::test]
async fn route_table_matches_core_specs_only_sessions() {
    let mapping = mapping_with(|m| {
        m.only = vec![Module::DatabaseAuthenticatable];
    });
    let expected: Vec<(String, String)> = mapping
        .route_specs()
        .iter()
        .map(|s| (s.method.clone(), s.path.clone()))
        .collect();
    assert_eq!(expected.len(), 3);
    let (_state, app) = common::build_app(common::test_state(mapping));
    for (method, path) in &expected {
        let response = app
            .clone()
            .oneshot(request(method_of(method), path))
            .await
            .expect("oneshot");
        assert_ne!(response.status(), StatusCode::NOT_FOUND, "{method} {path}");
    }
    // Registration routes must be ABSENT after only-filtering (core owns
    // the filter; the router never re-filters).
    let response = app
        .oneshot(request(Method::POST, "/users"))
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn route_table_matches_core_specs_skip_and_path_names() {
    let mapping = mapping_with(|m| {
        m.skip = vec![Module::Confirmable];
        m.path_names = PathNames {
            sign_in: "log_in".to_string(),
            sign_out: "log_out".to_string(),
            sign_up: "register".to_string(),
            password: "credentials".to_string(),
            ..PathNames::default()
        };
    });
    let (_state, app) = common::build_app(common::test_state(mapping));

    // Renamed routes answer.
    for method in [Method::GET, Method::POST] {
        let response = app
            .clone()
            .oneshot(request(method, "/users/log_in"))
            .await
            .expect("oneshot");
        assert_ne!(response.status(), StatusCode::NOT_FOUND);
    }
    // Confirmation routes are skipped entirely.
    let response = app
        .oneshot(request(Method::GET, "/users/confirmation"))
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn route_table_matches_core_specs_sign_out_via_get() {
    let mapping = mapping_with(|m| {
        m.sign_out_via = SignOutVia::Get;
    });
    let (_state, app) = common::build_app(common::test_state(mapping));
    let response = app
        .clone()
        .oneshot(request(Method::GET, "/users/sign_out"))
        .await
        .expect("oneshot");
    assert_ne!(response.status(), StatusCode::NOT_FOUND);
    // DELETE no longer matches (axum answers 405 for a known path with an
    // unregistered method).
    let response = app
        .oneshot(request(Method::DELETE, "/users/sign_out"))
        .await
        .expect("oneshot");
    assert!(
        matches!(
            response.status(),
            StatusCode::METHOD_NOT_ALLOWED | StatusCode::NOT_FOUND
        ),
        "DELETE must not match sign_out_via=GET, got {}",
        response.status()
    );
}

#[tokio::test]
async fn unlock_routes_vanish_without_email_unlock_strategy() {
    let mut config = test_config();
    config.unlock_strategy = "time".to_string();
    let mapping = default_mapping();
    let state = common::test_state_with_config(mapping, config);
    let (_state, app) = common::build_app(state);

    for (method, path) in [
        (Method::GET, "/users/unlock"),
        (Method::POST, "/users/unlock"),
    ] {
        let response = app
            .clone()
            .oneshot(request(method, path))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

/// Boot contract (Devise `raise_no_secret_key`, `rails/routes.rb:228`): an
/// EMPTY `secret_key` must fail state construction with the actionable
/// `must be set` Config error — it keys every token HMAC, so a boot
/// without it is a silent account-takeover channel.
#[test]
fn web_state_refuses_empty_secret_key_at_boot() {
    let result = DeviseWebState::<
        FixtureUser,
        common::IdAssigningAdapter,
        devise_rust::mailer::TestMailer,
    >::new(
        default_mapping(),
        common::registry_with(&[default_mapping()]),
        std::sync::Arc::new(DeviseConfig {
            secret_key: "   ".to_string(),
            ..test_config()
        }),
        std::sync::Arc::new(common::IdAssigningAdapter::new()),
        std::sync::Arc::new(devise_rust::mailer::TestMailer::default()),
        std::sync::Arc::new(SystemClock),
    );
    let Err(err) = result else {
        panic!("an empty secret_key must fail at boot");
    };
    assert!(
        matches!(
            &err,
            devise_rust::error::DeviseError::Config(message)
                if message.contains("secret_key must be set")
        ),
        "the boot failure must carry the raise_no_secret_key contract: {err:?}"
    );
}

/// Sessions controller: correct credentials sign in (302 + `signed_in`
/// flash toward the scope root for HTML; JSON callers get 200), wrong
/// credentials split per format.
#[tokio::test]
async fn sessions_controller_happy_path_and_flash_split() {
    let (state, app) = common::build_app(common::test_state(default_mapping()));
    let config = common::test_config();
    let user = FixtureUser::new_with_password("route@example.com", "secret123", &config)
        .confirmed_now(&SystemClock);
    state.adapter.create(user).await.expect("seed");

    // HTML: 302 + flash cookie toward the scope root (the core
    // `after_sign_in_path_for` fallback).
    let response = app
        .clone()
        .oneshot(form_request(
            Method::POST,
            "/users/sign_in",
            Some("text/html"),
            "email=route%40example.com&password=secret123",
        ))
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/users")
    );
    let cookies = set_cookie_pairs(&response);
    assert!(
        common::flash_keys_from_cookies(&cookies, &state.config).contains(&"signed_in".to_string()),
        "flash cookie carries signed_in: {cookies:?}"
    );
    assert!(
        cookies.iter().any(|c| c.starts_with("id=")),
        "session cookie rotated"
    );

    // JSON failure: wrong password → 401 with the symbolic key.
    let response = app
        .oneshot(json_request(
            Method::POST,
            "/users/sign_in",
            r#"{"email":"route@example.com","password":"wrong"}"#,
        ))
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = body_json(response).await;
    assert_eq!(body["error"], serde_json::json!("invalid"));
}

/// Registrations create: valid params sign up + sign in; duplicate email
/// lands 422 in both formats; the form routes answer.
#[tokio::test]
async fn registrations_controller_create_matrix() {
    let (state, app) = common::build_app(common::test_state(default_mapping()));
    let config = common::test_config();
    let existing = FixtureUser::new_with_password("taken@example.com", "secret123", &config)
        .confirmed_now(&SystemClock);
    state.adapter.create(existing).await.expect("seed");

    // Valid JSON sign-up → 201.
    let response = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/users",
            r#"{"user":{"email":"new@example.com","password":"secret123","password_confirmation":"secret123"}}"#,
        ))
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::CREATED);

    // Duplicate email → 422 with :taken key on email.
    let response = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/users",
            r#"{"user":{"email":"taken@example.com","password":"secret123","password_confirmation":"secret123"}}"#,
        ))
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = body_json(response).await;
    let errors = body["errors"]["email"].as_array().expect("email errors");
    assert!(
        errors
            .iter()
            .any(|e| e.as_str().is_some_and(|s| s.contains("taken"))),
        "{errors:?}"
    );

    // Remaining form routes exist (new/edit gated, cancel open). Devise's
    // cancel expires the session data and redirects to the sign-up path
    // (registrations_controller.rb:78-81) — 303, not the old stub body.
    let response = app
        .clone()
        .oneshot(request(Method::GET, "/users/sign_up"))
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::OK, "/users/sign_up");

    let response = app
        .clone()
        .oneshot(request(Method::GET, "/users/cancel"))
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::SEE_OTHER, "/users/cancel");
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/users/sign_up"),
        "cancel redirects to the sign-up path"
    );
}

/// Passwords controller: create always sends instructions (201 JSON); edit
/// without a token redirects with the `no_token` flash.
#[tokio::test]
async fn passwords_controller_basics() {
    let (state, app) = common::build_app(common::test_state(default_mapping()));
    let config = common::test_config();
    let user = FixtureUser::new_with_password("reset@example.com", "secret123", &config)
        .confirmed_now(&SystemClock);
    state.adapter.create(user).await.expect("seed");

    let response = app
        .clone()
        .oneshot(form_request(
            Method::POST,
            "/users/password",
            Some("application/json"),
            "email=reset%40example.com",
        ))
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        state.mailer.sent_mails().len(),
        1,
        "reset instructions mailed"
    );

    // assert_reset_token_passed: missing token → redirect + no_token flash.
    let response = app
        .oneshot(request(Method::GET, "/users/password/edit"))
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::FOUND);
    let cookies = set_cookie_pairs(&response);
    assert!(
        common::flash_keys_from_cookies(&cookies, &state.config).contains(&"no_token".to_string()),
        "{cookies:?}"
    );
}

/// Unconfirmed fixture with the DIGEST of `raw` stored in the token column
/// (the real mailed-link shape: emails carry the raw, the DB the digest).
fn unconfirmed_with_token(email: &str, raw: &str, config: &DeviseConfig) -> FixtureUser {
    let mut user = FixtureUser::new_with_password(email, "secret123", config);
    user.confirmation_token = Some(devise_rust::crypto::token_generator::digest(
        &config.secret_key,
        devise_rust::confirmable::CONFIRMATION_TOKEN_COLUMN,
        raw,
    ));
    user.confirmation_sent_at = Some(SystemClock.now());
    user
}

/// Confirmations controller: the mailed raw token confirms the account —
/// HTML answers 302 to the sign-in path with the `confirmed` flash, JSON
/// answers 200 with the confirmed body (CNF controller happy path).
#[tokio::test]
async fn confirmations_controller_happy_path() {
    let (state, app) = common::build_app(common::test_state(default_mapping()));
    let config = common::test_config();
    state
        .adapter
        .create(unconfirmed_with_token(
            "confirm@example.com",
            "raw-confirm-one",
            &config,
        ))
        .await
        .expect("seed html user");
    state
        .adapter
        .create(unconfirmed_with_token(
            "confirm-json@example.com",
            "raw-confirm-two",
            &config,
        ))
        .await
        .expect("seed json user");

    // HTML: 302 → sign-in path with the `confirmed` flash.
    let response = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/users/confirmation?confirmation_token=raw-confirm-one",
        ))
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/users/sign_in")
    );
    let cookies = set_cookie_pairs(&response);
    assert!(
        common::flash_keys_from_cookies(&cookies, &state.config).contains(&"confirmed".to_string()),
        "{cookies:?}"
    );

    // JSON: 200 with the confirmed body.
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/users/confirmation?confirmation_token=raw-confirm-two")
                .header(header::ACCEPT, "application/json")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["confirmed"], serde_json::json!(true));
}

/// Unlocks controller: the emailed raw token unlocks the locked account —
/// HTML answers 302 to the sign-in path with the `unlocked` flash and the
/// lock is released in the store (LCK controller happy path).
#[tokio::test]
async fn unlocks_controller_happy_path() {
    let (state, app) = common::build_app(common::test_state(default_mapping()));
    let config = common::test_config();
    let mut user = FixtureUser::new_with_password("locked@example.com", "secret123", &config)
        .confirmed_now(&SystemClock);
    user.locked_at = Some(SystemClock.now());
    user.unlock_token = Some(devise_rust::crypto::token_generator::digest(
        &config.secret_key,
        devise_rust::lockable::UNLOCK_TOKEN_COLUMN,
        "raw-unlock-one",
    ));
    let user = state.adapter.create(user).await.expect("seed locked user");

    let response = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/users/unlock?unlock_token=raw-unlock-one",
        ))
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/users/sign_in")
    );
    let cookies = set_cookie_pairs(&response);
    assert!(
        common::flash_keys_from_cookies(&cookies, &state.config).contains(&"unlocked".to_string()),
        "{cookies:?}"
    );

    // The account is actually unlocked in the store.
    let reloaded = state
        .adapter
        .get(&user.to_key())
        .await
        .expect("reload")
        .expect("user persists");
    assert!(
        reloaded.locked_at.is_none(),
        "lock released: {:?}",
        reloaded.locked_at
    );
}

// ============================================================================
// Remember transport (signed jar over the core codec)
// ============================================================================

/// The end-to-end remember transport: sign in with `remember_me` and the
/// response's remember `Set-Cookie` carries the hardened attributes, the
/// signature, and the core codec triple (verified by round-trip).
#[tokio::test]
async fn remember_set_cookie_carries_hardened_attrs_and_codec() {
    let (state, app) = common::build_app(common::test_state(default_mapping()));
    let config = common::test_config();
    let user = FixtureUser::new_with_password("remember@example.com", "secret123", &config)
        .confirmed_now(&SystemClock);
    let created = state.adapter.create(user).await.expect("seed");

    let response = app
        .clone()
        .oneshot(form_request(
            Method::POST,
            "/users/sign_in",
            Some("text/html"),
            "email=remember%40example.com&password=secret123&remember_me=1",
        ))
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::FOUND);
    let set_cookies: Vec<String> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_string))
        .collect();
    let remember_header = set_cookies
        .iter()
        .find(|c| c.starts_with("remember_user_token="))
        .expect("remember Set-Cookie drained through the signed transport");

    // D-16 hardened attributes on the wire.
    assert!(remember_header.contains("HttpOnly"), "{remember_header}");
    assert!(remember_header.contains("Secure"), "{remember_header}");
    assert!(
        remember_header.contains("SameSite=Lax"),
        "{remember_header}"
    );
    assert!(remember_header.contains("Expires="), "{remember_header}");

    // Expires ~= sign-in instant + remember_for (D-13).
    let parsed = cookie::Cookie::parse(remember_header.clone()).expect("cookie parses");
    let expires = parsed
        .expires()
        .and_then(cookie::Expiration::datetime)
        .expect("expires renders");
    let expected = SystemClock.now() + state.config.remember_for;
    let skew = (expires.unix_timestamp() - expected.timestamp()).abs();
    assert!(skew <= 5, "expires ~= now + remember_for, skew {skew}s");

    // The signed value: 44-char HMAC digest prefix + the core codec
    // triple in plaintext (cookie 0.18 signed semantics).
    let raw_value = remember_header
        .trim_start_matches("remember_user_token=")
        .split(';')
        .next()
        .unwrap_or_default();
    assert!(
        raw_value.len() > 44 + 2,
        "value carries the 44-char digest prefix + payload"
    );

    // Round-trip: a fresh jar over the same key verifies the signature and
    // exposes the core codec triple.
    let key = axum_remember::derive_remember_key(&state.config).expect("derive");
    let mut read_jar = cookie::CookieJar::new();
    read_jar.add_original(cookie::Cookie::new(
        "remember_user_token".to_string(),
        raw_value.to_string(),
    ));
    match axum_remember::read_cookie(&read_jar.signed(&key), "remember_user_token") {
        axum_remember::RememberRead::Valid {
            key: triple_key,
            value,
            generated_at,
        } => {
            assert_eq!(triple_key, created.id.to_string());
            // The fixture has no remember_token column: the value is the
            // authenticatable salt (bcrypt digest prefix).
            assert_eq!(value, created.authenticatable_salt().unwrap_or_default());
            assert!(
                generated_at.parse::<i64>().is_ok(),
                "integer epoch timestamp"
            );
        }
        other => panic!("expected Valid, got {other:?}"),
    }
}

/// Stale signed cookie: signature verifies but the codec rejects — the
/// read yields `Stale` and `resolve_inbound` returns the `Clear` op
/// (delete-and-pass-through, never a `Failure`).
#[tokio::test]
async fn stale_signed_cookie_yields_clear_and_pass_through() {
    let config = common::test_config();
    let key = axum_remember::derive_remember_key(&config).expect("derive");

    // Properly SIGNED garbage value: signature verifies, codec rejects.
    let mut jar = cookie::CookieJar::new();
    {
        let mut signed = jar.signed_mut(&key);
        signed.add(cookie::Cookie::new(
            "remember_user_token".to_string(),
            "not-a-triple".to_string(),
        ));
    }
    assert_eq!(
        axum_remember::read_cookie(&jar.signed(&key), "remember_user_token"),
        axum_remember::RememberRead::Stale
    );

    // Stale decodes to a Clear op (scope- and key-aware).
    let clear = axum_remember::resolve_inbound(&jar.signed(&key), "user", &config)
        .expect_err("stale inbound resolves to a clear op");
    let RememberCookieOp::Clear {
        key: clear_key,
        scope: clear_scope,
    } = &*clear
    else {
        panic!("clear op");
    };
    assert_eq!(clear_key, "remember_user_token");
    assert_eq!(clear_scope, "user");

    // Applying the clear renders a signed tombstone (delete + pass).
    let headers = axum_remember::ops_as_set_cookie_headers(
        &key,
        &config,
        std::slice::from_ref(clear.as_ref()),
    );
    assert_eq!(headers.len(), 1, "one tombstone delta");
    let tombstone = &headers[0];
    assert!(tombstone.starts_with("remember_user_token="), "{tombstone}");
    assert!(tombstone.contains("Max-Age=0"), "tombstone: {tombstone}");
}

/// The plain-HTTP development opt-out: `rememberable_options["secure"] =
/// "false"` renders no `Secure` attribute; the `key` override renames the
/// cookie.
#[tokio::test]
async fn secure_opt_out_renders_no_secure_attribute() {
    use devise_rust::time::Clock as _;

    let mut config = common::test_config();
    config
        .rememberable_options
        .insert("secure".to_string(), "false".to_string());
    let clock = SystemClock;
    let attrs = axum_remember::attrs_for_scope("user", &config, &clock);
    let value = encode_cookie_value("1", "raw-token", &clock.now().timestamp().to_string());
    let cookie = axum_remember::cookie_for_set(&value, &attrs);
    let rendered = cookie.to_string();
    assert!(!rendered.contains("Secure"), "{rendered}");
    assert!(rendered.contains("HttpOnly"), "{rendered}");
    assert!(rendered.contains("SameSite=Lax"), "{rendered}");

    // Key override through rememberable_options.
    let mut keyed = common::test_config();
    keyed
        .rememberable_options
        .insert("key".to_string(), "custom_remember".to_string());
    let attrs = axum_remember::attrs_for_scope("user", &keyed, &clock);
    assert_eq!(attrs.key, "custom_remember");
}

/// S9 (security audit): the remember `Clear` tombstone must carry the SAME
/// path/domain/secure attributes as the Set — a `Path=/` tombstone never
/// deletes a cookie the app scoped to `/app`, leaving a live remember
/// login in the browser after sign-out (a T-09-07 regression).
#[test]
fn clear_tombstone_carries_the_configured_path_domain_and_secure() {
    use devise_rust::time::Clock as _;

    let mut config = common::test_config();
    config
        .rememberable_options
        .insert("path".to_string(), "/app".to_string());
    config
        .rememberable_options
        .insert("domain".to_string(), "example.com".to_string());
    let clock = SystemClock;
    let attrs = axum_remember::attrs_for_scope("user", &config, &clock);

    // The Set cookie renders with the configured attrs.
    let value = encode_cookie_value("1", "raw-token", &clock.now().timestamp().to_string());
    let set = axum_remember::cookie_for_set(&value, &attrs);
    assert_eq!(set.path(), Some("/app"));
    assert_eq!(set.domain(), Some("example.com"));
    assert_eq!(set.secure(), Some(true));

    // The tombstone must match the Set attrs exactly.
    let clear = axum_remember::clear_op("user", &config);
    let RememberCookieOp::Clear { key: clear_key, .. } = &clear else {
        panic!("clear op");
    };
    let removal = axum_remember::removal_cookie(clear_key, &config);
    assert_eq!(
        removal.path(),
        Some("/app"),
        "tombstone must carry the Set cookie's path"
    );
    assert_eq!(
        removal.domain(),
        Some("example.com"),
        "tombstone must carry the Set cookie's domain"
    );
    assert_eq!(
        removal.secure(),
        Some(true),
        "tombstone must carry the Set cookie's Secure flag"
    );
}

/// S11: `take_flash` is the read-once consumer — a signed envelope yields
/// the bare flash key PLUS the clearing tombstone the caller must attach;
/// with the cookie consumed (absent), the next read is `None`.
#[test]
fn flash_take_flash_reads_once_and_clears() {
    let config = common::test_config();
    let key = devise_rust_axum::callbacks::derive_session_key(&config.secret_key)
        .expect("flash key derives");

    // Mint a signed flash envelope exactly like `flash_cookie_header`.
    let mut jar = cookie::CookieJar::new();
    jar.signed_mut(&key).add(cookie::Cookie::new(
        "devise.flash",
        "signed_in".to_string(),
    ));
    let raw = jar
        .iter()
        .find(|c| c.name() == "devise.flash")
        .map(|c| c.value().to_string())
        .expect("signed envelope renders");
    assert_ne!(raw, "signed_in", "the envelope is MAC-prefixed, not bare");

    let mut request =
        devise_rust::request::AuthRequest::new(devise_rust::request::HttpMethod::Get, "/".to_string());
    request
        .cookies
        .insert("devise.flash".to_string(), raw);
    let read = take_flash(&request, &config);
    assert_eq!(read.key.as_deref(), Some("signed_in"));
    let clear = read.clear.expect("read-once hands back the tombstone");
    assert!(
        String::from_utf8_lossy(clear.as_bytes()).contains("Max-Age=0"),
        "the tombstone clears the cookie: {clear:?}"
    );

    // Consumed: no cookie left, so nothing reads back and nothing clears.
    let consumed =
        devise_rust::request::AuthRequest::new(devise_rust::request::HttpMethod::Get, "/".to_string());
    let read = take_flash(&consumed, &config);
    assert!(read.key.is_none() && read.clear.is_none());
}

/// S11: a TAMPERED flash envelope never yields a key — and is still
/// cleared, so a forged flash neither renders nor survives.
#[test]
fn flash_take_flash_rejects_tampered_values() {
    let config = common::test_config();
    let key = devise_rust_axum::callbacks::derive_session_key(&config.secret_key)
        .expect("flash key derives");

    let mut jar = cookie::CookieJar::new();
    jar.signed_mut(&key).add(cookie::Cookie::new(
        "devise.flash",
        "signed_in".to_string(),
    ));
    let raw = jar
        .iter()
        .find(|c| c.name() == "devise.flash")
        .map(|c| c.value().to_string())
        .expect("signed envelope renders");
    // Flip one character inside the MAC region.
    let mut tampered = raw;
    let first = if tampered.starts_with('X') { 'Y' } else { 'X' };
    tampered.replace_range(0..1, &first.to_string());

    let mut request =
        devise_rust::request::AuthRequest::new(devise_rust::request::HttpMethod::Get, "/".to_string());
    request
        .cookies
        .insert("devise.flash".to_string(), tampered);
    let read = take_flash(&request, &config);
    assert!(
        read.key.is_none(),
        "a tampered flash envelope must never yield a key: {:?}",
        read.key
    );
    assert!(
        read.clear.is_some(),
        "a tampered flash must still be cleared"
    );
}
