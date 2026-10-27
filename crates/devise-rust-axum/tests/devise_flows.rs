//! Ported devise `test/integration` flows for axum (TEST-02 axum leg).
//!
//! Drives the real middleware + controllers via `tower::ServiceExt::oneshot`
//! with cookie replay, mirroring Devise's integration suite (and the actix
//! leg's matrix): sign in/out, flashes, redirects, error keys, cookie
//! flows — including the two-cookie-jar salt + remember regression
//! (Phase 5 D-15), the four-path D-04 renewal gates (sign-in, bypass
//! sign-in, account update, sign-out), and the IntegrationHelpers-parity
//! bypass probes (`sign_in` reaches a protected route without posting a
//! password; `sign_out` clears it).

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]

mod common;

use axum::Router;
use axum::body::Body;
use axum::extract::Query;
use axum::http::{Method, Request, StatusCode, header};
use axum::response::IntoResponse;
use common::{FixtureUser, SystemClock, default_mapping};
use devise_rust::adapter::{Conditions, OrmAdapter, Value};
use devise_rust::config::DeviseConfig;
use devise_rust::failure::AnyDeviseModel;
use devise_rust::hooks::HookRegistry;
use devise_rust::model::{AdapterBridge, ModelFinder};
use devise_rust::time::Clock as _;
use devise_rust_axum::test_helpers::{cookie_header, set_cookie_pairs};
use devise_rust_axum::{DeviseLayer, devise_for_router, session_manager_layer};
use http_body_util::BodyExt;
use std::sync::Arc;
use tower::ServiceExt;
use tower_sessions::Session;

type Response = axum::http::Response<axum::body::Body>;

/// Browser-style cookie jar: newest value per name, renewal-aware.
struct Jar(Vec<String>);

impl Jar {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn merge(&mut self, response: &Response) {
        for pair in set_cookie_pairs(response) {
            let name = pair.split('=').next().unwrap_or("").to_string();
            self.0
                .retain(|existing| existing.split('=').next() != Some(name.as_str()));
            if !name.is_empty() {
                self.0.push(pair);
            }
        }
    }

    fn header(&self) -> String {
        cookie_header(&self.0)
    }

    fn value(&self, name: &str) -> Option<String> {
        self.0
            .iter()
            .find(|c| c.starts_with(&format!("{name}=")))
            .and_then(|c| c.split_once('='))
            .map(|(_, v)| v.to_string())
    }
}

impl Default for Jar {
    fn default() -> Self {
        Self::new()
    }
}

async fn call(app: &Router, request: Request<Body>) -> Response {
    app.clone().oneshot(request).await.expect("oneshot")
}

async fn body_text(response: Response) -> String {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body collects")
        .to_bytes();
    String::from_utf8(bytes.to_vec()).expect("utf8")
}

async fn body_json(response: Response) -> serde_json::Value {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body collects")
        .to_bytes();
    serde_json::from_slice(&bytes).expect("json body")
}

async fn seed_user(state: &common::TestState, email: &str, password: &str) -> FixtureUser {
    let mut user =
        FixtureUser::new_with_password(email, password, &state.config).confirmed_now(&SystemClock);
    user = state.adapter.create(user).await.expect("seed");
    user
}

/// Seed WITHOUT a `confirmed_at` stamp (confirmable flows own confirmation).
async fn seed_user_unconfirmed(
    state: &common::TestState,
    email: &str,
    password: &str,
) -> FixtureUser {
    let user = FixtureUser::new_with_password(email, password, &state.config);
    state.adapter.create(user).await.expect("seed")
}

fn urlencode(email: &str) -> String {
    email.replace('@', "%40")
}

fn form_sign_in_request(email: &str, password: &str, cookie: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri("/users/sign_in")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder
        .body(Body::from(format!(
            "email={}&password={password}",
            urlencode(email)
        )))
        .expect("request")
}

async fn form_sign_in(app: &Router, email: &str, password: &str) -> Response {
    call(app, form_sign_in_request(email, password, None)).await
}

/// Devise `authentication_test.rb`: sign in → 302 + `signed_in` flash +
/// renewed session; sign out → 302 + `signed_out` flash; the jar ends
/// anonymous.
#[tokio::test]
async fn flow_sign_in_and_sign_out_with_flashes() {
    let (state, app) = common::build_app(common::test_state(default_mapping()));
    seed_user(&state, "flow@example.com", "secret123").await;

    let mut jar = Jar::new();
    // Anonymous GET sign-in form primes a session cookie.
    let resp = call(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri("/users/sign_in")
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    jar.merge(&resp);
    let anon_session = jar.value("id");

    let resp = form_sign_in(&app, "flow@example.com", "secret123").await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    jar.merge(&resp);
    assert!(
        common::flash_keys_from_cookies(&jar.0, &state.config).contains(&"signed_in".to_string()),
        "signed_in flash expected in the jar"
    );
    let signed_in_session = jar.value("id").expect("session cookie");
    assert_ne!(
        anon_session.as_deref(),
        Some(signed_in_session.as_str()),
        "session id rotates on sign-in (D-04 fixation guard)"
    );

    // Authenticated probe: the layer resolved the seeded user.
    let resp = call(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri("/users_dashboard")
            .header(header::COOKIE, jar.header())
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["email"], serde_json::json!("flow@example.com"));

    // Sign out: 302 + signed_out + rotate again (remember tombstone is
    // covered by the regression test below).
    let resp = call(
        &app,
        Request::builder()
            .method(Method::DELETE)
            .uri("/users/sign_out")
            .header(header::COOKIE, jar.header())
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    jar.merge(&resp);
    assert!(
        common::flash_keys_from_cookies(&jar.0, &state.config).contains(&"signed_out".to_string()),
        "signed_out flash expected in the jar"
    );
    let signed_out_session = jar.value("id");
    assert_ne!(
        signed_out_session.as_deref(),
        Some(signed_in_session.as_str()),
        "session id rotates on sign-out"
    );

    // Jar is now signed out.
    let resp = call(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri("/users_dashboard")
            .header(header::COOKIE, jar.header())
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
}

/// Devise parity (`strategies/database_authenticatable.rb:24-25`): an unknown
/// account fails with `not_found_in_database` outside paranoid mode.
#[tokio::test]
async fn flow_sign_in_unknown_email_reports_not_found() {
    let (state, app) = common::build_app(common::test_state(default_mapping()));
    seed_user(&state, "known@example.com", "secret123").await;

    let resp = form_sign_in(&app, "ghost@example.com", "secret123").await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let cookies = set_cookie_pairs(&resp);
    assert!(
        common::flash_keys_from_cookies(&cookies, &state.config)
            .contains(&"not_found_in_database".to_string()),
        "not_found_in_database flash on unknown email: {cookies:?}"
    );
}

/// Devise parity: inside paranoid mode the same miss reports the unified
/// `invalid` key (no enumeration oracle).
#[tokio::test]
async fn flow_sign_in_unknown_email_paranoid_reports_invalid() {
    let mut config = common::test_config();
    config.paranoid = true;
    let (state, app) = common::build_app(common::test_state_with_config(default_mapping(), config));
    seed_user(&state, "known@example.com", "secret123").await;

    let resp = form_sign_in(&app, "ghost@example.com", "secret123").await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let cookies = set_cookie_pairs(&resp);
    assert!(
        common::flash_keys_from_cookies(&cookies, &state.config).contains(&"invalid".to_string()),
        "unified invalid flash under paranoid: {cookies:?}"
    );
    assert!(
        !common::flash_keys_from_cookies(&cookies, &state.config)
            .contains(&"not_found_in_database".to_string()),
        "paranoid must not leak account absence: {cookies:?}"
    );
}

/// Devise's `request_keys` second parse pass
/// (`strategies/authenticatable.rb:147-167`, integration contract
/// `authenticatable_test.rb:579-608`): a configured request key the layer
/// snapshot never carries (neither `host`-mapped nor `remote_ip`-mapped) is a
/// MISSING REQUIRED lookup condition, so the parse fails before
/// `find_for_authentication` runs: which is why CORRECT credentials fail
/// exactly like the wrong-password flow: the navigational 302 plus the
/// generic `invalid` flash, and the returned cookies stay anonymous.
#[tokio::test]
async fn flow_sign_in_request_keys_missing_aborts_before_lookup() {
    let mut config = common::test_config();
    config.request_keys = vec!["subdomain".to_string()];
    let (state, app) = common::build_app(common::test_state_with_config(default_mapping(), config));
    seed_user(&state, "flow-rk@example.com", "secret123").await;

    let resp = form_sign_in(&app, "flow-rk@example.com", "secret123").await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(
        resp.headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/users/sign_in"),
        "the navigational failure path redirects back to the sign-in form"
    );
    let cookies = set_cookie_pairs(&resp);
    assert!(
        common::flash_keys_from_cookies(&cookies, &state.config).contains(&"invalid".to_string()),
        "a missing required request key reports the generic invalid failure: {cookies:?}"
    );

    // The failure jar must not authenticate against a guarded route.
    let mut jar = Jar::new();
    jar.merge(&resp);
    let probe = call(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri("/users_dashboard")
            .header(header::COOKIE, jar.header())
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(
        probe.status(),
        StatusCode::FOUND,
        "a failed sign-in must not mint a session"
    );
}

/// Devise: invalid password → 302 back to `sign_in` with the `invalid`
/// flash (HTML) and 401 + symbolic key for JSON callers (D-09 analogue).
#[tokio::test]
async fn flow_sign_in_failure_formats() {
    let (state, app) = common::build_app(common::test_state(default_mapping()));
    seed_user(&state, "flow2@example.com", "secret123").await;

    let resp = form_sign_in(&app, "flow2@example.com", "wrongpass").await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let cookies = set_cookie_pairs(&resp);
    assert!(
        common::flash_keys_from_cookies(&cookies, &state.config).contains(&"invalid".to_string()),
        "invalid flash on HTML miss: {cookies:?}"
    );

    let resp = call(
        &app,
        Request::builder()
            .method(Method::POST)
            .uri("/users/sign_in")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json")
            .body(Body::from(
                r#"{"email":"flow2@example.com","password":"wrongpass"}"#,
            ))
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = body_json(resp).await;
    assert_eq!(body["error"], serde_json::json!("invalid"));
}

/// Devise `registerable` failure path: mismatched confirmation re-renders
/// (the configured `error_status`, 200 by default) with the virtual
/// password fields cleared (never echoed back).
#[tokio::test]
async fn flow_sign_up_failure_clears_passwords_and_keeps_errors() {
    let (_state, app) = common::build_app(common::test_state(default_mapping()));

    let resp = call(
        &app,
        Request::builder()
            .method(Method::POST)
            .uri("/users")
            .header(
                header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(Body::from(
                "user[email]=flow3%40example.com&user[password]=secret123&user[password_confirmation]=mismatch",
            ))
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let text = body_text(resp).await;
    assert!(
        text.contains("confirmation"),
        "confirmation error key: {text}"
    );
    assert!(
        !text.contains("secret123"),
        "passwords must never echo back: {text}"
    );
}

/// Devise: the `current_password` gate — a wrong current password updates
/// nothing (`encrypted_password` byte-identical afterwards), answering the
/// configured `error_status` (200 by default).
#[tokio::test]
async fn flow_account_update_requires_current_password() {
    let (state, app) = common::build_app(common::test_state(default_mapping()));
    let user = seed_user(&state, "flow4@example.com", "secret123").await;
    let digest_before = user.encrypted_password.clone();

    let mut jar = Jar::new();
    let resp = form_sign_in(&app, "flow4@example.com", "secret123").await;
    jar.merge(&resp);

    let resp = call(
        &app,
        Request::builder()
            .method(Method::PATCH)
            .uri("/users")
            .header(header::COOKIE, jar.header())
            .header(
                header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(Body::from(
                "user[current_password]=wrongpass&user[password]=brand-new-pass&user[password_confirmation]=brand-new-pass",
            ))
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let mut conditions = Conditions::new();
    conditions.insert("email", Value::String("flow4@example.com".to_string()));
    let after = state
        .adapter
        .find_first(&conditions)
        .await
        .expect("lookup")
        .expect("record");
    assert_eq!(after.encrypted_password, digest_before, "nothing persisted");
}

/// Devise reconfirmable parity (`confirmable.rb:261-270`, #5783): an account
/// update that changes the email postpones the change — the DB keeps the
/// ORIGINAL address, `unconfirmed_email` carries the new one, and the flash
/// key becomes `update_needs_confirmation`.
#[tokio::test]
async fn flow_account_update_email_postpones_until_confirmation() {
    let (state, app) = common::build_app(common::test_state(default_mapping()));
    seed_user(&state, "flow6@example.com", "secret123").await;

    let mut jar = Jar::new();
    let resp = form_sign_in(&app, "flow6@example.com", "secret123").await;
    jar.merge(&resp);

    let resp = call(
        &app,
        Request::builder()
            .method(Method::PATCH)
            .uri("/users")
            .header(header::COOKIE, jar.header())
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(
                "user[current_password]=secret123&user[email]=attacker@example.com",
            ))
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let cookies = set_cookie_pairs(&resp);
    assert!(
        common::flash_keys_from_cookies(&cookies, &state.config)
            .contains(&"update_needs_confirmation".to_string()),
        "update_needs_confirmation flash expected: {cookies:?}"
    );
    // The bypass re-sign-in cycles the session id; a browser follows the
    // fresh cookie, so the jar must absorb it before the probe.
    jar.merge(&resp);

    let mut conditions = Conditions::new();
    conditions.insert("email", Value::String("flow6@example.com".to_string()));
    let after = state
        .adapter
        .find_first(&conditions)
        .await
        .expect("lookup")
        .expect("record");
    assert_eq!(after.email, "flow6@example.com", "email postponed");
    assert_eq!(
        after.unconfirmed_email.as_deref(),
        Some("attacker@example.com"),
        "new address parked in unconfirmed_email"
    );
    assert!(
        after
            .confirmation_token
            .as_deref()
            .is_some_and(|t| !t.is_empty()),
        "a confirmation token was minted"
    );

    // The original session must survive (the victim keeps access).
    let resp = call(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri("/users_dashboard")
            .header(header::COOKIE, jar.header())
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

/// Devise recoverable parity (`recoverable.rb:32`): a password change
/// through the account update clears outstanding reset tokens.
#[tokio::test]
async fn flow_account_update_clears_reset_token_on_password_change() {
    let (state, app) = common::build_app(common::test_state(default_mapping()));
    seed_user(&state, "flow7@example.com", "secret123").await;

    let mut jar = Jar::new();
    let resp = form_sign_in(&app, "flow7@example.com", "secret123").await;
    jar.merge(&resp);

    let resp = call(
        &app,
        Request::builder()
            .method(Method::PATCH)
            .uri("/users")
            .header(header::COOKIE, jar.header())
            .header(
                header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(Body::from(
                "user[current_password]=secret123&user[password]=brand-new-pass&user[password_confirmation]=brand-new-pass",
            ))
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);

    let mut conditions = Conditions::new();
    conditions.insert("email", Value::String("flow7@example.com".to_string()));
    let after = state
        .adapter
        .find_first(&conditions)
        .await
        .expect("lookup")
        .expect("record");
    assert_eq!(
        after.reset_password_token, None,
        "password change must clear the reset token"
    );
}

/// Devise `set_flash_message_for_update`: a plain update flashes `updated`.
#[tokio::test]
async fn flow_account_update_plain_flash() {
    let (state, app) = common::build_app(common::test_state(default_mapping()));
    seed_user(&state, "flow8@example.com", "secret123").await;

    let mut jar = Jar::new();
    let resp = form_sign_in(&app, "flow8@example.com", "secret123").await;
    jar.merge(&resp);

    let resp = call(
        &app,
        Request::builder()
            .method(Method::PATCH)
            .uri("/users")
            .header(header::COOKIE, jar.header())
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from("user[current_password]=secret123"))
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let cookies = set_cookie_pairs(&resp);
    assert!(
        common::flash_keys_from_cookies(&cookies, &state.config).contains(&"updated".to_string()),
        "plain update flash expected: {cookies:?}"
    );
}

/// Devise passwords controller: blank token on edit redirects with
/// `no_token`; unknown tokens on update yield `:invalid` errors.
#[tokio::test]
async fn flow_reset_token_errors() {
    let (state, app) = common::build_app(common::test_state(default_mapping()));
    seed_user(&state, "flow5@example.com", "secret123").await;

    // Blank/absent token → redirect + no_token flash.
    let resp = call(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri("/users/password/edit")
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let cookies = set_cookie_pairs(&resp);
    assert!(
        common::flash_keys_from_cookies(&cookies, &state.config).contains(&"no_token".to_string()),
        "{cookies:?}"
    );

    // Unknown token on update → the configured error_status (200 by
    // default) with the invalid key.
    let resp = call(
        &app,
        Request::builder()
            .method(Method::PATCH)
            .uri("/users/password")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json")
            .body(Body::from(
                r#"{"user":{"reset_password_token":"totally-unknown","password":"brand-new-pass","password_confirmation":"brand-new-pass"}}"#,
            ))
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let rendered = body["errors"]["reset_password_token"]
        .as_array()
        .expect("token errors")
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect::<Vec<_>>()
        .join(",");
    assert!(rendered.contains("invalid"), "{rendered}");
}

/// Devise confirmable: blank confirmation token → 422 `:blank`; legacy RAW
/// token lookup still confirms (raw-first semantics of `confirm_by_token`).
///
/// The blank-token SHOW leg keeps asserting the hardcoded 422: Devise
/// carves `confirmations#show` out of the configurable `error_status` with
/// a TODO to adopt it only when the default changes
/// (`confirmations_controller.rb:30-31`), so the port mirrors the
/// hardcode and this test pins the carve-out.
#[tokio::test]
async fn flow_confirm_by_token_blank_and_legacy_paths() {
    let (state, app) = common::build_app(common::test_state(default_mapping()));
    let user = seed_user_unconfirmed(&state, "flow6@example.com", "secret123").await;

    // Blank token (missing query param) → the SHOW carve-out keeps
    // Devise's hardcoded 422 with :blank.
    let resp = call(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri("/users/confirmation")
            .header(header::ACCEPT, "application/json")
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = body_json(resp).await;
    assert!(body.to_string().contains("blank"), "{body}");

    // Legacy: store the RAW token in the column (pre-digest rows) — lookup
    // tries raw first, so confirmation succeeds.
    let raw = "legacy-raw-token";
    let mut fields = std::collections::HashMap::new();
    fields.insert(
        "confirmation_token".to_string(),
        Value::String(raw.to_string()),
    );
    state
        .adapter
        .update_columns(&user.to_key(), &fields)
        .await
        .expect("store raw token");
    let resp = call(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/users/confirmation?confirmation_token={raw}"))
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let cookies = set_cookie_pairs(&resp);
    assert!(
        common::flash_keys_from_cookies(&cookies, &state.config).contains(&"confirmed".to_string())
    );
}

/// Devise lockable: the emailed raw token unlocks the locked account and
/// the redirect carries the `unlocked` flash; sign-in works again after.
#[tokio::test]
async fn flow_unlock_by_token() {
    let (state, app) = common::build_app(common::test_state(default_mapping()));
    let user = seed_user(&state, "flow7@example.com", "secret123").await;

    // Lock it (maximum_attempts default 20 equivalent).
    let mut fields = std::collections::HashMap::new();
    fields.insert(
        "locked_at".to_string(),
        Value::String(common::now_rfc3339()),
    );
    fields.insert("failed_attempts".to_string(), Value::Integer(20));
    state
        .adapter
        .update_columns(&user.to_key(), &fields)
        .await
        .expect("lock");

    // Request instructions → raw token rides the mail; then unlock.
    let resp = call(
        &app,
        Request::builder()
            .method(Method::POST)
            .uri("/users/unlock")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from("email=flow7%40example.com"))
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let raw = state
        .mailer
        .sent_mails()
        .last()
        .and_then(|mail| mail.template_vars.token.clone())
        .expect("unlock mail carries raw token");
    let resp = call(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/users/unlock?unlock_token={raw}"))
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let cookies = set_cookie_pairs(&resp);
    assert!(
        common::flash_keys_from_cookies(&cookies, &state.config).contains(&"unlocked".to_string()),
        "{cookies:?}"
    );

    // Sign-in now works again.
    let resp = form_sign_in(&app, "flow7@example.com", "secret123").await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let cookies = set_cookie_pairs(&resp);
    assert!(
        common::flash_keys_from_cookies(&cookies, &state.config).contains(&"signed_in".to_string())
    );
}

/// Phase 5 D-15 regression: TWO cookie jars (session via `id=`, remember
/// via `remember_user_token=`) — a password change must kill BOTH: the
/// session by salt mismatch and the remember cookie by value mismatch
/// (the fixture's remember value is the salt when no token column is set).
/// The fixture pre-stamps `remember_created_at` in the past so the minted
/// remember cookie is genuinely ALIVE before the change.
#[tokio::test]
async fn flow_two_cookie_jar_password_change_kills_session_and_remember() {
    let (state, app) = common::build_app(common::test_state(default_mapping()));
    let past = SystemClock.now() - chrono::Duration::seconds(3600);
    let mut seeded =
        FixtureUser::new_with_password("flow8@example.com", "secret123", &state.config)
            .confirmed_now(&SystemClock)
            .remembered_since(past);
    seeded = state.adapter.create(seeded).await.expect("seed");
    let _ = seeded;

    let mut old_jar = Jar::new();
    let resp = call(
        &app,
        Request::builder()
            .method(Method::POST)
            .uri("/users/sign_in")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(
                "email=flow8%40example.com&password=secret123&remember_me=1",
            ))
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    old_jar.merge(&resp);
    assert!(
        old_jar.value("remember_user_token").is_some(),
        "remember cookie issued"
    );

    // Snapshot the PRE-CHANGE jars (session + remember) — the regression is
    // about THESE cookies dying, not the current jar.
    let stale_session_jar = old_jar.header();
    let stale_remember = old_jar
        .value("remember_user_token")
        .expect("remember cookie");

    // Password change through the account-update path (bypass_sign_in
    // renews; D-04 renewal gate).
    let resp = call(
        &app,
        Request::builder()
            .method(Method::PATCH)
            .uri("/users")
            .header(header::COOKIE, old_jar.header())
            .header(
                header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(Body::from(
                "user[current_password]=secret123&user[password]=rotated-pass&user[password_confirmation]=rotated-pass",
            ))
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let mut conditions = Conditions::new();
    conditions.insert("email", Value::String("flow8@example.com".to_string()));
    let after = state
        .adapter
        .find_first(&conditions)
        .await
        .expect("look up")
        .expect("record");
    assert!(
        devise_rust::model::PasswordVerifiable::valid_password(
            &after,
            "rotated-pass",
            &state.config
        ),
        "password must be rotated after the update"
    );

    // OLD session jar (salt pinned to the pre-change digest): dead.
    let resp = call(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri("/users_dashboard")
            .header(header::COOKIE, stale_session_jar.clone())
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::FOUND,
        "old session jar must be dead (salt mismatch)"
    );

    // Remember-only jar (no session): dead too (remember value == salt
    // rotated with the password, Phase-5 D-15).
    let resp = call(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri("/users_dashboard")
            .header(
                header::COOKIE,
                format!("remember_user_token={stale_remember}"),
            )
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::FOUND,
        "remember cookie must be dead after password change"
    );
}

/// D-04 renewal gates: Set-Cookie rotation asserted on ALL FOUR privilege
/// paths — `sign_in`, `bypass_sign_in`, account update (`bypass_sign_in`
/// re-sign-in), and `sign_out` — in one running session jar.
#[tokio::test]
async fn flow_renewal_rotation_on_privilege_paths() {
    let (state, app) = common::build_app(common::test_state(default_mapping()));
    seed_user(&state, "flow9@example.com", "secret123").await;

    // 1. sign_in path.
    let mut jar = Jar::new();
    let resp = form_sign_in(&app, "flow9@example.com", "secret123").await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    jar.merge(&resp);
    let after_sign_in = jar.value("id").expect("session");

    // 2. bypass_sign_in path: the IntegrationHelpers probe over the SAME
    // jar cycles without any password post.
    let resp = call(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri("/devise-test/bypass-sign-in?email=flow9%40example.com")
            .header(header::COOKIE, jar.header())
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    jar.merge(&resp);
    let after_bypass = jar.value("id").expect("session");
    assert_ne!(after_sign_in, after_bypass, "bypass sign-in renews");

    // 3. Account update (the controller's bypass_sign_in re-sign-in path).
    let resp = call(
        &app,
        Request::builder()
            .method(Method::PATCH)
            .uri("/users")
            .header(header::COOKIE, jar.header())
            .header(
                header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(Body::from(
                "user[current_password]=secret123&user[password]=rotated-pass&user[password_confirmation]=rotated-pass",
            ))
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    jar.merge(&resp);
    let after_update = jar.value("id").expect("session");
    assert_ne!(after_bypass, after_update, "account update renews");

    // 4. Sign out.
    let resp = call(
        &app,
        Request::builder()
            .method(Method::DELETE)
            .uri("/users/sign_out")
            .header(header::COOKIE, jar.header())
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    jar.merge(&resp);
    let after_sign_out = jar.value("id");
    assert_ne!(
        after_sign_out.as_deref(),
        Some(after_update.as_str()),
        "sign out renews"
    );

    // Sign in again: fresh id, distinct from the signed-out one.
    let resp = form_sign_in(&app, "flow9@example.com", "rotated-pass").await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    jar.merge(&resp);
    let after_second = jar.value("id").expect("session");
    assert_ne!(
        after_sign_out.as_deref(),
        Some(after_second.as_str()),
        "sign in renews"
    );
}

/// Devise `store_location`: unauthenticated navigational GET stores the
/// location (same-host only); POST never stores.
#[tokio::test]
async fn flow_stored_location_get_only() {
    let (state, app) = common::build_app(common::test_state(default_mapping()));
    seed_user(&state, "flow10@example.com", "secret123").await;

    // GET navigational: 302 + flash + location stored → sign-in returns there.
    let mut jar = Jar::new();
    let resp = call(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri("/users_dashboard")
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    jar.merge(&resp);
    let resp = call(
        &app,
        form_sign_in_request("flow10@example.com", "secret123", Some(&jar.header())),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let location = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    assert_eq!(
        location.as_deref(),
        Some("/users_dashboard"),
        "stored location wins"
    );

    // POST to a protected route: never stored — sign-in lands on the
    // scope root (the axum `after_sign_in_path_for` fallback).
    let resp = call(
        &app,
        Request::builder()
            .method(Method::POST)
            .uri("/users_dashboard")
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let resp = form_sign_in(&app, "flow10@example.com", "secret123").await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let location = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    assert_eq!(location.as_deref(), Some("/users"), "POST is never stored");
}

/// AXUM-04 acceptance: the IntegrationHelpers-parity bypass —
/// `sign_in` reaches a protected route WITHOUT posting a password, and
/// `sign_out` clears it; the drained remember op names the scope + the
/// `remember_user_token` key (T-09-07).
#[tokio::test]
async fn bypass_helpers_reach_protected_route_via_cookie_replay() {
    let (state, app) = common::build_app(common::test_state(default_mapping()));
    let mut user = FixtureUser::new_with_password("bypass@example.com", "secret123", &state.config)
        .confirmed_now(&SystemClock);
    user = state.adapter.create(user).await.expect("seed");
    let _ = user;

    // Bypass sign-in: no password post anywhere — the Set-Cookie carries
    // the rotated id.
    let resp = call(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri("/devise-test/bypass-sign-in?email=bypass%40example.com")
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let mut jar = Jar::new();
    jar.merge(&resp);
    assert!(
        jar.value("id").is_some(),
        "bypass sign-in rotates the session cookie"
    );

    // Replay into the full middleware stack: RequireAuth sees the user.
    let resp = call(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri("/users_dashboard")
            .header(header::COOKIE, jar.header())
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    jar.merge(&resp);
    let body = body_json(resp).await;
    assert_eq!(
        body["email"],
        serde_json::json!("bypass@example.com"),
        "protected route resolves the bypassed user"
    );

    // Bypass sign-out with the remember intent: op scope + key assert.
    let resp = call(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri("/devise-test/bypass-sign-out")
            .header(header::COOKIE, jar.header())
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    jar.merge(&resp);
    let body = body_json(resp).await;
    assert_eq!(body["scope"], serde_json::json!("user"));
    assert_eq!(body["key"], serde_json::json!("remember_user_token"));

    // The jar is signed out: the protected route rejects it.
    let resp = call(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri("/users_dashboard")
            .header(header::COOKIE, jar.header())
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::FOUND,
        "bypass sign-out clears the scope"
    );
}

/// Devise `verify_signed_out_user` (`sessions_controller.rb:6`): a second
/// sign-out with no session reports `already_signed_out`.
#[tokio::test]
async fn flow_sign_out_again_reports_already_signed_out() {
    let (state, app) = common::build_app(common::test_state(default_mapping()));
    seed_user(&state, "flow9@example.com", "secret123").await;
    let mut jar = Jar::new();

    let resp = form_sign_in(&app, "flow9@example.com", "secret123").await;
    jar.merge(&resp);

    let resp = call(
        &app,
        Request::builder()
            .method(Method::DELETE)
            .uri("/users/sign_out")
            .header(header::COOKIE, jar.header())
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    jar.merge(&resp);

    let resp = call(
        &app,
        Request::builder()
            .method(Method::DELETE)
            .uri("/users/sign_out")
            .header(header::COOKIE, jar.header())
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let cookies = set_cookie_pairs(&resp);
    assert!(
        common::flash_keys_from_cookies(&cookies, &state.config)
            .contains(&"already_signed_out".to_string()),
        "already_signed_out flash expected: {cookies:?}"
    );
}

/// Devise `require_no_authentication` (`sessions_controller.rb:4`): a sign-in
/// POST from an already signed-in session redirects home with
/// `already_authenticated` instead of re-authenticating.
#[tokio::test]
async fn flow_sign_in_while_signed_in_reports_already_authenticated() {
    let (state, app) = common::build_app(common::test_state(default_mapping()));
    seed_user(&state, "flow10@example.com", "secret123").await;
    let mut jar = Jar::new();

    let resp = form_sign_in(&app, "flow10@example.com", "secret123").await;
    jar.merge(&resp);

    let resp = call(
        &app,
        form_sign_in_request("flow10@example.com", "secret123", Some(&jar.header())),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let cookies = set_cookie_pairs(&resp);
    assert!(
        common::flash_keys_from_cookies(&cookies, &state.config)
            .contains(&"already_authenticated".to_string()),
        "already_authenticated flash expected: {cookies:?}"
    );
}

/// S11 (security audit): the `devise.flash` cookie must be SIGNED (the
/// cookie 0.18 signed jar over the Devise-derived key — the same lineage
/// the session cookie signs with) and carry `Secure`: the old transport
/// wrote the bare key unsigned with no `Secure`, so any client could
/// forge flash payloads and plain-http links could read them.
#[tokio::test]
async fn flow_flash_cookie_is_signed_and_secure() {
    let (state, app) = common::build_app(common::test_state(default_mapping()));
    seed_user(&state, "flash-sign@example.com", "secret123").await;

    let resp = form_sign_in(&app, "flash-sign@example.com", "secret123").await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let raw_flash = resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with("devise.flash="))
        .expect("flash cookie rides the redirect")
        .to_string();
    assert!(
        raw_flash.contains("Secure"),
        "the flash cookie must carry Secure: {raw_flash}"
    );
    assert!(
        !raw_flash.starts_with("devise.flash=signed_in"),
        "the flash value must be a signed envelope, not the bare key: {raw_flash}"
    );
    let cookies = set_cookie_pairs(&resp);
    let verified = common::flash_keys_from_cookies(&cookies, &state.config);
    assert!(
        verified.contains(&"signed_in".to_string()),
        "the signed envelope must verify to the bare flash key: {cookies:?}"
    );
}

/// S13 (security audit): Devise's `RegistrationsController` declares
/// `prepend_before_action :require_no_authentication, only: [:new, :create,
/// :cancel]` (`registrations_controller.rb:4`). Without the guard, a
/// signed-in POST /users created a SECOND account.
#[tokio::test]
async fn flow_sign_up_while_signed_in_is_rejected_with_already_authenticated() {
    let (state, app) = common::build_app(common::test_state(default_mapping()));
    seed_user(&state, "flow-second@example.com", "secret123").await;
    let mut jar = Jar::new();

    let resp = form_sign_in(&app, "flow-second@example.com", "secret123").await;
    jar.merge(&resp);

    // Signed-in sign-up POST: redirect home with `already_authenticated`,
    // never a second account.
    let resp = call(
        &app,
        Request::builder()
            .method(Method::POST)
            .uri("/users")
            .header(header::COOKIE, jar.header())
            .header(
                header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(Body::from(
                "user[email]=second-account@example.com&user[password]=another-secret-1&user[password_confirmation]=another-secret-1",
            ))
            .expect("request"),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::FOUND,
        "signed-in sign-up must redirect (require_no_authentication)"
    );
    let cookies = set_cookie_pairs(&resp);
    assert!(
        common::flash_keys_from_cookies(&cookies, &state.config)
            .contains(&"already_authenticated".to_string()),
        "already_authenticated flash expected: {cookies:?}"
    );

    let mut conditions = Conditions::new();
    conditions.insert(
        "email",
        Value::String("second-account@example.com".to_string()),
    );
    let second = state.adapter.find_first(&conditions).await.expect("lookup");
    assert!(
        second.is_none(),
        "no second account may be created while signed in"
    );

    // The same guard covers registrations#cancel and registrations#new.
    for uri in ["/users/cancel", "/users/sign_up"] {
        let resp = call(
            &app,
            Request::builder()
                .method(Method::GET)
                .uri(uri)
                .header(header::COOKIE, jar.header())
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::FOUND,
            "signed-in {uri} must redirect (require_no_authentication)"
        );
        let cookies = set_cookie_pairs(&resp);
        assert!(
            common::flash_keys_from_cookies(&cookies, &state.config)
                .contains(&"already_authenticated".to_string()),
            "already_authenticated flash expected on {uri}: {cookies:?}"
        );
    }

    // Anonymous sign-up still creates: the guard only rejects signed-in
    // sessions (registrations_controller matrix covers the rest).
    let resp = call(
        &app,
        Request::builder()
            .method(Method::POST)
            .uri("/users")
            .header(
                header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(Body::from(
                "user[email]=fresh-user@example.com&user[password]=fresh-secret-1&user[password_confirmation]=fresh-secret-1",
            ))
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let mut conditions = Conditions::new();
    conditions.insert("email", Value::String("fresh-user@example.com".to_string()));
    let fresh = state
        .adapter
        .find_first(&conditions)
        .await
        .expect("lookup")
        .expect("record");
    assert_ne!(
        fresh.encrypted_password, "",
        "the anonymous sign-up persists a password"
    );
}

/// S7 (security audit): Devise's strong-parameters contract — the
/// registrations controller builds records from the `:sign_up` sanitized
/// params ONLY (`authenticatable + password + password_confirmation`,
/// `parameter_sanitizer.rb`), so mass-assignment probes like
/// `unconfirmed_email` or `failed_attempts` never reach the model.
#[tokio::test]
async fn flow_sign_up_mass_assignment_is_dropped_by_sanitizer() {
    let (state, app) = common::build_app(common::test_state(default_mapping()));

    let resp = call(
        &app,
        Request::builder()
            .method(Method::POST)
            .uri("/users")
            .header(
                header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(Body::from(
                "user[email]=mass-assign@example.com&user[password]=mass-secret-1&user[password_confirmation]=mass-secret-1&user[unconfirmed_email]=attacker-chosen@example.com&user[failed_attempts]=99",
            ))
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND, "sign-up succeeds");
    let cookies = set_cookie_pairs(&resp);
    assert!(
        common::flash_keys_from_cookies(&cookies, &state.config)
            .contains(&"signed_up_but_unconfirmed".to_string()),
        "signed_up flash expected: {cookies:?}"
    );

    let mut conditions = Conditions::new();
    conditions.insert(
        "email",
        Value::String("mass-assign@example.com".to_string()),
    );
    let created = state
        .adapter
        .find_first(&conditions)
        .await
        .expect("lookup")
        .expect("record");
    assert_eq!(
        created.unconfirmed_email, None,
        "unconfirmed_email must never be mass-assigned"
    );
    assert_eq!(
        created.failed_attempts, 0,
        "failed_attempts must never be mass-assigned"
    );
}

/// M-fix (audit): sign-in conditions must come from
/// `config.authentication_keys` (Devise's `authentication_keys` config),
/// not a hardcoded `email` column.
#[tokio::test]
async fn flow_sign_in_with_username_authentication_key() {
    let mut config = common::test_config();
    config.authentication_keys = vec!["username".to_string()];
    let (state, app) = common::build_app(common::test_state_with_config(default_mapping(), config));

    let mut user =
        FixtureUser::new_with_password("username-identity@example.com", "secret123", &state.config)
            .confirmed_now(&SystemClock);
    user.username = Some("alice".to_string());
    state.adapter.create(user).await.expect("seed");

    let resp = call(
        &app,
        Request::builder()
            .method(Method::POST)
            .uri("/users/sign_in")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from("username=alice&password=secret123"))
            .expect("request"),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::FOUND,
        "username-keyed sign-in must authenticate"
    );
    let cookies = set_cookie_pairs(&resp);
    assert!(
        common::flash_keys_from_cookies(&cookies, &state.config).contains(&"signed_in".to_string()),
        "signed_in flash expected: {cookies:?}"
    );
}

/// M-fix (audit, DBAU-07): Devise's `DatabaseAuthenticatable` strategy fires
/// `after_database_authentication` right after a successful password check
/// (`strategies/database_authenticatable.rb:40`); the sessions controller
/// must do the same.
#[tokio::test]
async fn flow_sign_in_fires_after_database_authentication() {
    let (state, app) = common::build_app(common::test_state(default_mapping()));
    seed_user(&state, "dbau-hook@example.com", "secret123").await;

    let resp = form_sign_in(&app, "dbau-hook@example.com", "secret123").await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert!(
        common::after_db_auth_fired("dbau-hook@example.com"),
        "after_database_authentication must fire on a successful password check"
    );
}

/// M-fix (audit): Devise's `verify_signed_out_user` consults
/// `all_signed_out?`, which iterates EVERY registered mapping
/// (`sessions_controller.rb:69-73`) — a sibling scope's active session
/// means the user is NOT "already signed out", and the sign-out proceeds.
#[tokio::test]
async fn flow_sign_out_with_sibling_scope_signed_in_is_not_already_signed_out() {
    let (state, app) = common::build_two_scope_app();
    seed_user(&state, "sibling@example.com", "secret123").await;

    // Sign into the ADMIN scope (the sibling mapping).
    let resp = call(
        &app,
        Request::builder()
            .method(Method::POST)
            .uri("/admins/sign_in")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from("email=sibling%40example.com&password=secret123"))
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let mut jar = Jar::new();
    jar.merge(&resp);

    // Sign out through the USER scope's route: the admin session means NOT
    // all scopes are signed out — the response flashes `signed_out`, never
    // `already_signed_out`.
    let resp = call(
        &app,
        Request::builder()
            .method(Method::DELETE)
            .uri("/users/sign_out")
            .header(header::COOKIE, jar.header())
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::FOUND,
        "a sibling scope's session must not read as already_signed_out"
    );
    let cookies = set_cookie_pairs(&resp);
    assert!(
        common::flash_keys_from_cookies(&cookies, &state.config)
            .contains(&"signed_out".to_string()),
        "signed_out flash expected: {cookies:?}"
    );
    assert!(
        !common::flash_keys_from_cookies(&cookies, &state.config)
            .contains(&"already_signed_out".to_string()),
        "already_signed_out must not fire while a sibling scope is signed in: {cookies:?}"
    );
}

/// Devise parity (`database_authenticatable.rb:163-168`): the reconfirmation
/// flow notifies `email_changed` to the ORIGINAL address and the
/// confirmation instructions to the new one.
#[tokio::test]
async fn flow_account_update_email_change_notifies_both_addresses() {
    let mut config = common::test_config();
    // Devise's default is `false`; this test opts in to prove the split.
    config.send_email_changed_notification = true;
    let (state, app) = common::build_app(common::test_state_with_config(default_mapping(), config));
    seed_user(&state, "flow11@example.com", "secret123").await;
    let mut jar = Jar::new();
    let resp = form_sign_in(&app, "flow11@example.com", "secret123").await;
    jar.merge(&resp);

    let resp = call(
        &app,
        Request::builder()
            .method(Method::PATCH)
            .uri("/users")
            .header(header::COOKIE, jar.header())
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(
                "user[current_password]=secret123&user[email]=new-addr@example.com",
            ))
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);

    let sent = state.mailer.sent_mails();
    let changed: Vec<_> = sent
        .iter()
        .filter(|mail| mail.subject == "Email Changed")
        .collect();
    assert_eq!(
        changed.len(),
        1,
        "exactly one email_changed delivery: {:?}",
        sent.iter().map(|m| (&m.to, &m.subject)).collect::<Vec<_>>()
    );
    assert_eq!(changed[0].to, "flow11@example.com", "original recipient");
    let confirmations: Vec<_> = sent
        .iter()
        .filter(|mail| mail.subject == "Confirmation instructions")
        .collect();
    assert_eq!(
        confirmations.len(),
        1,
        "confirmation mailed to the new address"
    );
    assert_eq!(confirmations[0].to, "new-addr@example.com");
}

/// Devise lockable parity (`lockable.rb:127-131`): the attempt that CROSSES
/// the threshold and locks the account still reports the paranoid-unified
/// `invalid` key, and a later correct-password attempt on the locked account
/// reports `invalid` too.
#[tokio::test]
async fn flow_sign_in_lock_under_paranoid_reports_invalid() {
    let mut config = common::test_config();
    config.maximum_attempts = 2;
    config.paranoid = true;
    let (state, app) = common::build_app(common::test_state_with_config(default_mapping(), config));
    seed_user(&state, "flow12@example.com", "secret123").await;

    let first = form_sign_in(&app, "flow12@example.com", "wrongpass").await;
    assert_eq!(first.status(), StatusCode::FOUND);

    let resp = form_sign_in(&app, "flow12@example.com", "wrongpass").await;
    let cookies = set_cookie_pairs(&resp);
    assert!(
        common::flash_keys_from_cookies(&cookies, &state.config).contains(&"invalid".to_string()),
        "threshold lock under paranoid reports invalid: {cookies:?}"
    );
    assert!(
        !common::flash_keys_from_cookies(&cookies, &state.config).contains(&"locked".to_string()),
        "paranoid must not leak the lock: {cookies:?}"
    );

    let resp = form_sign_in(&app, "flow12@example.com", "secret123").await;
    let cookies = set_cookie_pairs(&resp);
    assert!(
        common::flash_keys_from_cookies(&cookies, &state.config).contains(&"invalid".to_string()),
        "locked + correct password stays unified: {cookies:?}"
    );
}

/// The non-paranoid counterpart: the same threshold lock reports `locked`.
#[tokio::test]
async fn flow_sign_in_lock_without_paranoid_reports_locked() {
    let mut config = common::test_config();
    config.maximum_attempts = 2;
    let (state, app) = common::build_app(common::test_state_with_config(default_mapping(), config));
    seed_user(&state, "flow13@example.com", "secret123").await;

    let _ = form_sign_in(&app, "flow13@example.com", "wrongpass").await;
    let resp = form_sign_in(&app, "flow13@example.com", "wrongpass").await;
    let cookies = set_cookie_pairs(&resp);
    assert!(
        common::flash_keys_from_cookies(&cookies, &state.config).contains(&"locked".to_string()),
        "threshold lock without paranoid reports locked: {cookies:?}"
    );
}

// ============================================================================
// Activatable session-fetch gate (Devise `hooks/activatable.rb`): a locked
// record held in the session authenticates nothing on the next request, the
// scope session key dies on the request that rejected it, and unlocking the
// account does not resurrect the dead session (T-261026-ghb-01/02).
// ============================================================================

/// Guarded route under the scope prefix: 200 plus the email for an
/// authenticated record, otherwise the `RequireAuth` failure path (302 to
/// the sign-in path plus the inactive flash key).
async fn flow_fetch_gate_private(
    user: devise_rust_axum::RequireAuth<common::FixtureUser>,
) -> impl IntoResponse {
    let email = user
        .user()
        .map(|user| user.email.clone())
        .unwrap_or_default();
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({ "email": email })),
    )
}

/// Non-strict probe: whether the layer resolved a record for this request.
async fn flow_fetch_gate_probe(
    auth: devise_rust_axum::Auth<common::FixtureUser>,
) -> axum::Json<bool> {
    axum::Json(auth.is_authenticated())
}

/// Build the fetch-gate app: the devise routes plus the guarded and
/// non-strict probes mounted under the scope prefix, sharing the devise
/// layer's session store.
fn flow_fetch_gate_app(state: common::TestState) -> (common::TestState, Router) {
    let mut hooks = HookRegistry::new();
    devise_rust::hooks::register_devise_hooks(&mut hooks, &state.mapping);

    let mapping = state.mapping.clone();
    let scope_name = mapping.name.clone();
    let finder: Arc<dyn ModelFinder> = Arc::new(AdapterBridge::new(state.adapter.as_ref().clone()));
    let devise_layer = DeviseLayer::new(
        common::registry_with(std::slice::from_ref(&mapping)),
        state.config.clone(),
    )
    .with_hooks(Arc::new(hooks))
    .with_finder(&scope_name, finder);
    let session_layer = session_manager_layer(&state.config).expect("session layer builds");

    let app = Router::new()
        .merge(devise_for_router(state.clone()))
        .route(
            "/users/private",
            axum::routing::get(flow_fetch_gate_private),
        )
        .route(
            "/users/anonymous-probe",
            axum::routing::get(flow_fetch_gate_probe),
        )
        .layer(devise_layer)
        .layer(session_layer);
    (state, app)
}

/// Write the lock state of the seeded account straight through the test
/// adapter (the fixture manipulation the lockable flow tests use).
async fn flow_fetch_gate_write_lock(
    state: &common::TestState,
    key: &devise_rust::adapter::DeviseKey,
    locked: bool,
) {
    let mut fields = std::collections::HashMap::new();
    if locked {
        fields.insert(
            "locked_at".to_string(),
            Value::String(common::now_rfc3339()),
        );
        fields.insert("failed_attempts".to_string(), Value::Integer(20));
    } else {
        fields.insert("locked_at".to_string(), Value::Null);
        fields.insert("failed_attempts".to_string(), Value::Integer(0));
    }
    state
        .adapter
        .update_columns(key, &fields)
        .await
        .expect("lock write");
}

/// GET the guarded route with the jar's cookies replayed.
async fn flow_fetch_gate_guarded(app: &Router, cookie: String) -> Response {
    call(
        app,
        Request::builder()
            .method(Method::GET)
            .uri("/users/private")
            .header(header::ACCEPT, "text/html")
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .expect("request"),
    )
    .await
}

/// GET the non-strict probe with the jar's cookies replayed.
async fn flow_fetch_gate_probe_call(app: &Router, cookie: String) -> bool {
    let resp = call(
        app,
        Request::builder()
            .method(Method::GET)
            .uri("/users/anonymous-probe")
            .header(header::ACCEPT, "text/html")
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "the soft probe never fails");
    body_json(resp).await.as_bool().expect("boolean body")
}

/// Devise `hooks/activatable.rb` fetch arm: sign in, lock the account, then
/// hit the guarded route with the session cookie replayed. The request is
/// rejected (302 to the sign-in path, never 200), the flash carries the
/// `locked` key, and the non-strict surface resolves anonymous. Unlocking
/// the account afterwards still rejects, because the gate deleted the scope
/// session key on the request that rejected it.
#[tokio::test]
async fn flow_fetch_gate_locked_session_rejects_and_survives_unlock() {
    let (state, app) = flow_fetch_gate_app(common::test_state(default_mapping()));
    let user = seed_user(&state, "flowgate@example.com", "secret123").await;

    let mut jar = Jar::new();
    jar.merge(&form_sign_in(&app, "flowgate@example.com", "secret123").await);
    // The signed-in session really reaches the guarded route.
    let ok = flow_fetch_gate_guarded(&app, jar.header()).await;
    assert_eq!(
        ok.status(),
        StatusCode::OK,
        "a live session passes the gate"
    );

    // Lock the account: the session payload stays valid, but the record no
    // longer passes `active_for_authentication?`.
    flow_fetch_gate_write_lock(&state, &user.to_key(), true).await;

    let rejected = flow_fetch_gate_guarded(&app, jar.header()).await;
    assert_eq!(
        rejected.status(),
        StatusCode::FOUND,
        "the locked session must not render the guarded route"
    );
    assert_eq!(
        rejected
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/users/sign_in"),
        "the rejection redirects to the scope sign-in path"
    );
    let cookies = set_cookie_pairs(&rejected);
    assert!(
        common::flash_keys_from_cookies(&cookies, &state.config).contains(&"locked".to_string()),
        "the inactive message rides the flash: {cookies:?}"
    );
    // The non-strict surface stays anonymous on the same locked session.
    assert!(
        !flow_fetch_gate_probe_call(&app, jar.header()).await,
        "the locked session resolves anonymous on the soft extractor"
    );

    // The browser keeps whatever cookies the rejected response carried.
    jar.merge(&rejected);

    // Unlock the account: the dead session must stay dead (T-261026-ghb-02).
    flow_fetch_gate_write_lock(&state, &user.to_key(), false).await;
    let after_unlock = flow_fetch_gate_guarded(&app, jar.header()).await;
    assert_eq!(
        after_unlock.status(),
        StatusCode::FOUND,
        "the deleted session key must not resurrect after the unlock"
    );
    let after_body = body_text(after_unlock).await;
    assert!(
        !after_body.contains("flowgate@example.com"),
        "the guarded handler never ran: {after_body}"
    );
    assert!(
        !flow_fetch_gate_probe_call(&app, jar.header()).await,
        "the unlocked replay still resolves anonymous"
    );
}

// ============================================================================
// Blank-password sign-in gate (Devise `strategies/database_authenticatable.rb:10`
// and `:22-25`): a password-less POST on a KNOWN email never runs the
// lookup and never moves `failed_attempts`, so the known-email lockout-DoS
// vector is closed (T-261026-ghd-03).
// ============================================================================

/// Devise parity: a blank password on a seeded account fails with the
/// unknown-account key (`not_found_in_database` outside paranoid) instead of
/// running the lookup, and the lockable counter stays untouched. A
/// wrong-password control on the same row does move the counter, proving
/// only the blank branch skips accounting.
#[tokio::test]
async fn flow_blank_password_reports_not_found_in_database() {
    let (state, app) = common::build_app(common::test_state(default_mapping()));
    let user = seed_user(&state, "blank@example.com", "secret123").await;
    assert_eq!(user.failed_attempts, 0, "the fixture starts unlocked");

    let resp = form_sign_in(&app, "blank@example.com", "").await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let cookies = set_cookie_pairs(&resp);
    assert!(
        common::flash_keys_from_cookies(&cookies, &state.config)
            .contains(&"not_found_in_database".to_string()),
        "blank password reports not_found_in_database: {cookies:?}"
    );

    // The lookup never ran and the counter never moved.
    let stored = state
        .adapter
        .get(&user.to_key())
        .await
        .expect("reload")
        .expect("user persists");
    assert_eq!(
        stored.failed_attempts, 0,
        "a blank password must not increment failed_attempts"
    );

    // Wrong-password control: the counting path still runs.
    let resp = form_sign_in(&app, "blank@example.com", "wrongpass").await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let stored = state
        .adapter
        .get(&user.to_key())
        .await
        .expect("reload")
        .expect("user persists");
    assert_eq!(
        stored.failed_attempts, 1,
        "the wrong-password control still counts an attempt"
    );

    // JSON leg (D-09 shape): 401 with the same symbolic key.
    let resp = call(
        &app,
        Request::builder()
            .method(Method::POST)
            .uri("/users/sign_in")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json")
            .body(Body::from(r#"{"email":"blank@example.com","password":""}"#))
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = body_json(resp).await;
    assert_eq!(body["error"], serde_json::json!("not_found_in_database"));
}

/// Devise parity: inside paranoid mode the same blank-password POST reports
/// the unified `invalid` key and never leaks account existence.
#[tokio::test]
async fn flow_blank_password_paranoid_reports_invalid() {
    let mut config = common::test_config();
    config.paranoid = true;
    let (state, app) = common::build_app(common::test_state_with_config(default_mapping(), config));
    seed_user(&state, "blank-paranoid@example.com", "secret123").await;

    let resp = form_sign_in(&app, "blank-paranoid@example.com", "").await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let cookies = set_cookie_pairs(&resp);
    assert!(
        common::flash_keys_from_cookies(&cookies, &state.config).contains(&"invalid".to_string()),
        "unified invalid flash under paranoid: {cookies:?}"
    );
    assert!(
        !common::flash_keys_from_cookies(&cookies, &state.config)
            .contains(&"not_found_in_database".to_string()),
        "paranoid must not leak account absence: {cookies:?}"
    );
}

/// `error_status` wiring: a non-default `error_status` demonstrably reaches
/// the wire through the real app (build via `test_state_with_config`), so
/// the duplicate-email render reads the config instead of a constant.
/// Setting `error_status` to 422 is also the documented one-line
/// restoration path for apps that want the generated-Devise posture.
#[tokio::test]
async fn error_status_config_reaches_validation_render() {
    let mut config = common::test_config();
    config.error_status = 422;
    let (state, app) = common::build_app(common::test_state_with_config(default_mapping(), config));
    let existing = FixtureUser::new_with_password("taken@example.com", "secret123", &state.config)
        .confirmed_now(&SystemClock);
    state.adapter.create(existing).await.expect("seed");

    let resp = call(
        &app,
        Request::builder()
            .method(Method::POST)
            .uri("/users")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json")
            .body(Body::from(
                r#"{"user":{"email":"taken@example.com","password":"secret123","password_confirmation":"secret123"}}"#,
            ))
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = body_json(resp).await;
    assert!(
        body["errors"]["email"]
            .as_array()
            .expect("email errors")
            .iter()
            .any(|e| e.as_str().is_some_and(|s| s.contains("taken"))),
        "taken key must reach the 422 render: {body}"
    );
}

// ============================================================================
// Passwords update parity (Devise `passwords_controller.rb#update`, lines
// 37-46 for the flash and sign-in branch, 79-83 for `unlockable?`):
// unlock only under the email strategy, sign in UNCONDITIONALLY when
// `sign_in_after_reset_password`, the flash matrix, and the
// `after_database_authentication` hook (T-261026-ghf-01/02).
// ============================================================================

/// Stamp the account locked through the test adapter (the lockable flow
/// fixture: a `locked_at` value plus a counter over the threshold).
async fn lock_record(state: &common::TestState, key: &devise_rust::adapter::DeviseKey) {
    let mut fields = std::collections::HashMap::new();
    fields.insert(
        "locked_at".to_string(),
        Value::String(common::now_rfc3339()),
    );
    fields.insert("failed_attempts".to_string(), Value::Integer(20));
    state
        .adapter
        .update_columns(key, &fields)
        .await
        .expect("lock write");
}

/// The stored lock state of a record, read through the adapter.
async fn lock_state(
    state: &common::TestState,
    key: &devise_rust::adapter::DeviseKey,
) -> (bool, u32) {
    let record = state
        .adapter
        .get(key)
        .await
        .expect("lookup")
        .expect("record");
    (record.locked_at.is_some(), record.failed_attempts)
}

/// POST the create action and read the raw reset token off the captured
/// mail (the emailed-token round trip the update action requires).
async fn reset_token_for(state: &common::TestState, app: &Router, email: &str) -> String {
    let resp = call(
        app,
        Request::builder()
            .method(Method::POST)
            .uri("/users/password")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!("user[email]={}", urlencode(email))))
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND, "instructions redirect");
    state
        .mailer
        .sent_mails()
        .last()
        .and_then(|mail| mail.template_vars.token.clone())
        .expect("reset mail carries the raw token")
}

/// PUT the update action with a valid token and a new password (the
/// `resource_params` Devise feeds `reset_password_by_token`).
async fn submit_reset(app: &Router, token: &str, password: &str) -> Response {
    call(
        app,
        Request::builder()
            .method(Method::PATCH)
            .uri("/users/password")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!(
                "user[reset_password_token]={token}&user[password]={password}&user[password_confirmation]={password}"
            )))
            .expect("request"),
    )
    .await
}

/// GET the guarded probe with the given cookie replayed (200 only when a
/// live, active session resolves).
async fn probe_private(app: &Router, cookie: &str) -> Response {
    call(
        app,
        Request::builder()
            .method(Method::GET)
            .uri("/users_dashboard")
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .expect("request"),
    )
    .await
}

/// Devise `passwords_controller.rb#update` + `unlockable?`: an email-unlock
/// strategy unlocks the locked account on reset, the active record flashes
/// `updated`, and the reset signs the user in with the new password.
#[tokio::test]
async fn flow_reset_password_unlocks_under_email_strategy() {
    let mut config = common::test_config();
    config.unlock_strategy = "email".to_string();
    let (state, app) = common::build_app(common::test_state_with_config(default_mapping(), config));
    let user = seed_user(&state, "reset-unlock@example.com", "secret123").await;
    lock_record(&state, &user.to_key()).await;
    let token = reset_token_for(&state, &app, "reset-unlock@example.com").await;

    let mut jar = Jar::new();
    let resp = submit_reset(&app, &token, "brand-new-pass").await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    jar.merge(&resp);
    let keys = common::flash_keys_from_cookies(&jar.0, &state.config);
    assert!(
        keys.contains(&"updated".to_string()),
        "the unlocked record is active, so Devise flashes updated: {keys:?}"
    );

    // The email strategy ran the unlock: no lock and a zeroed counter.
    let (locked, attempts) = lock_state(&state, &user.to_key()).await;
    assert!(
        !locked,
        "unlock_access clears locked_at under the email strategy"
    );
    assert_eq!(attempts, 0, "unlock_access zeroes failed_attempts");

    // Signed in: the guarded probe resolves the record.
    let probe = probe_private(&app, &jar.header()).await;
    assert_eq!(
        probe.status(),
        StatusCode::OK,
        "the reset signs the user in"
    );
    assert_eq!(
        body_json(probe).await["email"],
        serde_json::json!("reset-unlock@example.com")
    );

    // The NEW password is the one that authenticates.
    let resp = form_sign_in(&app, "reset-unlock@example.com", "brand-new-pass").await;
    let cookies = set_cookie_pairs(&resp);
    assert!(
        common::flash_keys_from_cookies(&cookies, &state.config).contains(&"signed_in".to_string()),
        "signed_in flash expected: {cookies:?}"
    );
}

/// Devise `unlockable?` guard: a `:time` unlock strategy NEVER unlocks on a
/// password reset, so the time penalty survives the reset. The reset still
/// succeeds and signs the record in unconditionally (the ghb activatable
/// gate rejects the next request with the `locked` message).
#[tokio::test]
async fn flow_reset_password_keeps_lock_under_time_strategy() {
    let mut config = common::test_config();
    config.unlock_strategy = "time".to_string();
    let (state, app) = common::build_app(common::test_state_with_config(default_mapping(), config));
    let user = seed_user(&state, "reset-time@example.com", "secret123").await;
    lock_record(&state, &user.to_key()).await;
    let token = reset_token_for(&state, &app, "reset-time@example.com").await;

    let mut jar = Jar::new();
    let resp = submit_reset(&app, &token, "brand-new-pass").await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    jar.merge(&resp);
    let keys = common::flash_keys_from_cookies(&jar.0, &state.config);
    assert!(
        keys.contains(&"updated_not_active".to_string()),
        "a locked record is inactive, so Devise flashes updated_not_active: {keys:?}"
    );
    assert!(
        !keys.contains(&"updated".to_string()),
        "the inactive record must not flash updated: {keys:?}"
    );

    // No unlock ran: the time penalty is intact.
    let (locked, attempts) = lock_state(&state, &user.to_key()).await;
    assert!(locked, "the time strategy never unlocks on a reset");
    assert_eq!(attempts, 20, "the failed-attempt counter stays");

    // Devise signs in unconditionally, so a session exists; the activatable
    // fetch gate rejects it with the inactive message (item ghb).
    let rejected = probe_private(&app, &jar.header()).await;
    assert_eq!(
        rejected.status(),
        StatusCode::FOUND,
        "the locked session resolves dead on the next request"
    );
    assert_eq!(
        rejected
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/users/sign_in"),
        "the inactive record redirects to the sign-in path"
    );
    let cookies = set_cookie_pairs(&rejected);
    assert!(
        common::flash_keys_from_cookies(&cookies, &state.config).contains(&"locked".to_string()),
        "the inactive message rides the flash: {cookies:?}"
    );
}

/// Devise parity: an unconfirmed record resets, flashes `updated_not_active`,
/// is signed in UNCONDITIONALLY (Devise does not gate the sign-in on
/// `active_for_authentication?`), and fires `after_database_authentication`
/// before the sign-in. The activatable fetch gate rejects the next request
/// with `unconfirmed`, matching the reference behavior.
#[tokio::test]
async fn flow_reset_password_signs_in_unconfirmed_record() {
    let (state, app) = common::build_app(common::test_state(default_mapping()));
    seed_user_unconfirmed(&state, "reset-unconfirmed@example.com", "secret123").await;
    let token = reset_token_for(&state, &app, "reset-unconfirmed@example.com").await;

    let mut jar = Jar::new();
    let resp = submit_reset(&app, &token, "brand-new-pass").await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    jar.merge(&resp);
    let keys = common::flash_keys_from_cookies(&jar.0, &state.config);
    assert!(
        keys.contains(&"updated_not_active".to_string()),
        "an unconfirmed record flashes updated_not_active: {keys:?}"
    );
    assert!(
        common::after_db_auth_fired("reset-unconfirmed@example.com"),
        "the reset path fires after_database_authentication before the sign-in"
    );

    // A session exists (signed in unconditionally) and dies on the next
    // request, carrying the confirmable inactive message.
    let rejected = probe_private(&app, &jar.header()).await;
    assert_eq!(rejected.status(), StatusCode::FOUND);
    assert_eq!(
        rejected
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/users/sign_in"),
        "the inactive session redirects to the sign-in path"
    );
    let cookies = set_cookie_pairs(&rejected);
    assert!(
        common::flash_keys_from_cookies(&cookies, &state.config)
            .contains(&"unconfirmed".to_string()),
        "unconfirmed rides the flash of the rejected request: {cookies:?}"
    );
}

/// Devise parity: with `sign_in_after_reset_password` off, the successful
/// reset flashes `updated_not_active` even for an active record and leaves
/// the visitor anonymous (no session is minted).
#[tokio::test]
async fn flow_reset_password_without_sign_in_leaves_visitor_anonymous() {
    let mut config = common::test_config();
    config.sign_in_after_reset_password = false;
    let (state, app) = common::build_app(common::test_state_with_config(default_mapping(), config));
    seed_user(&state, "reset-nosign@example.com", "secret123").await;
    let token = reset_token_for(&state, &app, "reset-nosign@example.com").await;

    let resp = submit_reset(&app, &token, "brand-new-pass").await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let cookies = set_cookie_pairs(&resp);
    let keys = common::flash_keys_from_cookies(&cookies, &state.config);
    assert!(
        keys.contains(&"updated_not_active".to_string()),
        "no sign-in means updated_not_active, even for an active record: {keys:?}"
    );
    assert!(
        !keys.contains(&"updated".to_string()),
        "updated must not fire without the sign-in branch: {keys:?}"
    );
    assert!(
        !common::after_db_auth_fired("reset-nosign@example.com"),
        "no sign-in branch means no after_database_authentication firing"
    );

    // No session: the guarded probe rejects as anonymous.
    let probe = probe_private(&app, "").await;
    assert_eq!(
        probe.status(),
        StatusCode::FOUND,
        "the reset without sign-in leaves no live session"
    );
}

/// The captured mails whose subject is the password-change notice.
fn password_change_mails(state: &common::TestState) -> Vec<devise_rust::mailer::SentMail> {
    state
        .mailer
        .sent_mails()
        .into_iter()
        .filter(|mail| mail.subject == "Password Changed")
        .collect()
}

/// Devise `after_update :send_password_change_notification`
/// (`database_authenticatable.rb:163-168`): a successful token reset mails
/// the password-change notice to the record's current address when the
/// config enables it (the port has no callbacks, so the controller path
/// owns the decision).
#[tokio::test]
async fn flow_reset_password_sends_password_change_notification() {
    let mut config = common::test_config();
    config.send_password_change_notification = true;
    let (state, app) = common::build_app(common::test_state_with_config(default_mapping(), config));
    seed_user(&state, "reset-notify@example.com", "secret123").await;
    let token = reset_token_for(&state, &app, "reset-notify@example.com").await;

    let resp = submit_reset(&app, &token, "brand-new-pass").await;
    assert_eq!(resp.status(), StatusCode::FOUND);

    let changed = password_change_mails(&state);
    assert_eq!(
        changed.len(),
        1,
        "exactly one password_change delivery: {:?}",
        state
            .mailer
            .sent_mails()
            .iter()
            .map(|m| (&m.to, &m.subject))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        changed[0].to, "reset-notify@example.com",
        "the notice goes to the current address"
    );
}

/// Devise parity: with `send_password_change_notification` off the reset
/// stays silent (the Devise default).
#[tokio::test]
async fn flow_reset_password_notification_disabled_stays_silent() {
    let (state, app) = common::build_app(common::test_state(default_mapping()));
    seed_user(&state, "reset-quiet@example.com", "secret123").await;
    let token = reset_token_for(&state, &app, "reset-quiet@example.com").await;

    let resp = submit_reset(&app, &token, "brand-new-pass").await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert!(
        password_change_mails(&state).is_empty(),
        "no password_change notice when the config is off"
    );
}

/// Devise parity: a failed reset never mails the notice (no digest moved,
/// so the `after_update` decision stays pending-free).
#[tokio::test]
async fn flow_reset_password_failure_sends_no_notification() {
    let mut config = common::test_config();
    config.send_password_change_notification = true;
    let (state, app) = common::build_app(common::test_state_with_config(default_mapping(), config));
    seed_user(&state, "reset-failed@example.com", "secret123").await;

    // Unknown token: the update renders errors and persists nothing.
    let resp = submit_reset(&app, "totally-unknown", "brand-new-pass").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        password_change_mails(&state).is_empty(),
        "a failed reset mails no password_change notice"
    );
}

// ============================================================================
// Registrations update flash/bypass matrix (Devise
// `registrations_controller.rb#update` lines 46-62, 131-135, 151-162):
// the flash key and the bypass re-sign-in follow Devise's branch order
// exactly - pending reconfirmation first, then `sign_in_after_change_password?`
// (config OR a blank submitted password), and the flash NEVER consults
// `active_for_authentication?`. M-4.
// ============================================================================

/// PATCH the account update action with the given urlencoded body and the
/// jar's cookie replayed.
async fn submit_account_update(app: &Router, body: &str, cookie: &str) -> Response {
    call(
        app,
        Request::builder()
            .method(Method::PATCH)
            .uri("/users")
            .header(header::COOKIE, cookie)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body.to_string()))
            .expect("request"),
    )
    .await
}

/// The flash keys a response staged into the signed flash cookie.
fn update_flash_keys(response: &Response, config: &DeviseConfig) -> Vec<String> {
    common::flash_keys_from_cookies(&set_cookie_pairs(response), config)
}

/// Devise registrations#update (M-4): a password change under the default
/// `sign_in_after_change_password` config flashes `updated` AND runs
/// `bypass_sign_in` (the session id is recycled, so the new salt rides a
/// fresh session instead of the pre-update one).
#[tokio::test]
async fn flow_account_update_password_change_flashes_updated_and_renews() {
    let (state, app) = common::build_app(common::test_state(default_mapping()));
    seed_user(&state, "upd-pw@example.com", "secret123").await;

    let mut jar = Jar::new();
    jar.merge(&form_sign_in(&app, "upd-pw@example.com", "secret123").await);
    let before = jar.value("id").expect("session");

    let resp = submit_account_update(
        &app,
        "user[current_password]=secret123&user[password]=brand-new-pass&user[password_confirmation]=brand-new-pass",
        &jar.header(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    jar.merge(&resp);
    assert!(
        update_flash_keys(&resp, &state.config).contains(&"updated".to_string()),
        "a password change with the config on flashes updated"
    );
    assert_ne!(
        before,
        jar.value("id").expect("session"),
        "the updated branch performs bypass_sign_in (session renewed)"
    );
    // The re-signed-in session carries the NEW salt, so the next request
    // still resolves the account (the pre-update salt would fail the
    // warden compare and log the user out).
    assert_eq!(
        probe_private(&app, &jar.header()).await.status(),
        StatusCode::OK,
        "the bypass re-sign-in keeps the session live"
    );
}

/// Devise `sign_in_after_change_password?` (`registrations_controller.rb:132`):
/// a BLANK submitted password returns true immediately, so the update still
/// flashes `updated` and still re-signs in (the salt never moved, so the
/// existing session stays valid either way).
#[tokio::test]
async fn flow_account_update_blank_password_still_renews_with_updated_flash() {
    let (state, app) = common::build_app(common::test_state(default_mapping()));
    seed_user(&state, "upd-blank@example.com", "secret123").await;

    let mut jar = Jar::new();
    jar.merge(&form_sign_in(&app, "upd-blank@example.com", "secret123").await);
    let before = jar.value("id").expect("session");

    // Whitespace-only password: Devise's `blank?` treats it as absent.
    let resp = submit_account_update(
        &app,
        "user[current_password]=secret123&user[password]=%20%20",
        &jar.header(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    jar.merge(&resp);
    assert!(
        update_flash_keys(&resp, &state.config).contains(&"updated".to_string()),
        "a blank password keeps the updated branch"
    );
    assert_ne!(
        before,
        jar.value("id").expect("session"),
        "a blank password still performs bypass_sign_in"
    );
}

/// Devise `sign_in_after_change_password?` returning false (config off AND a
/// real password change): flash `updated_but_not_signed_in` and NO session
/// renewal, because Devise never calls `bypass_sign_in` on that branch.
#[tokio::test]
async fn flow_account_update_password_change_without_sign_in_keeps_session() {
    let mut config = common::test_config();
    config.sign_in_after_change_password = false;
    let (state, app) = common::build_app(common::test_state_with_config(default_mapping(), config));
    seed_user(&state, "upd-nosignin@example.com", "secret123").await;

    let mut jar = Jar::new();
    jar.merge(&form_sign_in(&app, "upd-nosignin@example.com", "secret123").await);
    let before = jar.value("id").expect("session");

    let resp = submit_account_update(
        &app,
        "user[current_password]=secret123&user[password]=brand-new-pass&user[password_confirmation]=brand-new-pass",
        &jar.header(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    jar.merge(&resp);
    assert!(
        update_flash_keys(&resp, &state.config).contains(&"updated_but_not_signed_in".to_string()),
        "config off plus a changed password flashes updated_but_not_signed_in"
    );
    assert_eq!(
        before,
        jar.value("id").expect("session"),
        "the no-sign-in branch never renews the session"
    );
}

/// Devise `set_flash_message_for_update` (M-4): the flash decision reads the
/// reconfirmation/`sign_in_after_change_password?` branches ONLY. The port
/// previously consulted `active_for_authentication?`, so an unconfirmed
/// record changing its password flashed `updated_but_not_signed_in` where
/// Devise flashes `updated`.
///
/// The app is wired WITHOUT the activatable fetch hook: ghb's gate deletes
/// the scope session key before the handler runs, so the controller branch
/// under test is reached through the hook-free wiring (the hook is an
/// independent layer concern, not part of this decision).
#[tokio::test]
async fn flow_account_update_inactive_record_ignores_active_gate_for_flash() {
    let (state, app) = update_matrix_no_gate_app(common::test_state(default_mapping()));
    seed_user_unconfirmed(&state, "upd-unconfirmed@example.com", "secret123").await;

    let mut jar = Jar::new();
    let resp = call(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri("/devise-test/bypass-sign-in?email=upd-unconfirmed%40example.com")
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "bypass sign-in installs the session"
    );
    jar.merge(&resp);

    let resp = submit_account_update(
        &app,
        "user[current_password]=secret123&user[password]=brand-new-pass&user[password_confirmation]=brand-new-pass",
        &jar.header(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert!(
        update_flash_keys(&resp, &state.config).contains(&"updated".to_string()),
        "an inactive record follows the Devise branch, not the active_for_authentication key"
    );

    // The password really moved (the branch ran, it did not bail early).
    let mut conditions = Conditions::new();
    conditions.insert(
        "email",
        Value::String("upd-unconfirmed@example.com".to_string()),
    );
    let after = state
        .adapter
        .find_first(&conditions)
        .await
        .expect("lookup")
        .expect("record");
    assert_ne!(
        after.encrypted_password, "",
        "the password change persisted on the inactive record too"
    );
}

/// Hook-free wiring of the devise router plus the bypass probe (see
/// [`flow_account_update_inactive_record_ignores_active_gate_for_flash`]).
fn update_matrix_no_gate_app(state: common::TestState) -> (common::TestState, Router) {
    let mapping = state.mapping.clone();
    let scope_name = mapping.name.clone();
    let finder: Arc<dyn ModelFinder> = Arc::new(AdapterBridge::new(state.adapter.as_ref().clone()));
    let devise_layer = DeviseLayer::new(
        common::registry_with(std::slice::from_ref(&mapping)),
        state.config.clone(),
    )
    .with_hooks(Arc::new(HookRegistry::new()))
    .with_finder(&scope_name, finder);
    let session_layer = session_manager_layer(&state.config).expect("session layer builds");
    let probe_adapter = state.adapter.clone();

    let app = Router::new()
        .merge(devise_for_router(state.clone()))
        .route(
            "/devise-test/bypass-sign-in",
            axum::routing::get(
                move |session: Session,
                      Query(query): Query<std::collections::HashMap<String, String>>| {
                    let adapter = probe_adapter.clone();
                    async move {
                        let mut conditions = Conditions::new();
                        conditions.insert("email", Value::String(query.get("email").cloned().unwrap_or_default()));
                        let Some(user) = OrmAdapter::find_first(adapter.as_ref(), &conditions)
                            .await
                            .expect("lookup")
                        else {
                            return StatusCode::NOT_FOUND;
                        };
                        devise_rust_axum::test_helpers::bypass_sign_in(&session, "user", &user)
                            .await
                            .expect("bypass");
                        StatusCode::OK
                    }
                },
            ),
        )
        .layer(devise_layer)
        .layer(session_layer);
    (state, app)
}

// ============================================================================
// Sign-in order and the sign-up pipeline (IN-04 / IN-03):
// Devise's `hooks/activatable.rb` registers before `hooks/lockable.rb`
// (models.rb include order), and its `throw :warden` aborts the request
// before the lockable `after_set_user` hook can reset the counter;
// `registrations#create` signs the new record in through the SAME
// pipeline `sessions#create` uses, so trackable writes once.
// ============================================================================

/// Write `failed_attempts` straight through the test adapter (the brute-force
/// history the IN-04 test proves is preserved).
async fn write_failed_attempts(
    state: &common::TestState,
    key: &devise_rust::adapter::DeviseKey,
    attempts: i64,
) {
    let mut fields = std::collections::HashMap::new();
    fields.insert("failed_attempts".to_string(), Value::Integer(attempts));
    state
        .adapter
        .update_columns(key, &fields)
        .await
        .expect("counter write");
}

/// IN-04: the activatable gate runs BEFORE the lockable reset, so a failed
/// sign-in on an inactive (unconfirmed) account must leave the stored
/// `failed_attempts` untouched. Resetting first would let an attacker erase
/// brute-force history by submitting the correct password on an account
/// they cannot yet use.
#[tokio::test]
async fn flow_sign_in_inactive_account_preserves_failed_attempts() {
    let (state, app) = common::build_app(common::test_state(default_mapping()));
    let user = seed_user_unconfirmed(&state, "inactive-count@example.com", "secret123").await;
    let key = AnyDeviseModel::to_key(&user);
    write_failed_attempts(&state, &key, 7).await;

    // The CORRECT password: the account is authenticated, then the
    // activatable gate rejects it with the confirmable inactive message.
    let resp = form_sign_in(&app, "inactive-count@example.com", "secret123").await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let cookies = set_cookie_pairs(&resp);
    assert!(
        common::flash_keys_from_cookies(&cookies, &state.config)
            .contains(&"unconfirmed".to_string()),
        "the rejection carries the confirmable inactive message: {cookies:?}"
    );
    assert_eq!(
        state
            .adapter
            .get(&key)
            .await
            .expect("lookup")
            .expect("record")
            .failed_attempts,
        7,
        "a failed inactive sign-in must not reset the counter"
    );
}

/// IN-03: `registrations#create` signs the new record in through the same
/// pipeline `sessions#create` runs (trackable bookkeeping, hooks, session
/// insert), so `sign_in_count` is 1 after a sign-up with an active record.
/// The port previously only inserted the session payload, leaving the
/// trackable columns at zero (an unaudited sign-up).
#[tokio::test]
async fn flow_sign_up_runs_the_sign_in_pipeline_with_trackable() {
    // An unconfirmed record with a never-expiring access window is ACTIVE
    // (`allow_unconfirmed_access_for: nil`), so the create action takes the
    // sign-in branch (`registrations_controller.rb:22-25`).
    let mut config = common::test_config();
    config.allow_unconfirmed_access_for = None;
    let (state, app) = common::build_app(common::test_state_with_config(default_mapping(), config));

    let mut jar = Jar::new();
    let resp = call(
        &app,
        Request::builder()
            .method(Method::POST)
            .uri("/users")
            .header(
                header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(Body::from(
                "user[email]=signup-track@example.com&user[password]=secret123&user[password_confirmation]=secret123",
            ))
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let cookies = set_cookie_pairs(&resp);
    assert!(
        common::flash_keys_from_cookies(&cookies, &state.config).contains(&"signed_up".to_string()),
        "an active sign-up record flashes signed_up (the sign-in branch): {cookies:?}"
    );
    jar.merge(&resp);

    // The sign-in pipeline ran: the follow-up authenticated request resolves
    // the new account through the session the create action minted.
    let probe = probe_private(&app, &jar.header()).await;
    assert_eq!(
        probe.status(),
        StatusCode::OK,
        "the sign-up live-sessions the new account"
    );
    let email = body_json(probe).await["email"].as_str().map(str::to_string);
    assert_eq!(email.as_deref(), Some("signup-track@example.com"));

    let mut conditions = Conditions::new();
    conditions.insert(
        "email",
        Value::String("signup-track@example.com".to_string()),
    );
    let record = state
        .adapter
        .find_first(&conditions)
        .await
        .expect("lookup")
        .expect("record");
    assert_eq!(
        record.sign_in_count, 1,
        "trackable wrote exactly once on the sign-up path"
    );
    assert!(
        record.current_sign_in_at.is_some(),
        "the sign-in bookkeeping stamped the current sign-in time"
    );
}

// ============================================================================
// D-04 renewal-gate propagation (261026-ghh): a failed session-id cycle must
// answer 500, never a flashed success. The `CycleFailStore` budget lets a
// sign-in succeed and the NEXT transition's cycle fail.
// ============================================================================

/// The account-update renewal (`bypass_sign_in_and_renew`) propagates a
/// failed cycle as a 500 instead of flashing `updated`.
#[tokio::test]
async fn flow_account_update_failed_renewal_answers_internal_error() {
    let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (state, app) =
        common::build_app_with_cycle_switch(common::test_state(default_mapping()), closed.clone());
    seed_user(&state, "renew-update@example.com", "secret123").await;
    let mut jar = Jar::new();

    // The switch stays open through the sign-in.
    let resp = form_sign_in(&app, "renew-update@example.com", "secret123").await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    jar.merge(&resp);
    closed.store(true, std::sync::atomic::Ordering::SeqCst);

    // The account update's cycle spends the spent budget: 500, not a
    // flashed success.
    let resp = call(
        &app,
        Request::builder()
            .method(Method::PATCH)
            .uri("/users")
            .header(header::COOKIE, jar.header())
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(
                "user[current_password]=secret123&user[password]=rotated-pass&user[password_confirmation]=rotated-pass",
            ))
            .expect("request"),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "a failed account-update renewal must fail the request"
    );
    let cookies = set_cookie_pairs(&resp);
    assert!(
        !common::flash_keys_from_cookies(&cookies, &state.config).contains(&"updated".to_string()),
        "no success flash may survive a failed renewal: {cookies:?}"
    );
}

/// The registrations#destroy renewal (`sign_out_and_renew`) propagates a
/// failed cycle as a 500 instead of flashing `destroyed`.
#[tokio::test]
async fn flow_registrations_destroy_failed_renewal_answers_internal_error() {
    let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (state, app) =
        common::build_app_with_cycle_switch(common::test_state(default_mapping()), closed.clone());
    seed_user(&state, "renew-destroy@example.com", "secret123").await;
    let mut jar = Jar::new();

    let resp = form_sign_in(&app, "renew-destroy@example.com", "secret123").await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    jar.merge(&resp);
    closed.store(true, std::sync::atomic::Ordering::SeqCst);

    let resp = call(
        &app,
        Request::builder()
            .method(Method::DELETE)
            .uri("/users")
            .header(header::COOKIE, jar.header())
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "a failed destroy renewal must fail the request"
    );
    let cookies = set_cookie_pairs(&resp);
    assert!(
        !common::flash_keys_from_cookies(&cookies, &state.config)
            .contains(&"destroyed".to_string()),
        "no success flash may survive a failed renewal: {cookies:?}"
    );
}

/// The passwords#update sign-in renewal (`insert_session_and_renew`)
/// propagates a failed cycle as a 500 instead of flashing `updated`.
#[tokio::test]
async fn flow_passwords_update_failed_renewal_answers_internal_error() {
    let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (state, app) =
        common::build_app_with_cycle_switch(common::test_state(default_mapping()), closed.clone());
    seed_user(&state, "renew-reset@example.com", "secret123").await;
    let token = reset_token_for(&state, &app, "renew-reset@example.com").await;

    // Close the switch: the reset sign-in renewal must fail.
    closed.store(true, std::sync::atomic::Ordering::SeqCst);
    let resp = submit_reset(&app, &token, "brand-new-pass").await;
    assert_eq!(
        resp.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "a failed reset sign-in renewal must fail the request"
    );
    let cookies = set_cookie_pairs(&resp);
    assert!(
        !common::flash_keys_from_cookies(&cookies, &state.config).contains(&"updated".to_string())
            && !common::flash_keys_from_cookies(&cookies, &state.config)
                .contains(&"updated_not_active".to_string()),
        "no success flash may survive a failed renewal: {cookies:?}"
    );
}

// ============================================================================
// 261026-ghh controller drift sweep: mailer failure, no_token target, and
// the timeout flash pair (the `timedout` marker Devise stages beside the
// `timeout` alert, failure_app.rb:137).
// ============================================================================

/// A mailer whose every delivery fails (the "SMTP down" stand-in, mirroring
/// the actix `FailingMailer` fixture).
#[derive(Default)]
struct FailingMailer;

impl devise_rust::mailer::Mailer<FixtureUser> for FailingMailer {
    fn confirmation_instructions(
        &self,
        _record: &FixtureUser,
        _token: Option<&str>,
        _context: &devise_rust::mailer::MailerContext,
    ) -> Result<String, devise_rust::error::DeviseError> {
        Err(devise_rust::error::DeviseError::Mailer(
            "SMTP unavailable (test)".to_string(),
        ))
    }

    fn reset_password_instructions(
        &self,
        _record: &FixtureUser,
        _token: Option<&str>,
        _context: &devise_rust::mailer::MailerContext,
    ) -> Result<String, devise_rust::error::DeviseError> {
        Err(devise_rust::error::DeviseError::Mailer(
            "SMTP unavailable (test)".to_string(),
        ))
    }

    fn unlock_instructions(
        &self,
        _record: &FixtureUser,
        _token: Option<&str>,
        _context: &devise_rust::mailer::MailerContext,
    ) -> Result<String, devise_rust::error::DeviseError> {
        Err(devise_rust::error::DeviseError::Mailer(
            "SMTP unavailable (test)".to_string(),
        ))
    }

    fn email_changed(
        &self,
        _record: &FixtureUser,
        _token: Option<&str>,
        _context: &devise_rust::mailer::MailerContext,
    ) -> Result<String, devise_rust::error::DeviseError> {
        Err(devise_rust::error::DeviseError::Mailer(
            "SMTP unavailable (test)".to_string(),
        ))
    }

    fn password_change(
        &self,
        _record: &FixtureUser,
        _token: Option<&str>,
        _context: &devise_rust::mailer::MailerContext,
    ) -> Result<String, devise_rust::error::DeviseError> {
        Err(devise_rust::error::DeviseError::Mailer(
            "SMTP unavailable (test)".to_string(),
        ))
    }
}

/// Devise propagates a failed confirmation delivery after sign-up as a 500
/// (Rails renders the raised delivery error): swallowing it behind an
/// eprintln turns a broken mailer into silent "check your inbox" dead air.
#[tokio::test]
async fn flow_sign_up_with_failing_mailer_answers_internal_error() {
    use devise_rust_axum::DeviseWebState;

    type FailingState = DeviseWebState<FixtureUser, common::IdAssigningAdapter, FailingMailer>;

    let state = FailingState::new(
        common::default_mapping(),
        common::registry_with(std::slice::from_ref(&common::default_mapping())),
        std::sync::Arc::new(common::test_config()),
        std::sync::Arc::new(common::IdAssigningAdapter::new()),
        std::sync::Arc::new(FailingMailer),
        std::sync::Arc::new(SystemClock),
    )
    .expect("failing-mailer state builds");
    let (_state, app) = common::build_app_with_mailer(state);

    let resp = call(
        &app,
        Request::builder()
            .method(Method::POST)
            .uri("/users")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ACCEPT, "text/html")
            .body(Body::from(
                "user[email]=m-mailer%40example.com&user[password]=secret123&user[password_confirmation]=secret123",
            ))
            .expect("request"),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "a failed confirmation delivery must NOT report a successful sign-up"
    );
}

/// Devise's `assert_reset_token_passed` (`passwords_controller.rb:65-70`)
/// redirects a blank-token edit to `new_session_path`, NOT to the site
/// root: the user must land on the sign-in form with the `no_token` alert.
#[tokio::test]
async fn flow_passwords_edit_without_token_redirects_to_sign_in_path() {
    let (state, app) = common::build_app(common::test_state(common::default_mapping()));

    let resp = call(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri("/users/password/edit")
            .header(header::ACCEPT, "text/html")
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let location = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert_eq!(
        location, "/users/sign_in",
        "a missing reset token redirects to the scope sign-in path, not /"
    );
    let cookies = set_cookie_pairs(&resp);
    assert!(
        common::flash_keys_from_cookies(&cookies, &state.config).contains(&"no_token".to_string()),
        "the no_token alert rides the redirect: {cookies:?}"
    );
}

/// A session the timeoutable hook expires fails with the Devise timeout
/// flash PAIR: the `timeout` alert key and the `timedout` marker
/// (`failure_app.rb:135-139` stages both; the marker is how a later
/// failure knows to keep the pair).
#[tokio::test]
async fn flow_timeout_failure_carries_timeout_flash_and_marker() {
    let (state, app) = common::build_app(common::test_state(common::timeout_mapping()));
    seed_user(&state, "timedout@example.com", "secret123").await;
    let mut jar = Jar::new();

    let resp = form_sign_in(&app, "timedout@example.com", "secret123").await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    jar.merge(&resp);

    // Age the timeoutable tick far past the default 30-minute window.
    let resp = call(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri("/devise-test/age-tick?scope=user")
            .header(header::COOKIE, jar.header())
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert!(resp.status().is_success(), "age probe reachable");
    jar.merge(&resp);

    let resp = call(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri("/users_dashboard")
            .header(header::COOKIE, jar.header())
            .header(header::ACCEPT, "text/html")
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::FOUND,
        "an expired session answers the navigational timeout redirect"
    );
    let cookies = set_cookie_pairs(&resp);
    assert!(
        common::flash_keys_from_cookies(&cookies, &state.config).contains(&"timeout".to_string()),
        "the timeout alert key rides the redirect: {cookies:?}"
    );
    assert!(
        common::timedout_marker_from_cookies(&cookies, &state.config),
        "the timedout marker rides the SAME redirect (failure_app.rb:137): {cookies:?}"
    );
}
