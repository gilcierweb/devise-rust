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
use axum::http::{Method, Request, StatusCode, header};
use common::{FixtureUser, SystemClock, default_mapping};
use devise_rust::adapter::{Conditions, OrmAdapter, Value};
use devise_rust::failure::AnyDeviseModel;
use devise_rust::time::Clock as _;
use devise_rust_axum::test_helpers::{cookie_header, set_cookie_pairs};
use http_body_util::BodyExt;
use tower::ServiceExt;

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
    assert_eq!(jar.value("devise.flash").as_deref(), Some("signed_in"));
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
    assert_eq!(jar.value("devise.flash").as_deref(), Some("signed_out"));
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
        cookies
            .iter()
            .any(|c| c.starts_with("devise.flash=not_found_in_database")),
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
        cookies
            .iter()
            .any(|c| c.starts_with("devise.flash=invalid")),
        "unified invalid flash under paranoid: {cookies:?}"
    );
    assert!(
        !cookies
            .iter()
            .any(|c| c.starts_with("devise.flash=not_found_in_database")),
        "paranoid must not leak account absence: {cookies:?}"
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
        cookies
            .iter()
            .any(|c| c.starts_with("devise.flash=invalid")),
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
/// (422) with the virtual password fields cleared (never echoed back).
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
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
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
/// nothing (`encrypted_password` byte-identical afterwards), 422 response.
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
            .uri("/users/")
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
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

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
            .uri("/users/")
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
        cookies
            .iter()
            .any(|c| c.starts_with("devise.flash=update_needs_confirmation")),
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
            .uri("/users/")
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
            .uri("/users/")
            .header(header::COOKIE, jar.header())
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from("user[current_password]=secret123"))
            .expect("request"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let cookies = set_cookie_pairs(&resp);
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("devise.flash=updated")),
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
        cookies
            .iter()
            .any(|c| c.starts_with("devise.flash=no_token")),
        "{cookies:?}"
    );

    // Unknown token on update → 422 with the invalid key.
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
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
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
#[tokio::test]
async fn flow_confirm_by_token_blank_and_legacy_paths() {
    let (state, app) = common::build_app(common::test_state(default_mapping()));
    let user = seed_user_unconfirmed(&state, "flow6@example.com", "secret123").await;

    // Blank token (missing query param) → 422 with :blank.
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
        cookies
            .iter()
            .any(|c| c.starts_with("devise.flash=confirmed"))
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
        cookies
            .iter()
            .any(|c| c.starts_with("devise.flash=unlocked")),
        "{cookies:?}"
    );

    // Sign-in now works again.
    let resp = form_sign_in(&app, "flow7@example.com", "secret123").await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let cookies = set_cookie_pairs(&resp);
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("devise.flash=signed_in"))
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
            .uri("/users/")
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
            .uri("/users/")
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
        cookies
            .iter()
            .any(|c| c.starts_with("devise.flash=already_signed_out")),
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
        cookies
            .iter()
            .any(|c| c.starts_with("devise.flash=already_authenticated")),
        "already_authenticated flash expected: {cookies:?}"
    );
}
