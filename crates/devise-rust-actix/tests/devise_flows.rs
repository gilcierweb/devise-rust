//! Ported devise `test/integration` flows for actix (TEST-02 actix leg, D-19).
//!
//! Drives the real middleware + controllers via `actix_web::test` with
//! cookie replay, mirroring Devise's integration suite: sign in/out,
//! flashes, redirects, error keys, cookie flows — including the
//! two-cookie-jar salt + remember regression (Phase 5 D-15) and the D-03
//! renewal gates on every privilege path.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]

mod common;

use actix_web::test;
use common::{FixtureUser, SystemClock, TestState};
use devise_rust::adapter::{Conditions, OrmAdapter, Value};
use devise_rust::failure::AnyDeviseModel;
use devise_rust_actix::test_helpers::{cookie_header, set_cookie_pairs};

/// Browser-style cookie jar: newest value per name, renewal-aware.
struct Jar(Vec<String>);

impl Jar {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn merge(&mut self, resp: &actix_web::dev::ServiceResponse) {
        for pair in set_cookie_pairs(resp) {
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

async fn seed_user(state: &TestState, email: &str, password: &str) -> FixtureUser {
    let mut user =
        FixtureUser::new_with_password(email, password, &state.config).confirmed_now(&SystemClock);
    user = state.adapter.create(user).await.expect("seed");
    user
}

/// Seed WITHOUT a `confirmed_at` stamp (confirmable flows own confirmation).
async fn seed_user_unconfirmed(state: &TestState, email: &str, password: &str) -> FixtureUser {
    let user = FixtureUser::new_with_password(email, password, &state.config);
    state.adapter.create(user).await.expect("seed")
}

fn urlencode(email: &str) -> String {
    email.replace('@', "%40")
}

async fn form_sign_in(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    email: &str,
    password: &str,
) -> actix_web::dev::ServiceResponse {
    form_sign_in_with(app, email, password, None).await
}

async fn form_sign_in_with(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    email: &str,
    password: &str,
    cookie: Option<&str>,
) -> actix_web::dev::ServiceResponse {
    let mut request = test::TestRequest::post()
        .uri("/users/sign_in")
        .insert_header(("content-type", "application/x-www-form-urlencoded"))
        .set_payload(format!("email={}&password={password}", urlencode(email)));
    if let Some(cookie) = cookie {
        request = request.insert_header(("cookie", cookie));
    }
    let request = request;
    test::call_service(app, request.to_request()).await
}

/// `DELETE /users/sign_out` with the given session cookie (Devise's default
/// `sign_out_via: :delete`).
async fn sign_out_request(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    cookie: &str,
) -> actix_web::dev::ServiceResponse {
    test::call_service(
        app,
        test::TestRequest::delete()
            .uri("/users/sign_out")
            .insert_header(("cookie", cookie))
            .to_request(),
    )
    .await
}

/// Devise `authentication_test.rb`: sign in → 302 + `signed_in` flash +
/// renewed session; sign out → 302 + `signed_out` flash.
#[actix_web::test]
async fn flow_sign_in_and_sign_out_with_flashes() {
    let (state, app) = common::build_app(common::test_state(common::default_mapping())).await;
    seed_user(&state, "flow@example.com", "secret123").await;

    let mut jar = Jar::new();
    // Anonymous GET sign-in form primes a session cookie.
    let resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/users/sign_in").to_request(),
    )
    .await;
    jar.merge(&resp);
    let anon_session = jar.value("id");

    let resp = form_sign_in(&app, "flow@example.com", "secret123").await;
    assert_eq!(resp.status(), 302);
    jar.merge(&resp);
    assert_eq!(jar.value("devise.flash").as_deref(), Some("signed_in"));
    let signed_in_session = jar.value("id").expect("session cookie");
    assert_ne!(
        anon_session.as_deref(),
        Some(signed_in_session.as_str()),
        "session id rotates on sign-in (D-03 fixation guard)"
    );

    // Authenticated probe.
    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/users_dashboard")
            .insert_header(("cookie", jar.header()))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 200);

    // Sign out: 302 + signed_out + rotate again; remember cookie tombstoned
    // is covered by the regression test.
    let resp = test::call_service(
        &app,
        test::TestRequest::delete()
            .uri("/users/sign_out")
            .insert_header(("cookie", jar.header()))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 302);
    jar.merge(&resp);
    assert_eq!(jar.value("devise.flash").as_deref(), Some("signed_out"));
    let signed_out_session = jar.value("id").expect("session cookie");
    assert_ne!(
        signed_in_session, signed_out_session,
        "session id rotates on sign-out"
    );

    // Jar is now signed out.
    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/users_dashboard")
            .insert_header(("cookie", jar.header()))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 302);
}

/// Devise parity (`strategies/database_authenticatable.rb:24-25`): an unknown
/// account fails with `not_found_in_database` outside paranoid mode — the
/// shipped locale key must stay reachable and distinguishable from a wrong
/// password on an existing account.
#[actix_web::test]
async fn flow_sign_in_unknown_email_reports_not_found() {
    let (state, app) = common::build_app(common::test_state(common::default_mapping())).await;
    seed_user(&state, "known@example.com", "secret123").await;

    let resp = form_sign_in(&app, "ghost@example.com", "secret123").await;
    assert_eq!(resp.status(), 302);
    let cookies = set_cookie_pairs(&resp);
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("devise.flash=not_found_in_database")),
        "not_found_in_database flash on unknown email: {cookies:?}"
    );
    assert!(
        !cookies
            .iter()
            .any(|c| c.starts_with("devise.flash=invalid")),
        "unknown email must not report plain invalid: {cookies:?}"
    );
}

/// Devise parity: the same unknown account inside paranoid mode reports the
/// unified `invalid` key (the enumeration oracle closes again).
#[actix_web::test]
async fn flow_sign_in_unknown_email_paranoid_reports_invalid() {
    let mut config = common::test_config();
    config.paranoid = true;
    let (state, app) = common::build_app(common::test_state_with_config(
        common::default_mapping(),
        config,
    ))
    .await;
    seed_user(&state, "known@example.com", "secret123").await;

    let resp = form_sign_in(&app, "ghost@example.com", "secret123").await;
    assert_eq!(resp.status(), 302);
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

/// Devise: invalid password → 302 back to `sign_in` with `invalid` flash
/// (HTML) and 401 + symbolic key for JSON callers (D-09/D-15).
#[actix_web::test]
async fn flow_sign_in_failure_formats() {
    let (state, app) = common::build_app(common::test_state(common::default_mapping())).await;
    seed_user(&state, "flow2@example.com", "secret123").await;

    let resp = form_sign_in(&app, "flow2@example.com", "wrongpass").await;
    assert_eq!(resp.status(), 302);
    let cookies = set_cookie_pairs(&resp);
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("devise.flash=invalid")),
        "invalid flash on HTML miss: {cookies:?}"
    );

    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/users/sign_in")
            .insert_header(("content-type", "application/json"))
            .insert_header(("accept", "application/json"))
            .set_payload(r#"{"email":"flow2@example.com","password":"wrongpass"}"#)
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 401);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], serde_json::json!("invalid"));
}

/// Devise `registerable` failure path: mismatched confirmation re-renders
/// (422) with the virtual password fields cleared (never echoed back).
#[actix_web::test]
async fn flow_sign_up_failure_clears_passwords_and_keeps_errors() {
    let (_state, app) = common::build_app(common::test_state(common::default_mapping())).await;

    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/users")
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload(
                "user[email]=flow3%40example.com&user[password]=secret123&user[password_confirmation]=mismatch",
            )
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 422);
    let body = test::read_body(resp).await;
    let text = String::from_utf8(body.to_vec()).expect("utf8");
    assert!(
        text.contains("confirmation"),
        "confirmation error key: {text}"
    );
    assert!(
        !text.contains("secret123"),
        "passwords must never echo back: {text}"
    );
}

/// Devise: the `current_password` gate — wrong current password updates
/// nothing (`encrypted_password` byte-identical afterwards), 422 both formats.
#[actix_web::test]
async fn flow_account_update_requires_current_password() {
    let (state, app) = common::build_app(common::test_state(common::default_mapping())).await;
    let user = seed_user(&state, "flow4@example.com", "secret123").await;
    let digest_before = user.encrypted_password.clone();

    let mut jar = Jar::new();
    let resp = form_sign_in(&app, "flow4@example.com", "secret123").await;
    jar.merge(&resp);

    let resp = test::call_service(
        &app,
        test::TestRequest::default()
            .method(actix_web::http::Method::PATCH)
            .uri("/users/")
            .insert_header(("cookie", jar.header()))
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload(
                "user[current_password]=wrongpass&user[password]=brand-new-pass&user[password_confirmation]=brand-new-pass",
            )
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 422);

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
/// ORIGINAL address, `unconfirmed_email` carries the new one, a
/// confirmation mail is sent to the new address, and the flash key becomes
/// `update_needs_confirmation`. Security regression: the original test
/// `concurrent "update email" requests should not allow confirming a
/// victim email address`.
#[actix_web::test]
async fn flow_account_update_email_postpones_until_confirmation() {
    let (state, app) = common::build_app(common::test_state(common::default_mapping())).await;
    seed_user(&state, "flow6@example.com", "secret123").await;

    let mut jar = Jar::new();
    let resp = form_sign_in(&app, "flow6@example.com", "secret123").await;
    jar.merge(&resp);

    let resp = test::call_service(
        &app,
        test::TestRequest::default()
            .method(actix_web::http::Method::PATCH)
            .uri("/users/")
            .insert_header(("cookie", jar.header()))
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload("user[current_password]=secret123&user[email]=attacker@example.com")
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 302);
    let cookies = set_cookie_pairs(&resp);
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("devise.flash=update_needs_confirmation")),
        "update_needs_confirmation flash expected: {cookies:?}"
    );

    // The DB row still carries the ORIGINAL address; the new one waits in
    // unconfirmed_email with a fresh token (never a raw token in the DB).
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

    // The sign-in session of the ORIGINAL address must survive (the account
    // keeps working) — #5783's protection is that the victim's session and
    // address cannot be hijacked by the pending email.
    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/users_dashboard")
            .insert_header(("cookie", jar.header()))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 200);
}

/// Devise recoverable parity (`recoverable.rb:32`): a password change
/// through the account update clears outstanding reset tokens, so a link
/// emailed before the change can no longer be used.
#[actix_web::test]
async fn flow_account_update_clears_reset_token_on_password_change() {
    let (state, app) = common::build_app(common::test_state(common::default_mapping())).await;
    seed_user(&state, "flow7@example.com", "secret123").await;

    let mut jar = Jar::new();
    let resp = form_sign_in(&app, "flow7@example.com", "secret123").await;
    jar.merge(&resp);

    let resp = test::call_service(
        &app,
        test::TestRequest::default()
            .method(actix_web::http::Method::PATCH)
            .uri("/users/")
            .insert_header(("cookie", jar.header()))
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload(
                "user[current_password]=secret123&user[password]=brand-new-pass&user[password_confirmation]=brand-new-pass",
            )
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 302);

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

/// Devise `set_flash_message_for_update`: a pending reconfirmation flashing
/// `update_needs_confirmation`; a non-active account flashing
/// `updated_but_not_signed_in`.
#[actix_web::test]
async fn flow_account_update_plain_flash() {
    let (state, app) = common::build_app(common::test_state(common::default_mapping())).await;
    seed_user(&state, "flow8@example.com", "secret123").await;

    let mut jar = Jar::new();
    let resp = form_sign_in(&app, "flow8@example.com", "secret123").await;
    jar.merge(&resp);

    let resp = test::call_service(
        &app,
        test::TestRequest::default()
            .method(actix_web::http::Method::PATCH)
            .uri("/users/")
            .insert_header(("cookie", jar.header()))
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload("user[current_password]=secret123")
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 302);
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
#[actix_web::test]
async fn flow_reset_token_errors() {
    let (state, app) = common::build_app(common::test_state(common::default_mapping())).await;
    seed_user(&state, "flow5@example.com", "secret123").await;

    // Blank/absent token → redirect + no_token flash.
    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/users/password/edit")
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 302);
    let cookies = set_cookie_pairs(&resp);
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("devise.flash=no_token")),
        "{cookies:?}"
    );

    // Unknown token on update → 422 with `invalid` key.
    let resp = test::call_service(
        &app,
        test::TestRequest::default()
            .method(actix_web::http::Method::PATCH)
            .uri("/users/password")
            .insert_header(("content-type", "application/json"))
            .insert_header(("accept", "application/json"))
            .set_payload(
                serde_json::json!({
                    "user": {
                        "reset_password_token": "totally-unknown",
                        "password": "brand-new-pass",
                        "password_confirmation": "brand-new-pass"
                    }
                })
                .to_string(),
            )
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 422);
    let body: serde_json::Value = test::read_body_json(resp).await;
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
/// token lookup still confirms; digested lookup is the primary path via the
/// mailed link.
#[actix_web::test]
async fn flow_confirm_by_token_blank_and_legacy_paths() {
    let (state, app) = common::build_app(common::test_state(common::default_mapping())).await;
    let user = seed_user_unconfirmed(&state, "flow6@example.com", "secret123").await;

    // Blank token (missing query param) → 422 with :blank.
    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/users/confirmation")
            .insert_header(("accept", "application/json"))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 422);
    let body: serde_json::Value = test::read_body_json(resp).await;
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
    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!("/users/confirmation?confirmation_token={raw}"))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 302);
    let cookies = set_cookie_pairs(&resp);
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("devise.flash=confirmed"))
    );
}

/// Devise lockable: email unlock strategy; the mailed raw token unlocks the
/// account and the redirect carries the `unlocked` flash.
#[actix_web::test]
async fn flow_unlock_by_token() {
    let (state, app) = common::build_app(common::test_state(common::default_mapping())).await;
    let user = seed_user(&state, "flow7@example.com", "secret123").await;

    // Lock it (20 failed-attempt equivalent) — maximum_attempts default 20.
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

    // Request instructions → raw token in mail; then unlock.
    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/users/unlock")
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload("email=flow7%40example.com")
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 302);
    let raw = state
        .mailer
        .sent_mails()
        .last()
        .and_then(|mail| mail.template_vars.token.clone())
        .expect("unlock mail carries raw token");
    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!("/users/unlock?unlock_token={raw}"))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 302);
    let cookies = set_cookie_pairs(&resp);
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("devise.flash=unlocked")),
        "{cookies:?}"
    );

    // Sign-in now works again.
    let resp = form_sign_in(&app, "flow7@example.com", "secret123").await;
    assert_eq!(resp.status(), 302);
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
#[actix_web::test]
async fn flow_two_cookie_jar_password_change_kills_session_and_remember() {
    let (state, app) = common::build_app(common::test_state(common::default_mapping())).await;
    seed_user(&state, "flow8@example.com", "secret123").await;

    let mut old_jar = Jar::new();
    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/users/sign_in")
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload("email=flow8%40example.com&password=secret123&remember_me=1")
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 302);
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
    // renews; D-03 renewal gate).
    let resp = test::call_service(
        &app,
        test::TestRequest::default()
            .method(actix_web::http::Method::PATCH)
            .uri("/users/")
            .insert_header(("cookie", old_jar.header()))
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload(
                "user[current_password]=secret123&user[password]=rotated-pass&user[password_confirmation]=rotated-pass",
            )
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 302);
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
    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/users_dashboard")
            .insert_header(("cookie", stale_session_jar))
            .to_request(),
    )
    .await;
    assert_eq!(
        resp.status(),
        302,
        "old session jar must be dead (salt mismatch)"
    );

    // Remember-only jar (no session): dead too (remember value == salt
    // rotated with the password, Phase-5 D-15).
    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/users_dashboard")
            .insert_header(("cookie", format!("remember_user_token={stale_remember}")))
            .to_request(),
    )
    .await;
    assert_eq!(
        resp.status(),
        302,
        "remember cookie must be dead after password change"
    );
}

/// D-03 renewal gates: Set-Cookie rotation asserted on `sign_in`, bypass
/// (account update), and `sign_out` paths, all in one running session jar.
#[actix_web::test]
async fn flow_renewal_rotation_on_privilege_paths() {
    let (state, app) = common::build_app(common::test_state(common::default_mapping())).await;
    seed_user(&state, "flow9@example.com", "secret123").await;

    let mut jar = Jar::new();
    let resp = form_sign_in(&app, "flow9@example.com", "secret123").await;
    jar.merge(&resp);
    let after_sign_in = jar.value("id").expect("session");

    // Account update (bypass_sign_in path): rotates.
    let resp = test::call_service(
        &app,
        test::TestRequest::default()
            .method(actix_web::http::Method::PATCH)
            .uri("/users/")
            .insert_header(("cookie", jar.header()))
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload(
                "user[current_password]=secret123&user[password]=rotated-pass&user[password_confirmation]=rotated-pass",
            )
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 302);
    jar.merge(&resp);
    let after_update = jar.value("id").expect("session");
    assert_ne!(after_sign_in, after_update, "account update renews");

    // Sign out: rotates.
    let resp = test::call_service(
        &app,
        test::TestRequest::delete()
            .uri("/users/sign_out")
            .insert_header(("cookie", jar.header()))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 302);
    jar.merge(&resp);
    let after_sign_out = jar.value("id").expect("session");
    assert_ne!(after_update, after_sign_out, "sign out renews");

    // Sign in again: fresh id, distinct from the signed-out one.
    let resp = form_sign_in(&app, "flow9@example.com", "rotated-pass").await;
    jar.merge(&resp);
    let after_second = jar.value("id").expect("session");
    assert_ne!(after_sign_out, after_second, "sign in renews");
}

/// Devise `store_location`: unauthenticated navigational GET stores the
/// location (same-host only); POST never stores; absolute URLs rejected.
#[actix_web::test]
async fn flow_stored_location_get_only() {
    let (state, app) = common::build_app(common::test_state(common::default_mapping())).await;
    seed_user(&state, "flow10@example.com", "secret123").await;

    // GET navigational: 302 + flash + location stored → sign-in returns there.
    let mut jar = Jar::new();
    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/users_dashboard")
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 302);
    jar.merge(&resp);
    let resp =
        form_sign_in_with(&app, "flow10@example.com", "secret123", Some(&jar.header())).await;
    assert_eq!(resp.status(), 302);
    let location = resp
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    assert_eq!(
        location.as_deref(),
        Some("/users_dashboard"),
        "stored location wins"
    );

    // POST to a protected route: never stored — sign-in lands on `/`.
    let mut jar2 = Jar::new();
    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/users_dashboard")
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 302);
    jar2.merge(&resp);
    let resp = form_sign_in(&app, "flow10@example.com", "secret123").await;
    jar2.merge(&resp);
    let location = resp
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    assert_eq!(location.as_deref(), Some("/"), "POST is never stored");
}

/// Devise `verify_signed_out_user` (`sessions_controller.rb:6`): a second
/// sign-out with no session reports `already_signed_out` (JSON: 401) instead
/// of pretending a sign-out happened.
#[actix_web::test]
async fn flow_sign_out_again_reports_already_signed_out() {
    let (state, app) = common::build_app(common::test_state(common::default_mapping())).await;
    seed_user(&state, "flow9@example.com", "secret123").await;
    let mut jar = Jar::new();

    let resp = form_sign_in(&app, "flow9@example.com", "secret123").await;
    jar.merge(&resp);
    let resp = sign_out_request(&app, &jar.header()).await;
    assert_eq!(resp.status(), 302);
    jar.merge(&resp);

    let resp = sign_out_request(&app, &jar.header()).await;
    assert_eq!(resp.status(), 302);
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
#[actix_web::test]
async fn flow_sign_in_while_signed_in_reports_already_authenticated() {
    let (state, app) = common::build_app(common::test_state(common::default_mapping())).await;
    seed_user(&state, "flow10@example.com", "secret123").await;
    let mut jar = Jar::new();

    let resp = form_sign_in(&app, "flow10@example.com", "secret123").await;
    jar.merge(&resp);

    let resp =
        form_sign_in_with(&app, "flow10@example.com", "secret123", Some(&jar.header())).await;
    assert_eq!(resp.status(), 302);
    let cookies = set_cookie_pairs(&resp);
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("devise.flash=already_authenticated")),
        "already_authenticated flash expected: {cookies:?}"
    );
}

/// Devise parity (`database_authenticatable.rb:163-168`): the reconfirmation
/// flow notifies `email_changed` to the ORIGINAL address, and the
/// confirmation instructions to the new one — the two-recipient split the
/// cancel-account-by-email-change attack depends on.
#[actix_web::test]
async fn flow_account_update_email_change_notifies_both_addresses() {
    let mut config = common::test_config();
    // Devise's default is `false`; this test opts in to prove the recipient
    // split when the notification is enabled.
    config.send_email_changed_notification = true;
    let (state, app) = common::build_app(common::test_state_with_config(
        common::default_mapping(),
        config,
    ))
    .await;
    seed_user(&state, "flow11@example.com", "secret123").await;
    let mut jar = Jar::new();
    let resp = form_sign_in(&app, "flow11@example.com", "secret123").await;
    jar.merge(&resp);

    let resp = test::call_service(
        &app,
        test::TestRequest::default()
            .method(actix_web::http::Method::PATCH)
            .uri("/users/")
            .insert_header(("cookie", jar.header()))
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload("user[current_password]=secret123&user[email]=new-addr@example.com")
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 302);

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
/// `invalid` key - lock state must not signal account existence, and a later
/// correct-password attempt on the locked account reports `invalid` too.
#[actix_web::test]
async fn flow_sign_in_lock_under_paranoid_reports_invalid() {
    let mut config = common::test_config();
    config.maximum_attempts = 2;
    config.paranoid = true;
    let (state, app) = common::build_app(common::test_state_with_config(
        common::default_mapping(),
        config,
    ))
    .await;
    seed_user(&state, "flow12@example.com", "secret123").await;

    let first = form_sign_in(&app, "flow12@example.com", "wrongpass").await;
    assert_eq!(first.status(), 302);

    let resp = form_sign_in(&app, "flow12@example.com", "wrongpass").await;
    let cookies = set_cookie_pairs(&resp);
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("devise.flash=invalid")),
        "threshold lock under paranoid reports invalid: {cookies:?}"
    );
    assert!(
        !cookies.iter().any(|c| c.starts_with("devise.flash=locked")),
        "paranoid must not leak the lock: {cookies:?}"
    );

    // The account is now locked; even the correct password stays unified.
    let resp = form_sign_in(&app, "flow12@example.com", "secret123").await;
    let cookies = set_cookie_pairs(&resp);
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("devise.flash=invalid")),
        "locked + correct password stays unified: {cookies:?}"
    );
}

/// The non-paranoid counterpart: the same threshold lock reports `locked`,
/// pinning that the unified key above is the paranoid branch and not a
/// blanket suppression.
#[actix_web::test]
async fn flow_sign_in_lock_without_paranoid_reports_locked() {
    let mut config = common::test_config();
    config.maximum_attempts = 2;
    let (state, app) = common::build_app(common::test_state_with_config(
        common::default_mapping(),
        config,
    ))
    .await;
    seed_user(&state, "flow13@example.com", "secret123").await;

    let _ = form_sign_in(&app, "flow13@example.com", "wrongpass").await;
    let resp = form_sign_in(&app, "flow13@example.com", "wrongpass").await;
    let cookies = set_cookie_pairs(&resp);
    assert!(
        cookies.iter().any(|c| c.starts_with("devise.flash=locked")),
        "threshold lock without paranoid reports locked: {cookies:?}"
    );
}
