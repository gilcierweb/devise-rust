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

use actix_web::HttpResponse;
use actix_web::dev::ServiceResponse;
use actix_web::http::header;
use actix_web::test;
use common::{FixtureUser, SystemClock, TestState};
use devise_rust::adapter::{Conditions, DeviseKey, OrmAdapter, Value};
use devise_rust::failure::AnyDeviseModel;
use devise_rust::time::Clock as _;
use devise_rust_actix::test_helpers::{cookie_header, set_cookie_pairs};
use std::collections::HashMap;

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

/// The session (`id=`) cookie pair of a response, for flash probe replay
/// (the flash rides the signed session now, S11).
fn session_cookie(resp: &actix_web::dev::ServiceResponse) -> String {
    set_cookie_pairs(resp)
        .into_iter()
        .find(|c| c.starts_with("id="))
        .expect("session cookie on the response")
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
    assert_eq!(
        common::flash_of(&app, &jar.header()).await.as_deref(),
        Some("signed_in")
    );
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
    assert_eq!(
        common::flash_of(&app, &jar.header()).await.as_deref(),
        Some("signed_out")
    );
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
    assert_eq!(
        common::flash_of(&app, &session_cookie(&resp))
            .await
            .as_deref(),
        Some("not_found_in_database"),
        "not_found_in_database flash on unknown email"
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
    assert_eq!(
        common::flash_of(&app, &session_cookie(&resp))
            .await
            .as_deref(),
        Some("invalid"),
        "unified invalid flash under paranoid"
    );
}

/// Devise's `request_keys` second parse pass
/// (`strategies/authenticatable.rb:147-167`, integration contract
/// `authenticatable_test.rb:579-608`): a configured request key the bridge
/// snapshot never carries (neither `host`-mapped nor `remote_ip`-mapped) is a
/// MISSING REQUIRED lookup condition, so the parse fails and the request
/// never reaches `find_for_authentication`: which is why CORRECT
/// credentials fail exactly like the wrong-password flow: the navigational
/// 302 plus the generic `invalid` flash, and the returned cookies stay
/// anonymous.
#[actix_web::test]
async fn flow_sign_in_request_keys_missing_aborts_before_lookup() {
    let mut config = common::test_config();
    config.request_keys = vec!["subdomain".to_string()];
    let (state, app) = common::build_app(common::test_state_with_config(
        common::default_mapping(),
        config,
    ))
    .await;
    seed_user(&state, "flow-rk@example.com", "secret123").await;

    // Correct credentials, no `subdomain` on the bridge snapshot: Devise's
    // `with_authentication_hash` returns false, so no strategy applies and
    // the generic invalid failure is reported.
    let resp = form_sign_in(&app, "flow-rk@example.com", "secret123").await;
    assert_eq!(resp.status(), 302);
    assert_eq!(
        resp.headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/users/sign_in")
    );
    jar_assert_anon(&app, &resp, "a missing request key must abort the sign in").await;
    assert_eq!(
        common::flash_of(&app, &session_cookie(&resp))
            .await
            .as_deref(),
        Some("invalid"),
        "a missing required request key reports the generic invalid failure"
    );
}

/// Replay the failure response's cookies against a guarded route and assert
/// the request stays anonymous (a failed sign-in must not mint a session).
async fn jar_assert_anon(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    resp: &actix_web::dev::ServiceResponse,
    message: &str,
) {
    let mut jar = Jar::new();
    jar.merge(resp);
    let probe = test::call_service(
        app,
        test::TestRequest::get()
            .uri("/users_dashboard")
            .insert_header(("cookie", jar.header()))
            .to_request(),
    )
    .await;
    assert_eq!(probe.status(), 302, "{message}");
}

/// Devise: invalid password → 302 back to `sign_in` with `invalid` flash
/// (HTML) and 401 + symbolic key for JSON callers (D-09/D-15).
#[actix_web::test]
async fn flow_sign_in_failure_formats() {
    let (state, app) = common::build_app(common::test_state(common::default_mapping())).await;
    seed_user(&state, "flow2@example.com", "secret123").await;

    let resp = form_sign_in(&app, "flow2@example.com", "wrongpass").await;
    assert_eq!(resp.status(), 302);
    assert_eq!(
        common::flash_of(&app, &session_cookie(&resp))
            .await
            .as_deref(),
        Some("invalid"),
        "invalid flash on HTML miss"
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
/// (the configured `error_status`, 200 by default) with the virtual
/// password fields cleared (never echoed back).
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
    assert_eq!(resp.status(), 200);
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
/// nothing (`encrypted_password` byte-identical afterwards), answering the
/// configured `error_status` (200 by default) in both formats.
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
            .uri("/users")
            .insert_header(("cookie", jar.header()))
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload(
                "user[current_password]=wrongpass&user[password]=brand-new-pass&user[password_confirmation]=brand-new-pass",
            )
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 200);

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
            .uri("/users")
            .insert_header(("cookie", jar.header()))
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload("user[current_password]=secret123&user[email]=attacker@example.com")
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 302);
    assert_eq!(
        common::flash_of(&app, &session_cookie(&resp))
            .await
            .as_deref(),
        Some("update_needs_confirmation"),
        "update_needs_confirmation flash expected"
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
            .uri("/users")
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
            .uri("/users")
            .insert_header(("cookie", jar.header()))
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload("user[current_password]=secret123")
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 302);
    assert_eq!(
        common::flash_of(&app, &session_cookie(&resp))
            .await
            .as_deref(),
        Some("updated"),
        "plain update flash expected"
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
    assert_eq!(
        common::flash_of(&app, &session_cookie(&resp))
            .await
            .as_deref(),
        Some("no_token")
    );

    // Unknown token on update → the configured error_status (200 by
    // default) with `invalid` key.
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
    assert_eq!(resp.status(), 200);
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
///
/// The blank-token SHOW leg keeps asserting the hardcoded 422: Devise
/// carves `confirmations#show` out of the configurable `error_status` with
/// a TODO to adopt it only when the default changes
/// (`confirmations_controller.rb:30-31`), so the port mirrors the
/// hardcode and this test pins the carve-out.
#[actix_web::test]
async fn flow_confirm_by_token_blank_and_legacy_paths() {
    let (state, app) = common::build_app(common::test_state(common::default_mapping())).await;
    let user = seed_user_unconfirmed(&state, "flow6@example.com", "secret123").await;

    // Blank token (missing query param) → the SHOW carve-out keeps
    // Devise's hardcoded 422 with :blank.
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
    assert_eq!(
        common::flash_of(&app, &session_cookie(&resp))
            .await
            .as_deref(),
        Some("confirmed")
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
    assert_eq!(
        common::flash_of(&app, &session_cookie(&resp))
            .await
            .as_deref(),
        Some("unlocked")
    );

    // Sign-in now works again.
    let resp = form_sign_in(&app, "flow7@example.com", "secret123").await;
    assert_eq!(resp.status(), 302);
    assert_eq!(
        common::flash_of(&app, &session_cookie(&resp))
            .await
            .as_deref(),
        Some("signed_in")
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
            .uri("/users")
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
            .uri("/users")
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

    // POST to a protected route: never stored — sign-in lands on the scope
    // root (Devise `after_sign_in_path_for` → `signed_in_root_path`).
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
    assert_eq!(location.as_deref(), Some("/users"), "POST is never stored");
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
    assert_eq!(
        common::flash_of(&app, &session_cookie(&resp))
            .await
            .as_deref(),
        Some("already_signed_out"),
        "already_signed_out flash expected"
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
    assert_eq!(
        common::flash_of(&app, &session_cookie(&resp))
            .await
            .as_deref(),
        Some("already_authenticated"),
        "already_authenticated flash expected"
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
            .uri("/users")
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
    assert_eq!(
        common::flash_of(&app, &session_cookie(&resp))
            .await
            .as_deref(),
        Some("invalid"),
        "threshold lock under paranoid reports invalid"
    );

    // The account is now locked; even the correct password stays unified.
    let resp = form_sign_in(&app, "flow12@example.com", "secret123").await;
    assert_eq!(
        common::flash_of(&app, &session_cookie(&resp))
            .await
            .as_deref(),
        Some("invalid"),
        "locked + correct password stays unified"
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
    assert_eq!(
        common::flash_of(&app, &session_cookie(&resp))
            .await
            .as_deref(),
        Some("locked"),
        "threshold lock without paranoid reports locked"
    );
}

// ============================================================================
// Activatable session-fetch gate (Devise `hooks/activatable.rb`): a locked
// record held in the session authenticates nothing on the next request, the
// scope session key dies on the request that rejected it, and neither an
// unlock nor a live remember cookie resurrects the record
// (T-261026-ghb-01/02).
// ============================================================================

/// Write the lock state of the seeded account straight through the test
/// adapter (the fixture manipulation the lockable flow tests use).
async fn flow_fetch_gate_write_lock(state: &TestState, key: &DeviseKey, locked: bool) {
    let mut fields = HashMap::new();
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

/// Non-strict probe: whether the middleware resolved a record for the request.
async fn flow_fetch_gate_soft(auth: devise_rust_actix::Auth<FixtureUser>) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({ "authenticated": auth.is_authenticated() }))
}

/// GET the guarded route (the scope's `RequireAuth` probe) with the cookies
/// of `cookie` replayed.
async fn flow_fetch_gate_guarded(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = ServiceResponse,
        Error = actix_web::Error,
    >,
    cookie: &str,
) -> ServiceResponse {
    test::call_service(
        app,
        test::TestRequest::get()
            .uri("/users_dashboard")
            .insert_header((header::ACCEPT, "text/html"))
            .insert_header((header::COOKIE, cookie))
            .to_request(),
    )
    .await
}

/// Devise `hooks/activatable.rb` fetch arm: sign in, lock the account, then
/// hit the guarded route with the session cookie replayed. The request is
/// rejected (302 to the sign-in path, never 200), the flash carries the
/// `locked` key, and the non-strict surface resolves anonymous. Unlocking
/// the account afterwards still rejects, because the middleware deleted the
/// scope session key on the request that rejected it.
#[actix_web::test]
async fn flow_fetch_gate_locked_session_rejects_and_survives_unlock() {
    let soft: actix_web::Route = actix_web::web::get().to(flow_fetch_gate_soft);
    let (state, app) = common::build_app_with(
        common::test_state(common::default_mapping()),
        vec![("/users_soft", soft)],
    )
    .await;
    let user = seed_user(&state, "flowgate@example.com", "secret123").await;

    let mut jar = Jar::new();
    jar.merge(&form_sign_in(&app, "flowgate@example.com", "secret123").await);
    let live = flow_fetch_gate_guarded(&app, &jar.header()).await;
    assert_eq!(
        live.status(),
        200,
        "a live signed-in session passes the guarded route"
    );
    assert!(
        !test::read_body_json::<serde_json::Value, _>(live).await["email"]
            .as_str()
            .unwrap_or_default()
            .is_empty(),
        "the guarded handler rendered the signed-in email"
    );

    // Lock the account: the session payload stays valid, but the record no
    // longer passes `active_for_authentication?`.
    flow_fetch_gate_write_lock(&state, &user.to_key(), true).await;

    let rejected = flow_fetch_gate_guarded(&app, &jar.header()).await;
    assert_eq!(
        rejected.status(),
        302,
        "the locked session must not render the guarded route"
    );
    assert_eq!(
        rejected
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default(),
        "/users/sign_in",
        "the rejection redirects to the scope sign-in path"
    );
    assert_eq!(
        common::flash_of(&app, &session_cookie(&rejected))
            .await
            .as_deref(),
        Some("locked"),
        "the inactive message rides the flash"
    );
    // The non-strict surface stays anonymous on the same locked session.
    let soft_resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/users_soft")
            .insert_header((header::COOKIE, jar.header()))
            .to_request(),
    )
    .await;
    assert!(
        soft_resp.status().is_success(),
        "the soft probe never fails"
    );
    let soft_body: serde_json::Value = test::read_body_json(soft_resp).await;
    assert_eq!(
        soft_body["authenticated"],
        serde_json::json!(false),
        "the locked session resolves anonymous on the soft extractor"
    );

    // The browser keeps whatever cookies the rejected response carried
    // (actix sessions are cookie-carried, so the deleted key ships here).
    jar.merge(&rejected);

    // Unlock the account: the dead session must stay dead (T-261026-ghb-02).
    flow_fetch_gate_write_lock(&state, &user.to_key(), false).await;
    let after_unlock = flow_fetch_gate_guarded(&app, &jar.header()).await;
    assert_eq!(
        after_unlock.status(),
        302,
        "the deleted session key must not resurrect after the unlock"
    );
    assert_eq!(
        after_unlock
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default(),
        "/users/sign_in",
        "the unlocked replay still redirects to the sign-in path"
    );
    let after_body = actix_web::test::read_body(after_unlock).await;
    assert!(
        after_body.is_empty(),
        "the guarded handler never ran after the unlock: {:?}",
        String::from_utf8_lossy(&after_body)
    );
}

/// The remember arm is gated too: a locked user whose SESSION is gone but
/// whose remember cookie is still live resolves anonymous instead of
/// resurrecting through the strategy chain (T-261026-ghb-01).
#[actix_web::test]
async fn flow_fetch_gate_remember_arm_rejects_locked_record() {
    let (state, app) = common::build_app(common::test_state(common::default_mapping())).await;
    // The remember strategy's strict `generated_at > remember_created_at`
    // window needs a stamped instant, so the minted cookie is genuinely
    // ALIVE (the same fixture shape the two-cookie-jar regression uses).
    let mut seeded =
        FixtureUser::new_with_password("flowgate2@example.com", "secret123", &state.config)
            .confirmed_now(&SystemClock);
    seeded.remember_created_at = Some(SystemClock.now() - chrono::Duration::seconds(3600));
    let user = state.adapter.create(seeded).await.expect("seed");

    // Sign in with `remember_me` checked: the response mints BOTH the
    // session cookie and a live remember cookie.
    let mut jar = Jar::new();
    let sign_in = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/users/sign_in")
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload("email=flowgate2%40example.com&password=secret123&remember_me=1")
            .to_request(),
    )
    .await;
    assert_eq!(sign_in.status(), 302, "the remember sign-in succeeds");
    jar.merge(&sign_in);
    let remember_pair = jar
        .0
        .iter()
        .find(|pair| pair.starts_with("remember_user_token="))
        .cloned()
        .expect("the sign-in minted a live remember cookie");

    // Lock the account: the remember cookie stays valid (Devise's failure
    // app does not clear it), but the record no longer passes
    // `active_for_authentication?`.
    flow_fetch_gate_write_lock(&state, &user.to_key(), true).await;

    // Replay ONLY the remember cookie: no session payload rides the request,
    // so the remember arm is the only path to identity.
    let rejected = flow_fetch_gate_guarded(&app, &remember_pair).await;
    assert_eq!(
        rejected.status(),
        302,
        "the locked remember arm must not render the guarded route"
    );
    assert_eq!(
        common::flash_of(&app, &session_cookie(&rejected))
            .await
            .as_deref(),
        Some("locked"),
        "the inactive message rides the remember-arm rejection"
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
#[actix_web::test]
async fn flow_blank_password_reports_not_found_in_database() {
    let (state, app) = common::build_app(common::test_state(common::default_mapping())).await;
    let user = seed_user(&state, "blank@example.com", "secret123").await;
    assert_eq!(user.failed_attempts, 0, "the fixture starts unlocked");

    let resp = form_sign_in(&app, "blank@example.com", "").await;
    assert_eq!(resp.status(), 302);
    assert_eq!(
        common::flash_of(&app, &session_cookie(&resp))
            .await
            .as_deref(),
        Some("not_found_in_database"),
        "blank password reports not_found_in_database"
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
    assert_eq!(resp.status(), 302);
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
    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/users/sign_in")
            .insert_header(("content-type", "application/json"))
            .insert_header(("accept", "application/json"))
            .set_payload(r#"{"email":"blank@example.com","password":""}"#)
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 401);
    let body: serde_json::Value = actix_web::test::read_body_json(resp).await;
    assert_eq!(body["error"], serde_json::json!("not_found_in_database"));
}

/// Devise parity: inside paranoid mode the same blank-password POST reports
/// the unified `invalid` key and never leaks account existence.
#[actix_web::test]
async fn flow_blank_password_paranoid_reports_invalid() {
    let mut config = common::test_config();
    config.paranoid = true;
    let (state, app) = common::build_app(common::test_state_with_config(
        common::default_mapping(),
        config,
    ))
    .await;
    seed_user(&state, "blank-paranoid@example.com", "secret123").await;

    let resp = form_sign_in(&app, "blank-paranoid@example.com", "").await;
    assert_eq!(resp.status(), 302);
    assert_eq!(
        common::flash_of(&app, &session_cookie(&resp))
            .await
            .as_deref(),
        Some("invalid"),
        "unified invalid flash under paranoid"
    );
}

/// `error_status` wiring: a non-default `error_status` demonstrably reaches
/// the wire through the real app (build via `test_state_with_config`), so
/// the duplicate-email render reads the config instead of a constant.
/// Setting `error_status` to 422 is also the documented one-line
/// restoration path for apps that want the generated-Devise posture.
#[actix_web::test]
async fn error_status_config_reaches_validation_render() {
    let mut config = common::test_config();
    config.error_status = 422;
    let (state, app) = common::build_app(common::test_state_with_config(
        common::default_mapping(),
        config,
    ))
    .await;
    let existing = FixtureUser::new_with_password("taken@example.com", "secret123", &state.config)
        .confirmed_now(&common::SystemClock);
    state.adapter.create(existing).await.expect("seed");

    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/users")
            .insert_header(("content-type", "application/json"))
            .insert_header(("accept", "application/json"))
            .set_payload(
                r#"{"user":{"email":"taken@example.com","password":"secret123","password_confirmation":"secret123"}}"#,
            )
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 422);
    let body: serde_json::Value = test::read_body_json(resp).await;
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
async fn lock_record(state: &TestState, key: &DeviseKey) {
    let mut fields = HashMap::new();
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
async fn lock_state(state: &TestState, key: &DeviseKey) -> (bool, u32) {
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
async fn reset_token_for(
    state: &TestState,
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = ServiceResponse,
        Error = actix_web::Error,
    >,
    email: &str,
) -> String {
    let resp = test::call_service(
        app,
        test::TestRequest::post()
            .uri("/users/password")
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload(format!("user[email]={}", urlencode(email)))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 302, "instructions redirect");
    state
        .mailer
        .sent_mails()
        .last()
        .and_then(|mail| mail.template_vars.token.clone())
        .expect("reset mail carries the raw token")
}

/// PUT the update action with a valid token and a new password (the
/// `resource_params` Devise feeds `reset_password_by_token`).
async fn submit_reset(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = ServiceResponse,
        Error = actix_web::Error,
    >,
    token: &str,
    password: &str,
) -> ServiceResponse {
    test::call_service(
        app,
        test::TestRequest::patch()
            .uri("/users/password")
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload(format!(
                "user[reset_password_token]={token}&user[password]={password}&user[password_confirmation]={password}"
            ))
            .to_request(),
    )
    .await
}

/// GET the guarded probe with the cookies of `cookie` replayed (200 only
/// when a live, active session resolves).
async fn probe_private(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = ServiceResponse,
        Error = actix_web::Error,
    >,
    cookie: &str,
) -> ServiceResponse {
    test::call_service(
        app,
        test::TestRequest::get()
            .uri("/users_dashboard")
            .insert_header((header::ACCEPT, "text/html"))
            .insert_header((header::COOKIE, cookie))
            .to_request(),
    )
    .await
}

/// Devise `passwords_controller.rb#update` + `unlockable?`: an email-unlock
/// strategy unlocks the locked account on reset, the active record flashes
/// `updated`, and the reset signs the user in with the new password.
#[actix_web::test]
async fn flow_reset_password_unlocks_under_email_strategy() {
    let mut config = common::test_config();
    config.unlock_strategy = "email".to_string();
    let (state, app) =
        common::build_app(common::test_state_with_config(common::default_mapping(), config)).await;
    let user = seed_user(&state, "reset-unlock@example.com", "secret123").await;
    lock_record(&state, &user.to_key()).await;
    let token = reset_token_for(&state, &app, "reset-unlock@example.com").await;

    let mut jar = Jar::new();
    let resp = submit_reset(&app, &token, "brand-new-pass").await;
    assert_eq!(resp.status(), 302);
    jar.merge(&resp);
    assert_eq!(
        common::flash_of(&app, &jar.header()).await.as_deref(),
        Some("updated"),
        "the unlocked record is active, so Devise flashes updated"
    );

    // The email strategy ran the unlock: no lock and a zeroed counter.
    let (locked, attempts) = lock_state(&state, &user.to_key()).await;
    assert!(!locked, "unlock_access clears locked_at under the email strategy");
    assert_eq!(attempts, 0, "unlock_access zeroes failed_attempts");

    // Signed in: the guarded probe resolves the record.
    let probe = probe_private(&app, &jar.header()).await;
    assert_eq!(probe.status(), 200, "the reset signs the user in");

    // The NEW password is the one that authenticates.
    let resp = form_sign_in(&app, "reset-unlock@example.com", "brand-new-pass").await;
    assert_eq!(resp.status(), 302);
    assert_eq!(
        common::flash_of(&app, &session_cookie(&resp))
            .await
            .as_deref(),
        Some("signed_in")
    );
}

/// Devise `unlockable?` guard: a `:time` unlock strategy NEVER unlocks on a
/// password reset, so the time penalty survives the reset. The reset still
/// succeeds and signs the record in unconditionally (the activatable fetch
/// gate rejects the next request with the `locked` message, item ghb).
#[actix_web::test]
async fn flow_reset_password_keeps_lock_under_time_strategy() {
    let mut config = common::test_config();
    config.unlock_strategy = "time".to_string();
    let (state, app) =
        common::build_app(common::test_state_with_config(common::default_mapping(), config)).await;
    let user = seed_user(&state, "reset-time@example.com", "secret123").await;
    lock_record(&state, &user.to_key()).await;
    let token = reset_token_for(&state, &app, "reset-time@example.com").await;

    let mut jar = Jar::new();
    let resp = submit_reset(&app, &token, "brand-new-pass").await;
    assert_eq!(resp.status(), 302);
    jar.merge(&resp);
    assert_eq!(
        common::flash_of(&app, &jar.header()).await.as_deref(),
        Some("updated_not_active"),
        "a locked record is inactive, so Devise flashes updated_not_active"
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
        302,
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
    assert_eq!(
        common::flash_of(&app, &session_cookie(&rejected))
            .await
            .as_deref(),
        Some("locked"),
        "the inactive message rides the flash"
    );
}

/// Devise parity: an unconfirmed record resets, flashes `updated_not_active`,
/// is signed in UNCONDITIONALLY (Devise does not gate the sign-in on
/// `active_for_authentication?`), and fires `after_database_authentication`
/// before the sign-in. The activatable fetch gate rejects the next request
/// with `unconfirmed`, matching the reference behavior.
#[actix_web::test]
async fn flow_reset_password_signs_in_unconfirmed_record() {
    let (state, app) = common::build_app(common::test_state(common::default_mapping())).await;
    let user = seed_user_unconfirmed(&state, "reset-unconfirmed@example.com", "secret123").await;
    let token = reset_token_for(&state, &app, "reset-unconfirmed@example.com").await;
    // The oracle's write ops round-trip through JSON, so the stored record
    // carries a FRESH hook flag: re-read the row to observe the one the
    // controller will load and flip.
    let stored = state
        .adapter
        .get(&user.to_key())
        .await
        .expect("lookup")
        .expect("record");
    let flag = stored.after_db_auth_flag.clone();

    let mut jar = Jar::new();
    let resp = submit_reset(&app, &token, "brand-new-pass").await;
    assert_eq!(resp.status(), 302);
    jar.merge(&resp);
    assert_eq!(
        common::flash_of(&app, &jar.header()).await.as_deref(),
        Some("updated_not_active"),
        "an unconfirmed record flashes updated_not_active"
    );

    // A session exists (signed in unconditionally) and dies on the next
    // request, carrying the confirmable inactive message.
    let rejected = probe_private(&app, &jar.header()).await;
    assert_eq!(rejected.status(), 302);
    assert_eq!(
        rejected
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/users/sign_in"),
        "the inactive session redirects to the sign-in path"
    );
    assert_eq!(
        common::flash_of(&app, &session_cookie(&rejected))
            .await
            .as_deref(),
        Some("unconfirmed"),
        "unconfirmed rides the flash of the rejected request"
    );
    assert!(
        flag.load(std::sync::atomic::Ordering::SeqCst),
        "the reset path fires after_database_authentication before the sign-in"
    );
}

/// Devise parity: with `sign_in_after_reset_password` off, the successful
/// reset flashes `updated_not_active` even for an active record and leaves
/// the visitor anonymous (no session is minted).
#[actix_web::test]
async fn flow_reset_password_without_sign_in_leaves_visitor_anonymous() {
    let mut config = common::test_config();
    config.sign_in_after_reset_password = false;
    let (state, app) =
        common::build_app(common::test_state_with_config(common::default_mapping(), config)).await;
    let user = seed_user(&state, "reset-nosign@example.com", "secret123").await;
    let token = reset_token_for(&state, &app, "reset-nosign@example.com").await;
    // Fresh hook-flag handle on the stored row (see the unconfirmed test).
    let stored = state
        .adapter
        .get(&user.to_key())
        .await
        .expect("lookup")
        .expect("record");
    let flag = stored.after_db_auth_flag.clone();

    let resp = submit_reset(&app, &token, "brand-new-pass").await;
    assert_eq!(resp.status(), 302);
    assert_eq!(
        common::flash_of(&app, &session_cookie(&resp))
            .await
            .as_deref(),
        Some("updated_not_active"),
        "no sign-in means updated_not_active, even for an active record"
    );
    assert!(
        !flag.load(std::sync::atomic::Ordering::SeqCst),
        "no sign-in branch means no after_database_authentication firing"
    );

    // No session: the guarded probe rejects as anonymous.
    let probe = probe_private(&app, "").await;
    assert_eq!(
        probe.status(),
        302,
        "the reset without sign-in leaves no live session"
    );
}
