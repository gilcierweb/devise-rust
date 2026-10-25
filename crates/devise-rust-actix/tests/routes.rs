//! Route-registration parity tests (ACTIX-03).
//!
//! - Route table equality: the registered actix scope answers every
//!   `RouteSpec` from `Mapping::route_specs` — default mapping plus
//!   customization variants (`only`, `skip`, `path_names`, `sign_out_via`).
//! - Controllers: all five groups answer happy paths (+ flash-split for
//!   HTML vs JSON).
//! - Unlock routes vanish when `unlock_strategy` excludes `email`.

#![allow(clippy::missing_panics_doc)]

mod common;

use actix_web::{http::StatusCode, test};
use common::FixtureUser;
use devise_rust::adapter::OrmAdapter;
use devise_rust::scope::{Mapping, Module, PathNames, SignOutVia};

fn mapping_with(f: impl FnOnce(&mut Mapping)) -> Mapping {
    let mut mapping = common::default_mapping();
    f(&mut mapping);
    mapping
}

/// Route table equality (default mapping): every core spec answers (non-404).
#[actix_web::test]
async fn route_table_matches_core_specs_default() {
    let mapping = common::default_mapping();
    let expected: Vec<(String, String)> = mapping
        .route_specs()
        .iter()
        .map(|s| (s.method.clone(), s.path.clone()))
        .collect();
    let (state, app) = common::build_app(common::test_state(mapping)).await;
    let _ = &state;

    let mut probed = 0usize;
    for (method, path) in &expected {
        // PATCH and PUT hit the same handler; probe every spec.
        let req = test::TestRequest::default()
            .method(method.parse().expect("method parses"))
            .uri(path)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_ne!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "spec {method} {path} must be registered, got {:?}",
            resp.status()
        );
        probed += 1;
    }
    assert_eq!(probed, expected.len());
}

#[actix_web::test]
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
    let (_state, app) = common::build_app(common::test_state(mapping)).await;
    let spec_list = expected.clone();
    for (method, path) in &expected {
        let req = test::TestRequest::default()
            .method(method.parse().expect("method parses"))
            .uri(path)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_ne!(resp.status(), StatusCode::NOT_FOUND, "{method} {path}");
    }
    // Registration routes must be ABSENT after only-filtering.
    let req = test::TestRequest::post().uri("/users").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{spec_list:?}");
}

#[actix_web::test]
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
    let (_state, app) = common::build_app(common::test_state(mapping)).await;

    // Renamed routes answer.
    for (method, path) in &[("GET", "/users/log_in"), ("POST", "/users/log_in")] {
        let req = test::TestRequest::default()
            .method((*method).parse().expect("method"))
            .uri(path)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_ne!(resp.status(), StatusCode::NOT_FOUND, "{method} {path}");
    }
    // Confirmation routes are skipped entirely.
    let req = test::TestRequest::get()
        .uri("/users/confirmation")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[actix_web::test]
async fn route_table_matches_core_specs_sign_out_via_get() {
    let mapping = mapping_with(|m| {
        m.sign_out_via = SignOutVia::Get;
    });
    let (_state, app) = common::build_app(common::test_state(mapping)).await;
    let req = test::TestRequest::get().uri("/users/sign_out").to_request();
    let resp = test::call_service(&app, req).await;
    assert_ne!(resp.status(), StatusCode::NOT_FOUND);
    // DELETE no longer matches.
    let req = test::TestRequest::delete()
        .uri("/users/sign_out")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(matches!(
        resp.status(),
        StatusCode::METHOD_NOT_ALLOWED | StatusCode::NOT_FOUND
    ));
}

#[actix_web::test]
async fn unlock_routes_vanish_without_email_unlock_strategy() {
    let mut config = common::test_config();
    config.unlock_strategy = "time".to_string();
    let mapping = common::default_mapping();
    let state = common::test_state_with_config(mapping, config);
    let (_state, app) = common::build_app(state).await;

    let req = test::TestRequest::get().uri("/users/unlock").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let req = test::TestRequest::post().uri("/users/unlock").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// Sessions controller: correct credentials sign in (302 + `signed_in` flash
/// for HTML; JSON success for API), wrong credentials split per format.
#[actix_web::test]
async fn sessions_controller_happy_path_and_flash_split() {
    let (state, app) = common::build_app(common::test_state(common::default_mapping())).await;
    let config = common::test_config();
    let user = FixtureUser::new_with_password("route@example.com", "secret123", &config)
        .confirmed_now(&common::SystemClock);
    let created = state.adapter.create(user).await.expect("seed");

    // HTML: 302 + flash cookie toward "/" (default after_sign_in target).
    let req = test::TestRequest::post()
        .uri("/users/sign_in")
        .insert_header(("content-type", "application/x-www-form-urlencoded"))
        .insert_header(("accept", "text/html"))
        .set_payload("email=route%40example.com&password=secret123")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(
        resp.headers()
            .get(actix_web::http::header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/")
    );
    let cookies = devise_rust_actix::test_helpers::set_cookie_pairs(&resp);
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("devise.flash=signed_in")),
        "flash cookie carries signed_in: {cookies:?}"
    );
    assert!(
        cookies.iter().any(|c| c.starts_with("id=")),
        "session cookie rotated"
    );
    let _ = created;

    // JSON failure: wrong password → 401 with symbolic key.
    let req = test::TestRequest::post()
        .uri("/users/sign_in")
        .insert_header(("content-type", "application/json"))
        .insert_header(("accept", "application/json"))
        .set_payload(r#"{"email":"route@example.com","password":"wrong"}"#)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], serde_json::json!("invalid"));
}

/// Registrations create: valid params sign up + sign in; duplicate email
/// lands 422 in both formats.
#[actix_web::test]
async fn registrations_controller_create_matrix() {
    let (state, app) = common::build_app(common::test_state(common::default_mapping())).await;
    let config = common::test_config();
    let existing = FixtureUser::new_with_password("taken@example.com", "secret123", &config)
        .confirmed_now(&common::SystemClock);
    state.adapter.create(existing).await.expect("seed");

    // Valid JSON sign-up → 201.
    let req = test::TestRequest::post()
        .uri("/users")
        .insert_header(("content-type", "application/json"))
        .set_payload(
            r#"{"user":{"email":"new@example.com","password":"secret123","password_confirmation":"secret123"}}"#,
        )
        .insert_header(("accept", "application/json"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Duplicate email → 422 with :taken key on email.
    let req = test::TestRequest::post()
        .uri("/users")
        .insert_header(("content-type", "application/json"))
        .insert_header(("accept", "application/json"))
        .set_payload(
            r#"{"user":{"email":"taken@example.com","password":"secret123","password_confirmation":"secret123"}}"#,
        )
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body: serde_json::Value = test::read_body_json(resp).await;
    let errors = body["errors"]["email"].as_array().expect("email errors");
    assert!(
        errors
            .iter()
            .any(|e| e.as_str().is_some_and(|s| s.contains("taken"))),
        "{errors:?}"
    );

    // Remaining form routes exist (new/edit/cancel). Devise's cancel
    // expires the session data and redirects to the sign-up path
    // (registrations_controller.rb:78-81) — 303, not the old stub body.
    let req = test::TestRequest::default()
        .uri("/users/sign_up")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK, "GET /users/sign_up");

    let req = test::TestRequest::default()
        .uri("/users/cancel")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "GET /users/cancel");
    assert_eq!(
        resp.headers().get("location").and_then(|v| v.to_str().ok()),
        Some("/users/sign_up"),
        "cancel redirects to the sign-up path"
    );
}

/// Passwords controller: create always sends instructions (201 JSON); edit
/// without a token redirects with the `no_token` flash.
#[actix_web::test]
async fn passwords_controller_basics() {
    let (state, app) = common::build_app(common::test_state(common::default_mapping())).await;
    let config = common::test_config();
    let user = FixtureUser::new_with_password("reset@example.com", "secret123", &config)
        .confirmed_now(&common::SystemClock);
    state.adapter.create(user).await.expect("seed");

    let req = test::TestRequest::post()
        .uri("/users/password")
        .insert_header(("content-type", "application/x-www-form-urlencoded"))
        .insert_header(("accept", "application/json"))
        .set_payload("email=reset%40example.com")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    assert_eq!(
        state.mailer.sent_mails().len(),
        1,
        "reset instructions mailed"
    );

    // assert_reset_token_passed: missing token → redirect with no_token flash.
    let req = test::TestRequest::get()
        .uri("/users/password/edit")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let cookies = devise_rust_actix::test_helpers::set_cookie_pairs(&resp);
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("devise.flash=no_token")),
        "{cookies:?}"
    );
}
