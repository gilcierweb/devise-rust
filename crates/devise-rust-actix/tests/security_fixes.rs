//! Security / parity fix suites (S2, S4, S6, S7, S9, S11, S13 + the
//! `M`-prefixed parity fixes).
//!
//! Every test in this file is written against the *desired* Devise
//! behavior; the corresponding source fix lands only after the test is
//! seen failing.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::unwrap_used)]

mod common;

use std::sync::Arc;

use actix_web::HttpMessage;
use actix_web::cookie::CookieJar;
use actix_web::http::StatusCode;
use actix_web::test;
use common::FixtureUser;
use devise_rust::adapter::OrmAdapter;
use devise_rust::config::DeviseConfig;
use devise_rust::rememberable::RememberCookieOp;
use devise_rust::time::SystemClock;

// ===========================================================================
// S9 — the Clear tombstone must carry the same attrs as the Set cookie
// ===========================================================================

/// S9: a cookie is only deleted when name+path+domain match. An app that
/// mounts Devise under `/app` (or on a domain) sets the remember cookie with
/// `Path=/app`; a tombstone rendered with the hardcoded `Path=/` leaves the
/// live cookie in place, so the user stays signed in after sign-out.
#[actix_web::test]
async fn s9_clear_tombstone_carries_configured_path_and_domain() {
    let mut config = common::test_config();
    config
        .rememberable_options
        .insert("path".to_string(), "/app".to_string());
    config
        .rememberable_options
        .insert("domain".to_string(), "app.example.test".to_string());

    let key = devise_rust_actix::derive_remember_key(&config).expect("derive");
    let op: RememberCookieOp = devise_rust_actix::remember::forget_op("user", &config);
    assert!(
        matches!(op, RememberCookieOp::Clear { .. }),
        "forget_op yields the Clear variant"
    );

    let mut jar = CookieJar::new();
    {
        let mut signed = jar.signed_mut(&key);
        devise_rust_actix::remember::apply_op(&mut signed, &op, &config, &SystemClock);
    }
    let tombstone = jar.delta().next().expect("tombstone").to_string();
    assert!(
        tombstone.contains("Path=/app"),
        "tombstone must carry the configured path: {tombstone}"
    );
    assert!(
        tombstone.contains("Domain=app.example.test"),
        "tombstone must carry the configured domain: {tombstone}"
    );
    assert!(
        tombstone.contains("Max-Age=0"),
        "tombstone must expire immediately: {tombstone}"
    );
}

// ===========================================================================
// S4 — `allow_params_authentication` is sessions#create-only
// ===========================================================================

/// S4: Devise enables params authentication ONLY inside
/// `SessionsController#create` (`allow_params_authentication!`,
/// `sessions_controller.rb:5`). The middleware snapshot staged the flag
/// from `config.params_authenticatable` on EVERY request, so any guarded
/// route would authenticate `?user_email=…&user_password=…` query
/// credentials (credentials in URLs and logs) the moment an app or helper
/// runs the core strategy chain over the staged request.
///
/// The probe renders what the core chain over the STAGED snapshot decides
/// for query credentials on a non-sign-in route.
#[actix_web::test]
async fn s4_query_credentials_do_not_authenticate_guarded_routes() {
    let state = common::test_state(common::default_mapping());
    let email = "s4-params@example.com";
    let user = FixtureUser::new_with_password(email, "secret123", &common::test_config())
        .confirmed_now(&common::SystemClock);
    state.adapter.create(user).await.expect("seed");

    let probe = actix_web::web::get().to(params_probe);
    let (_state, app) = common::build_app_with(state, vec![("/users_params_probe", probe)]).await;

    // Raw '@' in the query (RFC 3986 allows it): the middleware snapshot
    // copies the raw pair values, so the lookup key matches the stored row.
    let query = "user_email=s4-params@example.com&user_password=secret123";
    let req = test::TestRequest::get()
        .uri(&format!("/users_params_probe?{query}"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(
        body["params_authenticated"], false,
        "query credentials must not authenticate a guarded route: {body}"
    );

    // The sign-in controller keeps its params path: form POST to
    // sessions#create still signs in (302 + signed_in flash).
    let req = test::TestRequest::post()
        .uri("/users/sign_in")
        .insert_header(("content-type", "application/x-www-form-urlencoded"))
        .insert_header(("accept", "text/html"))
        .set_payload("email=s4-params%40example.com&password=secret123")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FOUND, "form sign-in still works");
}

/// Whether the core strategy chain over the staged request snapshot
/// authenticates: the exact surface app code sees from the middleware.
async fn params_probe(
    req: actix_web::HttpRequest,
    state: actix_web::web::Data<common::TestState>,
) -> actix_web::HttpResponse {
    let staged = req
        .extensions()
        .get::<devise_rust::request::AuthRequest>()
        .cloned()
        .expect("middleware stages the request snapshot");
    let finder = devise_rust::model::AdapterBridge::new(state.adapter.as_ref().clone());
    let mut authenticated = false;
    for strategy in devise_rust::strategy::strategies_for(&state.mapping, &state.config) {
        if strategy.valid(&staged, &state.mapping, &state.config).await
            && matches!(
                strategy
                    .authenticate(&staged, &state.mapping, &finder, &state.config)
                    .await,
                Ok(devise_rust::failure::AuthOutcome::Success(_))
            )
        {
            authenticated = true;
        }
    }
    actix_web::HttpResponse::Ok().json(serde_json::json!({ "params_authenticated": authenticated }))
}

// ===========================================================================
// S13 — registrations#new/#create/#cancel require_no_authentication
// ===========================================================================

/// S13: Devise guards registrations#new/#create/#cancel with
/// `require_no_authentication` (`registrations_controller.rb:4`) — a signed-in
/// (navigational) request must be redirected home with
/// `already_authenticated` instead of creating a SECOND account, and cancel
/// must not abandon the flow it just left. Navigational-only, exactly like
/// Devise's `require_no_authentication` (`return unless is_navigational_format?`).
#[actix_web::test]
async fn s13_signed_in_sign_up_is_rejected_no_second_account() {
    let (state, app) = common::build_app(common::test_state(common::default_mapping())).await;
    let config = common::test_config();
    let existing = FixtureUser::new_with_password("s13@example.com", "secret123", &config)
        .confirmed_now(&common::SystemClock);
    state.adapter.create(existing).await.expect("seed");

    // Sign in first.
    let mut jar = std::collections::HashMap::new();
    let resp = test::TestRequest::post()
        .uri("/users/sign_in")
        .insert_header(("content-type", "application/x-www-form-urlencoded"))
        .insert_header(("accept", "text/html"))
        .set_payload("email=s13%40example.com&password=secret123")
        .to_request();
    let resp = test::call_service(&app, resp).await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let cookies = devise_rust_actix::test_helpers::set_cookie_pairs(&resp);
    let session_cookie = cookies
        .iter()
        .find(|c| c.starts_with("id="))
        .expect("session cookie")
        .clone();
    jar.insert("session", session_cookie);

    // Signed-in HTML POST /users: redirected with already_authenticated and
    // NO second row appears.
    let resp = test::TestRequest::post()
        .uri("/users")
        .insert_header(("cookie", jar.get("session").cloned().unwrap_or_default()))
        .insert_header(("content-type", "application/x-www-form-urlencoded"))
        .insert_header(("accept", "text/html"))
        .set_payload("user[email]=second@example.com&user[password]=secret123&user[password_confirmation]=secret123")
        .to_request();
    let resp = test::call_service(&app, resp).await;
    assert_eq!(
        resp.status(),
        StatusCode::FOUND,
        "signed-in POST is rejected"
    );
    let cookies = devise_rust_actix::test_helpers::set_cookie_pairs(&resp);
    let rejection_session = cookies
        .iter()
        .find(|c| c.starts_with("id="))
        .cloned()
        .unwrap_or_else(|| jar.get("session").cloned().unwrap_or_default());
    assert_eq!(
        common::flash_of(&app, rejection_session.as_str())
            .await
            .as_deref(),
        Some("already_authenticated"),
        "already_authenticated flash expected"
    );
    let mut conditions = devise_rust::adapter::Conditions::new();
    conditions.insert(
        "email",
        devise_rust::adapter::Value::String("second@example.com".to_string()),
    );
    let second = state.adapter.find_first(&conditions).await.expect("lookup");
    assert!(
        second.is_none(),
        "no second account may be created for a signed-in user"
    );

    // Signed-in GET /users/cancel + /users/sign_up: same rejection.
    for path in ["/users/cancel", "/users/sign_up"] {
        let resp = test::TestRequest::get()
            .uri(path)
            .insert_header(("cookie", jar.get("session").cloned().unwrap_or_default()))
            .insert_header(("accept", "text/html"))
            .to_request();
        let resp = test::call_service(&app, resp).await;
        assert_eq!(resp.status(), StatusCode::FOUND, "GET {path} is rejected");
        let cookies = devise_rust_actix::test_helpers::set_cookie_pairs(&resp);
        let rejection_session = cookies
            .iter()
            .find(|c| c.starts_with("id="))
            .cloned()
            .unwrap_or_else(|| jar.get("session").cloned().unwrap_or_default());
        assert_eq!(
            common::flash_of(&app, rejection_session.as_str())
                .await
                .as_deref(),
            Some("already_authenticated"),
            "already_authenticated flash on {path}"
        );
    }

    // Anonymous POST still creates the account (the guard passes through).
    let resp = test::TestRequest::post()
        .uri("/users")
        .insert_header(("content-type", "application/x-www-form-urlencoded"))
        .insert_header(("accept", "text/html"))
        .set_payload("user[email]=anon@example.com&user[password]=secret123&user[password_confirmation]=secret123")
        .to_request();
    let resp = test::call_service(&app, resp).await;
    assert_eq!(
        resp.status(),
        StatusCode::FOUND,
        "anonymous sign-up creates"
    );
    let mut conditions = devise_rust::adapter::Conditions::new();
    conditions.insert(
        "email",
        devise_rust::adapter::Value::String("anon@example.com".to_string()),
    );
    assert!(
        state
            .adapter
            .find_first(&conditions)
            .await
            .expect("lookup")
            .is_some(),
        "anonymous account exists"
    );
}

// ===========================================================================
// S7 — the controller must sanitize params per action (Devise strong params)
// ===========================================================================

/// S7: Devise sanitizes `sign_up` params to `authentication_keys +
/// password + password_confirmation` (`parameter_sanitizer.rb`). The
/// controller fed the WHOLE param map into `new_with_session`, so a client
/// could submit internal columns (`unconfirmed_email`, `failed_attempts`)
/// and have them assigned onto the new record. The model assigns what the
/// controller hands it (real-ORM parity); the controller must hand it only
/// the permitted keys.
#[actix_web::test]
async fn s7_sign_up_drops_unpermitted_internal_columns() {
    let (state, app) = common::build_app(common::test_state(common::default_mapping())).await;

    let resp = test::TestRequest::post()
        .uri("/users")
        .insert_header(("content-type", "application/json"))
        .insert_header(("accept", "application/json"))
        .set_payload(
            serde_json::json!({
                "user": {
                    "email": "s7@example.com",
                    "password": "secret123",
                    "password_confirmation": "secret123",
                    "unconfirmed_email": "attacker@example.com",
                    "failed_attempts": 19
                }
            })
            .to_string(),
        )
        .to_request();
    let resp = test::call_service(&app, resp).await;
    assert_eq!(resp.status(), StatusCode::CREATED, "valid sign-up");

    let mut conditions = devise_rust::adapter::Conditions::new();
    conditions.insert(
        "email",
        devise_rust::adapter::Value::String("s7@example.com".to_string()),
    );
    let record = state
        .adapter
        .find_first(&conditions)
        .await
        .expect("lookup")
        .expect("created");
    assert_eq!(
        record.unconfirmed_email, None,
        "unconfirmed_email must never be assigned from params (S7)"
    );
    assert_eq!(
        record.failed_attempts, 0,
        "failed_attempts must never be assigned from params (S7)"
    );
}

// ===========================================================================
// M — sessions#create builds lookup conditions from config.authentication_keys
// ===========================================================================

/// M (auth keys): Devise's `find_for_database_authentication` resolves the
/// record through `authentication_keys` (`database_authenticatable.rb`) —
/// email is only the DEFAULT. The controller hardcoded `email`, so any app
/// configuring `authentication_keys = ["username"]` could never sign in.
#[actix_web::test]
async fn m_authentication_keys_username_signs_in() {
    let mut config = common::test_config();
    config.authentication_keys = vec!["username".to_string()];
    config.case_insensitive_keys = vec!["username".to_string()];
    config.strip_whitespace_keys = vec!["username".to_string()];
    let (state, app) = common::build_app(common::test_state_with_config(
        common::default_mapping(),
        config,
    ))
    .await;

    let mut user =
        FixtureUser::new_with_password("m-auth@example.com", "secret123", &common::test_config())
            .confirmed_now(&common::SystemClock);
    user.username = Some("alice".to_string());
    state.adapter.create(user).await.expect("seed");

    // Case-insensitive username + password: the conditions come from
    // `config.authentication_keys`, normalized like the params filter does.
    let resp = test::TestRequest::post()
        .uri("/users/sign_in")
        .insert_header(("content-type", "application/x-www-form-urlencoded"))
        .insert_header(("accept", "text/html"))
        .set_payload("username=ALICE&password=secret123")
        .to_request();
    let resp = test::call_service(&app, resp).await;
    assert_eq!(
        resp.status(),
        StatusCode::FOUND,
        "username sign-in succeeds"
    );
    let cookies = devise_rust_actix::test_helpers::set_cookie_pairs(&resp);
    let session_cookie = cookies
        .iter()
        .find(|c| c.starts_with("id="))
        .expect("session cookie")
        .clone();
    assert_eq!(
        common::flash_of(&app, session_cookie.as_str())
            .await
            .as_deref(),
        Some("signed_in"),
        "signed_in flash expected"
    );
}

// ===========================================================================
// M — sessions#create fires after_database_authentication (DBAU-07)
// ===========================================================================

/// M (`after_database_authentication)`: Devise's `database_authenticatable`
/// strategy runs the hook right after a successful password check
/// (`strategies/database_authenticatable.rb`); the actix controller never
/// called it, so apps relying on the documented extension point (audit
/// logs, session stamping, OTP rotation) saw nothing on sign-in.
#[actix_web::test]
async fn m_after_database_authentication_fires_on_sign_in() {
    let (state, app) = common::build_app(common::test_state(common::default_mapping())).await;

    let user =
        FixtureUser::new_with_password("m-dbau@example.com", "secret123", &common::test_config())
            .confirmed_now(&common::SystemClock);
    let flag = user.after_db_auth_flag.clone();
    state.adapter.create(user).await.expect("seed");
    assert!(
        !flag.load(std::sync::atomic::Ordering::SeqCst),
        "flag starts clear"
    );

    let resp = test::TestRequest::post()
        .uri("/users/sign_in")
        .insert_header(("content-type", "application/x-www-form-urlencoded"))
        .insert_header(("accept", "text/html"))
        .set_payload("email=m-dbau%40example.com&password=secret123")
        .to_request();
    let resp = test::call_service(&app, resp).await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert!(
        flag.load(std::sync::atomic::Ordering::SeqCst),
        "after_database_authentication must fire on the successful sign-in"
    );
}

// ===========================================================================
// M — remember_me accepts a JSON boolean, not only "1"/"true" strings
// ===========================================================================

/// M (`remember_me` bool): JSON clients send `"remember_me": true` (a real
/// boolean). The controller only read string params, so every JSON sign-in
/// silently ignored the remember-me request.
#[actix_web::test]
async fn m_remember_me_json_bool_is_honored() {
    let (state, app) = common::build_app(common::test_state(common::default_mapping())).await;
    let user = FixtureUser::new_with_password(
        "m-remember@example.com",
        "secret123",
        &common::test_config(),
    )
    .confirmed_now(&common::SystemClock);
    state.adapter.create(user).await.expect("seed");

    let resp = test::TestRequest::post()
        .uri("/users/sign_in")
        .insert_header(("content-type", "application/json"))
        .insert_header(("accept", "application/json"))
        .set_payload(
            serde_json::json!({
                "email": "m-remember@example.com",
                "password": "secret123",
                "remember_me": true
            })
            .to_string(),
        )
        .to_request();
    let resp = test::call_service(&app, resp).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let cookies = devise_rust_actix::test_helpers::set_cookie_pairs(&resp);
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("remember_user_token=")),
        "boolean remember_me must issue the remember cookie: {cookies:?}"
    );
}

// ===========================================================================
// M — a failed confirmation mail after sign-up must surface, not vanish
// ===========================================================================

/// A mailer whose every delivery fails (the "SMTP down" stand-in).
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

type FailingState =
    devise_rust_actix::DeviseWebState<FixtureUser, common::IdAssigningAdapter, FailingMailer>;

/// M (confirmation delivery): registrations#create swallowed a failed
/// confirmation delivery with `eprintln!` — the user was told "signed up",
/// but no mail ever went out and the response claimed success (Devise
/// propagates the delivery failure; the user must learn delivery failed).
#[actix_web::test]
async fn m_failed_confirmation_mail_surfaces_as_error() {
    use actix_session::{SessionMiddleware, storage::CookieSessionStore};
    use actix_web::{App, web};
    use std::sync::Arc;

    let state: FailingState = devise_rust_actix::DeviseWebState {
        mapping: common::default_mapping(),
        config: Arc::new(common::test_config()),
        scope_registry: common::registry_with(common::default_mapping()),
        adapter: Arc::new(common::IdAssigningAdapter::new()),
        mailer: Arc::new(FailingMailer),
        clock: Arc::new(SystemClock),
        all_scopes: vec!["user".to_string()],
        marker: std::marker::PhantomData,
    };
    let key =
        devise_rust_actix::derive_actix_key(&state.config.secret_key).expect("derive actix key");
    let finder: Arc<dyn devise_rust::model::ModelFinder> = Arc::new(
        devise_rust::model::AdapterBridge::new(state.adapter.as_ref().clone()),
    );
    let scope_name = state.mapping.name.clone();
    let registry = common::registry_with(state.mapping.clone());
    let middleware = devise_rust_actix::DeviseMiddleware::new(registry, state.config.clone())
        .with_finder(&scope_name, finder);

    let data_state = state.clone();
    let app = test::init_service(
        App::new()
            .wrap(middleware)
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), key)
                    .cookie_secure(false)
                    .build(),
            )
            .service(devise_rust_actix::devise_for_users(web::Data::new(
                data_state,
            ))),
    )
    .await;

    let resp = test::TestRequest::post()
        .uri("/users")
        .insert_header(("content-type", "application/x-www-form-urlencoded"))
        .insert_header(("accept", "text/html"))
        .set_payload("user[email]=m-mailer%40example.com&user[password]=secret123&user[password_confirmation]=secret123")
        .to_request();
    let resp = test::call_service(&app, resp).await;
    assert_ne!(
        resp.status(),
        StatusCode::FOUND,
        "a failed confirmation delivery must NOT report a successful sign-up"
    );
    assert_eq!(
        resp.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "Devise propagates the mailer failure (500), never silent success"
    );
}

// ===========================================================================
// S2 — sign_out_all_scopes covers every registered mapping + sweeps devise data
// ===========================================================================

/// Status probe for the two-scope app: which scopes the middleware still
/// resolves as signed in.
async fn scope_status(req: actix_web::HttpRequest) -> actix_web::HttpResponse {
    use devise_rust_actix::extractors::scope_signed_in;
    actix_web::HttpResponse::Ok().json(serde_json::json!({
        "user": scope_signed_in(&req, "user"),
        "admin": scope_signed_in(&req, "admin"),
    }))
}

/// Bridge route inserting the seeded ADMIN row's session payload (scope
/// `admin` has no sessions controller in this fixture — the bridge is the
/// sign-in transport, like Devise's `IntegrationHelpers`).
async fn admin_bridge_sign_in(
    session: actix_session::Session,
    state: actix_web::web::Data<common::TestState>,
) -> actix_web::HttpResponse {
    let admin = state
        .adapter
        .find_first(&{
            let mut conditions = devise_rust::adapter::Conditions::new();
            conditions.insert(
                "email",
                devise_rust::adapter::Value::String("s2-admin@example.com".to_string()),
            );
            conditions
        })
        .await
        .expect("admin lookup")
        .expect("admin row");
    let (key, salt) = devise_rust::failure::AnyDeviseModel::session_pair(&admin);
    devise_rust_actix::test_helpers::sign_in(&session, "admin", &key, &salt)
        .await
        .expect("bridge sign-in");
    actix_web::HttpResponse::Ok().finish()
}

/// The two-mapping app: `user` (full devise routes) + `admin` (bridge
/// sign-in only), one shared registry, `sign_out_all_scopes` on.
async fn two_scope_app() -> (
    common::TestState,
    common::TestState,
    impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
) {
    use actix_session::{SessionMiddleware, storage::CookieSessionStore};
    use actix_web::{App, web};
    use std::sync::Arc;

    let mut config = common::test_config();
    config.sign_out_all_scopes = true;
    let user_state = common::test_state_with_config(common::default_mapping(), config.clone());
    let mut admin_mapping = common::default_mapping();
    admin_mapping.name = "admin".to_string();
    admin_mapping.class_name = "FixtureUser".to_string();
    admin_mapping.path = "admins".to_string();
    admin_mapping.singular = "admin".to_string();
    let admin_state = common::test_state_with_config(admin_mapping, config.clone());

    // The shared registry holds BOTH mappings — the source the sign-out
    // sweep must iterate. Both states carry it, the way a real app shares
    // the one registry the middleware was built with.
    let registry: Arc<devise_rust::scope::ScopeRegistry> = {
        let mut reg = devise_rust::scope::ScopeRegistry::new();
        reg.register(user_state.mapping.clone());
        reg.register(admin_state.mapping.clone());
        Arc::new(reg)
    };
    let mut user_state = user_state;
    user_state.scope_registry = registry.clone();
    let mut admin_state = admin_state;
    admin_state.scope_registry = registry.clone();

    // Seed one row in each adapter.
    let user = FixtureUser::new_with_password("s2-user@example.com", "secret123", &config)
        .confirmed_now(&SystemClock);
    user_state.adapter.create(user).await.expect("seed user");
    let admin = FixtureUser::new_with_password("s2-admin@example.com", "secret123", &config)
        .confirmed_now(&SystemClock);
    admin_state.adapter.create(admin).await.expect("seed admin");

    let key =
        devise_rust_actix::derive_actix_key(&user_state.config.secret_key).expect("derive key");
    let middleware = devise_rust_actix::DeviseMiddleware::new(registry, user_state.config.clone())
        .with_finder(
            "user",
            Arc::new(devise_rust::model::AdapterBridge::new(
                user_state.adapter.as_ref().clone(),
            )) as Arc<dyn devise_rust::model::ModelFinder>,
        )
        .with_finder(
            "admin",
            Arc::new(devise_rust::model::AdapterBridge::new(
                admin_state.adapter.as_ref().clone(),
            )) as Arc<dyn devise_rust::model::ModelFinder>,
        );

    let app = test::init_service(
        App::new()
            .wrap(middleware)
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), key)
                    .cookie_secure(false)
                    .build(),
            )
            .app_data(web::Data::new(admin_state.clone()))
            .service(devise_rust_actix::devise_for_users(web::Data::new(
                user_state.clone(),
            )))
            .route(
                "/devise-test/admin-sign-in",
                web::get().to(admin_bridge_sign_in),
            )
            .route("/users_status", web::get().to(scope_status))
            .route("/admins_status", web::get().to(scope_status)),
    )
    .await;
    (user_state, admin_state, app)
}

/// S2: Devise's `sign_out_all_scopes` iterates `Devise.mappings` — EVERY
/// registered mapping — and drops every devise-owned session key. The
/// controller degraded the scope list to the one scope that mounted the
/// sign-out route, so a signed-in `admin` survived a user sign-out, and the
/// timeout tick / stash keys outlived the logout too.
#[actix_web::test]
async fn s2_sign_out_all_scopes_clears_every_mapping() {
    let (_user_state, _admin_state, app) = two_scope_app().await;

    // Sign in BOTH scopes on one jar.
    let mut jar = std::collections::HashMap::new();
    let resp = test::TestRequest::post()
        .uri("/users/sign_in")
        .insert_header(("content-type", "application/x-www-form-urlencoded"))
        .insert_header(("accept", "text/html"))
        .set_payload("email=s2-user%40example.com&password=secret123")
        .to_request();
    let resp = test::call_service(&app, resp).await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let cookies = devise_rust_actix::test_helpers::set_cookie_pairs(&resp);
    let session_cookie = cookies
        .iter()
        .find(|c| c.starts_with("id="))
        .expect("session cookie")
        .clone();
    jar.insert("session", session_cookie);

    let resp = test::TestRequest::get()
        .uri("/devise-test/admin-sign-in")
        .insert_header(("cookie", jar.get("session").cloned().unwrap_or_default()))
        .to_request();
    let resp = test::call_service(&app, resp).await;
    assert!(resp.status().is_success());
    for pair in devise_rust_actix::test_helpers::set_cookie_pairs(&resp) {
        if pair.starts_with("id=") {
            jar.insert("session", pair);
        }
    }

    let resp = test::TestRequest::get()
        .uri("/users_status")
        .insert_header(("cookie", jar.get("session").cloned().unwrap_or_default()))
        .to_request();
    let body: serde_json::Value = test::read_body_json(test::call_service(&app, resp).await).await;
    assert_eq!(body["user"], true, "user signed in: {body}");
    assert_eq!(body["admin"], true, "admin signed in: {body}");

    // DELETE /users/sign_out: Devise's sign_out_all_scopes.
    let resp = test::TestRequest::delete()
        .uri("/users/sign_out")
        .insert_header(("cookie", jar.get("session").cloned().unwrap_or_default()))
        .to_request();
    let resp = test::call_service(&app, resp).await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    for pair in devise_rust_actix::test_helpers::set_cookie_pairs(&resp) {
        if pair.starts_with("id=") {
            jar.insert("session", pair);
        }
    }

    // BOTH scopes are gone (the registry defines the mapping set).
    let resp = test::TestRequest::get()
        .uri("/users_status")
        .insert_header(("cookie", jar.get("session").cloned().unwrap_or_default()))
        .to_request();
    let body: serde_json::Value = test::read_body_json(test::call_service(&app, resp).await).await;
    assert_eq!(body["user"], false, "user signed out: {body}");
    assert_eq!(
        body["admin"], false,
        "admin must be signed out too (S2): {body}"
    );
}

/// M (`verify_signed_out_user)`: Devise checks `all_signed_out?` over EVERY
/// mapping (`sessions_controller.rb:67-69`) — `already_signed_out` only
/// fires when NO scope is signed in. The controller probed only the
/// requesting scope, so a session signed in as ADMIN got
/// `already_signed_out` for a user sign-out — and the sign-out never ran.
#[actix_web::test]
async fn m_verify_signed_out_user_iterates_all_scopes() {
    let (_user_state, _admin_state, app) = two_scope_app().await;

    // Sign in ONLY the admin scope.
    let mut jar = std::collections::HashMap::new();
    let resp = test::TestRequest::get()
        .uri("/devise-test/admin-sign-in")
        .to_request();
    let resp = test::call_service(&app, resp).await;
    assert!(resp.status().is_success());
    let cookies = devise_rust_actix::test_helpers::set_cookie_pairs(&resp);
    let session_cookie = cookies
        .iter()
        .find(|c| c.starts_with("id="))
        .expect("session cookie")
        .clone();
    jar.insert("session", session_cookie);

    let resp = test::TestRequest::get()
        .uri("/users_status")
        .insert_header(("cookie", jar.get("session").cloned().unwrap_or_default()))
        .to_request();
    let body: serde_json::Value = test::read_body_json(test::call_service(&app, resp).await).await;
    assert_eq!(body["user"], false, "user never signed in: {body}");
    assert_eq!(body["admin"], true, "admin signed in: {body}");

    // DELETE /users/sign_out: the user scope is anonymous but ADMIN is
    // signed in — not `all_signed_out?`, so Devise PROCEEDS with the
    // sign-out (which, with sign_out_all_scopes, clears admin too).
    let resp = test::TestRequest::delete()
        .uri("/users/sign_out")
        .insert_header(("cookie", jar.get("session").cloned().unwrap_or_default()))
        .to_request();
    let resp = test::call_service(&app, resp).await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let cookies = devise_rust_actix::test_helpers::set_cookie_pairs(&resp);
    assert!(
        !cookies
            .iter()
            .any(|c| c.starts_with("devise.flash=already_signed_out")),
        "a signed-in admin means NOT all signed out: {cookies:?}"
    );
    for pair in cookies {
        if pair.starts_with("id=") {
            jar.insert("session", pair);
        }
    }

    let resp = test::TestRequest::get()
        .uri("/users_status")
        .insert_header(("cookie", jar.get("session").cloned().unwrap_or_default()))
        .to_request();
    let body: serde_json::Value = test::read_body_json(test::call_service(&app, resp).await).await;
    assert_eq!(body["admin"], false, "admin was signed out: {body}");
}

// ===========================================================================
// S6 — models without an encrypted_password keep their session (S6)
// ===========================================================================

/// Bridge sign-in route over query params (the IntegrationHelpers-style
/// transport for tests that need an exact `[key, salt]` payload).
async fn bridge_sign_in_query(
    session: actix_session::Session,
    query: actix_web::web::Query<std::collections::HashMap<String, String>>,
) -> actix_web::HttpResponse {
    let key: devise_rust::adapter::DeviseKey = query
        .get("key")
        .cloned()
        .unwrap_or_default()
        .parse()
        .expect("key parses");
    let salt = query.get("salt").cloned().unwrap_or_default();
    devise_rust_actix::test_helpers::sign_in(&session, "user", &key, &salt)
        .await
        .expect("bridge sign-in");
    actix_web::HttpResponse::Ok().finish()
}

/// S6: Devise's session serializer stores `authenticatable_salt` as an
/// EMPTY string when the model has no password (omniauth-only rows) and the
/// fetch compares it against the record's own empty salt — the user stays
/// signed in. The actix reader propagated `None` from `authenticatable_salt()`
/// and refused to resolve the session on EVERY request, logging
/// omniauth-created users out continuously.
#[actix_web::test]
async fn s6_empty_salt_record_stays_signed_in() {
    let (state, app) = common::build_app_with(
        common::test_state(common::default_mapping()),
        vec![(
            "/devise-test/bridge-sign-in",
            actix_web::web::get().to(bridge_sign_in_query),
        )],
    )
    .await;

    // An omniauth-only row: no encrypted_password at all.
    let mut oauth_user = FixtureUser {
        email: "s6-oauth@example.com".to_string(),
        confirmed_at: Some(<SystemClock as devise_rust::time::Clock>::now(&SystemClock)),
        ..FixtureUser::default()
    };
    oauth_user.provider = Some("stub".to_string());
    oauth_user.uid = Some("s6-uid".to_string());
    let created = state.adapter.create(oauth_user).await.expect("seed");
    assert!(
        created.encrypted_password.is_empty(),
        "omniauth-only fixture carries no password digest"
    );

    // Insert the session payload the way every sign-in path does
    // (`session_pair` already defaults the salt to "").
    let (key, salt) = devise_rust::failure::AnyDeviseModel::session_pair(&created);
    assert_eq!(salt, "", "empty password serializes to an empty salt");
    let resp = test::TestRequest::get()
        .uri(&format!(
            "/devise-test/bridge-sign-in?key={key}&salt={salt}"
        ))
        .to_request();
    let resp = test::call_service(&app, resp).await;
    assert!(resp.status().is_success());
    let cookies = devise_rust_actix::test_helpers::set_cookie_pairs(&resp);
    let session_cookie = cookies
        .iter()
        .find(|c| c.starts_with("id="))
        .expect("session cookie")
        .clone();

    // The middleware fetch must resolve the empty-salt session (S6).
    let resp = test::TestRequest::get()
        .uri("/users_dashboard")
        .insert_header(("cookie", session_cookie))
        .to_request();
    let resp = test::call_service(&app, resp).await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "an empty-salt (omniauth-only) session must resolve, not log out every request"
    );
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["email"], "s6-oauth@example.com");
}

// ===========================================================================
// M — after_sign_in_path_for precedence + full path+query storage
// ===========================================================================

/// M (`after_sign_in_path_for)`: Devise's precedence is stored location →
/// scope root (`signed_in_root_path`) → `/` (`helpers.rb`). The controller
/// kept a reduced local copy that always fell back to `/`, so a plain
/// sign-in landed on the app root instead of the scope's root.
#[actix_web::test]
async fn m_plain_sign_in_lands_on_scope_root() {
    let (state, app) = common::build_app(common::test_state(common::default_mapping())).await;
    let user = FixtureUser::new_with_password("m-root@example.com", "secret123", &state.config)
        .confirmed_now(&SystemClock);
    state.adapter.create(user).await.expect("seed");

    let resp = test::TestRequest::post()
        .uri("/users/sign_in")
        .insert_header(("content-type", "application/x-www-form-urlencoded"))
        .insert_header(("accept", "text/html"))
        .set_payload("email=m-root%40example.com&password=secret123")
        .to_request();
    let resp = test::call_service(&app, resp).await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let location = resp
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    assert_eq!(
        location.as_deref(),
        Some("/users"),
        "no stored location → the scope root (Devise after_sign_in_path_for): {location:?}"
    );
}

/// M (`store_location)`: Devise stores the FULL request path including the
/// query string (`request.fullpath`); the extractor stored the bare path,
/// so a sign-in round trip lost `?tab=…` and friends.
#[actix_web::test]
async fn m_stored_location_keeps_query_string() {
    let (state, app) = common::build_app(common::test_state(common::default_mapping())).await;
    let user = FixtureUser::new_with_password("m-query@example.com", "secret123", &state.config)
        .confirmed_now(&SystemClock);
    state.adapter.create(user).await.expect("seed");

    // Unauthenticated navigational GET with a query → stored verbatim.
    let resp = test::TestRequest::get()
        .uri("/users_dashboard?tab=secret&page=2")
        .insert_header(("accept", "text/html"))
        .to_request();
    let resp = test::call_service(&app, resp).await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let cookies = devise_rust_actix::test_helpers::set_cookie_pairs(&resp);
    let session_cookie = cookies
        .iter()
        .find(|c| c.starts_with("id="))
        .expect("session cookie")
        .clone();

    // Sign in on the same session: the stored location (with query) wins.
    let resp = test::TestRequest::post()
        .uri("/users/sign_in")
        .insert_header(("content-type", "application/x-www-form-urlencoded"))
        .insert_header(("accept", "text/html"))
        .insert_header(("cookie", session_cookie))
        .set_payload("email=m-query%40example.com&password=secret123")
        .to_request();
    let resp = test::call_service(&app, resp).await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let location = resp
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    assert!(
        location
            .as_deref()
            .is_some_and(|loc| loc.starts_with("/users_dashboard?")
                && loc.contains("tab=secret")
                && loc.contains("page=2")),
        "stored location must keep the query string: {location:?}"
    );
}

// ===========================================================================
// S11 — the flash rides the signed session, read-once; one key format
// ===========================================================================

/// S11: Devise's flash is SESSION state (Rails' flash hash), read once and
/// cleared on read. The old transport was an unsigned, never-cleared
/// `devise.flash` cookie — client-forgeable text rendered by the app
/// (spoofing channel) and sticky across requests. The ported contract:
/// `bridge::set_flash` stages the I18n KEY in the session (signed by the
/// actix-session cookie, Secure per the app's session configuration), and
/// `bridge::take_flash` reads it ONCE.
#[actix_web::test]
async fn s11_flash_reads_once_then_clears() {
    let (state, app) = common::build_app(common::test_state(common::default_mapping())).await;
    let user = FixtureUser::new_with_password("s11@example.com", "secret123", &state.config)
        .confirmed_now(&SystemClock);
    state.adapter.create(user).await.expect("seed");

    let resp = test::TestRequest::post()
        .uri("/users/sign_in")
        .insert_header(("content-type", "application/x-www-form-urlencoded"))
        .insert_header(("accept", "text/html"))
        .set_payload("email=s11%40example.com&password=secret123")
        .to_request();
    let resp = test::call_service(&app, resp).await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let cookies = devise_rust_actix::test_helpers::set_cookie_pairs(&resp);
    let session_cookie = cookies
        .iter()
        .find(|c| c.starts_with("id="))
        .expect("session cookie")
        .clone();

    // First read returns the key and clears it (read-once).
    assert_eq!(
        common::flash_of(&app, session_cookie.as_str())
            .await
            .as_deref(),
        Some("signed_in"),
        "the flash key must be readable once"
    );
    // The response cookie (flash consumed) replayed: nothing left.
    let resp = test::TestRequest::get()
        .uri("/devise-test/flash")
        .insert_header(("cookie", session_cookie.as_str()))
        .to_request();
    let resp = test::call_service(&app, resp).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let fresh = devise_rust_actix::test_helpers::set_cookie_pairs(&resp)
        .into_iter()
        .find(|c| c.starts_with("id="))
        .unwrap_or(session_cookie.clone());
    assert_eq!(
        common::flash_of(&app, &fresh).await,
        None,
        "the flash must be cleared after the first read"
    );
}

/// S11: a tampered flash value is rejected outright. The session cookie is
/// signature-verified by `SessionMiddleware`, so any tampering invalidates
/// the whole session — the flash (like every session payload) reads back
/// empty instead of rendering attacker-chosen text.
#[actix_web::test]
async fn s11_tampered_flash_is_rejected() {
    let (state, app) = common::build_app(common::test_state(common::default_mapping())).await;
    let user = FixtureUser::new_with_password("s11b@example.com", "secret123", &state.config)
        .confirmed_now(&SystemClock);
    state.adapter.create(user).await.expect("seed");

    let resp = test::TestRequest::post()
        .uri("/users/sign_in")
        .insert_header(("content-type", "application/x-www-form-urlencoded"))
        .insert_header(("accept", "text/html"))
        .set_payload("email=s11b%40example.com&password=secret123")
        .to_request();
    let resp = test::call_service(&app, resp).await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let cookies = devise_rust_actix::test_helpers::set_cookie_pairs(&resp);
    let session_cookie = cookies
        .iter()
        .find(|c| c.starts_with("id="))
        .expect("session cookie")
        .clone();

    // Tamper: flip a byte in the signed session cookie.
    let mut chars: Vec<char> = session_cookie.chars().collect();
    let tail = chars.len().saturating_sub(6);
    chars[tail] = if chars[tail] == 'A' { 'B' } else { 'A' };
    let tampered: String = chars.into_iter().collect();

    assert_eq!(
        common::flash_of(&app, tampered.as_str()).await,
        None,
        "a tampered flash carrier must read back empty, never attacker text"
    );
}

/// M (flash format): one key format everywhere. The omniauth callbacks
/// previously wrote RENDERED sentences ("Successfully authenticated from
/// Stub account.") into the same slot the controllers fill with bare I18n
/// keys (`signed_in`, `invalid`, …) — two incompatible formats. The omniauth
/// flash now carries the bare `devise.omniauth_callbacks.*` key the app
/// translates through the same catalog.
#[actix_web::test]
async fn m_omniauth_flash_carries_bare_key() {
    let config = common::omniauth_test_config(&["stub"]);
    let mapping = common::omniauth_mapping();
    let providers = std::collections::HashMap::from([(
        "stub".to_string(),
        devise_rust::omniauthable::OAuthProviderConfig {
            client_id: "stub-client-id".to_string(),
            client_secret: "stub-secret".to_string(),
            auth_url: "http://127.0.0.1:1/authorize".to_string(),
            token_url: "http://127.0.0.1:1/token".to_string(),
            userinfo_url: "http://127.0.0.1:1/userinfo".to_string(),
            scopes: vec!["openid".to_string()],
        },
    )]);
    let (_state, app) = common::build_omniauth_service(mapping, config, providers).await;

    // Start an authorize attempt (stashes state + verifier), then deliver
    // a callback carrying a MISMATCHED state — the failure path.
    let resp = test::TestRequest::post()
        .uri("/users/auth/stub")
        .insert_header(("host", "app.test"))
        .to_request();
    let resp = test::call_service(&app, resp).await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let cookies = devise_rust_actix::test_helpers::set_cookie_pairs(&resp);
    let session_cookie = cookies
        .iter()
        .find(|c| c.starts_with("id=") || c.starts_with("actix-session="))
        .expect("session cookie")
        .clone();

    let resp = test::TestRequest::get()
        .uri("/users/auth/stub/callback?code=x&state=tampered")
        .insert_header(("host", "app.test"))
        .insert_header(("cookie", session_cookie.as_str()))
        .to_request();
    let resp = test::call_service(&app, resp).await;
    assert_eq!(resp.status(), StatusCode::FOUND);

    let mut all_cookies = session_cookie;
    for pair in devise_rust_actix::test_helpers::set_cookie_pairs(&resp) {
        if pair.starts_with("id=") || pair.starts_with("actix-session=") {
            all_cookies = pair;
        }
    }
    let flash = common::flash_of(&app, &all_cookies).await;
    assert_eq!(
        flash.as_deref(),
        Some("devise.omniauth_callbacks.failure"),
        "omniauth failure flash must be the bare I18n key: {flash:?}"
    );
}

// ===========================================================================
// M — no silently-inert session store surface
// ===========================================================================

/// M (inert store): the public `ActixSessionStore` satisfied the core
/// `SessionStore` trait with no-op bodies — `insert_value` stored nothing
/// and `get_value` always read `None` — so any caller wiring it into core
/// machinery (`AuthProxy`) got a silently broken session. There is no
/// faithful implementation over actix's `!Send` `Session` handle, so the
/// fix REMOVES the store surface entirely: `DeviseMiddleware::new` takes no
/// store argument and nothing can construct the inert type. This test pins
/// the constructor shape (it compiled against the 3-argument version
/// before the fix — the removed parameter is the removed defect).
#[actix_web::test]
async fn m_no_silently_inert_session_store_surface() {
    let registry = common::registry_with(common::default_mapping());
    let middleware =
        devise_rust_actix::DeviseMiddleware::new(registry, Arc::new(common::test_config()));
    let _ = middleware;
}

// ===========================================================================
// Boot — empty secret_key fails at construction (Devise raise_no_secret_key)
// ===========================================================================

/// Devise refuses to boot without a `secret_key` (`raise_no_secret_key`):
/// the key HMACs every token digest, so an empty key makes every
/// reset/confirmation/unlock token forgeable. The middleware constructor
/// (the actix boot point) must fail with the same raise semantics, not
/// construct silently and forge tokens later.
#[actix_web::test]
#[should_panic(expected = "secret_key")]
async fn m_empty_secret_key_fails_at_middleware_boot() {
    let config = DeviseConfig::default();
    assert!(
        config.secret_key.trim().is_empty(),
        "fixture: default config carries no secret"
    );
    let _middleware = devise_rust_actix::DeviseMiddleware::new(
        common::registry_with(common::default_mapping()),
        Arc::new(config),
    );
}

// ===========================================================================
// L — the registered surface IS the core config-aware route table
// ===========================================================================

/// L: `devise_for_users` must register EXACTLY what
/// `Mapping::route_specs_for(&config)` emits — the core table owns the
/// `only`/`skip`/`path_names`/`sign_out_via` filters AND the unlock-strategy
/// guard. The registration previously re-implemented the unlock guard
/// locally; this pin runs under a non-default unlock strategy so the
/// config-aware path (not the config-free ceiling) is what's asserted.
/// (Behavior-preserving refactor: green before AND after the fix — the
/// local guard and the core guard agree on this table.)
#[actix_web::test]
async fn l_registered_routes_match_core_config_aware_specs() {
    let mut config = common::test_config();
    config.unlock_strategy = "time".to_string(); // unlock routes drop
    let mapping = common::default_mapping();
    let expected: Vec<(String, String)> = mapping
        .route_specs_for(&config)
        .iter()
        .map(|s| (s.method.clone(), s.path.clone()))
        .collect();
    assert!(
        expected.iter().all(|(_, path)| !path.contains("unlock")),
        "fixture: the config-aware table drops unlock routes"
    );
    let (_state, app) = common::build_app(common::test_state_with_config(mapping, config)).await;

    for (method, path) in &expected {
        let req = test::TestRequest::default()
            .method(method.parse().expect("method parses"))
            .uri(path)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_ne!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "spec {method} {path} must be registered"
        );
    }
}
