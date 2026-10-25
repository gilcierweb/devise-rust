//! Extractor + guard tests (08-02): `Auth` / `RequireAuth` behaviour, the
//! D-09 302/401 split, per-scope helpers and group support, the remember
//! `SignedJar` transport, and the `IntegrationHelpers`-parity bypass helpers.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::expect_used)]

use std::collections::HashMap;
use std::sync::Arc;

use actix_session::{Session, SessionMiddleware, storage::CookieSessionStore};
use actix_web::http::header;
use actix_web::{App, HttpMessage, HttpRequest, HttpResponse, test, web};
use devise_rust::adapter::memory::MemoryAdapter;
use devise_rust::adapter::{DeviseKey, OrmAdapter};
use devise_rust::config::DeviseConfig;
use devise_rust::failure::AnyDeviseModel;
use devise_rust::model::AdapterBridge;
use devise_rust::scope::{Mapping, Module, PathNames, ScopeRegistry, SignOutVia};
use devise_rust_actix::{
    ActixSessionStore, DeviseMiddleware,
    extractors::{
        Auth, AuthGroup, RequireAuth, admin_signed_in, authenticate_group, current_admin,
        current_user, group_signed_in, user_session, user_signed_in,
    },
};

/// User fixture for the `user` scope.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct AuthUser {
    id: i64,
    email: String,
    encrypted_password: String,
}

impl AnyDeviseModel for AuthUser {
    fn to_key(&self) -> DeviseKey {
        DeviseKey::from_i64(self.id)
    }

    fn authenticatable_salt(&self) -> Option<String> {
        self.encrypted_password.get(..29).map(str::to_string)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Admin fixture for the `admin` scope (distinct type).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct AdminUser {
    id: i64,
    email: String,
    encrypted_password: String,
}

impl AnyDeviseModel for AdminUser {
    fn to_key(&self) -> DeviseKey {
        DeviseKey::from_i64(self.id)
    }

    fn authenticatable_salt(&self) -> Option<String> {
        self.encrypted_password.get(..29).map(str::to_string)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Test config: 32-byte secret, `stretches = 4`, html-only navigational
/// formats so `Accept: application/json` exercises the D-09 401 branch.
fn extractor_config() -> DeviseConfig {
    DeviseConfig {
        secret_key: "0123456789abcdef0123456789abcdef".to_string(),
        stretches: 4,
        navigational_formats: vec!["html".to_string()],
        ..DeviseConfig::default()
    }
}

fn mapping(name: &str, path: &str) -> Mapping {
    Mapping {
        name: name.to_string(),
        class_name: name.to_string(),
        path: path.to_string(),
        path_prefix: None,
        singular: name.to_string(),
        path_names: PathNames::default(),
        controllers: HashMap::new(),
        modules: vec![Module::DatabaseAuthenticatable],
        only: vec![],
        skip: vec![],
        constraints: HashMap::new(),
        defaults: HashMap::new(),
        format: None,
        router_name: None,
        sign_out_via: SignOutVia::Delete,
        failure_app: None,
    }
}

/// Shared app state: adapters behind `Arc`s so the test and the handlers
/// observe the same storage (`MemoryAdapter` shares its `Arc<RwLock>` store).
struct TestAppState {
    config: DeviseConfig,
    scope_registry: Arc<ScopeRegistry>,
    user_adapter: MemoryAdapter<AuthUser>,
    admin_adapter: MemoryAdapter<AdminUser>,
}

impl TestAppState {
    fn new() -> Self {
        let config = extractor_config();
        let mut registry = ScopeRegistry::new();
        registry.register(mapping("user", "users"));
        registry.register(mapping("admin", "admins"));
        Self {
            config,
            scope_registry: Arc::new(registry),
            user_adapter: MemoryAdapter::new(),
            admin_adapter: MemoryAdapter::new(),
        }
    }

    async fn seed_user(&self, id: i64, email: &str) -> AuthUser {
        let user = AuthUser {
            id,
            email: email.to_string(),
            encrypted_password: "$2a$04$abcdefghijklmnopqrstuu01234".to_string(),
        };
        self.user_adapter
            .create(user.clone())
            .await
            .expect("seed user");
        user
    }

    async fn seed_admin(&self, id: i64, email: &str) -> AdminUser {
        let admin = AdminUser {
            id,
            email: email.to_string(),
            encrypted_password: "$2a$04$abcdefghijklmnopqrstuu56789".to_string(),
        };
        self.admin_adapter
            .create(admin.clone())
            .await
            .expect("seed admin");
        admin
    }
}

/// Protected route guarded by `RequireAuth` over the `user` scope.
async fn protected_user(auth: RequireAuth<AuthUser>) -> HttpResponse {
    let user = auth.user().cloned().expect("typed user present");
    HttpResponse::Ok().json(user)
}

/// Soft route: `Auth` never fails; it reports the authentication state.
async fn soft_user(auth: Auth<AuthUser>) -> HttpResponse {
    HttpResponse::Ok().json(auth.is_authenticated())
}

/// Reports the staged `AuthRequest.peer_addr` (D-11 socket-only source).
async fn peer_probe(req: HttpRequest) -> HttpResponse {
    let peer = req
        .extensions()
        .get::<devise_rust::request::AuthRequest>()
        .and_then(|r| r.peer_addr.clone());
    HttpResponse::Ok().json(peer)
}

/// Sign a user in via the session bridge (Task 1 slice) for cookie replay.
async fn bridge_sign_in(session: Session, state: web::Data<Arc<TestAppState>>) -> HttpResponse {
    let user = state
        .user_adapter
        .get(&DeviseKey::from_i64(1))
        .await
        .expect("lookup")
        .expect("user present");
    let (key, salt) = user.session_pair();
    devise_rust_actix::bridge::insert_session_and_renew_sync(&session, "user", &key, &salt)
        .expect("insert");
    HttpResponse::Ok().finish()
}

/// Sign an admin in via the session bridge (Task 2 multi-scope slice).
async fn bridge_sign_in_admin(
    session: Session,
    state: web::Data<Arc<TestAppState>>,
) -> HttpResponse {
    let admin = state
        .admin_adapter
        .get(&DeviseKey::from_i64(1))
        .await
        .expect("lookup")
        .expect("admin present");
    let (key, salt) = admin.session_pair();
    devise_rust_actix::bridge::insert_session_and_renew_sync(&session, "admin", &key, &salt)
        .expect("insert");
    HttpResponse::Ok().finish()
}

/// Sign the `user` scope out while leaving other scopes untouched (D-10
/// multi-scope independence).
async fn bridge_sign_out_user(session: Session) -> HttpResponse {
    devise_rust_actix::bridge::sign_out_and_renew(&session, "user").expect("sign out");
    HttpResponse::Ok().finish()
}

/// Multi-scope status route: reads `user` + `admin` plus the group helper
/// results in one handler (D-10).
async fn multi_scope_status(req: HttpRequest) -> HttpResponse {
    let group = AuthGroup::new("any", &["user", "admin"]);
    let group_scopes = authenticate_group(&req, &group).unwrap_or_default();
    HttpResponse::Ok().json(serde_json::json!({
        "user_signed_in": user_signed_in(&req),
        "admin_signed_in": admin_signed_in(&req),
        "current_user": current_user::<AuthUser>(&req).map(|u| u.email),
        "current_admin": current_admin::<AdminUser>(&req).map(|a| a.email),
        "user_session": user_session(&req).is_some(),
        "group_signed_in": group_signed_in(&req, &group),
        "group_scopes": group_scopes,
    }))
}

/// Build the full test app inside the caller's async block (the service
/// type is intentionally left opaque to `actix_web::test`).
macro_rules! test_app {
    ($state:expr) => {{
        let state: Arc<TestAppState> = $state;
        let key = devise_rust_actix::callbacks::derive_actix_key(&state.config.secret_key)
            .expect("derive key");
        let store: Arc<dyn devise_rust::session::SessionStore> =
            Arc::new(ActixSessionStore::new(key.clone()));
        let middleware = DeviseMiddleware::new(
            store,
            state.scope_registry.clone(),
            Arc::new(state.config.clone()),
        )
        .with_finder(
            "user",
            Arc::new(AdapterBridge::new(state.user_adapter.clone())),
        )
        .with_finder(
            "admin",
            Arc::new(AdapterBridge::new(state.admin_adapter.clone())),
        );
        test::init_service(
            App::new()
                .wrap(middleware)
                .wrap(
                    SessionMiddleware::builder(CookieSessionStore::default(), key)
                        .cookie_secure(false)
                        .build(),
                )
                .app_data(web::Data::new(state.clone()))
                .route("/users/private", web::get().to(protected_user))
                .route("/users/soft", web::get().to(soft_user))
                .route("/users/peer", web::get().to(peer_probe))
                .route("/users/status", web::get().to(multi_scope_status))
                .route("/devise-test/sign-in", web::get().to(bridge_sign_in))
                .route(
                    "/devise-test/admin-sign-in",
                    web::get().to(bridge_sign_in_admin),
                )
                .route(
                    "/devise-test/sign-out-user",
                    web::get().to(bridge_sign_out_user),
                ),
        )
        .await
    }};
}

/// Extract `name=value` pairs from a response's `Set-Cookie` headers.
fn set_cookie_pairs(resp: &actix_web::dev::ServiceResponse) -> Vec<String> {
    resp.headers()
        .get_all(header::SET_COOKIE)
        .filter_map(|v| v.to_str().ok())
        .filter_map(|v| v.split(';').next())
        .map(str::to_string)
        .collect()
}

#[actix_web::test]
async fn anonymous_html_redirects_with_flash() {
    let state = Arc::new(TestAppState::new());
    let app = test_app!(state.clone());

    let req = test::TestRequest::get()
        .uri("/users/private")
        .insert_header((header::ACCEPT, "text/html"))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), actix_web::http::StatusCode::FOUND);
    let location = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert_eq!(location, "/users/sign_in");
    let flash = resp
        .headers()
        .get_all(header::SET_COOKIE)
        .filter_map(|v| v.to_str().ok())
        .map(str::to_string)
        .find(|c| c.starts_with("devise.flash="))
        .expect("flash cookie present");
    assert!(flash.contains("unauthenticated"), "flash key: {flash}");

    // Soft extractor on the same stack stays anonymous.
    let req = test::TestRequest::get().uri("/users/soft").to_request();
    let resp = test::call_service(&app, req).await;
    let authed: bool = test::read_body_json(resp).await;
    assert!(!authed);
}

#[actix_web::test]
async fn anonymous_json_is_unauthorized() {
    let state = Arc::new(TestAppState::new());
    let app = test_app!(state.clone());

    let req = test::TestRequest::get()
        .uri("/users/private")
        .insert_header((header::ACCEPT, "application/json"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), actix_web::http::StatusCode::UNAUTHORIZED);
    assert!(resp.headers().get(header::LOCATION).is_none());
}

/// Sign in through the bridge, replay the session cookie, and expect the
/// `RequireAuth` route to render the resolved user 200 (Task 1 acceptance).
#[actix_web::test]
async fn signed_in_user_reads_record_via_require_auth() {
    let state = Arc::new(TestAppState::new());
    state.seed_user(1, "user@example.com").await;
    let app = test_app!(state.clone());

    let req = test::TestRequest::get()
        .uri("/devise-test/sign-in")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    let cookies = set_cookie_pairs(&resp);
    assert!(!cookies.is_empty(), "session Set-Cookie captured");

    let req = test::TestRequest::get()
        .uri("/users/private")
        .insert_header((header::COOKIE, cookies.join("; ")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
    let user: AuthUser = test::read_body_json(resp).await;
    assert_eq!(user.email, "user@example.com");

    // D-11: the staged AuthRequest reports the socket peer address.
    let req = test::TestRequest::get()
        .uri("/users/peer")
        .peer_addr("192.0.2.44:8080".parse().expect("addr"))
        .insert_header((header::COOKIE, cookies.join("; ")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let peer: Option<String> = test::read_body_json(resp).await;
    // ConnectionInfo::peer_addr() yields the socket IP (port stripped).
    assert_eq!(peer.as_deref(), Some("192.0.2.44"));
}

/// D-10: `user` and `admin` authenticate simultaneously and independently;
/// signing out `user` leaves `admin` signed in; the group helper succeeds
/// when either scope is present.
#[actix_web::test]
async fn multi_scope_independence_and_group() {
    let state = Arc::new(TestAppState::new());
    state.seed_user(1, "user@example.com").await;
    state.seed_admin(1, "admin@example.com").await;
    let app = test_app!(state.clone());

    // Sign in BOTH scopes on the same session cookie jar.
    let req = test::TestRequest::get()
        .uri("/devise-test/sign-in")
        .to_request();
    let resp = test::call_service(&app, req).await;
    let cookies = set_cookie_pairs(&resp);
    let req = test::TestRequest::get()
        .uri("/devise-test/admin-sign-in")
        .insert_header((header::COOKIE, cookies.join("; ")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let cookies = set_cookie_pairs(&resp);
    assert_ne!(cookies.len(), 0);

    let body: serde_json::Value = {
        let req = test::TestRequest::get()
            .uri("/users/status")
            .insert_header((header::COOKIE, cookies.join("; ")))
            .to_request();
        let resp = test::call_service(&app, req).await;
        test::read_body_json(resp).await
    };
    assert_eq!(body["user_signed_in"], true);
    assert_eq!(body["admin_signed_in"], true);
    assert_eq!(body["current_user"], "user@example.com");
    assert_eq!(body["current_admin"], "admin@example.com");
    assert_eq!(body["user_session"], true);
    assert_eq!(body["group_signed_in"], true);
    assert_eq!(body["group_scopes"], serde_json::json!(["user", "admin"]));

    // Sign out the user scope only: admin stays signed in (SESS-07 parity).
    let req = test::TestRequest::get()
        .uri("/devise-test/sign-out-user")
        .insert_header((header::COOKIE, cookies.join("; ")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let cookies = set_cookie_pairs(&resp);

    let body: serde_json::Value = {
        let req = test::TestRequest::get()
            .uri("/users/status")
            .insert_header((header::COOKIE, cookies.join("; ")))
            .to_request();
        let resp = test::call_service(&app, req).await;
        test::read_body_json(resp).await
    };
    assert_eq!(body["user_signed_in"], false);
    assert_eq!(body["admin_signed_in"], true);
    assert_eq!(body["current_user"], serde_json::Value::Null);
    assert_eq!(body["current_admin"], "admin@example.com");
    // Group still succeeds with admin alone.
    assert_eq!(body["group_signed_in"], true);
    assert_eq!(body["group_scopes"], serde_json::json!(["admin"]));
}

// ---------------------------------------------------------------------------
// Task 3: remember-cookie SignedJar transport + bypass test helpers
// ---------------------------------------------------------------------------

use devise_rust::rememberable::{RememberCookieOp, encode_cookie_value};
use devise_rust::time::{Clock, SystemClock};
use devise_rust_actix::remember as actix_remember;

/// Build the remember `Set` op exactly as the core hook would push it:
/// hardened attrs from `for_scope` over an encoded core codec triple.
fn remember_set_op(config: &DeviseConfig) -> RememberCookieOp {
    let clock = SystemClock;
    let attrs = actix_remember::attrs_for_scope("user", config, &clock);
    let value = encode_cookie_value("1", "raw-token", &clock.now().timestamp().to_string());
    RememberCookieOp::Set {
        scope: "user".to_string(),
        key: attrs.key.clone(),
        value,
        attrs,
    }
}

#[actix_web::test]
async fn remember_set_cookie_carries_hardened_attrs_and_codec() {
    let config = extractor_config();
    let key = actix_remember::derive_remember_key(&config).expect("derive");
    let op = remember_set_op(&config);

    // Sign into a jar and render the delta (what Set-Cookie would carry).
    let mut jar = actix_web::cookie::CookieJar::new();
    {
        let mut signed = jar.signed_mut(&key);
        actix_remember::apply_op(&mut signed, &op);
    }
    let rendered: Vec<String> = jar.delta().map(ToString::to_string).collect();
    assert_eq!(rendered.len(), 1, "one cookie delta");
    let header = &rendered[0];

    // D-16 hardened attributes on the wire.
    assert!(header.starts_with("remember_user_token="), "name: {header}");
    assert!(header.contains("HttpOnly"), "{header}");
    assert!(header.contains("Secure"), "{header}");
    assert!(header.contains("SameSite=Lax"), "{header}");
    assert!(header.contains("Expires="), "{header}");

    // Expires equals now + remember_for (fixed window, D-13).
    let clock = devise_rust::time::SystemClock;
    let attrs =
        devise_rust::rememberable::RememberableCookieAttrs::for_scope("user", &config, &clock);
    let expected = attrs
        .expires
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string();
    assert!(
        header.contains(&expected) || {
            // Cookie values are signed+url-encoded; expires is rendered via
            // the cookie crate from seconds, so compare within one second.
            let earlier = (attrs.expires - chrono::TimeDelta::seconds(1))
                .format("%a, %d %b %Y %H:%M:%S GMT")
                .to_string();
            header.contains(&earlier)
        },
        "expires ~= now + remember_for in {header}"
    );

    // Round-trip: a fresh jar over the same key verifies the signature and
    // exposes the core codec triple.
    let mut jar = actix_web::cookie::CookieJar::new();
    let signed_value = {
        let mut signed = jar.signed_mut(&key);
        actix_remember::apply_op(&mut signed, &op);
        let Some(cookie) = jar.delta().next() else {
            panic!("delta cookie");
        };
        cookie.value().to_string()
    };
    let mut read_jar = actix_web::cookie::CookieJar::new();
    read_jar.add_original(actix_web::cookie::Cookie::new(
        "remember_user_token".to_string(),
        signed_value,
    ));
    let read_signed = read_jar.signed(&key);
    match actix_remember::read_cookie(&read_signed, "remember_user_token") {
        actix_remember::RememberRead::Valid {
            key,
            value,
            generated_at,
        } => {
            assert_eq!(key, "1");
            assert_eq!(value, "raw-token");
            assert!(generated_at.parse::<i64>().is_ok(), "integer epoch");
        }
        other => panic!("expected Valid, got {other:?}"),
    }
}

#[actix_web::test]
async fn stale_signed_cookie_yields_clear_and_pass_through() {
    let config = extractor_config();
    let key = actix_remember::derive_remember_key(&config).expect("derive");

    // Properly SIGNED garbage value: signature verifies, codec rejects.
    let mut jar = actix_web::cookie::CookieJar::new();
    let signed_value = {
        let mut signed = jar.signed_mut(&key);
        signed.add(actix_web::cookie::Cookie::new(
            "remember_user_token".to_string(),
            "not-a-triple".to_string(),
        ));
        jar.delta().next().expect("delta").value().to_string()
    };
    let mut read_jar = actix_web::cookie::CookieJar::new();
    read_jar.add_original(actix_web::cookie::Cookie::new(
        "remember_user_token".to_string(),
        signed_value,
    ));
    let read_signed = read_jar.signed(&key);

    assert_eq!(
        actix_remember::read_cookie(&read_signed, "remember_user_token"),
        actix_remember::RememberRead::Stale
    );

    // Stale decodes to a Clear op (drop-clear + pass-through, never Failure).
    let clear = actix_remember::resolve_inbound(&read_signed, "user", &config)
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

    // Applying the clear renders a tombstone cookie.
    let mut out_jar = actix_web::cookie::CookieJar::new();
    {
        let mut signed = out_jar.signed_mut(&key);
        actix_remember::apply_op(&mut signed, clear.as_ref());
    }
    let tombstone = out_jar.delta().next().expect("tombstone").to_string();
    assert!(tombstone.starts_with("remember_user_token="), "{tombstone}");
    // cookie 0.16 `make_removal` renders Max-Age=0 + immediate Expires.
    assert!(tombstone.contains("Max-Age=0"), "tombstone: {tombstone}");
}

#[actix_web::test]
async fn secure_opt_out_renders_no_secure_attribute() {
    let mut config = extractor_config();
    config
        .rememberable_options
        .insert("secure".to_string(), "false".to_string());
    let op = remember_set_op(&config);
    let RememberCookieOp::Set { attrs, value, .. } = &op else {
        panic!("set op");
    };
    let cookie = actix_remember::cookie_for_set(value, attrs);
    let rendered = cookie.to_string();
    assert!(!rendered.contains("Secure"), "{rendered}");
    assert!(rendered.contains("HttpOnly"), "{rendered}");
    assert!(rendered.contains("SameSite=Lax"), "{rendered}");

    // Key override through rememberable_options.
    let mut keyed = extractor_config();
    keyed
        .rememberable_options
        .insert("key".to_string(), "custom_remember".to_string());
    let clock = SystemClock;
    let attrs = actix_remember::attrs_for_scope("user", &keyed, &clock);
    assert_eq!(attrs.key, "custom_remember");
}

/// D-17: `test_helpers::sign_in` (bypass + renew) replays into the
/// `RequireAuth` route without a password post; `sign_out_with_forget`
/// clears the scope AND emits the remember tombstone.
#[actix_web::test]
async fn bypass_helpers_reach_protected_route_via_cookie_replay() {
    let state = Arc::new(TestAppState::new());
    state.seed_user(1, "bypass@example.com").await;

    let config = state.config.clone();
    let app = test::init_service(
        App::new()
            .wrap(
                SessionMiddleware::builder(
                    CookieSessionStore::default(),
                    devise_rust_actix::callbacks::derive_actix_key(&config.secret_key)
                        .expect("key"),
                )
                .cookie_secure(false)
                .build(),
            )
            .app_data(web::Data::new(state.clone()))
            .route(
                "/devise-test/bypass-sign-in",
                web::get().to(
                    |session: Session, state: web::Data<Arc<TestAppState>>| async move {
                        let user = state
                            .user_adapter
                            .get(&DeviseKey::from_i64(1))
                            .await
                            .expect("lookup")
                            .expect("user present");
                        // IntegrationHelpers parity: bypass_sign_in — the
                        // helper never hashes a password.
                        devise_rust_actix::test_helpers::bypass_sign_in(&session, "user", &user)
                            .await
                            .expect("bypass");
                        HttpResponse::Ok().finish()
                    },
                ),
            )
            .route(
                "/devise-test/bypass-sign-out",
                web::get().to(|session: Session| async move {
                    let config = extractor_config();
                    let op = devise_rust_actix::test_helpers::sign_out_with_forget(
                        &session, "user", &config,
                    )
                    .await
                    .expect("sign out");
                    assert_eq!(op.scope(), "user");
                    assert_eq!(op.key(), "remember_user_token");
                    HttpResponse::Ok().finish()
                }),
            ),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/devise-test/bypass-sign-in")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    let cookies = devise_rust_actix::test_helpers::set_cookie_pairs(&resp);
    assert!(!cookies.is_empty(), "bypass sign-in rotates session cookie");

    // Replay into the FULL middleware stack: RequireAuth must see the user.
    let full = test_app!(state.clone());
    let req = test::TestRequest::get()
        .uri("/users/private")
        .insert_header((
            header::COOKIE,
            devise_rust_actix::test_helpers::cookie_header(&cookies),
        ))
        .to_request();
    let resp = test::call_service(&full, req).await;
    assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
    let user: AuthUser = test::read_body_json(resp).await;
    assert_eq!(user.email, "bypass@example.com");

    // Sign out via the helper: the protected route 302s afterwards.
    let req = test::TestRequest::get()
        .uri("/devise-test/bypass-sign-out")
        .insert_header((
            header::COOKIE,
            devise_rust_actix::test_helpers::cookie_header(&cookies),
        ))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let cookies = devise_rust_actix::test_helpers::set_cookie_pairs(&resp);

    let req = test::TestRequest::get()
        .uri("/users/private")
        .insert_header((
            header::COOKIE,
            devise_rust_actix::test_helpers::cookie_header(&cookies),
        ))
        .insert_header((header::ACCEPT, "text/html"))
        .to_request();
    let resp = test::call_service(&full, req).await;
    assert_eq!(resp.status(), actix_web::http::StatusCode::FOUND);
}
