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
    extractors::{Auth, RequireAuth},
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

    #[allow(dead_code)] // used by Task 2 multi-scope tests
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
                .route("/devise-test/sign-in", web::get().to(bridge_sign_in)),
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
