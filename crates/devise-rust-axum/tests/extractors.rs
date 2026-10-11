//! Extractor + guard tests (AXUM-02): `Auth` / `RequireAuth` behaviour, the
//! 302/401 split, per-scope helpers and `devise_group` multi-scope support
//! over the layer-resolved proxy — all through `tower::ServiceExt::oneshot`
//! with `Set-Cookie` replay (the AXUM-04 harness shape).

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Extension, State};
use axum::http::{Method, Request, StatusCode, header};
use axum::routing::get;
use devise_rust::adapter::{DeviseKey, OrmAdapter, memory::MemoryAdapter};
use devise_rust::config::DeviseConfig;
use devise_rust::failure::AnyDeviseModel;
use devise_rust::helpers::AuthenticateOpts;
use devise_rust::model::{AdapterBridge, PasswordVerifiable};
use devise_rust::request::AuthRequest;
use devise_rust::scope::{Mapping, Module, PathNames, ScopeRegistry, SignOutVia};
use devise_rust_axum::extractors::{
    Auth, AuthGroup, RequireAuth, admin_signed_in, authenticate_group, current_admin, current_user,
    group_signed_in, user_session, user_signed_in,
};
use devise_rust_axum::{AuthProxyHandle, DeviseLayer, session_manager_layer};
use http_body_util::BodyExt;
use tower::ServiceExt;
use tower_sessions::Session;

/// User fixture for the `user` scope (distinct type from the admin fixture,
/// proving typed multi-scope isolation).
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

impl PasswordVerifiable for AuthUser {
    fn valid_password(&self, password: &str, config: &DeviseConfig) -> bool {
        devise_rust::crypto::encryptor::compare(password, &self.encrypted_password, config)
    }
}

/// Admin fixture for the `admin` scope.
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
/// formats so `Accept: application/json` exercises the 401 branch.
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

/// Shared test state: adapters behind `Arc`s so the test side and the
/// handlers observe the same storage (`MemoryAdapter` shares its store).
struct TestAppState {
    config: Arc<DeviseConfig>,
    user_adapter: MemoryAdapter<AuthUser>,
    admin_adapter: MemoryAdapter<AdminUser>,
}

impl TestAppState {
    fn new() -> Self {
        let config = Arc::new(extractor_config());
        Self {
            config,
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
async fn protected_user(auth: RequireAuth<AuthUser>) -> axum::Json<AuthUser> {
    let user = auth.user().cloned().expect("typed user present");
    axum::Json(user)
}

/// Soft route: `Auth` never fails; it reports the authentication state.
async fn soft_user(auth: Auth<AuthUser>) -> axum::Json<bool> {
    axum::Json(auth.is_authenticated())
}

/// Reports the staged `AuthRequest.peer_addr` (D-11 socket-only source).
async fn peer_probe(Extension(request): Extension<AuthRequest>) -> axum::Json<Option<String>> {
    axum::Json(request.peer_addr.clone())
}

/// Session-side probe: the `store_location!` write a strict failure leaves
/// behind (same-host path only; POST and absolute targets store nothing).
async fn session_probe(session: Session) -> axum::Json<serde_json::Value> {
    let stored_location = session
        .get_value(&devise_rust::failure::stored_location_key("user"))
        .await
        .ok()
        .flatten();
    axum::Json(serde_json::json!({ "stored_location": stored_location }))
}

/// Multi-scope status route: reads `user` + `admin` plus the group helper
/// results in one handler (D-10) through the layer-staged proxy.
async fn multi_scope_status(
    Extension(handle): Extension<AuthProxyHandle>,
    Extension(request): Extension<AuthRequest>,
) -> axum::Json<serde_json::Value> {
    let group = AuthGroup::new("any", vec!["user".to_string(), "admin".to_string()]);
    let opts = AuthenticateOpts::default();
    let mut proxy = handle.lock().await;
    let group_scopes = authenticate_group(&group, &mut proxy, &request, &opts).await;
    axum::Json(serde_json::json!({
        "user_signed_in": user_signed_in(&proxy),
        "admin_signed_in": admin_signed_in(&proxy),
        "current_user": current_user::<AuthUser>(&proxy).map(|u| u.email.clone()),
        "current_admin": current_admin::<AdminUser>(&proxy).map(|a| a.email.clone()),
        "user_session": user_session(&proxy).await.is_some(),
        "group_signed_in": group_signed_in(&group, &proxy),
        "group_scopes": group_scopes,
    }))
}

/// Bridge sign-in for the `user` scope (test-only route; the Set-Cookie it
/// returns is the replay jar for later oneshot calls).
async fn bridge_sign_in(
    State(state): State<Arc<TestAppState>>,
    Extension(session): Extension<Session>,
) -> StatusCode {
    let user = state
        .user_adapter
        .get(&DeviseKey::from_i64(1))
        .await
        .expect("lookup")
        .expect("user seeded");
    let (key, salt) = user.session_pair();
    devise_rust_axum::insert_session_and_renew(&session, "user", &key, &salt)
        .await
        .expect("bridge insert");
    StatusCode::OK
}

/// Bridge sign-in for the `admin` scope.
async fn bridge_sign_in_admin(
    State(state): State<Arc<TestAppState>>,
    Extension(session): Extension<Session>,
) -> StatusCode {
    let admin = state
        .admin_adapter
        .get(&DeviseKey::from_i64(1))
        .await
        .expect("lookup")
        .expect("admin seeded");
    let (key, salt) = admin.session_pair();
    devise_rust_axum::insert_session_and_renew(&session, "admin", &key, &salt)
        .await
        .expect("bridge insert");
    StatusCode::OK
}

/// Sign the `user` scope out while leaving other scopes untouched (D-10
/// multi-scope independence).
async fn bridge_sign_out_user(Extension(session): Extension<Session>) -> StatusCode {
    devise_rust_axum::sign_out_and_renew(&session, "user")
        .await
        .expect("sign out");
    StatusCode::OK
}

/// Build the extractor test app: devise + session layers over the probe
/// routes, with `state` shared into the test-only bridge routes.
fn test_app(state: Arc<TestAppState>) -> Router {
    let mut registry = ScopeRegistry::new();
    registry.register(mapping("user", "users"));
    registry.register(mapping("admin", "admins"));
    let devise_layer = DeviseLayer::new(Arc::new(registry), state.config.clone())
        .with_finder(
            "user",
            Arc::new(AdapterBridge::new(state.user_adapter.clone())),
        )
        .with_finder(
            "admin",
            Arc::new(AdapterBridge::new(state.admin_adapter.clone())),
        );
    let session_layer = session_manager_layer(&state.config).expect("session layer");

    Router::new()
        .route("/users/private", get(protected_user))
        .route("/users/soft", get(soft_user))
        .route("/users/peer", get(peer_probe))
        .route("/users/session-probe", get(session_probe))
        .route("/users/status", get(multi_scope_status))
        .route("/devise-test/sign-in", get(bridge_sign_in))
        .route("/devise-test/admin-sign-in", get(bridge_sign_in_admin))
        .route("/devise-test/sign-out-user", get(bridge_sign_out_user))
        .with_state(state)
        .layer(devise_layer)
        .layer(session_layer)
}

fn request(method: Method, uri: &str, accept: &str, cookie: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::ACCEPT, accept);
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(Body::empty()).expect("request")
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

/// Anonymous navigational request: 302 to the mapping's `sign_in_path`
/// with the `unauthenticated` flash; the GET target is remembered via
/// `store_location!` (replayed probe reads it back).
#[tokio::test]
async fn anonymous_html_redirects_with_flash_and_stored_location() {
    let state = Arc::new(TestAppState::new());
    let app = test_app(state.clone());

    let response = app
        .clone()
        .oneshot(request(Method::GET, "/users/private", "text/html", None))
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
        cookies
            .iter()
            .any(|c| c.starts_with("devise.flash=unauthenticated")),
        "flash cookie carries the unauthenticated key: {cookies:?}"
    );

    // store_location wrote the session: replay the cookie into the probe.
    let session_cookie = cookies
        .iter()
        .find(|c| c.starts_with("id="))
        .map(String::as_str)
        .expect("session cookie issued by the store_location write");
    let response = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/users/session-probe",
            "text/html",
            Some(session_cookie),
        ))
        .await
        .expect("oneshot probe");
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(
        body["stored_location"],
        serde_json::json!("/users/private"),
        "GET navigational target is stored for redirect-after-sign-in"
    );

    // Soft extractor on the same stack stays anonymous (never rejects).
    let response = app
        .oneshot(request(Method::GET, "/users/soft", "text/html", None))
        .await
        .expect("oneshot soft");
    assert_eq!(response.status(), StatusCode::OK);
    let authed: bool = body_json(response).await.as_bool().expect("bool body");
    assert!(!authed);
}

/// Anonymous API request: 401 JSON, no redirect (D-09 split).
#[tokio::test]
async fn anonymous_json_is_unauthorized() {
    let state = Arc::new(TestAppState::new());
    let app = test_app(state);

    let response = app
        .oneshot(request(
            Method::GET,
            "/users/private",
            "application/json",
            None,
        ))
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().get(header::LOCATION).is_none());
    let body = body_json(response).await;
    assert_eq!(body["error"], serde_json::json!("unauthorized"));
}

/// Sign in through the bridge, replay the session cookie, and expect the
/// `RequireAuth` route to render the layer-resolved user 200; the staged
/// `AuthRequest` reports the socket peer (D-11).
#[tokio::test]
async fn signed_in_user_reads_record_via_require_auth() {
    let state = Arc::new(TestAppState::new());
    state.seed_user(1, "user@example.com").await;
    let app = test_app(state.clone());

    let response = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/devise-test/sign-in",
            "text/html",
            None,
        ))
        .await
        .expect("oneshot sign-in");
    assert_eq!(response.status(), StatusCode::OK);
    let cookies = set_cookie_pairs(&response);
    assert!(!cookies.is_empty(), "session Set-Cookie captured");
    let cookie = cookies.join("; ");

    let response = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/users/private",
            "text/html",
            Some(&cookie),
        ))
        .await
        .expect("oneshot private");
    assert_eq!(response.status(), StatusCode::OK);
    let user: AuthUser =
        serde_json::from_value(body_json(response).await).expect("typed user body");
    assert_eq!(user.email, "user@example.com");

    // D-11: peer comes from the socket ConnectInfo, never forwarding headers.
    let addr: SocketAddr = "192.0.2.44:8080".parse().expect("socket addr");
    let app = app.layer(Extension(ConnectInfo(addr)));
    let mut probe = request(Method::GET, "/users/peer", "text/html", Some(&cookie));
    probe.headers_mut().insert(
        header::HeaderName::from_static("x-forwarded-for"),
        header::HeaderValue::from_static("1.2.3.4, 5.6.7.8"),
    );
    let response = app.oneshot(probe).await.expect("oneshot peer");
    assert_eq!(response.status(), StatusCode::OK);
    let peer = body_json(response).await;
    assert_eq!(peer, serde_json::json!("192.0.2.44"));
}

/// D-10: `user` and `admin` authenticate simultaneously and independently;
/// signing out `user` leaves `admin` signed in; the group helper succeeds
/// when either scope is present.
#[tokio::test]
async fn multi_scope_independence_and_group() {
    let state = Arc::new(TestAppState::new());
    state.seed_user(1, "user@example.com").await;
    state.seed_admin(1, "admin@example.com").await;
    let app = test_app(state);

    // Sign in BOTH scopes on the same session cookie jar.
    let response = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/devise-test/sign-in",
            "text/html",
            None,
        ))
        .await
        .expect("sign in user");
    let cookies = set_cookie_pairs(&response).join("; ");
    let response = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/devise-test/admin-sign-in",
            "text/html",
            Some(&cookies),
        ))
        .await
        .expect("sign in admin");
    let cookies = set_cookie_pairs(&response).join("; ");
    assert!(!cookies.is_empty());

    let response = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/users/status",
            "text/html",
            Some(&cookies),
        ))
        .await
        .expect("status");
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["user_signed_in"], true);
    assert_eq!(body["admin_signed_in"], true);
    assert_eq!(body["current_user"], "user@example.com");
    assert_eq!(body["current_admin"], "admin@example.com");
    assert_eq!(body["user_session"], true);
    assert_eq!(body["group_signed_in"], true);
    assert_eq!(body["group_scopes"], serde_json::json!(["user", "admin"]));

    // Sign out the user scope only: admin stays signed in (SESS-07 parity).
    let response = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/devise-test/sign-out-user",
            "text/html",
            Some(&cookies),
        ))
        .await
        .expect("sign out user");
    let cookies = set_cookie_pairs(&response).join("; ");

    let response = app
        .oneshot(request(
            Method::GET,
            "/users/status",
            "text/html",
            Some(&cookies),
        ))
        .await
        .expect("status after user sign-out");
    let body = body_json(response).await;
    assert_eq!(body["user_signed_in"], false);
    assert_eq!(body["admin_signed_in"], true);
    assert_eq!(body["current_user"], serde_json::Value::Null);
    assert_eq!(body["current_admin"], "admin@example.com");
    // Group still succeeds with admin alone.
    assert_eq!(body["group_signed_in"], true);
    assert_eq!(body["group_scopes"], serde_json::json!(["admin"]));
}

/// Signed-in request returns 200 with the same user the LAYER resolved
/// (memoized fetch parity — the strict path reuses the memo, no re-auth).
#[tokio::test]
async fn strict_auth_reuses_the_layer_memo() {
    let state = Arc::new(TestAppState::new());
    state.seed_user(1, "memo@example.com").await;
    let app = test_app(state);

    let response = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/devise-test/sign-in",
            "text/html",
            None,
        ))
        .await
        .expect("sign in");
    let cookies = set_cookie_pairs(&response).join("; ");

    // The soft extractor memoizes; the strict one then resolves through the
    // same memoized record (both report the identical user).
    let response = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/users/soft",
            "text/html",
            Some(&cookies),
        ))
        .await
        .expect("soft");
    assert_eq!(response.status(), StatusCode::OK);
    let authed: bool = body_json(response).await.as_bool().expect("bool");
    assert!(authed);

    let response = app
        .oneshot(request(
            Method::GET,
            "/users/private",
            "text/html",
            Some(&cookies),
        ))
        .await
        .expect("strict");
    assert_eq!(response.status(), StatusCode::OK);
    let user: AuthUser =
        serde_json::from_value(body_json(response).await).expect("typed user body");
    assert_eq!(user.email, "memo@example.com");
}
