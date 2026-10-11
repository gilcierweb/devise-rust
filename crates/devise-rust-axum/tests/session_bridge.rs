//! Session bridge tracer — end-to-end cookie sign-in slice through the
//! bridge, `DeviseLayer`, extractors, failure renderer, and the session
//! routes, exercised over the real tower-sessions `MemoryStore` via
//! `tower::ServiceExt::oneshot` (AXUM-04 harness shape).
//!
//! # Scope
//!
//! - Oneshot sign-in with a `MemoryAdapter`-backed user returns a signed
//!   `Set-Cookie` (D-01 / the single-secret story).
//! - Replaying the cookie reaches a protected route as the same user.
//! - The session id differs across the sign-in transition (D-04 cycle
//!   BEFORE insert), with the `[key, salt]` payload present afterwards.
//! - Sign-out ends the session; the protected route then renders the core
//!   302 navigational failure (no new decision logic in the renderer).

#![allow(clippy::missing_panics_doc)]

use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use axum::routing::get;
use devise_rust::adapter::{DeviseKey, OrmAdapter, memory::MemoryAdapter};
use devise_rust::config::DeviseConfig;
use devise_rust::crypto;
use devise_rust::error::DeviseError;
use devise_rust::failure::AnyDeviseModel;
use devise_rust::model::{AdapterBridge, ModelFinder, PasswordVerifiable};
use devise_rust::scope::{Mapping, Module, PathNames, ScopeRegistry, SignOutVia};
use devise_rust_axum::{
    DeviseLayer, DeviseRouterState, RequireAuth, session_manager_layer, sessions_router,
};
use http_body_util::BodyExt;
use tower::ServiceExt;
use tower_sessions::Session;

/// Minimal fixture user backed by the in-memory adapter (the test oracle).
///
/// `MemoryAdapter` assigns its own map key via `next_id()` on create; the
/// first insertion lands under key `1`, so the fixture's `id` field mirrors
/// that to keep `session_pair` and the adapter's lookup key aligned.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct TracerUser {
    id: i64,
    email: String,
    encrypted_password: String,
}

impl AnyDeviseModel for TracerUser {
    fn to_key(&self) -> DeviseKey {
        DeviseKey::from_i64(self.id)
    }

    fn authenticatable_salt(&self) -> Option<String> {
        self.encrypted_password.get(..29).map(str::to_string)
    }

    fn as_password_verifiable(&self) -> Option<&dyn PasswordVerifiable> {
        Some(self)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl PasswordVerifiable for TracerUser {
    fn valid_password(&self, password: &str, config: &DeviseConfig) -> bool {
        crypto::encryptor::compare(password, &self.encrypted_password, config)
    }
}

fn test_config() -> DeviseConfig {
    DeviseConfig {
        secret_key: "tracer-secret-key-for-axum-testing".to_string(),
        stretches: 4,
        ..DeviseConfig::default()
    }
}

fn user_mapping() -> Mapping {
    Mapping {
        name: "user".to_string(),
        class_name: "User".to_string(),
        path: "users".to_string(),
        path_prefix: None,
        singular: "user".to_string(),
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

/// Protected route: strict extractor, so an anonymous hit renders the core
/// failure decision (302 navigational here).
async fn dashboard(user: RequireAuth<TracerUser>) -> String {
    user.user()
        .map_or_else(|| "anonymous".to_string(), |user| user.email.clone())
}

async fn tracer_app() -> Router {
    let config = Arc::new(test_config());
    let mut registry = ScopeRegistry::new();
    let mapping = user_mapping();
    registry.register(mapping.clone());

    // Seed the oracle adapter; the bcrypt digest drives the salt and the
    // password check (stretches 4 keeps the test fast).
    let adapter = MemoryAdapter::<TracerUser>::new();
    let digest = crypto::encryptor::digest("password123", &config);
    adapter
        .create(TracerUser {
            id: 1,
            email: "tracer@example.com".to_string(),
            encrypted_password: digest,
        })
        .await
        .expect("seed user");
    let finder: Arc<dyn ModelFinder> = Arc::new(AdapterBridge::new(adapter));

    let state = DeviseRouterState {
        config: config.clone(),
        mapping: mapping.clone(),
        finders: HashMap::from([("user".to_string(), finder.clone())]),
    };

    let devise_layer =
        DeviseLayer::new(Arc::new(registry), config.clone()).with_finder("user", finder);
    // SameSite Lax + signed cookie over the Devise-derived key (A2/A3 wiring).
    let session_layer = session_manager_layer(&config).expect("session layer builds");

    Router::new()
        .merge(sessions_router(state))
        .route("/users/dashboard", get(dashboard))
        .layer(devise_layer)
        .layer(session_layer)
}

fn sign_in_request(cookie: Option<&str>) -> Request<Body> {
    request(
        Method::POST,
        "/users/sign_in",
        "user_email=tracer@example.com&user_password=password123",
        cookie,
    )
}

fn request(method: Method, uri: &str, body: &str, cookie: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::ACCEPT, "text/html");
    if !body.is_empty() {
        builder = builder.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    }
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(Body::from(body.to_string())).expect("request")
}

/// Extract the session cookie pair (`id=<signed value>`) from Set-Cookie.
fn session_cookie(response: &axum::response::Response) -> Option<String> {
    for value in response.headers().get_all(header::SET_COOKIE) {
        let raw = value.to_str().ok()?;
        if let Some(pair) = raw.split(';').next() {
            if pair.starts_with("id=") {
                return Some(pair.to_string());
            }
        }
    }
    None
}

async fn body_string(response: axum::response::Response) -> String {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body collects")
        .to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[tokio::test]
async fn tracer_sign_in_roundtrip_rotates_session_id() {
    let app = tracer_app().await;

    // 1. Sign in: navigational 302 + a signed session Set-Cookie.
    let response = app
        .clone()
        .oneshot(sign_in_request(None))
        .await
        .expect("oneshot sign-in");
    assert_eq!(response.status(), StatusCode::FOUND);
    let cookie_a = session_cookie(&response).expect("session cookie after sign-in");

    // 2. Replay the cookie into the protected route: same user, 200.
    let response = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/users/dashboard",
            "",
            Some(&cookie_a),
        ))
        .await
        .expect("oneshot dashboard");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_string(response).await, "tracer@example.com");

    // 3. Sign in again through the live session: cycle_id fires BEFORE the
    //    insert, so the response carries a different session id.
    let response = app
        .clone()
        .oneshot(sign_in_request(Some(&cookie_a)))
        .await
        .expect("oneshot re-sign-in");
    assert_eq!(response.status(), StatusCode::FOUND);
    let cookie_b = session_cookie(&response).expect("rotated session cookie");
    assert_ne!(
        cookie_a, cookie_b,
        "session id differs across the sign-in transition"
    );

    // 4. The warden payload survived the rotation: the protected route
    //    still reads the session back as the same user.
    let response = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/users/dashboard",
            "",
            Some(&cookie_b),
        ))
        .await
        .expect("oneshot dashboard after rotation");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_string(response).await, "tracer@example.com");

    // 5. Sign out, then the dashboard renders the core navigational
    //    failure: 302 to the mapping's sign_in path (flash + redirect,
    //    no new decision logic in the renderer).
    let response = app
        .clone()
        .oneshot(request(
            Method::DELETE,
            "/users/sign_out",
            "",
            Some(&cookie_b),
        ))
        .await
        .expect("oneshot sign-out");
    assert_eq!(response.status(), StatusCode::FOUND);
    let response = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/users/dashboard",
            "",
            Some(&cookie_b),
        ))
        .await
        .expect("oneshot dashboard after sign-out");
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/users/sign_in")
    );
}

/// The key-derivation contract (A3): variable-length-safe `derive_from`
/// only, with a `Config` error on empty or too-short secrets, and no
/// `Key::from` anywhere in the crate.
#[test]
fn tracer_key_derivation_contract() {
    assert!(matches!(
        devise_rust_axum::derive_session_key(""),
        Err(DeviseError::Config(_))
    ));
    assert!(matches!(
        devise_rust_axum::derive_session_key("short-secret"),
        Err(DeviseError::Config(_))
    ));
    assert!(devise_rust_axum::derive_session_key("tracer-secret-key-for-axum-testing").is_ok());
}

/// The A2 fail-closed rule: a router wired WITHOUT `SessionManagerLayer`
/// must 500, never proceed as if anonymous.
#[tokio::test]
async fn tracer_missing_session_layer_fails_closed() {
    let config = Arc::new(test_config());
    let mut registry = ScopeRegistry::new();
    registry.register(user_mapping());
    let adapter = MemoryAdapter::<TracerUser>::new();
    let finder = Arc::new(AdapterBridge::new(adapter));
    let devise_layer =
        DeviseLayer::new(Arc::new(registry), config.clone()).with_finder("user", finder);

    let app = Router::new()
        .route("/users/dashboard", get(dashboard))
        .layer(devise_layer); // session layer intentionally absent

    let response = app
        .oneshot(request(Method::GET, "/users/dashboard", "", None))
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

/// Compile-time gate: the bridge session handle is `Send + Sync`, so no
/// owned-extract dance is needed anywhere in the crate (F-1 divergence).
#[test]
fn tracer_session_handle_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>(_: T) {}
    let store = tower_sessions::MemoryStore::default();
    let session = Session::new(None, Arc::new(store), None);
    assert_send_sync(session.clone());
    assert_send_sync(devise_rust_axum::TowerSessionStore::new(session));
}
