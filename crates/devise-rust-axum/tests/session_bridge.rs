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
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Extension};
use axum::http::{Method, Request, StatusCode, header};
use axum::routing::get;
use chrono::DateTime;
use devise_rust::adapter::{DeviseKey, OrmAdapter, memory::MemoryAdapter};
use devise_rust::config::DeviseConfig;
use devise_rust::crypto;
use devise_rust::error::DeviseError;
use devise_rust::failure::AnyDeviseModel;
use devise_rust::hooks::HookRegistry;
use devise_rust::model::{AdapterBridge, ModelFinder, PasswordVerifiable};
use devise_rust::proxy::AuthProxy;
use devise_rust::request::{AuthRequest, HttpMethod};
use devise_rust::scope::{Mapping, Module, PathNames, ScopeRegistry, SignOutVia};
use devise_rust::session::SessionStore as _;
use devise_rust::session::keys;
use devise_rust::time::FixedClock;
use devise_rust_axum::{
    DeviseLayer, DeviseRouterState, RequireAuth, session_manager_layer, sessions_router,
};
use http_body_util::BodyExt;
use tower::ServiceExt;
use tower_sessions::{MemoryStore, Session};

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

fn user_mapping_with(modules: Vec<Module>) -> Mapping {
    Mapping {
        modules,
        ..user_mapping()
    }
}

/// Protected route: strict extractor, so an anonymous hit renders the core
/// failure decision (302 navigational here).
async fn dashboard(user: RequireAuth<TracerUser>) -> String {
    user.user()
        .map_or_else(|| "anonymous".to_string(), |user| user.email.clone())
}

/// POST route behind the strict extractor (stored-location POST matrix).
async fn submit(_: RequireAuth<TracerUser>) -> &'static str {
    "created"
}

/// Peer probe: exposes the layer-built `AuthRequest.peer_addr` so tests
/// can assert the socket-only contract (D-20) and `None` tolerance.
async fn peer_probe(
    axum::extract::Extension(request): axum::extract::Extension<AuthRequest>,
) -> String {
    request.peer_addr.unwrap_or_else(|| "none".to_string())
}

/// Session dump: exposes the session-side state the layer and extractors
/// persist (epoch tick, stored location) for the Task 3 probes.
async fn session_dump(session: Session) -> axum::Json<serde_json::Value> {
    let last_request_at = session
        .get_value(&devise_rust::timeoutable::last_request_at_key("user"))
        .await
        .ok()
        .flatten();
    let stored_location = session
        .get_value(&devise_rust::failure::stored_location_key("user"))
        .await
        .ok()
        .flatten();
    axum::Json(serde_json::json!({
        "last_request_at": last_request_at,
        "stored_location": stored_location,
    }))
}

/// App factory: config + hook registry + module set in, full Devise stack
/// out (session layer outermost).
async fn devise_app(
    config: DeviseConfig,
    hooks: Arc<HookRegistry>,
    modules: Vec<Module>,
) -> Router {
    let config = Arc::new(config);
    let mut registry = ScopeRegistry::new();
    let mapping = user_mapping_with(modules);
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

    let devise_layer = DeviseLayer::new(Arc::new(registry), config.clone())
        .with_hooks(hooks)
        .with_finder("user", finder);
    // SameSite Lax + signed cookie over the Devise-derived key (A2/A3 wiring).
    let session_layer = session_manager_layer(&config).expect("session layer builds");

    Router::new()
        .merge(sessions_router(state))
        .route("/users/dashboard", get(dashboard))
        .route("/users/peer-probe", get(peer_probe))
        .route("/users/session-dump", get(session_dump))
        .route("/users/submit", axum::routing::post(submit))
        .layer(devise_layer)
        .layer(session_layer)
}

async fn tracer_app() -> Router {
    devise_app(
        test_config(),
        Arc::new(HookRegistry::new()),
        vec![Module::DatabaseAuthenticatable],
    )
    .await
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

// ============================================================================
// Task 2 battery — full bridge contract, per-path renewal, CSRF rotation,
// epoch ticks, peer sourcing (all over the real MemoryStore).
// ============================================================================

/// A session over a fresh `MemoryStore`.
fn fresh_session() -> Session {
    Session::new(None, Arc::new(MemoryStore::default()), None)
}

fn fixture_pair() -> (DeviseKey, String) {
    (
        DeviseKey::from_i64(7),
        "$2a$04$salt-pepper-1234567890abcd".to_string(),
    )
}

/// A proxy over the bridge store with the seeded `user` finder — the real
/// core fetch path (salt validation lives in `AuthProxy`). Returns the
/// seeded user so tests derive the matching `[key, salt]` pair.
async fn bridge_proxy(session: &Session) -> (AuthProxy, TracerUser) {
    let config = Arc::new(test_config());
    let mut registry = ScopeRegistry::new();
    registry.register(user_mapping());
    let adapter = MemoryAdapter::<TracerUser>::new();
    let digest = crypto::encryptor::digest("password123", &config);
    let user = TracerUser {
        id: 1,
        email: "tracer@example.com".to_string(),
        encrypted_password: digest,
    };
    adapter.create(user.clone()).await.expect("seed user");
    let finder: Arc<dyn ModelFinder> = Arc::new(AdapterBridge::new(adapter));
    let mut proxy = AuthProxy::new(
        Arc::new(devise_rust_axum::TowerSessionStore::new(session.clone())),
        Arc::new(registry),
        Arc::new(HookRegistry::new()),
        config,
    );
    proxy.register_finder("user", finder);
    (proxy, user)
}

fn fetch_probe_request() -> AuthRequest {
    AuthRequest::new(HttpMethod::Get, "/users/dashboard")
}

/// Round-trip: the `[key, salt]` payload stored under
/// `warden.user.user.session` fetches back as the same user through the
/// core proxy (T-09-02).
#[tokio::test]
async fn bridge_roundtrips_warden_payload_through_core_proxy() {
    let session = fresh_session();
    let (mut proxy, user) = bridge_proxy(&session).await;
    let (key, salt) = user.session_pair();

    let session_key = keys::scope_session_key("user");
    let store = devise_rust_axum::TowerSessionStore::new(session.clone());
    store
        .insert_value(&session_key, serde_json::json!([key.to_string(), salt]))
        .await;

    let request = fetch_probe_request();
    let fetched = proxy.authenticate("user", &request).await;
    assert!(fetched.is_some(), "session fetch resolves the user");
    assert_eq!(
        proxy.user::<TracerUser>("user").map(|user| user.id),
        Some(1)
    );
}

/// Salt mismatch deletes the session key and yields no user (warden fetch
/// semantics; T-09-02).
#[tokio::test]
async fn bridge_salt_mismatch_deletes_session_key() {
    let session = fresh_session();
    let (mut proxy, _) = bridge_proxy(&session).await;

    // Payload carries a salt that cannot match the live record's digest.
    let session_key = keys::scope_session_key("user");
    let store = devise_rust_axum::TowerSessionStore::new(session.clone());
    store
        .insert_value(
            &session_key,
            serde_json::json!(["1", "stale-salt-that-no-longer-matches"]),
        )
        .await;

    let request = fetch_probe_request();
    assert!(proxy.authenticate("user", &request).await.is_none());

    // The mismatch deleted the key: the poisoning payload is gone.
    assert!(
        store.get_value(&session_key).await.is_none(),
        "salt mismatch must delete the session key"
    );
}

/// SIGN-IN path: cycle fires before the insert; the id differs across the
/// transition and the payload survives (T-09-01, Pitfall 2 convergence).
#[tokio::test]
async fn renewal_sign_in_cycles_id_with_payload_present() {
    let session = fresh_session();
    let (key, salt) = fixture_pair();
    let session_key = keys::scope_session_key("user");

    devise_rust_axum::bridge::insert_session_and_renew(&session, "user", &key, &salt)
        .await
        .expect("first sign-in transition");
    session.save().await.expect("save assigns the id");
    let id_before = session.id().expect("id assigned after save");
    assert!(
        session
            .get_value(&session_key)
            .await
            .expect("read")
            .is_some(),
        "payload present after sign-in"
    );

    // A second sign-in transition on the same session: cycle BEFORE insert.
    devise_rust_axum::bridge::insert_session_and_renew(&session, "user", &key, &salt)
        .await
        .expect("second sign-in transition");
    session.save().await.expect("save assigns the new id");
    let id_after = session.id().expect("id reassigned after cycle");
    assert_ne!(id_before, id_after, "session id differs across sign-in");
    let payload = session.get_value(&session_key).await.expect("read");
    assert_eq!(
        payload,
        Some(serde_json::json!([key.to_string(), salt])),
        "payload survived the rotation"
    );
}

/// SIGN-OUT path: cycle fires before the removal; the id differs and the
/// payload is gone (T-09-01).
#[tokio::test]
async fn renewal_sign_out_cycles_id_and_clears_payload() {
    let session = fresh_session();
    let (key, salt) = fixture_pair();
    let session_key = keys::scope_session_key("user");

    devise_rust_axum::bridge::insert_session_and_renew(&session, "user", &key, &salt)
        .await
        .expect("sign-in seed");
    session.save().await.expect("save assigns the id");
    let id_before = session.id().expect("id assigned after save");

    devise_rust_axum::bridge::sign_out_and_renew(&session, "user")
        .await
        .expect("sign-out transition");
    session.save().await.expect("save assigns the new id");
    let id_after = session.id().expect("id reassigned after cycle");
    assert_ne!(id_before, id_after, "session id differs across sign-out");
    assert!(
        session
            .get_value(&session_key)
            .await
            .expect("read")
            .is_none(),
        "payload cleared on sign-out"
    );
}

/// SIGN-OUT-ALL-SCOPES path: one cycle, every scope key removed (T-09-01).
#[tokio::test]
async fn renewal_sign_out_all_scopes_cycles_id_and_clears_every_scope() {
    let session = fresh_session();
    let (key, salt) = fixture_pair();
    let user_key = keys::scope_session_key("user");
    let admin_key = keys::scope_session_key("admin");

    let store = devise_rust_axum::TowerSessionStore::new(session.clone());
    store
        .insert_value(&user_key, serde_json::json!([key.to_string(), &salt]))
        .await;
    store
        .insert_value(&admin_key, serde_json::json!([key.to_string(), &salt]))
        .await;
    session.save().await.expect("save assigns the id");
    let id_before = session.id().expect("id assigned after save");

    let scopes = vec!["user".to_string(), "admin".to_string()];
    devise_rust_axum::bridge::sign_out_all_scopes_and_renew(&session, &scopes)
        .await
        .expect("sign-out-all transition");
    session.save().await.expect("save assigns the new id");
    let id_after = session.id().expect("id reassigned after cycle");
    assert_ne!(
        id_before, id_after,
        "session id differs across sign-out-all"
    );
    assert!(session.get_value(&user_key).await.expect("read").is_none());
    assert!(session.get_value(&admin_key).await.expect("read").is_none());
}

/// BYPASS-SIGN-IN path: cycle before insert, closing the core
/// `bypass_sign_in` renewal gap (T-09-01 / proxy.rs gap).
#[tokio::test]
async fn renewal_bypass_sign_in_cycles_id_with_payload_present() {
    let session = fresh_session();
    let (key, salt) = fixture_pair();
    let session_key = keys::scope_session_key("user");

    devise_rust_axum::bridge::insert_session_and_renew(&session, "user", &key, &salt)
        .await
        .expect("sign-in seed");
    session.save().await.expect("save assigns the id");
    let id_before = session.id().expect("id assigned after save");

    devise_rust_axum::bridge::bypass_sign_in_and_renew(&session, "user", &key, &salt)
        .await
        .expect("bypass transition");
    session.save().await.expect("save assigns the new id");
    let id_after = session.id().expect("id reassigned after cycle");
    assert_ne!(id_before, id_after, "session id differs across bypass");
    let payload = session.get_value(&session_key).await.expect("read");
    assert_eq!(
        payload,
        Some(serde_json::json!([key.to_string(), salt])),
        "payload survived the bypass rotation"
    );
}

/// ACCOUNT-UPDATE path: the password-change re-sign-in cycles too
/// (T-09-01; `update_with_password` -> re-sign-in in Devise).
#[tokio::test]
async fn renewal_account_update_cycles_id_with_payload_present() {
    let session = fresh_session();
    let (key, salt) = fixture_pair();
    let session_key = keys::scope_session_key("user");

    devise_rust_axum::bridge::insert_session_and_renew(&session, "user", &key, &salt)
        .await
        .expect("sign-in seed");
    session.save().await.expect("save assigns the id");
    let id_before = session.id().expect("id assigned after save");

    devise_rust_axum::bridge::account_update_and_renew(&session, "user", &key, &salt)
        .await
        .expect("account-update transition");
    session.save().await.expect("save assigns the new id");
    let id_after = session.id().expect("id reassigned after cycle");
    assert_ne!(
        id_before, id_after,
        "session id differs across account update"
    );
    let payload = session.get_value(&session_key).await.expect("read");
    assert_eq!(
        payload,
        Some(serde_json::json!([key.to_string(), salt])),
        "payload survived the account-update rotation"
    );
}

/// A store whose `delete` always fails, proving a failed cycle fails the
/// transition instead of persisting under the old id.
#[derive(Debug)]
struct FailingDeleteStore {
    inner: MemoryStore,
}

#[async_trait::async_trait]
impl tower_sessions::session_store::SessionStore for FailingDeleteStore {
    async fn create(
        &self,
        session_record: &mut tower_sessions::session::Record,
    ) -> tower_sessions::session_store::Result<()> {
        self.inner.create(session_record).await
    }

    async fn save(
        &self,
        session_record: &tower_sessions::session::Record,
    ) -> tower_sessions::session_store::Result<()> {
        self.inner.save(session_record).await
    }

    async fn load(
        &self,
        session_id: &tower_sessions::session::Id,
    ) -> tower_sessions::session_store::Result<Option<tower_sessions::session::Record>> {
        self.inner.load(session_id).await
    }

    async fn delete(
        &self,
        _session_id: &tower_sessions::session::Id,
    ) -> tower_sessions::session_store::Result<()> {
        Err(tower_sessions::session_store::Error::Backend(
            "delete unavailable".to_string(),
        ))
    }
}

/// The D-04 error contract: a failed cycle fails the transition — the
/// payload is never inserted.
#[tokio::test]
async fn failed_cycle_fails_the_transition() {
    let store = Arc::new(FailingDeleteStore {
        inner: MemoryStore::default(),
    });
    let session = Session::new(None, store, None);
    let (key, salt) = fixture_pair();

    let result =
        devise_rust_axum::bridge::insert_session_and_renew(&session, "user", &key, &salt).await;
    assert!(
        matches!(result, Err(DeviseError::Internal(_))),
        "a failed cycle must fail the transition, got {result:?}"
    );
    assert!(
        session
            .get_value(&keys::scope_session_key("user"))
            .await
            .expect("read")
            .is_none(),
        "no payload may be persisted when the cycle fails"
    );
}

/// Epoch tick helpers: strict integer epochs; malformed (float) values read
/// back as `None` so timeout checks fail closed to expired (D-06).
#[tokio::test]
async fn epoch_tick_helpers_are_strict_integer_epochs() {
    let session = fresh_session();
    let clock = FixedClock::new(DateTime::from_timestamp(1_700_000_000, 0).expect("epoch"));
    let tick_key = devise_rust::timeoutable::last_request_at_key("user");

    devise_rust_axum::bridge::tick_last_request_at(&session, "user", &clock).await;
    let at = devise_rust_axum::bridge::read_last_request_at(&session, "user")
        .await
        .expect("integer epoch parses");
    assert_eq!(at.timestamp(), 1_700_000_000);

    // Float strings never parse (fail closed to expired).
    session
        .insert_value(&tick_key, serde_json::json!("1700000000.5"))
        .await
        .expect("insert");
    assert!(
        devise_rust_axum::bridge::read_last_request_at(&session, "user")
            .await
            .is_none(),
        "float strings must fail closed"
    );

    // Free-form dates never parse either.
    session
        .insert_value(&tick_key, serde_json::json!("yesterday"))
        .await
        .expect("insert");
    assert!(
        devise_rust_axum::bridge::read_last_request_at(&session, "user")
            .await
            .is_none(),
        "malformed values must fail closed"
    );

    // Absent key reads as None (first request, Devise nil).
    assert!(
        devise_rust_axum::bridge::read_last_request_at(&session, "admin")
            .await
            .is_none()
    );
}

/// CSRF rotation (D-07): rotates while the config flag is on, no-ops when
/// off; the token is app-owned and lives in the session.
#[tokio::test]
async fn csrf_rotation_honors_config_flag() {
    let session = fresh_session();
    let csrf_key = devise_rust_axum::csrf_token_key("user");
    let config_on = test_config();

    devise_rust_axum::rotate_csrf_token(&session, "user", &config_on).await;
    let first = session
        .get_value(&csrf_key)
        .await
        .expect("read")
        .expect("token present after rotation");
    devise_rust_axum::rotate_csrf_token(&session, "user", &config_on).await;
    let second = session
        .get_value(&csrf_key)
        .await
        .expect("read")
        .expect("token present after second rotation");
    assert_ne!(first, second, "rotation replaces the token");

    let config_off = DeviseConfig {
        clean_up_csrf_token_on_authentication: false,
        ..test_config()
    };
    let before = session.get_value(&csrf_key).await.expect("read");
    devise_rust_axum::rotate_csrf_token(&session, "user", &config_off).await;
    let after = session.get_value(&csrf_key).await.expect("read");
    assert_eq!(before, after, "flag off means no-op");
}

/// Peer sourcing (D-20): `None` (no connect info wired) is tolerated.
#[tokio::test]
async fn peer_addr_none_is_tolerated() {
    let app = tracer_app().await;
    let response = app
        .oneshot(request(Method::GET, "/users/peer-probe", "", None))
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_string(response).await, "none");
}

/// With `ConnectInfo` staged outermost (the runtime
/// `into_make_service_with_connect_info` shape), the probe reads the
/// socket peer and ignores attacker-controlled forwarding headers (D-20).
#[tokio::test]
async fn peer_addr_comes_from_the_socket_not_forwarded_headers() {
    let addr: SocketAddr = "203.0.113.9:40000".parse().expect("socket addr");
    let app = tracer_app().await.layer(Extension(ConnectInfo(addr)));
    let mut probe = request(Method::GET, "/users/peer-probe", "", None);
    probe.headers_mut().insert(
        header::HeaderName::from_static("x-forwarded-for"),
        header::HeaderValue::from_static("1.2.3.4, 5.6.7.8"),
    );
    let response = app.oneshot(probe).await.expect("oneshot");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_string(response).await, "203.0.113.9");
}

// ============================================================================
// Task 3 battery — layer pipeline, layer-order probe (A2), session cookie
// posture, stored-location matrix, 302/401 split, Request-hook tick,
// remember-ops drain.
// ============================================================================

/// A2 probe, positive leg: with `SessionManagerLayer` outermost the
/// `Session` is resolvable inside `DeviseLayer`, so a handler reading the
/// session directly answers 200 through the full stack.
#[tokio::test]
async fn layer_order_probe_session_resolvable_inside_devise_layer() {
    let app = tracer_app().await;
    let response = app
        .oneshot(request(Method::GET, "/users/session-dump", "", None))
        .await
        .expect("oneshot");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "session layer must be outermost so DeviseLayer never fails closed here"
    );
}

/// The `session_manager_layer` contract: SameSite=Lax (never the Strict
/// default that breaks OAuth round-trips), `HttpOnly`, `Secure`, and a signed
/// value (cookie 0.18 prepends a 44-char base64 HMAC digest to the id).
#[tokio::test]
async fn session_cookie_attributes_lax_signed_httponly_secure() {
    let app = tracer_app().await;
    let response = app
        .clone()
        .oneshot(sign_in_request(None))
        .await
        .expect("oneshot sign-in");
    assert_eq!(response.status(), StatusCode::FOUND);

    let session_pair = session_cookie(&response).expect("session cookie");
    let raw = session_pair.trim_start_matches("id=");
    assert!(
        raw.contains(';')
            || response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .any(|v| v.to_str().is_ok_and(|c| c.contains("SameSite=Lax"))),
        "attributes render on the cookie"
    );
    let all: Vec<String> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_string))
        .collect();
    let id_cookie = all
        .iter()
        .find(|c| c.starts_with("id="))
        .expect("session cookie present");
    assert!(
        id_cookie.contains("SameSite=Lax"),
        "Lax override, not Strict"
    );
    assert!(id_cookie.contains("HttpOnly"));
    assert!(id_cookie.contains("Secure"));
    assert!(id_cookie.contains("Path=/"));
    let value = id_cookie
        .trim_start_matches("id=")
        .split(';')
        .next()
        .unwrap_or_default();
    assert!(
        value.len() > 44,
        "signed cookie: value carries the 44-char HMAC digest prefix"
    );
}

/// Stored-location matrix, GET leg: an unauthenticated navigational GET is
/// remembered in the session so post-sign-in can return.
#[tokio::test]
async fn stored_location_get_navigational_is_stored() {
    let app = tracer_app().await;
    let response = app
        .clone()
        .oneshot(request(Method::GET, "/users/dashboard", "", None))
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::FOUND);
    let cookie = session_cookie(&response)
        .expect("store_location wrote the session, so a cookie was issued");

    let response = app
        .oneshot(request(
            Method::GET,
            "/users/session-dump",
            "",
            Some(&cookie),
        ))
        .await
        .expect("oneshot dump");
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_str(&body_string(response).await).expect("json body");
    assert_eq!(
        body["stored_location"],
        serde_json::json!("/users/dashboard")
    );
}

/// Stored-location matrix, POST + absolute legs: POST stores nothing (no
/// session write at all), and the core parser rejects absolute and
/// protocol-relative targets (the failure.rs assert shapes).
#[tokio::test]
async fn stored_location_post_and_absolute_targets_store_nothing() {
    let app = tracer_app().await;
    let response = app
        .oneshot(request(Method::POST, "/users/submit", "", None))
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(
        session_cookie(&response).is_none(),
        "POST stores nothing — the session is never written (only the flash may be set)"
    );

    // Core parser matrix (mirrors devise-rust/src/failure.rs tests).
    assert!(AuthRequest::parse_stored_uri("http://evil.example/x").is_none());
    assert!(AuthRequest::parse_stored_uri("https://evil.example/x").is_none());
    assert!(AuthRequest::parse_stored_uri("//evil.example/x").is_none());
    assert!(AuthRequest::parse_stored_uri("relative").is_none());
    assert_eq!(
        AuthRequest::parse_stored_uri("/users/dashboard"),
        Some("/users/dashboard".to_string())
    );
}

/// The failure split (D-09): navigational requests get the core 302 +
/// flash; API requests (navigational formats without `*/*`) get 401 JSON.
#[tokio::test]
async fn failure_split_navigational_302_api_401() {
    // Navigational: 302 toward the mapping's sign-in path with the flash.
    let app = tracer_app().await;
    let response = app
        .clone()
        .oneshot(request(Method::GET, "/users/dashboard", "", None))
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
    let has_flash = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .any(|v| {
            v.to_str().is_ok_and(|c| {
                // S11: the flash value is a signed envelope over the bare
                // key — the name still prefixes the cookie.
                c.split(';')
                    .next()
                    .unwrap_or_default()
                    .starts_with("devise.flash=")
            })
        });
    assert!(has_flash, "navigational failures carry the flash cookie");

    // API: 401 JSON, no redirect.
    let api_config = DeviseConfig {
        navigational_formats: vec!["html".to_string(), "turbo_stream".to_string()],
        ..test_config()
    };
    let app = devise_app(
        api_config,
        Arc::new(HookRegistry::new()),
        vec![Module::DatabaseAuthenticatable],
    )
    .await;
    let mut probe = request(Method::GET, "/users/dashboard", "", None);
    probe.headers_mut().insert(
        header::ACCEPT,
        axum::http::HeaderValue::from_static("application/json"),
    );
    let response = app.oneshot(probe).await.expect("oneshot");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().get(header::LOCATION).is_none());
    assert_eq!(body_string(response).await, r#"{"error":"unauthorized"}"#);
}

/// http_auth-eligible failures render 401 with the `WWW-Authenticate:
/// Basic realm="..."` challenge from config (RFC 7235 quoted realm).
#[tokio::test]
async fn http_auth_failure_carries_www_authenticate_challenge() {
    let config = DeviseConfig {
        http_authenticatable: true,
        navigational_formats: vec!["html".to_string()],
        ..test_config()
    };
    let app = devise_app(
        config,
        Arc::new(HookRegistry::new()),
        vec![Module::DatabaseAuthenticatable],
    )
    .await;
    let mut probe = request(Method::GET, "/users/dashboard", "", None);
    probe.headers_mut().insert(
        header::AUTHORIZATION,
        axum::http::HeaderValue::from_static("Basic dXNlcjp3cm9uZw=="),
    );
    probe.headers_mut().insert(
        header::ACCEPT,
        axum::http::HeaderValue::from_static("application/json"),
    );
    let response = app.oneshot(probe).await.expect("oneshot");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok()),
        Some("Basic realm=\"Application\"")
    );
}

/// S4 (security audit): query-string credentials must NOT authenticate a
/// guarded route. Devise enables params authentication ONLY inside
/// sessions#create (`allow_params_authentication!`,
/// `sessions_controller.rb:5`); the layer defaulting the request flag
/// from `Devise.params_authenticatable` on EVERY request let any
/// `RequireAuth` route authenticate `?user_email=…&user_password=…` —
/// credentials leaking into URLs, proxies, and access logs.
#[tokio::test]
async fn query_credentials_do_not_authenticate_guarded_routes() {
    let app = tracer_app().await;
    // The seeded tracer user's password IS "password123": if the params
    // strategy ran, this request would authenticate (200). It must not.
    let mut probe = Request::builder()
        .method(Method::GET)
        .uri("/users/dashboard?user_email=tracer@example.com&user_password=password123")
        .body(Body::empty())
        .expect("request");
    probe.headers_mut().insert(
        header::ACCEPT,
        axum::http::HeaderValue::from_static("application/json"),
    );
    let response = app.oneshot(probe).await.expect("oneshot");
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "query-string credentials must never authenticate a guarded route"
    );
}

/// The layer dispatches `Event::Request` hooks with the live record: the
/// core timeoutable body persists the integer-epoch `last_request_at`
/// tick into the session on authenticated requests.
#[tokio::test]
async fn layer_dispatches_request_hooks_persisting_epoch_tick() {
    let modules = vec![Module::DatabaseAuthenticatable, Module::Timeoutable];
    let mut hooks = HookRegistry::new();
    devise_rust::hooks::register_devise_hooks(&mut hooks, &user_mapping_with(modules.clone()));
    let app = devise_app(test_config(), Arc::new(hooks), modules).await;

    // Sign in, then make an authenticated request: the Request hooks fire.
    let response = app
        .clone()
        .oneshot(sign_in_request(None))
        .await
        .expect("sign-in");
    assert_eq!(response.status(), StatusCode::FOUND);
    let cookie = session_cookie(&response).expect("session cookie");

    let response = app
        .clone()
        .oneshot(request(Method::GET, "/users/dashboard", "", Some(&cookie)))
        .await
        .expect("dashboard");
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .oneshot(request(
            Method::GET,
            "/users/session-dump",
            "",
            Some(&cookie),
        ))
        .await
        .expect("dump");
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_str(&body_string(response).await).expect("json body");
    assert!(
        body["last_request_at"].is_i64(),
        "integer-epoch tick persisted by the Request hook, got {body}"
    );
}

/// The layer drains the remember-cookie outbox into Set-Cookie: `Set` ops
/// render the hardened attributes, `Clear` ops render tombstones.
#[tokio::test]
async fn remember_ops_drain_into_set_cookie() {
    use devise_rust::hooks::HookFilter;
    use devise_rust::rememberable::{
        RememberCookieOp, RememberableCookieAttrs, remember_cookie_key,
    };
    use devise_rust::time::SystemClock;

    let mut hooks = HookRegistry::new();
    hooks.add_hook(
        HookFilter::new().only(vec![devise_rust::hooks::Event::Request]),
        Box::new(|ctx| {
            Box::pin(async move {
                let config = ctx.proxy.devise_config().clone();
                let scope = ctx.scope.to_string();
                let attrs = RememberableCookieAttrs::for_scope(&scope, &config, &SystemClock);
                ctx.proxy.push_remember_cookie_op(RememberCookieOp::Set {
                    scope: scope.clone(),
                    key: remember_cookie_key(&scope, &config),
                    value: "encoded-cookie-triple".to_string(),
                    attrs,
                });
                ctx.proxy.push_remember_cookie_op(RememberCookieOp::Clear {
                    scope,
                    key: "remember_admin_token".to_string(),
                });
                Ok(())
            })
        }),
        false,
    );

    let app = devise_app(
        test_config(),
        Arc::new(hooks),
        vec![Module::DatabaseAuthenticatable],
    )
    .await;

    // Sign in, then hit the protected route: the Request hook queues both
    // ops and the layer drains them onto the response.
    let response = app
        .clone()
        .oneshot(sign_in_request(None))
        .await
        .expect("sign-in");
    let cookie = session_cookie(&response).expect("session cookie");

    let response = app
        .oneshot(request(Method::GET, "/users/dashboard", "", Some(&cookie)))
        .await
        .expect("dashboard");
    assert_eq!(response.status(), StatusCode::OK);
    let set_cookies: Vec<String> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_string))
        .collect();

    let set = set_cookies
        .iter()
        .find(|c| c.starts_with("remember_user_token="))
        .expect("Set op drained into Set-Cookie");
    // 09-02 signed transport: the value is the 44-char HMAC digest prefix
    // followed by the core codec payload in plaintext (cookie 0.18
    // signed-jar semantics — the 09-01 unsigned intermediate is closed).
    assert!(
        set.contains("encoded-cookie-triple"),
        "signed value carries the core codec payload: {set}"
    );
    assert!(set.contains("HttpOnly"));
    assert!(set.contains("Secure"));
    assert!(set.contains("SameSite=Lax"));
    assert!(set.contains("Expires="));

    let clear = set_cookies
        .iter()
        .find(|c| c.starts_with("remember_admin_token="))
        .expect("Clear op drained into a tombstone");
    assert!(clear.contains("Max-Age=0"));
}

/// Devise `handle_unverified_request` parity (`controllers/helpers.rb:254-260`):
/// a CSRF failure clears every scope's session payload (plus the timeoutable
/// tick) and cycles the session id.
#[tokio::test]
async fn renewal_handle_unverified_request_clears_every_scope() {
    let session = fresh_session();
    let (key, salt) = fixture_pair();
    let user_key = keys::scope_session_key("user");
    let admin_key = keys::scope_session_key("admin");
    let tick_key = devise_rust::timeoutable::last_request_at_key("user");

    let store = devise_rust_axum::TowerSessionStore::new(session.clone());
    store
        .insert_value(&user_key, serde_json::json!([key.to_string(), &salt]))
        .await;
    store
        .insert_value(&admin_key, serde_json::json!([key.to_string(), &salt]))
        .await;
    store
        .insert_value(&tick_key, serde_json::json!(i64::MAX))
        .await;
    session.save().await.expect("save assigns the id");
    let id_before = session.id().expect("id assigned after save");

    let scopes = vec!["user".to_string(), "admin".to_string()];
    devise_rust_axum::bridge::handle_unverified_request(&session, &scopes)
        .await
        .expect("unverified request");
    session.save().await.expect("save assigns the new id");
    let id_after = session.id().expect("id reassigned after cycle");

    assert_ne!(id_before, id_after, "session id must cycle on CSRF failure");
    assert!(session.get_value(&user_key).await.expect("read").is_none());
    assert!(session.get_value(&admin_key).await.expect("read").is_none());
    assert!(session.get_value(&tick_key).await.expect("read").is_none());
}
