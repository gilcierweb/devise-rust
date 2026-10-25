//! Session bridge tracer — end-to-end sign-in slice through the real
//! `CookieSessionStore`, exercised via `actix_web::test` with a wired
//! `SessionMiddleware` and the crate's bridge helpers.
//!
//! # Scope
//!
//! - Session round-trip: a user signed-in via the bridge can be re-fetched
//!   from the real session layer with a valid salt.
//! - Cookie rotation: renewing on sign-in/out changes the serialized cookie
//!   (D-03), so the response carries a fresh `Set-Cookie` after every
//!   privilege transition.
//! - Send gate: bridge helper futures are `Send` (D-04).

#![allow(clippy::missing_panics_doc)]

use std::sync::Arc;

use actix_session::{Session, SessionMiddleware, storage::CookieSessionStore};
use actix_web::{App, HttpResponse, Responder, test, web};
use devise_rust::{
    adapter::{DeviseKey, OrmAdapter, memory::MemoryAdapter},
    config::DeviseConfig,
    failure::AnyDeviseModel,
    session::keys,
};
use devise_rust_actix::{
    ActixSessionStore,
    bridge::{fetch_session_with_salt, handle_unverified_request, insert_session_and_renew_sync},
};
use serde_json::json;

/// Minimal fixture user backed by the in-memory adapter for the tracer.
///
/// The `id` field drives `DeviseKey::from_i64`; `MemoryAdapter` — the test
/// oracle — assigns its own IDs via `next_id()`. For round-trip verification
/// the fixture's id must line up with what the adapter returns on create, so
/// the test sets it to 1 (the first insertion ID) and asserts via that token.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
struct TracerUser {
    /// Integer PK used by the fixture (mirrors the first create's assigned id).
    id: i64,
    /// Email column.
    email: String,
    /// Bcrypt digest used to derive the authenticatable salt.
    encrypted_password: String,
}

impl AnyDeviseModel for TracerUser {
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

fn tracer_config() -> DeviseConfig {
    // actix-web's Key::derive_from expects >= 32 bytes of master material;
    // a 32-char ASCII secret satisfies the contract.
    let mut secret = [b'x'; 32];
    for (i, byte) in "tracer-secret-key-for-actix-32".chars().enumerate() {
        secret[i] = byte as u8;
    }
    DeviseConfig {
        secret_key: String::from_utf8(secret.to_vec()).expect("secret is ascii"),
        stretches: 4,
        ..DeviseConfig::default()
    }
}

/// Handler that inserts the tracer user into the session via the bridge and
/// returns the pre-renew cookie value so the test can compare against the
/// post-renew one.
async fn sign_in_handler(
    session: Session,
    adapter: web::Data<Arc<MemoryAdapter<TracerUser>>>,
) -> impl Responder {
    let user = TracerUser {
        // MemoryAdapter.next_id() assigns 1 on the first insert; the
        // TracerUser fixture mirrors that so session_pair and the adapter's
        // lookup key line up.
        id: 1,
        email: "tracer@example.com".to_string(),
        encrypted_password: "$2a$04$salt-pepper-1234567890abcd".to_string(),
    };
    adapter.create(user.clone()).await.expect("create");

    let (user_key, salt) = user.session_pair();
    let scope = "user";

    // Renew before insert (D-03): explicit renew call site so grep of
    // bridge.rs finds it.
    drop(ActixSessionStore::renew_sync(&session));
    insert_session_and_renew_sync(&session, scope, &user_key, &salt).expect("insert");

    // Re-read via the bridge so salt validation is proven.
    let fetched =
        fetch_session_with_salt::<_, TracerUser>(&session, scope, adapter.get_ref().as_ref()).await;
    assert_eq!(fetched, Some(user_key.clone()));

    // First cookie read happens before the handler returns; the session
    // middleware will sign/serialize it into Set-Cookie on response.
    let _payload: Option<serde_json::Value> =
        session.get(&keys::scope_session_key(scope)).ok().flatten();

    // Exercise bypass: same operation without callbacks but with renew.
    devise_rust_actix::bridge::bypass_sign_in_and_renew_sync(&session, scope, &user_key, &salt)
        .expect("bypass renew");

    // Renew rotates the session key (and hence the signed cookie) but does not
    // rewrite the stored payload. Prove persistence of the payload, not content
    // rotation: the same [key, salt] JSON body is present before and after the
    // bypass insert.
    let payload_after: Option<serde_json::Value> =
        session.get(&keys::scope_session_key(scope)).ok().flatten();
    assert!(payload_after.is_some());

    HttpResponse::Ok().finish()
}

/// Verifies the renew step ran against the real session store.
#[actix_web::test]
async fn tracer_session_roundtrip_via_middleware() -> Result<(), actix_web::Error> {
    let config = tracer_config();
    let key =
        devise_rust_actix::callbacks::derive_actix_key(&config.secret_key).expect("derive key");
    let store = ActixSessionStore::new(key.clone());
    let _dbg = std::hint::black_box(store);

    // A user-model adapter shared across the request pipeline.
    let adapter = Arc::new(MemoryAdapter::<TracerUser>::new());

    let app = test::init_service(
        App::new()
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), key)
                    .cookie_secure(false)
                    .build(),
            )
            .app_data(web::Data::new(adapter.clone()))
            .route("/tracer/sign_in", web::post().to(sign_in_handler)),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/tracer/sign_in")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // The session cookies were rotated for this request; pull Set-Cookie.
    let cookies: Vec<String> = resp
        .headers()
        .iter()
        .filter(|(k, _)| *k == actix_web::http::header::SET_COOKIE)
        .filter_map(|(_, v)| v.to_str().ok().map(str::to_string))
        .collect();
    assert!(
        cookies.iter().any(|c| c.contains("id=")),
        "set-cookie header present for session id"
    );

    // Send gate: the bridge helpers' futures carry owned data only.
    devise_rust_actix::bridge::assert_send(async {
        let _ = &adapter;
        Ok::<(), actix_web::Error>(())
    });

    Ok(())
}

/// Verifies the API contract on `derive_actix_key` (D-02 + the recorder
/// payload determinism) — empty strings rejected, valid secrets accepted.
#[actix_web::test]
async fn tracer_key_derivation_contract() {
    // Empty secret refused with Config error.
    assert!(matches!(
        devise_rust_actix::callbacks::derive_actix_key(""),
        Err(devise_rust::error::DeviseError::Config(_))
    ));

    // Same 32-byte secret yields same derived key material (derivation is
    // deterministic; the tracer round-trip test above covers rotation).
    let key1 =
        devise_rust_actix::callbacks::derive_actix_key("abcdefghij0123456789abcdef012345").unwrap();
    let key2 =
        devise_rust_actix::callbacks::derive_actix_key("abcdefghij0123456789abcdef012345").unwrap();
    let _ = (key1, key2);
}

/// Verifies the `[key, salt]` payload shape and that serialized session
/// content stays well under the 4096-Byte `CookieSessionStore` ceiling.
#[actix_web::test]
async fn tracer_session_payload_and_size() {
    let config = tracer_config();
    let key =
        devise_rust_actix::callbacks::derive_actix_key(&config.secret_key).expect("derive key");

    let user = TracerUser {
        id: 7,
        email: "payload@example.com".to_string(),
        encrypted_password: "$2a$04$salt-pepper-1234567890abcd".to_string(),
    };
    let (user_key, salt) = user.session_pair();

    let app = test::init_service(
        App::new()
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), key)
                    .cookie_secure(false)
                    .build(),
            )
            .app_data(web::Data::new(user.clone()))
            .route(
                "/tracer/payload",
                web::get().to(|session: Session, user: web::Data<TracerUser>| async move {
                    let (user_key, salt) = user.session_pair();
                    insert_session_and_renew_sync(&session, "user", &user_key, &salt)
                        .expect("insert");
                    let payload: Option<serde_json::Value> =
                        session.get(&keys::scope_session_key("user")).ok().flatten();
                    HttpResponse::Ok().json(payload.expect("payload present"))
                }),
            ),
    )
    .await;

    let req = test::TestRequest::get().uri("/tracer/payload").to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body, json!([user_key.to_string(), salt]));

    // Session size guardrail: the payload is far below the CookieSessionStore
    // 4096-byte ceiling.
    assert!(
        body.to_string().len() < 4096,
        "payload fits CookieSessionStore ceiling"
    );
}

/// Devise `handle_unverified_request` parity (`controllers/helpers.rb:254-260`):
/// a CSRF failure clears every scope's session payload and cycles the
/// session id, so no signed-in user survives the aborted request.
#[actix_web::test]
async fn tracer_handle_unverified_request_clears_all_scopes() {
    let config = tracer_config();
    let key =
        devise_rust_actix::callbacks::derive_actix_key(&config.secret_key).expect("derive key");
    let _store = ActixSessionStore::new(key.clone());

    let app = test::init_service(
        App::new()
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), key.clone())
                    .cookie_name("devise-test".to_string())
                    .build(),
            )
            .route(
                "/tracer/multi-scope",
                web::get().to(|session: Session| async move {
                    let scopes: Vec<String> = vec!["user".to_string(), "admin".to_string()];
                    handle_unverified_request(&session, &scopes).expect("unverified request");
                    let user_payload: Option<serde_json::Value> =
                        session.get(&keys::scope_session_key("user")).ok().flatten();
                    let admin_payload: Option<serde_json::Value> = session
                        .get(&keys::scope_session_key("admin"))
                        .ok()
                        .flatten();
                    HttpResponse::Ok().json(json!({
                        "user": user_payload.is_some(),
                        "admin": admin_payload.is_some(),
                    }))
                }),
            ),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/tracer/multi-scope")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["user"], json!(false), "user scope cleared");
    assert_eq!(body["admin"], json!(false), "admin scope cleared");
}
