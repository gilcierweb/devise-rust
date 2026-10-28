//! Stub-provider OAuth flow matrix — the actix leg (OMN-01..03, TEST-02
//! omniauth leg).
//!
//! Drives the same full authorize -> stub -> callback round trip against
//! the SAME generic `OAuth2` stub provider the axum crate's suite uses
//! (D-06: the actix tests dev-depend on the axum crate's test-support
//! stub, so both frameworks prove one stub), with real cookie-jar
//! replay. The matrix mirrors the axum leg:
//!
//! - authorize 302 carries PKCE S256 + state; GET authorize is rejected
//! - the round trip verifies state, exchanges with the PKCE verifier,
//!   fetches userinfo, and signs in with the success flash
//! - verified-email collision LINKS the identity pair; unverified
//!   collision creates new and NEVER links (D-09/D-10)
//! - unknown provider 404s with passthru parity
//! - missing state, mismatched state, and PKCE verifier mismatch all
//!   fail closed to the failure flash + sign-in redirect
//! - the POST callback variant answers the same exchange (`OmniAuth` 2
//!   form-post shape)

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

mod common;

use std::collections::HashMap;
use std::net::SocketAddr;

use actix_web::dev::Service;
use actix_web::http::{StatusCode, header};
use actix_web::test::{self, TestRequest};
use common::{
    FixtureUser, SystemClock, TestState, build_omniauth_service, omniauth_mapping,
    omniauth_test_config,
};
use devise_rust::adapter::{Conditions, DeviseKey, OrmAdapter};
use devise_rust::failure::AnyDeviseModel as _;
use devise_rust::omniauthable::{PROVIDER_COLUMN, UID_COLUMN};
use devise_rust_actix::test_helpers::{cookie_header, set_cookie_pairs};
use devise_rust_axum::stub_provider::{StubProfile, spawn_stub_provider, stub_provider_config};

/// Browser-style cookie jar: newest value per name, renewal-aware (the
/// actix `devise_flows` shape — real jar replay, never injected state).
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
            .find(|cookie| cookie.starts_with(&format!("{name}=")))
            .and_then(|cookie| cookie.split_once('='))
            .map(|(_, value)| value.to_string())
    }
}

impl Default for Jar {
    fn default() -> Self {
        Self::new()
    }
}

/// The `Host` every request carries — the redirect URIs derive from it
/// (the handler never trusts proxy headers; the default derivation is
/// exercised here).
const APP_HOST: &str = "app.test";

/// Read the session-staged devise flash (S11) over the probe, replaying the
/// jar's session cookie. Consumes the flash (read-once).
async fn flash_of(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    jar: &mut Jar,
) -> Option<String> {
    let resp = test::call_service(
        app,
        TestRequest::get()
            .uri("/devise-test/flash")
            .insert_header(("host", APP_HOST))
            .insert_header(("cookie", jar.header()))
            .to_request(),
    )
    .await;
    assert!(resp.status().is_success(), "flash probe reachable");
    jar.merge(&resp);
    let body: serde_json::Value = test::read_body_json(resp).await;
    body["flash"].as_str().map(str::to_string)
}

fn location(resp: &actix_web::dev::ServiceResponse) -> String {
    resp.response()
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

/// Build the wired omniauth service with the stub provider registered
/// as the sole allowlisted provider.
async fn omniauth_service(
    profile: StubProfile,
) -> (
    TestState,
    impl Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    SocketAddr,
) {
    let (stub_addr, _handle) = spawn_stub_provider(profile).await;
    let providers = HashMap::from([(
        "stub".to_string(),
        stub_provider_config(&format!("http://{stub_addr}")),
    )]);
    let (state, service) = build_omniauth_service(
        omniauth_mapping(),
        omniauth_test_config(&["stub"]),
        providers,
    )
    .await;
    (state, service, stub_addr)
}

/// POST the authorize step; returns the 302 Location to the stub.
async fn authorize<S>(app: &S, jar: &mut Jar) -> String
where
    S: Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse,
            Error = actix_web::Error,
        >,
{
    let resp = test::call_service(
        app,
        TestRequest::post()
            .uri("/users/auth/stub")
            .insert_header(("host", APP_HOST))
            .insert_header(("cookie", jar.header()))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND, "authorize redirects");
    jar.merge(&resp);
    location(&resp)
}

/// The stub-driving HTTP client: redirects DISABLED — the stub's 302
/// back to the app callback carries the code + state the test must read
/// (following it would try to resolve the app's fake `Host` origin).
fn stub_http_client() -> oauth2::reqwest::Client {
    oauth2::reqwest::Client::builder()
        .redirect(oauth2::reqwest::redirect::Policy::none())
        .build()
        .expect("stub client builds")
}

/// Follow the stub's authorize URL over real HTTP; the stub 302s back
/// to the app callback with code + state. Returns the RELATIVE callback
/// URI (path + query) for the test service.
///
/// The stub's response rides the oauth2/reqwest `http` major (http 1.x)
/// while actix-http 3 pins http 0.2, so status + header assertions go
/// through primitive accessors (`as_u16` / name lookup), never the
/// constant types.
async fn drive_stub(location: &str) -> String {
    let http = stub_http_client();
    let response = http.get(location).send().await.expect("stub authorize");
    assert_eq!(
        response.status().as_u16(),
        302,
        "stub authorize redirects back"
    );
    let callback = response
        .headers()
        .get("location")
        .expect("callback location")
        .to_str()
        .expect("utf8 location")
        .to_string();
    relative_uri(&callback)
}

/// Collapse an absolute URL to its path?query form for the test service.
fn relative_uri(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let path_start = rest.find('/').unwrap_or(0);
    rest[path_start..].to_string()
}

/// GET the callback with the replayed jar; returns the response.
async fn get_callback<S>(
    app: &S,
    jar: &mut Jar,
    callback_uri: &str,
) -> actix_web::dev::ServiceResponse
where
    S: Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse,
            Error = actix_web::Error,
        >,
{
    let resp = test::call_service(
        app,
        TestRequest::get()
            .uri(callback_uri)
            .insert_header(("host", APP_HOST))
            .insert_header(("cookie", jar.header()))
            .to_request(),
    )
    .await;
    jar.merge(&resp);
    resp
}

/// The full authorize -> stub -> GET-callback round trip.
async fn round_trip<S>(app: &S, jar: &mut Jar) -> actix_web::dev::ServiceResponse
where
    S: Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse,
            Error = actix_web::Error,
        >,
{
    let location = authorize(app, jar).await;
    let callback_uri = drive_stub(&location).await;
    get_callback(app, jar, &callback_uri).await
}

async fn seed_user(state: &TestState, email: &str) -> DeviseKey {
    let mut user = FixtureUser::new_with_password(email, "password-123456", &common::test_config());
    user.confirmed_at = Some(<SystemClock as devise_rust::time::Clock>::now(&SystemClock));
    let created = state.adapter.create(user).await.expect("seed row");
    created.to_key()
}

async fn find_by_identity(state: &TestState, uid: &str) -> Option<FixtureUser> {
    let mut conditions = Conditions::new();
    conditions.insert(PROVIDER_COLUMN, "stub");
    conditions.insert(UID_COLUMN, uid);
    state.adapter.find_first(&conditions).await.expect("lookup")
}

fn stub_profile(email: &str, email_verified: bool) -> StubProfile {
    StubProfile {
        uid: "stub-uid-1".to_string(),
        email: Some(email.to_string()),
        email_verified,
        name: Some("Stub User".to_string()),
    }
}

#[actix_web::test]
async fn authorize_redirects_to_stub_with_pkce_and_state() {
    let (_state, app, stub_addr) = omniauth_service(StubProfile::default()).await;

    let mut jar = Jar::new();
    let location = authorize(&app, &mut jar).await;

    // The redirect targets the STUB's authorize endpoint.
    assert!(
        location.starts_with(&format!("http://{stub_addr}/authorize?")),
        "authorize targets the stub: {location}"
    );
    // Always-on PKCE S256 + CSRF state (D-07) + the app-supplied config.
    assert!(location.contains("code_challenge="));
    assert!(location.contains("code_challenge_method=S256"));
    assert!(location.contains("state="));
    assert!(location.contains("client_id=stub-client-id"));
    assert!(
        location.contains("redirect_uri=http%3A%2F%2Fapp.test%2Fusers%2Fauth%2Fstub%2Fcallback"),
        "redirect URI derives from the request Host: {location}"
    );
    // The authorize step primed a session cookie the callback must replay.
    assert!(
        jar.value("actix-session").is_some() || jar.value("id").is_some(),
        "authorize sets a session cookie: {:?}",
        jar.0
    );
}

#[actix_web::test]
async fn get_authorize_is_rejected() {
    let (_state, app, _stub_addr) = omniauth_service(StubProfile::default()).await;

    let resp = test::call_service(
        &app,
        TestRequest::get()
            .uri("/users/auth/stub")
            .insert_header(("host", APP_HOST))
            .to_request(),
    )
    .await;
    // OMN-03: POST-only authorize — GET never starts a flow.
    assert!(
        resp.status() == StatusCode::METHOD_NOT_ALLOWED || resp.status() == StatusCode::NOT_FOUND
    );
    assert_ne!(resp.status(), StatusCode::FOUND);
}

#[actix_web::test]
async fn unknown_provider_answers_passthru_404() {
    let (_state, app, _stub_addr) = omniauth_service(StubProfile::default()).await;

    let resp = test::call_service(
        &app,
        TestRequest::post()
            .uri("/users/auth/nope")
            .insert_header(("host", APP_HOST))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = test::read_body(resp).await;
    assert_eq!(body, "Not found. Authentication passthru.");
}

#[actix_web::test]
async fn callback_round_trip_signs_in_with_success_flash() {
    let (state, app, _stub_addr) = omniauth_service(stub_profile("fresh@example.com", true)).await;

    let mut jar = Jar::new();
    let resp = round_trip(&app, &mut jar).await;

    // Success: redirect to the after-sign-in path (Devise precedence: no
    // stored location → the scope root) with the success flash.
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(location(&resp), "/users");
    assert_eq!(
        flash_of(&app, &mut jar).await.as_deref(),
        Some("devise.omniauth_callbacks.success"),
        "success flash carries the bare I18n key (M)"
    );

    // The identity row exists (provider + uid persisted, D-11).
    let row = find_by_identity(&state, "stub-uid-1")
        .await
        .expect("identity row created");
    assert_eq!(row.email, "fresh@example.com");
    // 261026-ghl: the omniauth sign-in path keeps running the trackable
    // bookkeeping through the core changeset — exactly one shift.
    assert_eq!(
        row.sign_in_count, 1,
        "the omniauth sign-in shifted trackable exactly once"
    );
    assert!(row.current_sign_in_at.is_some());

    // REAL jar replay into the protected probe: the sign-in session
    // resolves (the session cookie survived the cross-site-shaped round
    // trip — T-09-13).
    let probe = test::call_service(
        &app,
        TestRequest::get()
            .uri("/users_dashboard")
            .insert_header(("host", APP_HOST))
            .insert_header(("cookie", jar.header()))
            .to_request(),
    )
    .await;
    assert_eq!(probe.status(), StatusCode::OK);
    let body = String::from_utf8(test::read_body(probe).await.to_vec()).expect("utf8");
    assert!(body.contains("fresh@example.com"), "probe reads the record");
}

#[actix_web::test]
async fn verified_email_collision_links_identity() {
    let (state, app, _stub_addr) = omniauth_service(stub_profile("linked@example.com", true)).await;

    let seeded_key = seed_user(&state, "linked@example.com").await;

    let mut jar = Jar::new();
    let resp = round_trip(&app, &mut jar).await;
    assert_eq!(
        resp.status(),
        StatusCode::FOUND,
        "verified collision signs in"
    );

    // The pre-existing row now carries the identity pair (LINK, not
    // create: the seeded key is the linked row).
    let linked = state
        .adapter
        .get(&seeded_key)
        .await
        .expect("lookup")
        .expect("row");
    assert_eq!(linked.provider.as_deref(), Some("stub"));
    assert_eq!(linked.uid.as_deref(), Some("stub-uid-1"));

    // Linking created no second row: the identity lookup and the email
    // lookup resolve to the same seeded key.
    let by_identity = find_by_identity(&state, "stub-uid-1")
        .await
        .expect("identity row");
    assert_eq!(by_identity.to_key(), seeded_key);
}

#[actix_web::test]
async fn unverified_email_collision_creates_new_and_never_links() {
    let (state, app, _stub_addr) =
        omniauth_service(stub_profile("unlinked@example.com", false)).await;

    let seeded_key = seed_user(&state, "unlinked@example.com").await;

    let mut jar = Jar::new();
    let resp = round_trip(&app, &mut jar).await;
    assert_eq!(
        resp.status(),
        StatusCode::FOUND,
        "unverified collision still signs in"
    );

    // T-09-08/D-10 boundary: the pre-existing row keeps EMPTY provider
    // and uid — unverified provider emails NEVER link.
    let original = state
        .adapter
        .get(&seeded_key)
        .await
        .expect("lookup")
        .expect("row");
    assert_eq!(original.provider, None);
    assert_eq!(original.uid, None);

    // A NEW row was created carrying the identity pair.
    let created = find_by_identity(&state, "stub-uid-1")
        .await
        .expect("unverified collision created a new identity row");
    assert_ne!(created.to_key(), seeded_key, "create-new, never link");
    assert_eq!(created.email, "unlinked@example.com");
}

#[actix_web::test]
async fn callback_without_state_fails_closed() {
    let (_state, app, _stub_addr) = omniauth_service(StubProfile::default()).await;

    let mut jar = Jar::new();
    let _ = authorize(&app, &mut jar).await;

    // No returned state: verify_state(Some, None) fails closed.
    let resp = get_callback(&app, &mut jar, "/users/auth/stub/callback?code=stub-code-x").await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(
        location(&resp),
        "/users/sign_in",
        "failure redirects to after_omniauth_failure_path_for"
    );
    assert_eq!(
        flash_of(&app, &mut jar).await.as_deref(),
        Some("devise.omniauth_callbacks.failure"),
        "failure flash carries the bare I18n key (missing state branch)"
    );
}

#[actix_web::test]
async fn callback_with_mismatched_state_fails_closed() {
    let (_state, app, _stub_addr) = omniauth_service(StubProfile::default()).await;

    let mut jar = Jar::new();
    let _ = authorize(&app, &mut jar).await;

    let resp = get_callback(
        &app,
        &mut jar,
        "/users/auth/stub/callback?code=stub-code-x&state=tampered-state",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(location(&resp), "/users/sign_in");
    assert_eq!(
        flash_of(&app, &mut jar).await.as_deref(),
        Some("devise.omniauth_callbacks.failure"),
        "failure flash carries the bare I18n key (mismatched state branch)"
    );
}

#[actix_web::test]
async fn pkce_verifier_mismatch_fails_closed() {
    let (_state, app, stub_addr) = omniauth_service(StubProfile::default()).await;

    // A REAL authorize stashes the app's verifier + state.
    let mut jar = Jar::new();
    let authorize_location = authorize(&app, &mut jar).await;

    // The TEST mints its own PKCE pair and drives the stub authorize
    // directly: the issued code binds to the TEST's challenge, while
    // the app's stash carries its own verifier.
    let state = authorize_location
        .split("state=")
        .nth(1)
        .and_then(|rest| rest.split('&').next())
        .expect("state on the authorize URL")
        .to_string();

    // The TEST mints its own PKCE pair and drives the stub authorize
    // directly: the issued code binds to the TEST's challenge, while
    // the app's stash carries its own verifier.
    let (challenge, _verifier) = oauth2::PkceCodeChallenge::new_random_sha256();
    let http = stub_http_client();
    let stub_authorize_url = format!(
        "http://{stub_addr}/authorize?redirect_uri=http%3A%2F%2Fapp.test%2Fusers%2Fauth%2Fstub%2Fcallback&state={state}&code_challenge={}",
        challenge.as_str()
    );
    let stub_response = http
        .get(stub_authorize_url)
        .send()
        .await
        .expect("stub authorize");
    assert_eq!(stub_response.status().as_u16(), 302);
    let callback = stub_response
        .headers()
        .get("location")
        .expect("callback location")
        .to_str()
        .expect("utf8")
        .to_string();

    // The state is REAL (it verifies); the code is bound to the TEST's
    // challenge, so the app's stashed verifier fails the stub's PKCE
    // check at exchange time.
    let resp = get_callback(&app, &mut jar, &relative_uri(&callback)).await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(location(&resp), "/users/sign_in");
    assert_eq!(
        flash_of(&app, &mut jar).await.as_deref(),
        Some("devise.omniauth_callbacks.failure"),
        "PKCE mismatch surfaces through the bare failure key"
    );
}

#[actix_web::test]
async fn post_callback_variant_completes_the_exchange() {
    let (state, app, _stub_addr) =
        omniauth_service(stub_profile("post-variant@example.com", true)).await;

    let mut jar = Jar::new();
    let authorize_location = authorize(&app, &mut jar).await;

    // Drive the stub authorize for a code, but deliver the callback as
    // the `OmniAuth` 2 form-POST shape instead of the redirect GET.
    let http = stub_http_client();
    let stub_response = http
        .get(authorize_location)
        .send()
        .await
        .expect("stub authorize");
    let callback = stub_response
        .headers()
        .get("location")
        .expect("callback location")
        .to_str()
        .expect("utf8")
        .to_string();
    let relative = relative_uri(&callback);
    let (path, query) = relative.split_once('?').expect("callback query");
    let form = query
        .split('&')
        .map(str::to_string)
        .collect::<Vec<_>>()
        .join("&");

    let resp = test::call_service(
        &app,
        TestRequest::post()
            .uri(path)
            .insert_header(("host", APP_HOST))
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .insert_header(("cookie", jar.header()))
            .set_payload(form)
            .to_request(),
    )
    .await;
    jar.merge(&resp);

    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(
        flash_of(&app, &mut jar).await.as_deref(),
        Some("devise.omniauth_callbacks.success"),
        "POST callback signs in with the bare success key"
    );
    assert!(
        find_by_identity(&state, "stub-uid-1").await.is_some(),
        "POST callback completed the exchange"
    );
}
