//! Stub-provider OAuth flow matrix (OMN-01..03, TEST-02 omniauth leg).
//!
//! Drives the full authorize -> stub -> callback round trip against the
//! generic `OAuth2` stub provider (D-06) with REAL cookie-jar replay —
//! the Lax session cookie must survive the cross-site-shaped
//! authorize-POST -> callback-GET navigation (no test injects session
//! state by hand; the stash rides the real session store). The matrix:
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

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use common::{
    FixtureUser, SystemClock, build_omniauth_app, omniauth_mapping, omniauth_test_config,
};
use devise_rust::adapter::{Conditions, DeviseKey, OrmAdapter};
use devise_rust::failure::AnyDeviseModel as _;
use devise_rust::omniauthable::{PROVIDER_COLUMN, UID_COLUMN};
use devise_rust_axum::stub_provider::{StubProfile, spawn_stub_provider, stub_provider_config};
use devise_rust_axum::test_helpers::{cookie_header, set_cookie_pairs};
use http_body_util::BodyExt;
use tower::ServiceExt;

type Response = axum::http::Response<axum::body::Body>;

/// Browser-style cookie jar: newest value per name, renewal-aware (the
/// 09-02 `devise_flows` shape — real jar replay, never injected state).
struct Jar(Vec<String>);

impl Jar {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn merge(&mut self, response: &Response) {
        for pair in set_cookie_pairs(response) {
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

async fn call(app: &Router, request: Request<Body>) -> Response {
    app.clone().oneshot(request).await.expect("oneshot")
}

async fn body_text(response: Response) -> String {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body collects")
        .to_bytes();
    String::from_utf8(bytes.to_vec()).expect("utf8")
}

fn flash_cookie(response: &Response) -> String {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with("devise.flash="))
        .map(str::to_string)
        .unwrap_or_default()
}

/// The `Host` every request carries — the redirect URIs derive from it
/// (the handler never trusts proxy headers; the default derivation is
/// exercised here).
const APP_HOST: &str = "app.test";

/// Build the wired omniauth app with the stub provider registered as
/// the sole allowlisted provider.
async fn omniauth_app(profile: StubProfile) -> (common::TestState, Router, SocketAddr) {
    let (stub_addr, _handle) = spawn_stub_provider(profile).await;
    let providers = HashMap::from([(
        "stub".to_string(),
        stub_provider_config(&format!("http://{stub_addr}")),
    )]);
    let (state, app) = build_omniauth_app(
        omniauth_mapping(),
        omniauth_test_config(&["stub"]),
        providers,
    );
    (state, app, stub_addr)
}

/// POST the authorize step; returns the 302 Location to the stub.
async fn authorize(app: &Router, jar: &mut Jar) -> String {
    let request = Request::builder()
        .method(Method::POST)
        .uri("/users/auth/stub")
        .header(header::HOST, APP_HOST)
        .header(header::COOKIE, jar.header())
        .body(Body::empty())
        .expect("authorize request");
    let response = call(app, request).await;
    assert_eq!(response.status(), StatusCode::FOUND, "authorize redirects");
    jar.merge(&response);
    response
        .headers()
        .get(header::LOCATION)
        .expect("authorize location")
        .to_str()
        .expect("utf8 location")
        .to_string()
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
/// URI (path + query) for the oneshot app.
async fn drive_stub(location: &str) -> String {
    let http = stub_http_client();
    let response = http.get(location).send().await.expect("stub authorize");
    assert_eq!(
        response.status(),
        StatusCode::FOUND,
        "stub authorize redirects back"
    );
    let callback = response
        .headers()
        .get(header::LOCATION)
        .expect("callback location")
        .to_str()
        .expect("utf8 location")
        .to_string();
    relative_uri(&callback)
}

/// Collapse an absolute URL to its path?query form for the oneshot app.
fn relative_uri(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let path_start = rest.find('/').unwrap_or(0);
    rest[path_start..].to_string()
}

/// GET the callback with the replayed jar; returns the response.
async fn get_callback(app: &Router, jar: &mut Jar, callback_uri: &str) -> Response {
    let request = Request::builder()
        .method(Method::GET)
        .uri(callback_uri)
        .header(header::HOST, APP_HOST)
        .header(header::COOKIE, jar.header())
        .body(Body::empty())
        .expect("callback request");
    let response = call(app, request).await;
    jar.merge(&response);
    response
}

/// The full authorize -> stub -> GET-callback round trip.
async fn round_trip(app: &Router, jar: &mut Jar) -> Response {
    let location = authorize(app, jar).await;
    let callback_uri = drive_stub(&location).await;
    get_callback(app, jar, &callback_uri).await
}

async fn seed_user(state: &common::TestState, email: &str) -> DeviseKey {
    let mut user = FixtureUser::new_with_password(email, "password-123456", &common::test_config());
    user.confirmed_at = Some(<SystemClock as devise_rust::time::Clock>::now(&SystemClock));
    let created = state.adapter.create(user).await.expect("seed row");
    created.to_key()
}

async fn find_by_identity(state: &common::TestState, uid: &str) -> Option<FixtureUser> {
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

#[tokio::test]
async fn authorize_redirects_to_stub_with_pkce_and_state() {
    let (_state, app, stub_addr) = omniauth_app(StubProfile::default()).await;

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
    // The authorize step created a session carrying the stash — the jar
    // holds the session cookie the callback must replay.
    assert!(jar.value("id").is_some(), "authorize sets a session cookie");
}

#[tokio::test]
async fn get_authorize_is_rejected() {
    let (_state, app, _stub_addr) = omniauth_app(StubProfile::default()).await;

    let request = Request::builder()
        .method(Method::GET)
        .uri("/users/auth/stub")
        .header(header::HOST, APP_HOST)
        .body(Body::empty())
        .expect("GET authorize");
    let response = call(&app, request).await;
    // OMN-03: POST-only authorize — GET never starts a flow.
    assert!(
        response.status() == StatusCode::METHOD_NOT_ALLOWED
            || response.status() == StatusCode::NOT_FOUND
    );
    assert_ne!(response.status(), StatusCode::FOUND);
}

#[tokio::test]
async fn unknown_provider_answers_passthru_404() {
    let (_state, app, _stub_addr) = omniauth_app(StubProfile::default()).await;

    let request = Request::builder()
        .method(Method::POST)
        .uri("/users/auth/nope")
        .header(header::HOST, APP_HOST)
        .body(Body::empty())
        .expect("unknown provider");
    let response = call(&app, request).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = body_text(response).await;
    assert_eq!(body, "Not found. Authentication passthru.");
}

#[tokio::test]
async fn callback_round_trip_signs_in_with_success_flash() {
    let (state, app, _stub_addr) = omniauth_app(stub_profile("fresh@example.com", true)).await;

    let mut jar = Jar::new();
    let response = round_trip(&app, &mut jar).await;

    // Success: redirect to the after-sign-in path (the scope's root when
    // no stored location exists) with the success flash.
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/users"),
        "after_sign_in_path_for resolves the scope root"
    );
    let flash = flash_cookie(&response);
    // M-flash: ONE flash format everywhere — the BARE I18n key
    // (`devise.omniauth_callbacks.success`), carried in the SIGNED
    // envelope (S11) shared with the controllers.
    assert!(
        common::flash_keys_from_cookies(
            std::slice::from_ref(&flash),
            &state.config
        )
        .contains(&"omniauth_callbacks.success".to_string()),
        "success flash rides the signed devise.flash cookie: {flash}"
    );

    // The identity row exists (provider + uid persisted, D-11).
    let row = find_by_identity(&state, "stub-uid-1")
        .await
        .expect("identity row created");
    assert_eq!(row.email, "fresh@example.com");

    // REAL jar replay into the protected probe: the sign-in session
    // resolves (the Lax cookie survived the cross-site-shaped round
    // trip — T-09-13).
    let probe = Request::builder()
        .method(Method::GET)
        .uri("/users_dashboard")
        .header(header::HOST, APP_HOST)
        .header(header::COOKIE, jar.header())
        .body(Body::empty())
        .expect("probe request");
    let probe_response = call(&app, probe).await;
    assert_eq!(probe_response.status(), StatusCode::OK);
    let body = body_text(probe_response).await;
    assert!(
        body.contains("fresh@example.com"),
        "probe reads the record: {body}"
    );
}

#[tokio::test]
async fn verified_email_collision_links_identity() {
    let (state, app, _stub_addr) = omniauth_app(stub_profile("linked@example.com", true)).await;

    let seeded_key = seed_user(&state, "linked@example.com").await;

    let mut jar = Jar::new();
    let response = round_trip(&app, &mut jar).await;
    assert_eq!(
        response.status(),
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

#[tokio::test]
async fn unverified_email_collision_creates_new_and_never_links() {
    let (state, app, _stub_addr) = omniauth_app(stub_profile("unlinked@example.com", false)).await;

    let seeded_key = seed_user(&state, "unlinked@example.com").await;

    let mut jar = Jar::new();
    let response = round_trip(&app, &mut jar).await;
    assert_eq!(
        response.status(),
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

#[tokio::test]
async fn callback_without_state_fails_closed() {
    let (state, app, _stub_addr) = omniauth_app(StubProfile::default()).await;

    let mut jar = Jar::new();
    let _ = authorize(&app, &mut jar).await;

    // No returned state: verify_state(Some, None) fails closed.
    let response = get_callback(&app, &mut jar, "/users/auth/stub/callback?code=stub-code-x").await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/users/sign_in"),
        "failure redirects to after_omniauth_failure_path_for"
    );
    let flash = flash_cookie(&response);
    // M-flash: the failure path carries the BARE
    // `devise.omniauth_callbacks.failure` key in the SIGNED envelope —
    // one flash format everywhere.
    assert!(
        common::flash_keys_from_cookies(std::slice::from_ref(&flash), &state.config)
            .contains(&"omniauth_callbacks.failure".to_string()),
        "failure flash rides the signed devise.flash cookie: {flash}"
    );
}

#[tokio::test]
async fn callback_with_mismatched_state_fails_closed() {
    let (state, app, _stub_addr) = omniauth_app(StubProfile::default()).await;

    let mut jar = Jar::new();
    let _ = authorize(&app, &mut jar).await;

    let response = get_callback(
        &app,
        &mut jar,
        "/users/auth/stub/callback?code=stub-code-x&state=tampered-state",
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/users/sign_in")
    );
    let flash = flash_cookie(&response);
    assert!(
        common::flash_keys_from_cookies(std::slice::from_ref(&flash), &state.config)
            .contains(&"omniauth_callbacks.failure".to_string()),
        "mismatched state surfaces as the bare omniauth_callbacks.failure key: {flash}"
    );
}

#[tokio::test]
async fn pkce_verifier_mismatch_fails_closed() {
    let (app_state, app, stub_addr) = omniauth_app(StubProfile::default()).await;

    // A REAL authorize stashes the app's verifier + state.
    let mut jar = Jar::new();
    let location = authorize(&app, &mut jar).await;
    let state = location
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
    assert_eq!(stub_response.status(), StatusCode::FOUND);
    let callback = stub_response
        .headers()
        .get(header::LOCATION)
        .expect("callback location")
        .to_str()
        .expect("utf8")
        .to_string();

    // The state is REAL (it verifies); the code is bound to the TEST's
    // challenge, so the app's stashed verifier fails the stub's PKCE
    // check at exchange time.
    let response = get_callback(&app, &mut jar, &relative_uri(&callback)).await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/users/sign_in")
    );
    let flash = flash_cookie(&response);
    assert!(
        common::flash_keys_from_cookies(std::slice::from_ref(&flash), &app_state.config)
            .contains(&"omniauth_callbacks.failure".to_string()),
        "PKCE mismatch surfaces as the bare omniauth_callbacks.failure key: {flash}"
    );
}

#[tokio::test]
async fn post_callback_variant_completes_the_exchange() {
    let (state, app, _stub_addr) =
        omniauth_app(stub_profile("post-variant@example.com", true)).await;

    let mut jar = Jar::new();
    let location = authorize(&app, &mut jar).await;

    // Drive the stub authorize for a code, but deliver the callback as
    // the `OmniAuth` 2 form-POST shape instead of the redirect GET.
    let http = stub_http_client();
    let stub_response = http.get(location).send().await.expect("stub authorize");
    let callback = stub_response
        .headers()
        .get(header::LOCATION)
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

    let request = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::HOST, APP_HOST)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, jar.header())
        .body(Body::from(form))
        .expect("POST callback");
    let response = call(&app, request).await;
    jar.merge(&response);

    assert_eq!(response.status(), StatusCode::FOUND);
    let flash = flash_cookie(&response);
    assert!(
        common::flash_keys_from_cookies(std::slice::from_ref(&flash), &state.config)
            .contains(&"omniauth_callbacks.success".to_string()),
        "POST callback signs in with the bare success flash key: {flash}"
    );
    assert!(
        find_by_identity(&state, "stub-uid-1").await.is_some(),
        "POST callback completed the exchange"
    );
}
