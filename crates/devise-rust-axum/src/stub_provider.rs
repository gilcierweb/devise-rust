//! Generic `OAuth2` stub provider — documented test support (D-06).
//!
//! A generic `OAuth2` provider shape for the omniauth flow tests: an
//! authorize endpoint issuing codes, a token endpoint exchanging codes
//! (with real PKCE S256 verification so verifier mismatches fail
//! closed), and a userinfo endpoint returning profile JSON with the
//! `email_verified` toggle that drives the D-10 verified gate. It
//! mimics NO real vendor (D-06): generic `OAuth2` wire shapes only, and
//! all vendor variance stays behind
//! [`ProviderProfile`](devise_rust::omniauthable::ProviderProfile) in
//! the assertions.
//!
//! This module is gated behind the `test-support` cargo feature and is
//! NEVER compiled into non-test builds. Both framework crates' flow
//! suites consume the one stub (the actix crate dev-depends on this
//! crate), so both prove the same generic provider. It adds no new
//! registry package: the PKCE digest reuses the workspace `sha2` +
//! `base64` pins already resolved in the graph (T-09-SC).
//!
//! == Examples
//!
//! ```rust,ignore
//! use devise_rust_axum::stub_provider::{StubProfile, spawn_stub_provider, stub_provider_config};
//!
//! let (addr, handle) = spawn_stub_provider(StubProfile {
//!     uid: "stub-uid-1".to_string(),
//!     email: Some("user@example.com".to_string()),
//!     email_verified: true,
//!     name: Some("Stub User".to_string()),
//! })
//! .await;
//! let config = stub_provider_config(&format!("http://{addr}"));
//! // Point OmniauthWebState.providers at `config` and drive the flow.
//! handle.set_profile(profile_with_email_verified(false));
//! ```

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URLSAFE_NO_PAD;
use devise_rust::omniauthable::OAuthProviderConfig;
use sha2::{Digest, Sha256};

/// The profile the stub's userinfo endpoint returns (D-06: generic
/// shapes only; `email_verified` drives the D-10 verified gate).
#[derive(Debug, Clone)]
pub struct StubProfile {
    /// Provider-unique account id (rides `sub` in the userinfo JSON).
    pub uid: String,
    /// Email the stub asserts for the account, when present.
    pub email: Option<String>,
    /// Whether the stub VERIFIES the email (the D-09/D-10 gate toggle).
    pub email_verified: bool,
    /// Display name, when the stub carries one.
    pub name: Option<String>,
}

impl Default for StubProfile {
    fn default() -> Self {
        Self {
            uid: "stub-uid-1".to_string(),
            email: Some("stub-user@example.com".to_string()),
            email_verified: true,
            name: Some("Stub User".to_string()),
        }
    }
}

/// One issued authorization code: the PKCE challenge it is bound to.
#[derive(Debug, Clone)]
struct StubGrant {
    code_challenge: String,
}

#[derive(Debug, Default)]
struct StubState {
    codes: HashMap<String, StubGrant>,
    tokens: HashMap<String, StubProfile>,
    profile: StubProfile,
    next_id: u64,
}

/// The generic `OAuth2` stub provider: shared state behind an `Arc` so
/// the spawned server and the test handle read the same store.
#[derive(Debug, Clone)]
pub struct StubProvider {
    state: Arc<Mutex<StubState>>,
}

impl StubProvider {
    /// New stub asserting `profile` at the userinfo endpoint.
    #[must_use]
    pub fn new(profile: StubProfile) -> Self {
        Self {
            state: Arc::new(Mutex::new(StubState {
                profile,
                ..StubState::default()
            })),
        }
    }

    /// Test-side handle over the same store (profile toggle + token
    /// lookups for assertions).
    #[must_use]
    pub fn handle(&self) -> StubHandle {
        StubHandle {
            state: self.state.clone(),
        }
    }

    /// The stub's endpoint `Router` (authorize/token/userinfo).
    pub fn router(self) -> Router {
        Router::new()
            .route("/authorize", axum::routing::get(stub_authorize))
            .route("/token", axum::routing::post(stub_token))
            .route("/userinfo", axum::routing::get(stub_userinfo))
            .with_state(self)
    }

    fn next_id(&self) -> u64 {
        let mut state = self.state.lock().expect("stub lock");
        state.next_id += 1;
        state.next_id
    }
}

/// Test-side handle over the spawned stub's shared state.
pub struct StubHandle {
    state: Arc<Mutex<StubState>>,
}

impl StubHandle {
    /// Change the profile the userinfo endpoint asserts (the
    /// `email_verified` toggle between flow cases).
    pub fn set_profile(&self, profile: StubProfile) {
        self.state.lock().expect("stub lock").profile = profile;
    }
}

/// Spawn the stub provider on an ephemeral `127.0.0.1` port, returning
/// the bound address and the test-side handle.
///
/// The server runs on the current tokio runtime until the task is
/// dropped; the flow tests keep the returned address for
/// [`stub_provider_config`].
pub async fn spawn_stub_provider(profile: StubProfile) -> (SocketAddr, StubHandle) {
    let stub = StubProvider::new(profile);
    let handle = stub.handle();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("ephemeral bind");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, stub.router())
            .await
            .expect("stub server runs");
    });
    (addr, handle)
}

/// Point an [`OAuthProviderConfig`] at the stub's endpoints (the helper
/// the flow tests use to wire `OmniauthWebState::providers`).
#[must_use]
pub fn stub_provider_config(stub_base_url: &str) -> OAuthProviderConfig {
    OAuthProviderConfig {
        client_id: "stub-client-id".to_string(),
        client_secret: "stub-client-secret".to_string(),
        auth_url: format!("{stub_base_url}/authorize"),
        token_url: format!("{stub_base_url}/token"),
        userinfo_url: format!("{stub_base_url}/userinfo"),
        scopes: vec!["openid".to_string(), "email".to_string()],
    }
}

/// `GET /authorize` — issue a code bound to the request's PKCE
/// challenge and 302 back to the redirect URI echoing the state (the
/// real-provider redirect shape the flow tests drive).
async fn stub_authorize(
    State(stub): State<StubProvider>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let Some(redirect_uri) = params.get("redirect_uri").cloned() else {
        return plain_error(StatusCode::BAD_REQUEST, "missing redirect_uri");
    };
    let code = format!("stub-code-{}", stub.next_id());
    {
        let mut state = stub.state.lock().expect("stub lock");
        state.codes.insert(
            code.clone(),
            StubGrant {
                code_challenge: params.get("code_challenge").cloned().unwrap_or_default(),
            },
        );
    }
    let mut location = format!("{redirect_uri}?code={code}");
    if let Some(returned) = params.get("state") {
        location.push_str("&state=");
        location.push_str(returned);
    }
    let mut response = StatusCode::FOUND.into_response();
    let location =
        HeaderValue::from_str(&location).unwrap_or_else(|_| HeaderValue::from_static("/"));
    response.headers_mut().insert(header::LOCATION, location);
    response
}

/// `POST /token` — the code exchange with real PKCE S256 verification:
/// `BASE64URL_NOPAD(sha256(code_verifier))` must equal the challenge
/// bound at authorize time, so a mismatched verifier fails closed (the
/// OMN-03 matrix case).
async fn stub_token(
    State(stub): State<StubProvider>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let Some(code) = form.get("code").cloned() else {
        return token_error("missing code");
    };
    let Some(verifier) = form.get("code_verifier").cloned() else {
        return token_error("missing code_verifier");
    };
    let grant = {
        let mut state = stub.state.lock().expect("stub lock");
        // Single-use codes: consume on the exchange attempt.
        state.codes.remove(&code)
    };
    let Some(grant) = grant else {
        return token_error("unknown or consumed code");
    };
    let digest = Sha256::digest(verifier.as_bytes());
    let computed = BASE64_URLSAFE_NO_PAD.encode(digest);
    // M-fix (audit): constant-time compare — the same `Devise.secure_compare`
    // the transport paths use; a `!=` here leaked a timing signal on the
    // verifier prefix (test-only code, but the stub feeds the OMN-03 matrix).
    if !devise_rust::crypto::secure_compare(&computed, &grant.code_challenge) {
        return token_error("pkce verification failed");
    }
    let token = format!("stub-token-{}", stub.next_id());
    {
        let mut state = stub.state.lock().expect("stub lock");
        let profile = state.profile.clone();
        state.tokens.insert(token.clone(), profile);
    }
    axum::Json(serde_json::json!({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "openid email",
    }))
    .into_response()
}

/// `GET /userinfo` — the profile JSON for the bearer token (generic
/// shapes only: `sub`, `email`, `email_verified`, `name`).
async fn stub_userinfo(State(stub): State<StubProvider>, headers: HeaderMap) -> Response {
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::to_string);
    let Some(token) = bearer else {
        return plain_error(StatusCode::UNAUTHORIZED, "missing bearer token");
    };
    let profile = {
        let state = stub.state.lock().expect("stub lock");
        state.tokens.get(&token).cloned()
    };
    let Some(profile) = profile else {
        return plain_error(StatusCode::UNAUTHORIZED, "unknown token");
    };
    axum::Json(serde_json::json!({
        "sub": profile.uid,
        "email": profile.email,
        "email_verified": profile.email_verified,
        "name": profile.name,
    }))
    .into_response()
}

fn plain_error(status: StatusCode, message: &str) -> Response {
    (status, message.to_string()).into_response()
}

fn token_error(error: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        axum::Json(serde_json::json!({ "error": "invalid_grant", "error_description": error })),
    )
        .into_response()
}
