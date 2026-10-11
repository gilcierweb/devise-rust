//! Omniauth route handlers — the authorize + callback pair rendering the
//! 09-03 core policy (OMN-01 routes, OMN-02 flows, OMN-03 POST-only
//! authorize).
//!
//! Thin renderers: every policy decision lives in core —
//! [`authorize_start`]
//! (always-on PKCE S256 + CSRF state, D-07),
//! [`verify_state`]
//! (`secure_compare` only, fail-closed, T-09-09),
//! [`http_client`]
//! (redirects-disabled exchange transport, T-09-10/T-09-12), the
//! [`Omniauthable::from_omniauth`]
//! seam over the D-09/D-10 verified-gated linking policy, the vendored
//! `devise.omniauth_callbacks` flash templates, and the
//! `omniauth_providers` request-time allowlist. The route table is the
//! shared core spec data ([`omniauth_router`] iterates
//! [`Mapping::omniauth_route_specs_for`](devise_rust::scope::Mapping::omniauth_route_specs_for)
//! — no per-framework omniauth paths anywhere).
//!
//! ## Session stash (D-07 / D-12)
//!
//! The authorize attempt stashes the raw CSRF state and PKCE verifier in
//! the session under `devise.{scope}.omniauth.{provider}.*` keys written
//! through the bridge store (so the bridge key index tracks them and
//! core `expire_devise_keys` clears them on sign-in). They are
//! single-use: the callback removes both keys immediately after reading.
//! OAuth access and refresh tokens live in the requesting flow only and
//! never reach the database (D-12).
//!
//! ## Redirect origin
//!
//! OAuth `redirect_uri` values must be absolute. The state's
//! [`origin`](OmniauthWebState::origin) override supplies the external
//! origin for production mounts (e.g. behind TLS); when unset the
//! handler derives `http://{Host}` from the request's Host header — the
//! handler never trusts `X-Forwarded-*` proxy headers (D-11/D-20
//! posture), so TLS-terminated apps set the override.
//!
//! ## Examples
//!
//! ```rust,ignore
//! let providers = HashMap::from([("stub".to_string(), stub_config)]);
//! let state = OmniauthWebState::new(devise_state, providers)
//!     .with_origin("https://app.example.com");
//! let app = Router::new()
//!     .merge(devise_for_router(devise_state))
//!     .merge(omniauth_router(state)?);
//! ```

#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::too_many_lines)]

use std::collections::{BTreeMap, HashMap};

use axum::Router;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::MethodRouter;
use devise_rust::adapter::OrmAdapter;
use devise_rust::error::DeviseError;
use devise_rust::omniauthable::{
    OAuthProviderConfig, Omniauthable, ProviderProfile, authorize_start, basic_client,
    failure_message, http_client, success_message, verify_state,
};
use devise_rust::proxy::{SetUserEvent, SetUserOpts};
use devise_rust::request::AuthRequest;
use devise_rust::scope::RouteSpec;
use devise_rust::session::SessionStore;
use oauth2::{AuthorizationCode, PkceCodeVerifier, TokenResponse};
use serde_json::Value as JsonValue;
use tower_sessions::Session;

use crate::bridge::{self, TowerSessionStore};
use crate::callbacks::rotate_csrf_token;
use crate::layer::AuthProxyHandle;
use crate::routes::{DeviseParams, DeviseWebState, FullDeviseModel, sign_in_bookkeeping};

/// Session key carrying the stashed CSRF state for one (scope, provider)
/// authorize attempt. The `devise.{scope}.` prefix means core
/// `expire_devise_keys` clears it on sign-in.
fn omniauth_state_key(scope: &str, provider: &str) -> String {
    format!("devise.{scope}.omniauth.{provider}.state")
}

/// Session key carrying the stashed PKCE verifier for one (scope,
/// provider) authorize attempt (single-use; removed on callback read).
fn omniauth_verifier_key(scope: &str, provider: &str) -> String {
    format!("devise.{scope}.omniauth.{provider}.pkce_verifier")
}

/// `OmniAuth::Utils.camelize` for the flash `kind`: "stub" -> "Stub",
/// `google_oauth2` -> `GoogleOauth2`.
fn omniauth_kind(provider: &str) -> String {
    let mut out = String::new();
    for word in provider.split('_') {
        let mut chars = word.chars();
        if let Some(first) = chars.next() {
            out.extend(first.to_uppercase());
            out.push_str(chars.as_str());
        }
    }
    out
}

/// Shared application state for one omniauth mount: the mapping's devise
/// state plus the app's `OAuth2` provider endpoint configs (D-05 —
/// app-supplied, zero vendor presets) and the external origin for OAuth
/// redirect URIs.
///
/// == Options
///
/// * `devise` — the mapping's [`DeviseWebState`] (config, adapter,
///   clock; the config carries the `omniauth_providers` allowlist).
/// * `providers` — [`OAuthProviderConfig`] per provider name; a
///   provider allowlisted in config but missing here fails the request
///   with 500 (app misconfiguration).
/// * `origin` — absolute origin for OAuth `redirect_uri` values; `None`
///   derives `http://{Host}` from the request Host header.
///
/// == Examples
///
/// ```rust,ignore
/// let state = OmniauthWebState::new(devise_state, providers);
/// let router = omniauth_router(state)?;
/// ```
pub struct OmniauthWebState<M, A, L> {
    /// The mapping's devise state (config with the provider allowlist,
    /// adapter, clock).
    pub devise: DeviseWebState<M, A, L>,
    /// `OAuth2` provider endpoint configs keyed by provider name (D-05).
    pub providers: HashMap<String, OAuthProviderConfig>,
    /// External origin for OAuth redirect URIs; `None` derives
    /// `http://{Host}` from the request.
    pub origin: Option<String>,
}

// Manual Clone: `A` and `L` sit behind `Arc`s (same shape as
// `DeviseWebState`'s manual impl).
impl<M, A, L> Clone for OmniauthWebState<M, A, L> {
    fn clone(&self) -> Self {
        Self {
            devise: self.devise.clone(),
            providers: self.providers.clone(),
            origin: self.origin.clone(),
        }
    }
}

impl<M, A, L> OmniauthWebState<M, A, L> {
    /// Build the omniauth state for one mapping.
    #[must_use]
    pub fn new(
        devise: DeviseWebState<M, A, L>,
        providers: HashMap<String, OAuthProviderConfig>,
    ) -> Self {
        Self {
            devise,
            providers,
            origin: None,
        }
    }

    /// Override the external origin for OAuth redirect URIs (production
    /// mounts behind TLS set this; the default derivation is `http`
    /// because the handler never trusts proxy headers).
    #[must_use]
    pub fn with_origin(mut self, origin: impl Into<String>) -> Self {
        self.origin = Some(origin.into());
        self
    }
}

/// The absolute redirect URI for one provider's callback: the external
/// origin override or the request's Host header, joined with the
/// callback path derived from the shared spec table.
fn redirect_uri<M, A, L>(
    st: &OmniauthWebState<M, A, L>,
    auth_request: &AuthRequest,
    provider: &str,
) -> String {
    let callback_path = st
        .devise
        .mapping
        .omniauth_callback_path(&st.devise.config, provider);
    let origin = st.origin.clone().unwrap_or_else(|| {
        let host = auth_request
            .headers
            .get("host")
            .cloned()
            .unwrap_or_default();
        format!("http://{host}")
    });
    format!("{origin}{callback_path}")
}

/// Devise's `OmniauthCallbacksController#passthru`: 404 with the Devise
/// body. Unknown providers hit this (the route is a generic
/// `{provider}` capture; the allowlist applies at request time).
fn passthru_not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        [("content-type", "text/plain; charset=utf-8")],
        "Not found. Authentication passthru.",
    )
        .into_response()
}

fn internal_error() -> Response {
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

/// 302 + the `devise.flash` cookie carrying the RENDERED omniauth flash
/// message (kind + reason interpolation per T-09-14 — the value derives
/// from the provider name and symbolic reasons, never user input or
/// tokens).
fn omniauth_flash_redirect(target: &str, message: &str) -> Response {
    let mut response = StatusCode::FOUND.into_response();
    let location = HeaderValue::from_str(target).unwrap_or_else(|_| HeaderValue::from_static("/"));
    response.headers_mut().insert(header::LOCATION, location);
    let mut cookie =
        tower_sessions::cookie::Cookie::new(crate::failure::FLASH_COOKIE, message.to_string());
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_same_site(tower_sessions::cookie::SameSite::Lax);
    if let Ok(value) = HeaderValue::from_str(&cookie.to_string()) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

/// The omniauth failure path: `devise.omniauth_callbacks.failure` flash
/// with the camelize'd kind and symbolic reason, redirecting to
/// `after_omniauth_failure_path_for` (Devise: the scope's new-session
/// path).
fn omniauth_failure<M, A, L>(
    st: &OmniauthWebState<M, A, L>,
    provider: &str,
    reason: &str,
) -> Response {
    let kind = omniauth_kind(provider);
    let message = failure_message(&kind, reason);
    let target = st.devise.mapping.sign_in_path();
    omniauth_flash_redirect(&target, &message)
}

/// Register the mapping's omniauth route pair (POST-only authorize plus
/// GET-or-POST callback) from the shared core spec data — the single
/// omniauth route table both framework crates render from.
///
/// The mapping must be omniauthable (`Module::Omniauthable`); the model
/// must implement the [`Omniauthable`] seam (the opt-in bundle —
/// non-omniauth apps never implement `from_omniauth`). Registration
/// validates Devise's dynamic-segment ban and fails with
/// [`DeviseError::Config`] for omniauthable mappings scoped under a
/// dynamic segment.
///
/// # Errors
///
/// Returns [`DeviseError::Config`] when the mapping is omniauthable and
/// its scope path carries a dynamic segment (Devise's
/// `devise_omniauth_callback` raise, ported).
///
/// == Examples
///
/// ```rust,ignore
/// let omniauth = omniauth_router(omniauth_state)?;
/// let app = Router::new()
///     .merge(devise_for_router(devise_state))
///     .merge(omniauth);
/// ```
pub fn omniauth_router<M, A, L>(state: OmniauthWebState<M, A, L>) -> Result<Router, DeviseError>
where
    M: FullDeviseModel + Omniauthable,
    A: OrmAdapter<M, New = <M as Omniauthable>::New> + Send + Sync + 'static,
    L: Send + Sync + 'static,
{
    // Registration-time Config error: Devise's dynamic-segment ban.
    state.devise.mapping.validate_omniauth_paths()?;
    // The route table IS the shared core spec data — no per-framework
    // omniauth paths (OMN-01 prohibition).
    let specs = state
        .devise
        .mapping
        .omniauth_route_specs_for(&state.devise.config);
    let mut by_path: BTreeMap<String, Vec<RouteSpec>> = BTreeMap::new();
    for spec in specs {
        by_path.entry(spec.path.clone()).or_default().push(spec);
    }
    let mut router = Router::new();
    for (path, specs) in by_path {
        let mut method_router = MethodRouter::new();
        for spec in specs {
            method_router = match spec.action.as_str() {
                "passthru" => method_router.post(omniauth_authorize::<M, A, L>),
                "callback" if spec.method == "GET" => {
                    method_router.get(omniauth_callback::<M, A, L>)
                }
                "callback" => method_router.post(omniauth_callback::<M, A, L>),
                _ => method_router,
            };
        }
        router = router.route(&path, method_router);
    }
    Ok(router.with_state(state))
}

/// `POST {omniauth_base}/{provider}` — the authorize step (passthru
/// action, OMN-03 POST-only).
///
/// Builds the provider client from the app's [`OAuthProviderConfig`],
/// generates the always-on PKCE S256 pair + CSRF state (core
/// `authorize_start`, D-07), stashes verifier + state in the session,
/// and 302s to the provider URL. Unknown providers answer with the
/// Devise passthru 404.
#[allow(clippy::type_complexity)]
async fn omniauth_authorize<M, A, L>(
    State(st): State<OmniauthWebState<M, A, L>>,
    Extension(session): Extension<Session>,
    Extension(auth_request): Extension<AuthRequest>,
    Path(provider): Path<String>,
) -> Response
where
    M: FullDeviseModel + Omniauthable,
    A: OrmAdapter<M, New = <M as Omniauthable>::New> + Send + Sync + 'static,
    L: Send + Sync + 'static,
{
    let devise = &st.devise;
    let scope = devise.mapping.name.clone();
    // Request-time provider allowlist (the route is a generic
    // `{provider}` capture; Devise generates per-provider routes — the
    // port keeps one row pair and gates here).
    if !devise
        .config
        .omniauth_providers
        .iter()
        .any(|allowed| allowed == &provider)
    {
        return passthru_not_found();
    }
    // Allowlisted but unconfigured: app misconfiguration, not a client
    // failure — 500 (never a passthru 404, which would mask it).
    let Some(provider_config) = st.providers.get(&provider) else {
        return internal_error();
    };

    let redirect_url = redirect_uri(&st, &auth_request, &provider);
    // Config error on malformed provider URLs: app configuration, 500.
    let Ok(start) = authorize_start(provider_config, &redirect_url) else {
        return internal_error();
    };

    // Stash verifier + state in the session through the bridge store so
    // the keys ride the bridge index (cleared on sign-in by core
    // `expire_devise_keys`). Session-only secrets — never URLs, forms,
    // or cookies (D-07/D-12).
    let store = TowerSessionStore::new(session);
    store
        .insert_value(
            &omniauth_state_key(&scope, &provider),
            JsonValue::String(start.state.clone()),
        )
        .await;
    store
        .insert_value(
            &omniauth_verifier_key(&scope, &provider),
            JsonValue::String(start.pkce_verifier.clone()),
        )
        .await;

    // 302 out to the provider authorize URL.
    let mut response = StatusCode::FOUND.into_response();
    let location =
        HeaderValue::from_str(&start.auth_url).unwrap_or_else(|_| HeaderValue::from_static("/"));
    response.headers_mut().insert(header::LOCATION, location);
    response
}

/// `GET|POST {omniauth_base}/{provider}/callback` — the callback step.
///
/// Re-reads the stashed state, fails closed through `verify_state` on
/// mismatch or absence (T-09-09), exchanges the code with the PKCE
/// verifier over the redirects-disabled transport (T-09-10/T-09-12),
/// fetches userinfo, builds the [`ProviderProfile`] (the auth-hash
/// role: `sub`/`uid` -> uid, `email_verified` defaulting false when the
/// vendor claim is absent, T-09-08), hands it to the app's
/// `from_omniauth` seam (D-08), and signs in through the shared SESS
/// path with `SetUserEvent::Authentication` so the trackable/lockable
/// hooks fire, cycling the session id per D-04.
async fn omniauth_callback<M, A, L>(
    State(st): State<OmniauthWebState<M, A, L>>,
    Extension(session): Extension<Session>,
    Extension(handle): Extension<AuthProxyHandle>,
    Extension(auth_request): Extension<AuthRequest>,
    Path(provider): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    params: DeviseParams,
) -> Response
where
    M: FullDeviseModel + Omniauthable,
    A: OrmAdapter<M, New = <M as Omniauthable>::New> + Send + Sync + 'static,
    L: Send + Sync + 'static,
{
    let devise = &st.devise;
    let scope = devise.mapping.name.clone();
    // Request-time allowlist: unknown providers 404 with passthru parity.
    if !devise
        .config
        .omniauth_providers
        .iter()
        .any(|allowed| allowed == &provider)
    {
        return passthru_not_found();
    }
    let Some(provider_config) = st.providers.get(&provider) else {
        return internal_error();
    };

    // Callback params: the provider redirect carries query params (GET);
    // `OmniAuth` 2 form-posts carry them in the body. Query wins on
    // overlap (the redirect shape is authoritative).
    let mut callback_params: HashMap<String, String> = params
        .0
        .iter()
        .filter_map(|(key, value)| value.as_str().map(|raw| (key.clone(), raw.to_string())))
        .collect();
    for (key, value) in query {
        callback_params.entry(key).or_insert(value);
    }
    let returned_state = callback_params.get("state").cloned();
    let code = callback_params.get("code").cloned();

    // Single-use stash: read then remove both keys on every path.
    let store = TowerSessionStore::new(session.clone());
    let state_key = omniauth_state_key(&scope, &provider);
    let verifier_key = omniauth_verifier_key(&scope, &provider);
    let stashed_state = store
        .get_value(&state_key)
        .await
        .and_then(|value| value.as_str().map(str::to_string));
    let stashed_verifier = store
        .get_value(&verifier_key)
        .await
        .and_then(|value| value.as_str().map(str::to_string));
    store.remove(&state_key).await;
    store.remove(&verifier_key).await;

    // CSRF state: secure_compare only; absence on either side fails
    // closed (T-09-09).
    if !verify_state(stashed_state.as_deref(), returned_state.as_deref()) {
        return omniauth_failure(&st, &provider, "Invalid state");
    }
    let (Some(code), Some(verifier)) = (code.filter(|code| !code.is_empty()), stashed_verifier)
    else {
        return omniauth_failure(&st, &provider, "Invalid credentials");
    };

    // Token exchange over the redirects-disabled transport (SSRF rule,
    // T-09-10/T-09-12). The transport comes from core so the rule cannot
    // be forgotten handler-side.
    let redirect_url = redirect_uri(&st, &auth_request, &provider);
    let Ok(client) = basic_client(provider_config, &redirect_url) else {
        return omniauth_failure(&st, &provider, "Token exchange failed");
    };
    let Ok(http) = http_client() else {
        return omniauth_failure(&st, &provider, "Token exchange failed");
    };
    let Ok(token) = client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(PkceCodeVerifier::new(verifier))
        .request_async(&http)
        .await
    else {
        return omniauth_failure(&st, &provider, "Token exchange failed");
    };

    // Userinfo fetch with the access token (session-only, D-12 — the
    // token never reaches the database, the model seam, or logs). The
    // body parses through serde_json (the oauth2 re-exported reqwest
    // does not enable the `json` method).
    let access_token = token.access_token().secret().clone();
    let raw_claims = match http
        .get(&provider_config.userinfo_url)
        .bearer_auth(&access_token)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => match response.text().await {
            Ok(text) => text,
            Err(_) => return omniauth_failure(&st, &provider, "Userinfo fetch failed"),
        },
        _ => return omniauth_failure(&st, &provider, "Userinfo fetch failed"),
    };
    let claims: JsonValue = match serde_json::from_str(&raw_claims) {
        Ok(claims) => claims,
        Err(_) => return omniauth_failure(&st, &provider, "Userinfo fetch failed"),
    };

    // Auth-hash build (the OmniAuth middleware role): uid from `sub` or
    // `uid`; `email_verified` defaults FALSE when the claim is absent
    // (T-09-08 — unasserted verification never links).
    let Some(uid) = claims
        .get("sub")
        .and_then(JsonValue::as_str)
        .or_else(|| claims.get("uid").and_then(JsonValue::as_str))
    else {
        return omniauth_failure(&st, &provider, "Userinfo fetch failed");
    };
    let profile = ProviderProfile {
        provider: provider.clone(),
        uid: uid.to_string(),
        email: claims
            .get("email")
            .and_then(JsonValue::as_str)
            .map(str::to_string),
        email_verified: claims
            .get("email_verified")
            .and_then(JsonValue::as_bool)
            .unwrap_or(false),
        name: claims
            .get("name")
            .and_then(JsonValue::as_str)
            .map(str::to_string),
        raw_claims: claims,
    };

    // The app's from_omniauth seam owns the handoff (D-08); the core
    // default policy (D-09/D-10) runs when the app delegates to it.
    let outcome = M::from_omniauth(profile, devise.adapter.as_ref(), devise.clock.as_ref()).await;
    let mut record = if outcome.is_valid() {
        outcome.record
    } else {
        // Model rejection: symbolic failure, never model values.
        return omniauth_failure(&st, &provider, "Invalid credentials");
    };

    // Warden after_set_user parity on the Authentication event: lockable
    // failed-attempt reset + trackable durable shift (hooks are
    // memo-only by Phase 5 design, so the controller owns the durable
    // writes — the same bookkeeping `sessions_create` runs).
    drop(record.reset_failed_attempts(devise.adapter.as_ref()).await);
    sign_in_bookkeeping(
        &mut record,
        devise.adapter.as_ref(),
        &auth_request.peer_addr.clone().unwrap_or_default(),
        devise.clock.as_ref(),
    )
    .await;

    let (key, salt) = record.session_pair();

    // Sign in through AuthProxy set_user: Authentication hooks +
    // memoization + expire_devise_keys (which also clears the omniauth
    // stash prefix). `store: false` — the physical write belongs to the
    // cycle-before-insert bridge helper below (D-04).
    let target = {
        let mut proxy = handle.lock().await;
        let opts = SetUserOpts {
            event: SetUserEvent::Authentication,
            store: false,
            run_callbacks: true,
            force: false,
        };
        if proxy
            .set_user(&scope, Some(Box::new(record)), opts)
            .await
            .is_err()
        {
            return internal_error();
        }
        devise_rust::helpers::after_sign_in_path_for(&scope, &proxy, &auth_request).await
    };

    // D-04: cycle BEFORE the insert; a failed cycle fails the sign-in.
    if bridge::insert_session_and_renew(store.session(), &scope, &key, &salt)
        .await
        .is_err()
    {
        return internal_error();
    }
    rotate_csrf_token(store.session(), &scope, &devise.config).await;

    // Success: the devise.omniauth_callbacks.success flash with the
    // camelize'd kind, redirecting to after_sign_in_path_for.
    let message = success_message(&omniauth_kind(&provider));
    omniauth_flash_redirect(&target, &message)
}
