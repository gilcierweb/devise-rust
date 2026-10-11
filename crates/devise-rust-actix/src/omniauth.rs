//! Omniauth route handlers — the actix rendering of the same authorize +
//! callback pair over the same shared core spec + 09-03 policy (OMN-01
//! routes, OMN-02 flows, OMN-03 POST-only authorize).
//!
//! Thin renderers, twin of the axum crate's `omniauth` module: every
//! policy decision lives in core —
//! [`authorize_start`](devise_rust::omniauthable::authorize_start)
//! (always-on PKCE S256 + CSRF state, D-07),
//! [`verify_state`](devise_rust::omniauthable::verify_state)
//! (`secure_compare` only, fail-closed, T-09-09),
//! [`http_client`](devise_rust::omniauthable::http_client)
//! (redirects-disabled exchange transport, T-09-10/T-09-12), the
//! [`Omniauthable::from_omniauth`](devise_rust::omniauthable::Omniauthable::from_omniauth)
//! seam over the D-09/D-10 verified-gated linking policy, the vendored
//! `devise.omniauth_callbacks` flash templates, and the
//! `omniauth_providers` request-time allowlist. The route table is the
//! shared core spec data —
//! [`devise_omniauth_scope`] iterates
//! [`Mapping::omniauth_route_specs_for`](devise_rust::scope::Mapping::omniauth_route_specs_for)
//! — actix-router 0.5 consumes the spec's `{provider}` curly-brace
//! captures natively, so the shared paths render verbatim.
//!
//! ## Mounting
//!
//! Mount the returned [`Scope`] BEFORE the `devise_for_users` scope in
//! the `App` service list: actix matches top-level services in
//! registration order, and the omniauth base (`{full_path}/auth` or the
//! `omniauth_path_prefix` override) is a longer prefix than the devise
//! scope itself.
//!
//! ## Session stash (D-07 / D-12)
//!
//! The authorize attempt stashes the raw CSRF state and PKCE verifier in
//! the session under `devise.{scope}.omniauth.{provider}.*` keys. They
//! are single-use: the callback removes both keys immediately after
//! reading. OAuth access and refresh tokens live in the requesting flow
//! only and never reach the database (D-12).
//!
//! == Examples
//!
//! ```rust,ignore
//! let providers = HashMap::from([("stub".to_string(), stub_config)]);
//! let state = web::Data::new(OmniauthWebState::new(devise_state, providers));
//! App::new()
//!     .service(devise_omniauth_scope(state.clone())?)
//!     .service(devise_for_users(devise_data))
//! ```

#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::future_not_send)]
#![allow(clippy::too_many_lines)]

use std::collections::{BTreeMap, HashMap};

use actix_session::Session;
use actix_web::{HttpRequest, HttpResponse, Scope, web};
use devise_rust::adapter::{OrmAdapter, Value as AdapterValue};
use devise_rust::error::DeviseError;
use devise_rust::omniauthable::{
    OAuthProviderConfig, Omniauthable, ProviderProfile, authorize_start, basic_client,
    failure_message, http_client, success_message, verify_state,
};
use devise_rust::scope::RouteSpec;
use oauth2::{AuthorizationCode, PkceCodeVerifier, TokenResponse};
use serde_json::Value as JsonValue;

use crate::bridge::insert_session_and_renew_sync;
use crate::callbacks::rotate_csrf_token;
use crate::routes::{DeviseWebState, FullDeviseModel};

/// Session key carrying the stashed CSRF state for one (scope, provider)
/// authorize attempt (twin of the axum module's key shape; actix and
/// axum sessions never interoperate, but the key grammar stays
/// identical for auditability).
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
/// * `devise` — the mapping's [`DeviseWebState`] (config with the
///   `omniauth_providers` allowlist, adapter, clock).
/// * `providers` — [`OAuthProviderConfig`] per provider name; a provider
///   allowlisted in config but missing here fails the request with 500
///   (app misconfiguration).
/// * `origin` — absolute origin for OAuth `redirect_uri` values; `None`
///   derives `http://{Host}` from the request Host header.
///
/// == Examples
///
/// ```rust,ignore
/// let state = OmniauthWebState::new(devise_state, providers);
/// let scope = devise_omniauth_scope(web::Data::new(state))?;
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
    req: &HttpRequest,
    provider: &str,
) -> String {
    let callback_path = st
        .devise
        .mapping
        .omniauth_callback_path(&st.devise.config, provider);
    let origin = st.origin.clone().unwrap_or_else(|| {
        let host = req
            .headers()
            .get(actix_web::http::header::HOST)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        format!("http://{host}")
    });
    format!("{origin}{callback_path}")
}

/// Devise's `OmniauthCallbacksController#passthru`: 404 with the Devise
/// body. Unknown providers hit this (the route is a generic `:provider`
/// capture; the allowlist applies at request time).
fn passthru_not_found() -> HttpResponse {
    HttpResponse::NotFound()
        .content_type("text/plain; charset=utf-8")
        .body("Not found. Authentication passthru.")
}

fn internal_error() -> HttpResponse {
    HttpResponse::InternalServerError().finish()
}

/// 302 + the `devise.flash` cookie carrying the RENDERED omniauth flash
/// message (kind + reason interpolation per T-09-14 — the value derives
/// from the provider name and symbolic reasons, never user input or
/// tokens).
fn omniauth_flash_redirect(location: &str, message: &str) -> HttpResponse {
    let mut response = HttpResponse::Found()
        .insert_header((actix_web::http::header::LOCATION, location))
        .finish();
    let mut cookie = actix_web::cookie::Cookie::new("devise.flash", message.to_string());
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_same_site(actix_web::cookie::SameSite::Lax);
    response.add_cookie(&cookie).ok();
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
) -> HttpResponse {
    let kind = omniauth_kind(provider);
    let message = failure_message(&kind, reason);
    omniauth_flash_redirect(&st.devise.mapping.sign_in_path(), &message)
}

/// Success redirect target after sign-in: stored location (same-host
/// parsed via core validator) or the app root — the actix
/// `after_sign_in_target` parity.
fn after_sign_in_target(session: &Session, scope: &str) -> String {
    let key = devise_rust::failure::stored_location_key(scope);
    if let Some(raw) = session.get::<String>(&key).ok().flatten() {
        session.remove(&key);
        if let Some(target) = devise_rust::request::AuthRequest::parse_stored_uri(&raw) {
            return target;
        }
    }
    "/".to_string()
}

/// Durable sign-in bookkeeping on the omniauth callback path (twin of
/// the axum crate's shared helper; actix `routes.rs` keeps its own inline
/// block and stays outside this plan's file set): the trackable shift
/// (current to last, now + peer) persisted through `update_columns`.
async fn sign_in_bookkeeping<M, A, L>(
    record: &mut M,
    state: &DeviseWebState<M, A, L>,
    peer_addr: &str,
) where
    M: FullDeviseModel,
    A: OrmAdapter<M> + Send + Sync,
{
    let now = state.clock.now();
    record.update_tracked_fields(now, peer_addr);
    let fields = HashMap::from([
        (
            "sign_in_count".to_string(),
            AdapterValue::Integer(i64::try_from(record.sign_in_count()).unwrap_or(i64::MAX)),
        ),
        (
            "current_sign_in_at".to_string(),
            record
                .current_sign_in_at()
                .map_or(AdapterValue::Null, |t| AdapterValue::String(t.to_rfc3339())),
        ),
        (
            "last_sign_in_at".to_string(),
            record
                .last_sign_in_at()
                .map_or(AdapterValue::Null, |t| AdapterValue::String(t.to_rfc3339())),
        ),
        (
            "current_sign_in_ip".to_string(),
            record
                .current_sign_in_ip()
                .map_or(AdapterValue::Null, |ip| {
                    AdapterValue::String(ip.to_string())
                }),
        ),
        (
            "last_sign_in_ip".to_string(),
            record.last_sign_in_ip().map_or(AdapterValue::Null, |ip| {
                AdapterValue::String(ip.to_string())
            }),
        ),
    ]);
    drop(
        state
            .adapter
            .update_columns(&record.to_key(), &fields)
            .await,
    );
}

/// Register the mapping's omniauth route pair (POST-only authorize plus
/// GET-or-POST callback) as an actix [`Scope`] mounted at the resolved
/// omniauth base — the same shared core spec data the axum crate
/// renders — actix-router 0.5 consumes the `{provider}` captures
/// natively, so the spec paths render verbatim.
///
/// The mapping must be omniauthable (`Module::Omniauthable`); the model
/// must implement the [`Omniauthable`] seam. Registration validates
/// Devise's dynamic-segment ban and fails with [`DeviseError::Config`]
/// for omniauthable mappings scoped under a dynamic segment.
///
/// Mount the scope BEFORE the `devise_for_users` scope (actix matches
/// top-level services in registration order; the omniauth base is the
/// longer prefix).
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
/// App::new()
///     .service(devise_omniauth_scope(omniauth_data)?)
///     .service(devise_for_users(devise_data))
/// ```
pub fn devise_omniauth_scope<M, A, L>(
    state: web::Data<OmniauthWebState<M, A, L>>,
) -> Result<Scope, DeviseError>
where
    M: FullDeviseModel + Omniauthable,
    A: OrmAdapter<M, New = <M as Omniauthable>::New> + Send + Sync + 'static,
    L: 'static,
{
    let devise = &state.devise;
    // Registration-time Config error: Devise's dynamic-segment ban.
    devise.mapping.validate_omniauth_paths()?;
    let base = devise.mapping.omniauth_base(&devise.config);
    // The route table IS the shared core spec data. actix-router 0.5
    // consumes the same `{provider}` curly-brace captures as the spec,
    // so the paths render verbatim — only the leading slash is trimmed
    // (actix matches dynamic-segment resources inside scopes only in
    // that form, verified against actix-router 0.5's resource parser).
    let specs = devise.mapping.omniauth_route_specs_for(&devise.config);
    let mut by_path: BTreeMap<String, Vec<&RouteSpec>> = BTreeMap::new();
    for spec in &specs {
        let rel = spec
            .path
            .strip_prefix(&base)
            .map_or_else(|| spec.path.clone(), str::to_string)
            .trim_start_matches('/')
            .to_string();
        by_path.entry(rel).or_default().push(spec);
    }

    let mut scope = web::scope(&base);
    for (rel, specs) in by_path {
        let mut resource = web::resource(rel);
        for spec in specs {
            resource = match spec.action.as_str() {
                "passthru" => resource.route(web::post().to(omniauth_authorize::<M, A, L>)),
                "callback" if spec.method == "GET" => {
                    resource.route(web::get().to(omniauth_callback::<M, A, L>))
                }
                "callback" => resource.route(web::post().to(omniauth_callback::<M, A, L>)),
                _ => resource,
            };
        }
        scope = scope.service(resource);
    }
    Ok(scope.app_data(state))
}

/// `POST {omniauth_base}/{provider}` — the authorize step (passthru
/// action, OMN-03 POST-only).
///
/// Builds the provider client from the app's [`OAuthProviderConfig`],
/// generates the always-on PKCE S256 pair + CSRF state (core
/// `authorize_start`, D-07), stashes verifier + state in the session,
/// and 302s to the provider URL. Unknown providers answer with the
/// Devise passthru 404.
async fn omniauth_authorize<M, A, L>(
    req: HttpRequest,
    session: Session,
    state: web::Data<OmniauthWebState<M, A, L>>,
    provider: web::Path<String>,
) -> HttpResponse
where
    M: FullDeviseModel + Omniauthable,
    A: OrmAdapter<M, New = <M as Omniauthable>::New> + Send + Sync + 'static,
    L: 'static,
{
    let provider = provider.into_inner();
    let devise = &state.devise;
    let scope = devise.mapping.name.clone();
    // Request-time provider allowlist (the route is a generic
    // `:provider` capture; Devise generates per-provider routes — the
    // port keeps one row pair and gates here).
    if !devise
        .config
        .omniauth_providers
        .iter()
        .any(|allowed| allowed == &provider)
    {
        return passthru_not_found();
    }
    let Some(provider_config) = state.providers.get(&provider) else {
        // Allowlisted but unconfigured: app misconfiguration, not a
        // client failure — 500 (never a passthru 404, which would mask
        // it).
        return internal_error();
    };

    let redirect_url = redirect_uri(&state, &req, &provider);
    // Config error on malformed provider URLs: app configuration, 500.
    let Ok(start) = authorize_start(provider_config, &redirect_url) else {
        return internal_error();
    };

    // Stash verifier + state in the session (session-only secrets —
    // never URLs, forms, or cookies; D-07/D-12).
    if session
        .insert(omniauth_state_key(&scope, &provider), start.state.clone())
        .is_err()
    {
        return internal_error();
    }
    if session
        .insert(
            omniauth_verifier_key(&scope, &provider),
            start.pkce_verifier.clone(),
        )
        .is_err()
    {
        return internal_error();
    }

    // 302 out to the provider authorize URL.
    HttpResponse::Found()
        .insert_header((actix_web::http::header::LOCATION, start.auth_url))
        .finish()
}

/// `GET|POST {omniauth_base}/{provider}/callback` — the callback step.
///
/// Re-reads the stashed state, fails closed through `verify_state` on
/// mismatch or absence (T-09-09), exchanges the code with the PKCE
/// verifier over the redirects-disabled transport (T-09-10/T-09-12),
/// fetches userinfo, builds the [`ProviderProfile`] (the auth-hash
/// role: `sub`/`uid` -> uid, `email_verified` defaulting false when the
/// vendor claim is absent, T-09-08), hands it to the app's
/// `from_omniauth` seam (D-08), and signs in through the bridge
/// renew-before-insert path cycling the session id per D-03.
async fn omniauth_callback<M, A, L>(
    req: HttpRequest,
    session: Session,
    state: web::Data<OmniauthWebState<M, A, L>>,
    provider: web::Path<String>,
    query: web::Query<HashMap<String, String>>,
    body: Option<web::Form<HashMap<String, String>>>,
) -> HttpResponse
where
    M: FullDeviseModel + Omniauthable,
    A: OrmAdapter<M, New = <M as Omniauthable>::New> + Send + Sync + 'static,
    L: 'static,
{
    let provider = provider.into_inner();
    let devise = &state.devise;
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
    let Some(provider_config) = state.providers.get(&provider) else {
        return internal_error();
    };

    // Callback params: the provider redirect carries query params (GET);
    // `OmniAuth` 2 form-posts carry them in the body. Query wins on
    // overlap (the redirect shape is authoritative).
    let mut callback_params = query.into_inner();
    if let Some(form) = body {
        for (key, value) in form.into_inner() {
            callback_params.entry(key).or_insert(value);
        }
    }
    let returned_state = callback_params.get("state").cloned();
    let code = callback_params.get("code").cloned();

    // Single-use stash: read then remove both keys on every path
    // (actix-session cookie payloads carry typed values).
    let state_key = omniauth_state_key(&scope, &provider);
    let verifier_key = omniauth_verifier_key(&scope, &provider);
    let stashed_state: Option<String> = session.get(&state_key).ok().flatten();
    let stashed_verifier: Option<String> = session.get(&verifier_key).ok().flatten();
    session.remove(&state_key);
    session.remove(&verifier_key);

    // CSRF state: `secure_compare` only; absence on either side fails
    // closed (T-09-09).
    if !verify_state(stashed_state.as_deref(), returned_state.as_deref()) {
        return omniauth_failure(&state, &provider, "Invalid state");
    }
    let (Some(code), Some(verifier)) = (code.filter(|code| !code.is_empty()), stashed_verifier)
    else {
        return omniauth_failure(&state, &provider, "Invalid credentials");
    };

    // Token exchange over the redirects-disabled transport (SSRF rule,
    // T-09-10/T-09-12). The transport comes from core so the rule cannot
    // be forgotten handler-side.
    let redirect_url = redirect_uri(&state, &req, &provider);
    let Ok(client) = basic_client(provider_config, &redirect_url) else {
        return omniauth_failure(&state, &provider, "Token exchange failed");
    };
    let Ok(http) = http_client() else {
        return omniauth_failure(&state, &provider, "Token exchange failed");
    };
    let Ok(token) = client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(PkceCodeVerifier::new(verifier))
        .request_async(&http)
        .await
    else {
        return omniauth_failure(&state, &provider, "Token exchange failed");
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
            Err(_) => return omniauth_failure(&state, &provider, "Userinfo fetch failed"),
        },
        _ => return omniauth_failure(&state, &provider, "Userinfo fetch failed"),
    };
    let Ok(claims) = serde_json::from_str::<JsonValue>(&raw_claims) else {
        return omniauth_failure(&state, &provider, "Userinfo fetch failed");
    };

    // Auth-hash build (the OmniAuth middleware role): uid from `sub` or
    // `uid`; `email_verified` defaults FALSE when the claim is absent
    // (T-09-08 — unasserted verification never links).
    let Some(uid) = claims
        .get("sub")
        .and_then(JsonValue::as_str)
        .or_else(|| claims.get("uid").and_then(JsonValue::as_str))
    else {
        return omniauth_failure(&state, &provider, "Userinfo fetch failed");
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
        return omniauth_failure(&state, &provider, "Invalid credentials");
    };

    // Warden after_set_user parity on the authentication event: lockable
    // failed-attempt reset + trackable durable shift (the same
    // bookkeeping the actix sessions controller runs).
    drop(record.reset_failed_attempts(devise.adapter.as_ref()).await);
    let peer = req
        .connection_info()
        .peer_addr()
        .map(str::to_string)
        .unwrap_or_default();
    sign_in_bookkeeping(&mut record, devise, &peer).await;

    let (key, salt) = record.session_pair();
    if insert_session_and_renew_sync(&session, &scope, &key, &salt).is_err() {
        return internal_error();
    }
    rotate_csrf_token(&session, &scope, &devise.config);

    // Success: the devise.omniauth_callbacks.success flash with the
    // camelize'd kind, redirecting to the stored location or root.
    let target = after_sign_in_target(&session, &scope);
    let message = success_message(&omniauth_kind(&provider));
    omniauth_flash_redirect(&target, &message)
}
