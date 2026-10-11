//! Omniauthable module - generic `OAuth2` provider wiring, always-on PKCE plus
//! state, and the provider profile handoff (OMN-01/OMN-02 core).
//!
//! Mirrors `devise/lib/devise/models/omniauthable.rb` plus
//! `devise/lib/devise/omniauth/config.rb`: apps register generic provider
//! endpoints per provider name (D-05 - core ships no vendor presets) and the
//! authorize machinery is generic over any compliant `OAuth2` provider.
//!
//! Security invariants (locked with the phase threat model):
//!
//! * PKCE (S256) and a random CSRF `state` are generated for EVERY authorize
//!   attempt - there is no opt-out parameter anywhere on this path (D-07).
//! * The `state` comparison runs through
//!   [`secure_compare`](crate::crypto::secure_compare) only; the oauth2
//!   `CsrfToken` deliberately has no `PartialEq`, so a timing oracle cannot
//!   compile in (T-09-09).
//! * Provider endpoint URLs come from app configuration
//!   ([`OAuthProviderConfig`]), never from request params (T-09-10); the
//!   token-exchange HTTP client disables redirects (SSRF rule).
//! * OAuth access and refresh tokens live in the session for the duration of
//!   the requesting flow and never reach the database; only the identity pair
//!   (`provider` + `uid`) persists (D-12, T-09-10).
//!
//! == Options
//!
//! Omniauthable adds the `omniauth_providers` option (the provider-name
//! allowlist checked at request time by the framework handlers) to
//! [`DeviseConfig`](crate::config::DeviseConfig), mirroring Devise's
//! `devise :omniauthable, omniauth_providers: [...]`.
//!
//! == Examples
//!
//! ```ignore
//! use devise_rust::omniauthable::{OAuthProviderConfig, authorize_start, verify_state};
//!
//! let config = OAuthProviderConfig {
//!     client_id: "client-id".to_string(),
//!     client_secret: "client-secret".to_string(),
//!     auth_url: "https://provider.example.com/oauth/authorize".to_string(),
//!     token_url: "https://provider.example.com/oauth/token".to_string(),
//!     userinfo_url: "https://provider.example.com/oauth/userinfo".to_string(),
//!     scopes: vec!["openid".to_string(), "email".to_string()],
//! };
//! let start = authorize_start(&config, "https://app.example.com/users/auth/stub/callback").unwrap();
//! // Stash `start.state` + `start.pkce_verifier` in the session, then 302 to
//! // `start.auth_url`; on callback compare through verify_state.
//! assert!(!verify_state(Some(&start.state), Some("tampered")));
//! ```

use crate::crypto::secure_compare;
use crate::error::DeviseError;
use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, ClientId, ClientSecret, CsrfToken, EndpointNotSet, EndpointSet, PkceCodeChallenge,
    RedirectUrl, Scope, TokenUrl,
};
use serde::{Deserialize, Serialize};

/// The `oauth2` crate's reqwest re-export, namespaced behind this module.
///
/// The reqwest major stays coupled to the oauth2 line here instead of leaking
/// into a top-level crate dependency: public signatures reference
/// `omniauthable::reqwest::Client`, never a bare top-level `reqwest`.
pub use oauth2::reqwest;

/// Column holding the provider name on omniauthable models (D-11).
pub const PROVIDER_COLUMN: &str = "provider";

/// Column holding the provider-unique account id (D-11).
pub const UID_COLUMN: &str = "uid";

/// Required model fields for Omniauthable.
///
/// Devise's own `Omniauthable.required_fields` returns `[]` because the gem
/// leaves the identity columns to the host app; this port ships them as part
/// of the module contract (D-11): the migration generator emits exactly this
/// pair for the omniauthable block, and the default linking policy reads and
/// writes both columns.
///
/// == Examples
///
/// ```
/// use devise_rust::omniauthable::required_fields;
///
/// assert_eq!(required_fields(), vec!["provider", "uid"]);
/// ```
#[must_use]
pub fn required_fields() -> Vec<&'static str> {
    vec![PROVIDER_COLUMN, UID_COLUMN]
}

/// Generic `OAuth2` provider endpoints and credentials, one per provider name
/// (D-05). Core ships no vendor presets: every field comes from app
/// configuration, and any compliant `OAuth2` provider can be wired by filling
/// this struct.
///
/// Provider endpoint URLs travel ONLY through this config (never from
/// request params), so the token exchange and userinfo fetch hit
/// allowlisted URLs (T-09-10).
///
/// == Options
///
/// * `client_id` / `client_secret` - credentials issued by the provider.
/// * `auth_url` - authorization endpoint the browser is redirected to.
/// * `token_url` - token exchange endpoint (POST, redirects disabled).
/// * `userinfo_url` - identity claims endpoint fetched with the access token.
/// * `scopes` - OAuth scopes requested on every authorize attempt.
///
/// == Examples
///
/// ```
/// use devise_rust::omniauthable::OAuthProviderConfig;
///
/// let config = OAuthProviderConfig {
///     client_id: "id".to_string(),
///     client_secret: "secret".to_string(),
///     auth_url: "https://provider.example.com/authorize".to_string(),
///     token_url: "https://provider.example.com/token".to_string(),
///     userinfo_url: "https://provider.example.com/userinfo".to_string(),
///     scopes: vec!["email".to_string()],
/// };
/// let json = serde_json::to_string(&config).unwrap();
/// let round: OAuthProviderConfig = serde_json::from_str(&json).unwrap();
/// assert_eq!(round.client_id, "id");
/// assert_eq!(round.scopes, vec!["email".to_string()]);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthProviderConfig {
    /// `OAuth2` client id issued by the provider.
    pub client_id: String,
    /// `OAuth2` client secret issued by the provider.
    pub client_secret: String,
    /// Provider authorization endpoint (app config, never request params).
    pub auth_url: String,
    /// Provider token exchange endpoint (app config, never request params).
    pub token_url: String,
    /// Provider userinfo endpoint fetched with the access token.
    pub userinfo_url: String,
    /// OAuth scopes requested on every authorize attempt for this provider.
    pub scopes: Vec<String>,
}

/// The provider identity pair plus claims handed to the model seam.
///
/// The vendor userinfo JSON is untrusted input (T-09-08): `email_verified`
/// defaults to `false` when the claim is absent, so the default linking policy
/// never links on an unasserted email. `raw_claims` carries the unmodified
/// vendor payload for app-side use and is never persisted.
///
/// == Examples
///
/// ```
/// use devise_rust::omniauthable::ProviderProfile;
///
/// let json = r#"{ "provider": "stub", "uid": "42" }"#;
/// let profile: ProviderProfile = serde_json::from_str(json).unwrap();
/// assert_eq!(profile.provider, "stub");
/// assert_eq!(profile.uid, "42");
/// // Absent email_verified defaults to false - unverified by construction.
/// assert!(!profile.email_verified);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderProfile {
    /// Provider name as registered in `omniauth_providers` (e.g. "github").
    pub provider: String,
    /// Provider-unique account id (`OmniAuth`'s `uid`).
    pub uid: String,
    /// Email the provider asserts for the account, when present.
    #[serde(default)]
    pub email: Option<String>,
    /// Whether the provider VERIFIED the email (D-10 gate).
    ///
    /// Defaults to `false` when the vendor claim is absent.
    #[serde(default)]
    pub email_verified: bool,
    /// Display name, when the provider carries one.
    #[serde(default)]
    pub name: Option<String>,
    /// Raw vendor userinfo claims, unmodified (never persisted).
    #[serde(default)]
    pub raw_claims: serde_json::Value,
}

/// A fully typestated oauth2 `BasicClient`: authorization AND token endpoints
/// are set, so `authorize_url` and `exchange_code` are callable without any
/// runtime missing-endpoint check.
pub type OmniauthClient = BasicClient<
    EndpointSet,    // HasAuthUrl
    EndpointNotSet, // HasDeviceAuthUrl
    EndpointNotSet, // HasIntrospectionUrl
    EndpointNotSet, // HasRevocationUrl
    EndpointSet,    // HasTokenUrl
>;

/// Build the typestated [`OmniauthClient`] from a provider config.
///
/// Auth, token, and redirect endpoints are set through the oauth2 typestate
/// builder, so a client missing either endpoint cannot exist: the endpoint
/// methods (`authorize_url`, `exchange_code`) are only implemented once the
/// builder has set the corresponding URL, and missing endpoints fail at
/// compile time.
///
/// # Errors
///
/// Returns [`DeviseError::Config`] when any configured URL fails to parse.
///
/// == Examples
///
/// ```
/// use devise_rust::omniauthable::{OAuthProviderConfig, basic_client};
/// use oauth2::AuthorizationCode;
///
/// let config = OAuthProviderConfig {
///     client_id: "id".to_string(),
///     client_secret: "secret".to_string(),
///     auth_url: "https://provider.example.com/authorize".to_string(),
///     token_url: "https://provider.example.com/token".to_string(),
///     userinfo_url: "https://provider.example.com/userinfo".to_string(),
///     scopes: vec![],
/// };
/// let client = basic_client(&config, "https://app.example.com/callback").unwrap();
/// // Compiles only because the token endpoint is set (typestate proof).
/// let _request = client.exchange_code(AuthorizationCode::new("code".to_string()));
/// ```
#[must_use = "building the client without using it discards the parsed endpoints"]
pub fn basic_client(
    config: &OAuthProviderConfig,
    redirect_url: &str,
) -> Result<OmniauthClient, DeviseError> {
    let auth_url = AuthUrl::new(config.auth_url.clone())
        .map_err(|e| DeviseError::Config(format!("omniauthable: invalid auth_url: {e}")))?;
    let token_url = TokenUrl::new(config.token_url.clone())
        .map_err(|e| DeviseError::Config(format!("omniauthable: invalid token_url: {e}")))?;
    let redirect = RedirectUrl::new(redirect_url.to_string())
        .map_err(|e| DeviseError::Config(format!("omniauthable: invalid redirect_url: {e}")))?;
    Ok(BasicClient::new(ClientId::new(config.client_id.clone()))
        .set_client_secret(ClientSecret::new(config.client_secret.clone()))
        .set_auth_uri(auth_url)
        .set_token_uri(token_url)
        .set_redirect_uri(redirect))
}

/// One authorize attempt: the redirect target plus the two session-stashed
/// secrets.
///
/// `state` and `pkce_verifier` are raw secrets: stash both in the SESSION
/// (never URLs, forms, or cookies), and compare the returned `state` on
/// callback through [`verify_state`].
#[derive(Debug, Clone)]
pub struct AuthorizeStart {
    /// Full provider authorize URL to redirect the browser to (302 target).
    pub auth_url: String,
    /// Raw CSRF state token - stash in the session, compare on callback.
    pub state: String,
    /// Raw PKCE verifier - stash in the session; the challenge rides the URL.
    pub pkce_verifier: String,
}

/// Start an authorize attempt with PKCE (S256) and CSRF state ALWAYS ON.
///
/// There is no parameter to disable either (D-07): the S256 challenge plus
/// verifier pair and the random CSRF token are generated on every call, the
/// challenge and state ride the authorize URL, and the verifier plus state
/// come back for session stashing.
///
/// # Errors
///
/// Propagates [`basic_client`]'s [`DeviseError::Config`] when a configured URL
/// fails to parse.
///
/// == Examples
///
/// ```
/// use devise_rust::omniauthable::{OAuthProviderConfig, authorize_start};
///
/// let config = OAuthProviderConfig {
///     client_id: "id".to_string(),
///     client_secret: "secret".to_string(),
///     auth_url: "https://provider.example.com/authorize".to_string(),
///     token_url: "https://provider.example.com/token".to_string(),
///     userinfo_url: "https://provider.example.com/userinfo".to_string(),
///     scopes: vec!["email".to_string()],
/// };
/// let start = authorize_start(&config, "https://app.example.com/callback").unwrap();
/// assert!(start.auth_url.contains("code_challenge_method=S256"));
/// assert!(start.auth_url.contains("state="));
/// assert!(start.pkce_verifier.len() >= 43); // RFC 7636 minimum
/// ```
#[must_use = "discarding an authorize start loses the session-stashed secrets"]
pub fn authorize_start(
    config: &OAuthProviderConfig,
    redirect_url: &str,
) -> Result<AuthorizeStart, DeviseError> {
    let client = basic_client(config, redirect_url)?;
    // Always-on (D-07): no code path constructs an authorize URL without both.
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (auth_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        .add_scopes(config.scopes.iter().cloned().map(Scope::new))
        .set_pkce_challenge(pkce_challenge)
        .url();
    Ok(AuthorizeStart {
        auth_url: auth_url.to_string(),
        state: csrf_state.secret().clone(),
        pkce_verifier: pkce_verifier.secret().clone(),
    })
}

/// Async HTTP client for the token exchange and userinfo fetch.
///
/// Redirects are disabled (`Policy::none()`): the oauth2 crate's documented
/// SSRF rule - a malicious or misconfigured provider must not be able to
/// bounce the token exchange or userinfo fetch onto an arbitrary URL.
///
/// # Errors
///
/// Returns [`DeviseError::Internal`] when the underlying client fails to
/// build (TLS backend initialization failure).
///
/// == Examples
///
/// ```
/// assert!(devise_rust::omniauthable::http_client().is_ok());
/// ```
pub fn http_client() -> Result<reqwest::Client, DeviseError> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| DeviseError::Internal(format!("omniauthable: http client build failed: {e}")))
}

/// Compare the callback's returned `state` with the session-stashed state.
///
/// The only comparison is [`secure_compare`](crate::crypto::secure_compare)
/// (constant time); absence on either side fails closed - a callback that
/// arrives without a stashed state (session cookie withheld, direct hit) or
/// without a returned `state` never passes (T-09-09).
///
/// == Examples
///
/// ```
/// use devise_rust::omniauthable::verify_state;
///
/// assert!(verify_state(Some("stashed"), Some("stashed")));
/// assert!(!verify_state(Some("stashed"), Some("tampered")));
/// // Absent on either side fails closed.
/// assert!(!verify_state(None, Some("stashed")));
/// assert!(!verify_state(Some("stashed"), None));
/// ```
#[must_use]
pub fn verify_state(stashed_state: Option<&str>, returned_state: Option<&str>) -> bool {
    match (stashed_state, returned_state) {
        (Some(stashed), Some(returned)) => secure_compare(stashed, returned),
        (None, _) | (_, None) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stub_provider_config() -> OAuthProviderConfig {
        OAuthProviderConfig {
            client_id: "client-id".to_string(),
            client_secret: "client-secret".to_string(),
            auth_url: "https://provider.example.com/oauth/authorize".to_string(),
            token_url: "https://provider.example.com/oauth/token".to_string(),
            userinfo_url: "https://provider.example.com/oauth/userinfo".to_string(),
            scopes: vec!["openid".to_string(), "email".to_string()],
        }
    }

    #[test]
    fn omniauthable_required_fields_list_provider_and_uid() {
        assert_eq!(required_fields(), vec!["provider", "uid"]);
    }

    #[test]
    fn omniauthable_provider_config_serde_roundtrip() {
        let config = stub_provider_config();
        let json = serde_json::to_string(&config).expect("config serializes");
        let round: OAuthProviderConfig = serde_json::from_str(&json).expect("config deserializes");
        assert_eq!(round, config);
        assert_eq!(
            round.scopes,
            vec!["openid".to_string(), "email".to_string()]
        );
    }

    #[test]
    fn omniauthable_profile_email_verified_defaults_false_when_absent() {
        let json = r#"{ "provider": "stub", "uid": "42", "email": "user@example.com" }"#;
        let profile: ProviderProfile = serde_json::from_str(json).expect("profile parses");
        assert_eq!(profile.provider, "stub");
        assert_eq!(profile.uid, "42");
        assert_eq!(profile.email.as_deref(), Some("user@example.com"));
        // Absent email_verified claim defaults to false: untrusted vendors
        // cannot assert verification by omission (T-09-08).
        assert!(!profile.email_verified);
        assert_eq!(profile.name, None);
    }

    #[test]
    fn omniauthable_authorize_start_always_carries_pkce_and_state() {
        let config = stub_provider_config();
        let start = authorize_start(&config, "https://app.example.com/users/auth/stub/callback")
            .expect("authorize start builds");

        // PKCE S256 is on the URL with no opt-out anywhere (D-07).
        assert!(start.auth_url.contains("code_challenge="));
        assert!(start.auth_url.contains("code_challenge_method=S256"));
        // CSRF state is on the URL and returned for session stashing.
        assert!(start.auth_url.contains("state="));
        // App-configured endpoints and params ride the URL.
        assert!(start.auth_url.contains("client_id=client-id"));
        assert!(start.auth_url.contains("response_type=code"));
        assert!(start.auth_url.contains(
            "redirect_uri=https%3A%2F%2Fapp.example.com%2Fusers%2Fauth%2Fstub%2Fcallback"
        ));
        assert!(start.auth_url.contains("scope=openid+email"));
        // RFC 7636: the verifier is at least 43 chars.
        assert!(start.pkce_verifier.len() >= 43);

        // Two attempts never share state or verifier (fresh randomness).
        let second = authorize_start(&config, "https://app.example.com/users/auth/stub/callback")
            .expect("second start builds");
        assert_ne!(start.state, second.state);
        assert_ne!(start.pkce_verifier, second.pkce_verifier);
    }

    #[test]
    fn omniauthable_verify_state_mismatch_fails_closed() {
        assert!(verify_state(Some("stashed-state"), Some("stashed-state")));
        assert!(!verify_state(Some("stashed-state"), Some("tampered-state")));
        // Absent on either side never passes (T-09-09).
        assert!(!verify_state(None, Some("stashed-state")));
        assert!(!verify_state(Some("stashed-state"), None));
        assert!(!verify_state(None, None));
        // Length mismatch never panics and never leaks through.
        assert!(!verify_state(
            Some("short"),
            Some("a-much-longer-returned-state")
        ));
    }

    #[test]
    fn omniauthable_basic_client_rejects_malformed_urls() {
        let mut config = stub_provider_config();
        config.auth_url = "not-a-url".to_string();
        let err = basic_client(&config, "https://app.example.com/callback")
            .expect_err("malformed auth_url must fail");
        assert!(matches!(err, DeviseError::Config(_)));
        assert!(err.to_string().contains("auth_url"));

        let mut config = stub_provider_config();
        config.token_url = "also not a url".to_string();
        let err = basic_client(&config, "https://app.example.com/callback")
            .expect_err("malformed token_url must fail");
        assert!(err.to_string().contains("token_url"));

        let err = authorize_start(&stub_provider_config(), "::bad redirect::")
            .expect_err("malformed redirect_url must fail");
        assert!(err.to_string().contains("redirect_url"));
    }

    #[test]
    fn omniauthable_config_providers_default_empty_and_override_resolves() {
        use crate::config::{DeviseConfig, DeviseConfigOverride};

        // Devise default: no providers registered (empty allowlist, fail closed).
        assert!(DeviseConfig::default().omniauth_providers.is_empty());

        // Per-scope override resolves over the global, mirroring every other
        // DeviseConfig option.
        let global = DeviseConfig::default();
        let r#override = DeviseConfigOverride {
            omniauth_providers: Some(vec!["github".to_string(), "stub".to_string()]),
            ..DeviseConfigOverride::default()
        };
        let resolved = r#override.resolve(&global);
        assert_eq!(
            resolved.omniauth_providers,
            vec!["github".to_string(), "stub".to_string()]
        );
    }
}
