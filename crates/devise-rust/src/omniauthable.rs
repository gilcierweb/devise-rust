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
//!   [`secure_compare`] only; the oauth2
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
//! == The model seam
//!
//! [`Omniauthable`] carries the REQUIRED [`from_omniauth`](Omniauthable::from_omniauth)
//! method (D-08): the Devise convention `User.from_omniauth(auth)` where the
//! app owns the handoff. The core DEFAULT policy
//! ([`default_from_omniauth`]) implements find-by-identity, link on VERIFIED
//! email only, else create (D-09/D-10); apps override by writing their own
//! trait method body.
//!
//! Super-chain position: third, after `DatabaseAuthenticatable` and
//! `Rememberable` (`database_authenticatable -> rememberable -> omniauthable
//! -> ...` from `devise/lib/devise/modules.rb`).
//!
//! == Token contract (D-12)
//!
//! OAuth access and refresh tokens live in the SESSION for the duration of
//! the requesting flow only; the trait never receives them and they never
//! reach the database. Only the identity pair (`provider` + `uid`)
//! persists; [`ProviderProfile`] carries the identity pair plus display
//! claims, never tokens.
//!
//! == Examples
//!
//! ```ignore
//! // Ignored doctest: requires a live adapter and an async runtime; the compiled equivalent lives in the crate tests and the example apps.
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

use crate::adapter::{Conditions, OrmAdapter, OrmError, Value};
use crate::confirmable::Confirmable;
use crate::crypto::secure_compare;
use crate::error::{DeviseError, ResourceWithErrors, ValidationErrors};
use crate::failure::AnyDeviseModel;
use crate::model::Authenticatable;
use crate::time::Clock;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, ClientId, ClientSecret, CsrfToken, EndpointNotSet, EndpointSet, PkceCodeChallenge,
    RedirectUrl, Scope, TokenUrl,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
/// The only comparison is [`secure_compare`]
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

/// The `Omniauthable` model module - the `from_omniauth` seam (D-08).
///
/// Devise's convention is `User.from_omniauth(request.env["omniauth.auth"])`:
/// the app owns the handoff. Core mirrors this as a REQUIRED trait method
/// with no default body - router-registered callback closures are rejected
/// by design. Apps wanting Devise's standard behavior delegate to
/// [`default_from_omniauth`], which implements find-by-identity, link on
/// VERIFIED email only, else create (D-09/D-10).
///
/// Super-chain position: third, after `DatabaseAuthenticatable` and
/// `Rememberable` (`database_authenticatable -> rememberable ->
/// omniauthable -> ...` from `devise/lib/devise/modules.rb`).
///
/// == Options
///
/// * `omniauth_providers` (config) - the provider-name allowlist the
///   framework handlers check at request time.
///
/// == Examples
///
/// ```ignore
/// // Ignored doctest: requires a live adapter and an async runtime; the compiled equivalent lives in the crate tests and the example apps.
/// #[async_trait]
/// impl Omniauthable for User {
///     type New = NewUser;
///
///     async fn from_omniauth<A>(
///         profile: ProviderProfile,
///         adapter: &A,
///         clock: &dyn Clock,
///     ) -> ResourceWithErrors<Self>
///     where
///         Self: Sized,
///         A: OrmAdapter<Self, New = Self::New> + Send + Sync,
///     {
///         default_from_omniauth(adapter, &profile, &crate::config::DeviseConfig::default(), clock).await
///     }
///
///     fn new_from_profile(profile: &ProviderProfile, now: DateTime<Utc>) -> Self::New {
///         NewUser {
///             email: profile.email.clone().unwrap_or_default(),
///             provider: Some(profile.provider.clone()),
///             uid: Some(profile.uid.clone()),
///             name: profile.name.clone(),
///             created_at: Some(now),
///         }
///     }
/// }
/// ```
#[async_trait]
pub trait Omniauthable: Authenticatable {
    /// The insert shape [`default_from_omniauth`] persists on the create
    /// path - the same `New` type the app's
    /// [`OrmAdapter`] consumes.
    type New: Send + Sync + 'static;

    /// Devise's `from_omniauth` seam (REQUIRED - no default body, D-08).
    ///
    /// Returns the record-with-errors flow value the other modules use
    /// ([`ResourceWithErrors`]), never a bare `Option`: an empty `errors`
    /// set means the record is ready to sign in, a populated one means the
    /// caller renders the failure path.
    ///
    /// Adapter lookup/persist errors propagate as [`DeviseError`] (WR-05) so
    /// transient backend failures surface as 500 instead of minting duplicate
    /// identities.
    ///
    /// == Token contract (D-12)
    ///
    /// This method NEVER receives access or refresh tokens: they live in
    /// the session for the requesting flow only and never reach the model
    /// or the database. [`ProviderProfile`] carries only the identity pair
    /// plus display claims.
    async fn from_omniauth<A>(
        profile: ProviderProfile,
        adapter: &A,
        clock: &dyn Clock,
    ) -> Result<ResourceWithErrors<Self>, DeviseError>
    where
        Self: Sized,
        A: OrmAdapter<Self, New = Self::New> + Send + Sync;

    /// Build the insert shape for a new identity row (the create path of
    /// [`default_from_omniauth`]).
    ///
    /// `now` is the flow's authoritative instant from `clock`, so created
    /// rows stamp `created_at` consistently regardless of backend
    /// auto-stamping.
    fn new_from_profile(profile: &ProviderProfile, now: DateTime<Utc>) -> Self::New;

    /// Normalize an incoming profile before the policy runs (defaulted hook).
    ///
    /// Override to downcase emails, trim whitespace, or map vendor-specific
    /// claim shapes. [`default_from_omniauth`] runs the profile through
    /// this hook first.
    #[must_use]
    fn normalize_profile(profile: ProviderProfile) -> ProviderProfile {
        profile
    }
}

/// Core DEFAULT find-link-create policy (D-09) behind the verified gate (D-10).
///
/// 1. Look up `find_first` on `(provider, uid)` and return the row on hit.
/// 2. Else look up `find_first` on email: when the profile asserts
///    `email_verified` true, persist `provider` + `uid` onto the row and
///    return it. When the email is unverified - or the claim is absent,
///    which deserializes to `false` - linking is skipped entirely and a new
///    row is created: unverified provider emails NEVER link to an existing
///    account (T-09-08 security boundary, not a nicety).
/// 3. When no email row exists, create a new row with provider, uid,
///    email, and name via [`Omniauthable::new_from_profile`].
///
/// Adapter lookup failures propagate as [`DeviseError`] (WR-05) so callers
/// never swallow transient backend errors as "not found" and mint duplicate
/// identities. Persist failures return the best available record with errors,
/// so callers render the failure path instead of signing in.
///
/// # Errors
///
/// Returns [`DeviseError::Adapter`] when the identity lookup or the
/// verified-email lookup fails; the create/update persist path keeps
/// returning the record-with-errors shape instead of an error.
///
/// == Examples
///
/// ```ignore
/// // Ignored doctest: requires a live adapter and an async runtime; the compiled equivalent lives in the crate tests and the example apps.
/// let outcome = default_from_omniauth(&adapter, &profile, &config, &clock).await?;
/// if outcome.is_valid() {
///     proxy.set_user("user", Some(Box::new(outcome.record)), SetUserOpts {
///         event: SetUserEvent::Authentication, ..SetUserOpts::default()
///     }).await?;
/// }
/// ```
pub async fn default_from_omniauth<M, A>(
    adapter: &A,
    profile: &ProviderProfile,
    config: &crate::config::DeviseConfig,
    clock: &dyn Clock,
) -> Result<ResourceWithErrors<M>, DeviseError>
where
    M: Omniauthable + Default + Sized + Send + Sync + 'static,
    A: OrmAdapter<M, New = <M as Omniauthable>::New> + Send + Sync,
{
    let mut profile = M::normalize_profile(profile.clone());

    // Devise routes EVERY credential source through the parameter filter
    // (`authenticatable.rb:267-269` + `downcase_keys`): a provider asserting
    // `User@Example.COM` must link to the stored `user@example.com`, not
    // fall through to create-new and mint a duplicate account.
    if let Some(email) = profile.email.as_deref() {
        profile.email = Some(crate::model::normalize_credential_value(
            email,
            "email",
            &config.case_insensitive_keys,
            &config.strip_whitespace_keys,
        ));
    }

    // 1. Existing identity pair: return the row untouched.
    let mut identity = Conditions::new();
    identity.insert(PROVIDER_COLUMN, profile.provider.as_str());
    identity.insert(UID_COLUMN, profile.uid.as_str());
    if let Some(record) = adapter
        .find_first(&identity)
        .await
        .map_err(DeviseError::Adapter)?
    {
        return Ok(ResourceWithErrors::new(record, ValidationErrors::new()));
    }

    // 2. Email collision: link ONLY on a provider-asserted verified email.
    if let Some(email) = profile.email.as_deref() {
        let mut by_email = Conditions::new();
        by_email.insert("email", email);
        if let Some(existing) = adapter
            .find_first(&by_email)
            .await
            .map_err(DeviseError::Adapter)?
        {
            if profile.email_verified {
                let mut fields = HashMap::new();
                fields.insert(
                    PROVIDER_COLUMN.to_string(),
                    Value::from(profile.provider.as_str()),
                );
                fields.insert(UID_COLUMN.to_string(), Value::from(profile.uid.as_str()));
                if let Ok(linked) = adapter.update_columns(&existing.to_key(), &fields).await {
                    return Ok(ResourceWithErrors::new(linked, ValidationErrors::new()));
                }
                // The row stays unlinked; the caller sees the errors.
                let mut errors = ValidationErrors::new();
                errors.add(PROVIDER_COLUMN, ":invalid");
                return Ok(ResourceWithErrors::new(existing, errors));
            }
            // Unverified: fall through to create-new. NEVER link (T-09-08).
        }
    }

    // 3. Create the new identity row.
    let new = M::new_from_profile(&profile, clock.now());
    match adapter.create(new).await {
        Ok(created) => Ok(ResourceWithErrors::new(created, ValidationErrors::new())),
        Err(orm_error) => {
            let mut errors = ValidationErrors::new();
            if matches!(orm_error, OrmError::UniqueViolation { .. }) {
                errors.add("email", ":taken");
            } else {
                errors.add(PROVIDER_COLUMN, ":invalid");
            }
            Ok(ResourceWithErrors::new(M::default(), errors))
        }
    }
}

/// Devise's canonical `from_omniauth` pattern for provider-verified
/// identities: `skip_confirmation!` when the provider asserts the email is
/// verified.
///
/// The port's default policy links an identity onto an existing row ONLY
/// for verified emails (`default_from_omniauth` step 2), and the same
/// trust level must apply to NEW rows: a verified new identity is
/// confirmed on creation, an unverified one stays pending (the core
/// activatable gate then blocks its sign-in until the user confirms).
/// Applications call this from their own `from_omniauth` right after
/// [`default_from_omniauth`] - one home for the rule, so fixtures and the
/// example apps never hand-roll it.
///
/// Returns `true` when the record was confirmed (and persisted).
///
/// # Errors
///
/// `DeviseError::Adapter` when the confirmation write fails.
pub async fn confirm_verified_identity<A, M>(
    record: &mut M,
    profile: &ProviderProfile,
    adapter: &A,
    clock: &dyn Clock,
) -> Result<bool, DeviseError>
where
    A: OrmAdapter<M> + Send + Sync,
    M: Confirmable + AnyDeviseModel + Sync,
{
    if !profile.email_verified || record.confirmed() {
        return Ok(false);
    }
    let now = clock.now();
    record.set_confirmed_at(Some(now));
    let fields = HashMap::from([("confirmed_at".to_string(), Value::String(now.to_rfc3339()))]);
    adapter
        .update_columns(&record.to_key(), &fields)
        .await
        .map_err(DeviseError::Adapter)?;
    Ok(true)
}

/// `devise.omniauth_callbacks.failure` flash text.
///
/// Mirrors the Devise callbacks controller's
/// `set_flash_message! :alert, :failure, kind: ..., reason: ...` with the
/// vendored en.yml copy: `Could not authenticate you from %{kind} because
/// "%{reason}".`
///
/// == Examples
///
/// ```
/// use devise_rust::omniauthable::failure_message;
///
/// assert_eq!(
///     failure_message("GitHub", "Invalid credentials"),
///     "Could not authenticate you from GitHub because \"Invalid credentials\"."
/// );
/// ```
#[must_use]
pub fn failure_message(kind: &str, reason: &str) -> String {
    crate::i18n::translate(
        "devise.omniauth_callbacks.failure",
        &[("kind", kind), ("reason", reason)],
    )
}

/// `devise.omniauth_callbacks.success` flash text.
///
/// Mirrors the callbacks controller's success flash with the vendored
/// en.yml copy: `Successfully authenticated from %{kind} account.`
///
/// == Examples
///
/// ```
/// use devise_rust::omniauthable::success_message;
///
/// assert_eq!(
///     success_message("GitHub"),
///     "Successfully authenticated from GitHub account."
/// );
/// ```
#[must_use]
pub fn success_message(kind: &str) -> String {
    crate::i18n::translate("devise.omniauth_callbacks.success", &[("kind", kind)])
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
        assert_eq!(DeviseConfig::default().omniauth_providers.len(), 0);

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

    // ========================================================================
    // Default linking-policy matrix (D-09/D-10) over the MemoryAdapter oracle
    // ========================================================================

    use crate::adapter::DeviseKey;
    use crate::adapter::memory::MemoryAdapter;
    use crate::failure::AnyDeviseModel;
    use crate::hooks::{HookRegistry, register_devise_hooks};
    use crate::proxy::{AuthProxy, SetUserEvent, SetUserOpts};
    use crate::scope::{Mapping, Module, PathNames, SignOutVia};
    use crate::session::{SessionStore, keys};
    use crate::time::FixedClock;
    use chrono::TimeZone;

    /// Identity-carrying test model: the omniauthable column surface plus the
    /// `database_authenticatable` pair.
    #[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
    struct OmniUser {
        id: i64,
        email: String,
        encrypted_password: String,
        provider: Option<String>,
        uid: Option<String>,
        name: Option<String>,
        created_at: Option<DateTime<Utc>>,
    }

    impl AnyDeviseModel for OmniUser {
        fn to_key(&self) -> DeviseKey {
            DeviseKey::from_i64(self.id)
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    impl Authenticatable for OmniUser {}

    #[async_trait]
    impl Omniauthable for OmniUser {
        type New = OmniUser;

        // D-08: the required seam - apps delegate to the default policy.
        async fn from_omniauth<A>(
            profile: ProviderProfile,
            adapter: &A,
            clock: &dyn Clock,
        ) -> Result<ResourceWithErrors<Self>, DeviseError>
        where
            Self: Sized,
            A: OrmAdapter<Self, New = Self::New> + Send + Sync,
        {
            default_from_omniauth(
                adapter,
                &profile,
                &crate::config::DeviseConfig::default(),
                clock,
            )
            .await
        }

        fn new_from_profile(profile: &ProviderProfile, now: DateTime<Utc>) -> Self::New {
            OmniUser {
                id: 0,
                email: profile.email.clone().unwrap_or_default(),
                encrypted_password: String::new(),
                provider: Some(profile.provider.clone()),
                uid: Some(profile.uid.clone()),
                name: profile.name.clone(),
                created_at: Some(now),
            }
        }
    }

    fn omni_profile(email: Option<&str>, email_verified: bool) -> ProviderProfile {
        ProviderProfile {
            provider: "stub".to_string(),
            uid: "uid-42".to_string(),
            email: email.map(ToString::to_string),
            email_verified,
            name: Some("Stub User".to_string()),
            raw_claims: serde_json::json!({ "sub": "uid-42" }),
        }
    }

    async fn seed_row(adapter: &MemoryAdapter<OmniUser>, email: &str) {
        // The MemoryAdapter oracle assigns synthetic storage keys 1, 2, ... in
        // create order and returns the model unchanged; mirroring the key in
        // the fixture id keeps `to_key()` resolvable (real backends return
        // the DB-assigned id from the adapter, so no alignment is needed).
        adapter
            .create(OmniUser {
                id: 1,
                email: email.to_string(),
                encrypted_password: "$2a$12$seededhash".to_string(),
                provider: None,
                uid: None,
                name: None,
                created_at: None,
            })
            .await
            .expect("seed row");
    }

    fn test_config() -> crate::config::DeviseConfig {
        crate::config::DeviseConfig {
            secret_key: "test-secret-key".to_string(),
            ..crate::config::DeviseConfig::default()
        }
    }

    #[tokio::test]
    async fn omniauthable_policy_returns_existing_identity_row() {
        let adapter = MemoryAdapter::<OmniUser>::new();
        // A row already carrying this exact identity pair.
        adapter
            .create(OmniUser {
                id: 0,
                email: "known@example.com".to_string(),
                encrypted_password: String::new(),
                provider: Some("stub".to_string()),
                uid: Some("uid-42".to_string()),
                name: None,
                created_at: None,
            })
            .await
            .expect("seed identity row");

        let clock = FixedClock::new(Utc.timestamp_opt(1_700_000_000, 0).unwrap());
        let outcome: ResourceWithErrors<OmniUser> = default_from_omniauth(
            &adapter,
            &omni_profile(Some("known@example.com"), true),
            &test_config(),
            &clock,
        )
        .await
        .expect("from_omniauth");

        assert!(outcome.is_valid());
        assert_eq!(outcome.record.email, "known@example.com");
        assert_eq!(outcome.record.provider.as_deref(), Some("stub"));
        assert_eq!(outcome.record.uid.as_deref(), Some("uid-42"));
        // Hit path: the row under the identity pair is the seeded one, not a
        // second row minted by the policy.
        let mut identity = Conditions::new();
        identity.insert(PROVIDER_COLUMN, "stub");
        identity.insert(UID_COLUMN, "uid-42");
        let stored = adapter
            .find_first(&identity)
            .await
            .expect("store readable")
            .expect("identity row");
        assert_eq!(stored.email, "known@example.com");
        assert_eq!(stored.provider.as_deref(), Some("stub"));
    }

    #[tokio::test]
    async fn omniauthable_policy_links_verified_email_collision() {
        let adapter = MemoryAdapter::<OmniUser>::new();
        seed_row(&adapter, "user@example.com").await;

        let clock = FixedClock::new(Utc.timestamp_opt(1_700_000_000, 0).unwrap());
        let outcome: ResourceWithErrors<OmniUser> = default_from_omniauth(
            &adapter,
            &omni_profile(Some("user@example.com"), true),
            &test_config(),
            &clock,
        )
        .await
        .expect("from_omniauth");

        assert!(outcome.is_valid());
        // The pre-existing row now carries the identity pair.
        let mut by_email = Conditions::new();
        by_email.insert("email", "user@example.com");
        let row = adapter
            .find_first(&by_email)
            .await
            .expect("store readable")
            .expect("email row");
        assert_eq!(row.provider.as_deref(), Some("stub"));
        assert_eq!(row.uid.as_deref(), Some("uid-42"));
        // Linking is an update, not a create: exactly one row exists.
        let mut identity = Conditions::new();
        identity.insert(PROVIDER_COLUMN, "stub");
        identity.insert(UID_COLUMN, "uid-42");
        assert!(
            adapter
                .find_first(&identity)
                .await
                .expect("store readable")
                .is_some()
        );
    }

    /// Devise routes EVERY credential source through the parameter filter
    /// (`authenticatable.rb:267-269`): a provider asserting
    /// `User@Example.COM` against a stored `user@example.com` links to the
    /// existing account. An unnormalized lookup falls through to
    /// create-new and mints a duplicate account (or surfaces :taken).
    #[tokio::test]
    async fn omniauthable_policy_normalizes_provider_email_before_linking() {
        let adapter = MemoryAdapter::<OmniUser>::new();
        seed_row(&adapter, "user@example.com").await;

        let clock = FixedClock::new(Utc.timestamp_opt(1_700_000_000, 0).unwrap());
        let outcome: ResourceWithErrors<OmniUser> = default_from_omniauth(
            &adapter,
            &omni_profile(Some("  User@Example.COM  "), true),
            &test_config(),
            &clock,
        )
        .await
        .expect("from_omniauth");

        assert!(
            outcome.is_valid(),
            "a mixed-case provider email must link to the stored row, got errors {:?}",
            outcome.errors
        );
        // Exactly one row: the existing one, updated with the identity pair.
        let mut identity = Conditions::new();
        identity.insert(PROVIDER_COLUMN, "stub");
        identity.insert(UID_COLUMN, "uid-42");
        let row = adapter
            .find_first(&identity)
            .await
            .expect("store readable")
            .expect("linked identity row");
        assert_eq!(row.email, "user@example.com");
        let mut by_email = Conditions::new();
        by_email.insert("email", "user@example.com");
        assert!(
            adapter
                .find_first(&by_email)
                .await
                .expect("store readable")
                .is_some(),
            "the stored row must be reachable under its normalized email"
        );
    }

    #[tokio::test]
    async fn omniauthable_policy_unverified_email_never_links() {
        let adapter = MemoryAdapter::<OmniUser>::new();
        seed_row(&adapter, "user@example.com").await;

        let clock = FixedClock::new(Utc.timestamp_opt(1_700_000_000, 0).unwrap());
        // Same email, but the provider does NOT assert verification.
        let outcome: ResourceWithErrors<OmniUser> = default_from_omniauth(
            &adapter,
            &omni_profile(Some("user@example.com"), false),
            &test_config(),
            &clock,
        )
        .await
        .expect("from_omniauth");

        // The fallthrough is create-new - a valid outcome, never a silent error.
        assert!(outcome.is_valid());
        assert_eq!(outcome.record.provider.as_deref(), Some("stub"));
        assert_eq!(outcome.record.uid.as_deref(), Some("uid-42"));

        // T-09-08 boundary: the pre-existing row keeps EMPTY provider and uid.
        let mut unlinked = Conditions::new();
        unlinked.insert("email", "user@example.com");
        unlinked.insert(PROVIDER_COLUMN, Value::Null);
        let original = adapter
            .find_first(&unlinked)
            .await
            .expect("store readable")
            .expect("original row untouched");
        assert_eq!(original.provider, None);
        assert_eq!(original.uid, None);
        assert_eq!(original.encrypted_password, "$2a$12$seededhash");
    }

    #[tokio::test]
    async fn omniauthable_policy_creates_new_row_on_unknown_email() {
        let adapter = MemoryAdapter::<OmniUser>::new();

        let fixed = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        let clock = FixedClock::new(fixed);
        let outcome: ResourceWithErrors<OmniUser> = default_from_omniauth(
            &adapter,
            &omni_profile(Some("fresh@example.com"), true),
            &test_config(),
            &clock,
        )
        .await
        .expect("from_omniauth");

        assert!(outcome.is_valid());
        assert_eq!(outcome.record.email, "fresh@example.com");
        assert_eq!(outcome.record.provider.as_deref(), Some("stub"));
        assert_eq!(outcome.record.uid.as_deref(), Some("uid-42"));
        assert_eq!(outcome.record.name.as_deref(), Some("Stub User"));
        // The clock is the flow's authoritative instant: created_at is the
        // fixed stamp, not wall time.
        assert_eq!(outcome.record.created_at, Some(fixed));
    }

    #[tokio::test]
    async fn omniauthable_policy_without_email_never_links_and_creates() {
        let adapter = MemoryAdapter::<OmniUser>::new();
        seed_row(&adapter, "user@example.com").await;

        let clock = FixedClock::new(Utc.timestamp_opt(1_700_000_000, 0).unwrap());
        // A profile with no email at all: nothing to collide with, and the
        // default policy cannot look up by a nonexistent column value.
        let outcome: ResourceWithErrors<OmniUser> =
            default_from_omniauth(&adapter, &omni_profile(None, false), &test_config(), &clock)
                .await
                .expect("from_omniauth");

        assert!(outcome.is_valid());
        assert_eq!(outcome.record.provider.as_deref(), Some("stub"));
        // The email-less create path stores the empty-string email.
        assert_eq!(outcome.record.email, "");
    }

    #[test]
    fn omniauthable_failure_message_renders_devise_template() {
        // en.yml: Could not authenticate you from %{kind} because "%{reason}".
        assert_eq!(
            failure_message("GitHub", "Invalid credentials"),
            "Could not authenticate you from GitHub because \"Invalid credentials\"."
        );
        assert_eq!(
            failure_message("Stub Provider", "not authorized"),
            "Could not authenticate you from Stub Provider because \"not authorized\"."
        );
    }

    #[test]
    fn omniauthable_success_message_renders_devise_template() {
        // en.yml: Successfully authenticated from %{kind} account.
        assert_eq!(
            success_message("GitHub"),
            "Successfully authenticated from GitHub account."
        );
    }

    /// `HashMap` session store for the proxy wiring test.
    #[derive(Default, Clone)]
    struct MapSessionStore(std::sync::Arc<std::sync::RwLock<HashMap<String, serde_json::Value>>>);

    #[async_trait]
    impl SessionStore for MapSessionStore {
        async fn get_value(&self, key: &str) -> Option<serde_json::Value> {
            self.0.read().unwrap().get(key).cloned()
        }

        async fn insert_value(&self, key: &str, value: serde_json::Value) {
            self.0.write().unwrap().insert(key.to_string(), value);
        }

        async fn remove(&self, key: &str) {
            self.0.write().unwrap().remove(key);
        }

        async fn remove_prefix(&self, prefix: &str) {
            self.0
                .write()
                .unwrap()
                .retain(|key, _| !key.starts_with(prefix));
        }

        async fn keys_with_prefix(&self, prefix: &str) -> Vec<String> {
            self.0
                .read()
                .unwrap()
                .keys()
                .filter(|key| key.starts_with(prefix))
                .cloned()
                .collect()
        }

        async fn renew(&self) -> Result<(), DeviseError> {
            Ok(())
        }

        async fn reset(&self) -> Result<(), DeviseError> {
            self.0.write().unwrap().clear();
            Ok(())
        }
    }

    fn omniauth_test_proxy() -> (AuthProxy, std::sync::Arc<MapSessionStore>) {
        let store = std::sync::Arc::new(MapSessionStore::default());
        let mut scope_registry = crate::scope::ScopeRegistry::new();
        let mapping = Mapping {
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
        };
        let mut hooks = HookRegistry::new();
        register_devise_hooks(&mut hooks, &mapping);
        scope_registry.register(mapping);
        let proxy = AuthProxy::new(
            store.clone(),
            std::sync::Arc::new(scope_registry),
            std::sync::Arc::new(hooks),
            std::sync::Arc::new(crate::config::DeviseConfig::default()),
        );
        (proxy, store)
    }

    #[tokio::test]
    async fn omniauthable_success_path_signs_in_with_set_user_event_authentication() {
        // The full core handoff: default policy -> valid record -> the SESS
        // sign-in path with SetUserEvent::Authentication (fires the
        // Authentication hooks, persists the [key, salt] session pair).
        let adapter = MemoryAdapter::<OmniUser>::new();
        let clock = FixedClock::new(Utc.timestamp_opt(1_700_000_000, 0).unwrap());
        let outcome: ResourceWithErrors<OmniUser> = default_from_omniauth(
            &adapter,
            &omni_profile(Some("new@example.com"), true),
            &test_config(),
            &clock,
        )
        .await
        .expect("from_omniauth");
        assert!(outcome.is_valid());

        let (mut proxy, store) = omniauth_test_proxy();
        let accepted = proxy
            .set_user(
                "user",
                Some(Box::new(outcome.record)),
                SetUserOpts {
                    event: SetUserEvent::Authentication,
                    store: true,
                    run_callbacks: true,
                    force: false,
                },
            )
            .await
            .expect("omniauth success sign-in persists the session");
        assert!(accepted);

        // The session holds the warden [key, salt] pair and the scope is signed in.
        let session_key = keys::scope_session_key("user");
        assert!(store.get_value(&session_key).await.is_some());
        assert!(proxy.authenticated("user"));
        assert!(
            proxy
                .user::<OmniUser>("user")
                .expect("typed user")
                .provider
                .is_some()
        );
    }

    /// WR-05: an adapter lookup failure propagates as [`DeviseError`]
    /// instead of the old "treat the error as not-found" swallow, which
    /// let a transient backend outage mint a SECOND identity row on the
    /// next attempt. The framework callbacks map this error onto their
    /// internal-error (500) path, so the user sees a failure, never a
    /// silently duplicated account.
    #[tokio::test]
    async fn default_from_omniauth_propagates_adapter_lookup_failures() {
        use crate::adapter::{ChangeSet, Conditions, DeviseKey, OrmError};

        struct FailingAdapter;

        #[async_trait]
        impl OrmAdapter<OmniUser> for FailingAdapter {
            type New = OmniUser;

            async fn get(&self, _id: &DeviseKey) -> Result<Option<OmniUser>, OrmError> {
                Err(OrmError::Connection {
                    message: "pool exhausted".to_string(),
                    source: None,
                })
            }

            async fn find_first(
                &self,
                _conditions: &Conditions,
            ) -> Result<Option<OmniUser>, OrmError> {
                Err(OrmError::Connection {
                    message: "pool exhausted".to_string(),
                    source: None,
                })
            }

            async fn create(&self, _model: OmniUser) -> Result<OmniUser, OrmError> {
                Err(OrmError::Connection {
                    message: "pool exhausted".to_string(),
                    source: None,
                })
            }

            async fn update(
                &self,
                _key: &DeviseKey,
                _changes: &ChangeSet,
            ) -> Result<OmniUser, OrmError> {
                Err(OrmError::Connection {
                    message: "pool exhausted".to_string(),
                    source: None,
                })
            }

            async fn update_columns(
                &self,
                _key: &DeviseKey,
                _fields: &std::collections::HashMap<String, crate::adapter::Value>,
            ) -> Result<OmniUser, OrmError> {
                Err(OrmError::Connection {
                    message: "pool exhausted".to_string(),
                    source: None,
                })
            }

            async fn increment_counter(
                &self,
                _key: &DeviseKey,
                _column: &'static str,
            ) -> Result<OmniUser, OrmError> {
                Err(OrmError::Connection {
                    message: "pool exhausted".to_string(),
                    source: None,
                })
            }

            async fn delete(&self, _id: &DeviseKey) -> Result<(), OrmError> {
                Err(OrmError::Connection {
                    message: "pool exhausted".to_string(),
                    source: None,
                })
            }
        }

        let adapter = FailingAdapter;
        let clock = FixedClock::new(
            chrono::Utc
                .with_ymd_and_hms(2026, 10, 28, 12, 0, 0)
                .single()
                .expect("fixed time"),
        );
        let outcome = default_from_omniauth(
            &adapter,
            &omni_profile(Some("new@example.com"), true),
            &crate::config::DeviseConfig::default(),
            &clock,
        )
        .await;

        let err = outcome.expect_err("a failed lookup is an error, not a miss");
        assert!(
            matches!(err, DeviseError::Adapter(_)),
            "the adapter error propagates verbatim: {err:?}"
        );
    }
}
