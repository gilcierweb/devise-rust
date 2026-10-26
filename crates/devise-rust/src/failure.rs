//! Failure enum - Warden-compatible failure decision types
//!
//! Mirrors `Devise::FailureApp` (`devise/lib/devise/failure_app.rb`): the redirect, flash, stored-location, and 401 decisions.
//!
//! These are the failure modes that strategies and hooks can return to halt
//! the authentication chain. The decision logic (navigational vs API vs HTTP Basic
//! vs Recall) is added in Plan 04; this file defines the enum variants only.

use crate::adapter::DeviseKey;
use crate::request::AuthRequest;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Type alias for authentication rules closure
///
/// Request-shape inputs to the failure decision; mirrors the Rack env data devise's failure app reads.
pub type AuthRules = dyn Fn(&dyn AnyDeviseModel) -> bool + Send + Sync;

/// Failure decision variants - mirrors Devise's `throw :warden` message types
/// and the Failure App's response classification.
///
/// Strategy `authenticate` returns `Result<AuthOutcome, Failure>` where
/// `Failure` carries the decision data needed for rendering.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Failure {
    /// Navigational request (HTML/Turbo) failed - redirect to sign-in with flash
    NavigationalRedirect {
        /// Target path (e.g., `/users/sign_in`)
        location: String,
        /// Flash message I18n key (e.g., "unauthenticated", "invalid", "unconfirmed")
        flash_key: &'static str,
        /// Stored location for redirect-after-sign-in (optional)
        stored_location: Option<String>,
    },

    /// API request (JSON) failed - return 401 without redirect
    ApiUnauthorized {
        /// HTTP status (always 401)
        status: u16,
        /// WWW-Authenticate header value for HTTP Basic (optional)
        www_authenticate: Option<String>,
    },

    /// Recall - re-dispatch to controller/action preserving params
    /// (for custom sign-in forms that need the original params)
    Recall {
        /// Controller name (e.g., "sessions")
        controller: String,
        /// Action name (e.g., "new")
        action: String,
    },

    /// Unauthenticated - generic unauthenticated failure
    Unauthenticated {
        /// I18n message key
        message: &'static str,
    },

    /// Session timeout
    Timeout,

    /// Invalid credentials (wrong password)
    InvalidCredentials {
        /// I18n message key
        message: &'static str,
    },

    /// Configuration error
    Config(String),

    /// Locked account (lockable module)
    Locked {
        /// I18n message key
        message: &'static str,
    },

    /// Unconfirmed account (confirmable module)
    Unconfirmed {
        /// I18n message key
        message: &'static str,
    },

    /// Record not found (used by `ParanoidStrategy`)
    NotFound,

    /// Internal error
    Internal(String),
}

impl Failure {
    /// Check if this failure is a navigational redirect
    ///
    /// Mirrors `navigational_format?` in `Devise::FailureApp` (`devise/lib/devise/failure_app.rb`): the redirect-plus-flash branch.
    #[must_use]
    pub fn is_navigational(&self) -> bool {
        matches!(self, Failure::NavigationalRedirect { .. })
    }

    /// Check if this failure is an API unauthorized response
    ///
    /// Mirrors the 401 branch of the failure app for API requests.
    #[must_use]
    pub fn is_api_unauthorized(&self) -> bool {
        matches!(self, Failure::ApiUnauthorized { .. })
    }

    /// Check if this failure is a recall
    ///
    /// Mirrors the failure app's `recall`: replaying the stored location instead of redirecting to sign in.
    #[must_use]
    pub fn is_recall(&self) -> bool {
        matches!(self, Failure::Recall { .. })
    }

    /// Get the flash key for navigational failures
    ///
    /// Maps a failure to the `devise.failure.*` flash key family, mirroring the I18n lookup devise's failure app renders.
    #[must_use]
    pub fn flash_key(&self) -> Option<&'static str> {
        match self {
            Failure::NavigationalRedirect { flash_key, .. } => Some(*flash_key),
            _ => None,
        }
    }

    /// Get the stored location for navigational failures
    ///
    /// Mirrors `stored_location!` in the failure app: recalling the `#{scope}_return_to` value.
    #[must_use]
    pub fn stored_location(&self) -> Option<&str> {
        match self {
            Failure::NavigationalRedirect {
                stored_location, ..
            } => stored_location.as_deref(),
            _ => None,
        }
    }

    /// Get the HTTP status code for this failure
    ///
    /// The 401 status arm, mirroring the failure app's API response.
    #[must_use]
    pub fn status_code(&self) -> u16 {
        match self {
            Failure::ApiUnauthorized { status, .. } => *status,
            Failure::NavigationalRedirect { .. } => 302,
            _ => 401,
        }
    }

    /// Get the WWW-Authenticate header value if present
    ///
    /// Builds the `WWW-Authenticate` header with `http_authentication_realm`, mirroring the failure app's HTTP Basic challenge.
    #[must_use]
    pub fn www_authenticate(&self) -> Option<&str> {
        match self {
            Failure::ApiUnauthorized {
                www_authenticate, ..
            } => www_authenticate.as_deref(),
            _ => None,
        }
    }
}

/// Result of a successful strategy authentication
///
/// Mirrors warden's strategy outcome vocabulary: success, fail, and the redirect carry-over devise's `throw :warden` produces.
#[derive(Debug)]
pub enum AuthOutcome {
    /// Authentication succeeded with a user record
    Success(Box<dyn AnyDeviseModel>),
    /// Rememberable hit with `extend_remember_period`: success plus a
    /// re-issued cookie triple for the bridge to set (the Devise
    /// `remember_me` re-issue). The proxy converts this into a remember
    /// `Set` op carrying the hardened attributes, then proceeds as success.
    SuccessWithCookieRefresh {
        /// Authenticated record.
        user: Box<dyn AnyDeviseModel>,
        /// Cookie name (key-override aware).
        cookie_key: String,
        /// Jar string (encoded triple with a fresh timestamp).
        cookie_value: String,
        /// Cookie expiry (`remember_for` after the refresh instant).
        expires: DateTime<Utc>,
    },
    /// Stale remember cookie: the bridge must delete `cookie_key`, then the
    /// chain continues with pass-through semantics (Devise `cookies.delete`
    /// plus `pass`, never `Failure`).
    ClearCookieAndPass {
        /// Cookie name to delete.
        cookie_key: String,
    },
    /// Strategy passed (not applicable) - continue to next strategy
    Pass,
}

/// Trait for type-erased Devise models - allows storing heterogeneous models
/// in `AuthProxy`'s user map while preserving downcast capability.
///
/// Object-safe model facet mirroring the duck-typed record warden's proxy requires.
pub trait AnyDeviseModel: Send + Sync + 'static {
    /// Get the model's primary key
    fn to_key(&self) -> DeviseKey;

    /// Get the model's authenticatable salt (bcrypt hash prefix)
    ///
    /// Base default is `None`; `DatabaseAuthenticatable` models override it
    /// with the `encrypted_password[0,29]` prefix.
    fn authenticatable_salt(&self) -> Option<String> {
        None
    }

    /// Check if the model is valid for authentication (can be overridden by modules)
    fn valid_for_authentication(&self, _rules: Option<&AuthRules>) -> bool {
        true
    }

    /// Get the inactive message for this model
    fn unauthenticated_message(&self) -> &'static str {
        "invalid"
    }

    /// Check if this model is the same as another (for `sign_in` no-op check)
    fn is_same(&self, other: &dyn AnyDeviseModel) -> bool {
        self.to_key() == other.to_key()
            && crate::crypto::secure_compare(
                &self.authenticatable_salt().unwrap_or_default(),
                &other.authenticatable_salt().unwrap_or_default(),
            )
    }

    /// Downcast to the password-checking facet, if this model stores a
    /// password hash (`DatabaseAuthenticatable` models override this).
    fn as_password_verifiable(&self) -> Option<&dyn crate::model::PasswordVerifiable> {
        None
    }

    /// Object-safe view over this model's activatable gate pair
    /// (`active_for_authentication?` / `inactive_message`).
    ///
    /// Default `None` (nothing to gate); models that implement
    /// [`Authenticatable`](crate::model::Authenticatable) return
    /// `Some(self)` - the blanket [`Activatable`](crate::model::Activatable)
    /// impl then reads the very same composition the typed side calls, so
    /// hooks and controllers can never disagree.
    fn as_activatable(&self) -> Option<&dyn crate::model::Activatable> {
        None
    }

    /// Devise `after_database_authentication` entrypoint (DBAU-07).
    ///
    /// Default no-op; `DatabaseAuthenticatable` models wire it to the trait
    /// method (strategies call it after a successful password check, exactly
    /// where Devise's `database_authenticatable` strategy invokes it).
    fn after_database_authentication(&self) {}

    /// Devise `reset_failed_attempts!` in-memory hook entrypoint (LCK-06).
    ///
    /// Default no-op returning `false`; lockable models override it to zero
    /// the in-memory `failed_attempts` counter so the memoized record
    /// reflects the sign-in reset. The typed `Lockable` trait owns adapter
    /// persistence; this seam exists because that trait is not object-safe
    /// and hook bodies only see `dyn AnyDeviseModel`.
    fn reset_failed_attempts_hook(&mut self) -> bool {
        false
    }

    /// Devise `update_tracked_fields` in-memory hook entrypoint (TRK-01).
    ///
    /// Default no-op returning `false`; trackable models override it to
    /// apply the current-into-last shift to the memoized record. The typed
    /// [`Trackable`](crate::trackable::Trackable) trait owns adapter
    /// persistence through `update_tracked_fields_bang` (with the #4673
    /// new-record probe); this seam exists because that trait is not
    /// object-safe and hook bodies only see `dyn AnyDeviseModel`.
    fn apply_tracked_fields_hook(&mut self, _now: DateTime<Utc>, _peer_ip: Option<&str>) -> bool {
        false
    }

    /// Remember value for cookie validation: the `remember_token` column
    /// when the model carries one, else `authenticatable_salt`.
    ///
    /// Default `None` (model does not support rememberable). Typed
    /// [`Rememberable`](crate::rememberable::Rememberable) impls delegate
    /// here so the erased strategy chain can validate without naming the
    /// concrete model (the typed trait is not object-safe).
    fn rememberable_value_opt(&self) -> Option<String> {
        None
    }

    /// `remember_created_at` instant, when the model tracks it.
    ///
    /// Default `None`; typed rememberable impls delegate here. The strategy
    /// reads this through the seam for the strict greater-than check.
    fn remember_created_at_opt(&self) -> Option<DateTime<Utc>> {
        None
    }

    /// Virtual `remember_me` sign-in flag (Devise `attr_accessor`).
    ///
    /// Strategies stamp this from the sign-in params; the rememberable-set
    /// hook reads it. Default `None` (unset).
    fn remember_me_flag_opt(&self) -> Option<bool> {
        None
    }

    /// Assign the virtual `remember_me` flag (memory only, no persistence).
    ///
    /// Default no-op; rememberable models store the flag.
    fn set_remember_me_flag(&mut self, _flag: bool) {}

    /// Extension hook run after a successful remember-hit (Devise
    /// `after_remembered`).
    ///
    /// Default no-op; override for custom logic that runs only after the
    /// user is remembered.
    fn after_remembered_hook(&self) {}

    /// Session pair for this model: `(key, salt)`.
    ///
    /// Mirrors Devise's `serialize_into_session(record)` so `AuthProxy` can
    /// persist sessions without depending on the `Authenticatable` trait
    /// (which is not object-safe).
    fn session_pair(&self) -> (DeviseKey, String) {
        (
            self.to_key(),
            self.authenticatable_salt().unwrap_or_default(),
        )
    }

    /// Downcast to concrete type
    fn as_any(&self) -> &dyn std::any::Any;

    /// The model's redaction projection, the object-safe twin of
    /// [`Authenticatable::serializable_hash`](crate::model::Authenticatable::serializable_hash):
    /// an empty object by default, so generic Debug/logging paths print
    /// nothing rather than secrets. Models that own a concrete
    /// `serializable_hash` override this by delegating to it, and
    /// [`Redacted`](crate::error::Redacted) reads it. It is a DISTINCT
    /// method name on purpose: `serializable_hash` already resolves to
    /// `Authenticatable` on every model implementing both traits.
    fn redacted_hash(&self) -> serde_json::Value {
        serde_json::Value::Object(serde_json::Map::new())
    }
}

impl From<crate::error::DeviseError> for Failure {
    fn from(error: crate::error::DeviseError) -> Self {
        Failure::Internal(format!("{error}"))
    }
}

impl std::fmt::Debug for dyn AnyDeviseModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AnyDeviseModel(key={:?})", self.to_key())
    }
}

/// Bridges must NOT route application 401s through Devise failure handling.
///
/// Mirrors `Devise.http_authenticatable_on_xhr` and the 401 interception decision in the failure app.
pub const INTERCEPT_401: bool = false;

/// Why authentication failed - maps to `devise.failure.*` I18n keys.
///
/// Mirrors the `throw :warden` payload: the message key and scope the failure app receives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureReason {
    /// No session or credentials presented.
    Unauthenticated,
    /// Wrong credentials.
    Invalid,
    /// Unknown account (non-paranoid mode; Devise's `:not_found_in_database`).
    NotFoundInDatabase,
    /// Email not confirmed.
    Unconfirmed,
    /// Account locked.
    Locked,
    /// Session timed out.
    Timeout,
    /// Already signed in (for `require_no_authentication`).
    AlreadyAuthenticated,
}

impl FailureReason {
    /// I18n key under `devise.failure.*`.
    ///
    /// Mirrors the failure app's flash mapping: failure reason to devise key (`devise.failure.locked`, `devise.failure.timeout`, ...).
    #[must_use]
    pub fn flash_key(self) -> &'static str {
        match self {
            FailureReason::Unauthenticated => "unauthenticated",
            FailureReason::Invalid => "invalid",
            FailureReason::NotFoundInDatabase => "not_found_in_database",
            FailureReason::Unconfirmed => "unconfirmed",
            FailureReason::Locked => "locked",
            FailureReason::Timeout => "timeout",
            FailureReason::AlreadyAuthenticated => "already_authenticated",
        }
    }
}

/// Classify an `inactive_message` stem into the matching [`Failure`].
///
/// Devise's activatable hook (`devise/lib/devise/hooks/activatable.rb`)
/// throws `record.inactive_message`, and the failure app renders the
/// matching `devise.failure.*` I18n key. This maps that stem onto the
/// port's classified failure variant so a renderer picks the locked or
/// unconfirmed flash key instead of the generic unauthenticated one.
///
/// Deviation from the reference: an application-defined custom stem falls
/// back to [`Failure::Unauthenticated`] because the port's failure
/// vocabulary is a closed enum, so a custom `inactive_message` cannot mint
/// a new variant at runtime the way the I18n key can.
#[must_use]
pub fn inactive_failure(message: &'static str) -> Failure {
    match message {
        "locked" => Failure::Locked { message },
        "unconfirmed" => Failure::Unconfirmed { message },
        _ => Failure::Unauthenticated { message },
    }
}

/// Classify an `inactive_message` stem into the matching [`FailureReason`].
///
/// The renderer-side twin of [`inactive_failure`]: the actix extractor
/// builds its failure-app reason from the stem staged by the gate, which
/// is how the locked or unconfirmed flash key reaches the response
/// (Devise throws `record.inactive_message`, `activatable.rb`).
///
/// Same closed-enum deviation as [`inactive_failure`]: an app-defined
/// custom stem reports the generic unauthenticated reason.
#[must_use]
pub fn failure_reason_from_message(message: &str) -> FailureReason {
    match message {
        "locked" => FailureReason::Locked,
        "unconfirmed" => FailureReason::Unconfirmed,
        _ => FailureReason::Unauthenticated,
    }
}

/// Check the request format against configured navigational formats.
///
/// Delegates to [`AuthRequest::is_navigational_format`](crate::request::AuthRequest::is_navigational_format).
///
/// Mirrors `Devise.navigational_formats` matching in the failure app.
#[must_use]
pub fn is_navigational_format(
    request: &crate::request::AuthRequest,
    config: &crate::config::DeviseConfig,
) -> bool {
    request.is_navigational_format(config)
}

/// Whether the request uses HTTP Basic auth that Devise should answer.
///
/// Detects the HTTP Basic request arm, mirroring the env check in `Devise::Strategies::Authenticatable`.
#[must_use]
pub fn http_auth(
    request: &crate::request::AuthRequest,
    config: &crate::config::DeviseConfig,
) -> bool {
    config.http_authenticatable && request.has_http_basic()
}

/// Core failure decision, mirroring `failure_app.rb`.
///
/// Priority: HTTP Basic, recall target, navigational redirect, API 401 -
/// `failure_app.rb:42-50` asks `http_auth?` first and `recall` second.
/// The stored location is kept only for `GET` navigational non-XHR
/// requests, per `store_location.rb`. A `Timeout` on a navigational
/// request redirects to the attempted path (`failure_app.rb:135-149`)
/// instead of the sign-in page, so an expired session resumes where it
/// left off after re-authenticating.
#[must_use]
pub fn build_failure(
    request: &crate::request::AuthRequest,
    mapping: &crate::scope::Mapping,
    config: &crate::config::DeviseConfig,
    reason: FailureReason,
) -> Failure {
    if http_auth(request, config) {
        return Failure::ApiUnauthorized {
            status: 401,
            // Devise quotes the realm (`failure_app.rb:54` builds it with
            // `.inspect`); quotes are syntactically required once the
            // configured realm contains a space.
            www_authenticate: Some(format!(
                "Basic realm=\"{}\"",
                config.http_authentication_realm
            )),
        };
    }
    if let Some((controller, action)) = request.recall_target() {
        return Failure::Recall { controller, action };
    }
    if is_navigational_format(request, config) {
        let stored_location =
            if request.method == crate::request::HttpMethod::Get && !request.is_xhr() {
                AuthRequest::parse_stored_uri(&request.path)
            } else {
                None
            };
        // Devise's `redirect_url`: a timed-out session returns the user to
        // the page they were trying to reach (GET) or the referrer path
        // (non-GET), falling back to the sign-in path.
        let location = if reason == FailureReason::Timeout {
            timeout_redirect_target(request).unwrap_or_else(|| mapping.sign_in_path())
        } else {
            mapping.sign_in_path()
        };
        return Failure::NavigationalRedirect {
            location,
            flash_key: reason.flash_key(),
            stored_location,
        };
    }
    Failure::ApiUnauthorized {
        status: 401,
        www_authenticate: None,
    }
}

/// Devise's timeout `redirect_url` arm (`failure_app.rb:135-149`): the
/// attempted path on GET, the referrer's path otherwise. Values that fail
/// the same-host guard are discarded by the caller.
fn timeout_redirect_target(request: &crate::request::AuthRequest) -> Option<String> {
    if request.method == crate::request::HttpMethod::Get {
        AuthRequest::parse_stored_uri(&request.path)
    } else {
        request
            .headers
            .get("referer")
            .and_then(|referer| AuthRequest::parse_stored_uri(referer))
    }
}

/// Session key holding the post-sign-in redirect target.
///
/// Builds the `#{scope}_return_to` key, mirroring the stored-location slot the failure app reads for redirects.
#[must_use]
pub fn stored_location_key(scope: &str) -> String {
    format!("{scope}_return_to")
}

/// Save the attempted path for redirect-after-sign-in.
///
/// Only `GET` navigational non-XHR requests are stored, and only relative
/// paths survive [`parse_stored_uri`](crate::request::AuthRequest::parse_stored_uri),
/// which blocks open redirects.
pub async fn store_location(
    request: &crate::request::AuthRequest,
    scope: &str,
    config: &crate::config::DeviseConfig,
    session_store: &dyn crate::session::SessionStore,
) {
    if request.method != crate::request::HttpMethod::Get
        || request.is_xhr()
        || !is_navigational_format(request, config)
    {
        return;
    }
    if let Some(location) = crate::request::AuthRequest::parse_stored_uri(&request.path) {
        session_store
            .insert_value(
                &stored_location_key(scope),
                serde_json::Value::String(location),
            )
            .await;
    }
}

/// Take and clear the stored location for a scope.
pub async fn stored_location_for(
    scope: &str,
    session_store: &dyn crate::session::SessionStore,
) -> Option<String> {
    let key = stored_location_key(scope);
    let location = session_store.get_value(&key).await?;
    // Read-once, matching Devise's take semantics.
    session_store.remove(&key).await;
    // Defense in depth on the READ path: a value poisoned straight into
    // the store (shared session backend, stale server, tampered cookie)
    // must never surface as a `Location` header - the same off-host guard
    // the writers apply (S1).
    location
        .as_str()
        .and_then(crate::request::AuthRequest::parse_stored_uri)
}

/// Framework rendering contract for failures (S-13).
///
/// Core decides the `Failure`; bridges render it. Core never constructs
/// HTTP responses.
///
/// Mirrors `Devise::FailureApp`: redirect plus flash for navigational formats, 401 plus `WWW-Authenticate` otherwise.
pub trait FailureRenderer: Send + Sync {
    /// The framework response type (opaque to core).
    type Response;
    /// Render a failure for a scope mapping.
    fn render(&self, failure: &Failure, mapping: &crate::scope::Mapping) -> Self::Response;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_failure_variants() {
        let nav = Failure::NavigationalRedirect {
            location: "/users/sign_in".to_string(),
            flash_key: "unauthenticated",
            stored_location: Some("/protected".to_string()),
        };
        assert!(nav.is_navigational());
        assert_eq!(nav.flash_key(), Some("unauthenticated"));
        assert_eq!(nav.stored_location(), Some("/protected"));
        assert_eq!(nav.status_code(), 302);

        let api = Failure::ApiUnauthorized {
            status: 401,
            www_authenticate: None,
        };
        assert!(api.is_api_unauthorized());
        assert_eq!(api.status_code(), 401);
        assert_eq!(api.www_authenticate(), None);

        let api_basic = Failure::ApiUnauthorized {
            status: 401,
            // Devise emits `Basic realm="Application"` - failure_app.rb:54
            // (`Devise.http_authentication_realm.inspect`); the quotes are
            // syntactically required for multi-word realms.
            www_authenticate: Some("Basic realm=\"Application\"".to_string()),
        };
        assert_eq!(
            api_basic.www_authenticate(),
            Some("Basic realm=\"Application\"")
        );
        let api_multiword = Failure::ApiUnauthorized {
            status: 401,
            www_authenticate: Some("Basic realm=\"My Application\"".to_string()),
        };
        assert_eq!(
            api_multiword.www_authenticate(),
            Some("Basic realm=\"My Application\"")
        );

        let recall = Failure::Recall {
            controller: "sessions".to_string(),
            action: "new".to_string(),
        };
        assert!(recall.is_recall());
    }

    /// Devise `hooks/activatable.rb` classification: the inactive message
    /// stem must reach the renderer as the classified failure, so the
    /// locked and unconfirmed flash keys survive the round trip.
    #[test]
    fn test_inactive_message_classifies_to_the_locked_and_unconfirmed_failures() {
        assert!(matches!(
            inactive_failure("locked"),
            Failure::Locked { message } if message == "locked"
        ));
        assert!(matches!(
            inactive_failure("unconfirmed"),
            Failure::Unconfirmed { message } if message == "unconfirmed"
        ));
        // An unknown (app-defined) stem fails closed to the generic key.
        assert!(matches!(
            inactive_failure("deactivated"),
            Failure::Unauthenticated { message } if message == "deactivated"
        ));

        assert_eq!(failure_reason_from_message("locked"), FailureReason::Locked);
        assert_eq!(
            failure_reason_from_message("unconfirmed"),
            FailureReason::Unconfirmed
        );
        assert_eq!(
            failure_reason_from_message("deactivated"),
            FailureReason::Unauthenticated
        );
        // The reason round-trips into the same flash key the reference
        // renders through `devise.failure.*`.
        assert_eq!(failure_reason_from_message("locked").flash_key(), "locked");
        assert_eq!(
            failure_reason_from_message("unconfirmed").flash_key(),
            "unconfirmed"
        );
    }

    #[test]
    fn test_failure_equality() {
        let f1 = Failure::Timeout;
        let f2 = Failure::Timeout;
        assert_eq!(f1, f2);

        let f3 = Failure::InvalidCredentials { message: "invalid" };
        let f4 = Failure::InvalidCredentials { message: "invalid" };
        assert_eq!(f3, f4);
    }

    #[derive(Debug, Default)]
    struct FailureTestStore {
        data:
            std::sync::Arc<std::sync::RwLock<std::collections::HashMap<String, serde_json::Value>>>,
    }

    #[async_trait::async_trait]
    impl crate::session::SessionStore for FailureTestStore {
        async fn get_value(&self, key: &str) -> Option<serde_json::Value> {
            self.data.read().unwrap().get(key).cloned()
        }

        async fn insert_value(&self, key: &str, value: serde_json::Value) {
            self.data.write().unwrap().insert(key.to_string(), value);
        }

        async fn remove(&self, key: &str) {
            self.data.write().unwrap().remove(key);
        }

        async fn remove_prefix(&self, prefix: &str) {
            let mut data = self.data.write().unwrap();
            let doomed: Vec<String> = data
                .keys()
                .filter(|key| key.starts_with(prefix))
                .cloned()
                .collect();
            for key in doomed {
                data.remove(&key);
            }
        }

        async fn keys_with_prefix(&self, prefix: &str) -> Vec<String> {
            self.data
                .read()
                .unwrap()
                .keys()
                .filter(|key| key.starts_with(prefix))
                .cloned()
                .collect()
        }

        async fn renew(&self) -> Result<(), crate::error::DeviseError> {
            Ok(())
        }

        async fn reset(&self) -> Result<(), crate::error::DeviseError> {
            self.data.write().unwrap().clear();
            Ok(())
        }
    }

    fn failure_test_mapping() -> crate::scope::Mapping {
        crate::scope::Mapping {
            name: "user".to_string(),
            class_name: "User".to_string(),
            path: "users".to_string(),
            path_prefix: None,
            singular: "user".to_string(),
            path_names: crate::scope::PathNames::default(),
            controllers: std::collections::HashMap::new(),
            modules: vec![crate::scope::Module::DatabaseAuthenticatable],
            only: vec![],
            skip: vec![],
            constraints: std::collections::HashMap::new(),
            defaults: std::collections::HashMap::new(),
            format: None,
            router_name: None,
            sign_out_via: crate::scope::SignOutVia::Delete,
            failure_app: None,
        }
    }

    fn html_request(path: &str) -> crate::request::AuthRequest {
        let mut request =
            crate::request::AuthRequest::new(crate::request::HttpMethod::Get, path.to_string());
        request
            .headers
            .insert("accept".to_string(), "text/html".to_string());
        request
    }

    #[test]
    fn test_failure_decision() {
        use crate::config::DeviseConfig;
        let config = DeviseConfig::default();
        let mapping = failure_test_mapping();

        let navigational = build_failure(
            &html_request("/protected"),
            &mapping,
            &config,
            FailureReason::Unauthenticated,
        );
        assert!(matches!(
            navigational,
            Failure::NavigationalRedirect {
                ref location,
                flash_key: "unauthenticated",
                ref stored_location,
            } if location == "/users/sign_in" && stored_location.as_deref() == Some("/protected")
        ));

        let mut api = crate::request::AuthRequest::new(
            crate::request::HttpMethod::Get,
            "/api/resource".to_string(),
        );
        api.headers
            .insert("accept".to_string(), "application/json".to_string());
        // Default config includes */* as navigational, so override formats.
        let api_config = DeviseConfig {
            navigational_formats: vec!["html".to_string()],
            ..DeviseConfig::default()
        };
        let unauthorized = build_failure(&api, &mapping, &api_config, FailureReason::Invalid);
        assert!(matches!(
            unauthorized,
            Failure::ApiUnauthorized {
                status: 401,
                www_authenticate: None
            }
        ));

        assert_eq!(FailureReason::Locked.flash_key(), "locked");
        assert_eq!(
            FailureReason::AlreadyAuthenticated.flash_key(),
            "already_authenticated"
        );
        let intercept = INTERCEPT_401;
        assert!(!intercept);
    }

    #[tokio::test]
    async fn test_failure_decision_nav_api_recall() {
        use crate::config::DeviseConfig;
        let config = DeviseConfig::default();
        let mapping = failure_test_mapping();

        // Navigational: redirect with stored location.
        let navigational = build_failure(
            &html_request("/protected"),
            &mapping,
            &config,
            FailureReason::Unauthenticated,
        );
        assert!(matches!(
            navigational,
            Failure::NavigationalRedirect {
                flash_key: "unauthenticated",
                ..
            }
        ));
        assert_eq!(navigational.stored_location(), Some("/protected"));

        // API: 401 without redirect or stored location.
        let mut api = crate::request::AuthRequest::new(
            crate::request::HttpMethod::Get,
            "/api/resource".to_string(),
        );
        api.headers
            .insert("accept".to_string(), "application/json".to_string());
        let api_config = DeviseConfig {
            navigational_formats: vec!["html".to_string()],
            ..DeviseConfig::default()
        };
        let unauthorized = build_failure(&api, &mapping, &api_config, FailureReason::Invalid);
        assert_eq!(unauthorized.status_code(), 401);
        assert!(unauthorized.stored_location().is_none());

        // HTTP Basic + API: WWW-Authenticate header present.
        let mut basic_config = api_config.clone();
        basic_config.http_authenticatable = true;
        let mut basic = api.clone();
        basic.headers.insert(
            "authorization".to_string(),
            "Basic dXNlcjpwYXNz".to_string(),
        );
        let challenged = build_failure(&basic, &mapping, &basic_config, FailureReason::Invalid);
        assert_eq!(
            challenged.www_authenticate(),
            // Devise quotes the realm (failure_app.rb:54 `realm.inspect`).
            Some("Basic realm=\"Application\"")
        );

        // HTTP Basic outranks recall (failure_app.rb:42-50 `respond`):
        // http_auth? is asked first, recall second.
        let mut basic_recall = basic.clone();
        basic_recall
            .params
            .insert("recall_controller".to_string(), "sessions".to_string());
        basic_recall
            .params
            .insert("recall_action".to_string(), "new".to_string());
        let recalled = build_failure(
            &basic_recall,
            &mapping,
            &basic_config,
            FailureReason::Invalid,
        );
        assert!(
            recalled.is_api_unauthorized(),
            "http_auth must win over recall (got {recalled:?})"
        );

        // Timeout on GET redirects to the attempted path, not the sign-in
        // page (failure_app.rb:135-149 redirect_url).
        let timed_out = build_failure(
            &html_request("/secret/page?q=1"),
            &mapping,
            &DeviseConfig::default(),
            FailureReason::Timeout,
        );
        assert!(matches!(
            timed_out,
            Failure::NavigationalRedirect {
                ref location,
                flash_key: "timeout",
                ..
            } if location == "/secret/page?q=1"
        ));

        // Recall: re-dispatch data preserved.
        let mut recall = html_request("/users/sign_in");
        recall
            .params
            .insert("recall_controller".to_string(), "sessions".to_string());
        recall
            .params
            .insert("recall_action".to_string(), "new".to_string());
        let recalled = build_failure(&recall, &mapping, &config, FailureReason::Invalid);
        assert!(matches!(recalled, Failure::Recall { .. }));
    }

    #[tokio::test]
    async fn test_stored_location() {
        use crate::config::DeviseConfig;
        let config = DeviseConfig::default();
        let store = FailureTestStore::default();

        // GET navigational request is stored.
        store_location(&html_request("/protected"), "user", &config, &store).await;
        assert_eq!(
            stored_location_for("user", &store).await.as_deref(),
            Some("/protected")
        );
        // Take clears the key.
        assert!(stored_location_for("user", &store).await.is_none());

        // POST is never stored.
        let mut post = crate::request::AuthRequest::new(
            crate::request::HttpMethod::Post,
            "/protected".to_string(),
        );
        post.headers
            .insert("accept".to_string(), "text/html".to_string());
        store_location(&post, "user", &config, &store).await;
        assert!(stored_location_for("user", &store).await.is_none());

        // Absolute URLs are rejected by the parser.
        assert!(crate::request::AuthRequest::parse_stored_uri("http://evil.example/x").is_none());
        assert_eq!(stored_location_key("user"), "user_return_to");
    }

    /// Defense in depth (`store_location.rb` + the S1 hardening): the READ
    /// path must validate too. A value poisoned straight into the session
    /// store (shared Redis, a stale server, a tampered session) must never
    /// surface as a `Location` header - `stored_location_for` returns None
    /// and consumes the key.
    #[tokio::test]
    async fn test_stored_location_read_validates_the_stored_value() {
        use crate::session::SessionStore;

        let store = FailureTestStore::default();

        // Protocol-relative backslash: passes no prefix check but browsers
        // normalize `\` to `/` - an off-host redirect.
        store
            .insert_value(
                &stored_location_key("user"),
                serde_json::json!("/\\evil.example"),
            )
            .await;
        assert!(
            stored_location_for("user", &store).await.is_none(),
            "a backslash target must not survive the read path"
        );
        // Read-once still applies: the poisoned key is consumed.
        assert_eq!(
            store.get_value(&stored_location_key("user")).await,
            None,
            "a rejected value must not linger in the store"
        );

        // A valid path still round-trips.
        store
            .insert_value(
                &stored_location_key("user"),
                serde_json::json!("/landing?tab=1"),
            )
            .await;
        assert_eq!(
            stored_location_for("user", &store).await.as_deref(),
            Some("/landing?tab=1")
        );
    }
}
