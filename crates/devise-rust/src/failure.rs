//! Failure enum - Warden-compatible failure decision types
//!
//! These are the failure modes that strategies and hooks can return to halt
//! the authentication chain. The decision logic (navigational vs API vs HTTP Basic
//! vs Recall) is added in Plan 04; this file defines the enum variants only.

use crate::adapter::DeviseKey;
use crate::request::AuthRequest;
use serde::{Deserialize, Serialize};

/// Type alias for authentication rules closure
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
    #[must_use]
    pub fn is_navigational(&self) -> bool {
        matches!(self, Failure::NavigationalRedirect { .. })
    }

    /// Check if this failure is an API unauthorized response
    #[must_use]
    pub fn is_api_unauthorized(&self) -> bool {
        matches!(self, Failure::ApiUnauthorized { .. })
    }

    /// Check if this failure is a recall
    #[must_use]
    pub fn is_recall(&self) -> bool {
        matches!(self, Failure::Recall { .. })
    }

    /// Get the flash key for navigational failures
    #[must_use]
    pub fn flash_key(&self) -> Option<&'static str> {
        match self {
            Failure::NavigationalRedirect { flash_key, .. } => Some(*flash_key),
            _ => None,
        }
    }

    /// Get the stored location for navigational failures
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
    #[must_use]
    pub fn status_code(&self) -> u16 {
        match self {
            Failure::ApiUnauthorized { status, .. } => *status,
            Failure::NavigationalRedirect { .. } => 302,
            _ => 401,
        }
    }

    /// Get the WWW-Authenticate header value if present
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
#[derive(Debug)]
pub enum AuthOutcome {
    /// Authentication succeeded with a user record
    Success(Box<dyn AnyDeviseModel>),
    /// Strategy passed (not applicable) - continue to next strategy
    Pass,
}

/// Trait for type-erased Devise models - allows storing heterogeneous models
/// in `AuthProxy`'s user map while preserving downcast capability.
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
            && self.authenticatable_salt() == other.authenticatable_salt()
    }

    /// Downcast to the password-checking facet, if this model stores a
    /// password hash (`DatabaseAuthenticatable` models override this).
    fn as_password_verifiable(&self) -> Option<&dyn crate::model::PasswordVerifiable> {
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
pub const INTERCEPT_401: bool = false;

/// Why authentication failed - maps to `devise.failure.*` I18n keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureReason {
    /// No session or credentials presented.
    Unauthenticated,
    /// Wrong credentials.
    Invalid,
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
    #[must_use]
    pub fn flash_key(self) -> &'static str {
        match self {
            FailureReason::Unauthenticated => "unauthenticated",
            FailureReason::Invalid => "invalid",
            FailureReason::Unconfirmed => "unconfirmed",
            FailureReason::Locked => "locked",
            FailureReason::Timeout => "timeout",
            FailureReason::AlreadyAuthenticated => "already_authenticated",
        }
    }
}

/// Check the request format against configured navigational formats.
///
/// Delegates to [`AuthRequest::is_navigational_format`](crate::request::AuthRequest::is_navigational_format).
#[must_use]
pub fn is_navigational_format(
    request: &crate::request::AuthRequest,
    config: &crate::config::DeviseConfig,
) -> bool {
    request.is_navigational_format(config)
}

/// Whether the request uses HTTP Basic auth that Devise should answer.
#[must_use]
pub fn http_auth(
    request: &crate::request::AuthRequest,
    config: &crate::config::DeviseConfig,
) -> bool {
    config.http_authenticatable && request.has_http_basic()
}

/// Core failure decision, mirroring `failure_app.rb`.
///
/// Priority: recall target, HTTP Basic, navigational redirect, API 401.
/// The stored location is kept only for `GET` navigational non-XHR
/// requests, per `store_location.rb`.
#[must_use]
pub fn build_failure(
    request: &crate::request::AuthRequest,
    mapping: &crate::scope::Mapping,
    config: &crate::config::DeviseConfig,
    reason: FailureReason,
) -> Failure {
    if let Some((controller, action)) = request.recall_target() {
        return Failure::Recall { controller, action };
    }
    if http_auth(request, config) {
        return Failure::ApiUnauthorized {
            status: 401,
            www_authenticate: Some(format!("Basic realm={}", config.http_authentication_realm)),
        };
    }
    if is_navigational_format(request, config) {
        let stored_location =
            if request.method == crate::request::HttpMethod::Get && !request.is_xhr() {
                AuthRequest::parse_stored_uri(&request.path)
            } else {
                None
            };
        return Failure::NavigationalRedirect {
            location: mapping.sign_in_path(),
            flash_key: reason.flash_key(),
            stored_location,
        };
    }
    Failure::ApiUnauthorized {
        status: 401,
        www_authenticate: None,
    }
}

/// Session key holding the post-sign-in redirect target.
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
    session_store.remove(&key).await;
    location.as_str().map(str::to_string)
}

/// Framework rendering contract for failures (S-13).
///
/// Core decides the `Failure`; bridges render it. Core never constructs
/// HTTP responses.
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
            www_authenticate: Some("Basic realm=Application".to_string()),
        };
        assert_eq!(
            api_basic.www_authenticate(),
            Some("Basic realm=Application")
        );

        let recall = Failure::Recall {
            controller: "sessions".to_string(),
            action: "new".to_string(),
        };
        assert!(recall.is_recall());
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
            Some("Basic realm=Application")
        );

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
}
