//! Failure enum - Warden-compatible failure decision types
//!
//! These are the failure modes that strategies and hooks can return to halt
//! the authentication chain. The decision logic (navigational vs API vs HTTP Basic
//! vs Recall) is added in Plan 04; this file defines the enum variants only.

use crate::adapter::DeviseKey;
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

    /// Downcast to concrete type
    fn as_any(&self) -> &dyn std::any::Any;
}

impl std::fmt::Debug for dyn AnyDeviseModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AnyDeviseModel(key={:?})", self.to_key())
    }
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
}
