//! Configuration module - `DeviseConfig` with all Devise options and per-scope overrides

use chrono::TimeDelta;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Serde module for `TimeDelta` (as seconds)
mod serde_time_delta {
    use chrono::TimeDelta;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(td: &TimeDelta, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_i64(td.num_seconds())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<TimeDelta, D::Error>
    where
        D: Deserializer<'de>,
    {
        let seconds = i64::deserialize(deserializer)?;
        Ok(TimeDelta::seconds(seconds))
    }
}

/// Serde module for `Option<TimeDelta>` (as seconds)
mod serde_time_delta_option {
    use chrono::TimeDelta;
    use serde::{Deserialize, Deserializer, Serializer};

    // serde's `with` attribute requires `&Option<T>` - the lint suggestion is incompatible
    #[allow(clippy::ref_option)]
    pub fn serialize<S>(td: &Option<TimeDelta>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match td {
            Some(t) => serializer.serialize_some(&t.num_seconds()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<TimeDelta>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let seconds = Option::<i64>::deserialize(deserializer)?;
        Ok(seconds.map(TimeDelta::seconds))
    }
}

/// Global Devise configuration with all options matching Devise 5.0.4
// The Devise surface has many independent boolean flags by design (parity requirement);
// grouping them into bitflags/enums would deviate from Devise's documented option names.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviseConfig {
    // Crypto
    /// Secret key used for token generation (HMAC key)
    pub secret_key: String,
    /// Pepper string appended to password before bcrypt (optional)
    pub pepper: Option<String>,
    /// Bcrypt cost factor (default: 12)
    pub stretches: u32,

    // Auth keys
    /// Keys used for authentication (default: `[:email]`)
    pub authentication_keys: Vec<String>,
    /// Additional keys required for authentication (default: [])
    pub request_keys: Vec<String>,
    /// Keys that are case-insensitive (default: `[:email]`)
    pub case_insensitive_keys: Vec<String>,
    /// Keys that should have whitespace stripped (default: `[:email]`)
    pub strip_whitespace_keys: Vec<String>,
    /// Enable HTTP authentication (default: false)
    pub http_authenticatable: bool,
    /// Key for HTTP authentication (default: nil)
    pub http_authentication_key: Option<String>,
    /// Enable HTTP auth on XHR (default: true)
    pub http_authenticatable_on_xhr: bool,
    /// Enable params authentication (default: true)
    pub params_authenticatable: bool,
    /// HTTP authentication realm (default: "Application")
    pub http_authentication_realm: String,

    // Validation
    /// Email regexp (default: /\A[^@\s]+@[^@\s]+\z/)
    pub email_regexp: String,
    /// Password length range (default: 6..128)
    pub password_length: std::ops::Range<usize>,

    // Rememberable
    /// Remember token validity (default: 2.weeks)
    #[serde(with = "serde_time_delta")]
    pub remember_for: TimeDelta,
    /// Extend remember period on each access (default: false)
    pub extend_remember_period: bool,
    /// Additional cookie options (default: {})
    pub rememberable_options: HashMap<String, String>,
    /// Expire all remember tokens on sign out (default: true)
    pub expire_all_remember_me_on_sign_out: bool,

    // Confirmable
    /// Time allowed for unconfirmed access (default: 0.days)
    #[serde(with = "serde_time_delta")]
    pub allow_unconfirmed_access_for: TimeDelta,
    /// Confirmation token validity (default: nil = no expiry)
    #[serde(with = "serde_time_delta_option")]
    pub confirm_within: Option<TimeDelta>,
    /// Keys used for confirmation (default: `[:email]`)
    pub confirmation_keys: Vec<String>,
    /// Require reconfirmation on email change (default: true)
    pub reconfirmable: bool,

    // Lockable
    /// Lock strategy: "`failed_attempts`" or "none" (default: "`failed_attempts`")
    pub lock_strategy: String,
    /// Unlock strategy: "time", "email", "both", "none" (default: "both")
    pub unlock_strategy: String,
    /// Keys for unlock (default: `[:email]`)
    pub unlock_keys: Vec<String>,
    /// Maximum failed attempts before lock (default: 20)
    pub maximum_attempts: u32,
    /// Time after which lock expires (default: 1.hour)
    #[serde(with = "serde_time_delta")]
    pub unlock_in: TimeDelta,
    /// Warn on last attempt (default: true)
    pub last_attempt_warning: bool,

    // Recoverable
    /// Keys for password reset (default: `[:email]`)
    pub reset_password_keys: Vec<String>,
    /// Reset token validity (default: 6.hours)
    #[serde(with = "serde_time_delta")]
    pub reset_password_within: TimeDelta,
    /// Sign in after password reset (default: true)
    pub sign_in_after_reset_password: bool,

    // Timeoutable
    /// Session timeout (default: 30.minutes)
    #[serde(with = "serde_time_delta")]
    pub timeout_in: TimeDelta,

    // Sessions / scopes
    /// Default scope (default: nil - Devise has no implicit default scope)
    pub default_scope: Option<String>,
    /// Sign out all scopes on sign out (default: true)
    pub sign_out_all_scopes: bool,
    /// Sign out via method (default: "delete")
    pub sign_out_via: String,
    /// Skip session storage for these strategies (default: `[:http_auth]`)
    pub skip_session_storage: Vec<String>,

    // Framework
    /// Parent controller (default: "`ApplicationController`")
    pub parent_controller: String,
    /// Parent mailer (default: "`ActionMailer::Base`")
    pub parent_mailer: String,
    /// Mailer sender (default: `nil`)
    pub mailer_sender: Option<String>,
    /// Router name (default: `nil`)
    pub router_name: Option<String>,
    /// Scoped views (default: false)
    pub scoped_views: bool,
    /// Navigational formats (default: `["*/*", :html, :turbo_stream]`)
    pub navigational_formats: Vec<String>,
    /// Responder class (default: "`Devise::Controllers::Responder`")
    pub responder: String,
    /// Reload routes (default: true)
    pub reload_routes: bool,
    /// Clean up CSRF token on authentication (default: true)
    pub clean_up_csrf_token_on_authentication: bool,
    /// `OmniAuth` path prefix (default: nil)
    pub omniauth_path_prefix: Option<String>,
    /// `OmniAuth` provider name allowlist (default: [])
    pub omniauth_providers: Vec<String>,

    // Behavior flags
    /// Paranoid mode - uniform failure messages + dummy password hash on missing users
    /// (default: false, matching Devise 5.0.4 `@@paranoid = false`)
    pub paranoid: bool,
    /// Send email changed notification (default: false)
    pub send_email_changed_notification: bool,
    /// Send password change notification (default: false)
    pub send_password_change_notification: bool,
    /// Sign in after password change (default: true)
    pub sign_in_after_change_password: bool,
}

impl Default for DeviseConfig {
    fn default() -> Self {
        Self {
            secret_key: String::new(),
            pepper: None,
            stretches: 12,
            authentication_keys: vec!["email".to_string()],
            request_keys: vec![],
            case_insensitive_keys: vec!["email".to_string()],
            strip_whitespace_keys: vec!["email".to_string()],
            http_authenticatable: false,
            http_authentication_key: None,
            http_authenticatable_on_xhr: true,
            params_authenticatable: true,
            http_authentication_realm: "Application".to_string(),
            email_regexp: r"\A[^@\s]+@[^@\s]+\z".to_string(),
            password_length: 6..128,
            remember_for: TimeDelta::weeks(2),
            extend_remember_period: false,
            rememberable_options: HashMap::new(),
            expire_all_remember_me_on_sign_out: true,
            allow_unconfirmed_access_for: TimeDelta::zero(),
            confirm_within: None,
            confirmation_keys: vec!["email".to_string()],
            reconfirmable: true,
            lock_strategy: "failed_attempts".to_string(),
            unlock_strategy: "both".to_string(),
            unlock_keys: vec!["email".to_string()],
            maximum_attempts: 20,
            unlock_in: TimeDelta::hours(1),
            last_attempt_warning: true,
            reset_password_keys: vec!["email".to_string()],
            reset_password_within: TimeDelta::hours(6),
            sign_in_after_reset_password: true,
            timeout_in: TimeDelta::minutes(30),
            default_scope: None,
            sign_out_all_scopes: true,
            sign_out_via: "delete".to_string(),
            skip_session_storage: vec!["http_auth".to_string()],
            parent_controller: "ApplicationController".to_string(),
            parent_mailer: "ActionMailer::Base".to_string(),
            mailer_sender: None,
            router_name: None,
            scoped_views: false,
            navigational_formats: vec![
                "*/*".to_string(),
                "html".to_string(),
                "turbo_stream".to_string(),
            ],
            responder: "Devise::Controllers::Responder".to_string(),
            reload_routes: true,
            clean_up_csrf_token_on_authentication: true,
            omniauth_path_prefix: None,
            omniauth_providers: vec![],
            paranoid: false,
            send_email_changed_notification: false,
            send_password_change_notification: false,
            sign_in_after_change_password: true,
        }
    }
}

/// Per-scope configuration override - all fields optional, cascade over global
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeviseConfigOverride {
    pub secret_key: Option<String>,
    pub pepper: Option<String>,
    pub stretches: Option<u32>,
    pub authentication_keys: Option<Vec<String>>,
    pub request_keys: Option<Vec<String>>,
    pub case_insensitive_keys: Option<Vec<String>>,
    pub strip_whitespace_keys: Option<Vec<String>>,
    pub http_authenticatable: Option<bool>,
    pub http_authentication_key: Option<String>,
    pub http_authenticatable_on_xhr: Option<bool>,
    pub params_authenticatable: Option<bool>,
    pub http_authentication_realm: Option<String>,
    pub email_regexp: Option<String>,
    pub password_length: Option<std::ops::Range<usize>>,
    #[serde(with = "serde_time_delta_option")]
    pub remember_for: Option<TimeDelta>,
    pub extend_remember_period: Option<bool>,
    pub rememberable_options: Option<HashMap<String, String>>,
    pub expire_all_remember_me_on_sign_out: Option<bool>,
    #[serde(with = "serde_time_delta_option")]
    pub allow_unconfirmed_access_for: Option<TimeDelta>,
    #[serde(with = "serde_time_delta_option")]
    pub confirm_within: Option<TimeDelta>,
    pub confirmation_keys: Option<Vec<String>>,
    pub reconfirmable: Option<bool>,
    pub lock_strategy: Option<String>,
    pub unlock_strategy: Option<String>,
    pub unlock_keys: Option<Vec<String>>,
    pub maximum_attempts: Option<u32>,
    #[serde(with = "serde_time_delta_option")]
    pub unlock_in: Option<TimeDelta>,
    pub last_attempt_warning: Option<bool>,
    pub reset_password_keys: Option<Vec<String>>,
    #[serde(with = "serde_time_delta_option")]
    pub reset_password_within: Option<TimeDelta>,
    pub sign_in_after_reset_password: Option<bool>,
    #[serde(with = "serde_time_delta_option")]
    pub timeout_in: Option<TimeDelta>,
    pub default_scope: Option<String>,
    pub sign_out_all_scopes: Option<bool>,
    pub sign_out_via: Option<String>,
    pub skip_session_storage: Option<Vec<String>>,
    pub parent_controller: Option<String>,
    pub parent_mailer: Option<String>,
    pub mailer_sender: Option<String>,
    pub router_name: Option<String>,
    pub scoped_views: Option<bool>,
    pub navigational_formats: Option<Vec<String>>,
    pub responder: Option<String>,
    pub reload_routes: Option<bool>,
    pub clean_up_csrf_token_on_authentication: Option<bool>,
    pub omniauth_path_prefix: Option<String>,
    pub omniauth_providers: Option<Vec<String>>,
    pub paranoid: Option<bool>,
    pub send_email_changed_notification: Option<bool>,
    pub send_password_change_notification: Option<bool>,
    pub sign_in_after_change_password: Option<bool>,
}

/// Macro to apply override fields to resolved config
/// Handles different type patterns:
/// - Direct assignment: `field` (config: T, override: Option<T>) -> resolved.field = v
/// - Option assignment: `field as Option` (config: Option<T>, override: Option<T>) -> resolved.field = Some(v.clone())
macro_rules! apply_override {
    // Pattern: config field is T, override is Option<T> -> assign directly
    ($resolved:ident, $self:ident, $($field:ident),*) => {
        $(
            if let Some(v) = &$self.$field {
                $resolved.$field = v.clone();
            }
        )*
    };
    // Pattern: config field is Option<T>, override is Option<T> -> wrap in Some
    ($resolved:ident, $self:ident, Option: $($field:ident),*) => {
        $(
            if let Some(v) = &$self.$field {
                $resolved.$field = Some(v.clone());
            }
        )*
    };
    // Pattern: config field is T (Copy), override is Option<T> -> assign directly
    ($resolved:ident, $self:ident, Copy: $($field:ident),*) => {
        $(
            if let Some(v) = $self.$field {
                $resolved.$field = v;
            }
        )*
    };
}

impl DeviseConfigOverride {
    /// Resolve override against global config, returning a complete `DeviseConfig`
    #[must_use]
    pub fn resolve(&self, global: &DeviseConfig) -> DeviseConfig {
        let mut resolved = global.clone();

        // Direct assignment (config: T, override: Option<T>)
        apply_override!(
            resolved,
            self,
            secret_key,
            authentication_keys,
            request_keys,
            case_insensitive_keys,
            strip_whitespace_keys,
            http_authentication_realm,
            email_regexp,
            password_length,
            rememberable_options,
            confirmation_keys,
            lock_strategy,
            unlock_strategy,
            unlock_keys,
            reset_password_keys,
            sign_out_via,
            skip_session_storage,
            parent_controller,
            parent_mailer,
            navigational_formats,
            responder,
            omniauth_providers
        );

        // Option assignment (config: Option<T>, override: Option<T>)
        apply_override!(resolved, self, Option:
            pepper,
            http_authentication_key,
            confirm_within,
            mailer_sender,
            router_name,
            omniauth_path_prefix,
            default_scope
        );

        // Copy assignment (config: T where T: Copy, override: Option<T>)
        apply_override!(resolved, self, Copy:
            stretches,
            http_authenticatable,
            http_authenticatable_on_xhr,
            params_authenticatable,
            extend_remember_period,
            expire_all_remember_me_on_sign_out,
            allow_unconfirmed_access_for,
            reconfirmable,
            maximum_attempts,
            last_attempt_warning,
            sign_in_after_reset_password,
            sign_out_all_scopes,
            scoped_views,
            reload_routes,
            clean_up_csrf_token_on_authentication,
            paranoid,
            send_email_changed_notification,
            send_password_change_notification,
            sign_in_after_change_password
        );

        // TimeDelta fields (config: TimeDelta, override: Option<TimeDelta>)
        // TimeDelta implements Copy, so we could use Copy, but keeping explicit for clarity
        apply_override!(resolved, self, Copy:
            remember_for,
            unlock_in,
            reset_password_within,
            timeout_in
        );

        resolved
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ported from `devise/test/devise_test.rb` - `Devise.email_regexp` matrix.
    #[test]
    fn test_email_regexp_matches_devise_matrix() {
        let config = DeviseConfig::default();
        // Ruby's \A…\z anchors translate to Rust regex as ^…$
        let re = regex::Regex::new(&config.email_regexp.replace(r"\A", "^").replace(r"\z", "$"))
            .expect("default email_regexp must compile");

        let valid = [
            "test@example.com",
            "jo@jo.co",
            "f4$_m@you.com",
            "testing.example@example.com.ua",
            "test@tt",
            "test@valid---domain.com",
        ];
        let invalid = [
            "rex",
            "test user@example.com",
            "test_user@example server.com",
        ];

        for email in valid {
            assert!(re.is_match(email), "expected valid: {email}");
        }
        for email in invalid {
            assert!(!re.is_match(email), "expected invalid: {email}");
        }
    }

    #[test]
    fn test_config_override_cascade() {
        let global = DeviseConfig::default();
        let override_config = DeviseConfigOverride {
            stretches: Some(10),
            pepper: Some("my-pepper".to_string()),
            ..DeviseConfigOverride::default()
        };

        let resolved = override_config.resolve(&global);
        assert_eq!(resolved.stretches, 10);
        assert_eq!(resolved.pepper, Some("my-pepper".to_string()));
        // Other values should come from global
        assert_eq!(resolved.remember_for, TimeDelta::weeks(2));
    }
}
