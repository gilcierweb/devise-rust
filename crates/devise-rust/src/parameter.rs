//! Parameter filtering and sanitization - `ParameterFilter` and `ParameterSanitizer`
//!
//! Mirrors `Devise::ParameterFilter` and `Devise::ParameterSanitizer` (`devise/lib/devise/parameter_filter.rb`, `parameter_sanitizer.rb`).

use crate::config::DeviseConfig;
use crate::error::DeviseError;
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};

/// Filter parameters for case-insensitivity and whitespace stripping
///
/// Mirrors `Devise::ParameterFilter` (`devise/lib/devise/parameter_filter.rb`).
pub struct ParameterFilter;

impl ParameterFilter {
    /// Apply Devise's parameter filtering to a JSON value
    ///
    /// - Downcases `case_insensitive_keys`
    /// - Strips whitespace from `strip_whitespace_keys`
    /// - Non-string scalars are left typed (stringify at the query layer if needed)
    ///
    /// The per-value rules live in
    /// [`crate::model::normalize_credential_value`] - the single home shared
    /// with the finder and write paths, so this method only owns the JSON-tree
    /// walk.
    ///
    /// Mirrors `ParameterFilter#filter`: downcase `case_insensitive_keys`, strip `strip_whitespace_keys`, and stringify scalar values.
    pub fn filter(value: &mut Value, config: &DeviseConfig) {
        match value {
            Value::Object(map) => {
                for (key, val) in map.iter_mut() {
                    if let Value::String(text) = val {
                        let raw = std::mem::take(text);
                        *text = crate::model::normalize_credential_value(
                            &raw,
                            key,
                            &config.case_insensitive_keys,
                            &config.strip_whitespace_keys,
                        );
                    }
                    // Recurse for nested objects
                    Self::filter(val, config);
                }
            }
            Value::Array(arr) => {
                for item in arr.iter_mut() {
                    Self::filter(item, config);
                }
            }
            _ => {}
        }
    }
}

/// Read one credential param value honoring Devise's param shapes.
///
/// Precedence: the scoped `{singular}[{key}]` bracket form, the bridge
/// flat `{singular}_{key}` form, then the bare `{key}` (the framework
/// body maps usually already collapse the bracket form to the bare key;
/// the lookup keeps working over raw maps too). Mirrors the params
/// parsing of Devise's authenticatable strategy: `params[scope]` plus
/// `parse_authentication_key_values`
/// (`devise/lib/devise/strategies/authenticatable.rb`).
///
/// Missing or non-string values read as the empty string, exactly like
/// the per-framework lookups this replaces (the bridge flat key
/// previously reached only the axum controller).
///
/// == Examples
///
/// ```
/// use devise_rust::parameter::param_for;
/// use serde_json::json;
///
/// let params = json!({
///     "user_email": "bridge@example.com",
///     "email": "bare@example.com",
/// }).as_object().unwrap().clone();
/// assert_eq!(param_for(&params, "user", "email"), "bridge@example.com");
///
/// let bare_only = json!({ "email": "bare@example.com" }).as_object().unwrap().clone();
/// assert_eq!(param_for(&bare_only, "user", "email"), "bare@example.com");
/// assert_eq!(param_for(&bare_only, "user", "name"), "");
/// ```
#[must_use]
pub fn param_for(
    params: &Map<String, Value>,
    singular: &str,
    key: &str,
) -> String {
    let scoped = format!("{singular}[{key}]");
    let flat = format!("{singular}_{key}");
    params
        .get(&scoped)
        .or_else(|| params.get(&flat))
        .or_else(|| params.get(key))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

/// Whether the parsed params request a persistent sign-in (Devise
/// `remember_me`).
///
/// Devise's sign-in form posts the string `"1"` (`TRUE_VALUES`
/// membership, `devise/lib/devise/strategies/authenticatable.rb:56-57`);
/// JSON clients send a real boolean. Both shapes mean the same thing,
/// so the string arm reuses
/// [`is_true_value`](crate::rememberable::is_true_value) - the single
/// `TRUE_VALUES` home - instead of per-framework copies (the axum
/// controller previously honored only the string shape, silently
/// dropping `remember_me: true` from JSON clients).
///
/// == Examples
///
/// ```
/// use devise_rust::parameter::remember_me_from;
/// use serde_json::json;
///
/// assert!(remember_me_from(json!({ "remember_me": true }).as_object().unwrap()));
/// assert!(remember_me_from(json!({ "remember_me": "1" }).as_object().unwrap()));
/// assert!(!remember_me_from(json!({ "remember_me": "0" }).as_object().unwrap()));
/// assert!(!remember_me_from(json!({}).as_object().unwrap()));
/// ```
#[must_use]
pub fn remember_me_from(params: &Map<String, Value>) -> bool {
    params.get("remember_me").is_some_and(|value| match value {
        Value::Bool(flag) => *flag,
        Value::String(text) => crate::rememberable::is_true_value(text),
        _ => false,
    })
}

/// Strong-parameters style sanitizer for Devise actions
///
/// Mirrors `Devise::ParameterSanitizer` (`devise/lib/devise/parameter_sanitizer.rb`).
#[derive(Debug, Clone, Default)]
pub struct ParameterSanitizer {
    /// Permitted keys per action
    permitted: HashMap<String, HashSet<String>>,
}

impl ParameterSanitizer {
    /// Create a new sanitizer with Devise defaults
    ///
    /// Mirrors the sanitizer initialization from the auth keys, the way devise's initializer builds per-action defaults.
    #[must_use]
    pub fn new(config: &DeviseConfig) -> Self {
        let mut permitted = HashMap::new();

        // sign_in: authentication_keys + password + remember_me
        let mut sign_in_keys: HashSet<_> = config.authentication_keys.iter().cloned().collect();
        sign_in_keys.insert("password".to_string());
        sign_in_keys.insert("remember_me".to_string());
        permitted.insert("sign_in".to_string(), sign_in_keys);

        // sign_up: authentication_keys + password + password_confirmation
        let mut sign_up_keys: HashSet<_> = config.authentication_keys.iter().cloned().collect();
        sign_up_keys.insert("password".to_string());
        sign_up_keys.insert("password_confirmation".to_string());
        permitted.insert("sign_up".to_string(), sign_up_keys);

        // account_update: authentication_keys + password + password_confirmation + current_password
        let mut account_update_keys: HashSet<_> =
            config.authentication_keys.iter().cloned().collect();
        account_update_keys.insert("password".to_string());
        account_update_keys.insert("password_confirmation".to_string());
        account_update_keys.insert("current_password".to_string());
        permitted.insert("account_update".to_string(), account_update_keys);

        Self { permitted }
    }

    /// Get permitted keys for an action
    ///
    /// Reads the permitted keys for an action, mirroring the sanitizer's defaults table.
    #[must_use]
    pub fn permitted(&self, action: &str) -> Option<&HashSet<String>> {
        self.permitted.get(action)
    }

    /// Permit additional keys for an action
    ///
    /// Mirrors the sanitizer's `permit(action, keys:)` extension API.
    pub fn permit(&mut self, action: &str, keys: &[&str]) {
        let set = self.permitted.entry(action.to_string()).or_default();
        for key in keys {
            set.insert(key.to_string());
        }
    }

    /// Remove keys from permitted list for an action
    ///
    /// Mirrors the sanitizer's `except` extension option.
    pub fn except(&mut self, action: &str, keys: &[&str]) {
        if let Some(set) = self.permitted.get_mut(action) {
            for key in keys {
                set.remove(*key);
            }
        }
    }

    /// Sanitize parameters for an action, keeping only permitted keys.
    ///
    /// An action that was never registered (a missing `permit` call, or a typo
    /// in the caller's action name) is REPORTED as
    /// [`DeviseError::Config`], mirroring Devise's
    /// `unknown_action!` (`parameter_sanitizer.rb:162`), which raises
    /// `NotImplementedError` with actionable guidance:
    ///
    /// ```text
    /// Devise doesn't know how to sanitize parameters for 'sign_in'
    /// ```
    ///
    /// Devise raises into Rails' exception handler (a 500 for the request);
    /// a Rust `panic!` in a request-facing API does far more damage than a
    /// 500 - it unwinds the handler task, and on a `panic = "abort"` build it
    /// takes the whole process down - so the failure travels in the return
    /// value for the caller to render as an error response.
    ///
    /// # Errors
    ///
    /// `DeviseError::Config` when `action` has not been registered through
    /// [`Self::new`] or [`Self::permit`].
    ///
    /// Mirrors `ParameterSanitizer#sanitize(action)`: the permitted params for `sign_in`, `sign_up`, and `account_update`.
    pub fn sanitize(
        &self,
        action: &str,
        params: &Map<String, Value>,
    ) -> Result<Map<String, Value>, DeviseError> {
        let Some(permitted) = self.permitted.get(action) else {
            return Err(DeviseError::Config(format!(
                "Devise doesn't know how to sanitize parameters for '{action}'.\n\
                 If you want to define a new set of parameters to be sanitized use the \
                 `permit` method first:\n\
                 \u{20} ParameterSanitizer::permit(\"{action}\", &[\"param1\", \"param2\", \"param3\"])"
            )));
        };

        Ok(params
            .iter()
            .filter(|(k, _)| permitted.contains(*k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }

    /// Sanitize with a custom block for complex logic.
    ///
    /// # Errors
    ///
    /// `DeviseError::Config` when `action` has not been registered through
    /// [`Self::new`] or [`Self::permit`] (the block never runs).
    ///
    /// Mirrors the sanitizer's block form, `sanitize(action) { |attrs| ... }`.
    pub fn sanitize_with<F>(
        &self,
        action: &str,
        params: &Map<String, Value>,
        f: F,
    ) -> Result<Map<String, Value>, DeviseError>
    where
        F: FnOnce(&mut Map<String, Value>),
    {
        let mut sanitized = self.sanitize(action, params)?;
        f(&mut sanitized);
        Ok(sanitized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DeviseConfig;
    use serde_json::json;

    #[test]
    fn test_parameter_filter_downcase() {
        let config = DeviseConfig {
            case_insensitive_keys: vec!["email".to_string()],
            ..DeviseConfig::default()
        };

        let mut params = json!({
            "email": "USER@EXAMPLE.COM",
            "password": "secret"
        });

        ParameterFilter::filter(&mut params, &config);

        assert_eq!(params["email"], "user@example.com");
        assert_eq!(params["password"], "secret"); // unchanged
    }

    #[test]
    fn test_parameter_filter_strip_whitespace() {
        let config = DeviseConfig {
            strip_whitespace_keys: vec!["email".to_string()],
            ..DeviseConfig::default()
        };

        let mut params = json!({
            "email": "  user@example.com  ",
            "password": "secret"
        });

        ParameterFilter::filter(&mut params, &config);

        assert_eq!(params["email"], "user@example.com");
    }

    #[test]
    fn test_parameter_filter_nested() {
        let config = DeviseConfig {
            case_insensitive_keys: vec!["email".to_string()],
            ..DeviseConfig::default()
        };

        let mut params = json!({
            "user": {
                "email": "USER@EXAMPLE.COM"
            }
        });

        ParameterFilter::filter(&mut params, &config);

        assert_eq!(params["user"]["email"], "user@example.com");
    }

    /// Devise's `String#downcase` is Unicode-aware; the filter must share the
    /// single normalization home instead of an ASCII-only lowercase.
    #[test]
    fn test_parameter_filter_downcase_is_unicode_aware() {
        let config = DeviseConfig {
            case_insensitive_keys: vec!["email".to_string()],
            ..DeviseConfig::default()
        };

        let mut params = json!({
            "email": "ÜSER@ÉXAMPLE.COM",
            "password": "secret"
        });

        ParameterFilter::filter(&mut params, &config);

        assert_eq!(params["email"], "üser@éxample.com");
    }

    #[test]
    fn test_parameter_sanitizer_defaults() {
        let config = DeviseConfig::default();
        let sanitizer = ParameterSanitizer::new(&config);

        let sign_in = sanitizer.permitted("sign_in").unwrap();
        assert!(sign_in.contains("email"));
        assert!(sign_in.contains("password"));
        assert!(sign_in.contains("remember_me"));

        let sign_up = sanitizer.permitted("sign_up").unwrap();
        assert!(sign_up.contains("email"));
        assert!(sign_up.contains("password"));
        assert!(sign_up.contains("password_confirmation"));

        let account_update = sanitizer.permitted("account_update").unwrap();
        assert!(account_update.contains("email"));
        assert!(account_update.contains("current_password"));
    }

    #[test]
    fn test_parameter_sanitizer_sanitize() {
        let config = DeviseConfig::default();
        let sanitizer = ParameterSanitizer::new(&config);

        let raw_params = json!({
            "email": "user@example.com",
            "password": "secret",
            "password_confirmation": "secret",
            "current_password": "old",
            "unpermitted": "value"
        });

        let result = sanitizer
            .sanitize("sign_up", raw_params.as_object().unwrap())
            .expect("sign_up is a registered action");

        assert_eq!(result.get("email").unwrap(), "user@example.com");
        assert_eq!(result.get("password").unwrap(), "secret");
        assert_eq!(result.get("password_confirmation").unwrap(), "secret");
        assert!(result.get("current_password").is_none());
        assert!(result.get("unpermitted").is_none());
    }

    #[test]
    fn test_parameter_sanitizer_permit_except() {
        let config = DeviseConfig::default();
        let mut sanitizer = ParameterSanitizer::new(&config);

        sanitizer.permit("sign_up", &["username", "avatar"]);
        assert!(sanitizer.permitted("sign_up").unwrap().contains("username"));

        sanitizer.except("sign_up", &["password_confirmation"]);
        assert!(
            !sanitizer
                .permitted("sign_up")
                .unwrap()
                .contains("password_confirmation")
        );
    }

    /// S7-core: `sanitize` is a request-facing API. An unregistered action is
    /// a configuration problem to REPORT, not a panic in the request path -
    /// Devise raises `NotImplementedError` ("Devise doesn't know how to
    /// sanitize parameters for '<action>'"), which the port maps to
    /// `DeviseError::Config`.
    #[test]
    fn test_parameter_sanitizer_unknown_action_reports_config_error() {
        let config = DeviseConfig::default();
        let sanitizer = ParameterSanitizer::new(&config);
        let params = json!({}).as_object().unwrap().clone();

        let error = sanitizer
            .sanitize("unknown_action", &params)
            .expect_err("an unregistered action is a config error, not a panic");
        assert!(
            matches!(error, DeviseError::Config(ref message) if message.contains("unknown_action")),
            "the error must name the action: {error:?}"
        );
        assert!(
            matches!(error, DeviseError::Config(ref message) if message.contains("permit")),
            "the error must carry Devise's actionable guidance: {error:?}"
        );

        // The block form propagates the same error instead of panicking.
        let block_error = sanitizer
            .sanitize_with("unknown_action", &params, |attrs| {
                attrs.clear();
            })
            .expect_err("the block form reports the same error");
        assert!(matches!(block_error, DeviseError::Config(_)));
    }

    /// The credential lookup precedence: the scoped bracket form, the
    /// bridge flat form, then the bare key (the flat `user_email` shape
    /// must reach the lookup on every framework, matching the axum
    /// controller's existing behavior).
    #[test]
    fn test_param_for_honors_the_devise_param_shapes() {
        let params = json!({
            "user[email]": "scoped@example.com",
            "user_email": "flat@example.com",
            "email": "bare@example.com",
        })
        .as_object()
        .unwrap()
        .clone();
        assert_eq!(
            param_for(&params, "user", "email"),
            "scoped@example.com",
            "the scoped bracket form wins"
        );

        let flat_and_bare = json!({
            "user_email": "flat@example.com",
            "email": "bare@example.com",
        })
        .as_object()
        .unwrap()
        .clone();
        assert_eq!(
            param_for(&flat_and_bare, "user", "email"),
            "flat@example.com",
            "the bridge flat form beats the bare key"
        );

        let bare_only = json!({ "email": "bare@example.com" })
            .as_object()
            .unwrap()
            .clone();
        assert_eq!(param_for(&bare_only, "user", "email"), "bare@example.com");

        // Missing and non-string values read as the empty string.
        let non_string = json!({ "email": 42 }).as_object().unwrap().clone();
        assert_eq!(param_for(&non_string, "user", "email"), "");
        assert_eq!(param_for(&serde_json::Map::new(), "user", "email"), "");
    }

    /// `remember_me` accepts the JSON boolean AND the Devise `TRUE_VALUES`
    /// strings through the same `is_true_value` rule the actix controller
    /// used (the axum leg previously dropped the boolean shape).
    #[test]
    fn test_remember_me_from_accepts_bool_and_true_value_strings() {
        let of = |value: serde_json::Value| {
            json!({ "remember_me": value })
                .as_object()
                .cloned()
                .expect("object")
        };
        assert!(remember_me_from(&of(json!(true))));
        assert!(!remember_me_from(&of(json!(false))));
        // Devise's TRUE_VALUES: "1", "on", "t", "true" (case variants).
        for text in ["1", "on", "ON", "t", "T", "true", "TRUE"] {
            assert!(
                remember_me_from(&of(json!(text))),
                "'{text}' must request a persistent sign-in"
            );
        }
        // Everything else means a session-only sign-in.
        for text in ["0", "yes", "false", ""] {
            assert!(
                !remember_me_from(&of(json!(text))),
                "'{text}' must not request a persistent sign-in"
            );
        }
        assert!(!remember_me_from(&of(json!(7))));
        assert!(!remember_me_from(&serde_json::Map::new()));
    }
}
