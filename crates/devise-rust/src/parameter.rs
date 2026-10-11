//! Parameter filtering and sanitization - `ParameterFilter` and `ParameterSanitizer`
//!
//! Mirrors `Devise::ParameterFilter` and `Devise::ParameterSanitizer` (`devise/lib/devise/parameter_filter.rb`, `parameter_sanitizer.rb`).

use crate::config::DeviseConfig;
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
    /// Mirrors `ParameterFilter#filter`: downcase `case_insensitive_keys`, strip `strip_whitespace_keys`, and stringify scalar values.
    pub fn filter(value: &mut Value, config: &DeviseConfig) {
        match value {
            Value::Object(map) => {
                for (key, val) in map.iter_mut() {
                    if config.case_insensitive_keys.iter().any(|k| k == key) {
                        if let Value::String(s) = val {
                            *s = s.to_lowercase();
                        }
                    }
                    if config.strip_whitespace_keys.iter().any(|k| k == key) {
                        if let Value::String(s) = val {
                            *s = s.trim().to_string();
                        }
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

    /// Sanitize parameters for an action, keeping only permitted keys
    ///
    /// # Panics
    ///
    /// Panics if `action` has not been registered via [`Self::new`] or [`Self::permit`].
    /// Unknown actions are a programmer error, not a runtime condition - call sites
    /// must use the known action names (`sign_in`, `sign_up`, `account_update`).
    ///
    /// Mirrors `ParameterSanitizer#sanitize(action)`: the permitted params for `sign_in`, `sign_up`, and `account_update`.
    #[must_use]
    pub fn sanitize(&self, action: &str, params: &Map<String, Value>) -> Map<String, Value> {
        let Some(permitted) = self.permitted.get(action) else {
            panic!("unknown action '{action}' for parameter sanitization");
        };

        params
            .iter()
            .filter(|(k, _)| permitted.contains(*k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Sanitize with a custom block for complex logic
    ///
    /// Mirrors the sanitizer's block form, `sanitize(action) { |attrs| ... }`.
    pub fn sanitize_with<F>(
        &self,
        action: &str,
        params: &Map<String, Value>,
        f: F,
    ) -> Map<String, Value>
    where
        F: FnOnce(&mut Map<String, Value>),
    {
        let mut sanitized = self.sanitize(action, params);
        f(&mut sanitized);
        sanitized
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

        let result = sanitizer.sanitize("sign_up", raw_params.as_object().unwrap());

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

    #[test]
    #[should_panic(expected = "unknown action")]
    fn test_parameter_sanitizer_unknown_action() {
        let config = DeviseConfig::default();
        let sanitizer = ParameterSanitizer::new(&config);
        let params = json!({}).as_object().unwrap().clone();
        let _unused = sanitizer.sanitize("unknown_action", &params);
    }
}
