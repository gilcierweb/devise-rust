//! Error types - `DeviseError`, `ValidationErrors`, `ResourceWithErrors`, `BlankRecord`
//!
//! Mirrors Devise's error surface: `errors.add(attr, :symbol)` with I18n keys,
//! the `ResourceWithErrors` pattern from `find_or_initialize_with_errors`, and
//! the `BlankRecord` trait for paranoid-mode dummy records.

use crate::adapter::OrmError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Core Devise error taxonomy - all error paths from strategies, hooks, and
/// controller flows map to one of these variants.
///
/// Programmer-error taxonomy mirroring devise's raises: `Devise::Models::MissingAttribute` and the missing-mapping assert, each with an actionable message.
#[derive(Debug, Error)]
pub enum DeviseError {
    /// Configuration error (missing `secret_key`, invalid config combination)
    #[error("Configuration error: {0}")]
    Config(String),
    /// Devise's `Devise::Models::MissingAttribute`: the model is missing
    /// columns a selected module requires (comma-joined names).
    #[error("The following attribute(s) is (are) missing on your model: {0}")]
    MissingAttribute(String),
    /// Adapter/backend error
    #[error("Adapter error: {0}")]
    Adapter(#[from] OrmError),
    /// Record not found (`find_by_token` lookups, etc.)
    #[error("Record not found")]
    NotFound,
    /// Invalid credentials (wrong password, unknown user in paranoid mode)
    #[error("Invalid credentials")]
    InvalidCredentials,
    /// Token expired (reset password, confirmation, unlock)
    #[error("Token expired")]
    TokenExpired,
    /// Token invalid (tampered, malformed)
    #[error("Token invalid")]
    TokenInvalid,
    /// Account already confirmed
    #[error("Already confirmed")]
    AlreadyConfirmed,
    /// Account not locked (unlock attempted on unlocked account)
    #[error("Not locked")]
    NotLocked,
    /// Confirmation period expired
    #[error("Confirmation period expired")]
    ConfirmationPeriodExpired,
    /// Unauthorized access
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    /// Forbidden access
    #[error("Forbidden: {0}")]
    Forbidden(String),
    /// Internal error (should not happen in normal operation)
    #[error("Internal error: {0}")]
    Internal(String),
    /// Mailer/rendering error (template render failure, delivery failure)
    #[error("Mailer error: {0}")]
    Mailer(String),
}

/// Validation errors container - field -> list of I18n error keys
/// (e.g., `email` -> `[:blank, :invalid]`, `password` -> `[:too_short]`).
///
/// Mirrors `ActiveModel` `errors` with Devise's symbolic keys:
/// `:blank`, `:invalid`, `:not_found`, `:expired`, `:already_confirmed`,
/// `:not_locked`, `:confirmation_period_expired`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationErrors {
    inner: HashMap<String, Vec<String>>,
    /// Per-entry I18n interpolation options keyed by `(field, key)`.
    ///
    /// Devise's `errors.add(attr, :key, period: ...)` carries the
    /// interpolation payload beside the symbolic key
    /// (`confirmable.rb:82-83`); this parallel map is that payload. Keys
    /// stay the only rendered surface; options feed the renderer's
    /// `%{placeholder}` substitution, never the wire body by themselves.
    #[serde(skip)]
    options: HashMap<(String, String), Vec<(String, String)>>,
}

impl ValidationErrors {
    /// Create empty validation errors
    ///
    /// Constructs the errors map; the `ActiveModel` `errors` object mirror.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an error key for a field
    ///
    /// Mirrors `ActiveModel` `errors.add(attr, :symbol)` with devise's symbolic keys.
    pub fn add(&mut self, field: &str, key: &str) {
        self.inner
            .entry(field.to_string())
            .or_default()
            .push(key.to_string());
    }

    /// Add an error key for a field with I18n interpolation options.
    ///
    /// Mirrors `errors.add(attr, :key, period: "3 days")`
    /// (`devise/lib/devise/models/confirmable.rb:82-83`): the symbolic
    /// key rides the errors map exactly like [`Self::add`], and the
    /// named options become the renderer's `%{placeholder}`
    /// substitutions
    /// ([`translate`](crate::i18n::translate) consumes them through
    /// [`Self::options_for`]). Keys-only usage is unchanged: entries
    /// without options behave exactly like plain `add` calls.
    pub fn add_with_options(&mut self, field: &str, key: &str, options: &[(&str, &str)]) {
        self.add(field, key);
        if options.is_empty() {
            return;
        }
        self.options
            .entry((field.to_string(), key.to_string()))
            .or_default()
            .extend(
                options
                    .iter()
                    .map(|(name, value)| (name.to_string(), value.to_string())),
            );
    }

    /// Interpolation options for one `(field, key)` entry.
    ///
    /// The payload a renderer pairs with the symbolic key before the
    /// I18n lookup; empty for keys-only entries.
    #[must_use]
    pub fn options_for(&self, field: &str, key: &str) -> &[(String, String)] {
        self.options
            .get(&(field.to_string(), key.to_string()))
            .map_or(&[], Vec::as_slice)
    }

    /// Get all error keys for a field
    ///
    /// Mirrors `ActiveModel` `errors[attr]` reads.
    #[must_use]
    pub fn get(&self, field: &str) -> Option<&Vec<String>> {
        self.inner.get(field)
    }

    /// Check if there are any errors
    ///
    /// Mirrors `ActiveModel` `errors.empty?`, the branch point of every devise controller flow.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Get all fields that have errors
    ///
    /// Mirrors `ActiveModel` `errors.attribute_names`.
    #[must_use]
    pub fn fields(&self) -> Vec<String> {
        self.inner.keys().cloned().collect()
    }

    /// Get full messages for I18n interpolation (field + key pairs)
    ///
    /// Mirrors `ActiveModel` `errors.full_messages` rendered through I18n.
    #[must_use]
    pub fn full_messages(&self) -> Vec<(String, String)> {
        self.inner
            .iter()
            .flat_map(|(field, keys)| keys.iter().map(move |k| (field.clone(), k.clone())))
            .collect()
    }

    /// Merge another `ValidationErrors` into this one
    ///
    /// Mirrors `ActiveModel` `errors.merge!`; the interpolation options
    /// travel with their entries.
    pub fn merge(&mut self, other: ValidationErrors) {
        for (field, keys) in other.inner {
            self.inner.entry(field).or_default().extend(keys);
        }
        for (entry, opts) in other.options {
            self.options.entry(entry).or_default().extend(opts);
        }
    }
}

/// Unsaved record carrying validation errors - the `find_or_initialize_with_errors`
/// pattern from Devise. Returns a record (new or existing) with `errors` populated
/// instead of raising exceptions.
///
/// # Type Parameters
///
/// - `M`: The model type implementing `BlankRecord`
///
/// Mirrors `find_or_initialize_with_errors`: an unsaved record carrying errors instead of raising (do not collapse this to an Option).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceWithErrors<M> {
    /// The record (may be newly instantiated via `BlankRecord::blank()`)
    pub record: M,
    /// Validation errors preventing persistence
    pub errors: ValidationErrors,
}

impl<M> ResourceWithErrors<M> {
    /// Create a new `ResourceWithErrors`
    ///
    /// Wraps a record with its validation errors; mirrors the value devise's `find_or_initialize_with_errors` hands to controllers.
    #[must_use]
    pub fn new(record: M, errors: ValidationErrors) -> Self {
        Self { record, errors }
    }

    /// Check if the resource has no errors (can be persisted)
    ///
    /// Mirrors the `errors.empty?` check of the devise controller flows.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Trait for creating a "blank" record instance - used by `ParanoidStrategy`
/// to construct a dummy record for timing-safe password hashing when the user
/// doesn't exist.
///
/// Default implementation uses `Default::default()`; implement for types that
/// need specific initialization (e.g., setting required fields).
///
/// Mirrors the unsaved record `find_or_initialize_with_errors` returns instead of raising.
pub trait BlankRecord: Send + Sync + 'static {
    /// Create a blank instance
    fn blank() -> Self;
}

impl<M> BlankRecord for M
where
    M: Default + Send + Sync + 'static,
{
    fn blank() -> Self {
        M::default()
    }
}

/// UNSAFE attributes that must never be serialized or logged - Devise's
/// 18-attribute `UNSAFE_ATTRIBUTES_FOR_SERIALIZATION` from
/// `authenticatable.rb` plus the port's 3 virtual password fields
/// (`password`, `password_confirmation`, `current_password`), 21 entries.
///
/// These are excluded from `serializable_hash` and `Debug` implementations
/// to prevent credential leakage in logs, error reports, and API responses.
///
/// Mirrors the devise constant of the same name (`devise/lib/devise/models/authenticatable.rb`): attributes never serialized or printed.
pub const UNSAFE_ATTRIBUTES_FOR_SERIALIZATION: &[&str] = &[
    "encrypted_password",
    "reset_password_token",
    "reset_password_sent_at",
    "remember_created_at",
    "sign_in_count",
    "current_sign_in_at",
    "last_sign_in_at",
    "current_sign_in_ip",
    "last_sign_in_ip",
    "password_salt",
    "confirmation_token",
    "confirmed_at",
    "confirmation_sent_at",
    "remember_token",
    "unconfirmed_email",
    "failed_attempts",
    "locked_at",
    "unlock_token",
    "password",
    "password_confirmation",
    "current_password",
];

/// Check if an attribute name is in the UNSAFE list
///
/// Membership check mirroring devise's filter over `UNSAFE_ATTRIBUTES_FOR_SERIALIZATION` that keeps secrets out of logs and exceptions.
#[must_use]
pub fn is_unsafe_attribute(attr: &str) -> bool {
    UNSAFE_ATTRIBUTES_FOR_SERIALIZATION.contains(&attr)
}

/// Strip every UNSAFE attribute from a JSON map (Devise's
/// `serializable_hash` filter).
///
/// The application-facing enforcement seam for CONCERNS #6: models whose
/// `serializable_hash` (or any API-facing projection) is built by hand call
/// this on the map they are about to return, so `encrypted_password`,
/// `reset_password_token`, `confirmation_token`, `unlock_token`, sign-in IPs
/// and friends can never leak through serialization. The default
/// `Authenticatable::serializable_hash` is empty (nothing to leak); models
/// that widen it must call this filter.
///
/// == Examples
///
/// ```
/// use devise_rust::error::filter_unsafe_attributes;
///
/// let mut map = serde_json::Map::new();
/// map.insert("email".to_string(), serde_json::json!("user@example.com"));
/// map.insert("encrypted_password".to_string(), serde_json::json!("$2b$12$..."));
/// let safe = filter_unsafe_attributes(&map);
/// assert_eq!(safe["email"], serde_json::json!("user@example.com"));
/// assert!(safe.get("encrypted_password").is_none());
/// ```
#[must_use]
pub fn filter_unsafe_attributes(
    map: &serde_json::Map<String, serde_json::Value>,
) -> serde_json::Map<String, serde_json::Value> {
    map.iter()
        .filter(|(key, _)| !is_unsafe_attribute(key))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

/// Render [`ValidationErrors`] as the keyed JSON body the framework
/// controllers emit for validation failures: one field mapped to the
/// ordered list of its symbolic I18n error keys (en.yml symbols, never
/// record values).
///
/// This is the single core definition of a body the actix and axum
/// routers previously carried as byte-for-byte duplicates; both now
/// consume this one (the consolidation the DRY audit asked for). The
/// output shape is pinned against the pre-change verbatim output:
/// `full_messages` yields every `(field, key)` pair in insertion order,
/// grouped per field exactly like the removed framework copies.
///
/// == Examples
///
/// ```
/// use devise_rust::error::{ValidationErrors, errors_json};
///
/// let mut errors = ValidationErrors::new();
/// errors.add("email", ":blank");
/// errors.add("email", ":invalid");
/// let rendered = errors_json(&errors);
/// assert_eq!(rendered["email"][0], ":blank");
/// assert_eq!(rendered["email"][1], ":invalid");
/// ```
#[must_use]
pub fn errors_json(errors: &ValidationErrors) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for (field, message) in errors.full_messages() {
        if let Some(list) = map
            .entry(field)
            .or_insert_with(|| serde_json::Value::Array(Vec::new()))
            .as_array_mut()
        {
            list.push(serde_json::Value::String(message));
        }
    }
    serde_json::Value::Object(map)
}

/// Render the per-entry I18n interpolation options as the JSON payload a
/// renderer pairs with [`errors_json`]: one object keyed
/// `"{field}::{key}"` mapping the option names to their values.
///
/// Empty (`{}`) when no entry carries options, so the plain keys-only
/// flows add nothing to their payloads. The options are the Devise
/// `errors.add(attr, :key, period: ...)` payload
/// (`confirmable.rb:82-83`): the renderer feeds them into the
/// `%{placeholder}` substitution
/// ([`translate`](crate::i18n::translate)) of the symbolic key.
///
/// == Examples
///
/// ```
/// use devise_rust::error::{ValidationErrors, errors_options_json};
///
/// let mut errors = ValidationErrors::new();
/// assert_eq!(errors_options_json(&errors), serde_json::json!({}));
/// errors.add_with_options("email", ":confirmation_period_expired", &[("period", "3 days")]);
/// assert_eq!(
///     errors_options_json(&errors),
///     serde_json::json!({
///         "email::confirmation_period_expired": { "period": "3 days" }
///     })
/// );
/// ```
#[must_use]
pub fn errors_options_json(errors: &ValidationErrors) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for ((field, key), options) in &errors.options {
        let entry: serde_json::Map<String, serde_json::Value> = options
            .iter()
            .map(|(name, value)| (name.clone(), serde_json::Value::String(value.clone())))
            .collect();
        // The stored keys carry Devise's leading colon (":blank"); the
        // composite drops it so the idiom reads "field::key".
        let bare = key.trim_start_matches(':');
        map.insert(format!("{field}::{bare}"), serde_json::Value::Object(entry));
    }
    serde_json::Value::Object(map)
}

/// Debug redaction for OWNED models: the `inspect` half of
/// [`UNSAFE_ATTRIBUTES_FOR_SERIALIZATION`] for concrete application types.
///
/// Core redacts the trait-object path already (`AnyDeviseModel` prints only
/// the filtered hash wherever core formats a record); a concrete model that
/// derives `Debug` bypasses that, and Devise's own answer is `inspect` over
/// `serializable_hash`. Application models therefore delegate: remove
/// `Debug` from the derive list and write
/// `impl fmt::Debug for User { fn fmt(&self, f) -> fmt::Result { devise_rust::error::Redacted(self).fmt(f) } }`.
/// Models whose `serializable_hash` is hand-written already exclude secrets;
/// the filter runs again here as the second line of defense.
///
/// == Examples
///
/// ```
/// use devise_rust::error::Redacted;
/// # use devise_rust::adapter::DeviseKey;
/// # use devise_rust::failure::AnyDeviseModel;
/// # struct User { id: i64, email: String, encrypted_password: String }
/// # impl AnyDeviseModel for User {
/// #     fn to_key(&self) -> DeviseKey { DeviseKey::from_i64(self.id) }
/// #     fn redacted_hash(&self) -> serde_json::Value {
/// #         serde_json::json!({
/// #             "id": self.id,
/// #             "email": self.email,
/// #             "encrypted_password": self.encrypted_password,
/// #         })
/// #     }
/// #     fn as_any(&self) -> &dyn std::any::Any { self }
/// # }
/// let user = User {
///     id: 7,
///     email: "user@example.com".to_string(),
///     encrypted_password: "$2b$12$notprintable".to_string(),
/// };
/// let printed = format!("{user:?}", user = Redacted(&user));
/// assert!(printed.contains("user@example.com"), "safe fields still print");
/// assert!(!printed.contains("encrypted_password"));
/// assert!(!printed.contains("notprintable"));
/// ```
#[derive(Clone, Copy)]
pub struct Redacted<'a>(pub &'a dyn crate::failure::AnyDeviseModel);

impl std::fmt::Debug for Redacted<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0.redacted_hash() {
            serde_json::Value::Object(map) => {
                let safe = filter_unsafe_attributes(&map);
                f.debug_map()
                    .entries(safe.iter().map(|(k, v)| (k.as_str(), v)))
                    .finish()
            }
            other => write!(f, "{other}"),
        }
    }
}

impl From<crate::failure::Failure> for DeviseError {
    fn from(failure: crate::failure::Failure) -> Self {
        DeviseError::Internal(format!("{failure:?}"))
    }
}

#[cfg(test)]
mod redaction_tests {
    use super::*;
    use crate::adapter::DeviseKey;

    #[derive(serde::Serialize)]
    struct LeakyUser {
        id: i64,
        email: String,
        encrypted_password: String,
        reset_password_token: Option<String>,
    }

    impl crate::failure::AnyDeviseModel for LeakyUser {
        fn to_key(&self) -> DeviseKey {
            DeviseKey::from_i64(self.id)
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }

        fn redacted_hash(&self) -> serde_json::Value {
            let map = serde_json::to_value(self).expect("serializes");
            match map {
                serde_json::Value::Object(map) => {
                    serde_json::Value::Object(filter_unsafe_attributes(&map))
                }
                other => other,
            }
        }
    }

    /// CONCERNS #6: the owned-model redaction prints safe fields and never
    /// the bcrypt digest or the token (the derive(Debug) leak the demos
    /// carried, closed 2026-10-25).
    #[test]
    fn redacted_debug_never_prints_secrets() {
        let user = LeakyUser {
            id: 42,
            email: "user@example.com".to_string(),
            encrypted_password: "$2b$12$deadbeef".to_string(),
            reset_password_token: Some("rawtokenvalue".to_string()),
        };
        let printed = format!("{:?}", Redacted(&user));
        assert!(printed.contains("user@example.com"));
        assert!(printed.contains("42"));
        assert!(!printed.contains("deadbeef"));
        assert!(!printed.contains("encrypted_password"));
        assert!(!printed.contains("rawtokenvalue"));
        assert!(!printed.contains("reset_password_token"));
    }

    /// A model that keeps the default (no override) prints nothing.
    #[test]
    fn default_redacted_hash_is_empty() {
        struct PlainUser;

        impl crate::failure::AnyDeviseModel for PlainUser {
            fn to_key(&self) -> DeviseKey {
                DeviseKey::from_i64(0)
            }

            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        let user = PlainUser;
        assert_eq!(
            crate::failure::AnyDeviseModel::redacted_hash(&user),
            serde_json::Value::Object(serde_json::Map::new())
        );
        assert_eq!(
            format!("{:?}", Redacted(&user)),
            "{}",
            "the default projection is an empty map"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
    struct TestUser {
        id: i64,
        email: String,
        encrypted_password: String,
        name: String,
    }

    #[test]
    fn test_devise_error_variants() {
        assert!(matches!(
            DeviseError::Config(String::new()),
            DeviseError::Config(_)
        ));
        assert!(matches!(DeviseError::NotFound, DeviseError::NotFound));
        assert!(matches!(
            DeviseError::InvalidCredentials,
            DeviseError::InvalidCredentials
        ));
        assert!(matches!(
            DeviseError::TokenExpired,
            DeviseError::TokenExpired
        ));
    }

    #[test]
    fn test_validation_errors() {
        let mut errors = ValidationErrors::new();
        assert!(errors.is_empty());

        errors.add("email", ":blank");
        errors.add("email", ":invalid");
        errors.add("password", ":too_short");

        assert!(!errors.is_empty());
        assert_eq!(errors.get("email").unwrap().len(), 2);
        assert_eq!(errors.get("password").unwrap().len(), 1);
        let mut fields = errors.fields();
        fields.sort();
        assert_eq!(fields, vec!["email", "password"]);

        let messages = errors.full_messages();
        assert_eq!(messages.len(), 3);
    }

    #[test]
    fn test_resource_with_errors() {
        let user = TestUser::default();
        let mut errors = ValidationErrors::new();
        errors.add("email", ":blank");

        let resource = ResourceWithErrors::new(user.clone(), errors);
        assert!(!resource.is_valid());

        let valid_errors = ValidationErrors::new();
        let valid_resource = ResourceWithErrors::new(user, valid_errors);
        assert!(valid_resource.is_valid());
    }

    #[test]
    fn test_blank_record_default() {
        let user = TestUser::blank();
        assert_eq!(user.id, 0);
        assert_eq!(user.email.len(), 0);
    }

    #[test]
    fn test_unsafe_attributes() {
        assert!(is_unsafe_attribute("encrypted_password"));
        assert!(is_unsafe_attribute("reset_password_token"));
        assert!(is_unsafe_attribute("password"));
        assert!(is_unsafe_attribute("password_salt"));
        assert!(is_unsafe_attribute("remember_token"));
        assert!(!is_unsafe_attribute("email"));
        assert!(!is_unsafe_attribute("name"));
        assert!(!is_unsafe_attribute("id"));
    }

    #[test]
    fn test_unsafe_attributes_count() {
        // Devise's list carries 18 attributes (authenticatable.rb:58-61); the
        // port adds the 3 virtual password fields (password,
        // password_confirmation, current_password), so the list has 21 entries.
        assert_eq!(UNSAFE_ATTRIBUTES_FOR_SERIALIZATION.len(), 21);
    }

    /// The keyed error body both framework controllers render for
    /// validation failures: each field maps to the ordered list of its
    /// symbolic keys, byte-identical to the shape the routers emitted
    /// before the helper moved into core (T-261026-ghi-02: the output
    /// shape is pinned, never changed by the move).
    #[test]
    fn test_errors_json_pins_the_framework_shape() {
        let mut errors = ValidationErrors::new();
        assert_eq!(errors_json(&errors), serde_json::json!({}));

        errors.add("email", ":blank");
        errors.add("email", ":invalid");
        errors.add("password", ":too_short");
        assert_eq!(
            errors_json(&errors),
            serde_json::json!({
                "email": [":blank", ":invalid"],
                "password": [":too_short"],
            })
        );

        // Two fields render independently; a second key on the same field
        // appends (insertion order preserved).
        let mut nested = ValidationErrors::new();
        nested.add("email", ":taken");
        errors.merge(nested);
        assert_eq!(
            errors_json(&errors)["email"],
            serde_json::json!([":blank", ":invalid", ":taken"])
        );
    }

    /// The interpolation options ride the (field, key) entry exactly like
    /// Devise's `errors.add(attr, :key, period: ...)` payload, without
    /// changing the keys-only surface (M-8 / T-261026-ghk-01).
    #[test]
    fn test_add_with_options_carries_the_interpolation_payload() {
        let mut errors = ValidationErrors::new();
        errors.add_with_options(
            "email",
            ":confirmation_period_expired",
            &[("period", "3 days")],
        );
        // The keys map is unchanged by the options.
        assert_eq!(
            errors_json(&errors),
            serde_json::json!({ "email": [":confirmation_period_expired"] })
        );
        assert_eq!(
            errors.options_for("email", ":confirmation_period_expired"),
            &[("period".to_string(), "3 days".to_string())]
        );
        // A keys-only entry has no options.
        errors.add("password", ":too_short");
        assert_eq!(errors.options_for("password", ":too_short"), []);

        // Multiple options on one entry, and the rendered options JSON.
        errors.add_with_options("email", ":confirmation_period_expired", &[("count", "2")]);
        assert_eq!(
            errors.options_for("email", ":confirmation_period_expired"),
            &[
                ("period".to_string(), "3 days".to_string()),
                ("count".to_string(), "2".to_string())
            ]
        );
        assert_eq!(
            errors_options_json(&errors),
            serde_json::json!({
                "email::confirmation_period_expired": { "period": "3 days", "count": "2" }
            })
        );
        assert_eq!(
            errors_options_json(&ValidationErrors::new()),
            serde_json::json!({})
        );
    }

    /// `errors.merge!` carries the options with their entries.
    #[test]
    fn test_merge_carries_options() {
        let mut errors = ValidationErrors::new();
        errors.add("email", ":invalid");
        let mut incoming = ValidationErrors::new();
        incoming.add_with_options(
            "email",
            ":confirmation_period_expired",
            &[("period", "3 days")],
        );
        errors.merge(incoming);
        assert_eq!(
            errors.get("email").map(Vec::as_slice),
            Some(
                &[
                    ":invalid".to_string(),
                    ":confirmation_period_expired".to_string()
                ][..]
            )
        );
        assert_eq!(
            errors.options_for("email", ":confirmation_period_expired"),
            &[("period".to_string(), "3 days".to_string())]
        );
    }
}
