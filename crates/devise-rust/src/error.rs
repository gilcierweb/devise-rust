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
#[derive(Debug, Error)]
pub enum DeviseError {
    /// Configuration error (missing `secret_key`, invalid config combination)
    #[error("Configuration error: {0}")]
    Config(String),
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
}

/// Validation errors container - field -> list of I18n error keys
/// (e.g., `email` -> `[:blank, :invalid]`, `password` -> `[:too_short]`).
///
/// Mirrors `ActiveModel` `errors` with Devise's symbolic keys:
/// `:blank`, `:invalid`, `:not_found`, `:expired`, `:already_confirmed`,
/// `:not_locked`, `:confirmation_period_expired`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ValidationErrors {
    inner: HashMap<String, Vec<String>>,
}

impl ValidationErrors {
    /// Create empty validation errors
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an error key for a field
    pub fn add(&mut self, field: &str, key: &str) {
        self.inner
            .entry(field.to_string())
            .or_default()
            .push(key.to_string());
    }

    /// Get all error keys for a field
    #[must_use]
    pub fn get(&self, field: &str) -> Option<&Vec<String>> {
        self.inner.get(field)
    }

    /// Check if there are any errors
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Get all fields that have errors
    #[must_use]
    pub fn fields(&self) -> Vec<String> {
        self.inner.keys().cloned().collect()
    }

    /// Get full messages for I18n interpolation (field + key pairs)
    #[must_use]
    pub fn full_messages(&self) -> Vec<(String, String)> {
        self.inner
            .iter()
            .flat_map(|(field, keys)| keys.iter().map(move |k| (field.clone(), k.clone())))
            .collect()
    }

    /// Merge another `ValidationErrors` into this one
    pub fn merge(&mut self, other: ValidationErrors) {
        for (field, keys) in other.inner {
            self.inner.entry(field).or_default().extend(keys);
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceWithErrors<M> {
    /// The record (may be newly instantiated via `BlankRecord::blank()`)
    pub record: M,
    /// Validation errors preventing persistence
    pub errors: ValidationErrors,
}

impl<M> ResourceWithErrors<M> {
    /// Create a new `ResourceWithErrors`
    #[must_use]
    pub fn new(record: M, errors: ValidationErrors) -> Self {
        Self { record, errors }
    }

    /// Check if the resource has no errors (can be persisted)
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

/// UNSAFE attributes that must never be serialized or logged - exact list from
/// Devise's `UNSAFE_ATTRIBUTES_FOR_SERIALIZATION` (18 attributes).
///
/// These are excluded from `serializable_hash` and `Debug` implementations
/// to prevent credential leakage in logs, error reports, and API responses.
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
    "confirmation_token",
    "confirmed_at",
    "confirmation_sent_at",
    "unconfirmed_email",
    "failed_attempts",
    "locked_at",
    "unlock_token",
    "password",
    "password_confirmation",
    "current_password",
];

/// Check if an attribute name is in the UNSAFE list
#[must_use]
pub fn is_unsafe_attribute(attr: &str) -> bool {
    UNSAFE_ATTRIBUTES_FOR_SERIALIZATION.contains(&attr)
}

impl From<crate::failure::Failure> for DeviseError {
    fn from(failure: crate::failure::Failure) -> Self {
        DeviseError::Internal(format!("{failure:?}"))
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
        assert!(user.email.is_empty());
    }

    #[test]
    fn test_unsafe_attributes() {
        assert!(is_unsafe_attribute("encrypted_password"));
        assert!(is_unsafe_attribute("reset_password_token"));
        assert!(is_unsafe_attribute("password"));
        assert!(!is_unsafe_attribute("email"));
        assert!(!is_unsafe_attribute("name"));
        assert!(!is_unsafe_attribute("id"));
    }

    #[test]
    fn test_unsafe_attributes_count() {
        // Devise has 19 unsafe attributes (updated from 18 in newer versions)
        assert_eq!(UNSAFE_ATTRIBUTES_FOR_SERIALIZATION.len(), 19);
    }
}
