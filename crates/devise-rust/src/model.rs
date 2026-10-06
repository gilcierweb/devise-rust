//! Model traits - `Authenticatable` base, password checking, boxed finder bridge
//!
//! Mirrors `devise/lib/devise/models/authenticatable.rb`: default
//! implementations for validity checks, session serialization, and finders
//! with `ParameterFilter`-style normalization (AUTH-06).
//!
//! The [`ModelFinder`] bridge lets the strategy chain (`strategy.rs`) and
//! `AuthProxy` (`proxy.rs`) work with heterogeneous per-scope models through
//! one object-safe trait, while concrete adapters keep their typed
//! [`OrmAdapter`](crate::adapter::OrmAdapter) contract.

use crate::adapter::{Conditions, DeviseKey, OrmAdapter, Value};
use crate::config::DeviseConfig;
use crate::error::ResourceWithErrors;
use crate::error::ValidationErrors;
use crate::failure::{AnyDeviseModel, AuthRules};
use async_trait::async_trait;
use serde_json::Value as JsonValue;
use std::marker::PhantomData;

/// Normalize one credential value per Devise config (AUTH-06).
///
/// Single home for the downcase/trim rules that `ParameterFilter::filter`
/// applies to `serde_json::Value` trees; this is its flat `Conditions`
/// counterpart, shared by finders and strategies.
#[must_use]
pub fn normalize_credential_value(
    value: String,
    key: &str,
    case_insensitive_keys: &[String],
    strip_whitespace_keys: &[String],
) -> String {
    let mut value = value;
    if case_insensitive_keys.iter().any(|k| k == key) {
        value.make_ascii_lowercase();
    }
    if strip_whitespace_keys.iter().any(|k| k == key) {
        value = value.trim().to_string();
    }
    value
}

/// Normalize auth conditions per Devise config (AUTH-06).
///
/// Applies [`normalize_credential_value`] to every string entry, returning
/// a new map. Concrete models call this on their condition maps before
/// validation and lookup.
#[must_use]
pub fn normalize_auth_conditions(conditions: &Conditions, config: &DeviseConfig) -> Conditions {
    let mut normalized = Conditions::new();
    for (key, value) in conditions.iter() {
        let mut value = value.clone();
        if let Value::String(text) = &mut value {
            let raw = std::mem::take(text);
            *text = normalize_credential_value(
                raw,
                key,
                &config.case_insensitive_keys,
                &config.strip_whitespace_keys,
            );
        }
        normalized.insert(key.clone(), value);
    }
    normalized
}

/// Password-checking facet for `DatabaseAuthenticatable` models.
///
/// Strategies resolve it through
/// [`AnyDeviseModel::as_password_verifiable`](crate::failure::AnyDeviseModel::as_password_verifiable),
/// so the strategy chain never needs the concrete model type.
pub trait PasswordVerifiable: AnyDeviseModel {
    /// Check a plaintext password against the stored hash.
    fn valid_password(&self, password: &str, config: &DeviseConfig) -> bool;
}

// ============================================================================
// DatabaseAuthenticatable (DBAU-01..10)
// Mirrors devise/lib/devise/models/database_authenticatable.rb
// ============================================================================

/// `DatabaseAuthenticatable` module - password handling over
/// `encrypted_password` with virtual `password`/`password_confirmation`.
///
/// == Options
///
/// * `pepper` - appended to the password before bcrypt hashing
/// * `stretches` - bcrypt cost factor (default 12)
/// * `send_email_changed_notification` - email the ORIGINAL address on email change
/// * `send_password_change_notification` - email on password change
///
/// == Examples
///
/// ```ignore
/// user.set_password(Some("secret123".to_string()), &config);
/// assert!(user.valid_password("secret123", &config));
/// assert!(!user.valid_password("wrong", &config));
/// ```
#[async_trait]
pub trait DatabaseAuthenticatable: Authenticatable {
    /// Stored `encrypted_password` column value (None before first set).
    fn encrypted_password(&self) -> Option<&str>;
    /// Set the `encrypted_password` column (already hashed value).
    fn set_encrypted_password(&mut self, value: Option<String>);
    /// Virtual `password` attribute (never persisted).
    fn password(&self) -> Option<&str>;
    /// Store the virtual `password` value as-is (no hashing).
    fn set_password_virtual(&mut self, password: Option<String>);
    /// Virtual `password_confirmation` attribute.
    fn password_confirmation(&self) -> Option<&str>;
    /// Store the virtual `password_confirmation` value.
    fn set_password_confirmation(&mut self, value: Option<String>);
    /// Whether the record is persisted (Devise `persisted?`).
    fn persisted(&self) -> bool;
    /// Devise `assign_attributes` - model-defined mapping of raw params onto
    /// fields. Implementations must ignore `password`/`password_confirmation`/
    /// `current_password` keys (password assignment goes through
    /// [`set_password`](Self::set_password) which carries the config).
    fn assign_attributes(&mut self, attrs: &serde_json::Map<String, JsonValue>);

    /// `password=` setter (DBAU-01): encrypts via `Encryptor::digest`
    /// (stretches, pepper) and stores to `encrypted_password` ONLY when the
    /// password is present (Devise `password.present?` - None or empty skips).
    fn set_password(&mut self, password: Option<String>, config: &DeviseConfig) {
        if let Some(plain) = password.as_deref().filter(|p| !p.is_empty()) {
            let digest = crate::crypto::encryptor::digest(plain, config);
            self.set_encrypted_password(Some(digest));
        }
        self.set_password_virtual(password);
    }

    /// `valid_password?(password)` (DBAU-02): bcrypt verify via
    /// `Encryptor::compare` (constant-time). False when `encrypted_password`
    /// is blank (matches Devise).
    fn valid_password(&self, password: &str, config: &DeviseConfig) -> bool {
        match self.encrypted_password() {
            Some(hash) if !hash.is_empty() => {
                crate::crypto::encryptor::compare(password, hash, config)
            }
            _ => false,
        }
    }

    /// `authenticatable_salt` (DBAU-06): `encrypted_password[0,29]` - changing
    /// the password invalidates existing sessions. Wire the model's
    /// `AnyDeviseModel::authenticatable_salt` to this default.
    fn database_authenticatable_salt(&self) -> Option<String> {
        self.encrypted_password()
            .filter(|p| !p.is_empty())
            .and_then(|p| p.get(..29).map(str::to_string))
    }

    /// `clean_up_passwords` (DBAU-utils): clears the virtual password fields
    /// after save so they cannot leak into serialization. Devise
    /// `clean_up_passwords`.
    fn clean_up_passwords(&mut self) {
        self.set_password_virtual(None);
        self.set_password_confirmation(None);
    }

    /// Whether the email-change notification is suppressed
    /// (Devise `skip_email_changed_notification!` flag state).
    fn skips_email_changed_notification(&self) -> bool {
        false
    }

    /// Whether the password-change notification is suppressed
    /// (Devise `skip_password_change_notification!` flag state).
    fn skips_password_change_notification(&self) -> bool {
        false
    }

    /// Devise `skip_email_changed_notification!`: suppress the notification
    /// for the current in-flight update.
    fn skip_email_changed_notification(&mut self) {}

    /// Devise `skip_password_change_notification!`: suppress the notification
    /// for the current in-flight update.
    fn skip_password_change_notification(&mut self) {}

    /// `update_with_password(params)` (DBAU-03): requires the current password,
    /// strips blank password fields (so an untouched password is never reset),
    /// applies the remaining attributes. Returns the `:current_password :invalid`
    /// error after applying attrs (Devise re-renders the form with the edits).
    fn update_with_password(
        &mut self,
        params: &mut serde_json::Map<String, JsonValue>,
        config: &DeviseConfig,
    ) -> Result<(), ValidationErrors> {
        let current = params
            .remove("current_password")
            .and_then(|v| v.as_str().map(str::to_string));
        if params
            .get("password")
            .is_none_or(|p| p.as_str().is_none_or(str::is_empty))
        {
            params.remove("password");
            params.remove("password_confirmation");
        }

        let allowed = current
            .as_deref()
            .is_some_and(|pw| self.valid_password(pw, config));
        self.assign_attributes(params);
        let mut errors = ValidationErrors::new();
        if !allowed {
            errors.add("current_password", ":invalid");
        }
        self.clean_up_passwords();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// `update_without_password(params)` (DBAU-04): never touches password
    /// fields - strips all three keys and applies the rest.
    fn update_without_password(&mut self, params: &mut serde_json::Map<String, JsonValue>) {
        params.remove("password");
        params.remove("password_confirmation");
        params.remove("current_password");
        self.assign_attributes(params);
        self.clean_up_passwords();
    }

    /// `destroy_with_password(current_password)` (DBAU-05): destroys the
    /// record only when the supplied password is valid; returns whether the
    /// record was destroyed (Devise: `valid_password? && destroy`).
    async fn destroy_with_password<A>(
        &self,
        current_password: &str,
        adapter: &A,
        config: &DeviseConfig,
    ) -> Result<bool, crate::adapter::OrmError>
    where
        Self: Sized,
        A: OrmAdapter<Self> + Send + Sync,
    {
        if !self.valid_password(current_password, config) {
            return Ok(false);
        }
        adapter.delete(&self.to_key()).await?;
        Ok(true)
    }

    /// `after_database_authentication` hook (DBAU-07): documented no-op
    /// extension point, called by the strategy after successful password auth.
    fn after_database_authentication(&self) {}

    /// Email-change notification recipient (DBAU-08): the ORIGINAL email from
    /// the ChangeSet's previous value. `None` when the notification is
    /// disabled, skipped, or no email change occurred.
    fn email_notification_recipient(
        &self,
        changes: &crate::adapter::ChangeSet,
        config: &DeviseConfig,
    ) -> Option<String> {
        if !config.send_email_changed_notification || self.skips_email_changed_notification() {
            return None;
        }
        if !changes.has_changed("email") {
            return None;
        }
        match changes.previous_value("email") {
            Some(crate::adapter::Value::String(email)) if !email.is_empty() => Some(email.clone()),
            _ => None,
        }
    }

    /// Password-change notification decision (DBAU-09): pending when enabled,
    /// not skipped, and `encrypted_password` changed. Recipient is the record's
    /// current email (the new address wins for password changes).
    fn password_change_notification_pending(
        &self,
        changes: &crate::adapter::ChangeSet,
        config: &DeviseConfig,
    ) -> bool {
        config.send_password_change_notification
            && !self.skips_password_change_notification()
            && changes.has_changed("encrypted_password")
    }

    /// `find_for_database_authentication(conditions)` (DBAU-10): the strategy
    /// entry point - conditions arrive already filtered/normalized by the
    /// parameter layer (DBAU-strategy locked decision).
    async fn find_for_database_authentication<A>(
        conditions: &Conditions,
        adapter: &A,
        config: &DeviseConfig,
    ) -> Option<Self>
    where
        Self: Sized,
        A: OrmAdapter<Self> + Send + Sync,
    {
        Self::find_for_authentication(conditions, adapter, config).await
    }
}

/// `Authenticatable` base trait - mirrors Devise's `Authenticatable` module.
///
/// All Devise models implement this trait. Static finders are generic over
/// the adapter (`A: OrmAdapter<Self>`) instead of taking trait objects, since
/// `OrmAdapter` carries the `New` associated type and cannot be object-safe.
#[async_trait]
pub trait Authenticatable: AnyDeviseModel {
    /// Check if the record is valid for authentication.
    ///
    /// The optional `rules` closure lets modules AND-chain extra checks
    /// (Confirmable adds `confirmed`, Lockable adds `not locked`).
    fn valid_for_authentication(&self, rules: Option<&AuthRules>) -> bool
    where
        Self: Sized,
    {
        rules.is_none_or(|rule| rule(self as &dyn AnyDeviseModel))
    }

    /// Check if the record is active for authentication (default `true`).
    ///
    /// Overridden by modules: Confirmable returns false for unconfirmed
    /// records past the grace period, Lockable for locked records.
    fn active_for_authentication(&self) -> bool {
        true
    }

    /// Inactive message I18n key (default `"inactive"`).
    fn inactive_message(&self) -> &'static str {
        "inactive"
    }

    /// Unauthenticated message I18n key (default `"invalid"`).
    fn unauthenticated_message(&self) -> &'static str {
        "invalid"
    }

    /// Serialize record into session payload `(key, salt)`.
    ///
    /// Mirrors Devise's `serialize_into_session(record)`.
    fn serialize_into_session(&self) -> (DeviseKey, String)
    where
        Self: Sized,
    {
        self.session_pair()
    }

    /// Deserialize a session payload back to the record with salt validation.
    ///
    /// Returns `None` on missing record or salt mismatch (the caller deletes
    /// the session key on mismatch, per warden fetch semantics).
    async fn serialize_from_session<A>(key: &DeviseKey, salt: &str, adapter: &A) -> Option<Self>
    where
        Self: Sized,
        A: OrmAdapter<Self> + Send + Sync,
    {
        let record = adapter.get(key).await.ok()??;
        let current_salt = record.authenticatable_salt()?;
        if !crate::crypto::secure_compare(&current_salt, salt) {
            return None;
        }
        Some(record)
    }

    /// Find a record for authentication with normalized conditions.
    async fn find_for_authentication<A>(
        conditions: &Conditions,
        adapter: &A,
        config: &DeviseConfig,
    ) -> Option<Self>
    where
        Self: Sized,
        A: OrmAdapter<Self> + Send + Sync,
    {
        let filtered = Self::normalize_auth_attributes_static(conditions, config);
        adapter.find_first(&filtered).await.ok().flatten()
    }

    /// Alias for [`find_for_authentication`](Self::find_for_authentication).
    async fn find_first_by_auth_conditions<A>(
        conditions: &Conditions,
        adapter: &A,
        config: &DeviseConfig,
    ) -> Option<Self>
    where
        Self: Sized,
        A: OrmAdapter<Self> + Send + Sync,
    {
        Self::find_for_authentication(conditions, adapter, config).await
    }

    /// Find by one attribute or return a blank record carrying `error`.
    ///
    /// Mirrors Devise's `find_or_initialize_with_error_by`.
    async fn find_or_initialize_with_error_by<A>(
        attr: &str,
        value: &str,
        error: &str,
        adapter: &A,
        config: &DeviseConfig,
    ) -> ResourceWithErrors<Self>
    where
        Self: Sized + Default,
        A: OrmAdapter<Self> + Send + Sync,
    {
        let mut conditions = Conditions::new();
        conditions.insert(attr.to_string(), Value::String(value.to_string()));
        let filtered = Self::normalize_auth_attributes_static(&conditions, config);
        if let Ok(Some(record)) = adapter.find_first(&filtered).await {
            ResourceWithErrors::new(record, ValidationErrors::new())
        } else {
            let mut errors = ValidationErrors::new();
            errors.add(attr, error);
            ResourceWithErrors::new(Self::default(), errors)
        }
    }

    /// Find by several attributes or return a blank record with errors.
    ///
    /// Mirrors Devise's `find_or_initialize_with_errors`.
    async fn find_or_initialize_with_errors<A>(
        attrs: &[&str],
        conditions: &Conditions,
        error: &str,
        adapter: &A,
        config: &DeviseConfig,
    ) -> ResourceWithErrors<Self>
    where
        Self: Sized + Default,
        A: OrmAdapter<Self> + Send + Sync,
    {
        let filtered = Self::normalize_auth_attributes_static(conditions, config);
        if let Ok(Some(record)) = adapter.find_first(&filtered).await {
            ResourceWithErrors::new(record, ValidationErrors::new())
        } else {
            let mut errors = ValidationErrors::new();
            for attr in attrs {
                errors.add(attr, error);
            }
            ResourceWithErrors::new(Self::default(), errors)
        }
    }

    /// Serializable hash excluding unsafe attributes.
    ///
    /// Concrete models override this to serialize their fields while
    /// filtering [`UNSAFE_ATTRIBUTES_FOR_SERIALIZATION`](crate::error::UNSAFE_ATTRIBUTES_FOR_SERIALIZATION).
    fn serializable_hash(&self) -> JsonValue {
        JsonValue::Object(serde_json::Map::new())
    }

    /// Normalize conditions per config (delegates to [`normalize_auth_conditions`]).
    #[must_use]
    fn normalize_auth_attributes_static(
        conditions: &Conditions,
        config: &DeviseConfig,
    ) -> Conditions {
        normalize_auth_conditions(conditions, config)
    }
}

/// Object-safe read bridge over any typed adapter.
///
/// `OrmAdapter<M>` cannot be turned into a trait object over heterogeneous
/// models (it returns `M` by value and carries `type New`), so per-scope
/// finders are registered behind this erased trait instead. Mirrors the
/// `orm_adapter` gem's duck typing: each mapping resolves to its own model
/// class at registration time.
#[async_trait]
pub trait ModelFinder: Send + Sync {
    /// Fetch a record by primary key, boxed for heterogeneous storage.
    async fn get_boxed(
        &self,
        id: &DeviseKey,
    ) -> Result<Option<Box<dyn AnyDeviseModel>>, crate::adapter::OrmError>;

    /// Find the first record matching `conditions`, boxed.
    async fn find_first_boxed(
        &self,
        conditions: &Conditions,
    ) -> Result<Option<Box<dyn AnyDeviseModel>>, crate::adapter::OrmError>;
}

/// Bridges a typed `OrmAdapter<M>` into the erased [`ModelFinder`] contract.
pub struct AdapterBridge<A, M> {
    adapter: A,
    model: PhantomData<M>,
}

impl<A, M> AdapterBridge<A, M> {
    /// Wrap a typed adapter for registration under a scope.
    #[must_use]
    pub fn new(adapter: A) -> Self {
        Self {
            adapter,
            model: PhantomData,
        }
    }

    /// Access the inner typed adapter.
    #[must_use]
    pub fn inner(&self) -> &A {
        &self.adapter
    }
}

#[async_trait]
impl<A, M> ModelFinder for AdapterBridge<A, M>
where
    A: OrmAdapter<M> + Send + Sync,
    M: AnyDeviseModel + Send + Sync + 'static,
{
    async fn get_boxed(
        &self,
        id: &DeviseKey,
    ) -> Result<Option<Box<dyn AnyDeviseModel>>, crate::adapter::OrmError> {
        let record = self.adapter.get(id).await?;
        Ok(record.map(|model| Box::new(model) as Box<dyn AnyDeviseModel>))
    }

    async fn find_first_boxed(
        &self,
        conditions: &Conditions,
    ) -> Result<Option<Box<dyn AnyDeviseModel>>, crate::adapter::OrmError> {
        let record = self.adapter.find_first(conditions).await?;
        Ok(record.map(|model| Box::new(model) as Box<dyn AnyDeviseModel>))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::Value as AdapterValue;
    use crate::adapter::memory::MemoryAdapter;

    #[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
    struct TestUser {
        id: i64,
        email: String,
        encrypted_password: String,
        #[serde(skip)]
        password: Option<String>,
        #[serde(skip)]
        password_confirmation: Option<String>,
        #[serde(skip)]
        skip_email_notification: bool,
        #[serde(skip)]
        skip_password_notification: bool,
    }

    impl TestUser {
        fn testing(password: &str, config: &DeviseConfig) -> Self {
            Self {
                id: 1,
                email: "test@example.com".to_string(),
                encrypted_password: crate::crypto::encryptor::digest(password, config),
                password: None,
                password_confirmation: None,
                skip_email_notification: false,
                skip_password_notification: false,
            }
        }
    }

    impl AnyDeviseModel for TestUser {
        fn to_key(&self) -> DeviseKey {
            DeviseKey::from_i64(self.id)
        }

        fn authenticatable_salt(&self) -> Option<String> {
            self.encrypted_password.get(..29).map(str::to_string)
        }

        fn as_password_verifiable(&self) -> Option<&dyn PasswordVerifiable> {
            Some(self)
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    impl PasswordVerifiable for TestUser {
        fn valid_password(&self, password: &str, config: &DeviseConfig) -> bool {
            crate::crypto::encryptor::compare(password, &self.encrypted_password, config)
        }
    }

    impl Authenticatable for TestUser {
        fn serializable_hash(&self) -> JsonValue {
            serde_json::json!({ "id": self.id, "email": self.email })
        }
    }

    impl crate::mailer::HasEmail for TestUser {
        fn email(&self) -> &str {
            &self.email
        }
    }

    #[async_trait]
    impl DatabaseAuthenticatable for TestUser {
        fn encrypted_password(&self) -> Option<&str> {
            if self.encrypted_password.is_empty() {
                None
            } else {
                Some(&self.encrypted_password)
            }
        }

        fn set_encrypted_password(&mut self, value: Option<String>) {
            self.encrypted_password = value.unwrap_or_default();
        }

        fn password(&self) -> Option<&str> {
            self.password.as_deref()
        }

        fn set_password_virtual(&mut self, password: Option<String>) {
            self.password = password;
        }

        fn password_confirmation(&self) -> Option<&str> {
            self.password_confirmation.as_deref()
        }

        fn set_password_confirmation(&mut self, value: Option<String>) {
            self.password_confirmation = value;
        }

        fn persisted(&self) -> bool {
            self.id != 0
        }

        fn assign_attributes(&mut self, attrs: &serde_json::Map<String, JsonValue>) {
            // Password keys are virtual and hashed by set_password (config
            // needed), so assign_attributes deliberately skips them.
            if let Some(JsonValue::String(email)) = attrs.get("email") {
                self.email = email.clone();
            }
        }

        fn skips_email_changed_notification(&self) -> bool {
            self.skip_email_notification
        }

        fn skips_password_change_notification(&self) -> bool {
            self.skip_password_notification
        }

        fn skip_email_changed_notification(&mut self) {
            self.skip_email_notification = true;
        }

        fn skip_password_change_notification(&mut self) {
            self.skip_password_notification = true;
        }
    }

    fn test_config() -> DeviseConfig {
        DeviseConfig {
            stretches: 4,
            ..DeviseConfig::default()
        }
    }

    #[tokio::test]
    async fn test_authenticatable_trait() {
        let config = test_config();
        let adapter = MemoryAdapter::<TestUser>::new();
        let user = TestUser::testing("secret123", &config);
        adapter.create(user.clone()).await.unwrap();

        let mut conditions = Conditions::new();
        conditions.insert(
            "email",
            AdapterValue::String("test@example.com".to_string()),
        );
        let found = TestUser::find_for_authentication(&conditions, &adapter, &config).await;
        assert_eq!(found.map(|u| u.id), Some(1));

        let found = TestUser::find_first_by_auth_conditions(&conditions, &adapter, &config).await;
        assert!(found.is_some());

        let hit = TestUser::find_or_initialize_with_error_by(
            "email",
            "test@example.com",
            ":invalid",
            &adapter,
            &config,
        )
        .await;
        assert!(hit.is_valid());

        let miss = TestUser::find_or_initialize_with_error_by(
            "email",
            "missing@example.com",
            ":not_found",
            &adapter,
            &config,
        )
        .await;
        assert!(!miss.is_valid());
        assert_eq!(miss.errors.get("email").map(Vec::len), Some(1));

        let multi = TestUser::find_or_initialize_with_errors(
            &["email"],
            &conditions,
            ":invalid",
            &adapter,
            &config,
        )
        .await;
        assert!(multi.is_valid());
    }

    #[tokio::test]
    async fn test_serialize_from_session() {
        let config = test_config();
        let adapter = MemoryAdapter::<TestUser>::new();
        let user = TestUser::testing("secret123", &config);
        adapter.create(user.clone()).await.unwrap();

        let (key, salt) = user.serialize_into_session();
        let roundtrip = TestUser::serialize_from_session(&key, &salt, &adapter).await;
        assert!(roundtrip.is_some());

        let mismatch = TestUser::serialize_from_session(&key, "bogus-salt", &adapter).await;
        assert!(mismatch.is_none());
    }

    #[test]
    fn test_password_verifiable_facet() {
        let config = test_config();
        let user = TestUser::testing("secret123", &config);
        let facet = user.as_password_verifiable().expect("facet");
        assert!(facet.valid_password("secret123", &config));
        assert!(!facet.valid_password("wrong", &config));
    }

    #[test]
    fn test_serializable_hash_excludes_password() {
        let config = test_config();
        let user = TestUser::testing("secret123", &config);
        let hash = user.serializable_hash();
        assert!(hash.get("email").is_some());
        assert!(hash.get("encrypted_password").is_none());
    }

    #[test]
    fn database_authenticatable_tracer() {
        let config = test_config();
        let mut user = TestUser {
            id: 1,
            email: "tracer@example.com".to_string(),
            ..TestUser::default()
        };

        // password= encrypts via Encryptor and stores to encrypted_password.
        DatabaseAuthenticatable::set_password(&mut user, Some("secret123".to_string()), &config);
        let encrypted = user.encrypted_password.clone();
        assert!(encrypted.starts_with("$2"), "bcrypt hash: {encrypted}");
        assert!(!encrypted.contains("secret123"));

        // valid_password verifies with the constant-time compare.
        assert!(DatabaseAuthenticatable::valid_password(
            &user,
            "secret123",
            &config
        ));
        assert!(!DatabaseAuthenticatable::valid_password(
            &user, "wrong", &config
        ));

        // authenticatable_salt = encrypted_password[0,29].
        let salt = DatabaseAuthenticatable::database_authenticatable_salt(&user)
            .expect("salt for encrypted record");
        assert_eq!(salt, encrypted[..29]);
        assert_eq!(salt.len(), 29);

        // Blank password leaves encrypted_password untouched (present? semantics).
        DatabaseAuthenticatable::set_password(&mut user, Some(String::new()), &config);
        assert_eq!(user.encrypted_password, encrypted);
        DatabaseAuthenticatable::set_password(&mut user, None, &config);
        assert_eq!(user.encrypted_password, encrypted);

        // valid_password is false for a blank encrypted_password (Devise parity).
        let new_user = TestUser::default();
        assert!(!DatabaseAuthenticatable::valid_password(
            &new_user, "anything", &config
        ));
    }

    #[tokio::test]
    async fn database_authenticatable_methods() {
        use std::collections::HashMap;

        let config = DeviseConfig {
            stretches: 4,
            send_email_changed_notification: true,
            send_password_change_notification: true,
            ..DeviseConfig::default()
        };
        let adapter = MemoryAdapter::<TestUser>::new();
        let user = TestUser::testing("secret123", &config);
        adapter.create(user.clone()).await.unwrap();

        // clean_up_passwords clears the virtual fields.
        let mut cleaned = user.clone();
        cleaned.password = Some("x".to_string());
        cleaned.password_confirmation = Some("x".to_string());
        DatabaseAuthenticatable::clean_up_passwords(&mut cleaned);
        assert_eq!(
            (cleaned.password(), cleaned.password_confirmation()),
            (None, None)
        );

        // update_with_password: valid current_password applies attrs (DBAU-03).
        let mut ok_user = user.clone();
        let mut params = serde_json::Map::new();
        params.insert(
            "current_password".to_string(),
            JsonValue::String("secret123".to_string()),
        );
        params.insert(
            "email".to_string(),
            JsonValue::String("new@example.com".to_string()),
        );
        DatabaseAuthenticatable::update_with_password(&mut ok_user, &mut params, &config)
            .expect("valid current password");
        assert_eq!(ok_user.email, "new@example.com");

        // update_with_password: wrong current_password keeps attrs applied to
        // the in-memory record (Devise re-render semantics) and returns
        // :current_password :invalid. Virtual fields cleared afterward.
        let mut bad_user = user.clone();
        let mut params = serde_json::Map::new();
        params.insert(
            "current_password".to_string(),
            JsonValue::String("wrong".to_string()),
        );
        params.insert(
            "email".to_string(),
            JsonValue::String("nope@example.com".to_string()),
        );
        params.insert("password".to_string(), JsonValue::String(String::new()));
        params.insert(
            "password_confirmation".to_string(),
            JsonValue::String(String::new()),
        );
        let err =
            DatabaseAuthenticatable::update_with_password(&mut bad_user, &mut params, &config)
                .expect_err("wrong current password");
        assert_eq!(
            err.get("current_password").map(Vec::as_slice),
            Some(&[":invalid".to_string()][..])
        );
        assert!(!params.contains_key("password"), "blank password stripped");

        // update_without_password never touches password keys (DBAU-04).
        let mut plain = user.clone();
        let encrypted_before = plain.encrypted_password.clone();
        let mut params = serde_json::Map::new();
        params.insert(
            "password".to_string(),
            JsonValue::String("hacked123".to_string()),
        );
        params.insert(
            "email".to_string(),
            JsonValue::String("safe@example.com".to_string()),
        );
        DatabaseAuthenticatable::update_without_password(&mut plain, &mut params);
        assert_eq!(plain.encrypted_password, encrypted_before);
        assert_eq!(plain.email, "safe@example.com");

        // find_for_database_authentication routes through find_for_authentication (DBAU-10).
        // (Runs before the destroy checks below: the record must exist.)
        let mut conditions = Conditions::new();
        conditions.insert(
            "email",
            AdapterValue::String("test@example.com".to_string()),
        );
        let found =
            TestUser::find_for_database_authentication(&conditions, &adapter, &config).await;
        assert_eq!(found.map(|u| u.id), Some(1));

        // destroy_with_password destroys only on a valid password (DBAU-05).
        assert!(
            !DatabaseAuthenticatable::destroy_with_password(&user, "wrong", &adapter, &config)
                .await
                .unwrap()
        );
        assert!(
            DatabaseAuthenticatable::destroy_with_password(&user, "secret123", &adapter, &config)
                .await
                .unwrap()
        );
        assert!(
            adapter
                .get(&DeviseKey::from_i64(1))
                .await
                .unwrap()
                .is_none()
        );

        // after_database_authentication hook exists and defaults to no-op (DBAU-07).
        DatabaseAuthenticatable::after_database_authentication(&user);

        // Notification decisions (DBAU-08/09): email change notifies the
        // ORIGINAL address; password change notifies the current one.
        let previous = HashMap::from([(
            "email".to_string(),
            crate::adapter::Value::String("old@example.com".to_string()),
        )]);
        let current = HashMap::from([
            (
                "email".to_string(),
                crate::adapter::Value::String("new@example.com".to_string()),
            ),
            (
                "encrypted_password".to_string(),
                crate::adapter::Value::String("hash".to_string()),
            ),
        ]);
        let changes = crate::adapter::ChangeSet::new(previous, current);
        assert_eq!(
            DatabaseAuthenticatable::email_notification_recipient(&user, &changes, &config)
                .as_deref(),
            Some("old@example.com")
        );
        assert!(
            DatabaseAuthenticatable::password_change_notification_pending(&user, &changes, &config)
        );

        // Skip flags and disabled config suppress notifications.
        let mut skipping = user.clone();
        DatabaseAuthenticatable::skip_email_changed_notification(&mut skipping);
        DatabaseAuthenticatable::skip_password_change_notification(&mut skipping);
        assert!(
            DatabaseAuthenticatable::email_notification_recipient(&skipping, &changes, &config)
                .is_none()
        );
        assert!(
            !DatabaseAuthenticatable::password_change_notification_pending(
                &skipping, &changes, &config
            )
        );
        let quiet = DeviseConfig {
            stretches: 4,
            send_email_changed_notification: false,
            send_password_change_notification: false,
            ..DeviseConfig::default()
        };
        assert!(
            DatabaseAuthenticatable::email_notification_recipient(&user, &changes, &quiet)
                .is_none()
        );
        assert!(
            !DatabaseAuthenticatable::password_change_notification_pending(&user, &changes, &quiet)
        );

        // No email change -> no email notification.
        let steady = crate::adapter::ChangeSet::new(
            HashMap::from([(
                "email".to_string(),
                crate::adapter::Value::String("a@example.com".to_string()),
            )]),
            HashMap::from([(
                "email".to_string(),
                crate::adapter::Value::String("a@example.com".to_string()),
            )]),
        );
        assert!(
            DatabaseAuthenticatable::email_notification_recipient(&user, &steady, &config)
                .is_none()
        );
    }

    #[test]
    fn test_normalize_auth_conditions() {
        let config = DeviseConfig {
            case_insensitive_keys: vec!["email".to_string()],
            strip_whitespace_keys: vec!["email".to_string()],
            ..DeviseConfig::default()
        };
        let mut conditions = Conditions::new();
        conditions.insert(
            "email",
            AdapterValue::String("  TEST@EXAMPLE.COM  ".to_string()),
        );
        let normalized = normalize_auth_conditions(&conditions, &config);
        let email: Option<String> = normalized.get("email");
        assert_eq!(email.as_deref(), Some("test@example.com"));
    }

    #[tokio::test]
    async fn test_adapter_bridge_boxes_models() {
        let config = test_config();
        let adapter = MemoryAdapter::<TestUser>::new();
        adapter
            .create(TestUser::testing("secret123", &config))
            .await
            .unwrap();
        let bridge = AdapterBridge::new(adapter);

        let by_key = bridge.get_boxed(&DeviseKey::from_i64(1)).await.unwrap();
        assert!(by_key.is_some());

        let mut conditions = Conditions::new();
        conditions.insert(
            "email",
            AdapterValue::String("test@example.com".to_string()),
        );
        let by_conditions = bridge.find_first_boxed(&conditions).await.unwrap();
        let boxed = by_conditions.expect("found");
        assert!(boxed.as_password_verifiable().is_some());
    }
}
