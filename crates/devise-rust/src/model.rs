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

/// Normalize auth conditions per Devise config (AUTH-06).
///
/// Applies `case_insensitive_keys` (downcase) and `strip_whitespace_keys`
/// (trim) to string values, returning a new map. Concrete models call this
/// on their condition maps before validation and lookup.
#[must_use]
pub fn normalize_auth_conditions(conditions: &Conditions, config: &DeviseConfig) -> Conditions {
    let mut normalized = Conditions::new();
    for (key, value) in conditions.iter() {
        let mut value = value.clone();
        if let Value::String(text) = &mut value {
            if config.case_insensitive_keys.iter().any(|k| k == key) {
                text.make_ascii_lowercase();
            }
            if config.strip_whitespace_keys.iter().any(|k| k == key) {
                *text = text.trim().to_string();
            }
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
        (
            self.to_key(),
            self.authenticatable_salt().unwrap_or_default(),
        )
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
    }

    impl TestUser {
        fn testing(password: &str, config: &DeviseConfig) -> Self {
            Self {
                id: 1,
                email: "test@example.com".to_string(),
                encrypted_password: crate::crypto::encryptor::digest(password, config),
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
