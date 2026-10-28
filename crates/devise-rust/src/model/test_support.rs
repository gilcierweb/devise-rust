//! Shared test fixtures for the model module tree (cfg(test) only).
//!
//! The single `TestUser` fixture (all module traits) plus the lookup-counting
//! adapter live here once; every module's inline tests consume them, so the
//! split never duplicated the fixture.

use super::*;
use crate::adapter::{Conditions, DeviseKey, Value as AdapterValue, memory::MemoryAdapter};
use crate::config::DeviseConfig;
use crate::failure::AnyDeviseModel;
use crate::model::database_authenticatable::DatabaseAuthenticatable;
use crate::model::recoverable::Recoverable;
use crate::model::registerable::Registerable;
use crate::model::validatable::Validatable;
use async_trait::async_trait;
use serde_json::Value as JsonValue;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub(crate) struct TestUser {
    pub(crate) id: i64,
    pub(crate) email: String,
    pub(crate) encrypted_password: String,
    #[serde(skip)]
    pub(crate) password: Option<String>,
    #[serde(skip)]
    pub(crate) password_confirmation: Option<String>,
    #[serde(skip)]
    pub(crate) skip_email_notification: bool,
    #[serde(skip)]
    pub(crate) skip_password_notification: bool,
    #[serde(skip)]
    pub(crate) inactive: bool,
    pub(crate) reset_password_token: Option<String>,
    pub(crate) reset_password_sent_at: Option<chrono::DateTime<chrono::Utc>>,
    pub(crate) unconfirmed_email: Option<String>,
    #[serde(skip)]
    pub(crate) raw_reset_token: Option<String>,
    /// Devise `devise_will_save_change_to_email?` override: `None` keeps
    /// the trait default (the email is changing), `Some(false)` models an
    /// update that leaves the address untouched.
    #[serde(skip)]
    pub(crate) email_changed_override: Option<bool>,
    /// `uniqueness_scope_id`: `None` models the models that never override
    /// the accessor (the trait default), which is where the self-update
    /// rejection used to bite.
    #[serde(skip)]
    pub(crate) uniqueness_scope_id: Option<String>,
    /// `password_required?` override, the `validatable_test.rb:105`
    /// stubbing shape: `Some(false)` models a record whose password is
    /// not required (so the length validation still applies),
    /// `None`/`Some(true)` keep the trait default expression.
    #[serde(skip)]
    pub(crate) password_required_override: Option<bool>,
    #[serde(skip)]
    pub(crate) after_auth_count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}
impl TestUser {
    pub(crate) fn testing(password: &str, config: &DeviseConfig) -> Self {
        Self {
            id: 1,
            email: "test@example.com".to_string(),
            encrypted_password: crate::crypto::encryptor::digest(password, config),
            password: None,
            password_confirmation: None,
            skip_email_notification: false,
            skip_password_notification: false,
            inactive: false,
            reset_password_token: None,
            reset_password_sent_at: None,
            unconfirmed_email: None,
            raw_reset_token: None,
            email_changed_override: None,
            uniqueness_scope_id: Some("1".to_string()),
            password_required_override: None,
            after_auth_count: std::sync::Arc::default(),
        }
    }
}
/// Adapter wrapper counting every lookup, proving gated paths perform no
/// adapter call at all (the mirror of lockable's `CountingAdapter`), and
/// optionally failing reads to model a backend outage.
pub(crate) struct CountingAdapter<'a> {
    pub(crate) inner: &'a MemoryAdapter<TestUser>,
    pub(crate) calls: Arc<AtomicUsize>,
    pub(crate) fail_reads: bool,
}
#[async_trait]
impl crate::adapter::OrmAdapter<TestUser> for CountingAdapter<'_> {
    type New = TestUser;

    async fn get(&self, id: &DeviseKey) -> Result<Option<TestUser>, crate::adapter::OrmError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_reads {
            return Err(crate::adapter::OrmError::Connection {
                message: "session fetch down".to_string(),
                source: None,
            });
        }
        self.inner.get(id).await
    }

    async fn find_first(
        &self,
        conditions: &Conditions,
    ) -> Result<Option<TestUser>, crate::adapter::OrmError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.find_first(conditions).await
    }

    async fn create(&self, model: TestUser) -> Result<TestUser, crate::adapter::OrmError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.create(model).await
    }

    async fn update(
        &self,
        key: &DeviseKey,
        changes: &crate::adapter::ChangeSet,
    ) -> Result<TestUser, crate::adapter::OrmError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.update(key, changes).await
    }

    async fn update_columns(
        &self,
        key: &DeviseKey,
        fields: &std::collections::HashMap<String, AdapterValue>,
    ) -> Result<TestUser, crate::adapter::OrmError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.update_columns(key, fields).await
    }

    async fn increment_counter(
        &self,
        key: &DeviseKey,
        column: &'static str,
    ) -> Result<TestUser, crate::adapter::OrmError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.increment_counter(key, column).await
    }

    async fn delete(&self, id: &DeviseKey) -> Result<(), crate::adapter::OrmError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.delete(id).await
    }
}
impl AnyDeviseModel for TestUser {
    fn as_activatable(&self) -> Option<&dyn crate::model::Activatable> {
        Some(self)
    }
    fn to_key(&self) -> DeviseKey {
        DeviseKey::from_i64(self.id)
    }

    fn authenticatable_salt(&self) -> Option<String> {
        self.encrypted_password.get(..29).map(str::to_string)
    }

    fn as_password_verifiable(&self) -> Option<&dyn PasswordVerifiable> {
        Some(self)
    }

    fn after_database_authentication(&self) {
        self.after_auth_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
    fn serializable_fields(&self) -> serde_json::Map<String, JsonValue> {
        // Deliberately includes `unconfirmed_email` (an UNSAFE attribute)
        // so the default `serializable_hash` filter is exercised: a model
        // that forgot the filter would leak it.
        let mut fields = serde_json::Map::new();
        fields.insert("id".to_string(), JsonValue::from(self.id));
        fields.insert("email".to_string(), JsonValue::from(self.email.clone()));
        if let Some(unconfirmed) = &self.unconfirmed_email {
            fields.insert(
                "unconfirmed_email".to_string(),
                JsonValue::String(unconfirmed.clone()),
            );
        }
        fields
    }

    fn seed_initialized_attributes(&mut self, attributes: &serde_json::Map<String, JsonValue>) {
        self.assign_attributes(attributes);
    }

    fn active_for_authentication(&self) -> bool {
        !self.inactive
    }

    fn inactive_message(&self) -> &'static str {
        if self.inactive {
            "unconfirmed"
        } else {
            "inactive"
        }
    }
}
impl Registerable for TestUser {}
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
#[async_trait]
impl Validatable for TestUser {
    fn email_value(&self) -> Option<&str> {
        Some(&self.email)
    }

    fn uniqueness_scope_id(&self) -> Option<String> {
        self.uniqueness_scope_id.clone()
    }

    fn email_changed(&self) -> bool {
        self.email_changed_override.unwrap_or(true)
    }

    fn password_required(&self) -> bool {
        self.password_required_override.unwrap_or_else(|| {
            !self.persisted() || self.password().is_some() || self.password_confirmation().is_some()
        })
    }
}
#[async_trait]
impl Recoverable for TestUser {
    fn reset_password_token(&self) -> Option<&str> {
        self.reset_password_token.as_deref()
    }

    fn reset_password_sent_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.reset_password_sent_at
    }

    fn set_reset_password_token_fields(
        &mut self,
        token: Option<String>,
        sent_at: Option<chrono::DateTime<chrono::Utc>>,
    ) {
        self.reset_password_token = token;
        self.reset_password_sent_at = sent_at;
    }

    fn raw_reset_password_token(&self) -> Option<&str> {
        self.raw_reset_token.as_deref()
    }

    fn set_raw_reset_password_token(&mut self, raw: Option<String>) {
        self.raw_reset_token = raw;
    }
}
pub(crate) fn test_config() -> DeviseConfig {
    DeviseConfig {
        stretches: 4,
        ..DeviseConfig::default()
    }
}
