//! `Registerable` module - mirrors `devise/lib/devise/models/registerable.rb`
//! (REGS-01..04): building records from sign-up params and the post-sign-up
//! / post-change-password decisions. The flow orchestration (controllers in
//! Devise) consumes these model-level decisions.

use crate::adapter::OrmAdapter;
use crate::config::DeviseConfig;
use crate::error::ResourceWithErrors;
use crate::model::authenticatable::normalize_attribute_map;
use crate::model::database_authenticatable::DatabaseAuthenticatable;
use crate::model::validatable::Validatable;
use async_trait::async_trait;
use serde_json::Value as JsonValue;

// ============================================================================
// Registerable (REGS-01..04)
// Mirrors devise/lib/devise/models/registerable.rb
// ============================================================================

/// `Registerable` module: building records from sign-up params and the
/// post-sign-up / post-change-password decisions. The flow orchestration
/// (controllers in Devise) consumes these model-level decisions.
///
/// == Options
///
/// * `sign_in_after_change_password` - sign the user back in after a
///   password-changing account update (Devise default: true)
///
/// == Examples
///
/// ```ignore
/// // Ignored doctest: requires a live adapter and an async runtime; the compiled equivalent lives in the crate tests and the example apps.
/// let user = TestUser::new_with_session(&params, &session, &config);
/// // save via adapter; then:
/// match user.post_sign_up_message() {
///     None => { /* active_for_authentication: sign in (flash :signed_up) */ }
///     Some(key) => { /* flash "signed_up_but_{key}", no session data */ }
/// }
/// ```
///
/// Mirrors `Devise::Models::Registerable` (`devise/lib/devise/models/registerable.rb`): `new_with_session` and the post-sign-up decisions.
#[async_trait]
pub trait Registerable: DatabaseAuthenticatable {
    /// `new_with_session(params, session)` (REGS-01): build a record from
    /// sign-up params. Devise merges `session["resource.data"]` (OAuth
    /// first-visit handoffs); the default port applies params, and password
    /// keys go through the hashing [`set_password`](DatabaseAuthenticatable::set_password).
    fn new_with_session(
        params: &serde_json::Map<String, JsonValue>,
        session: &JsonValue,
        config: &DeviseConfig,
    ) -> Self
    where
        Self: Default + Sized,
    {
        let _ = session;
        // Devise `before_validation :downcase_keys` / `:strip_whitespace`
        // (`authenticatable.rb:198-204`): normalize configured keys on WRITE
        // so the stored email matches what lookups will send (CONCERNS #4).
        let params = normalize_attribute_map(params, config);
        let mut record = Self::default();
        record.assign_attributes(&params);
        if let Some(password) = params.get("password").and_then(JsonValue::as_str) {
            record.set_password(Some(password.to_string()), config);
        }
        if let Some(confirmation) = params
            .get("password_confirmation")
            .and_then(JsonValue::as_str)
        {
            record.set_password_confirmation(Some(confirmation.to_string()));
        }
        record
    }

    /// `sign_in_after_change_password` (REGS-04): config-controlled decision
    /// for re-sign-in after a password-changing account update (the controller
    /// may use `bypass_sign_in` when true).
    fn sign_in_after_change_password(&self, config: &DeviseConfig) -> bool {
        config.sign_in_after_change_password
    }

    /// Post-sign-up decision (REGS-02): `None` when `active_for_authentication`
    /// (caller signs in, flash `:signed_up`); `Some(key)` flashes
    /// `signed_up_but_<key>` (Devise `inactive_message`) with no session data.
    fn post_sign_up_message(&self) -> Option<&'static str> {
        if self.active_for_authentication() {
            None
        } else {
            Some(self.inactive_message())
        }
    }

    /// Sign-up flow (REGS-02/03): validates the built record (Validatable +
    /// uniqueness), saves via the adapter, then branches on
    /// `active_for_authentication`:
    /// * active -> sign in through the proxy (session written), `SignedIn`
    /// * inactive -> NO session data, `SignedUpButInactive` with the flash key
    /// * invalid -> `clean_up_passwords` applied, `Invalid` carries the errors
    ///
    /// # Errors
    /// Returns `OrmError` when the adapter write fails.
    async fn sign_up<A>(
        mut self,
        adapter: &A,
        proxy: &mut crate::proxy::AuthProxy,
        scope: &str,
        config: &DeviseConfig,
    ) -> Result<SignUpOutcome<Self>, crate::adapter::OrmError>
    where
        Self: Validatable + Clone + Sized + 'static,
        A: OrmAdapter<Self, New = Self> + Send + Sync,
    {
        let mut errors = self.validate(config);
        self.validate_email_uniqueness(adapter, &mut errors).await;
        if !errors.is_empty() {
            self.clean_up_passwords();
            return Ok(SignUpOutcome::Invalid(ResourceWithErrors::new(
                self, errors,
            )));
        }
        let saved = adapter.create(self).await?;
        match saved.post_sign_up_message() {
            None => {
                proxy.sign_in(scope, Box::new(saved.clone()), false).await;
                Ok(SignUpOutcome::SignedIn(saved))
            }
            Some(message) => Ok(SignUpOutcome::SignedUpButInactive(saved, message)),
        }
    }
}

/// Outcome of [`Registerable::sign_up`] (REGS-02/03), mirroring Devise
/// `RegistrationsController#create` branches at the model layer.
#[derive(Debug)]
pub enum SignUpOutcome<M> {
    /// Saved and `active_for_authentication`: signed in (flash `:signed_up`).
    SignedIn(M),
    /// Saved but inactive: flash `signed_up_but_<message>`, no session data.
    SignedUpButInactive(M, &'static str),
    /// Validation failed: record carries errors; password fields cleared.
    Invalid(ResourceWithErrors<M>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::{Conditions, Value as AdapterValue, memory::MemoryAdapter};
    use crate::config::DeviseConfig;
    use crate::model::authenticatable::AdapterBridge;
    use crate::model::authenticatable::Authenticatable;
    use crate::model::database_authenticatable::DatabaseAuthenticatable;
    use crate::model::registerable::Registerable;
    use crate::model::test_support::{TestUser, test_config};
    use crate::model::validatable::Validatable;
    use serde_json::Value as JsonValue;
    use std::sync::Arc;

    #[test]
    fn registerable_tests() {
        let config = test_config();

        // REGS-01: new_with_session builds from params; password hashed.
        let mut params = serde_json::Map::new();
        params.insert(
            "email".to_string(),
            JsonValue::String("signup@example.com".to_string()),
        );
        params.insert(
            "password".to_string(),
            JsonValue::String("secret123".to_string()),
        );
        params.insert(
            "password_confirmation".to_string(),
            JsonValue::String("secret123".to_string()),
        );
        let user = TestUser::new_with_session(
            &params,
            &JsonValue::Object(serde_json::Map::new()),
            &config,
        );
        assert_eq!(user.email, "signup@example.com");
        assert!(user.encrypted_password.starts_with("$2"));
        assert!(DatabaseAuthenticatable::valid_password(
            &user,
            "secret123",
            &config
        ));
        let errors = Validatable::validate(&user, &config);
        assert!(errors.is_empty(), "sign-up record validates: {errors:?}");

        // Blank password param: never resets encrypted_password.
        let mut params = serde_json::Map::new();
        params.insert(
            "email".to_string(),
            JsonValue::String("nobody@example.com".to_string()),
        );
        params.insert("password".to_string(), JsonValue::String(String::new()));
        let user = TestUser::new_with_session(&params, &JsonValue::Null, &config);
        assert!(user.encrypted_password().is_none());

        // REGS-02: post-sign-up decision - active signs in, inactive flashes.
        let active = TestUser::testing("secret123", &config);
        assert_eq!(Registerable::post_sign_up_message(&active), None);
        let inactive = TestUser {
            inactive: true,
            ..TestUser::testing("secret123", &config)
        };
        assert_eq!(
            Registerable::post_sign_up_message(&inactive),
            Some("unconfirmed")
        );

        // REGS-03: clean_up_passwords clears fields on failure re-render.
        let mut failed = TestUser::default();
        failed.set_password_virtual(Some("secret123".to_string()));
        failed.set_password_confirmation(Some("secret123".to_string()));
        DatabaseAuthenticatable::clean_up_passwords(&mut failed);
        assert_eq!(
            (failed.password(), failed.password_confirmation()),
            (None, None)
        );

        // REGS-04: sign_in_after_change_password reads config (default true).
        let user = TestUser::testing("secret123", &config);
        assert!(Registerable::sign_in_after_change_password(&user, &config));
        let config_off = DeviseConfig {
            stretches: 4,
            sign_in_after_change_password: false,
            ..DeviseConfig::default()
        };
        assert!(!Registerable::sign_in_after_change_password(
            &user,
            &config_off
        ));
    }
    #[derive(Default)]
    struct FlowStore {
        data: std::sync::Arc<std::sync::RwLock<std::collections::HashMap<String, JsonValue>>>,
    }
    #[async_trait]
    impl crate::session::SessionStore for FlowStore {
        async fn get_value(&self, key: &str) -> Option<JsonValue> {
            self.data.read().unwrap().get(key).cloned()
        }

        async fn insert_value(&self, key: &str, value: JsonValue) {
            self.data.write().unwrap().insert(key.to_string(), value);
        }

        async fn remove(&self, key: &str) {
            self.data.write().unwrap().remove(key);
        }

        async fn remove_prefix(&self, prefix: &str) {
            self.data
                .write()
                .unwrap()
                .retain(|k, _| !k.starts_with(prefix));
        }

        async fn keys_with_prefix(&self, prefix: &str) -> Vec<String> {
            self.data
                .read()
                .unwrap()
                .keys()
                .filter(|k| k.starts_with(prefix))
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
    fn flow_proxy(
        config: &DeviseConfig,
        adapter: MemoryAdapter<TestUser>,
    ) -> crate::proxy::AuthProxy {
        use crate::scope::{Mapping, Module, PathNames, ScopeRegistry, SignOutVia};

        let mut registry = ScopeRegistry::new();
        registry.register(Mapping {
            name: "user".to_string(),
            class_name: "TestUser".to_string(),
            path: "users".to_string(),
            path_prefix: None,
            singular: "user".to_string(),
            path_names: PathNames::default(),
            controllers: std::collections::HashMap::new(),
            modules: vec![Module::DatabaseAuthenticatable, Module::Registerable],
            only: vec![],
            skip: vec![],
            constraints: std::collections::HashMap::new(),
            defaults: std::collections::HashMap::new(),
            format: None,
            router_name: None,
            sign_out_via: SignOutVia::Delete,
            failure_app: None,
        });
        let mut proxy = crate::proxy::AuthProxy::new(
            Arc::new(FlowStore::default()),
            Arc::new(registry),
            Arc::new(crate::hooks::HookRegistry::new()),
            Arc::new(config.clone()),
        );
        proxy.register_finder("user", Arc::new(AdapterBridge::new(adapter)));
        proxy
    }
    fn sign_up_params(email: &str, password: &str) -> serde_json::Map<String, JsonValue> {
        let mut params = serde_json::Map::new();
        params.insert("email".to_string(), JsonValue::String(email.to_string()));
        params.insert(
            "password".to_string(),
            JsonValue::String(password.to_string()),
        );
        params.insert(
            "password_confirmation".to_string(),
            JsonValue::String(password.to_string()),
        );
        params
    }
    #[tokio::test]
    async fn registerable_tracer() {
        let config = test_config();
        let adapter = MemoryAdapter::<TestUser>::new();
        let mut proxy = flow_proxy(&config, adapter.clone());

        // Active record: saved AND signed in (session payload written).
        let user = TestUser::new_with_session(
            &sign_up_params("active@example.com", "secret123"),
            &JsonValue::Null,
            &config,
        );
        let outcome = user
            .sign_up(&adapter, &mut proxy, "user", &config)
            .await
            .unwrap();
        let SignUpOutcome::SignedIn(saved) = outcome else {
            panic!("expected SignedIn, got {outcome:?}")
        };
        assert!(saved.encrypted_password.starts_with("$2"));
        let session_value = proxy
            .session_store()
            .get_value(&crate::session::keys::scope_session_key("user"))
            .await;
        assert!(session_value.is_some(), "session written on active sign-up");

        // Inactive record (fresh proxy): saved, NOT signed in, flash key set.
        let mut inactive_proxy = flow_proxy(&config, adapter.clone());
        let mut inactive_user = TestUser::new_with_session(
            &sign_up_params("pending@example.com", "secret123"),
            &JsonValue::Null,
            &config,
        );
        inactive_user.inactive = true;
        let outcome = inactive_user
            .sign_up(&adapter, &mut inactive_proxy, "user", &config)
            .await
            .unwrap();
        let SignUpOutcome::SignedUpButInactive(_, message) = outcome else {
            panic!("expected SignedUpButInactive, got {outcome:?}")
        };
        assert_eq!(message, "unconfirmed");
        assert!(
            inactive_proxy
                .session_store()
                .get_value(&crate::session::keys::scope_session_key("user"))
                .await
                .is_none(),
            "no session data for inactive sign-up"
        );

        // Invalid record (duplicate email): errors carried, passwords cleared.
        let dupe = TestUser::new_with_session(
            &sign_up_params("active@example.com", "secret123"),
            &JsonValue::Null,
            &config,
        );
        let outcome = dupe
            .sign_up(&adapter, &mut proxy, "user", &config)
            .await
            .unwrap();
        let SignUpOutcome::Invalid(record) = outcome else {
            panic!("expected Invalid, got {outcome:?}")
        };
        assert_eq!(
            record.errors.get("email").map(Vec::as_slice),
            Some(&[":taken".to_string()][..])
        );
        assert_eq!(
            (
                record.record.password(),
                record.record.password_confirmation()
            ),
            (None, None)
        );
    }
    #[tokio::test]
    async fn registerable_signup() {
        let config = test_config();
        let adapter = MemoryAdapter::<TestUser>::new();
        let mut proxy = flow_proxy(&config, adapter.clone());

        // Scope-specific config flows through new_with_session (pepper changes the hash).
        let peppered = DeviseConfig {
            stretches: 4,
            pepper: Some("scope-pepper".to_string()),
            ..DeviseConfig::default()
        };
        let plain_user = TestUser::new_with_session(
            &sign_up_params("a@example.com", "secret123"),
            &JsonValue::Null,
            &config,
        );
        let peppered_user = TestUser::new_with_session(
            &sign_up_params("a@example.com", "secret123"),
            &JsonValue::Null,
            &peppered,
        );
        assert_ne!(
            plain_user.encrypted_password,
            peppered_user.encrypted_password
        );
        assert!(DatabaseAuthenticatable::valid_password(
            &peppered_user,
            "secret123",
            &peppered
        ));
        assert!(!DatabaseAuthenticatable::valid_password(
            &peppered_user,
            "secret123",
            &config
        ));

        // Full flow persists: record retrievable by its auth conditions afterward.
        let user = TestUser::new_with_session(
            &sign_up_params("persisted@example.com", "secret123"),
            &JsonValue::Null,
            &config,
        );
        let outcome = user
            .sign_up(&adapter, &mut proxy, "user", &config)
            .await
            .unwrap();
        assert!(matches!(outcome, SignUpOutcome::SignedIn(_)));
        let mut conditions = Conditions::new();
        conditions.insert(
            "email",
            AdapterValue::String("persisted@example.com".to_string()),
        );
        let found = TestUser::find_for_authentication(&conditions, &adapter, &config).await;
        assert!(found.is_some(), "saved record found for authentication");

        // REGS-04: post-change sign-in decision reads config.
        let saved = found.unwrap();
        assert!(Registerable::sign_in_after_change_password(&saved, &config));
        let config_off = DeviseConfig {
            stretches: 4,
            sign_in_after_change_password: false,
            ..DeviseConfig::default()
        };
        assert!(!Registerable::sign_in_after_change_password(
            &saved,
            &config_off
        ));
    }
}
