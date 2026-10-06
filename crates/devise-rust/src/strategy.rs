//! Authentication strategies - params, HTTP Basic, rememberable, paranoid
//!
//! Mirrors Devise's warden strategies
//! (`strategies/authenticatable.rb`, `strategies/database_authenticatable.rb`,
//! `strategies/rememberable.rb`): each strategy reports `valid` for its
//! request shape and `authenticate` for the decision. `AuthProxy`
//! (`proxy.rs`) runs them in Devise order: rememberable, params, HTTP Basic.

use crate::adapter::{Conditions, Value};
use crate::config::DeviseConfig;
use crate::failure::{AuthOutcome, Failure};
use crate::model::ModelFinder;
use crate::request::AuthRequest;
use crate::scope::Mapping;
use async_trait::async_trait;
use std::collections::HashMap;

/// Authentication strategy contract.
#[async_trait]
pub trait Strategy: Send + Sync {
    /// Whether this strategy applies to the request.
    async fn valid(&self, request: &AuthRequest, mapping: &Mapping) -> bool;

    /// Attempt authentication.
    ///
    /// Returns `Ok(AuthOutcome::Success)` on success, `Ok(AuthOutcome::Pass)`
    /// when the strategy does not apply, and `Err(Failure)` on failure.
    async fn authenticate(
        &self,
        request: &AuthRequest,
        mapping: &Mapping,
        finder: &dyn ModelFinder,
        config: &DeviseConfig,
    ) -> Result<AuthOutcome, Failure>;

    /// Whether to persist the session after success.
    fn store(&self) -> bool {
        true
    }

    /// Whether this strategy runs without credentials (remember-me).
    fn no_input(&self) -> bool {
        false
    }

    /// Stable id for performed-strategy tracking.
    fn id(&self) -> &'static str;
}

#[async_trait]
impl Strategy for Box<dyn Strategy> {
    async fn valid(&self, request: &AuthRequest, mapping: &Mapping) -> bool {
        (**self).valid(request, mapping).await
    }

    async fn authenticate(
        &self,
        request: &AuthRequest,
        mapping: &Mapping,
        finder: &dyn ModelFinder,
        config: &DeviseConfig,
    ) -> Result<AuthOutcome, Failure> {
        (**self)
            .authenticate(request, mapping, finder, config)
            .await
    }

    fn store(&self) -> bool {
        (**self).store()
    }

    fn no_input(&self) -> bool {
        (**self).no_input()
    }

    fn id(&self) -> &'static str {
        (**self).id()
    }
}

/// Extract a credential honoring Devise's three param shapes.
///
/// Looks up `scope[key]`, then `scope_key`, then the bare `key`, mirroring
/// how Rails nests `params[scope]` while staying flat-map friendly.
fn extract_param(request: &AuthRequest, scope: &str, key: &str) -> Option<String> {
    request
        .params
        .get(&format!("{scope}[{key}]"))
        .or_else(|| request.params.get(&format!("{scope}_{key}")))
        .or_else(|| request.params.get(key))
        .cloned()
}

/// Build the strategy chain in Devise execution order.
///
/// Rememberable (no-input) runs first when the mapping enables it, then
/// params, then HTTP Basic. Each entry is paranoid-wrapped when `paranoid`
/// is set. `AuthProxy` consumes this so the order is defined once.
#[must_use]
pub fn strategies_for(mapping: &Mapping, paranoid: bool) -> Vec<Box<dyn Strategy>> {
    fn boxed<S: Strategy + 'static>(strategy: S, paranoid: bool) -> Box<dyn Strategy> {
        if paranoid {
            Box::new(ParanoidStrategy::new(strategy))
        } else {
            Box::new(strategy)
        }
    }

    let mut chain: Vec<Box<dyn Strategy>> = Vec::with_capacity(3);
    if mapping.has_module(crate::scope::Module::Rememberable) {
        chain.push(boxed(RememberableStrategy::default(), paranoid));
    }
    chain.push(boxed(ParamsStrategy::default(), paranoid));
    chain.push(boxed(HttpBasicStrategy::default(), paranoid));
    chain
}

/// Params strategy - form credentials in `params[scope]`.
///
/// Mirrors `DatabaseAuthenticatable`: honors `params_authenticatable`,
/// `authentication_keys`, `case_insensitive_keys`, and
/// `strip_whitespace_keys`.
pub struct ParamsStrategy {
    /// Identity keys (default `["email"]`).
    pub authentication_keys: Vec<String>,
    /// Case-insensitive keys (default `["email"]`).
    pub case_insensitive_keys: Vec<String>,
    /// Whitespace-stripped keys (default `["email"]`).
    pub strip_whitespace_keys: Vec<String>,
}

impl Default for ParamsStrategy {
    fn default() -> Self {
        Self {
            authentication_keys: vec!["email".to_string()],
            case_insensitive_keys: vec!["email".to_string()],
            strip_whitespace_keys: vec!["email".to_string()],
        }
    }
}

impl ParamsStrategy {
    /// Collect identity conditions plus the password for a scope.
    fn credentials(&self, request: &AuthRequest, scope: &str) -> Option<(Conditions, String)> {
        let mut conditions = Conditions::new();
        let mut found = false;
        for key in &self.authentication_keys {
            let raw = extract_param(request, scope, key)?;
            let value = crate::model::normalize_credential_value(
                raw,
                key,
                &self.case_insensitive_keys,
                &self.strip_whitespace_keys,
            );
            conditions.insert(key.clone(), Value::String(value));
            found = true;
        }
        if !found {
            return None;
        }
        let password = extract_param(request, scope, "password")?;
        Some((conditions, password))
    }
}

#[async_trait]
impl Strategy for ParamsStrategy {
    async fn valid(&self, request: &AuthRequest, mapping: &Mapping) -> bool {
        request.flags.allow_params_authentication
            && self.credentials(request, &mapping.name).is_some()
    }

    async fn authenticate(
        &self,
        request: &AuthRequest,
        mapping: &Mapping,
        finder: &dyn ModelFinder,
        config: &DeviseConfig,
    ) -> Result<AuthOutcome, Failure> {
        if !config.params_authenticatable {
            return Err(Failure::Config(
                "params_authenticatable is disabled".to_string(),
            ));
        }
        let Some((conditions, password)) = self.credentials(request, &mapping.name) else {
            return Ok(AuthOutcome::Pass);
        };
        let Some(user) = finder
            .find_first_boxed(&conditions)
            .await
            .map_err(|error| Failure::Config(format!("{error}")))?
        else {
            return Err(Failure::NotFound);
        };
        let Some(check) = user.as_password_verifiable() else {
            return Err(Failure::Config(
                "model does not support password verification".to_string(),
            ));
        };
        if check.valid_password(&password, config) {
            // DBAU-07: Devise fires after_database_authentication after a
            // successful password check in the database_authenticatable strategy.
            user.after_database_authentication();
            Ok(AuthOutcome::Success(user))
        } else {
            Err(Failure::InvalidCredentials { message: "invalid" })
        }
    }

    fn id(&self) -> &'static str {
        "params"
    }
}

/// HTTP Basic strategy - `Authorization: Basic` header.
///
/// Honors `http_authenticatable`, `http_authenticatable_on_xhr`, and
/// `http_authentication_key` (falling back to the first authentication key).
pub struct HttpBasicStrategy {
    /// Identity keys (default `["email"]`).
    pub authentication_keys: Vec<String>,
    /// Explicit Basic username key, if different from `authentication_keys`.
    pub http_authentication_key: Option<String>,
    /// Whether XHR requests may use Basic auth.
    pub http_authenticatable_on_xhr: bool,
}

impl Default for HttpBasicStrategy {
    fn default() -> Self {
        Self {
            authentication_keys: vec!["email".to_string()],
            http_authentication_key: None,
            http_authenticatable_on_xhr: true,
        }
    }
}

#[async_trait]
impl Strategy for HttpBasicStrategy {
    async fn valid(&self, request: &AuthRequest, _mapping: &Mapping) -> bool {
        if !request.has_http_basic() {
            return false;
        }
        if request.is_xhr() && !self.http_authenticatable_on_xhr {
            return false;
        }
        true
    }

    async fn authenticate(
        &self,
        request: &AuthRequest,
        _mapping: &Mapping,
        finder: &dyn ModelFinder,
        config: &DeviseConfig,
    ) -> Result<AuthOutcome, Failure> {
        if !config.http_authenticatable {
            return Err(Failure::Config(
                "http_authenticatable is disabled".to_string(),
            ));
        }
        let Some((username, password)) = request.http_basic_credentials() else {
            return Ok(AuthOutcome::Pass);
        };
        let key = self.http_authentication_key.clone().unwrap_or_else(|| {
            self.authentication_keys
                .first()
                .cloned()
                .unwrap_or_else(|| "email".to_string())
        });
        let mut conditions = Conditions::new();
        conditions.insert(key, Value::String(username));
        let Some(user) = finder
            .find_first_boxed(&conditions)
            .await
            .map_err(|error| Failure::Config(format!("{error}")))?
        else {
            return Err(Failure::NotFound);
        };
        let Some(check) = user.as_password_verifiable() else {
            return Err(Failure::Config(
                "model does not support password verification".to_string(),
            ));
        };
        if check.valid_password(&password, config) {
            // DBAU-07: after_database_authentication fires here (Devise's
            // database_authenticatable strategy); http_basic is its twin.
            user.after_database_authentication();
            Ok(AuthOutcome::Success(user))
        } else {
            Err(Failure::InvalidCredentials { message: "invalid" })
        }
    }

    fn id(&self) -> &'static str {
        "http_basic"
    }
}

/// Rememberable strategy shell - remember-me cookie.
///
/// Full cookie validation lands in Phase 5; this shell keeps the Devise
/// strategy order (rememberable first, `no_input`) compiling.
pub struct RememberableStrategy {
    /// Cookie name (default `remember_{scope}_token`).
    pub cookie_key: String,
}

impl Default for RememberableStrategy {
    fn default() -> Self {
        Self {
            cookie_key: "remember_user_token".to_string(),
        }
    }
}

#[async_trait]
impl Strategy for RememberableStrategy {
    async fn valid(&self, request: &AuthRequest, _mapping: &Mapping) -> bool {
        request.cookies.contains_key(&self.cookie_key)
    }

    async fn authenticate(
        &self,
        _request: &AuthRequest,
        _mapping: &Mapping,
        _finder: &dyn ModelFinder,
        _config: &DeviseConfig,
    ) -> Result<AuthOutcome, Failure> {
        // Phase 5: validate via serialize_from_cookie (RMB-03).
        Ok(AuthOutcome::Pass)
    }

    fn no_input(&self) -> bool {
        true
    }

    fn id(&self) -> &'static str {
        "rememberable"
    }
}

/// Paranoid wrapper - uniform failure with dummy hash on unknown users.
///
/// When `config.paranoid` is set, a `NotFound` from the inner strategy is
/// converted to `InvalidCredentials` after hashing a dummy password, so the
/// response timing and message reveal nothing about account existence.
pub struct ParanoidStrategy<S: Strategy> {
    inner: S,
}

impl<S: Strategy> ParanoidStrategy<S> {
    /// Wrap a strategy with paranoid handling.
    #[must_use]
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl<S: Strategy + Send + Sync> Strategy for ParanoidStrategy<S> {
    async fn valid(&self, request: &AuthRequest, mapping: &Mapping) -> bool {
        self.inner.valid(request, mapping).await
    }

    async fn authenticate(
        &self,
        request: &AuthRequest,
        mapping: &Mapping,
        finder: &dyn ModelFinder,
        config: &DeviseConfig,
    ) -> Result<AuthOutcome, Failure> {
        match self
            .inner
            .authenticate(request, mapping, finder, config)
            .await
        {
            Err(Failure::NotFound) if config.paranoid => {
                let _dummy = crate::crypto::encryptor::digest("", config);
                Err(Failure::InvalidCredentials { message: "invalid" })
            }
            result => result,
        }
    }

    fn store(&self) -> bool {
        self.inner.store()
    }

    fn no_input(&self) -> bool {
        self.inner.no_input()
    }

    fn id(&self) -> &'static str {
        self.inner.id()
    }
}

/// Credential map for tests and bridges: scope-keyed flat params.
#[must_use]
pub fn test_params(scope: &str, pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(key, value)| (format!("{scope}_{key}"), (*value).to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::OrmAdapter;
    use crate::adapter::memory::MemoryAdapter;
    use crate::config::DeviseConfig;
    use crate::failure::AnyDeviseModel;
    use crate::model::{AdapterBridge, PasswordVerifiable};
    use crate::scope::{Mapping, Module, PathNames, SignOutVia};
    use std::collections::HashMap;

    #[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
    struct StrategyUser {
        id: i64,
        email: String,
        encrypted_password: String,
    }

    impl AnyDeviseModel for StrategyUser {
        fn to_key(&self) -> crate::adapter::DeviseKey {
            crate::adapter::DeviseKey::from_i64(self.id)
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

    impl PasswordVerifiable for StrategyUser {
        fn valid_password(&self, password: &str, config: &DeviseConfig) -> bool {
            crate::crypto::encryptor::compare(password, &self.encrypted_password, config)
        }
    }

    fn test_config() -> DeviseConfig {
        DeviseConfig {
            stretches: 4,
            ..DeviseConfig::default()
        }
    }

    fn test_mapping() -> Mapping {
        Mapping {
            name: "user".to_string(),
            class_name: "User".to_string(),
            path: "users".to_string(),
            path_prefix: None,
            singular: "user".to_string(),
            path_names: PathNames::default(),
            controllers: HashMap::new(),
            modules: vec![Module::DatabaseAuthenticatable],
            only: vec![],
            skip: vec![],
            constraints: HashMap::new(),
            defaults: HashMap::new(),
            format: None,
            router_name: None,
            sign_out_via: SignOutVia::Delete,
            failure_app: None,
        }
    }

    async fn seeded_finder(
        config: &DeviseConfig,
    ) -> AdapterBridge<MemoryAdapter<StrategyUser>, StrategyUser> {
        let adapter = MemoryAdapter::<StrategyUser>::new();
        adapter
            .create(StrategyUser {
                id: 1,
                email: "test@example.com".to_string(),
                encrypted_password: crate::crypto::encryptor::digest("secret123", config),
            })
            .await
            .unwrap();
        AdapterBridge::new(adapter)
    }

    fn params_request(pairs: &[(&str, &str)]) -> AuthRequest {
        let mut request = AuthRequest::new(crate::request::HttpMethod::Post, "/users/sign_in");
        request.params = test_params("user", pairs);
        request.flags.allow_params_authentication = true;
        request
    }

    #[test]
    fn test_strategy_chain_order() {
        let plain = strategies_for(&test_mapping(), false);
        let plain_ids: Vec<&str> = plain.iter().map(Strategy::id).collect();
        assert_eq!(plain_ids, vec!["params", "http_basic"]);

        let mut with_remember = test_mapping();
        with_remember.modules = vec![
            crate::scope::Module::DatabaseAuthenticatable,
            crate::scope::Module::Rememberable,
        ];
        let ordered = strategies_for(&with_remember, false);
        let ordered_ids: Vec<&str> = ordered.iter().map(Strategy::id).collect();
        assert_eq!(ordered_ids, vec!["rememberable", "params", "http_basic"]);

        // Paranoid wrapping preserves order and ids.
        let paranoid = strategies_for(&with_remember, true);
        let paranoid_ids: Vec<&str> = paranoid.iter().map(Strategy::id).collect();
        assert_eq!(paranoid_ids, ordered_ids);
    }

    #[tokio::test]
    async fn test_params_strategy_success() {
        let config = test_config();
        let finder = seeded_finder(&config).await;
        let strategy = ParamsStrategy::default();
        let mapping = test_mapping();
        let request = params_request(&[("email", "test@example.com"), ("password", "secret123")]);
        assert!(strategy.valid(&request, &mapping).await);
        match strategy
            .authenticate(&request, &mapping, &finder, &config)
            .await
        {
            Ok(AuthOutcome::Success(_)) => {}
            other => panic!("expected success, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_params_strategy_wrong_password() {
        let config = test_config();
        let finder = seeded_finder(&config).await;
        let strategy = ParamsStrategy::default();
        let request = params_request(&[("email", "test@example.com"), ("password", "wrong")]);
        let result = strategy
            .authenticate(&request, &test_mapping(), &finder, &config)
            .await;
        assert!(matches!(result, Err(Failure::InvalidCredentials { .. })));
    }

    #[tokio::test]
    async fn test_params_strategy_unknown_user() {
        let config = test_config();
        let finder = seeded_finder(&config).await;
        let strategy = ParamsStrategy::default();
        let request = params_request(&[("email", "ghost@example.com"), ("password", "x")]);
        let result = strategy
            .authenticate(&request, &test_mapping(), &finder, &config)
            .await;
        assert!(matches!(result, Err(Failure::NotFound)));
    }

    #[tokio::test]
    async fn test_paranoid_strategy_masks_not_found() {
        let mut config = test_config();
        config.paranoid = true;
        let finder = seeded_finder(&config).await;
        let strategy = ParanoidStrategy::new(ParamsStrategy::default());
        let request = params_request(&[("email", "ghost@example.com"), ("password", "x")]);
        let result = strategy
            .authenticate(&request, &test_mapping(), &finder, &config)
            .await;
        assert!(matches!(result, Err(Failure::InvalidCredentials { .. })));
    }

    #[tokio::test]
    async fn test_http_basic_strategy_success() {
        use base64::Engine as _;
        let mut config = test_config();
        config.http_authenticatable = true;
        let finder = seeded_finder(&config).await;
        let strategy = HttpBasicStrategy::default();
        let mapping = test_mapping();
        let raw = base64::engine::general_purpose::STANDARD.encode("test@example.com:secret123");
        let mut request = AuthRequest::new(crate::request::HttpMethod::Get, "/");
        request
            .headers
            .insert("authorization".to_string(), format!("Basic {raw}"));
        assert!(strategy.valid(&request, &mapping).await);
        match strategy
            .authenticate(&request, &mapping, &finder, &config)
            .await
        {
            Ok(AuthOutcome::Success(_)) => {}
            other => panic!("expected success, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_rememberable_strategy_shell() {
        let config = test_config();
        let finder = seeded_finder(&config).await;
        let strategy = RememberableStrategy::default();
        assert!(strategy.no_input());
        let mut request = AuthRequest::new(crate::request::HttpMethod::Get, "/");
        request
            .cookies
            .insert("remember_user_token".to_string(), "token".to_string());
        assert!(strategy.valid(&request, &test_mapping()).await);
        let result = strategy
            .authenticate(&request, &test_mapping(), &finder, &config)
            .await;
        assert!(matches!(result, Ok(AuthOutcome::Pass)));
    }

    #[test]
    fn test_strategy_ids() {
        assert_eq!(ParamsStrategy::default().id(), "params");
        assert_eq!(HttpBasicStrategy::default().id(), "http_basic");
        assert_eq!(RememberableStrategy::default().id(), "rememberable");
        assert_eq!(
            ParanoidStrategy::new(ParamsStrategy::default()).id(),
            "params"
        );
    }
}
