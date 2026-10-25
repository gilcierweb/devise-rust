//! Authentication strategies - params, HTTP Basic, rememberable, paranoid
//!
//! Mirrors Devise's warden strategies
//! (`strategies/authenticatable.rb`, `strategies/database_authenticatable.rb`,
//! `strategies/rememberable.rb`): each strategy reports `valid` for its
//! request shape and `authenticate` for the decision. `AuthProxy`
//! (`proxy.rs`) runs them in Devise order: rememberable, params, HTTP Basic.

use crate::adapter::{Conditions, DeviseKey, Value};
use crate::config::DeviseConfig;
use crate::failure::{AuthOutcome, Failure, FailureReason};
use crate::model::ModelFinder;
use crate::request::AuthRequest;
use crate::scope::Mapping;
use async_trait::async_trait;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

/// Authentication strategy contract.
///
/// Mirrors `Warden::Strategies::Base` (`devise/lib/devise/strategies/base.rb`): the valid/store/fail vocabulary every devise strategy shares.
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

    /// Attach the failed-attempt accounting sink when this strategy carries
    /// credential checks (params, HTTP Basic). Default no-op: strategies
    /// without password attempts ignore it.
    fn with_failed_attempt_sink(
        &mut self,
        _sink: Arc<dyn crate::failed_attempt::FailedAttemptSink>,
    ) {
    }
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

    fn with_failed_attempt_sink(
        &mut self,
        sink: Arc<dyn crate::failed_attempt::FailedAttemptSink>,
    ) {
        (**self).with_failed_attempt_sink(sink);
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
/// params, then HTTP Basic. This order is the resolved RMB-04 verdict: the
/// stale S-07 after-params sentence in the Phase 3 context is superseded, so
/// this order stays untouched and pinned by test. Each entry is
/// paranoid-wrapped when `config.paranoid` is set. The rememberable cookie
/// key resolves from `config` (key override aware). `AuthProxy` consumes
/// this so the order is defined once.
///
/// Mirrors devise's strategy dispatch order: the no-input rememberable strategy first, then params and HTTP Basic (the RMB-04 verdict).
#[must_use]
pub fn strategies_for(mapping: &Mapping, config: &DeviseConfig) -> Vec<Box<dyn Strategy>> {
    fn boxed<S: Strategy + 'static>(strategy: S, paranoid: bool) -> Box<dyn Strategy> {
        if paranoid {
            Box::new(ParanoidStrategy::new(strategy))
        } else {
            Box::new(strategy)
        }
    }

    let mut chain: Vec<Box<dyn Strategy>> = Vec::with_capacity(3);
    if mapping.has_module(crate::scope::Module::Rememberable) {
        chain.push(boxed(
            RememberableStrategy {
                cookie_key: crate::rememberable::remember_cookie_key(&mapping.name, config),
                ..RememberableStrategy::default()
            },
            config.paranoid,
        ));
    }
    chain.push(boxed(ParamsStrategy::default(), config.paranoid));
    chain.push(boxed(HttpBasicStrategy::default(), config.paranoid));
    chain
}

/// Devise's unknown-account failure branch.
///
/// Mirrors `Devise::Strategies::DatabaseAuthenticatable#authenticate!`
/// (`devise/lib/devise/strategies/database_authenticatable.rb:22-25`):
/// in paranoid mode a dummy password is hashed so the request takes the same
/// time as an existing account (enumeration timing mitigation), and the
/// unified `:invalid` failure is reported; otherwise the account's absence
/// is reported through the `:not_found_in_database` failure key.
///
/// Returns the flash/I18n key the caller must fail with. Single home for the
/// rule - [`ParanoidStrategy`] and the framework controllers share it.
#[must_use]
pub fn unknown_account_failure(config: &DeviseConfig) -> &'static str {
    if config.paranoid {
        paranoid_timing_equalize(config);
        "invalid"
    } else {
        FailureReason::NotFoundInDatabase.flash_key()
    }
}

/// Hash a dummy password so an unknown-account failure costs the same as a
/// real bcrypt verification (Devise's paranoid mitigation,
/// `strategies/database_authenticatable.rb:22`).
///
/// The digest is discarded: only the elapsed work matters.
pub fn paranoid_timing_equalize(config: &DeviseConfig) {
    if config.paranoid {
        let _dummy = crate::crypto::encryptor::digest("", config);
    }
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
    /// Failed-attempt persistence (Devise's `valid_for_authentication?`
    /// side effects over the strategy path); `None` = no accounting, the
    /// pre-seam behavior.
    pub failed_attempt_sink: Option<Arc<dyn crate::failed_attempt::FailedAttemptSink>>,
}

impl Default for ParamsStrategy {
    fn default() -> Self {
        Self {
            authentication_keys: vec!["email".to_string()],
            case_insensitive_keys: vec!["email".to_string()],
            strip_whitespace_keys: vec!["email".to_string()],
            failed_attempt_sink: None,
        }
    }
}

impl ParamsStrategy {
    /// Attach the failed-attempt sink (builder).
    #[must_use]
    pub fn with_failed_attempt_sink(
        mut self,
        sink: Arc<dyn crate::failed_attempt::FailedAttemptSink>,
    ) -> Self {
        self.failed_attempt_sink = Some(sink);
        self
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
                &raw,
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
        let Some(mut user) = finder
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
        let password_ok = check.valid_password(&password, config);
        // Devise's `Authenticatable#validate(resource) { resource.valid_password?(password) }`
        // evaluates the module side effects for BOTH outcomes: lockable's
        // `valid_for_authentication?` counts the attempt, releases an expired
        // lock, locks at the threshold, and rejects an already-locked record
        // even when the password is correct.
        if let Some(sink) = &self.failed_attempt_sink {
            if let crate::failed_attempt::AttemptVerdict::Failed(message) =
                sink.record(&user.to_key(), password_ok).await
            {
                return Err(Failure::InvalidCredentials { message });
            }
        }
        if password_ok {
            // DBAU-07: Devise fires after_database_authentication after a
            // successful password check in the database_authenticatable strategy.
            user.after_database_authentication();
            // Devise `Authenticatable#remember_me`: stamp the virtual flag
            // from the sign-in params so the rememberable-set hook can act.
            user.set_remember_me_flag(crate::rememberable::remember_flag_set(
                request,
                &mapping.name,
            ));
            Ok(AuthOutcome::Success(user))
        } else {
            Err(Failure::InvalidCredentials { message: "invalid" })
        }
    }

    fn id(&self) -> &'static str {
        "params"
    }

    fn with_failed_attempt_sink(
        &mut self,
        sink: Arc<dyn crate::failed_attempt::FailedAttemptSink>,
    ) {
        self.failed_attempt_sink = Some(sink);
    }
}

/// HTTP Basic strategy - `Authorization: Basic` header.
///
/// Honors `http_authenticatable`, `http_authenticatable_on_xhr`, and
/// `http_authentication_key` (falling back to the first authentication key).
///
/// Mirrors the HTTP Basic arm of `Devise::Strategies::DatabaseAuthenticatable` (`devise/lib/devise/strategies/database_authenticatable.rb`) with the 401 handshake.
pub struct HttpBasicStrategy {
    /// Identity keys (default `["email"]`).
    pub authentication_keys: Vec<String>,
    /// Explicit Basic username key, if different from `authentication_keys`.
    pub http_authentication_key: Option<String>,
    /// Whether XHR requests may use Basic auth.
    pub http_authenticatable_on_xhr: bool,
    /// Failed-attempt persistence (Devise's `valid_for_authentication?`
    /// side effects over this strategy path); `None` = no accounting,
    /// matching the params strategy's default.
    pub failed_attempt_sink: Option<Arc<dyn crate::failed_attempt::FailedAttemptSink>>,
}

impl Default for HttpBasicStrategy {
    fn default() -> Self {
        Self {
            authentication_keys: vec!["email".to_string()],
            http_authentication_key: None,
            http_authenticatable_on_xhr: true,
            failed_attempt_sink: None,
        }
    }
}

impl HttpBasicStrategy {
    /// Attach the failed-attempt sink (builder).
    #[must_use]
    pub fn with_failed_attempt_sink(
        mut self,
        sink: Arc<dyn crate::failed_attempt::FailedAttemptSink>,
    ) -> Self {
        self.failed_attempt_sink = Some(sink);
        self
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
        let password_ok = check.valid_password(&password, config);
        // Devise's `Authenticatable#validate(resource) { resource.valid_password?(password) }`
        // runs the module side effects for BOTH outcomes on this strategy too:
        // lockable counts an HTTP Basic brute force, releases an expired lock,
        // locks at the threshold, and rejects an already-locked record even
        // when the password is correct (closed 2026-10-25).
        if let Some(sink) = &self.failed_attempt_sink {
            if let crate::failed_attempt::AttemptVerdict::Failed(message) =
                sink.record(&user.to_key(), password_ok).await
            {
                return Err(Failure::InvalidCredentials { message });
            }
        }
        if password_ok {
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

    fn with_failed_attempt_sink(
        &mut self,
        sink: Arc<dyn crate::failed_attempt::FailedAttemptSink>,
    ) {
        self.failed_attempt_sink = Some(sink);
    }
}

/// Rememberable strategy - remember-me cookie, no-input, runs first.
///
/// Mirrors `devise/lib/devise/strategies/rememberable.rb`: `valid` on cookie
/// presence, `authenticate` deserializing the triple and enforcing the
/// five-condition check. Every miss shape (undecodable cookie, bad key,
/// unknown record, valueless record, failed check) deletes the cookie and
/// passes through, never failing. On a hit the strategy optionally re-issues
/// the cookie when `extend_remember_period` holds, calls
/// `after_remembered`, and succeeds.
pub struct RememberableStrategy {
    /// Cookie name (default `remember_{scope}_token`, override aware).
    pub cookie_key: String,
    /// Clock for the remember window and refresh timestamps.
    pub clock: Arc<dyn crate::time::Clock>,
}

impl Default for RememberableStrategy {
    fn default() -> Self {
        Self {
            cookie_key: "remember_user_token".to_string(),
            clock: Arc::new(crate::time::SystemClock),
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
        request: &AuthRequest,
        mapping: &Mapping,
        finder: &dyn ModelFinder,
        config: &DeviseConfig,
    ) -> Result<AuthOutcome, Failure> {
        let stale = || AuthOutcome::ClearCookieAndPass {
            cookie_key: self.cookie_key.clone(),
        };
        let Some(cookie) = request.cookies.get(&self.cookie_key) else {
            return Ok(AuthOutcome::Pass);
        };
        let Some((key, token, generated_at)) = crate::rememberable::decode_cookie_value(cookie)
        else {
            return Ok(stale());
        };
        let Ok(key) = DeviseKey::from_str(&key) else {
            return Ok(stale());
        };
        let record = finder
            .get_boxed(&key)
            .await
            .map_err(|error| Failure::Config(format!("{error}")))?;
        let Some(record) = record else {
            return Ok(stale());
        };
        let Some(stored) = record.rememberable_value_opt() else {
            return Ok(stale());
        };
        let generated = crate::rememberable::parse_generated_at(&generated_at);
        if !crate::rememberable::remember_cookie_valid(
            &stored,
            &token,
            generated,
            record.remember_created_at_opt(),
            config,
            self.clock.as_ref(),
        ) {
            return Ok(stale());
        }
        // Devise `validate(resource)`: the remembered record must still pass
        // its authentication rules, else fail with its own message.
        if !record.valid_for_authentication(None) {
            return Err(Failure::Unauthenticated {
                message: record.unauthenticated_message(),
            });
        }
        if config.extend_remember_period {
            let (fresh_key, fresh_value, fresh_generated) =
                crate::rememberable::build_cookie_triple(
                    &key.to_string(),
                    &stored,
                    self.clock.as_ref(),
                );
            let attrs = crate::rememberable::RememberableCookieAttrs::for_scope(
                &mapping.name,
                config,
                self.clock.as_ref(),
            );
            let cookie_value = crate::rememberable::encode_cookie_value(
                &fresh_key,
                &fresh_value,
                &fresh_generated,
            );
            record.after_remembered_hook();
            return Ok(AuthOutcome::SuccessWithCookieRefresh {
                user: record,
                cookie_key: self.cookie_key.clone(),
                cookie_value,
                expires: attrs.expires,
            });
        }
        record.after_remembered_hook();
        Ok(AuthOutcome::Success(record))
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
///
/// Mirrors the paranoid timing mitigation of devise's `config.paranoid`: dummy bcrypt on unknown accounts with uniform messages (CONCERNS 2).
pub struct ParanoidStrategy<S: Strategy> {
    inner: S,
}

impl<S: Strategy> ParanoidStrategy<S> {
    /// Wrap a strategy with paranoid handling.
    ///
    /// Constructs the paranoid wrapper around the inner strategy chain; mirrors devise's paranoid mode wrapping its strategies.
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
                paranoid_timing_equalize(config);
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
///
/// Test accessor for the params arm; no devise counterpart to mirror (devise reads `params` directly in its strategies).
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
        #[serde(skip)]
        remember_flag: Option<bool>,
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

        fn remember_me_flag_opt(&self) -> Option<bool> {
            self.remember_flag
        }

        fn set_remember_me_flag(&mut self, flag: bool) {
            self.remember_flag = Some(flag);
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

    fn paranoid_config() -> DeviseConfig {
        DeviseConfig {
            stretches: 4,
            paranoid: true,
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
                remember_flag: None,
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
        let config = test_config();
        let plain = strategies_for(&test_mapping(), &config);
        let plain_ids: Vec<&str> = plain.iter().map(Strategy::id).collect();
        assert_eq!(plain_ids, vec!["params", "http_basic"]);

        let mut with_remember = test_mapping();
        with_remember.modules = vec![
            crate::scope::Module::DatabaseAuthenticatable,
            crate::scope::Module::Rememberable,
        ];
        // RMB-04 verdict pinned: the no-input strategy runs BEFORE params
        // and HTTP Basic; the stale S-07 after-params sentence is superseded.
        let ordered = strategies_for(&with_remember, &config);
        let ordered_ids: Vec<&str> = ordered.iter().map(Strategy::id).collect();
        assert_eq!(ordered_ids, vec!["rememberable", "params", "http_basic"]);
        assert!(ordered.first().is_some_and(Strategy::no_input));

        // Paranoid wrapping preserves order and ids.
        let paranoid = strategies_for(&with_remember, &paranoid_config());
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

    /// Devise parity (`database_authenticatable.rb:22-25`): an unknown
    /// account fails with the `:not_found_in_database` key when paranoid is
    /// off, and the unified `:invalid` (after the dummy-hash timing
    /// equalization) when paranoid is on.
    #[test]
    fn test_unknown_account_failure_keys() {
        assert_eq!(
            unknown_account_failure(&test_config()),
            "not_found_in_database"
        );

        let mut paranoid = test_config();
        paranoid.paranoid = true;
        assert_eq!(unknown_account_failure(&paranoid), "invalid");
    }

    /// The `not_found_in_database` locale key must stay reachable through
    /// `FailureReason` (the controllers fail with the flash key).
    #[test]
    fn test_not_found_reason_flash_key() {
        assert_eq!(
            FailureReason::NotFoundInDatabase.flash_key(),
            "not_found_in_database"
        );
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
        // Absent cookie: plain pass-through.
        let bare = AuthRequest::new(crate::request::HttpMethod::Get, "/");
        assert!(!strategy.valid(&bare, &test_mapping()).await);
        let result = strategy
            .authenticate(&bare, &test_mapping(), &finder, &config)
            .await;
        assert!(matches!(result, Ok(AuthOutcome::Pass)));
        // Undecodable cookie: stale-cookie delete signal plus pass, never failure.
        let mut request = AuthRequest::new(crate::request::HttpMethod::Get, "/");
        request
            .cookies
            .insert("remember_user_token".to_string(), "token".to_string());
        assert!(strategy.valid(&request, &test_mapping()).await);
        let result = strategy
            .authenticate(&request, &test_mapping(), &finder, &config)
            .await;
        assert!(matches!(
            result,
            Ok(AuthOutcome::ClearCookieAndPass { ref cookie_key })
            if cookie_key == "remember_user_token"
        ));
    }

    #[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
    struct RememberStrategyUser {
        id: i64,
        email: String,
        remember_token: Option<String>,
        remember_created_at: Option<chrono::DateTime<chrono::Utc>>,
        #[serde(skip)]
        remember_flag: Option<bool>,
        #[serde(skip)]
        inactive: bool,
        #[serde(skip)]
        remembered: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl RememberStrategyUser {
        fn remembered(id: i64, created_at: chrono::DateTime<chrono::Utc>, token: &str) -> Self {
            Self {
                id,
                email: "remember@example.com".to_string(),
                remember_token: Some(token.to_string()),
                remember_created_at: Some(created_at),
                ..Self::default()
            }
        }
    }

    impl AnyDeviseModel for RememberStrategyUser {
        fn to_key(&self) -> crate::adapter::DeviseKey {
            crate::adapter::DeviseKey::from_i64(self.id)
        }

        fn valid_for_authentication(&self, _rules: Option<&crate::failure::AuthRules>) -> bool {
            !self.inactive
        }

        fn rememberable_value_opt(&self) -> Option<String> {
            Some(self.remember_token.clone().unwrap_or_default())
        }

        fn remember_created_at_opt(&self) -> Option<chrono::DateTime<chrono::Utc>> {
            self.remember_created_at
        }

        fn remember_me_flag_opt(&self) -> Option<bool> {
            self.remember_flag
        }

        fn set_remember_me_flag(&mut self, flag: bool) {
            self.remember_flag = Some(flag);
        }

        fn after_remembered_hook(&self) {
            self.remembered
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    fn remember_test_clock() -> crate::time::FixedClock {
        crate::time::FixedClock::new(
            chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("valid epoch"),
        )
    }

    async fn seeded_remember_finder()
    -> AdapterBridge<MemoryAdapter<RememberStrategyUser>, RememberStrategyUser> {
        let adapter = MemoryAdapter::<RememberStrategyUser>::new();
        adapter
            .create(RememberStrategyUser::remembered(
                1,
                chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("valid epoch"),
                "cookie-token",
            ))
            .await
            .unwrap();
        AdapterBridge::new(adapter)
    }

    fn remember_strategy_at(instant: chrono::DateTime<chrono::Utc>) -> RememberableStrategy {
        RememberableStrategy {
            cookie_key: "remember_user_token".to_string(),
            clock: Arc::new(crate::time::FixedClock::new(instant)),
        }
    }

    fn remember_cookie_for(token: &str, generated_epoch: i64) -> HashMap<String, String> {
        HashMap::from([(
            "remember_user_token".to_string(),
            crate::rememberable::encode_cookie_value("1", token, &generated_epoch.to_string()),
        )])
    }

    #[tokio::test]
    async fn test_strategy_rememberable_round_trip_success() {
        let config = test_config();
        let finder = seeded_remember_finder().await;
        let clock = remember_test_clock();
        let strategy = remember_strategy_at(crate::time::Clock::now(&clock));
        let mapping = test_mapping();

        let mut request = AuthRequest::new(crate::request::HttpMethod::Get, "/");
        // Cookie minted a minute after creation: inside the window and
        // strictly greater than `remember_created_at`.
        request.cookies = remember_cookie_for("cookie-token", 1_700_000_060);
        assert!(strategy.valid(&request, &mapping).await);
        match strategy
            .authenticate(&request, &mapping, &finder, &config)
            .await
        {
            Ok(AuthOutcome::Success(user)) => {
                assert_eq!(user.to_key(), crate::adapter::DeviseKey::from_i64(1));
                assert!(
                    user.as_any()
                        .downcast_ref::<RememberStrategyUser>()
                        .is_some_and(|record| record
                            .remembered
                            .load(std::sync::atomic::Ordering::SeqCst)),
                    "after_remembered runs on hit"
                );
            }
            other => panic!("expected success, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_strategy_rememberable_miss_shapes_delete_and_pass() {
        let config = test_config();
        let finder = seeded_remember_finder().await;
        let clock = remember_test_clock();
        let strategy = remember_strategy_at(crate::time::Clock::now(&clock));
        let mapping = test_mapping();

        let miss_cookies = vec![
            // Undecodable jar string.
            "garbage".to_string(),
            // Short array: the Devise "no timestamp" miss.
            "[\"1\",\"cookie-token\"]".to_string(),
            // Unparseable key.
            crate::rememberable::encode_cookie_value("nope", "cookie-token", "1700000060"),
            // Unknown record.
            crate::rememberable::encode_cookie_value("999", "cookie-token", "1700000060"),
            // Unparseable timestamp.
            crate::rememberable::encode_cookie_value("1", "cookie-token", "not-a-time"),
            // Expired generation.
            crate::rememberable::encode_cookie_value("1", "cookie-token", "1000"),
            // Generation at creation (strict greater-than fails).
            crate::rememberable::encode_cookie_value("1", "cookie-token", "1700000000"),
            // Wrong token (constant-time mismatch).
            crate::rememberable::encode_cookie_value("1", "wrong", "1700000060"),
        ];
        for jar in miss_cookies {
            let mut request = AuthRequest::new(crate::request::HttpMethod::Get, "/");
            request
                .cookies
                .insert("remember_user_token".to_string(), jar);
            let result = strategy
                .authenticate(&request, &mapping, &finder, &config)
                .await;
            assert!(
                matches!(
                    result,
                    Ok(AuthOutcome::ClearCookieAndPass { ref cookie_key })
                    if cookie_key == "remember_user_token"
                ),
                "stale cookie deletes and passes, never fails"
            );
        }
    }

    #[tokio::test]
    async fn test_strategy_rememberable_rejects_inactive_record() {
        let config = test_config();
        let adapter = MemoryAdapter::<RememberStrategyUser>::new();
        let mut locked_out = RememberStrategyUser::remembered(
            1,
            chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("valid epoch"),
            "cookie-token",
        );
        locked_out.inactive = true;
        adapter.create(locked_out).await.unwrap();
        let finder = AdapterBridge::new(adapter);
        let clock = remember_test_clock();
        let strategy = remember_strategy_at(crate::time::Clock::now(&clock));

        let mut request = AuthRequest::new(crate::request::HttpMethod::Get, "/");
        request.cookies = remember_cookie_for("cookie-token", 1_700_000_060);
        let result = strategy
            .authenticate(&request, &test_mapping(), &finder, &config)
            .await;
        assert!(matches!(
            result,
            Err(crate::failure::Failure::Unauthenticated { .. })
        ));
    }

    #[tokio::test]
    async fn test_strategy_rememberable_extend_reissues_when_enabled() {
        let mut config = test_config();
        config.extend_remember_period = true;
        let finder = seeded_remember_finder().await;
        let mapping = test_mapping();

        let mut request = AuthRequest::new(crate::request::HttpMethod::Get, "/");
        request.cookies = remember_cookie_for("cookie-token", 1_700_000_060);
        let refresh_at = chrono::DateTime::from_timestamp(1_700_010_000, 0).expect("valid epoch");
        let strategy = remember_strategy_at(refresh_at);
        match strategy
            .authenticate(&request, &mapping, &finder, &config)
            .await
        {
            Ok(AuthOutcome::SuccessWithCookieRefresh {
                user,
                cookie_key,
                cookie_value,
                expires,
            }) => {
                assert_eq!(user.to_key(), crate::adapter::DeviseKey::from_i64(1));
                assert_eq!(cookie_key, "remember_user_token");
                let decoded = crate::rememberable::decode_cookie_value(&cookie_value)
                    .expect("refresh carries a triple");
                assert_eq!(decoded.0, "1");
                assert_eq!(decoded.1, "cookie-token");
                let refreshed: i64 = decoded.2.parse().expect("epoch timestamp");
                assert_eq!(refreshed, refresh_at.timestamp());
                assert_eq!(expires, refresh_at + config.remember_for);
            }
            other => panic!("expected refresh, got {other:?}"),
        }

        // Fixed expiry (D-14): reuse never re-issues.
        let fixed_config = test_config();
        let fixed = remember_strategy_at(refresh_at);
        let mut fixed_request = AuthRequest::new(crate::request::HttpMethod::Get, "/");
        fixed_request.cookies = remember_cookie_for("cookie-token", 1_700_000_060);
        let result = fixed
            .authenticate(&fixed_request, &mapping, &finder, &fixed_config)
            .await;
        assert!(matches!(result, Ok(AuthOutcome::Success(_))));
    }

    #[tokio::test]
    async fn test_params_strategy_stamps_remember_flag() {
        let config = test_config();
        let finder = seeded_finder(&config).await;
        let strategy = ParamsStrategy::default();
        let mapping = test_mapping();

        let flagged = params_request(&[
            ("email", "test@example.com"),
            ("password", "secret123"),
            ("remember_me", "1"),
        ]);
        match strategy
            .authenticate(&flagged, &mapping, &finder, &config)
            .await
        {
            Ok(AuthOutcome::Success(user)) => {
                assert_eq!(user.remember_me_flag_opt(), Some(true));
            }
            other => panic!("expected success, got {other:?}"),
        }

        let plain = params_request(&[("email", "test@example.com"), ("password", "secret123")]);
        match strategy
            .authenticate(&plain, &mapping, &finder, &config)
            .await
        {
            Ok(AuthOutcome::Success(user)) => {
                assert_eq!(user.remember_me_flag_opt(), Some(false));
            }
            other => panic!("expected success, got {other:?}"),
        }
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
