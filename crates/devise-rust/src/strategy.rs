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
    ///
    /// Devise's `valid?` also consults the capability switches
    /// (`valid_for_params_auth?` / `valid_for_http_auth?`,
    /// `strategies/authenticatable.rb:77-90`): a disabled strategy is
    /// simply not valid and the chain moves on - it never aborts the
    /// request.
    async fn valid(&self, request: &AuthRequest, mapping: &Mapping, config: &DeviseConfig) -> bool;

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

    /// Devise's `authentication_type` (`:params_auth` / `:http_auth`):
    /// the slot checked against `skip_session_storage`
    /// (`strategies/authenticatable.rb:13-15`). Default: the strategy id.
    fn authentication_type(&self) -> &'static str {
        self.id()
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
    async fn valid(&self, request: &AuthRequest, mapping: &Mapping, config: &DeviseConfig) -> bool {
        (**self).valid(request, mapping, config).await
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

/// Decide whether a winning strategy's success persists a session.
///
/// Devise composes three gates (`strategies/authenticatable.rb:13-15` plus
/// warden's `env["devise.skip_storage"]`): the strategy's own `store?`, the
/// `skip_session_storage` list keyed by authentication type (default
/// `["http_auth"]` - an HTTP Basic login never creates a session), and the
/// request flag `handle_unverified_request` raises after a CSRF failure.
#[must_use]
pub fn session_should_store(
    strategy: &dyn Strategy,
    config: &DeviseConfig,
    request: &AuthRequest,
) -> bool {
    strategy.store()
        && !config
            .skip_session_storage
            .iter()
            .any(|skipped| skipped == strategy.authentication_type())
        && !request.flags.skip_storage
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

/// Whether every Devise `request_keys` entry resolves to a present,
/// non-blank value on the request snapshot.
///
/// The shared presence half of [`merge_request_keys`]: Devise's
/// `parse_authentication_key_values` (over `request_values`) returns false on
/// the first blank or missing key, which makes `with_authentication_hash`
/// false and the strategy simply not valid. The HTTP Basic strategy consults
/// this predicate inside its own `valid?` gate, and the params strategy gets
/// the same answer as the by-product of the merge.
fn request_keys_present(request: &AuthRequest, config: &DeviseConfig) -> bool {
    config.request_keys.iter().all(|key| {
        crate::model::value_present(request.request_values.get(key).map(String::as_str)).is_some()
    })
}

/// Merge Devise's `request_keys` lookup conditions into the authentication
/// conditions (core translation of `parse_authentication_key_values` over
/// `request_values`, `strategies/authenticatable.rb:157-167`).
///
/// Devise builds the authentication hash in two parse passes
/// (`with_authentication_hash`): the params (or HTTP Basic) keys first, then
/// the request-derived keys, so a same-named request value OVERWRITES a param
/// value (later parse wins). Each pass reports failure on the first key whose
/// value is missing or blank, and that failure makes the whole strategy not
/// apply rather than widening the lookup: a configured request key is a
/// REQUIRED lookup condition, never an optional refinement.
///
/// Returns `false` when any configured request key is missing or blank, in
/// which case the caller must not run a find (the strategy does not apply).
///
/// Every listed key is enforced here: this port's `request_keys` is a
/// `Vec<String>`, which has no equivalent of Devise's `{key => enforce}`
/// Hash form that lets an app opt a key out of enforcement.
///
/// Values are inserted RAW (no `ParameterFilter` normalization): Devise
/// routes params through the filter, while `request.send(key)` values enter
/// the authentication hash unnormalized.
pub fn merge_request_keys(
    conditions: &mut Conditions,
    request: &AuthRequest,
    config: &DeviseConfig,
) -> bool {
    for key in &config.request_keys {
        match crate::model::value_present(request.request_values.get(key).map(String::as_str)) {
            Some(value) => {
                conditions.insert(key.clone(), Value::String(value.to_string()));
            }
            None => return false,
        }
    }
    true
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
    ///
    /// Returns `None` when any required input is missing: an authentication
    /// key or the password is absent from the params, or a configured
    /// `request_keys` entry is missing or blank on the request snapshot
    /// ([`merge_request_keys`]). In Devise the last case is
    /// `with_authentication_hash` returning false inside `valid?`, so the
    /// strategy does not apply at all instead of running a find
    /// (`strategies/authenticatable.rb:79` and `:128-134`).
    fn credentials(
        &self,
        request: &AuthRequest,
        scope: &str,
        config: &DeviseConfig,
    ) -> Option<(Conditions, String)> {
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
        // Devise's second parse pass over the request-derived keys: the
        // values overwrite a same-named param condition (later parse wins),
        // and a missing or blank required key fails the parse.
        if !merge_request_keys(&mut conditions, request, config) {
            return None;
        }
        let password = extract_param(request, scope, "password")?;
        Some((conditions, password))
    }
}

#[async_trait]
impl Strategy for ParamsStrategy {
    async fn valid(&self, request: &AuthRequest, mapping: &Mapping, config: &DeviseConfig) -> bool {
        // Devise gates the capability inside `valid?`
        // (`valid_for_params_auth?`): a disabled strategy is skipped, never
        // fatal to the chain.
        config.params_authenticatable
            && request.flags.allow_params_authentication
            && self.credentials(request, &mapping.name, config).is_some()
    }

    /// Devise's `:params_auth` slot in `skip_session_storage`.
    fn authentication_type(&self) -> &'static str {
        "params_auth"
    }

    async fn authenticate(
        &self,
        request: &AuthRequest,
        mapping: &Mapping,
        finder: &dyn ModelFinder,
        config: &DeviseConfig,
    ) -> Result<AuthOutcome, Failure> {
        let Some((conditions, password)) = self.credentials(request, &mapping.name, config) else {
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
    async fn valid(
        &self,
        request: &AuthRequest,
        _mapping: &Mapping,
        config: &DeviseConfig,
    ) -> bool {
        // Devise gates the capability inside `valid?` (`valid_for_http_auth?`):
        // with the default `http_authenticatable = false`, a stale Basic
        // header simply makes this strategy not apply.
        if !config.http_authenticatable {
            return false;
        }
        if !request.has_http_basic() {
            return false;
        }
        if request.is_xhr() && !self.http_authenticatable_on_xhr {
            return false;
        }
        // Devise runs `with_authentication_hash` inside `valid?`
        // (`valid_for_http_auth?`, `strategies/authenticatable.rb:64-67`), so
        // a missing or blank required request key makes this strategy not
        // apply exactly as it does for the params strategy.
        request_keys_present(request, config)
    }

    /// Devise's `:http_auth` slot - the default member of
    /// `skip_session_storage`, so HTTP Basic never persists a session.
    fn authentication_type(&self) -> &'static str {
        "http_auth"
    }

    async fn authenticate(
        &self,
        request: &AuthRequest,
        _mapping: &Mapping,
        finder: &dyn ModelFinder,
        config: &DeviseConfig,
    ) -> Result<AuthOutcome, Failure> {
        let Some((username, password)) = request.http_basic_credentials() else {
            return Ok(AuthOutcome::Pass);
        };
        let key = self.http_authentication_key.clone().unwrap_or_else(|| {
            self.authentication_keys
                .first()
                .cloned()
                .unwrap_or_else(|| "email".to_string())
        });
        // Devise routes EVERY credential source through the parameter
        // filter (`authenticatable.rb:267-269`): `curl -u
        // "USER@Example.COM"` must find the stored `user@example.com`.
        let username = crate::model::normalize_credential_value(
            &username,
            &key,
            &config.case_insensitive_keys,
            &config.strip_whitespace_keys,
        );
        let mut conditions = Conditions::new();
        conditions.insert(key, Value::String(username));
        // Devise's second parse pass over the request-derived keys runs
        // inside `with_authentication_hash` before `authenticate!` is ever
        // reached, so a missing or blank required key can only surface here
        // as a defense in depth: pass through instead of widening the lookup
        // (`strategies/authenticatable.rb:147-167`).
        if !merge_request_keys(&mut conditions, request, config) {
            return Ok(AuthOutcome::Pass);
        }
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
/// the cookie when the record's overridable `extend_remember_period` holds,
/// calls `after_remembered`, and succeeds.
///
/// The re-issue decision is read from the RESOURCE exactly as Devise's
/// `extend_remember_me?` does (`strategies/rememberable.rb:47-49`), never
/// from the global config directly: the model method defaults to the config
/// cascade (`models/rememberable.rb:69-71`), so an app override flips the
/// refresh while every non-overriding model keeps the config behavior.
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
    async fn valid(
        &self,
        request: &AuthRequest,
        _mapping: &Mapping,
        _config: &DeviseConfig,
    ) -> bool {
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
        // Devise's strategy asks the record (`strategies/rememberable.rb:47-49`):
        // the per-model `extend_remember_period` decides the re-issue, with
        // the global config as its default.
        if record.extend_remember_period_hook(config) {
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
    async fn valid(&self, request: &AuthRequest, mapping: &Mapping, config: &DeviseConfig) -> bool {
        self.inner.valid(request, mapping, config).await
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

    /// `strategies/authenticatable.rb:13-15`: `store?` is `super &&`
    /// not-in-`skip_session_storage` - with Devise's default
    /// `[:http_auth]`, an HTTP Basic success must NOT persist a session,
    /// and `env["devise.skip_storage"]` (set by
    /// `handle_unverified_request`) suppresses storage for every strategy.
    #[test]
    fn test_session_storage_respects_skip_list_and_flag() {
        let config = test_config();
        let mapping = test_mapping();
        let strategies = strategies_for(&mapping, &config);
        let http_basic = strategies
            .iter()
            .find(|strategy| strategy.id() == "http_basic")
            .expect("http_basic strategy in chain");
        let params = strategies
            .iter()
            .find(|strategy| strategy.id() == "params")
            .expect("params strategy in chain");

        let request = AuthRequest::new(crate::request::HttpMethod::Get, "/");
        // Devise default skip_session_storage = ["http_auth"].
        assert!(
            !session_should_store(http_basic.as_ref(), &config, &request),
            "http_auth must not store a session by default"
        );
        assert!(
            session_should_store(params.as_ref(), &config, &request),
            "params auth stores a session by default"
        );

        // An app that opts http_auth into storage gets it back.
        let storing = DeviseConfig {
            skip_session_storage: vec![],
            ..test_config()
        };
        assert!(session_should_store(
            http_basic.as_ref(),
            &storing,
            &request
        ));

        // The CSRF-failure flag (`devise.skip_storage`) suppresses storage
        // for every strategy.
        let mut skipped = request.clone();
        skipped.flags.skip_storage = true;
        assert!(!session_should_store(params.as_ref(), &config, &skipped));
    }

    /// A disabled strategy is NOT valid and is skipped by the chain -
    /// never a fatal `Failure::Config` aborting the request
    /// (`strategies/authenticatable.rb:77-90` gates inside `valid?`).
    #[tokio::test]
    async fn test_disabled_strategy_is_skipped_not_fatal() {
        let config = test_config();
        let mapping = test_mapping();
        let strategies = strategies_for(&mapping, &config);

        let mut request = AuthRequest::new(crate::request::HttpMethod::Get, "/");
        request.headers.insert(
            "authorization".to_string(),
            "Basic dXNlcjpwYXNz".to_string(),
        );
        let disabled = DeviseConfig {
            http_authenticatable: false,
            ..test_config()
        };

        let http_basic = strategies
            .iter()
            .find(|strategy| strategy.id() == "http_basic")
            .expect("http_basic strategy in chain");
        assert!(
            !http_basic.valid(&request, &mapping, &disabled).await,
            "a disabled strategy must be invalid, not fatal"
        );
        // Devise's chain only calls authenticate after valid? - the hard
        // contract is that a disabled capability can never surface an
        // internal Failure::Config to the request.
        let finder = seeded_finder(&config).await;
        let outcome = http_basic
            .authenticate(&request, &mapping, &finder, &disabled)
            .await;
        assert!(
            !matches!(outcome, Err(Failure::Config(_))),
            "a disabled strategy must never abort the chain with a config error: {outcome:?}"
        );
    }

    #[tokio::test]
    async fn test_params_strategy_success() {
        let config = test_config();
        let finder = seeded_finder(&config).await;
        let strategy = ParamsStrategy::default();
        let mapping = test_mapping();
        let request = params_request(&[("email", "test@example.com"), ("password", "secret123")]);
        assert!(strategy.valid(&request, &mapping, &config).await);
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

    /// Devise's `request_keys` second parse pass
    /// (`strategies/authenticatable.rb:157-167`, integration contract
    /// `authenticatable_test.rb:579-608`): a request-derived value joins the
    /// authentication hash AFTER the params keys, so it OVERWRITES a
    /// same-named param value, and the lookup then finds the record the
    /// request-derived value names.
    #[tokio::test]
    async fn test_request_keys_params_value_overwrites_param_value() {
        let config = DeviseConfig {
            request_keys: vec!["email".to_string()],
            ..test_config()
        };
        let finder = seeded_finder(&config).await;
        let strategy = ParamsStrategy::default();
        // The params carry a stranger's address; the request snapshot carries
        // the seeded one, so the merge must win on the later parse.
        let mut request =
            params_request(&[("email", "wrong@example.com"), ("password", "secret123")]);
        request
            .request_values
            .insert("email".to_string(), "test@example.com".to_string());
        assert!(
            strategy.valid(&request, &test_mapping(), &config).await,
            "a present request key keeps the strategy valid"
        );
        match strategy
            .authenticate(&request, &test_mapping(), &finder, &config)
            .await
        {
            Ok(AuthOutcome::Success(user)) => {
                assert_eq!(user.to_key(), crate::adapter::DeviseKey::from_i64(1));
            }
            other => panic!("expected the request-key lookup to succeed, got {other:?}"),
        }
    }

    /// A configured `request_keys` entry with no value on the request is a
    /// MISSING lookup condition: Devise's second parse pass returns false,
    /// `valid?` reports false, and the chain fails with the generic invalid
    /// failure instead of looking the params email up (integration test
    /// `authenticatable_test.rb:600`).
    #[tokio::test]
    async fn test_request_keys_missing_value_makes_params_strategy_not_valid() {
        let config = DeviseConfig {
            request_keys: vec!["subdomain".to_string()],
            ..test_config()
        };
        let finder = seeded_finder(&config).await;
        let strategy = ParamsStrategy::default();
        // Correct credentials, still refused: the missing key aborts the parse.
        let request = params_request(&[("email", "test@example.com"), ("password", "secret123")]);
        assert!(
            !strategy.valid(&request, &test_mapping(), &config).await,
            "a missing request key must make the strategy not apply"
        );
        let outcome = strategy
            .authenticate(&request, &test_mapping(), &finder, &config)
            .await;
        assert!(
            matches!(outcome, Ok(AuthOutcome::Pass)),
            "the strategy must never reach a find: {outcome:?}"
        );
    }

    /// Devise's `presence` check treats a whitespace-only request value as
    /// missing (Ruby `blank?`), so `"   "` aborts the parse exactly as an
    /// absent key does (integration test at `authenticatable_test.rb:600`).
    #[tokio::test]
    async fn test_request_keys_blank_value_behaves_like_missing() {
        let config = DeviseConfig {
            request_keys: vec!["subdomain".to_string()],
            ..test_config()
        };
        let finder = seeded_finder(&config).await;
        let strategy = ParamsStrategy::default();
        let mut request =
            params_request(&[("email", "test@example.com"), ("password", "secret123")]);
        request
            .request_values
            .insert("subdomain".to_string(), "   ".to_string());
        assert!(!strategy.valid(&request, &test_mapping(), &config).await);
        let outcome = strategy
            .authenticate(&request, &test_mapping(), &finder, &config)
            .await;
        assert!(
            matches!(outcome, Ok(AuthOutcome::Pass)),
            "a blank request key must not reach a find: {outcome:?}"
        );
    }

    /// HTTP Basic reads the same request-key set
    /// (`strategies/authenticatable.rb:64-67`): a present request value
    /// overwrites the Basic username condition, and a missing one makes the
    /// strategy not valid at all.
    #[tokio::test]
    async fn test_request_keys_http_basic_value_overwrites_and_missing_aborts() {
        use base64::Engine as _;
        let config = DeviseConfig {
            http_authenticatable: true,
            request_keys: vec!["email".to_string()],
            ..test_config()
        };
        let finder = seeded_finder(&config).await;
        let strategy = HttpBasicStrategy::default();
        let mapping = test_mapping();
        let raw = base64::engine::general_purpose::STANDARD.encode("wrong@example.com:secret123");
        let mut request = AuthRequest::new(crate::request::HttpMethod::Get, "/");
        request
            .headers
            .insert("authorization".to_string(), format!("Basic {raw}"));
        request
            .request_values
            .insert("email".to_string(), "test@example.com".to_string());
        assert!(strategy.valid(&request, &mapping, &config).await);
        match strategy
            .authenticate(&request, &mapping, &finder, &config)
            .await
        {
            Ok(AuthOutcome::Success(user)) => {
                assert_eq!(user.to_key(), crate::adapter::DeviseKey::from_i64(1));
            }
            other => panic!("expected the request-key lookup to succeed, got {other:?}"),
        }

        // Same header, key configured to a value the request never carries:
        // the strategy does not apply, so no find runs.
        let absent = DeviseConfig {
            request_keys: vec!["subdomain".to_string()],
            ..config
        };
        assert!(
            !strategy.valid(&request, &mapping, &absent).await,
            "a missing request key must make the Basic strategy not apply"
        );
        let outcome = strategy
            .authenticate(&request, &mapping, &finder, &absent)
            .await;
        assert!(
            matches!(outcome, Ok(AuthOutcome::Pass)),
            "the Basic strategy must never reach a find: {outcome:?}"
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
        assert!(strategy.valid(&request, &mapping, &config).await);
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
        assert!(!strategy.valid(&bare, &test_mapping(), &config).await);
        let result = strategy
            .authenticate(&bare, &test_mapping(), &finder, &config)
            .await;
        assert!(matches!(result, Ok(AuthOutcome::Pass)));
        // Undecodable cookie: stale-cookie delete signal plus pass, never failure.
        let mut request = AuthRequest::new(crate::request::HttpMethod::Get, "/");
        request
            .cookies
            .insert("remember_user_token".to_string(), "token".to_string());
        assert!(strategy.valid(&request, &test_mapping(), &config).await);
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
        assert!(strategy.valid(&request, &mapping, &config).await);
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
