//! Lockable module - failed-attempt counting, lock/unlock, strategies (LCK-01..06).
//!
//! Mirrors `devise/lib/devise/models/lockable.rb`: the counter-to-lock path
//! (`increment_failed_attempts` plus `attempts_exceeded` lock at
//! `maximum_attempts` with the `:last_attempt` warning at N-1), the
//! time/email/both unlock strategies with `unlock_in` expiry, digest-only
//! unlock tokens with raw-token restore, paranoid message suppression, and
//! the sign-in reset hook semantics.
//!
//! Persistence always goes through `update_columns` (the forced-write verb,
//! never the diff-only `update`) plus a re-get, mirroring Devise's
//! `increment_counter` plus `reload` so concurrent increments read from the
//! store. Every time read takes `&dyn Clock`.
//!
//! == Options
//!
//! * `maximum_attempts` - failures accepted before locking (default 20)
//! * `lock_strategy` - lock by `failed_attempts` or `none` (default `failed_attempts`)
//! * `unlock_strategy` - unlock by `time`, `email`, `both` or `none` (default `both`)
//! * `unlock_in` - auto-release window for time locks (default 1 hour)
//! * `unlock_keys` - attributes used for unlock lookup (default `[:email]`)
//! * `last_attempt_warning` - warn on the next-to-last attempt (default true)
//!
//! == Examples
//!
//! ```ignore
//! // Ignored doctest: requires a live adapter and an async runtime; the compiled equivalent lives in the crate tests and the example apps.
//! // Two failures then the locking failure (maximum_attempts = 3).
//! user.increment_failed_attempts(&adapter).await?;
//! user.increment_failed_attempts(&adapter).await?;
//! user.increment_failed_attempts(&adapter).await?;
//! user.lock_access(&adapter, &mailer, &config, &clock).await?;
//! assert!(user.access_locked(&config, &clock));
//! ```

use crate::adapter::{Conditions, OrmAdapter, Value};
use crate::config::DeviseConfig;
use crate::error::{DeviseError, ResourceWithErrors, ValidationErrors};
use crate::mailer::{HasEmail, Mailer, MailerContext};
use crate::model::Authenticatable;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// Column bound into the HMAC key for unlock tokens.
///
/// Matches Devise's `TokenGenerator` key context `"Devise #{column}"`.
///
/// Mirrors Devise's `TokenGenerator` key context for the `unlock_token` column: the literal string "Devise {column}".
pub const UNLOCK_TOKEN_COLUMN: &str = "unlock_token";

/// Strategies enabled when `unlock_strategy` is `both`.
///
/// Mirrors Devise's `Lockable::BOTH_STRATEGIES = [:time, :email]`.
pub const BOTH_STRATEGIES: [&str; 2] = ["time", "email"];

/// Required model fields for Lockable, mirroring Devise's
/// `Lockable.required_fields`.
///
/// `failed_attempts` joins when the lock strategy counts attempts,
/// `locked_at` when a time unlock is enabled, `unlock_token` when an email
/// unlock is enabled.
///
/// == Examples
///
/// ```ignore
/// // Ignored doctest: requires a live adapter and an async runtime; the compiled equivalent lives in the crate tests and the example apps.
/// assert_eq!(required_fields(&config), vec!["failed_attempts", "locked_at", "unlock_token"]);
/// ```
#[must_use]
pub fn required_fields(config: &DeviseConfig) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if lock_strategy_enabled_for("failed_attempts", config) {
        fields.push("failed_attempts");
    }
    if unlock_strategy_enabled_for("time", config) {
        fields.push("locked_at");
    }
    if unlock_strategy_enabled_for("email", config) {
        fields.push("unlock_token");
    }
    fields
}

/// Whether the lock strategy enables the given strategy name.
///
/// Mirrors Devise's `lock_strategy_enabled?`: exact match only, so `both`
/// never enables a lock strategy.
///
/// == Examples
///
/// ```ignore
/// // Ignored doctest: requires a live adapter and an async runtime; the compiled equivalent lives in the crate tests and the example apps.
/// assert!(lock_strategy_enabled_for("failed_attempts", &config));
/// ```
#[must_use]
pub fn lock_strategy_enabled_for(strategy: &str, config: &DeviseConfig) -> bool {
    config.lock_strategy == strategy
}

/// Whether the unlock strategy enables the given strategy name.
///
/// Mirrors Devise's `unlock_strategy_enabled?`: exact match, or `both`
/// enabling each member of [`BOTH_STRATEGIES`].
///
/// == Examples
///
/// ```ignore
/// // Ignored doctest: requires a live adapter and an async runtime; the compiled equivalent lives in the crate tests and the example apps.
/// assert!(unlock_strategy_enabled_for("time", &config));
/// ```
#[must_use]
pub fn unlock_strategy_enabled_for(strategy: &str, config: &DeviseConfig) -> bool {
    config.unlock_strategy == strategy
        || (config.unlock_strategy == "both" && BOTH_STRATEGIES.contains(&strategy))
}

/// Outcome of one evaluated authentication attempt through
/// [`Lockable::apply_failed_attempt`].
///
/// The three variants are the patch-plus-outcome contract of Devise's
/// `valid_for_authentication?`: success, counted failure, or lock.
///
/// Outcome taxonomy of the lockable arm of `valid_for_authentication?`; mirrors devise's increment, lock, and unlock decision set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockAttemptOutcome {
    /// The base check passed and the record is unlocked: proceed to sign in.
    /// No lock state was written (an expired lock released first still
    /// counts as a write, but the outcome is success).
    Authenticated,
    /// A failure was recorded: the counter incremented while counting is
    /// enabled, and the record is still unlocked.
    FailedIncremented,
    /// The record is locked (already locked, or just locked at the
    /// threshold): reject the attempt as locked.
    Locked,
}

/// `Lockable` module - attempt counting and lock state over the three Devise
/// columns (`failed_attempts`, `locked_at`, `unlock_token`).
///
/// The DB stores the HMAC digest of the unlock token (keyed
/// `"Devise unlock_token"`); the raw token travels only in e-mail links,
/// request params, and the transient in-memory accessor.
///
/// == Options
///
/// See the module-level docs: `maximum_attempts`, `lock_strategy`,
/// `unlock_strategy`, `unlock_in`, `unlock_keys`, `last_attempt_warning`.
///
/// == Examples
///
/// ```ignore
/// // Ignored doctest: requires a live adapter and an async runtime; the compiled equivalent lives in the crate tests and the example apps.
/// impl Lockable for User {
///     fn failed_attempts(&self) -> u32 { self.failed_attempts }
///     // ... column accessors ...
/// }
/// ```
///
/// Mirrors `Devise::Models::Lockable` (`devise/lib/devise/models/lockable.rb`) as the trait surface: attempt counting, `lock_access`, `unlock_access`, and the unlock strategies.
#[async_trait]
pub trait Lockable: Authenticatable + HasEmail {
    /// Stored `failed_attempts` counter column.
    fn failed_attempts(&self) -> u32;
    /// Write the `failed_attempts` counter column.
    fn set_failed_attempts(&mut self, count: u32);
    /// `locked_at` timestamp column.
    fn locked_at(&self) -> Option<DateTime<Utc>>;
    /// Write the `locked_at` column.
    fn set_locked_at(&mut self, at: Option<DateTime<Utc>>);
    /// Stored `unlock_token` column, always the HMAC digest, never raw.
    fn unlock_token(&self) -> Option<&str>;
    /// Write the `unlock_token` column.
    fn set_unlock_token(&mut self, token: Option<String>);
    /// Whether the record is persisted (Devise `persisted?`). Unpersisted
    /// records never write lock state.
    fn persisted(&self) -> bool;

    /// Transient raw token, restored on the record after token creation or a
    /// successful `unlock_access_by_token`. Never persisted.
    fn raw_unlock_token(&self) -> Option<&str> {
        None
    }
    /// Restore the transient raw token (memory only).
    fn set_raw_unlock_token(&mut self, _raw: Option<String>) {}

    /// `lock_strategy_enabled?`: instance delegate to
    /// [`lock_strategy_enabled_for`].
    fn lock_strategy_enabled(&self, strategy: &str, config: &DeviseConfig) -> bool {
        lock_strategy_enabled_for(strategy, config)
    }

    /// `unlock_strategy_enabled?`: instance delegate to
    /// [`unlock_strategy_enabled_for`].
    fn unlock_strategy_enabled(&self, strategy: &str, config: &DeviseConfig) -> bool {
        unlock_strategy_enabled_for(strategy, config)
    }

    /// Whether this record participates in failure counting (LCK-01 guard):
    /// persisted records under the `failed_attempts` lock strategy only.
    /// Every counting path checks this first so `none`-strategy and new
    /// records produce zero writes.
    fn lock_counting_enabled(&self, config: &DeviseConfig) -> bool {
        self.persisted() && self.lock_strategy_enabled("failed_attempts", config)
    }

    /// `attempts_exceeded?`: the counter reached `maximum_attempts` (D-09).
    fn attempts_exceeded(&self, config: &DeviseConfig) -> bool {
        self.failed_attempts() >= config.maximum_attempts
    }

    /// `last_attempt?`: the counter sits exactly one below `maximum_attempts`
    /// (D-09). The checked subtraction keeps an absurd zero maximum from
    /// reporting a last attempt, matching Ruby's unbounded integers.
    fn last_attempt(&self, config: &DeviseConfig) -> bool {
        config
            .maximum_attempts
            .checked_sub(1)
            .is_some_and(|previous| self.failed_attempts() == previous)
    }

    /// `lock_expired?`: true only when a time unlock is enabled and
    /// `locked_at` predates now minus `unlock_in` (D-10, D-11). The
    /// comparison is strict `<`, so a lock exactly `unlock_in` old is still
    /// live (Devise-exact boundary).
    fn lock_expired(&self, config: &DeviseConfig, clock: &dyn crate::time::Clock) -> bool {
        if !self.unlock_strategy_enabled("time", config) {
            return false;
        }
        self.locked_at()
            .is_some_and(|locked_at| locked_at < clock.now() - config.unlock_in)
    }

    /// `access_locked?` (LCK-02): `locked_at` set plus not expired.
    fn access_locked(&self, config: &DeviseConfig, clock: &dyn crate::time::Clock) -> bool {
        self.locked_at().is_some() && !self.lock_expired(config, clock)
    }

    /// Lockable slice of `active_for_authentication?`: `base` carries the
    /// upstream chain result (confirmable gate first); this gate adds
    /// `!access_locked`. Evaluate after the confirmable gate (canonical
    /// super-chain order: confirmable before lockable).
    fn lock_gate_active(
        &self,
        base: bool,
        config: &DeviseConfig,
        clock: &dyn crate::time::Clock,
    ) -> bool {
        base && !self.access_locked(config, clock)
    }

    /// Lockable slice of `inactive_message`: `Some("locked")` while locked,
    /// `None` to defer to the next gate in the chain.
    fn lock_inactive_message(
        &self,
        config: &DeviseConfig,
        clock: &dyn crate::time::Clock,
    ) -> Option<&'static str> {
        if self.access_locked(config, clock) {
            Some("locked")
        } else {
            None
        }
    }

    /// Generate a fresh raw-plus-digest unlock pair, persist the digest plus
    /// the current `locked_at` via `update_columns`, and return the raw
    /// bearer. Shared by `lock_access` and `send_unlock_instructions` so the
    /// token pair flow has a single home.
    ///
    /// Uniqueness loops through
    /// [`column_value_unused`](crate::adapter::OrmAdapter::column_value_unused).
    ///
    /// # Errors
    ///
    /// `DeviseError::Adapter` when the uniqueness probe or persistence fails.
    async fn store_fresh_unlock_token<A>(
        &mut self,
        adapter: &A,
        config: &DeviseConfig,
    ) -> Result<String, DeviseError>
    where
        Self: Sized,
        A: OrmAdapter<Self> + Send + Sync,
    {
        let (raw, enc) = loop {
            let (raw, enc) =
                crate::crypto::token_generator::generate(&config.secret_key, UNLOCK_TOKEN_COLUMN);
            if adapter
                .column_value_unused(UNLOCK_TOKEN_COLUMN, &Value::String(enc.clone()))
                .await
                .map_err(DeviseError::Adapter)?
            {
                break (raw, enc);
            }
        };
        self.set_unlock_token(Some(enc.clone()));
        self.set_raw_unlock_token(Some(raw.clone()));
        let mut fields = HashMap::from([(UNLOCK_TOKEN_COLUMN.to_string(), Value::String(enc))]);
        if let Some(locked_at) = self.locked_at() {
            fields.insert(
                "locked_at".to_string(),
                Value::String(locked_at.to_rfc3339()),
            );
        }
        adapter
            .update_columns(&self.to_key(), &fields)
            .await
            .map_err(DeviseError::Adapter)?;
        Ok(raw)
    }

    /// `lock_access!` (LCK-03): stamp `locked_at`, then mail fresh unlock
    /// instructions when an email unlock is enabled unless `send_instructions`
    /// is false, else persist the stamp directly. Returns the mailed raw
    /// token when instructions went out.
    ///
    /// # Errors
    ///
    /// `DeviseError::Adapter` on persistence failure, `DeviseError::Mailer`
    /// when the notification cannot render.
    async fn lock_access<A, L>(
        &mut self,
        adapter: &A,
        mailer: &L,
        config: &DeviseConfig,
        clock: &dyn crate::time::Clock,
    ) -> Result<Option<String>, DeviseError>
    where
        Self: Sized,
        A: OrmAdapter<Self> + Send + Sync,
        L: Mailer<Self>,
    {
        self.lock_access_with_options(adapter, mailer, config, clock, true)
            .await
    }

    /// `lock_access!` with an explicit send flag: `send_instructions = false`
    /// skips the e-mail while still persisting the lock (Devise
    /// `lock_access!(send_instructions: false)`).
    ///
    /// # Errors
    ///
    /// `DeviseError::Adapter` on persistence failure, `DeviseError::Mailer`
    /// when the notification cannot render.
    async fn lock_access_with_options<A, L>(
        &mut self,
        adapter: &A,
        mailer: &L,
        config: &DeviseConfig,
        clock: &dyn crate::time::Clock,
        send_instructions: bool,
    ) -> Result<Option<String>, DeviseError>
    where
        Self: Sized,
        A: OrmAdapter<Self> + Send + Sync,
        L: Mailer<Self>,
    {
        let now = clock.now();
        self.set_locked_at(Some(now));
        if self.unlock_strategy_enabled("email", config) && send_instructions {
            let raw = self.store_fresh_unlock_token(adapter, config).await?;
            let context = MailerContext::from_record(self)
                .with_token(raw.clone())
                .with_resource(self.serializable_hash());
            mailer.unlock_instructions(self, Some(&raw), &context)?;
            Ok(Some(raw))
        } else {
            let fields =
                HashMap::from([("locked_at".to_string(), Value::String(now.to_rfc3339()))]);
            adapter
                .update_columns(&self.to_key(), &fields)
                .await
                .map_err(DeviseError::Adapter)?;
            Ok(None)
        }
    }

    /// `unlock_access!` (LCK-03): clear `locked_at`, `failed_attempts`, and
    /// `unlock_token` together, persisting via `update_columns`.
    ///
    /// # Errors
    ///
    /// `DeviseError::Adapter` when persistence fails.
    async fn unlock_access<A>(&mut self, adapter: &A) -> Result<(), DeviseError>
    where
        Self: Sized,
        A: OrmAdapter<Self> + Send + Sync,
    {
        self.set_locked_at(None);
        self.set_failed_attempts(0);
        self.set_unlock_token(None);
        let fields = HashMap::from([
            ("locked_at".to_string(), Value::Null),
            ("failed_attempts".to_string(), Value::Integer(0)),
            (UNLOCK_TOKEN_COLUMN.to_string(), Value::Null),
        ]);
        let updated = adapter
            .update_columns(&self.to_key(), &fields)
            .await
            .map_err(DeviseError::Adapter)?;
        *self = updated;
        Ok(())
    }

    /// `increment_failed_attempts` (LCK-01): re-read the counter from the
    /// store, add one, persist via `update_columns`, and reload the record.
    ///
    /// The re-get mirrors Devise's `increment_counter` plus `reload`: two
    /// concurrent processes each read the committed value, so no increment
    /// is lost to a stale in-memory copy. Diesel backends must keep this a
    /// single-statement increment (one `UPDATE ... SET failed_attempts =
    /// failed_attempts + 1`); the re-get here only refreshes the caller's
    /// copy afterwards.
    ///
    /// # Errors
    ///
    /// `DeviseError::NotFound` when the record is not in the store,
    /// `DeviseError::Adapter` on other persistence failures.
    async fn increment_failed_attempts<A>(&mut self, adapter: &A) -> Result<(), DeviseError>
    where
        Self: Sized,
        A: OrmAdapter<Self> + Send + Sync,
    {
        let fresh = adapter
            .get(&self.to_key())
            .await
            .map_err(DeviseError::Adapter)?
            .ok_or(DeviseError::NotFound)?;
        let next = fresh.failed_attempts().saturating_add(1);
        let fields = HashMap::from([(
            "failed_attempts".to_string(),
            Value::Integer(i64::from(next)),
        )]);
        let updated = adapter
            .update_columns(&self.to_key(), &fields)
            .await
            .map_err(DeviseError::Adapter)?;
        *self = updated;
        Ok(())
    }

    /// `reset_failed_attempts!` (LCK-06): zero a nonzero counter, persisting
    /// via `update_columns` (Devise `save(validate: false)`). Returns whether
    /// a reset was written; a zero counter is a no-op returning false.
    ///
    /// # Errors
    ///
    /// `DeviseError::Adapter` when persistence fails.
    async fn reset_failed_attempts<A>(&mut self, adapter: &A) -> Result<bool, DeviseError>
    where
        Self: Sized,
        A: OrmAdapter<Self> + Send + Sync,
    {
        if self.failed_attempts() == 0 {
            return Ok(false);
        }
        let fields = HashMap::from([("failed_attempts".to_string(), Value::Integer(0))]);
        let updated = adapter
            .update_columns(&self.to_key(), &fields)
            .await
            .map_err(DeviseError::Adapter)?;
        self.set_failed_attempts(updated.failed_attempts());
        Ok(true)
    }

    /// `send_unlock_instructions` (LCK-04): generate a raw token via
    /// [`store_fresh_unlock_token`](Self::store_fresh_unlock_token)
    /// (digest-only storage), e-mail the RAW token through
    /// `Mailer::unlock_instructions`, and return the raw token.
    ///
    /// # Errors
    ///
    /// `DeviseError::Adapter` on persistence failure, `DeviseError::Mailer`
    /// when the notification cannot render.
    async fn send_unlock_instructions<A, L>(
        &mut self,
        adapter: &A,
        mailer: &L,
        config: &DeviseConfig,
    ) -> Result<String, DeviseError>
    where
        Self: Sized,
        A: OrmAdapter<Self> + Send + Sync,
        L: Mailer<Self>,
    {
        let raw = self.store_fresh_unlock_token(adapter, config).await?;
        let context = MailerContext::from_record(self)
            .with_token(raw.clone())
            .with_resource(self.serializable_hash());
        mailer.unlock_instructions(self, Some(&raw), &context)?;
        Ok(raw)
    }

    /// `resend_unlock_instructions` (LCK-04): re-mail instructions only while
    /// locked (Devise `if_access_locked`); returns the fresh raw token, or
    /// `None` when the record is not locked. The `:not_locked` error belongs
    /// to the class-level caller, which owns the errors object.
    ///
    /// # Errors
    ///
    /// `DeviseError::Adapter` on persistence failure, `DeviseError::Mailer`
    /// when the notification cannot render.
    async fn resend_unlock_instructions<A, L>(
        &mut self,
        adapter: &A,
        mailer: &L,
        config: &DeviseConfig,
        clock: &dyn crate::time::Clock,
    ) -> Result<Option<String>, DeviseError>
    where
        Self: Sized,
        A: OrmAdapter<Self> + Send + Sync,
        L: Mailer<Self>,
    {
        if self.access_locked(config, clock) {
            Ok(Some(
                self.send_unlock_instructions(adapter, mailer, config)
                    .await?,
            ))
        } else {
            Ok(None)
        }
    }

    /// `unlock_access_by_token` (LCK-04): blank tokens fail with `:blank` on
    /// a fresh record without touching the adapter (T-05-04); otherwise the
    /// HMAC digest is looked up, a persisted match is unlocked, and the input
    /// token is restored on the returned record for re-render. Unknown tokens
    /// fail with `:invalid`. Unlocking never checks `access_locked`: any
    /// digest match unlocks, even an already-released lock.
    ///
    /// # Errors
    ///
    /// `DeviseError::Adapter` on lookup or persistence failure.
    async fn unlock_access_by_token<A>(
        token: Option<&str>,
        adapter: &A,
        config: &DeviseConfig,
    ) -> Result<ResourceWithErrors<Self>, DeviseError>
    where
        Self: Sized + Default,
        A: OrmAdapter<Self> + Send + Sync,
    {
        let raw = token.map(str::trim).filter(|text| !text.is_empty());
        let Some(raw) = raw else {
            let mut errors = ValidationErrors::new();
            errors.add(UNLOCK_TOKEN_COLUMN, ":blank");
            return Ok(ResourceWithErrors::new(Self::default(), errors));
        };
        let digest =
            crate::crypto::token_generator::digest(&config.secret_key, UNLOCK_TOKEN_COLUMN, raw);
        let mut conditions = Conditions::new();
        conditions.insert(UNLOCK_TOKEN_COLUMN, Value::String(digest));
        let Some(mut record) = adapter
            .find_first(&conditions)
            .await
            .map_err(DeviseError::Adapter)?
        else {
            let mut errors = ValidationErrors::new();
            errors.add(UNLOCK_TOKEN_COLUMN, ":invalid");
            return Ok(ResourceWithErrors::new(Self::default(), errors));
        };
        record.unlock_access(adapter).await?;
        record.set_raw_unlock_token(Some(raw.to_string()));
        Ok(ResourceWithErrors::new(record, ValidationErrors::new()))
    }

    /// Class `send_unlock_instructions(attributes)` (LCK-04): slice the
    /// attributes to `unlock_keys`, drop blanks, and require every key
    /// (Devise `find_or_initialize_with_errors`): missing keys fail with
    /// `:blank` and present keys with `:not_found`, with zero adapter calls.
    /// A persisted match re-mails only while locked, attaching `:not_locked`
    /// to the first unlock key otherwise.
    ///
    /// # Errors
    ///
    /// `DeviseError::Adapter` on lookup or persistence failure,
    /// `DeviseError::Mailer` when the notification cannot render.
    async fn send_unlock_instructions_for<A, L>(
        attributes: &serde_json::Map<String, serde_json::Value>,
        adapter: &A,
        mailer: &L,
        config: &DeviseConfig,
        clock: &dyn crate::time::Clock,
    ) -> Result<ResourceWithErrors<Self>, DeviseError>
    where
        Self: Sized + Default,
        A: OrmAdapter<Self> + Send + Sync,
        L: Mailer<Self>,
    {
        let keys: Vec<&str> = config.unlock_keys.iter().map(String::as_str).collect();
        let mut present: Vec<(&str, String)> = Vec::new();
        for key in &keys {
            if let Some(value) = attributes.get(*key).and_then(|item| item.as_str()) {
                let trimmed = value.trim();
                if !trimmed.is_empty() {
                    present.push((*key, trimmed.to_string()));
                }
            }
        }
        if present.len() != keys.len() {
            let mut errors = ValidationErrors::new();
            for key in &keys {
                if present.iter().any(|(found, _)| found == key) {
                    errors.add(key, ":not_found");
                } else {
                    errors.add(key, ":blank");
                }
            }
            return Ok(ResourceWithErrors::new(Self::default(), errors));
        }
        let mut conditions = Conditions::new();
        for (key, value) in &present {
            conditions.insert((*key).to_string(), Value::String(value.clone()));
        }
        let filtered = Self::normalize_auth_attributes_static(&conditions, config);
        let found = adapter
            .find_first(&filtered)
            .await
            .map_err(DeviseError::Adapter)?;
        let mut resource = if let Some(record) = found {
            ResourceWithErrors::new(record, ValidationErrors::new())
        } else {
            let mut errors = ValidationErrors::new();
            for key in &keys {
                errors.add(key, ":not_found");
            }
            ResourceWithErrors::new(Self::default(), errors)
        };
        if resource.is_valid() {
            let resent = resource
                .record
                .resend_unlock_instructions(adapter, mailer, config, clock)
                .await?;
            if resent.is_none() {
                let first = keys.first().copied().unwrap_or("email");
                resource.errors.add(first, ":not_locked");
            }
        }
        Ok(resource)
    }

    /// `unauthenticated_message` lockable branch (LCK-05, D-12): paranoid
    /// mode returns the uniform base message first, so locked, last-attempt,
    /// and unknown states stay indistinguishable; then `locked` while locked
    /// or past the threshold; then `last_attempt` on the next-to-last
    /// attempt with the warning enabled; else the base message.
    fn lock_unauthenticated_message(
        &self,
        config: &DeviseConfig,
        clock: &dyn crate::time::Clock,
    ) -> &'static str {
        if config.paranoid {
            return Authenticatable::unauthenticated_message(self);
        }
        if self.access_locked(config, clock)
            || (self.lock_strategy_enabled("failed_attempts", config)
                && self.attempts_exceeded(config))
        {
            return "locked";
        }
        if self.lock_strategy_enabled("failed_attempts", config)
            && self.last_attempt(config)
            && config.last_attempt_warning
        {
            return "last_attempt";
        }
        Authenticatable::unauthenticated_message(self)
    }

    /// `valid_for_authentication?` side-effect chain (LCK-01): evaluate one
    /// password attempt (`base_valid` is the password result) with Devise's
    /// exact side effects, persisting every mutation through
    /// `update_columns`.
    ///
    /// Order (mirrors `lockable.rb`):
    /// 1. Unpersisted records or the `none` lock strategy: no side effects,
    ///    pass the base result through.
    /// 2. Release an expired time-lock first, no matter the password result.
    /// 3. Base valid plus unlocked: success, nothing further to write (the
    ///    sign-in reset hook owns counter clearing on this path).
    /// 4. Otherwise increment the counter (even on already-locked records),
    ///    locking with instructions when the threshold is reached.
    ///
    /// Diesel backends must keep the increment a single-statement
    /// `UPDATE ... SET failed_attempts = failed_attempts + 1` (see
    /// [`increment_failed_attempts`](Self::increment_failed_attempts)); the
    /// trailing Devise `save(validate: false)` is intentionally not ported
    /// because every mutation above already persisted.
    ///
    /// == Examples
    ///
    /// ```ignore
    /// // Ignored doctest: requires a live adapter and an async runtime; the compiled equivalent lives in the crate tests and the example apps.
    /// match user.apply_failed_attempt(false, &adapter, &mailer, &config, &clock).await? {
    ///     LockAttemptOutcome::Locked => { /* reject as locked */ }
    ///     LockAttemptOutcome::FailedIncremented => { /* reject as invalid */ }
    ///     LockAttemptOutcome::Authenticated => { /* sign in */ }
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// `DeviseError::Adapter` on persistence failure, `DeviseError::Mailer`
    /// when auto-lock instructions cannot render.
    async fn apply_failed_attempt<A, L>(
        &mut self,
        base_valid: bool,
        adapter: &A,
        mailer: &L,
        config: &DeviseConfig,
        clock: &dyn crate::time::Clock,
    ) -> Result<LockAttemptOutcome, DeviseError>
    where
        Self: Sized,
        A: OrmAdapter<Self> + Send + Sync,
        L: Mailer<Self>,
    {
        if !self.lock_counting_enabled(config) {
            return Ok(if base_valid {
                LockAttemptOutcome::Authenticated
            } else {
                LockAttemptOutcome::FailedIncremented
            });
        }
        if self.lock_expired(config, clock) {
            self.unlock_access(adapter).await?;
        }
        if base_valid && !self.access_locked(config, clock) {
            return Ok(LockAttemptOutcome::Authenticated);
        }
        self.increment_failed_attempts(adapter).await?;
        if self.attempts_exceeded(config) {
            if !self.access_locked(config, clock) {
                self.lock_access(adapter, mailer, config, clock).await?;
            }
            return Ok(LockAttemptOutcome::Locked);
        }
        Ok(LockAttemptOutcome::FailedIncremented)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::memory::MemoryAdapter;
    use crate::failure::AnyDeviseModel;
    use crate::mailer::TestMailer;
    use crate::scope::{Mapping, Module, PathNames, SignOutVia};
    use crate::time::{Clock, FixedClock};
    use serde::{Deserialize, Serialize};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    struct TestUser {
        id: i64,
        email: String,
        encrypted_password: String,
        failed_attempts: u32,
        locked_at: Option<DateTime<Utc>>,
        unlock_token: Option<String>,
        #[serde(skip)]
        raw_unlock_token: Option<String>,
    }

    impl TestUser {
        fn fresh(id: i64, email: &str) -> Self {
            Self {
                id,
                email: email.to_string(),
                ..Self::default()
            }
        }
    }

    impl TestUser {
        fn with_password(mut self, password: &str, config: &DeviseConfig) -> Self {
            self.encrypted_password = crate::crypto::encryptor::digest(password, config);
            self
        }
    }

    impl crate::model::PasswordVerifiable for TestUser {
        fn valid_password(&self, password: &str, config: &DeviseConfig) -> bool {
            crate::crypto::encryptor::compare(password, &self.encrypted_password, config)
        }
    }

    #[async_trait::async_trait]
    impl crate::model::DatabaseAuthenticatable for TestUser {
        fn encrypted_password(&self) -> Option<&str> {
            Some(&self.encrypted_password)
        }
        fn set_encrypted_password(&mut self, hash: Option<String>) {
            self.encrypted_password = hash.unwrap_or_default();
        }
        fn password(&self) -> Option<&str> {
            None
        }
        fn set_password(&mut self, password: Option<String>, config: &DeviseConfig) {
            if let Some(password) = password {
                self.encrypted_password = crate::crypto::encryptor::digest(&password, config);
            }
        }
        fn password_confirmation(&self) -> Option<&str> {
            None
        }
        fn set_password_confirmation(&mut self, _confirmation: Option<String>) {}
        fn set_password_virtual(&mut self, _password: Option<String>) {}
        fn persisted(&self) -> bool {
            true
        }
        fn assign_attributes(&mut self, _attrs: &serde_json::Map<String, serde_json::Value>) {}
    }

    impl AnyDeviseModel for TestUser {
        fn to_key(&self) -> crate::adapter::DeviseKey {
            crate::adapter::DeviseKey::from_i64(self.id)
        }

        fn as_password_verifiable(&self) -> Option<&dyn crate::model::PasswordVerifiable> {
            Some(self)
        }

        fn reset_failed_attempts_hook(&mut self) -> bool {
            if self.failed_attempts == 0 {
                return false;
            }
            self.failed_attempts = 0;
            true
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    impl HasEmail for TestUser {
        fn email(&self) -> &str {
            &self.email
        }
    }

    #[async_trait]
    impl Authenticatable for TestUser {
        fn serializable_hash(&self) -> serde_json::Value {
            serde_json::json!({ "id": self.id, "email": self.email })
        }
    }

    #[async_trait]
    impl Lockable for TestUser {
        fn failed_attempts(&self) -> u32 {
            self.failed_attempts
        }

        fn set_failed_attempts(&mut self, count: u32) {
            self.failed_attempts = count;
        }

        fn locked_at(&self) -> Option<DateTime<Utc>> {
            self.locked_at
        }

        fn set_locked_at(&mut self, at: Option<DateTime<Utc>>) {
            self.locked_at = at;
        }

        fn unlock_token(&self) -> Option<&str> {
            self.unlock_token.as_deref()
        }

        fn set_unlock_token(&mut self, token: Option<String>) {
            self.unlock_token = token;
        }

        fn persisted(&self) -> bool {
            self.id != 0
        }

        fn raw_unlock_token(&self) -> Option<&str> {
            self.raw_unlock_token.as_deref()
        }

        fn set_raw_unlock_token(&mut self, raw: Option<String>) {
            self.raw_unlock_token = raw;
        }
    }

    fn test_config() -> DeviseConfig {
        DeviseConfig {
            secret_key: "test-secret-key".to_string(),
            ..DeviseConfig::default()
        }
    }

    /// Adapter wrapper counting every call, proving guarded paths perform
    /// zero adapter calls.
    struct CountingAdapter<'a> {
        inner: &'a MemoryAdapter<TestUser>,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl crate::adapter::OrmAdapter<TestUser> for CountingAdapter<'_> {
        type New = TestUser;

        async fn get(
            &self,
            id: &crate::adapter::DeviseKey,
        ) -> Result<Option<TestUser>, crate::adapter::OrmError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.get(id).await
        }

        async fn find_first(
            &self,
            conditions: &crate::adapter::Conditions,
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
            key: &crate::adapter::DeviseKey,
            changes: &crate::adapter::ChangeSet,
        ) -> Result<TestUser, crate::adapter::OrmError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.update(key, changes).await
        }

        async fn update_columns(
            &self,
            key: &crate::adapter::DeviseKey,
            fields: &HashMap<String, Value>,
        ) -> Result<TestUser, crate::adapter::OrmError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.update_columns(key, fields).await
        }

        async fn increment_counter(
            &self,
            key: &crate::adapter::DeviseKey,
            column: &'static str,
        ) -> Result<TestUser, crate::adapter::OrmError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.increment_counter(key, column).await
        }

        async fn delete(
            &self,
            id: &crate::adapter::DeviseKey,
        ) -> Result<(), crate::adapter::OrmError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.delete(id).await
        }
    }

    #[tokio::test]
    async fn lockable_tracer_counter_to_lock() {
        let config = DeviseConfig {
            maximum_attempts: 3,
            unlock_strategy: "time".to_string(),
            ..test_config()
        };
        let clock = FixedClock::now();
        let adapter = MemoryAdapter::<TestUser>::new();
        let mailer = TestMailer::default();
        let mut user = TestUser::fresh(1, "tracer@example.com");
        adapter.create(user.clone()).await.unwrap();

        user.increment_failed_attempts(&adapter).await.unwrap();
        assert_eq!(user.failed_attempts(), 1);
        assert!(!user.attempts_exceeded(&config));
        assert!(!user.access_locked(&config, &clock));

        user.increment_failed_attempts(&adapter).await.unwrap();
        assert_eq!(user.failed_attempts(), 2);
        assert!(!user.attempts_exceeded(&config));
        assert!(!user.access_locked(&config, &clock));

        user.increment_failed_attempts(&adapter).await.unwrap();
        assert_eq!(user.failed_attempts(), 3);
        assert!(user.attempts_exceeded(&config));

        user.lock_access_with_options(&adapter, &mailer, &config, &clock, false)
            .await
            .unwrap();
        assert!(user.locked_at().is_some());
        assert!(user.access_locked(&config, &clock));
        assert!(mailer.sent_mails().is_empty());

        let stored = adapter.get(&user.to_key()).await.unwrap().unwrap();
        assert_eq!(stored.failed_attempts, 3);
        assert!(stored.locked_at.is_some());
    }

    #[tokio::test]
    async fn lockable_tracer_none_strategy_no_side_effects() {
        let config = DeviseConfig {
            lock_strategy: "none".to_string(),
            maximum_attempts: 2,
            ..test_config()
        };
        let inner = MemoryAdapter::<TestUser>::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let adapter = CountingAdapter {
            inner: &inner,
            calls: Arc::clone(&calls),
        };
        let mut user = TestUser::fresh(1, "none@example.com");
        adapter.create(user.clone()).await.unwrap();
        let calls_after_seed = calls.load(Ordering::SeqCst);

        for _ in 0..3 {
            if user.lock_counting_enabled(&config) {
                user.increment_failed_attempts(&adapter).await.unwrap();
            }
        }
        assert_eq!(user.failed_attempts(), 0);
        assert!(!user.attempts_exceeded(&config));
        assert!(!user.access_locked(&config, &FixedClock::now()));
        assert_eq!(calls.load(Ordering::SeqCst), calls_after_seed);
    }

    #[tokio::test]
    async fn lockable_unlock_strategy_predicates_and_required_fields() {
        let both = test_config();
        assert_eq!(both.unlock_strategy, "both");
        assert!(unlock_strategy_enabled_for("both", &both));
        assert!(unlock_strategy_enabled_for("time", &both));
        assert!(unlock_strategy_enabled_for("email", &both));
        assert!(!unlock_strategy_enabled_for("none", &both));
        assert!(!unlock_strategy_enabled_for("undefined", &both));
        assert_eq!(
            required_fields(&both),
            vec!["failed_attempts", "locked_at", "unlock_token"]
        );

        let email_only = DeviseConfig {
            unlock_strategy: "email".to_string(),
            ..test_config()
        };
        assert!(!unlock_strategy_enabled_for("both", &email_only));
        assert!(!unlock_strategy_enabled_for("time", &email_only));
        assert!(unlock_strategy_enabled_for("email", &email_only));
        assert_eq!(
            required_fields(&email_only),
            vec!["failed_attempts", "unlock_token"]
        );

        let time_only = DeviseConfig {
            unlock_strategy: "time".to_string(),
            ..test_config()
        };
        assert!(unlock_strategy_enabled_for("time", &time_only));
        assert!(!unlock_strategy_enabled_for("email", &time_only));
        assert_eq!(
            required_fields(&time_only),
            vec!["failed_attempts", "locked_at"]
        );

        assert!(lock_strategy_enabled_for("failed_attempts", &both));
        assert!(!lock_strategy_enabled_for("none", &both));
    }

    #[tokio::test]
    async fn lockable_expired_time_lock_releases_live_lock_holds() {
        let config = test_config();
        let clock = FixedClock::now();

        let mut stale = TestUser::fresh(1, "stale@example.com");
        stale.set_locked_at(Some(clock.now() - chrono::TimeDelta::hours(2)));
        assert!(!stale.access_locked(&config, &clock));

        let mut fresh = TestUser::fresh(2, "fresh@example.com");
        fresh.set_locked_at(Some(clock.now() - chrono::TimeDelta::minutes(30)));
        assert!(fresh.access_locked(&config, &clock));

        let email_only = DeviseConfig {
            unlock_strategy: "email".to_string(),
            ..test_config()
        };
        let mut old_email_lock = TestUser::fresh(3, "old@example.com");
        old_email_lock.set_locked_at(Some(clock.now() - chrono::TimeDelta::hours(2)));
        assert!(old_email_lock.access_locked(&email_only, &clock));
    }

    #[tokio::test]
    async fn lockable_lock_access_mails_raw_stores_digest() {
        let config = test_config();
        let clock = FixedClock::now();
        let adapter = MemoryAdapter::<TestUser>::new();
        let mailer = TestMailer::default();
        let mut user = TestUser::fresh(1, "locked@example.com");
        adapter.create(user.clone()).await.unwrap();

        let sent_raw = user
            .lock_access(&adapter, &mailer, &config, &clock)
            .await
            .unwrap()
            .expect("email strategy mails on lock");
        assert_eq!(sent_raw.len(), 20);

        let stored = user.unlock_token().unwrap().to_string();
        assert_eq!(stored.len(), 64);
        assert_ne!(stored, sent_raw);
        assert_eq!(user.raw_unlock_token(), Some(sent_raw.as_str()));

        let mails = mailer.sent_mails();
        assert_eq!(mails.len(), 1);
        assert_eq!(mails[0].to, "locked@example.com");
        assert_eq!(
            mails[0].template_vars.token.as_deref(),
            Some(sent_raw.as_str())
        );
    }

    #[tokio::test]
    async fn lockable_lock_access_opt_out_skips_mail() {
        let config = test_config();
        let clock = FixedClock::now();
        let adapter = MemoryAdapter::<TestUser>::new();
        let mailer = TestMailer::default();
        let mut user = TestUser::fresh(1, "quiet@example.com");
        adapter.create(user.clone()).await.unwrap();

        let sent_opt = user
            .lock_access_with_options(&adapter, &mailer, &config, &clock, false)
            .await
            .unwrap();
        assert!(sent_opt.is_none());
        assert!(user.locked_at().is_some());
        assert!(user.unlock_token().is_none());
        assert!(mailer.sent_mails().is_empty());
        assert_eq!(user.lock_unauthenticated_message(&config, &clock), "locked");
    }

    #[tokio::test]
    async fn lockable_unlock_access_by_token_round_trip() {
        let config = test_config();
        let clock = FixedClock::now();
        let adapter = MemoryAdapter::<TestUser>::new();
        let mailer = TestMailer::default();
        let mut user = TestUser::fresh(1, "roundtrip@example.com");
        adapter.create(user.clone()).await.unwrap();
        user.set_failed_attempts(3);
        let raw = user
            .lock_access(&adapter, &mailer, &config, &clock)
            .await
            .unwrap()
            .expect("lock mails the raw token");
        assert!(user.access_locked(&config, &clock));

        let outcome = TestUser::unlock_access_by_token(Some(&raw), &adapter, &config)
            .await
            .unwrap();
        assert!(outcome.is_valid());
        assert_eq!(outcome.record.raw_unlock_token(), Some(raw.as_str()));
        assert!(!outcome.record.access_locked(&config, &clock));

        let stored = adapter.get(&user.to_key()).await.unwrap().unwrap();
        assert!(stored.locked_at.is_none());
        assert!(stored.unlock_token.is_none());
        assert_eq!(stored.failed_attempts, 0);
    }

    #[tokio::test]
    async fn lockable_unlock_access_by_token_blank_touches_no_adapter() {
        let config = test_config();
        let inner = MemoryAdapter::<TestUser>::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let adapter = CountingAdapter {
            inner: &inner,
            calls: Arc::clone(&calls),
        };

        for blank in [None, Some(""), Some("   ")] {
            let outcome = TestUser::unlock_access_by_token(blank, &adapter, &config)
                .await
                .unwrap();
            assert!(!outcome.is_valid());
            assert_eq!(
                outcome.errors.get("unlock_token"),
                Some(&vec![":blank".to_string()])
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn lockable_unlock_access_by_token_invalid() {
        let config = test_config();
        let adapter = MemoryAdapter::<TestUser>::new();

        let outcome = TestUser::unlock_access_by_token(Some("invalid_token"), &adapter, &config)
            .await
            .unwrap();
        assert!(!outcome.is_valid());
        assert!(!outcome.record.persisted());
        assert_eq!(
            outcome.errors.get("unlock_token"),
            Some(&vec![":invalid".to_string()])
        );
    }

    #[tokio::test]
    async fn lockable_last_attempt_matrix() {
        let config = DeviseConfig {
            maximum_attempts: 20,
            last_attempt_warning: true,
            ..test_config()
        };
        let clock = FixedClock::now();

        let mut user = TestUser::fresh(1, "matrix@example.com");
        user.set_failed_attempts(18);
        assert_eq!(
            user.lock_unauthenticated_message(&config, &clock),
            "invalid"
        );

        user.set_failed_attempts(19);
        assert!(user.last_attempt(&config));
        assert_eq!(
            user.lock_unauthenticated_message(&config, &clock),
            "last_attempt"
        );

        user.set_failed_attempts(20);
        assert!(user.attempts_exceeded(&config));
        assert_eq!(user.lock_unauthenticated_message(&config, &clock), "locked");

        let quiet = DeviseConfig {
            last_attempt_warning: false,
            ..test_config()
        };
        user.set_failed_attempts(19);
        assert_eq!(user.lock_unauthenticated_message(&quiet, &clock), "invalid");
    }

    #[tokio::test]
    async fn lockable_paranoid_suppresses_lock_messages() {
        let config = DeviseConfig {
            paranoid: true,
            maximum_attempts: 20,
            ..test_config()
        };
        let clock = FixedClock::now();

        let mut locked = TestUser::fresh(1, "paranoid@example.com");
        locked.set_locked_at(Some(clock.now()));
        locked.set_failed_attempts(21);
        assert_eq!(
            locked.lock_unauthenticated_message(&config, &clock),
            "invalid"
        );

        let mut last_attempt = TestUser::fresh(2, "edge@example.com");
        last_attempt.set_failed_attempts(19);
        assert_eq!(
            last_attempt.lock_unauthenticated_message(&config, &clock),
            "invalid"
        );
    }

    #[tokio::test]
    async fn lockable_class_send_unlock_instructions() {
        let config = test_config();
        let clock = FixedClock::now();
        let adapter = MemoryAdapter::<TestUser>::new();
        let mailer = TestMailer::default();

        let mut user = TestUser::fresh(1, "class@example.com");
        adapter.create(user.clone()).await.unwrap();
        user.lock_access(&adapter, &mailer, &config, &clock)
            .await
            .unwrap();

        let mut params = serde_json::Map::new();
        params.insert(
            "email".to_string(),
            serde_json::Value::String("class@example.com".to_string()),
        );
        let outcome =
            TestUser::send_unlock_instructions_for(&params, &adapter, &mailer, &config, &clock)
                .await
                .unwrap();
        assert!(outcome.is_valid());
        assert_eq!(mailer.sent_mails().len(), 2);

        let mut unknown = serde_json::Map::new();
        unknown.insert(
            "email".to_string(),
            serde_json::Value::String("nobody@example.com".to_string()),
        );
        let missing =
            TestUser::send_unlock_instructions_for(&unknown, &adapter, &mailer, &config, &clock)
                .await
                .unwrap();
        assert!(!missing.is_valid());
        assert_eq!(
            missing.errors.get("email"),
            Some(&vec![":not_found".to_string()])
        );
        assert_eq!(mailer.sent_mails().len(), 2);
    }

    #[tokio::test]
    async fn lockable_class_send_requires_all_unlock_keys() {
        let config = DeviseConfig {
            unlock_keys: vec!["email".to_string(), "username".to_string()],
            ..test_config()
        };
        let clock = FixedClock::now();
        let adapter = MemoryAdapter::<TestUser>::new();
        let mailer = TestMailer::default();

        let user = TestUser::fresh(1, "keys@example.com");
        adapter.create(user.clone()).await.unwrap();

        let mut partial = serde_json::Map::new();
        partial.insert(
            "email".to_string(),
            serde_json::Value::String("keys@example.com".to_string()),
        );
        let outcome =
            TestUser::send_unlock_instructions_for(&partial, &adapter, &mailer, &config, &clock)
                .await
                .unwrap();
        assert!(!outcome.is_valid());
        assert_eq!(
            outcome.errors.get("username"),
            Some(&vec![":blank".to_string()])
        );
        assert!(mailer.sent_mails().is_empty());
    }

    #[tokio::test]
    async fn lockable_resend_refuses_unlocked_record() {
        let config = test_config();
        let clock = FixedClock::now();
        let adapter = MemoryAdapter::<TestUser>::new();
        let mailer = TestMailer::default();

        let user = TestUser::fresh(1, "open@example.com");
        adapter.create(user.clone()).await.unwrap();

        let mut params = serde_json::Map::new();
        params.insert(
            "email".to_string(),
            serde_json::Value::String("open@example.com".to_string()),
        );
        let outcome =
            TestUser::send_unlock_instructions_for(&params, &adapter, &mailer, &config, &clock)
                .await
                .unwrap();
        assert!(!outcome.is_valid());
        assert_eq!(
            outcome.errors.get("email"),
            Some(&vec![":not_locked".to_string()])
        );
        assert!(mailer.sent_mails().is_empty());
    }

    #[tokio::test]
    async fn lockable_chain_locks_at_threshold_and_counts_when_locked() {
        let config = DeviseConfig {
            maximum_attempts: 2,
            ..test_config()
        };
        let clock = FixedClock::now();
        let adapter = MemoryAdapter::<TestUser>::new();
        let mailer = TestMailer::default();
        let mut user = TestUser::fresh(1, "chain@example.com");
        adapter.create(user.clone()).await.unwrap();

        let first = user
            .apply_failed_attempt(false, &adapter, &mailer, &config, &clock)
            .await
            .unwrap();
        assert_eq!(first, LockAttemptOutcome::FailedIncremented);
        assert_eq!(user.failed_attempts(), 1);
        assert!(!user.access_locked(&config, &clock));

        let second = user
            .apply_failed_attempt(false, &adapter, &mailer, &config, &clock)
            .await
            .unwrap();
        assert_eq!(second, LockAttemptOutcome::Locked);
        assert_eq!(user.failed_attempts(), 2);
        assert!(user.access_locked(&config, &clock));
        assert_eq!(mailer.sent_mails().len(), 1);

        let third = user
            .apply_failed_attempt(true, &adapter, &mailer, &config, &clock)
            .await
            .unwrap();
        assert_eq!(third, LockAttemptOutcome::Locked);
        assert_eq!(user.failed_attempts(), 3);

        let stored = adapter.get(&user.to_key()).await.unwrap().unwrap();
        assert_eq!(stored.failed_attempts, 3);
        assert!(stored.locked_at.is_some());
    }

    #[tokio::test]
    async fn lockable_chain_skips_unpersisted_and_none_strategy() {
        let clock = FixedClock::now();
        let inner = MemoryAdapter::<TestUser>::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let adapter = CountingAdapter {
            inner: &inner,
            calls: Arc::clone(&calls),
        };
        let mailer = TestMailer::default();

        let mut ghost = TestUser::fresh(0, "ghost@example.com");
        let ghost_outcome = ghost
            .apply_failed_attempt(false, &adapter, &mailer, &test_config(), &clock)
            .await
            .unwrap();
        assert_eq!(ghost_outcome, LockAttemptOutcome::FailedIncremented);
        assert_eq!(ghost.failed_attempts(), 0);

        let none_config = DeviseConfig {
            lock_strategy: "none".to_string(),
            maximum_attempts: 2,
            ..test_config()
        };
        let mut plain = TestUser::fresh(1, "plain@example.com");
        adapter.create(plain.clone()).await.unwrap();
        let calls_after_seed = calls.load(Ordering::SeqCst);
        let none_outcome = plain
            .apply_failed_attempt(false, &adapter, &mailer, &none_config, &clock)
            .await
            .unwrap();
        assert_eq!(none_outcome, LockAttemptOutcome::FailedIncremented);
        assert_eq!(plain.failed_attempts(), 0);
        assert_eq!(calls.load(Ordering::SeqCst), calls_after_seed);
    }

    #[tokio::test]
    async fn lockable_chain_releases_expired_lock() {
        let config = DeviseConfig {
            unlock_in: chrono::TimeDelta::minutes(1),
            ..test_config()
        };
        let clock = FixedClock::now();
        let adapter = MemoryAdapter::<TestUser>::new();
        let mailer = TestMailer::default();

        let mut stale_failure = TestUser::fresh(1, "stale-fail@example.com");
        adapter.create(stale_failure.clone()).await.unwrap();
        let fields = HashMap::from([
            ("failed_attempts".to_string(), Value::Integer(2)),
            (
                "locked_at".to_string(),
                Value::String((clock.now() - chrono::TimeDelta::minutes(2)).to_rfc3339()),
            ),
        ]);
        adapter
            .update_columns(&stale_failure.to_key(), &fields)
            .await
            .unwrap();
        stale_failure = adapter
            .get(&stale_failure.to_key())
            .await
            .unwrap()
            .expect("seeded lockable record reloads");
        let failed = stale_failure
            .apply_failed_attempt(false, &adapter, &mailer, &config, &clock)
            .await
            .unwrap();
        assert_eq!(failed, LockAttemptOutcome::FailedIncremented);
        assert_eq!(stale_failure.failed_attempts(), 1);
        assert!(!stale_failure.access_locked(&config, &clock));

        let mut stale_success = TestUser::fresh(2, "stale-ok@example.com");
        adapter.create(stale_success.clone()).await.unwrap();
        let stale_fields = HashMap::from([
            ("failed_attempts".to_string(), Value::Integer(2)),
            (
                "locked_at".to_string(),
                Value::String((clock.now() - chrono::TimeDelta::minutes(2)).to_rfc3339()),
            ),
        ]);
        adapter
            .update_columns(&stale_success.to_key(), &stale_fields)
            .await
            .unwrap();
        stale_success = adapter
            .get(&stale_success.to_key())
            .await
            .unwrap()
            .expect("seeded lockable record reloads");
        let succeeded = stale_success
            .apply_failed_attempt(true, &adapter, &mailer, &config, &clock)
            .await
            .unwrap();
        assert_eq!(succeeded, LockAttemptOutcome::Authenticated);
        assert_eq!(stale_success.failed_attempts(), 0);
        assert!(stale_success.locked_at().is_none());
    }

    #[tokio::test]
    async fn lockable_chain_reads_counter_from_store() {
        let config = test_config();
        let clock = FixedClock::now();
        let adapter = MemoryAdapter::<TestUser>::new();
        let mailer = TestMailer::default();
        let mut user = TestUser::fresh(1, "race@example.com");
        adapter.create(user.clone()).await.unwrap();

        user.increment_failed_attempts(&adapter).await.unwrap();
        assert_eq!(user.failed_attempts(), 1);

        adapter
            .update_columns(
                &user.to_key(),
                &HashMap::from([("failed_attempts".to_string(), Value::Integer(5))]),
            )
            .await
            .unwrap();
        user.increment_failed_attempts(&adapter).await.unwrap();
        assert_eq!(user.failed_attempts(), 6);

        let outcome = user
            .apply_failed_attempt(false, &adapter, &mailer, &config, &clock)
            .await
            .unwrap();
        assert_eq!(outcome, LockAttemptOutcome::FailedIncremented);
        assert_eq!(user.failed_attempts(), 7);
    }

    #[tokio::test]
    async fn lockable_reset_failed_attempts_writes_zero() {
        let adapter = MemoryAdapter::<TestUser>::new();
        let mut user = TestUser::fresh(1, "reset@example.com");
        adapter.create(user.clone()).await.unwrap();
        user.increment_failed_attempts(&adapter).await.unwrap();
        assert_eq!(user.failed_attempts(), 1);

        assert!(user.reset_failed_attempts(&adapter).await.unwrap());
        assert_eq!(user.failed_attempts(), 0);
        let stored = adapter.get(&user.to_key()).await.unwrap().unwrap();
        assert_eq!(stored.failed_attempts, 0);

        assert!(!user.reset_failed_attempts(&adapter).await.unwrap());
    }

    #[derive(Debug, Default)]
    struct NoopStore;
    #[async_trait::async_trait]
    impl crate::session::SessionStore for NoopStore {
        async fn get_value(&self, _key: &str) -> Option<serde_json::Value> {
            None
        }

        async fn insert_value(&self, _key: &str, _value: serde_json::Value) {}

        async fn remove(&self, _key: &str) {}

        async fn remove_prefix(&self, _prefix: &str) {}

        async fn keys_with_prefix(&self, _prefix: &str) -> Vec<String> {
            Vec::new()
        }

        async fn renew(&self) -> Result<(), crate::error::DeviseError> {
            Ok(())
        }

        async fn reset(&self) -> Result<(), crate::error::DeviseError> {
            Ok(())
        }
    }

    struct LockHookProxy {
        store: NoopStore,
        users: HashMap<String, Option<Box<dyn AnyDeviseModel>>>,
    }

    impl crate::hooks::HookProxy for LockHookProxy {
        fn session_store(&self) -> &dyn crate::session::SessionStore {
            &self.store
        }

        fn scope_registry(&self) -> &crate::scope::ScopeRegistry {
            unimplemented!("lockable hook tests never touch the scope registry")
        }

        fn user_mut(&mut self, scope: &str) -> Option<&mut Option<Box<dyn AnyDeviseModel>>> {
            self.users.get_mut(scope)
        }

        fn lock(&mut self) {}
    }

    fn lockable_test_mapping() -> crate::scope::Mapping {
        crate::scope::Mapping {
            name: "user".to_string(),
            class_name: "User".to_string(),
            path: "users".to_string(),
            path_prefix: None,
            singular: "user".to_string(),
            path_names: crate::scope::PathNames::default(),
            controllers: HashMap::new(),
            modules: vec![
                crate::scope::Module::DatabaseAuthenticatable,
                crate::scope::Module::Lockable,
            ],
            only: vec![],
            skip: vec![],
            constraints: HashMap::new(),
            defaults: HashMap::new(),
            format: None,
            router_name: None,
            sign_out_via: crate::scope::SignOutVia::Delete,
            failure_app: None,
        }
    }

    #[tokio::test]
    async fn lockable_reset_hook_fires_on_authentication_skips_fetch() {
        use crate::hooks::{Event, HookContext, HookRegistry, register_devise_hooks};

        let mut registry = HookRegistry::new();
        register_devise_hooks(&mut registry, &lockable_test_mapping());
        assert_eq!(registry.len(), 3);

        let mut proxy = LockHookProxy {
            store: NoopStore,
            users: HashMap::new(),
        };
        let mut signed_in = TestUser::fresh(1, "hook@example.com");
        signed_in.set_failed_attempts(5);
        proxy
            .users
            .insert("user".to_string(), Some(Box::new(signed_in)));

        {
            let mut auth_ctx = HookContext {
                proxy: &mut proxy,
                scope: "user",
                event: Event::Authentication,
                request: None,
                record: None,
            };
            registry.run_hooks(&mut auth_ctx).await.unwrap();
        }
        let cleared = proxy.users["user"]
            .as_ref()
            .expect("user stays signed in")
            .as_any()
            .downcast_ref::<TestUser>()
            .expect("memoized record is the lockable test user");
        assert_eq!(cleared.failed_attempts(), 0);

        let mut relocked = TestUser::fresh(1, "hook@example.com");
        relocked.set_failed_attempts(5);
        proxy
            .users
            .insert("user".to_string(), Some(Box::new(relocked)));
        {
            let mut fetch_ctx = HookContext {
                proxy: &mut proxy,
                scope: "user",
                event: Event::Fetch,
                request: None,
                record: None,
            };
            registry.run_hooks(&mut fetch_ctx).await.unwrap();
        }
        let kept = proxy.users["user"]
            .as_ref()
            .expect("user stays memoized")
            .as_any()
            .downcast_ref::<TestUser>()
            .expect("memoized record is the lockable test user");
        assert_eq!(kept.failed_attempts(), 5);
    }

    use crate::adapter::DeviseKey;
    use crate::failed_attempt::{AttemptVerdict, FailedAttemptSink};
    use crate::failure::{AuthOutcome, Failure};
    use crate::lockable::LockAttemptOutcome;
    use crate::model::AdapterBridge;
    use crate::request::AuthRequest;
    use crate::strategy::{ParamsStrategy, Strategy as _};

    fn chain_config() -> DeviseConfig {
        DeviseConfig {
            maximum_attempts: 3,
            unlock_strategy: "time".to_string(),
            stretches: 4,
            ..test_config()
        }
    }

    fn mapping() -> crate::scope::Mapping {
        let mut mapping = Mapping {
            name: "user".to_string(),
            class_name: "TestUser".to_string(),
            path: "users".to_string(),
            path_prefix: None,
            singular: "user".to_string(),
            path_names: PathNames::default(),
            controllers: HashMap::new(),
            modules: vec![Module::DatabaseAuthenticatable, Module::Lockable],
            only: vec![],
            skip: vec![],
            constraints: HashMap::new(),
            defaults: HashMap::new(),
            format: None,
            router_name: None,
            sign_out_via: SignOutVia::Delete,
            failure_app: None,
        };
        mapping.modules.sort();
        mapping
    }

    /// Typed sink over the in-memory adapter - the shape a framework bridge
    /// registers per scope.
    struct MemorySink {
        adapter: Arc<MemoryAdapter<TestUser>>,
        mailer: Arc<TestMailer>,
        config: Arc<DeviseConfig>,
        clock: Arc<FixedClock>,
    }

    #[async_trait::async_trait]
    impl FailedAttemptSink for MemorySink {
        async fn record(&self, key: &DeviseKey, password_ok: bool) -> AttemptVerdict {
            let Ok(Some(mut record)) = self.adapter.get(key).await else {
                return AttemptVerdict::Recorded;
            };
            match record
                .apply_failed_attempt(
                    password_ok,
                    self.adapter.as_ref(),
                    self.mailer.as_ref(),
                    &self.config,
                    self.clock.as_ref(),
                )
                .await
            {
                Ok(LockAttemptOutcome::Locked | LockAttemptOutcome::FailedIncremented) => {
                    AttemptVerdict::Failed(
                        record.lock_unauthenticated_message(&self.config, self.clock.as_ref()),
                    )
                }
                Ok(LockAttemptOutcome::Authenticated) | Err(_) => AttemptVerdict::Recorded,
            }
        }
    }

    fn request(password: &str) -> AuthRequest {
        let mut request = AuthRequest::new(crate::request::HttpMethod::Post, "/users/sign_in");
        request.params = HashMap::from([
            ("user[email]".to_string(), "chain@example.com".to_string()),
            ("password".to_string(), password.to_string()),
        ]);
        request.flags.allow_params_authentication = true;
        request
    }

    #[tokio::test]
    async fn strategy_chain_counts_and_locks_through_the_sink() {
        let config = chain_config();
        let clock = FixedClock::now();
        let adapter = Arc::new(MemoryAdapter::<TestUser>::new());
        let seeded = TestUser::fresh(1, "chain@example.com").with_password("secret123", &config);
        adapter.create(seeded).await.unwrap();

        let finder = AdapterBridge::new((*adapter).clone());
        let sink = Arc::new(MemorySink {
            adapter: adapter.clone(),
            mailer: Arc::new(TestMailer::default()),
            config: Arc::new(config.clone()),
            clock: Arc::new(clock),
        });
        let strategy = ParamsStrategy::default().with_failed_attempt_sink(sink);
        let mapping = mapping();

        // Wrong password #1: counted, reported :invalid.
        let first = strategy
            .authenticate(&request("wrong"), &mapping, &finder, &config)
            .await;
        assert!(matches!(
            first,
            Err(Failure::InvalidCredentials { message: "invalid" })
        ));
        let stored = adapter.get(&DeviseKey::from_i64(1)).await.unwrap().unwrap();
        assert_eq!(
            stored.failed_attempts(),
            1,
            "attempt 1 counted on the chain"
        );

        // Attempt 3 crosses maximum_attempts: the chain reports `locked`.
        let _ = strategy
            .authenticate(&request("wrong"), &mapping, &finder, &config)
            .await;
        let third = strategy
            .authenticate(&request("wrong"), &mapping, &finder, &config)
            .await;
        assert!(matches!(
            third,
            Err(Failure::InvalidCredentials { message: "locked" })
        ));

        // Locked record: even the correct password fails with `locked`.
        let right = strategy
            .authenticate(&request("secret123"), &mapping, &finder, &config)
            .await;
        assert!(matches!(
            right,
            Err(Failure::InvalidCredentials { message: "locked" })
        ));

        // Without a sink the chain keeps the pre-seam behavior: plain
        // :invalid, nothing counted.
        let plain = ParamsStrategy::default();
        let result = plain
            .authenticate(&request("wrong"), &mapping, &finder, &config)
            .await;
        assert!(matches!(
            result,
            Err(Failure::InvalidCredentials { message: "invalid" })
        ));
    }

    #[tokio::test]
    async fn strategy_chain_success_with_sink_stays_authenticated() {
        let config = chain_config();
        let clock = FixedClock::now();
        let adapter = Arc::new(MemoryAdapter::<TestUser>::new());
        let seeded = TestUser::fresh(1, "chain@example.com").with_password("secret123", &config);
        adapter.create(seeded).await.unwrap();

        let finder = AdapterBridge::new((*adapter).clone());
        let sink = Arc::new(MemorySink {
            adapter: adapter.clone(),
            mailer: Arc::new(TestMailer::default()),
            config: Arc::new(config.clone()),
            clock: Arc::new(clock),
        });
        let strategy = ParamsStrategy::default().with_failed_attempt_sink(sink);
        let result = strategy
            .authenticate(&request("secret123"), &mapping(), &finder, &config)
            .await;
        assert!(
            matches!(result, Ok(AuthOutcome::Success(_))),
            "correct password authenticates through the chain"
        );
    }
}
