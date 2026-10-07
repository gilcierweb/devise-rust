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
//! // Two failures then the locking failure (maximum_attempts = 3).
//! user.increment_failed_attempts(&adapter).await?;
//! user.increment_failed_attempts(&adapter).await?;
//! user.increment_failed_attempts(&adapter).await?;
//! user.lock_access(&adapter, &mailer, &config, &clock, true).await?;
//! assert!(user.access_locked(&config, &clock));
//! ```

use crate::adapter::{OrmAdapter, Value};
use crate::config::DeviseConfig;
use crate::error::DeviseError;
use crate::mailer::{HasEmail, Mailer, MailerContext};
use crate::model::Authenticatable;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// Column bound into the HMAC key for unlock tokens.
///
/// Matches Devise's `TokenGenerator` key context `"Devise #{column}"`.
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
/// assert!(unlock_strategy_enabled_for("time", &config));
/// ```
#[must_use]
pub fn unlock_strategy_enabled_for(strategy: &str, config: &DeviseConfig) -> bool {
    config.unlock_strategy == strategy
        || (config.unlock_strategy == "both" && BOTH_STRATEGIES.contains(&strategy))
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
/// impl Lockable for User {
///     fn failed_attempts(&self) -> u32 { self.failed_attempts }
///     // ... column accessors ...
/// }
/// ```
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::memory::MemoryAdapter;
    use crate::failure::AnyDeviseModel;
    use crate::mailer::TestMailer;
    use crate::time::FixedClock;
    use serde::{Deserialize, Serialize};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    struct TestUser {
        id: i64,
        email: String,
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

    impl AnyDeviseModel for TestUser {
        fn to_key(&self) -> crate::adapter::DeviseKey {
            crate::adapter::DeviseKey::from_i64(self.id)
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
}
