//! Confirmable module - email confirmation with reconfirmable postponement (CNF-01..08).
//!
//! Mirrors `devise/lib/devise/models/confirmable.rb`: token generation with
//! digest-only storage, `confirm` with `confirm_within` expiry and
//! `after_confirmation` hook, `confirm_by_token` with blank guard and
//! raw-then-digest legacy lookup, reconfirmable email postponement with the
//! #5783 forced write, resend reuse, paranoid instruction requests, and the
//! `active_for_authentication` gate shape (confirmable before lockable).
//!
//! == Options
//!
//! * `allow_unconfirmed_access_for` - grace window before confirmation is
//!   required (default zero, so new accounts are blocked until confirmed)
//! * `confirm_within` - token validity window (default nil, so tokens never expire)
//! * `confirmation_keys` - attributes used for instruction lookup (default `[:email]`)
//! * `reconfirmable` - postpone email changes into `unconfirmed_email` (default true)
//!
//! == Examples
//!
//! ```ignore
//! let raw = user.ensure_confirmation_token(&adapter, &config, &clock).await?;
//! let outcome = TestUser::confirm_by_token(Some(&raw), &adapter, &config, &clock, &|_| ValidationErrors::new()).await?;
//! assert!(outcome.is_valid());
//! ```

use crate::adapter::{Conditions, OrmAdapter, Value};
use crate::config::DeviseConfig;
use crate::error::{DeviseError, ResourceWithErrors, ValidationErrors};
use crate::mailer::HasEmail;
use crate::model::Authenticatable;
use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use std::collections::HashMap;

/// Column bound into the HMAC key for confirmation tokens.
///
/// Matches Devise's `TokenGenerator` key context `"Devise #{column}"`.
pub const CONFIRMATION_TOKEN_COLUMN: &str = "confirmation_token";

/// Required model fields for Confirmable, mirroring Devise's
/// `Confirmable.required_fields`.
///
/// == Options
///
/// * `reconfirmable` - when true the `unconfirmed_email` column is required too
///
/// == Examples
///
/// ```ignore
/// assert_eq!(required_fields(false), vec!["confirmation_token", "confirmed_at", "confirmation_sent_at"]);
/// ```
#[must_use]
pub fn required_fields(reconfirmable: bool) -> Vec<&'static str> {
    let mut fields = vec!["confirmation_token", "confirmed_at", "confirmation_sent_at"];
    if reconfirmable {
        fields.push("unconfirmed_email");
    }
    fields
}

/// Render a `TimeDelta` window the way Devise's `TimeInflector` does for the
/// `confirmation_period_expired` message `%{period}` interpolation.
///
/// == Examples
///
/// ```
/// use devise_rust::confirmable::humanize_period;
///
/// assert_eq!(humanize_period(chrono::TimeDelta::days(3)), "3 days");
/// assert_eq!(humanize_period(chrono::TimeDelta::hours(1)), "1 hour");
/// ```
#[must_use]
pub fn humanize_period(delta: TimeDelta) -> String {
    let secs = delta.num_seconds();
    if secs >= SECONDS_PER_WEEK && secs % SECONDS_PER_WEEK == 0 {
        let count = secs / SECONDS_PER_WEEK;
        return format!("{count} week{}", plural_s(count));
    }
    if secs >= SECONDS_PER_DAY && secs % SECONDS_PER_DAY == 0 {
        let count = secs / SECONDS_PER_DAY;
        return format!("{count} day{}", plural_s(count));
    }
    if secs >= SECONDS_PER_HOUR && secs % SECONDS_PER_HOUR == 0 {
        let count = secs / SECONDS_PER_HOUR;
        return format!("{count} hour{}", plural_s(count));
    }
    if secs >= SECONDS_PER_MINUTE && secs % SECONDS_PER_MINUTE == 0 {
        let count = secs / SECONDS_PER_MINUTE;
        return format!("{count} minute{}", plural_s(count));
    }
    format!("{secs} second{}", plural_s(secs))
}

fn plural_s(count: i64) -> &'static str {
    if count == 1 { "" } else { "s" }
}

const SECONDS_PER_WEEK: i64 = 7 * 24 * 3600;
const SECONDS_PER_DAY: i64 = 24 * 3600;
const SECONDS_PER_HOUR: i64 = 3600;
const SECONDS_PER_MINUTE: i64 = 60;

/// `Confirmable` module - email confirmation over the four Devise columns.
///
/// The DB stores the HMAC digest of the token (keyed
/// `"Devise confirmation_token"`); the raw token travels only in e-mail links,
/// request params, and the transient in-memory accessor. Lookups try the raw
/// value first (legacy rows that still hold raw tokens), then the digest.
///
/// == Options
///
/// See the module-level docs: `allow_unconfirmed_access_for`,
/// `confirm_within`, `confirmation_keys`, `reconfirmable`.
///
/// == Examples
///
/// ```ignore
/// impl Confirmable for User {
///     fn confirmation_token(&self) -> Option<&str> { self.confirmation_token.as_deref() }
///     // ... column accessors ...
/// }
/// ```
#[async_trait]
pub trait Confirmable: Authenticatable + HasEmail {
    /// Stored `confirmation_token` column, always the HMAC digest, never raw.
    fn confirmation_token(&self) -> Option<&str>;
    /// Write the `confirmation_token` column.
    fn set_confirmation_token(&mut self, token: Option<String>);
    /// `confirmed_at` timestamp column.
    fn confirmed_at(&self) -> Option<DateTime<Utc>>;
    /// Write the `confirmed_at` column.
    fn set_confirmed_at(&mut self, at: Option<DateTime<Utc>>);
    /// `confirmation_sent_at` timestamp column.
    fn confirmation_sent_at(&self) -> Option<DateTime<Utc>>;
    /// Write the `confirmation_sent_at` column.
    fn set_confirmation_sent_at(&mut self, at: Option<DateTime<Utc>>);
    /// `unconfirmed_email` column (reconfirmable postponement target).
    fn unconfirmed_email(&self) -> Option<&str>;
    /// Write the `unconfirmed_email` column.
    fn set_unconfirmed_email(&mut self, email: Option<String>);
    /// Assign the primary email address (reconfirmation moves the confirmed
    /// address back into `email` through this setter).
    fn set_email_address(&mut self, email: String);

    /// Transient raw token, restored on the record after token creation or a
    /// successful `confirm_by_token`. Never persisted.
    fn raw_confirmation_token(&self) -> Option<&str> {
        None
    }
    /// Restore the transient raw token (memory only).
    fn set_raw_confirmation_token(&mut self, _raw: Option<String>) {}

    /// Whether the create-time notification is suppressed
    /// (Devise `skip_confirmation_notification!` flag state).
    fn confirmation_notification_skipped(&self) -> bool {
        false
    }
    /// Devise `skip_confirmation_notification!`: suppress the
    /// confirmation/reconfirmation notification while still requiring
    /// confirmation.
    fn skip_confirmation_notification(&mut self) {}

    /// Consume the one-shot reconfirmation bypass set by
    /// [`skip_reconfirmation`](Self::skip_reconfirmation). The flag resets on
    /// read, mirroring Devise's `@bypass_confirmation_postpone` reset inside
    /// `postpone_email_change?`.
    fn consume_reconfirmation_bypass(&mut self) -> bool {
        false
    }
    /// Devise `skip_reconfirmation!`: the next email change applies directly
    /// without postponement or token regeneration.
    fn skip_reconfirmation(&mut self) {}

    /// `after_confirmation` hook (CNF-02): documented no-op extension point,
    /// called after a successful confirm.
    fn after_confirmation(&self) {}

    /// `confirmed?`: the account completed confirmation.
    fn confirmed(&self) -> bool {
        self.confirmed_at().is_some()
    }

    /// `pending_reconfirmation?`: a reconfirmable model holds an unconfirmed
    /// replacement address.
    fn pending_reconfirmation(&self, config: &DeviseConfig) -> bool {
        config.reconfirmable
            && self
                .unconfirmed_email()
                .is_some_and(|email| !email.is_empty())
    }

    /// `confirmation_required?`: confirmation still gates this record.
    fn confirmation_required(&self) -> bool {
        !self.confirmed()
    }

    /// `confirmation_period_valid?` (CNF-03): the three-way allow-window table.
    /// Zero `allow_unconfirmed_access_for` (the Devise default) is never
    /// valid; otherwise the record is valid while `confirmation_sent_at` sits
    /// inside the window. A missing `confirmation_sent_at` is never valid.
    fn confirmation_period_valid(
        &self,
        config: &DeviseConfig,
        clock: &dyn crate::time::Clock,
    ) -> bool {
        if config.allow_unconfirmed_access_for.is_zero() {
            return false;
        }
        self.confirmation_sent_at()
            .is_some_and(|sent_at| sent_at >= clock.now() - config.allow_unconfirmed_access_for)
    }

    /// `confirmation_period_expired?` (CNF-02): true only when both
    /// `confirm_within` and `confirmation_sent_at` exist and now passed
    /// `sent_at + within`. The nil default (D-01) never expires.
    fn confirmation_period_expired(
        &self,
        config: &DeviseConfig,
        clock: &dyn crate::time::Clock,
    ) -> bool {
        match (config.confirm_within, self.confirmation_sent_at()) {
            (Some(within), Some(sent_at)) => clock.now() > sent_at + within,
            _ => false,
        }
    }

    /// Confirmable slice of `active_for_authentication?` (CNF-03): `base`
    /// carries the upstream chain result; this gate adds
    /// `!required || confirmed || period-valid`. Evaluate this gate before the
    /// lockable gate (canonical super-chain order).
    fn confirmation_gate_active(
        &self,
        base: bool,
        config: &DeviseConfig,
        clock: &dyn crate::time::Clock,
    ) -> bool {
        base && (!self.confirmation_required()
            || self.confirmed()
            || self.confirmation_period_valid(config, clock))
    }

    /// Confirmable slice of `inactive_message` (CNF-04): `Some("unconfirmed")`
    /// while unconfirmed, `None` to defer to the next gate in the chain.
    fn confirmation_inactive_message(&self) -> Option<&'static str> {
        if self.confirmed() {
            None
        } else {
            Some("unconfirmed")
        }
    }

    /// Ensure a confirmation token exists, reusing the live one (D-07).
    ///
    /// When a stored token exists and is not expired, the stored digest is
    /// reused as the bearer without touching `confirmation_sent_at`, so the
    /// `confirm_within` window is preserved. Otherwise a fresh raw-plus-digest
    /// pair is generated (uniqueness looped through
    /// [`column_value_unused`](crate::adapter::OrmAdapter::column_value_unused))
    /// and persisted via `update_columns`. Returns the bearer token: the fresh
    /// raw value, or the reused stored digest (accepted by the raw-first
    /// lookup path).
    ///
    /// # Errors
    ///
    /// `DeviseError::Adapter` when the uniqueness probe or persistence fails.
    async fn ensure_confirmation_token<A>(
        &mut self,
        adapter: &A,
        config: &DeviseConfig,
        clock: &dyn crate::time::Clock,
    ) -> Result<String, DeviseError>
    where
        Self: Sized,
        A: OrmAdapter<Self> + Send + Sync,
    {
        if let Some(stored) = self.confirmation_token().map(str::to_string) {
            if !stored.is_empty() && !self.confirmation_period_expired(config, clock) {
                self.set_raw_confirmation_token(Some(stored.clone()));
                return Ok(stored);
            }
        }
        let (raw, enc) = loop {
            let (raw, enc) = crate::crypto::token_generator::generate(
                &config.secret_key,
                CONFIRMATION_TOKEN_COLUMN,
            );
            if adapter
                .column_value_unused(CONFIRMATION_TOKEN_COLUMN, &Value::String(enc.clone()))
                .await
                .map_err(DeviseError::Adapter)?
            {
                break (raw, enc);
            }
        };
        let now = clock.now();
        self.set_confirmation_token(Some(enc.clone()));
        self.set_confirmation_sent_at(Some(now));
        self.set_raw_confirmation_token(Some(raw.clone()));
        let fields = HashMap::from([
            ("confirmation_token".to_string(), Value::String(enc)),
            (
                "confirmation_sent_at".to_string(),
                Value::String(now.to_rfc3339()),
            ),
        ]);
        adapter
            .update_columns(&self.to_key(), &fields)
            .await
            .map_err(DeviseError::Adapter)?;
        Ok(raw)
    }

    /// `confirm` (CNF-02): set `confirmed_at`, move a pending reconfirmation
    /// address back into `email`, persist, and fire `after_confirmation`.
    ///
    /// Already-confirmed records (with no pending reconfirmation) fail with an
    /// `:already_confirmed`-style error (D-06). Expired tokens fail with
    /// `:confirmation_period_expired` (rendered with the `%{period}`
    /// interpolation from [`humanize_period`]). Reconfirmation always runs the
    /// caller-supplied `validate` closure (D-04); plain confirms honor
    /// `ensure_valid`. Nothing persists on validation failure.
    ///
    /// # Errors
    ///
    /// Outer `DeviseError::Adapter` on persistence failure. Inner
    /// `Err(ValidationErrors)`: Devise's `false` plus populated `errors`.
    async fn confirm<A>(
        &mut self,
        adapter: &A,
        config: &DeviseConfig,
        clock: &dyn crate::time::Clock,
        ensure_valid: bool,
        validate: &(dyn for<'r> Fn(&'r Self) -> ValidationErrors + Send + Sync),
    ) -> Result<Result<(), ValidationErrors>, DeviseError>
    where
        Self: Sized,
        A: OrmAdapter<Self> + Send + Sync,
    {
        if self.confirmed() && !self.pending_reconfirmation(config) {
            let mut errors = ValidationErrors::new();
            errors.add("email", ":already_confirmed");
            return Ok(Err(errors));
        }
        if self.confirmation_period_expired(config, clock) {
            let mut errors = ValidationErrors::new();
            errors.add("email", ":confirmation_period_expired");
            return Ok(Err(errors));
        }
        let now = clock.now();
        self.set_confirmed_at(Some(now));
        if self.pending_reconfirmation(config) {
            let pending = self.unconfirmed_email().unwrap_or_default().to_string();
            self.set_email_address(pending);
            self.set_unconfirmed_email(None);
            let errors = validate(self);
            if !errors.is_empty() {
                return Ok(Err(errors));
            }
            let fields = HashMap::from([
                ("confirmed_at".to_string(), Value::String(now.to_rfc3339())),
                ("email".to_string(), Value::String(self.email().to_string())),
                ("unconfirmed_email".to_string(), Value::Null),
            ]);
            adapter
                .update_columns(&self.to_key(), &fields)
                .await
                .map_err(DeviseError::Adapter)?;
            self.after_confirmation();
            return Ok(Ok(()));
        }
        if ensure_valid {
            let errors = validate(self);
            if !errors.is_empty() {
                return Ok(Err(errors));
            }
        }
        let fields = HashMap::from([("confirmed_at".to_string(), Value::String(now.to_rfc3339()))]);
        adapter
            .update_columns(&self.to_key(), &fields)
            .await
            .map_err(DeviseError::Adapter)?;
        self.after_confirmation();
        Ok(Ok(()))
    }

    /// `confirm_by_token` (CNF-06): blank tokens fail with `:blank` on a fresh
    /// record without touching the adapter (T-05-01); otherwise the raw value
    /// is looked up first (legacy rows), then the HMAC digest (digest-only
    /// rows). A persisted match is confirmed with `ensure_valid` off
    /// (reconfirmation still validates); the input token is restored on the
    /// returned record.
    ///
    /// # Errors
    ///
    /// `DeviseError::Adapter` on lookup or persistence failure.
    async fn confirm_by_token<A>(
        token: Option<&str>,
        adapter: &A,
        config: &DeviseConfig,
        clock: &dyn crate::time::Clock,
        validate: &(dyn for<'r> Fn(&'r Self) -> ValidationErrors + Send + Sync),
    ) -> Result<ResourceWithErrors<Self>, DeviseError>
    where
        Self: Sized + Default,
        A: OrmAdapter<Self> + Send + Sync,
    {
        let raw = token.map(str::trim).filter(|text| !text.is_empty());
        let Some(raw) = raw else {
            let mut errors = ValidationErrors::new();
            errors.add("confirmation_token", ":blank");
            return Ok(ResourceWithErrors::new(Self::default(), errors));
        };
        let mut conditions = Conditions::new();
        conditions.insert(CONFIRMATION_TOKEN_COLUMN, Value::String(raw.to_string()));
        let found = adapter
            .find_first(&conditions)
            .await
            .map_err(DeviseError::Adapter)?;
        let mut record = if let Some(record) = found {
            record
        } else {
            let digest = crate::crypto::token_generator::digest(
                &config.secret_key,
                CONFIRMATION_TOKEN_COLUMN,
                raw,
            );
            let mut digest_conditions = Conditions::new();
            digest_conditions.insert(CONFIRMATION_TOKEN_COLUMN, Value::String(digest));
            if let Some(record) = adapter
                .find_first(&digest_conditions)
                .await
                .map_err(DeviseError::Adapter)?
            {
                record
            } else {
                let mut errors = ValidationErrors::new();
                errors.add("confirmation_token", ":invalid");
                return Ok(ResourceWithErrors::new(Self::default(), errors));
            }
        };
        record.set_raw_confirmation_token(Some(raw.to_string()));
        match record
            .confirm(adapter, config, clock, false, validate)
            .await?
        {
            Ok(()) => Ok(ResourceWithErrors::new(record, ValidationErrors::new())),
            Err(errors) => Ok(ResourceWithErrors::new(record, errors)),
        }
    }
}

/// `confirmation_period_valid?` with an explicit allow window (CNF-03).
///
/// A missing window (`None`, Devise `nil`) is always valid; a zero window is
/// never valid (D-02); otherwise `sent_at` must sit inside the window. A
/// missing `sent_at` is never valid. `DeviseConfig` stores the zero default,
/// so config-driven callers use
/// [`Confirmable::confirmation_period_valid`]; this free function covers the
/// nil case for direct tests and per-scope overrides.
///
/// == Examples
///
/// ```
/// use devise_rust::confirmable::confirmation_period_valid_with_allow;
/// use devise_rust::time::FixedClock;
///
/// let clock = FixedClock::now();
/// assert!(confirmation_period_valid_with_allow(None, None, &clock));
/// assert!(!confirmation_period_valid_with_allow(None, Some(chrono::TimeDelta::zero()), &clock));
/// ```
#[must_use]
pub fn confirmation_period_valid_with_allow(
    sent_at: Option<DateTime<Utc>>,
    allow: Option<TimeDelta>,
    clock: &dyn crate::time::Clock,
) -> bool {
    let Some(allow) = allow else {
        return true;
    };
    if allow.is_zero() {
        return false;
    }
    sent_at.is_some_and(|sent| sent >= clock.now() - allow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::memory::MemoryAdapter;
    use crate::config::DeviseConfig;
    use crate::failure::AnyDeviseModel;
    use crate::time::FixedClock;
    use serde::{Deserialize, Serialize};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    struct TestUser {
        id: i64,
        email: String,
        confirmation_token: Option<String>,
        confirmed_at: Option<DateTime<Utc>>,
        confirmation_sent_at: Option<DateTime<Utc>>,
        unconfirmed_email: Option<String>,
        #[serde(skip)]
        raw_confirmation_token: Option<String>,
        #[serde(skip)]
        skip_notification: bool,
        #[serde(skip)]
        bypass_postpone: bool,
        #[serde(skip)]
        after_confirmation_count: Arc<AtomicUsize>,
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
            let mut map = serde_json::json!({ "id": self.id, "email": self.email });
            if let Some(unconfirmed) = &self.unconfirmed_email {
                map["unconfirmed_email"] = serde_json::Value::String(unconfirmed.clone());
            }
            map
        }
    }

    #[async_trait]
    impl Confirmable for TestUser {
        fn confirmation_token(&self) -> Option<&str> {
            self.confirmation_token.as_deref()
        }

        fn set_confirmation_token(&mut self, token: Option<String>) {
            self.confirmation_token = token;
        }

        fn confirmed_at(&self) -> Option<DateTime<Utc>> {
            self.confirmed_at
        }

        fn set_confirmed_at(&mut self, at: Option<DateTime<Utc>>) {
            self.confirmed_at = at;
        }

        fn confirmation_sent_at(&self) -> Option<DateTime<Utc>> {
            self.confirmation_sent_at
        }

        fn set_confirmation_sent_at(&mut self, at: Option<DateTime<Utc>>) {
            self.confirmation_sent_at = at;
        }

        fn unconfirmed_email(&self) -> Option<&str> {
            self.unconfirmed_email.as_deref()
        }

        fn set_unconfirmed_email(&mut self, email: Option<String>) {
            self.unconfirmed_email = email;
        }

        fn set_email_address(&mut self, email: String) {
            self.email = email;
        }

        fn raw_confirmation_token(&self) -> Option<&str> {
            self.raw_confirmation_token.as_deref()
        }

        fn set_raw_confirmation_token(&mut self, raw: Option<String>) {
            self.raw_confirmation_token = raw;
        }

        fn confirmation_notification_skipped(&self) -> bool {
            self.skip_notification
        }

        fn skip_confirmation_notification(&mut self) {
            self.skip_notification = true;
        }

        fn consume_reconfirmation_bypass(&mut self) -> bool {
            std::mem::take(&mut self.bypass_postpone)
        }

        fn skip_reconfirmation(&mut self) {
            self.bypass_postpone = true;
        }

        fn after_confirmation(&self) {
            self.after_confirmation_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn test_config() -> DeviseConfig {
        DeviseConfig {
            secret_key: "test-secret-key".to_string(),
            ..DeviseConfig::default()
        }
    }

    fn valid(_user: &TestUser) -> ValidationErrors {
        ValidationErrors::new()
    }

    /// Adapter wrapper counting every call, proving the blank-token guard
    /// performs zero adapter calls (T-05-01).
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
    async fn confirmable_tracer_generate_then_confirm_by_token() {
        let config = test_config();
        let clock = FixedClock::now();
        let adapter = MemoryAdapter::<TestUser>::new();
        let mut user = TestUser::fresh(1, "tracer@example.com");
        adapter.create(user.clone()).await.unwrap();

        let raw = user
            .ensure_confirmation_token(&adapter, &config, &clock)
            .await
            .unwrap();
        assert_eq!(raw.len(), 20);

        let stored = user.confirmation_token().unwrap().to_string();
        assert_eq!(stored.len(), 64);
        assert_ne!(stored, raw);

        let outcome = TestUser::confirm_by_token(Some(&raw), &adapter, &config, &clock, &valid)
            .await
            .unwrap();
        assert!(outcome.is_valid());
        assert!(outcome.record.confirmed());
        assert!(outcome.record.confirmed_at().is_some());
        assert_eq!(
            outcome
                .record
                .after_confirmation_count
                .load(Ordering::SeqCst),
            1
        );
    }

    #[tokio::test]
    async fn confirmable_tracer_blank_token_touches_no_adapter() {
        let config = test_config();
        let clock = FixedClock::now();
        let inner = MemoryAdapter::<TestUser>::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let adapter = CountingAdapter {
            inner: &inner,
            calls: Arc::clone(&calls),
        };

        for blank in [None, Some(""), Some("   ")] {
            let outcome = TestUser::confirm_by_token(blank, &adapter, &config, &clock, &valid)
                .await
                .unwrap();
            assert!(!outcome.is_valid());
            assert_eq!(
                outcome.errors.get("confirmation_token"),
                Some(&vec![":blank".to_string()])
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
