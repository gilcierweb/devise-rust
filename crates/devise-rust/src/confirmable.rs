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
//! // Ignored doctest: requires a live adapter and an async runtime; the compiled equivalent lives in the crate tests and the example apps.
//! let raw = user.ensure_confirmation_token(&adapter, &config, &clock).await?;
//! let outcome = TestUser::confirm_by_token(Some(&raw), &adapter, &config, &clock, &|_| ValidationErrors::new()).await?;
//! assert!(outcome.is_valid());
//! ```

use crate::adapter::{Conditions, OrmAdapter, Value};
use crate::config::DeviseConfig;
use crate::error::{DeviseError, ResourceWithErrors, ValidationErrors};
use crate::mailer::{HasEmail, Mailer, MailerContext};
use crate::model::Authenticatable;
use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use std::collections::HashMap;

/// Column bound into the HMAC key for confirmation tokens.
///
/// Matches Devise's `TokenGenerator` key context `"Devise #{column}"`.
///
/// Mirrors Devise's `TokenGenerator` key context for the `confirmation_token` column: the literal string "Devise {column}".
pub const CONFIRMATION_TOKEN_COLUMN: &str = "confirmation_token";

/// Required model fields for Confirmable, mirroring Devise's
/// `Confirmable.required_fields`.
///
/// == Options
///
/// * `reconfirmable` - when true the `unconfirmed_email` column joins the
///   required set (Devise checks `klass.reconfirmable` the same way)
///
/// == Examples
///
/// ```
/// use devise_rust::confirmable::required_fields;
///
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
///
/// Mirrors `Devise::TimeInflector.time_ago_in_words` as used by the `confirmation_period_expired` message interpolation.
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
/// // Ignored doctest: requires a live adapter and an async runtime; the compiled equivalent lives in the crate tests and the example apps.
/// impl Confirmable for User {
///     fn confirmation_token(&self) -> Option<&str> { self.confirmation_token.as_deref() }
///     // ... column accessors ...
/// }
/// ```
///
/// Mirrors `Devise::Models::Confirmable` (`devise/lib/devise/models/confirmable.rb`) as the trait surface: token generation, confirm, `confirm_by_token`, reconfirmable postponement, and resend reuse.
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
        match config.allow_unconfirmed_access_for {
            // Devise `allow_unconfirmed_access_for: nil` = unconfirmed access
            // never expires.
            None => true,
            Some(window) if window.is_zero() => false,
            Some(window) => self
                .confirmation_sent_at()
                .is_some_and(|sent_at| sent_at >= clock.now() - window),
        }
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

    /// Generate a fresh raw-plus-digest pair, persist the digest plus
    /// `sent_at` via `update_columns`, and return the raw bearer.
    ///
    /// Uniqueness loops through
    /// [`column_value_unused`](crate::adapter::OrmAdapter::column_value_unused).
    ///
    /// # Errors
    ///
    /// `DeviseError::Adapter` when the uniqueness probe or persistence fails.
    async fn store_fresh_confirmation_token<A>(
        &mut self,
        adapter: &A,
        config: &DeviseConfig,
        clock: &dyn crate::time::Clock,
    ) -> Result<String, DeviseError>
    where
        Self: Sized,
        A: OrmAdapter<Self> + Send + Sync,
    {
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
        self.store_fresh_confirmation_token(adapter, config, clock)
            .await
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

    /// `skip_confirmation!` (CNF-05): mark confirmed in memory without saving.
    /// No token is generated and no notification decision is made; the caller
    /// persists when it saves the record.
    fn skip_confirmation(&mut self, clock: &dyn crate::time::Clock) {
        self.set_confirmed_at(Some(clock.now()));
    }

    /// Whether the create-time confirmation notification goes out (CNF-01):
    /// confirmation required, not suppressed, and an address exists.
    fn should_send_confirmation_notification(&self) -> bool {
        self.confirmation_required()
            && !self.confirmation_notification_skipped()
            && !self.email().is_empty()
    }

    /// Send confirmation instructions for this record (CNF-01 worker).
    ///
    /// Ensures a token (reusing the live one per D-07), then mails
    /// `confirmation_instructions` carrying the bearer to the pending
    /// `unconfirmed_email` when reconfirming, else to `email` (D-05).
    /// Returns the bearer token.
    ///
    /// # Errors
    ///
    /// `DeviseError::Adapter` on token persistence failure,
    /// `DeviseError::Mailer` when the notification cannot render.
    async fn send_confirmation_instructions<A, L>(
        &mut self,
        adapter: &A,
        mailer: &L,
        config: &DeviseConfig,
        clock: &dyn crate::time::Clock,
    ) -> Result<String, DeviseError>
    where
        Self: Sized,
        A: OrmAdapter<Self> + Send + Sync,
        L: Mailer<Self>,
    {
        let raw = self
            .ensure_confirmation_token(adapter, config, clock)
            .await?;
        let recipient = if self.pending_reconfirmation(config) {
            self.unconfirmed_email().unwrap_or_default().to_string()
        } else {
            self.email().to_string()
        };
        let context = MailerContext {
            email: recipient,
            token: Some(raw.clone()),
            url: None,
            resource: self.serializable_hash(),
        };
        mailer.confirmation_instructions(self, Some(&raw), &context)?;
        Ok(raw)
    }

    /// `resend_confirmation_instructions` (CNF-05, CNF-06): guarded resend.
    /// Already-confirmed records (with no pending reconfirmation) fail with an
    /// `:already_confirmed`-style error instead of pretending to send (D-06).
    ///
    /// # Errors
    ///
    /// Outer `DeviseError` on token/mailer failure. Inner
    /// `Err(ValidationErrors)` for the already-confirmed notice.
    async fn resend_confirmation_instructions<A, L>(
        &mut self,
        adapter: &A,
        mailer: &L,
        config: &DeviseConfig,
        clock: &dyn crate::time::Clock,
    ) -> Result<Result<String, ValidationErrors>, DeviseError>
    where
        Self: Sized,
        A: OrmAdapter<Self> + Send + Sync,
        L: Mailer<Self>,
    {
        if self.confirmed() && !self.pending_reconfirmation(config) {
            let mut errors = ValidationErrors::new();
            errors.add("email", ":already_confirmed");
            return Ok(Err(errors));
        }
        Ok(Ok(self
            .send_confirmation_instructions(adapter, mailer, config, clock)
            .await?))
    }

    /// Create-time notification decision (CNF-01): send only when
    /// [`should_send_confirmation_notification`](Self::should_send_confirmation_notification).
    /// Returns the bearer when sent, `None` when suppressed.
    ///
    /// # Errors
    ///
    /// `DeviseError::Adapter` on token persistence failure,
    /// `DeviseError::Mailer` when the notification cannot render.
    async fn send_on_create_confirmation_instructions<A, L>(
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
        if !self.should_send_confirmation_notification() {
            return Ok(None);
        }
        Ok(Some(
            self.send_confirmation_instructions(adapter, mailer, config, clock)
                .await?,
        ))
    }

    /// Request an email change on a reconfirmable record (CNF-07, D-03, D-05).
    ///
    /// Moves the new address into `unconfirmed_email`, keeps `email` at the
    /// original, clears the token, and stores a fresh raw-plus-digest pair.
    /// The postponement persists through `update_columns` with an explicit
    /// field map, so the write lands even when the submitted value equals the
    /// stored `unconfirmed_email` (the #5783 race fix; this path is never gated
    /// on change detection). A submission equal to the current `email` is a
    /// no-op (the explicit-API equivalent of Devise's
    /// `devise_will_save_change_to_email?` guard).
    ///
    /// Notifications follow D-05: `email_changed` goes to the ORIGINAL address
    /// when `send_email_changed_notification` is set, and
    /// `confirmation_instructions` carrying the raw token goes to the NEW
    /// address. With `reconfirmable` off, a consumed `skip_reconfirmation`,
    /// or a blank address, the address applies directly with no token or mail.
    /// Returns the raw token when postponed, `None` otherwise.
    ///
    /// # Errors
    ///
    /// `DeviseError::Adapter` on persistence failure, `DeviseError::Mailer`
    /// when a notification cannot render.
    async fn change_email_with_reconfirmation<A, L>(
        &mut self,
        new_email: &str,
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
        if new_email.is_empty() || new_email == self.email() {
            return Ok(None);
        }
        if !config.reconfirmable || self.consume_reconfirmation_bypass() {
            self.set_email_address(new_email.to_string());
            let fields =
                HashMap::from([("email".to_string(), Value::String(new_email.to_string()))]);
            adapter
                .update_columns(&self.to_key(), &fields)
                .await
                .map_err(DeviseError::Adapter)?;
            return Ok(None);
        }
        let original = self.email().to_string();
        self.set_confirmation_token(None);
        self.set_unconfirmed_email(Some(new_email.to_string()));
        let raw = self
            .store_fresh_confirmation_token(adapter, config, clock)
            .await?;
        let fields = HashMap::from([
            (
                "unconfirmed_email".to_string(),
                Value::String(new_email.to_string()),
            ),
            ("email".to_string(), Value::String(original.clone())),
            (
                "confirmation_token".to_string(),
                Value::String(self.confirmation_token().unwrap_or_default().to_string()),
            ),
            (
                "confirmation_sent_at".to_string(),
                Value::String(
                    self.confirmation_sent_at()
                        .map(|sent| sent.to_rfc3339())
                        .unwrap_or_default(),
                ),
            ),
        ]);
        adapter
            .update_columns(&self.to_key(), &fields)
            .await
            .map_err(DeviseError::Adapter)?;
        if config.send_email_changed_notification {
            let context = MailerContext {
                email: original,
                token: None,
                url: None,
                resource: self.serializable_hash(),
            };
            mailer.email_changed(self, None, &context)?;
        }
        let context = MailerContext {
            email: new_email.to_string(),
            token: Some(raw.clone()),
            url: None,
            resource: self.serializable_hash(),
        };
        mailer.confirmation_instructions(self, Some(&raw), &context)?;
        Ok(Some(raw))
    }

    /// Class `send_confirmation_instructions` (CNF-08, D-08).
    ///
    /// With `reconfirmable` on, an `unconfirmed_email` match wins first (so a
    /// pending address resolves to its record); otherwise the lookup falls
    /// back to `find_or_initialize_with_errors` over `confirmation_keys`.
    /// Unknown addresses fail with `:not_found`, except in paranoid mode,
    /// which returns uniform success with nothing sent. Persisted matches are
    /// resent (already-confirmed accounts surface the `:already_confirmed`
    /// notice through the returned errors).
    ///
    /// # Errors
    ///
    /// `DeviseError::Adapter` on lookup or persistence failure,
    /// `DeviseError::Mailer` when the notification cannot render.
    async fn send_confirmation_instructions_for<A, L>(
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
        if config.reconfirmable {
            let unconfirmed =
                Self::find_by_unconfirmed_email_with_errors(attributes, adapter, config).await;
            if unconfirmed.is_valid() {
                let mut record = unconfirmed.record;
                return match record
                    .resend_confirmation_instructions(adapter, mailer, config, clock)
                    .await?
                {
                    Ok(_) => Ok(ResourceWithErrors::new(record, ValidationErrors::new())),
                    Err(errors) => Ok(ResourceWithErrors::new(record, errors)),
                };
            }
        }
        let keys: Vec<&str> = config
            .confirmation_keys
            .iter()
            .map(String::as_str)
            .collect();
        let mut conditions = Conditions::new();
        for key in &keys {
            if let Some(value) = attributes.get(*key).and_then(|value| value.as_str()) {
                conditions.insert((*key).to_string(), Value::String(value.to_string()));
            }
        }
        let mut resource = if conditions.iter().next().is_none() {
            let mut errors = ValidationErrors::new();
            for key in &keys {
                errors.add(key, ":not_found");
            }
            ResourceWithErrors::new(Self::default(), errors)
        } else {
            Self::find_or_initialize_with_errors(&keys, &conditions, ":not_found", adapter, config)
                .await
        };
        if !resource.is_valid() {
            if config.paranoid {
                return Ok(ResourceWithErrors::new(
                    Self::default(),
                    ValidationErrors::new(),
                ));
            }
            return Ok(resource);
        }
        match resource
            .record
            .resend_confirmation_instructions(adapter, mailer, config, clock)
            .await?
        {
            Ok(_) => Ok(resource),
            Err(errors) => Ok(ResourceWithErrors::new(resource.record, errors)),
        }
    }

    /// Find by the pending address for reconfirmable instruction requests
    /// (CNF-08): `confirmation_keys` remapped from `email` to
    /// `unconfirmed_email`, miss yields `:not_found` on a blank record.
    async fn find_by_unconfirmed_email_with_errors<A>(
        attributes: &serde_json::Map<String, serde_json::Value>,
        adapter: &A,
        config: &DeviseConfig,
    ) -> ResourceWithErrors<Self>
    where
        Self: Sized + Default,
        A: OrmAdapter<Self> + Send + Sync,
    {
        let remapped_keys: Vec<String> = config
            .confirmation_keys
            .iter()
            .map(|key| {
                if key == "email" {
                    "unconfirmed_email".to_string()
                } else {
                    key.clone()
                }
            })
            .collect();
        let key_refs: Vec<&str> = remapped_keys.iter().map(String::as_str).collect();
        let mut conditions = Conditions::new();
        for (key, remapped) in config.confirmation_keys.iter().zip(remapped_keys.iter()) {
            if let Some(value) = attributes.get(key).and_then(|value| value.as_str()) {
                conditions.insert(remapped.clone(), Value::String(value.to_string()));
            }
        }
        if conditions.iter().next().is_none() {
            let mut errors = ValidationErrors::new();
            for key in &key_refs {
                errors.add(key, ":not_found");
            }
            return ResourceWithErrors::new(Self::default(), errors);
        }
        Self::find_or_initialize_with_errors(&key_refs, &conditions, ":not_found", adapter, config)
            .await
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
///
/// Mirrors `confirmation_period_valid?` with the `allow_unconfirmed_access_for` window passed explicitly (nil means unconfirmed access is never allowed past the grace window).
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
    use crate::time::{Clock, FixedClock};
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

    async fn confirmed_user(
        adapter: &MemoryAdapter<TestUser>,
        config: &DeviseConfig,
        clock: &FixedClock,
        id: i64,
        email: &str,
    ) -> TestUser {
        let mut user = TestUser::fresh(id, email);
        adapter.create(user.clone()).await.unwrap();
        user.ensure_confirmation_token(adapter, config, clock)
            .await
            .unwrap();
        let outcome = TestUser::confirm_by_token(
            user.raw_confirmation_token(),
            adapter,
            config,
            clock,
            &valid,
        )
        .await
        .unwrap();
        assert!(outcome.is_valid());
        outcome.record
    }

    #[tokio::test]
    async fn confirmable_reconfirmation_postpones_with_d05_routing() {
        let mut config = test_config();
        config.send_email_changed_notification = true;
        let clock = FixedClock::now();
        let adapter = MemoryAdapter::<TestUser>::new();
        let mailer = crate::mailer::TestMailer::default();
        let mut user = confirmed_user(&adapter, &config, &clock, 1, "original@example.com").await;
        let old_digest = user.confirmation_token().unwrap().to_string();

        let raw = user
            .change_email_with_reconfirmation("new@example.com", &adapter, &mailer, &config, &clock)
            .await
            .unwrap()
            .expect("postponement returns the raw token");
        assert_eq!(raw.len(), 20);

        assert_eq!(user.email(), "original@example.com");
        assert_eq!(user.unconfirmed_email(), Some("new@example.com"));
        let rotated = user.confirmation_token().unwrap().to_string();
        assert_eq!(rotated.len(), 64);
        assert_ne!(rotated, old_digest);
        assert!(user.confirmed());

        let sent = mailer.sent_mails();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].to, "original@example.com");
        assert_eq!(sent[0].subject, "Email Changed");
        assert_eq!(sent[1].to, "new@example.com");
        assert_eq!(sent[1].subject, "Confirmation instructions");
        assert_eq!(sent[1].template_vars.token.as_deref(), Some(raw.as_str()));

        let outcome = TestUser::confirm_by_token(Some(&raw), &adapter, &config, &clock, &valid)
            .await
            .unwrap();
        assert!(outcome.is_valid());
        assert_eq!(outcome.record.email(), "new@example.com");
        assert_eq!(outcome.record.unconfirmed_email(), None);
    }

    #[tokio::test]
    async fn confirmable_5783_double_submit_keeps_victim_unconfirmed() {
        let config = test_config();
        let clock = FixedClock::now();
        let adapter = MemoryAdapter::<TestUser>::new();
        let mailer = crate::mailer::TestMailer::default();
        let mut user = confirmed_user(&adapter, &config, &clock, 1, "owner@example.com").await;

        let first = user
            .change_email_with_reconfirmation(
                "victim@example.com",
                &adapter,
                &mailer,
                &config,
                &clock,
            )
            .await
            .unwrap()
            .expect("first submit postpones");
        assert_ne!(user.email(), "victim@example.com");

        let second = user
            .change_email_with_reconfirmation(
                "victim@example.com",
                &adapter,
                &mailer,
                &config,
                &clock,
            )
            .await
            .unwrap()
            .expect("unchanged resubmit still force-writes");
        assert_ne!(user.email(), "victim@example.com");
        assert_eq!(user.unconfirmed_email(), Some("victim@example.com"));
        assert_ne!(first, second);

        let mut pending_conditions = Conditions::new();
        pending_conditions.insert(
            "unconfirmed_email",
            Value::String("victim@example.com".to_string()),
        );
        let stored = adapter.find_first(&pending_conditions).await.unwrap();
        assert!(stored.is_some());
    }

    #[tokio::test]
    async fn confirmable_resend_reuses_live_token_without_sent_at_bump() {
        let config = test_config();
        let clock = FixedClock::now();
        let adapter = MemoryAdapter::<TestUser>::new();
        let mailer = crate::mailer::TestMailer::default();
        let mut user = TestUser::fresh(1, "resend@example.com");
        adapter.create(user.clone()).await.unwrap();
        user.ensure_confirmation_token(&adapter, &config, &clock)
            .await
            .unwrap();
        let digest = user.confirmation_token().unwrap().to_string();
        let sent_at = user.confirmation_sent_at();

        let outcome = user
            .resend_confirmation_instructions(&adapter, &mailer, &config, &clock)
            .await
            .unwrap();
        assert!(outcome.is_ok());
        assert_eq!(user.confirmation_token(), Some(digest.as_str()));
        assert_eq!(user.confirmation_sent_at(), sent_at);
        assert_eq!(mailer.sent_mails().len(), 1);

        let bearer = outcome.unwrap();
        let confirm = TestUser::confirm_by_token(Some(&bearer), &adapter, &config, &clock, &valid)
            .await
            .unwrap();
        assert!(confirm.is_valid());
    }

    #[tokio::test]
    async fn confirmable_resend_rotates_expired_token_and_sent_at() {
        let mut config = test_config();
        config.confirm_within = Some(chrono::TimeDelta::days(3));
        let mut clock = FixedClock::now();
        let adapter = MemoryAdapter::<TestUser>::new();
        let mailer = crate::mailer::TestMailer::default();
        let mut user = TestUser::fresh(1, "expired@example.com");
        adapter.create(user.clone()).await.unwrap();
        user.ensure_confirmation_token(&adapter, &config, &clock)
            .await
            .unwrap();
        let old_digest = user.confirmation_token().unwrap().to_string();
        let old_sent_at = user.confirmation_sent_at();

        clock.advance(chrono::TimeDelta::days(4));
        let outcome = user
            .resend_confirmation_instructions(&adapter, &mailer, &config, &clock)
            .await
            .unwrap();
        assert!(outcome.is_ok());
        assert_ne!(user.confirmation_token().unwrap(), old_digest.as_str());
        assert_ne!(user.confirmation_sent_at(), old_sent_at);
        assert_eq!(user.confirmation_sent_at(), Some(clock.now()));
    }

    #[tokio::test]
    async fn confirmable_resend_on_confirmed_errors_already_confirmed() {
        let config = test_config();
        let clock = FixedClock::now();
        let adapter = MemoryAdapter::<TestUser>::new();
        let mailer = crate::mailer::TestMailer::default();
        let mut user = confirmed_user(&adapter, &config, &clock, 1, "done@example.com").await;

        let outcome = user
            .resend_confirmation_instructions(&adapter, &mailer, &config, &clock)
            .await
            .unwrap();
        let Err(errors) = outcome else {
            panic!("resend on a confirmed account must error");
        };
        assert_eq!(
            errors.get("email"),
            Some(&vec![":already_confirmed".to_string()])
        );
        assert!(mailer.sent_mails().is_empty());
    }

    #[tokio::test]
    async fn confirmable_skip_flags_suppress_without_confirming() {
        let config = test_config();
        let clock = FixedClock::now();
        let adapter = MemoryAdapter::<TestUser>::new();
        let mailer = crate::mailer::TestMailer::default();

        let mut skipped = TestUser::fresh(1, "skipped@example.com");
        skipped.skip_confirmation(&clock);
        assert!(skipped.confirmed());
        assert_eq!(skipped.confirmation_token(), None);

        let mut silenced = TestUser::fresh(2, "silenced@example.com");
        silenced.skip_confirmation_notification();
        let sent = silenced
            .send_on_create_confirmation_instructions(&adapter, &mailer, &config, &clock)
            .await
            .unwrap();
        assert_eq!(sent, None);
        assert!(!silenced.confirmed());
        assert_eq!(silenced.confirmation_token(), None);
        assert!(mailer.sent_mails().is_empty());

        let mut plain = TestUser::fresh(1, "plain@example.com");
        adapter.create(plain.clone()).await.unwrap();
        let sent = plain
            .send_on_create_confirmation_instructions(&adapter, &mailer, &config, &clock)
            .await
            .unwrap()
            .expect("create-time send returns the bearer");
        assert_eq!(sent.len(), 20);
        assert_eq!(mailer.sent_mails().len(), 1);
        assert_eq!(mailer.sent_mails()[0].to, "plain@example.com");

        let mut blank = TestUser::fresh(4, "");
        let sent = blank
            .send_on_create_confirmation_instructions(&adapter, &mailer, &config, &clock)
            .await
            .unwrap();
        assert_eq!(sent, None);
    }

    #[tokio::test]
    async fn confirmable_skip_reconfirmation_applies_email_directly() {
        let config = test_config();
        let clock = FixedClock::now();
        let adapter = MemoryAdapter::<TestUser>::new();
        let mailer = crate::mailer::TestMailer::default();
        let mut user = confirmed_user(&adapter, &config, &clock, 1, "before@example.com").await;
        user.skip_reconfirmation();

        let outcome = user
            .change_email_with_reconfirmation(
                "after@example.com",
                &adapter,
                &mailer,
                &config,
                &clock,
            )
            .await
            .unwrap();
        assert_eq!(outcome, None);
        assert_eq!(user.email(), "after@example.com");
        assert_eq!(user.unconfirmed_email(), None);
        assert!(mailer.sent_mails().is_empty());
    }

    #[tokio::test]
    async fn confirmable_class_send_finds_unconfirmed_first_and_paranoid_stays_silent() {
        let config = test_config();
        let clock = FixedClock::now();
        let adapter = MemoryAdapter::<TestUser>::new();
        let mailer = crate::mailer::TestMailer::default();
        let mut user = confirmed_user(&adapter, &config, &clock, 1, "holder@example.com").await;
        user.change_email_with_reconfirmation(
            "pending@example.com",
            &adapter,
            &mailer,
            &config,
            &clock,
        )
        .await
        .unwrap();
        assert_eq!(mailer.sent_mails().len(), 1);

        let mut params = serde_json::Map::new();
        params.insert(
            "email".to_string(),
            serde_json::Value::String("pending@example.com".to_string()),
        );
        let outcome = TestUser::send_confirmation_instructions_for(
            &params, &adapter, &mailer, &config, &clock,
        )
        .await
        .unwrap();
        assert!(outcome.is_valid());
        assert_eq!(outcome.record.id, 1);
        assert_eq!(mailer.sent_mails().len(), 2);
        assert_eq!(mailer.sent_mails()[1].to, "pending@example.com");

        let mut unknown = serde_json::Map::new();
        unknown.insert(
            "email".to_string(),
            serde_json::Value::String("ghost@example.com".to_string()),
        );
        let outcome = TestUser::send_confirmation_instructions_for(
            &unknown, &adapter, &mailer, &config, &clock,
        )
        .await
        .unwrap();
        assert!(!outcome.is_valid());
        assert_eq!(
            outcome.errors.get("email"),
            Some(&vec![":not_found".to_string()])
        );
        assert_eq!(mailer.sent_mails().len(), 2);

        let mut paranoid = test_config();
        paranoid.paranoid = true;
        let outcome = TestUser::send_confirmation_instructions_for(
            &unknown, &adapter, &mailer, &paranoid, &clock,
        )
        .await
        .unwrap();
        assert!(outcome.is_valid());
        assert_eq!(mailer.sent_mails().len(), 2);
    }

    #[tokio::test]
    async fn confirmable_confirm_within_none_never_expires() {
        let config = test_config();
        assert_eq!(config.confirm_within, None);
        let mut clock = FixedClock::now();
        let adapter = MemoryAdapter::<TestUser>::new();
        let mut user = TestUser::fresh(1, "ancient@example.com");
        adapter.create(user.clone()).await.unwrap();
        let raw = user
            .ensure_confirmation_token(&adapter, &config, &clock)
            .await
            .unwrap();

        clock.advance(chrono::TimeDelta::days(5 * 365));
        assert!(!user.confirmation_period_expired(&config, &clock));
        let outcome = TestUser::confirm_by_token(Some(&raw), &adapter, &config, &clock, &valid)
            .await
            .unwrap();
        assert!(outcome.is_valid());
        assert!(outcome.record.confirmed());
    }

    #[tokio::test]
    async fn confirmable_confirm_within_window_edges() {
        let mut config = test_config();
        config.confirm_within = Some(chrono::TimeDelta::days(3));
        let adapter = MemoryAdapter::<TestUser>::new();

        let mut early_clock = FixedClock::now();
        let mut fresh = TestUser::fresh(1, "early@example.com");
        adapter.create(fresh.clone()).await.unwrap();
        let raw = fresh
            .ensure_confirmation_token(&adapter, &config, &early_clock)
            .await
            .unwrap();
        early_clock.advance(chrono::TimeDelta::days(2));
        assert!(!fresh.confirmation_period_expired(&config, &early_clock));
        let outcome =
            TestUser::confirm_by_token(Some(&raw), &adapter, &config, &early_clock, &valid)
                .await
                .unwrap();
        assert!(outcome.is_valid());

        let mut late_clock = FixedClock::now();
        let mut stale = TestUser::fresh(2, "stale@example.com");
        adapter.create(stale.clone()).await.unwrap();
        let stale_raw = stale
            .ensure_confirmation_token(&adapter, &config, &late_clock)
            .await
            .unwrap();
        late_clock.advance(chrono::TimeDelta::days(4));
        assert!(stale.confirmation_period_expired(&config, &late_clock));
        let outcome =
            TestUser::confirm_by_token(Some(&stale_raw), &adapter, &config, &late_clock, &valid)
                .await
                .unwrap();
        assert!(!outcome.is_valid());
        assert_eq!(
            outcome.errors.get("email"),
            Some(&vec![":confirmation_period_expired".to_string()])
        );
        assert_eq!(humanize_period(config.confirm_within.unwrap()), "3 days");
    }

    #[tokio::test]
    async fn confirmable_allow_window_three_way_table() {
        let clock = FixedClock::now();
        let zero_config = test_config();
        assert_eq!(
            zero_config.allow_unconfirmed_access_for,
            Some(chrono::TimeDelta::zero())
        );

        // Devise's nil = unconfirmed access never expires (the third arm).
        let mut nil_config = test_config();
        nil_config.allow_unconfirmed_access_for = None;

        let mut pending = TestUser::fresh(1, "pending@example.com");
        pending.set_confirmation_sent_at(Some(clock.now()));
        // Devise's nil = unconfirmed access never expires (the third arm).
        assert!(
            pending.confirmation_period_valid(&nil_config, &clock),
            "nil allow_unconfirmed_access_for never expires"
        );
        assert!(pending.confirmation_gate_active(true, &nil_config, &clock));
        assert!(!pending.confirmation_period_valid(&zero_config, &clock));
        assert!(!pending.confirmation_gate_active(true, &zero_config, &clock));
        assert_eq!(pending.confirmation_inactive_message(), Some("unconfirmed"));

        let mut windowed = test_config();
        windowed.allow_unconfirmed_access_for = Some(chrono::TimeDelta::days(5));
        let mut inside = TestUser::fresh(2, "inside@example.com");
        inside.set_confirmation_sent_at(Some(clock.now() - chrono::TimeDelta::days(4)));
        assert!(inside.confirmation_period_valid(&windowed, &clock));
        assert!(inside.confirmation_gate_active(true, &windowed, &clock));

        let mut outside = TestUser::fresh(3, "outside@example.com");
        outside.set_confirmation_sent_at(Some(clock.now() - chrono::TimeDelta::days(6)));
        assert!(!outside.confirmation_period_valid(&windowed, &clock));
        assert!(!outside.confirmation_gate_active(true, &windowed, &clock));

        assert!(confirmation_period_valid_with_allow(
            Some(clock.now() - chrono::TimeDelta::days(400)),
            None,
            &clock
        ));

        let mut done = TestUser::fresh(4, "done@example.com");
        done.set_confirmed_at(Some(clock.now()));
        assert!(done.confirmation_gate_active(true, &zero_config, &clock));
        assert_eq!(done.confirmation_inactive_message(), None);
        assert!(!done.confirmation_required());
    }

    #[tokio::test]
    async fn confirmable_blank_rows_never_confirm() {
        let config = test_config();
        let clock = FixedClock::now();
        let adapter = MemoryAdapter::<TestUser>::new();

        let mut empty_token = TestUser::fresh(1, "empty@example.com");
        empty_token.set_confirmation_token(Some(String::new()));
        adapter.create(empty_token.clone()).await.unwrap();
        let mut nil_token = TestUser::fresh(2, "nil@example.com");
        nil_token.set_confirmation_token(None);
        adapter.create(nil_token.clone()).await.unwrap();

        for blank in [None, Some("")] {
            let outcome = TestUser::confirm_by_token(blank, &adapter, &config, &clock, &valid)
                .await
                .unwrap();
            assert!(!outcome.is_valid());
            assert_eq!(
                outcome.errors.get("confirmation_token"),
                Some(&vec![":blank".to_string()])
            );
        }

        let stored_empty = adapter
            .get(&crate::adapter::DeviseKey::from_i64(1))
            .await
            .unwrap()
            .unwrap();
        assert!(!stored_empty.confirmed());
        let stored_nil = adapter
            .get(&crate::adapter::DeviseKey::from_i64(2))
            .await
            .unwrap()
            .unwrap();
        assert!(!stored_nil.confirmed());
    }

    #[tokio::test]
    async fn confirmable_digest_legacy_row_confirms_through_raw_lookup() {
        let config = test_config();
        let clock = FixedClock::now();
        let adapter = MemoryAdapter::<TestUser>::new();

        let legacy_raw = "legacyrawtoken123456";
        assert_eq!(legacy_raw.len(), 20);
        let mut legacy = TestUser::fresh(1, "legacy@example.com");
        legacy.set_confirmation_token(Some(legacy_raw.to_string()));
        legacy.set_confirmation_sent_at(Some(clock.now()));
        adapter.create(legacy.clone()).await.unwrap();

        let outcome =
            TestUser::confirm_by_token(Some(legacy_raw), &adapter, &config, &clock, &valid)
                .await
                .unwrap();
        assert!(outcome.is_valid());
        assert!(outcome.record.confirmed());
    }

    #[tokio::test]
    async fn confirmable_double_confirm_errors_without_refiring_hook() {
        let config = test_config();
        let clock = FixedClock::now();
        let adapter = MemoryAdapter::<TestUser>::new();
        let mut user = TestUser::fresh(1, "twice@example.com");
        adapter.create(user.clone()).await.unwrap();
        user.ensure_confirmation_token(&adapter, &config, &clock)
            .await
            .unwrap();

        let first = user
            .confirm(&adapter, &config, &clock, false, &valid)
            .await
            .unwrap();
        assert!(first.is_ok());
        assert_eq!(user.after_confirmation_count.load(Ordering::SeqCst), 1);

        let second = user
            .confirm(&adapter, &config, &clock, false, &valid)
            .await
            .unwrap();
        let Err(errors) = second else {
            panic!("double confirm must error");
        };
        assert_eq!(
            errors.get("email"),
            Some(&vec![":already_confirmed".to_string()])
        );
        assert_eq!(user.after_confirmation_count.load(Ordering::SeqCst), 1);

        let raw = user.raw_confirmation_token().unwrap().to_string();
        let replay = TestUser::confirm_by_token(Some(&raw), &adapter, &config, &clock, &valid)
            .await
            .unwrap();
        assert!(!replay.is_valid());
        assert_eq!(
            replay.errors.get("email"),
            Some(&vec![":already_confirmed".to_string()])
        );
    }

    #[tokio::test]
    async fn confirmable_reconfirmation_always_validates() {
        let config = test_config();
        let clock = FixedClock::now();
        let adapter = MemoryAdapter::<TestUser>::new();
        let mailer = crate::mailer::TestMailer::default();
        let invalid = |_user: &TestUser| {
            let mut errors = ValidationErrors::new();
            errors.add("email", ":invalid");
            errors
        };

        let mut lax = TestUser::fresh(1, "lenient@example.com");
        adapter.create(lax.clone()).await.unwrap();
        lax.ensure_confirmation_token(&adapter, &config, &clock)
            .await
            .unwrap();
        let lax_outcome = lax
            .confirm(&adapter, &config, &clock, false, &invalid)
            .await
            .unwrap();
        assert!(lax_outcome.is_ok());

        let mut strict = TestUser::fresh(2, "strict@example.com");
        adapter.create(strict.clone()).await.unwrap();
        strict
            .ensure_confirmation_token(&adapter, &config, &clock)
            .await
            .unwrap();
        let strict_outcome = strict
            .confirm(&adapter, &config, &clock, true, &invalid)
            .await
            .unwrap();
        let Err(strict_errors) = strict_outcome else {
            panic!("ensure_valid must run the validation closure");
        };
        assert_eq!(
            strict_errors.get("email"),
            Some(&vec![":invalid".to_string()])
        );

        let mut moving = confirmed_user(&adapter, &config, &clock, 3, "mover@example.com").await;
        moving
            .change_email_with_reconfirmation(
                "mover-new@example.com",
                &adapter,
                &mailer,
                &config,
                &clock,
            )
            .await
            .unwrap();
        let forced = moving
            .confirm(&adapter, &config, &clock, false, &invalid)
            .await
            .unwrap();
        assert!(forced.is_err());
    }

    #[test]
    fn confirmable_module_order_pins_chain_position() {
        use crate::scope::Module;

        assert!(Module::Confirmable < Module::Lockable);
        let chain = Module::all();
        let position = |module| chain.iter().position(|item| item == &module).unwrap();
        assert!(position(Module::Confirmable) < position(Module::Lockable));
        assert!(position(Module::Lockable) < position(Module::Timeoutable));
        assert!(position(Module::Timeoutable) < position(Module::Trackable));
    }

    #[test]
    fn confirmable_required_fields_match_devise() {
        assert_eq!(
            required_fields(false),
            vec!["confirmation_token", "confirmed_at", "confirmation_sent_at"]
        );
        assert_eq!(
            required_fields(true),
            vec![
                "confirmation_token",
                "confirmed_at",
                "confirmation_sent_at",
                "unconfirmed_email"
            ]
        );
    }

    #[test]
    fn confirmable_unsafe_attributes_cover_confirmation_columns() {
        for field in [
            "confirmation_token",
            "confirmed_at",
            "confirmation_sent_at",
            "unconfirmed_email",
        ] {
            assert!(
                crate::error::UNSAFE_ATTRIBUTES_FOR_SERIALIZATION.contains(&field),
                "{field} must stay in the unsafe serialization list"
            );
        }
    }

    #[test]
    fn confirmable_humanize_period_renders_devise_windows() {
        assert_eq!(humanize_period(chrono::TimeDelta::weeks(2)), "2 weeks");
        assert_eq!(humanize_period(chrono::TimeDelta::days(1)), "1 day");
        assert_eq!(humanize_period(chrono::TimeDelta::hours(6)), "6 hours");
        assert_eq!(
            humanize_period(chrono::TimeDelta::minutes(30)),
            "30 minutes"
        );
    }

    /// CONCERNS #3 / divergence closure: the port stores the HMAC DIGEST in
    /// `confirmation_token` (Devise stores the raw token and carries an open
    /// TODO to converge to digest-only). Behavioral parity is what matters -
    /// a confirmation link works in both worlds:
    ///
    /// 1. a row the PORT minted (digest stored) confirms through the emailed
    ///    RAW token;
    /// 2. a row a DEVISE deployment minted (raw stored) confirms through the
    ///    legacy raw-first lookup.
    ///
    /// The port keeps the hardened storage and both lookup directions, which
    /// is the compatibility Devise's own TODO describes.
    #[tokio::test]
    async fn confirmable_token_storage_is_digest_and_both_lookups_work() {
        let config = test_config();
        let clock = FixedClock::now();
        let adapter = MemoryAdapter::<TestUser>::new();

        // 1. Port-minted row: the column holds the DIGEST, never the raw token.
        let mut user = TestUser::fresh(1, "port@example.com");
        adapter.create(user.clone()).await.unwrap();
        let raw = user
            .ensure_confirmation_token(&adapter, &config, &clock)
            .await
            .unwrap();
        let stored = adapter
            .get(&user.to_key())
            .await
            .unwrap()
            .unwrap()
            .confirmation_token()
            .map(str::to_string);
        let expected_digest = crate::crypto::token_generator::digest(
            &config.secret_key,
            CONFIRMATION_TOKEN_COLUMN,
            &raw,
        );
        assert_eq!(
            stored.as_deref(),
            Some(expected_digest.as_str()),
            "the port stores only the digest (CONCERNS #3)"
        );
        assert_ne!(
            stored.as_deref(),
            Some(raw.as_str()),
            "the raw token never reaches the database"
        );

        // The emailed raw token confirms the port-minted row.
        let outcome = TestUser::confirm_by_token(Some(&raw), &adapter, &config, &clock, &valid)
            .await
            .unwrap();
        assert!(
            outcome.is_valid(),
            "digest row confirms through the raw token"
        );
        assert!(outcome.record.confirmed());

        // 2. Legacy Devise row: the column holds the RAW token and still
        // confirms (the raw-first lookup).
        let mut legacy = TestUser::fresh(2, "legacy@example.com");
        let legacy_raw = "legacyrawtoken123456";
        legacy.set_confirmation_token(Some(legacy_raw.to_string()));
        legacy.set_confirmation_sent_at(Some(clock.now()));
        adapter.create(legacy).await.unwrap();
        let outcome =
            TestUser::confirm_by_token(Some(legacy_raw), &adapter, &config, &clock, &valid)
                .await
                .unwrap();
        assert!(outcome.is_valid(), "legacy raw row still confirms");
        assert!(outcome.record.confirmed());

        // A token that matches neither shape fails with :invalid - never :blank.
        let outcome = TestUser::confirm_by_token(
            Some("unknown-token-value-000000"),
            &adapter,
            &config,
            &clock,
            &valid,
        )
        .await
        .unwrap();
        assert!(!outcome.is_valid());
        assert_eq!(
            outcome.errors.get("confirmation_token").map(Vec::as_slice),
            Some(&[":invalid".to_string()][..])
        );
    }
}
