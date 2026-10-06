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

/// Normalize one credential value per Devise config (AUTH-06).
///
/// Single home for the downcase/trim rules that `ParameterFilter::filter`
/// applies to `serde_json::Value` trees; this is its flat `Conditions`
/// counterpart, shared by finders and strategies.
#[must_use]
pub fn normalize_credential_value(
    value: String,
    key: &str,
    case_insensitive_keys: &[String],
    strip_whitespace_keys: &[String],
) -> String {
    let mut value = value;
    if case_insensitive_keys.iter().any(|k| k == key) {
        value.make_ascii_lowercase();
    }
    if strip_whitespace_keys.iter().any(|k| k == key) {
        value = value.trim().to_string();
    }
    value
}

/// Normalize auth conditions per Devise config (AUTH-06).///
/// Applies [`normalize_credential_value`] to every string entry, returning
/// a new map. Concrete models call this on their condition maps before
/// validation and lookup.
#[must_use]
pub fn normalize_auth_conditions(conditions: &Conditions, config: &DeviseConfig) -> Conditions {
    let mut normalized = Conditions::new();
    for (key, value) in conditions.iter() {
        let mut value = value.clone();
        if let Value::String(text) = &mut value {
            let raw = std::mem::take(text);
            *text = normalize_credential_value(
                raw,
                key,
                &config.case_insensitive_keys,
                &config.strip_whitespace_keys,
            );
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

// ============================================================================
// DatabaseAuthenticatable (DBAU-01..10)
// Mirrors devise/lib/devise/models/database_authenticatable.rb
// ============================================================================

/// `DatabaseAuthenticatable` module - password handling over
/// `encrypted_password` with virtual `password`/`password_confirmation`.
///
/// == Options
///
/// * `pepper` - appended to the password before bcrypt hashing
/// * `stretches` - bcrypt cost factor (default 12)
/// * `send_email_changed_notification` - email the ORIGINAL address on email change
/// * `send_password_change_notification` - email on password change
///
/// == Examples
///
/// ```ignore
/// user.set_password(Some("secret123".to_string()), &config);
/// assert!(user.valid_password("secret123", &config));
/// assert!(!user.valid_password("wrong", &config));
/// ```
#[async_trait]
pub trait DatabaseAuthenticatable: Authenticatable {
    /// Stored `encrypted_password` column value (None before first set).
    fn encrypted_password(&self) -> Option<&str>;
    /// Set the `encrypted_password` column (already hashed value).
    fn set_encrypted_password(&mut self, value: Option<String>);
    /// Virtual `password` attribute (never persisted).
    fn password(&self) -> Option<&str>;
    /// Store the virtual `password` value as-is (no hashing).
    fn set_password_virtual(&mut self, password: Option<String>);
    /// Virtual `password_confirmation` attribute.
    fn password_confirmation(&self) -> Option<&str>;
    /// Store the virtual `password_confirmation` value.
    fn set_password_confirmation(&mut self, value: Option<String>);
    /// Whether the record is persisted (Devise `persisted?`).
    fn persisted(&self) -> bool;
    /// Devise `assign_attributes` - model-defined mapping of raw params onto
    /// fields. Implementations must ignore `password`/`password_confirmation`/
    /// `current_password` keys (password assignment goes through
    /// [`set_password`](Self::set_password) which carries the config).
    fn assign_attributes(&mut self, attrs: &serde_json::Map<String, JsonValue>);

    /// `password=` setter (DBAU-01): encrypts via `Encryptor::digest`
    /// (stretches, pepper) and stores to `encrypted_password` ONLY when the
    /// password is present (Devise `password.present?` - None or empty skips).
    fn set_password(&mut self, password: Option<String>, config: &DeviseConfig) {
        if let Some(plain) = password.as_deref().filter(|p| !p.is_empty()) {
            let digest = crate::crypto::encryptor::digest(plain, config);
            self.set_encrypted_password(Some(digest));
        }
        self.set_password_virtual(password);
    }

    /// `valid_password?(password)` (DBAU-02): bcrypt verify via
    /// `Encryptor::compare` (constant-time). False when `encrypted_password`
    /// is blank (matches Devise).
    fn valid_password(&self, password: &str, config: &DeviseConfig) -> bool {
        match self.encrypted_password() {
            Some(hash) if !hash.is_empty() => {
                crate::crypto::encryptor::compare(password, hash, config)
            }
            _ => false,
        }
    }

    /// `authenticatable_salt` (DBAU-06): `encrypted_password[0,29]` - changing
    /// the password invalidates existing sessions. Wire the model's
    /// `AnyDeviseModel::authenticatable_salt` to this default.
    fn database_authenticatable_salt(&self) -> Option<String> {
        self.encrypted_password()
            .filter(|p| !p.is_empty())
            .and_then(|p| p.get(..29).map(str::to_string))
    }

    /// `clean_up_passwords` (DBAU-utils): clears the virtual password fields
    /// after save so they cannot leak into serialization. Devise
    /// `clean_up_passwords`.
    fn clean_up_passwords(&mut self) {
        self.set_password_virtual(None);
        self.set_password_confirmation(None);
    }

    /// Whether the email-change notification is suppressed
    /// (Devise `skip_email_changed_notification!` flag state).
    fn skips_email_changed_notification(&self) -> bool {
        false
    }

    /// Whether the password-change notification is suppressed
    /// (Devise `skip_password_change_notification!` flag state).
    fn skips_password_change_notification(&self) -> bool {
        false
    }

    /// Devise `skip_email_changed_notification!`: suppress the notification
    /// for the current in-flight update.
    fn skip_email_changed_notification(&mut self) {}

    /// Devise `skip_password_change_notification!`: suppress the notification
    /// for the current in-flight update.
    fn skip_password_change_notification(&mut self) {}

    /// `update_with_password(params)` (DBAU-03): requires the current password,
    /// strips blank password fields (so an untouched password is never reset),
    /// applies the remaining attributes.
    ///
    /// # Errors
    /// Returns `:current_password :invalid` after applying attrs (Devise
    /// re-renders the form with the edits).
    fn update_with_password(
        &mut self,
        params: &mut serde_json::Map<String, JsonValue>,
        config: &DeviseConfig,
    ) -> Result<(), ValidationErrors> {
        let current = params
            .remove("current_password")
            .and_then(|v| v.as_str().map(str::to_string));
        if params
            .get("password")
            .is_none_or(|p| p.as_str().is_none_or(str::is_empty))
        {
            params.remove("password");
            params.remove("password_confirmation");
        }

        let allowed = current
            .as_deref()
            .is_some_and(|pw| self.valid_password(pw, config));
        self.assign_attributes(params);
        let mut errors = ValidationErrors::new();
        if !allowed {
            errors.add("current_password", ":invalid");
        }
        self.clean_up_passwords();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// `update_without_password(params)` (DBAU-04): never touches password
    /// fields - strips all three keys and applies the rest.
    fn update_without_password(&mut self, params: &mut serde_json::Map<String, JsonValue>) {
        params.remove("password");
        params.remove("password_confirmation");
        params.remove("current_password");
        self.assign_attributes(params);
        self.clean_up_passwords();
    }

    /// `destroy_with_password(current_password)` (DBAU-05): destroys the
    /// record only when the supplied password is valid; returns whether the
    /// record was destroyed (Devise: `valid_password? && destroy`).
    async fn destroy_with_password<A>(
        &self,
        current_password: &str,
        adapter: &A,
        config: &DeviseConfig,
    ) -> Result<bool, crate::adapter::OrmError>
    where
        Self: Sized,
        A: OrmAdapter<Self> + Send + Sync,
    {
        if !self.valid_password(current_password, config) {
            return Ok(false);
        }
        adapter.delete(&self.to_key()).await?;
        Ok(true)
    }

    /// `after_database_authentication` hook (DBAU-07): documented no-op
    /// extension point, called by the strategy after successful password auth.
    fn after_database_authentication(&self) {}

    /// Email-change notification recipient (DBAU-08): the ORIGINAL email from
    /// the `ChangeSet`'s previous value. `None` when the notification is
    /// disabled, skipped, or no email change occurred.
    fn email_notification_recipient(
        &self,
        changes: &crate::adapter::ChangeSet,
        config: &DeviseConfig,
    ) -> Option<String> {
        if !config.send_email_changed_notification || self.skips_email_changed_notification() {
            return None;
        }
        if !changes.has_changed("email") {
            return None;
        }
        match changes.previous_value("email") {
            Some(crate::adapter::Value::String(email)) if !email.is_empty() => Some(email.clone()),
            _ => None,
        }
    }

    /// Password-change notification decision (DBAU-09): pending when enabled,
    /// not skipped, and `encrypted_password` changed. Recipient is the record's
    /// current email (the new address wins for password changes).
    fn password_change_notification_pending(
        &self,
        changes: &crate::adapter::ChangeSet,
        config: &DeviseConfig,
    ) -> bool {
        config.send_password_change_notification
            && !self.skips_password_change_notification()
            && changes.has_changed("encrypted_password")
    }

    /// `find_for_database_authentication(conditions)` (DBAU-10): the strategy
    /// entry point - conditions arrive already filtered/normalized by the
    /// parameter layer (DBAU-strategy locked decision).
    async fn find_for_database_authentication<A>(
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

    /// `send_email_changed_notification` (DBAU-08): when enabled and not
    /// skipped, mail the ORIGINAL address (the `ChangeSet`'s previous email).
    /// The record's current state rides in the template's `resource` (so an
    /// in-flight `unconfirmed_email` renders "being changed to", matching
    /// Devise's conditional template).
    ///
    /// # Errors
    /// `DeviseError::Mailer` when the notification cannot render.
    fn send_email_changed_notification<L>(
        &self,
        changes: &crate::adapter::ChangeSet,
        mailer: &L,
        config: &DeviseConfig,
    ) -> Result<(), crate::error::DeviseError>
    where
        L: crate::mailer::Mailer<Self>,
        Self: crate::mailer::HasEmail + Sized,
    {
        let Some(recipient) = self.email_notification_recipient(changes, config) else {
            return Ok(());
        };
        let context = crate::mailer::MailerContext {
            email: recipient,
            token: None,
            url: None,
            resource: self.serializable_hash(),
        };
        mailer.email_changed(self, None, &context)?;
        Ok(())
    }

    /// `send_password_change_notification` (DBAU-09): when enabled, not
    /// skipped, and `encrypted_password` changed, mail the CURRENT email.
    ///
    /// # Errors
    /// `DeviseError::Mailer` when the notification cannot render.
    fn send_password_change_notification<L>(
        &self,
        changes: &crate::adapter::ChangeSet,
        mailer: &L,
        config: &DeviseConfig,
    ) -> Result<(), crate::error::DeviseError>
    where
        L: crate::mailer::Mailer<Self>,
        Self: crate::mailer::HasEmail + Sized,
    {
        if !self.password_change_notification_pending(changes, config) {
            return Ok(());
        }
        let context =
            crate::mailer::MailerContext::from_record(self).with_resource(self.serializable_hash());
        mailer.password_change(self, None, &context)?;
        Ok(())
    }
}

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
/// let user = TestUser::new_with_session(&params, &session, &config);
/// // save via adapter; then:
/// match user.post_sign_up_message() {
///     None => { /* active_for_authentication: sign in (flash :signed_up) */ }
///     Some(key) => { /* flash "signed_up_but_{key}", no session data */ }
/// }
/// ```
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
        let mut record = Self::default();
        record.assign_attributes(params);
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

// ============================================================================
// Recoverable (RCV-01..04)
// Mirrors devise/lib/devise/models/recoverable.rb
// ============================================================================

/// `Recoverable` module: password reset tokens. The DB stores the HMAC
/// digest and `reset_password_sent_at`; the RAW token only exists in the
/// email link and in memory on the record that just received it.
///
/// == Options
///
/// * `reset_password_keys` - attributes used for instructions lookup (default `[:email]`)
/// * `reset_password_within` - token validity window (default 6 hours)
/// * `sign_in_after_reset_password` - controller-side sign-in decision
///
/// == Examples
///
/// ```ignore
/// let raw = user.send_reset_password_instructions(&adapter, &mailer, &config, &clock).await?;
/// let outcome = TestUser::reset_password_by_token(&attrs, &adapter, &config, &clock).await?;
/// ```
#[async_trait]
pub trait Recoverable: DatabaseAuthenticatable + crate::mailer::HasEmail {
    /// Stored `reset_password_token` column - always the HMAC digest, never raw.
    fn reset_password_token(&self) -> Option<&str>;
    /// `reset_password_sent_at` timestamp column.
    fn reset_password_sent_at(&self) -> Option<chrono::DateTime<chrono::Utc>>;
    /// Write the token columns (digest + `sent_at`).
    fn set_reset_password_token_fields(
        &mut self,
        token: Option<String>,
        sent_at: Option<chrono::DateTime<chrono::Utc>>,
    );
    /// Transient raw token, restored on the record after
    /// `reset_password_by_token` (Devise restores the attribute in memory).
    /// Never persisted.
    fn raw_reset_password_token(&self) -> Option<&str> {
        None
    }
    /// Restore the transient raw token (memory only).
    fn set_raw_reset_password_token(&mut self, _raw: Option<String>) {}

    /// `reset_password_period_valid` (RCV-02): the token was sent within
    /// `reset_password_within`. Locked decision: takes `&dyn Clock`
    /// (`FixedClock` in tests, `SystemClock` by default).
    fn reset_password_period_valid(
        &self,
        config: &DeviseConfig,
        clock: &dyn crate::time::Clock,
    ) -> bool {
        self.reset_password_sent_at()
            .is_some_and(|sent_at| sent_at >= clock.ago(config.reset_password_within))
    }

    /// `send_reset_password_instructions` (RCV-01): generate a raw token via
    /// `TokenGenerator`, persist the DIGEST + `reset_password_sent_at`
    /// (`update_columns` = Devise `save(validate: false)`), email the RAW
    /// token, and return the raw token.
    ///
    /// # Errors
    /// `DeviseError::Adapter` on persistence failure, `DeviseError::Mailer`
    /// when the notification cannot render.
    async fn send_reset_password_instructions<A, L>(
        &mut self,
        adapter: &A,
        mailer: &L,
        config: &DeviseConfig,
        clock: &dyn crate::time::Clock,
    ) -> Result<String, crate::error::DeviseError>
    where
        Self: Sized,
        A: OrmAdapter<Self> + Send + Sync,
        L: crate::mailer::Mailer<Self>,
    {
        // Devise's TokenGenerator.generate loops until the digest is unique.
        let (raw, enc) = loop {
            let (raw, enc) = crate::crypto::token_generator::generate(
                &config.secret_key,
                "reset_password_token",
            );
            let mut conditions = Conditions::new();
            conditions.insert("reset_password_token", Value::String(enc.clone()));
            if adapter
                .find_first(&conditions)
                .await
                .map_err(crate::error::DeviseError::Adapter)?
                .is_none()
            {
                break (raw, enc);
            }
        };

        let now = clock.now();
        let current = std::collections::HashMap::from([
            (
                "reset_password_token".to_string(),
                Value::String(enc.clone()),
            ),
            (
                "reset_password_sent_at".to_string(),
                Value::String(now.to_rfc3339()),
            ),
        ]);
        adapter
            .update_columns(&self.to_key(), &current)
            .await
            .map_err(crate::error::DeviseError::Adapter)?;
        self.set_reset_password_token_fields(Some(enc), Some(now));

        let context = crate::mailer::MailerContext::from_record(self)
            .with_token(raw.clone())
            .with_resource(self.serializable_hash());
        mailer.reset_password_instructions(self, Some(&raw), &context)?;
        Ok(raw)
    }

    /// `with_reset_password_token(token)` (RCV-02): digest the token and look
    /// up the record by digest.
    ///
    /// # Errors
    /// `DeviseError::Adapter` on lookup failure.
    async fn with_reset_password_token<A>(
        token: &str,
        adapter: &A,
        config: &DeviseConfig,
    ) -> Result<Option<Self>, crate::error::DeviseError>
    where
        Self: Sized,
        A: OrmAdapter<Self> + Send + Sync,
    {
        let enc = crate::crypto::token_generator::digest(
            &config.secret_key,
            "reset_password_token",
            token,
        );
        let mut conditions = Conditions::new();
        conditions.insert("reset_password_token", Value::String(enc));
        adapter
            .find_first(&conditions)
            .await
            .map_err(crate::error::DeviseError::Adapter)
    }

    /// Devise class method `send_reset_password_instructions(attributes)`:
    /// find-or-initialize by `reset_password_keys` (paranoid-safe -
    /// `:not_found` errors on a blank record when nothing matches), send on
    /// hit.
    ///
    /// # Errors
    /// `DeviseError::Adapter` on lookup/persistence failure, `DeviseError::Mailer`
    /// when the notification cannot render.
    async fn send_reset_password_instructions_for<A, L>(
        attributes: &serde_json::Map<String, JsonValue>,
        adapter: &A,
        mailer: &L,
        config: &DeviseConfig,
        clock: &dyn crate::time::Clock,
    ) -> Result<ResourceWithErrors<Self>, crate::error::DeviseError>
    where
        Self: Sized + Default,
        A: OrmAdapter<Self> + Send + Sync,
        L: crate::mailer::Mailer<Self>,
    {
        let keys: Vec<&str> = config
            .reset_password_keys
            .iter()
            .map(String::as_str)
            .collect();
        let mut conditions = Conditions::new();
        for key in &keys {
            if let Some(value) = attributes.get(*key).and_then(JsonValue::as_str) {
                conditions.insert((*key).to_string(), Value::String(value.to_string()));
            }
        }
        // Missing all lookup keys must take Devise's :not_found path directly:
        // an empty condition set would match an ARBITRARY record in adapters
        // where "empty conditions match any record" holds.
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
        if resource.is_valid() {
            resource
                .record
                .send_reset_password_instructions(adapter, mailer, config, clock)
                .await?;
        }
        Ok(resource)
    }

    /// `reset_password(new_password, new_password_confirmation)`: blank new
    /// password -> `:password :blank`, no save. Otherwise assign virtuals,
    /// validate, clear the token fields, persist
    /// (Devise: `clear_reset_password_token` + `save`).
    ///
    /// # Errors
    /// Outer: `DeviseError::Adapter` on persistence failure. Inner
    /// `Err(ValidationErrors)`: Devise's `false` + populated `errors`.
    async fn reset_password<A>(
        &mut self,
        new_password: Option<String>,
        new_password_confirmation: Option<String>,
        adapter: &A,
        config: &DeviseConfig,
    ) -> Result<Result<(), ValidationErrors>, crate::error::DeviseError>
    where
        Self: Validatable + Sized,
        A: OrmAdapter<Self, New = Self> + Send + Sync,
    {
        let mut errors = ValidationErrors::new();
        let Some(plain) = new_password.filter(|p| !p.is_empty()) else {
            errors.add("password", ":blank");
            return Ok(Err(errors));
        };
        self.set_password(Some(plain), config);
        self.set_password_confirmation(new_password_confirmation);

        let errors = self.validate(config);
        if !errors.is_empty() {
            return Ok(Err(errors));
        }

        self.clear_reset_password_token();
        let current = std::collections::HashMap::from([
            (
                "encrypted_password".to_string(),
                Value::String(self.encrypted_password().unwrap_or_default().to_string()),
            ),
            ("reset_password_token".to_string(), Value::Null),
            ("reset_password_sent_at".to_string(), Value::Null),
        ]);
        adapter
            .update_columns(&self.to_key(), &current)
            .await
            .map_err(crate::error::DeviseError::Adapter)?;
        Ok(Ok(()))
    }

    /// `reset_password_by_token(attributes)` (RCV-02/03): blank token ->
    /// `:reset_password_token :blank` on a fresh record; unknown token ->
    /// `:not_found`; expired window -> `:expired`; otherwise reset, clear,
    /// and restore the RAW token on the returned record (in memory).
    ///
    /// # Errors
    /// `DeviseError::Adapter` on lookup/persistence failure.
    async fn reset_password_by_token<A>(
        attributes: &serde_json::Map<String, JsonValue>,
        adapter: &A,
        config: &DeviseConfig,
        clock: &dyn crate::time::Clock,
    ) -> Result<ResourceWithErrors<Self>, crate::error::DeviseError>
    where
        Self: Validatable + Sized + Default,
        A: OrmAdapter<Self, New = Self> + Send + Sync,
    {
        let original = attributes
            .get("reset_password_token")
            .and_then(JsonValue::as_str)
            .unwrap_or("")
            .to_string();
        if original.is_empty() {
            let mut errors = ValidationErrors::new();
            errors.add("reset_password_token", ":blank");
            return Ok(ResourceWithErrors::new(Self::default(), errors));
        }

        let Some(mut record) = Self::with_reset_password_token(&original, adapter, config).await?
        else {
            let mut errors = ValidationErrors::new();
            errors.add("reset_password_token", ":not_found");
            return Ok(ResourceWithErrors::new(Self::default(), errors));
        };

        if !record.reset_password_period_valid(config, clock) {
            let mut errors = ValidationErrors::new();
            errors.add("reset_password_token", ":expired");
            return Ok(ResourceWithErrors::new(record, errors));
        }

        let password = attributes
            .get("password")
            .and_then(JsonValue::as_str)
            .map(str::to_string);
        let confirmation = attributes
            .get("password_confirmation")
            .and_then(JsonValue::as_str)
            .map(str::to_string);
        match record
            .reset_password(password, confirmation, adapter, config)
            .await?
        {
            Ok(()) => {
                // Devise restores the raw token on the returned record.
                record.set_raw_reset_password_token(Some(original));
                Ok(ResourceWithErrors::new(record, ValidationErrors::new()))
            }
            Err(errors) => Ok(ResourceWithErrors::new(record, errors)),
        }
    }

    /// RCV-04 (Devise `before_update` decision): reset token columns must be
    /// cleared when the update changes `encrypted_password` or any
    /// `authentication_keys` field.
    fn pending_reset_token_clear(
        &self,
        changes: &crate::adapter::ChangeSet,
        config: &DeviseConfig,
    ) -> bool {
        changes.has_changed("encrypted_password")
            || config
                .authentication_keys
                .iter()
                .any(|key| changes.has_changed(key))
    }

    /// Devise `clear_reset_password_token`: nil the token columns.
    fn clear_reset_password_token(&mut self) {
        self.set_reset_password_token_fields(None, None);
    }
}

// ============================================================================
// Validatable (VAL-01, VAL-02)
// Mirrors devise/lib/devise/models/validatable.rb
// ============================================================================

/// `Validatable` module: email and password validations. Validation lives on
/// the model and runs against [`DeviseConfig`] (`email_regexp`,
/// `password_length`); uniqueness additionally needs the adapter.
///
/// == Options
///
/// * `email_regexp` - format for the email attribute (Devise default
///   `\\A[^@\\s]+@[^@\\s]+\\z`)
/// * `password_length` - allowed password length (Devise default `6..128`,
///   bounds inclusive as in Ruby)
///
/// == Examples
///
/// ```ignore
/// let errors = user.validate(&config);
/// assert!(errors.is_empty());
/// ```
#[async_trait]
pub trait Validatable: DatabaseAuthenticatable {
    /// The record's email for validation (None until set).
    fn email_value(&self) -> Option<&str>;

    /// `password_required?`: true for new records OR when password/
    /// confirmation is present (VAL-password-cond locked decision).
    fn password_required(&self) -> bool {
        !self.persisted() || self.password().is_some() || self.password_confirmation().is_some()
    }

    /// `email_required?`: true by default; models may override.
    fn email_required(&self) -> bool {
        true
    }

    /// The record's primary key as a string, for excluding self from the
    /// uniqueness check on persisted records.
    fn uniqueness_scope_id(&self) -> Option<String> {
        None
    }

    /// Match `email` against the configured `email_regexp` (Devise default
    /// `\\A[^@\\s]+@[^@\\s]+\\z`; `\\A`/`\\z` anchors translated for the
    /// `regex` crate).
    #[must_use]
    fn email_format_valid(email: &str, config: &DeviseConfig) -> bool {
        let pattern = config.email_regexp.replace(r"\A", "^").replace(r"\z", "$");
        regex::Regex::new(&pattern).is_ok_and(|re| re.is_match(email))
    }

    /// Run the full Validatable validation set, returning Devise-keyed errors
    /// (`:blank`, `:invalid`, `:confirmation`, `:too_short`, `:too_long`).
    ///
    /// Uniqueness is NOT checked here (needs the adapter) - see
    /// [`validate_email_uniqueness`](Self::validate_email_uniqueness).
    fn validate(&self, config: &DeviseConfig) -> ValidationErrors {
        let mut errors = ValidationErrors::new();

        if self.email_required() {
            match self.email_value() {
                Some(email) if !email.is_empty() => {
                    if !Self::email_format_valid(email, config) {
                        errors.add("email", ":invalid");
                    }
                }
                _ => errors.add("email", ":blank"),
            }
        }

        if self.password_required() {
            match self.password() {
                Some(password) if !password.is_empty() => {
                    if let Some(confirmation) = self.password_confirmation() {
                        if confirmation != password {
                            errors.add("password_confirmation", ":confirmation");
                        }
                    }
                    // `password_length` mirrors Ruby's inclusive `..` range.
                    let length = password.len();
                    if length < config.password_length.start {
                        errors.add("password", ":too_short");
                    } else if length > config.password_length.end {
                        errors.add("password", ":too_long");
                    }
                }
                _ => errors.add("password", ":blank"),
            }
        }

        errors
    }

    /// Devise `validates_uniqueness_of :email, case_sensitive: true` (VAL-01):
    /// the email was already downcased/stripped by `before_validation`
    /// (normalize hooks), so the lookup uses the value as stored - no
    /// second normalization here (that would diverge from the DB check).
    async fn validate_email_uniqueness<A>(&self, adapter: &A, errors: &mut ValidationErrors)
    where
        Self: Sized,
        A: OrmAdapter<Self> + Send + Sync,
    {
        let Some(email) = self.email_value().filter(|e| !e.is_empty()) else {
            return;
        };
        let mut conditions = Conditions::new();
        conditions.insert("email", Value::String(email.to_string()));
        if let Ok(Some(existing)) = adapter.find_first(&conditions).await {
            let existing_id = existing.uniqueness_scope_id();
            if existing_id.is_none() || existing_id != self.uniqueness_scope_id() {
                errors.add("email", ":taken");
            }
        }
    }
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
        self.session_pair()
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

    #[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
    struct TestUser {
        id: i64,
        email: String,
        encrypted_password: String,
        #[serde(skip)]
        password: Option<String>,
        #[serde(skip)]
        password_confirmation: Option<String>,
        #[serde(skip)]
        skip_email_notification: bool,
        #[serde(skip)]
        skip_password_notification: bool,
        #[serde(skip)]
        inactive: bool,
        reset_password_token: Option<String>,
        reset_password_sent_at: Option<chrono::DateTime<chrono::Utc>>,
        unconfirmed_email: Option<String>,
        #[serde(skip)]
        raw_reset_token: Option<String>,
        #[serde(skip)]
        after_auth_count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl TestUser {
        fn testing(password: &str, config: &DeviseConfig) -> Self {
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
                after_auth_count: std::sync::Arc::default(),
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
        fn serializable_hash(&self) -> JsonValue {
            let mut map = serde_json::json!({ "id": self.id, "email": self.email });
            if let Some(unconfirmed) = &self.unconfirmed_email {
                map["unconfirmed_email"] = JsonValue::String(unconfirmed.clone());
            }
            map
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
            self.persisted().then(|| self.id.to_string())
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
    fn database_authenticatable_tracer() {
        let config = test_config();
        let mut user = TestUser {
            id: 1,
            email: "tracer@example.com".to_string(),
            ..TestUser::default()
        };

        // password= encrypts via Encryptor and stores to encrypted_password.
        DatabaseAuthenticatable::set_password(&mut user, Some("secret123".to_string()), &config);
        let encrypted = user.encrypted_password.clone();
        assert!(encrypted.starts_with("$2"), "bcrypt hash: {encrypted}");
        assert!(!encrypted.contains("secret123"));

        // valid_password verifies with the constant-time compare.
        assert!(DatabaseAuthenticatable::valid_password(
            &user,
            "secret123",
            &config
        ));
        assert!(!DatabaseAuthenticatable::valid_password(
            &user, "wrong", &config
        ));

        // authenticatable_salt = encrypted_password[0,29].
        let salt = DatabaseAuthenticatable::database_authenticatable_salt(&user)
            .expect("salt for encrypted record");
        assert_eq!(salt, encrypted[..29]);
        assert_eq!(salt.len(), 29);

        // Blank password leaves encrypted_password untouched (present? semantics).
        DatabaseAuthenticatable::set_password(&mut user, Some(String::new()), &config);
        assert_eq!(user.encrypted_password, encrypted);
        DatabaseAuthenticatable::set_password(&mut user, None, &config);
        assert_eq!(user.encrypted_password, encrypted);

        // valid_password is false for a blank encrypted_password (Devise parity).
        let new_user = TestUser::default();
        assert!(!DatabaseAuthenticatable::valid_password(
            &new_user, "anything", &config
        ));
    }

    #[tokio::test]
    async fn database_authenticatable_methods() {
        let config = DeviseConfig {
            stretches: 4,
            send_email_changed_notification: true,
            send_password_change_notification: true,
            ..DeviseConfig::default()
        };
        let adapter = MemoryAdapter::<TestUser>::new();
        let user = TestUser::testing("secret123", &config);
        adapter.create(user.clone()).await.unwrap();

        // clean_up_passwords clears the virtual fields.
        let mut cleaned = user.clone();
        cleaned.password = Some("x".to_string());
        cleaned.password_confirmation = Some("x".to_string());
        DatabaseAuthenticatable::clean_up_passwords(&mut cleaned);
        assert_eq!(
            (cleaned.password(), cleaned.password_confirmation()),
            (None, None)
        );

        // update_with_password: valid current_password applies attrs (DBAU-03).
        let mut ok_user = user.clone();
        let mut params = serde_json::Map::new();
        params.insert(
            "current_password".to_string(),
            JsonValue::String("secret123".to_string()),
        );
        params.insert(
            "email".to_string(),
            JsonValue::String("new@example.com".to_string()),
        );
        DatabaseAuthenticatable::update_with_password(&mut ok_user, &mut params, &config)
            .expect("valid current password");
        assert_eq!(ok_user.email, "new@example.com");

        // update_with_password: wrong current_password keeps attrs applied to
        // the in-memory record (Devise re-render semantics) and returns
        // :current_password :invalid. Virtual fields cleared afterward.
        let mut bad_user = user.clone();
        let mut params = serde_json::Map::new();
        params.insert(
            "current_password".to_string(),
            JsonValue::String("wrong".to_string()),
        );
        params.insert(
            "email".to_string(),
            JsonValue::String("nope@example.com".to_string()),
        );
        params.insert("password".to_string(), JsonValue::String(String::new()));
        params.insert(
            "password_confirmation".to_string(),
            JsonValue::String(String::new()),
        );
        let err =
            DatabaseAuthenticatable::update_with_password(&mut bad_user, &mut params, &config)
                .expect_err("wrong current password");
        assert_eq!(
            err.get("current_password").map(Vec::as_slice),
            Some(&[":invalid".to_string()][..])
        );
        assert!(!params.contains_key("password"), "blank password stripped");

        // update_without_password never touches password keys (DBAU-04).
        let mut plain = user.clone();
        let encrypted_before = plain.encrypted_password.clone();
        let mut params = serde_json::Map::new();
        params.insert(
            "password".to_string(),
            JsonValue::String("hacked123".to_string()),
        );
        params.insert(
            "email".to_string(),
            JsonValue::String("safe@example.com".to_string()),
        );
        DatabaseAuthenticatable::update_without_password(&mut plain, &mut params);
        assert_eq!(plain.encrypted_password, encrypted_before);
        assert_eq!(plain.email, "safe@example.com");

        // find_for_database_authentication routes through find_for_authentication (DBAU-10).
        // (Runs before the destroy checks below: the record must exist.)
        let mut conditions = Conditions::new();
        conditions.insert(
            "email",
            AdapterValue::String("test@example.com".to_string()),
        );
        let found =
            TestUser::find_for_database_authentication(&conditions, &adapter, &config).await;
        assert_eq!(found.map(|u| u.id), Some(1));

        // destroy_with_password destroys only on a valid password (DBAU-05).
        assert!(
            !DatabaseAuthenticatable::destroy_with_password(&user, "wrong", &adapter, &config)
                .await
                .unwrap()
        );
        assert!(
            DatabaseAuthenticatable::destroy_with_password(&user, "secret123", &adapter, &config)
                .await
                .unwrap()
        );
        assert!(
            adapter
                .get(&DeviseKey::from_i64(1))
                .await
                .unwrap()
                .is_none()
        );

        // after_database_authentication hook exists and defaults to no-op (DBAU-07).
        DatabaseAuthenticatable::after_database_authentication(&user);
    }

    #[test]
    fn database_authenticatable_notifications() {
        use std::collections::HashMap;

        let config = DeviseConfig {
            stretches: 4,
            send_email_changed_notification: true,
            send_password_change_notification: true,
            ..DeviseConfig::default()
        };
        let user = TestUser::testing("secret123", &config);

        // Notification decisions (DBAU-08/09): email change notifies the
        // ORIGINAL address; password change notifies the current one.
        let previous = HashMap::from([(
            "email".to_string(),
            crate::adapter::Value::String("old@example.com".to_string()),
        )]);
        let current = HashMap::from([
            (
                "email".to_string(),
                crate::adapter::Value::String("new@example.com".to_string()),
            ),
            (
                "encrypted_password".to_string(),
                crate::adapter::Value::String("hash".to_string()),
            ),
        ]);
        let changes = crate::adapter::ChangeSet::new(previous, current);
        assert_eq!(
            DatabaseAuthenticatable::email_notification_recipient(&user, &changes, &config)
                .as_deref(),
            Some("old@example.com")
        );
        assert!(
            DatabaseAuthenticatable::password_change_notification_pending(&user, &changes, &config)
        );

        // Skip flags and disabled config suppress notifications.
        let mut skipping = user.clone();
        DatabaseAuthenticatable::skip_email_changed_notification(&mut skipping);
        DatabaseAuthenticatable::skip_password_change_notification(&mut skipping);
        assert!(
            DatabaseAuthenticatable::email_notification_recipient(&skipping, &changes, &config)
                .is_none()
        );
        assert!(
            !DatabaseAuthenticatable::password_change_notification_pending(
                &skipping, &changes, &config
            )
        );
        let quiet = DeviseConfig {
            stretches: 4,
            send_email_changed_notification: false,
            send_password_change_notification: false,
            ..DeviseConfig::default()
        };
        assert!(
            DatabaseAuthenticatable::email_notification_recipient(&user, &changes, &quiet)
                .is_none()
        );
        assert!(
            !DatabaseAuthenticatable::password_change_notification_pending(&user, &changes, &quiet)
        );

        // No email change -> no email notification.
        let steady = crate::adapter::ChangeSet::new(
            HashMap::from([(
                "email".to_string(),
                crate::adapter::Value::String("a@example.com".to_string()),
            )]),
            HashMap::from([(
                "email".to_string(),
                crate::adapter::Value::String("a@example.com".to_string()),
            )]),
        );
        assert!(
            DatabaseAuthenticatable::email_notification_recipient(&user, &steady, &config)
                .is_none()
        );
    }

    #[tokio::test]
    async fn validatable_tests() {
        let config = test_config();

        // New record: password required; blank email/password flagged.
        let blank = TestUser::default();
        assert!(Validatable::password_required(&blank));
        let errors = Validatable::validate(&blank, &config);
        assert_eq!(
            errors.get("email").map(Vec::as_slice),
            Some(&[":blank".to_string()][..])
        );
        assert_eq!(
            errors.get("password").map(Vec::as_slice),
            Some(&[":blank".to_string()][..])
        );

        // Format via email_regexp (Devise default \A[^@\s]+@[^@\s]+\z).
        for bad in ["not-an-email", "missing@", "@example.com", "a b@c.com"] {
            let user = TestUser {
                email: bad.to_string(),
                password: Some("secret123".to_string()),
                ..TestUser::default()
            };
            let errors = Validatable::validate(&user, &config);
            assert_eq!(
                errors.get("email").map(Vec::as_slice),
                Some(&[":invalid".to_string()][..]),
                "{bad} should be :invalid"
            );
        }

        // Confirmation mismatch and length bounds (6..128 inclusive, Ruby range).
        let mut mismatch = TestUser {
            email: "fresh@example.com".to_string(),
            ..TestUser::default()
        };
        mismatch.set_password(Some("secret123".to_string()), &config);
        mismatch.set_password_confirmation(Some("different".to_string()));
        let errors = Validatable::validate(&mismatch, &config);
        assert_eq!(
            errors.get("password_confirmation").map(Vec::as_slice),
            Some(&[":confirmation".to_string()][..])
        );

        let short = TestUser {
            email: "fresh@example.com".to_string(),
            password: Some("12345".to_string()),
            ..TestUser::default()
        };
        let errors = Validatable::validate(&short, &config);
        assert_eq!(
            errors.get("password").map(Vec::as_slice),
            Some(&[":too_short".to_string()][..])
        );

        let long = TestUser {
            email: "fresh@example.com".to_string(),
            password: Some("x".repeat(129)),
            ..TestUser::default()
        };
        let errors = Validatable::validate(&long, &config);
        assert_eq!(
            errors.get("password").map(Vec::as_slice),
            Some(&[":too_long".to_string()][..])
        );

        // 6 and 128 are valid bounds (Ruby inclusive range parity).
        for len in [6usize, 128] {
            let user = TestUser {
                email: "bounds@example.com".to_string(),
                password: Some("x".repeat(len)),
                ..TestUser::default()
            };
            let errors = Validatable::validate(&user, &config);
            assert!(errors.is_empty(), "length {len} should pass: {errors:?}");
        }

        // Persisted record with no password fields: password not required.
        let persisted = TestUser::testing("secret123", &config);
        assert!(!Validatable::password_required(&persisted));
    }

    #[tokio::test]
    async fn validatable_uniqueness() {
        let config = test_config();
        let adapter = MemoryAdapter::<TestUser>::new();
        adapter
            .create(TestUser::testing("secret123", &config))
            .await
            .unwrap();

        // Uniqueness: another record with the same email (case-sensitive at DB).
        let dupe = TestUser {
            email: "test@example.com".to_string(),
            password: Some("secret123".to_string()),
            ..TestUser::default()
        };
        let mut errors = Validatable::validate(&dupe, &config);
        Validatable::validate_email_uniqueness(&dupe, &adapter, &mut errors).await;
        assert_eq!(
            errors.get("email").map(Vec::as_slice),
            Some(&[":taken".to_string()][..])
        );

        // Same record updating itself: not a uniqueness violation.
        let mut self_update = TestUser::testing("secret123", &config);
        self_update.email = "self@example.com".to_string();
        adapter
            .update(
                &DeviseKey::from_i64(1),
                &crate::adapter::ChangeSet::new(
                    std::collections::HashMap::from([(
                        "email".to_string(),
                        crate::adapter::Value::String("test@example.com".to_string()),
                    )]),
                    std::collections::HashMap::from([(
                        "email".to_string(),
                        crate::adapter::Value::String("self@example.com".to_string()),
                    )]),
                ),
            )
            .await
            .unwrap();
        let mut errors = ValidationErrors::new();
        Validatable::validate_email_uniqueness(&self_update, &adapter, &mut errors).await;
        assert!(errors.is_empty(), "self-update must not be :taken");
    }

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
        use std::sync::Arc;

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

    #[tokio::test]
    async fn reset_flow_tracer() {
        use crate::mailer::TestMailer;
        use crate::time::FixedClock;

        let config = test_config();
        let adapter = MemoryAdapter::<TestUser>::new();
        let mailer = TestMailer::default();
        let clock = FixedClock::now();
        let user = TestUser::testing("secret123", &config);
        adapter.create(user.clone()).await.unwrap();

        // 1. request reset: digest + timestamp persisted, RAW token emailed.
        let mut found = TestUser::find_for_authentication(
            &{
                let mut c = Conditions::new();
                c.insert(
                    "email",
                    AdapterValue::String("test@example.com".to_string()),
                );
                c
            },
            &adapter,
            &config,
        )
        .await
        .expect("user exists");
        Recoverable::send_reset_password_instructions(
            &mut found, &adapter, &mailer, &config, &clock,
        )
        .await
        .expect("instructions send");

        let sent = mailer.sent_mails();
        let captured = sent.last().expect("email captured");
        assert_eq!(captured.to, "test@example.com");
        assert_eq!(captured.subject, "Reset password instructions");
        let raw = captured
            .template_vars
            .token
            .clone()
            .expect("email delivers the raw token");

        // Stored column holds the DIGEST, not the raw token.
        assert_ne!(found.reset_password_token().unwrap(), raw);
        assert_eq!(
            found.reset_password_token().unwrap(),
            crate::crypto::token_generator::digest(
                &config.secret_key,
                "reset_password_token",
                &raw
            )
        );
        assert!(found.reset_password_sent_at.is_some());

        // 2. user follows the link: window validated, password reset, token
        // cleared, raw token restored on the record.
        let mut attrs = serde_json::Map::new();
        attrs.insert(
            "reset_password_token".to_string(),
            JsonValue::String(raw.clone()),
        );
        attrs.insert(
            "password".to_string(),
            JsonValue::String("newsecret456".to_string()),
        );
        attrs.insert(
            "password_confirmation".to_string(),
            JsonValue::String("newsecret456".to_string()),
        );
        let outcome = TestUser::reset_password_by_token(&attrs, &adapter, &config, &clock)
            .await
            .unwrap();
        assert!(outcome.is_valid(), "reset succeeds: {:?}", outcome.errors);
        assert!(DatabaseAuthenticatable::valid_password(
            &outcome.record,
            "newsecret456",
            &config
        ));
        assert_eq!(outcome.record.reset_password_token(), None);
        assert_eq!(outcome.record.reset_password_sent_at, None);
        assert_eq!(
            outcome.record.raw_reset_password_token(),
            Some(raw.as_str())
        );

        // The cleared state persisted.
        let reloaded = adapter.get(&DeviseKey::from_i64(1)).await.unwrap().unwrap();
        assert_eq!(Recoverable::reset_password_token(&reloaded), None);
        assert!(DatabaseAuthenticatable::valid_password(
            &reloaded,
            "newsecret456",
            &config
        ));
    }

    /// Shared setup for the split `send_reset_password_instructions` tests
    /// (clippy pedantic keeps each test under the 100-line limit).
    async fn instructions_setup() -> (
        DeviseConfig,
        MemoryAdapter<TestUser>,
        crate::mailer::TestMailer,
        crate::time::FixedClock,
    ) {
        let config = test_config();
        let adapter = MemoryAdapter::<TestUser>::new();
        adapter
            .create(TestUser::testing("secret123", &config))
            .await
            .unwrap();
        let fixed = chrono::DateTime::parse_from_rfc3339("2026-10-06T00:00:00Z")
            .unwrap()
            .to_utc();
        (
            config,
            adapter,
            crate::mailer::TestMailer::default(),
            crate::time::FixedClock::new(fixed),
        )
    }

    #[tokio::test]
    async fn send_reset_password_instructions() {
        use crate::time::Clock as _;

        let (config, adapter, mailer, clock) = instructions_setup().await;
        let fixed = clock.now();

        // Class entry: finds by reset_password_keys, sends instructions.
        let mut attributes = serde_json::Map::new();
        attributes.insert(
            "email".to_string(),
            JsonValue::String("test@example.com".to_string()),
        );
        let outcome = TestUser::send_reset_password_instructions_for(
            &attributes,
            &adapter,
            &mailer,
            &config,
            &clock,
        )
        .await
        .unwrap();
        assert!(outcome.is_valid());

        // digest+timestamp persisted; raw token returned by the instance path.
        let stored = adapter.get(&DeviseKey::from_i64(1)).await.unwrap().unwrap();
        let digest = Recoverable::reset_password_token(&stored)
            .unwrap()
            .to_string();
        assert_eq!(digest.len(), 64, "HMAC-SHA256 hex digest");
        assert_eq!(
            Recoverable::reset_password_sent_at(&stored).unwrap(),
            fixed,
            "reset_password_sent_at uses the injected clock"
        );

        // Unknown email: find-or-initialize errors :not_found (no send, no panic).
        let mut attributes = serde_json::Map::new();
        attributes.insert(
            "email".to_string(),
            JsonValue::String("ghost@example.com".to_string()),
        );
        let outcome = TestUser::send_reset_password_instructions_for(
            &attributes,
            &adapter,
            &mailer,
            &config,
            &clock,
        )
        .await
        .unwrap();
        assert!(!outcome.is_valid());
        assert_eq!(
            outcome.errors.get("email").map(Vec::as_slice),
            Some(&[":not_found".to_string()][..])
        );
        assert_eq!(mailer.sent_mails().len(), 1, "no email for unknown record");

        // No lookup keys at all: :not_found on every configured key, nothing
        // sent (regression: empty conditions must not match an arbitrary record).
        let empty_attributes = serde_json::Map::new();
        let outcome = TestUser::send_reset_password_instructions_for(
            &empty_attributes,
            &adapter,
            &mailer,
            &config,
            &clock,
        )
        .await
        .unwrap();
        assert!(!outcome.is_valid());
        assert_eq!(
            outcome.errors.get("email").map(Vec::as_slice),
            Some(&[":not_found".to_string()][..])
        );
        assert_eq!(
            mailer.sent_mails().len(),
            1,
            "no email for empty attributes"
        );
    }

    #[tokio::test]
    async fn send_reset_password_instructions_regenerates_and_clears() {
        use std::collections::HashMap;

        let (config, adapter, mailer, clock) = instructions_setup().await;
        let mut attributes = serde_json::Map::new();
        attributes.insert(
            "email".to_string(),
            JsonValue::String("test@example.com".to_string()),
        );

        TestUser::send_reset_password_instructions_for(
            &attributes,
            &adapter,
            &mailer,
            &config,
            &clock,
        )
        .await
        .unwrap();
        let first = adapter.get(&DeviseKey::from_i64(1)).await.unwrap().unwrap();
        let first_digest = Recoverable::reset_password_token(&first)
            .unwrap()
            .to_string();

        // Second send for the same user REGENERATES the token (digest changes).
        TestUser::send_reset_password_instructions_for(
            &attributes,
            &adapter,
            &mailer,
            &config,
            &clock,
        )
        .await
        .unwrap();
        let stored2 = adapter.get(&DeviseKey::from_i64(1)).await.unwrap().unwrap();
        assert_ne!(
            first_digest,
            Recoverable::reset_password_token(&stored2).unwrap()
        );
        assert_eq!(mailer.sent_mails().len(), 2);

        // RCV-04: password change or auth-key change clears the token fields.
        let changes = crate::adapter::ChangeSet::new(
            HashMap::from([(
                "encrypted_password".to_string(),
                Value::String("old".to_string()),
            )]),
            HashMap::from([(
                "encrypted_password".to_string(),
                Value::String("new".to_string()),
            )]),
        );
        assert!(Recoverable::pending_reset_token_clear(
            &stored2, &changes, &config
        ));
        let email_change = crate::adapter::ChangeSet::new(
            HashMap::from([("email".to_string(), Value::String("a@x.com".to_string()))]),
            HashMap::from([("email".to_string(), Value::String("b@x.com".to_string()))]),
        );
        assert!(Recoverable::pending_reset_token_clear(
            &stored2,
            &email_change,
            &config
        ));
        let unrelated = crate::adapter::ChangeSet::new(
            HashMap::from([("other".to_string(), Value::String("a".to_string()))]),
            HashMap::from([("other".to_string(), Value::String("b".to_string()))]),
        );
        assert!(!Recoverable::pending_reset_token_clear(
            &stored2, &unrelated, &config
        ));

        // Clearing nils both columns.
        let mut cleared = stored2.clone();
        Recoverable::clear_reset_password_token(&mut cleared);
        assert_eq!(Recoverable::reset_password_token(&cleared), None);
        assert_eq!(Recoverable::reset_password_sent_at(&cleared), None);
    }

    fn reset_attrs(
        token: &str,
        password: &str,
        confirmation: &str,
    ) -> serde_json::Map<String, JsonValue> {
        let mut attrs = serde_json::Map::new();
        attrs.insert(
            "reset_password_token".to_string(),
            JsonValue::String(token.to_string()),
        );
        attrs.insert(
            "password".to_string(),
            JsonValue::String(password.to_string()),
        );
        attrs.insert(
            "password_confirmation".to_string(),
            JsonValue::String(confirmation.to_string()),
        );
        attrs
    }

    async fn issue_reset_token(
        adapter: &MemoryAdapter<TestUser>,
        mailer: &crate::mailer::TestMailer,
        config: &DeviseConfig,
        clock: &crate::time::FixedClock,
    ) -> String {
        let mut stored = adapter.get(&DeviseKey::from_i64(1)).await.unwrap().unwrap();
        stored
            .send_reset_password_instructions(adapter, mailer, config, clock)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn reset_password_by_token_guards() {
        use crate::time::FixedClock;

        let config = test_config();
        let adapter = MemoryAdapter::<TestUser>::new();
        let clock = FixedClock::now();
        adapter
            .create(TestUser::testing("secret123", &config))
            .await
            .unwrap();

        // Blank token: :reset_password_token :blank on a fresh record (RCV-03).
        let mut attrs = serde_json::Map::new();
        attrs.insert(
            "reset_password_token".to_string(),
            JsonValue::String(String::new()),
        );
        attrs.insert(
            "password".to_string(),
            JsonValue::String("freshpass1".to_string()),
        );
        let outcome = TestUser::reset_password_by_token(&attrs, &adapter, &config, &clock)
            .await
            .unwrap();
        assert!(!outcome.is_valid());
        assert_eq!(
            outcome
                .errors
                .get("reset_password_token")
                .map(Vec::as_slice),
            Some(&[":blank".to_string()][..])
        );

        // Unknown token: :not_found, nothing changes.
        let mut attrs = serde_json::Map::new();
        attrs.insert(
            "reset_password_token".to_string(),
            JsonValue::String("bogus".to_string()),
        );
        attrs.insert(
            "password".to_string(),
            JsonValue::String("freshpass1".to_string()),
        );
        let outcome = TestUser::reset_password_by_token(&attrs, &adapter, &config, &clock)
            .await
            .unwrap();
        assert_eq!(
            outcome
                .errors
                .get("reset_password_token")
                .map(Vec::as_slice),
            Some(&[":not_found".to_string()][..])
        );
        assert!(DatabaseAuthenticatable::valid_password(
            &TestUser::testing("secret123", &config),
            "secret123",
            &config
        ));
    }

    #[tokio::test]
    async fn reset_password_by_token_window() {
        use crate::time::FixedClock;

        let config = test_config();
        let adapter = MemoryAdapter::<TestUser>::new();
        let mailer = crate::mailer::TestMailer::default();
        let mut clock = FixedClock::now();
        adapter
            .create(TestUser::testing("secret123", &config))
            .await
            .unwrap();

        // Expired window: advance past reset_password_within (6h) -> :expired.
        let raw = issue_reset_token(&adapter, &mailer, &config, &clock).await;
        clock.advance(chrono::TimeDelta::hours(6) + chrono::TimeDelta::minutes(1));
        let outcome = TestUser::reset_password_by_token(
            &reset_attrs(&raw, "freshpass1", "freshpass1"),
            &adapter,
            &config,
            &clock,
        )
        .await
        .unwrap();
        assert_eq!(
            outcome
                .errors
                .get("reset_password_token")
                .map(Vec::as_slice),
            Some(&[":expired".to_string()][..])
        );

        // Inside the window the same kind of token succeeds.
        let raw = issue_reset_token(&adapter, &mailer, &config, &clock).await;
        clock.advance(chrono::TimeDelta::hours(1));
        let outcome = TestUser::reset_password_by_token(
            &reset_attrs(&raw, "freshpass1", "freshpass1"),
            &adapter,
            &config,
            &clock,
        )
        .await
        .unwrap();
        assert!(outcome.is_valid(), "in-window reset: {:?}", outcome.errors);
        assert_eq!(
            outcome.record.raw_reset_password_token(),
            Some(raw.as_str())
        );

        // Mismatched confirmation surfaces :confirmation (validation path).
        let raw = issue_reset_token(&adapter, &mailer, &config, &clock).await;
        let outcome = TestUser::reset_password_by_token(
            &reset_attrs(&raw, "freshpass1", "different9"),
            &adapter,
            &config,
            &clock,
        )
        .await
        .unwrap();
        assert_eq!(
            outcome
                .errors
                .get("password_confirmation")
                .map(Vec::as_slice),
            Some(&[":confirmation".to_string()][..])
        );
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
