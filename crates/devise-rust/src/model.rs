//! Model traits - `Authenticatable` base, password checking, boxed finder bridge
//!
//! Mirrors `devise/lib/devise/models/authenticatable.rb`: default
//! implementations for validity checks, session serialization, and finders
//! with `ParameterFilter`-style normalization (AUTH-06).
//!
//! The [`ModelFinder`] bridge lets the strategy chain (`strategy.rs`) and
//! `AuthProxy` (`proxy.rs`) work with heterogeneous per-scope models through
//! one object-safe trait, while concrete adapters keep their typed
//! [`OrmAdapter`] contract.

use crate::adapter::{Conditions, DeviseKey, OrmAdapter, Value};
use crate::config::DeviseConfig;
use crate::confirmable::Confirmable;
use crate::error::ResourceWithErrors;
use crate::error::ValidationErrors;
use crate::failure::{AnyDeviseModel, AuthRules};
use crate::lockable::Lockable;
use async_trait::async_trait;
use serde_json::Value as JsonValue;
use std::marker::PhantomData;

/// Normalize one credential value per Devise config (AUTH-06).
///
/// Single home for the downcase/trim rules Devise applies in
/// `ParameterFilter#filter` and in the `downcase_keys`/`strip_whitespace`
/// `before_validation` hooks. The finder path (`Conditions`), the JSON-tree
/// path (`ParameterFilter::filter`), and the write path
/// (`normalize_attribute_map`) all share this function, so a value can never
/// normalize differently depending on which door it came through.
///
/// Mirrors the per-value half of `Devise::ParameterFilter#filter` (`devise/lib/devise/parameter_filter.rb`): Ruby's `String#downcase`/`strip`, Unicode-aware like the original.
#[must_use]
pub fn normalize_credential_value(
    value: &str,
    key: &str,
    case_insensitive_keys: &[String],
    strip_whitespace_keys: &[String],
) -> String {
    let mut value = value;
    if case_insensitive_keys.iter().any(|k| k == key) {
        value = value.trim();
        value.to_lowercase()
    } else if strip_whitespace_keys.iter().any(|k| k == key) {
        value = value.trim();
        value.to_string()
    } else {
        value.to_string()
    }
}

/// Normalize a write-path attribute map per Devise config (AUTH-06).
///
/// The counterpart of [`normalize_auth_conditions`] for attribute maps:
/// applies [`normalize_credential_value`] to every string entry of the flat
/// param map that lands on a record through `assign_attributes`. This is the
/// port of Devise's `before_validation :downcase_keys` /
/// `:strip_whitespace` (`devise/lib/devise/models/authenticatable.rb:198-204`),
/// normalizing on WRITE, not just on lookup, so `"  Foo@Bar.COM "` is
/// stored as `foo@bar.com` and cannot coexist with `foo@bar.com`
/// (`CONCERNS.md` items 4 and 44).
#[must_use]
pub fn normalize_attribute_map(
    params: &serde_json::Map<String, JsonValue>,
    config: &DeviseConfig,
) -> serde_json::Map<String, JsonValue> {
    let mut normalized = params.clone();
    for (key, value) in &mut normalized {
        if let JsonValue::String(text) = value {
            let raw = std::mem::take(text);
            *text = normalize_credential_value(
                &raw,
                key,
                &config.case_insensitive_keys,
                &config.strip_whitespace_keys,
            );
        }
    }
    normalized
}

/// Normalize auth conditions per Devise config (AUTH-06).
///
/// Applies [`normalize_credential_value`] to every string entry, returning
/// a new map. Concrete models call this on their condition maps before
/// validation and lookup.
///
/// Mirrors the conditions normalization devise applies inside `find_for_authentication` through the `ParameterFilter`.
#[must_use]
pub fn normalize_auth_conditions(conditions: &Conditions, config: &DeviseConfig) -> Conditions {
    let mut normalized = Conditions::new();
    for (key, value) in conditions.iter() {
        let mut value = value.clone();
        if let Value::String(text) = &mut value {
            *text = normalize_credential_value(
                text,
                key,
                &config.case_insensitive_keys,
                &config.strip_whitespace_keys,
            );
        }
        normalized.insert(key.clone(), value);
    }
    normalized
}

/// Single home for the password-family blank predicate.
///
/// Devise gates every password path on Ruby's `String#present?`, which is
/// `false` for `nil`, `""`, AND whitespace-only strings (`"   "`). The bare
/// `is_empty` check that a port reaches for first treats `"   "` as a real
/// password: it gets bcrypt-hashed into `encrypted_password`, survives as a
/// credential, and then reports `:too_short` instead of Devise's `:blank`.
/// `set_password`, the `update_with_password` blank-strip, `reset_password`'s
/// guard, and `Validatable::validate` all read this one function so the
/// definition of "present" cannot drift between the write, the validation,
/// and the reset paths.
pub(crate) fn value_present(value: Option<&str>) -> Option<&str> {
    value.filter(|item| !item.trim().is_empty())
}

pub(crate) fn value_blank(value: Option<&str>) -> bool {
    value_present(value).is_none()
}

/// `destroy_with_password` result: the Devise outcome split into "the record
/// is gone" and "the record survives with the failure surface attached".
///
/// Devise (`database_authenticatable.rb:132-142`) returns a bare `bool`
/// while the record's shared `errors` object carries the failure: a wrong
/// `current_password` adds `:current_password :invalid` and a blank one adds
/// `:current_password :blank`. A `bool` return discards that distinction, so
/// callers cannot render Devise's copy ("is invalid" versus "can't be
/// blank"). This enum pairs the two halves Devise keeps in one place; the
/// port hands validation maps around explicitly, the same convention
/// [`update_with_password`](DatabaseAuthenticatable::update_with_password)
/// already ships.
///
/// The refusal map carries the `current_password` symbolic key ONLY. A model
/// that wants its own `valid?` errors rendered alongside (Devise calls
/// `valid?` on the refusal branch, populating the shared object) merges them
/// into this map at the call site.
#[derive(Debug, Clone, PartialEq)]
pub enum DestroyOutcome {
    /// The password checked out and the adapter `delete` ran: Devise's
    /// `valid_password?(current_password) && destroy` true branch.
    Destroyed,
    /// The password did NOT check out: the record is untouched (no adapter
    /// delete runs) and the errors carry the `current_password` symbolic key,
    /// `:blank` for a blank or whitespace-only submission and `:invalid`
    /// otherwise.
    Refused(ValidationErrors),
}

/// The adapter-value half of the same blank predicate: Ruby's `blank?` is
/// `false` for every non-nil, non-empty (after trimming) value, so `0`,
/// `false`, and typed JSON scalars stay present while a whitespace-only
/// string does not.
///
/// Shares [`value_blank`]'s trim rule so the password path and the
/// `find_or_initialize_with_errors` slice cannot disagree about what counts
/// as a submitted value.
fn condition_value_blank(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(text) => text.trim().is_empty(),
        _ => false,
    }
}

/// Password-checking facet for `DatabaseAuthenticatable` models.
///
/// Strategies resolve it through
/// [`AnyDeviseModel::as_password_verifiable`],
/// so the strategy chain never needs the concrete model type.
///
/// Mirrors `valid_password?` from `Devise::Models::DatabaseAuthenticatable` as the object-safe facet the strategy chain resolves through `AnyDeviseModel`.
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
/// // Ignored doctest: requires a live adapter and an async runtime; the compiled equivalent lives in the crate tests and the example apps.
/// user.set_password(Some("secret123".to_string()), &config);
/// assert!(user.valid_password("secret123", &config));
/// assert!(!user.valid_password("wrong", &config));
/// ```
///
/// Mirrors `Devise::Models::DatabaseAuthenticatable` (`devise/lib/devise/models/database_authenticatable.rb`): password handling over `encrypted_password`, `update_with/without_password`, `destroy_with_password`, `authenticatable_salt`, and the email/password change notifications.
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
    /// password is present (Devise `password.present?` - `None`, empty, or
    /// whitespace-only skips: a blank value is never hashed).
    fn set_password(&mut self, password: Option<String>, config: &DeviseConfig) {
        if let Some(plain) = value_present(password.as_deref()) {
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
        // Devise `before_validation :downcase_keys` / `:strip_whitespace`
        // (`authenticatable.rb:198-204`): normalize configured keys on WRITE
        // (CONCERNS #4) - the same single home the finder path uses.
        *params = normalize_attribute_map(params, config);
        let current = params
            .remove("current_password")
            .and_then(|v| v.as_str().map(str::to_string));
        // Devise's `password.present?` strip: a whitespace-only param is
        // blank, so the pair is dropped instead of hashed.
        if value_blank(params.get("password").and_then(JsonValue::as_str)) {
            params.remove("password");
            params.remove("password_confirmation");
        }

        let allowed = current
            .as_deref()
            .is_some_and(|pw| self.valid_password(pw, config));
        // Devise mass-assignment routes `password`/`password_confirmation`
        // through the `password=` setter (which hashes) in BOTH the success
        // and the failure branch (the failed record re-renders with the new
        // attributes in memory but is never persisted). `assign_attributes`
        // deliberately ignores password keys (per its contract), so the pair
        // goes through `set_password` here, mirroring `new_with_session`.
        let new_password = params
            .remove("password")
            .and_then(|v| v.as_str().map(str::to_string));
        let new_confirmation = params
            .remove("password_confirmation")
            .and_then(|v| v.as_str().map(str::to_string));
        if new_password.is_some() {
            self.set_password(new_password, config);
        }
        self.set_password_confirmation(new_confirmation);
        self.assign_attributes(params);
        let mut errors = ValidationErrors::new();
        if !allowed {
            // Devise (`database_authenticatable.rb:100`): a BLANK
            // current password reports `:blank`; a wrong one reports
            // `:invalid`. The keys carry distinct I18n copy (blank =
            // "can't be blank"), so collapsing them loses the distinction.
            let key = if current.as_deref().is_none_or(str::is_empty) {
                ":blank"
            } else {
                ":invalid"
            };
            errors.add("current_password", key);
        }
        // Virtuals always cleared after the round-trip (Devise
        // `clean_up_passwords` runs on both branches).
        self.clean_up_passwords();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// `update_without_password(params)` (DBAU-04): never touches password
    /// fields - strips all three keys and applies the rest.
    fn update_without_password(
        &mut self,
        params: &mut serde_json::Map<String, JsonValue>,
        config: &DeviseConfig,
    ) {
        // Same write-path normalization as `update_with_password` (CONCERNS #4).
        *params = normalize_attribute_map(params, config);
        params.remove("password");
        params.remove("password_confirmation");
        params.remove("current_password");
        self.assign_attributes(params);
        self.clean_up_passwords();
    }

    /// `destroy_with_password(current_password)` (DBAU-05): destroys the
    /// record only when the supplied password is valid, and reports WHY it
    /// refused when it did not.
    ///
    /// Devise (`database_authenticatable.rb:132-142`) refuses a wrong
    /// `current_password` by adding `:current_password :invalid` to the
    /// record's errors and a blank one by adding `:current_password :blank`,
    /// then calls `valid?` so the shared `errors` object also carries the
    /// model's other validation messages. The port keeps the same refusal
    /// key split (the two keys carry distinct I18n copy) and pairs it with
    /// the destroyed/refused outcome, because a bare `bool` cannot tell the
    /// caller which failure copy to render.
    ///
    /// The refusal key uses the shared trim-aware blank predicate
    /// ([`value_blank`]): Ruby's `current_password.blank?` is `true` for
    /// `nil`, `""`, and `"   "` alike, so a whitespace-only submission is
    /// `:blank`, never a bcrypt comparison.
    ///
    /// The refusal branch returns BEFORE any adapter call, so no code path
    /// deletes the record on a wrong or blank password.
    ///
    /// # Errors
    ///
    /// Returns [`crate::adapter::OrmError`] when the adapter `delete` fails
    /// on the valid-password branch (Devise's destroy raising).
    async fn destroy_with_password<A>(
        &self,
        current_password: &str,
        adapter: &A,
        config: &DeviseConfig,
    ) -> Result<DestroyOutcome, crate::adapter::OrmError>
    where
        Self: Sized,
        A: OrmAdapter<Self> + Send + Sync,
    {
        if self.valid_password(current_password, config) {
            adapter.delete(&self.to_key()).await?;
            return Ok(DestroyOutcome::Destroyed);
        }
        let mut errors = ValidationErrors::new();
        // Devise: `errors.add(:current_password, current_password.blank? ? :blank : :invalid)`.
        let key = if value_blank(Some(current_password)) {
            ":blank"
        } else {
            ":invalid"
        };
        errors.add("current_password", key);
        Ok(DestroyOutcome::Refused(errors))
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
/// // Ignored doctest: requires a live adapter and an async runtime; the compiled equivalent lives in the crate tests and the example apps.
/// let raw = user.send_reset_password_instructions(&adapter, &mailer, &config, &clock).await?;
/// let outcome = TestUser::reset_password_by_token(&attrs, &adapter, &config, &clock).await?;
/// ```
///
/// Mirrors `Devise::Models::Recoverable` (`devise/lib/devise/models/recoverable.rb`): the reset token lifecycle with digest-only storage.
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
        let Some(plain) = value_present(new_password.as_deref()).map(str::to_string) else {
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
    /// and restore the RAW token on the returned record (in memory) on the
    /// FAILURE branch - Devise's `recoverable.rb:148` restores it exactly
    /// when the token is still present, so the re-rendered form keeps it.
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
            errors.add("reset_password_token", ":invalid");
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
            Ok(()) => Ok(ResourceWithErrors::new(record, ValidationErrors::new())),
            Err(errors) => {
                // Devise (`recoverable.rb:148`) restores the raw token on the
                // returned record when the token was still present - the
                // failure branch (a validation error aborts the save before
                // `clear_reset_password_token` runs), so the re-rendered form
                // keeps the user's token instead of the digest. The success
                // branch does NOT restore: the column is already nil'd.
                record.set_raw_reset_password_token(Some(original));
                Ok(ResourceWithErrors::new(record, errors))
            }
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

    /// `sign_in_after_reset_password` (RCV-02 switch): whether a successful
    /// `reset_password_by_token` should sign the user in. Model-level decision;
    /// the controller/framework layer performs the actual sign-in.
    fn sign_in_after_reset_password(&self, config: &DeviseConfig) -> bool {
        config.sign_in_after_reset_password
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
/// // Ignored doctest: requires a live adapter and an async runtime; the compiled equivalent lives in the crate tests and the example apps.
/// let errors = user.validate(&config);
/// assert!(errors.is_empty());
/// ```
///
/// Mirrors `Devise::Models::Validatable` (`devise/lib/devise/models/validatable.rb`): email and password validations against `email_regexp` and `password_length`.
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

    /// Devise `devise_will_save_change_to_email?`: whether this validation
    /// round is writing a NEW email address.
    ///
    /// Devise gates the uniqueness and format validations on it
    /// (`validates_uniqueness_of :email, if: :devise_will_save_change_to_email?`,
    /// `validatable.rb:34-35`), so an update that leaves the address alone
    /// never runs the lookup. The trait holds no in-memory copy of the
    /// persisted address (an app model owns its columns), so the default
    /// reports `true` and the self-exclusion in
    /// [`email_uniqueness_taken`](Self::email_uniqueness_taken) keeps an
    /// untouched update clean; a model that tracks its original email (or the
    /// framework bridge, which knows which params it assigned) overrides this
    /// to return `false` and skip the lookup entirely.
    fn email_changed(&self) -> bool {
        true
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

        // Devise `validatable.rb:37-39` registers three independent
        // validations, and only two of them carry an `if:` gate:
        //
        //   validates_presence_of     :password, if: :password_required?
        //   validates_confirmation_of :password, if: :password_required?
        //   validates_length_of       :password, minimum: proc { password_length.min },
        //                               maximum: proc { password_length.max }, allow_blank: true
        //
        // The length validation has NO `password_required?` gate: its only
        // gate is `allow_blank: true`, so a present password complains about
        // its length whether or not the password is required, and a blank
        // password never complains (that is the presence validation's job).
        if self.password_required() {
            // `validates_presence_of :password, if: :password_required?`
            // with Ruby's `present?` rule (Devise `blank?` is trim-aware).
            if value_blank(self.password()) {
                errors.add("password", ":blank");
            }

            // `validates_confirmation_of :password, if: :password_required?`.
            // Rails compares the RAW attribute values, skipping only a nil
            // confirmation, and reads a missing password as the empty
            // string: a persisted record with a blank password but a present
            // confirmation compares `""` against the confirmation and
            // reports `:confirmation` alongside the presence `:blank`.
            if let Some(confirmation) = self.password_confirmation() {
                if confirmation != self.password().unwrap_or_default() {
                    errors.add("password_confirmation", ":confirmation");
                }
            }
        }

        // `validates_length_of :password, allow_blank: true` - ungated by
        // `password_required?`, so the length rules apply whenever a
        // non-blank password is present.
        if let Some(password) = value_present(self.password()) {
            // `password_length` mirrors Ruby's inclusive `..` range.
            let length = password.len();
            if length < config.password_length.start {
                errors.add("password", ":too_short");
            } else if length > config.password_length.end {
                errors.add("password", ":too_long");
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
        // TODO(propagate): an adapter failure (`Err`) is Devise's 500, not a
        // clean record, and the swallowing is forced by the call shape - see
        // `email_uniqueness_taken`'s docs for the propagating core.
        if matches!(self.email_uniqueness_taken(adapter).await, Ok(true)) {
            errors.add("email", ":taken");
        }
    }

    /// Whether ANOTHER record already holds this record's email (VAL-01).
    ///
    /// The propagating core behind
    /// [`validate_email_uniqueness`](Self::validate_email_uniqueness), carrying
    /// Devise's two exclusion rules:
    /// * the email-change gate ([`email_changed`](Self::email_changed)) - an
    ///   untouched address never touches the store;
    /// * self-exclusion - the lookup meeting the record under validation is
    ///   Devise's `unless: ->(record) { record.id == id }`, decided on the
    ///   primary key rather than a nullable scope id whose `None` arm used to
    ///   flag every self-update as `:taken`. A model whose key cannot express
    ///   identity (a composite uniqueness scope) narrows the exclusion
    ///   through [`uniqueness_scope_id`](Self::uniqueness_scope_id).
    ///
    /// # Errors
    ///
    /// Returns [`crate::adapter::OrmError`] when the lookup fails: a backend
    /// outage is a 500, never a silent "the email is free".
    async fn email_uniqueness_taken<A>(&self, adapter: &A) -> Result<bool, crate::adapter::OrmError>
    where
        Self: Sized,
        A: OrmAdapter<Self> + Send + Sync,
    {
        if !self.email_changed() {
            return Ok(false);
        }
        let Some(email) = value_present(self.email_value()) else {
            return Ok(false);
        };
        let mut conditions = Conditions::new();
        conditions.insert("email", Value::String(email.to_string()));
        let Some(existing) = adapter.find_first(&conditions).await? else {
            return Ok(false);
        };
        // The lookup met this very record: not a uniqueness violation. Both
        // sides must be persisted rows for the key to mean anything - a
        // store that hands back a pre-insert model (the in-memory oracle's
        // `create`) leaves a placeholder id on every row, so two DIFFERENT
        // records can share one key and must not be read as the same row.
        if existing.persisted() && self.persisted() && existing.to_key() == self.to_key() {
            return Ok(false);
        }
        // A model that cannot express identity through its key narrows the
        // self-exclusion through `uniqueness_scope_id` (composite scopes).
        match (existing.uniqueness_scope_id(), self.uniqueness_scope_id()) {
            (Some(existing), Some(own)) => Ok(existing != own),
            _ => Ok(true),
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
    /// `Ok(None)` is the warden fetch verdict - a missing record or a salt
    /// mismatch (the caller deletes the session key), matching Devise. An
    /// adapter failure returns `Err` instead of silently becoming "not
    /// logged in": a backend outage on the fetch path used to read as a
    /// valid "no user", logging every signed-in visitor out at once.
    ///
    /// # Errors
    ///
    /// Returns [`crate::adapter::OrmError`] when the backend fails.
    async fn serialize_from_session<A>(
        key: &DeviseKey,
        salt: &str,
        adapter: &A,
    ) -> Result<Option<Self>, crate::adapter::OrmError>
    where
        Self: Sized,
        A: OrmAdapter<Self> + Send + Sync,
    {
        let Some(record) = adapter.get(key).await? else {
            return Ok(None);
        };
        let Some(current_salt) = record.authenticatable_salt() else {
            return Ok(None);
        };
        if !crate::crypto::secure_compare(&current_salt, salt) {
            return Ok(None);
        }
        Ok(Some(record))
    }

    /// Find a record for authentication with normalized conditions.
    ///
    /// A backend failure is reported as `None` here. TODO(propagate): the
    /// actix/axum bridges call `M::find_for_authentication(...).await` and use
    /// the result as an `Option`, so returning a `Result` would leave their
    /// call sites discarding a `must_use` value and trip the workspace's
    /// `-D warnings` gate; the propagating sibling belongs on the adapter
    /// seam (`find_first_strict`).
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
        // TODO(propagate): see the method docs - the Option return shape is
        // pinned by the bridges' call sites.
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
    /// Mirrors Devise's `find_or_initialize_with_error_by`, which is a thin
    /// wrapper over the group form - so the blank handling lives in exactly
    /// one place.
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
        Self::find_or_initialize_with_errors(&[attr], &conditions, error, adapter, config).await
    }

    /// Find by several attributes or return a blank record with errors.
    ///
    /// Mirrors Devise's `find_or_initialize_with_errors`
    /// (`authenticatable.rb:277-292`) step for step:
    /// 1. `slice(*required_attributes).delete_if { |k, v| v.blank? }` - only
    ///    the required keys survive, and only when their submitted value is
    ///    present (a whitespace-only string is blank, per Ruby's `blank?`);
    /// 2. `if attributes.size == required_attributes.size` - the lookup runs
    ///    ONLY when EVERY required key survived, so a partial key set can
    ///    never revive an arbitrary row on a permissive backend;
    /// 3. otherwise an unsaved record seeded with the surviving attributes,
    ///    each required key carrying `:blank` when its submitted value was
    ///    blank and the caller's error otherwise.
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
        let mut present = Conditions::new();
        for attr in attrs {
            if let Some(value) = conditions
                .get_raw(attr)
                .filter(|v| !condition_value_blank(v))
            {
                present.insert((*attr).to_string(), value.clone());
            }
        }

        // Step 2: lookup only with the complete key set.
        if present.iter().count() == attrs.len() {
            let filtered = Self::normalize_auth_attributes_static(&present, config);
            // TODO(propagate): the call sites (recoverable, confirmable, lockable)
            // consume this as a record-and-errors value, so an adapter failure
            // here is currently reported as "not found"; a Result-returning
            // sibling belongs on those call sites.
            if let Ok(Some(record)) = adapter.find_first(&filtered).await {
                return ResourceWithErrors::new(record, ValidationErrors::new());
            }
        }

        // Step 3: unsaved record seeded with the normalized surviving
        // attributes (Devise's `new(devise_parameter_filter.filter(attributes))`),
        // plus one error per required key.
        let filtered = Self::normalize_auth_attributes_static(&present, config);
        let seeded: serde_json::Map<String, JsonValue> = filtered
            .iter()
            .map(|(key, value)| {
                (
                    key.clone(),
                    serde_json::to_value(value).unwrap_or(JsonValue::Null),
                )
            })
            .collect();
        let mut record = Self::default();
        record.seed_initialized_attributes(&seeded);
        let mut errors = ValidationErrors::new();
        for attr in attrs {
            let blank = conditions.get_raw(attr).is_none_or(condition_value_blank);
            errors.add(attr, if blank { ":blank" } else { error });
        }
        ResourceWithErrors::new(record, errors)
    }

    /// Seed a freshly initialized record with filtered attributes.
    ///
    /// The "initialize" half of Devise's `find_or_initialize_with_errors`,
    /// whose miss branch returns `new(devise_parameter_filter.filter(attributes))`
    /// rather than a bare `new`. The base trait cannot bound
    /// `DatabaseAuthenticatable` (whose `assign_attributes` is the write
    /// seam), so the default is a no-op and app models wire it:
    ///
    /// ```ignore
    /// fn seed_initialized_attributes(&mut self, attributes: &serde_json::Map<String, JsonValue>) {
    ///     self.assign_attributes(attributes);
    /// }
    /// ```
    fn seed_initialized_attributes(&mut self, _attributes: &serde_json::Map<String, JsonValue>) {}

    /// The model's own serializable fields, BEFORE the unsafe-attribute
    /// filter runs.
    ///
    /// App models override this instead of [`serializable_hash`](Self::serializable_hash):
    /// the default `serializable_hash` composes this field map with
    /// [`filter_unsafe_attributes`](crate::error::filter_unsafe_attributes), so
    /// the CONCERNS #6 filter is applied by construction and cannot be
    /// forgotten the way the old "override `serializable_hash` and remember to
    /// filter" contract could be.
    fn serializable_fields(&self) -> serde_json::Map<String, JsonValue> {
        serde_json::Map::new()
    }

    /// Serializable hash excluding unsafe attributes.
    ///
    /// Default composition: [`serializable_fields`](Self::serializable_fields)
    /// through [`filter_unsafe_attributes`](crate::error::filter_unsafe_attributes)
    /// - so a model that publishes `encrypted_password`, a reset/confirmation
    /// token, `unconfirmed_email`, or a sign-in IP through its fields still
    /// never leaks it (Devise's `serializable_hash` filters
    /// [`UNSAFE_ATTRIBUTES_FOR_SERIALIZATION`](crate::error::UNSAFE_ATTRIBUTES_FOR_SERIALIZATION)).
    /// A model may still override this to hand-build the JSON; it then owns the
    /// filter call itself.
    fn serializable_hash(&self) -> JsonValue {
        JsonValue::Object(crate::error::filter_unsafe_attributes(
            &self.serializable_fields(),
        ))
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

// ============================================================================
// Gate chain: confirmable before lockable (05-04)
// Mirrors the `super`-chain order in devise/lib/devise/modules.rb
// ============================================================================

/// Compose the canonical confirmable-before-lockable activity gate.
///
/// `confirmable_active` is the [`Confirmable::confirmation_gate_active`]
/// slice, `lockable_active` the [`Lockable::lock_gate_active`]
/// slice. App `User` types call confirmable-then-lockable through this fn;
/// the order is fixed here so call sites cannot invert it.
///
/// == Examples
///
/// ```
/// use devise_rust::model::chain_active_for_authentication;
///
/// assert!(chain_active_for_authentication(true, true));
/// assert!(!chain_active_for_authentication(false, true));
/// assert!(!chain_active_for_authentication(true, false));
/// ```
///
/// Mirrors the `super` chain of `active_for_authentication?` in devise's module stack: confirmable before lockable, per `devise/lib/devise/modules.rb`.
#[must_use]
pub fn chain_active_for_authentication(confirmable_active: bool, lockable_active: bool) -> bool {
    confirmable_active && lockable_active
}

/// First-failing inactive message for the canonical chain.
///
/// The lockable slice wins over the confirmable slice (`locked` before
/// `unconfirmed`, mirroring Devise's `super`-chain evaluation: lockable is
/// included after confirmable in `Devise::ALL` order, so it is the
/// outermost link and `lockable.rb:95-97` checks `access_locked?` first);
/// `inactive` when every gate defers.
///
/// == Examples
///
/// ```
/// use devise_rust::model::chain_inactive_message;
///
/// assert_eq!(chain_inactive_message(Some("unconfirmed"), Some("locked")), "locked");
/// assert_eq!(chain_inactive_message(None, Some("locked")), "locked");
/// assert_eq!(chain_inactive_message(Some("unconfirmed"), None), "unconfirmed");
/// assert_eq!(chain_inactive_message(None, None), "inactive");
/// ```
#[must_use]
pub fn chain_inactive_message(
    confirmable_message: Option<&'static str>,
    lockable_message: Option<&'static str>,
) -> &'static str {
    // Lockable is the outermost link of Devise's super-chain: included
    // after confirmable (modules.rb order), `lockable.rb:95-97` answers
    // `:locked` first and only defers via `super` when not locked - an
    // account that is BOTH locked and unconfirmed reports `locked`.
    lockable_message
        .or(confirmable_message)
        .unwrap_or("inactive")
}

/// Compose `active_for_authentication?` over a record's module gates.
///
/// The single home for the composition Devise's `super`-chain produces: the
/// base `true`, then the confirmable gate, then the lockable gate
/// (`modules.rb` order). Application models delegate their
/// [`Authenticatable::active_for_authentication`] impl here instead of
/// hand-rolling the gate arithmetic; the object-safe
/// [`Activatable`] view exposes the same result to the hook pipeline.
///
/// == Examples
///
/// ```ignore
/// use devise_rust::model::compose_active_for_authentication;
/// # use devise_rust::confirmable::Confirmable;
/// # use devise_rust::lockable::Lockable;
/// # use devise_rust::time::SystemClock;
/// # use devise_rust::config::DeviseConfig;
/// # use chrono::{DateTime, Utc};
/// # struct Record {
/// #     confirmed: bool,
/// #     confirmed_at: Option<DateTime<Utc>>,
/// #     confirmation_sent_at: Option<DateTime<Utc>>,
/// #     locked_at: Option<DateTime<Utc>>,
/// # }
/// # #[async_trait::async_trait]
/// # impl Confirmable for Record {
/// #     fn confirmation_token(&self) -> Option<&str> { None }
/// #     fn set_confirmation_token(&mut self, _t: Option<String>) {}
/// #     fn confirmed_at(&self) -> Option<DateTime<Utc>> { self.confirmed_at }
/// #     fn set_confirmed_at(&mut self, _a: Option<DateTime<Utc>>) {}
/// #     fn confirmation_sent_at(&self) -> Option<DateTime<Utc>> { self.confirmation_sent_at }
/// #     fn set_confirmation_sent_at(&mut self, _a: Option<DateTime<Utc>>) {}
/// #     fn unconfirmed_email(&self) -> Option<&str> { None }
/// #     fn set_unconfirmed_email(&mut self, _e: Option<String>) {}
/// #     fn set_email_address(&mut self, _e: String) {}
/// #     fn confirmed(&self) -> bool { self.confirmed }
/// # }
/// # #[async_trait::async_trait]
/// # impl Lockable for Record {
/// #     fn failed_attempts(&self) -> u32 { 0 }
/// #     fn set_failed_attempts(&mut self, _c: u32) {}
/// #     fn locked_at(&self) -> Option<DateTime<Utc>> { self.locked_at }
/// #     fn set_locked_at(&mut self, _a: Option<DateTime<Utc>>) {}
/// #     fn unlock_token(&self) -> Option<&str> { None }
/// #     fn set_unlock_token(&mut self, _t: Option<String>) {}
/// #     fn persisted(&self) -> bool { true }
/// # }
/// # let record = Record {
/// #     confirmed: true,
/// #     confirmed_at: Some(Utc::now()),
/// #     confirmation_sent_at: Some(Utc::now()),
/// #     locked_at: None,
/// # };
/// let config = DeviseConfig::default();
/// assert!(compose_active_for_authentication(&record, &config, &SystemClock));
/// ```
///
/// ```ignore
/// use devise_rust::model::{compose_active_for_authentication, compose_inactive_message};
/// # use devise_rust::confirmable::Confirmable;
/// # use devise_rust::lockable::Lockable;
/// # use devise_rust::time::SystemClock;
/// # use devise_rust::config::DeviseConfig;
/// # use chrono::{DateTime, Utc};
/// # struct Record {
/// #     confirmed: bool,
/// #     confirmed_at: Option<DateTime<Utc>>,
/// #     confirmation_sent_at: Option<DateTime<Utc>>,
/// #     locked_at: Option<DateTime<Utc>>,
/// # }
/// # #[async_trait::async_trait]
/// # impl Confirmable for Record {
/// #     fn confirmation_token(&self) -> Option<&str> { None }
/// #     fn set_confirmation_token(&mut self, _t: Option<String>) {}
/// #     fn confirmed_at(&self) -> Option<DateTime<Utc>> { self.confirmed_at }
/// #     fn set_confirmed_at(&mut self, _a: Option<DateTime<Utc>>) {}
/// #     fn confirmation_sent_at(&self) -> Option<DateTime<Utc>> { self.confirmation_sent_at }
/// #     fn set_confirmation_sent_at(&mut self, _a: Option<DateTime<Utc>>) {}
/// #     fn unconfirmed_email(&self) -> Option<&str> { None }
/// #     fn set_unconfirmed_email(&mut self, _e: Option<String>) {}
/// #     fn set_email_address(&mut self, _e: String) {}
/// #     fn confirmed(&self) -> bool { self.confirmed }
/// # }
/// # #[async_trait::async_trait]
/// # impl Lockable for Record {
/// #     fn failed_attempts(&self) -> u32 { 0 }
/// #     fn set_failed_attempts(&mut self, _c: u32) {}
/// #     fn locked_at(&self) -> Option<DateTime<Utc>> { self.locked_at }
/// #     fn set_locked_at(&mut self, _a: Option<DateTime<Utc>>) {}
/// #     fn unlock_token(&self) -> Option<&str> { None }
/// #     fn set_unlock_token(&mut self, _t: Option<String>) {}
/// #     fn persisted(&self) -> bool { true }
/// # }
/// # let pending = Record {
/// #     confirmed: false,
/// #     confirmed_at: None,
/// #     confirmation_sent_at: Some(Utc::now()),
/// #     locked_at: None,
/// # };
/// let config = DeviseConfig::default();
/// assert!(!compose_active_for_authentication(&pending, &config, &SystemClock));
/// assert_eq!(
///     compose_inactive_message(&pending, &config, &SystemClock),
///     "unconfirmed"
/// );
/// ```
#[must_use]
pub fn compose_active_for_authentication<M>(
    record: &M,
    config: &DeviseConfig,
    clock: &dyn crate::time::Clock,
) -> bool
where
    M: Confirmable + Lockable,
{
    chain_active_for_authentication(
        record.confirmation_gate_active(true, config, clock),
        record.lock_gate_active(true, config, clock),
    )
}

/// Compose `inactive_message` over a record's module gates (the
/// first-failing gate's I18n key, Devise's `super`-chain order).
///
/// Companion of [`compose_active_for_authentication`]: the same single home
/// for the message selection (`unconfirmed` before `locked`).
#[must_use]
pub fn compose_inactive_message<M>(
    record: &M,
    config: &DeviseConfig,
    clock: &dyn crate::time::Clock,
) -> &'static str
where
    M: Confirmable + Lockable,
{
    chain_inactive_message(
        record.confirmation_inactive_message(),
        record.lock_inactive_message(config, clock),
    )
}

/// Object-safe view over the activatable gate pair.
///
/// Blanket-implemented for every [`Authenticatable`] model, so the hook
/// pipeline (which only sees `dyn AnyDeviseModel`) reads the very same
/// implementation the typed controllers call - no second composition to
/// drift. Devise's `active_for_authentication?` / `inactive_message` pair.
pub trait Activatable: Send + Sync {
    /// Devise `active_for_authentication?`.
    fn active_for_authentication(&self) -> bool;
    /// Devise `inactive_message` (I18n key).
    fn inactive_message(&self) -> &'static str;
}

impl<T: Authenticatable> Activatable for T {
    fn active_for_authentication(&self) -> bool {
        Authenticatable::active_for_authentication(self)
    }

    fn inactive_message(&self) -> &'static str {
        Authenticatable::inactive_message(self)
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
///
/// Object-safe bridge over the typed `OrmAdapter`; mirrors devise's `to_adapter` dispatch, which is duck-typed in Ruby and typed in the port.
pub struct AdapterBridge<A, M> {
    adapter: A,
    model: PhantomData<M>,
}

impl<A, M> AdapterBridge<A, M> {
    /// Wrap a typed adapter for registration under a scope.
    ///
    /// Wraps one adapter in the object-safe bridge; mirrors devise's `to_adapter` dispatch used by strategies and the proxy.
    #[must_use]
    pub fn new(adapter: A) -> Self {
        Self {
            adapter,
            model: PhantomData,
        }
    }

    /// Access the inner typed adapter.
    ///
    /// Borrows the wrapped adapter for typed call sites; the downcast mirror of devise's duck-typed adapter calls.
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
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

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
        /// Devise `devise_will_save_change_to_email?` override: `None` keeps
        /// the trait default (the email is changing), `Some(false)` models an
        /// update that leaves the address untouched.
        #[serde(skip)]
        email_changed_override: Option<bool>,
        /// `uniqueness_scope_id`: `None` models the models that never override
        /// the accessor (the trait default), which is where the self-update
        /// rejection used to bite.
        #[serde(skip)]
        uniqueness_scope_id: Option<String>,
        /// `password_required?` override, the `validatable_test.rb:105`
        /// stubbing shape: `Some(false)` models a record whose password is
        /// not required (so the length validation still applies),
        /// `None`/`Some(true)` keep the trait default expression.
        #[serde(skip)]
        password_required_override: Option<bool>,
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
    struct CountingAdapter<'a> {
        inner: &'a MemoryAdapter<TestUser>,
        calls: Arc<AtomicUsize>,
        fail_reads: bool,
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
                !self.persisted()
                    || self.password().is_some()
                    || self.password_confirmation().is_some()
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

    fn test_config() -> DeviseConfig {
        DeviseConfig {
            stretches: 4,
            ..DeviseConfig::default()
        }
    }

    /// Devise `String#present?`: a whitespace-only password is BLANK. The
    /// hashing setter, the blank-strip in `update_with_password`, and the
    /// `reset_password` guard must share one blank predicate instead of the
    /// bare `is_empty` check, otherwise `"      "` is hashed into
    /// `encrypted_password` and then reported as `:too_short` instead of
    /// Devise's `:blank`.
    #[tokio::test]
    async fn blank_password_is_never_hashed_and_reports_blank() {
        let config = test_config();

        // set_password: the stored digest survives a whitespace-only value.
        let mut user = TestUser::testing("secret123", &config);
        let digest_before = user.encrypted_password.clone();
        DatabaseAuthenticatable::set_password(&mut user, Some("      ".to_string()), &config);
        assert_eq!(
            user.encrypted_password, digest_before,
            "whitespace-only password must not be hashed"
        );

        // Validation: Devise reports `:blank`, never a length error.
        let errors = Validatable::validate(&user, &config);
        assert_eq!(
            errors.get("password").map(Vec::as_slice),
            Some(&[":blank".to_string()][..]),
            "whitespace-only password validates as blank: {errors:?}"
        );

        // update_with_password strips the whitespace-only pair so the stored
        // digest survives an untouched password update.
        let mut updating = TestUser::testing("secret123", &config);
        let digest_before = updating.encrypted_password.clone();
        let mut params = serde_json::Map::new();
        params.insert(
            "current_password".to_string(),
            JsonValue::String("secret123".to_string()),
        );
        params.insert(
            "password".to_string(),
            JsonValue::String("  \t ".to_string()),
        );
        params.insert(
            "password_confirmation".to_string(),
            JsonValue::String("  \t ".to_string()),
        );
        params.insert(
            "email".to_string(),
            JsonValue::String("kept@example.com".to_string()),
        );
        DatabaseAuthenticatable::update_with_password(&mut updating, &mut params, &config)
            .expect("valid current password");
        assert!(
            !params.contains_key("password"),
            "blank password stripped from params"
        );
        assert_eq!(updating.encrypted_password, digest_before);

        // reset_password: the same blank predicate guards the reset guard.
        let mut changing = TestUser::testing("secret123", &config);
        let digest_before = changing.encrypted_password.clone();
        let outcome = Recoverable::reset_password(
            &mut changing,
            Some("     ".to_string()),
            Some("     ".to_string()),
            &MemoryAdapter::<TestUser>::new(),
            &config,
        )
        .await
        .expect("adapter untouched on a blank reset")
        .expect_err("blank reset password carries validation errors");
        assert_eq!(
            outcome.get("password").map(Vec::as_slice),
            Some(&[":blank".to_string()][..]),
            "whitespace-only reset password is blank: {outcome:?}"
        );
        assert_eq!(changing.encrypted_password, digest_before);
    }

    /// Ruby `String#downcase` is Unicode-aware; the single normalization home
    /// must agree with Devise instead of ASCII-only lowercasing.
    #[test]
    fn test_normalize_credential_value_uses_unicode_lowercase() {
        let ci_keys = ["email".to_string()];
        assert_eq!(
            normalize_credential_value("ÜSER@ÉXAMPLE.COM", "email", &ci_keys, &[]),
            "üser@éxample.com"
        );
        // Non-configured keys are untouched.
        assert_eq!(
            normalize_credential_value("ÜSER", "name", &ci_keys, &[]),
            "ÜSER"
        );
    }

    /// Write-path map normalization (`before_validation` downcase/strip): the
    /// same rules the finder path applies must be applied to attributes before
    /// they land on a record, so `"  Foo@Bar.COM "` is stored as
    /// `foo@bar.com` and cannot coexist with `foo@bar.com`.
    #[test]
    fn test_normalize_attribute_map_normalizes_configured_keys() {
        let config = test_config();
        let mut params = serde_json::Map::new();
        params.insert("email".to_string(), JsonValue::from("  Foo@Bar.COM  "));
        params.insert("password".to_string(), JsonValue::from("secret123"));
        let normalized = normalize_attribute_map(&params, &config);
        assert_eq!(normalized["email"], JsonValue::from("foo@bar.com"));
        assert_eq!(normalized["password"], JsonValue::from("secret123"));
    }

    /// REGS-01 + CONCERNS #4: `new_with_session` normalizes configured keys
    /// before assigning, mirroring Devise's `before_validation` hooks.
    #[tokio::test]
    async fn test_new_with_session_normalizes_email() {
        let config = test_config();
        let mut params = serde_json::Map::new();
        params.insert("email".to_string(), JsonValue::from("  Foo@Bar.COM "));
        params.insert("password".to_string(), JsonValue::from("secret123"));
        let user = TestUser::new_with_session(&params, &JsonValue::Null, &config);
        assert_eq!(user.email_value(), Some("foo@bar.com"));
    }

    /// DBAU-03 + CONCERNS #4: `update_with_password` normalizes the new email
    /// before assigning it to the record.
    #[tokio::test]
    async fn test_update_with_password_normalizes_email() {
        let config = test_config();
        let user = TestUser::testing("secret123", &config);
        let mut record = user.clone();
        let mut params = serde_json::Map::new();
        params.insert(
            "current_password".to_string(),
            JsonValue::from("secret123".to_string()),
        );
        params.insert("email".to_string(), JsonValue::from("  NEW@Example.COM "));
        DatabaseAuthenticatable::update_with_password(&mut record, &mut params, &config)
            .expect("valid current password");
        assert_eq!(record.email_value(), Some("new@example.com"));
    }

    /// End-to-end parity for CONCERNS #4/#44: a sign-up with a mixed-case,
    /// whitespace-padded email must be findable by its normalized form and
    /// must collide with a plain normalized duplicate.
    #[tokio::test]
    async fn test_write_path_normalization_matches_finder_path() {
        let config = test_config();
        let mut params = serde_json::Map::new();
        params.insert("email".to_string(), JsonValue::from(" Foo@Bar.COM "));
        params.insert("password".to_string(), JsonValue::from("secret123"));
        let user = TestUser::new_with_session(&params, &JsonValue::Null, &config);

        let adapter = MemoryAdapter::<TestUser>::new();
        adapter.create(user.clone()).await.unwrap();

        let mut conditions = Conditions::new();
        conditions.insert("email", AdapterValue::String("foo@bar.com".to_string()));
        let found = TestUser::find_for_authentication(&conditions, &adapter, &config).await;
        assert!(found.is_some(), "normalized sign-up email must be findable");
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

    /// The session-fetch path must not turn a backend failure into "nobody is
    /// logged in": an `OrmError` travels to the caller, which can render the
    /// 500 instead of silently logging every visitor out.
    #[tokio::test]
    async fn serialize_from_session_propagates_adapter_failures() {
        let config = test_config();
        let adapter = MemoryAdapter::<TestUser>::new();
        let user = TestUser::testing("secret123", &config);
        adapter.create(user.clone()).await.unwrap();

        let (key, salt) = user.serialize_into_session();
        let roundtrip = TestUser::serialize_from_session(&key, &salt, &adapter)
            .await
            .expect("fetch succeeds");
        assert!(roundtrip.is_some());

        let mismatch = TestUser::serialize_from_session(&key, "bogus-salt", &adapter)
            .await
            .expect("salt mismatch is not a backend failure");
        assert!(mismatch.is_none());

        let missing = TestUser::serialize_from_session(&DeviseKey::from_i64(999), &salt, &adapter)
            .await
            .expect("a missing record is not a backend failure");
        assert!(missing.is_none());
    }

    /// A backend outage on the session fetch surfaces as an error, never as a
    /// valid "nobody is logged in" (which would silently sign every user out).
    #[tokio::test]
    async fn serialize_from_session_reports_backend_failure() {
        let config = test_config();
        let inner = MemoryAdapter::<TestUser>::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let adapter = CountingAdapter {
            inner: &inner,
            calls,
            fail_reads: true,
        };
        let user = TestUser::testing("secret123", &config);
        adapter.create(user.clone()).await.unwrap();
        let (key, salt) = user.serialize_into_session();

        let fetched = TestUser::serialize_from_session(&key, &salt, &adapter).await;
        assert!(
            matches!(fetched, Err(crate::adapter::OrmError::Connection { .. })),
            "a backend failure must reach the caller: {fetched:?}"
        );
    }

    #[test]
    fn test_password_verifiable_facet() {
        let config = test_config();
        let user = TestUser::testing("secret123", &config);
        let facet = user.as_password_verifiable().expect("facet");
        assert!(facet.valid_password("secret123", &config));
        assert!(!facet.valid_password("wrong", &config));
    }

    /// M5: the unsafe-attribute filter is applied BY CONSTRUCTION. A model
    /// publishing `unconfirmed_email` through `serializable_fields` (an entry
    /// of [`crate::error::UNSAFE_ATTRIBUTES_FOR_SERIALIZATION`]) must not see
    /// it rendered, because the default `serializable_hash` composes the
    /// field map with `filter_unsafe_attributes` instead of trusting the model
    /// to remember the call.
    #[test]
    fn serializable_hash_filters_unsafe_fields_by_default() {
        let config = test_config();
        let mut user = TestUser::testing("secret123", &config);
        user.unconfirmed_email = Some("pending@example.com".to_string());

        let fields = user.serializable_fields();
        assert_eq!(
            fields.get("unconfirmed_email").and_then(JsonValue::as_str),
            Some("pending@example.com"),
            "the raw field map carries the attribute the model wants"
        );

        let hash = user.serializable_hash();
        assert_eq!(
            hash.get("email").and_then(JsonValue::as_str),
            Some("test@example.com")
        );
        assert!(
            hash.get("unconfirmed_email").is_none(),
            "the default hash must filter UNSAFE attributes: {hash}"
        );
        assert!(hash.get("encrypted_password").is_none());
        assert!(hash.get("reset_password_token").is_none());
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
        DatabaseAuthenticatable::update_without_password(&mut plain, &mut params, &config);
        assert_eq!(plain.encrypted_password, encrypted_before);
        assert_eq!(plain.email, "safe@example.com");
    }

    /// The lookup and destroy half of the `DatabaseAuthenticatable` surface:
    /// `find_for_database_authentication` routes through
    /// `find_for_authentication` (DBAU-10), `destroy_with_password` refuses a
    /// wrong password and destroys on the valid one (DBAU-05; the full
    /// three-way outcome split is pinned in
    /// `destroy_with_password_error_surface`), and the
    /// `after_database_authentication` hook defaults to a no-op (DBAU-07).
    #[tokio::test]
    async fn database_authenticatable_lookup_and_destroy() {
        let config = DeviseConfig {
            stretches: 4,
            send_email_changed_notification: true,
            send_password_change_notification: true,
            ..DeviseConfig::default()
        };
        let adapter = MemoryAdapter::<TestUser>::new();
        let user = TestUser::testing("secret123", &config);
        adapter.create(user.clone()).await.unwrap();

        let mut conditions = Conditions::new();
        conditions.insert(
            "email",
            AdapterValue::String("test@example.com".to_string()),
        );
        let found =
            TestUser::find_for_database_authentication(&conditions, &adapter, &config).await;
        assert_eq!(found.map(|u| u.id), Some(1));

        assert!(
            matches!(
                DatabaseAuthenticatable::destroy_with_password(&user, "wrong", &adapter, &config)
                    .await
                    .unwrap(),
                DestroyOutcome::Refused(_)
            ),
            "a wrong current password refuses the destroy"
        );
        assert!(
            matches!(
                DatabaseAuthenticatable::destroy_with_password(
                    &user,
                    "secret123",
                    &adapter,
                    &config
                )
                .await
                .unwrap(),
                DestroyOutcome::Destroyed
            ),
            "the valid current password destroys the record"
        );
        assert!(
            adapter
                .get(&DeviseKey::from_i64(1))
                .await
                .unwrap()
                .is_none()
        );

        DatabaseAuthenticatable::after_database_authentication(&user);
    }

    /// `destroy_with_password` mirrors the three Devise cases of
    /// `database_authenticatable_test.rb:221-239`: a valid password
    /// destroys, a wrong one refuses with `:current_password :invalid` and
    /// leaves the record in the store, and a blank one (Devise's `nil`, spelled
    /// here as `""` and as a whitespace-only string, since `blank?` is
    /// trim-aware) refuses with `:current_password :blank`.
    #[tokio::test]
    async fn destroy_with_password_error_surface() {
        let config = test_config();

        // The valid password destroys the record (ruby test at :221).
        let doomed_adapter = MemoryAdapter::<TestUser>::new();
        let doomed = TestUser::testing("secret123", &config);
        doomed_adapter.create(doomed.clone()).await.unwrap();
        let outcome = DatabaseAuthenticatable::destroy_with_password(
            &doomed,
            "secret123",
            &doomed_adapter,
            &config,
        )
        .await
        .unwrap();
        assert_eq!(outcome, DestroyOutcome::Destroyed);
        assert!(
            doomed_adapter
                .get(&DeviseKey::from_i64(1))
                .await
                .unwrap()
                .is_none(),
            "the record must be gone from the store"
        );

        // A wrong password refuses with :invalid and the record survives
        // (ruby test at :227).
        let wrong_adapter = MemoryAdapter::<TestUser>::new();
        let wrong = TestUser::testing("secret123", &config);
        wrong_adapter.create(wrong.clone()).await.unwrap();
        let outcome = DatabaseAuthenticatable::destroy_with_password(
            &wrong,
            "other",
            &wrong_adapter,
            &config,
        )
        .await
        .unwrap();
        let DestroyOutcome::Refused(errors) = outcome else {
            panic!("a wrong password must refuse, got {outcome:?}");
        };
        assert_eq!(
            errors.get("current_password").map(Vec::as_slice),
            Some(&[":invalid".to_string()][..])
        );
        assert!(
            wrong_adapter
                .get(&DeviseKey::from_i64(1))
                .await
                .unwrap()
                .is_some(),
            "the record must still be persisted after a refusal"
        );

        // A blank password refuses with :blank, both for the empty string and
        // for a whitespace-only one (ruby test at :234, `current_password.blank?`).
        for blank in ["", "   "] {
            let blank_adapter = MemoryAdapter::<TestUser>::new();
            let kept = TestUser::testing("secret123", &config);
            blank_adapter.create(kept.clone()).await.unwrap();
            let outcome = DatabaseAuthenticatable::destroy_with_password(
                &kept,
                blank,
                &blank_adapter,
                &config,
            )
            .await
            .unwrap();
            let DestroyOutcome::Refused(errors) = outcome else {
                panic!("a blank password must refuse, got {outcome:?}");
            };
            assert_eq!(
                errors.get("current_password").map(Vec::as_slice),
                Some(&[":blank".to_string()][..]),
                "blank submission {blank:?} must report :blank"
            );
            assert!(
                blank_adapter
                    .get(&DeviseKey::from_i64(1))
                    .await
                    .unwrap()
                    .is_some(),
                "a refusal must never delete the record"
            );
        }
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

    /// S10: Devise runs the uniqueness check only when the email is changing
    /// (`validates_uniqueness_of :email, if: :devise_will_save_change_to_email?`)
    /// and excludes the record itself. A model that does not override
    /// `uniqueness_scope_id` must not reject its own untouched update with
    /// `:taken`, which the `existing_id.is_none() || existing_id != self.id`
    /// shape did for every defaulted accessor.
    #[tokio::test]
    async fn validatable_uniqueness_self_exclusion_without_scope_override() {
        let config = test_config();
        let adapter = MemoryAdapter::<TestUser>::new();
        let stored = TestUser::testing("test@example.com", &config);
        adapter.create(stored.clone()).await.unwrap();

        // A record updating its own unchanged email finds ITSELF: no :taken.
        // `uniqueness_scope_id: None` models the models that never override the
        // accessor - the trait default that used to flag every self-update.
        let self_update = TestUser {
            uniqueness_scope_id: None,
            ..stored.clone()
        };
        let mut errors = ValidationErrors::new();
        Validatable::validate_email_uniqueness(&self_update, &adapter, &mut errors).await;
        assert!(
            errors.is_empty(),
            "an unchanged-email update must not be :taken: {errors:?}"
        );

        // A DIFFERENT record holding the same email is still :taken.
        let other = TestUser {
            id: 2,
            uniqueness_scope_id: None,
            ..stored.clone()
        };
        let mut errors = ValidationErrors::new();
        Validatable::validate_email_uniqueness(&other, &adapter, &mut errors).await;
        assert_eq!(
            errors.get("email").map(Vec::as_slice),
            Some(&[":taken".to_string()][..]),
            "a second record with the same address is :taken"
        );

        // A new record with the taken email is :taken.
        let fresh = TestUser {
            id: 0,
            email: "test@example.com".to_string(),
            password: Some("secret123".to_string()),
            ..TestUser::default()
        };
        let mut errors = ValidationErrors::new();
        Validatable::validate_email_uniqueness(&fresh, &adapter, &mut errors).await;
        assert_eq!(
            errors.get("email").map(Vec::as_slice),
            Some(&[":taken".to_string()][..]),
            "a new record with a taken address is :taken"
        );
    }

    /// M3: Devise's `find_or_initialize_with_errors`
    /// (`authenticatable.rb:277-292`) slices the submitted conditions to the
    /// required attributes, drops blank values, and runs the lookup ONLY when
    /// every required key survived. A partial key set must never reach the
    /// adapter (a permissive "partial conditions match" backend would revive
    /// an arbitrary record), and the missing keys report Devise's `:blank`,
    /// not the caller's error.
    #[tokio::test]
    async fn find_or_initialize_with_errors_partial_keys_skip_the_lookup() {
        let config = test_config();
        let inner = MemoryAdapter::<TestUser>::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let adapter = CountingAdapter {
            inner: &inner,
            calls: Arc::clone(&calls),
            fail_reads: false,
        };
        adapter
            .create(TestUser::testing("secret123", &config))
            .await
            .unwrap();
        let calls_after_seed = calls.load(Ordering::SeqCst);

        let required = ["email", "username"];
        let mut conditions = Conditions::new();
        conditions.insert(
            "email",
            AdapterValue::String("test@example.com".to_string()),
        );

        let resource = TestUser::find_or_initialize_with_errors(
            &required,
            &conditions,
            ":not_found",
            &adapter,
            &config,
        )
        .await;

        assert_eq!(
            calls.load(Ordering::SeqCst),
            calls_after_seed,
            "a partial key set must not reach the adapter"
        );
        assert_eq!(
            resource.errors.get("username").map(Vec::as_slice),
            Some(&[":blank".to_string()][..]),
            "the missing key is :blank, not the caller error: {:?}",
            resource.errors
        );
        assert_eq!(
            resource.errors.get("email").map(Vec::as_slice),
            Some(&[":not_found".to_string()][..]),
            "a present-but-unmatched key keeps the caller error"
        );
        assert!(!resource.record.persisted());
    }

    /// M3: every required key blank (or absent) still performs no lookup and
    /// reports `:blank` per key.
    #[tokio::test]
    async fn find_or_initialize_with_errors_all_blank_keys_skip_the_lookup() {
        let config = test_config();
        let inner = MemoryAdapter::<TestUser>::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let adapter = CountingAdapter {
            inner: &inner,
            calls: Arc::clone(&calls),
            fail_reads: false,
        };
        adapter
            .create(TestUser::testing("secret123", &config))
            .await
            .unwrap();
        let calls_after_seed = calls.load(Ordering::SeqCst);

        let required = ["email", "username"];
        let mut conditions = Conditions::new();
        conditions.insert("email", AdapterValue::String("   ".to_string()));
        conditions.insert("username", AdapterValue::String(String::new()));
        conditions.insert(
            "admin",
            AdapterValue::String("ignored@example.com".to_string()),
        );

        let resource = TestUser::find_or_initialize_with_errors(
            &required,
            &conditions,
            ":not_found",
            &adapter,
            &config,
        )
        .await;

        assert_eq!(
            calls.load(Ordering::SeqCst),
            calls_after_seed,
            "blank keys must not reach the adapter"
        );
        assert_eq!(
            resource.errors.get("email").map(Vec::as_slice),
            Some(&[":blank".to_string()][..])
        );
        assert_eq!(
            resource.errors.get("username").map(Vec::as_slice),
            Some(&[":blank".to_string()][..])
        );
        assert!(
            resource.errors.get("admin").is_none(),
            "conditions are sliced to the required attributes"
        );
    }

    /// M3: the full key set reaches the adapter, and a miss initializes a
    /// record carrying the caller's error on every required key.
    #[tokio::test]
    async fn find_or_initialize_with_errors_full_keys_lookup_reports_error() {
        let config = test_config();
        let inner = MemoryAdapter::<TestUser>::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let adapter = CountingAdapter {
            inner: &inner,
            calls: Arc::clone(&calls),
            fail_reads: false,
        };
        let stored = TestUser::testing("secret123", &config);
        adapter.create(stored).await.unwrap();
        let calls_after_seed = calls.load(Ordering::SeqCst);

        let required = ["email", "username"];
        let mut conditions = Conditions::new();
        conditions.insert(
            "email",
            AdapterValue::String("test@example.com".to_string()),
        );
        conditions.insert("username", AdapterValue::String(" tester ".to_string()));

        let miss = TestUser::find_or_initialize_with_errors(
            &required,
            &conditions,
            ":not_found",
            &adapter,
            &config,
        )
        .await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            calls_after_seed + 1,
            "the full key set performs exactly one lookup"
        );
        assert_eq!(
            miss.errors.get("email").map(Vec::as_slice),
            Some(&[":not_found".to_string()][..])
        );
        assert_eq!(
            miss.errors.get("username").map(Vec::as_slice),
            Some(&[":not_found".to_string()][..])
        );

        // A key outside the required list never widens the lookup: the
        // stored record matches on `email` alone only when `username` is
        // absent from the required set.
        let hit = TestUser::find_or_initialize_with_errors(
            &["email"],
            &conditions,
            ":not_found",
            &adapter,
            &config,
        )
        .await;
        assert!(
            hit.is_valid(),
            "one required key that matches finds the record"
        );
        assert_eq!(hit.record.id, 1);
    }

    /// M3: the single-attribute helper delegates to the group form, so a blank
    /// value reports `:blank` without touching the adapter (Devise's
    /// `find_or_initialize_with_error_by` is a thin wrapper).
    #[tokio::test]
    async fn find_or_initialize_with_error_by_blank_reports_blank() {
        let config = test_config();
        let inner = MemoryAdapter::<TestUser>::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let adapter = CountingAdapter {
            inner: &inner,
            calls: Arc::clone(&calls),
            fail_reads: false,
        };
        let calls_after_seed = calls.load(Ordering::SeqCst);

        for blank in ["", "   "] {
            let resource = TestUser::find_or_initialize_with_error_by(
                "email",
                blank,
                ":not_found",
                &adapter,
                &config,
            )
            .await;
            assert_eq!(
                resource.errors.get("email").map(Vec::as_slice),
                Some(&[":blank".to_string()][..]),
                "a blank attribute reports :blank"
            );
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            calls_after_seed,
            "blank attributes never reach the adapter"
        );
    }

    /// S10: the email-change gate. Devise skips the uniqueness lookup entirely
    /// when the email is not changing, so a model that tracks its original
    /// address (overriding [`Validatable::email_changed`]) performs ZERO
    /// adapter lookups on a non-email update.
    #[tokio::test]
    async fn validatable_uniqueness_is_gated_on_the_email_change() {
        let config = test_config();
        let inner = MemoryAdapter::<TestUser>::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let adapter = CountingAdapter {
            inner: &inner,
            calls: Arc::clone(&calls),
            fail_reads: false,
        };
        let stored = TestUser::testing("gate@example.com", &config);
        adapter.create(stored.clone()).await.unwrap();
        let calls_after_seed = calls.load(Ordering::SeqCst);

        let gate = TestUser {
            id: 3,
            email: "gate@example.com".to_string(),
            email_changed_override: Some(false),
            ..TestUser::default()
        };
        let mut errors = ValidationErrors::new();
        Validatable::validate_email_uniqueness(&gate, &adapter, &mut errors).await;
        assert!(errors.is_empty());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            calls_after_seed,
            "an unchanged email must not run the uniqueness lookup"
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

    /// Devise's `password_length` bounds are configurable and pinned by the
    /// Ruby suite at `validatable_test.rb:83` and `:89`: with a 7..72 range a
    /// 5-char password is `:too_short`, a 73-char one `:too_long`, and both
    /// bounds themselves pass (Ruby ranges are inclusive on both ends).
    #[test]
    fn validatable_custom_password_length_bounds() {
        let config = DeviseConfig {
            password_length: 7..72,
            ..test_config()
        };
        for (len, expected) in [(5usize, Some(":too_short")), (73, Some(":too_long"))] {
            let user = TestUser {
                email: "bounds@example.com".to_string(),
                password: Some("x".repeat(len)),
                password_confirmation: Some("x".repeat(len)),
                ..TestUser::default()
            };
            let errors = Validatable::validate(&user, &config);
            let keys: Vec<String> = errors.get("password").cloned().unwrap_or_default();
            assert_eq!(
                keys,
                expected.map_or_else(Vec::new, |key| vec![key.to_string()]),
                "length {len} against the 7..72 range"
            );
        }
        for len in [7usize, 72] {
            let user = TestUser {
                email: "bounds@example.com".to_string(),
                password: Some("x".repeat(len)),
                password_confirmation: Some("x".repeat(len)),
                ..TestUser::default()
            };
            let errors = Validatable::validate(&user, &config);
            assert!(errors.is_empty(), "length {len} must pass: {errors:?}");
        }
    }

    /// `validatable.rb:37-39` plus `validatable_test.rb:75-81` and `:95-103`:
    /// `validates_confirmation_of` compares the RAW values (Rails reads a
    /// missing password as the empty string), so a persisted record with a
    /// blank password and a present confirmation reports BOTH the presence
    /// `:blank` on `password` and the `:confirmation` on
    /// `password_confirmation`, and never a length error (`allow_blank: true`
    /// keeps the length validation away from a blank password).
    #[test]
    fn validatable_blank_password_with_confirmation_errors_both() {
        let config = test_config();
        let mut user = TestUser::testing("secret123", &config);
        user.password = None;
        user.password_confirmation = Some("confirmation".to_string());

        assert!(
            Validatable::password_required(&user),
            "the present confirmation keeps the password required (Devise `password_required?` reads the confirmation too)"
        );
        let errors = Validatable::validate(&user, &config);
        assert_eq!(
            errors.get("password").map(Vec::as_slice),
            Some(&[":blank".to_string()][..])
        );
        assert_eq!(
            errors.get("password_confirmation").map(Vec::as_slice),
            Some(&[":confirmation".to_string()][..])
        );
        assert!(
            !errors.get("password").is_some_and(|keys| keys
                .iter()
                .any(|key| key == ":too_short" || key == ":too_long")),
            "a blank password never draws a length error: {errors:?}"
        );
    }

    /// `validatable_test.rb:105` (`should complain about length even if
    /// password is not required`) pins that `validates_length_of` carries
    /// `allow_blank: true` and NO `password_required?` gate: the fixture knob
    /// forces the record into the not-required state and the length error
    /// still fires, while the gated `:blank`/`:confirmation` errors stay away.
    #[test]
    fn validatable_length_not_gated_on_password_required() {
        let config = DeviseConfig {
            password_length: 7..72,
            ..test_config()
        };
        let user = TestUser {
            email: "gated@example.com".to_string(),
            password: Some("x".repeat(73)),
            password_confirmation: Some("x".repeat(73)),
            password_required_override: Some(false),
            ..TestUser::default()
        };
        let errors = Validatable::validate(&user, &config);
        assert_eq!(
            errors.get("password").map(Vec::as_slice),
            Some(&[":too_long".to_string()][..])
        );
        assert!(
            errors.get("password_confirmation").is_none(),
            "the confirmation validation is gated on password_required: {errors:?}"
        );
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
        // Devise parity (`recoverable.rb:148`): the raw token is restored on
        // the FAILURE branch only; a successful reset nil'd the column.
        assert_eq!(outcome.record.raw_reset_password_token(), None);

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
            Some(&[":invalid".to_string()][..])
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
        // Devise parity (`recoverable.rb:148`): success does NOT restore the
        // raw token (the column is cleared); restoration is failure-branch.
        assert_eq!(outcome.record.raw_reset_password_token(), None);

        // Mismatched confirmation surfaces :confirmation (validation path).
        // Devise restores the raw token on this failure branch so the
        // re-rendered form keeps the user's token (`recoverable.rb:148`).
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
        assert_eq!(
            outcome.record.raw_reset_password_token(),
            Some(raw.as_str()),
            "failed reset must keep the raw token for the re-rendered form"
        );

        // RCV-02 switch: sign_in_after_reset_password reads config (Warden-side
        // sign-in itself is the controller/integration layer).
        let saved = adapter.get(&DeviseKey::from_i64(1)).await.unwrap().unwrap();
        assert!(Recoverable::sign_in_after_reset_password(&saved, &config));
        let config_off = DeviseConfig {
            stretches: 4,
            sign_in_after_reset_password: false,
            ..DeviseConfig::default()
        };
        assert!(!Recoverable::sign_in_after_reset_password(
            &saved,
            &config_off
        ));
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

    #[test]
    fn test_gate_chain_confirmable_before_lockable() {
        use crate::scope::Module;

        // Module order pins the registration order (modules.rb): Confirmable
        // sorts below Lockable - and because Ruby's `include` makes the LAST
        // module the outermost super-chain link, Lockable's `inactive_message`
        // wins for an unconfirmed-plus-locked record (`lockable.rb:95-97`).
        assert!(Module::Confirmable < Module::Lockable);
        assert!(Module::Lockable < Module::Timeoutable);
        assert!(Module::Timeoutable < Module::Trackable);
        let mut ordered = vec![Module::Lockable, Module::Confirmable];
        ordered.sort();
        assert_eq!(ordered, vec![Module::Confirmable, Module::Lockable]);

        // Composition truth table through the chain fns.
        assert!(chain_active_for_authentication(true, true));
        assert!(!chain_active_for_authentication(false, true));
        assert!(!chain_active_for_authentication(true, false));
        assert!(!chain_active_for_authentication(false, false));

        // Outermost-link message wins: locked before unconfirmed (lockable
        // is included after confirmable, so `access_locked?` answers first).
        assert_eq!(
            chain_inactive_message(Some("unconfirmed"), Some("locked")),
            "locked"
        );
        assert_eq!(
            chain_inactive_message(Some("unconfirmed"), None),
            "unconfirmed"
        );
        assert_eq!(chain_inactive_message(None, Some("locked")), "locked");
        assert_eq!(chain_inactive_message(None, None), "inactive");
    }
}
