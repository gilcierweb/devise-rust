//! `DatabaseAuthenticatable` module - mirrors
//! `devise/lib/devise/models/database_authenticatable.rb` (DBAU-01..10):
//! password handling over `encrypted_password` with the virtual
//! `password` / `password_confirmation` pair.

use crate::adapter::{Conditions, OrmAdapter};
use crate::config::DeviseConfig;
use crate::error::ValidationErrors;
use crate::model::authenticatable::{
    Authenticatable, DestroyOutcome, normalize_attribute_map, value_blank, value_present,
};
use async_trait::async_trait;
use serde_json::Value as JsonValue;

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
    /// (`value_blank`, the single home of Devise's `String#present?` rule):
    /// Ruby's `current_password.blank?` is `true` for
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::{Conditions, DeviseKey, Value as AdapterValue, memory::MemoryAdapter};
    use crate::config::DeviseConfig;
    use crate::model::database_authenticatable::DatabaseAuthenticatable;
    use crate::model::recoverable::Recoverable;
    use crate::model::test_support::{TestUser, test_config};
    use crate::model::validatable::Validatable;
    use serde_json::Value as JsonValue;

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
}
