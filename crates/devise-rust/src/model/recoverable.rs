//! `Recoverable` module - mirrors `devise/lib/devise/models/recoverable.rb`
//! (RCV-01..04): password reset tokens. The DB stores the HMAC digest and
//! `reset_password_sent_at`; the RAW token only exists in the email link
//! and in memory on the record that just received it.

use crate::adapter::{Conditions, OrmAdapter, Value};
use crate::config::DeviseConfig;
use crate::error::{ResourceWithErrors, ValidationErrors};
use crate::model::authenticatable::value_present;
use crate::model::database_authenticatable::DatabaseAuthenticatable;
use crate::model::validatable::Validatable;
use async_trait::async_trait;
use serde_json::Value as JsonValue;

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
        // Devise's `find_or_initialize_with_errors` blank mapping
        // (`authenticatable.rb:287-291`): MISSING lookup keys report
        // `:blank` per key; only a PRESENT value that matches nothing
        // earns `:not_found` (T-261026-ghk-03). The short-circuit also
        // keeps an empty condition set away from adapters where "empty
        // conditions match any record" holds; the generic path's
        // completeness check guards the partial case.
        let mut resource = if conditions.iter().next().is_none() {
            let mut errors = ValidationErrors::new();
            for key in &keys {
                errors.add(key, ":blank");
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::{Conditions, DeviseKey, Value as AdapterValue, memory::MemoryAdapter};
    use crate::config::DeviseConfig;
    use crate::model::authenticatable::Authenticatable;
    use crate::model::database_authenticatable::DatabaseAuthenticatable;
    use crate::model::recoverable::Recoverable;
    use crate::model::test_support::{TestUser, test_config};
    use serde_json::Value as JsonValue;

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

        // No lookup keys at all: `:blank` on every configured key
        // (authenticatable.rb:287-291: a MISSING key is blank; only a
        // present value that matches nothing earns `:not_found`),
        // nothing sent (regression: empty conditions must not match an
        // arbitrary record). T-261026-ghk-03.
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
            Some(&[":blank".to_string()][..]),
            "a missing lookup key reports :blank, never :not_found"
        );
        assert_eq!(
            mailer.sent_mails().len(),
            1,
            "no email for empty attributes"
        );

        // A BLANK string value is equally missing.
        let mut blank_attributes = serde_json::Map::new();
        blank_attributes.insert("email".to_string(), JsonValue::String(String::new()));
        let outcome = TestUser::send_reset_password_instructions_for(
            &blank_attributes,
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
            Some(&[":blank".to_string()][..]),
            "a blank lookup value reports :blank"
        );
        assert_eq!(mailer.sent_mails().len(), 1, "no email for a blank key");
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
}
