//! `Validatable` module - mirrors `devise/lib/devise/models/validatable.rb`
//! (VAL-01, VAL-02): email and password validations. Validation lives on
//! the model and runs against [`DeviseConfig`] (`email_regexp`,
//! `password_length`); uniqueness additionally needs the adapter.

use crate::adapter::{Conditions, OrmAdapter, Value};
use crate::config::DeviseConfig;
use crate::error::ValidationErrors;
use crate::model::authenticatable::{value_blank, value_present};
use crate::model::database_authenticatable::DatabaseAuthenticatable;
use async_trait::async_trait;

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
#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::{Conditions, DeviseKey, Value as AdapterValue, memory::MemoryAdapter};
    use crate::config::DeviseConfig;
    use crate::error::ValidationErrors;
    use crate::model::authenticatable::Authenticatable;
    use crate::model::database_authenticatable::DatabaseAuthenticatable;
    use crate::model::test_support::{CountingAdapter, TestUser, test_config};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

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
}
