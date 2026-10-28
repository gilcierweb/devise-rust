//! `Authenticatable` base module - mirrors Devise's `Authenticatable`
//! (`devise/lib/devise/models/authenticatable.rb`): default implementations
//! for validity checks, session serialization, and finders with
//! `ParameterFilter`-style normalization (AUTH-06).
//!
//! This file also carries the three object-safe seams the base module owns
//! in Devise: the credential/attribute normalization helpers (the
//! `ParameterFilter` port), [`PasswordVerifiable`] (the `valid_password?`
//! face), [`DestroyOutcome`] (the `find_or_initialize_with_errors` /
//! `destroy_with_password` outcomes), the confirmable-before-lockable
//! [`Activatable`] gate chain (the `super`-chain order from
//! `devise/lib/devise/models.rb`), and the [`ModelFinder`] /
//! [`AdapterBridge`] finder bridge (the `orm_adapter` port).

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
/// [`update_with_password`](crate::model::database_authenticatable::DatabaseAuthenticatable::update_with_password)
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
    /// WR-06 closure (261026-ghl): a record without an authenticatable salt
    /// (omniauth-only models) deserializes normally - `None` compares as the
    /// empty string under the constant-time compare, matching the core
    /// proxy, the session helpers, and the framework S6 semantics. A PRESENT
    /// salt still must match in both directions.
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
        let current_salt = record.authenticatable_salt().unwrap_or_default();
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
    use crate::adapter::{Conditions, DeviseKey, Value as AdapterValue, memory::MemoryAdapter};
    use crate::model::authenticatable::Authenticatable;
    use crate::model::database_authenticatable::DatabaseAuthenticatable;
    use crate::model::registerable::Registerable;
    use crate::model::test_support::{CountingAdapter, TestUser, test_config};
    use crate::model::validatable::Validatable;
    use serde_json::Value as JsonValue;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

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
    /// WR-06 closure (261026-ghl): a record without an authenticatable salt
    /// (omniauth-only models) deserializes normally from the `""` salt its
    /// `serialize_into_session` persisted — the typed path mirrors the core
    /// proxy and the framework S6 semantics, so None compares as the empty
    /// string under the constant-time compare. A present salt still has to
    /// match in BOTH directions.
    #[tokio::test]
    async fn serialize_from_session_accepts_saltless_records() {
        let config = test_config();
        let adapter = MemoryAdapter::<TestUser>::new();
        let mut saltless = TestUser::testing("secret123", &config);
        saltless.encrypted_password = String::new();
        adapter.create(saltless.clone()).await.unwrap();

        // The stored payload carries the empty salt (session_pair's
        // unwrap_or_default) and fetches back.
        let (key, salt) = saltless.serialize_into_session();
        assert_eq!(salt, "", "a saltless record serializes an empty salt");
        let fetched = TestUser::serialize_from_session(&key, &salt, &adapter)
            .await
            .expect("fetch succeeds");
        assert!(
            fetched.is_some(),
            "a saltless record fetches from the empty-salt payload (WR-06)"
        );

        // None on the record side is NOT acceptance of a present salt.
        let mismatch = TestUser::serialize_from_session(&key, "stored-salt", &adapter)
            .await
            .expect("salt mismatch is not a backend failure");
        assert!(
            mismatch.is_none(),
            "a saltless record fails against a present stored salt"
        );

        // A salted record fails against the empty stored salt (both
        // directions mismatch).
        let mut salted = TestUser::testing("secret123", &config);
        salted.id = 2;
        adapter.create(salted.clone()).await.unwrap();
        let (salted_key, _salted_salt) = salted.serialize_into_session();
        assert_ne!(salted_key, key, "the two fixtures must be distinct rows");
        let mismatch = TestUser::serialize_from_session(&salted_key, "", &adapter)
            .await
            .expect("salt mismatch is not a backend failure");
        assert!(
            mismatch.is_none(),
            "a salted record fails against an empty stored salt"
        );
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
