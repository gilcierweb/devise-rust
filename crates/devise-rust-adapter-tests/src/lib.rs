//! Shared data-parameterized `OrmAdapter` contract suite (D-24).
//!
//! The locked behavior list (D-28) lives here ONCE as generic case
//! functions. Every backend (diesel today; sqlx and sea-orm next) and the
//! [`MemoryAdapter`](devise_rust::adapter::memory::MemoryAdapter) oracle
//! (D-29) run the identical cases through a [`ContractFactory`]. The
//! per-backend hand-written suites do not survive the retrofit (D-27): a
//! behavior asserted in only one backend is a portability lie.
//!
//! # Zero waivers (D-30)
//!
//! This crate carries no ignored cases and no backend-conditional
//! assertions. A divergence between legs is a bug fixed at the diverging
//! backend, never a waiver here.
//!
//! # Organization
//!
//! Cases are data-driven: each one builds its rows through
//! [`ContractModel::sample_new`] (the fixture contract below), operates
//! only through the public `OrmAdapter` verbs, and asserts outcomes via
//! the [`ContractModel`] accessors. Every case calls
//! [`ContractFactory::adapter`] once and works inside its own email
//! namespace, so a case never observes another case's rows: sqlite rigs
//! hand out a fresh `:memory:` pool per case, the pg rig shares one
//! container database where the per-case namespaces keep rows disjoint,
//! and the oracle starts from an empty store.
//!
//! # Fixture contract
//!
//! [`ContractModel::sample_new`] must produce, for `email` stamped at
//! `now`, exactly: `encrypted_password` `bcrypt-digest`,
//! `reset_password_token`/`confirmation_token`/`unlock_token` as
//! `enc-reset-`/`enc-confirm-`/`enc-unlock-` prefixed with the email,
//! both `*_sent_at` timestamps `Some(now)`, `unconfirmed_email` `None`,
//! both counters `0`, `locked_at` `None`, and
//! `created_at`/`updated_at` `now`. The full-column assertions in
//! [`crud_roundtrip_case`] pin this shape; a leg that drifts fails loudly
//! there.

use chrono::NaiveDateTime;
use devise_rust::adapter::{ChangeSet, Conditions, DeviseKey, OrmAdapter, OrmError, Value};
use std::collections::HashMap;
use std::fmt::Debug;

/// Backend-neutral row accessors the generic cases assert through.
///
/// Each leg implements this for its model type (diesel `FixtureUser`, the
/// oracle fixture, future sqlx/sea-orm models); the identical case fns
/// then run unchanged against every adapter.
pub trait ContractModel: Sized + Send + Sync + Debug + PartialEq + 'static {
    /// The adapter's insert shape ([`OrmAdapter::New`]).
    type New: Send + Sync + 'static;

    /// Full sample insert shape for `email` stamped at `now`
    /// (see the fixture contract in the crate docs).
    fn sample_new(email: &str, now: NaiveDateTime) -> Self::New;

    /// The row's authentication key value.
    fn contract_email(&self) -> &str;

    /// The row's bcrypt digest column (salt source and password-change
    /// notification trigger).
    fn contract_encrypted_password(&self) -> &str;

    /// The row's recoverable token digest, `None` when cleared.
    fn contract_reset_password_token(&self) -> Option<&str>;

    /// When the reset token was sent.
    fn contract_reset_password_sent_at(&self) -> Option<NaiveDateTime>;

    /// The row's confirmable token digest, `None` when cleared.
    fn contract_confirmation_token(&self) -> Option<&str>;

    /// When the confirmation token was sent.
    fn contract_confirmation_sent_at(&self) -> Option<NaiveDateTime>;

    /// The row's reconfirmable pending email, `None` when unset.
    fn contract_unconfirmed_email(&self) -> Option<&str>;

    /// The row's lockable attempt counter.
    fn contract_failed_attempts(&self) -> i64;

    /// The row's trackable visit counter.
    fn contract_sign_in_count(&self) -> i64;

    /// The row's lockable token digest, `None` when cleared.
    fn contract_unlock_token(&self) -> Option<&str>;

    /// When the account was locked, `None` when unlocked.
    fn contract_locked_at(&self) -> Option<NaiveDateTime>;

    /// Rails timestamp: row creation time.
    fn contract_created_at(&self) -> NaiveDateTime;

    /// Rails timestamp: last update time.
    fn contract_updated_at(&self) -> NaiveDateTime;
}

/// A leg's adapter factory: how the shared runner reaches one backend.
///
/// Implement this per backend-and-PK-shape leg (sqlite i64, sqlite uuid,
/// pg i64, pg uuid, oracle); the identical cases then run against the
/// leg's adapter (D-24/D-26).
pub trait ContractFactory: Send + Sync {
    /// The model the cases read and assert through.
    type Model: ContractModel;

    /// The adapter under test.
    type Adapter: OrmAdapter<Self::Model, New = <Self::Model as ContractModel>::New>;

    /// Builds a fresh adapter over this leg's storage. Rigs that can
    /// isolate per case (sqlite `:memory:`, the oracle store) hand out a
    /// truly fresh adapter; rigs that share storage (the testcontainers
    /// pg database) return a new adapter over the shared store, and the
    /// per-case email namespaces keep the cases disjoint.
    fn adapter(&self) -> impl std::future::Future<Output = Self::Adapter>;

    /// Names the storage key the adapter assigned to `row` on create.
    ///
    /// Database backends echo the key in the created row; the oracle
    /// assigns sequential integer keys on a fresh store (the case's
    /// tracked row is always the first create in its store).
    fn key_of_created(&self, row: &Self::Model) -> DeviseKey;

    /// A key no row of this leg ever stores under (miss assertions).
    fn missing_key(&self) -> DeviseKey;
}

/// Fixed sample timestamp (`2026-01-02 03:04:05`) for deterministic
/// fixtures (diesel rig precedent).
///
/// # Panics
///
/// Panics when the constant fails to parse (a static-configuration bug).
#[must_use]
pub fn sample_time() -> NaiveDateTime {
    NaiveDateTime::parse_from_str("2026-01-02 03:04:05", "%Y-%m-%d %H:%M:%S")
        .expect("fixed sample time parses")
}

/// A second fixed timestamp, distinct from [`sample_time`], in the ISO
/// 8601 `T` form every leg accepts as a `Value::String` timestamp write
/// (the diesel changeset bridge parses both spellings; chrono's serde
/// bridge requires this one).
///
/// # Panics
///
/// Panics when the constant fails to parse (a static-configuration bug).
#[must_use]
pub fn later_time() -> NaiveDateTime {
    NaiveDateTime::parse_from_str(later_time_iso(), "%Y-%m-%dT%H:%M:%S")
        .expect("fixed later time parses")
}

/// The [`later_time`] instant in ISO 8601 `T` form, the string spelling
/// the cases use when writing a timestamp column through
/// [`OrmAdapter::update_columns`].
#[must_use]
pub fn later_time_iso() -> &'static str {
    "2026-06-07T08:09:10"
}

/// Asserts the full sample-row contract (see the crate docs) on `row`.
fn assert_full_sample_row<M: ContractModel>(row: &M, email: &str, now: NaiveDateTime) {
    let expected_reset = format!("enc-reset-{email}");
    let expected_confirm = format!("enc-confirm-{email}");
    let expected_unlock = format!("enc-unlock-{email}");
    assert_eq!(row.contract_email(), email);
    assert_eq!(row.contract_encrypted_password(), "bcrypt-digest");
    assert_eq!(
        row.contract_reset_password_token(),
        Some(expected_reset.as_str())
    );
    assert_eq!(row.contract_reset_password_sent_at(), Some(now));
    assert_eq!(
        row.contract_confirmation_token(),
        Some(expected_confirm.as_str())
    );
    assert_eq!(row.contract_confirmation_sent_at(), Some(now));
    assert_eq!(row.contract_unconfirmed_email(), None);
    assert_eq!(row.contract_failed_attempts(), 0);
    assert_eq!(row.contract_sign_in_count(), 0);
    assert_eq!(row.contract_unlock_token(), Some(expected_unlock.as_str()));
    assert_eq!(row.contract_locked_at(), None);
    assert_eq!(row.contract_created_at(), now);
    assert_eq!(row.contract_updated_at(), now);
}

/// CRUD round-trip: `create` stores every devise column, the `insert`
/// alias stores a second row, `get`/`get_strict` hit and miss,
/// `find_first` resolves by authentication key and refuses absence, a
/// diff-scoped `update` preserves untouched columns, and `delete` removes
/// the row (a second delete is a no-op).
///
/// # Panics
///
/// Panics when any contract assertion fails; case fns are the assertion
/// mechanism (see the crate docs).
pub async fn crud_roundtrip_case<F: ContractFactory>(factory: &F) {
    let adapter = factory.adapter().await;
    let now = sample_time();
    let email = "crud-tracer@example.test";

    let created = adapter
        .create(<F::Model as ContractModel>::sample_new(email, now))
        .await
        .expect("create stores the row");
    assert_full_sample_row(&created, email, now);
    let key = factory.key_of_created(&created);

    let second_email = "crud-second@example.test";
    let second = adapter
        .insert(<F::Model as ContractModel>::sample_new(second_email, now))
        .await
        .expect("insert alias stores the row");
    assert_full_sample_row(&second, second_email, now);

    crud_read_find_steps(&adapter, factory, email, &key).await;
    crud_update_delete_steps(&adapter, email, &key, &created).await;
}

/// `get`/`get_strict` hit and miss, plus `find_first` by authentication
/// key with strict refusal of absence (the CRUD case's read half).
async fn crud_read_find_steps<F: ContractFactory>(
    adapter: &F::Adapter,
    factory: &F,
    email: &str,
    key: &DeviseKey,
) {
    let found = adapter.get(key).await.expect("get works");
    assert_eq!(
        found.as_ref().map(ContractModel::contract_email),
        Some(email)
    );
    let strict = adapter.get_strict(key).await.expect("get_strict hits");
    assert_eq!(strict.contract_email(), email);

    let missing = factory.missing_key();
    assert_eq!(
        adapter.get(&missing).await.expect("get miss works"),
        None,
        "get on a missing key is Ok(None), never an error"
    );
    assert!(
        matches!(
            adapter.get_strict(&missing).await.unwrap_err(),
            OrmError::NotFound
        ),
        "get_strict must refuse absence"
    );

    let mut by_email = Conditions::new();
    by_email.insert("email", email);
    let found_by_email = adapter
        .find_first(&by_email)
        .await
        .expect("email finder works");
    assert_eq!(
        found_by_email.as_ref().map(ContractModel::contract_email),
        Some(email)
    );
    assert_eq!(
        adapter
            .find_first_strict(&by_email)
            .await
            .expect("strict email finder hits")
            .contract_email(),
        email,
        "strict hit matches finder hit"
    );

    let mut nobody = Conditions::new();
    nobody.insert("email", "crud-nobody@example.test");
    assert_eq!(
        adapter
            .find_first(&nobody)
            .await
            .expect("finder miss works"),
        None
    );
    assert!(
        matches!(
            adapter.find_first_strict(&nobody).await.unwrap_err(),
            OrmError::NotFound
        ),
        "find_first_strict must refuse absence"
    );
}

/// A diff-scoped `update` preserving untouched columns, then `delete`
/// with a no-op second delete (the CRUD case's write half).
async fn crud_update_delete_steps<A, M>(adapter: &A, email: &str, key: &DeviseKey, created: &M)
where
    A: OrmAdapter<M, New = <M as ContractModel>::New>,
    M: ContractModel,
{
    let token_digest = created
        .contract_reset_password_token()
        .expect("sample sets a reset token")
        .to_owned();
    let changes = ChangeSet::new(
        HashMap::from([
            ("email".to_owned(), Value::from(email)),
            (
                "reset_password_token".to_owned(),
                Value::from(token_digest.as_str()),
            ),
        ]),
        HashMap::from([
            ("email".to_owned(), Value::from("crud-renamed@example.test")),
            (
                "reset_password_token".to_owned(),
                Value::from(token_digest.as_str()),
            ),
        ]),
    );
    let updated = adapter.update(key, &changes).await.expect("update works");
    assert_eq!(updated.contract_email(), "crud-renamed@example.test");
    assert_eq!(
        updated.contract_reset_password_token(),
        Some(token_digest.as_str()),
        "untouched token column is preserved by a diff-scoped update"
    );

    adapter.delete(key).await.expect("delete works");
    assert_eq!(
        adapter.get(key).await.expect("get works"),
        None,
        "deleted row reads back None"
    );
    adapter
        .delete(key)
        .await
        .expect("deleting a missing row is a no-op");
}

/// Runs every shared contract case against one leg's factory.
///
/// # Panics
///
/// Panics when any included case fails; the runner is the assertion
/// entry point for backend integration tests (see the crate docs).
pub async fn run_contract_suite<F: ContractFactory>(factory: &F) {
    crud_roundtrip_case(factory).await;
}
