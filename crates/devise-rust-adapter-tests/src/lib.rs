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

/// Token-digest lookups: `find_first` resolves the row by every curated
/// digest column (`reset_password_token`, `confirmation_token`,
/// `unlock_token`) and by the reconfirmable `unconfirmed_email` after a
/// pending-email write (D-28 digest-lookup list; D-02 finder set).
///
/// # Panics
///
/// Panics when any contract assertion fails; case fns are the assertion
/// mechanism (see the crate docs).
pub async fn token_digest_case<F: ContractFactory>(factory: &F) {
    let adapter = factory.adapter().await;
    let now = sample_time();
    let email = "digest-tracer@example.test";
    let created = adapter
        .create(<F::Model as ContractModel>::sample_new(email, now))
        .await
        .expect("create stores the row");
    let key = factory.key_of_created(&created);

    for column in ["reset_password_token", "confirmation_token", "unlock_token"] {
        let digest = match column {
            "reset_password_token" => created
                .contract_reset_password_token()
                .expect("sample sets a reset digest")
                .to_owned(),
            "confirmation_token" => created
                .contract_confirmation_token()
                .expect("sample sets a confirmation digest")
                .to_owned(),
            _ => created
                .contract_unlock_token()
                .expect("sample sets an unlock digest")
                .to_owned(),
        };
        let mut conditions = Conditions::new();
        conditions.insert(column, digest.as_str());
        let found = adapter
            .find_first(&conditions)
            .await
            .unwrap_or_else(|e| panic!("{column} digest lookup works: {e}"));
        assert_eq!(
            found.as_ref().map(ContractModel::contract_email),
            Some(email),
            "{column} digest lookup resolves the row"
        );
        assert_eq!(
            adapter
                .find_first_strict(&conditions)
                .await
                .expect("strict digest lookup hits")
                .contract_email(),
            email,
            "strict hit matches finder hit on {column}"
        );
    }

    let pending_email = "digest-pending@example.test";
    let stamped = adapter
        .update_columns(
            &key,
            &HashMap::from([("unconfirmed_email".to_owned(), Value::from(pending_email))]),
        )
        .await
        .expect("pending email write works");
    assert_eq!(stamped.contract_unconfirmed_email(), Some(pending_email));
    let mut by_pending = Conditions::new();
    by_pending.insert("unconfirmed_email", pending_email);
    assert_eq!(
        adapter
            .find_first(&by_pending)
            .await
            .expect("pending email lookup works")
            .map(|row| row.contract_email().to_owned()),
        Some(email.to_owned()),
        "unconfirmed_email lookup resolves the row"
    );

    let mut missing = Conditions::new();
    missing.insert("confirmation_token", "enc-confirm-nobody@example.test");
    assert_eq!(
        adapter
            .find_first(&missing)
            .await
            .expect("digest miss works"),
        None
    );
}

/// Uniqueness probe and retry loop (D-28): `column_value_unused` flips
/// false for a stored digest, stays true for fresh values, and a
/// token-generator-style regeneration loop skips the taken candidate and
/// terminates on the next free one (the `crypto::token_generator`
/// `generate_with` shape).
///
/// # Panics
///
/// Panics when any contract assertion fails; case fns are the assertion
/// mechanism (see the crate docs).
pub async fn uniqueness_retry_case<F: ContractFactory>(factory: &F) {
    let adapter = factory.adapter().await;
    let now = sample_time();

    let pioneer_email = "retry-r1@example.test";
    adapter
        .create(<F::Model as ContractModel>::sample_new(pioneer_email, now))
        .await
        .expect("pioneer row stores");
    let pioneer_digest = format!("enc-reset-{pioneer_email}");
    assert!(
        !adapter
            .column_value_unused(
                "reset_password_token",
                &Value::from(pioneer_digest.as_str())
            )
            .await
            .expect("probe works"),
        "a stored digest reports taken"
    );

    let mut attempts = 0;
    let winner_email = loop {
        attempts += 1;
        assert!(attempts <= 8, "uniqueness retry loop must terminate");
        let candidate = format!("retry-r{attempts}@example.test");
        let candidate_digest = format!("enc-reset-{candidate}");
        if adapter
            .column_value_unused(
                "reset_password_token",
                &Value::from(candidate_digest.as_str()),
            )
            .await
            .expect("probe works")
        {
            break candidate;
        }
    };
    assert_eq!(
        attempts, 2,
        "the loop must skip the taken candidate and take the next"
    );

    adapter
        .create(<F::Model as ContractModel>::sample_new(&winner_email, now))
        .await
        .expect("winner row stores");
    let winner_digest = format!("enc-reset-{winner_email}");
    assert!(
        !adapter
            .column_value_unused("reset_password_token", &Value::from(winner_digest.as_str()))
            .await
            .expect("probe works"),
        "the freshly created digest flips the probe to taken"
    );
}

/// `ChangeSet` tristate (D-28): absent fields are skipped by a diff-scoped
/// `update`, an explicit `Value::Null` writes `NULL` (devise token
/// clearing), `update_columns` force-writes a named field even when
/// unchanged without moving `updated_at` (devise #5783), naming
/// `updated_at` writes it, and a named `NULL` clears the token column.
///
/// # Panics
///
/// Panics when any contract assertion fails; case fns are the assertion
/// mechanism (see the crate docs).
pub async fn changeset_tristate_case<F: ContractFactory>(factory: &F) {
    let adapter = factory.adapter().await;
    let now = sample_time();
    let email = "tristate-tracer@example.test";
    let created = adapter
        .create(<F::Model as ContractModel>::sample_new(email, now))
        .await
        .expect("create stores the row");
    let key = factory.key_of_created(&created);
    let token_digest = created
        .contract_reset_password_token()
        .expect("sample sets a reset token")
        .to_owned();

    let rename = ChangeSet::new(
        HashMap::from([
            ("email".to_owned(), Value::from(email)),
            (
                "reset_password_token".to_owned(),
                Value::from(token_digest.as_str()),
            ),
        ]),
        HashMap::from([
            (
                "email".to_owned(),
                Value::from("tristate-renamed@example.test"),
            ),
            (
                "reset_password_token".to_owned(),
                Value::from(token_digest.as_str()),
            ),
        ]),
    );
    let renamed = adapter.update(&key, &rename).await.expect("rename works");
    assert_eq!(renamed.contract_email(), "tristate-renamed@example.test");
    assert_eq!(
        renamed.contract_reset_password_token(),
        Some(token_digest.as_str()),
        "an untouched column never enters the diff, so it is preserved"
    );

    let clearing = ChangeSet::new(
        HashMap::from([(
            "reset_password_token".to_owned(),
            Value::from(token_digest.as_str()),
        )]),
        HashMap::from([("reset_password_token".to_owned(), Value::Null)]),
    );
    let cleared = adapter
        .update(&key, &clearing)
        .await
        .expect("clearing works");
    assert_eq!(cleared.contract_reset_password_token(), None);
    let reread = adapter.get_strict(&key).await.expect("row exists");
    assert_eq!(
        reread.contract_reset_password_token(),
        None,
        "Value::Null through update SETs NULL (devise clearing)"
    );

    let before = adapter.get_strict(&key).await.expect("row exists");
    let forced = adapter
        .update_columns(
            &key,
            &HashMap::from([(
                "email".to_owned(),
                Value::from("tristate-renamed@example.test"),
            )]),
        )
        .await
        .expect("force-write works");
    assert_eq!(forced.contract_email(), "tristate-renamed@example.test");
    assert_eq!(
        forced.contract_updated_at(),
        before.contract_updated_at(),
        "update_columns leaves updated_at alone unless named"
    );

    let stamped = adapter
        .update_columns(
            &key,
            &HashMap::from([("updated_at".to_owned(), Value::from(later_time_iso()))]),
        )
        .await
        .expect("naming updated_at writes it");
    assert_eq!(stamped.contract_updated_at(), later_time());

    let nulled = adapter
        .update_columns(
            &key,
            &HashMap::from([("unlock_token".to_owned(), Value::Null)]),
        )
        .await
        .expect("named NULL writes NULL");
    assert_eq!(nulled.contract_unlock_token(), None);
    let reread = adapter.get_strict(&key).await.expect("row exists");
    assert_eq!(reread.contract_unlock_token(), None);
}

/// Atomic counters (D-28, D-11): two sequential `increment_counter` calls
/// raise the stored counter by exactly 2, the two counter columns
/// increment independently, an out-of-set column refuses with a
/// value-free `OrmError::Query` naming the column without touching
/// storage, and a missing key refuses with `NotFound`.
///
/// # Panics
///
/// Panics when any contract assertion fails; case fns are the assertion
/// mechanism (see the crate docs).
pub async fn counter_case<F: ContractFactory>(factory: &F) {
    let adapter = factory.adapter().await;
    let now = sample_time();
    let created = adapter
        .create(<F::Model as ContractModel>::sample_new(
            "counter-tracer@example.test",
            now,
        ))
        .await
        .expect("create stores the row");
    let key = factory.key_of_created(&created);
    assert_eq!(created.contract_failed_attempts(), 0);
    assert_eq!(created.contract_sign_in_count(), 0);

    let bumped = adapter
        .increment_counter(&key, "failed_attempts")
        .await
        .expect("first failed_attempts increment works");
    assert_eq!(bumped.contract_failed_attempts(), 1);
    let locked = adapter
        .increment_counter(&key, "failed_attempts")
        .await
        .expect("second failed_attempts increment works");
    assert_eq!(
        locked.contract_failed_attempts(),
        2,
        "two increments raise the stored counter by exactly 2"
    );
    assert_eq!(
        locked.contract_sign_in_count(),
        0,
        "counter columns increment independently"
    );

    let tracked = adapter
        .increment_counter(&key, "sign_in_count")
        .await
        .expect("first sign_in_count increment works");
    assert_eq!(tracked.contract_sign_in_count(), 1);
    let revisits = adapter
        .increment_counter(&key, "sign_in_count")
        .await
        .expect("second sign_in_count increment works");
    assert_eq!(
        revisits.contract_sign_in_count(),
        2,
        "two increments raise the stored counter by exactly 2"
    );
    assert_eq!(
        revisits.contract_failed_attempts(),
        2,
        "counter columns increment independently"
    );

    let err = adapter
        .increment_counter(&key, "locked_at")
        .await
        .unwrap_err();
    let rendered = err.to_string();
    assert!(
        rendered.contains("locked_at"),
        "the error must name the column: {rendered}"
    );
    assert!(
        !rendered.contains('@'),
        "the error must not leak record values: {rendered}"
    );
    assert!(
        matches!(err, OrmError::Query { .. }),
        "out-of-set column must yield OrmError::Query, got {rendered}"
    );
    let untouched = adapter.get_strict(&key).await.expect("row exists");
    assert_eq!(
        untouched.contract_failed_attempts(),
        2,
        "a rejected increment never reaches the database"
    );

    let missing = factory.missing_key();
    assert!(
        matches!(
            adapter
                .increment_counter(&missing, "failed_attempts")
                .await
                .unwrap_err(),
            OrmError::NotFound
        ),
        "increment on a missing key must refuse with NotFound"
    );
}

/// Salt-invalidation reads (D-28): rewriting `encrypted_password` through
/// `update_columns` changes what a fresh read returns, so the session salt
/// (`authenticatable_salt`, the digest prefix) changes and old sessions
/// invalidate on password rotation.
///
/// # Panics
///
/// Panics when any contract assertion fails; case fns are the assertion
/// mechanism (see the crate docs).
pub async fn salt_invalidation_case<F: ContractFactory>(factory: &F) {
    let adapter = factory.adapter().await;
    let now = sample_time();
    let created = adapter
        .create(<F::Model as ContractModel>::sample_new(
            "salt-tracer@example.test",
            now,
        ))
        .await
        .expect("create stores the row");
    let key = factory.key_of_created(&created);
    let old_digest = created.contract_encrypted_password().to_owned();

    let rewritten = adapter
        .update_columns(
            &key,
            &HashMap::from([(
                "encrypted_password".to_owned(),
                Value::from("bcrypt-rotated-digest"),
            )]),
        )
        .await
        .expect("password rewrite works");
    assert_eq!(
        rewritten.contract_encrypted_password(),
        "bcrypt-rotated-digest"
    );
    let reread = adapter.get_strict(&key).await.expect("row exists");
    assert_eq!(
        reread.contract_encrypted_password(),
        "bcrypt-rotated-digest",
        "a fresh read observes the rotated digest"
    );
    assert_ne!(
        reread.contract_encrypted_password(),
        old_digest.as_str(),
        "the salt source must change on password rotation"
    );
}

/// Change-notification hook point (D-28): the model-layer notifications
/// (`send_email_changed_notification`, `send_password_change_notification`)
/// observe exactly the `email` and `encrypted_password` columns, so the
/// adapter-level contract is that both trigger columns round-trip through
/// `update_columns` and a fresh read observes them. The notification
/// dispatch itself lives in the model modules, not the adapter.
///
/// # Panics
///
/// Panics when any contract assertion fails; case fns are the assertion
/// mechanism (see the crate docs).
pub async fn change_notification_case<F: ContractFactory>(factory: &F) {
    let adapter = factory.adapter().await;
    let now = sample_time();
    let created = adapter
        .create(<F::Model as ContractModel>::sample_new(
            "notify-tracer@example.test",
            now,
        ))
        .await
        .expect("create stores the row");
    let key = factory.key_of_created(&created);

    let renamed = adapter
        .update_columns(
            &key,
            &HashMap::from([("email".to_owned(), Value::from("notify-new@example.test"))]),
        )
        .await
        .expect("email trigger column writes");
    assert_eq!(renamed.contract_email(), "notify-new@example.test");

    let reworded = adapter
        .update_columns(
            &key,
            &HashMap::from([(
                "encrypted_password".to_owned(),
                Value::from("bcrypt-notified-digest"),
            )]),
        )
        .await
        .expect("password trigger column writes");
    assert_eq!(
        reworded.contract_encrypted_password(),
        "bcrypt-notified-digest"
    );

    let reread = adapter.get_strict(&key).await.expect("row exists");
    assert_eq!(reread.contract_email(), "notify-new@example.test");
    assert_eq!(
        reread.contract_encrypted_password(),
        "bcrypt-notified-digest",
        "a fresh read observes both notification trigger columns"
    );
}

/// Runs every shared contract case against one leg's factory.
///
/// # Panics
///
/// Panics when any included case fails; the runner is the assertion
/// entry point for backend integration tests (see the crate docs).
pub async fn run_contract_suite<F: ContractFactory>(factory: &F) {
    crud_roundtrip_case(factory).await;
    token_digest_case(factory).await;
    uniqueness_retry_case(factory).await;
    changeset_tristate_case(factory).await;
    counter_case(factory).await;
    salt_invalidation_case(factory).await;
    change_notification_case(factory).await;
}
