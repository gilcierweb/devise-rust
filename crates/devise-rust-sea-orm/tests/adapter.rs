//! Sea-orm sqlite contract suite entry (D-24/D-26): thin wrappers that run
//! the shared `devise-rust-adapter-tests` cases against the sqlite rig for
//! both PK shapes — no hand-written combinatorial tests. The fixture bridge
//! ([`ContractModel`]) lives in `models.rs`, the rig bootstrap in
//! `common/mod.rs`. Only sqlite-specific edges stay here: the finder
//! allowlist rejection, the duplicate-create `UniqueViolation`
//! discrimination, the pk shape-mismatch contract, and the write-bridge
//! rejection edges.
//!
//! [`ContractModel`]: devise_rust_adapter_tests::ContractModel

#[path = "common/mod.rs"]
mod common;
#[path = "models.rs"]
mod models;

use devise_rust::adapter::{Conditions, DeviseKey, OrmAdapter, OrmError, Value};
use devise_rust_adapter_tests::{ContractFactory, run_contract_suite, sample_time};
use devise_rust_sea_orm::SeaOrmAdapter;
use models::{NewFixtureUser, NewUuidUser, users, uuid_users};

/// Shared-suite leg over the integer-PK `users` table: a fresh `:memory:`
/// rig per case (pool-of-1, emitted DDL applied).
struct SqliteUsersFactory;

impl ContractFactory for SqliteUsersFactory {
    type Model = users::Model;
    type Adapter = SeaOrmAdapter<users::Entity>;

    async fn adapter(&self) -> Self::Adapter {
        common::bootstrap_sqlite_memory().await.users
    }

    fn key_of_created(&self, row: &users::Model) -> DeviseKey {
        DeviseKey::from_i64(row.id)
    }

    fn missing_key(&self) -> DeviseKey {
        DeviseKey::from_i64(999_999)
    }
}

/// Shared-suite leg over the uuid-PK `uuid_users` table (native UUID on pg,
/// hyphenated `TEXT` on sqlite — D-35): same fresh-rig-per-case shape.
struct SqliteUuidUsersFactory;

impl ContractFactory for SqliteUuidUsersFactory {
    type Model = uuid_users::Model;
    type Adapter = SeaOrmAdapter<uuid_users::Entity>;

    async fn adapter(&self) -> Self::Adapter {
        common::bootstrap_sqlite_memory().await.uuid_users
    }

    fn key_of_created(&self, row: &uuid_users::Model) -> DeviseKey {
        // On sqlite the UUID is stored as TEXT, but sea-orm with-uuid feature
        // returns it as Uuid; convert to DeviseKey::Uuid.
        DeviseKey::from_uuid(row.id)
    }

    fn missing_key(&self) -> DeviseKey {
        DeviseKey::from_uuid(uuid::Uuid::new_v4())
    }
}

/// The full D-28 case list — CRUD, token-digest lookups, uniqueness retry,
/// `ChangeSet` tristate + #5783 force-write, atomic counters, salt reads,
/// change-notification round-trips — on the integer-PK leg.
#[tokio::test]
async fn sqlite_contract_suite_integer_pk() {
    run_contract_suite(&SqliteUsersFactory).await;
}

/// The identical full D-28 case list on the hyphenated-`TEXT` uuid leg.
#[tokio::test]
async fn sqlite_contract_suite_uuid_pk() {
    run_contract_suite(&SqliteUuidUsersFactory).await;
}

/// Driver error edge: a duplicate create must discriminate
/// `UniqueViolation` with a value-free `Display` (T-07-02). The oracle
/// store has no constraints, so the violation itself is a database-driver
/// behavior; this leg-local test pins the sqlite mapping through
/// `DbErr::sql_err()` (the shared suite owns the portable probe/retry loop
/// contract).
#[tokio::test]
async fn sqlite_duplicate_create_discriminates_unique_violation() {
    let rig = common::bootstrap_sqlite_memory().await;
    let now = sample_time();
    rig.users
        .create(NewFixtureUser::sample("edge-dup@example.test", now))
        .await
        .expect("first row stores");
    let dupe = rig
        .users
        .create(NewFixtureUser::sample("edge-dup@example.test", now))
        .await
        .expect_err("a duplicate email violates the unique index");
    assert!(
        matches!(dupe, OrmError::UniqueViolation { .. }),
        "duplicate email must discriminate UniqueViolation, got {dupe:?}"
    );
    let rendered = dupe.to_string();
    assert!(
        !rendered.contains("edge-dup@example.test"),
        "error Display must not leak the value: {rendered}"
    );
}

/// Out-of-set finder columns are rejected with a value-free
/// `OrmError::Query` naming the column, before any SQL exists (D-17,
/// T-07-01).
#[tokio::test]
async fn sqlite_unsupported_finder_column_is_rejected() {
    let rig = common::bootstrap_sqlite_memory().await;
    let mut conditions = Conditions::new();
    conditions.insert("encrypted_password", "digest-value");
    let err = rig
        .users
        .find_first(&conditions)
        .await
        .expect_err("out-of-set finder columns never execute");
    let rendered = err.to_string();
    assert!(
        matches!(err, OrmError::Query { .. }),
        "out-of-set column must yield OrmError::Query, got {rendered}"
    );
    assert!(
        rendered.contains("encrypted_password"),
        "the error must name the column: {rendered}"
    );
    assert!(
        !rendered.contains("digest-value"),
        "the error must not leak the value: {rendered}"
    );
}

/// Primary-key shape mismatches refuse with `OrmError::InvalidKey` naming
/// table and column — never a silent miss (Pitfall 10, D-35).
#[tokio::test]
async fn sqlite_pk_shape_mismatch_yields_invalid_key() {
    let rig = common::bootstrap_sqlite_memory().await;

    let uuid_on_integer = rig
        .users
        .get(&DeviseKey::from_uuid(uuid::Uuid::new_v4()))
        .await
        .expect_err("a uuid key against an integer table must refuse");
    assert!(
        matches!(uuid_on_integer, OrmError::InvalidKey(ref message) if message.contains("users.id")),
        "expected InvalidKey naming users.id, got {uuid_on_integer:?}"
    );

    let integer_on_uuid = rig
        .uuid_users
        .get(&DeviseKey::from_i64(1))
        .await
        .expect_err("an integer key against a uuid table must refuse");
    assert!(
        matches!(integer_on_uuid, OrmError::InvalidKey(ref message) if message.contains("uuid_users.id")),
        "expected InvalidKey naming uuid_users.id, got {integer_on_uuid:?}"
    );
}

/// The write bridge rejects unknown columns and the immutable id, naming
/// the column and never the value (D-16 bridge contract).
#[tokio::test]
async fn sqlite_write_bridge_rejects_unknown_and_id_columns() {
    use std::collections::HashMap;

    let rig = common::bootstrap_sqlite_memory().await;
    let now = sample_time();
    let created = rig
        .users
        .create(NewFixtureUser::sample("bridge-edge@example.test", now))
        .await
        .expect("row stores");
    let key = DeviseKey::from_i64(created.id);

    let unknown = rig
        .users
        .update_columns(
            &key,
            &HashMap::from([("no_such_column".to_owned(), Value::from("x"))]),
        )
        .await
        .expect_err("unknown columns refuse");
    assert!(
        matches!(unknown, OrmError::Query { ref message, .. } if message.contains("no_such_column")),
        "expected Query naming the column, got {unknown:?}"
    );

    let immutable = rig
        .users
        .update_columns(
            &key,
            &HashMap::from([("id".to_owned(), Value::from(42_i64))]),
        )
        .await
        .expect_err("the id column is immutable");
    assert!(
        matches!(immutable, OrmError::Query { ref message, .. } if message.contains("id is immutable")),
        "expected the immutable-id refusal, got {immutable:?}"
    );

    // The same bridge discipline holds on the uuid leg.
    let uuid_created = rig
        .uuid_users
        .create(NewUuidUser::sample("bridge-edge-uuid@example.test", now))
        .await
        .expect("uuid row stores");
    let uuid_key = DeviseKey::from_uuid(uuid_created.id);
    let uuid_unknown = rig
        .uuid_users
        .update_columns(
            &uuid_key,
            &HashMap::from([("no_such_column".to_owned(), Value::from("x"))]),
        )
        .await
        .expect_err("unknown columns refuse on the uuid leg too");
    assert!(
        matches!(uuid_unknown, OrmError::Query { ref message, .. } if message.contains("no_such_column")),
        "expected Query naming the column, got {uuid_unknown:?}"
    );
}
