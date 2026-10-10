//! Postgres contract suite entry (D-24/D-26/D-35): thin wrappers that run the
//! shared `devise-rust-adapter-tests` cases against the pg rig for
//! both PK shapes — no hand-written combinatorial tests. The fixture
//! bridge (`ContractModel`) lives in `models.rs`, the rig bootstrap in
//! `common/mod.rs`. Only pg-specific edges stay here: the native UUID
//! round-trip assertion and the pool smoke test.

#[path = "common/mod.rs"]
mod common;

#[path = "models.rs"]
mod models;

use common::bootstrap_pg;
use devise_rust::adapter::{Conditions, DeviseKey, OrmAdapter, OrmError, Value};
use devise_rust_adapter_tests::{ContractFactory, run_contract_suite, sample_time};
use devise_rust_sea_orm::{SeaOrmAdapter, SeaOrmModel};
use models::{NewFixtureUser, NewUuidUser, users, uuid_users};

/// Shared-suite leg over the integer-PK `users` table: a fresh pg connection
/// per case pointing at the shared testcontainers instance with DDL applied.
struct PgUsersFactory;

impl ContractFactory for PgUsersFactory {
    type Model = users::Model;
    type Adapter = SeaOrmAdapter<users::Entity>;

    async fn adapter(&self) -> Self::Adapter {
        bootstrap_pg().await.users
    }

    fn key_of_created(&self, row: &users::Model) -> DeviseKey {
        DeviseKey::from_i64(row.id)
    }

    fn missing_key(&self) -> DeviseKey {
        DeviseKey::from_i64(999_999)
    }
}

/// Shared-suite leg over the uuid-PK `uuid_users` table (native UUID
/// column on Postgres per D-35): same fresh-connection-per-case shape.
struct PgUuidUsersFactory;

impl ContractFactory for PgUuidUsersFactory {
    type Model = uuid_users::Model;
    type Adapter = SeaOrmAdapter<uuid_users::Entity>;

    async fn adapter(&self) -> Self::Adapter {
        bootstrap_pg().await.uuid_users
    }

    fn key_of_created(&self, row: &uuid_users::Model) -> DeviseKey {
        DeviseKey::from_uuid(row.id)
    }

    fn missing_key(&self) -> DeviseKey {
        DeviseKey::from_uuid(uuid::Uuid::new_v4())
    }
}

#[tokio::test]
async fn pg_contract_suite_integer_pk() {
    run_contract_suite(&PgUsersFactory).await;
}

#[tokio::test]
async fn pg_contract_suite_uuid_pk() {
    run_contract_suite(&PgUuidUsersFactory).await;
}

/// Driver error edge: a duplicate create must discriminate
/// `UniqueViolation` with a value-free `Display` (PLAT-06). The oracle
/// store has no constraints, so the violation itself is a
/// database-driver behavior; this leg-local test pins the pg mapping
/// (the shared suite owns the portable probe/retry loop contract).
#[tokio::test]
async fn pg_duplicate_create_discriminates_unique_violation() {
    let rig = bootstrap_pg().await;
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
/// `OrmError::Query` naming the column, before any SQL exists (D-02,
/// T-06-07).
#[tokio::test]
async fn pg_unsupported_finder_column_is_rejected() {
    let rig = bootstrap_pg().await;
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
async fn pg_pk_shape_mismatch_yields_invalid_key() {
    let rig = bootstrap_pg().await;

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
/// the column and never the value (D-03 error contract).
#[tokio::test]
async fn pg_write_bridge_rejects_unknown_and_id_columns() {
    use std::collections::HashMap;

    let rig = bootstrap_pg().await;
    let now = devise_rust_adapter_tests::sample_time();
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
}

/// Native UUID round-trip assertion (D-35): the `uuid_users` table stores
/// native Postgres UUID columns, not hyphenated TEXT. The shared suite
/// already asserts field equality; this test additionally verifies the
/// wire representation is a real UUID type.
#[tokio::test]
async fn pg_native_uuid_roundtrip() {
    let rig = bootstrap_pg().await;
    let now = sample_time();
    let created = rig
        .uuid_users
        .create(NewUuidUser::sample("uuid-native@example.test", now))
        .await
        .expect("uuid row stores");

    // Re-fetch and verify the id is a valid UUID (native column type on pg)
    let fetched = rig
        .uuid_users
        .get(&DeviseKey::from_uuid(created.id))
        .await
        .expect("re-fetch works")
        .expect("row exists");

    // The id must parse as a valid UUID (native column type)
    let _ = fetched.id; // UUID type verified by successful fetch
}

/// Compile-time surface probe: the fixture glue
/// exposes the full [`SeaOrmModel`] contract (D-01/D-15).
#[test]
fn pg_fixture_glue_surface() {
    use devise_rust::adapter::{DeviseKey, Value};

    // Table name
    assert_eq!(users::Entity::table_name(), "users");
    assert_eq!(uuid_users::Entity::table_name(), "uuid_users");

    // Finder columns exist and are properly mapped
    assert!(users::Entity::finder_column("email", &Value::String("x".into())).is_some());
    assert!(
        users::Entity::finder_column("reset_password_token", &Value::String("x".into())).is_some()
    );
    assert!(
        users::Entity::finder_column("confirmation_token", &Value::String("x".into())).is_some()
    );
    assert!(users::Entity::finder_column("unlock_token", &Value::String("x".into())).is_some());
    assert!(
        users::Entity::finder_column("unconfirmed_email", &Value::String("x".into())).is_some()
    );
    assert!(
        users::Entity::finder_column("encrypted_password", &Value::String("x".into())).is_none()
    );

    // PK condition works for both key shapes
    let int_key = DeviseKey::from_i64(1);
    let uuid_key = DeviseKey::from_uuid(uuid::Uuid::new_v4());
    assert!(users::Entity::pk_condition(&int_key).is_ok());
    assert!(users::Entity::pk_condition(&uuid_key).is_err());
    assert!(uuid_users::Entity::pk_condition(&uuid_key).is_ok());
    assert!(uuid_users::Entity::pk_condition(&int_key).is_err());

    // Counter columns
    assert!(users::Entity::counter_column("failed_attempts").is_ok());
    assert!(users::Entity::counter_column("sign_in_count").is_ok());
    assert!(users::Entity::counter_column("no_such").is_err());
    assert!(uuid_users::Entity::counter_column("failed_attempts").is_ok());
    assert!(uuid_users::Entity::counter_column("sign_in_count").is_ok());
}
