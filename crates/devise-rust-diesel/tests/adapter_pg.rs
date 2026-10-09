//! Postgres contract suite entry (e2e-pg feature): thin wrappers that run
//! the shared `devise-rust-adapter-tests` cases against the testcontainers
//! Postgres rig for both PK shapes (D-26 matrix closure; the `uuid_users`
//! fixture stores the id hyphenated as TEXT, the documented `diesel_async`
//! `LoadQuery` bound limitation). Only the pg driver error edge stays
//! leg-local. The whole entry serializes on one guard: every test shares
//! the single containerized database.

#![cfg(feature = "e2e-pg")]

#[path = "common/mod.rs"]
mod common;

#[path = "models.rs"]
mod models;

use common::pg::{PgConn, bootstrap_pg};
use devise_rust::adapter::{DeviseKey, OrmAdapter, OrmError};
use devise_rust_adapter_tests::{ContractFactory, run_contract_suite};
use devise_rust_diesel::DieselOrmAdapter;
use diesel::pg::Pg;
use models::{FixtureUser, NewFixtureUser, UuidUser};

/// Serializes every pg test: one shared container database, one DDL apply.
static PG_TEST_SERIALIZER: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Shared-suite leg over the integer-PK `users` table: a fresh pool per
/// case over the shared container database; the per-case email namespaces
/// in the shared suite keep rows disjoint.
struct PgUsersFactory;

impl ContractFactory for PgUsersFactory {
    type Model = FixtureUser;
    type Adapter = DieselOrmAdapter<FixtureUser, Pg, PgConn>;

    async fn adapter(&self) -> Self::Adapter {
        bootstrap_pg().await.users
    }

    fn key_of_created(&self, row: &FixtureUser) -> DeviseKey {
        DeviseKey::from_i64(row.id)
    }

    fn missing_key(&self) -> DeviseKey {
        DeviseKey::from_i64(999_999)
    }
}

/// Shared-suite leg over the uuid-PK `uuid_users` table (hyphenated TEXT
/// id on the pg fixture): same fresh-pool-per-case shape.
struct PgUuidUsersFactory;

impl ContractFactory for PgUuidUsersFactory {
    type Model = UuidUser;
    type Adapter = DieselOrmAdapter<UuidUser, Pg, PgConn>;

    async fn adapter(&self) -> Self::Adapter {
        bootstrap_pg().await.uuid_users
    }

    fn key_of_created(&self, row: &UuidUser) -> DeviseKey {
        DeviseKey::from_uuid(uuid::Uuid::parse_str(&row.id).expect("uuid ids are hyphenated"))
    }

    fn missing_key(&self) -> DeviseKey {
        DeviseKey::from_uuid(uuid::Uuid::new_v4())
    }
}

#[tokio::test]
async fn pg_contract_suite_integer_pk() {
    let _guard = PG_TEST_SERIALIZER.lock().await;
    run_contract_suite(&PgUsersFactory).await;
}

#[tokio::test]
async fn pg_contract_suite_uuid_pk() {
    let _guard = PG_TEST_SERIALIZER.lock().await;
    run_contract_suite(&PgUuidUsersFactory).await;
}

/// Driver error edge: a duplicate create must discriminate
/// `UniqueViolation` with a value-free `Display` (PLAT-06). The oracle
/// store has no constraints, so the violation itself is a database-driver
/// behavior; this leg-local test pins the pg mapping.
#[tokio::test]
async fn pg_duplicate_create_discriminates_unique_violation() {
    let _guard = PG_TEST_SERIALIZER.lock().await;
    let rig = bootstrap_pg().await;
    let now = common::sample_time();
    rig.users
        .create(NewFixtureUser::sample("edge-dup@example.test", now))
        .await
        .expect("first row stores");
    let dupe = rig
        .users
        .create(NewFixtureUser::sample("edge-dup@example.test", now))
        .await
        .unwrap_err();
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
