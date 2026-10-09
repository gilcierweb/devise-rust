//! SQLite contract suite entry (D-27 retrofit): thin wrappers that run the
//! shared `devise-rust-adapter-tests` cases against the sqlite rig for
//! both PK shapes. The per-op step tests this file used to carry live in
//! the shared crate now (D-24); only sqlite-specific edges stay here - the
//! driver error mapping canary and the pool smoke test.

#[path = "common/mod.rs"]
mod common;

#[path = "models.rs"]
mod models;

use chrono::NaiveDateTime;
use common::{SqliteConn, bootstrap_sqlite_memory, sample_time};
use devise_rust::adapter::{DeviseKey, OrmAdapter, OrmError};
use devise_rust_adapter_tests::{ContractFactory, ContractModel, run_contract_suite};
use devise_rust_diesel::DieselOrmAdapter;
use diesel::sqlite::Sqlite;
use models::{FixtureUser, NewFixtureUser, UuidUser};

impl ContractModel for FixtureUser {
    type New = NewFixtureUser;

    fn sample_new(email: &str, now: NaiveDateTime) -> Self::New {
        NewFixtureUser::sample(email, now)
    }

    fn contract_email(&self) -> &str {
        &self.email
    }

    fn contract_encrypted_password(&self) -> &str {
        &self.encrypted_password
    }

    fn contract_reset_password_token(&self) -> Option<&str> {
        self.reset_password_token.as_deref()
    }

    fn contract_reset_password_sent_at(&self) -> Option<NaiveDateTime> {
        self.reset_password_sent_at
    }

    fn contract_confirmation_token(&self) -> Option<&str> {
        self.confirmation_token.as_deref()
    }

    fn contract_confirmation_sent_at(&self) -> Option<NaiveDateTime> {
        self.confirmation_sent_at
    }

    fn contract_unconfirmed_email(&self) -> Option<&str> {
        self.unconfirmed_email.as_deref()
    }

    fn contract_failed_attempts(&self) -> i64 {
        i64::from(self.failed_attempts)
    }

    fn contract_sign_in_count(&self) -> i64 {
        i64::from(self.sign_in_count)
    }

    fn contract_unlock_token(&self) -> Option<&str> {
        self.unlock_token.as_deref()
    }

    fn contract_locked_at(&self) -> Option<NaiveDateTime> {
        self.locked_at
    }

    fn contract_created_at(&self) -> NaiveDateTime {
        self.created_at
    }

    fn contract_updated_at(&self) -> NaiveDateTime {
        self.updated_at
    }
}

impl ContractModel for UuidUser {
    type New = models::NewUuidUser;

    fn sample_new(email: &str, now: NaiveDateTime) -> Self::New {
        models::NewUuidUser::sample(email, now)
    }

    fn contract_email(&self) -> &str {
        &self.email
    }

    fn contract_encrypted_password(&self) -> &str {
        &self.encrypted_password
    }

    fn contract_reset_password_token(&self) -> Option<&str> {
        self.reset_password_token.as_deref()
    }

    fn contract_reset_password_sent_at(&self) -> Option<NaiveDateTime> {
        self.reset_password_sent_at
    }

    fn contract_confirmation_token(&self) -> Option<&str> {
        self.confirmation_token.as_deref()
    }

    fn contract_confirmation_sent_at(&self) -> Option<NaiveDateTime> {
        self.confirmation_sent_at
    }

    fn contract_unconfirmed_email(&self) -> Option<&str> {
        self.unconfirmed_email.as_deref()
    }

    fn contract_failed_attempts(&self) -> i64 {
        i64::from(self.failed_attempts)
    }

    fn contract_sign_in_count(&self) -> i64 {
        i64::from(self.sign_in_count)
    }

    fn contract_unlock_token(&self) -> Option<&str> {
        self.unlock_token.as_deref()
    }

    fn contract_locked_at(&self) -> Option<NaiveDateTime> {
        self.locked_at
    }

    fn contract_created_at(&self) -> NaiveDateTime {
        self.created_at
    }

    fn contract_updated_at(&self) -> NaiveDateTime {
        self.updated_at
    }
}

/// Shared-suite leg over the integer-PK `users` table: a fresh `:memory:`
/// rig per case (pool-of-1, emitted DDL applied).
struct SqliteUsersFactory;

impl ContractFactory for SqliteUsersFactory {
    type Model = FixtureUser;
    type Adapter = DieselOrmAdapter<FixtureUser, Sqlite, SqliteConn>;

    async fn adapter(&self) -> Self::Adapter {
        bootstrap_sqlite_memory().await.users
    }

    fn key_of_created(&self, row: &FixtureUser) -> DeviseKey {
        DeviseKey::from_i64(row.id)
    }

    fn missing_key(&self) -> DeviseKey {
        DeviseKey::from_i64(999_999)
    }
}

/// Shared-suite leg over the uuid-PK `uuid_users` table (hyphenated TEXT
/// id on sqlite): same fresh-rig-per-case shape.
struct SqliteUuidUsersFactory;

impl ContractFactory for SqliteUuidUsersFactory {
    type Model = UuidUser;
    type Adapter = DieselOrmAdapter<UuidUser, Sqlite, SqliteConn>;

    async fn adapter(&self) -> Self::Adapter {
        bootstrap_sqlite_memory().await.uuid_users
    }

    fn key_of_created(&self, row: &UuidUser) -> DeviseKey {
        DeviseKey::from_uuid(uuid::Uuid::parse_str(&row.id).expect("uuid ids are hyphenated"))
    }

    fn missing_key(&self) -> DeviseKey {
        DeviseKey::from_uuid(uuid::Uuid::new_v4())
    }
}

#[tokio::test]
async fn sqlite_contract_suite_integer_pk() {
    run_contract_suite(&SqliteUsersFactory).await;
}

#[tokio::test]
async fn sqlite_contract_suite_uuid_pk() {
    run_contract_suite(&SqliteUuidUsersFactory).await;
}

/// Driver error edge: a duplicate create must discriminate
/// `UniqueViolation` with a value-free `Display` (PLAT-06). The oracle
/// store has no constraints, so the violation itself is a
/// database-driver behavior; this leg-local test pins the sqlite mapping.
#[tokio::test]
async fn sqlite_duplicate_create_discriminates_unique_violation() {
    let rig = bootstrap_sqlite_memory().await;
    let now = sample_time();
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

/// Pool smoke test (infrastructure, not contract): the sqlite memory pool
/// builds and executes DDL on a pooled connection.
#[tokio::test]
async fn sqlite_pool_smoke() {
    use devise_rust_diesel::pool::sqlite_memory_pool;
    use diesel_async::SimpleAsyncConnection;

    let pool = sqlite_memory_pool().expect("pool");
    let mut conn = pool.get().await.expect("conn");
    conn.batch_execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL, encrypted_password TEXT NOT NULL);",
    )
    .await
    .expect("ddl");
    drop(conn);
}
