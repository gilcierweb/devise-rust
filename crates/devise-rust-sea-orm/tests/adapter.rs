//! Sea-orm sqlite contract suite entry (D-24/D-26): thin wrappers that run
//! the shared `devise-rust-adapter-tests` cases against the sqlite rig —
//! no hand-written combinatorial tests. The fixture bridge
//! ([`ContractModel`]) lives in `models.rs`, the rig bootstrap in
//! `common/mod.rs`. Only sqlite-specific edges stay here (the finder
//! allowlist rejection); the full D-28 case list on both PK legs lands with
//! the write-path task.
//!
//! [`ContractModel`]: devise_rust_adapter_tests::ContractModel

#[path = "common/mod.rs"]
mod common;
#[path = "models.rs"]
mod models;

use devise_rust::adapter::{Conditions, DeviseKey, OrmAdapter, OrmError};
use devise_rust_adapter_tests::{ContractFactory, crud_roundtrip_case};
use devise_rust_sea_orm::SeaOrmAdapter;
use models::users;

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

/// Tracer: the shared CRUD case proves the whole vertical — emitted DDL
/// applied through `SchemaManager`, `create` from a PK-`NotSet`
/// `ActiveModel`, `get`/`find_first` reads, diff-scoped `update`, `delete`.
#[tokio::test]
async fn sqlite_tracer_crud_roundtrip_integer_pk() {
    crud_roundtrip_case(&SqliteUsersFactory).await;
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
