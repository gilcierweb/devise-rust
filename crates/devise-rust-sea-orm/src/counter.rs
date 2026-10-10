//! Atomic counter increments via `update_many().col_expr(...)` (D-11;
//! T-07-03).
//!
//! Lockable's `failed_attempts` and trackable's `sign_in_count` must never
//! ride a read-modify-write [`ChangeSet`](devise_rust::adapter::ChangeSet)
//! path — its last-write-wins semantics lose counts under concurrent
//! sign-ins. This module renders exactly one
//! `UPDATE … SET column = column + 1 WHERE id = ?` statement
//! ([CITED](https://www.sea-ql.org/SeaORM/docs/1.1.x/basic-crud/update/);
//! RESEARCH example verified at compile time per assumption A6) and
//! re-reads the row, mirroring Devise's `increment_counter` + reload.
//!
//! The column name crosses TWO allowlist checks before any SQL exists: the
//! core [`validate_counter_column`] (the single cross-backend rejection
//! point, so every backend errors identically) and the model's
//! [`SeaOrmModel::counter_column`] mapping (defense in depth).

use devise_rust::adapter::{DeviseKey, OrmError, validate_counter_column};
use sea_orm::{QueryFilter, sea_query::Expr};

use crate::bridge::SeaOrmModel;
use crate::error::map_sea_orm_error;
use crate::finder::get;

/// Atomically increments `column` by one on the row under `key` and returns
/// the updated row (D-11).
///
/// # Errors
///
/// [`OrmError::Query`] naming the column when `column` is not a counter
/// column; [`OrmError::InvalidKey`] on a key-shape mismatch;
/// [`OrmError::NotFound`] when `key` matches nothing (never a silent zero);
/// backend failures propagate as their [`map_sea_orm_error`] mapping.
pub async fn increment_counter<E>(
    db: &sea_orm::DatabaseConnection,
    key: &DeviseKey,
    column: &'static str,
) -> Result<E::Model, OrmError>
where
    E: SeaOrmModel,
{
    validate_counter_column(column)?;
    let col = E::counter_column(column)?;
    let pk = E::pk_condition(key)?;

    // One statement: SET column = column + 1 (assumption A6 — the
    // `Expr::col(...).add(1)` shape is the cited sea-query arithmetic form,
    // verified at compile time here).
    E::update_many()
        .col_expr(col, Expr::col(col).add(1))
        .filter(pk)
        .exec(db)
        .await
        .map_err(map_sea_orm_error)?;

    // Re-read and return the stored row; a miss reports NotFound, never a
    // silent zero.
    get::<E>(db, key).await?.ok_or(OrmError::NotFound)
}
