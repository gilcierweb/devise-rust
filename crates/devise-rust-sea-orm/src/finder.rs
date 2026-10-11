//! Sea-orm `Entity` reads: the curated LIMIT-1 finder and the primary-key
//! fetch (D-17, Pitfall 7).
//!
//! Reads are `E::find()` chained with one `.filter(column.eq(value))` per
//! condition (AND semantics — the planner-picked composition; intersecting
//! per-condition result sets like diesel is unnecessary because sea-orm
//! predicates compose) and finished with
//! `one()`, the LIMIT-1 shape. `one()` returns
//! `Ok(None)` on a miss — a miss is never an error (Pitfall 7; T-07-05).
//!
//! The [`SeaOrmModel`] bridge maps each curated column name to the entity's
//! `Column` *before any query exists*; out-of-set names (and non-string
//! values against these text columns) yield [`OrmError::Query`] naming the
//! column and never the value (D-17, T-07-01).

use devise_rust::adapter::{Conditions, DeviseKey, OrmError};
use sea_orm::{ColumnTrait, QueryFilter};

use crate::bridge::SeaOrmModel;
use crate::error::map_sea_orm_error;

/// Finds the first record matching `conditions` (the LIMIT-1 shape, D-17).
///
/// Chained `.filter()` per condition gives AND semantics; empty conditions
/// return the first row of the table (oracle parity with the diesel leg).
///
/// # Errors
///
/// [`OrmError::Query`] naming the column when any condition column is not
/// in the curated [`FINDER_COLUMNS`](crate::bridge::FINDER_COLUMNS) set or
/// carries a non-string value; backend failures propagate as their
/// [`map_sea_orm_error`] mapping.
pub async fn find_first<E>(
    db: &sea_orm::DatabaseConnection,
    conditions: &Conditions,
) -> Result<Option<E::Model>, OrmError>
where
    E: SeaOrmModel,
{
    let mut query = E::find();
    for (column, value) in conditions.iter() {
        let Some(col) = E::finder_column(column, value) else {
            return Err(OrmError::Query {
                message: format!("unsupported finder column: {column}"),
                source: None,
            });
        };
        // finder_column returned Some, so `value` is a string (the bridge
        // rejects every other shape); the bind goes through `eq` — never
        // interpolated into SQL text (T-07-01).
        let devise_rust::adapter::Value::String(text) = value else {
            return Err(OrmError::Query {
                message: format!("unsupported finder column: {column}"),
                source: None,
            });
        };
        query = query.filter(col.eq(text.clone()));
    }
    query.one(db).await.map_err(map_sea_orm_error)
}

/// Fetches a record by primary key; a missing key is `Ok(None)`, never an
/// error.
///
/// # Errors
///
/// [`OrmError::InvalidKey`] when the key shape does not fit the model's
/// primary key (the bridge names `table.id`); backend failures propagate as
/// their [`map_sea_orm_error`] mapping.
pub async fn get<E>(
    db: &sea_orm::DatabaseConnection,
    key: &DeviseKey,
) -> Result<Option<E::Model>, OrmError>
where
    E: SeaOrmModel,
{
    E::find()
        .filter(E::pk_condition(key)?)
        .one(db)
        .await
        .map_err(map_sea_orm_error)
}
