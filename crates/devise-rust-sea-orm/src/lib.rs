//! `SeaORM` backend for devise-rust: the third [`OrmAdapter`] implementation
//! (ORM-07, D-15), built on sea-orm 1.1.x.
//!
//! The public API every sea-orm consuming app writes (D-15/D-19):
//!
//! * a standard `DeriveEntityModel` entity per table (one module per table,
//!   struct named `Model` as the derive requires), plus
//! * a hand-written [`SeaOrmModel`] bridge impl (finder columns, pk
//!   condition, `ChangeSet` tristate mapping) — see [`bridge`], and
//! * one [`SeaOrmAdapter`] per model, constructed from the application's
//!   existing [`DatabaseConnection`]: the app owns the pool configuration
//!   and lifecycle; the adapter never builds its own connection (D-19).
//!
//! ## Features
//!
//! Per-dialect features forward to sea-orm's `sqlx-*` drivers (D-23 — same
//! opt-in cost model as diesel/sqlx, D-14):
//!
//! * `sqlx-postgres` — async Postgres backend (execution lands in 07-02's
//!   testcontainers leg).
//! * `sqlx-sqlite` — async SQLite backend; the in-memory rig runs the shared
//!   contract suite in unit CI.
//! * `sqlx-mysql` — **experimental**: compiles behind the feature, no CI
//!   execution and no execution verification (D-33).
//!
//! Runtime and codecs (`runtime-tokio-rustls`, `with-chrono`, `with-uuid`,
//! `macros`) are unconditional. The pinned line is sea-orm **1.1.20** (last
//! 1.x; rust-version 1.81, inside the 1.85 MSRV — sea-orm 2.0.x needs 1.94
//! and stays out per STACK).
//!
//! ## Module layout
//!
//! * [`bridge`] — [`SeaOrmModel`] per-model binding (D-15/D-16/D-17).
//! * [`finder`] — curated LIMIT-1 `find_first` + primary-key `get` reads.
//! * [`counter`] — atomic `SET column = column + 1` increments (D-11).
//! * [`error`] — `DbErr` → [`OrmError`] edge mapping (privacy contract: no
//!   record values, no URLs in `Display`).
//!
//! Migrations are NOT re-expressed sea-orm-natively: apps apply the
//! migrations-crate plain-SQL DDL verbatim through sea-orm's
//! `SchemaManager::execute_unprepared` (D-18); the migrations crate stays
//! the single column source of truth. No entity relations surface through
//! the adapter — standalone Devise tables only (D-22).

pub mod bridge;
pub mod counter;
pub mod error;
pub mod finder;

use std::collections::HashMap;
use std::marker::PhantomData;

use async_trait::async_trait;
use devise_rust::adapter::{ChangeSet, Conditions, DeviseKey, OrmAdapter, OrmError, Value};
use sea_orm::{
    ActiveModelBehavior, ActiveModelTrait, DatabaseConnection, IntoActiveModel, QueryFilter,
};

use crate::error::map_sea_orm_error;

pub use crate::bridge::SeaOrmModel;

/// Generic sea-orm adapter: one type, generic over the per-model binding
/// `E: SeaOrmModel` (D-15) — the sea-orm sibling of `DieselOrmAdapter` /
/// `SqlxAdapter`.
///
/// Construct with [`SeaOrmAdapter::new`] over the app's
/// [`DatabaseConnection`] (D-19).
///
/// ## Write semantics
///
/// * `update` writes only the [`ChangeSet`] diff through the model's
///   [`SeaOrmModel::apply_changeset`] bridge and short-circuits an empty
///   diff to a re-read (empty `UPDATE` is invalid SQL — Pitfall 6).
/// * `update_columns` writes the full named map regardless of diff —
///   `ActiveRecord::Persistence#update_columns` parity: no validations, no
///   callbacks, `updated_at` untouched unless named — and that is what
///   carries an unchanged-value force-write (devise #5783, D-16: every
///   named field is `Set`; sea-orm's unchanged-detection never appears).
/// * `increment_counter` renders one atomic `SET column = column + 1`
///   statement via [`counter::increment_counter`] and re-reads (D-11).
/// * `create` inserts the bridge-built `ActiveModel` (PK `NotSet` on
///   database-assigned legs, D-20) and returns the stored row.
#[derive(Debug)]
pub struct SeaOrmAdapter<E: SeaOrmModel> {
    db: DatabaseConnection,
    binding: PhantomData<fn() -> E>,
}

impl<E: SeaOrmModel> SeaOrmAdapter<E> {
    /// Wraps the application's existing connection (D-19): the app builds
    /// and configures the pool; the adapter never builds its own.
    #[must_use]
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            db,
            binding: PhantomData,
        }
    }

    /// Borrows the underlying connection (health checks, manual plumbing).
    #[must_use]
    pub fn db(&self) -> &DatabaseConnection {
        &self.db
    }
}

// The compiler requires the adapters `Clone`-ability of the entity binding
// only through the owned connection; the marker is a plain function pointer.
impl<E: SeaOrmModel> Clone for SeaOrmAdapter<E> {
    fn clone(&self) -> Self {
        Self::new(self.db.clone())
    }
}

#[async_trait]
impl<E> OrmAdapter<E::Model> for SeaOrmAdapter<E>
where
    E: SeaOrmModel,
    E::Model: Send + Sync + IntoActiveModel<E::ActiveModel> + 'static,
    E::ActiveModel: ActiveModelBehavior + Send + 'static,
{
    type New = E::InsertModel;

    async fn get(&self, id: &DeviseKey) -> Result<Option<E::Model>, OrmError> {
        finder::get::<E>(&self.db, id).await
    }

    async fn find_first(&self, conditions: &Conditions) -> Result<Option<E::Model>, OrmError> {
        finder::find_first::<E>(&self.db, conditions).await
    }

    async fn create(&self, model: Self::New) -> Result<E::Model, OrmError> {
        E::insert_model(model)
            .insert(&self.db)
            .await
            .map_err(map_sea_orm_error)
    }

    async fn update(&self, key: &DeviseKey, changes: &ChangeSet) -> Result<E::Model, OrmError> {
        let mut fields = HashMap::new();
        for field in changes.changed_fields() {
            if let Some(value) = changes.current_value(&field) {
                fields.insert(field, value.clone());
            }
        }
        self.write_map(key, &fields).await
    }

    async fn update_columns(
        &self,
        key: &DeviseKey,
        fields: &HashMap<String, Value>,
    ) -> Result<E::Model, OrmError> {
        self.write_map(key, fields).await
    }

    async fn increment_counter(
        &self,
        key: &DeviseKey,
        column: &'static str,
    ) -> Result<E::Model, OrmError> {
        counter::increment_counter::<E>(&self.db, key, column).await
    }

    async fn delete(&self, id: &DeviseKey) -> Result<(), OrmError> {
        // Deleting a missing key is a no-op (rows_affected == 0 is fine) —
        // `to_adapter.destroy` parity.
        E::delete_many()
            .filter(E::pk_condition(id)?)
            .exec(&self.db)
            .await
            .map_err(map_sea_orm_error)?;
        Ok(())
    }
}

impl<E> SeaOrmAdapter<E>
where
    E: SeaOrmModel,
    E::Model: Send + Sync + IntoActiveModel<E::ActiveModel> + 'static,
    E::ActiveModel: ActiveModelBehavior + Send + 'static,
{
    /// Shared partial-write path: empty maps short-circuit to a re-read
    /// (missing → `NotFound`; an empty `UPDATE` is invalid SQL — Pitfall 6;
    /// assumption A5 confirmed: sea-orm's own `is_noop()` guard would also
    /// re-select without erroring, so this adapter guard is belt and
    /// braces); otherwise the bridge builds a Set-only `ActiveModel` (D-16)
    /// and `Update::one` executes it and re-reads the fresh row (on miss
    /// sea-orm raises `RecordNotUpdated`, mapped to `NotFound` — T-07-05).
    async fn write_map(
        &self,
        key: &DeviseKey,
        fields: &HashMap<String, Value>,
    ) -> Result<E::Model, OrmError> {
        if fields.is_empty() {
            return finder::get::<E>(&self.db, key)
                .await?
                .ok_or(OrmError::NotFound);
        }
        let mut active_model = E::update_base(key)?;
        E::apply_changeset(&mut active_model, fields)?;
        active_model
            .update(&self.db)
            .await
            .map_err(map_sea_orm_error)
    }
}
