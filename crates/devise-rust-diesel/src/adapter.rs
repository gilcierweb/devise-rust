//! Generic diesel backend implementing the core [`OrmAdapter`] (D-06).
//!
//! [`DieselOrmAdapter<M, DB, Conn>`] is the single public adapter type (D-06):
//! one crate, generic over the model binding `M: DieselModel`, the diesel
//! backend `DB`, and the pooled connection `Conn`. Reads filter
//! `into_boxed` queries with the glue's boxed predicates and execute only at
//! op boundaries via `diesel_async::RunQueryDsl` — sync diesel execution
//! never appears on the hot path, and `use schema::dsl::*` style glob
//! imports stay out (the mixed-prelude anti-pattern).
//!
//! ## Why writes live behind [`BackendWrites`]
//!
//! Diesel seals even the *absence* of `RETURNING` (`NoReturningClause`)
//! behind its internal `DieselReserveSpecialization` trait, so no
//! `INSERT`/`UPDATE`/`DELETE` statement can execute in backend-generic code —
//! the bound is unprovable for an abstract `DB`. Each backend therefore
//! implements the private [`BackendWrites`] seam once, concretely (the mysql
//! arm additionally carries the transaction + re-select `create` fallback,
//! since MySQL has no `RETURNING` at all). Reads (`SELECT`) are unsealed and
//! stay fully generic. Updates `execute` plus re-read rather than
//! `RETURNING`, uniformly on every backend, so the outcome contract is
//! identical everywhere.
//!
//! A second sealed-trait consequence shapes the read path: diesel's query
//! builder normalizes associated types (`AsQuery::Query`, `BoxedDsl::Output`)
//! through impls the compiler cannot expand for an abstract table, so the
//! adapter never names an intermediate statement type. It asserts end-state
//! bounds instead — the boxed query filters to itself and loads — which hold
//! for every concrete `table!` type without asking the compiler to expand a
//! single projection.
//!
//! ## Pool storage
//!
//! The adapter holds its deadpool behind the [`Checkout`](crate::pool::Checkout)
//! erasure for the same sealed-trait reason: `Pool<Conn>`'s `Manager` bound
//! is unprovable abstractly. Construction still takes the real managed
//! deadpool; only the field type is erased.
//!
//! ## Write semantics
//!
//! * `update` writes only the [`ChangeSet`](devise_rust::adapter::ChangeSet)
//!   diff through the model's `AsChangeset` bridge and short-circuits an
//!   empty diff to a re-read (Pitfall 1 decision).
//! * `update_columns` writes the full named map regardless of diff —
//!   `ActiveRecord::Persistence#update_columns` parity: no validations, no
//!   callbacks, `updated_at` untouched unless named — which is also what
//!   carries an unchanged-value force-write (devise #5783).
//! * `increment_counter` renders one atomic `SET column = column + 1`
//!   statement through the [`BackendWrites`] seam and re-reads on the same
//!   connection (D-11): counters never ride a value-typed changeset path,
//!   whose last-write-wins semantics lose counts under concurrent sign-ins.
//!
//! [`OrmAdapter`]: devise_rust::adapter::OrmAdapter

use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::ops::DerefMut;

use async_trait::async_trait;
use devise_rust::adapter::{
    ChangeSet, Conditions, DeviseKey, OrmAdapter, OrmError, Value, validate_counter_column,
};
use diesel::associations::HasTable;
use diesel::deserialize::FromSqlRow;
use diesel::expression::is_aggregate::No;
use diesel::expression::{BoxableExpression, MixedAggregates, QueryMetadata, ValidGrouping};
use diesel::insertable::CanInsertInSingleQuery;
use diesel::query_builder::{IntoUpdateTarget, QueryFragment, QueryId};
use diesel::query_dsl::CompatibleType;
use diesel::query_dsl::filter_dsl::FilterDsl;
use diesel::query_source::QuerySource;
use diesel::{AsChangeset, Expression, Table, backend::Backend, delete, insert_into, update};
use diesel_async::methods::LoadQuery;
use diesel_async::{AsyncConnection, RunQueryDsl};

use crate::error::map_diesel_error;
use crate::glue::{BoxPred, DieselModel, DieselPredicates};
use crate::pool::Checkout;

/// Full-row record `SqlType`: the `AllColumns` tuple every load maps from.
type RecordSql<M> = <<<M as DieselModel>::Table as Table>::AllColumns as Expression>::SqlType;

/// Single-filter select over a model's table. Never expanded — only loaded.
type Filt<M, DB> =
    <<M as DieselModel>::Table as FilterDsl<BoxPred<<M as DieselModel>::Table, DB>>>::Output;

/// Generic diesel adapter: the first concrete [`OrmAdapter`] backend.
///
/// `M` is the model (bound via [`DieselModel`]), `DB` the diesel backend
/// marker (`Pg`, `Sqlite`, …), `Conn` the pooled async connection
/// (`AsyncPgConnection`, `SyncConnectionWrapper<SqliteConnection>`, …).
/// Construct with a deadpool built by [`crate::pool`] builders.
pub struct DieselOrmAdapter<M, DB, Conn> {
    pool: Box<dyn Checkout<Conn> + Send + Sync>,
    binding: PhantomData<fn() -> (M, DB)>,
}

impl<M, DB, Conn> DieselOrmAdapter<M, DB, Conn> {
    /// Wraps an existing checkout-capable pool.
    ///
    /// Accepts any [`Checkout`] pool — in practice the deadpools from
    /// [`crate::pool`], which implement it once per backend.
    #[must_use]
    pub fn new(pool: impl Checkout<Conn> + Send + Sync + 'static) -> Self {
        Self {
            pool: Box::new(pool),
            binding: PhantomData,
        }
    }

    /// Borrows the underlying pool (for health checks, manual checkouts).
    #[must_use]
    pub fn pool(&self) -> &(dyn Checkout<Conn> + Send + Sync) {
        &*self.pool
    }

    /// Checks out one pooled connection.
    async fn pooled(&self) -> Result<Box<dyn DerefMut<Target = Conn> + Send + '_>, OrmError> {
        self.pool.checkout().await
    }
}

/// Private per-backend write seam: every `INSERT`/`UPDATE`/`DELETE`
/// statement embeds a returning-clause slot whose fragment impls diesel seals
/// internally, so writes execute here — once per concrete backend — and never
/// in backend-generic code.
///
/// `#[doc(hidden)]`: public only because it appears in
/// [`DieselOrmAdapter`]'s bounds; not implemented outside this crate.
#[doc(hidden)]
#[async_trait]
pub trait BackendWrites<M: DieselModel, Conn>: Send + Sync {
    /// Inserts `new` into `table` and returns the stored row (`RETURNING` on
    /// Postgres/SQLite; transaction + re-select on MySQL).
    async fn create_row(conn: &mut Conn, table: M::Table, new: M::New) -> Result<M, OrmError>;
    /// Executes one partial `UPDATE` over `fields` (already diff- or
    /// full-map-selected by the caller).
    async fn write_fields(
        conn: &mut Conn,
        table: M::Table,
        key: &DeviseKey,
        fields: &HashMap<String, Value>,
    ) -> Result<(), OrmError>;
    /// Executes one primary-key `DELETE` (missing rows are a no-op).
    async fn delete_row(conn: &mut Conn, table: M::Table, key: &DeviseKey) -> Result<(), OrmError>;
    /// Executes one atomic `UPDATE ... SET column = column + 1 WHERE pk`
    /// for the named counter column (D-11): one statement, no
    /// read-modify-write. `column` has already passed the core counter
    /// allowlist and the assignment expression comes from the model glue -
    /// never user input.
    async fn increment_field(
        conn: &mut Conn,
        table: M::Table,
        key: &DeviseKey,
        column: &'static str,
    ) -> Result<(), OrmError>;
}

/// Postgres write arm (`RETURNING` for create; `execute` for the rest).
#[cfg(feature = "postgres")]
#[async_trait]
impl<M, Conn> BackendWrites<M, Conn> for diesel::pg::Pg
where
    M: DieselPredicates<diesel::pg::Pg> + FromSqlRow<RecordSql<M>, diesel::pg::Pg>,
    M::New: diesel::Insertable<M::Table>,
    <M::New as diesel::Insertable<M::Table>>::Values:
        Send + QueryFragment<diesel::pg::Pg> + QueryId + CanInsertInSingleQuery<diesel::pg::Pg>,
    M::Table: QueryId,
    M::Changeset: AsChangeset<Target = M::Table>,
    <M::Changeset as AsChangeset>::Changeset: Send + QueryFragment<diesel::pg::Pg>,
    M::IncrementChangeset: AsChangeset<Target = M::Table>,
    <M::IncrementChangeset as AsChangeset>::Changeset: Send + QueryFragment<diesel::pg::Pg>,
    <M::Table as QuerySource>::FromClause: Send + QueryFragment<diesel::pg::Pg>,
    M::Table: FilterDsl<BoxPred<M::Table, diesel::pg::Pg>>,
    <M::Table as FilterDsl<BoxPred<M::Table, diesel::pg::Pg>>>::Output:
        IntoUpdateTarget + HasTable<Table = M::Table>,
    <<M::Table as FilterDsl<BoxPred<M::Table, diesel::pg::Pg>>>::Output as IntoUpdateTarget>::WhereClause:
        Send + QueryFragment<diesel::pg::Pg> + QueryId,
    <M::Table as Table>::AllColumns:
        Send + ValidGrouping<()> + QueryId + QueryFragment<diesel::pg::Pg>,
    <<M::Table as Table>::AllColumns as ValidGrouping<()>>::IsAggregate:
        MixedAggregates<No, Output = No>,
    RecordSql<M>: CompatibleType<M, diesel::pg::Pg, SqlType = RecordSql<M>>,
    diesel::pg::Pg: QueryMetadata<RecordSql<M>>,
    Conn: AsyncConnection<Backend = diesel::pg::Pg>,
{
    async fn create_row(
        conn: &mut Conn,
        table: M::Table,
        new: M::New,
    ) -> Result<M, OrmError> {
        insert_into(table)
            .values(new)
            .get_result(conn)
            .await
            .map_err(map_diesel_error)
    }

    async fn write_fields(
        conn: &mut Conn,
        table: M::Table,
        key: &DeviseKey,
        fields: &HashMap<String, Value>,
    ) -> Result<(), OrmError> {
        let pk = M::pk_predicate(key)?;
        let changeset = M::changeset_from_map(fields)?;
        update(FilterDsl::filter(table, pk))
            .set(changeset)
            .execute(conn)
            .await
            .map_err(map_diesel_error)?;
        Ok(())
    }

    async fn delete_row(
        conn: &mut Conn,
        table: M::Table,
        key: &DeviseKey,
    ) -> Result<(), OrmError> {
        let pk = M::pk_predicate(key)?;
        delete(FilterDsl::filter(table, pk))
            .execute(conn)
            .await
            .map_err(map_diesel_error)?;
        Ok(())
    }

    async fn increment_field(
        conn: &mut Conn,
        table: M::Table,
        key: &DeviseKey,
        column: &'static str,
    ) -> Result<(), OrmError> {
        let pk = M::pk_predicate(key)?;
        let changeset = M::increment_changeset(column)?;
        update(FilterDsl::filter(table, pk))
            .set(changeset)
            .execute(conn)
            .await
            .map_err(map_diesel_error)?;
        Ok(())
    }
}

/// SQLite write arm (`RETURNING` via `returning_clauses_for_sqlite_3_35`).
#[cfg(feature = "sqlite")]
#[async_trait]
impl<M, Conn> BackendWrites<M, Conn> for diesel::sqlite::Sqlite
where
    M: DieselPredicates<diesel::sqlite::Sqlite> + FromSqlRow<RecordSql<M>, diesel::sqlite::Sqlite>,
    M::New: diesel::Insertable<M::Table>,
    <M::New as diesel::Insertable<M::Table>>::Values:
        Send + QueryFragment<diesel::sqlite::Sqlite> + QueryId + CanInsertInSingleQuery<diesel::sqlite::Sqlite>,
    M::Table: QueryId,
    M::Changeset: AsChangeset<Target = M::Table>,
    <M::Changeset as AsChangeset>::Changeset: Send + QueryFragment<diesel::sqlite::Sqlite>,
    M::IncrementChangeset: AsChangeset<Target = M::Table>,
    <M::IncrementChangeset as AsChangeset>::Changeset: Send + QueryFragment<diesel::sqlite::Sqlite>,
    <M::Table as QuerySource>::FromClause: Send + QueryFragment<diesel::sqlite::Sqlite>,
    M::Table: FilterDsl<BoxPred<M::Table, diesel::sqlite::Sqlite>>,
    <M::Table as FilterDsl<BoxPred<M::Table, diesel::sqlite::Sqlite>>>::Output:
        IntoUpdateTarget + HasTable<Table = M::Table>,
    <<M::Table as FilterDsl<BoxPred<M::Table, diesel::sqlite::Sqlite>>>::Output as IntoUpdateTarget>::WhereClause:
        Send + QueryFragment<diesel::sqlite::Sqlite> + QueryId,
    <M::Table as Table>::AllColumns:
        Send + ValidGrouping<()> + QueryId + QueryFragment<diesel::sqlite::Sqlite>,
    <<M::Table as Table>::AllColumns as ValidGrouping<()>>::IsAggregate:
        MixedAggregates<No, Output = No>,
    RecordSql<M>: CompatibleType<M, diesel::sqlite::Sqlite, SqlType = RecordSql<M>>,
    diesel::sqlite::Sqlite: QueryMetadata<RecordSql<M>>,
    Conn: AsyncConnection<Backend = diesel::sqlite::Sqlite>,
{
    async fn create_row(
        conn: &mut Conn,
        table: M::Table,
        new: M::New,
    ) -> Result<M, OrmError> {
        insert_into(table)
            .values(new)
            .get_result(conn)
            .await
            .map_err(map_diesel_error)
    }

    async fn write_fields(
        conn: &mut Conn,
        table: M::Table,
        key: &DeviseKey,
        fields: &HashMap<String, Value>,
    ) -> Result<(), OrmError> {
        let pk = M::pk_predicate(key)?;
        let changeset = M::changeset_from_map(fields)?;
        update(FilterDsl::filter(table, pk))
            .set(changeset)
            .execute(conn)
            .await
            .map_err(map_diesel_error)?;
        Ok(())
    }

    async fn delete_row(
        conn: &mut Conn,
        table: M::Table,
        key: &DeviseKey,
    ) -> Result<(), OrmError> {
        let pk = M::pk_predicate(key)?;
        delete(FilterDsl::filter(table, pk))
            .execute(conn)
            .await
            .map_err(map_diesel_error)?;
        Ok(())
    }

    async fn increment_field(
        conn: &mut Conn,
        table: M::Table,
        key: &DeviseKey,
        column: &'static str,
    ) -> Result<(), OrmError> {
        let pk = M::pk_predicate(key)?;
        let changeset = M::increment_changeset(column)?;
        update(FilterDsl::filter(table, pk))
            .set(changeset)
            .execute(conn)
            .await
            .map_err(map_diesel_error)?;
        Ok(())
    }
}

#[async_trait]
impl<M, DB, Conn> OrmAdapter<M> for DieselOrmAdapter<M, DB, Conn>
where
    M: DieselPredicates<DB>,
    M::Table: FilterDsl<BoxPred<M::Table, DB>> + LoadQuery<'static, Conn, M>,
    Filt<M, DB>: LoadQuery<'static, Conn, M>,
    for<'x> <M::Table as FilterDsl<
        Box<
            dyn BoxableExpression<
                    M::Table,
                    DB,
                    SqlType = diesel::sql_types::Nullable<diesel::sql_types::Bool>,
                > + 'x,
        >,
    >>::Output: Send,
    DB: Backend + BackendWrites<M, Conn> + Send + Sync + 'static,
    Conn: AsyncConnection<Backend = DB>,
{
    type New = M::New;

    async fn get(&self, id: &DeviseKey) -> Result<Option<M>, OrmError> {
        let filtered: Filt<M, DB> = FilterDsl::filter(M::table(), M::pk_predicate(id)?);
        let mut guard = self.pooled().await?;
        let conn: &mut Conn = &mut guard;
        let rows: Vec<M> = filtered.load(conn).await.map_err(map_diesel_error)?;
        Ok(rows.into_iter().next())
    }

    async fn find_first(&self, conditions: &Conditions) -> Result<Option<M>, OrmError> {
        let mut guard = self.pooled().await?;
        let conn: &mut Conn = &mut guard;
        let mut ordered: Vec<DeviseKey> = Vec::new();
        let mut members: HashMap<DeviseKey, M> = HashMap::new();
        let mut first_condition = true;
        for (column, value) in conditions.iter() {
            let Some(predicate) = M::finder_predicate(column, value) else {
                return Err(OrmError::Query {
                    message: format!("unsupported finder column: {column}"),
                    source: None,
                });
            };
            let filtered: Filt<M, DB> = FilterDsl::filter(M::table(), predicate);
            let rows: Vec<M> = filtered.load(conn).await.map_err(map_diesel_error)?;
            if first_condition {
                ordered = Vec::with_capacity(rows.len());
                members = HashMap::with_capacity(rows.len());
                for model in rows {
                    let key = M::key_of(&model);
                    ordered.push(key.clone());
                    members.insert(key, model);
                }
                first_condition = false;
            } else {
                let hits: HashSet<DeviseKey> = rows.iter().map(M::key_of).collect();
                members.retain(|key, _| hits.contains(key));
                if members.is_empty() {
                    break;
                }
            }
        }
        if first_condition {
            // No conditions: first row of the table, like the oracle.
            let rows: Vec<M> = M::table().load(conn).await.map_err(map_diesel_error)?;
            return Ok(rows.into_iter().next());
        }
        ordered.retain(|key| members.contains_key(key));
        Ok(ordered.into_iter().find_map(|key| members.remove(&key)))
    }

    async fn create(&self, model: Self::New) -> Result<M, OrmError> {
        let mut guard = self.pooled().await?;
        let conn: &mut Conn = &mut guard;
        DB::create_row(conn, M::table(), model).await
    }

    async fn update(&self, key: &DeviseKey, changes: &ChangeSet) -> Result<M, OrmError> {
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
    ) -> Result<M, OrmError> {
        self.write_map(key, fields).await
    }

    async fn increment_counter(
        &self,
        key: &DeviseKey,
        column: &'static str,
    ) -> Result<M, OrmError> {
        validate_counter_column(column)?;
        let mut guard = self.pooled().await?;
        let conn: &mut Conn = &mut guard;
        DB::increment_field(conn, M::table(), key, column).await?;
        // Re-read using the SAME connection to avoid deadlock with pool size = 1
        // (mirrors write_map); a miss reports NotFound, never a silent zero.
        let filtered: Filt<M, DB> = FilterDsl::filter(M::table(), M::pk_predicate(key)?);
        let rows: Vec<M> = filtered.load(conn).await.map_err(map_diesel_error)?;
        rows.into_iter().next().ok_or(OrmError::NotFound)
    }

    async fn delete(&self, id: &DeviseKey) -> Result<(), OrmError> {
        let mut guard = self.pooled().await?;
        let conn: &mut Conn = &mut guard;
        DB::delete_row(conn, M::table(), id).await
    }
}

impl<M, DB, Conn> DieselOrmAdapter<M, DB, Conn>
where
    M: DieselPredicates<DB>,
    M::Table: FilterDsl<BoxPred<M::Table, DB>> + LoadQuery<'static, Conn, M>,
    Filt<M, DB>: LoadQuery<'static, Conn, M>,
    for<'x> <M::Table as FilterDsl<
        Box<
            dyn BoxableExpression<
                    M::Table,
                    DB,
                    SqlType = diesel::sql_types::Nullable<diesel::sql_types::Bool>,
                > + 'x,
        >,
    >>::Output: Send,
    DB: Backend + BackendWrites<M, Conn> + Send + Sync + 'static,
    Conn: AsyncConnection<Backend = DB>,
{
    /// Shared partial-write path: empty maps short-circuit to a re-read
    /// (missing → `NotFound`); otherwise the backend executes one `UPDATE`
    /// and the fresh row is re-read.
    async fn write_map(
        &self,
        key: &DeviseKey,
        fields: &HashMap<String, Value>,
    ) -> Result<M, OrmError> {
        if fields.is_empty() {
            // Empty SET would be invalid SQL; re-read instead.
            return self.get(key).await?.ok_or(OrmError::NotFound);
        }
        let mut guard = self.pooled().await?;
        let conn: &mut Conn = &mut guard;
        DB::write_fields(conn, M::table(), key, fields).await?;
        // Re-read using the SAME connection to avoid deadlock with pool size = 1
        let filtered: Filt<M, DB> = FilterDsl::filter(M::table(), M::pk_predicate(key)?);
        let rows: Vec<M> = filtered.load(conn).await.map_err(map_diesel_error)?;
        rows.into_iter().next().ok_or(OrmError::NotFound)
    }
}
