//! Per-database insert with id echo (D-05).
//!
//! `create` consumes the model's [`New`](SqlxModel::New) insert shape
//! (every column except the database-assigned id) and returns the stored
//! row — the id echo differs per database:
//!
//! * **Postgres**: `INSERT … RETURNING <columns>` mapped through
//!   `query_as` — one round trip.
//! * **SQLite**: the same `RETURNING` shape (SQLite ≥ 3.35; the `sqlite`
//!   feature's bundled `libsqlite3-sys` ships ≥ 3.44 — the same posture as
//!   the diesel backend's `returning_clauses_for_sqlite_3_35`).
//! * **MySQL** (experimental, D-33: compiles without CI execution): MySQL
//!   has no `RETURNING`, so the arm runs the insert inside a transaction
//!   and re-selects the row by `LAST_INSERT_ID()` on the same connection
//!   (the diesel D-03 fallback precedent).
//!
//! Placeholder rendering stays the driver's own (`$N` vs `?` — D-34); all
//! statement text is static glue names plus binds.

use devise_rust::adapter::OrmError;

use crate::error::map_sqlx_error;
use crate::glue::SqlxModel;
use crate::query::Dialect;

/// Per-database insert + id-echo seam (the diesel `BackendWrites::create_row`
/// analogue): the RETURNING/transaction shape is per-database, so each
/// backend implements this once, concretely.
///
/// `#[doc(hidden)]`: implementation detail of
/// [`SqlxAdapter`](crate::SqlxAdapter), implemented in this crate only.
#[doc(hidden)]
#[async_trait::async_trait]
pub trait InsertEcho<M: SqlxModel>: Dialect {
    /// Inserts `model` into the model's table and returns the stored row.
    ///
    /// # Errors
    ///
    /// Returns [`OrmError::UniqueViolation`] when a uniqueness constraint
    /// rejects the row; other backend failures surface as their
    /// [`OrmError`] mapping.
    async fn insert_row(
        conn: &mut <Self as sqlx::Database>::Connection,
        model: M::New,
    ) -> Result<M, OrmError>;
}

/// Shared `INSERT … RETURNING <columns>` execution (the Postgres and SQLite
/// arms): one round trip, the stored row mapped straight through
/// `query_as`.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
async fn insert_returning<'c, M, DB>(
    conn: &'c mut <DB as sqlx::Database>::Connection,
    model: M::New,
) -> Result<M, OrmError>
where
    M: SqlxModel + Unpin,
    for<'r> M: sqlx::FromRow<'r, <DB as sqlx::Database>::Row>,
    DB: Dialect,
    for<'q> <DB as sqlx::Database>::Arguments<'q>: sqlx::IntoArguments<'q, DB>,
    for<'x> &'x mut <DB as sqlx::Database>::Connection: sqlx::Executor<'x, Database = DB>,
{
    let mut args = <DB as sqlx::Database>::Arguments::<'_>::default();
    let mut qb = sqlx::QueryBuilder::<DB>::new("INSERT INTO ");
    qb.push(M::table_name());
    qb.push(" (");
    let mut first = true;
    for column in M::insert_columns() {
        if !first {
            qb.push(", ");
        }
        qb.push(*column);
        first = false;
    }
    qb.push(") VALUES (");
    let values = M::insert_values(&model);
    assert_eq!(
        M::insert_columns().len(),
        values.len(),
        "SqlxModel::insert_values must match insert_columns positionally"
    );
    let mut first = true;
    for value in values {
        if !first {
            qb.push(", ");
        }
        crate::query::push_bind(&mut qb, &mut args, value)?;
        first = false;
    }
    qb.push(") RETURNING ");
    let mut first = true;
    for column in M::columns() {
        if !first {
            qb.push(", ");
        }
        qb.push(*column);
        first = false;
    }
    log::debug!("devise-rust-sqlx create: {}", qb.sql());
    let (sql, args) = (qb.into_sql(), args);
    sqlx::query_as_with::<DB, M, _>(&sql, args)
        .fetch_one(&mut *conn)
        .await
        .map_err(map_sqlx_error)
}

/// Postgres arm: `INSERT … RETURNING` via `query_as` (one round trip).
#[cfg(feature = "postgres")]
#[async_trait::async_trait]
impl<M> InsertEcho<M> for sqlx::Postgres
where
    M: SqlxModel + Unpin,
    for<'r> M: sqlx::FromRow<'r, sqlx::postgres::PgRow>,
{
    async fn insert_row(conn: &mut sqlx::PgConnection, model: M::New) -> Result<M, OrmError> {
        insert_returning::<M, sqlx::Postgres>(conn, model).await
    }
}

/// SQLite arm: the same `RETURNING` shape on SQLite ≥ 3.35 (bundled ≥ 3.44).
#[cfg(feature = "sqlite")]
#[async_trait::async_trait]
impl<M> InsertEcho<M> for sqlx::Sqlite
where
    M: SqlxModel + Unpin,
    for<'r> M: sqlx::FromRow<'r, sqlx::sqlite::SqliteRow>,
{
    async fn insert_row(conn: &mut sqlx::SqliteConnection, model: M::New) -> Result<M, OrmError> {
        insert_returning::<M, sqlx::Sqlite>(conn, model).await
    }
}

/// MySQL arm — **experimental** (D-33: compiles behind the `mysql` feature,
/// no CI execution, no execution verification): MySQL has no `RETURNING`,
/// so the arm opens a transaction, inserts, re-selects the row by
/// `LAST_INSERT_ID()` on the same connection, and commits. The re-select
/// only resolves integer identity keys; uuid-key tables on MySQL remain
/// unsupported until the arm gains execution verification.
#[cfg(feature = "mysql")]
#[async_trait::async_trait]
impl<M> InsertEcho<M> for sqlx::MySql
where
    M: SqlxModel + Unpin,
    for<'r> M: sqlx::FromRow<'r, sqlx::mysql::MySqlRow>,
{
    async fn insert_row(conn: &mut sqlx::MySqlConnection, model: M::New) -> Result<M, OrmError> {
        use sqlx::Connection as _;

        let mut args = <sqlx::MySql as sqlx::Database>::Arguments::<'_>::default();
        let mut qb = sqlx::QueryBuilder::<sqlx::MySql>::new("INSERT INTO ");
        qb.push(M::table_name());
        qb.push(" (");
        let mut first = true;
        for column in M::insert_columns() {
            if !first {
                qb.push(", ");
            }
            qb.push(*column);
            first = false;
        }
        qb.push(") VALUES (");
        let values = M::insert_values(&model);
        assert_eq!(
            M::insert_columns().len(),
            values.len(),
            "SqlxModel::insert_values must match insert_columns positionally"
        );
        let mut first = true;
        for value in values {
            if !first {
                qb.push(", ");
            }
            crate::query::push_bind(&mut qb, &mut args, value)?;
            first = false;
        }
        qb.push(")");
        log::debug!("devise-rust-sqlx create: {}", qb.sql());
        let (sql, args) = (qb.into_sql(), args);

        let mut tx = conn.begin().await.map_err(map_sqlx_error)?;
        sqlx::query_with::<sqlx::MySql, _>(&sql, args)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;

        let mut reselect = sqlx::QueryBuilder::<sqlx::MySql>::new("SELECT ");
        let mut first = true;
        for column in M::columns() {
            if !first {
                reselect.push(", ");
            }
            reselect.push(*column);
            first = false;
        }
        reselect.push(" FROM ");
        reselect.push(M::table_name());
        reselect.push(" WHERE ");
        reselect.push(M::pk_column());
        reselect.push(" = LAST_INSERT_ID()");
        let reselect_sql = reselect.into_sql();
        log::debug!("devise-rust-sqlx create reselect: {reselect_sql}");
        let row = sqlx::query_as_with::<sqlx::MySql, M, _>(
            &reselect_sql,
            <sqlx::MySql as sqlx::Database>::Arguments::<'_>::default(),
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(map_sqlx_error)?;
        tx.commit().await.map_err(map_sqlx_error)?;
        Ok(row)
    }
}
