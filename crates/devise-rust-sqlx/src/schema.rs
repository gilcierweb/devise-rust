//! Schema probe — the `column_exists` answer behind
//! [`devise_rust::schema::check_fields`] (Devise's `check_fields!`).
//!
//! The catalog statement is dialect-shaped through [`Dialect::probe_sql`]
//! (the same seam bind conversion rides); both identifiers travel as BINDS
//! and the logged skeleton carries placeholders only (D-12). The answer is
//! row EXISTENCE (`fetch_optional`), so no per-database scalar decoder
//! enters the generic path. A catalog failure propagates as [`OrmError`] —
//! never swallowed into "absent", because a missing column and an
//! unreachable catalog must not look alike to the caller.

use devise_rust::adapter::OrmError;

use crate::error::{map_pool_error, map_sqlx_error};
use crate::glue::{Bind, SqlxModel};
use crate::query::{Dialect, push_bind};

/// Probe the database catalog for one column of this model's table.
///
/// # Errors
///
/// Returns [`OrmError`] when the pool checkout or the catalog query fails.
pub(crate) async fn column_exists<M, DB>(
    pool: &sqlx::Pool<DB>,
    column: &str,
) -> Result<bool, OrmError>
where
    M: SqlxModel,
    DB: Dialect,
    for<'q> <DB as sqlx::Database>::Arguments<'q>: sqlx::IntoArguments<'q, DB>,
    for<'c> &'c mut <DB as sqlx::Database>::Connection: sqlx::Executor<'c, Database = DB>,
{
    let mut conn = pool.acquire().await.map_err(map_pool_error)?;
    let (prefix, infix) = DB::probe_sql();
    let mut args = <DB as sqlx::Database>::Arguments::<'_>::default();
    let mut qb = sqlx::QueryBuilder::<DB>::new("");
    qb.push(prefix);
    push_bind::<DB>(&mut qb, &mut args, Bind::Text(M::table_name().to_string()))?;
    qb.push(infix);
    push_bind::<DB>(&mut qb, &mut args, Bind::Text(column.to_string()))?;
    qb.push(" LIMIT 1");
    log::debug!("devise-rust-sqlx column_exists: {}", qb.sql());
    let (sql, args) = (qb.into_sql(), args);
    let hit = sqlx::query_with::<DB, _>(&sql, args)
        .fetch_optional(&mut *conn)
        .await
        .map_err(map_sqlx_error)?;
    Ok(hit.is_some())
}
