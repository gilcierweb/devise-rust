//! Atomic counter increments (D-11).
//!
//! `increment_counter` renders one `UPDATE <table> SET <column> = <column> + 1
//! WHERE <pk> = ?` statement — never a read-modify-write `ChangeSet`
//! write, whose last-write-wins semantics lose counts under concurrent
//! sign-ins. The caller (`SqlxAdapter::increment_counter`) validates the
//! column against the core `COUNTER_COLUMNS` allowlist before this
//! module sees it, so the identifier interpolated into SQL text is a
//! validated `&'static` name; the adapter then re-reads the row on the
//! same checkout and returns it (Devise's `increment_counter` + reload).

use devise_rust::adapter::{DeviseKey, OrmError};

use crate::error::map_sqlx_error;
use crate::glue::SqlxModel;
use crate::query::{Dialect, key_bind, push_bind};

/// Executes one atomic `UPDATE … SET column = column + 1 WHERE pk = ?` for
/// the already-validated counter column.
///
/// # Errors
///
/// Returns [`OrmError::InvalidKey`] on a key-shape mismatch (before any
/// SQL); backend failures surface as their [`OrmError`] mapping.
pub(crate) async fn increment_field<'c, M, DB>(
    conn: &'c mut <DB as sqlx::Database>::Connection,
    key: &DeviseKey,
    column: &'static str,
) -> Result<(), OrmError>
where
    M: SqlxModel,
    DB: Dialect,
    for<'q> <DB as sqlx::Database>::Arguments<'q>: sqlx::IntoArguments<'q, DB>,
    &'c mut <DB as sqlx::Database>::Connection: sqlx::Executor<'c, Database = DB>,
{
    let key = key_bind::<M, DB>(key)?;
    let mut args = <DB as sqlx::Database>::Arguments::<'_>::default();
    let mut qb = sqlx::QueryBuilder::<DB>::new("UPDATE ");
    qb.push(M::table_name());
    qb.push(" SET ");
    // Column ident from the core allowlist (validated by the caller) — a
    // &'static name, never user input.
    qb.push(column);
    qb.push(" = ");
    qb.push(column);
    qb.push(" + 1 WHERE ");
    qb.push(M::pk_column());
    qb.push(" = ");
    push_bind(&mut qb, &mut args, key)?;
    log::debug!("devise-rust-sqlx increment_counter: {}", qb.sql());
    let (sql, args) = (qb.into_sql(), args);
    sqlx::query_with::<DB, _>(&sql, args)
        .execute(&mut *conn)
        .await
        .map_err(map_sqlx_error)?;
    Ok(())
}
