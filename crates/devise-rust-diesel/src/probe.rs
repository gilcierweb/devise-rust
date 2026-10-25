//! Schema probe: the `column_exists` answer behind
//! [`devise_rust::schema::check_fields`] (Devise's `check_fields!`), shared
//! by both write arms of [`BackendWrites`](super::adapter::BackendWrites).
//!
//! The statement shape carries both identifiers as binds; the dialect only
//! supplies the SQL text (the same seam bind conversion rides). The answer
//! is the probed row's value (`1` means the column exists), so a miss is
//! `Ok(false)` and a catalog failure is the error, never a silent
//! "absent".
//!
//! The two functions are concrete per backend because diesel decodes
//! `Integer` through per-backend `FromSql` impls: no generic execution
//! helper can be written, so each dialect owns its statement while the
//! projection struct stays in this one home.
//!
//! `#![allow(clippy::redundant_field_names)]` is pinned to this module for
//! one reason: diesel's `QueryableByName` derive expands to a field-shorthand
//! initializer (`Hit { hit }`), which clippy 1.99 flags at the derive site.
//! The lint cannot be suppressed on the generated impl, so it is contained
//! here, in the only module that consumes the derive.

#![allow(clippy::redundant_field_names)]

use devise_rust::adapter::OrmError;

use diesel_async::{AsyncConnection, RunQueryDsl};

/// The one-row projection both dialect probes select: `1` when the column
/// exists.
#[derive(diesel::QueryableByName)]
struct Hit {
    #[diesel(sql_type = diesel::sql_types::Integer)]
    hit: i32,
}

/// Postgres catalog statement (`information_schema`, both identifiers as
/// binds).
#[cfg(feature = "postgres")]
const POSTGRES_SQL: &str = "SELECT 1 AS hit FROM information_schema.columns \
                            WHERE table_name = $1 AND column_name = $2 LIMIT 1";

/// SQLite catalog statement: the `pragma_table_info` table-valued function
/// is the catalog (the table name is itself a bind argument).
#[cfg(feature = "sqlite")]
const SQLITE_SQL: &str = "SELECT 1 AS hit FROM pragma_table_info($1) \
                          WHERE name = $2 LIMIT 1";

/// Probe the Postgres catalog for one column of `table`.
///
/// # Errors
///
/// Returns [`OrmError`] when the catalog query itself fails; a miss is
/// `Ok(false)`, never an error.
#[cfg(feature = "postgres")]
pub(crate) async fn postgres_column_exists<Conn>(
    conn: &mut Conn,
    table: &str,
    column: &str,
) -> Result<bool, OrmError>
where
    Conn: AsyncConnection<Backend = diesel::pg::Pg>,
{
    let hit = diesel::sql_query(POSTGRES_SQL)
        .bind::<diesel::sql_types::Text, _>(table)
        .bind::<diesel::sql_types::Text, _>(column)
        .get_result::<Hit>(conn)
        .await;
    Ok(hit.is_ok_and(|hit| hit.hit == 1))
}

/// Probe the SQLite catalog for one column of `table`.
///
/// # Errors
///
/// Returns [`OrmError`] when the catalog query itself fails; a miss is
/// `Ok(false)`, never an error.
#[cfg(feature = "sqlite")]
pub(crate) async fn sqlite_column_exists<Conn>(
    conn: &mut Conn,
    table: &str,
    column: &str,
) -> Result<bool, OrmError>
where
    Conn: AsyncConnection<Backend = diesel::sqlite::Sqlite>,
{
    let hit = diesel::sql_query(SQLITE_SQL)
        .bind::<diesel::sql_types::Text, _>(table)
        .bind::<diesel::sql_types::Text, _>(column)
        .get_result::<Hit>(conn)
        .await;
    Ok(hit.is_ok_and(|hit| hit.hit == 1))
}
