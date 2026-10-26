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

/// Classifies one catalog-probe outcome into the `column_exists` answer.
///
/// A hit row carries the answer (`1` means present). diesel's `get_result`
/// reports "zero rows" as [`diesel::result::Error::NotFound`] — that is the
/// column-absent answer, `Ok(false)`, never a failure. Every OTHER catalog
/// failure (connection loss, malformed schema, …) maps through the crate's
/// diesel error mapper ([`crate::error::map_diesel_error`]) and surfaces as
/// [`OrmError`], never swallowed into a silent "absent" (M1: parity with the
/// sqlx `fetch_optional(...).map_err(map_sqlx_error)?` and sea-orm
/// `query_one(...).map_err(map_sea_orm_error)?` seams, and with this module's
/// own doc contract).
fn classify_probe_result(
    result: Result<Hit, diesel::result::Error>,
) -> Result<bool, OrmError> {
    match result {
        Ok(hit) => Ok(hit.hit == 1),
        Err(diesel::result::Error::NotFound) => Ok(false),
        Err(other) => Err(crate::error::map_diesel_error(other)),
    }
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
    let result = diesel::sql_query(POSTGRES_SQL)
        .bind::<diesel::sql_types::Text, _>(table)
        .bind::<diesel::sql_types::Text, _>(column)
        .get_result::<Hit>(conn)
        .await;
    // Not-found is `Ok(false)`; every other catalog failure maps to `OrmError`
    // (never swallowed into "absent") — see `classify_probe_result`.
    classify_probe_result(result)
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
    let result = diesel::sql_query(SQLITE_SQL)
        .bind::<diesel::sql_types::Text, _>(table)
        .bind::<diesel::sql_types::Text, _>(column)
        .get_result::<Hit>(conn)
        .await;
    // Not-found is `Ok(false)`; every other catalog failure maps to `OrmError`
    // (never swallowed into "absent") — see `classify_probe_result`.
    classify_probe_result(result)
}

#[cfg(test)]
mod tests {
    use super::{Hit, classify_probe_result};

    /// A hit row carries the existence answer: `1` is present, any other
    /// value is absent — both `Ok`, never an error.
    #[test]
    fn hit_row_reports_presence() {
        assert!(matches!(classify_probe_result(Ok(Hit { hit: 1 })), Ok(true)));
        assert!(matches!(classify_probe_result(Ok(Hit { hit: 0 })), Ok(false)));
    }

    /// diesel reports "zero rows" as `NotFound`; that is the absent answer,
    /// `Ok(false)` — NOT a catalog failure.
    #[test]
    fn not_found_is_absent_not_error() {
        assert!(matches!(
            classify_probe_result(Err(diesel::result::Error::NotFound)),
            Ok(false)
        ));
    }

    /// The M1 regression guard: a genuine catalog failure (any non-NotFound
    /// diesel error) must surface as [`devise_rust::adapter::OrmError`],
    /// never silently collapse into `Ok(false)` — the pre-fix
    /// `is_ok_and` swallowed every error into "absent".
    #[test]
    fn catalog_failure_is_not_swallowed_into_absent() {
        let result =
            classify_probe_result(Err(diesel::result::Error::RollbackTransaction));
        assert!(
            result.is_err(),
            "a catalog failure must map to Err, not Ok(false): {result:?}"
        );
    }

    /// End-to-end sqlite sibling: the real catalog query reports a present
    /// column as `Ok(true)` and an absent one as `Ok(false)` over a live
    /// `:memory:` pool (the classifier's `NotFound` arm rides this query).
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn sqlite_probe_reports_present_and_absent() {
        use diesel_async::RunQueryDsl as _;

        let pool = crate::pool::sqlite_memory_pool().expect("in-memory pool builds");
        let mut conn = pool.get().await.expect("pool checkout works");
        let conn: &mut _ = &mut conn;
        diesel::sql_query("CREATE TABLE probe_target (present INTEGER, other INTEGER)")
            .execute(conn)
            .await
            .expect("fixture table creates");

        assert!(
            super::sqlite_column_exists(conn, "probe_target", "present")
                .await
                .expect("present probe is Ok"),
            "an existing column reports Ok(true)"
        );
        assert!(
            !super::sqlite_column_exists(conn, "probe_target", "missing_column")
                .await
                .expect("absent probe is Ok(false), never an error"),
            "a missing column reports Ok(false)"
        );
    }
}
