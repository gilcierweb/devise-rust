//! Schema probe — the `column_exists` answer behind
//! [`devise_rust::schema::check_fields`] (Devise's `check_fields!`).
//!
//! Both identifiers travel as statement BINDS (never interpolated into the
//! SQL text); the answer is row existence (`fetch().is_some()`), so no
//! per-database decoder enters the path. A catalog failure propagates as
//! [`OrmError`] — never swallowed into "absent", because a missing column
//! and an unreachable catalog must not look alike to the caller.

use devise_rust::adapter::OrmError;
use sea_orm::{ConnectionTrait, DbBackend, Statement};

use crate::bridge::SeaOrmModel;
use crate::error::map_sea_orm_error;

/// Probe the database catalog for one column of this entity's table.
///
/// # Errors
///
/// Returns [`OrmError`] when the catalog query fails.
pub async fn column_exists<E>(db: &impl ConnectionTrait, column: &str) -> Result<bool, OrmError>
where
    E: SeaOrmModel,
{
    // SQLite has no information_schema: the pragma table-valued function is
    // the catalog; every other backend answers from information_schema.
    let sql = match db.get_database_backend() {
        DbBackend::Sqlite => "SELECT 1 AS hit FROM pragma_table_info($1) WHERE name = $2 LIMIT 1",
        DbBackend::Postgres | DbBackend::MySql => {
            "SELECT 1 AS hit FROM information_schema.columns \
             WHERE table_name = $1 AND column_name = $2 LIMIT 1"
        }
    };
    let statement = Statement::from_sql_and_values(
        db.get_database_backend(),
        sql,
        vec![<E as SeaOrmModel>::table_name().into(), column.into()],
    );
    let hit = db.query_one(statement).await.map_err(map_sea_orm_error)?;
    Ok(hit.is_some())
}
