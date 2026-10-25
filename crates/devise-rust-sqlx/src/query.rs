//! `QueryBuilder` reads and writes over the [`Dialect`] seam (D-03/D-34).
//!
//! All SQL text is shaped with [`sqlx::QueryBuilder`]; every caller-supplied
//! value travels through a bind. Placeholder spelling (`$N` on Postgres, `?`
//! elsewhere) is the driver's own rendering —
//! [`Arguments::format_placeholder`](sqlx::Arguments::format_placeholder) —
//! so no dialect branch exists in this module (D-34).
//!
//! ## Why binds go through the [`Dialect`] seam
//!
//! sqlx's `Encode`/`Type` impls exist per concrete database, not for an
//! abstract `DB: Database`, so the backend-neutral [`Bind`] payload is
//! converted by each backend arm once, concretely — the sqlx analogue of
//! the diesel crate's `BackendWrites` seam. The seam also owns the uuid
//! key spelling per database (D-35): native `UUID` on Postgres, hyphenated
//! `TEXT` on SQLite/MySQL.
//!
//! ## Logging (D-12)
//!
//! Every statement logs its skeleton (`qb.sql()`, `?`/`$N` placeholders
//! only) at debug level; bound values (emails, token digests) never reach
//! logs.
//!
//! ## Statement ownership
//!
//! Statements execute through [`sqlx::query_as_with`] over the owned
//! builder SQL (`into_sql`) plus the argument buffer, with the buffer
//! rebound to drop before the SQL string: the buffer's destructor keeps
//! its GAT lifetime live, and that lifetime is unified with the SQL borrow
//! at fetch time.

use std::collections::{HashMap, HashSet};

use devise_rust::adapter::{Conditions, DeviseKey, OrmError, Value};

use crate::error::map_sqlx_error;
use crate::glue::{Bind, KeyShape, SqlxModel, WriteValue};

/// Per-database bind conversion: the one place a backend's sqlx type
/// knowledge enters the adapter.
///
/// `#[doc(hidden)]`: implementation detail of
/// [`SqlxAdapter`](crate::SqlxAdapter), implemented in this crate only.
#[doc(hidden)]
pub trait Dialect: sqlx::Database + Send + Sync + 'static {
    /// Adds one typed bind into a fresh argument buffer (the sqlx
    /// `Encode`/`Type` impls are per-database, so each backend implements
    /// this once, concretely).
    ///
    /// # Errors
    ///
    /// Returns [`OrmError::Query`] when the driver rejects the encoding.
    fn add_bind(
        args: &mut <Self as sqlx::Database>::Arguments<'_>,
        bind: Bind,
    ) -> Result<(), OrmError>;

    /// The per-database spelling of a uuid primary-key bind (D-35):
    /// native `UUID` on Postgres, hyphenated `TEXT` elsewhere.
    fn uuid_key(id: uuid::Uuid) -> Bind;

    /// Catalog-probe SQL text around the two binds `(table, column)`, the
    /// `column_exists` answer behind `devise_rust::schema::check_fields`
    /// (Devise's `check_fields!`). The default is the `information_schema`
    /// family (Postgres, MySQL); SQLite overrides it with its `pragma`.
    #[must_use]
    fn probe_sql() -> (&'static str, &'static str) {
        (
            "SELECT 1 FROM information_schema.columns WHERE table_name = ",
            " AND column_name = ",
        )
    }
}

/// Adds one bind: the driver encodes the value and renders its placeholder
/// (`?` or `$N`) into the statement skeleton.
pub(crate) fn push_bind<DB>(
    qb: &mut sqlx::QueryBuilder<'_, DB>,
    args: &mut <DB as sqlx::Database>::Arguments<'_>,
    bind: Bind,
) -> Result<(), OrmError>
where
    DB: Dialect,
{
    use sqlx::Arguments as _;
    DB::add_bind(args, bind)?;
    let mut placeholder = String::new();
    args.format_placeholder(&mut placeholder)
        .map_err(|_| OrmError::Query {
            message: "placeholder rendering failed".to_owned(),
            source: None,
        })?;
    qb.push(placeholder);
    Ok(())
}

/// Pushes a comma-separated SQL-identifier list (static glue names only).
fn push_column_list<DB: sqlx::Database>(qb: &mut sqlx::QueryBuilder<'_, DB>, columns: &[&str]) {
    let mut first = true;
    for column in columns {
        if !first {
            qb.push(", ");
        }
        qb.push(*column);
        first = false;
    }
}

/// Opens `SELECT <columns> FROM <table>` — never `SELECT *` (Pitfall 2).
fn open_select<M: SqlxModel, DB: sqlx::Database>(qb: &mut sqlx::QueryBuilder<'_, DB>) {
    qb.push("SELECT ");
    push_column_list(qb, M::columns());
    qb.push(" FROM ");
    qb.push(M::table_name());
}

/// The validated primary-key bind for `key` against the model's key shape
/// (Pitfall 10): a shape mismatch refuses with [`OrmError::InvalidKey`]
/// naming the table and column — never a silent miss.
pub(crate) fn key_bind<M: SqlxModel, DB: Dialect>(key: &DeviseKey) -> Result<Bind, OrmError> {
    match (M::key_shape(), key) {
        (KeyShape::Integer, DeviseKey::Integer(id)) => Ok(Bind::Integer(*id)),
        (KeyShape::Uuid, DeviseKey::Uuid(id)) => Ok(DB::uuid_key(*id)),
        (KeyShape::Integer, DeviseKey::Uuid(_)) => Err(OrmError::InvalidKey(format!(
            "{}.{} is an integer primary key",
            M::table_name(),
            M::pk_column()
        ))),
        (KeyShape::Uuid, DeviseKey::Integer(_)) => Err(OrmError::InvalidKey(format!(
            "{}.{} is a uuid primary key",
            M::table_name(),
            M::pk_column()
        ))),
    }
}

/// The where-clause predicate of the per-condition finder select: the
/// glue-validated `&'static` column ident plus a string bind.
fn finder_condition<M: SqlxModel>(
    column: &str,
    value: &Value,
) -> Result<(&'static str, String), OrmError> {
    let Some(static_column) = M::finder_columns().iter().find(|c| **c == column).copied() else {
        return Err(OrmError::Query {
            message: format!("unsupported finder column: {column}"),
            source: None,
        });
    };
    // Non-string values never bind against these text columns (T-06-10):
    // the same clear rejection as an out-of-set column, before any SQL.
    let Value::String(text) = value else {
        return Err(OrmError::Query {
            message: format!("unsupported finder column: {column}"),
            source: None,
        });
    };
    Ok((static_column, text.clone()))
}

/// Fetches one row by primary key (`get`): `SELECT <columns> FROM <table>
/// WHERE <pk> = ?`.
///
/// # Errors
///
/// Returns [`OrmError::InvalidKey`] on a key-shape mismatch (before any
/// SQL); backend failures surface as their [`OrmError`] mapping. A missing
/// row is `Ok(None)`, never an error.
pub(crate) async fn get_row<'c, M, DB>(
    conn: &'c mut <DB as sqlx::Database>::Connection,
    key: &DeviseKey,
) -> Result<Option<M>, OrmError>
where
    M: SqlxModel + Unpin,
    for<'r> M: sqlx::FromRow<'r, <DB as sqlx::Database>::Row>,
    DB: Dialect,
    for<'q> <DB as sqlx::Database>::Arguments<'q>: sqlx::IntoArguments<'q, DB>,
    for<'x> &'x mut <DB as sqlx::Database>::Connection: sqlx::Executor<'x, Database = DB>,
{
    let key = key_bind::<M, DB>(key)?;
    let mut args = <DB as sqlx::Database>::Arguments::<'_>::default();
    let mut qb = sqlx::QueryBuilder::<DB>::new("");
    open_select::<M, DB>(&mut qb);
    qb.push(" WHERE ");
    qb.push(M::pk_column());
    qb.push(" = ");
    push_bind(&mut qb, &mut args, key)?;
    log::debug!("devise-rust-sqlx get: {}", qb.sql());
    let (sql, args) = (qb.into_sql(), args);
    sqlx::query_as_with::<DB, M, _>(&sql, args)
        .fetch_optional(&mut *conn)
        .await
        .map_err(map_sqlx_error)
}

/// Finds the first record matching `conditions` — the sqlx leg of
/// `orm_adapter`'s `find_first` (D-02): one SELECT per curated condition,
/// result sets intersected client-side keyed by
/// [`key_of`](SqlxModel::key_of), first-query order preserved (diesel
/// parity); empty conditions return the first row of the table, like the
/// oracle.
///
/// # Errors
///
/// Returns [`OrmError::Query`] naming the column for out-of-set finder
/// columns and for non-string finder values — both before any SQL exists.
pub(crate) async fn find_first_row<'c, M, DB>(
    conn: &'c mut <DB as sqlx::Database>::Connection,
    conditions: &Conditions,
) -> Result<Option<M>, OrmError>
where
    M: SqlxModel + Unpin,
    for<'r> M: sqlx::FromRow<'r, <DB as sqlx::Database>::Row>,
    DB: Dialect,
    for<'q> <DB as sqlx::Database>::Arguments<'q>: sqlx::IntoArguments<'q, DB>,
    for<'x> &'x mut <DB as sqlx::Database>::Connection: sqlx::Executor<'x, Database = DB>,
{
    let mut ordered: Vec<DeviseKey> = Vec::new();
    let mut members: HashMap<DeviseKey, M> = HashMap::new();
    let mut first_condition = true;
    for (column, value) in conditions.iter() {
        let (static_column, text) = finder_condition::<M>(column, value)?;
        let mut args = <DB as sqlx::Database>::Arguments::<'_>::default();
        let mut qb = sqlx::QueryBuilder::<DB>::new("");
        open_select::<M, DB>(&mut qb);
        qb.push(" WHERE ");
        qb.push(static_column);
        qb.push(" = ");
        push_bind(&mut qb, &mut args, Bind::Text(text))?;
        log::debug!("devise-rust-sqlx find_first: {}", qb.sql());
        let (sql, args) = (qb.into_sql(), args);
        let rows: Vec<M> = sqlx::query_as_with::<DB, M, _>(&sql, args)
            .fetch_all(&mut *conn)
            .await
            .map_err(map_sqlx_error)?;
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
        let mut qb = sqlx::QueryBuilder::<DB>::new("");
        open_select::<M, DB>(&mut qb);
        log::debug!("devise-rust-sqlx find_first: {}", qb.sql());
        let sql = qb.into_sql();
        return sqlx::query_as_with::<DB, M, _>(
            &sql,
            <DB as sqlx::Database>::Arguments::<'_>::default(),
        )
        .fetch_optional(&mut *conn)
        .await
        .map_err(map_sqlx_error);
    }
    ordered.retain(|key| members.contains_key(key));
    Ok(ordered.into_iter().find_map(|key| members.remove(&key)))
}

/// Executes one partial `UPDATE` over `fields` (already diff- or
/// full-map-selected by the caller): the D-03 tristate — `Value::Null`
/// writes the `NULL` keyword (token clearing), every other value binds even
/// when unchanged (the devise #5783 force-write) — with column identifiers
/// taken from the glue's `&'static` spellings, never caller text.
///
/// # Errors
///
/// Returns [`OrmError::InvalidKey`] on a key-shape mismatch and
/// glue-converted [`OrmError`]s for unknown or mistyped columns — all
/// before any SQL. Backend failures surface as their [`OrmError`] mapping.
pub(crate) async fn write_fields<'c, M, DB>(
    conn: &'c mut <DB as sqlx::Database>::Connection,
    key: &DeviseKey,
    fields: &HashMap<String, Value>,
) -> Result<(), OrmError>
where
    M: SqlxModel,
    DB: Dialect,
    for<'q> <DB as sqlx::Database>::Arguments<'q>: sqlx::IntoArguments<'q, DB>,
    for<'x> &'x mut <DB as sqlx::Database>::Connection: sqlx::Executor<'x, Database = DB>,
{
    let key = key_bind::<M, DB>(key)?;
    let mut args = <DB as sqlx::Database>::Arguments::<'_>::default();
    let mut qb = sqlx::QueryBuilder::<DB>::new("UPDATE ");
    qb.push(M::table_name());
    qb.push(" SET ");
    let mut first = true;
    for (column, value) in fields {
        let (static_column, write) = M::write_bind(column, value)?;
        if !first {
            qb.push(", ");
        }
        qb.push(static_column);
        qb.push(" = ");
        match write {
            WriteValue::Null => {
                qb.push("NULL");
            }
            WriteValue::Bind(bind) => push_bind(&mut qb, &mut args, bind)?,
        }
        first = false;
    }
    qb.push(" WHERE ");
    qb.push(M::pk_column());
    qb.push(" = ");
    push_bind(&mut qb, &mut args, key)?;
    log::debug!("devise-rust-sqlx update: {}", qb.sql());
    let (sql, args) = (qb.into_sql(), args);
    sqlx::query_with::<DB, _>(&sql, args)
        .execute(&mut *conn)
        .await
        .map_err(map_sqlx_error)?;
    Ok(())
}

/// Executes one primary-key `DELETE`; deleting a missing row is a no-op.
///
/// # Errors
///
/// Returns [`OrmError::InvalidKey`] on a key-shape mismatch (before any
/// SQL); backend failures surface as their [`OrmError`] mapping.
pub(crate) async fn delete_row<'c, M, DB>(
    conn: &'c mut <DB as sqlx::Database>::Connection,
    key: &DeviseKey,
) -> Result<(), OrmError>
where
    M: SqlxModel,
    DB: Dialect,
    for<'q> <DB as sqlx::Database>::Arguments<'q>: sqlx::IntoArguments<'q, DB>,
    for<'x> &'x mut <DB as sqlx::Database>::Connection: sqlx::Executor<'x, Database = DB>,
{
    let key = key_bind::<M, DB>(key)?;
    let mut args = <DB as sqlx::Database>::Arguments::<'_>::default();
    let mut qb = sqlx::QueryBuilder::<DB>::new("DELETE FROM ");
    qb.push(M::table_name());
    qb.push(" WHERE ");
    qb.push(M::pk_column());
    qb.push(" = ");
    push_bind(&mut qb, &mut args, key)?;
    log::debug!("devise-rust-sqlx delete: {}", qb.sql());
    let (sql, args) = (qb.into_sql(), args);
    sqlx::query_with::<DB, _>(&sql, args)
        .execute(&mut *conn)
        .await
        .map_err(map_sqlx_error)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Per-database Dialect arms
// ---------------------------------------------------------------------------

/// SQLite arm: text uuids bind hyphenated (D-35, diesel precedent), all
/// other binds encode through sqlx's own codecs. INET binds as text.
#[cfg(feature = "sqlite")]
impl Dialect for sqlx::Sqlite {
    fn add_bind(
        args: &mut <Self as sqlx::Database>::Arguments<'_>,
        bind: Bind,
    ) -> Result<(), OrmError> {
        use sqlx::Arguments as _;
        let encoding_failed = |e: sqlx::error::BoxDynError| OrmError::Query {
            message: "bind encoding failed".to_owned(),
            source: Some(e),
        };
        match bind {
            Bind::Text(s) => args.add(s).map_err(encoding_failed),
            Bind::NullableText(s) => args.add(s).map_err(encoding_failed),
            Bind::Integer(i) => args.add(i).map_err(encoding_failed),
            Bind::Timestamp(t) => args.add(t).map_err(encoding_failed),
            Bind::NullableTimestamp(t) => args.add(t).map_err(encoding_failed),
            // INET columns store as text on SQLite.
            Bind::Inet(ip) => args.add(ip.to_string()).map_err(encoding_failed),
            Bind::NullableInet(ip) => args.add(ip.map(|i| i.to_string())).map_err(encoding_failed),
            // Deterministic hyphenated TEXT spelling — never the driver's
            // private uuid storage choice (Pitfall 10).
            Bind::Uuid(id) => args
                .add(id.hyphenated().to_string())
                .map_err(encoding_failed),
        }
    }

    fn uuid_key(id: uuid::Uuid) -> Bind {
        Bind::Text(id.hyphenated().to_string())
    }

    // SQLite has no information_schema: the pragma table-valued function is
    // the catalog (the table name is itself a bind argument).
    fn probe_sql() -> (&'static str, &'static str) {
        ("SELECT 1 FROM pragma_table_info(", ") WHERE name = ")
    }
}

/// Postgres arm: uuids bind native (`UUID` column — D-35), INET binds native.
#[cfg(feature = "postgres")]
impl Dialect for sqlx::Postgres {
    fn add_bind(
        args: &mut <Self as sqlx::Database>::Arguments<'_>,
        bind: Bind,
    ) -> Result<(), OrmError> {
        use sqlx::Arguments as _;
        let encoding_failed = |e: sqlx::error::BoxDynError| OrmError::Query {
            message: "bind encoding failed".to_owned(),
            source: Some(e),
        };
        match bind {
            Bind::Text(s) => args.add(s).map_err(encoding_failed),
            Bind::NullableText(s) => args.add(s).map_err(encoding_failed),
            Bind::Integer(i) => args.add(i).map_err(encoding_failed),
            Bind::Timestamp(t) => args.add(t).map_err(encoding_failed),
            Bind::NullableTimestamp(t) => args.add(t).map_err(encoding_failed),
            Bind::Uuid(id) => args.add(id).map_err(encoding_failed),
            // INET columns use TEXT in test rig (sqlx 0.8.6 INET binding not supported).
            Bind::Inet(ip) => args.add(ip.to_string()).map_err(encoding_failed),
            Bind::NullableInet(ip) => args.add(ip.map(|i| i.to_string())).map_err(encoding_failed),
        }
    }

    fn uuid_key(id: uuid::Uuid) -> Bind {
        Bind::Uuid(id)
    }
}

/// MySQL arm (experimental, D-33: compiles without CI execution): the
/// emitted mysql DDL stores uuids as `CHAR(36)`, so keys bind hyphenated.
/// INET columns store as text.
#[cfg(feature = "mysql")]
impl Dialect for sqlx::MySql {
    fn add_bind(
        args: &mut <Self as sqlx::Database>::Arguments<'_>,
        bind: Bind,
    ) -> Result<(), OrmError> {
        use sqlx::Arguments as _;
        let encoding_failed = |e: sqlx::error::BoxDynError| OrmError::Query {
            message: "bind encoding failed".to_owned(),
            source: Some(e),
        };
        match bind {
            Bind::Text(s) => args.add(s).map_err(encoding_failed),
            Bind::NullableText(s) => args.add(s).map_err(encoding_failed),
            Bind::Integer(i) => args.add(i).map_err(encoding_failed),
            Bind::Timestamp(t) => args.add(t).map_err(encoding_failed),
            Bind::NullableTimestamp(t) => args.add(t).map_err(encoding_failed),
            // INET columns store as text on MySQL.
            Bind::Inet(ip) => args.add(ip.to_string()).map_err(encoding_failed),
            Bind::NullableInet(ip) => args.add(ip.map(|i| i.to_string())).map_err(encoding_failed),
            Bind::Uuid(id) => args
                .add(id.hyphenated().to_string())
                .map_err(encoding_failed),
        }
    }

    fn uuid_key(id: uuid::Uuid) -> Bind {
        Bind::Text(id.hyphenated().to_string())
    }
}
