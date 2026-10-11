//! Hand-written per-model binding glue (D-01/D-02/D-07).
//!
//! sqlx's `Encode`/`Type` impls are per-database, and the core crate must
//! stay free of ORM types (D-18b mongo-proofing), so binding happens in two
//! steps: each model implements [`SqlxModel`] by hand to expose its static
//! table/column names, its primary-key shape, and a backend-neutral
//! [`Bind`] conversion for write values; the per-database `Dialect` seam in
//! `crate::query` then turns each [`Bind`] into a real sqlx bind. The glue
//! never takes a connection — execution happens only at
//! `SqlxAdapter` op boundaries.
//!
//! ## Finder columns (D-02)
//!
//! [`finder_columns`](SqlxModel::finder_columns) covers ONLY the columns
//! Devise actually queries: authentication keys (`email` by default),
//! `reset_password_token`, `confirmation_token`, `unlock_token`, and
//! `unconfirmed_email`. Any other column name — and any non-string value
//! against these text columns — is rejected by the adapter as
//! [`OrmError::Query`] naming the
//! column and never the value, *before any SQL exists*. Identical behavior
//! to the diesel backend.
//!
//! ## Write tristate (D-03)
//!
//! [`write_bind`](SqlxModel::write_bind) mirrors the diesel changeset
//! extractors: `Value::Null` into a nullable column becomes
//! [`WriteValue::Null`] (writes `NULL` — token clearing), `Value::Null` into
//! a NOT NULL column refuses with [`OrmError::Serialization`], and every
//! typed value converts to a [`Bind`] that is written even when unchanged
//! (the devise #5783 force-write). Unknown or immutable (`id`) columns fail
//! loud, naming the column.
//!
//! ## Examples
//!
//! ```rust,ignore
//! use devise_rust::adapter::{DeviseKey, OrmError, Value};
//! use devise_rust_sqlx::{Bind, KeyShape, SqlxModel, WriteValue};
//! use std::collections::HashMap;
//!
//! # struct User;
//! # struct NewUser;
//! impl SqlxModel for User {
//!     type New = NewUser;
//!
//!     fn table_name() -> &'static str { "users" }
//!     fn pk_column() -> &'static str { "id" }
//!     fn columns() -> &'static [&'static str] {
//!         &["id", "email", "encrypted_password", "created_at", "updated_at"]
//!     }
//!     fn key_shape() -> KeyShape { KeyShape::Integer }
//!     fn key_of(model: &Self) -> DeviseKey { DeviseKey::from_i64(model.id) }
//!     fn finder_columns() -> &'static [&'static str] { &["email"] }
//!     fn insert_columns() -> &'static [&'static str] {
//!         &["email", "encrypted_password", "created_at", "updated_at"]
//!     }
//!     fn insert_values(new: &Self::New) -> Vec<Bind> { /* one Bind per insert column */ # vec![] }
//!     fn write_bind(column: &str, value: &Value)
//!         -> Result<(&'static str, WriteValue), OrmError> {
//!         # let _ = (column, value);
//!         # Err(OrmError::NotFound)
//!     }
//! }
//! ```

use chrono::NaiveDateTime;
use devise_rust::adapter::{DeviseKey, OrmError, Value};
use std::net::IpAddr;
use uuid::Uuid;

/// Primary-key shape a model stores under (D-35): integer identity columns
/// and uuid columns (native `UUID` on Postgres, hyphenated `TEXT` on SQLite).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyShape {
    /// Auto-increment integer identity (sqlite `INTEGER PRIMARY KEY
    /// AUTOINCREMENT`, postgres `BIGSERIAL`).
    Integer,
    /// Application-assigned uuid (postgres native `UUID`, sqlite
    /// hyphenated `TEXT`).
    Uuid,
}

/// Backend-neutral typed bind payload.
///
/// The per-database `Encode`/`Type` knowledge lives in the `Dialect` seam
/// (`crate::query`); the glue only decides WHICH type a column binds as.
/// Nullable variants carry `Option` directly so an insert of a cleared
/// column binds a TYPED null (Postgres requires typed parameters even for
/// `NULL`); the write path never uses them — `Value::Null` writes the SQL
/// `NULL` keyword instead (D-03).
#[derive(Debug, Clone)]
pub enum Bind {
    /// Text column value (tokens, digests, emails, hyphenated uuid `TEXT`).
    Text(String),
    /// Nullable text column insert (`None` binds a typed `NULL`).
    NullableText(Option<String>),
    /// Integer column value (i64 keys, counters).
    Integer(i64),
    /// Timestamp column value, bound as a native datetime (never
    /// pre-formatted — Pitfall 9).
    Timestamp(NaiveDateTime),
    /// Nullable timestamp column insert (`None` binds a typed `NULL`).
    NullableTimestamp(Option<NaiveDateTime>),
    /// Native uuid bind (Postgres primary keys — D-35).
    Uuid(Uuid),
    /// INET column value (Postgres `INET` type for IP addresses).
    Inet(IpAddr),
    /// Nullable INET column insert (`None` binds a typed `NULL`).
    NullableInet(Option<IpAddr>),
}

/// The write-state of one named column (D-03 tristate).
///
/// `Value::Null` into a nullable column becomes [`WriteValue::Null`]: the
/// adapter pushes the SQL `NULL` keyword (never a bind). Every other value
/// converts to a typed [`Bind`].
#[derive(Debug, Clone)]
pub enum WriteValue {
    /// Bind the typed value (written even when unchanged — #5783).
    Bind(Bind),
    /// Write the SQL `NULL` keyword (token clearing).
    Null,
}

/// Hand-written binding between a Devise model and its sqlx table (D-01).
///
/// Implement this by hand for every model deriving
/// `sqlx::FromRow` (no derive macro in this phase; a future
/// `devise-rust-derive` proc-macro may sugar the same trait). All names the
/// adapter interpolates into SQL text come from these `&'static` constants —
/// caller input only ever travels through binds, never into statement text.
pub trait SqlxModel: Send + Sync + Sized + 'static {
    /// The insert shape consumed by [`create`](devise_rust::adapter::OrmAdapter::create)
    /// (D-05): every column except the database-assigned id.
    type New: Send + Sync + 'static;

    /// The table name for query roots (`"users"`).
    fn table_name() -> &'static str;

    /// The primary-key column name (`"id"`).
    fn pk_column() -> &'static str;

    /// The ordered SELECT column list (Pitfall 2): every read builds
    /// `SELECT <columns> FROM <table>` from this — never `SELECT *`, so DDL
    /// drift breaks loudly instead of mapping fields positionally.
    fn columns() -> &'static [&'static str];

    /// The primary-key shape this table stores under.
    fn key_shape() -> KeyShape;

    /// Extracts the record's primary key as a [`DeviseKey`].
    fn key_of(model: &Self) -> DeviseKey;

    /// The curated finder allowlist (D-02): authentication keys plus the
    /// token-digest columns plus `unconfirmed_email`. Out-of-set names are
    /// rejected before any SQL exists.
    fn finder_columns() -> &'static [&'static str];

    /// The ordered INSERT column list (D-05), positionally matching
    /// [`insert_values`](SqlxModel::insert_values).
    fn insert_columns() -> &'static [&'static str];

    /// Typed bind values for one insert row — exactly one per
    /// [`insert_columns`](SqlxModel::insert_columns) entry, in order.
    fn insert_values(new: &Self::New) -> Vec<Bind>;

    /// Converts one named write value into a typed bind or a `NULL` write,
    /// validating the column name (D-03).
    ///
    /// The returned column name is the model's own `&'static` spelling —
    /// the ident the adapter interpolates, so caller text can never become
    /// SQL.
    ///
    /// # Errors
    ///
    /// Returns [`OrmError::Query`] naming `column` for unknown columns and
    /// for the immutable `id`; [`OrmError::Serialization`] for `Value::Null`
    /// into a NOT NULL column; [`OrmError::Query`] naming `column` for
    /// values that do not fit the column's type (never the value itself).
    fn write_bind(column: &str, value: &Value) -> Result<(&'static str, WriteValue), OrmError>;
}

/// The finder allowlist shared by every model (D-02): authentication keys,
/// the three token-digest columns, and reconfirmable's `unconfirmed_email`.
pub const FINDER_COLUMNS: &[&str] = &[
    "email",
    "reset_password_token",
    "confirmation_token",
    "unlock_token",
    "unconfirmed_email",
];

/// Failure message naming only the column (never the offending value).
fn type_mismatch(column: &str, expected: &str) -> OrmError {
    OrmError::Query {
        message: format!("column {column} cannot be written from a non-{expected} value"),
        source: None,
    }
}

/// `NULL` written into a NOT NULL column — a bridge-level refusal.
fn null_into_required(column: &str) -> OrmError {
    OrmError::Serialization(<serde_json::Error as serde::de::Error>::custom(format!(
        "column {column} is NOT NULL and cannot be written from Null"
    )))
}

/// Extracts a required (NOT NULL) string field.
///
/// # Errors
///
/// Returns [`OrmError::Serialization`] for `Value::Null`, [`OrmError::Query`]
/// for any other non-string value.
pub fn required_string(column: &str, value: &Value) -> Result<WriteValue, OrmError> {
    match value {
        Value::String(s) => Ok(WriteValue::Bind(Bind::Text(s.clone()))),
        Value::Null => Err(null_into_required(column)),
        _ => Err(type_mismatch(column, "string")),
    }
}

/// Extracts a nullable string field: `Null` becomes the SQL `NULL` write.
///
/// # Errors
///
/// Returns [`OrmError::Query`] for non-string, non-null values.
pub fn nullable_string(column: &str, value: &Value) -> Result<WriteValue, OrmError> {
    match value {
        Value::Null => Ok(WriteValue::Null),
        Value::String(s) => Ok(WriteValue::Bind(Bind::Text(s.clone()))),
        _ => Err(type_mismatch(column, "string")),
    }
}

/// Extracts a required (NOT NULL) 64-bit integer field (sqlite counters and
/// integer keys).
///
/// # Errors
///
/// Returns [`OrmError::Serialization`] for `Value::Null`,
/// [`OrmError::Query`] for non-integer values.
pub fn required_i64(column: &str, value: &Value) -> Result<WriteValue, OrmError> {
    match value {
        Value::Integer(i) => Ok(WriteValue::Bind(Bind::Integer(*i))),
        Value::Null => Err(null_into_required(column)),
        _ => Err(type_mismatch(column, "integer")),
    }
}

/// Extracts a nullable 64-bit integer field: `Null` becomes the SQL `NULL`
/// write.
///
/// # Errors
///
/// Returns [`OrmError::Query`] for non-integer, non-null values.
pub fn nullable_i64(column: &str, value: &Value) -> Result<WriteValue, OrmError> {
    match value {
        Value::Null => Ok(WriteValue::Null),
        Value::Integer(i) => Ok(WriteValue::Bind(Bind::Integer(*i))),
        _ => Err(type_mismatch(column, "integer")),
    }
}

/// Datetime string spellings accepted from string values (the diesel
/// changeset bridge accepts the same two).
const DATETIME_FORMATS: &[&str] = &["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"];

/// Parses a datetime string without ever echoing the value into the error.
fn parse_datetime(column: &str) -> OrmError {
    OrmError::Query {
        message: format!(
            "column {column} expects a datetime string ({} or {})",
            DATETIME_FORMATS[0], DATETIME_FORMATS[1]
        ),
        source: None,
    }
}

/// Extracts a required (NOT NULL) datetime field from its string spelling,
/// binding the parsed `NaiveDateTime` directly (Pitfall 9: never
/// pre-format back to a string — the driver owns the on-disk encoding).
///
/// # Errors
///
/// Returns [`OrmError::Serialization`] for `Value::Null`, [`OrmError::Query`]
/// for non-string values or unparseable strings.
pub fn required_datetime(column: &str, value: &Value) -> Result<WriteValue, OrmError> {
    match value {
        Value::Null => Err(null_into_required(column)),
        Value::String(s) => {
            let parsed = DATETIME_FORMATS
                .iter()
                .find_map(|fmt| NaiveDateTime::parse_from_str(s, fmt).ok())
                .ok_or_else(|| parse_datetime(column))?;
            Ok(WriteValue::Bind(Bind::Timestamp(parsed)))
        }
        _ => Err(type_mismatch(column, "datetime string")),
    }
}

/// Extracts a nullable datetime field: `Null` becomes the SQL `NULL` write.
///
/// # Errors
///
/// Returns [`OrmError::Query`] for non-string, non-null values or
/// unparseable strings.
pub fn nullable_datetime(column: &str, value: &Value) -> Result<WriteValue, OrmError> {
    match value {
        Value::Null => Ok(WriteValue::Null),
        Value::String(_) => required_datetime(column, value),
        _ => Err(type_mismatch(column, "datetime string")),
    }
}

/// Extracts a required (NOT NULL) INET field from its string spelling,
/// binding the parsed `IpAddr` directly.
///
/// # Errors
///
/// Returns [`OrmError::Serialization`] for `Value::Null`, [`OrmError::Query`]
/// for non-string values or unparseable strings.
pub fn required_inet(column: &str, value: &Value) -> Result<WriteValue, OrmError> {
    match value {
        Value::Null => Err(null_into_required(column)),
        Value::String(s) => {
            let parsed = s.parse::<IpAddr>().map_err(|_| OrmError::Query {
                message: format!("column {column} expects an IP address"),
                source: None,
            })?;
            Ok(WriteValue::Bind(Bind::Inet(parsed)))
        }
        _ => Err(type_mismatch(column, "IP address")),
    }
}

/// Extracts a nullable INET field: `Null` becomes the SQL `NULL` write.
///
/// # Errors
///
/// Returns [`OrmError::Query`] for non-string, non-null values or
/// unparseable strings.
pub fn nullable_inet(column: &str, value: &Value) -> Result<WriteValue, OrmError> {
    match value {
        Value::Null => Ok(WriteValue::Null),
        Value::String(_) => required_inet(column, value),
        _ => Err(type_mismatch(column, "IP address")),
    }
}
