//! `ChangeSet` → `AsChangeset` tristate bridge helpers (D-04/D-05).
//!
//! Devise must express three write states per column: skip the column
//! (untouched), write `NULL` (clearing `reset_password_token`, `unlock_token`,
//! `locked_at`, …), and force-write a value even when unchanged (devise
//! #5783 — the reconfirmation race fix). Diesel's `AsChangeset` derive carries
//! exactly this tristate when NULL-capable columns are typed
//! `Option<Option<T>>`: `None` skips, `Some(None)` writes `NULL`,
//! `Some(Some(v))` writes `v`. (Plain `Option<T>` gives skip/write only —
//! `None` never writes `NULL` — so NOT NULL columns stay plain `Option<T>`.)
//!
//! Each model declares its own changeset struct plus a hand-rolled per-field
//! `fill` (the research-sanctioned escape hatch — a plain serde derive cannot
//! express double-`Option` absent-vs-null without `serde_with` friction).
//! The fill delegates per column to one extractor below, so the error
//! contract is uniform:
//!
//! * `Value::Null` into a NOT NULL (plain-`Option`) field →
//!   [`OrmError::Serialization`] (the bridge refuses to write `NULL` where
//!   the column forbids it).
//! * Wrong-typed value, unparseable datetime, or unknown column →
//!   [`OrmError::Query`] naming the column, never the value.
//!
//! [`OrmError::Serialization`]: devise_rust::adapter::OrmError::Serialization
//! [`OrmError::Query`]: devise_rust::adapter::OrmError::Query

use devise_rust::adapter::{OrmError, Value};

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
pub fn required_string(column: &str, value: &Value) -> Result<String, OrmError> {
    match value {
        Value::String(s) => Ok(s.clone()),
        Value::Null => Err(null_into_required(column)),
        _ => Err(type_mismatch(column, "string")),
    }
}

/// Extracts a nullable string field: `Null` → `None` (write `NULL`).
///
/// # Errors
///
/// Returns [`OrmError::Query`] for non-string, non-null values.
pub fn nullable_string(column: &str, value: &Value) -> Result<Option<String>, OrmError> {
    match value {
        Value::Null => Ok(None),
        Value::String(s) => Ok(Some(s.clone())),
        _ => Err(type_mismatch(column, "string")),
    }
}

/// Extracts a required counter field.
///
/// # Errors
///
/// Returns [`OrmError::Serialization`] for `Value::Null` or an out-of-range
/// integer, [`OrmError::Query`] for non-integer values.
pub fn required_i32(column: &str, value: &Value) -> Result<i32, OrmError> {
    match value {
        Value::Integer(i) => (*i).try_into().map_err(|_| null_into_required(column)),
        Value::Null => Err(null_into_required(column)),
        _ => Err(type_mismatch(column, "integer")),
    }
}

/// Extracts a nullable counter field: `Null` → `None` (write `NULL`).
///
/// # Errors
///
/// Returns [`OrmError::Query`] for non-integer, non-null values.
pub fn nullable_i32(column: &str, value: &Value) -> Result<Option<i32>, OrmError> {
    match value {
        Value::Null => Ok(None),
        Value::Integer(i) => (*i)
            .try_into()
            .map(Some)
            .map_err(|_| type_mismatch(column, "32-bit integer")),
        _ => Err(type_mismatch(column, "integer")),
    }
}

/// SQLite datetime spellings accepted from string values.
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

/// Extracts a required datetime field from its SQLite string spelling.
///
/// # Errors
///
/// Returns [`OrmError::Serialization`] for `Value::Null`, [`OrmError::Query`]
/// for non-string values or unparseable strings.
pub fn required_datetime(column: &str, value: &Value) -> Result<chrono::NaiveDateTime, OrmError> {
    match value {
        Value::Null => Err(null_into_required(column)),
        Value::String(s) => DATETIME_FORMATS
            .iter()
            .find_map(|fmt| chrono::NaiveDateTime::parse_from_str(s, fmt).ok())
            .ok_or_else(|| parse_datetime(column)),
        _ => Err(type_mismatch(column, "datetime string")),
    }
}

/// Extracts a nullable datetime field: `Null` → `None` (write `NULL`).
///
/// # Errors
///
/// Returns [`OrmError::Query`] for non-string, non-null values or
/// unparseable strings.
pub fn nullable_datetime(
    column: &str,
    value: &Value,
) -> Result<Option<chrono::NaiveDateTime>, OrmError> {
    match value {
        Value::Null => Ok(None),
        Value::String(_) => required_datetime(column, value).map(Some),
        _ => Err(type_mismatch(column, "datetime string")),
    }
}
