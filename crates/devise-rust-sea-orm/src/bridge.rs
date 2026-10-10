//! Per-model binding bridge between a Devise model and its sea-orm `Entity`
//! (D-15/D-16/D-17).
//!
//! Apps write a standard sea-orm entity via `DeriveEntityModel` (one module
//! per table, struct named `Model` as the derive requires) plus a hand-written
//! [`SeaOrmModel`] impl (D-21; `sea-orm-codegen` stays an app-side option).
//! The bridge owns:
//!
//! * the **curated finder columns** (D-02/D-17) as a name → [`Column`] map.
//!   Only the five columns Devise actually queries — `email`,
//!   `reset_password_token`, `confirmation_token`, `unlock_token`,
//!   `unconfirmed_email` — map to `Some`; anything else (and any non-string
//!   value) maps to `None`, which the adapter turns into
//!   [`OrmError::Query`] naming the column *before any SQL text exists*
//!   (T-07-01).
//! * the **primary-key condition** per [`DeviseKey`] arm, owning the
//!   per-dialect conversion (hyphenated `TEXT` for uuid-on-sqlite D-35/D-18c)
//!   and refusing shape mismatches with [`OrmError::InvalidKey`] naming
//!   `table.column` — never a silent miss (Pitfall 10).
//! * the **`ChangeSet` tristate → `ActiveModel` state** mapping (D-16):
//!   absent → `NotSet` (column omitted from the `UPDATE`), explicit
//!   `Value::Null` → `Set(None)` (writes `NULL`, e.g. token clearing), a
//!   a value → `Set(value)` written **even when unchanged** (devise #5783
//!   force-write). Sea-orm's native unchanged-detection is NOT consulted
//!   (D-16), no write path builds its `ActiveModel` from a freshly re-read
//!   row, and equality-conditioned setters never appear (Pitfall 5;
//!   T-07-04).
//! * the **counter column** allowlist mapping for
//!   [`increment_counter`](crate::counter::increment_counter) (D-11).
//!
//! [`Column`]: sea_orm::entity::ColumnTrait

use std::collections::HashMap;

use devise_rust::adapter::{DeviseKey, OrmError, Value};
use sea_orm::{EntityTrait, sea_query::SimpleExpr};

/// The curated finder columns Devise actually queries (D-02/D-17) —
/// authentication keys (`email` by default), the three token digests, and
/// the reconfirmable pending email.
///
/// [`finder_column`](SeaOrmModel::finder_column) covers ONLY these five;
/// the full sea-orm filter API is never exposed through the adapter.
pub const FINDER_COLUMNS: &[&str] = &[
    "email",
    "reset_password_token",
    "confirmation_token",
    "unlock_token",
    "unconfirmed_email",
];

/// Manual per-model binding between a Devise model and its sea-orm `Entity`.
///
/// Implement this by hand for every model (D-21); the fixture entities under
/// `tests/models.rs` are the reference impls. No entity relations are exposed
/// through this bridge — the adapter works standalone tables only (D-22).
///
/// ## Options (required assoc type)
///
/// * `InsertModel` — the insert shape consumed by `create` (D-20): a plain
///   struct carrying every column except database-generated ones; the bridge
///   turns it into an `ActiveModel` with the primary key `NotSet` (integer
///   legs) or caller-assigned (uuid legs).
///
/// ## Examples
///
/// ```rust,ignore
/// impl SeaOrmModel for users::Entity {
///     type InsertModel = NewUser;
///
///     fn table_name() -> &'static str { "users" }
///
///     fn finder_column(column: &str, value: &Value) -> Option<users::Column> {
///         if !FINDER_COLUMNS.contains(&column) { return None; }
///         let Value::String(_) = value else { return None };
///         match column {
///             "email" => Some(users::Column::Email),
///             "reset_password_token" => Some(users::Column::ResetPasswordToken),
///             "confirmation_token" => Some(users::Column::ConfirmationToken),
///             "unlock_token" => Some(users::Column::UnlockToken),
///             "unconfirmed_email" => Some(users::Column::UnconfirmedEmail),
///             _ => None,
///         }
///     }
///     // ...pk_condition / insert_model / update_base / apply_changeset / counter_column
/// }
/// ```
pub trait SeaOrmModel: EntityTrait + Send + Sync + 'static {
    /// The insert shape consumed by `create` (D-20), e.g. `NewUser` without
    /// the database-assigned id.
    type InsertModel: Send + Sync + 'static;

    /// The table identifier used in error messages (`"users"` →
    /// `InvalidKey` names `"users.id"`).
    fn table_name() -> &'static str;

    /// Maps a curated finder column name to the entity's `Column` (D-17).
    ///
    /// Returns `Some` for the five [`FINDER_COLUMNS`] given a
    /// `Value::String`, `None` for any other column name or value shape.
    /// The adapter rejects `None` as [`OrmError::Query`]
    /// `unsupported finder column: {column}` before any query exists.
    fn finder_column(column: &str, value: &Value) -> Option<Self::Column>;

    /// Builds the primary-key predicate for `key` (D-18c): the per-dialect
    /// conversion lives here (e.g. hyphenated-`TEXT` uuid spelling on
    /// sqlite).
    ///
    /// # Errors
    ///
    /// Returns [`OrmError::InvalidKey`] naming `{table}.id` when the key
    /// shape does not fit this model's primary key (an integer key against
    /// a uuid table and vice versa) — never a silent miss (Pitfall 10,
    /// D-35).
    fn pk_condition(key: &DeviseKey) -> Result<SimpleExpr, OrmError>;

    /// Builds the insert `ActiveModel` from the insert shape (D-20): every
    /// caller-owned column `Set`, the primary key `NotSet` on database-
    /// assigned (integer) legs, `Set` on caller-assigned (uuid) legs.
    fn insert_model(new: Self::InsertModel) -> Self::ActiveModel;

    /// Builds the update base `ActiveModel` for `key`: primary key `Set`
    /// (drives the `UPDATE … WHERE id = ?`), every other field `NotSet` so
    /// absent fields stay omitted (D-16). Never derived by re-reading the
    /// stored row: starting from a fetched model would seed sea-orm's native
    /// unchanged-detection and drop the #5783 force-write.
    ///
    /// # Errors
    ///
    /// Returns [`OrmError::InvalidKey`] when `key` does not fit this model's
    /// primary key shape.
    fn update_base(key: &DeviseKey) -> Result<Self::ActiveModel, OrmError>;

    /// Applies a named field map onto the update base with Set-only states
    /// (D-16): `Value::Null` → `Set(None)` (writes `NULL`), any other value
    /// → `Set(value)` written even when equal to the stored value (devise
    /// #5783 force-write). Fields absent from the map stay `NotSet`.
    ///
    /// # Errors
    ///
    /// Returns [`OrmError::Query`] naming the column for unknown columns,
    /// the immutable `id`, a NULL aimed at a `NOT NULL` column, or a value
    /// that does not fit its column type — never the value itself.
    fn apply_changeset(
        am: &mut Self::ActiveModel,
        fields: &HashMap<String, Value>,
    ) -> Result<(), OrmError>;

    /// Maps the named counter column to the entity's `Column` for the
    /// atomic `SET column = column + 1` increment (D-11).
    ///
    /// The adapter validates `column` against the core
    /// [`COUNTER_COLUMNS`](devise_rust::adapter::COUNTER_COLUMNS) allowlist
    /// before calling; a hand-written impl receiving anything else must
    /// still error rather than write (defense in depth).
    ///
    /// # Errors
    ///
    /// Returns [`OrmError::Query`] naming `column` when it is not one of
    /// `failed_attempts` / `sign_in_count`.
    fn counter_column(column: &'static str) -> Result<Self::Column, OrmError>;
}

/// Extracts a required string, naming the column (never the value) on
/// mismatch — the diesel `changeset.rs` `type_mismatch` discipline.
///
/// # Errors
///
/// [`OrmError::Query`] when `value` is not a [`Value::String`].
pub fn extract_required_string(column: &str, value: &Value) -> Result<String, OrmError> {
    match value {
        Value::String(s) => Ok(s.clone()),
        Value::Null => Err(OrmError::Query {
            message: format!("column {column} cannot be null"),
            source: None,
        }),
        _ => Err(OrmError::Query {
            message: format!("column {column} cannot be written from a non-string value"),
            source: None,
        }),
    }
}

/// Extracts a nullable string; [`Value::Null`] becomes `None`
/// (`Set(None)` → writes `NULL`, e.g. token clearing).
///
/// # Errors
///
/// [`OrmError::Query`] when `value` is neither a string nor null.
pub fn extract_nullable_string(column: &str, value: &Value) -> Result<Option<String>, OrmError> {
    match value {
        Value::String(s) => Ok(Some(s.clone())),
        Value::Null => Ok(None),
        _ => Err(OrmError::Query {
            message: format!("column {column} cannot be written from a non-string value"),
            source: None,
        }),
    }
}

/// Extracts a required `i32` counter value (`sign_in_count`,
/// `failed_attempts` are `INTEGER NOT NULL DEFAULT 0`): refuses truncation
/// instead of wrapping.
///
/// # Errors
///
/// [`OrmError::Query`] when `value` is not an integer or falls outside
/// `i32`.
pub fn extract_required_i32(column: &str, value: &Value) -> Result<i32, OrmError> {
    let raw = match value {
        Value::Integer(i) => *i,
        Value::Null => {
            return Err(OrmError::Query {
                message: format!("column {column} cannot be null"),
                source: None,
            });
        }
        _ => {
            return Err(OrmError::Query {
                message: format!("column {column} cannot be written from a non-integer value"),
                source: None,
            });
        }
    };
    i32::try_from(raw).map_err(|_| OrmError::Query {
        message: format!("column {column} cannot be written from an out-of-range integer"),
        source: None,
    })
}

/// Parses the timestamp spellings the model layer writes through
/// `Value::String`: the shared-suite ISO 8601 `T` form
/// (`2026-06-07T08:09:10`) and the space-separated form
/// (`2026-01-02 03:04:05`) — the same dual acceptance the diesel changeset
/// bridge documents (STATE: chrono's serde requires the `T` form, the diesel
/// bridge accepts both).
///
/// # Errors
///
/// [`OrmError::Query`] when `value` is not a parseable timestamp string.
pub fn extract_required_datetime(
    column: &str,
    value: &Value,
) -> Result<chrono::NaiveDateTime, OrmError> {
    match value {
        Value::String(s) => parse_datetime(column, s),
        Value::Null => Err(OrmError::Query {
            message: format!("column {column} cannot be null"),
            source: None,
        }),
        _ => Err(OrmError::Query {
            message: format!("column {column} cannot be written from a non-datetime value"),
            source: None,
        }),
    }
}

/// Nullable variant of [`extract_required_datetime`]: `NULL` clears the
/// column (`Set(None)`).
///
/// # Errors
///
/// [`OrmError::Query`] when `value` is not a parseable timestamp string or
/// null.
pub fn extract_nullable_datetime(
    column: &str,
    value: &Value,
) -> Result<Option<chrono::NaiveDateTime>, OrmError> {
    match value {
        Value::String(s) => parse_datetime(column, s).map(Some),
        Value::Null => Ok(None),
        _ => Err(OrmError::Query {
            message: format!("column {column} cannot be written from a non-datetime value"),
            source: None,
        }),
    }
}

/// Both accepted spellings, one parser.
fn parse_datetime(column: &str, raw: &str) -> Result<chrono::NaiveDateTime, OrmError> {
    chrono::NaiveDateTime::parse_from_str(raw, "%Y-%m-%d %H:%M:%S")
        .or_else(|_| chrono::NaiveDateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M:%S"))
        .map_err(|_| OrmError::Query {
            message: format!("column {column} cannot be written from an invalid datetime value"),
            source: None,
        })
}
