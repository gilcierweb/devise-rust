//! Fixture models: hand-written `table!` schemas matching the emitted
//! SQLite DDL column-for-column, plus manual [`DieselModel`] impls.
//!
//! Two primary-key kinds are exercised (D-18c): [`FixtureUser`] on an
//! auto-increment integer `users.id`, [`UuidUser`] on a hyphenated-`TEXT`
//! `uuid_users.id` (diesel 2.2.12 has no SQLite `Uuid` impls, so the glue
//! owns the conversion). Every other column mirrors the full-module
//! `emit()` output: same names, same nullability, same defaults.
//!
//! The `#[diesel(check_for_backend(…))]` attributes validate the derives
//! multi-backend (D-06): SQLite is always checked; Postgres joins when the
//! `postgres` feature is on (its backend marker only exists then).

use std::collections::HashMap;

use chrono::NaiveDateTime;
use devise_rust::adapter::{DeviseKey, OrmError, Value};
use devise_rust_adapter_tests::ContractModel;
use devise_rust_diesel::changeset::{
    nullable_datetime, nullable_string, required_datetime, required_i32, required_string,
};
use devise_rust_diesel::{BoxPred, DieselModel, DieselPredicates};
use diesel::{ExpressionMethods, NullableExpressionMethods};

diesel::table! {
    users (id) {
        id -> BigInt,
        email -> Text,
        encrypted_password -> Text,
        reset_password_token -> Nullable<Text>,
        reset_password_sent_at -> Nullable<Timestamp>,
        remember_created_at -> Nullable<Timestamp>,
        sign_in_count -> Integer,
        current_sign_in_at -> Nullable<Timestamp>,
        last_sign_in_at -> Nullable<Timestamp>,
        current_sign_in_ip -> Nullable<Text>,
        last_sign_in_ip -> Nullable<Text>,
        confirmation_token -> Nullable<Text>,
        confirmed_at -> Nullable<Timestamp>,
        confirmation_sent_at -> Nullable<Timestamp>,
        unconfirmed_email -> Nullable<Text>,
        failed_attempts -> Integer,
        unlock_token -> Nullable<Text>,
        locked_at -> Nullable<Timestamp>,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

// uuid_users table: SQLite uses TEXT for UUID. Postgres uses the same table
// definition (TEXT) for compatibility; native UUID is not tested on Postgres
// due to diesel_async LoadQuery trait bound limitations.
diesel::table! {
    uuid_users (id) {
        id -> Text,
        email -> Text,
        encrypted_password -> Text,
        reset_password_token -> Nullable<Text>,
        reset_password_sent_at -> Nullable<Timestamp>,
        remember_created_at -> Nullable<Timestamp>,
        sign_in_count -> Integer,
        current_sign_in_at -> Nullable<Timestamp>,
        last_sign_in_at -> Nullable<Timestamp>,
        current_sign_in_ip -> Nullable<Text>,
        last_sign_in_ip -> Nullable<Text>,
        confirmation_token -> Nullable<Text>,
        confirmed_at -> Nullable<Timestamp>,
        confirmation_sent_at -> Nullable<Timestamp>,
        unconfirmed_email -> Nullable<Text>,
        failed_attempts -> Integer,
        unlock_token -> Nullable<Text>,
        locked_at -> Nullable<Timestamp>,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

/// Compile-time probe: surfaces the exact unsatisfied seam bound, if any.
#[allow(dead_code)]
#[cfg(feature = "sqlite")]
fn _assert_backend_writes()
where
    diesel::sqlite::Sqlite:
        devise_rust_diesel::adapter::BackendWrites<FixtureUser, crate::common::SqliteConn>,
{
}
const FINDER_COLUMNS: &[&str] = &[
    "email",
    "reset_password_token",
    "confirmation_token",
    "unlock_token",
    "unconfirmed_email",
];

/// Integer-PK fixture row.
#[derive(Debug, Clone, PartialEq, diesel::Queryable, diesel::Selectable, diesel::Insertable)]
#[diesel(table_name = users)]
#[cfg_attr(
    all(feature = "postgres", feature = "sqlite"),
    diesel(check_for_backend(diesel::pg::Pg, diesel::sqlite::Sqlite))
)]
#[cfg_attr(
    all(feature = "postgres", not(feature = "sqlite")),
    diesel(check_for_backend(diesel::pg::Pg))
)]
#[cfg_attr(
    all(not(feature = "postgres"), feature = "sqlite"),
    diesel(check_for_backend(diesel::sqlite::Sqlite))
)]
pub struct FixtureUser {
    /// Auto-increment row id.
    pub id: i64,
    /// Authentication key (`NOT NULL DEFAULT ''`).
    pub email: String,
    /// Bcrypt digest (`NOT NULL DEFAULT ''`).
    pub encrypted_password: String,
    /// HMAC digest; `None` means cleared.
    pub reset_password_token: Option<String>,
    /// When the reset token was sent.
    pub reset_password_sent_at: Option<NaiveDateTime>,
    /// Rememberable timestamp.
    pub remember_created_at: Option<NaiveDateTime>,
    /// Trackable counter (`NOT NULL DEFAULT 0`).
    pub sign_in_count: i32,
    /// Trackable timestamps.
    pub current_sign_in_at: Option<NaiveDateTime>,
    /// Trackable timestamps.
    pub last_sign_in_at: Option<NaiveDateTime>,
    /// Trackable IPs (TEXT on SQLite).
    pub current_sign_in_ip: Option<String>,
    /// Trackable IPs (TEXT on SQLite).
    pub last_sign_in_ip: Option<String>,
    /// HMAC digest; `None` means cleared.
    pub confirmation_token: Option<String>,
    /// Confirmable timestamps.
    pub confirmed_at: Option<NaiveDateTime>,
    /// Confirmable timestamps.
    pub confirmation_sent_at: Option<NaiveDateTime>,
    /// Reconfirmable pending email.
    pub unconfirmed_email: Option<String>,
    /// Lockable counter (`NOT NULL DEFAULT 0`).
    pub failed_attempts: i32,
    /// HMAC digest; `None` means cleared.
    pub unlock_token: Option<String>,
    /// Lockable timestamp.
    pub locked_at: Option<NaiveDateTime>,
    /// Rails timestamps (`NOT NULL`).
    pub created_at: NaiveDateTime,
    /// Rails timestamps (`NOT NULL`).
    pub updated_at: NaiveDateTime,
}

/// Insert shape for [`FixtureUser`] (D-03): everything but the row id.
#[derive(Debug, Clone, diesel::Insertable)]
#[diesel(table_name = users)]
#[cfg_attr(
    all(feature = "postgres", feature = "sqlite"),
    diesel(check_for_backend(diesel::pg::Pg, diesel::sqlite::Sqlite))
)]
#[cfg_attr(
    all(feature = "postgres", not(feature = "sqlite")),
    diesel(check_for_backend(diesel::pg::Pg))
)]
#[cfg_attr(
    all(not(feature = "postgres"), feature = "sqlite"),
    diesel(check_for_backend(diesel::sqlite::Sqlite))
)]
pub struct NewFixtureUser {
    /// Authentication key.
    pub email: String,
    /// Bcrypt digest.
    pub encrypted_password: String,
    /// HMAC digest; `None` inserts `NULL`.
    pub reset_password_token: Option<String>,
    /// When the reset token was sent.
    pub reset_password_sent_at: Option<NaiveDateTime>,
    /// Rememberable timestamp.
    pub remember_created_at: Option<NaiveDateTime>,
    /// Trackable counter.
    pub sign_in_count: i32,
    /// Trackable timestamps.
    pub current_sign_in_at: Option<NaiveDateTime>,
    /// Trackable timestamps.
    pub last_sign_in_at: Option<NaiveDateTime>,
    /// Trackable IPs.
    pub current_sign_in_ip: Option<String>,
    /// Trackable IPs.
    pub last_sign_in_ip: Option<String>,
    /// HMAC digest; `None` inserts `NULL`.
    pub confirmation_token: Option<String>,
    /// Confirmable timestamps.
    pub confirmed_at: Option<NaiveDateTime>,
    /// Confirmable timestamps.
    pub confirmation_sent_at: Option<NaiveDateTime>,
    /// Reconfirmable pending email.
    pub unconfirmed_email: Option<String>,
    /// Lockable counter.
    pub failed_attempts: i32,
    /// HMAC digest; `None` inserts `NULL`.
    pub unlock_token: Option<String>,
    /// Lockable timestamp.
    pub locked_at: Option<NaiveDateTime>,
    /// Rails timestamps.
    pub created_at: NaiveDateTime,
    /// Rails timestamps.
    pub updated_at: NaiveDateTime,
}

impl NewFixtureUser {
    /// Minimal sample row: distinct tokens per email, fixed timestamps.
    pub fn sample(email: &str, now: NaiveDateTime) -> Self {
        Self {
            email: email.to_owned(),
            encrypted_password: "bcrypt-digest".to_owned(),
            reset_password_token: Some(format!("enc-reset-{email}")),
            reset_password_sent_at: Some(now),
            remember_created_at: None,
            sign_in_count: 0,
            current_sign_in_at: None,
            last_sign_in_at: None,
            current_sign_in_ip: None,
            last_sign_in_ip: None,
            confirmation_token: Some(format!("enc-confirm-{email}")),
            confirmed_at: None,
            confirmation_sent_at: Some(now),
            unconfirmed_email: None,
            failed_attempts: 0,
            unlock_token: Some(format!("enc-unlock-{email}")),
            locked_at: None,
            created_at: now,
            updated_at: now,
        }
    }
}

/// Partial-write struct for [`FixtureUser`] (D-05): NULL-capable columns as
/// `Option<Option<T>>` (absent → skip, `Some(None)` → `SET NULL`),
/// NOT NULL columns as plain `Option<T>`.
#[derive(Debug, Default, diesel::AsChangeset)]
#[diesel(table_name = users)]
#[cfg_attr(
    all(feature = "postgres", feature = "sqlite"),
    diesel(check_for_backend(diesel::pg::Pg, diesel::sqlite::Sqlite))
)]
#[cfg_attr(
    all(feature = "postgres", not(feature = "sqlite")),
    diesel(check_for_backend(diesel::pg::Pg))
)]
#[cfg_attr(
    all(not(feature = "postgres"), feature = "sqlite"),
    diesel(check_for_backend(diesel::sqlite::Sqlite))
)]
#[allow(clippy::option_option)]
pub struct FixtureUserChangeset {
    /// Authentication key.
    pub email: Option<String>,
    /// Bcrypt digest.
    pub encrypted_password: Option<String>,
    /// Tristate token column.
    pub reset_password_token: Option<Option<String>>,
    /// Tristate timestamp column.
    pub reset_password_sent_at: Option<Option<NaiveDateTime>>,
    /// Tristate timestamp column.
    pub remember_created_at: Option<Option<NaiveDateTime>>,
    /// Trackable counter.
    pub sign_in_count: Option<i32>,
    /// Tristate timestamp column.
    pub current_sign_in_at: Option<Option<NaiveDateTime>>,
    /// Tristate timestamp column.
    pub last_sign_in_at: Option<Option<NaiveDateTime>>,
    /// Tristate IP column.
    pub current_sign_in_ip: Option<Option<String>>,
    /// Tristate IP column.
    pub last_sign_in_ip: Option<Option<String>>,
    /// Tristate token column.
    pub confirmation_token: Option<Option<String>>,
    /// Tristate timestamp column.
    pub confirmed_at: Option<Option<NaiveDateTime>>,
    /// Tristate timestamp column.
    pub confirmation_sent_at: Option<Option<NaiveDateTime>>,
    /// Tristate pending-email column.
    pub unconfirmed_email: Option<Option<String>>,
    /// Lockable counter.
    pub failed_attempts: Option<i32>,
    /// Tristate token column.
    pub unlock_token: Option<Option<String>>,
    /// Tristate timestamp column.
    pub locked_at: Option<Option<NaiveDateTime>>,
    /// Rails timestamps (writable so `update_columns` can name them).
    pub created_at: Option<NaiveDateTime>,
    /// Rails timestamps (writable so `update_columns` can name them).
    pub updated_at: Option<NaiveDateTime>,
}

/// Hand-rolled per-field fill (the D-05 escape hatch): every named field maps
/// through a [`devise_rust_diesel::changeset`] extractor; unknown or
/// immutable columns fail loud.
///
/// # Errors
///
/// Returns [`OrmError`] for unknown columns, `id` (immutable), or values
/// that do not fit their column.
fn fill_fixture_changeset(
    fields: &HashMap<String, Value>,
) -> Result<FixtureUserChangeset, OrmError> {
    let mut out = FixtureUserChangeset::default();
    for (column, value) in fields {
        match column.as_str() {
            "email" => out.email = Some(required_string(column, value)?),
            "encrypted_password" => {
                out.encrypted_password = Some(required_string(column, value)?);
            }
            "reset_password_token" => {
                out.reset_password_token = Some(nullable_string(column, value)?);
            }
            "reset_password_sent_at" => {
                out.reset_password_sent_at = Some(nullable_datetime(column, value)?);
            }
            "remember_created_at" => {
                out.remember_created_at = Some(nullable_datetime(column, value)?);
            }
            "sign_in_count" => out.sign_in_count = Some(required_i32(column, value)?),
            "current_sign_in_at" => {
                out.current_sign_in_at = Some(nullable_datetime(column, value)?);
            }
            "last_sign_in_at" => {
                out.last_sign_in_at = Some(nullable_datetime(column, value)?);
            }
            "current_sign_in_ip" => {
                out.current_sign_in_ip = Some(nullable_string(column, value)?);
            }
            "last_sign_in_ip" => {
                out.last_sign_in_ip = Some(nullable_string(column, value)?);
            }
            "confirmation_token" => {
                out.confirmation_token = Some(nullable_string(column, value)?);
            }
            "confirmed_at" => out.confirmed_at = Some(nullable_datetime(column, value)?),
            "confirmation_sent_at" => {
                out.confirmation_sent_at = Some(nullable_datetime(column, value)?);
            }
            "unconfirmed_email" => {
                out.unconfirmed_email = Some(nullable_string(column, value)?);
            }
            "failed_attempts" => out.failed_attempts = Some(required_i32(column, value)?),
            "unlock_token" => out.unlock_token = Some(nullable_string(column, value)?),
            "locked_at" => out.locked_at = Some(nullable_datetime(column, value)?),
            "created_at" => out.created_at = Some(required_datetime(column, value)?),
            "updated_at" => out.updated_at = Some(required_datetime(column, value)?),
            "id" => {
                return Err(OrmError::Query {
                    message: "column id is immutable".to_owned(),
                    source: None,
                });
            }
            _ => {
                return Err(OrmError::Query {
                    message: format!("unknown column for update: {column}"),
                    source: None,
                });
            }
        }
    }
    Ok(out)
}

/// `SET column = column + 1` assignment tuple for [`FixtureUser`] (D-11):
/// one `Option` slot per counter column - only the named column's slot is
/// filled; `None` slots are skipped by the changeset, so the single tuple
/// type serves both counters.
type FixtureUserIncrement = (
    Option<
        diesel::dsl::Eq<
            users::failed_attempts,
            <users::failed_attempts as std::ops::Add<i32>>::Output,
        >,
    >,
    Option<
        diesel::dsl::Eq<users::sign_in_count, <users::sign_in_count as std::ops::Add<i32>>::Output>,
    >,
);

impl DieselModel for FixtureUser {
    type Table = users::table;
    type New = NewFixtureUser;
    type Changeset = FixtureUserChangeset;
    type IncrementChangeset = FixtureUserIncrement;

    fn table() -> Self::Table {
        users::table
    }

    fn table_name() -> &'static str {
        "users"
    }

    fn key_of(model: &Self) -> DeviseKey {
        DeviseKey::from_i64(model.id)
    }

    fn changeset_from_map(fields: &HashMap<String, Value>) -> Result<Self::Changeset, OrmError> {
        fill_fixture_changeset(fields)
    }

    fn increment_changeset(column: &'static str) -> Result<Self::IncrementChangeset, OrmError> {
        match column {
            "failed_attempts" => Ok((
                Some(users::failed_attempts.eq(users::failed_attempts + 1)),
                None,
            )),
            "sign_in_count" => Ok((
                None,
                Some(users::sign_in_count.eq(users::sign_in_count + 1)),
            )),
            other => Err(OrmError::Query {
                message: format!("unsupported counter column: {other}"),
                source: None,
            }),
        }
    }
}

/// SQLite predicates for [`FixtureUser`]: identical bodies serve every
/// backend — one impl per backend marker, since `eq` fragments only resolve
/// against a concrete backend.
#[cfg(feature = "sqlite")]
impl DieselPredicates<diesel::sqlite::Sqlite> for FixtureUser {
    fn pk_predicate(
        key: &DeviseKey,
    ) -> Result<BoxPred<Self::Table, diesel::sqlite::Sqlite>, OrmError> {
        match key {
            DeviseKey::Integer(id) => Ok(Box::new(users::id.eq(*id).nullable())),
            DeviseKey::Uuid(_) => Err(OrmError::InvalidKey(
                "users.id is an integer primary key".to_owned(),
            )),
        }
    }

    fn finder_predicate(
        column: &str,
        value: &Value,
    ) -> Option<BoxPred<Self::Table, diesel::sqlite::Sqlite>> {
        if !FINDER_COLUMNS.contains(&column) {
            return None;
        }
        let Value::String(text) = value else {
            return None;
        };
        match column {
            // Non-nullable comparison widened to `Nullable<Bool>` (same SQL).
            "email" => Some(Box::new(users::email.eq(text.clone()).nullable())),
            "reset_password_token" => Some(Box::new(users::reset_password_token.eq(text.clone()))),
            "confirmation_token" => Some(Box::new(users::confirmation_token.eq(text.clone()))),
            "unlock_token" => Some(Box::new(users::unlock_token.eq(text.clone()))),
            "unconfirmed_email" => Some(Box::new(users::unconfirmed_email.eq(text.clone()))),
            _ => None,
        }
    }
}

/// Uuid-PK fixture row: identical columns, `TEXT`-stored hyphenated uuid id.
#[derive(Debug, Clone, PartialEq, diesel::Queryable, diesel::Selectable, diesel::Insertable)]
#[diesel(table_name = uuid_users)]
#[cfg_attr(
    all(feature = "postgres", feature = "sqlite"),
    diesel(check_for_backend(diesel::pg::Pg, diesel::sqlite::Sqlite))
)]
#[cfg_attr(
    all(feature = "postgres", not(feature = "sqlite")),
    diesel(check_for_backend(diesel::pg::Pg))
)]
#[cfg_attr(
    all(not(feature = "postgres"), feature = "sqlite"),
    diesel(check_for_backend(diesel::sqlite::Sqlite))
)]
pub struct UuidUser {
    /// Hyphenated uuid primary key.
    pub id: String,
    /// Authentication key (`NOT NULL DEFAULT ''`).
    pub email: String,
    /// Bcrypt digest (`NOT NULL DEFAULT ''`).
    pub encrypted_password: String,
    /// HMAC digest; `None` means cleared.
    pub reset_password_token: Option<String>,
    /// When the reset token was sent.
    pub reset_password_sent_at: Option<NaiveDateTime>,
    /// Rememberable timestamp.
    pub remember_created_at: Option<NaiveDateTime>,
    /// Trackable counter (`NOT NULL DEFAULT 0`).
    pub sign_in_count: i32,
    /// Trackable timestamps.
    pub current_sign_in_at: Option<NaiveDateTime>,
    /// Trackable timestamps.
    pub last_sign_in_at: Option<NaiveDateTime>,
    /// Trackable IPs (TEXT on SQLite, TEXT on Postgres for compatibility).
    pub current_sign_in_ip: Option<String>,
    /// Trackable IPs (TEXT on SQLite, TEXT on Postgres for compatibility).
    pub last_sign_in_ip: Option<String>,
    /// HMAC digest; `None` means cleared.
    pub confirmation_token: Option<String>,
    /// Confirmable timestamps.
    pub confirmed_at: Option<NaiveDateTime>,
    /// Confirmable timestamps.
    pub confirmation_sent_at: Option<NaiveDateTime>,
    /// Reconfirmable pending email.
    pub unconfirmed_email: Option<String>,
    /// Lockable counter (`NOT NULL DEFAULT 0`).
    pub failed_attempts: i32,
    /// HMAC digest; `None` means cleared.
    pub unlock_token: Option<String>,
    /// Lockable timestamp.
    pub locked_at: Option<NaiveDateTime>,
    /// Rails timestamps (`NOT NULL`).
    pub created_at: NaiveDateTime,
    /// Rails timestamps (`NOT NULL`).
    pub updated_at: NaiveDateTime,
}

/// Insert shape for [`UuidUser`] (D-03): the caller assigns the hyphenated id.
#[derive(Debug, Clone, diesel::Insertable)]
#[diesel(table_name = uuid_users)]
#[cfg_attr(
    all(feature = "postgres", feature = "sqlite"),
    diesel(check_for_backend(diesel::pg::Pg, diesel::sqlite::Sqlite))
)]
#[cfg_attr(
    all(feature = "postgres", not(feature = "sqlite")),
    diesel(check_for_backend(diesel::pg::Pg))
)]
#[cfg_attr(
    all(not(feature = "postgres"), feature = "sqlite"),
    diesel(check_for_backend(diesel::sqlite::Sqlite))
)]
pub struct NewUuidUser {
    /// Hyphenated uuid primary key (adapter-assigned by the caller).
    pub id: String,
    /// Authentication key.
    pub email: String,
    /// Bcrypt digest.
    pub encrypted_password: String,
    /// HMAC digest; `None` inserts `NULL`.
    pub reset_password_token: Option<String>,
    /// When the reset token was sent.
    pub reset_password_sent_at: Option<NaiveDateTime>,
    /// Rememberable timestamp.
    pub remember_created_at: Option<NaiveDateTime>,
    /// Trackable counter.
    pub sign_in_count: i32,
    /// Trackable timestamps.
    pub current_sign_in_at: Option<NaiveDateTime>,
    /// Trackable timestamps.
    pub last_sign_in_at: Option<NaiveDateTime>,
    /// Trackable IPs.
    pub current_sign_in_ip: Option<String>,
    /// Trackable IPs.
    pub last_sign_in_ip: Option<String>,
    /// HMAC digest; `None` inserts `NULL`.
    pub confirmation_token: Option<String>,
    /// Confirmable timestamps.
    pub confirmed_at: Option<NaiveDateTime>,
    /// Confirmable timestamps.
    pub confirmation_sent_at: Option<NaiveDateTime>,
    /// Reconfirmable pending email.
    pub unconfirmed_email: Option<String>,
    /// Lockable counter.
    pub failed_attempts: i32,
    /// HMAC digest; `None` inserts `NULL`.
    pub unlock_token: Option<String>,
    /// Lockable timestamp.
    pub locked_at: Option<NaiveDateTime>,
    /// Rails timestamps.
    pub created_at: NaiveDateTime,
    /// Rails timestamps.
    pub updated_at: NaiveDateTime,
}

impl NewUuidUser {
    /// Minimal sample row under a fresh random id.
    pub fn sample(email: &str, now: NaiveDateTime) -> Self {
        Self {
            id: uuid::Uuid::new_v4().hyphenated().to_string(),
            email: email.to_owned(),
            encrypted_password: "bcrypt-digest".to_owned(),
            reset_password_token: Some(format!("enc-reset-{email}")),
            reset_password_sent_at: Some(now),
            remember_created_at: None,
            sign_in_count: 0,
            current_sign_in_at: None,
            last_sign_in_at: None,
            current_sign_in_ip: None,
            last_sign_in_ip: None,
            confirmation_token: Some(format!("enc-confirm-{email}")),
            confirmed_at: None,
            confirmation_sent_at: Some(now),
            unconfirmed_email: None,
            failed_attempts: 0,
            unlock_token: Some(format!("enc-unlock-{email}")),
            locked_at: None,
            created_at: now,
            updated_at: now,
        }
    }
}

/// Partial-write struct for [`UuidUser`] (D-05): same tristate shape as
/// [`FixtureUserChangeset`].
#[derive(Debug, Default, diesel::AsChangeset)]
#[diesel(table_name = uuid_users)]
#[cfg_attr(
    all(feature = "postgres", feature = "sqlite"),
    diesel(check_for_backend(diesel::pg::Pg, diesel::sqlite::Sqlite))
)]
#[cfg_attr(
    all(feature = "postgres", not(feature = "sqlite")),
    diesel(check_for_backend(diesel::pg::Pg))
)]
#[cfg_attr(
    all(not(feature = "postgres"), feature = "sqlite"),
    diesel(check_for_backend(diesel::sqlite::Sqlite))
)]
#[allow(clippy::struct_field_names)]
#[allow(clippy::option_option)]
pub struct UuidUserChangeset {
    /// Authentication key.
    pub email: Option<String>,
    /// Bcrypt digest.
    pub encrypted_password: Option<String>,
    /// Tristate token column.
    pub reset_password_token: Option<Option<String>>,
    /// Tristate timestamp column.
    pub reset_password_sent_at: Option<Option<NaiveDateTime>>,
    /// Tristate timestamp column.
    pub remember_created_at: Option<Option<NaiveDateTime>>,
    /// Trackable counter.
    pub sign_in_count: Option<i32>,
    /// Tristate timestamp column.
    pub current_sign_in_at: Option<Option<NaiveDateTime>>,
    /// Tristate timestamp column.
    pub last_sign_in_at: Option<Option<NaiveDateTime>>,
    /// Tristate IP column.
    pub current_sign_in_ip: Option<Option<String>>,
    /// Tristate IP column.
    pub last_sign_in_ip: Option<Option<String>>,
    /// Tristate token column.
    pub confirmation_token: Option<Option<String>>,
    /// Tristate timestamp column.
    pub confirmed_at: Option<Option<NaiveDateTime>>,
    /// Tristate timestamp column.
    pub confirmation_sent_at: Option<Option<NaiveDateTime>>,
    /// Tristate pending-email column.
    pub unconfirmed_email: Option<Option<String>>,
    /// Lockable counter.
    pub failed_attempts: Option<i32>,
    /// Tristate token column.
    pub unlock_token: Option<Option<String>>,
    /// Tristate timestamp column.
    pub locked_at: Option<Option<NaiveDateTime>>,
    /// Rails timestamps (writable so `update_columns` can name them).
    pub created_at: Option<NaiveDateTime>,
    /// Rails timestamps (writable so `update_columns` can name them).
    pub updated_at: Option<NaiveDateTime>,
}

/// Hand-rolled per-field fill for [`UuidUserChangeset`].
///
/// # Errors
///
/// Returns [`OrmError`] for unknown columns, `id` (immutable), or values
/// that do not fit their column.
fn fill_uuid_changeset(fields: &HashMap<String, Value>) -> Result<UuidUserChangeset, OrmError> {
    let mut out = UuidUserChangeset::default();
    for (column, value) in fields {
        match column.as_str() {
            "email" => out.email = Some(required_string(column, value)?),
            "encrypted_password" => {
                out.encrypted_password = Some(required_string(column, value)?);
            }
            "reset_password_token" => {
                out.reset_password_token = Some(nullable_string(column, value)?);
            }
            "reset_password_sent_at" => {
                out.reset_password_sent_at = Some(nullable_datetime(column, value)?);
            }
            "remember_created_at" => {
                out.remember_created_at = Some(nullable_datetime(column, value)?);
            }
            "sign_in_count" => out.sign_in_count = Some(required_i32(column, value)?),
            "current_sign_in_at" => {
                out.current_sign_in_at = Some(nullable_datetime(column, value)?);
            }
            "last_sign_in_at" => {
                out.last_sign_in_at = Some(nullable_datetime(column, value)?);
            }
            "current_sign_in_ip" => {
                out.current_sign_in_ip = Some(nullable_string(column, value)?);
            }
            "last_sign_in_ip" => {
                out.last_sign_in_ip = Some(nullable_string(column, value)?);
            }
            "confirmation_token" => {
                out.confirmation_token = Some(nullable_string(column, value)?);
            }
            "confirmed_at" => out.confirmed_at = Some(nullable_datetime(column, value)?),
            "confirmation_sent_at" => {
                out.confirmation_sent_at = Some(nullable_datetime(column, value)?);
            }
            "unconfirmed_email" => {
                out.unconfirmed_email = Some(nullable_string(column, value)?);
            }
            "failed_attempts" => out.failed_attempts = Some(required_i32(column, value)?),
            "unlock_token" => out.unlock_token = Some(nullable_string(column, value)?),
            "locked_at" => out.locked_at = Some(nullable_datetime(column, value)?),
            "created_at" => out.created_at = Some(required_datetime(column, value)?),
            "updated_at" => out.updated_at = Some(required_datetime(column, value)?),
            "id" => {
                return Err(OrmError::Query {
                    message: "column id is immutable".to_owned(),
                    source: None,
                });
            }
            _ => {
                return Err(OrmError::Query {
                    message: format!("unknown column for update: {column}"),
                    source: None,
                });
            }
        }
    }
    Ok(out)
}

/// `SET column = column + 1` assignment tuple for [`UuidUser`] (D-11):
/// same shape as [`FixtureUserIncrement`] over the `uuid_users` columns.
type UuidUserIncrement = (
    Option<
        diesel::dsl::Eq<
            uuid_users::failed_attempts,
            <uuid_users::failed_attempts as std::ops::Add<i32>>::Output,
        >,
    >,
    Option<
        diesel::dsl::Eq<
            uuid_users::sign_in_count,
            <uuid_users::sign_in_count as std::ops::Add<i32>>::Output,
        >,
    >,
);

impl DieselModel for UuidUser {
    type Table = uuid_users::table;
    type New = NewUuidUser;
    type Changeset = UuidUserChangeset;
    type IncrementChangeset = UuidUserIncrement;

    fn table() -> Self::Table {
        uuid_users::table
    }

    fn table_name() -> &'static str {
        "uuid_users"
    }

    /// Parses the hyphenated `TEXT` id back into a [`DeviseKey::Uuid`].
    ///
    /// # Panics
    ///
    /// Panics when the stored id is not a valid uuid (fixture rows always
    /// carry adapter-assigned hyphenated ids).
    fn key_of(model: &Self) -> DeviseKey {
        DeviseKey::from_uuid(
            uuid::Uuid::parse_str(&model.id).expect("uuid fixture ids are hyphenated uuids"),
        )
    }

    fn changeset_from_map(fields: &HashMap<String, Value>) -> Result<Self::Changeset, OrmError> {
        fill_uuid_changeset(fields)
    }

    fn increment_changeset(column: &'static str) -> Result<Self::IncrementChangeset, OrmError> {
        match column {
            "failed_attempts" => Ok((
                Some(uuid_users::failed_attempts.eq(uuid_users::failed_attempts + 1)),
                None,
            )),
            "sign_in_count" => Ok((
                None,
                Some(uuid_users::sign_in_count.eq(uuid_users::sign_in_count + 1)),
            )),
            other => Err(OrmError::Query {
                message: format!("unsupported counter column: {other}"),
                source: None,
            }),
        }
    }
}

/// SQLite predicates for [`UuidUser`] (see [`FixtureUser`]'s impl for the
/// per-backend rationale).
#[cfg(feature = "sqlite")]
impl DieselPredicates<diesel::sqlite::Sqlite> for UuidUser {
    fn pk_predicate(
        key: &DeviseKey,
    ) -> Result<BoxPred<Self::Table, diesel::sqlite::Sqlite>, OrmError> {
        match key {
            // SQLite stores the uuid hyphenated (no native UUID type);
            // Postgres would bind natively through the same spelling's parse.
            DeviseKey::Uuid(id) => Ok(Box::new(
                uuid_users::id.eq(id.hyphenated().to_string()).nullable(),
            )),
            DeviseKey::Integer(_) => Err(OrmError::InvalidKey(
                "uuid_users.id is a uuid primary key".to_owned(),
            )),
        }
    }

    fn finder_predicate(
        column: &str,
        value: &Value,
    ) -> Option<BoxPred<Self::Table, diesel::sqlite::Sqlite>> {
        if !FINDER_COLUMNS.contains(&column) {
            return None;
        }
        let Value::String(text) = value else {
            return None;
        };
        match column {
            "email" => Some(Box::new(uuid_users::email.eq(text.clone()).nullable())),
            "reset_password_token" => {
                Some(Box::new(uuid_users::reset_password_token.eq(text.clone())))
            }
            "confirmation_token" => Some(Box::new(uuid_users::confirmation_token.eq(text.clone()))),
            "unlock_token" => Some(Box::new(uuid_users::unlock_token.eq(text.clone()))),
            "unconfirmed_email" => Some(Box::new(uuid_users::unconfirmed_email.eq(text.clone()))),
            _ => None,
        }
    }
}

/// Postgres predicates for [`FixtureUser`]: native UUID + INET support.
#[cfg(feature = "postgres")]
impl DieselPredicates<diesel::pg::Pg> for FixtureUser {
    fn pk_predicate(key: &DeviseKey) -> Result<BoxPred<Self::Table, diesel::pg::Pg>, OrmError> {
        match key {
            DeviseKey::Integer(id) => Ok(Box::new(users::id.eq(*id).nullable())),
            DeviseKey::Uuid(_) => Err(OrmError::InvalidKey(
                "users.id is an integer primary key".to_owned(),
            )),
        }
    }

    fn finder_predicate(
        column: &str,
        value: &Value,
    ) -> Option<BoxPred<Self::Table, diesel::pg::Pg>> {
        if !FINDER_COLUMNS.contains(&column) {
            return None;
        }
        let Value::String(text) = value else {
            return None;
        };
        match column {
            "email" => Some(Box::new(users::email.eq(text.clone()).nullable())),
            "reset_password_token" => Some(Box::new(users::reset_password_token.eq(text.clone()))),
            "confirmation_token" => Some(Box::new(users::confirmation_token.eq(text.clone()))),
            "unlock_token" => Some(Box::new(users::unlock_token.eq(text.clone()))),
            "unconfirmed_email" => Some(Box::new(users::unconfirmed_email.eq(text.clone()))),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Shared contract-suite fixture bridge (D-24/D-27)
// ---------------------------------------------------------------------------

/// Backend-neutral accessors for the shared adapter contract suite: the
/// identical generic cases run against this backend's rows and the
/// `MemoryAdapter` oracle through this bridge (D-29).
impl ContractModel for FixtureUser {
    type New = NewFixtureUser;

    fn sample_new(email: &str, now: NaiveDateTime) -> Self::New {
        NewFixtureUser::sample(email, now)
    }

    fn contract_email(&self) -> &str {
        &self.email
    }

    fn contract_encrypted_password(&self) -> &str {
        &self.encrypted_password
    }

    fn contract_reset_password_token(&self) -> Option<&str> {
        self.reset_password_token.as_deref()
    }

    fn contract_reset_password_sent_at(&self) -> Option<NaiveDateTime> {
        self.reset_password_sent_at
    }

    fn contract_confirmation_token(&self) -> Option<&str> {
        self.confirmation_token.as_deref()
    }

    fn contract_confirmation_sent_at(&self) -> Option<NaiveDateTime> {
        self.confirmation_sent_at
    }

    fn contract_unconfirmed_email(&self) -> Option<&str> {
        self.unconfirmed_email.as_deref()
    }

    fn contract_failed_attempts(&self) -> i64 {
        i64::from(self.failed_attempts)
    }

    fn contract_sign_in_count(&self) -> i64 {
        i64::from(self.sign_in_count)
    }

    fn contract_unlock_token(&self) -> Option<&str> {
        self.unlock_token.as_deref()
    }

    fn contract_locked_at(&self) -> Option<NaiveDateTime> {
        self.locked_at
    }

    fn contract_created_at(&self) -> NaiveDateTime {
        self.created_at
    }

    fn contract_updated_at(&self) -> NaiveDateTime {
        self.updated_at
    }
}

/// Shared-suite bridge for the uuid-PK fixture row (see [`FixtureUser`]'s
/// impl for the rationale).
impl ContractModel for UuidUser {
    type New = NewUuidUser;

    fn sample_new(email: &str, now: NaiveDateTime) -> Self::New {
        NewUuidUser::sample(email, now)
    }

    fn contract_email(&self) -> &str {
        &self.email
    }

    fn contract_encrypted_password(&self) -> &str {
        &self.encrypted_password
    }

    fn contract_reset_password_token(&self) -> Option<&str> {
        self.reset_password_token.as_deref()
    }

    fn contract_reset_password_sent_at(&self) -> Option<NaiveDateTime> {
        self.reset_password_sent_at
    }

    fn contract_confirmation_token(&self) -> Option<&str> {
        self.confirmation_token.as_deref()
    }

    fn contract_confirmation_sent_at(&self) -> Option<NaiveDateTime> {
        self.confirmation_sent_at
    }

    fn contract_unconfirmed_email(&self) -> Option<&str> {
        self.unconfirmed_email.as_deref()
    }

    fn contract_failed_attempts(&self) -> i64 {
        i64::from(self.failed_attempts)
    }

    fn contract_sign_in_count(&self) -> i64 {
        i64::from(self.sign_in_count)
    }

    fn contract_unlock_token(&self) -> Option<&str> {
        self.unlock_token.as_deref()
    }

    fn contract_locked_at(&self) -> Option<NaiveDateTime> {
        self.locked_at
    }

    fn contract_created_at(&self) -> NaiveDateTime {
        self.created_at
    }

    fn contract_updated_at(&self) -> NaiveDateTime {
        self.updated_at
    }
}

/// Postgres predicates for [`UuidUser`]: the pg `uuid_users` fixture stores
/// the id hyphenated as TEXT (the `diesel_async` `LoadQuery` bound
/// limitation documented in the rig bootstrap), so the pk binds the same
/// hyphenated spelling as the sqlite leg; the finder set is identical.
#[cfg(feature = "postgres")]
impl DieselPredicates<diesel::pg::Pg> for UuidUser {
    fn pk_predicate(key: &DeviseKey) -> Result<BoxPred<Self::Table, diesel::pg::Pg>, OrmError> {
        match key {
            DeviseKey::Uuid(id) => Ok(Box::new(
                uuid_users::id.eq(id.hyphenated().to_string()).nullable(),
            )),
            DeviseKey::Integer(_) => Err(OrmError::InvalidKey(
                "uuid_users.id is a uuid primary key".to_owned(),
            )),
        }
    }

    fn finder_predicate(
        column: &str,
        value: &Value,
    ) -> Option<BoxPred<Self::Table, diesel::pg::Pg>> {
        if !FINDER_COLUMNS.contains(&column) {
            return None;
        }
        let Value::String(text) = value else {
            return None;
        };
        match column {
            "email" => Some(Box::new(uuid_users::email.eq(text.clone()).nullable())),
            "reset_password_token" => {
                Some(Box::new(uuid_users::reset_password_token.eq(text.clone())))
            }
            "confirmation_token" => Some(Box::new(uuid_users::confirmation_token.eq(text.clone()))),
            "unlock_token" => Some(Box::new(uuid_users::unlock_token.eq(text.clone()))),
            "unconfirmed_email" => Some(Box::new(uuid_users::unconfirmed_email.eq(text.clone()))),
            _ => None,
        }
    }
}
