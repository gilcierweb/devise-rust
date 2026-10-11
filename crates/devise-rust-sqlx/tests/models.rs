//! Fixture models: hand-written `FromRow` structs matching the emitted
//! SQLite DDL column-for-column, plus manual [`SqlxModel`] impls.
//!
//! Two primary-key kinds are exercised (D-35/D-26): [`FixtureUser`] on an
//! auto-increment integer `users.id`, [`UuidUser`] on a hyphenated-`TEXT`
//! `uuid_users.id` (sqlite has no native UUID type, so the glue owns the
//! spelling — the diesel precedent). Every other column mirrors the
//! full-module `emit()` output: same names, same nullability, same
//! defaults.

use chrono::NaiveDateTime;
use devise_rust::adapter::{DeviseKey, OrmError, Value};
use devise_rust_adapter_tests::ContractModel;
use devise_rust_sqlx::glue::{
    Bind, KeyShape, SqlxModel, WriteValue, nullable_datetime, nullable_inet, nullable_string,
    required_datetime, required_i64, required_string,
};
use sqlx::Type;
use sqlx::decode::Decode;
#[cfg(feature = "postgres")]
use sqlx::postgres::{PgTypeInfo, PgValueRef};
#[cfg(feature = "sqlite")]
use sqlx::sqlite::{SqliteTypeInfo, SqliteValueRef};
use std::net::IpAddr;

/// A UUID type that decodes both native UUID (Postgres) and hyphenated TEXT (SQLite).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HybridUuid(pub uuid::Uuid);

#[cfg(feature = "postgres")]
impl<'r> Decode<'r, sqlx::Postgres> for HybridUuid {
    fn decode(
        value: PgValueRef<'r>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync + 'static>> {
        <uuid::Uuid as Decode<'r, sqlx::Postgres>>::decode(value).map(HybridUuid)
    }
}

#[cfg(feature = "sqlite")]
impl<'r> Decode<'r, sqlx::Sqlite> for HybridUuid {
    fn decode(
        value: SqliteValueRef<'r>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync + 'static>> {
        // Decode as TEXT and parse
        let text: &str = <&str as Decode<sqlx::Sqlite>>::decode(value)?;
        Ok(HybridUuid(uuid::Uuid::parse_str(text)?))
    }
}

#[cfg(feature = "postgres")]
impl Type<sqlx::Postgres> for HybridUuid {
    fn type_info() -> PgTypeInfo {
        <uuid::Uuid as Type<sqlx::Postgres>>::type_info()
    }
}

#[cfg(feature = "sqlite")]
impl Type<sqlx::Sqlite> for HybridUuid {
    fn type_info() -> SqliteTypeInfo {
        <String as Type<sqlx::Sqlite>>::type_info()
    }
}

/// The full-module column list in emitted-DDL order — the explicit SELECT
/// list (Pitfall 2) and the `RETURNING` projection.
const USER_COLUMNS: &[&str] = &[
    "id",
    "email",
    "encrypted_password",
    "reset_password_token",
    "reset_password_sent_at",
    "remember_created_at",
    "sign_in_count",
    "current_sign_in_at",
    "last_sign_in_at",
    "current_sign_in_ip",
    "last_sign_in_ip",
    "confirmation_token",
    "confirmed_at",
    "confirmation_sent_at",
    "unconfirmed_email",
    "failed_attempts",
    "unlock_token",
    "locked_at",
    "created_at",
    "updated_at",
];

/// Insert column list for `users` (D-05): every column except the
/// database-assigned id.
const USER_INSERT_COLUMNS: &[&str] = &[
    "email",
    "encrypted_password",
    "reset_password_token",
    "reset_password_sent_at",
    "remember_created_at",
    "sign_in_count",
    "current_sign_in_at",
    "last_sign_in_at",
    "current_sign_in_ip",
    "last_sign_in_ip",
    "confirmation_token",
    "confirmed_at",
    "confirmation_sent_at",
    "unconfirmed_email",
    "failed_attempts",
    "unlock_token",
    "locked_at",
    "created_at",
    "updated_at",
];

/// The curated finder allowlist (D-02) — the shared five columns.
const FINDER_COLUMNS: &[&str] = &[
    "email",
    "reset_password_token",
    "confirmation_token",
    "unlock_token",
    "unconfirmed_email",
];

/// Integer-PK fixture row.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
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

/// Insert shape for [`FixtureUser`] (D-05): everything but the row id.
#[derive(Debug, Clone)]
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
    /// Minimal sample row: distinct tokens per email, fixed timestamps
    /// (the shared-suite fixture contract).
    #[must_use]
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

/// Per-column write conversion (the diesel `fill_fixture_changeset`
/// analogue): every named field validates through a [`glue`](devise_rust_sqlx::glue)
/// extractor and yields its own static column name — so caller text can
/// never become SQL. Unknown or immutable columns fail loud, naming the
/// column.
fn write_bind(column: &str, value: &Value) -> Result<(&'static str, WriteValue), OrmError> {
    let (static_column, write) = match column {
        "email" => ("email", required_string(column, value)?),
        "encrypted_password" => ("encrypted_password", required_string(column, value)?),
        "reset_password_token" => ("reset_password_token", nullable_string(column, value)?),
        "reset_password_sent_at" => ("reset_password_sent_at", nullable_datetime(column, value)?),
        "remember_created_at" => ("remember_created_at", nullable_datetime(column, value)?),
        "sign_in_count" => ("sign_in_count", required_i64(column, value)?),
        "current_sign_in_at" => ("current_sign_in_at", nullable_datetime(column, value)?),
        "last_sign_in_at" => ("last_sign_in_at", nullable_datetime(column, value)?),
        "current_sign_in_ip" => ("current_sign_in_ip", nullable_inet(column, value)?),
        "last_sign_in_ip" => ("last_sign_in_ip", nullable_inet(column, value)?),
        "confirmation_token" => ("confirmation_token", nullable_string(column, value)?),
        "confirmed_at" => ("confirmed_at", nullable_datetime(column, value)?),
        "confirmation_sent_at" => ("confirmation_sent_at", nullable_datetime(column, value)?),
        "unconfirmed_email" => ("unconfirmed_email", nullable_string(column, value)?),
        "failed_attempts" => ("failed_attempts", required_i64(column, value)?),
        "unlock_token" => ("unlock_token", nullable_string(column, value)?),
        "locked_at" => ("locked_at", nullable_datetime(column, value)?),
        "created_at" => ("created_at", required_datetime(column, value)?),
        "updated_at" => ("updated_at", required_datetime(column, value)?),
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
    };
    Ok((static_column, write))
}

impl SqlxModel for FixtureUser {
    type New = NewFixtureUser;

    fn table_name() -> &'static str {
        "users"
    }

    fn pk_column() -> &'static str {
        "id"
    }

    fn columns() -> &'static [&'static str] {
        USER_COLUMNS
    }

    fn key_shape() -> KeyShape {
        KeyShape::Integer
    }

    fn key_of(model: &Self) -> DeviseKey {
        DeviseKey::from_i64(model.id)
    }

    fn finder_columns() -> &'static [&'static str] {
        FINDER_COLUMNS
    }

    fn insert_columns() -> &'static [&'static str] {
        USER_INSERT_COLUMNS
    }

    fn insert_values(new: &Self::New) -> Vec<Bind> {
        vec![
            Bind::Text(new.email.clone()),
            Bind::Text(new.encrypted_password.clone()),
            Bind::NullableText(new.reset_password_token.clone()),
            Bind::NullableTimestamp(new.reset_password_sent_at),
            Bind::NullableTimestamp(new.remember_created_at),
            Bind::Integer(new.sign_in_count.into()),
            Bind::NullableTimestamp(new.current_sign_in_at),
            Bind::NullableTimestamp(new.last_sign_in_at),
            Bind::NullableInet(
                new.current_sign_in_ip
                    .clone()
                    .and_then(|s| s.parse::<IpAddr>().ok()),
            ),
            Bind::NullableInet(
                new.last_sign_in_ip
                    .clone()
                    .and_then(|s| s.parse::<IpAddr>().ok()),
            ),
            Bind::NullableText(new.confirmation_token.clone()),
            Bind::NullableTimestamp(new.confirmed_at),
            Bind::NullableTimestamp(new.confirmation_sent_at),
            Bind::NullableText(new.unconfirmed_email.clone()),
            Bind::Integer(new.failed_attempts.into()),
            Bind::NullableText(new.unlock_token.clone()),
            Bind::NullableTimestamp(new.locked_at),
            Bind::Timestamp(new.created_at),
            Bind::Timestamp(new.updated_at),
        ]
    }

    fn write_bind(column: &str, value: &Value) -> Result<(&'static str, WriteValue), OrmError> {
        write_bind(column, value)
    }
}

/// Shared-suite bridge for the sqlite integer-PK leg (D-24): the identical
/// generic cases read and assert through these accessors.
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
        self.failed_attempts.into()
    }

    fn contract_sign_in_count(&self) -> i64 {
        self.sign_in_count.into()
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

/// Uuid-PK fixture row: identical columns, `TEXT`-stored hyphenated uuid id
/// (D-35 — the diesel sqlite precedent).
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct UuidUser {
    /// Hybrid UUID primary key: native UUID on Postgres, hyphenated TEXT on SQLite.
    pub id: HybridUuid,
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

/// Insert shape for [`UuidUser`] (D-03/D-05): the caller assigns the
/// hyphenated id (the database does not generate uuids on sqlite).
#[derive(Debug, Clone)]
pub struct NewUuidUser {
    /// Hybrid UUID primary key (caller-assigned).
    pub id: HybridUuid,
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
    /// Minimal sample row under a fresh random hyphenated id.
    #[must_use]
    pub fn sample(email: &str, now: NaiveDateTime) -> Self {
        Self {
            id: HybridUuid(uuid::Uuid::new_v4()),
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

/// Per-column write conversion for [`UuidUser`] — identical columns to
/// [`FixtureUser`] plus the (immutable) `id`.
fn uuid_write_bind(column: &str, value: &Value) -> Result<(&'static str, WriteValue), OrmError> {
    if column == "id" {
        return Err(OrmError::Query {
            message: "column id is immutable".to_owned(),
            source: None,
        });
    }
    write_bind(column, value)
}

impl SqlxModel for UuidUser {
    type New = NewUuidUser;

    fn table_name() -> &'static str {
        "uuid_users"
    }

    fn pk_column() -> &'static str {
        "id"
    }

    fn columns() -> &'static [&'static str] {
        USER_COLUMNS
    }

    fn key_shape() -> KeyShape {
        KeyShape::Uuid
    }

    fn key_of(model: &Self) -> DeviseKey {
        DeviseKey::from_uuid(model.id.0)
    }

    fn finder_columns() -> &'static [&'static str] {
        FINDER_COLUMNS
    }

    fn insert_columns() -> &'static [&'static str] {
        UUID_USER_INSERT_COLUMNS
    }

    fn insert_values(new: &Self::New) -> Vec<Bind> {
        let mut values = Vec::with_capacity(UUID_USER_INSERT_COLUMNS.len());
        // Use the native UUID directly for binding
        values.push(Bind::Uuid(new.id.0));
        values.extend(uuid_insert_tail(new));
        values
    }

    fn write_bind(column: &str, value: &Value) -> Result<(&'static str, WriteValue), OrmError> {
        uuid_write_bind(column, value)
    }
}

/// Insert column list for `uuid_users` (D-05): the caller-assigned id plus
/// every other column.
const UUID_USER_INSERT_COLUMNS: &[&str] = &[
    "id",
    "email",
    "encrypted_password",
    "reset_password_token",
    "reset_password_sent_at",
    "remember_created_at",
    "sign_in_count",
    "current_sign_in_at",
    "last_sign_in_at",
    "current_sign_in_ip",
    "last_sign_in_ip",
    "confirmation_token",
    "confirmed_at",
    "confirmation_sent_at",
    "unconfirmed_email",
    "failed_attempts",
    "unlock_token",
    "locked_at",
    "created_at",
    "updated_at",
];

/// The non-id insert fields both fixtures share: the insert-value tail
/// after the id column (diesel's per-model duplication precedent — the two
/// `New` types are distinct, so no shared trait).
fn uuid_insert_tail(new: &NewUuidUser) -> Vec<Bind> {
    vec![
        Bind::Text(new.email.clone()),
        Bind::Text(new.encrypted_password.clone()),
        Bind::NullableText(new.reset_password_token.clone()),
        Bind::NullableTimestamp(new.reset_password_sent_at),
        Bind::NullableTimestamp(new.remember_created_at),
        Bind::Integer(new.sign_in_count.into()),
        Bind::NullableTimestamp(new.current_sign_in_at),
        Bind::NullableTimestamp(new.last_sign_in_at),
        Bind::NullableInet(
            new.current_sign_in_ip
                .clone()
                .and_then(|s| s.parse::<IpAddr>().ok()),
        ),
        Bind::NullableInet(
            new.last_sign_in_ip
                .clone()
                .and_then(|s| s.parse::<IpAddr>().ok()),
        ),
        Bind::NullableText(new.confirmation_token.clone()),
        Bind::NullableTimestamp(new.confirmed_at),
        Bind::NullableTimestamp(new.confirmation_sent_at),
        Bind::NullableText(new.unconfirmed_email.clone()),
        Bind::Integer(new.failed_attempts.into()),
        Bind::NullableText(new.unlock_token.clone()),
        Bind::NullableTimestamp(new.locked_at),
        Bind::Timestamp(new.created_at),
        Bind::Timestamp(new.updated_at),
    ]
}

/// Shared-suite bridge for the sqlite uuid-PK leg (see [`FixtureUser`]'s
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
        self.failed_attempts.into()
    }

    fn contract_sign_in_count(&self) -> i64 {
        self.sign_in_count.into()
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
