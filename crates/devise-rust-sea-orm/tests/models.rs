//! Fixture entities: hand-written sea-orm `DeriveEntityModel` schemas
//! matching the emitted SQLite DDL column-for-column (D-21), plus the manual
//! [`SeaOrmModel`] bridge impls (D-15).
//!
//! Two primary-key kinds are exercised (D-26/D-35): [`users::Model`] on an
//! auto-increment integer `users.id`, and — landing with the full suite in
//! Task 2 — `uuid_users::Model` on a hyphenated-`TEXT` `uuid_users.id`
//! (sqlite has no native UUID type; the bridge owns the spelling, matching
//! the diesel/sqlx precedent). Every other column mirrors the full-module
//! `emit()` output: same names, same nullability, same defaults.
//!
//! `DeriveEntityModel` requires the row struct be named `Model` and generates
//! `Entity`/`Column`/`ActiveModel` in the same module, so each table gets its
//! own module (`users::Entity`, `uuid_users::Entity`).

use std::collections::HashMap;

use chrono::NaiveDateTime;
use devise_rust::adapter::{DeviseKey, OrmError, Value};
use devise_rust_adapter_tests::ContractModel;
use devise_rust_sea_orm::bridge::{
    FINDER_COLUMNS, SeaOrmModel, extract_nullable_datetime, extract_nullable_string,
    extract_required_datetime, extract_required_i32, extract_required_string,
};
use sea_orm::sea_query::SimpleExpr;
use uuid::Uuid;

/// Integer-PK fixture table (D-26 i64 leg).
pub mod users {
    use sea_orm::entity::prelude::*;

    /// Full-module fixture row over the emitted sqlite DDL.
    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "users")]
    pub struct Model {
        /// Auto-increment integer primary key.
        #[sea_orm(primary_key)]
        pub id: i64,
        /// Authentication key.
        pub email: String,
        /// Bcrypt digest.
        pub encrypted_password: String,
        /// Recoverable HMAC digest; `None` means cleared.
        pub reset_password_token: Option<String>,
        /// Recoverable send timestamp.
        pub reset_password_sent_at: Option<DateTime>,
        /// Rememberable timestamp.
        pub remember_created_at: Option<DateTime>,
        /// Trackable counter.
        pub sign_in_count: i32,
        /// Trackable timestamps.
        pub current_sign_in_at: Option<DateTime>,
        /// Trackable timestamps.
        pub last_sign_in_at: Option<DateTime>,
        /// Trackable IPs (TEXT on sqlite per the emitter's `ip_column` rule).
        pub current_sign_in_ip: Option<String>,
        /// Trackable IPs.
        pub last_sign_in_ip: Option<String>,
        /// Confirmable HMAC digest; `None` means cleared.
        pub confirmation_token: Option<String>,
        /// Confirmable timestamps.
        pub confirmed_at: Option<DateTime>,
        /// Confirmable send timestamp.
        pub confirmation_sent_at: Option<DateTime>,
        /// Reconfirmable pending email.
        pub unconfirmed_email: Option<String>,
        /// Lockable counter.
        pub failed_attempts: i32,
        /// Lockable HMAC digest; `None` means cleared.
        pub unlock_token: Option<String>,
        /// Lockable timestamp.
        pub locked_at: Option<DateTime>,
        /// Rails timestamps (`NOT NULL`).
        pub created_at: DateTime,
        /// Rails timestamps (`NOT NULL`).
        pub updated_at: DateTime,
    }

    /// No relations through the adapter (D-22): standalone users table only.
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

use users::{ActiveModel, Column, Entity, Model};

/// Insert shape for [`users::Model`] (D-20): every caller-owned column; the
/// database assigns `id`, so the bridge leaves the PK `NotSet`.
#[derive(Debug, Clone, Default)]
pub struct NewFixtureUser {
    /// Authentication key.
    pub email: String,
    /// Bcrypt digest.
    pub encrypted_password: String,
    /// Recoverable HMAC digest.
    pub reset_password_token: Option<String>,
    /// Recoverable send timestamp.
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
    /// Confirmable HMAC digest.
    pub confirmation_token: Option<String>,
    /// Confirmable timestamps.
    pub confirmed_at: Option<NaiveDateTime>,
    /// Confirmable send timestamp.
    pub confirmation_sent_at: Option<NaiveDateTime>,
    /// Reconfirmable pending email.
    pub unconfirmed_email: Option<String>,
    /// Lockable counter.
    pub failed_attempts: i32,
    /// Lockable HMAC digest.
    pub unlock_token: Option<String>,
    /// Lockable timestamp.
    pub locked_at: Option<NaiveDateTime>,
    /// Rails timestamps.
    pub created_at: NaiveDateTime,
    /// Rails timestamps.
    pub updated_at: NaiveDateTime,
}

impl NewFixtureUser {
    /// Full sample row per the shared-suite fixture contract: distinct
    /// token digests per email, fixed timestamps.
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

impl SeaOrmModel for Entity {
    type InsertModel = NewFixtureUser;

    fn table_name() -> &'static str {
        "users"
    }

    /// D-17: only the five curated finder columns, only `Value::String`
    /// carries a bind — anything else is `None`, which the adapter rejects
    /// as `OrmError::Query` naming the column before any SQL exists.
    fn finder_column(column: &str, value: &Value) -> Option<Column> {
        if !FINDER_COLUMNS.contains(&column) {
            return None;
        }
        let Value::String(_) = value else {
            return None;
        };
        match column {
            "email" => Some(Column::Email),
            "reset_password_token" => Some(Column::ResetPasswordToken),
            "confirmation_token" => Some(Column::ConfirmationToken),
            "unlock_token" => Some(Column::UnlockToken),
            "unconfirmed_email" => Some(Column::UnconfirmedEmail),
            _ => None,
        }
    }

    fn pk_condition(key: &DeviseKey) -> Result<SimpleExpr, OrmError> {
        use sea_orm::ColumnTrait as _;
        match key {
            DeviseKey::Integer(id) => Ok(Column::Id.eq(*id)),
            DeviseKey::Uuid(_) => Err(OrmError::InvalidKey(
                "users.id is an integer primary key".to_owned(),
            )),
        }
    }

    /// D-20: PK stays `NotSet`; the database assigns it (auto-increment).
    fn insert_model(new: NewFixtureUser) -> ActiveModel {
        use sea_orm::ActiveValue::Set;
        ActiveModel {
            email: Set(new.email),
            encrypted_password: Set(new.encrypted_password),
            reset_password_token: Set(new.reset_password_token),
            reset_password_sent_at: Set(new.reset_password_sent_at),
            remember_created_at: Set(new.remember_created_at),
            sign_in_count: Set(new.sign_in_count),
            current_sign_in_at: Set(new.current_sign_in_at),
            last_sign_in_at: Set(new.last_sign_in_at),
            current_sign_in_ip: Set(new.current_sign_in_ip),
            last_sign_in_ip: Set(new.last_sign_in_ip),
            confirmation_token: Set(new.confirmation_token),
            confirmed_at: Set(new.confirmed_at),
            confirmation_sent_at: Set(new.confirmation_sent_at),
            unconfirmed_email: Set(new.unconfirmed_email),
            failed_attempts: Set(new.failed_attempts),
            unlock_token: Set(new.unlock_token),
            locked_at: Set(new.locked_at),
            created_at: Set(new.created_at),
            updated_at: Set(new.updated_at),
            ..ActiveModel::default()
        }
    }

    /// D-16: only the PK is `Set` (drives `UPDATE … WHERE id = ?`); every
    /// other field stays `NotSet` so absent fields never enter the
    /// statement — built from the key alone, never by re-reading the stored
    /// row into sea-orm's unchanged-tracked states.
    fn update_base(key: &DeviseKey) -> Result<ActiveModel, OrmError> {
        use sea_orm::ActiveValue::Set;
        match key {
            DeviseKey::Integer(id) => Ok(ActiveModel {
                id: Set(*id),
                ..ActiveModel::default()
            }),
            DeviseKey::Uuid(_) => Err(OrmError::InvalidKey(
                "users.id is an integer primary key".to_owned(),
            )),
        }
    }

    /// D-16 tristate: each named field is `Set(...)` — `Value::Null` →
    /// `Set(None)` writes NULL; a value writes even when equal to the stored
    /// one (#5783 force-write). Assumption A4 verified at compile time: 1.1's
    /// `try_set` delegates to a panicking `set`, so typed match arms with
    /// field assignment are the fallible shape.
    fn apply_changeset(
        am: &mut ActiveModel,
        fields: &HashMap<String, Value>,
    ) -> Result<(), OrmError> {
        use sea_orm::ActiveValue::Set;
        for (column, value) in fields {
            match column.as_str() {
                "email" => am.email = Set(extract_required_string(column, value)?),
                "encrypted_password" => {
                    am.encrypted_password = Set(extract_required_string(column, value)?);
                }
                "reset_password_token" => {
                    am.reset_password_token = Set(extract_nullable_string(column, value)?);
                }
                "reset_password_sent_at" => {
                    am.reset_password_sent_at = Set(extract_nullable_datetime(column, value)?);
                }
                "remember_created_at" => {
                    am.remember_created_at = Set(extract_nullable_datetime(column, value)?);
                }
                "sign_in_count" => am.sign_in_count = Set(extract_required_i32(column, value)?),
                "current_sign_in_at" => {
                    am.current_sign_in_at = Set(extract_nullable_datetime(column, value)?);
                }
                "last_sign_in_at" => {
                    am.last_sign_in_at = Set(extract_nullable_datetime(column, value)?);
                }
                "current_sign_in_ip" => {
                    am.current_sign_in_ip = Set(extract_nullable_string(column, value)?);
                }
                "last_sign_in_ip" => {
                    am.last_sign_in_ip = Set(extract_nullable_string(column, value)?);
                }
                "confirmation_token" => {
                    am.confirmation_token = Set(extract_nullable_string(column, value)?);
                }
                "confirmed_at" => am.confirmed_at = Set(extract_nullable_datetime(column, value)?),
                "confirmation_sent_at" => {
                    am.confirmation_sent_at = Set(extract_nullable_datetime(column, value)?);
                }
                "unconfirmed_email" => {
                    am.unconfirmed_email = Set(extract_nullable_string(column, value)?);
                }
                "failed_attempts" => {
                    am.failed_attempts = Set(extract_required_i32(column, value)?);
                }
                "unlock_token" => am.unlock_token = Set(extract_nullable_string(column, value)?),
                "locked_at" => am.locked_at = Set(extract_nullable_datetime(column, value)?),
                "created_at" => am.created_at = Set(extract_required_datetime(column, value)?),
                "updated_at" => am.updated_at = Set(extract_required_datetime(column, value)?),
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
        Ok(())
    }

    /// D-11: the two counter columns; the adapter also validates against the
    /// core allowlist before calling, so anything else errors in two places
    /// regardless.
    fn counter_column(column: &'static str) -> Result<Column, OrmError> {
        match column {
            "failed_attempts" => Ok(Column::FailedAttempts),
            "sign_in_count" => Ok(Column::SignInCount),
            _ => Err(OrmError::Query {
                message: format!("unsupported counter column: {column}"),
                source: None,
            }),
        }
    }
}

impl ContractModel for Model {
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

/// Uuid-PK fixture table (D-26 uuid leg, D-35): identical columns, but the
/// primary key uses native UUID on pg (via sea-orm's `with-uuid` feature) and
/// hyphenated TEXT on sqlite (sqlite has no native UUID type). The bridge
/// handles both: on sqlite the UUID is stored as hyphenated TEXT; on pg it
/// uses the native UUID column type via `gen_random_uuid()`.
pub mod uuid_users {
    use sea_orm::entity::prelude::*;

    /// Full-module fixture row with a UUID primary key (native on pg, TEXT on sqlite).
    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "uuid_users")]
    pub struct Model {
        /// UUID primary key (native on pg, hyphenated TEXT on sqlite).
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        /// Authentication key.
        pub email: String,
        /// Bcrypt digest.
        pub encrypted_password: String,
        /// Recoverable HMAC digest; `None` means cleared.
        pub reset_password_token: Option<String>,
        /// Recoverable send timestamp.
        pub reset_password_sent_at: Option<DateTime>,
        /// Rememberable timestamp.
        pub remember_created_at: Option<DateTime>,
        /// Trackable counter.
        pub sign_in_count: i32,
        /// Trackable timestamps.
        pub current_sign_in_at: Option<DateTime>,
        /// Trackable timestamps.
        pub last_sign_in_at: Option<DateTime>,
        /// Trackable IPs.
        pub current_sign_in_ip: Option<String>,
        /// Trackable IPs.
        pub last_sign_in_ip: Option<String>,
        /// Confirmable HMAC digest; `None` means cleared.
        pub confirmation_token: Option<String>,
        /// Confirmable timestamps.
        pub confirmed_at: Option<DateTime>,
        /// Confirmable send timestamp.
        pub confirmation_sent_at: Option<DateTime>,
        /// Reconfirmable pending email.
        pub unconfirmed_email: Option<String>,
        /// Lockable counter.
        pub failed_attempts: i32,
        /// Lockable HMAC digest; `None` means cleared.
        pub unlock_token: Option<String>,
        /// Lockable timestamp.
        pub locked_at: Option<DateTime>,
        /// Rails timestamps (`NOT NULL`).
        pub created_at: DateTime,
        /// Rails timestamps (`NOT NULL`).
        pub updated_at: DateTime,
    }

    /// No relations through the adapter (D-22): standalone uuid table only.
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// Insert shape for [`uuid_users::Model`]: the caller assigns the
/// UUID id (the uuid-leg counterpart of the database-assigned
/// integer id — same ownership shape as the diesel/sqlx fixtures).
#[derive(Debug, Clone, Default)]
pub struct NewUuidUser {
    /// UUID primary key.
    pub id: Uuid,
    /// Authentication key.
    pub email: String,
    /// Bcrypt digest.
    pub encrypted_password: String,
    /// Recoverable HMAC digest.
    pub reset_password_token: Option<String>,
    /// Recoverable send timestamp.
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
    /// Confirmable HMAC digest.
    pub confirmation_token: Option<String>,
    /// Confirmable timestamps.
    pub confirmed_at: Option<NaiveDateTime>,
    /// Confirmable send timestamp.
    pub confirmation_sent_at: Option<NaiveDateTime>,
    /// Reconfirmable pending email.
    pub unconfirmed_email: Option<String>,
    /// Lockable counter.
    pub failed_attempts: i32,
    /// Lockable HMAC digest.
    pub unlock_token: Option<String>,
    /// Lockable timestamp.
    pub locked_at: Option<NaiveDateTime>,
    /// Rails timestamps.
    pub created_at: NaiveDateTime,
    /// Rails timestamps.
    pub updated_at: NaiveDateTime,
}

impl NewUuidUser {
    /// Full sample row under a fresh UUID id.
    #[must_use]
    pub fn sample(email: &str, now: NaiveDateTime) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
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

impl SeaOrmModel for uuid_users::Entity {
    type InsertModel = NewUuidUser;

    fn table_name() -> &'static str {
        "uuid_users"
    }

    fn finder_column(column: &str, value: &Value) -> Option<uuid_users::Column> {
        if !FINDER_COLUMNS.contains(&column) {
            return None;
        }
        let Value::String(_) = value else {
            return None;
        };
        match column {
            "email" => Some(uuid_users::Column::Email),
            "reset_password_token" => Some(uuid_users::Column::ResetPasswordToken),
            "confirmation_token" => Some(uuid_users::Column::ConfirmationToken),
            "unlock_token" => Some(uuid_users::Column::UnlockToken),
            "unconfirmed_email" => Some(uuid_users::Column::UnconfirmedEmail),
            _ => None,
        }
    }

    /// D-35: a uuid key binds as its native UUID; an integer
    /// key against this table refuses with `InvalidKey` naming the column —
    /// never a silent miss (Pitfall 10).
    fn pk_condition(key: &DeviseKey) -> Result<SimpleExpr, OrmError> {
        use sea_orm::ColumnTrait as _;
        match key {
            DeviseKey::Uuid(id) => Ok(uuid_users::Column::Id.eq(*id)),
            DeviseKey::Integer(_) => Err(OrmError::InvalidKey(
                "uuid_users.id is a uuid primary key".to_owned(),
            )),
        }
    }

    /// The caller-assigned UUID id arrives `Set` (uuid legs assign
    /// their own keys; D-20's `NotSet` rule covers database-assigned ids).
    fn insert_model(new: NewUuidUser) -> uuid_users::ActiveModel {
        use sea_orm::ActiveValue::Set;
        uuid_users::ActiveModel {
            id: Set(new.id),
            email: Set(new.email),
            encrypted_password: Set(new.encrypted_password),
            reset_password_token: Set(new.reset_password_token),
            reset_password_sent_at: Set(new.reset_password_sent_at),
            remember_created_at: Set(new.remember_created_at),
            sign_in_count: Set(new.sign_in_count),
            current_sign_in_at: Set(new.current_sign_in_at),
            last_sign_in_at: Set(new.last_sign_in_at),
            current_sign_in_ip: Set(new.current_sign_in_ip),
            last_sign_in_ip: Set(new.last_sign_in_ip),
            confirmation_token: Set(new.confirmation_token),
            confirmed_at: Set(new.confirmed_at),
            confirmation_sent_at: Set(new.confirmation_sent_at),
            unconfirmed_email: Set(new.unconfirmed_email),
            failed_attempts: Set(new.failed_attempts),
            unlock_token: Set(new.unlock_token),
            locked_at: Set(new.locked_at),
            created_at: Set(new.created_at),
            updated_at: Set(new.updated_at),
        }
    }

    fn update_base(key: &DeviseKey) -> Result<uuid_users::ActiveModel, OrmError> {
        use sea_orm::ActiveValue::Set;
        match key {
            DeviseKey::Uuid(id) => Ok(uuid_users::ActiveModel {
                id: Set(*id),
                ..uuid_users::ActiveModel::default()
            }),
            DeviseKey::Integer(_) => Err(OrmError::InvalidKey(
                "uuid_users.id is a uuid primary key".to_owned(),
            )),
        }
    }

    fn apply_changeset(
        am: &mut uuid_users::ActiveModel,
        fields: &HashMap<String, Value>,
    ) -> Result<(), OrmError> {
        use sea_orm::ActiveValue::Set;
        for (column, value) in fields {
            match column.as_str() {
                "email" => am.email = Set(extract_required_string(column, value)?),
                "encrypted_password" => {
                    am.encrypted_password = Set(extract_required_string(column, value)?);
                }
                "reset_password_token" => {
                    am.reset_password_token = Set(extract_nullable_string(column, value)?);
                }
                "reset_password_sent_at" => {
                    am.reset_password_sent_at = Set(extract_nullable_datetime(column, value)?);
                }
                "remember_created_at" => {
                    am.remember_created_at = Set(extract_nullable_datetime(column, value)?);
                }
                "sign_in_count" => am.sign_in_count = Set(extract_required_i32(column, value)?),
                "current_sign_in_at" => {
                    am.current_sign_in_at = Set(extract_nullable_datetime(column, value)?);
                }
                "last_sign_in_at" => {
                    am.last_sign_in_at = Set(extract_nullable_datetime(column, value)?);
                }
                "current_sign_in_ip" => {
                    am.current_sign_in_ip = Set(extract_nullable_string(column, value)?);
                }
                "last_sign_in_ip" => {
                    am.last_sign_in_ip = Set(extract_nullable_string(column, value)?);
                }
                "confirmation_token" => {
                    am.confirmation_token = Set(extract_nullable_string(column, value)?);
                }
                "confirmed_at" => am.confirmed_at = Set(extract_nullable_datetime(column, value)?),
                "confirmation_sent_at" => {
                    am.confirmation_sent_at = Set(extract_nullable_datetime(column, value)?);
                }
                "unconfirmed_email" => {
                    am.unconfirmed_email = Set(extract_nullable_string(column, value)?);
                }
                "failed_attempts" => {
                    am.failed_attempts = Set(extract_required_i32(column, value)?);
                }
                "unlock_token" => am.unlock_token = Set(extract_nullable_string(column, value)?),
                "locked_at" => am.locked_at = Set(extract_nullable_datetime(column, value)?),
                "created_at" => am.created_at = Set(extract_required_datetime(column, value)?),
                "updated_at" => am.updated_at = Set(extract_required_datetime(column, value)?),
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
        Ok(())
    }

    fn counter_column(column: &'static str) -> Result<uuid_users::Column, OrmError> {
        match column {
            "failed_attempts" => Ok(uuid_users::Column::FailedAttempts),
            "sign_in_count" => Ok(uuid_users::Column::SignInCount),
            _ => Err(OrmError::Query {
                message: format!("unsupported counter column: {column}"),
                source: None,
            }),
        }
    }
}

impl ContractModel for uuid_users::Model {
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
