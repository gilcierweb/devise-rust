//! actix-demo — browser-parity devise-rust example (D-16 / D-18).
//!
//! Boots the full Devise journey on actix-web 4.12 against diesel-sqlite
//! (`:memory:` pool, zero Docker): sign up → confirm → sign in → remember
//! → edit with current password → lock/unlock → reset → sign out, with
//! Devise redirects and flash keys.
//!
//! ## Modes
//!
//! - `--smoke`   Boot the full app in-process through `actix_web::test`
//!   (no port binding), asserting `SessionMiddleware` is outermost,
//!   fetch the sign-in form, sign in a seeded user, and probe a
//!   middleware-resolved private route. Exits 0.
//! - `--journey` Run the entire browser-parity matrix in-process and
//!   print each step with the observed Devise redirect + flash key.
//! - *(default)* Print the journey URL table, seed, and serve on
//!   127.0.0.1:8080 until killed.
//!
//! ## Local-dev cookie posture (RESEARCH Pitfall 4)
//!
//! `rememberable_options["secure"] = "false"` disables the `Secure`
//! attribute on the remember cookie for plain-HTTP localhost ONLY.
//! **Production deployments MUST remove this override.** The D-16 default
//! keeps `Secure` on.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::print_stdout)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::option_option)]

use std::collections::HashMap;
use std::sync::Arc;

use actix_session::{SessionMiddleware, storage::CookieSessionStore};
use actix_web::{App, HttpResponse, HttpServer, web};
use chrono::NaiveDateTime;
use devise_rust::adapter::{Conditions, DeviseKey, OrmAdapter, OrmError, Value};
use devise_rust::config::DeviseConfig;
use devise_rust::failure::AnyDeviseModel;
use devise_rust::mailer::TestMailer;
use devise_rust::model::{AdapterBridge, ModelFinder};
use devise_rust::rememberable::Rememberable;
use devise_rust::scope::{Mapping, Module, ScopeRegistry, SignOutVia};
use devise_rust::time::{Clock, SystemClock};
use devise_rust_actix::routes::DeviseWebState;
use devise_rust_actix::{ActixSessionStore, DeviseMiddleware, derive_actix_key, devise_for_users};
use devise_rust_diesel::changeset::{
    nullable_datetime, nullable_string, required_datetime, required_i32, required_string,
};
use devise_rust_diesel::pool::{SqlitePool, sqlite_memory_pool};
use devise_rust_migrations::{Dialect, EmitOptions, Flow, PkKind};
use diesel::{ExpressionMethods, QueryDsl, SqliteConnection};
use diesel_async::RunQueryDsl;
use diesel_async::sync_connection_wrapper::SyncConnectionWrapper;

// ============================================================================
// Schema (columns mirror `devise-rust-migrations::emit` full-module DDL)
// ============================================================================

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

type SqliteConn = SyncConnectionWrapper<SqliteConnection>;

/// Devise-facing user model: the diesel row plus the virtual password fields.
#[derive(Clone, Default, PartialEq)]
pub struct ExampleUser {
    pub id: i64,
    pub email: String,
    pub encrypted_password: String,
    pub password: Option<String>,
    pub password_confirmation: Option<String>,
    pub reset_password_token: Option<String>,
    pub reset_password_sent_at: Option<chrono::DateTime<chrono::Utc>>,
    pub remember_created_at: Option<chrono::DateTime<chrono::Utc>>,
    pub remember_token: Option<String>,
    pub sign_in_count: u64,
    pub current_sign_in_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_sign_in_at: Option<chrono::DateTime<chrono::Utc>>,
    pub current_sign_in_ip: Option<String>,
    pub last_sign_in_ip: Option<String>,
    pub confirmation_token: Option<String>,
    pub confirmed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub confirmation_sent_at: Option<chrono::DateTime<chrono::Utc>>,
    pub unconfirmed_email: Option<String>,
    pub failed_attempts: u32,
    pub unlock_token: Option<String>,
    pub locked_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Row shape diesel loads (columns only; virtuals are not columns).
#[derive(Debug, Clone, diesel::Queryable)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
#[allow(dead_code)]
struct UserRow {
    id: i64,
    email: String,
    encrypted_password: String,
    reset_password_token: Option<String>,
    reset_password_sent_at: Option<NaiveDateTime>,
    remember_created_at: Option<NaiveDateTime>,
    sign_in_count: i32,
    current_sign_in_at: Option<NaiveDateTime>,
    last_sign_in_at: Option<NaiveDateTime>,
    current_sign_in_ip: Option<String>,
    last_sign_in_ip: Option<String>,
    confirmation_token: Option<String>,
    confirmed_at: Option<NaiveDateTime>,
    confirmation_sent_at: Option<NaiveDateTime>,
    unconfirmed_email: Option<String>,
    failed_attempts: i32,
    unlock_token: Option<String>,
    locked_at: Option<NaiveDateTime>,
    created_at: NaiveDateTime,
    updated_at: NaiveDateTime,
}

fn row_to_model(row: UserRow) -> ExampleUser {
    ExampleUser {
        id: row.id,
        email: row.email,
        encrypted_password: row.encrypted_password,
        password: None,
        password_confirmation: None,
        reset_password_token: row.reset_password_token,
        reset_password_sent_at: row.reset_password_sent_at.map(|t| t.and_utc()),
        remember_created_at: row.remember_created_at.map(|t| t.and_utc()),
        remember_token: None,
        sign_in_count: u64::try_from(row.sign_in_count).unwrap_or(0),
        current_sign_in_at: row.current_sign_in_at.map(|t| t.and_utc()),
        last_sign_in_at: row.last_sign_in_at.map(|t| t.and_utc()),
        current_sign_in_ip: row.current_sign_in_ip,
        last_sign_in_ip: row.last_sign_in_ip,
        confirmation_token: row.confirmation_token,
        confirmed_at: row.confirmed_at.map(|t| t.and_utc()),
        confirmation_sent_at: row.confirmation_sent_at.map(|t| t.and_utc()),
        unconfirmed_email: row.unconfirmed_email,
        failed_attempts: u32::try_from(row.failed_attempts).unwrap_or(0),
        unlock_token: row.unlock_token,
        locked_at: row.locked_at.map(|t| t.and_utc()),
    }
}

#[derive(diesel::Insertable)]
#[diesel(table_name = users)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct NewUserRow {
    email: String,
    encrypted_password: String,
    reset_password_token: Option<String>,
    reset_password_sent_at: Option<NaiveDateTime>,
    remember_created_at: Option<NaiveDateTime>,
    sign_in_count: i32,
    current_sign_in_at: Option<NaiveDateTime>,
    last_sign_in_at: Option<NaiveDateTime>,
    current_sign_in_ip: Option<String>,
    last_sign_in_ip: Option<String>,
    confirmation_token: Option<String>,
    confirmed_at: Option<NaiveDateTime>,
    confirmation_sent_at: Option<NaiveDateTime>,
    unconfirmed_email: Option<String>,
    failed_attempts: i32,
    unlock_token: Option<String>,
    locked_at: Option<NaiveDateTime>,
    created_at: NaiveDateTime,
    updated_at: NaiveDateTime,
}

/// Tristate changeset for `update_columns` (absent = skip, Some(None) = NULL).
#[derive(Debug, Default, diesel::AsChangeset)]
#[diesel(table_name = users)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct UserChangeset {
    email: Option<String>,
    encrypted_password: Option<String>,
    reset_password_token: Option<Option<String>>,
    reset_password_sent_at: Option<Option<NaiveDateTime>>,
    remember_created_at: Option<Option<NaiveDateTime>>,
    sign_in_count: Option<i32>,
    current_sign_in_at: Option<Option<NaiveDateTime>>,
    last_sign_in_at: Option<Option<NaiveDateTime>>,
    current_sign_in_ip: Option<Option<String>>,
    last_sign_in_ip: Option<Option<String>>,
    confirmation_token: Option<Option<String>>,
    confirmed_at: Option<Option<NaiveDateTime>>,
    confirmation_sent_at: Option<Option<NaiveDateTime>>,
    unconfirmed_email: Option<Option<String>>,
    failed_attempts: Option<i32>,
    unlock_token: Option<Option<String>>,
    locked_at: Option<Option<NaiveDateTime>>,
    created_at: Option<NaiveDateTime>,
    updated_at: Option<NaiveDateTime>,
}

fn fill_changeset(fields: &HashMap<String, Value>) -> Result<UserChangeset, OrmError> {
    let mut out = UserChangeset::default();
    for (column, value) in fields {
        match column.as_str() {
            "email" => out.email = Some(required_string(column, value)?),
            "encrypted_password" => out.encrypted_password = Some(required_string(column, value)?),
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
            "last_sign_in_at" => out.last_sign_in_at = Some(nullable_datetime(column, value)?),
            "current_sign_in_ip" => out.current_sign_in_ip = Some(nullable_string(column, value)?),
            "last_sign_in_ip" => out.last_sign_in_ip = Some(nullable_string(column, value)?),
            "confirmation_token" => out.confirmation_token = Some(nullable_string(column, value)?),
            "confirmed_at" => out.confirmed_at = Some(nullable_datetime(column, value)?),
            "confirmation_sent_at" => {
                out.confirmation_sent_at = Some(nullable_datetime(column, value)?);
            }
            "unconfirmed_email" => out.unconfirmed_email = Some(nullable_string(column, value)?),
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
            other => {
                return Err(OrmError::Query {
                    message: format!("unknown column for update: {other}"),
                    source: None,
                });
            }
        }
    }
    Ok(out)
}

// ============================================================================
// Example adapter: raw diesel-async over the shared sqlite pool
// ============================================================================

/// Example-local `OrmAdapter` over the diesel-sqlite pool (D-18).
#[derive(Clone)]
pub struct ExampleAdapter {
    pool: SqlitePool,
}

impl ExampleAdapter {
    fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    async fn conn(
        &self,
    ) -> Result<Box<dyn std::ops::DerefMut<Target = SqliteConn> + Send>, OrmError> {
        let object = self.pool.get().await.map_err(|e| OrmError::Query {
            message: format!("pool checkout: {e}"),
            source: None,
        })?;
        Ok(Box::new(object))
    }
}

#[async_trait::async_trait]
impl OrmAdapter<ExampleUser> for ExampleAdapter {
    type New = ExampleUser;

    async fn get(&self, id: &DeviseKey) -> Result<Option<ExampleUser>, OrmError> {
        let Some(id) = id.as_i64() else {
            return Err(OrmError::InvalidKey("integer key required".to_owned()));
        };
        let mut conn = self.conn().await?;
        let row = users::table
            .find(id)
            .first::<UserRow>(&mut **conn)
            .await
            .optional()
            .map_err(query_err)?;
        Ok(row.map(row_to_model))
    }

    async fn find_first(&self, conditions: &Conditions) -> Result<Option<ExampleUser>, OrmError> {
        let mut conn = self.conn().await?;
        let mut query = users::table.into_boxed();
        for (column, value) in conditions.iter() {
            let Value::String(text) = value else {
                return Ok(None);
            };
            match column.as_str() {
                "email" => query = query.filter(users::email.eq(text.clone())),
                "reset_password_token" => {
                    query = query.filter(users::reset_password_token.eq(text.clone()));
                }
                "confirmation_token" => {
                    query = query.filter(users::confirmation_token.eq(text.clone()));
                }
                "unlock_token" => query = query.filter(users::unlock_token.eq(text.clone())),
                "unconfirmed_email" => {
                    query = query.filter(users::unconfirmed_email.eq(text.clone()));
                }
                _ => return Ok(None),
            }
        }
        let row = query
            .first::<UserRow>(&mut **conn)
            .await
            .optional()
            .map_err(query_err)?;
        Ok(row.map(row_to_model))
    }

    async fn create(&self, model: ExampleUser) -> Result<ExampleUser, OrmError> {
        let now = SystemClock.now().naive_utc();
        let row = NewUserRow {
            email: model.email.clone(),
            encrypted_password: model.encrypted_password.clone(),
            reset_password_token: model.reset_password_token.clone(),
            reset_password_sent_at: model.reset_password_sent_at.map(|t| t.naive_utc()),
            remember_created_at: model.remember_created_at.map(|t| t.naive_utc()),
            sign_in_count: i32::try_from(model.sign_in_count).unwrap_or(i32::MAX),
            current_sign_in_at: model.current_sign_in_at.map(|t| t.naive_utc()),
            last_sign_in_at: model.last_sign_in_at.map(|t| t.naive_utc()),
            current_sign_in_ip: model.current_sign_in_ip.clone(),
            last_sign_in_ip: model.last_sign_in_ip.clone(),
            confirmation_token: model.confirmation_token.clone(),
            confirmed_at: model.confirmed_at.map(|t| t.naive_utc()),
            confirmation_sent_at: model.confirmation_sent_at.map(|t| t.naive_utc()),
            unconfirmed_email: model.unconfirmed_email.clone(),
            failed_attempts: i32::try_from(model.failed_attempts).unwrap_or(i32::MAX),
            unlock_token: model.unlock_token.clone(),
            locked_at: model.locked_at.map(|t| t.naive_utc()),
            created_at: now,
            updated_at: now,
        };
        let mut conn = self.conn().await?;
        let inserted = diesel::insert_into(users::table)
            .values(&row)
            .get_result::<UserRow>(&mut **conn)
            .await
            .map_err(query_err)?;
        Ok(row_to_model(inserted))
    }

    async fn update(
        &self,
        key: &DeviseKey,
        changes: &devise_rust::adapter::ChangeSet,
    ) -> Result<ExampleUser, OrmError> {
        let mut fields = HashMap::new();
        for field in changes.changed_fields() {
            if let Some(value) = changes.current_value(&field) {
                fields.insert(field, value.clone());
            }
        }
        self.update_columns(key, &fields).await
    }

    async fn update_columns(
        &self,
        key: &DeviseKey,
        fields: &HashMap<String, Value>,
    ) -> Result<ExampleUser, OrmError> {
        let Some(id) = key.as_i64() else {
            return Err(OrmError::InvalidKey("integer key required".to_owned()));
        };
        let mut fields = fields.clone();
        fields.insert(
            "updated_at".to_string(),
            Value::String(SystemClock.now().to_rfc3339()),
        );
        let changeset = fill_changeset(&fields)?;
        let mut conn = self.conn().await?;
        let row = diesel::update(users::table.find(id))
            .set(&changeset)
            .get_result::<UserRow>(&mut **conn)
            .await
            .map_err(query_err)?;
        Ok(row_to_model(row))
    }

    async fn increment_counter(
        &self,
        key: &DeviseKey,
        column: &'static str,
    ) -> Result<ExampleUser, OrmError> {
        let Some(id) = key.as_i64() else {
            return Err(OrmError::InvalidKey("integer key required".to_owned()));
        };
        let mut conn = self.conn().await?;
        let row = match column {
            "failed_attempts" => diesel::update(users::table.find(id))
                .set(users::failed_attempts.eq(users::failed_attempts + 1))
                .get_result::<UserRow>(&mut **conn)
                .await
                .map_err(query_err)?,
            "sign_in_count" => diesel::update(users::table.find(id))
                .set(users::sign_in_count.eq(users::sign_in_count + 1))
                .get_result::<UserRow>(&mut **conn)
                .await
                .map_err(query_err)?,
            other => {
                return Err(OrmError::Query {
                    message: format!("unsupported counter column: {other}"),
                    source: None,
                });
            }
        };
        Ok(row_to_model(row))
    }

    async fn delete(&self, id: &DeviseKey) -> Result<(), OrmError> {
        let Some(id) = id.as_i64() else {
            return Err(OrmError::InvalidKey("integer key required".to_owned()));
        };
        let mut conn = self.conn().await?;
        diesel::delete(users::table.find(id))
            .execute(&mut **conn)
            .await
            .map_err(query_err)?;
        Ok(())
    }
}

fn query_err(e: diesel::result::Error) -> OrmError {
    match e {
        diesel::result::Error::NotFound => OrmError::NotFound,
        other => OrmError::Query {
            message: other.to_string(),
            source: None,
        },
    }
}

use diesel::OptionalExtension;

// ============================================================================
// Devise module trait bundle on ExampleUser
// ============================================================================

impl std::fmt::Debug for ExampleUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // CONCERNS #6: Devise's inspect never prints credentials; the
        // redaction wrapper is the port's single home for that on owned models.
        devise_rust::error::Redacted(self).fmt(f)
    }
}

impl AnyDeviseModel for ExampleUser {
    fn redacted_hash(&self) -> serde_json::Value {
        <Self as devise_rust::model::Authenticatable>::serializable_hash(self)
    }

    fn as_activatable(&self) -> Option<&dyn devise_rust::model::Activatable> {
        Some(self)
    }
    fn to_key(&self) -> DeviseKey {
        DeviseKey::from_i64(self.id)
    }

    fn authenticatable_salt(&self) -> Option<String> {
        self.encrypted_password.get(..29).map(str::to_string)
    }

    fn as_password_verifiable(&self) -> Option<&dyn devise_rust::model::PasswordVerifiable> {
        Some(self)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn rememberable_value_opt(&self) -> Option<String> {
        self.authenticatable_salt()
    }

    fn remember_created_at_opt(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.remember_created_at
    }
}

impl devise_rust::model::PasswordVerifiable for ExampleUser {
    fn valid_password(&self, password: &str, config: &DeviseConfig) -> bool {
        if self.encrypted_password.is_empty() {
            return false;
        }
        devise_rust::crypto::encryptor::compare(password, &self.encrypted_password, config)
    }
}

#[async_trait::async_trait]
impl devise_rust::model::Authenticatable for ExampleUser {
    fn active_for_authentication(&self) -> bool {
        devise_rust::model::compose_active_for_authentication(self, &example_config(), &SystemClock)
    }

    fn inactive_message(&self) -> &'static str {
        devise_rust::model::compose_inactive_message(self, &example_config(), &SystemClock)
    }

    fn serializable_hash(&self) -> serde_json::Value {
        serde_json::json!({ "id": self.id, "email": self.email })
    }
}

#[async_trait::async_trait]
impl devise_rust::model::DatabaseAuthenticatable for ExampleUser {
    fn encrypted_password(&self) -> Option<&str> {
        if self.encrypted_password.is_empty() {
            None
        } else {
            Some(&self.encrypted_password)
        }
    }

    fn set_encrypted_password(&mut self, value: Option<String>) {
        self.encrypted_password = value.unwrap_or_default();
    }

    fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    fn set_password_virtual(&mut self, password: Option<String>) {
        self.password = password;
    }

    fn password_confirmation(&self) -> Option<&str> {
        self.password_confirmation.as_deref()
    }

    fn set_password_confirmation(&mut self, value: Option<String>) {
        self.password_confirmation = value;
    }

    fn persisted(&self) -> bool {
        self.id != 0
    }

    fn assign_attributes(&mut self, attrs: &serde_json::Map<String, serde_json::Value>) {
        if let Some(serde_json::Value::String(email)) = attrs.get("email") {
            email.clone_into(&mut self.email);
        }
    }
}

impl devise_rust::model::Registerable for ExampleUser {}

#[async_trait::async_trait]
impl devise_rust::model::Validatable for ExampleUser {
    fn email_value(&self) -> Option<&str> {
        Some(&self.email)
    }

    fn uniqueness_scope_id(&self) -> Option<String> {
        self.persisted().then(|| self.id.to_string())
    }
}

#[async_trait::async_trait]
impl devise_rust::model::Recoverable for ExampleUser {
    fn reset_password_token(&self) -> Option<&str> {
        self.reset_password_token.as_deref()
    }

    fn reset_password_sent_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.reset_password_sent_at
    }

    fn set_reset_password_token_fields(
        &mut self,
        token: Option<String>,
        sent_at: Option<chrono::DateTime<chrono::Utc>>,
    ) {
        self.reset_password_token = token;
        self.reset_password_sent_at = sent_at;
    }
}

#[async_trait::async_trait]
impl devise_rust::confirmable::Confirmable for ExampleUser {
    fn confirmation_token(&self) -> Option<&str> {
        self.confirmation_token.as_deref()
    }

    fn set_confirmation_token(&mut self, token: Option<String>) {
        self.confirmation_token = token;
    }

    fn confirmed_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.confirmed_at
    }

    fn set_confirmed_at(&mut self, at: Option<chrono::DateTime<chrono::Utc>>) {
        self.confirmed_at = at;
    }

    fn confirmation_sent_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.confirmation_sent_at
    }

    fn set_confirmation_sent_at(&mut self, at: Option<chrono::DateTime<chrono::Utc>>) {
        self.confirmation_sent_at = at;
    }

    fn unconfirmed_email(&self) -> Option<&str> {
        self.unconfirmed_email.as_deref()
    }

    fn set_unconfirmed_email(&mut self, email: Option<String>) {
        self.unconfirmed_email = email;
    }

    fn set_email_address(&mut self, email: String) {
        self.email = email;
    }
}

#[async_trait::async_trait]
impl devise_rust::lockable::Lockable for ExampleUser {
    fn failed_attempts(&self) -> u32 {
        self.failed_attempts
    }

    fn set_failed_attempts(&mut self, count: u32) {
        self.failed_attempts = count;
    }

    fn locked_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.locked_at
    }

    fn set_locked_at(&mut self, at: Option<chrono::DateTime<chrono::Utc>>) {
        self.locked_at = at;
    }

    fn unlock_token(&self) -> Option<&str> {
        self.unlock_token.as_deref()
    }

    fn set_unlock_token(&mut self, token: Option<String>) {
        self.unlock_token = token;
    }

    fn persisted(&self) -> bool {
        self.id != 0
    }
}

impl Rememberable for ExampleUser {
    fn remember_created_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.remember_created_at
    }

    fn set_remember_created_at(&mut self, at: Option<chrono::DateTime<chrono::Utc>>) {
        self.remember_created_at = at;
    }

    fn remember_token(&self) -> Option<&str> {
        self.remember_token.as_deref()
    }

    fn set_remember_token(&mut self, token: Option<String>) {
        self.remember_token = token;
    }

    fn persisted(&self) -> bool {
        self.id != 0
    }
}

impl devise_rust::trackable::Trackable for ExampleUser {
    fn sign_in_count(&self) -> u64 {
        self.sign_in_count
    }

    fn set_sign_in_count(&mut self, count: u64) {
        self.sign_in_count = count;
    }

    fn current_sign_in_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.current_sign_in_at
    }

    fn set_current_sign_in_at(&mut self, at: Option<chrono::DateTime<chrono::Utc>>) {
        self.current_sign_in_at = at;
    }

    fn last_sign_in_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.last_sign_in_at
    }

    fn set_last_sign_in_at(&mut self, at: Option<chrono::DateTime<chrono::Utc>>) {
        self.last_sign_in_at = at;
    }

    fn current_sign_in_ip(&self) -> Option<&str> {
        self.current_sign_in_ip.as_deref()
    }

    fn set_current_sign_in_ip(&mut self, ip: Option<String>) {
        self.current_sign_in_ip = ip;
    }

    fn last_sign_in_ip(&self) -> Option<&str> {
        self.last_sign_in_ip.as_deref()
    }

    fn set_last_sign_in_ip(&mut self, ip: Option<String>) {
        self.last_sign_in_ip = ip;
    }

    fn persisted(&self) -> bool {
        self.id != 0
    }
}

impl devise_rust::mailer::HasEmail for ExampleUser {
    fn email(&self) -> &str {
        &self.email
    }
}

// ============================================================================
// App wiring (SessionMiddleware outermost → DeviseMiddleware → devise_for)
// ============================================================================

/// Example config: fast-ish stretches with the full surface. The
/// `rememberable_options["secure"] = "false"` below is the PLAIN-HTTP
/// LOCAL-DEV OPT-OUT ONLY — restore the default (Secure) in production.
fn example_config() -> DeviseConfig {
    let mut rememberable_options = HashMap::new();
    rememberable_options.insert("secure".to_string(), "false".to_string());
    DeviseConfig {
        secret_key: "example-secret-key-at-least-32-bytes-long!".to_string(),
        stretches: 4,
        mailer_sender: Some("demo@example.com".to_string()),
        rememberable_options,
        ..DeviseConfig::default()
    }
}

/// Scope mapping helper.
fn mapping(name: &str, path: &str) -> Mapping {
    Mapping {
        name: name.to_string(),
        class_name: "ExampleUser".to_string(),
        path: path.to_string(),
        path_prefix: None,
        singular: name.to_string(),
        path_names: devise_rust::scope::PathNames::default(),
        controllers: HashMap::new(),
        modules: vec![
            Module::DatabaseAuthenticatable,
            Module::Registerable,
            Module::Recoverable,
            Module::Rememberable,
            Module::Validatable,
            Module::Confirmable,
            Module::Lockable,
            Module::Trackable,
        ],
        only: vec![],
        skip: vec![],
        constraints: HashMap::new(),
        defaults: HashMap::new(),
        format: None,
        router_name: None,
        sign_out_via: SignOutVia::Delete,
        failure_app: None,
    }
}

type ExampleMailer = TestMailer;
type ExampleState = DeviseWebState<ExampleUser, ExampleAdapter, ExampleMailer>;

fn example_state(
    mapping: Mapping,
    config: Arc<DeviseConfig>,
    adapter: ExampleAdapter,
) -> ExampleState {
    DeviseWebState {
        all_scopes: vec!["user".to_string(), "admin".to_string()],
        mapping,
        config,
        adapter: Arc::new(adapter),
        mailer: Arc::new(TestMailer::default()),
        clock: Arc::new(SystemClock),
        marker: std::marker::PhantomData,
    }
}

/// Probe route proving the middleware resolves the signed-in scope user.
async fn private_probe(req: actix_web::HttpRequest) -> HttpResponse {
    match devise_rust_actix::current_user::<ExampleUser>(&req) {
        Some(user) => HttpResponse::Ok().json(serde_json::json!({ "email": user.email })),
        None => HttpResponse::Unauthorized().finish(),
    }
}

async fn root() -> HttpResponse {
    HttpResponse::Ok().body("devise-rust actix-demo: see --journey for the full matrix")
}

/// Migrate `:memory:` schema onto the pool (`max_size(1)` — one shared db).
async fn migrate(pool: &SqlitePool) {
    let opts = EmitOptions::new("users")
        .with_all_modules()
        .dialect(Dialect::Sqlite)
        .pk(PkKind::Integer)
        .flow(Flow::Create);
    let files = devise_rust_migrations::emit(&opts).expect("DDL emits");
    let mut conn = pool.get().await.expect("pool checkout");
    diesel_async::SimpleAsyncConnection::batch_execute(&mut *conn, &files.up_sql)
        .await
        .expect("DDL applies");
}

/// Full app factory: `SessionMiddleware` outermost (registered last → runs
/// first), then `DeviseMiddleware`, then both `devise_for` scopes plus the
/// probe routes. Shared by --smoke, --journey, and the HTTP server entry.
#[allow(clippy::needless_pass_by_value)] // owned place so the returned App is 'static
fn app_factory(
    pool: SqlitePool,
    config: Arc<DeviseConfig>,
    mailer: Arc<TestMailer>,
) -> App<
    impl actix_web::dev::ServiceFactory<
        actix_web::dev::ServiceRequest,
        Config = (),
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
        InitError = (),
    >,
> {
    let key = derive_actix_key(&config.secret_key).expect("derive key");

    let user_mapping = mapping("user", "users");
    let admin_mapping = mapping("admin", "admins");

    let adapter = ExampleAdapter::new(pool.clone());
    // Devise `check_fields!` parity: fail loudly at startup when a model's
    // required columns are missing from the database. `app_factory` is sync,
    // so each probe runs on the current runtime handle.
    for mapping in [&user_mapping, &admin_mapping] {
        let adapter = adapter.clone();
        let mapping = mapping.clone();
        let config = config.clone();
        let outcome = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                devise_rust_actix::schema::assert_model_schema(&adapter, &mapping, &config).await
            })
        });
        if let Err(error) = outcome {
            panic!(
                "{scope} model schema check failed: {error}",
                scope = mapping.name
            );
        }
    }
    let mut user_state = example_state(user_mapping.clone(), config.clone(), adapter.clone());
    user_state.mailer = mailer.clone();
    let mut admin_state = example_state(admin_mapping.clone(), config.clone(), adapter.clone());
    admin_state.mailer = mailer;

    let mut registry = ScopeRegistry::new();
    registry.register(user_mapping);
    registry.register(admin_mapping);
    let registry = Arc::new(registry);

    let user_finder: Arc<dyn ModelFinder> = Arc::new(AdapterBridge::new(adapter.clone()));
    let admin_finder: Arc<dyn ModelFinder> = Arc::new(AdapterBridge::new(adapter));

    let middleware = DeviseMiddleware::new(
        Arc::new(ActixSessionStore::new(key.clone())),
        registry,
        config,
    )
    .with_finder("user", user_finder)
    .with_finder("admin", admin_finder);

    App::new()
        .wrap(middleware)
        // SessionMiddleware registered LAST = runs FIRST (outermost).
        .wrap(
            SessionMiddleware::builder(CookieSessionStore::default(), key)
                .cookie_secure(false) // plain-HTTP local dev ONLY; restore in production
                .build(),
        )
        .route("/", web::get().to(root))
        .route("/private", web::get().to(private_probe))
        .service(devise_for_users(web::Data::new(user_state)))
        .service(devise_for_users(web::Data::new(admin_state)))
}

/// Seed one user idempotently on email.
async fn seed_one(adapter: &ExampleAdapter, email: &str, config: &DeviseConfig) -> ExampleUser {
    let mut conditions = Conditions::new();
    conditions.insert("email", Value::String(email.to_string()));
    if let Ok(Some(existing)) = adapter.find_first(&conditions).await {
        return existing;
    }
    let mut user = ExampleUser {
        email: email.to_string(),
        ..ExampleUser::default()
    };
    devise_rust::model::DatabaseAuthenticatable::set_password(
        &mut user,
        Some("password123".to_string()),
        config,
    );
    devise_rust::confirmable::Confirmable::skip_confirmation(&mut user, &SystemClock);
    adapter.create(user).await.expect("seed create")
}

/// Seed one confirmed user + one admin (idempotent on email).
async fn seed(pool: &SqlitePool, config: &DeviseConfig) -> (ExampleUser, ExampleUser) {
    let adapter = ExampleAdapter::new(pool.clone());
    let user = seed_one(&adapter, "demo@example.com", config).await;
    let admin = seed_one(&adapter, "admin@example.com", config).await;
    (user, admin)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map_or("serve", String::as_str);

    let pool = sqlite_memory_pool().expect("in-memory sqlite pool builds");
    migrate(&pool).await;
    let config = Arc::new(example_config());
    let mailer = Arc::new(TestMailer::default().with_sender(config.mailer_sender.clone()));

    match mode {
        "--smoke" => {
            smoke(&pool, config, mailer).await;
            println!("smoke: OK");
            Ok(())
        }
        "--journey" => {
            journey(&pool, config, mailer).await;
            Ok(())
        }
        _ => {
            print_journey_urls();
            let (user, admin) = seed(&pool, &config).await;
            println!(
                "seeded: {} (id {}), {} (id {}) — password: password123",
                user.email, user.id, admin.email, admin.id
            );
            let factory_pool = pool.clone();
            let factory_config = config.clone();
            let factory_mailer = mailer.clone();
            println!("serving on http://127.0.0.1:8080 — Ctrl-C to stop");
            HttpServer::new(move || {
                app_factory(
                    factory_pool.clone(),
                    factory_config.clone(),
                    factory_mailer.clone(),
                )
            })
            .bind(("127.0.0.1", 8080))?
            .run()
            .await
        }
    }
}

fn print_journey_urls() {
    println!("devise-rust actix-demo journey:");
    for (step, method, url, expect) in [
        (
            "sign up",
            "POST",
            "/users",
            "302 flash signed_up_but_unconfirmed",
        ),
        (
            "confirm",
            "GET",
            "/users/confirmation?confirmation_token=<raw>",
            "302 flash confirmed",
        ),
        ("sign in", "POST", "/users/sign_in", "302 flash signed_in"),
        (
            "remember",
            "POST",
            "/users/sign_in (remember_me=1)",
            "sets remember_user_token",
        ),
        ("private", "GET", "/private", "200 with {\"email\": ..}"),
        (
            "edit",
            "PATCH",
            "/users/",
            "302 flash updated (session renewed)",
        ),
        ("lock", "—", "seeded locked row", "sign-in 302 flash locked"),
        (
            "unlock",
            "GET",
            "/users/unlock?unlock_token=<raw>",
            "302 flash unlocked",
        ),
        (
            "reset",
            "PATCH",
            "/users/password",
            "302 flash updated (signed in)",
        ),
        (
            "sign out",
            "DELETE",
            "/users/sign_out",
            "302/— flash signed_out",
        ),
        (
            "admin sign in",
            "POST",
            "/admins/sign_in",
            "302 flash signed_in",
        ),
    ] {
        println!("  {step:<14} {method:8} {url:56} → {expect}");
    }
}

// ============================================================================
// In-process smoke + journey (actix_web::test, no port binding)
// ============================================================================

/// Cookie jar shaped like a browser's: merge every `Set-Cookie` seen so far,
/// keeping the newest per name (session renewals rotate the id).
#[derive(Default)]
struct Jar {
    cookies: Vec<String>,
}

impl Jar {
    fn merge(&mut self, resp: &actix_web::dev::ServiceResponse) {
        for pair in devise_rust_actix::test_helpers::set_cookie_pairs(resp) {
            let name = pair.split('=').next().unwrap_or("").to_string();
            self.cookies
                .retain(|existing| existing.split('=').next() != Some(name.as_str()));
            self.cookies.push(pair);
        }
    }

    fn header(&self) -> String {
        devise_rust_actix::test_helpers::cookie_header(&self.cookies)
    }
}

fn flash_of(jar: &Jar) -> Option<String> {
    jar.cookies
        .iter()
        .find(|c| c.starts_with("devise.flash="))?
        .split('=')
        .nth(1)
        .map(str::to_string)
}

async fn smoke(pool: &SqlitePool, config: Arc<DeviseConfig>, mailer: Arc<TestMailer>) {
    use actix_web::test;
    let (user, _admin) = seed(pool, &config).await;
    let service = test::init_service(app_factory(pool.clone(), config, mailer)).await;

    // Form answers 200 (route table wired, middleware order correct).
    let resp = test::call_service(
        &service,
        test::TestRequest::get().uri("/users/sign_in").to_request(),
    )
    .await;
    assert_eq!(resp.status(), 200, "sign-in form must answer 200");

    // Sign in through the real form: SessionMiddleware outermost proves the
    // session jar survives to the devise middleware.
    let resp = test::call_service(
        &service,
        test::TestRequest::post()
            .uri("/users/sign_in")
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload(format!(
                "email={}&password=password123",
                user.email.replace('@', "%40")
            ))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 302, "sign-in must redirect (found)");
    let mut jar = Jar::default();
    jar.merge(&resp);
    assert_eq!(
        flash_of(&jar).as_deref(),
        Some("signed_in"),
        "signed_in flash expected"
    );

    // Signed-in probe: /private resolves the user via middleware extensions.
    let resp = test::call_service(
        &service,
        test::TestRequest::get()
            .uri("/private")
            .insert_header(("cookie", jar.header()))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 200, "probe must answer 200 once signed in");
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["email"], serde_json::json!(user.email));

    // Middleware-order tripwire: without SessionMiddleware outermost the
    // devise middleware would see no session and this probe would never
    // resolve. Its passing IS the middleware-order assertion.
}

/// Full browser-parity journey (D-16): every step prints its verdict.
#[allow(clippy::cognitive_complexity)]
async fn journey(pool: &SqlitePool, config: Arc<DeviseConfig>, mailer: Arc<TestMailer>) {
    use actix_web::test;
    use devise_rust_actix::test_helpers::set_cookie_pairs;

    let (_demo, admin) = seed(pool, &config).await;
    let service =
        test::init_service(app_factory(pool.clone(), config.clone(), mailer.clone())).await;
    let mut jar = Jar::default();
    let step = |name: &str, ok: bool, detail: &str| {
        println!(
            "  {name:<28} [{what}] {detail}",
            what = if ok { " ok " } else { "FAIL" }
        );
        assert!(ok, "journey step failed: {name} ({detail})");
    };
    let urlencode = |raw: &str| raw.replace('@', "%40");

    // 1. Sign up → unconfirmed (confirmable active), mail sent.
    let resp = test::call_service(
        &service,
        test::TestRequest::post()
            .uri("/users")
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload(format!(
                "user[email]={}&user[password]=journey1&user[password_confirmation]=journey1",
                urlencode("journey@example.com")
            ))
            .to_request(),
    )
    .await;
    jar.merge(&resp);
    step(
        "sign up",
        resp.status().as_u16() == 302
            && flash_of(&jar).as_deref() == Some("signed_up_but_unconfirmed"),
        &format!("302, flash={:?}", flash_of(&jar)),
    );
    let sent = mailer.sent_mails();
    let raw_confirm = sent
        .last()
        .and_then(|mail| mail.template_vars.token.clone())
        .expect("confirmation mail carries raw token");

    // 2. Confirm via the emailed raw token.
    let resp = test::call_service(
        &service,
        test::TestRequest::get()
            .uri(&format!(
                "/users/confirmation?confirmation_token={raw_confirm}"
            ))
            .to_request(),
    )
    .await;
    jar.merge(&resp);
    step(
        "confirm",
        resp.status().as_u16() == 302 && flash_of(&jar).as_deref() == Some("confirmed"),
        &format!("302, flash={:?}", flash_of(&jar)),
    );

    // 3. Sign in with remember_me → session + remember cookie.
    let resp = test::call_service(
        &service,
        test::TestRequest::post()
            .uri("/users/sign_in")
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload("email=journey%40example.com&password=journey1&remember_me=1")
            .to_request(),
    )
    .await;
    jar.merge(&resp);
    let has_remember = jar
        .cookies
        .iter()
        .any(|c| c.starts_with("remember_user_token="));
    step(
        "sign in + remember",
        resp.status().as_u16() == 302
            && flash_of(&jar).as_deref() == Some("signed_in")
            && has_remember,
        &format!("302, remember cookie: {has_remember}"),
    );

    // 4. Probe: middleware resolves the user.
    let resp = test::call_service(
        &service,
        test::TestRequest::get()
            .uri("/private")
            .insert_header(("cookie", jar.header()))
            .to_request(),
    )
    .await;
    let status = resp.status().as_u16();
    step("private probe", status == 200, &format!("http {status}"));

    // 5. Edit account with current password → renewed session (rotated id).
    let session_before = jar.cookies.iter().find(|c| c.starts_with("id=")).cloned();
    let resp = test::call_service(
        &service,
        test::TestRequest::default()
            .method(actix_web::http::Method::PATCH)
            .uri("/users/")
            .insert_header(("cookie", jar.header()))
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload(
                "user[current_password]=journey1&user[password]=journey2&user[password_confirmation]=journey2",
            )
            .to_request(),
    )
    .await;
    jar.merge(&resp);
    let session_after = jar.cookies.iter().find(|c| c.starts_with("id=")).cloned();
    step(
        "edit w/ current password",
        resp.status().as_u16() == 302
            && flash_of(&jar).as_deref() == Some("updated")
            && session_before.is_some()
            && session_after.is_some()
            && session_before != session_after,
        "302 updated, session rotated",
    );

    // 6. Sign out → session + remember tombstone.
    let resp = test::call_service(
        &service,
        test::TestRequest::delete()
            .uri("/users/sign_out")
            .insert_header(("cookie", jar.header()))
            .to_request(),
    )
    .await;
    jar.merge(&resp);
    step(
        "sign out",
        resp.status().as_u16() == 302 && flash_of(&jar).as_deref() == Some("signed_out"),
        &format!("302, flash={:?}", flash_of(&jar)),
    );

    // 7. Lock the account directly (adapter-side), then sign in → locked.
    let adapter = ExampleAdapter::new(pool.clone());
    let mut conditions = Conditions::new();
    conditions.insert("email", Value::String("journey@example.com".to_string()));
    let mut locked_user = adapter
        .find_first(&conditions)
        .await
        .expect("lookup")
        .expect("present");
    locked_user.locked_at = Some(SystemClock.now());
    let mut lock_fields = HashMap::new();
    lock_fields.insert(
        "locked_at".to_string(),
        Value::String(SystemClock.now().to_rfc3339()),
    );
    // maximum_attempts=20 (Devise default): drive the counter to the
    // threshold so the sign-in attempt surfaces `locked`, not `invalid`.
    lock_fields.insert(
        "failed_attempts".to_string(),
        Value::Integer(config.maximum_attempts.into()),
    );
    adapter
        .update_columns(&locked_user.to_key(), &lock_fields)
        .await
        .expect("lock write");
    let resp = test::call_service(
        &service,
        test::TestRequest::post()
            .uri("/users/sign_in")
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload("email=journey%40example.com&password=journey2")
            .to_request(),
    )
    .await;
    let jar_lock: Vec<String> = set_cookie_pairs(&resp);
    let flash_lock = jar_lock
        .iter()
        .find(|c| c.starts_with("devise.flash="))
        .and_then(|c| c.split('=').nth(1))
        .map(str::to_string);
    step(
        "lock blocks sign-in",
        resp.status().as_u16() == 302 && flash_lock.as_deref() == Some("locked"),
        &format!("flash={flash_lock:?}"),
    );

    // 8. Unlock instructions → raw token via mail → unlock by token.
    let resp = test::call_service(
        &service,
        test::TestRequest::post()
            .uri("/users/unlock")
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload("email=journey%40example.com")
            .to_request(),
    )
    .await;
    let sent = mailer.sent_mails();
    let raw_unlock = sent
        .last()
        .and_then(|mail| mail.template_vars.token.clone())
        .expect("unlock mail carries raw token");
    step(
        "unlock instructions",
        resp.status().as_u16() == 302,
        &format!("http {}", resp.status()),
    );
    let resp = test::call_service(
        &service,
        test::TestRequest::get()
            .uri(&format!("/users/unlock?unlock_token={raw_unlock}"))
            .to_request(),
    )
    .await;
    let jar_unlock: Vec<String> = set_cookie_pairs(&resp);
    let flash_unlock = jar_unlock
        .iter()
        .find(|c| c.starts_with("devise.flash="))
        .and_then(|c| c.split('=').nth(1))
        .map(str::to_string);
    step(
        "unlock by token",
        resp.status().as_u16() == 302 && flash_unlock.as_deref() == Some("unlocked"),
        &format!("flash={flash_unlock:?}"),
    );

    // 9. Reset: instructions → raw token → PATCH password → signed in flash updated.
    let resp = test::call_service(
        &service,
        test::TestRequest::post()
            .uri("/users/password")
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload("email=journey%40example.com")
            .to_request(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 302);
    let sent = mailer.sent_mails();
    let raw_reset = sent
        .last()
        .and_then(|mail| mail.template_vars.token.clone())
        .expect("reset mail carries raw token");
    let resp = test::call_service(
        &service,
        test::TestRequest::default()
            .method(actix_web::http::Method::PATCH)
            .uri("/users/password")
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload(format!(
                "user[reset_password_token]={raw_reset}&user[password]=journey3&user[password_confirmation]=journey3"
            ))
            .to_request(),
    )
    .await;
    let jar_reset: Vec<String> = set_cookie_pairs(&resp);
    let flash_reset = jar_reset
        .iter()
        .find(|c| c.starts_with("devise.flash="))
        .and_then(|c| c.split('=').nth(1))
        .map(str::to_string);
    step(
        "reset by token",
        resp.status().as_u16() == 302 && flash_reset.as_deref() == Some("updated"),
        &format!("flash={flash_reset:?}"),
    );

    // 10. Admin scope on the second mapping/controller bundle.
    let resp = test::call_service(
        &service,
        test::TestRequest::post()
            .uri("/admins/sign_in")
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload(format!(
                "email={}&password=password123",
                urlencode(&admin.email)
            ))
            .to_request(),
    )
    .await;
    let jar_admin: Vec<String> = set_cookie_pairs(&resp);
    let flash_admin = jar_admin
        .iter()
        .find(|c| c.starts_with("devise.flash="))
        .and_then(|c| c.split('=').nth(1))
        .map(str::to_string);
    step(
        "admin sign in",
        resp.status().as_u16() == 302 && flash_admin.as_deref() == Some("signed_in"),
        &format!("flash={flash_admin:?}"),
    );

    println!("journey: all 10 steps passed");
}
