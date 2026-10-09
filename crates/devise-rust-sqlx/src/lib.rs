//! `devise-rust-sqlx` — sqlx ORM backend for devise-rust.
//!
//! This crate is the second concrete [`OrmAdapter`](devise_rust::adapter::OrmAdapter)
//! backend (ORM-06): a single generic [`SqlxAdapter`] over sqlx **0.8.6**
//! using runtime `query_as` + `QueryBuilder` only — the `query!` macro
//! family stays OFF so no downstream app inherits a compile-time
//! `DATABASE_URL`/`.sqlx` requirement. Models bind through the hand-written
//! [`SqlxModel`] glue (D-01/D-07) and the application owns the pool (D-09).
//!
//! ## Features
//!
//! * `postgres` — the Postgres arm: `INSERT … RETURNING` id echo, native
//!   `UUID` keys (D-35).
//! * `sqlite` — the SQLite arm: `RETURNING` id echo (bundled
//!   `libsqlite3-sys` ≥ 3.44), hyphenated `TEXT` uuid keys.
//! * `mysql` — **experimental** (D-33): the MySQL arm compiles behind this
//!   feature but has NO CI execution and NO execution verification; treat
//!   MySQL support as pending until verified.
//! * `e2e-pg` — compiles the Postgres arm plus the (upcoming)
//!   testcontainers rig entry; the CI backend-by-database matrix job runs
//!   `cargo test -p devise-rust-sqlx --features e2e-pg`.
//!
//! With no dialect feature the crate exposes only the backend-agnostic
//! pieces ([`SqlxModel`], the [`glue`] extractors, [`error`]); the adapter
//! needs a backend to exist.
//!
//! ## Modules
//!
//! * [`glue`](crate::glue) — [`SqlxModel`] (D-01/D-02) plus the tristate
//!   write extractors; implemented by hand per model.
//! * [`query`](crate::query) — `QueryBuilder` reads/writes over the
//!   per-database `Dialect` bind seam (D-03/D-34).
//! * [`create`](crate::create) — per-database insert id echo (D-05).
//! * [`counter`](crate::counter) — atomic `SET column = column + 1` (D-11).
//! * [`error`](crate::error) — sqlx error → `OrmError` mapper with
//!   unique-violation discrimination (Pitfall 4).
//! * [`pool`](crate::pool) — application-pool convenience builders,
//!   including the `max_connections(1)` `:memory:` helper (Pitfall 1).

#[cfg(any(feature = "postgres", feature = "sqlite", feature = "mysql"))]
use std::collections::HashMap;
#[cfg(any(feature = "postgres", feature = "sqlite", feature = "mysql"))]
use std::marker::PhantomData;

#[cfg(any(feature = "postgres", feature = "sqlite", feature = "mysql"))]
use async_trait::async_trait;
#[cfg(any(feature = "postgres", feature = "sqlite", feature = "mysql"))]
use devise_rust::adapter::{
    ChangeSet, Conditions, DeviseKey, OrmAdapter, OrmError, Value, validate_counter_column,
};

pub mod error;
pub mod glue;

#[cfg(any(feature = "postgres", feature = "sqlite", feature = "mysql"))]
pub mod counter;
#[cfg(any(feature = "postgres", feature = "sqlite", feature = "mysql"))]
pub mod create;
#[cfg(any(feature = "postgres", feature = "sqlite", feature = "mysql"))]
pub mod pool;
#[cfg(any(feature = "postgres", feature = "sqlite", feature = "mysql"))]
pub mod query;

pub use glue::{Bind, KeyShape, SqlxModel, WriteValue};

#[cfg(any(feature = "postgres", feature = "sqlite", feature = "mysql"))]
pub use create::InsertEcho;
#[cfg(any(feature = "postgres", feature = "sqlite", feature = "mysql"))]
pub use query::Dialect;

/// Generic sqlx adapter: the second concrete [`OrmAdapter`] backend (D-04).
///
/// `M` is the model (bound via [`SqlxModel`] and `sqlx::FromRow`), `DB` the
/// sqlx database marker ([`sqlx::Sqlite`], [`sqlx::Postgres`], …).
/// Construct it with the application's pool (D-09: the app owns size,
/// timeouts, and lifecycle; the adapter only runs queries).
///
/// # Examples
///
/// ```rust,ignore
/// use devise_rust_sqlx::SqlxAdapter;
/// # struct User;
/// # #[cfg(feature = "sqlite")]
/// # {
/// let pool = devise_rust_sqlx::pool::sqlite_memory_pool().expect("pool");
/// let adapter: SqlxAdapter<User, sqlx::Sqlite> = SqlxAdapter::new(pool);
/// # }
/// ```
#[cfg(any(feature = "postgres", feature = "sqlite", feature = "mysql"))]
pub struct SqlxAdapter<M, DB: sqlx::Database> {
    pool: sqlx::Pool<DB>,
    binding: PhantomData<fn() -> M>,
}

#[cfg(any(feature = "postgres", feature = "sqlite", feature = "mysql"))]
impl<M, DB: sqlx::Database> SqlxAdapter<M, DB> {
    /// Wraps the application's pool (D-09).
    #[must_use]
    pub fn new(pool: sqlx::Pool<DB>) -> Self {
        Self {
            pool,
            binding: PhantomData,
        }
    }

    /// Borrows the underlying pool (health checks, manual checkouts).
    #[must_use]
    pub fn pool(&self) -> &sqlx::Pool<DB> {
        &self.pool
    }
}

/// The full adapter surface over one database. Reads shape every SELECT
/// from the glue's explicit column list (never `SELECT *` — Pitfall 2);
/// writes carry the D-03 tristate; counters render one atomic `SET column
/// = column + 1` statement and re-read on the same checkout (D-11); the
/// insert echo is per-database (D-05, [`InsertEcho`]).
#[cfg(any(feature = "postgres", feature = "sqlite", feature = "mysql"))]
#[async_trait]
impl<M, DB> OrmAdapter<M> for SqlxAdapter<M, DB>
where
    M: SqlxModel + Unpin,
    for<'r> M: sqlx::FromRow<'r, <DB as sqlx::Database>::Row>,
    DB: Dialect + InsertEcho<M>,
    for<'q> <DB as sqlx::Database>::Arguments<'q>: sqlx::IntoArguments<'q, DB>,
    for<'x> &'x mut <DB as sqlx::Database>::Connection: sqlx::Executor<'x, Database = DB>,
    <DB as sqlx::Database>::Connection: Sync,
{
    type New = M::New;

    async fn get(&self, id: &DeviseKey) -> Result<Option<M>, OrmError> {
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(crate::error::map_pool_error)?;
        query::get_row::<M, DB>(&mut conn, id).await
    }

    async fn find_first(&self, conditions: &Conditions) -> Result<Option<M>, OrmError> {
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(crate::error::map_pool_error)?;
        query::find_first_row::<M, DB>(&mut conn, conditions).await
    }

    async fn create(&self, model: Self::New) -> Result<M, OrmError> {
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(crate::error::map_pool_error)?;
        <DB as InsertEcho<M>>::insert_row(&mut conn, model).await
    }

    async fn update(&self, key: &DeviseKey, changes: &ChangeSet) -> Result<M, OrmError> {
        let mut fields = HashMap::new();
        for field in changes.changed_fields() {
            if let Some(value) = changes.current_value(&field) {
                fields.insert(field, value.clone());
            }
        }
        self.write_map(key, &fields).await
    }

    async fn update_columns(
        &self,
        key: &DeviseKey,
        fields: &HashMap<String, Value>,
    ) -> Result<M, OrmError> {
        self.write_map(key, fields).await
    }

    async fn increment_counter(
        &self,
        key: &DeviseKey,
        column: &'static str,
    ) -> Result<M, OrmError> {
        validate_counter_column(column)?;
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(crate::error::map_pool_error)?;
        counter::increment_field::<M, DB>(&mut conn, key, column).await?;
        // Re-read on the SAME checkout (pool-of-1 discipline); a miss
        // reports NotFound, never a silent zero.
        query::get_row::<M, DB>(&mut conn, key)
            .await?
            .ok_or(OrmError::NotFound)
    }

    async fn delete(&self, id: &DeviseKey) -> Result<(), OrmError> {
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(crate::error::map_pool_error)?;
        query::delete_row::<M, DB>(&mut conn, id).await
    }
}

#[cfg(any(feature = "postgres", feature = "sqlite", feature = "mysql"))]
impl<M, DB> SqlxAdapter<M, DB>
where
    M: SqlxModel + Unpin,
    for<'r> M: sqlx::FromRow<'r, <DB as sqlx::Database>::Row>,
    DB: Dialect + InsertEcho<M>,
    for<'q> <DB as sqlx::Database>::Arguments<'q>: sqlx::IntoArguments<'q, DB>,
    for<'x> &'x mut <DB as sqlx::Database>::Connection: sqlx::Executor<'x, Database = DB>,
    <DB as sqlx::Database>::Connection: Sync,
{
    /// Shared partial-write path (diesel `write_map` parity): empty maps
    /// short-circuit to a re-read (missing → `NotFound`, never invalid
    /// `UPDATE … SET WHERE` SQL — Pitfall 6); otherwise the tristate
    /// `UPDATE` executes and the fresh row is re-read on the SAME
    /// connection (pool-of-1 deadlock avoidance).
    async fn write_map(
        &self,
        key: &DeviseKey,
        fields: &HashMap<String, Value>,
    ) -> Result<M, OrmError> {
        if fields.is_empty() {
            return self.get(key).await?.ok_or(OrmError::NotFound);
        }
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(crate::error::map_pool_error)?;
        query::write_fields::<M, DB>(&mut conn, key, fields).await?;
        query::get_row::<M, DB>(&mut conn, key)
            .await?
            .ok_or(OrmError::NotFound)
    }
}
