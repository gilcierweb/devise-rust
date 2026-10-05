//! Deadpool pool builders over diesel-async connections.
//!
//! Pooling uses diesel-async's first-party `deadpool` integration
//! (`deadpool ^0.12` arrives transitively via diesel-async's `deadpool`
//! feature — MSRV 1.85-verified). The third-party `deadpool-diesel` crate
//! wraps *synchronous* diesel and must never appear here.
//!
//! SQLite note (Pitfall 3): every `:memory:` connection owns a *private*
//! database, so a pooled in-memory rig must force `max_size(1)` — otherwise
//! migrations applied on one connection are invisible to the next. Use
//! [`sqlite_memory_pool`]; production SQLite pools stay single-writer by the
//! same token.

use std::ops::DerefMut;

use async_trait::async_trait;

use crate::error::map_pool_error;
use devise_rust::adapter::OrmError;

#[cfg(feature = "sqlite")]
use diesel::SqliteConnection;
#[cfg(feature = "postgres")]
use diesel_async::AsyncPgConnection;
#[cfg(any(feature = "postgres", feature = "sqlite"))]
use diesel_async::pooled_connection::{AsyncDieselConnectionManager, deadpool::Pool};
#[cfg(feature = "sqlite")]
use diesel_async::sync_connection_wrapper::SyncConnectionWrapper;

#[cfg(feature = "postgres")]
/// Pooled async PostgreSQL connections.
pub type PgPool = Pool<AsyncPgConnection>;

#[cfg(feature = "postgres")]
/// Builds a deadpool over `AsyncPgConnection` (docs.rs-verbatim shape).
///
/// # Errors
///
/// Returns [`OrmError::Connection`] when the pool cannot be built. The URL
/// never appears in the message.
///
/// # Examples
///
/// ```rust,no_run
/// # #[cfg(feature = "postgres")]
/// # {
/// use devise_rust_diesel::pool::pg_pool;
///
/// let pool = pg_pool("postgres://localhost/devise").expect("pool builds");
/// # let _ = pool;
/// # }
/// ```
pub fn pg_pool(url: &str) -> Result<PgPool, OrmError> {
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url);
    Pool::builder(manager).build().map_err(map_pool_error)
}

#[cfg(feature = "sqlite")]
/// Pooled SQLite connections through tokio `spawn_blocking`.
pub type SqlitePool = Pool<SyncConnectionWrapper<SqliteConnection>>;

#[cfg(feature = "sqlite")]
/// Builds a deadpool over `SyncConnectionWrapper<SqliteConnection>`.
///
/// `max_size` bounds the pool; pass `1` for `:memory:` databases (see
/// [`sqlite_memory_pool`]).
///
/// # Errors
///
/// Returns [`OrmError::Connection`] when the pool cannot be built.
///
/// # Examples
///
/// ```rust
/// # #[cfg(feature = "sqlite")]
/// # {
/// use devise_rust_diesel::pool::sqlite_pool;
///
/// let pool = sqlite_pool(":memory:", 1).expect("pool builds");
/// # let _ = pool;
/// # }
/// ```
pub fn sqlite_pool(url: &str, max_size: usize) -> Result<SqlitePool, OrmError> {
    let manager = AsyncDieselConnectionManager::<SyncConnectionWrapper<SqliteConnection>>::new(url);
    Pool::builder(manager)
        .max_size(max_size)
        .build()
        .map_err(map_pool_error)
}

#[cfg(feature = "sqlite")]
/// Builds the shared in-memory SQLite pool: `:memory:` with `max_size(1)` so
/// every checkout sees the same database.
///
/// # Errors
///
/// Returns [`OrmError::Connection`] when the pool cannot be built.
///
/// # Examples
///
/// ```rust
/// # #[cfg(feature = "sqlite")]
/// # {
/// use devise_rust_diesel::pool::sqlite_memory_pool;
///
/// let pool = sqlite_memory_pool().expect("pool builds");
/// # let _ = pool;
/// # }
/// ```
pub fn sqlite_memory_pool() -> Result<SqlitePool, OrmError> {
    sqlite_pool(":memory:", 1)
}

/// Type-erased pool checkout behind [`DieselOrmAdapter`](crate::adapter::DieselOrmAdapter).
///
/// `deadpool`'s `Manager` bound (which diesel seals behind its internal
/// `DieselReserveSpecialization`) is unprovable for an abstract connection
/// type, so the generic adapter cannot name `Pool<Conn>` in any position.
/// Instead each backend implements `Checkout` once, concretely, below — the
/// sealed machinery is crossed exactly there and never in generic code.
/// Application code never implements this trait; it arrives with the pool.
#[async_trait]
pub trait Checkout<Conn> {
    /// Checks out one connection; pool failures map to
    /// [`OrmError::Connection`] with a static message (never the URL).
    async fn checkout(&self) -> Result<Box<dyn DerefMut<Target = Conn> + Send + '_>, OrmError>;
}

#[cfg(feature = "postgres")]
#[async_trait]
impl Checkout<AsyncPgConnection> for PgPool {
    async fn checkout(
        &self,
    ) -> Result<Box<dyn DerefMut<Target = AsyncPgConnection> + Send + '_>, OrmError> {
        self.get().await.map_err(map_pool_error).map(|obj| {
            let boxed: Box<dyn DerefMut<Target = AsyncPgConnection> + Send> = Box::new(obj);
            boxed
        })
    }
}

#[cfg(feature = "sqlite")]
#[async_trait]
impl Checkout<SyncConnectionWrapper<SqliteConnection>> for SqlitePool {
    async fn checkout(
        &self,
    ) -> Result<
        Box<dyn DerefMut<Target = SyncConnectionWrapper<SqliteConnection>> + Send + '_>,
        OrmError,
    > {
        self.get().await.map_err(map_pool_error).map(|obj| {
            let boxed: Box<dyn DerefMut<Target = SyncConnectionWrapper<SqliteConnection>> + Send> =
                Box::new(obj);
            boxed
        })
    }
}
