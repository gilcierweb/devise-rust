//! Application-owned pool helpers (D-09).
//!
//! The adapter never builds its own pool — [`SqlxAdapter::new`](crate::SqlxAdapter::new)
//! takes the application's `sqlx::Pool`. The builders below are conveniences
//! for applications that want the same one-line construction the diesel
//! crate offers, with the connection URL never appearing in any error
//! message.
//!
//! ## SQLite `:memory:` (Pitfall 1)
//!
//! Every `:memory:` connection owns a PRIVATE database, so a pooled
//! in-memory rig must force `max_connections(1)` — otherwise migrations
//! applied on one connection are invisible to the next. Use
//! [`sqlite_memory_pool`].

use devise_rust::adapter::OrmError;

use crate::error::map_pool_error;

/// Builds a lazy Postgres pool over the application's URL (rustls TLS per
/// D-13; the adapter queries whatever pool it is given).
///
/// # Errors
///
/// Returns [`OrmError::Connection`] when the URL cannot be parsed. The URL
/// never appears in the message.
///
/// # Examples
///
/// ```rust,no_run
/// # #[cfg(feature = "postgres")]
/// # {
/// use devise_rust_sqlx::pool::pg_pool;
///
/// let pool = pg_pool("postgres://localhost/devise").expect("pool builds");
/// # let _ = pool;
/// # }
/// ```
#[cfg(feature = "postgres")]
pub fn pg_pool(url: &str) -> Result<sqlx::PgPool, OrmError> {
    sqlx::PgPool::connect_lazy(url).map_err(map_pool_error)
}

/// Builds a SQLite pool with an explicit connection ceiling. Pass `1` for
/// `sqlite::memory:` URLs (see [`sqlite_memory_pool`]).
///
/// # Errors
///
/// Returns [`OrmError::Connection`] when the URL cannot be parsed.
///
/// # Examples
///
/// ```rust,no_run
/// # #[cfg(feature = "sqlite")]
/// # {
/// use devise_rust_sqlx::pool::sqlite_pool;
///
/// let pool = sqlite_pool("sqlite::memory:", 1).expect("pool builds");
/// # let _ = pool;
/// # }
/// ```
#[cfg(feature = "sqlite")]
pub fn sqlite_pool(url: &str, max_connections: u32) -> Result<sqlx::SqlitePool, OrmError> {
    sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(max_connections)
        .connect_lazy(url)
        .map_err(map_pool_error)
}

/// Builds the in-memory SQLite pool: `sqlite::memory:` with
/// `max_connections(1)` so every checkout sees the same private database
/// (Pitfall 1 — the diesel rig precedent).
///
/// # Errors
///
/// Returns [`OrmError::Connection`] when the pool cannot be built.
///
/// # Examples
///
/// ```rust,no_run
/// # #[cfg(feature = "sqlite")]
/// # {
/// use devise_rust_sqlx::pool::sqlite_memory_pool;
///
/// let pool = sqlite_memory_pool().expect("pool builds");
/// # let _ = pool;
/// # }
/// ```
#[cfg(feature = "sqlite")]
pub fn sqlite_memory_pool() -> Result<sqlx::SqlitePool, OrmError> {
    sqlite_pool("sqlite::memory:", 1)
}

/// Builds a lazy MySQL pool — **experimental** (D-33: the mysql feature
/// compiles without CI execution; this builder exists for symmetry and is
/// not covered by any execution verification).
///
/// # Errors
///
/// Returns [`OrmError::Connection`] when the URL cannot be parsed. The URL
/// never appears in the message.
#[cfg(feature = "mysql")]
pub fn mysql_pool(url: &str) -> Result<sqlx::MySqlPool, OrmError> {
    sqlx::MySqlPool::connect_lazy(url).map_err(map_pool_error)
}
