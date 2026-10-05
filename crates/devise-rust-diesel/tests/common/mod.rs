//! SQLite rig bootstrap shared by the contract suite.
//!
//! The fixture schema is not hand-written SQL: it is the DDL that
//! `devise-rust-migrations::emit()` generates (the consumer end of 02-02's
//! key link), applied through `SimpleAsyncConnection::batch_execute` on a
//! pooled `:memory:` connection. If the generator emits non-executable DDL,
//! the rig fails here — loud and early.
//!
//! Each bootstrap owns a fresh pool, hence a fresh private `:memory:`
//! database: tests stay isolated under parallel execution. The struct is the
//! suite-sharing seam 02-04's Postgres leg reuses: same shape, different
//! backend.

use devise_rust_diesel::pool::sqlite_memory_pool;
use devise_rust_diesel::{DieselOrmAdapter, pool::SqlitePool};
use devise_rust_migrations::{Dialect, EmitOptions, Flow, PkKind};
use diesel::SqliteConnection;
use diesel::sqlite::Sqlite;
use diesel_async::SimpleAsyncConnection;
use diesel_async::sync_connection_wrapper::SyncConnectionWrapper;

use crate::models::{FixtureUser, UuidUser};

/// Pooled SQLite connection type behind [`DieselOrmAdapter`] here.
pub type SqliteConn = SyncConnectionWrapper<SqliteConnection>;

/// Live adapters over one freshly-migrated `:memory:` database.
pub struct SqliteRig {
    /// Adapter over the integer-PK `users` table.
    pub users: DieselOrmAdapter<FixtureUser, Sqlite, SqliteConn>,
    /// Adapter over the uuid-PK `uuid_users` table (uuid stored hyphenated).
    #[expect(dead_code)]
    pub uuid_users: DieselOrmAdapter<UuidUser, Sqlite, SqliteConn>,
}

/// Builds a `max_size(1)` pool and applies the full-module `emit()` DDL for
/// both fixture tables (`users` integer PK, `uuid_users` uuid PK).
///
/// # Panics
///
/// Panics when the pool cannot be built or the emitted DDL does not apply —
/// both are rig bugs, never test-input failures.
pub async fn bootstrap_sqlite_memory() -> SqliteRig {
    let pool: SqlitePool = sqlite_memory_pool().expect("in-memory pool builds");

    let int_ddl = EmitOptions::new("users")
        .with_all_modules()
        .dialect(Dialect::Sqlite)
        .pk(PkKind::Integer)
        .flow(Flow::Create);
    let uuid_ddl = EmitOptions::new("uuid_users")
        .with_all_modules()
        .dialect(Dialect::Sqlite)
        .pk(PkKind::Uuid)
        .flow(Flow::Create);

    let mut conn = pool.get().await.expect("pool checkout works");
    for opts in [int_ddl, uuid_ddl] {
        let files = devise_rust_migrations::emit(&opts).expect("fixture DDL emits");
        conn.batch_execute(&files.up_sql)
            .await
            .expect("emitted DDL applies to :memory:");
    }
    drop(conn);

    SqliteRig {
        users: DieselOrmAdapter::new(pool.clone()),
        uuid_users: DieselOrmAdapter::new(pool),
    }
}

/// Fixed sample timestamp (`2026-01-02 03:04:05`) for deterministic fixtures.
#[must_use]
pub fn sample_time() -> chrono::NaiveDateTime {
    chrono::NaiveDateTime::parse_from_str("2026-01-02 03:04:05", "%Y-%m-%d %H:%M:%S")
        .expect("fixed sample time parses")
}

/// A second fixed timestamp, distinct from [`sample_time`].
#[must_use]
pub fn later_time() -> chrono::NaiveDateTime {
    chrono::NaiveDateTime::parse_from_str("2026-06-07 08:09:10", "%Y-%m-%d %H:%M:%S")
        .expect("fixed later time parses")
}
