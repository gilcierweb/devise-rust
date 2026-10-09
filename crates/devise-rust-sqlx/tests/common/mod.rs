//! SQLite rig bootstrap shared by the contract suite (D-08/D-26).
//!
//! The fixture schema is not hand-written SQL: it is the DDL that
//! `devise-rust-migrations::emit()` generates — the single column source of
//! truth — applied verbatim through `sqlx::raw_sql` on a pooled
//! `:memory:` connection. If the generator emits non-executable DDL, the
//! rig fails here — loud and early.
//!
//! Each bootstrap owns a fresh pool, hence a fresh private `:memory:`
//! database (Pitfall 1: `max_connections(1)`, one pool = one database):
//! tests stay isolated under parallel execution.

use devise_rust_migrations::{Dialect, EmitOptions, Flow, PkKind};
use devise_rust_sqlx::SqlxAdapter;
use devise_rust_sqlx::pool::sqlite_memory_pool;

use crate::models::{FixtureUser, UuidUser};

/// Live adapters over one freshly-migrated `:memory:` database.
pub struct SqliteRig {
    /// Adapter over the integer-PK `users` table.
    pub users: SqlxAdapter<FixtureUser, sqlx::Sqlite>,
    /// Adapter over the uuid-PK `uuid_users` table (uuid stored hyphenated
    /// as TEXT — D-35).
    pub uuid_users: SqlxAdapter<UuidUser, sqlx::Sqlite>,
}

/// Builds a `max_connections(1)` pool and applies the full-module `emit()`
/// DDL for both fixture tables (`users` integer PK, `uuid_users` uuid PK).
///
/// # Panics
///
/// Panics when the pool cannot be built or the emitted DDL does not apply —
/// both are rig bugs, never test-input failures.
pub async fn bootstrap_sqlite_memory() -> SqliteRig {
    let pool = sqlite_memory_pool().expect("in-memory pool builds");

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

    let mut conn = pool.acquire().await.expect("pool checkout works");
    for opts in [int_ddl, uuid_ddl] {
        let files = devise_rust_migrations::emit(&opts).expect("fixture DDL emits");
        sqlx::raw_sql(&files.up_sql)
            .execute(&mut *conn)
            .await
            .expect("emitted DDL applies to :memory:");
    }
    drop(conn);

    SqliteRig {
        users: SqlxAdapter::new(pool.clone()),
        uuid_users: SqlxAdapter::new(pool),
    }
}
