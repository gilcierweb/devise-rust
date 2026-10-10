//! SQLite rig bootstrap for the sea-orm contract suite (D-18/D-26).
//!
//! The fixture schema is not hand-written SQL: it is the DDL that
//! `devise-rust-migrations::emit()` generates — the single column source of
//! truth — applied verbatim through sea-orm's
//! [`SchemaManager`](sea_orm_migration::SchemaManager) over
//! `execute_unprepared` (D-18). If the generator emits non-executable DDL,
//! the rig fails here — loud and early.
//!
//! Each bootstrap owns a fresh `DatabaseConnection` pool capped at
//! `max_connections(1)` (Pitfall 1: one pooled connection per `:memory:`
//! database, so the pool can never observe two different in-memory
//! databases); tests stay isolated under parallel execution.

use sea_orm::{ConnectOptions, ConnectionTrait, Database, DatabaseConnection};
use sea_orm_migration::SchemaManager;

use devise_rust_migrations::{Dialect, EmitOptions, Flow, PkKind, emit};
use devise_rust_sea_orm::SeaOrmAdapter;

use crate::models::users;

/// Live adapters over one freshly-migrated `:memory:` database.
#[allow(dead_code)]
pub struct SqliteRig {
    /// Adapter over the integer-PK `users` table.
    pub users: SeaOrmAdapter<users::Entity>,
    /// Kept alive for the rig's lifetime: dropping the last pooled
    /// connection drops the private `:memory:` database with it.
    db: DatabaseConnection,
}

/// Builds a pool-of-1 connection and applies the full-module `emit()` DDL
/// for the integer-PK `users` table (the `uuid_users` fixture lands with
/// the full-suite task).
///
/// # Panics
///
/// Panics when the connection cannot be built or the emitted DDL does not
/// apply — both are rig bugs, never test-input failures.
#[allow(dead_code)]
pub async fn bootstrap_sqlite_memory() -> SqliteRig {
    // Pitfall 1: one connection per pool, one private :memory: database.
    let mut options = ConnectOptions::new("sqlite::memory:");
    options.max_connections(1);
    let db = Database::connect(options)
        .await
        .expect("in-memory sqlite connection builds");

    let int_ddl = EmitOptions::new("users")
        .with_all_modules()
        .dialect(Dialect::Sqlite)
        .pk(PkKind::Integer)
        .flow(Flow::Create);
    let files = emit(&int_ddl).expect("fixture DDL emits");
    // D-18: plain-SQL DDL applied verbatim through sea-orm's SchemaManager;
    // `execute_unprepared` runs the full multi-statement script.
    SchemaManager::new(&db)
        .get_connection()
        .execute_unprepared(&files.up_sql)
        .await
        .expect("emitted DDL applies to :memory:");

    SqliteRig {
        users: SeaOrmAdapter::new(db.clone()),
        db,
    }
}
