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

use crate::models::{users, uuid_users};

/// Live adapters over one freshly-migrated `:memory:` database.
#[allow(dead_code)]
pub struct SqliteRig {
    /// Adapter over the integer-PK `users` table.
    pub users: SeaOrmAdapter<users::Entity>,
    /// Adapter over the uuid-PK `uuid_users` table (hyphenated-`TEXT` id,
    /// D-35).
    pub uuid_users: SeaOrmAdapter<uuid_users::Entity>,
    /// Kept alive for the rig's lifetime: dropping the last pooled
    /// connection drops the private `:memory:` database with it.
    db: DatabaseConnection,
}

/// Builds a pool-of-1 connection and applies the full-module `emit()` DDL
/// for both fixture tables (`users` integer PK, `uuid_users` uuid PK).
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
    let uuid_ddl = EmitOptions::new("uuid_users")
        .with_all_modules()
        .dialect(Dialect::Sqlite)
        .pk(PkKind::Uuid)
        .flow(Flow::Create);
    let schema = SchemaManager::new(&db);
    for opts in [int_ddl, uuid_ddl] {
        let files = emit(&opts).expect("fixture DDL emits");
        // D-18: plain-SQL DDL applied verbatim through sea-orm's
        // SchemaManager; `execute_unprepared` runs the full
        // multi-statement script.
        schema
            .get_connection()
            .execute_unprepared(&files.up_sql)
            .await
            .expect("emitted DDL applies to :memory:");
    }

    SqliteRig {
        users: SeaOrmAdapter::new(db.clone()),
        uuid_users: SeaOrmAdapter::new(db.clone()),
        db,
    }
}

/// Postgres bootstrap for the `e2e-pg-sea` feature: starts a testcontainers
/// Postgres instance, applies the same full-module emitted pg DDL via
/// `SchemaManager::execute_unprepared`, and builds a sea-orm pg connection.
/// The container is shared across all pg tests (one container per test process),
/// DDL applied once.
///
/// The container is held in a static async `Mutex<Option<...>>` so all
/// tests in the suite share one container while the guard may be held
/// across the container-start await. The connection is created fresh per
/// bootstrap call but points to the shared container.
///
/// # Panics
///
/// Panics when the container cannot start, DDL does not apply, or connection
/// cannot be built — all are rig bugs.
#[cfg(feature = "e2e-pg-sea")]
pub mod pg {
    use testcontainers::runners::AsyncRunner;
    use testcontainers_modules::postgres;

    use crate::models::{users, uuid_users};
    use devise_rust_migrations::{Dialect, EmitOptions, Flow, PkKind, emit};
    use devise_rust_sea_orm::SeaOrmAdapter;
    use sea_orm::{ConnectOptions, ConnectionTrait, Database, DatabaseConnection};
    use sea_orm_migration::SchemaManager;

    /// Global container holder — one Postgres instance per test process.
    static CONTAINER: std::sync::LazyLock<
        tokio::sync::Mutex<Option<testcontainers::ContainerAsync<postgres::Postgres>>>,
    > = std::sync::LazyLock::new(|| tokio::sync::Mutex::new(None));

    /// Tracks whether DDL has been applied to the shared container.
    static DDL_APPLIED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    /// Gets the database URL, starting the container and applying DDL on first call.
    async fn get_database_url() -> String {
        let mut guard = CONTAINER.lock().await;
        let container = if let Some(c) = guard.as_mut() {
            c
        } else {
            let new_container = postgres::Postgres::default()
                .start()
                .await
                .expect("testcontainers Postgres starts");
            *guard = Some(new_container);
            guard.as_mut().expect("container just stored")
        };

        // Apply DDL and pgcrypto extension on first initialization only
        if !DDL_APPLIED.swap(true, std::sync::atomic::Ordering::AcqRel) {
            let host = container.get_host().await.expect("container host");
            let port = container
                .get_host_port_ipv4(5432)
                .await
                .expect("container port");
            let database_url = format!("postgres://postgres:postgres@{host}:{port}/postgres");

            let mut options = ConnectOptions::new(&database_url);
            options.max_connections(1);
            let db = Database::connect(options)
                .await
                .expect("pg connection builds");

            // Enable pgcrypto for gen_random_uuid()
            db.execute_unprepared("CREATE EXTENSION IF NOT EXISTS pgcrypto;")
                .await
                .expect("pgcrypto extension");

            let schema = SchemaManager::new(&db);

            let int_ddl = EmitOptions::new("users")
                .with_all_modules()
                .dialect(Dialect::Postgres)
                .pk(PkKind::Integer)
                .flow(Flow::Create);

            let files = emit(&int_ddl).expect("fixture pg DDL emits");
            // sea-orm 1.1 / sqlx 0.8.6 doesn't support native INET binding; use TEXT for IP columns in test rig
            let up_sql = files
                .up_sql
                .replace("current_sign_in_ip INET", "current_sign_in_ip TEXT")
                .replace("last_sign_in_ip INET", "last_sign_in_ip TEXT");
            schema
                .get_connection()
                .execute_unprepared(&up_sql)
                .await
                .expect("emitted pg DDL applies to testcontainers Postgres");

            // Uuid fixture uses native UUID column on pg (D-35)
            let uuid_ddl = EmitOptions::new("uuid_users")
                .with_all_modules()
                .dialect(Dialect::Postgres)
                .pk(PkKind::Uuid)
                .flow(Flow::Create);

            let uuid_files =
                emit(&uuid_ddl).expect("fixture pg uuid DDL emits");
            let uuid_up_sql = uuid_files
                .up_sql
                .replace("current_sign_in_ip INET", "current_sign_in_ip TEXT")
                .replace("last_sign_in_ip INET", "last_sign_in_ip TEXT");
            schema
                .get_connection()
                .execute_unprepared(&uuid_up_sql)
                .await
                .expect("uuid fixture DDL applies to testcontainers Postgres");
        }

        let host = container.get_host().await.expect("container host");
        let port = container
            .get_host_port_ipv4(5432)
            .await
            .expect("container port");
        format!("postgres://postgres:postgres@{host}:{port}/postgres")
    }

    /// Live adapters over a testcontainers Postgres database with applied DDL.
    #[allow(dead_code)]
    pub struct PgRig {
        /// Adapter over the integer-PK `users` table.
        pub users: SeaOrmAdapter<users::Entity>,
        /// Adapter over the uuid-PK `uuid_users` table (native UUID column — D-35).
        pub uuid_users: SeaOrmAdapter<uuid_users::Entity>,
    }

    /// Builds a sea-orm pg connection pointing at the shared testcontainers
    /// instance. DDL is applied once during first `get_database_url()` call.
    ///
    /// # Panics
    ///
    /// Panics when the connection cannot be built.
    #[allow(dead_code)]
    pub async fn bootstrap_pg() -> PgRig {
        let database_url = get_database_url().await;

        let mut options = ConnectOptions::new(&database_url);
        options.max_connections(1);
        let db = Database::connect(options)
            .await
            .expect("pg connection builds");

        PgRig {
            users: SeaOrmAdapter::new(db.clone()),
            uuid_users: SeaOrmAdapter::new(db),
        }
    }
}

#[cfg(feature = "e2e-pg-sea")]
#[allow(unused_imports)]
pub use pg::{PgRig, bootstrap_pg};
