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
//!
//! When the `e2e-pg` feature is enabled, a parallel Postgres bootstrap is
//! provided that starts a testcontainers Postgres instance, applies the same
//! emitted pg DDL via `batch_execute`, and builds a deadpool pg pool.

#[cfg(feature = "sqlite")]
mod sqlite_common {
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
    ///
    /// Constructed only by the sqlite contract entry; the pg entry compiles
    /// this module too under feature unions (`--all-features`), where the
    /// struct is legitimately unreferenced.
    #[allow(dead_code)]
    pub struct SqliteRig {
        /// Adapter over the integer-PK `users` table.
        pub users: DieselOrmAdapter<FixtureUser, Sqlite, SqliteConn>,
        /// Adapter over the uuid-PK `uuid_users` table (uuid stored hyphenated).
        pub uuid_users: DieselOrmAdapter<UuidUser, Sqlite, SqliteConn>,
    }

    /// Builds a `max_size(1)` pool and applies the full-module `emit()` DDL for
    /// both fixture tables (`users` integer PK, `uuid_users` uuid PK).
    ///
    /// # Panics
    ///
    /// Panics when the pool cannot be built or the emitted DDL does not apply —
    /// both are rig bugs, never test-input failures.
    #[allow(dead_code)]
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
}

// The two re-export lines below serve DIFFERENT test targets (sqlite entry
// vs e2e-pg entry); under a feature union each target sees the other's
// re-export as unused, so the allow documents the cross-target sharing.
#[cfg(feature = "sqlite")]
#[allow(unused_imports)]
pub use sqlite_common::{SqliteConn, bootstrap_sqlite_memory};

/// Fixed sample timestamp (`2026-01-02 03:04:05`) for deterministic fixtures.
#[must_use]
pub fn sample_time() -> chrono::NaiveDateTime {
    chrono::NaiveDateTime::parse_from_str("2026-01-02 03:04:05", "%Y-%m-%d %H:%M:%S")
        .expect("fixed sample time parses")
}

/// Postgres bootstrap for the `e2e-pg` feature: starts a testcontainers
/// Postgres instance, applies the same full-module emitted pg DDL via
/// `batch_execute`, and builds a deadpool pg pool.
///
/// The container is held in a static async `Mutex<Option<...>>` so all
/// tests in the suite share one container (Q3 resolution: default
/// pool/container config, no recycling tuning) while the guard may be
/// held across the container-start await. The pool is created fresh per
/// bootstrap call but points to the shared container. Items the sqlite
/// entry does not reference carry `allow(dead_code)`: under a feature
/// union each test target compiles this module, and the sqlite target
/// legitimately never reaches for the pg rig.
///
/// # Panics
///
/// Panics when the container cannot start, DDL does not apply, or pool
/// cannot be built — all are rig bugs.
#[cfg(feature = "e2e-pg")]
pub mod pg {
    use diesel::pg::Pg;
    use diesel_async::AsyncPgConnection;
    use diesel_async::SimpleAsyncConnection;
    use diesel_async::pooled_connection::{AsyncDieselConnectionManager, deadpool::Pool};
    use testcontainers::runners::AsyncRunner;
    use testcontainers_modules::postgres;

    use crate::models::{FixtureUser, UuidUser};
    use devise_rust_diesel::{DieselOrmAdapter, pool::PgPool};
    use devise_rust_migrations::{Dialect, EmitOptions, Flow, PkKind};

    /// Pooled async Postgres connection type behind [`DieselOrmAdapter`].
    #[allow(dead_code)]
    pub type PgConn = AsyncPgConnection;

    /// Global container holder — one Postgres instance per test process.
    static CONTAINER: std::sync::LazyLock<
        tokio::sync::Mutex<Option<testcontainers::ContainerAsync<postgres::Postgres>>>,
    > = std::sync::LazyLock::new(|| tokio::sync::Mutex::new(None));

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

            let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(database_url);
            let pool: PgPool = Pool::builder(manager).build().expect("pg pool builds");

            let mut conn = pool.get().await.expect("pg pool checkout works");
            // Enable pgcrypto for gen_random_uuid()
            conn.batch_execute("CREATE EXTENSION IF NOT EXISTS pgcrypto;")
                .await
                .expect("pgcrypto extension");

            let int_ddl = EmitOptions::new("users")
                .with_all_modules()
                .dialect(Dialect::Postgres)
                .pk(PkKind::Integer)
                .flow(Flow::Create);

            let files = devise_rust_migrations::emit(&int_ddl).expect("fixture pg DDL emits");
            conn.batch_execute(&files.up_sql)
                .await
                .expect("emitted pg DDL applies to testcontainers Postgres");

            // The uuid_users fixture keeps the sqlite-compatible TEXT id
            // column: diesel_async LoadQuery trait bounds keep native UUID
            // columns from round-tripping through the TEXT-typed fixture
            // model (see tests/models.rs). The substitution asserts loudly
            // if the emitted id column ever changes shape.
            let uuid_ddl = EmitOptions::new("uuid_users")
                .with_all_modules()
                .dialect(Dialect::Postgres)
                .pk(PkKind::Uuid)
                .flow(Flow::Create);

            let uuid_files =
                devise_rust_migrations::emit(&uuid_ddl).expect("fixture pg uuid DDL emits");
            let text_id_ddl = uuid_files.up_sql.replace(
                "id UUID PRIMARY KEY DEFAULT gen_random_uuid()",
                "id TEXT PRIMARY KEY",
            );
            assert!(
                text_id_ddl != uuid_files.up_sql,
                "pg uuid fixture substitution missed: the emitted id column changed shape"
            );
            conn.batch_execute(&text_id_ddl)
                .await
                .expect("uuid fixture DDL applies to testcontainers Postgres");
            drop(conn);
        }

        let host = container.get_host().await.expect("container host");
        let port = container
            .get_host_port_ipv4(5432)
            .await
            .expect("container port");
        format!("postgres://postgres:postgres@{host}:{port}/postgres")
    }

    /// Tracks whether DDL has been applied to the shared container.
    #[allow(dead_code)]
    static DDL_APPLIED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    /// Live adapters over a testcontainers Postgres database with applied DDL.
    #[allow(dead_code)]
    pub struct PgRig {
        /// Adapter over the integer-PK `users` table.
        pub users: DieselOrmAdapter<FixtureUser, Pg, PgConn>,
        /// Adapter over the uuid-PK `uuid_users` table (id stored
        /// hyphenated as TEXT on the pg fixture).
        pub uuid_users: DieselOrmAdapter<UuidUser, Pg, PgConn>,
    }

    /// Builds a deadpool pg pool pointing at the shared testcontainers
    /// instance. DDL is applied once during first `get_database_url()` call.
    ///
    /// # Panics
    ///
    /// Panics when the pool cannot be built.
    #[allow(dead_code)]
    pub async fn bootstrap_pg() -> PgRig {
        let database_url = get_database_url().await;

        let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(database_url);
        let pool: PgPool = Pool::builder(manager).build().expect("pg pool builds");

        PgRig {
            users: DieselOrmAdapter::new(pool.clone()),
            uuid_users: DieselOrmAdapter::new(pool),
        }
    }
}

#[cfg(feature = "e2e-pg")]
#[allow(unused_imports)]
pub use pg::{PgRig, bootstrap_pg};
