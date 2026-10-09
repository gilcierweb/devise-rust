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

#[cfg(feature = "sqlite")]
mod sqlite_common {
    use devise_rust_migrations::{Dialect, EmitOptions, Flow, PkKind};
    use devise_rust_sqlx::SqlxAdapter;
    use devise_rust_sqlx::pool::sqlite_memory_pool;

    use crate::models::{FixtureUser, UuidUser};

    /// Live adapters over one freshly-migrated `:memory:` database.
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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
}

/// The two re-export lines below serve DIFFERENT test targets (sqlite entry
/// vs e2e-pg-sqlx entry); under a feature union each target sees the other's
/// re-export as unused, so the allow documents the cross-target sharing.
#[cfg(feature = "sqlite")]
#[allow(unused_imports)]
pub use sqlite_common::{SqliteRig, bootstrap_sqlite_memory};

/// Postgres bootstrap for the `e2e-pg-sqlx` feature: starts a testcontainers
/// Postgres instance, applies the same full-module emitted pg DDL via
/// `sqlx::raw_sql`, and builds an sqlx pg pool. The container is shared
/// across all pg tests (one container per test process), DDL applied once.
///
/// The container is held in a static async `Mutex<Option<...>>` so all
/// tests in the suite share one container while the guard may be held
/// across the container-start await. The pool is created fresh per
/// bootstrap call but points to the shared container.
///
/// # Panics
///
/// Panics when the container cannot start, DDL does not apply, or pool
/// cannot be built — all are rig bugs.
#[cfg(feature = "e2e-pg-sqlx")]
pub mod pg {
    use testcontainers::runners::AsyncRunner;
    use testcontainers_modules::postgres;

    use crate::models::{FixtureUser, UuidUser};
    use devise_rust_migrations::{Dialect, EmitOptions, Flow, PkKind};
    use devise_rust_sqlx::SqlxAdapter;
    use devise_rust_sqlx::pool::pg_pool;

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

            let pool = pg_pool(&database_url).expect("pg pool builds");

            let mut conn = pool.acquire().await.expect("pg pool checkout works");
            // Enable pgcrypto for gen_random_uuid()
            sqlx::raw_sql("CREATE EXTENSION IF NOT EXISTS pgcrypto;")
                .execute(&mut *conn)
                .await
                .expect("pgcrypto extension");

            let int_ddl = EmitOptions::new("users")
                .with_all_modules()
                .dialect(Dialect::Postgres)
                .pk(PkKind::Integer)
                .flow(Flow::Create);

            let files = devise_rust_migrations::emit(&int_ddl).expect("fixture pg DDL emits");
            // sqlx 0.8.6 doesn't support native INET binding; use TEXT for IP columns in test rig
            let up_sql = files
                .up_sql
                .replace("current_sign_in_ip INET", "current_sign_in_ip TEXT")
                .replace("last_sign_in_ip INET", "last_sign_in_ip TEXT");
            sqlx::raw_sql(&up_sql)
                .execute(&mut *conn)
                .await
                .expect("emitted pg DDL applies to testcontainers Postgres");

            // Uuid fixture uses native UUID column on pg (D-35)
            let uuid_ddl = EmitOptions::new("uuid_users")
                .with_all_modules()
                .dialect(Dialect::Postgres)
                .pk(PkKind::Uuid)
                .flow(Flow::Create);

            let uuid_files =
                devise_rust_migrations::emit(&uuid_ddl).expect("fixture pg uuid DDL emits");
            let uuid_up_sql = uuid_files
                .up_sql
                .replace("current_sign_in_ip INET", "current_sign_in_ip TEXT")
                .replace("last_sign_in_ip INET", "last_sign_in_ip TEXT");
            sqlx::raw_sql(&uuid_up_sql)
                .execute(&mut *conn)
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

    /// Live adapters over a testcontainers Postgres database with applied DDL.
    #[allow(dead_code)]
    pub struct PgRig {
        /// Adapter over the integer-PK `users` table.
        pub users: SqlxAdapter<FixtureUser, sqlx::Postgres>,
        /// Adapter over the uuid-PK `uuid_users` table (native UUID column — D-35).
        pub uuid_users: SqlxAdapter<UuidUser, sqlx::Postgres>,
    }

    /// Builds an sqlx pg pool pointing at the shared testcontainers
    /// instance. DDL is applied once during first `get_database_url()` call.
    ///
    /// # Panics
    ///
    /// Panics when the pool cannot be built.
    #[allow(dead_code)]
    pub async fn bootstrap_pg() -> PgRig {
        let database_url = get_database_url().await;

        let pool = pg_pool(&database_url).expect("pg pool builds");

        PgRig {
            users: SqlxAdapter::new(pool.clone()),
            uuid_users: SqlxAdapter::new(pool),
        }
    }
}

#[cfg(feature = "e2e-pg-sqlx")]
#[allow(unused_imports)]
pub use pg::{PgRig, bootstrap_pg};
