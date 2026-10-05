//! `devise-rust-diesel` — Diesel ORM backend for devise-rust.
//!
//! This crate is the first concrete [`OrmAdapter`](devise_rust::adapter::OrmAdapter)
//! backend (ORM-04): a single generic [`DieselOrmAdapter`] over diesel 2.2.12
//! + diesel-async 0.6.1 with deadpool pooling, bound to models through the
//!
//! explicit [`DieselModel`] glue trait.
//!
//! ## Features
//!
//! * `postgres` — async backend over `AsyncPgConnection` (compiled here;
//!   execution against a live database lands in 02-04's testcontainers leg).
//! * `sqlite` — async backend over `SyncConnectionWrapper<SqliteConnection>`.
//!   Enables diesel's `returning_clauses_for_sqlite_3_35` feature, which
//!   `create`/`update` require for `RETURNING` (SQLite ≥ 3.35; system libs
//!   here and in CI are ≥ 3.45).
//!
//! With neither feature the crate exposes only the backend-agnostic pieces
//! ([`DieselModel`], [`changeset`], [`error`]); the pooled adapter needs a
//! backend to exist.
//!
//! ## Modules
//!
//! * [`glue`](crate::glue) — [`DieselModel`] (D-01/D-02), implemented by hand
//!   per model; never takes a connection.
//! * [`adapter`](crate::adapter) — [`DieselOrmAdapter`] (D-06) implementing
//!   the amended `OrmAdapter` surface.
//! * [`changeset`] — `ChangeSet` → `AsChangeset` tristate bridge (D-04/D-05).
//! * [`error`] — diesel error → `OrmError` mapper (Pitfall 5).
//! * [`pool`] — deadpool builders, including the `:memory:` helper (Pitfall 3).
//!
//! [`DieselOrmAdapter`]: crate::adapter::DieselOrmAdapter
//! [`DieselModel`]: crate::glue::DieselModel

pub mod changeset;
pub mod error;
pub mod glue;

#[cfg(any(feature = "postgres", feature = "sqlite", feature = "mysql"))]
pub mod adapter;
#[cfg(any(feature = "postgres", feature = "sqlite", feature = "mysql"))]
pub mod pool;

#[cfg(any(feature = "postgres", feature = "sqlite", feature = "mysql"))]
pub use adapter::DieselOrmAdapter;
pub use glue::{BoxPred, DieselModel, DieselPredicates};
