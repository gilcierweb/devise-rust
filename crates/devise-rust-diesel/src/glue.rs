//! Explicit per-model binding trait (D-01/D-02).
//!
//! Diesel's compile-time schema coupling (the `table!` types, `Insertable`,
//! `AsChangeset`) cannot live in the DB-agnostic core crate (D-18b), so each
//! model implements [`DieselModel`] by hand: it names its table type, its
//! `Insertable` insert shape (D-03) and its `AsChangeset` changeset struct
//! (D-04/D-05), and exposes the primary-key and curated-finder predicates as
//! boxed diesel expressions.
//!
//! The trait follows the diesel Composing-Applications rule: glue returns
//! expressions and queries, and never takes a connection — execution happens
//! only at [`DieselOrmAdapter`](crate::adapter::DieselOrmAdapter) op
//! boundaries.
//!
//! ## Finder columns (D-02)
//!
//! [`finder_predicate`](DieselModel::finder_predicate) covers ONLY the columns
//! Devise actually queries: authentication keys (`email` by default),
//! `reset_password_token`, `confirmation_token`, `unlock_token`, and
//! `unconfirmed_email`. Any other column name — and any `Null`/non-string
//! value against these text columns — yields `None`, which the adapter turns
//! into [`OrmError::Query`](devise_rust::adapter::OrmError::Query) naming the
//! column and never the value, *before any SQL text exists*.
//!
//! ## Examples
//!
//! ```rust,ignore
//! use devise_rust::adapter::{DeviseKey, OrmError, Value};
//! use devise_rust_diesel::DieselModel;
//! use diesel::backend::Backend;
//! use diesel::expression::BoxableExpression;
//! use diesel::sql_types::Bool;
//! use std::collections::HashMap;
//!
//! # struct User;
//! # struct NewUser;
//! # struct UserChangeset;
//! # mod users { diesel::table! { users (id) { id -> diesel::sql_types::BigInt, email -> diesel::sql_types::Text, } } }
//! impl DieselModel for User {
//!     type Table = users::table;
//!     type New = NewUser;
//!     type Changeset = UserChangeset;
//!
//!     fn table() -> Self::Table {
//!         users::table
//!     }
//!
//!     fn pk_predicate<DB>(key: &DeviseKey)
//!         -> Result<Box<dyn BoxableExpression<Self::Table, DB, SqlType = Bool>>, OrmError>
//!     where DB: Backend {
//!         match key {
//!             DeviseKey::Integer(id) => Ok(Box::new(users::id.eq(*id))),
//!             DeviseKey::Uuid(_) => Err(OrmError::InvalidKey("integer primary key expected".to_owned())),
//!         }
//!     }
//!
//!     fn finder_predicate<DB>(column: &str, value: &Value)
//!         -> Option<Box<dyn BoxableExpression<Self::Table, DB, SqlType = Bool>>>
//!     where DB: Backend {
//!         let Value::String(s) = value else { return None };
//!         match column {
//!             "email" => Some(Box::new(users::email.eq(s.clone()))),
//!             _ => None,
//!         }
//!     }
//!
//!     fn changeset_from_map(fields: &HashMap<String, Value>) -> Result<Self::Changeset, OrmError> {
//!         // Hand-rolled per-field fill via `crate::changeset` extractors.
//!         # Err::<UserChangeset, _>(OrmError::NotFound)
//!     }
//! }
//! ```

use devise_rust::adapter::{DeviseKey, OrmError, Value};
use diesel::expression::BoxableExpression;
use diesel::sql_types::{Bool, Nullable};
use std::collections::HashMap;

/// Boxed `column = value` predicate over a model's table (D-02 shape).
///
/// `SqlType` is `Nullable<Bool>`: `eq` on a nullable column already yields
/// `Nullable<Bool>`, and non-nullable comparisons are widened with
/// `.nullable()` (same SQL, wider type) so every arm boxes uniformly.
/// `filter()` accepts both via `BoolOrNullableBool`, and no stored value the
/// adapter binds is ever `NULL`, so runtime semantics match plain `=`.
///
/// Returned by [`DieselPredicates::finder_predicate`]: one curated `eq` per
/// call. Multi-condition finders intersect per-condition result sets instead
/// of combining predicates in SQL — diesel seals the only public conjunction
/// constructors, so there is no projectible way to `AND` two boxes.
pub type BoxPred<Tab, DB> = Box<dyn BoxableExpression<Tab, DB, SqlType = Nullable<Bool>> + 'static>;
/// Manual per-model binding between a Devise model and its diesel table.
///
/// Implement this by hand for every model (no derive macro in this phase; a
/// future `devise-rust-derive` proc-macro may sugar the same trait). Validate
/// multi-backend compatibility with
/// `#[diesel(check_for_backend(diesel::pg::Pg, diesel::sqlite::Sqlite))]` on
/// the `Queryable`/`Insertable`/`AsChangeset` derives.
pub trait DieselModel: Send + Sync + Sized + 'static {
    /// The `table!`-generated table type this model reads and writes.
    type Table: diesel::Table + Send + Sync + 'static;
    /// The `Insertable` insert shape consumed by `create` (D-03), e.g.
    /// `NewUser` without id/timestamps owned by the database.
    type New: Send + Sync + 'static;
    /// The `AsChangeset` struct carrying the tristate write legs (D-05):
    /// NULL-capable columns as `Option<Option<T>>`, the rest as `Option<T>`.
    type Changeset: Send + Sync + 'static;

    /// The table value for query roots (`users::table`).
    fn table() -> Self::Table;

    /// Extracts the record's primary key as a [`DeviseKey`].
    ///
    /// Multi-condition finders load one result set per condition and
    /// intersect client-side (predicates cannot be `AND`-combined through
    /// public diesel API), keyed by this method in first-query order.
    fn key_of(model: &Self) -> DeviseKey;

    /// Fills the model's `AsChangeset` struct from a named field map —
    /// either the [`ChangeSet`](devise_rust::adapter::ChangeSet) diff (for
    /// `update`) or the full named map (for `update_columns`).
    ///
    /// # Errors
    ///
    /// Returns [`OrmError`] when a value does not fit its column (null into
    /// NOT NULL, wrong type, unknown column). See [`crate::changeset`].
    fn changeset_from_map(fields: &HashMap<String, Value>) -> Result<Self::Changeset, OrmError>;
}

/// Backend-bound predicate constructors for a [`DieselModel`].
///
/// Diesel seals parenthesized expressions (`Grouped`) and per-backend value
/// bindings behind internal traits, so `eq` predicates can only be built
/// against a *concrete* backend. Each model therefore implements this trait
/// once per backend it supports (`Sqlite` here; `Pg` joins in 02-04) with
/// identical bodies — the match arms name only the model's own columns plus
/// the backend marker. A future `devise-rust-derive` proc-macro may stamp
/// these impls from one definition; hand-written impls stay valid regardless.
pub trait DieselPredicates<DB>: DieselModel {
    /// Primary-key predicate, owning per-dialect conversion (D-18c): on
    /// SQLite a `Uuid` key becomes its hyphenated `TEXT` spelling because
    /// diesel 2.2 has no SQLite `Uuid` impls.
    ///
    /// # Errors
    ///
    /// Returns [`OrmError::InvalidKey`] when the key shape does not fit this
    /// model's primary key (e.g. a `Uuid` key against an integer table).
    fn pk_predicate(key: &DeviseKey) -> Result<BoxPred<Self::Table, DB>, OrmError>;

    /// Curated finder predicate (D-02): `Some` boxed `eq` expression for the
    /// five queryable columns, `None` for anything else — including
    /// `Null`/non-string values against these text columns. The adapter
    /// rejects `None` as [`OrmError::Query`](devise_rust::adapter::OrmError::Query)
    /// naming the column, before any SQL text exists.
    fn finder_predicate(column: &str, value: &Value) -> Option<BoxPred<Self::Table, DB>>;
}
