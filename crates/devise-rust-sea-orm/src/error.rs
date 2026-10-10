//! Sea-orm-to-core error edge mapper (Pitfalls 4 and 7; T-07-02).
//!
//! Every [`DbErr`] crossing into [`OrmError`] passes through
//! [`map_sea_orm_error`]. The mapping discriminates the variants Devise
//! semantics key on — notably [`OrmError::UniqueViolation`], which backs the
//! token-generator uniqueness loop — and handles the two miss shapes
//! (Pitfall 7): `one()` returning `Ok(None)` stays a miss passthrough (never
//! reaches here), while `RecordNotFound`/`RecordNotUpdated` map to
//! [`OrmError::NotFound`] (T-07-05).
//!
//! ## Privacy contract
//!
//! `Display` output carries category and constraint/column metadata only —
//! never a record field value (email, token) nor a connection URL (D-12).
//! Connection failures map to a static message with the driver error behind
//! `#[source]` for diagnostics; query failures forward sea-orm's `Display`,
//! which renders parameterized binds as placeholders (values are never
//! interpolated), mirroring the diesel edge's guarantee.

use devise_rust::adapter::OrmError;
use sea_orm::{DbErr, SqlErr};

/// Maps a sea-orm [`DbErr`] into the core [`OrmError`] taxonomy.
///
/// * `sql_err() == Some(SqlErr::UniqueConstraintViolation(_))` FIRST
///   (Pitfall 4 — the portable classification across pg/sqlite/mysql):
///   [`OrmError::UniqueViolation`]. Sea-orm 1.1 carries the driver message
///   rather than a parsed constraint name, so `constraint` stays `None`.
/// * `DbErr::RecordNotFound` / `DbErr::RecordNotUpdated` →
///   [`OrmError::NotFound`].
/// * `ConnectionAcquire` / `Conn` → [`OrmError::Connection`] with a static
///   message; the driver error (which may embed a URL) stays behind
///   `#[source]`.
/// * Everything else → [`OrmError::Query`] with sea-orm's `Display` text.
#[must_use]
pub fn map_sea_orm_error(error: DbErr) -> OrmError {
    // Unique-violation discrimination FIRST (Pitfall 4): `sql_err()`
    // reclassifies the driver's raw error portably across backends.
    if matches!(error.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) {
        return OrmError::UniqueViolation { constraint: None };
    }
    match error {
        DbErr::RecordNotFound(_) | DbErr::RecordNotUpdated => OrmError::NotFound,
        e @ (DbErr::ConnectionAcquire(_) | DbErr::Conn(_)) => OrmError::Connection {
            message: "database connection failure".to_owned(),
            source: Some(Box::new(e)),
        },
        other => OrmError::Query {
            message: other.to_string(),
            source: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::RuntimeErr;

    /// `RecordNotFound` (the `one()`-as-error shape sea-orm uses internally)
    /// and `RecordNotUpdated` both surface as a behavioral miss.
    #[test]
    fn record_misses_map_to_not_found() {
        let nf = map_sea_orm_error(DbErr::RecordNotFound("users".to_owned()));
        assert!(matches!(nf, OrmError::NotFound), "got {nf:?}");
        let nu = map_sea_orm_error(DbErr::RecordNotUpdated);
        assert!(matches!(nu, OrmError::NotFound), "got {nu:?}");
    }

    /// Connection failures carry a static message: the driver error — which
    /// can embed the connection URL — stays behind the source chain, never
    /// in `Display` (D-12, T-07-02, canary pattern from diesel error.rs).
    #[test]
    fn connection_error_display_hides_credentials() {
        let canary_url = "postgres://devise:canary-secret-9z@example.com/db";
        let mapped = map_sea_orm_error(DbErr::Conn(RuntimeErr::Internal(format!(
            "could not connect to {canary_url}"
        ))));
        assert!(
            matches!(mapped, OrmError::Connection { .. }),
            "expected Connection, got {mapped:?}"
        );
        let rendered = mapped.to_string();
        assert!(
            !rendered.contains("canary-secret-9z"),
            "Display must not leak credentials: {rendered}"
        );
        assert!(
            !rendered.contains(canary_url),
            "Display must not leak the URL: {rendered}"
        );
        assert!(
            std::error::Error::source(&mapped).is_some(),
            "the driver error stays behind source for diagnostics"
        );
    }

    /// The fallback arm degrades to `Query` carrying the category in
    /// `Display`.
    #[test]
    fn other_errors_become_query() {
        let mapped = map_sea_orm_error(DbErr::Custom("boom".to_owned()));
        assert!(
            matches!(mapped, OrmError::Query { .. }),
            "expected Query, got {mapped:?}"
        );
        assert!(
            mapped.to_string().contains("Query failed"),
            "Display must carry the category: {mapped}"
        );
    }

    /// `UniqueViolation` stays `Display`-value-free (`constraint: None` —
    /// sea-orm 1.1 does not expose a parsed constraint name); the duplicate-
    /// create live discrimination is pinned by the sqlite leg-local test.
    #[test]
    fn unique_violation_display_is_value_free() {
        let bare = OrmError::UniqueViolation { constraint: None };
        let rendered = bare.to_string();
        assert!(rendered.contains("Unique constraint violation"));
        assert!(!rendered.contains('@'), "never a record value: {rendered}");
    }
}
