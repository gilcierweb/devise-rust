//! Diesel-to-core error edge mapper (Pitfall 5).
//!
//! Every diesel failure crossing into [`OrmError`](devise_rust::adapter::OrmError)
//! passes through [`map_diesel_error`] (query path) or [`map_pool_error`]
//! (pool-acquisition path). The mapping discriminates the variants that
//! Devise semantics key on — notably [`OrmError::UniqueViolation`](devise_rust::adapter::OrmError::UniqueViolation),
//! which backs the token-generator uniqueness loop — and degrades everything
//! else to a category-level `Query`/`Connection` message.
//!
//! ## Privacy contract
//!
//! `Display` output carries category and constraint/column metadata only —
//! never a record field value (email, token) nor a connection URL. Diesel's
//! own `Display` renders parameterized binds as placeholders (values are
//! never interpolated into the message), so forwarding it is safe; pool
//! errors use a static message plus the driver error as `#[source]` for
//! diagnostics.

use devise_rust::adapter::OrmError;
use diesel::result::{DatabaseErrorKind, Error as DieselError};

/// Maps a diesel query error into the core [`OrmError`] taxonomy.
///
/// * `DatabaseError(UniqueViolation, info)` → [`OrmError::UniqueViolation`](devise_rust::adapter::OrmError::UniqueViolation)
///   carrying the constraint/index name when the driver reports one.
/// * `Error::NotFound` (e.g. from `get_result`) → [`OrmError::NotFound`].
/// * Everything else → [`OrmError::Query`] with diesel's `Display` text.
#[must_use]
pub fn map_diesel_error(error: DieselError) -> OrmError {
    match error {
        DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, info) => {
            OrmError::UniqueViolation {
                constraint: info.constraint_name().map(str::to_owned),
            }
        }
        DieselError::NotFound => OrmError::NotFound,
        other => OrmError::Query {
            message: other.to_string(),
            source: None,
        },
    }
}

/// Maps a connection-pool failure into [`OrmError::Connection`].
///
/// The `Display` message is a static category string — the pool/database URL
/// (which may carry credentials) is never rendered. The driver error is kept
/// behind `#[source]` for diagnostics.
pub fn map_pool_error<E>(error: E) -> OrmError
where
    E: std::error::Error + Send + Sync + 'static,
{
    OrmError::Connection {
        message: "database connection pool failure".to_owned(),
        source: Some(Box::new(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use diesel::result::DatabaseErrorInformation;

    /// Minimal [`DatabaseErrorInformation`] for constructing discrimination
    /// probes without a live database.
    #[derive(Debug)]
    struct FakeInfo {
        constraint: Option<String>,
    }

    impl std::fmt::Display for FakeInfo {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "fake database error")
        }
    }

    impl DatabaseErrorInformation for FakeInfo {
        #[allow(clippy::unnecessary_literal_bound)]
        fn message(&self) -> &str {
            "fake database error"
        }

        fn details(&self) -> Option<&str> {
            None
        }

        fn hint(&self) -> Option<&str> {
            None
        }

        fn table_name(&self) -> Option<&str> {
            None
        }

        fn column_name(&self) -> Option<&str> {
            None
        }

        fn constraint_name(&self) -> Option<&str> {
            self.constraint.as_deref()
        }

        fn statement_position(&self) -> Option<i32> {
            None
        }
    }

    #[test]
    fn unique_violation_carries_constraint_name() {
        let info: Box<dyn DatabaseErrorInformation + Send + Sync> = Box::new(FakeInfo {
            constraint: Some("index_users_on_email".to_owned()),
        });
        let mapped = map_diesel_error(DieselError::DatabaseError(
            DatabaseErrorKind::UniqueViolation,
            info,
        ));
        assert!(
            matches!(
                mapped,
                OrmError::UniqueViolation {
                    constraint: Some(_)
                }
            ),
            "expected UniqueViolation, got {mapped:?}"
        );
        let rendered = mapped.to_string();
        assert!(
            rendered.contains("index_users_on_email"),
            "Display must name the constraint: {rendered}"
        );
    }

    #[test]
    fn unique_violation_without_constraint_still_discriminates() {
        let info: Box<dyn DatabaseErrorInformation + Send + Sync> =
            Box::new(FakeInfo { constraint: None });
        let mapped = map_diesel_error(DieselError::DatabaseError(
            DatabaseErrorKind::UniqueViolation,
            info,
        ));
        assert!(
            matches!(mapped, OrmError::UniqueViolation { constraint: None }),
            "expected bare UniqueViolation, got {mapped:?}"
        );
    }

    #[test]
    fn not_found_maps_to_not_found() {
        assert!(matches!(
            map_diesel_error(DieselError::NotFound),
            OrmError::NotFound
        ));
    }

    #[test]
    fn other_errors_become_query() {
        let mapped = map_diesel_error(DieselError::RollbackTransaction);
        assert!(
            matches!(mapped, OrmError::Query { .. }),
            "expected Query, got {mapped:?}"
        );
        assert!(
            mapped.to_string().contains("Query"),
            "Display must carry the category: {mapped}"
        );
    }

    #[test]
    fn pool_error_display_hides_credentials() {
        let canary_url = "postgres://devise:canary-secret-9z@example.com/db";
        let mapped = map_pool_error(std::io::Error::other(format!(
            "could not connect to {canary_url}"
        )));
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
    }
}
