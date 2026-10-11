//! sqlx-to-core error edge mapper (Pitfall 4).
//!
//! Every sqlx failure crossing into
//! [`OrmError`] passes through
//! [`map_sqlx_error`] (query path) or [`map_pool_error`] (pool-acquisition
//! path). The mapping discriminates the variants Devise semantics key on —
//! notably [`OrmError::UniqueViolation`],
//! which backs the token-generator uniqueness retry loop — and degrades
//! everything else to a category-level `Query`/`Connection` message.
//!
//! ## Privacy contract
//!
//! `Display` output carries category and constraint/column metadata only —
//! never a record field value (email, token) nor a connection URL. sqlx's
//! `Display` renders parameterized binds as placeholders (values never enter
//! the statement text), and driver messages name constraints and columns,
//! not the conflicting values — so forwarding the driver's `Display` is
//! safe. Pool errors use a static message plus the driver error as
//! `#[source]` for diagnostics.
//!
//! ## Discrimination order (Pitfall 4)
//!
//! The portable [`DatabaseError::is_unique_violation`] check comes first;
//! the SQLSTATE/extended-code table (`23505` postgres, `1555`/`2067` sqlite)
//! is the fallback for drivers that misreport the kind; MySQL reports
//! driver error numbers instead of SQLSTATE, so its arm (behind the
//! experimental `mysql` feature) downcasts to `MySqlDatabaseError` and
//! matches the duplicate-key number family.
//!

use devise_rust::adapter::OrmError;
use sqlx::error::DatabaseError;

/// SQLSTATE / extended-result codes that mean a uniqueness violation on at
/// least one supported driver (pg `23505`; sqlite `1555`
/// `SQLITE_CONSTRAINT` and `2067` `SQLITE_CONSTRAINT_UNIQUE`).
const UNIQUE_CODES: &[&str] = &["23505", "1555", "2067"];

/// MySQL driver error numbers for duplicate-key failures (the mysql arm
/// compiles behind its feature; D-33 experimental).
#[cfg(feature = "mysql")]
const MYSQL_UNIQUE_NUMBERS: &[u16] = &[1022, 1062, 1169, 1586];

/// Maps a sqlx query error into the core [`OrmError`] taxonomy.
///
/// * `Error::Database(db)` with `db.is_unique_violation()` — or a
///   unique-violation code/number — →
///   [`OrmError::UniqueViolation`] carrying the constraint/index name when
///   the driver reports one (never the conflicting value).
/// * `Error::RowNotFound` → [`OrmError::NotFound`].
/// * Everything else → [`OrmError::Query`] with sqlx's `Display` text.
#[must_use]
pub fn map_sqlx_error(error: sqlx::Error) -> OrmError {
    if let sqlx::Error::Database(db) = &error {
        if is_unique(db.as_ref()) {
            return OrmError::UniqueViolation {
                constraint: db.constraint().map(str::to_owned),
            };
        }
    }
    match error {
        sqlx::Error::RowNotFound => OrmError::NotFound,
        other => OrmError::Query {
            message: other.to_string(),
            source: None,
        },
    }
}

/// True when the database error reports a uniqueness violation through any
/// of the three discrimination routes (kind flag first, code table second,
/// MySQL numbers third).
fn is_unique(db: &(dyn DatabaseError + 'static)) -> bool {
    db.is_unique_violation()
        || db
            .code()
            .is_some_and(|code| UNIQUE_CODES.contains(&code.as_ref()))
        || mysql_unique(db)
}

/// MySQL downcast arm: the driver reports numbers, not SQLSTATE (the
/// generic `code()` fallback cannot see them).
#[cfg(feature = "mysql")]
fn mysql_unique(db: &(dyn DatabaseError + 'static)) -> bool {
    db.try_downcast_ref::<sqlx::mysql::MySqlDatabaseError>()
        .is_some_and(|err| MYSQL_UNIQUE_NUMBERS.contains(&err.number()))
}

#[cfg(not(feature = "mysql"))]
fn mysql_unique(_db: &(dyn DatabaseError + 'static)) -> bool {
    false
}

/// Maps a connection-pool failure into [`OrmError::Connection`].
///
/// The `Display` message is a static category string — the pool/database
/// URL (which may carry credentials) is never rendered. The driver error is
/// kept behind `#[source]` for diagnostics.
#[must_use]
pub fn map_pool_error(error: sqlx::Error) -> OrmError {
    OrmError::Connection {
        message: "database connection pool failure".to_owned(),
        source: Some(Box::new(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::error::ErrorKind;

    /// Minimal [`DatabaseError`] probe for constructing discrimination
    /// tests without a live database (diesel error.rs precedent).
    #[derive(Debug)]
    struct FakeDbError {
        kind: FakeKind,
        code: Option<String>,
        constraint: Option<String>,
    }

    /// The kind tag — `ErrorKind` is neither `Copy` nor `Clone`, so the
    /// probe stores its own copy and maps on demand.
    #[derive(Debug)]
    enum FakeKind {
        Unique,
        NotNull,
        Check,
        Other,
    }

    impl std::fmt::Display for FakeDbError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "fake database error")
        }
    }

    impl std::error::Error for FakeDbError {}

    impl DatabaseError for FakeDbError {
        // Trait-impl `message` must keep the `&str` signature (E0053) even
        // though the probe returns a literal (diesel error.rs precedent).
        #[allow(clippy::unnecessary_literal_bound)]
        fn message(&self) -> &str {
            "fake database error"
        }

        fn code(&self) -> Option<std::borrow::Cow<'_, str>> {
            self.code.as_deref().map(std::borrow::Cow::Borrowed)
        }

        fn constraint(&self) -> Option<&str> {
            self.constraint.as_deref()
        }

        fn kind(&self) -> ErrorKind {
            match self.kind {
                FakeKind::Unique => ErrorKind::UniqueViolation,
                FakeKind::NotNull => ErrorKind::NotNullViolation,
                FakeKind::Check => ErrorKind::CheckViolation,
                FakeKind::Other => ErrorKind::Other,
            }
        }

        fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
            self
        }

        fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
            self
        }

        fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
            self
        }
    }

    #[test]
    fn unique_violation_by_kind_carries_constraint_name() {
        let mapped = map_sqlx_error(sqlx::Error::Database(Box::new(FakeDbError {
            kind: FakeKind::Unique,
            code: Some("23505".to_owned()),
            constraint: Some("index_users_on_email".to_owned()),
        })));
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
        let mapped = map_sqlx_error(sqlx::Error::Database(Box::new(FakeDbError {
            kind: FakeKind::Unique,
            code: None,
            constraint: None,
        })));
        assert!(
            matches!(mapped, OrmError::UniqueViolation { constraint: None }),
            "expected bare UniqueViolation, got {mapped:?}"
        );
    }

    #[test]
    fn unique_violation_by_sqlite_code_table_fallback() {
        // Misreported kind, real sqlite extended code: the code table still
        // discriminates so the token retry loop retries (Pitfall 4).
        let mapped = map_sqlx_error(sqlx::Error::Database(Box::new(FakeDbError {
            kind: FakeKind::Other,
            code: Some("1555".to_owned()),
            constraint: None,
        })));
        assert!(
            matches!(mapped, OrmError::UniqueViolation { .. }),
            "sqlite 1555 must discriminate UniqueViolation, got {mapped:?}"
        );
        let mapped = map_sqlx_error(sqlx::Error::Database(Box::new(FakeDbError {
            kind: FakeKind::Other,
            code: Some("2067".to_owned()),
            constraint: None,
        })));
        assert!(
            matches!(mapped, OrmError::UniqueViolation { .. }),
            "sqlite 2067 must discriminate UniqueViolation, got {mapped:?}"
        );
    }

    #[test]
    fn non_unique_codes_do_not_discriminate() {
        let mapped = map_sqlx_error(sqlx::Error::Database(Box::new(FakeDbError {
            kind: FakeKind::NotNull,
            code: Some("23502".to_owned()),
            constraint: None,
        })));
        assert!(
            matches!(mapped, OrmError::Query { .. }),
            "a not-null violation stays a Query failure, got {mapped:?}"
        );
    }

    #[test]
    fn row_not_found_maps_to_not_found() {
        assert!(matches!(
            map_sqlx_error(sqlx::Error::RowNotFound),
            OrmError::NotFound
        ));
    }

    #[test]
    fn other_errors_become_query_with_category_display() {
        let mapped = map_sqlx_error(sqlx::Error::Database(Box::new(FakeDbError {
            kind: FakeKind::Check,
            code: None,
            constraint: None,
        })));
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
        let mapped = map_pool_error(sqlx::Error::Configuration(
            format!("could not connect to {canary_url}").into(),
        ));
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
