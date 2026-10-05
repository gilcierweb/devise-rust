//! Devise-parity migration generator (ORM-agnostic DDL).
//!
//! This crate is the single source of truth for devise column definitions
//! (Phase 2 D-08). It emits plain-SQL `up.sql`/`down.sql` migrations whose
//! column names, nullability, defaults, and unique indexes are transcribed
//! verbatim from the vendored Devise generator
//! (`devise/lib/generators/active_record/devise_generator.rb`, `migration_data`
//! heredoc + `templates/migration.rb` / `templates/migration_existing.rb`).
//!
//! The output is ORM-agnostic: the files land in the diesel-CLI-compatible
//! layout (`migrations/<timestamp>_devise_create_<table>/{up,down}.sql`) so
//! they run verbatim under `diesel migration run`, while remaining plain SQL
//! reusable by any backend.
//!
//! ## Options
//!
//! Drive emission through [`EmitOptions::new`] plus the consuming builder
//! methods, then call [`emit`]:
//!
//! ```rust
//! use devise_rust_migrations::{Dialect, EmitOptions, Flow, Module, PkKind, emit};
//!
//! let mut opts = EmitOptions::new("users")
//!     .dialect(Dialect::Postgres)
//!     .flow(Flow::Create);
//! opts.modules.insert(Module::DatabaseAuthenticatable);
//! let files = emit(&opts).unwrap();
//! assert!(files.up_sql.contains("encrypted_password"));
//! ```
//!
//! ## Examples
//!
//! Full-module create flow written to disk:
//!
//! ```rust
//! use devise_rust_migrations::{EmitOptions, emit};
//!
//! let opts = EmitOptions::new("users").with_all_modules();
//! let files = emit(&opts).unwrap();
//! let dir = std::env::temp_dir().join("devise_migrations_doctest");
//! let _ = std::fs::remove_dir_all(&dir);
//! let written = files.write_to(&dir, "20260101000000").unwrap();
//! assert!(written.join("up.sql").exists());
//! let _ = std::fs::remove_dir_all(&dir);
//! ```

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

mod ddl;
mod emit;

pub use emit::emit;

/// A Devise model module that contributes database columns.
///
/// Only modules that add columns exist here. Devise modules without columns
/// (`validatable`, `registerable`, `timeoutable`, `omniauthable`) are rejected
/// at the [`FromStr`] boundary with [`EmitError::UnknownModule`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Module {
    /// `email` + `encrypted_password` (`NOT NULL DEFAULT ''`).
    DatabaseAuthenticatable,
    /// `reset_password_token` + `reset_password_sent_at`.
    Recoverable,
    /// `remember_created_at` (+ opt-in `remember_token` for DB-token mode).
    Rememberable,
    /// `sign_in_count`, `*_sign_in_at`, `*_sign_in_ip`.
    Trackable,
    /// `confirmation_token`, `confirmed_at`, `confirmation_sent_at`
    /// (+ `unconfirmed_email` when reconfirmable).
    Confirmable,
    /// `failed_attempts`, `locked_at` (+ `unlock_token` for email strategies).
    Lockable,
}

impl Module {
    /// Devise `snake_case` module name, as used by `rails generate devise`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DatabaseAuthenticatable => "database_authenticatable",
            Self::Recoverable => "recoverable",
            Self::Rememberable => "rememberable",
            Self::Trackable => "trackable",
            Self::Confirmable => "confirmable",
            Self::Lockable => "lockable",
        }
    }

    /// Every column-bearing module, in devise heredoc emission order.
    #[must_use]
    pub const fn all() -> [Self; 6] {
        [
            Self::DatabaseAuthenticatable,
            Self::Recoverable,
            Self::Rememberable,
            Self::Trackable,
            Self::Confirmable,
            Self::Lockable,
        ]
    }
}

impl fmt::Display for Module {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Module {
    type Err = EmitError;

    /// Parses a devise `snake_case` module name.
    ///
    /// # Errors
    ///
    /// Returns [`EmitError::UnknownModule`] for anything that is not a
    /// column-bearing module — including valid Devise modules that add no
    /// columns (`validatable`, `registerable`, `timeoutable`, `omniauthable`).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "database_authenticatable" => Ok(Self::DatabaseAuthenticatable),
            "recoverable" => Ok(Self::Recoverable),
            "rememberable" => Ok(Self::Rememberable),
            "trackable" => Ok(Self::Trackable),
            "confirmable" => Ok(Self::Confirmable),
            "lockable" => Ok(Self::Lockable),
            other => Err(EmitError::UnknownModule(other.to_owned())),
        }
    }
}

/// Primary-key shape (ORM-03 parity: integer/bigint AND uuid).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum PkKind {
    /// Rails-default bigint identity (`BIGSERIAL` / `AUTOINCREMENT` / …).
    #[default]
    Integer,
    /// UUID primary key (`gen_random_uuid()` / `TEXT` / `CHAR(36)`).
    Uuid,
}

/// SQL dialect for the emitted DDL.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Dialect {
    /// PostgreSQL (`VARCHAR`, `TIMESTAMP`, `INET`, `BIGSERIAL`).
    #[default]
    Postgres,
    /// SQLite (`TEXT`, `DATETIME`, `TEXT` IPs, `INTEGER AUTOINCREMENT`).
    Sqlite,
    /// MySQL (`VARCHAR(255)`, `DATETIME`, `VARCHAR(39)` IPs; CI-pending).
    Mysql,
}

/// Migration flow: fresh table vs adding devise to an existing table.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Flow {
    /// `CREATE TABLE` + indexes; `down.sql` drops the table.
    #[default]
    Create,
    /// `ALTER TABLE … ADD COLUMN` + indexes; `down.sql` drops the columns.
    AddToExisting,
}

/// Devise `lock_strategy` values with column implications.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum LockStrategy {
    /// Emit `failed_attempts` (devise default `"failed_attempts"`).
    #[default]
    FailedAttempts,
    /// Emit no `failed_attempts` column (`"none"`).
    None,
}

/// Devise `unlock_strategy` values with column implications.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum UnlockStrategy {
    /// Time-based unlock only: no `unlock_token` column.
    Time,
    /// Emit `unlock_token` + unique index.
    Email,
    /// Emit `unlock_token` + unique index (devise default `"both"`).
    #[default]
    Both,
    /// No `unlock_token` column, no `locked_at` semantics change.
    None,
}

/// Options driving [`emit`].
///
/// ## Options
///
/// * `table` — target table name; must match `^[a-z][a-z0-9_]*$`.
/// * `modules` — column-bearing modules to include.
/// * `pk` / `dialect` / `flow` — key shape, SQL dialect, migration flow.
/// * `reconfirmable` (default `true`, devise default) — emit
///   `unconfirmed_email` with confirmable.
/// * `lock_strategy` (default [`LockStrategy::FailedAttempts`]).
/// * `unlock_strategy` (default [`UnlockStrategy::Both`]).
/// * `remember_token` (default `false` — devise's core generator does not
///   emit it; opt-in for rememberable DB-token mode).
/// * `timestamps` (default `true`) — emit `created_at`/`updated_at NOT NULL`.
#[derive(Debug, Clone)]
pub struct EmitOptions {
    /// Target table name (validated as a SQL identifier).
    pub table: String,
    /// Selected column-bearing modules.
    pub modules: BTreeSet<Module>,
    /// Primary-key shape.
    pub pk: PkKind,
    /// SQL dialect.
    pub dialect: Dialect,
    /// Create vs add-to-existing flow.
    pub flow: Flow,
    /// Whether confirmable emits `unconfirmed_email`.
    pub reconfirmable: bool,
    /// Lock strategy (gates `failed_attempts`).
    pub lock_strategy: LockStrategy,
    /// Unlock strategy (gates `unlock_token` + index).
    pub unlock_strategy: UnlockStrategy,
    /// Emit `remember_token` (rememberable DB-token mode).
    pub remember_token: bool,
    /// Emit `created_at`/`updated_at NOT NULL`.
    pub timestamps: bool,
}

impl EmitOptions {
    /// Minimal options: devise's active-by-default generator set
    /// (`database_authenticatable`, `recoverable`, `rememberable`), postgres
    /// dialect, bigint PK, create flow.
    #[must_use]
    pub fn new(table: impl Into<String>) -> Self {
        Self {
            table: table.into(),
            modules: BTreeSet::from([
                Module::DatabaseAuthenticatable,
                Module::Recoverable,
                Module::Rememberable,
            ]),
            pk: PkKind::Integer,
            dialect: Dialect::Postgres,
            flow: Flow::Create,
            reconfirmable: true,
            lock_strategy: LockStrategy::FailedAttempts,
            unlock_strategy: UnlockStrategy::Both,
            remember_token: false,
            timestamps: true,
        }
    }

    /// Replace the module set with every column-bearing module.
    #[must_use]
    pub fn with_all_modules(mut self) -> Self {
        self.modules = Module::all().into_iter().collect();
        self
    }

    /// Set the module set.
    #[must_use]
    pub fn modules(mut self, modules: BTreeSet<Module>) -> Self {
        self.modules = modules;
        self
    }

    /// Set the primary-key shape.
    #[must_use]
    pub const fn pk(mut self, pk: PkKind) -> Self {
        self.pk = pk;
        self
    }

    /// Set the SQL dialect.
    #[must_use]
    pub const fn dialect(mut self, dialect: Dialect) -> Self {
        self.dialect = dialect;
        self
    }

    /// Set the migration flow.
    #[must_use]
    pub const fn flow(mut self, flow: Flow) -> Self {
        self.flow = flow;
        self
    }

    /// Set whether confirmable emits `unconfirmed_email`.
    #[must_use]
    pub const fn reconfirmable(mut self, reconfirmable: bool) -> Self {
        self.reconfirmable = reconfirmable;
        self
    }

    /// Set the lock strategy.
    #[must_use]
    pub const fn lock_strategy(mut self, strategy: LockStrategy) -> Self {
        self.lock_strategy = strategy;
        self
    }

    /// Set the unlock strategy.
    #[must_use]
    pub const fn unlock_strategy(mut self, strategy: UnlockStrategy) -> Self {
        self.unlock_strategy = strategy;
        self
    }

    /// Set whether rememberable emits the DB-token `remember_token` column.
    #[must_use]
    pub const fn remember_token(mut self, remember_token: bool) -> Self {
        self.remember_token = remember_token;
        self
    }

    /// Set whether `created_at`/`updated_at NOT NULL` are emitted.
    #[must_use]
    pub const fn timestamps(mut self, timestamps: bool) -> Self {
        self.timestamps = timestamps;
        self
    }
}

/// Emission failures.
///
/// Identifiers and module names are validated before any SQL string is built
/// and before any file exists (threat T-2-02).
#[derive(Debug, thiserror::Error)]
pub enum EmitError {
    /// Table name failed `^[a-z][a-z0-9_]*$` validation.
    #[error("invalid table name {0:?}: must match ^[a-z][a-z0-9_]*$")]
    InvalidIdentifier(String),
    /// Module name parses to nothing column-bearing (including real Devise
    /// modules like `validatable` that add no devise columns).
    #[error("module {0:?} adds no devise columns")]
    UnknownModule(String),
    /// The selected modules contribute zero columns.
    #[error("selected modules add no devise columns")]
    NoColumnsToEmit,
    /// `write_to` target directory already exists (never silently overwrite).
    #[error("migration directory already exists: {}", .0.display())]
    OutputExists(PathBuf),
    /// Filesystem failure while writing.
    #[error("failed to write migration files")]
    Io(#[from] std::io::Error),
}

/// Returns `true` when `table` is a safe SQL identifier (`^[a-z][a-z0-9_]*$`).
#[must_use]
pub fn is_valid_identifier(table: &str) -> bool {
    let mut chars = table.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => (),
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Returns `true` when `component` is a flat relative path component.
///
/// Only ASCII alphanumerics, `_`, `-`, and `.` are allowed, and the component
/// must not be `.`, `..`, or contain a path separator — so `dir.join(...)`
/// can never escape `dir` (threat T-2-04).
#[must_use]
fn is_flat_component(component: &str) -> bool {
    !component.is_empty()
        && component != "."
        && component != ".."
        && !component.contains(['/', '\\'])
        && component
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

/// Validates `table`, returning it on success.
///
/// # Errors
///
/// Returns [`EmitError::InvalidIdentifier`] when `table` is not
/// `^[a-z][a-z0-9_]*$`.
pub fn check_identifier(table: &str) -> Result<&str, EmitError> {
    if is_valid_identifier(table) {
        Ok(table)
    } else {
        Err(EmitError::InvalidIdentifier(table.to_owned()))
    }
}

/// Migration file payload, ready to write via [`MigrationFiles::write_to`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationPayload {
    /// Diesel-CLI-compatible directory name (without timestamp prefix).
    pub migration_name: String,
    /// Contents of `up.sql`.
    pub up_sql: String,
    /// Contents of `down.sql`.
    pub down_sql: String,
}

impl MigrationPayload {
    /// Writes `<dir>/<timestamp>_<migration_name>/{up.sql,down.sql}`.
    ///
    /// Creates parent directories as needed. Refuses to overwrite an
    /// existing migration directory (threat T-2-04). Both the timestamp and
    /// the migration name must be flat path components (no separators,
    /// no `..`, no absolute paths), so writes can never escape `dir` —
    /// even for a hand-constructed payload that bypassed [`emit`].
    ///
    /// # Errors
    ///
    /// Returns [`EmitError::InvalidIdentifier`] when the timestamp or
    /// migration name is not a flat path component,
    /// [`EmitError::OutputExists`] when the target directory already
    /// exists, or [`EmitError::Io`] on filesystem failures.
    pub fn write_to(&self, dir: &Path, timestamp: &str) -> Result<PathBuf, EmitError> {
        if !is_flat_component(timestamp) {
            return Err(EmitError::InvalidIdentifier(timestamp.to_owned()));
        }
        if !is_flat_component(&self.migration_name) {
            return Err(EmitError::InvalidIdentifier(self.migration_name.clone()));
        }
        let target = dir.join(format!("{timestamp}_{}", self.migration_name));
        if target.exists() {
            return Err(EmitError::OutputExists(target));
        }
        std::fs::create_dir_all(&target)?;
        std::fs::write(target.join("up.sql"), &self.up_sql)?;
        std::fs::write(target.join("down.sql"), &self.down_sql)?;
        Ok(target)
    }
}

/// Emitted migration files; re-exported payload type alias kept stable.
///
/// `MigrationFiles` is the plan-level name for the payload returned by
/// [`emit`]; it aliases [`MigrationPayload`].
pub type MigrationFiles = MigrationPayload;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_identifiers_pass() {
        for ok in ["users", "admin_users", "user2", "a", "u_s_e_r_s_1"] {
            assert!(is_valid_identifier(ok), "{ok} should be valid");
        }
    }

    #[test]
    fn malformed_identifiers_rejected() {
        for bad in [
            "",
            "Users",
            "USERS",
            "1users",
            "users; DROP TABLE users--",
            "users users",
            "users-users",
            "users.users",
            "_users",
            "useré",
        ] {
            assert!(!is_valid_identifier(bad), "{bad:?} should be invalid");
            assert!(matches!(
                check_identifier(bad),
                Err(EmitError::InvalidIdentifier(_))
            ));
        }
    }

    #[test]
    fn module_names_parse_and_display() {
        for module in Module::all() {
            assert_eq!(Module::from_str(module.as_str()).unwrap(), module);
            assert_eq!(module.to_string(), module.as_str());
        }
    }

    #[test]
    fn non_column_modules_rejected_with_columns_message() {
        for name in [
            "validatable",
            "registerable",
            "timeoutable",
            "omniauthable",
            "authenticatable",
            "bogus",
            "",
        ] {
            let err = Module::from_str(name).unwrap_err();
            assert!(
                err.to_string().contains("adds no devise columns"),
                "unexpected message for {name:?}: {err}"
            );
        }
    }
}
