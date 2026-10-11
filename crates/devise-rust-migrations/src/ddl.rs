//! Per-dialect DDL builders.
//!
//! Column names, nullability, and defaults are transcribed verbatim from
//! `devise_generator.rb`'s `migration_data` heredoc; type spellings follow the
//! RESEARCH "Devise Column Contract": string → `VARCHAR`/`TEXT`/`VARCHAR(255)`,
//! datetime → `TIMESTAMP`/`DATETIME`/`DATETIME`, counters → `INTEGER`/`INTEGER`/`INT`,
//! IPs follow devise's `ip_column` rule (`INET` on postgres, `TEXT` on sqlite,
//! `VARCHAR(39)` on mysql).

use crate::{Dialect, EmitOptions, LockStrategy, Module, PkKind, UnlockStrategy};

/// Digest-only storage note attached to every raw-token-shaped column.
///
/// DDL cannot enforce digest-only storage (devise parity — the gem's own
/// migration doesn't either); the comment documents the HMAC-SHA256 contract
/// enforced by the core `TokenGenerator` (threat T-2-03, accepted residual).
pub(crate) const DIGEST_COMMENT: &str =
    "-- stores HMAC-SHA256 digest; raw token only ever in email (devise parity)";

/// SQL string-column type for the dialect.
pub(crate) const fn string_type(dialect: Dialect) -> &'static str {
    match dialect {
        Dialect::Postgres => "VARCHAR",
        Dialect::Sqlite => "TEXT",
        Dialect::Mysql => "VARCHAR(255)",
    }
}

/// SQL datetime-column type for the dialect.
pub(crate) const fn datetime_type(dialect: Dialect) -> &'static str {
    match dialect {
        Dialect::Postgres => "TIMESTAMP",
        Dialect::Sqlite | Dialect::Mysql => "DATETIME",
    }
}

/// SQL counter-column type for the dialect (`sign_in_count`, `failed_attempts`).
pub(crate) const fn counter_type(dialect: Dialect) -> &'static str {
    match dialect {
        Dialect::Postgres | Dialect::Sqlite => "INTEGER",
        Dialect::Mysql => "INT",
    }
}

/// SQL IP-column type for the dialect (devise `ip_column` rule).
pub(crate) const fn ip_type(dialect: Dialect) -> &'static str {
    match dialect {
        Dialect::Postgres => "INET",
        Dialect::Sqlite => "TEXT",
        Dialect::Mysql => "VARCHAR(39)",
    }
}

/// Primary-key column definition line (without trailing comma).
pub(crate) fn pk_line(dialect: Dialect, pk: PkKind) -> String {
    match (dialect, pk) {
        (Dialect::Postgres, PkKind::Integer) => "id BIGSERIAL PRIMARY KEY".to_owned(),
        (Dialect::Postgres, PkKind::Uuid) => {
            "id UUID PRIMARY KEY DEFAULT gen_random_uuid()".to_owned()
        }
        (Dialect::Sqlite, PkKind::Integer) => "id INTEGER PRIMARY KEY AUTOINCREMENT".to_owned(),
        // No default: sqlite has no uuid function — the adapter assigns.
        (Dialect::Sqlite, PkKind::Uuid) => "id TEXT PRIMARY KEY".to_owned(),
        (Dialect::Mysql, PkKind::Integer) => "id BIGINT AUTO_INCREMENT PRIMARY KEY".to_owned(),
        (Dialect::Mysql, PkKind::Uuid) => "id CHAR(36) PRIMARY KEY".to_owned(),
    }
}

/// One devise column: name plus its per-dialect definition line.
///
/// The digest-only note is stored separately from `spec` so statement
/// builders can place it where it cannot break parsing (never between a
/// column spec and its statement terminator).
pub(crate) struct ColumnDef {
    /// Devise-verbatim column name.
    pub(crate) name: &'static str,
    /// `<name> <TYPE> [constraints]` for the dialect, without separators.
    pub(crate) spec: String,
    /// Whether to attach [`DIGEST_COMMENT`] to this column's line.
    pub(crate) digest: bool,
}

impl ColumnDef {
    fn plain(name: &'static str, spec: String) -> Self {
        Self {
            name,
            spec,
            digest: false,
        }
    }

    fn with_comment(name: &'static str, spec: String) -> Self {
        Self {
            name,
            spec,
            digest: true,
        }
    }

    /// Rendered `ADD COLUMN` statement (comment after the terminator).
    fn add_column_statement(&self, table: &str) -> String {
        let mut stmt = format!("ALTER TABLE {table} ADD COLUMN {};", self.spec);
        if self.digest {
            stmt.push(' ');
            stmt.push_str(DIGEST_COMMENT);
        }
        stmt
    }
}

/// Per-dialect type spellings shared by the module column builders below.
struct DialectTypes {
    string: &'static str,
    datetime: &'static str,
    counter: &'static str,
    ip: &'static str,
}

impl DialectTypes {
    const fn of(dialect: Dialect) -> Self {
        Self {
            string: string_type(dialect),
            datetime: datetime_type(dialect),
            counter: counter_type(dialect),
            ip: ip_type(dialect),
        }
    }
}

fn db_authenticatable_cols(t: &DialectTypes) -> Vec<ColumnDef> {
    let string = t.string;
    vec![
        ColumnDef::plain("email", format!("email {string} NOT NULL DEFAULT ''")),
        ColumnDef::plain(
            "encrypted_password",
            format!("encrypted_password {string} NOT NULL DEFAULT ''"),
        ),
    ]
}

fn recoverable_cols(t: &DialectTypes) -> Vec<ColumnDef> {
    let (string, datetime) = (t.string, t.datetime);
    vec![
        ColumnDef::with_comment(
            "reset_password_token",
            format!("reset_password_token {string}"),
        ),
        ColumnDef::plain(
            "reset_password_sent_at",
            format!("reset_password_sent_at {datetime}"),
        ),
    ]
}

fn rememberable_cols(t: &DialectTypes, with_token: bool) -> Vec<ColumnDef> {
    let (string, datetime) = (t.string, t.datetime);
    let mut cols = vec![ColumnDef::plain(
        "remember_created_at",
        format!("remember_created_at {datetime}"),
    )];
    if with_token {
        cols.push(ColumnDef::with_comment(
            "remember_token",
            format!("remember_token {string}"),
        ));
    }
    cols
}

fn trackable_cols(t: &DialectTypes) -> Vec<ColumnDef> {
    let (datetime, counter, ip) = (t.datetime, t.counter, t.ip);
    vec![
        ColumnDef::plain(
            "sign_in_count",
            format!("sign_in_count {counter} NOT NULL DEFAULT 0"),
        ),
        ColumnDef::plain(
            "current_sign_in_at",
            format!("current_sign_in_at {datetime}"),
        ),
        ColumnDef::plain("last_sign_in_at", format!("last_sign_in_at {datetime}")),
        ColumnDef::plain("current_sign_in_ip", format!("current_sign_in_ip {ip}")),
        ColumnDef::plain("last_sign_in_ip", format!("last_sign_in_ip {ip}")),
    ]
}

fn confirmable_cols(t: &DialectTypes, reconfirmable: bool) -> Vec<ColumnDef> {
    let (string, datetime) = (t.string, t.datetime);
    let mut cols = vec![
        ColumnDef::with_comment("confirmation_token", format!("confirmation_token {string}")),
        ColumnDef::plain("confirmed_at", format!("confirmed_at {datetime}")),
        ColumnDef::plain(
            "confirmation_sent_at",
            format!("confirmation_sent_at {datetime}"),
        ),
    ];
    if reconfirmable {
        cols.push(ColumnDef::plain(
            "unconfirmed_email",
            format!("unconfirmed_email {string}"),
        ));
    }
    cols
}

fn lockable_cols(t: &DialectTypes, opts: &EmitOptions) -> Vec<ColumnDef> {
    let (string, datetime, counter) = (t.string, t.datetime, t.counter);
    let mut cols = Vec::new();
    if opts.lock_strategy == LockStrategy::FailedAttempts {
        cols.push(ColumnDef::plain(
            "failed_attempts",
            format!("failed_attempts {counter} NOT NULL DEFAULT 0"),
        ));
    }
    if has_unlock_token(opts) {
        cols.push(ColumnDef::with_comment(
            "unlock_token",
            format!("unlock_token {string}"),
        ));
    }
    cols.push(ColumnDef::plain(
        "locked_at",
        format!("locked_at {datetime}"),
    ));
    cols
}

/// The omniauthable identity pair (D-11): `provider` + `uid` as plain
/// string columns, following the `rememberable_cols` shape.
///
/// D-12: no token-adjacent column ever ships here - OAuth access and
/// refresh tokens live in the session for the requesting flow only and are
/// never persisted.
fn omniauthable_cols(t: &DialectTypes) -> Vec<ColumnDef> {
    let string = t.string;
    vec![
        ColumnDef::plain("provider", format!("provider {string}")),
        ColumnDef::plain("uid", format!("uid {string}")),
    ]
}

/// Devise column block in heredoc order, honoring module/strategy conditionals.
pub(crate) fn column_defs(opts: &EmitOptions) -> Vec<ColumnDef> {
    let types = DialectTypes::of(opts.dialect);
    let modules = &opts.modules;
    let mut cols = Vec::new();

    if modules.contains(&Module::DatabaseAuthenticatable) {
        cols.extend(db_authenticatable_cols(&types));
    }
    if modules.contains(&Module::Recoverable) {
        cols.extend(recoverable_cols(&types));
    }
    if modules.contains(&Module::Rememberable) {
        cols.extend(rememberable_cols(&types, opts.remember_token));
    }
    if modules.contains(&Module::Trackable) {
        cols.extend(trackable_cols(&types));
    }
    if modules.contains(&Module::Confirmable) {
        cols.extend(confirmable_cols(&types, opts.reconfirmable));
    }
    if modules.contains(&Module::Lockable) {
        cols.extend(lockable_cols(&types, opts));
    }
    if modules.contains(&Module::Omniauthable) {
        cols.extend(omniauthable_cols(&types));
    }
    cols
}

/// `created_at` / `updated_at NOT NULL` lines for the dialect.
///
/// Kept separate from [`column_defs`] so [`crate::emit`] can distinguish
/// "no devise module contributed a column" ([`crate::EmitError::NoColumnsToEmit`])
/// from an explicit `timestamps: false` opt-out.
pub(crate) fn timestamp_defs(dialect: Dialect) -> Vec<ColumnDef> {
    let datetime = datetime_type(dialect);
    vec![
        ColumnDef::plain("created_at", format!("created_at {datetime} NOT NULL")),
        ColumnDef::plain("updated_at", format!("updated_at {datetime} NOT NULL")),
    ]
}

/// `true` when the `unlock_token` column is emitted.
pub(crate) fn has_unlock_token(opts: &EmitOptions) -> bool {
    opts.modules.contains(&Module::Lockable)
        && matches!(
            opts.unlock_strategy,
            UnlockStrategy::Email | UnlockStrategy::Both
        )
}

/// Full `CREATE UNIQUE INDEX …;` statements for the selected modules.
///
/// Mirrors `migration.rb:15-18`: email + `reset_password_token` always when
/// their modules are present; confirmation/unlock indexes become active (not
/// commented) when reconfirmable / email-unlock apply (D-10).
pub(crate) fn index_statements(opts: &EmitOptions) -> Vec<String> {
    let table = opts.table.as_str();
    let mut indexes = Vec::new();
    if opts.modules.contains(&Module::DatabaseAuthenticatable) {
        indexes.push(format!(
            "CREATE UNIQUE INDEX index_{table}_on_email ON {table} (email);"
        ));
    }
    if opts.modules.contains(&Module::Recoverable) {
        indexes.push(format!(
            "CREATE UNIQUE INDEX index_{table}_on_reset_password_token ON {table} (reset_password_token);"
        ));
    }
    if opts.modules.contains(&Module::Confirmable) {
        indexes.push(format!(
            "CREATE UNIQUE INDEX index_{table}_on_confirmation_token ON {table} (confirmation_token);"
        ));
    }
    if has_unlock_token(opts) {
        indexes.push(format!(
            "CREATE UNIQUE INDEX index_{table}_on_unlock_token ON {table} (unlock_token);"
        ));
    }
    indexes
}

/// `CREATE TABLE` statement for the create flow.
///
/// Digest notes render as their own `--` line AFTER the column's comma: a
/// trailing `-- comment,` would swallow the separator into the comment and
/// SQLite would silently merge the following column into the type name
/// (columns vanish without an error). Commas therefore stay glued to the
/// spec; comment lines never carry one.
pub(crate) fn create_table(opts: &EmitOptions, columns: &[ColumnDef]) -> String {
    let table = opts.table.as_str();
    let mut sql = format!("CREATE TABLE {table} (\n");
    // Body lines: a digest note follows its column on its own line, and the
    // separator comma stays glued to the spec — never inside the `--`
    // comment (where SQLite would swallow it and silently merge the next
    // column into the type name).
    let mut lines = vec![(format!("  {}", pk_line(opts.dialect, opts.pk)), true)];
    for col in columns {
        lines.push((format!("  {}", col.spec), true));
        if col.digest {
            lines.push((format!("  {DIGEST_COMMENT}"), false));
        }
    }
    let last = lines.len() - 1;
    for (index, (line, is_spec)) in lines.iter().enumerate() {
        if index > 0 {
            sql.push('\n');
        }
        sql.push_str(line);
        if *is_spec && index < last {
            sql.push(',');
        }
    }
    sql.push_str("\n);");
    sql
}

/// `DROP TABLE` statement for the create flow's `down.sql`.
pub(crate) fn drop_table(opts: &EmitOptions) -> String {
    format!("DROP TABLE {};", opts.table)
}

/// `ALTER TABLE … ADD COLUMN` lines for the add-to-existing flow.
pub(crate) fn alter_add_columns(opts: &EmitOptions, columns: &[ColumnDef]) -> Vec<String> {
    let table = opts.table.as_str();
    columns
        .iter()
        .map(|c| c.add_column_statement(table))
        .collect()
}

/// `ALTER TABLE … DROP COLUMN` lines (reverse order) for existing flow's `down.sql`.
pub(crate) fn alter_drop_columns(opts: &EmitOptions, columns: &[ColumnDef]) -> Vec<String> {
    let table = opts.table.as_str();
    columns
        .iter()
        .rev()
        .map(|c| format!("ALTER TABLE {table} DROP COLUMN {};", c.name))
        .collect()
}
