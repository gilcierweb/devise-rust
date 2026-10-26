//! Pure emission entry point: [`emit`].

use crate::ddl;
use crate::{EmitError, EmitOptions, Flow, MigrationFiles, check_identifier};

/// Emits devise-parity `up.sql`/`down.sql` for `opts`.
///
/// Pure function: no I/O, no clock. The output is byte-deterministic for
/// identical options — the timestamp only appears in the migration directory
/// name chosen by [`MigrationFiles::write_to`].
///
/// ## Flows
///
/// * [`Flow::Create`] — `up.sql` is one `CREATE TABLE` (primary key, all
///   selected module columns in devise heredoc order, `created_at`/`updated_at`
///   when `timestamps` is set) plus `CREATE UNIQUE INDEX` statements;
///   `down.sql` drops the table.
/// * [`Flow::AddToExisting`] — `up.sql` is one `ALTER TABLE … ADD COLUMN` per
///   column plus the same indexes; `down.sql` drops the indexes in reverse
///   order, then the added columns in reverse order (devise's
///   `migration_existing.rb` raises `IrreversibleMigration` here — we emit
///   `DROP INDEX` + `DROP COLUMN`s instead, per D-10). Dropping the indexes
///   first keeps a re-run's `CREATE UNIQUE INDEX` working and satisfies
///   engines (SQLite) that refuse to drop an indexed column (M2).
///
/// # Errors
///
/// Returns [`EmitError::InvalidIdentifier`] before building any string when
/// `opts.table` is not `^[a-z][a-z0-9_]*$`, or
/// [`EmitError::NoColumnsToEmit`] when the selection yields zero columns.
///
/// # Examples
///
/// ```rust
/// use devise_rust_migrations::{EmitOptions, emit};
///
/// let files = emit(&EmitOptions::new("users").with_all_modules()).unwrap();
/// assert!(files.migration_name.contains("users"));
/// assert!(files.down_sql.contains("DROP TABLE"));
/// ```
#[must_use = "emission builds SQL strings; discarding them is almost certainly a bug"]
pub fn emit(opts: &EmitOptions) -> Result<MigrationFiles, EmitError> {
    check_identifier(&opts.table)?;

    let mut columns = ddl::column_defs(opts);
    if columns.is_empty() {
        return Err(EmitError::NoColumnsToEmit);
    }
    if opts.timestamps {
        columns.extend(ddl::timestamp_defs(opts.dialect));
    }
    let indexes = ddl::index_statements(opts);

    let (up_sql, down_sql) = match opts.flow {
        Flow::Create => {
            let mut up = ddl::create_table(opts, &columns);
            for index in &indexes {
                up.push('\n');
                up.push_str(index);
            }
            up.push('\n');
            let mut down = ddl::drop_table(opts);
            down.push('\n');
            (up, down)
        }
        Flow::AddToExisting => {
            let mut up = ddl::alter_add_columns(opts, &columns).join("\n");
            for index in &indexes {
                up.push('\n');
                up.push_str(index);
            }
            up.push('\n');
            let mut down = ddl::drop_index_statements(opts).join("\n");
            down.push('\n');
            down.push_str(&ddl::alter_drop_columns(opts, &columns).join("\n"));
            down.push('\n');
            (up, down)
        }
    };

    let migration_name = match opts.flow {
        Flow::Create => format!("devise_create_{}", opts.table),
        Flow::AddToExisting => format!("add_devise_to_{}", opts.table),
    };

    Ok(MigrationFiles {
        migration_name,
        up_sql,
        down_sql,
    })
}
