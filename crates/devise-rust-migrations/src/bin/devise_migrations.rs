//! `devise-migrations` — thin CLI over [`devise_rust_migrations::emit`].
//!
//! The `rails generate devise User` experience: emits a diesel-CLI-compatible
//! migration directory for a table and module set.
//!
//! ```text
//! devise-migrations users --dialect postgres --modules all
//! ```

use std::collections::BTreeSet;
use std::path::PathBuf;

use devise_rust_migrations::{
    Dialect, EmitOptions, Flow, LockStrategy, Module, PkKind, UnlockStrategy, emit,
};

const HELP: &str = "\
devise-migrations — emit devise-parity SQL migrations

USAGE:
    devise-migrations <TABLE> [OPTIONS]

ARGS:
    <TABLE>    Target table name (must match ^[a-z][a-z0-9_]*$)

OPTIONS:
    --dialect <postgres|sqlite|mysql>
            SQL dialect (default: postgres)
    --pk <bigint|uuid>
            Primary-key shape; `integer` accepted as an alias of `bigint`
            (default: bigint)
    --modules <csv|all>
            Comma-separated devise module names, or `all` for every
            column-bearing module (default:
            database_authenticatable,recoverable,rememberable)
    --reconfirmable[=<true|false>]
            Emit `unconfirmed_email` with confirmable (default: true)
    --lock-strategy <failed_attempts|none>
            Lock strategy (default: failed_attempts)
    --unlock-strategy <time|email|both|none>
            Unlock strategy (default: both)
    --remember-token
            Emit the `remember_token` column (rememberable DB-token mode;
            devise core does not emit it by default)
    --existing
            Add-to-existing flow: ALTER TABLE ADD COLUMN + DROP COLUMN down
            migration instead of CREATE TABLE (default timestamps: off)
    --timestamps[=<true|false>]
            Emit `created_at`/`updated_at NOT NULL` (default: on for create,
            off for --existing)
    --output <dir>
            Output directory for the migration (default: migrations)
    --timestamp <YYYYMMDDHHMMSS>
            Migration timestamp prefix (default: current UTC time)
    --help, -h
            Print this help and exit 0
";

/// Parsed CLI configuration.
#[derive(Debug)]
struct Config {
    table: String,
    dialect: Dialect,
    pk: PkKind,
    modules: Option<BTreeSet<Module>>,
    reconfirmable: bool,
    lock_strategy: LockStrategy,
    unlock_strategy: UnlockStrategy,
    remember_token: bool,
    existing: bool,
    timestamps: Option<bool>,
    output: PathBuf,
    timestamp: Option<String>,
}

impl Config {
    fn new(table: String) -> Self {
        Self {
            table,
            dialect: Dialect::Postgres,
            pk: PkKind::Integer,
            modules: None,
            reconfirmable: true,
            lock_strategy: LockStrategy::FailedAttempts,
            unlock_strategy: UnlockStrategy::Both,
            remember_token: false,
            existing: false,
            timestamps: None,
            output: PathBuf::from("migrations"),
            timestamp: None,
        }
    }
}

/// Splits `--name=value` into `(name, Some(value))`, else `(arg, None)`.
fn split_equals(arg: &str) -> (&str, Option<&str>) {
    match arg.split_once('=') {
        Some((name, value)) => (name, Some(value)),
        None => (arg, None),
    }
}

/// Parses a boolean flag value (`--flag[=bool]`, `--no-flag` handled by caller).
fn parse_bool(name: &str, value: Option<&str>) -> Result<bool, String> {
    match value {
        None | Some("true") => Ok(true),
        Some("false") => Ok(false),
        Some(other) => Err(format!(
            "invalid value {other:?} for {name}: expected true or false"
        )),
    }
}

/// Consumes the next positional value for `--flag value`, or uses `=value`.
fn take_value(
    flag: &str,
    inline: Option<&str>,
    rest: &mut std::slice::Iter<'_, String>,
) -> Result<String, String> {
    if let Some(value) = inline {
        return Ok(value.to_owned());
    }
    rest.next()
        .cloned()
        .ok_or_else(|| format!("flag {flag} expects a value"))
}

/// Parses `argv` (without the program name) into a [`Config`].
fn parse_args(argv: &[String]) -> Result<Config, String> {
    let mut positional: Option<String> = None;
    let mut cfg_holder: Option<Config> = None;
    let mut rest = argv.iter();

    while let Some(arg) = rest.next() {
        if !arg.starts_with("--") {
            if positional.is_some() {
                return Err(format!("unexpected extra argument {arg:?}"));
            }
            positional = Some(arg.clone());
            continue;
        }
        let (flag, inline) = split_equals(arg);
        let cfg = cfg_holder.get_or_insert_with(|| Config::new(String::new()));
        match flag {
            "--dialect" => {
                cfg.dialect = match take_value(flag, inline, &mut rest)?.as_str() {
                    "postgres" => Dialect::Postgres,
                    "sqlite" => Dialect::Sqlite,
                    "mysql" => Dialect::Mysql,
                    other => {
                        return Err(format!(
                            "invalid --dialect {other:?}: expected postgres, sqlite, or mysql"
                        ));
                    }
                };
            }
            "--pk" => {
                cfg.pk = match take_value(flag, inline, &mut rest)?.as_str() {
                    "bigint" | "integer" => PkKind::Integer,
                    "uuid" => PkKind::Uuid,
                    other => {
                        return Err(format!("invalid --pk {other:?}: expected bigint or uuid"));
                    }
                };
            }
            "--modules" => {
                let raw = take_value(flag, inline, &mut rest)?;
                cfg.modules = Some(parse_modules(&raw)?);
            }
            "--reconfirmable" => cfg.reconfirmable = parse_bool(flag, inline)?,
            "--no-reconfirmable" => cfg.reconfirmable = false,
            "--lock-strategy" => {
                cfg.lock_strategy = match take_value(flag, inline, &mut rest)?.as_str() {
                    "failed_attempts" => LockStrategy::FailedAttempts,
                    "none" => LockStrategy::None,
                    other => {
                        return Err(format!(
                            "invalid --lock-strategy {other:?}: expected failed_attempts or none"
                        ));
                    }
                };
            }
            "--unlock-strategy" => {
                cfg.unlock_strategy = match take_value(flag, inline, &mut rest)?.as_str() {
                    "time" => UnlockStrategy::Time,
                    "email" => UnlockStrategy::Email,
                    "both" => UnlockStrategy::Both,
                    "none" => UnlockStrategy::None,
                    other => {
                        return Err(format!(
                            "invalid --unlock-strategy {other:?}: expected time, email, both, or none"
                        ));
                    }
                };
            }
            "--remember-token" => cfg.remember_token = parse_bool(flag, inline)?,
            "--no-remember-token" => cfg.remember_token = false,
            "--existing" => cfg.existing = parse_bool(flag, inline)?,
            "--timestamps" => cfg.timestamps = Some(parse_bool(flag, inline)?),
            "--no-timestamps" => cfg.timestamps = Some(false),
            "--output" => {
                cfg.output = PathBuf::from(take_value(flag, inline, &mut rest)?);
            }
            "--timestamp" => {
                let value = take_value(flag, inline, &mut rest)?;
                if value.len() != 14 || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(format!(
                        "invalid --timestamp {value:?}: expected YYYYMMDDHHMMSS"
                    ));
                }
                cfg.timestamp = Some(value);
            }
            other => return Err(format!("unknown flag {other:?} (see --help)")),
        }
    }

    let table = positional.ok_or_else(|| "missing <TABLE> argument (see --help)".to_owned())?;
    let mut cfg = cfg_holder.unwrap_or_else(|| Config::new(table.clone()));
    cfg.table = table;
    Ok(cfg)
}

/// Parses `--modules <csv>|all` into a module set.
fn parse_modules(raw: &str) -> Result<BTreeSet<Module>, String> {
    if raw == "all" {
        return Ok(Module::all().into_iter().collect());
    }
    let mut modules = BTreeSet::new();
    for name in raw.split(',') {
        let module: Module = name
            .parse()
            .map_err(|e: devise_rust_migrations::EmitError| e.to_string())?;
        modules.insert(module);
    }
    if modules.is_empty() {
        return Err("empty --modules set: selected modules add no devise columns".to_owned());
    }
    Ok(modules)
}

/// Builds [`EmitOptions`] from a [`Config`], applying flow timestamp defaults.
fn options_from(cfg: &Config) -> EmitOptions {
    let mut opts = EmitOptions::new(cfg.table.clone())
        .dialect(cfg.dialect)
        .pk(cfg.pk)
        .flow(if cfg.existing {
            Flow::AddToExisting
        } else {
            Flow::Create
        })
        .reconfirmable(cfg.reconfirmable)
        .lock_strategy(cfg.lock_strategy)
        .unlock_strategy(cfg.unlock_strategy)
        .remember_token(cfg.remember_token);
    if let Some(modules) = &cfg.modules {
        opts = opts.modules(modules.clone());
    }
    // Explicit --timestamps wins; otherwise create defaults on, existing off.
    opts = opts.timestamps(cfg.timestamps.unwrap_or(!cfg.existing));
    opts
}

/// Emits the migration and writes it; returns the written `up.sql`/`down.sql` paths.
fn run(argv: &[String]) -> Result<(PathBuf, PathBuf), String> {
    let cfg = parse_args(argv)?;
    let opts = options_from(&cfg);
    let files = emit(&opts).map_err(|e| e.to_string())?;
    let timestamp = cfg
        .timestamp
        .clone()
        .unwrap_or_else(|| chrono::Utc::now().format("%Y%m%d%H%M%S").to_string());
    let dir = files
        .write_to(&cfg.output, &timestamp)
        .map_err(|e| e.to_string())?;
    Ok((dir.join("up.sql"), dir.join("down.sql")))
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{HELP}");
        return;
    }
    match run(&argv) {
        Ok((up, down)) => {
            println!("{}", up.display());
            println!("{}", down.display());
        }
        Err(message) => {
            eprintln!("devise-migrations: {message}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn defaults_match_devise_generator_set() {
        let cfg = parse_args(&args(&["users"])).unwrap();
        assert_eq!(cfg.table, "users");
        assert_eq!(cfg.dialect, Dialect::Postgres);
        assert_eq!(cfg.pk, PkKind::Integer);
        assert!(cfg.modules.is_none());
        assert!(cfg.reconfirmable);
        assert!(!cfg.existing);
        let opts = options_from(&cfg);
        assert!(opts.modules.contains(&Module::DatabaseAuthenticatable));
        assert!(opts.modules.contains(&Module::Recoverable));
        assert!(opts.modules.contains(&Module::Rememberable));
        assert!(!opts.modules.contains(&Module::Lockable));
        assert!(opts.timestamps);
    }

    #[test]
    fn all_modules_selects_every_column_module() {
        let cfg = parse_args(&args(&["users", "--modules", "all"])).unwrap();
        let opts = options_from(&cfg);
        assert_eq!(opts.modules.len(), Module::all().len());
    }

    #[test]
    fn existing_flow_defaults_timestamps_off() {
        let cfg = parse_args(&args(&["users", "--existing"])).unwrap();
        assert!(!options_from(&cfg).timestamps);
        let cfg = parse_args(&args(&["users", "--existing", "--timestamps"])).unwrap();
        assert!(options_from(&cfg).timestamps);
    }

    #[test]
    fn invalid_values_rejected() {
        assert!(parse_args(&args(&["users", "--dialect", "oracle"])).is_err());
        assert!(parse_args(&args(&["users", "--pk", "serial"])).is_err());
        assert!(parse_args(&args(&["users", "--bogus"])).is_err());
        assert!(parse_args(&[]).is_err());
        assert!(parse_args(&args(&["users", "--timestamp", "yesterday"])).is_err());
        let err = parse_args(&args(&["users", "--modules", "validatable"])).unwrap_err();
        assert!(err.contains("adds no devise columns"));
    }
}
