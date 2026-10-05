//! Snapshot matrix over (modules × dialect × pk × flow) plus content-identity
//! assertions (snapshots are never the only assertion on emitted content).

use std::collections::BTreeSet;

use rstest::rstest;

use devise_rust_migrations::{
    Dialect, EmitError, EmitOptions, Flow, LockStrategy, Module, PkKind, UnlockStrategy, emit,
};

/// Every D-10 devise column name the generator must emit verbatim.
const ALL_COLUMNS: &[&str] = &[
    "encrypted_password",
    "reset_password_token",
    "reset_password_sent_at",
    "remember_created_at",
    "confirmation_token",
    "confirmed_at",
    "confirmation_sent_at",
    "unconfirmed_email",
    "failed_attempts",
    "locked_at",
    "unlock_token",
    "sign_in_count",
    "current_sign_in_at",
    "last_sign_in_at",
    "current_sign_in_ip",
    "last_sign_in_ip",
];

fn full_options() -> EmitOptions {
    EmitOptions::new("users").with_all_modules()
}

#[test]
fn tracer_postgres_bigint_create_full_modules() {
    let opts = full_options();
    let files = emit(&opts).unwrap();

    assert_eq!(files.migration_name, "devise_create_users");
    for column in ALL_COLUMNS {
        assert!(
            files.up_sql.contains(column),
            "up.sql missing devise column {column}"
        );
    }
    for index in [
        "index_users_on_email",
        "index_users_on_reset_password_token",
        "index_users_on_confirmation_token",
        "index_users_on_unlock_token",
    ] {
        assert!(files.up_sql.contains(index), "up.sql missing {index}");
    }
    assert!(files.up_sql.contains("id BIGSERIAL PRIMARY KEY"));
    assert!(!files.up_sql.contains("gen_random_uuid()"));
    assert!(files.up_sql.contains("current_sign_in_ip INET"));
    assert!(files.down_sql.contains("DROP TABLE users;"));
    assert!(
        !files.up_sql.contains("table!"),
        "D-08: no diesel table! content in emitted DDL"
    );

    insta::assert_snapshot!(
        "postgres_full_create",
        format!("{}\n---\n{}", files.up_sql, files.down_sql)
    );
}

#[test]
fn malformed_table_names_rejected_before_any_sql_exists() {
    for bad in [
        "users; DROP TABLE users--",
        "1users",
        "Users",
        "",
        "user table",
    ] {
        let opts = EmitOptions {
            table: bad.to_owned(),
            ..full_options()
        };
        assert!(
            matches!(emit(&opts), Err(EmitError::InvalidIdentifier(_))),
            "{bad:?} must be rejected"
        );
    }
}

#[test]
fn empty_module_set_yields_no_columns_error() {
    let opts = EmitOptions {
        modules: BTreeSet::new(),
        ..full_options()
    };
    assert!(matches!(emit(&opts), Err(EmitError::NoColumnsToEmit)));
}

#[test]
fn emission_is_byte_deterministic() {
    let opts = full_options()
        .dialect(Dialect::Postgres)
        .pk(PkKind::Integer)
        .flow(Flow::Create);
    let first = emit(&opts).unwrap();
    let second = emit(&opts).unwrap();
    assert_eq!(first.up_sql, second.up_sql);
    assert_eq!(first.down_sql, second.down_sql);
}

/// Devise heredoc emission order (create flow), used for order assertions.
const EMISSION_ORDER: &[&str] = &[
    "email",
    "encrypted_password",
    "reset_password_token",
    "reset_password_sent_at",
    "remember_created_at",
    "sign_in_count",
    "current_sign_in_at",
    "last_sign_in_at",
    "current_sign_in_ip",
    "last_sign_in_ip",
    "confirmation_token",
    "confirmed_at",
    "confirmation_sent_at",
    "unconfirmed_email",
    "failed_attempts",
    "unlock_token",
    "locked_at",
    "created_at",
    "updated_at",
];

fn dialect_tag(dialect: Dialect) -> &'static str {
    match dialect {
        Dialect::Postgres => "pg",
        Dialect::Sqlite => "sqlite",
        Dialect::Mysql => "mysql",
    }
}

fn pk_tag(pk: PkKind) -> &'static str {
    match pk {
        PkKind::Integer => "int",
        PkKind::Uuid => "uuid",
    }
}

fn expected_pk_line(dialect: Dialect, pk: PkKind) -> &'static str {
    match (dialect, pk) {
        (Dialect::Postgres, PkKind::Integer) => "id BIGSERIAL PRIMARY KEY",
        (Dialect::Postgres, PkKind::Uuid) => "id UUID PRIMARY KEY DEFAULT gen_random_uuid()",
        (Dialect::Sqlite, PkKind::Integer) => "id INTEGER PRIMARY KEY AUTOINCREMENT",
        (Dialect::Sqlite, PkKind::Uuid) => "id TEXT PRIMARY KEY",
        (Dialect::Mysql, PkKind::Integer) => "id BIGINT AUTO_INCREMENT PRIMARY KEY",
        (Dialect::Mysql, PkKind::Uuid) => "id CHAR(36) PRIMARY KEY",
    }
}

#[rstest]
#[case(Dialect::Postgres, PkKind::Integer)]
#[case(Dialect::Postgres, PkKind::Uuid)]
#[case(Dialect::Sqlite, PkKind::Integer)]
#[case(Dialect::Sqlite, PkKind::Uuid)]
#[case(Dialect::Mysql, PkKind::Integer)]
#[case(Dialect::Mysql, PkKind::Uuid)]
fn matrix_full_create(#[case] dialect: Dialect, #[case] pk: PkKind) {
    let opts = full_options().dialect(dialect).pk(pk);
    let files = emit(&opts).unwrap();

    assert_eq!(files.migration_name, "devise_create_users");
    for column in ALL_COLUMNS {
        assert!(
            files.up_sql.contains(column),
            "{dialect:?}/{pk:?} up.sql missing devise column {column}"
        );
    }
    assert!(files.up_sql.contains(expected_pk_line(dialect, pk)));
    if pk == PkKind::Integer {
        assert!(!files.up_sql.contains("gen_random_uuid()"));
    }
    // String/datetime/ip spellings per dialect.
    match dialect {
        Dialect::Postgres => {
            assert!(files.up_sql.contains("email VARCHAR NOT NULL"));
            assert!(files.up_sql.contains("reset_password_sent_at TIMESTAMP"));
            assert!(files.up_sql.contains("current_sign_in_ip INET"));
        }
        Dialect::Sqlite => {
            assert!(files.up_sql.contains("email TEXT NOT NULL"));
            assert!(files.up_sql.contains("reset_password_sent_at DATETIME"));
            assert!(files.up_sql.contains("current_sign_in_ip TEXT"));
            assert!(!files.up_sql.contains("INET"));
        }
        Dialect::Mysql => {
            assert!(files.up_sql.contains("email VARCHAR(255) NOT NULL"));
            assert!(files.up_sql.contains("reset_password_sent_at DATETIME"));
            assert!(files.up_sql.contains("current_sign_in_ip VARCHAR(39)"));
            assert!(!files.up_sql.contains("INET"));
        }
    }
    // Digest-only comment on every token column.
    for token_col in ["reset_password_token", "confirmation_token", "unlock_token"] {
        assert!(
            files
                .up_sql
                .contains("stores HMAC-SHA256 digest; raw token only ever in email"),
            "{token_col} missing digest comment"
        );
    }

    insta::assert_snapshot!(
        format!("full_{}_{}_create", dialect_tag(dialect), pk_tag(pk)),
        format!("{}\n---\n{}", files.up_sql, files.down_sql)
    );
}

#[rstest]
#[case(Dialect::Postgres)]
#[case(Dialect::Sqlite)]
#[case(Dialect::Mysql)]
fn matrix_minimal_create(#[case] dialect: Dialect) {
    let opts = EmitOptions {
        modules: BTreeSet::from([Module::DatabaseAuthenticatable]),
        ..EmitOptions::new("users")
    }
    .dialect(dialect);
    let files = emit(&opts).unwrap();

    assert!(files.up_sql.contains("email"));
    assert!(files.up_sql.contains("encrypted_password"));
    assert!(files.up_sql.contains("created_at"));
    assert!(files.up_sql.contains("index_users_on_email"));
    for absent in [
        "reset_password_token",
        "remember_created_at",
        "sign_in_count",
        "confirmation_token",
        "failed_attempts",
        "unlock_token",
        "index_users_on_reset_password_token",
    ] {
        assert!(
            !files.up_sql.contains(absent),
            "minimal up.sql must not contain {absent}"
        );
    }

    insta::assert_snapshot!(
        format!("minimal_{}_create", dialect_tag(dialect)),
        format!("{}\n---\n{}", files.up_sql, files.down_sql)
    );
}

#[rstest]
#[case(Dialect::Postgres)]
#[case(Dialect::Sqlite)]
fn matrix_existing_flow(#[case] dialect: Dialect) {
    let opts = full_options().dialect(dialect).flow(Flow::AddToExisting);
    let files = emit(&opts).unwrap();

    assert_eq!(files.migration_name, "add_devise_to_users");
    assert!(!files.up_sql.contains("CREATE TABLE"));
    assert!(files.up_sql.contains("ALTER TABLE users ADD COLUMN"));
    assert!(
        files
            .up_sql
            .contains("CREATE UNIQUE INDEX index_users_on_email")
    );
    for column in ALL_COLUMNS {
        assert!(
            files.up_sql.contains(&format!("ADD COLUMN {column}")),
            "existing up.sql missing ADD COLUMN {column}"
        );
    }
    // Deterministic order matches the create flow column order.
    let positions: Vec<usize> = EMISSION_ORDER
        .iter()
        .map(|c| files.up_sql.find(&format!("ADD COLUMN {c}")).unwrap())
        .collect();
    let mut sorted = positions.clone();
    sorted.sort_unstable();
    assert_eq!(positions, sorted, "existing flow column order drifted");
    // down.sql drops every added column in reverse order.
    for column in ALL_COLUMNS {
        assert!(
            files.down_sql.contains(&format!("DROP COLUMN {column}")),
            "existing down.sql missing DROP COLUMN {column}"
        );
    }
    assert!(!files.down_sql.contains("DROP TABLE"));

    insta::assert_snapshot!(
        format!("full_{}_existing", dialect_tag(dialect)),
        format!("{}\n---\n{}", files.up_sql, files.down_sql)
    );
}

#[test]
fn lockable_none_strategies_emit_only_locked_at() {
    let opts = EmitOptions {
        modules: BTreeSet::from([Module::DatabaseAuthenticatable, Module::Lockable]),
        ..EmitOptions::new("users")
    }
    .lock_strategy(LockStrategy::None)
    .unlock_strategy(UnlockStrategy::None);
    let files = emit(&opts).unwrap();

    assert!(files.up_sql.contains("locked_at"));
    for absent in [
        "failed_attempts",
        "unlock_token",
        "index_users_on_unlock_token",
    ] {
        assert!(
            !files.up_sql.contains(absent),
            "lock-none up.sql must not contain {absent}"
        );
    }

    insta::assert_snapshot!(
        "lockable_none",
        format!("{}\n---\n{}", files.up_sql, files.down_sql)
    );
}

#[test]
fn reconfirmable_off_omits_unconfirmed_email() {
    let opts = full_options().reconfirmable(false);
    let files = emit(&opts).unwrap();

    assert!(!files.up_sql.contains("unconfirmed_email"));
    assert!(files.up_sql.contains("confirmation_token"));
    assert!(files.up_sql.contains("index_users_on_confirmation_token"));

    insta::assert_snapshot!(
        "reconfirmable_off",
        format!("{}\n---\n{}", files.up_sql, files.down_sql)
    );
}

#[test]
fn remember_token_opt_in() {
    let without = full_options();
    assert!(
        !emit(&without)
            .unwrap()
            .up_sql
            .contains("remember_token VARCHAR")
            && !emit(&without)
                .unwrap()
                .up_sql
                .contains("remember_token TEXT")
            && !emit(&without)
                .unwrap()
                .up_sql
                .contains("remember_token VARCHAR(255)"),
        "remember_token must be opt-in"
    );
    let with = full_options().remember_token(true);
    let files = emit(&with).unwrap();
    assert!(files.up_sql.contains("remember_token"));
    assert!(files.up_sql.contains("remember_created_at"));

    insta::assert_snapshot!(
        "remember_token_on",
        format!("{}\n---\n{}", files.up_sql, files.down_sql)
    );
}

#[test]
fn recoverable_adds_its_index_without_confirmation_index() {
    let opts = EmitOptions {
        modules: BTreeSet::from([Module::DatabaseAuthenticatable, Module::Recoverable]),
        ..EmitOptions::new("users")
    };
    let files = emit(&opts).unwrap();

    assert!(files.up_sql.contains("index_users_on_reset_password_token"));
    assert!(!files.up_sql.contains("index_users_on_confirmation_token"));
    assert!(!files.up_sql.contains("index_users_on_unlock_token"));
}

#[test]
fn timestamps_opt_out() {
    let opts = full_options().timestamps(false);
    let files = emit(&opts).unwrap();

    // Full-line match: `remember_created_at` contains `created_at`.
    assert!(!files.up_sql.contains("\n  created_at "));
    assert!(!files.up_sql.contains("\n  updated_at "));
    assert!(files.up_sql.contains("encrypted_password"));
}

#[test]
fn invalid_identifier_matrix() {
    for bad in ["1users", "users;DROP", "Users", "_users", "user-name"] {
        let opts = EmitOptions {
            table: bad.to_owned(),
            ..full_options()
        };
        assert!(
            matches!(emit(&opts), Err(EmitError::InvalidIdentifier(_))),
            "{bad:?} must be rejected"
        );
    }
}

/// Absolute path to the compiled `devise-migrations` binary.
///
/// Cargo exposes `CARGO_BIN_EXE_<name>` to integration tests; the dash vs
/// underscore spelling differs across toolchains, so both are probed.
fn cli_binary() -> String {
    option_env!("CARGO_BIN_EXE_devise-migrations")
        .or(option_env!("CARGO_BIN_EXE_devise_migrations"))
        .expect("devise-migrations binary was not built")
        .to_owned()
}

fn cli_tempdir(suffix: &str) -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("devise_migrations_{suffix}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn write_to_confines_writes_to_output_dir() {
    use devise_rust_migrations::MigrationFiles;

    let files = emit(&full_options()).unwrap();
    let out = cli_tempdir("confine");

    // Timestamp traversal rejected before any file exists.
    assert!(matches!(
        files.write_to(&out, "../../evil"),
        Err(EmitError::InvalidIdentifier(_))
    ));
    assert!(!out.join("evil").exists());

    // Hand-built payload with an absolute migration name cannot escape either.
    let hostile = MigrationFiles {
        migration_name: "/tmp/devise_hostile".to_owned(),
        up_sql: String::new(),
        down_sql: String::new(),
    };
    assert!(matches!(
        hostile.write_to(&out, "20260101000000"),
        Err(EmitError::InvalidIdentifier(_))
    ));

    // Happy path still writes, second write refuses to overwrite.
    let written = files.write_to(&out, "20260101000000").unwrap();
    assert!(written.join("up.sql").exists());
    assert!(matches!(
        files.write_to(&out, "20260101000000"),
        Err(EmitError::OutputExists(_))
    ));

    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn cli_smoke_writes_devise_create_layout() {
    let out = cli_tempdir("smoke");
    let status = std::process::Command::new(cli_binary())
        .args([
            "users",
            "--dialect",
            "postgres",
            "--modules",
            "all",
            "--output",
            out.to_str().unwrap(),
            "--timestamp",
            "20260101000000",
        ])
        .status()
        .unwrap();
    assert!(status.success());

    let dir = out.join("20260101000000_devise_create_users");
    let up = std::fs::read_to_string(dir.join("up.sql")).unwrap();
    let down = std::fs::read_to_string(dir.join("down.sql")).unwrap();
    assert!(up.contains("encrypted_password"));
    assert!(up.contains("CREATE UNIQUE INDEX index_users_on_email"));
    assert!(down.contains("DROP TABLE users;"));

    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn cli_existing_flow_writes_add_devise_layout() {
    let out = cli_tempdir("existing");
    let status = std::process::Command::new(cli_binary())
        .args([
            "users",
            "--dialect",
            "sqlite",
            "--pk",
            "uuid",
            "--modules",
            "all",
            "--existing",
            "--output",
            out.to_str().unwrap(),
            "--timestamp",
            "20260101000001",
        ])
        .status()
        .unwrap();
    assert!(status.success());

    let dir = out.join("20260101000001_add_devise_to_users");
    let up = std::fs::read_to_string(dir.join("up.sql")).unwrap();
    assert!(up.contains("ALTER TABLE users ADD COLUMN"));
    assert!(!up.contains("CREATE TABLE"));

    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn cli_help_lists_every_flag() {
    let output = std::process::Command::new(cli_binary())
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    for flag in [
        "--dialect",
        "--pk",
        "--modules",
        "--reconfirmable",
        "--lock-strategy",
        "--unlock-strategy",
        "--remember-token",
        "--existing",
        "--timestamps",
        "--output",
        "--timestamp",
    ] {
        assert!(stdout.contains(flag), "--help missing {flag}");
    }
}

#[test]
fn cli_unknown_module_exits_two() {
    let out = cli_tempdir("unknown");
    let output = std::process::Command::new(cli_binary())
        .args([
            "users",
            "--modules",
            "validatable",
            "--output",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("adds no devise columns"), "{stderr}");
    assert!(!out.join("migrations").exists());

    let _ = std::fs::remove_dir_all(&out);
}
