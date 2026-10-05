//! Snapshot matrix over (modules × dialect × pk × flow) plus content-identity
//! assertions (snapshots are never the only assertion on emitted content).

use std::collections::BTreeSet;

use devise_rust_migrations::{Dialect, EmitError, EmitOptions, Flow, PkKind, emit};

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
