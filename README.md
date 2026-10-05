# DEVISE-RUST

## Workspace crates

| Crate | Purpose |
|-------|---------|
| `devise-rust` | Core crate: config, crypto, parameter filter, `OrmAdapter` trait |
| `devise-rust-diesel` | Diesel/diesel-async backend implementing `OrmAdapter` — **Postgres & SQLite tested** (in-memory SQLite + testcontainers Postgres CI); **MySQL experimental** (compile-only, no CI execution) |
| `devise-rust-actix` | actix-web integration |
| `devise-rust-axum` | axum integration |
| `devise-rust-migrations` | ORM-agnostic devise-parity migration generator (`emit()` library + `devise-migrations` CLI): `cargo run -p devise-rust-migrations --bin devise-migrations -- users --dialect postgres --modules all` |

## Diesel backend dialect status

| Dialect | Status | Notes |
|---------|--------|-------|
| Postgres | Tested | testcontainers CI + in-memory verification; native UUID, INET columns |
| SQLite | Tested | in-memory, max_size(1) pool; UUID stored as TEXT |
| MySQL | Experimental | Compile-only (`mysql` feature); no CI execution (mysql_async lacks rust_version metadata) |