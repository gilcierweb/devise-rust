# DEVISE-RUST

## Workspace crates

| Crate | Purpose |
|-------|---------|
| `devise-rust` | Core crate: config, crypto, parameter filter, `OrmAdapter` trait |
| `devise-rust-diesel` | Diesel/diesel-async backend implementing `OrmAdapter` |
| `devise-rust-actix` | actix-web integration |
| `devise-rust-axum` | axum integration |
| `devise-rust-migrations` | ORM-agnostic devise-parity migration generator (`emit()` library + `devise-migrations` CLI): `cargo run -p devise-rust-migrations --bin devise-migrations -- users --dialect postgres --modules all` |

