# devise-rust

[![Crates.io](https://img.shields.io/crates/v/devise-rust.svg)](https://crates.io/crates/devise-rust)
[![Documentation](https://docs.rs/devise-rust/badge.svg)](https://docs.rs/devise-rust)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-orange.svg)](https://github.com/rust-lang/rfcs/blob/master/text/2495-min-rust-version.md)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/gilcierweb/devise-rust/workflows/CI/badge.svg)](https://github.com/gilcierweb/devise-rust/actions)

> **A faithful Rust port of the Devise Ruby gem (v5.0.4)** - modular, full-featured authentication for Rust web applications with actix-web and axum.

devise-rust preserves Devise's public API wherever Rust allows: the same 10 modules (`database_authenticatable`, `registerable`, `recoverable`, `rememberable`, `validatable`, `trackable`, `confirmable`, `lockable`, `timeoutable`, `omniauthable` over the `authenticatable` base), the same method names (`valid_password`, `lock_access`, `reset_password_by_token`, `confirm_by_token`, ...), the same DB column names (`encrypted_password`, `reset_password_token`, ...), the same config option names (`stretches`, `pepper`, `remember_for`, `reset_password_within`, ...), the same I18n message keys, and the same route/action surface - adapted to idiomatic, DRY, high-quality Rust.

Documentation: start with [docs/getting-started-actix.md](docs/getting-started-actix.md) (shared core setup plus the actix-web track); the axum track and the rest of the guide corpus live under [docs/](docs/).

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            devise-rust Workspace                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐   ┌─────────────────┐   ┌──────────────────────────┐  │
│  │  devise-rust    │   │devise-rust-diesel│  │ devise-rust-migrations   │  │
│  │  (core)         │◄──┤ (diesel-async)   │  │ (ORM-agnostic DDL + CLI) │  │
│  │                 │   │                 │  │                          │  │
│  │ • DeviseConfig  │   │ • DieselOrmAdapter│  │ • emit() library         │  │
│  │ • Crypto        │   │ • DieselModel glue  │  │ • devise-migrations CLI  │  │
│  │ • TokenGenerator│   │ • Changeset bridge│  │ • Per-module columns     │  │
│  │ • ParameterFilter│  │ • Pool ownership  │  │ • PG/SQLite/MySQL DDL    │  │
│  │ • OrmAdapter trait│  │ • PG/SQLite/MySQL │  │ • UUID/BigInt PKs        │  │
│  │ • I18n catalog  │   │ • testcontainers  │  │                          │  │
│  │ • Mailer trait  │   │                   │  │                          │  │
│  │ • Model modules │   │                   │  │                          │  │
│  │ • Session/Strategies│ │                   │  │                          │  │
│  └────────┬────────┘   └────────┬────────┘   └────────────┬───────────────┘  │
│           │                     │                        │                    │
│           │                     │                        │                    │
│           ▼                     ▼                        ▼                    │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                    Framework Integrations                            │   │
│  ├──────────────────────────────────────────────────────────────────────┤   │
│  │  ┌─────────────────────┐                    ┌─────────────────────┐  │   │
│  │  │ devise-rust-actix   │                    │ devise-rust-axum    │  │   │
│  │  │                     │                    │                     │  │   │
│  │  │ • actix-session     │                    │ • tower-sessions    │  │   │
│  │  │   bridge            │                    │   bridge            │  │   │
│  │  │ • Auth<User>        │                    │ • FromRequestParts  │  │   │
│  │  │   extractor         │                    │   extractors        │  │   │
│  │  │ • Guards/Helpers    │                    │ • Router fn         │  │   │
│  │  │ • devise_for macro  │                    │ • devise_for macro  │  │   │
│  │  │ • Test helpers      │                    │ • Test helpers      │  │   │
│  │  └─────────────────────┘                    └─────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Module Stack (Devise Parity Order)

```
authenticatable (base)
├── database_authenticatable  ← password hashing, validation, salt
├── rememberable              ← remember-me cookie codec (5 conditions)
├── omniauthable              ← OAuth2 provider registry
├── recoverable               ← reset password token lifecycle
├── registerable              ← sign up / account update
├── validatable               ← email/password validations
├── confirmable               ← email confirmation + reconfirmable (#5783)
├── lockable                  ← failed attempts, time/email unlock
├── timeoutable               ← session timeout + remember exemption
└── trackable                 ← sign_in_count, IPs, timestamps
```

---

## Quick Start

### Prerequisites

- **Rust 1.85+** (MSRV pinned; `rustup install 1.85`)
- **PostgreSQL 14+** or **SQLite 3.35+** (for `RETURNING` clause support)
- **Docker** (optional, for containerized development)

### Add to Your Project

```toml
# Cargo.toml
[dependencies]
# Core (required)
devise-rust = { version = "0.1", features = ["test-utils"] }

# Choose ONE backend:
devise-rust-diesel = { version = "0.1", features = ["postgres", "sqlite"] }
# OR (planned)
# devise-rust-sqlx = { version = "0.1", features = ["postgres", "sqlite"] }
# devise-rust-sea-orm = { version = "0.1", features = ["postgres", "sqlite"] }

# Choose ONE framework integration:
devise-rust-actix = "0.1"  # actix-web 4.x
# OR
devise-rust-axum = "0.1"   # axum 0.7+

# Migrations (optional, for schema generation)
devise-rust-migrations = { version = "0.1", features = [] }
```

### Minimal Example (Actix-web + Diesel)

```rust
// Cargo.toml features: devise-rust-diesel = { features = ["postgres", "sqlite"] }
use devise_rust::{DeviseConfig, DeviseKey, OrmAdapter};
use devise_rust_diesel::{DieselOrmAdapter, DieselModel};
use actix_web::{web, App, HttpServer, middleware};
use actix_session::{SessionMiddleware, storage::CookieSessionStore};

#[derive(Debug, Clone, DieselModel)]
#[devise_rust(table = "users", pk = "id")]
struct User {
    id: i64,
    email: String,
    encrypted_password: String,
    // ... other devise columns
}

// Configure Devise
let config = DeviseConfig::builder()
    .pepper("your-secret-pepper")
    .stretches(12)
    .remember_for(std::time::Duration::from_secs(2 * 7 * 24 * 60 * 60)) // 2 weeks
    .build();

let pool = diesel_async::pooled_connection::deadpool::Pool::builder()
    .build(DATABASE_URL.parse()?)?;

let adapter = DieselOrmAdapter::<User>::new(pool);

HttpServer::new(move || {
    App::new()
        .wrap(SessionMiddleware::new(
            CookieSessionStore::default(),
            config.secret_key().clone(),
        ))
        .app_data(web::Data::new(adapter.clone()))
        .configure(devise_rust_actix::devise_for::<User>())
        .route("/protected", web::get().to(protected_handler))
})
.bind("127.0.0.1:8080")?
.run()
.await
```

---

## Docker Development Environment

### docker-compose.yml

```yaml
version: '3.8'

services:
  app:
    build:
      context: .
      dockerfile: Dockerfile.dev
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=postgres://devise:devise@db:5432/devise_rust
      - RUST_LOG=devise_rust=debug,actix_web=info
      - DEVISE_PEPPER=your-development-pepper-change-in-production
      - DEVISE_SECRET_KEY=your-secret-key-min-32-chars-change-in-production
    volumes:
      - .:/app
      - cargo-cache:/usr/local/cargo/registry
      - target-cache:/app/target
    depends_on:
      db:
        condition: service_healthy
    command: cargo watch -x "run --example actix_minimal"

  db:
    image: postgres:16-alpine
    environment:
      - POSTGRES_USER=devise
      - POSTGRES_PASSWORD=devise
      - POSTGRES_DB=devise_rust
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U devise -d devise_rust"]
      interval: 5s
      timeout: 3s
      retries: 10

  # Optional: Run migrations automatically
  migrate:
    build:
      context: .
      dockerfile: Dockerfile.dev
    environment:
      - DATABASE_URL=postgres://devise:devise@db:5432/devise_rust
    depends_on:
      db:
        condition: service_healthy
    command: cargo run -p devise-rust-migrations --bin devise-migrations -- users --dialect postgres --modules all --apply

volumes:
  pgdata:
  cargo-cache:
  target-cache:
```

### Dockerfile.dev

```dockerfile
# syntax = docker/dockerfile:1.4
FROM rust:1.85-bookworm AS base

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev \
    libsqlite3-dev \
    pkg-config \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install cargo-watch for hot reload
RUN cargo install cargo-watch

WORKDIR /app

# Cache dependencies
COPY Cargo.toml Cargo.lock ./
COPY crates/devise-rust/Cargo.toml crates/devise-rust/
COPY crates/devise-rust-diesel/Cargo.toml crates/devise-rust-diesel/
COPY crates/devise-rust-actix/Cargo.toml crates/devise-rust-actix/
COPY crates/devise-rust-axum/Cargo.toml crates/devise-rust-axum/
COPY crates/devise-rust-migrations/Cargo.toml crates/devise-rust-migrations/

RUN mkdir -p crates/devise-rust/src \
    crates/devise-rust-diesel/src \
    crates/devise-rust-actix/src \
    crates/devise-rust-axum/src \
    crates/devise-rust-migrations/src \
    && echo "fn main() {}" > crates/devise-rust/src/lib.rs \
    && echo "fn main() {}" > crates/devise-rust-diesel/src/lib.rs \
    && echo "fn main() {}" > crates/devise-rust-actix/src/lib.rs \
    && echo "fn main() {}" > crates/devise-rust-axum/src/lib.rs \
    && echo "fn main() {}" > crates/devise-rust-migrations/src/lib.rs \
    && cargo build --workspace 2>/dev/null || true

# Copy source
COPY . .

# Final build
RUN cargo build --workspace

EXPOSE 8080
CMD ["cargo", "run", "--example", "actix_minimal"]
```

### Dockerfile.prod (Multi-stage)

```dockerfile
# syntax = docker/dockerfile:1.4
FROM rust:1.85-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev libsqlite3-dev pkg-config ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY crates/*/Cargo.toml crates/*/
RUN mkdir -p crates/*/src && \
    for crate in devise-rust devise-rust-diesel devise-rust-actix devise-rust-axum devise-rust-migrations; do \
        echo "fn main() {}" > crates/$crate/src/lib.rs; \
    done

RUN cargo build --workspace --release 2>/dev/null || true

COPY . .
RUN cargo build --workspace --release

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 libsqlite3-0 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/your-app /app/your-app
COPY --from=builder /app/migrations /app/migrations

ENV RUST_LOG=info
EXPOSE 8080

CMD ["./your-app"]
```

---

## Configuration Reference

### DeviseConfig (Complete Options)

```rust
use devise_rust::DeviseConfig;
use std::time::Duration;

let config = DeviseConfig::builder()
    // Crypto
    .secret_key("base64-encoded-32-byte-secret")     // REQUIRED
    .pepper("optional-pepper-string")                 // Default: none
    .stretches(12)                                    // Default: 12 (bcrypt cost)

    // Authentication keys
    .authentication_keys(vec!["email"])               // Default: ["email"]
    .request_keys(vec![])                             // Default: []
    .case_insensitive_keys(vec!["email"])             // Default: ["email"]
    .strip_whitespace_keys(vec!["email"])             // Default: ["email"]

    // HTTP Auth
    .http_authenticatable(false)                      // Default: false
    .http_authentication_key(None)                    // Default: None
    .http_authenticatable_on_xhr(true)                // Default: true
    .http_authentication_realm("Application".into())  // Default: "Application"

    // Params Auth
    .params_authenticatable(true)                     // Default: true

    // Validation
    .email_regexp(regex::Regex::new(r"^[^@\s]+@[^@\s]+\z").unwrap()) // Devise default
    .password_length(6..=128)                         // Default: 6..128

    // Rememberable
    .remember_for(Duration::from_secs(2 * 7 * 24 * 60 * 60)) // 2 weeks
    .extend_remember_period(false)                    // Default: false
    .expire_all_remember_me_on_sign_out(true)         // Default: true
    .rememberable_options(std::collections::HashMap::new()) // Default: {}

    // Confirmable
    .allow_unconfirmed_access_for(Duration::from_secs(0))   // Default: 0
    .confirm_within(None)                               // Default: None (no expiry)
    .confirmation_keys(vec!["email"])                   // Default: ["email"]
    .reconfirmable(true)                                // Default: true

    // Lockable
    .lock_strategy(devise_rust::LockStrategy::FailedAttempts) // Default
    .unlock_strategy(devise_rust::UnlockStrategy::Both)       // Default
    .maximum_attempts(20)                                 // Default: 20
    .unlock_in(Duration::from_secs(3600))                 // 1 hour
    .unlock_keys(vec!["email"])                           // Default: ["email"]
    .last_attempt_warning(true)                           // Default: true

    // Recoverable
    .reset_password_keys(vec!["email"])                   // Default: ["email"]
    .reset_password_within(Duration::from_secs(6 * 3600)) // 6 hours
    .sign_in_after_reset_password(true)                   // Default: true

    // Timeoutable
    .timeout_in(Duration::from_secs(30 * 60))             // 30 minutes

    // Sessions
    .sign_out_all_scopes(true)                            // Default: true
    .sign_out_via(devise_rust::SignOutVia::Delete)        // Default: DELETE
    .skip_session_storage(vec!["http_auth"])              // Default: ["http_auth"]

    // Mailer
    .mailer_sender("no-reply@example.com".into())         // REQUIRED for mail
    .send_email_changed_notification(false)               // Default: false
    .send_password_change_notification(false)             // Default: false
    .sign_in_after_change_password(true)                  // Default: true

    // Paranoid mode (uniform error messages)
    .paranoid(false)                                      // Default: false

    // Omniauth
    .omniauth_path_prefix("/auth".into())                 // Default: "/auth"
    .omniauth_providers(vec![])                           // Configure per provider

    .build()?;
```

### Environment Variables (Production)

```bash
# Required
DEVISE_SECRET_KEY=base64-encoded-32-byte-secret
DEVISE_MAILER_SENDER=no-reply@yourdomain.com

# Optional (with defaults shown)
DEVISE_PEPPER=your-pepper-string
DEVISE_STRETCHES=12
DEVISE_REMEMBER_FOR=1209600           # 2 weeks in seconds
DEVISE_TIMEOUT_IN=1800                 # 30 minutes
DEVISE_MAXIMUM_ATTEMPTS=20
DEVISE_UNLOCK_IN=3600                  # 1 hour
DEVISE_RESET_PASSWORD_WITHIN=21600     # 6 hours
DEVISE_PARANOID=false
DEVISE_ALLOW_UNCONFIRMED_ACCESS_FOR=0
DEVISE_CONFIRM_WITHIN=                 # empty = no expiry
DEVISE_RECONFIRMABLE=true
DEVISE_EXTEND_REMEMBER_PERIOD=false
DEVISE_EXPIRE_ALL_REMEMBER_ME_ON_SIGN_OUT=true
DEVISE_SIGN_IN_AFTER_RESET_PASSWORD=true
DEVISE_SIGN_IN_AFTER_CHANGE_PASSWORD=true
DEVISE_SIGN_OUT_ALL_SCOPES=true
DEVISE_SIGN_OUT_VIA=delete
DEVISE_HTTP_AUTHENTICATABLE=false
DEVISE_HTTP_AUTHENTICATABLE_ON_XHR=true
DEVISE_PARAMS_AUTHENTICATABLE=true
```

Load with `config-rs` or manually:

```rust
let config = DeviseConfig::builder()
    .secret_key(std::env::var("DEVISE_SECRET_KEY")?)
    .mailer_sender(std::env::var("DEVISE_MAILER_SENDER")?)
    .pepper(std::env::var("DEVISE_PEPPER").ok())
    .stretches(std::env::var("DEVISE_STRETCHES").unwrap_or("12".into()).parse()?)
    // ... etc
    .build()?;
```

---

## Database Schema

### Generated Migration (devise-rust-migrations)

```bash
# Install CLI
cargo install --path devise-rust/crates/devise-rust-migrations

# Generate migration for all modules
devise-migrations users \
  --dialect postgres \
  --modules all \
  --pk-type bigint \
  --output migrations/001_devise_users.sql

# Or individual modules
devise-migrations users \
  --dialect sqlite \
  --modules database_authenticatable,confirmable,lockable,recoverable,rememberable,trackable \
  --pk-type uuid
```

### Core Tables (PostgreSQL Example)

```sql
-- Users table with all Devise modules
CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    encrypted_password VARCHAR(255) NOT NULL,

    -- rememberable
    remember_created_at TIMESTAMPTZ,
    remember_token VARCHAR(255),

    -- confirmable
    confirmation_token VARCHAR(255),
    confirmed_at TIMESTAMPTZ,
    confirmation_sent_at TIMESTAMPTZ,
    unconfirmed_email VARCHAR(255),

    -- lockable
    failed_attempts INTEGER DEFAULT 0 NOT NULL,
    locked_at TIMESTAMPTZ,
    unlock_token VARCHAR(255),

    -- recoverable
    reset_password_token VARCHAR(255),
    reset_password_sent_at TIMESTAMPTZ,

    -- trackable
    sign_in_count INTEGER DEFAULT 0 NOT NULL,
    current_sign_in_at TIMESTAMPTZ,
    last_sign_in_at TIMESTAMPTZ,
    current_sign_in_ip INET,
    last_sign_in_ip INET,

    -- timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE UNIQUE INDEX index_users_on_email ON users (email);
CREATE UNIQUE INDEX index_users_on_confirmation_token ON users (confirmation_token);
CREATE UNIQUE INDEX index_users_on_reset_password_token ON users (reset_password_token);
CREATE UNIQUE INDEX index_users_on_unlock_token ON users (unlock_token);
CREATE UNIQUE INDEX index_users_on_remember_token ON users (remember_token);
```

### Apply Migrations

```bash
# Using SQLx (recommended for sqlx projects)
sqlx migrate run --database-url $DATABASE_URL

# Using diesel
diesel migration run --database-url $DATABASE_URL

# Using psql directly
psql $DATABASE_URL -f migrations/001_devise_users.sql
```

---

## Framework Integration Examples

### Actix-web (devise-rust-actix)

```rust
// examples/actix_minimal.rs
use actix_web::{web, App, HttpServer, HttpResponse, Responder};
use actix_session::{SessionMiddleware, storage::CookieSessionStore, config::PersistentSession};
use devise_rust::DeviseConfig;
use devise_rust_diesel::{DieselOrmAdapter, DieselModel};
use devise_rust_actix::{devise_for, Auth, authenticate};

#[derive(Debug, Clone, DieselModel)]
#[devise_rust(table = "users", pk = "id")]
struct User {
    id: i64,
    email: String,
    encrypted_password: String,
    // Add all devise columns here...
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let config = DeviseConfig::builder()
        .secret_key("your-secret-key-here-min-32-chars")
        .mailer_sender("no-reply@example.com")
        .build()
        .expect("Invalid config");

    let pool = diesel_async::pooled_connection::deadpool::Pool::builder()
        .build(std::env::var("DATABASE_URL")?)?;

    let adapter = DieselOrmAdapter::<User>::new(pool);

    HttpServer::new(move || {
        App::new()
            .wrap(SessionMiddleware::builder(CookieSessionStore::default(), config.secret_key().clone())
                .cookie_secure(false) // Set true in production with HTTPS
                .session_lifecycle(PersistentSession::default().session_ttl(
                    std::time::Duration::from_secs(2 * 7 * 24 * 60 * 60)
                ))
                .build())
            .app_data(web::Data::new(config.clone()))
            .app_data(web::Data::new(adapter.clone()))
            .configure(devise_for::<User>())  // Registers all devise routes
            .service(web::resource("/protected").route(web::get().to(protected)))
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}

async fn protected(user: Auth<User>) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "message": "Hello, authenticated user!",
        "user_id": user.id,
        "email": user.email,
    }))
}
```

#### Actix-web Routes Generated

| Method | Path | Controller | Action |
|--------|------|------------|--------|
| GET | `/users/sign_in` | Sessions | new |
| POST | `/users/sign_in` | Sessions | create |
| DELETE | `/users/sign_out` | Sessions | destroy |
| GET | `/users/sign_up` | Registrations | new |
| POST | `/users` | Registrations | create |
| GET | `/users/edit` | Registrations | edit |
| PUT/PATCH | `/users` | Registrations | update |
| DELETE | `/users` | Registrations | destroy |
| GET | `/users/password/new` | Passwords | new |
| POST | `/users/password` | Passwords | create |
| GET | `/users/password/edit` | Passwords | edit |
| PUT/PATCH | `/users/password` | Passwords | update |
| GET | `/users/confirmation/new` | Confirmations | new |
| POST | `/users/confirmation` | Confirmations | create |
| GET | `/users/confirmation` | Confirmations | show |
| GET | `/users/unlock/new` | Unlocks | new |
| POST | `/users/unlock` | Unlocks | create |
| GET | `/users/unlock` | Unlocks | show |

### Axum (devise-rust-axum)

```rust
// examples/axum_minimal.rs
use axum::{
    Router, routing::{get, post}, extract::State, response::Json,
    middleware, http::StatusCode,
};
use axum_sessions::SessionLayer;
use tower_sessions::{MemoryStore, Expiry};
use devise_rust::DeviseConfig;
use devise_rust_diesel::{DieselOrmAdapter, DieselModel};
use devise_rust_axum::{devise_for, Auth, auth_required};

#[derive(Debug, Clone, DieselModel)]
#[devise_rust(table = "users", pk = "id")]
struct User {
    id: i64,
    email: String,
    encrypted_password: String,
    // ...
}

#[tokio::main]
async fn main() {
    let config = DeviseConfig::builder()
        .secret_key("your-secret-key-here-min-32-chars")
        .mailer_sender("no-reply@example.com")
        .build()
        .expect("Invalid config");

    let pool = diesel_async::pooled_connection::deadpool::Pool::builder()
        .build(std::env::var("DATABASE_URL").unwrap())?;

    let adapter = DieselOrmAdapter::<User>::new(pool);
    let session_store = MemoryStore::default();

    let app = Router::new()
        .route("/protected", get(protected))
        .layer(middleware::from_fn_with_state(
            adapter.clone(),
            auth_required::<User>,
        ))
        .merge(devise_for::<User>(config.clone(), adapter.clone()))
        .layer(SessionLayer::new(session_store).with_expiry(Expiry::OnInactivity(
            std::time::Duration::from_secs(2 * 7 * 24 * 60 * 60)
        )))
        .with_state((config, adapter));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn protected(Auth(user): Auth<User>) -> Result<Json<serde_json::Value>, StatusCode> {
    Ok(Json(serde_json::json!({
        "message": "Hello, authenticated user!",
        "user_id": user.id,
    })))
}
```

---

## Testing

### Run All Tests

```bash
# Unit tests (in-memory SQLite, no Docker)
cargo test --workspace --features sqlite

# Integration tests with Postgres (requires Docker)
cargo test --workspace --features e2e-pg

# Specific crate
cargo test -p devise-rust --features sqlite
cargo test -p devise-rust-diesel --features sqlite
cargo test -p devise-rust-actix --features sqlite

# Linting
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --check --workspace

# MSRV check
cargo +1.85 check --workspace --locked --manifest-path Cargo.toml.msrv
```

### Test Structure

```
devise-rust/
├── tests/
│   ├── adapter.rs          # Core adapter contract tests
│   ├── config.rs           # DeviseConfig cascade tests
│   ├── crypto.rs           # bcrypt, TokenGenerator, secure_compare
│   ├── parameter.rs        # ParameterFilter/Sanitizer
│   └── model/              # Module tests (mirrors Devise test suite)
│       ├── database_authenticatable.rs
│       ├── validatable.rs
│       ├── recoverable.rs
│       ├── confirmable.rs
│       ├── lockable.rs
│       ├── rememberable.rs
│       ├── timeoutable.rs
│       └── trackable.rs
└── benches/
    └── crypto.rs           # bcrypt performance
```

### Parity Test Suite

devise-rust ports Devise's own test matrices:

- `devise/test/models/*_test.rb` → `devise-rust/tests/model/*.rs`
- `devise/test/integration/*_test.rb` → framework-specific integration tests
- `devise/test/devise_test.rb` → core crypto/config tests

Run the parity verification:

```bash
# Full parity matrix (requires Postgres container)
cargo test --workspace --features e2e-pg parity

# Security regression suite (TEST-03)
cargo test -p devise-rust security_regression
```

---

## Security

### Built-in Protections

| Protection | Implementation |
|------------|----------------|
| **Timing-safe compare** | `subtle::ConstantTimeEq` for all token/password comparisons |
| **Digest-only token storage** | HMAC-SHA256 digests in DB; raw tokens only in emails |
| **Session salt invalidation** | Password change → salt mismatch → old sessions rejected |
| **Paranoid mode** | Uniform `:invalid` error; dummy bcrypt for unknown accounts |
| **Secret filtering** | `UNSAFE_ATTRIBUTES_FOR_SERIALIZATION` excluded from `Debug`/`Serialize` |
| **Bcrypt cost** | Configurable `stretches` (default 12); runs in `spawn_blocking` |
| **CSRF protection** | Framework bridge callbacks (`handle_unverified_request`) |

### Security Configuration (Production)

```rust
let config = DeviseConfig::builder()
    .paranoid(true)                    // Enable uniform errors
    .pepper("strong-random-pepper")    // Additional secret mixed into bcrypt
    .stretches(14)                     // Higher cost for production
    .http_authenticatable(false)       // Disable HTTP Basic unless needed
    .skip_session_storage(vec!["http_auth"])
    .expire_all_remember_me_on_sign_out(true)
    .sign_out_all_scopes(true)
    .build()?;
```

### Reporting Vulnerabilities

Email security@gilcierweb.dev with details. See [SECURITY.md](SECURITY.md) for full policy.

---

## Migration from Devise (Rails)

| Devise | devise-rust |
|--------|-------------|
| `devise :database_authenticatable, :registerable` | `#[derive(DeviseModules)]` or manual trait impl |
| `config.stretches = 12` | `DeviseConfig::builder().stretches(12)` |
| `config.pepper = "..."` | `.pepper("...")` |
| `config.remember_for = 2.weeks` | `.remember_for(Duration::from_secs(2*7*24*60*60))` |
| `User.find_for_database_authentication` | `OrmAdapter::find_first` + `valid_password` |
| `after_database_authentication` | Model hook `after_database_authentication` |
| `devise_for :users` | `devise_for::<User>()` (actix) / `devise_for::<User>()` (axum) |
| `current_user` | `Auth<User>` extractor / `current_user` helper |
| `user_signed_in?` | `user_signed_in?()` helper / `Auth<User>::optional()` |
| `confirm_by_token(token)` | `Confirmable::confirm_by_token(token)` |
| `reset_password_by_token(attrs)` | `Recoverable::reset_password_by_token(attrs)` |

### Column Mapping (Exact Match)

```
Devise column          → devise-rust column
encrypted_password     → encrypted_password
reset_password_token   → reset_password_token
reset_password_sent_at → reset_password_sent_at
remember_created_at    → remember_created_at
remember_token         → remember_token (optional)
confirmation_token     → confirmation_token
confirmed_at           → confirmed_at
confirmation_sent_at   → confirmation_sent_at
unconfirmed_email      → unconfirmed_email
failed_attempts        → failed_attempts
locked_at              → locked_at
unlock_token           → unlock_token
sign_in_count          → sign_in_count
current_sign_in_at     → current_sign_in_at
last_sign_in_at        → last_sign_in_at
current_sign_in_ip     → current_sign_in_ip
last_sign_in_ip        → last_sign_in_ip
```

---

## Roadmap

| Phase | Status | Description |
|-------|--------|-------------|
| **1** | ✅ Done | Core: config, crypto, i18n, parameter filter, OrmAdapter trait |
| **2** | ✅ Done | Diesel backend + migration generator |
| **3** | ✅ Done | Warden core: sessions, strategies, hooks, failure app |
| **4** | 🚧 In Progress | Mailer + database_authenticatable, validatable, registerable, recoverable |
| **5** | ⏳ Planned | Account-hygiene: confirmable, lockable, rememberable, timeoutable, trackable |
| **6** | ⏳ Planned | sqlx & sea-orm backends (proving trait portability) |
| **7** | ⏳ Planned | actix-web integration |
| **8** | ⏳ Planned | axum integration + omniauthable |
| **9** | ⏳ Planned | Docs, parity closure, v1 release |

---

## Contributing

```bash
# Fork → Clone → Branch
git checkout -b feat/your-feature

# Make changes, ensure:
cargo test --workspace --features sqlite
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --check --workspace

# Commit (Conventional Commits)
git commit -m "feat(scope): description"

# Push → PR
```

### Code Standards

- **Edition**: 2024
- **MSRV**: 1.85 (enforced in CI)
- **Linting**: `clippy::all + clippy::pedantic` as warnings → `-D warnings` in CI
- **Unsafe**: `unsafe_code = warn` (no unsafe in core)
- **Documentation**: All public API documented with rustdoc (Options + Examples sections)
- **Naming**: Devise parity preserved (snake_case, predicates without `?`, mutators without `!`)

---

## License

MIT License - matching Devise. See [LICENSE](LICENSE) for details.

---

## Acknowledgments

- **Devise** by [Plataformatec](https://github.com/heartcombo/devise) - the inspiration and behavioral contract
- **Warden** - the architectural foundation (Rack middleware)
- **bcrypt** - password hashing
- **diesel-async** - async ORM foundation
- **actix-web / axum** - framework integrations
- **lettre + Tera** - mailer implementation

---

## Links

- **Documentation**: https://docs.rs/devise-rust
- **Repository**: https://github.com/gilcierweb/devise-rust
- **Issues**: https://github.com/gilcierweb/devise-rust/issues
- **Discussions**: https://github.com/gilcierweb/devise-rust/discussions
- **Devise Reference**: https://github.com/heartcombo/devise