# devise-rust

[![Crates.io](https://img.shields.io/crates/v/devise-rust.svg)](https://crates.io/crates/devise-rust)
[![Documentation](https://docs.rs/devise-rust/badge.svg)](https://docs.rs/devise-rust)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-orange.svg)](https://github.com/rust-lang/rfcs/blob/master/text/2495-min-rust-version.md)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE-MIT)
[![CI](https://github.com/gilcierweb/devise-rust/workflows/CI/badge.svg)](https://github.com/gilcierweb/devise-rust/actions)
[![Docs](https://github.com/gilcierweb/devise-rust/workflows/Docs/badge.svg)](https://github.com/gilcierweb/devise-rust/actions/workflows/docs.yml)

> **A faithful Rust port of the Devise Ruby gem (v5.0.4)** - modular, full-featured authentication for Rust web applications with actix-web and axum.

devise-rust preserves Devise's public API wherever Rust allows: the same 10 modules (`database_authenticatable`, `registerable`, `recoverable`, `rememberable`, `validatable`, `trackable`, `confirmable`, `lockable`, `timeoutable`, `omniauthable` over the `authenticatable` base), the same method names (`valid_password`, `lock_access`, `reset_password_by_token`, `confirm_by_token`, ...), the same DB column names (`encrypted_password`, `reset_password_token`, ...), the same config option names (`stretches`, `pepper`, `remember_for`, `reset_password_within`, ...), the same I18n message keys, and the same route/action surface - adapted to idiomatic, DRY, high-quality Rust.

## Documentation hub

| Resource | Link |
|----------|------|
| Getting started (actix track, shared core setup) | [docs/getting-started-actix.md](docs/getting-started-actix.md) |
| Getting started (axum track) | [docs/getting-started-axum.md](docs/getting-started-axum.md) |
| Configuration reference | [docs/configuration.md](docs/configuration.md) |
| Per-module pages (Options + Examples) | [docs/modules/](docs/modules/) |
| Rails concept mapping | [docs/rails-mapping.md](docs/rails-mapping.md) |
| API reference | [docs.rs/devise-rust](https://docs.rs/devise-rust) and per-crate pages on docs.rs |
| Example app (actix) | [crates/devise-rust-actix/examples/actix-demo/main.rs](crates/devise-rust-actix/examples/actix-demo/main.rs) |
| Example app (axum) | [crates/devise-rust-axum/examples/axum-demo/main.rs](crates/devise-rust-axum/examples/axum-demo/main.rs) |
| Security policy | [SECURITY.md](SECURITY.md) |
| Changelog | [CHANGELOG.md](CHANGELOG.md) |

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
│  │  │ • devise_for routes │                    │ • devise_for routes │  │   │
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
- A database: SQLite for local development, Postgres for production

### Add to Your Project

```toml
[dependencies]
# Core (required)
devise-rust = "0.1"

# Choose ONE backend:
devise-rust-diesel = { version = "0.1", features = ["sqlite"] }   # or ["postgres"]
# OR
devise-rust-sqlx = { version = "0.1", features = ["sqlite"] }     # or ["postgres"]
# OR
devise-rust-sea-orm = { version = "0.1", features = ["sqlite"] }  # or ["postgres"]

# Choose ONE framework integration:
devise-rust-actix = "0.1"   # actix-web 4.12
# OR
devise-rust-axum = "0.1"    # axum 0.8

# Schema generation (optional)
devise-rust-migrations = "0.1"
```

### Minimal setup, both frameworks side by side

The two tracks are symmetrical: same `DeviseConfig`, same `Mapping`, same
module traits; only the wiring differs. Full walkthroughs:
[docs/getting-started-actix.md](docs/getting-started-actix.md) and
[docs/getting-started-axum.md](docs/getting-started-axum.md).

<!-- text fences: framework wiring needs sibling crates; cargo compiles rustdoc
     fences only in the core crate, so these blocks are kept in sync with the
     compiled example apps instead -->
**actix-web:**

```text
let config = Arc::new(DeviseConfig { secret_key: env_secret(), ..DeviseConfig::default() });
let key = devise_rust_actix::derive_actix_key(&config.secret_key).expect("derive session key");
let (mapping, adapter) = user_scope(&pool);
let middleware = devise_rust_actix::DeviseMiddleware::new(/* session store, registry, config */)
    .with_finder("user", Arc::new(AdapterBridge::new(adapter.clone())));
App::new().wrap(middleware)
    .wrap(SessionMiddleware::builder(CookieSessionStore::default(), key).build())
    .service(devise_rust_actix::devise_for_users(web::Data::new(user_state)))
    .route("/private", web::get().to(private))
```

**axum:**

```text
let config = Arc::new(DeviseConfig { secret_key: env_secret(), ..DeviseConfig::default() });
let state = devise_rust_axum::DeviseWebState::<User, _, TestMailer>::new(/* mapping, config, adapter, mailer, clock */)
    .expect("state builds").with_all_scopes(vec!["user".to_string()]);
let devise_layer = devise_rust_axum::DeviseLayer::new(/* registry, config */).with_hooks(/* hooks */);
Router::new().route("/private", get(private))
    .merge(devise_rust_axum::devise_for_router(state))
    .layer(devise_layer)
    .layer(session_manager_layer)
```

Protecting a handler is the same shape in both frameworks:

```text
async fn private(user: Auth<User>) -> impl Responder {          // current_user shape
    match user.user() { Some(u) => ok(u.email), None => unauthorized() }
}
```

The full runnable versions (pool, mapping, session layer, protected
handler) live in the getting-started guides and the example apps linked in
the [hub](#documentation-hub).

---

## Feature Matrix

Module coverage by backend and framework integration. All combinations
below are implemented and gated by the shared backend contract suite plus
the per-framework controller flow tests.

| Module | diesel | sqlx | sea-orm | actix | axum |
|--------|--------|------|---------|-------|------|
| `database_authenticatable` | yes | yes | yes | yes | yes |
| `rememberable` | yes | yes | yes | yes | yes |
| `omniauthable` | yes | yes | yes | yes | yes |
| `recoverable` | yes | yes | yes | yes | yes |
| `registerable` | yes | yes | yes | yes | yes |
| `validatable` | yes | yes | yes | yes | yes |
| `confirmable` | yes | yes | yes | yes | yes |
| `lockable` | yes | yes | yes | yes | yes |
| `timeoutable` | yes | yes | yes | yes | yes |
| `trackable` | yes | yes | yes | yes | yes |

Every cell is proven by the shared adapter contract suite (diesel, sqlx,
sea-orm on SQLite and Postgres) and by the per-framework browser-parity
flow matrices (`omniauth_flows` plus the controller suites) running in CI.

### Out of scope

The following are intentionally out of scope for v1, mirroring the Devise
ecosystem's own boundaries:

- **JWT / stateless token auth**: Devise itself is session-cookie based;
  token-auth API mode is not part of parity.
- **2FA / TOTP**: third-party territory in the Devise ecosystem too.
- **MongoDB (Mongo v2)**: the mongodb adapter is deferred to v2; the
  `OrmAdapter` trait hardens on SQL backends first.
- **Authorization** (CanCanCan-style abilities, rolify-style roles):
  separate companion projects.

---

## Testing

```bash
cargo test --all                                     # full workspace
cargo test -p devise-rust-diesel --features e2e-pg    # testcontainers Postgres leg (needs Docker)
cargo test -p devise-rust                            # core suites (model, strategy, security regressions)

cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

CI additionally runs the MSRV job: `cp Cargo.lock.msrv Cargo.lock` then
`cargo +1.85 test --all --locked`, and the docs gate
([.github/workflows/docs.yml](.github/workflows/docs.yml)): rustdoc with
`-D warnings`, markdown link checks, and the no-em-dash prose lint.

The example apps double as living documentation of the full flow matrix:

```bash
cargo run -p devise-rust-actix --example actix-demo -- --journey
cargo run -p devise-rust-axum --example axum-demo -- --journey
```

Each journey drives sign up, confirm, sign in, remember me, edit account,
lock and unlock, reset, and sign out, printing the observed Devise
redirect, flash key, and status code for every step.

---

## Security

Built-in protections (full policy in [SECURITY.md](SECURITY.md)):

| Protection | Implementation |
|------------|----------------|
| **Timing-safe compare** | `subtle::ConstantTimeEq` for all token/password comparisons |
| **Digest-only token storage** | HMAC-SHA256 digests in DB; raw tokens only in emails |
| **Session salt invalidation** | Password change → salt mismatch → old sessions rejected |
| **Paranoid mode** | Uniform `:invalid` error; dummy bcrypt for unknown accounts |
| **Secret filtering** | `UNSAFE_ATTRIBUTES_FOR_SERIALIZATION` excluded from `Debug`/`Serialize` |
| **Bcrypt cost** | Configurable `stretches` (default 12); runs in `spawn_blocking` |
| **CSRF protection** | Framework bridge callbacks (`handle_unverified_request`) |

Report vulnerabilities to the contact in [SECURITY.md](SECURITY.md).

---

## Migration from Devise (Rails)

| Devise | devise-rust |
|--------|-------------|
| `devise :database_authenticatable, :registerable` | implement the module traits on your model |
| `config.stretches = 12` | `DeviseConfig { stretches: 12, ..DeviseConfig::default() }` |
| `config.pepper = "..."` | `DeviseConfig { pepper: Some("...".into()), .. }` |
| `config.remember_for = 2.weeks` | `.remember_for` field (`chrono::TimeDelta::weeks(2)`) |
| `User.find_for_database_authentication` | `OrmAdapter::find_first` + `valid_password` |
| `devise_for :users` | `Mapping` + `devise_for_users` (actix) / `devise_for_router` (axum) |
| `current_user` | `Auth<User>` extractor / `current_user` helper |
| `confirm_by_token(token)` | `Confirmable::confirm_by_token(...)` |
| `reset_password_by_token(attrs)` | `Recoverable::reset_password_by_token(...)` |

Column names are identical on both sides (`encrypted_password`,
`reset_password_token`, `remember_created_at`, ...), so an existing Devise
schema works without a migration. The extended concept mapping (warden,
callbacks, generators, views) lives in
[docs/rails-mapping.md](docs/rails-mapping.md).

---

## Roadmap

| Phase | Status | Description |
|-------|--------|-------------|
| 1-7 | done | Core, diesel backend + migrations CLI, warden core, mailer + modules I, hygiene modules II, sqlx backend, sea-orm backend |
| 8 | done | actix-web integration (bridge, middleware, extractors, routes, actix-demo) |
| 9 | done | axum integration + omniauthable (tower layer, bridge, routes, stub-provider flows, axum-demo) |
| 10 | in flight | Docs and v1 hardening (this corpus, parity closure, publish prep) |

---

## Contributing

```bash
# Fork → Clone → Branch
git checkout -b feat/your-feature

# Make changes, ensure:
cargo test --all
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check

# Commit (Conventional Commits)
git commit -m "feat(scope): description"
```

### Code Standards

- **Edition**: 2024
- **MSRV**: 1.85 (enforced in CI)
- **Linting**: `clippy::all + clippy::pedantic` as warnings → `-D warnings` in CI
- **Unsafe**: `unsafe_code = warn` (no unsafe in core)
- **Documentation**: All public API documented with rustdoc (Options + Examples sections) carrying a Devise parity note
- **Naming**: Devise parity preserved (snake_case, predicates without `?`, mutators without `!`)
- **Prose**: professional English, no em dashes (enforced by the docs gate)

---

## License

MIT License - matching Devise. See [LICENSE-MIT](LICENSE-MIT) for details.

---

## Acknowledgments

- **Devise** by [Plataformatec](https://github.com/heartcombo/devise) - the inspiration and behavioral contract
- **Warden** - the architectural foundation (Rack middleware)
- **bcrypt** - password hashing
- **diesel-async / sqlx / sea-orm** - ORM backends
- **actix-web / axum** - framework integrations
- **lettre + Tera** - mailer implementation

---

## Links

- **Guides**: [docs/](docs/) (start with [getting-started-actix.md](docs/getting-started-actix.md) or [getting-started-axum.md](docs/getting-started-axum.md))
- **API reference**: https://docs.rs/devise-rust (and each `devise-rust-*` crate)
- **Repository**: https://github.com/gilcierweb/devise-rust
- **Issues**: https://github.com/gilcierweb/devise-rust/issues
- **Discussions**: https://github.com/gilcierweb/devise-rust/discussions
- **Devise Reference**: https://github.com/heartcombo/devise
