# Getting Started with devise-rust (Actix)

This guide walks a new application from an empty crate to a running actix-web
server with sign up, confirmation, sign in, remember me, password reset,
lock and unlock, and one protected handler. It is a close adaptation of the
Devise (Ruby) getting-started flow, with every example translated to the
shipped Rust API.

The shared core setup (dependencies, model, schema, configuration) is
identical for both frameworks. The axum track lives in
[getting-started-axum.md](getting-started-axum.md) and reuses this page's
[Shared core setup](#shared-core-setup) section instead of repeating it.

> **Snippet policy.** Code blocks in this guide that wire actix-web,
> diesel, or the CLI are fenced as `text` on purpose: cargo compiles rustdoc
> fences in the core crate, and framework wiring needs sibling crates and a
> running database that core doctests cannot provide. Every wiring block is
> kept in sync with `crates/devise-rust-actix/examples/actix-demo/main.rs`,
> which is compiled and green in CI.

## What you will build

A single-scope `user` app exposing the full Devise route table:

| Method | Path | Purpose |
|--------|------|---------|
| GET/POST | `/users/sign_in` | sign in and create the session |
| DELETE | `/users/sign_out` | sign out |
| GET `/users/sign_up`, POST `/users` | registrations | sign up and create the account |
| GET/POST | `/users/password` | request and apply a password reset |
| GET/POST | `/users/confirmation` | resend and confirm the email address |
| GET/POST | `/users/unlock` | request and apply an unlock |

plus one application route, `/private`, that only signed-in users can reach.

## Shared core setup

### Prerequisites

- Rust 1.85 or later (the workspace pins `rust-version = "1.85"`).
- A database. The walkthrough uses SQLite so it runs with zero setup;
  production apps use Postgres by enabling the `postgres` feature instead.
- No Docker required for this guide.

### 1. Add the dependencies

<!-- text fence: framework wiring needs sibling crates; see snippet policy -->
```text
[dependencies]
devise-rust = "0.1"
devise-rust-diesel = { version = "0.1", features = ["sqlite"] }
devise-rust-actix = "0.1"

actix-web = "~4.12"
actix-session = { version = "0.11", features = ["cookie-session"], default-features = false }
```

- `devise-rust` is the framework-neutral core: configuration, crypto, model
  modules, strategies, hooks, and the failure pipeline.
- `devise-rust-diesel` is the ORM backend. Pick exactly one database
  feature: `sqlite` (this guide) or `postgres`.
- `devise-rust-actix` maps the core surface onto actix-web extractors,
  middleware, and route registration.

### 2. Define your model

Your model is a plain struct with Devise's exact column names plus two
virtual password fields. The struct below carries the columns every module
in this guide needs:

<!-- text fence: model shape is kept in sync with the compiled example app -->
```text
use devise_rust::model::DatabaseAuthenticatable;

#[derive(Debug, Clone, Default)]
pub struct User {
    pub id: i64,
    pub email: String,
    pub encrypted_password: String,
    // virtual fields: never stored in the database
    pub password: Option<String>,
    pub password_confirmation: Option<String>,
    // rememberable
    pub remember_created_at: Option<chrono::DateTime<chrono::Utc>>,
    // confirmable
    pub confirmation_token: Option<String>,
    pub confirmed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub confirmation_sent_at: Option<chrono::DateTime<chrono::Utc>>,
    pub unconfirmed_email: Option<String>,
    // lockable
    pub failed_attempts: u32,
    pub unlock_token: Option<String>,
    pub locked_at: Option<chrono::DateTime<chrono::Utc>>,
    // recoverable
    pub reset_password_token: Option<String>,
    pub reset_password_sent_at: Option<chrono::DateTime<chrono::Utc>>,
    // trackable
    pub sign_in_count: u64,
    pub current_sign_in_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_sign_in_at: Option<chrono::DateTime<chrono::Utc>>,
    pub current_sign_in_ip: Option<String>,
    pub last_sign_in_ip: Option<String>,
}
```

The model then implements the module traits, each named after its Devise
counterpart. A full-stack model implements:

<!-- text fence: trait-impl skeletons are compiled in the example app -->
```text
impl devise_rust::model::Authenticatable for User { /* key + salt + serialization */ }
impl devise_rust::model::DatabaseAuthenticatable for User { /* password hashing, notifications */ }
impl devise_rust::model::Registerable for User {}
impl devise_rust::model::Validatable for User { /* email + password validation */ }
impl devise_rust::model::Recoverable for User { /* reset token lifecycle */ }
impl devise_rust::confirmable::Confirmable for User { /* confirmation + reconfirmation */ }
impl devise_rust::lockable::Lockable for User { /* attempt counting, lock, unlock */ }
impl devise_rust::rememberable::Rememberable for User { /* remember cookie triple */ }
impl devise_rust::trackable::Trackable for User { /* sign-in auditing */ }
impl devise_rust::mailer::HasEmail for User { /* recipient for the 5 notifications */ }
```

Most of those impls are one to five lines because the logic lives in the
core traits and your backend glue. Two compiled references cover the whole
model story:

- [`crates/devise-rust-actix/examples/actix-demo/main.rs`](https://github.com/gilcierweb/devise-rust/blob/main/crates/devise-rust-actix/examples/actix-demo/main.rs)
  implements every trait above end to end and wires the full Devise journey.
- [`crates/devise-rust-diesel/tests/models.rs`](https://github.com/gilcierweb/devise-rust/blob/main/crates/devise-rust-diesel/tests/models.rs)
  shows the hand-written `DieselModel` glue (the `table!` schema, the
  diesel row shape, the insert and changeset bridges) that
  `DieselOrmAdapter` needs, for both integer and UUID primary keys.

Per-module method documentation lives in the [module pages](modules/) and
on [docs.rs/devise-rust](https://docs.rs/devise-rust).

### 3. Generate the schema

`devise-rust-migrations` emits the exact column set Devise expects, per
module, for Postgres, SQLite, and MySQL:

<!-- text fence: CLI invocation; schema files are applied by your tooling -->
```text
cargo install --path crates/devise-rust-migrations

devise-migrations users --dialect sqlite --modules all --pk-type bigint --output migrations/001_devise_users.sql
```

Apply the emitted SQL with the migration tool you already use
(`sqlx migrate run`, `diesel migration run`, or `psql -f`).

### 4. Configure Devise

`DeviseConfig` carries Devise's exact option names and defaults. Build it
with struct-update syntax over `DeviseConfig::default()`; `stretches`
defaults to 12, matching Devise:

<!-- text fence: configuration shape; the defaults table is compiled as a
     core doctest on DeviseConfig (see docs/configuration.md) -->
```text
use devise_rust::config::DeviseConfig;

let config = DeviseConfig {
    secret_key: std::env::var("DEVISE_SECRET_KEY").expect("DEVISE_SECRET_KEY"),
    mailer_sender: Some("no-reply@example.com".to_string()),
    ..DeviseConfig::default()
};
```

Every option, its Devise default, and its environment-variable loading
idiom are documented in [configuration.md](configuration.md).

## The actix track

### 5. Wire the application

The complete wiring is one `main` plus a mapping helper. Register
`SessionMiddleware` last so it runs first (outermost), then
`DeviseMiddleware`, then the `devise_for_users` scope and your routes:

<!-- text fence: framework wiring needs sibling crates; kept in sync with
     the compiled actix-demo example (snippet policy) -->
```text
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let pool = devise_rust_diesel::pool::sqlite_memory_pool().expect("sqlite pool");
    let config = std::sync::Arc::new(example_config());
    let key = devise_rust_actix::derive_actix_key(&config.secret_key).expect("derive session key");
    let (mapping, adapter) = user_scope(&pool);
    let mut registry = devise_rust::scope::ScopeRegistry::new();
    registry.register(mapping.clone());
    let middleware = devise_rust_actix::DeviseMiddleware::new(
        std::sync::Arc::new(devise_rust_actix::ActixSessionStore::new(key.clone())),
        std::sync::Arc::new(registry),
        config.clone(),
    )
    .with_finder("user", std::sync::Arc::new(devise_rust::model::AdapterBridge::new(adapter.clone())));
    let state = devise_rust_actix::DeviseWebState {
        mapping: mapping.clone(),
        config: config.clone(),
        adapter: std::sync::Arc::new(adapter),
        mailer: std::sync::Arc::new(devise_rust::mailer::TestMailer::default()),
        clock: std::sync::Arc::new(devise_rust::time::SystemClock),
        all_scopes: vec!["user".to_string()],
        marker: std::marker::PhantomData,
    };
    actix_web::HttpServer::new(move || {
        actix_web::App::new()
            .wrap(middleware.clone())
            .wrap(actix_session::SessionMiddleware::builder(
                actix_session::storage::CookieSessionStore::default(),
                key.clone(),
            ).build())
            .service(devise_rust_actix::devise_for_users(actix_web::web::Data::new(state.clone())))
            .route("/private", actix_web::web::get().to(private))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
```

`user_scope` builds the `Mapping` (Devise's `devise_for :users` equivalent):
a scope name, a path, and the module list. `Module` variants and path
overrides follow Devise's option names. The struct has no `Default`, so a
mapping helper spells out every field, exactly like the example app does:

<!-- text fence: mapping shape; compiled in the example app -->
```text
fn user_scope(pool: &SqlitePool) -> (Mapping, DieselOrmAdapter<User, Sqlite, SqliteConn>) {
    let mapping = Mapping {
        name: "user".to_string(),
        class_name: "User".to_string(),
        path: "users".to_string(),
        path_prefix: None,
        singular: "user".to_string(),
        path_names: PathNames::default(),
        controllers: HashMap::new(),
        modules: vec![
            Module::DatabaseAuthenticatable, Module::Registerable, Module::Recoverable,
            Module::Rememberable, Module::Validatable, Module::Confirmable,
            Module::Lockable, Module::Trackable,
        ],
        only: vec![],
        skip: vec![],
        constraints: HashMap::new(),
        defaults: HashMap::new(),
        format: None,
        router_name: None,
        sign_out_via: SignOutVia::Delete,
        failure_app: None,
    };
    (mapping, DieselOrmAdapter::new(pool.clone()))
}
```

The exact field list of `Mapping` and every route option
(`path_names`, `only`, `skip`, `sign_out_via`) is on
[docs.rs/devise-rust](https://docs.rs/devise-rust/latest/devise_rust/scope/struct.Mapping.html),
and the fully working version is in the example app.

### 6. Protect a handler

`Auth<User>` is the `current_user` shape: it never rejects and hands you
`Option<&User>`. `RequireAuth<User>` is the `authenticate_user!` shape: it
fails closed with Devise's 302 redirect plus flash for navigational
requests, or 401 for API requests:

<!-- text fence: framework wiring needs sibling crates; compiled in the
     example app -->
```text
async fn private(user: devise_rust_actix::Auth<User>) -> impl actix_web::Responder {
    match user.user() {
        Some(record) => actix_web::HttpResponse::Ok().json(serde_json::json!({ "email": record.email })),
        None => actix_web::HttpResponse::Unauthorized().finish(),
    }
}
```

### 7. Run the journey

The example app runs the full Devise journey in three modes:

```text
cargo run -p devise-rust-actix --example actix-demo -- --smoke    # in-process boot + sign-in probe
cargo run -p devise-rust-actix --example actix-demo -- --journey # full flow matrix with redirects and flashes
cargo run -p devise-rust-actix --example actix-demo               # serve on 127.0.0.1:8080
```

The `--journey` mode drives sign up, confirm, sign in, remember me, edit
account, lock and unlock, reset, and sign out, printing the observed Devise
redirect and flash key for every step. The same flows are asserted in the
`omniauth_flows` and controller test matrices that gate CI.

## Next steps

- [getting-started-axum.md](getting-started-axum.md): the axum track over
  the same shared core setup.
- [configuration.md](configuration.md): every `DeviseConfig` option with
  its Devise default.
- [modules/](modules/): per-module pages with Options and Examples in
  Devise RDoc shape.
- [rails-mapping.md](rails-mapping.md): concept mapping for developers
  arriving from Devise on Rails.
- [SECURITY.md](../SECURITY.md): built-in protections and reporting policy.
