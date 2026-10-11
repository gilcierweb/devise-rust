# Getting Started with devise-rust (Axum)

This guide is the axum track over the same shared core setup as the actix
track. Read [getting-started-actix.md](getting-started-actix.md) first for
the prerequisites, the dependency block, the model, the schema, and the
Devise configuration: all of it is identical here. This page picks up at
the wiring step and translates the actix track onto axum 0.8 and
tower-sessions.

> **Snippet policy.** Code blocks in this guide that wire axum, tower, or
> diesel are fenced as `text` on purpose: cargo compiles rustdoc fences in
> the core crate, and framework wiring needs sibling crates and a running
> database that core doctests cannot provide. Every wiring block is kept
> in sync with `crates/devise-rust-axum/examples/axum-demo/main.rs`, which
> is compiled and green in CI.

## Dependencies

Same as the actix track, swapping the framework integration
(see [Shared core setup](getting-started-actix.md#shared-core-setup)):

<!-- text fence: framework wiring needs sibling crates; see snippet policy -->
```text
[dependencies]
devise-rust = "0.1"
devise-rust-diesel = { version = "0.1", features = ["sqlite"] }
devise-rust-axum = "0.1"

axum = "0.8"
tower-sessions = { version = "0.15", features = ["signed"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## The axum track

### Wire the application

The layer order is the load-bearing detail: build the `Router` with the
devise routers merged, apply `DeviseLayer`, then add the session layer
last so it runs outermost and observes the request before devise does:

<!-- text fence: framework wiring needs sibling crates; kept in sync with
     the compiled axum-demo example (snippet policy) -->
```text
#[tokio::main]
async fn main() {
    let pool = devise_rust_diesel::pool::sqlite_memory_pool().expect("sqlite pool");
    let config = std::sync::Arc::new(example_config());
    let (mapping, adapter) = user_scope(&pool);

    let state = devise_rust_axum::DeviseWebState::<User, _, TestMailer>::new(
        mapping.clone(), config.clone(), std::sync::Arc::new(adapter),
        std::sync::Arc::new(devise_rust::mailer::TestMailer::default()),
        std::sync::Arc::new(devise_rust::time::SystemClock),
    ).expect("user state builds").with_all_scopes(vec!["user".to_string()]);

    let mut hooks = devise_rust::hooks::HookRegistry::new();
    devise_rust::hooks::register_devise_hooks(&mut hooks, &mapping);

    let mut registry = devise_rust::scope::ScopeRegistry::new();
    registry.register(mapping.clone());
    let finder = std::sync::Arc::new(devise_rust::model::AdapterBridge::new(state.adapter.clone()));

    let devise_layer = devise_rust_axum::DeviseLayer::new(
        std::sync::Arc::new(registry), config.clone(),
    ).with_hooks(std::sync::Arc::new(hooks)).with_finder("user", finder);

    let session_layer = devise_rust_axum::session_manager_layer_with_secure(&config, false)
        .expect("session layer");

    let app = axum::Router::new()
        .route("/private", axum::routing::get(private))
        .merge(devise_rust_axum::devise_for_router(state))
        .layer(devise_layer)
        .layer(session_layer);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await.expect("bind");
    axum::serve(listener, app).await.expect("serve");
}
```

`session_manager_layer_with_secure(&config, false)` opts out of the
`Secure` cookie attribute for plain-HTTP local development only;
production keeps the default, which signs the session cookie and sets
`Secure`.

`user_scope` builds the same `Mapping` as the actix track; see
[the actix track's mapping helper](getting-started-actix.md#the-actix-track)
for the full field list. The `Mapping` struct, `Module` variants, and
`SignOutVia` all come from `devise_rust::scope` and are identical across
frameworks.

### Protect a handler

`Auth<User>` is the `current_user` shape and `RequireAuth<User>` is the
`authenticate_user!` shape, the same names and semantics as the actix
crate (one doc page serves both frameworks by design):

<!-- text fence: framework wiring needs sibling crates; compiled in the
     example app -->
```text
async fn private(user: devise_rust_axum::Auth<User>) -> impl axum::response::IntoResponse {
    match user.user() {
        Some(record) => axum::Json(serde_json::json!({ "email": record.email })).into_response(),
        None => axum::http::StatusCode::UNAUTHORIZED.into_response(),
    }
}
```

### Run the journey

The example app mirrors the actix demo's three modes:

```text
cargo run -p devise-rust-axum --example axum-demo -- --smoke
cargo run -p devise-rust-axum --example axum-demo -- --journey
cargo run -p devise-rust-axum --example axum-demo
```

`--journey` drives the full Devise flow matrix (sign up, confirm, sign
in, remember me, edit account, lock and unlock, reset, sign out) and
prints the observed Devise redirect and flash key for every step. The
same flows are asserted by the `omniauth_flows` and controller test
matrices that gate CI.

## Differences from the actix track

- Sessions ride `tower-sessions` (server-side store, signed cookie)
  instead of `actix-session`'s cookie store.
- The bridge holds a cloned `Session` handle, so there is no
  owned-extract dance: async session writes await freely inside the
  layer.
- `Session::cycle_id()` is fallible, so every privilege transition
  (sign in, remember-me upgrade) propagates rotation errors instead of
  persisting the old session id.
- Route registration is `.merge(devise_for_router(state))` on a
  `Router` instead of `.service(devise_for_users(...))` on an actix
  `App`.

## Next steps

- [configuration.md](configuration.md): every `DeviseConfig` option with
  its Devise default.
- [modules/](modules/): per-module pages with Options and Examples in
  Devise RDoc shape.
- [rails-mapping.md](rails-mapping.md): concept mapping for developers
  arriving from Devise on Rails.
