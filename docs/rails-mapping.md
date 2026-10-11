# Rails to Rust: Devise Concept Mapping

This guide maps every core Devise (Rails) concept onto its devise-rust
counterpart, for developers arriving from Devise. Method, option, column,
and message names carry over verbatim wherever Rust's naming rules allow
(predicates keep their stem: `confirmed?` becomes `confirmed`, mutators
keep theirs: `lock_access!` becomes `lock_access`).

## Concept table

| Devise (Rails) | devise-rust |
|----------------|-------------|
| `devise :database_authenticatable, :registerable` model macro | implement the module traits on your model; trait names are identical (`DatabaseAuthenticatable`, `Registerable`, ...) |
| `Devise.setup { config.stretches = 12 }` | `DeviseConfig` built with struct-update syntax over `DeviseConfig::default()`; per-scope overrides via `DeviseConfigOverride::resolve` |
| warden session management (`Warden::Manager`, `serialize_into_session` `[key, salt]`) | framework middleware over the core `SessionStore`: `DeviseMiddleware` (actix) and `DeviseLayer` (axum); the `[key, salt]` session serialization is byte-for-byte Devise's, so a password change still invalidates old sessions |
| warden strategy dispatch (`Warden::Strategies`: params, HTTP Basic, rememberable) | the core `Strategy` chain dispatched by the middleware/layer on every request: params, HTTP Basic, rememberable cookie, and the paranoid dummy-hash mitigation |
| `throw :warden` plus the failure app | core `Failure` decisions rendered by `ActixFailureRenderer` / `AxumFailureRenderer`: 302 plus flash plus `stored_location` for navigational formats, 401 plus `WWW-Authenticate` for API requests |
| warden callbacks (`after_set_user`, `before_logout`) | explicit pipeline functions registered in a `HookRegistry` (`register_devise_hooks`); the same hook events with the same filters, called by the bridge at the same lifecycle points |
| `devise_for :users` in `config/routes.rb` | a `Mapping` (scope name, path, module list, `path_names`, `only`/`skip`, `sign_out_via`) registered in a `ScopeRegistry`, rendered by `devise_for_users` (actix) or `devise_for_router` (axum) |
| generators (`rails generate devise:install`, `rails generate devise:migration`) | the `devise-migrations` CLI and the `EmitOptions` library: per-module DDL for Postgres, SQLite, and MySQL with integer and UUID primary keys |
| views (`app/views/devise/*`) | framework response templates; the five mailer notifications ship as Tera templates with Devise's subject and copy keys |
| `current_user` | `Auth<User>` extractor (`.user() -> Option<&User>`) or the `current_user` helper |
| `authenticate_user!` | `RequireAuth<User>` extractor or the `authenticate_user` helper; fails closed with the Devise 302/401 split |
| `user_signed_in?` | `user_signed_in()` |
| `warden.authenticate!(scope: :user)` | `authenticate_scope("user")` (arbitrary scopes) with `authenticate_user` built in |
| `devise_parameter_sanitizer` | core `ParameterSanitizer` with Devise's defaults (`sign_in`, `sign_up`, `account_update`) |
| I18n (`devise.*` keys in `config/locales/en.yml`) | the embedded catalog with Devise's exact message keys and interpolation values |
| `User.confirm_by_token(token)` | `Confirmable::confirm_by_token(...)`; same name, same blank-token guard, same raw-then-digest lookup |
| `User.reset_password_by_token(attrs)` | `Recoverable::reset_password_by_token(...)`; same name, same expired-token error |

## Method mapping

The API-level method mapping (Devise method to Rust counterpart, per
module) lives in the README's "Migration from Devise" section and on
[docs.rs/devise-rust](https://docs.rs/devise-rust), where every public
item carries a parity note naming the Devise method or option it mirrors.
Column names are identical on both sides (`encrypted_password`,
`reset_password_token`, `remember_created_at`, ...), so an existing
Devise schema works against devise-rust without a migration.

## Where orchestration lives

Devise splits behavior between models, controllers, and warden callbacks.
devise-rust keeps the same split with explicit seams:

- Model logic: the module traits (identical names, identical chaining
  order for `active_for_authentication` and `inactive_message`).
- Controller logic: the route groups in the framework crates render the
  same actions (sessions, registrations, passwords, confirmations,
  unlocks) with the same redirects, flashes, and status codes.
- Warden logic: the middleware/layer plus the hook registry, described
  above.

Nothing is hidden behind monkey patching or `method_missing` semantics:
every extension point is a trait method with a default body you can
override, mirroring the Devise hook methods (`after_database_authentication`,
`after_confirmation`, `after_remembered`).
