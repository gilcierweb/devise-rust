# Configuration Reference

`DeviseConfig` carries every Devise option under its Devise name, with
Devise's defaults. It lives in
[`devise_rust::config`](https://docs.rs/devise-rust/latest/devise_rust/config/struct.DeviseConfig.html).

## How configuration works

There is no global mutable `Devise.setup` block in Rust. You build a
`DeviseConfig` value and share it (usually behind an `Arc`) with the
framework integration. The two ways to set options are struct-update
syntax over `DeviseConfig::default()` and per-scope overrides through
`DeviseConfigOverride`:

<!-- rust fence: this exact shape is compiled as the doctest on
     DeviseConfig (see docs.rs); it uses only core APIs -->
```rust
use devise_rust::config::DeviseConfig;

let config = DeviseConfig {
    secret_key: "base64-encoded-32-byte-secret".to_string(), // REQUIRED
    mailer_sender: Some("no-reply@example.com".to_string()), // REQUIRED for mail
    pepper: None,                    // Devise default: nil
    stretches: 12,                   // Devise default: 12 (bcrypt cost)
    ..DeviseConfig::default()        // every other option keeps its Devise default
};

assert_eq!(config.stretches, 12);
assert_eq!(config.remember_for, chrono::TimeDelta::weeks(2));
assert_eq!(config.timeout_in, chrono::TimeDelta::minutes(30));
assert_eq!(config.reset_password_within, chrono::TimeDelta::hours(6));
assert!(!config.paranoid);
```

### Per-scope overrides

Devise lets a model override global config
(`Devise::Models.config`). The Rust equivalent is
[`DeviseConfigOverride`](https://docs.rs/devise-rust/latest/devise_rust/config/struct.DeviseConfigOverride.html):
a sparse struct resolved against the global config with
`resolve(&global)`, where every `Some` field wins and every `None` field
falls back:

<!-- rust fence: compiled as the doctest on DeviseConfigOverride::resolve -->
```rust
use devise_rust::config::{DeviseConfig, DeviseConfigOverride};

let global = DeviseConfig {
    secret_key: "global-secret".to_string(),
    ..DeviseConfig::default()
};
let admin = DeviseConfigOverride {
    stretches: Some(14),
    timeout_in: Some(chrono::TimeDelta::minutes(5)),
    ..DeviseConfigOverride::default()
};

let resolved = admin.resolve(&global);
assert_eq!(resolved.stretches, 14);                       // override wins
assert_eq!(resolved.remember_for, chrono::TimeDelta::weeks(2)); // global default holds
```

## Complete options reference

Every option, its type, and its Devise default. Option names are Devise's
exact names.

### Crypto

| Option | Type | Devise default | Notes |
|--------|------|---------------|-------|
| `secret_key` | `String` | (required) | HMAC key for `TokenGenerator` and the framework session-signing key derivation |
| `pepper` | `Option<String>` | nil | appended to the password before bcrypt hashing |
| `stretches` | `u32` | 12 | bcrypt cost factor |

### Authentication keys

| Option | Type | Devise default | Notes |
|--------|------|---------------|-------|
| `authentication_keys` | `Vec<String>` | `[:email]` | attributes a credential is looked up by |
| `request_keys` | `Vec<String>` | `[]` | extra request attributes required to authenticate |
| `case_insensitive_keys` | `Vec<String>` | `[:email]` | downcased before lookup |
| `strip_whitespace_keys` | `Vec<String>` | `[:email]` | stripped before lookup |
| `http_authenticatable` | `bool` | false | allow HTTP Basic authentication |
| `http_authentication_key` | `Option<String>` | nil | override the HTTP Basic param key |
| `http_authenticatable_on_xhr` | `bool` | true | allow HTTP Basic on Ajax requests |
| `params_authenticatable` | `bool` | true | allow credentials in request params |
| `http_authentication_realm` | `String` | `"Application"` | realm returned with 401 responses |

### Validation

| Option | Type | Devise default | Notes |
|--------|------|---------------|-------|
| `email_regexp` | `String` | `\A[^@\s]+@[^@\s]+\z` | Devise's exact default pattern |
| `password_length` | `Range<usize>` | `6..128` | bounds inclusive, as in Ruby |

### Rememberable

| Option | Type | Devise default | Notes |
|--------|------|---------------|-------|
| `remember_for` | `TimeDelta` | 2 weeks | cookie validity window |
| `extend_remember_period` | `bool` | false | re-issue the cookie on each remember hit |
| `rememberable_options` | `HashMap<String, String>` | `{}` | cookie overrides: `key`, `secure`, `path`, `domain` |
| `expire_all_remember_me_on_sign_out` | `bool` | true | `forget_me` clears `remember_created_at` |

### Confirmable

| Option | Type | Devise default | Notes |
|--------|------|---------------|-------|
| `allow_unconfirmed_access_for` | `TimeDelta` | 0 days | grace window before confirmation is required |
| `confirm_within` | `Option<TimeDelta>` | nil | token validity window; nil means tokens never expire |
| `confirmation_keys` | `Vec<String>` | `[:email]` | attributes used for instruction lookup |
| `reconfirmable` | `bool` | true | postpone email changes into `unconfirmed_email` |

### Lockable

| Option | Type | Devise default | Notes |
|--------|------|---------------|-------|
| `maximum_attempts` | `u32` | 20 | failures accepted before locking |
| `lock_strategy` | `String` | `:failed_attempts` | or `"none"` |
| `unlock_strategy` | `String` | `:both` | `time`, `email`, `both`, or `none` |
| `unlock_in` | `TimeDelta` | 1 hour | auto-release window for time locks |
| `unlock_keys` | `Vec<String>` | `[:email]` | attributes used for unlock lookup |
| `last_attempt_warning` | `bool` | true | warn on the next-to-last attempt |

### Recoverable

| Option | Type | Devise default | Notes |
|--------|------|---------------|-------|
| `reset_password_keys` | `Vec<String>` | `[:email]` | attributes used for instructions lookup |
| `reset_password_within` | `TimeDelta` | 6 hours | reset token validity window |
| `sign_in_after_reset_password` | `bool` | true | controller-side sign-in decision after reset |

### Timeoutable

| Option | Type | Devise default | Notes |
|--------|------|---------------|-------|
| `timeout_in` | `TimeDelta` | 30 minutes | inactivity window before the session expires |

### Sessions and scopes

| Option | Type | Devise default | Notes |
|--------|------|---------------|-------|
| `default_scope` | `Option<String>` | nil | Devise has no implicit default scope |
| `sign_out_all_scopes` | `bool` | true | sign out every scope on sign out |
| `sign_out_via` | `String` | `:delete` | HTTP method accepted for sign out |
| `skip_session_storage` | `Vec<String>` | `[:http_auth]` | strategies that skip session storage |

### Framework

| Option | Type | Devise default | Notes |
|--------|------|---------------|-------|
| `parent_controller` | `String` | `"ApplicationController"` | informational; framework integrations own the controller surface |
| `parent_mailer` | `String` | `"ActionMailer::Base"` | informational; the `Mailer` trait replaces the ActionMailer base |
| `mailer_sender` | `Option<String>` | nil | sender for the 5 notifications; required for mail |
| `router_name` | `Option<String>` | nil | informational; scope registries replace named routers |
| `scoped_views` | `bool` | false | informational; framework templates replace Rails views |
| `navigational_formats` | `Vec<String>` | `["*/*", :html, :turbo_stream]` | formats that get redirects and flashes instead of 401 |
| `responder` | `String` | `"Devise::Controllers::Responder"` | informational; failure renderers replace the responder |
| `reload_routes` | `bool` | true | informational; route specs are built at startup in Rust |
| `clean_up_csrf_token_on_authentication` | `bool` | true | rotate the CSRF token on sign in via the framework bridge |
| `omniauth_path_prefix` | `Option<String>` | nil | global prefix override; default is `{scope_path}/auth` |
| `omniauth_providers` | `Vec<String>` | `[]` | provider-name allowlist checked at request time |

### Behavior flags

| Option | Type | Devise default | Notes |
|--------|------|---------------|-------|
| `paranoid` | `bool` | false | uniform failure messages plus a dummy bcrypt hash on unknown accounts |
| `send_email_changed_notification` | `bool` | false | email the ORIGINAL address on email change |
| `send_password_change_notification` | `bool` | false | email on password change |
| `sign_in_after_change_password` | `bool` | true | sign the user back in after a password-changing update |

## Loading configuration from the environment

Production apps load secrets from the environment and fall back to the
Devise default for optional values:

<!-- text fence: reads process environment, which core doctests cannot
     provide; see the snippet policy in getting-started-actix.md -->
```text
let config = DeviseConfig {
    secret_key: std::env::var("DEVISE_SECRET_KEY").expect("DEVISE_SECRET_KEY"),
    mailer_sender: std::env::var("DEVISE_MAILER_SENDER").ok(),
    pepper: std::env::var("DEVISE_PEPPER").ok(),
    stretches: std::env::var("DEVISE_STRETCHES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(12), // Devise default: 12
    ..DeviseConfig::default()
};
```

Common variables: `DEVISE_SECRET_KEY` (required), `DEVISE_MAILER_SENDER`,
`DEVISE_PEPPER`, `DEVISE_STRETCHES` (12), `DEVISE_REMEMBER_FOR` (1209600
seconds), `DEVISE_TIMEOUT_IN` (1800), `DEVISE_MAXIMUM_ATTEMPTS` (20),
`DEVISE_UNLOCK_IN` (3600), `DEVISE_RESET_PASSWORD_WITHIN` (21600), and
`DEVISE_PARANOID` (false).

## Where each option is enforced

Every option documents its enforcing module on
[docs.rs](https://docs.rs/devise-rust/latest/devise_rust/config/struct.DeviseConfig.html);
the per-module pages under [modules/](modules/) list the options each
module reads.
