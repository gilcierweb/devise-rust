# `rememberable`

Mirrors `Devise::Models::Rememberable`
(`devise/lib/devise/models/rememberable.rb`, untracked upstream
reference). Persistent sessions via the signed cookie triple
`[key, value, timestamp]`, with the five-condition validity check and
hardened cookie attributes.

The trait lives at
[`devise_rust::rememberable::Rememberable`](https://docs.rs/devise-rust/latest/devise_rust/rememberable/trait.Rememberable.html)
and the cookie codec at
[`devise_rust::rememberable`](https://docs.rs/devise-rust/latest/devise_rust/rememberable/index.html).

## Options

| devise option | Rust config field | Default | Notes |
|---------------|-------------------|---------|-------|
| `remember_for` | `DeviseConfig.remember_for` | 2 weeks | cookie validity window |
| `extend_remember_period` | `DeviseConfig.extend_remember_period` | false | re-issue the cookie on each remember hit |
| `rememberable_options` | `DeviseConfig.rememberable_options` | `{}` | cookie overrides: `key` renames the cookie, `secure` opts out of `Secure` for plain-HTTP development, `path` and `domain` pass through |
| `expire_all_remember_me_on_sign_out` | `DeviseConfig.expire_all_remember_me_on_sign_out` | true | `forget_me` clears `remember_created_at` |

## Examples

The required-fields and cookie-attribute helpers are pure functions
compiled as doctests in the core crate:

```rust
use devise_rust::config::DeviseConfig;
use devise_rust::rememberable::{SameSite, remember_cookie_key, required_fields};

assert_eq!(required_fields(), vec!["remember_created_at"]);
assert_eq!(remember_cookie_key("user", &DeviseConfig::default()), "remember_user_token");
assert_eq!(SameSite::Lax.header_value(), "Lax");
```

The remember and forget lifecycle is adapter-dependent (it persists
`remember_created_at` and optionally `remember_token`):

<!-- text fence: adapter and clock parameters; compiled in the example apps -->
```text
user.remember_me(&adapter, &clock).await?;
let (key, value, generated_at) = user.serialize_into_cookie(&clock)?;
user.forget_me(&adapter, &config, &clock).await?;
```

## Chaining note

`rememberable` is second in the Devise module super-chain (lib.rs chain
position 1, after `database_authenticatable`). It adds no
`active_for_authentication` or `inactive_message` condition: its hooks
run around sign-in and sign-out, minting and clearing the cookie. A live
remember cookie exempts the session from `timeoutable` expiry, which is
the one cross-module interaction the chain order documents.
