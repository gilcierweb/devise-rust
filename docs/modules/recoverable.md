# `recoverable`

Mirrors `Devise::Models::Recoverable`
(`devise/lib/devise/models/recoverable.rb`, untracked upstream
reference). Password reset tokens: the database stores the HMAC digest
plus `reset_password_sent_at`, and the raw token only exists in the
email link and in memory on the record that just received it.

The trait lives at
[`devise_rust::model::Recoverable`](https://docs.rs/devise-rust/latest/devise_rust/model/trait.Recoverable.html).

## Options

| devise option | Rust config field | Default | Notes |
|---------------|-------------------|---------|-------|
| `reset_password_keys` | `DeviseConfig.reset_password_keys` | `[:email]` | attributes used for instructions lookup |
| `reset_password_within` | `DeviseConfig.reset_password_within` | 6 hours | token validity window |
| `sign_in_after_reset_password` | `DeviseConfig.sign_in_after_reset_password` | true | controller-side sign-in decision after a successful reset |

## Examples

Sending instructions returns the raw token (the only place it exists in
clear text); the database stores the digest:

<!-- text fence: adapter, mailer, and clock parameters; compiled in the
     example apps and the recoverable model tests -->
```text
let raw = user.send_reset_password_instructions(&adapter, &mailer, &config, &clock).await?;
```

Resetting by token mirrors Devise's `reset_password_by_token`, including
the expired-token error (`:reset_password_token, :expired`) when the
window has passed:

<!-- text fence: adapter-dependent; compiled in the recoverable model
     tests -->
```text
let outcome = User::reset_password_by_token(&attrs, &adapter, &config, &clock).await?;
assert!(outcome.is_valid());
```

## Chaining note

`recoverable` is fourth in the Devise module super-chain (after
`omniauthable`). It adds no `active_for_authentication` or
`inactive_message` condition: the module owns the token lifecycle and
the `reset_password` save path, and its only cross-module interaction is
clearing the reset token when the password or authentication keys change.
