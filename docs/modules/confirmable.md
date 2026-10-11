# `confirmable`

Mirrors `Devise::Models::Confirmable`
(`devise/lib/devise/models/confirmable.rb`, untracked upstream
reference). Email confirmation with digest-only tokens, the
`confirm_within` expiry window, reconfirmable email postponement
(including the race-condition fix from Devise issue #5783), resend token
reuse, and paranoid uniformity for instruction requests.

The trait lives at
[`devise_rust::confirmable::Confirmable`](https://docs.rs/devise-rust/latest/devise_rust/confirmable/trait.Confirmable.html).

## Options

| devise option | Rust config field | Default | Notes |
|---------------|-------------------|---------|-------|
| `allow_unconfirmed_access_for` | `DeviseConfig.allow_unconfirmed_access_for` | 0 days | grace window before confirmation is required; zero blocks new accounts until confirmed |
| `confirm_within` | `DeviseConfig.confirm_within` | nil | token validity window; nil means tokens never expire |
| `confirmation_keys` | `DeviseConfig.confirmation_keys` | `[:email]` | attributes used for instruction lookup |
| `reconfirmable` | `DeviseConfig.reconfirmable` | true | postpone email changes into `unconfirmed_email` until reconfirmed |

## Examples

The required-fields helper (which grows by `unconfirmed_email` when
`reconfirmable` is on) and the period humanizer for the
`confirmation_period_expired` message are pure functions compiled as
doctests in the core crate:

```rust
use devise_rust::confirmable::{humanize_period, required_fields};

assert_eq!(
    required_fields(false),
    vec!["confirmation_token", "confirmed_at", "confirmation_sent_at"]
);
assert_eq!(
    required_fields(true),
    vec!["confirmation_token", "confirmed_at", "confirmation_sent_at", "unconfirmed_email"]
);
assert_eq!(humanize_period(chrono::TimeDelta::days(3)), "3 days");
assert_eq!(humanize_period(chrono::TimeDelta::hours(1)), "1 hour");
```

Confirming by token mirrors Devise's `confirm_by_token`, including the
blank-token guard and the raw-then-digest legacy lookup:

<!-- text fence: adapter, mailer, and clock parameters; compiled in the
     confirmable model tests and the example apps -->
```text
let outcome = User::confirm_by_token(
    Some(&raw), &adapter, &config, &clock, &|_| ValidationErrors::new(),
).await?;
assert!(outcome.is_valid());
```

## Chaining note

`confirmable` is seventh in the Devise module super-chain (lib.rs chain
position 6, before `lockable`). It is the first module that contributes
to the chain verdict: `active_for_authentication` becomes
`super && confirmation gate` (unconfirmed accounts outside the grace
window are blocked), and `inactive_message` becomes `:unconfirmed`
unless the record is confirmed. Every module later in the chain sees the
confirmable verdict through its `super` call.
