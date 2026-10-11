# `timeoutable`

Mirrors `Devise::Models::Timeoutable`
(`devise/lib/devise/models/timeoutable.rb` and
`devise/lib/devise/hooks/timeoutable.rb`, untracked upstream reference).
Inactivity timeout over the session's `last_request_at` integer-epoch
tick, with the Devise-exact less-than-or-equal boundary, the live
remember-me exemption, all-scopes sign-out with the `:timeout` failure,
and the `skip_timeout` bypass flags.

The trait lives at
[`devise_rust::timeoutable::Timeoutable`](https://docs.rs/devise-rust/latest/devise_rust/timeoutable/trait.Timeoutable.html).

## Options

| devise option | Rust config field | Default | Notes |
|---------------|-------------------|---------|-------|
| `timeout_in` | `DeviseConfig.timeout_in` | 30 minutes | inactivity window before the session expires |
| `sign_out_all_scopes` | `DeviseConfig.sign_out_all_scopes` | true | a timeout signs out every scope |

## Examples

The tick classification and the expiry boundary are pure functions
compiled as doctests in the core crate:

```rust
use chrono::{TimeDelta, Utc};
use devise_rust::time::FixedClock;
use devise_rust::timeoutable::{
    LastRequestTick, classify_last_request, required_fields, tick_expired,
};

// Session-based module: no model columns.
assert!(required_fields().is_empty());

// The stored session value classifies to Missing, At, or Malformed.
assert_eq!(classify_last_request(None), LastRequestTick::Missing);
assert!(matches!(
    classify_last_request(Some(&serde_json::json!("not-a-number"))),
    LastRequestTick::Malformed
));

// The Devise-exact boundary: Missing is live, Malformed fails closed.
let clock = FixedClock::new(Utc::now());
assert!(!tick_expired(LastRequestTick::Missing, TimeDelta::minutes(30), &clock));
assert!(tick_expired(LastRequestTick::Malformed, TimeDelta::minutes(30), &clock));
```

The timed-out verdict on the model mirrors Devise's `timedout?` boundary;
a missing `last_request_at` never times out and a live remember login
is exempt:

<!-- text fence: clock parameters; compiled in the timeoutable model tests
     and the framework hook tests -->
```text
assert!(user.timedout(Some(last_access), &config, &clock));
assert!(!user.timedout(None, &config, &clock));
```

## Chaining note

`timeoutable` is ninth in the Devise module super-chain (lib.rs chain
position 8, after `lockable`). It adds no model-side
`active_for_authentication` condition: enforcement is the per-request
hook, which throws the `:timeout` failure when the boundary is crossed
and the remember-me exemption does not hold, signing out through the
real sign-out paths so logout hooks clear the remember cookie.
