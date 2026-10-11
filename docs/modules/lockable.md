# `lockable`

Mirrors `Devise::Models::Lockable`
(`devise/lib/devise/models/lockable.rb`, untracked upstream reference).
Failed-attempt counting with the counter-to-lock path, the time, email,
and both unlock strategies with `unlock_in` expiry, digest-only unlock
tokens with raw-token restore, and paranoid message suppression.

The trait lives at
[`devise_rust::lockable::Lockable`](https://docs.rs/devise-rust/latest/devise_rust/lockable/trait.Lockable.html).

## Options

| devise option | Rust config field | Default | Notes |
|---------------|-------------------|---------|-------|
| `maximum_attempts` | `DeviseConfig.maximum_attempts` | 20 | failures accepted before locking |
| `lock_strategy` | `DeviseConfig.lock_strategy` | `:failed_attempts` | or `"none"` to disable counting |
| `unlock_strategy` | `DeviseConfig.unlock_strategy` | `:both` | `time`, `email`, `both`, or `none` |
| `unlock_in` | `DeviseConfig.unlock_in` | 1 hour | auto-release window for time locks |
| `unlock_keys` | `DeviseConfig.unlock_keys` | `[:email]` | attributes used for unlock lookup |
| `last_attempt_warning` | `DeviseConfig.last_attempt_warning` | true | warn on the next-to-last attempt |

## Examples

The counter-to-lock path, mirroring Devise's `increment_failed_attempts`
plus `lock_access!` (persistence runs through the forced-write
`update_columns` verb plus a re-get, like Devise's `increment_counter`
plus `reload`):

<!-- text fence: adapter, mailer, and clock parameters; compiled in the
     lockable model tests and the example apps -->
```text
user.increment_failed_attempts(&adapter).await?;
assert!(user.last_attempt(&config, &clock));
user.lock_access(&adapter, &mailer, &config, &clock, true).await?;
assert!(user.access_locked(&config, &clock));
```

Unlocking by token mirrors Devise's `unlock_access_by_token` with the
digest lookup and the raw-token restore:

<!-- text fence: adapter-dependent; compiled in the lockable model tests -->
```text
let outcome = User::unlock_access_by_token(&raw, &adapter, &config, &clock).await?;
assert!(outcome.is_valid());
```

## Chaining note

`lockable` is eighth in the Devise module super-chain (lib.rs chain
position 7, after `confirmable`). It extends the chain verdict:
`active_for_authentication` becomes `super && !access_locked` (an
expired time lock auto-unlocks first), and `inactive_message` becomes
`:locked`. Its `unauthenticated_message` contributes the paranoid-aware
`:locked` and `:last_attempt` messages on failed sign-ins, and the
sign-in hook resets the counter on success exactly like Devise's warden
`after_set_user` lockable hook.
