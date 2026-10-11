# `registerable`

Mirrors `Devise::Models::Registerable`
(`devise/lib/devise/models/registerable.rb`, untracked upstream
reference). Building records from sign-up params and the post-sign-up
and post-change-password decisions. The flow orchestration that Devise
puts in `RegistrationsController` is consumed by the framework route
groups in `devise-rust-actix` and `devise-rust-axum`.

The trait lives at
[`devise_rust::model::Registerable`](https://docs.rs/devise-rust/latest/devise_rust/model/trait.Registerable.html).

## Options

| devise option | Rust config field | Default | Notes |
|---------------|-------------------|---------|-------|
| `sign_in_after_change_password` | `DeviseConfig.sign_in_after_change_password` | true | sign the user back in after a password-changing account update |

## Examples

`new_with_session` builds the record from sign-up params, mirroring
Devise's class method of the same name:

<!-- text fence: params and session parameters; compiled in the example
     apps -->
```text
let user = User::new_with_session(&params, &session, &config);
```

The post-sign-up decision mirrors Devise's controller branch: an active
record signs in with the `:signed_up` flash, an inactive one signs up
without session data and flashes `signed_up_but_{inactive_message}`:

<!-- text fence: model-dependent decision flow; compiled in the
     registrations controller tests -->
```text
match user.post_sign_up_message() {
    None => { /* active_for_authentication: sign in, flash :signed_up */ }
    Some(key) => { /* flash "signed_up_but_{key}", no session data */ }
}
```

## Chaining note

`registerable` is fifth in the Devise module super-chain (after
`recoverable`). It adds no `active_for_authentication` or
`inactive_message` condition of its own; it consumes the chained verdict
(`active_for_authentication` plus `inactive_message`) that `confirmable`
and `lockable` contribute later in the chain to decide the sign-up flash
and session posture.
