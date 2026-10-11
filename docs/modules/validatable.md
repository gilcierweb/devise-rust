# `validatable`

Mirrors `Devise::Models::Validatable`
(`devise/lib/devise/models/validatable.rb`, untracked upstream
reference). Email and password validations: presence, format
(`email_regexp`), confirmation, and length (`password_length`).
Validation lives on the model and runs against the configuration;
uniqueness additionally needs the adapter.

The trait lives at
[`devise_rust::model::Validatable`](https://docs.rs/devise-rust/latest/devise_rust/model/trait.Validatable.html).

## Options

| devise option | Rust config field | Default | Notes |
|---------------|-------------------|---------|-------|
| `email_regexp` | `DeviseConfig.email_regexp` | `\A[^@\s]+@[^@\s]+\z` | Devise's exact default pattern |
| `password_length` | `DeviseConfig.password_length` | `6..128` | bounds inclusive, as in Ruby |

## Examples

`validate` returns the errors map with Devise's symbolic keys
(`:blank`, `:invalid`, `:taken`, `:too_short`, `:confirmation`), which
render through the I18n catalog with Devise's exact message keys:

<!-- text fence: model and config parameters; compiled in the validatable
     model tests -->
```text
let errors = user.validate(&config);
assert!(errors.is_empty());

let bad = User { email: "not-an-email".into(), password: Some("123".into()), ..Default::default() };
let errors = bad.validate(&config);
assert!(errors.fields().contains(&"email".to_string()));
```

`password_required` mirrors Devise's predicate: a password is required
for new records or whenever a password field is present:

<!-- text fence: model-dependent predicate; compiled in the validatable
     model tests -->
```text
assert!(user.password_required());
```

## Chaining note

`validatable` is sixth in the Devise module super-chain (after
`registerable`). It adds no `active_for_authentication` or
`inactive_message` condition: validations run inside the save paths that
`database_authenticatable`, `recoverable`, and `confirmable` drive, and
contribute their error keys to the `ResourceWithErrors` flow values the
controllers render.
