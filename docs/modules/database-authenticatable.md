# `database_authenticatable`

Mirrors `Devise::Models::DatabaseAuthenticatable`
(`devise/lib/devise/models/database_authenticatable.rb`, untracked
upstream reference). Password handling over the `encrypted_password`
column, with virtual `password` and `password_confirmation` fields, the
bcrypt `Encryptor`, and the email/password change notifications.

The trait lives at
[`devise_rust::model::DatabaseAuthenticatable`](https://docs.rs/devise-rust/latest/devise_rust/model/trait.DatabaseAuthenticatable.html).

## Options

| devise option | Rust config field | Default | Notes |
|---------------|-------------------|---------|-------|
| `pepper` | `DeviseConfig.pepper` | nil | appended to the password before bcrypt hashing |
| `stretches` | `DeviseConfig.stretches` | 12 | bcrypt cost factor |
| `send_email_changed_notification` | `DeviseConfig.send_email_changed_notification` | false | email the ORIGINAL address on email change |
| `send_password_change_notification` | `DeviseConfig.send_password_change_notification` | false | email on password change |

Base options inherited from `Authenticatable` (all models implement the
base trait):

| devise option | Rust config field | Default | Notes |
|---------------|-------------------|---------|-------|
| `authentication_keys` | `DeviseConfig.authentication_keys` | `[:email]` | lookup attributes for credentials |
| `request_keys` | `DeviseConfig.request_keys` | `[]` | extra request attributes required to authenticate |
| `case_insensitive_keys` | `DeviseConfig.case_insensitive_keys` | `[:email]` | downcased before lookup |
| `strip_whitespace_keys` | `DeviseConfig.strip_whitespace_keys` | `[:email]` | stripped before lookup |

## Examples

Setting and verifying a password (the `password=` setter hashes through
the `Encryptor`; `valid_password` checks with the same pepper and
stretches):

<!-- text fence: needs a model and config in scope; the same call shape is
     compiled in the actix/axum example apps -->
```text
user.set_password(Some("secret123".to_string()), &config);
assert!(user.valid_password("secret123", &config));
assert!(!user.valid_password("wrong", &config));
```

Changing the account with the current-password check mirrors Devise's
`update_with_password`; a wrong `current_password` returns errors and
never persists:

<!-- text fence: adapter-dependent; compiled in the example apps -->
```text
let mut params = serde_json::Map::new();
params.insert("email".into(), serde_json::json!("new@example.com"));
params.insert("current_password".into(), serde_json::json!("wrong"));
match user.update_with_password(&mut params, &config) { Ok(()) => {} Err(errors) => {} }
```

## Chaining note

`database_authenticatable` is first in the Devise module super-chain
(`devise/lib/devise/modules.rb` order). Every later module's
`active_for_authentication` evaluation starts from the base
`Authenticatable` implementation this module builds on, and
`database_authenticatable` itself adds no condition: it provides the
password and salt surface (`authenticatable_salt` is the first 29
characters of `encrypted_password`) that session serialization and
rememberable both consume.
