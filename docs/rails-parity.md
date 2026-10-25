# Rails parity table

This is the exhaustive method-by-method parity audit between the vendored Devise Ruby gem (v5.0.4, `devise/` in the workspace root) and this Rust port. Every public method, every configuration option, every migration column, every I18n message key, every `devise_for` route row, and the 18 unsafe serialization attributes appear exactly once below with a status. The companion file [parity-checklist.md](parity-checklist.md) enumerates every Devise test block as ported or waived with per-case reasons; the two files are the single source of truth the guides, the CHANGELOG, and the Rails mapping doc cite.

Status values:

- `ported`: the Devise behavior exists in devise-rust under the same name (Rust naming rules applied: `?` and `!` suffixes dropped, predicates keep the stem) and is proven by the cited test.
- `deviated`: the behavior exists but with a documented, deliberate divergence; the note names the divergence and where it is documented.
- `waived`: the behavior is out of v1 scope; every waived row carries its reason and v1 impact in the checklist and here in the notes column.

## How to read the table

Columns are fixed for every section: `devise name`, `kind` (method, option, column, message, route), `devise source` (path with line in the vendored gem), `Rust counterpart` (path in this workspace), `status`, `test evidence` (the test path that proves the behavior), `notes`.

Test paths follow the workspace layout: core unit tests live in `#[cfg(test)]` modules inside the source file cited (for example `crates/devise-rust/src/confirmable.rs tests`), integration tests under `crates/*/tests/`, and the browser-parity flow matrices under `crates/devise-rust-actix/tests/devise_flows.rs` and `crates/devise-rust-axum/tests/devise_flows.rs`.

## Module methods

The ten modules appear in Devise's super-chain order (`devise/lib/devise/modules.rb`): database_authenticatable, rememberable, omniauthable, recoverable, registerable, validatable, confirmable, lockable, timeoutable, trackable, over the `authenticatable` base.

### authenticatable (base)

Mirrors `Devise::Models::Authenticatable` (`devise/lib/devise/models/authenticatable.rb`).

| devise name | kind | devise source | Rust counterpart | status | test evidence | notes |
|---|---|---|---|---|---|---|
| `valid_for_authentication?` | method | `models/authenticatable.rb:81` | `Authenticatable::valid_for_authentication` (`crates/devise-rust/src/model.rs:978`) | ported | `crates/devise-rust/src/model.rs tests` | yield-and-reject shape kept; rules parameter carries the lockable chain |
| `unauthenticated_message` | method | `models/authenticatable.rb:85` | `Authenticatable::unauthenticated_message` (`crates/devise-rust/src/model.rs:999`) | ported | `crates/devise-rust/src/strategy.rs tests` | `:invalid` default; paranoid-aware overrides in lockable |
| `active_for_authentication?` | method | `models/authenticatable.rb:89` | `Authenticatable::active_for_authentication` (`crates/devise-rust/src/model.rs:989`) | ported | `crates/devise-rust/src/model.rs tests (test_gate_chain_confirmable_before_lockable)` | super-chain order preserved: confirmable gate evaluated before lockable |
| `inactive_message` | method | `models/authenticatable.rb:93` | `Authenticatable::inactive_message` (`crates/devise-rust/src/model.rs:994`) | ported | `crates/devise-rust/src/model.rs tests` | `:inactive` default |
| `authenticatable_salt` | method | `models/authenticatable.rb:97` | `AnyDeviseModel::authenticatable_salt` (`crates/devise-rust/src/failure.rs:206`, base default) with `DatabaseAuthenticatable::authenticatable_salt` (`crates/devise-rust/src/model.rs:155`) | ported | `crates/devise-rust/src/session.rs tests (test_secure_compare_salt)` | salt embedded in the session payload; password change invalidates sessions |
| `serializable_hash` | method | `models/authenticatable.rb:105` | `Authenticatable::serializable_hash` (`crates/devise-rust/src/model.rs:1113`) | ported | `crates/devise-rust/src/model.rs tests (test_serializable_hash_excludes_password)` | unsafe attributes always excluded |
| `inspect` | method | `models/authenticatable.rb:120` | unsafe-attribute filtering on `serializable_hash` plus the `UNSAFE_ATTRIBUTES` list (`crates/devise-rust/src/error.rs`) | deviated | `crates/devise-rust/src/error.rs tests (test_unsafe_attributes)` | Rust has no global `Object#inspect` to override; model `Debug` impls are app-owned, so the guard is enforced at the library seam (`serializable_hash` plus `UNSAFE_ATTRIBUTES`) instead of on a Ruby global |
| `devise_mailer` | method | `models/authenticatable.rb:129` | `Mailer` trait (`crates/devise-rust/src/mailer.rs`) resolved through `DeviseConfig::mailer_sender` | ported | `crates/devise-rust/src/mailer.rs tests (mailer_sender_config_flows_to_from_header)` | per-app mailer replaces the `parent_mailer` class reference |
| `send_devise_notification` | method | `models/authenticatable.rb:193` | explicit notification dispatch on the module methods (`confirmable`, `recoverable`, `lockable`, `database_authenticatable`) | deviated | `crates/devise-rust/tests/notifications.rs` | documented extension point kept: Ruby defers to the mailer deliver call, Rust sends through the `Mailer` trait at the module call site; background queues plug in by implementing the trait |
| `downcase_keys` (callback) | method | `models/authenticatable.rb:198` | `ParameterFilter` downcase (`crates/devise-rust/src/parameter.rs`) plus `normalize_auth_attributes_static` (`crates/devise-rust/src/model.rs:1119`) | ported | `crates/devise-rust/src/parameter.rs tests (test_parameter_filter_downcase)` | explicit pipeline instead of `before_validation` callback |
| `strip_whitespace` (callback) | method | `models/authenticatable.rb:202` | `ParameterFilter` strip (`crates/devise-rust/src/parameter.rs`) | ported | `crates/devise-rust/src/parameter.rs tests (test_parameter_filter_strip_whitespace)` | explicit pipeline instead of callback |
| `required_fields` | method | `models/authenticatable.rb:71` | per-module `required_fields` functions (`crates/devise-rust/src/{confirmable,lockable,rememberable,timeoutable,trackable,omniauthable}.rs`) | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_required_fields_match_devise)` | base returns no columns; each module lists its own |
| `serialize_into_session` | method | `models/authenticatable.rb:225` | `session::serialize_into_session` (`crates/devise-rust/src/session.rs:105`) | ported | `crates/devise-rust/src/session.rs tests (test_session_serializer_roundtrip)` | payload is `[key, authenticatable_salt]` |
| `serialize_from_session` | method | `models/authenticatable.rb:229` | `session::serialize_from_session` (`crates/devise-rust/src/session.rs:118`) | ported | `crates/devise-rust/src/session.rs tests (test_session_salt_mismatch_deletes_key)` | salt mismatch deletes the session key (stale session rejection) |
| `params_authenticatable?` | method | `models/authenticatable.rb:234` | params strategy gating (`crates/devise-rust/src/strategy.rs`) | ported | `crates/devise-rust/src/strategy.rs tests (test_params_strategy_success)` | honors `DeviseConfig::params_authenticatable` |
| `http_authenticatable?` | method | `models/authenticatable.rb:239` | HTTP Basic strategy gating (`crates/devise-rust/src/strategy.rs`) | ported | `crates/devise-rust/src/strategy.rs tests (test_http_basic_strategy_success)` | honors `DeviseConfig::http_authenticatable` |
| `find_for_authentication` | method | `models/authenticatable.rb:263` | `Authenticatable::find_for_authentication` (`crates/devise-rust/src/model.rs:1031`) | ported | `crates/devise-rust/src/model.rs tests (test_normalize_auth_conditions)` | goes through the parameter filter |
| `find_first_by_auth_conditions` | method | `models/authenticatable.rb:267` | `Authenticatable::find_first_by_auth_conditions` (`crates/devise-rust/src/model.rs:1045`) | ported | `crates/devise-rust/src/model.rs tests` | custom filtering parameters supported |
| `find_or_initialize_with_error_by` | method | `models/authenticatable.rb:272` | `Authenticatable::find_or_initialize_with_error_by` (`crates/devise-rust/src/model.rs:1060`) | ported | `crates/devise-rust/src/model.rs tests` | blank and invalid error shapes |
| `find_or_initialize_with_errors` | method | `models/authenticatable.rb:277` | `Authenticatable::find_or_initialize_with_errors` (`crates/devise-rust/src/model.rs:1086`) | ported | `crates/devise-rust/src/model.rs tests` | unsaved record carrying errors, never a raise |
| `devise_parameter_filter` | method | `models/authenticatable.rb:296` | `ParameterFilter` (`crates/devise-rust/src/parameter.rs`) | ported | `crates/devise-rust/src/parameter.rs tests` | downcase and strip configured keys, stringifies scalars (UUID-safe) |
| `UNSAFE_ATTRIBUTES_FOR_SERIALIZATION` | method | `models/authenticatable.rb:58` | `UNSAFE_ATTRIBUTES` (`crates/devise-rust/src/error.rs`) | ported | `crates/devise-rust/src/error.rs tests (test_unsafe_attributes_count)` | all 18 attributes; full list in the unsafe attributes section below |

### database_authenticatable

Mirrors `Devise::Models::DatabaseAuthenticatable` (`devise/lib/devise/models/database_authenticatable.rb`).

| devise name | kind | devise source | Rust counterpart | status | test evidence | notes |
|---|---|---|---|---|---|---|
| `password=` | method | `models/database_authenticatable.rb:65` | `DatabaseAuthenticatable::set_password` (`crates/devise-rust/src/model.rs:132`) | ported | `crates/devise-rust/src/model.rs tests (database_authenticatable_methods)` | sets `encrypted_password` digest when present, blank stays blank |
| `valid_password?` | method | `models/database_authenticatable.rb:71` | `PasswordVerifiable::valid_password` (`crates/devise-rust/src/model.rs:79`) | ported | `crates/devise-rust/src/crypto.rs tests (test_encryptor_digest_compare)` | bcrypt re-hash plus constant-time compare, never `==` |
| `clean_up_passwords` | method | `models/database_authenticatable.rb:76` | `DatabaseAuthenticatable::clean_up_passwords` (`crates/devise-rust/src/model.rs:164`) | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_sign_up_failure_clears_passwords_and_keeps_errors)` | clears the virtual password fields on re-render |
| `update_with_password` | method | `models/database_authenticatable.rb:87` | `DatabaseAuthenticatable::update_with_password` (`crates/devise-rust/src/model.rs:196`) | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_account_update_requires_current_password)` | never persists when `current_password` is invalid; deletes blank password fields from params |
| `update_without_password` | method | `models/database_authenticatable.rb:120` | `DatabaseAuthenticatable::update_without_password` (`crates/devise-rust/src/model.rs:248`) | ported | `crates/devise-rust/src/model.rs tests (database_authenticatable_methods)` | never touches the password |
| `destroy_with_password` | method | `models/database_authenticatable.rb:132` | `DatabaseAuthenticatable::destroy_with_password` (`crates/devise-rust/src/model.rs:259`) | ported | `crates/devise-rust/src/model.rs tests (database_authenticatable_methods)` | requires valid `current_password` |
| `after_database_authentication` | method | `models/database_authenticatable.rb:154` | `DatabaseAuthenticatable::after_database_authentication` (`crates/devise-rust/src/model.rs:278`) | ported | `crates/devise-rust/tests/notifications.rs (after_database_authentication_fires_on_password_strategies)` | fired from the password strategies, same as Devise |
| `authenticatable_salt` | method | `models/database_authenticatable.rb:158` | `DatabaseAuthenticatable::database_authenticatable_salt` (`crates/devise-rust/src/model.rs:155`) | ported | `crates/devise-rust/src/model.rs tests` | `encrypted_password[0,29]` slice |
| `skip_email_changed_notification!` | method | `models/database_authenticatable.rb:49` | `DatabaseAuthenticatable::skip_email_changed_notification` (`crates/devise-rust/src/model.rs:183`) | ported | `crates/devise-rust/src/model.rs tests (database_authenticatable_notifications)` | one-shot skip flag |
| `skip_password_change_notification!` | method | `models/database_authenticatable.rb:54` | `DatabaseAuthenticatable::skip_password_change_notification` (`crates/devise-rust/src/model.rs:187`) | ported | `crates/devise-rust/src/model.rs tests (database_authenticatable_notifications)` | one-shot skip flag |
| `send_email_changed_notification` | method | `models/database_authenticatable.rb:163` | `DatabaseAuthenticatable::send_email_changed_notification` (`crates/devise-rust/src/model.rs:336`) | ported | `crates/devise-rust/tests/notifications.rs (email_change_notification_goes_to_original_address)` | recipient is the ORIGINAL address, driven by the ChangeSet |
| `send_password_change_notification` | method | `models/database_authenticatable.rb:168` | `DatabaseAuthenticatable::send_password_change_notification` (`crates/devise-rust/src/model.rs:364`) | ported | `crates/devise-rust/tests/notifications.rs (password_change_notification_goes_to_current_address)` | recipient is the current address |
| `send_email_changed_notification?` | method | `models/database_authenticatable.rb:183` | `DatabaseAuthenticatable::email_notification_recipient` (`crates/devise-rust/src/model.rs:283`) | ported | `crates/devise-rust/src/model.rs tests (database_authenticatable_notifications)` | dirty tracking via ChangeSet old/new maps |
| `send_password_change_notification?` | method | `models/database_authenticatable.rb:187` | `DatabaseAuthenticatable::password_change_notification_pending` (`crates/devise-rust/src/model.rs:303`) | ported | `crates/devise-rust/src/model.rs tests (database_authenticatable_notifications)` | honors config plus skip flag |
| `password_digest` | method | `models/database_authenticatable.rb:179` | `crypto::encryptor::digest` (`crates/devise-rust/src/crypto.rs:66`) | ported | `crates/devise-rust/src/crypto.rs tests (test_encryptor_with_pepper)` | bcrypt with pepper and `stretches` cost |
| `find_for_database_authentication` | method | `models/database_authenticatable.rb:198` | `DatabaseAuthenticatable::find_for_database_authentication` (`crates/devise-rust/src/model.rs:316`) | ported | `crates/devise-rust/src/strategy.rs tests (test_params_strategy_success)` | delegates to `find_for_authentication` |
| `encrypted_password` | column | `models/database_authenticatable.rb:58` | `crates/devise-rust-migrations` DDL | ported | `crates/devise-rust-migrations/tests/snapshots.rs (matrix_full_create)` | NOT NULL DEFAULT '' parity |

### registerable

Mirrors `Devise::Models::Registerable` (`devise/lib/devise/models/registerable.rb`). Behavior lives in the registrations flow of both framework crates.

| devise name | kind | devise source | Rust counterpart | status | test evidence | notes |
|---|---|---|---|---|---|---|
| `new_with_session` | method | `models/registerable.rb:21` | `Registerable::new_with_session` (`crates/devise-rust/src/model.rs:417`) | ported | `crates/devise-rust/src/model.rs tests (registerable_tests)` | session parameter present; default ignores it, same as Devise |
| `sign_in_after_change_password` | option | `models/registerable.rb` plus `devise/lib/devise.rb:312` | `DeviseConfig::sign_in_after_change_password` plus `Registerable::sign_in_after_change_password` (`crates/devise-rust/src/model.rs:443`) | ported | `crates/devise-rust/src/model.rs tests (registerable_tests)` | bypass sign-in when true, framework flows honor it |
| registrations controller surface | method | `devise/app/controllers/devise/registrations_controller.rb` | registration handlers in `crates/devise-rust-{actix,axum}/src/routes.rs` | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_sign_up_failure_clears_passwords_and_keeps_errors, flow_account_update_requires_current_password)` | build_resource, sign_up, update (update_with_password default), destroy, cancel semantics |

### recoverable

Mirrors `Devise::Models::Recoverable` (`devise/lib/devise/models/recoverable.rb`).

| devise name | kind | devise source | Rust counterpart | status | test evidence | notes |
|---|---|---|---|---|---|---|
| `reset_password` | method | `models/recoverable.rb:37` | `Recoverable::reset_password` (`crates/devise-rust/src/model.rs:716`) | ported | `crates/devise-rust/src/model.rs tests (reset_password_by_token_guards)` | save or `:blank` error on the password |
| `send_reset_password_instructions` | method | `models/recoverable.rb:50` | `Recoverable::send_reset_password_instructions` (`crates/devise-rust/src/model.rs:574`) | ported | `crates/devise-rust/src/model.rs tests (send_reset_password_instructions)` | returns the raw token; digest stored |
| `reset_password_period_valid?` | method | `models/recoverable.rb:77` | `Recoverable::reset_password_period_valid` (`crates/devise-rust/src/model.rs:557`) | ported | `crates/devise-rust/src/model.rs tests (reset_password_by_token_window)` | `reset_password_within` window |
| `set_reset_password_token` (protected) | method | `models/recoverable.rb:89` | fresh token issue inside `send_reset_password_instructions` (`crates/devise-rust/src/model.rs`) | ported | `crates/devise-rust/src/model.rs tests (issue_reset_token)` | generate, digest, save without validation, return RAW |
| `clear_reset_password_token` (protected) | method | `models/recoverable.rb:84` | `Recoverable::clear_reset_password_token` (`crates/devise-rust/src/model.rs:834`) | ported | `crates/devise-rust/src/model.rs tests` | clears on password or authentication key change |
| `send_reset_password_instructions_notification` (protected) | method | `models/recoverable.rb:98` | mail dispatch inside `send_reset_password_instructions` | ported | `crates/devise-rust/src/model.rs tests (send_reset_password_instructions)` | raw token only in the email |
| `with_reset_password_token` | method | `models/recoverable.rb:114` | `Recoverable::with_reset_password_token` (`crates/devise-rust/src/model.rs:633`) | ported | `crates/devise-rust/src/model.rs tests (issue_reset_token)` | digest lookup |
| `send_reset_password_instructions` (class) | method | `models/recoverable.rb:123` | `Recoverable::send_reset_password_instructions_for` (`crates/devise-rust/src/model.rs:663`) | ported | `crates/devise-rust/src/model.rs tests` | uses `reset_password_keys`; paranoid-safe through `find_or_initialize_with_errors` |
| `reset_password_by_token` | method | `models/recoverable.rb:134` | `Recoverable::reset_password_by_token` (`crates/devise-rust/src/model.rs:763`) | ported | `crates/devise-rust/src/model.rs tests (reset_password_by_token_guards, reset_password_by_token_window)` | blank token guard, window check, `:expired` error, raw token restored on the returned record |
| `reset_password_token` | column | `models/recoverable.rb:27` | `crates/devise-rust-migrations` DDL | ported | `crates/devise-rust-migrations/tests/snapshots.rs (recoverable_adds_its_index_without_confirmation_index)` | digest only |
| `reset_password_sent_at` | column | `models/recoverable.rb:27` | `crates/devise-rust-migrations` DDL | ported | `crates/devise-rust-migrations/tests/snapshots.rs (matrix_full_create)` | window anchor |

### rememberable

Mirrors `Devise::Models::Rememberable` (`devise/lib/devise/models/rememberable.rb`).

| devise name | kind | devise source | Rust counterpart | status | test evidence | notes |
|---|---|---|---|---|---|---|
| `remember_me!` | method | `models/rememberable.rb:50` | `Rememberable::remember_me` (`crates/devise-rust/src/rememberable.rs`) | ported | `crates/devise-rust/src/rememberable.rs tests (rememberable_tracer_remember_then_cookie_round_trip_valid, rememberable_remember_reuse_keeps_token_without_write)` | token column reused when present, salt mode otherwise; save without validation on change |
| `forget_me!` | method | `models/rememberable.rb:58` | `Rememberable::forget_me` (`crates/devise-rust/src/rememberable.rs`) | ported | `crates/devise-rust/src/rememberable.rs tests (rememberable_forget_clears_per_expire_all, rememberable_forget_unpersisted_touches_no_adapter)` | honors `expire_all_remember_me_on_sign_out` |
| `remember_expires_at` | method | `models/rememberable.rb:65` | `Rememberable::remember_expires_at` (`crates/devise-rust/src/rememberable.rs`) | ported | `crates/devise-rust/src/rememberable.rs tests` | `remember_for` from now |
| `extend_remember_period` | method | `models/rememberable.rb:69` | `Rememberable::extend_remember_period` (`crates/devise-rust/src/rememberable.rs`) | ported | `crates/devise-rust/src/strategy.rs tests (test_strategy_rememberable_extend_reissues_when_enabled)` | re-issues the cookie on remember-hit when enabled |
| `rememberable_value` | method | `models/rememberable.rb:73` | `Rememberable::rememberable_value` (`crates/devise-rust/src/rememberable.rs`) | ported | `crates/devise-rust/src/rememberable.rs tests (rememberable_value_resolution)` | token column or `authenticatable_salt`; explicit error when neither |
| `rememberable_options` | method | `models/rememberable.rb:86` | `Rememberable::rememberable_options` (`crates/devise-rust/src/rememberable.rs`) | ported | `crates/devise-rust/src/rememberable.rs tests` | cookie options map from config |
| `after_remembered` | method | `models/rememberable.rb:100` | `Rememberable::after_remembered` (`crates/devise-rust/src/rememberable.rs`) | ported | `crates/devise-rust/src/strategy.rs tests (test_strategy_rememberable_round_trip_success)` | hook extension point, fired by the strategy |
| `remember_me?` (5 conditions) | method | `models/rememberable.rb:103` | `Rememberable::remember_me_valid` (`crates/devise-rust/src/rememberable.rs`) | ported | `crates/devise-rust/src/rememberable.rs tests (rememberable_nil_case_* , rememberable_equal_timestamps_are_invalid, rememberable_password_rotation_kills_older_cookies)` | all five Devise conditions including `secure_compare` and the generated-at check |
| `time_from_json` | method | `models/rememberable.rb:124` | strict integer-epoch parse inside `serialize_from_cookie` (`crates/devise-rust/src/rememberable.rs`) | deviated | `crates/devise-rust/src/rememberable.rs tests (rememberable_nil_case_invalid_datetime)` | Devise carries a TODO accepting float strings; the port rejects them fail-closed (documented divergence, STATE Phase 5 decision) |
| `serialize_into_cookie` | method | `models/rememberable.rb:134` | `Rememberable::serialize_into_cookie` (`crates/devise-rust/src/rememberable.rs`) | ported | `crates/devise-rust/src/session.rs tests (test_cookie_serializer)` | `[key, rememberable_value, timestamp]` |
| `serialize_from_cookie` | method | `models/rememberable.rb:139` | `Rememberable::serialize_from_cookie` (`crates/devise-rust/src/session.rs:171`) | ported | `crates/devise-rust/src/rememberable.rs tests (rememberable_nil_case_unknown_resource, rememberable_missing_created_at_is_invalid)` | validates all conditions before reviving |
| `remember_token` (class helper) | method | `models/rememberable.rb:147` | `session::generate_remember_token` (`crates/devise-rust/src/session.rs:216`) | ported | `crates/devise-rust/src/session.rs tests` | friendly-token loop until unused |
| `remember_created_at` | column | `models/rememberable.rb:46` | `crates/devise-rust-migrations` DDL | ported | `crates/devise-rust-migrations/tests/snapshots.rs (remember_token_opt_in)` | plus opt-in `remember_token` for DB-token mode |
| rememberable strategy | method | `devise/lib/devise/strategies/rememberable.rb:21` | `RememberableStrategy` (`crates/devise-rust/src/strategy.rs`) | ported | `crates/devise-rust/src/strategy.rs tests (test_strategy_rememberable_miss_shapes_delete_and_pass)` | stale cookie deletes and passes through; runs before params and HTTP Basic (no-input first) |

### omniauthable

Mirrors `Devise::Models::Omniauthable` (`devise/lib/devise/models/omniauthable.rb`) plus `devise/lib/devise/omniauth/`.

| devise name | kind | devise source | Rust counterpart | status | test evidence | notes |
|---|---|---|---|---|---|---|
| `from_omniauth` (app-supplied) | method | `models/omniauthable.rb:24` | required `Omniauthable::from_omniauth` trait method plus `default_from_omniauth` (`crates/devise-rust/src/omniauthable.rs:512`) | deviated | `crates/devise-rust/src/omniauthable.rs tests (omniauthable_policy_returns_existing_identity_row, omniauthable_policy_links_verified_email_collision)` | Devise leaves the finder to the app; the port makes it a required trait method and ships the find-link-create policy behind the verified-email gate as a default helper (STATE Phase 9 decision, D-08) |
| `omniauth_providers` | option | `devise/lib/devise.rb` plus `models/omniauthable.rb` | `DeviseConfig::omniauth_providers` allowlist plus `OAuthProviderConfig` registry (`crates/devise-rust/src/omniauthable.rs`) | ported | `crates/devise-rust/src/omniauthable.rs tests (omniauthable_config_providers_default_empty_and_override_resolves)` | providers resolved through `DeviseConfigOverride` |
| authorize + callback routes | route | `devise/lib/devise/rails/routes.rb` omniauth block | `omniauth_route_specs` (`crates/devise-rust/src/scope.rs:656`) mounted by both framework crates | ported | `crates/devise-rust/src/scope.rs tests (test_route_specs_omniauthable_emits_post_authorize_get_or_post_callback)` | POST authorize, GET or POST callback (devise 5.0.4 amendment) |
| `omniauth_callbacks` controller | method | `devise/app/controllers/devise/omniauth_callbacks_controller.rb` | omniauth handlers in `crates/devise-rust-{actix,axum}/src/omniauth.rs` | ported | `crates/devise-rust-axum/tests/omniauth_flows.rs`, `crates/devise-rust-actix/tests/omniauth_flows.rs` | 10-case flow matrix per framework with the stub provider |
| state + PKCE stash | method | `devise/lib/devise/omniauth/` plus devise 5.0.4 CSRF handling | session-resident `devise.{scope}.omniauth.{provider}.*` keys, single-use, bridge-indexed | ported | `crates/devise-rust/src/omniauthable.rs tests (omniauthable_authorize_start_always_carries_pkce_and_state, omniauthable_verify_state_mismatch_fails_closed)` | absent state fails closed by construction (T-09-09) |
| `passthru` | method | `devise/app/controllers/devise/omniauth_callbacks_controller.rb` | provider-not-configured fallthrough in the omniauth handlers | ported | `crates/devise-rust-axum/tests/omniauth_flows.rs` | unconfigured provider 404s, same surface |
| failure message | message | `devise/config/locales/en.yml` `devise.omniauth_callbacks.failure` | `omniauthable::failure_message` (`crates/devise-rust/src/omniauthable.rs:589`) | ported | `crates/devise-rust/src/omniauthable.rs tests (omniauthable_failure_message_renders_devise_template)` | renders the Devise interpolation |
| success message | message | `devise/config/locales/en.yml` `devise.omniauth_callbacks.success` | `omniauthable::success_message` (`crates/devise-rust/src/omniauthable.rs:612`) | ported | `crates/devise-rust/src/omniauthable.rs tests (omniauthable_success_message_renders_devise_template)` | renders the Devise interpolation |

### validatable

Mirrors `Devise::Models::Validatable` (`devise/lib/devise/models/validatable.rb`).

| devise name | kind | devise source | Rust counterpart | status | test evidence | notes |
|---|---|---|---|---|---|---|
| `password_required?` | method | `models/validatable.rb:57` | `Validatable::password_required` (`crates/devise-rust/src/model.rs:878`) | ported | `crates/devise-rust/tests/model_validation.rs (password_confirmation_must_match)` | new record or password present |
| `email_required?` | method | `models/validatable.rb:61` | `Validatable::email_required` (`crates/devise-rust/src/model.rs:883`) | ported | `crates/devise-rust/tests/model_validation.rs (blank_values_use_blank_error_keys)` | overridable, default true |
| email format validation | method | `models/validatable.rb:29` | `Validatable::email_format_valid` plus `validate` (`crates/devise-rust/src/model.rs:897`) | ported | `crates/devise-rust/tests/model_validation.rs (email_format_validation_uses_devise_regexp)` | Devise's exact regexp matrix |
| password length validation | method | `models/validatable.rb:83` | length check inside `Validatable::validate` (`crates/devise-rust/src/model.rs:907`) | ported | `crates/devise-rust/tests/model_validation.rs (password_length_bounds_6_to_128_inclusive)` | `password_length` 6..128 inclusive |
| confirmation validation | method | `models/validatable.rb:75` | confirmation check inside `Validatable::validate` | ported | `crates/devise-rust/tests/model_validation.rs (password_confirmation_must_match)` | `:confirmation` error key |
| uniqueness validation | method | `models/validatable.rb:14` | `Validatable::validate_email_uniqueness` (`crates/devise-rust/src/model.rs:948`) | ported | `crates/devise-rust/tests/model_validation.rs (email_uniqueness_is_case_sensitive_at_db)` | DB-level lookup stays case-sensitive; the parameter filter normalizes before persistence (AUTH-06) |
| `assert_validations_api!` | method | `models/validatable.rb:43` | compile-time trait bounds on `Validatable` | waived | `crates/devise-rust/tests/model_validation.rs` | reason: Ruby asserts a runtime validations API on the including class; Rust replaces the check with compile-time trait bounds, so there is no runtime API to assert. v1 impact: none, validation semantics are enforced by `Validatable::validate` and its tests. |
| `VALIDATIONS` const | method | `models/validatable.rb` | trait surface itself | waived | `crates/devise-rust/tests/model_validation.rs` | reason: the constant exists so Devise can probe the ActiveModel validations API at load time; no such runtime probe exists in Rust. v1 impact: none. |

### confirmable

Mirrors `Devise::Models::Confirmable` (`devise/lib/devise/models/confirmable.rb`).

| devise name | kind | devise source | Rust counterpart | status | test evidence | notes |
|---|---|---|---|---|---|---|
| `confirm` | method | `models/confirmable.rb:79` | `Confirmable::confirm` (`crates/devise-rust/src/confirmable.rs`) | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_tracer_generate_then_confirm_by_token, confirmable_double_confirm_errors_without_refiring_hook)` | guards `pending_any_confirmation`; validation via caller-supplied closure (STATE Phase 5 decision) |
| `confirmed?` | method | `models/confirmable.rb:106` | `Confirmable::confirmed` (`crates/devise-rust/src/confirmable.rs`) | ported | `crates/devise-rust/src/confirmable.rs tests` | `confirmed_at` presence |
| `pending_reconfirmation?` | method | `models/confirmable.rb:110` | `Confirmable::pending_reconfirmation` (`crates/devise-rust/src/confirmable.rs`) | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_reconfirmation_postpones_with_d05_routing)` | unconfirmed_email present |
| `send_confirmation_instructions` | method | `models/confirmable.rb:115` | send path on `Confirmable` (`crates/devise-rust/src/confirmable.rs`) | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_class_send_finds_unconfirmed_first_and_paranoid_stays_silent)` | generates or reuses the live token |
| `send_reconfirmation_instructions` | method | `models/confirmable.rb:124` | reconfirmation send path on `Confirmable` | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_reconfirmation_postpones_with_d05_routing)` | emails the unconfirmed address |
| `resend_confirmation_instructions` | method | `models/confirmable.rb:134` | resend path on `Confirmable` | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_resend_reuses_live_token_without_sent_at_bump, confirmable_resend_rotates_expired_token_and_sent_at)` | live token reused without bumping sent_at; expired token rotates |
| `active_for_authentication?` | method | `models/confirmable.rb:144` | `Confirmable::confirmation_gate_active` (`crates/devise-rust/src/confirmable.rs`) | ported | `crates/devise-rust/src/model.rs tests (test_gate_chain_confirmable_before_lockable)` | super && confirmation gate; evaluated before lockable |
| `inactive_message` | method | `models/confirmable.rb:149` | `Confirmable::confirmation_inactive_message` (`crates/devise-rust/src/confirmable.rs`) | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_allow_window_three_way_table)` | `:unconfirmed`, unsuppressed under paranoid |
| `skip_confirmation!` | method | `models/confirmable.rb:155` | `Confirmable::skip_confirmation` (`crates/devise-rust/src/confirmable.rs`) | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_skip_flags_suppress_without_confirming)` | sets confirmed_at now without save |
| `skip_confirmation_notification!` | method | `models/confirmable.rb:161` | `Confirmable::skip_confirmation_notification` (`crates/devise-rust/src/confirmable.rs`) | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_skip_flags_suppress_without_confirming)` | suppresses the mail only |
| `skip_reconfirmation!` | method | `models/confirmable.rb:167` | `Confirmable::skip_reconfirmation` plus `consume_reconfirmation_bypass` (`crates/devise-rust/src/confirmable.rs`) | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_skip_reconfirmation_applies_email_directly)` | explicit flag pair replaces the callback variant |
| `after_confirmation` | method | `models/confirmable.rb:310` | `Confirmable::after_confirmation` (`crates/devise-rust/src/confirmable.rs`) | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_double_confirm_errors_without_refiring_hook)` | fired exactly once per confirmation |
| `confirmation_required?` (protected) | method | `models/confirmable.rb:187` | `Confirmable::confirmation_required` (`crates/devise-rust/src/confirmable.rs`) | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_allow_window_three_way_table)` | nil means true, zero means false |
| `confirmation_period_valid?` (protected) | method | `models/confirmable.rb:213` | `Confirmable::confirmation_period_valid` (`crates/devise-rust/src/confirmable.rs`) | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_confirm_within_window_edges)` | three-way window table ported |
| `confirmation_period_expired?` (protected) | method | `models/confirmable.rb:232` | `Confirmable::confirmation_period_expired` (`crates/devise-rust/src/confirmable.rs`) | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_confirm_within_none_never_expires)` | `confirm_within` nil never expires |
| `generate_confirmation_token` / `!` (protected) | method | `models/confirmable.rb:248` | `Confirmable::store_fresh_confirmation_token` plus `ensure_confirmation_token` (`crates/devise-rust/src/confirmable.rs`) | ported | `crates/devise-rust/src/confirmable.rs tests` | reuses the live token; raw kept transient, digest stored |
| `postpone_email_change_until_confirmation_and_regenerate_confirmation_token` (protected) | method | `models/confirmable.rb:261` | reconfirmation postponement path (`crates/devise-rust/src/confirmable.rs`) | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_reconfirmation_postpones_with_d05_routing, confirmable_5783_double_submit_keeps_victim_unconfirmed)` | email postponed to `unconfirmed_email`, token regenerated; the #5783 forced write is preserved (TEST-03 item 3) |
| `postpone_email_change?` / `reconfirmation_required?` (protected) | method | `models/confirmable.rb:272,282` | postponement predicates on `Confirmable` | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_reconfirmation_always_validates)` | reconfirmation always validates |
| `send_confirmation_notification?` (protected) | method | `models/confirmable.rb:286` | `Confirmable::should_send_confirmation_notification` (`crates/devise-rust/src/confirmable.rs`) | ported | `crates/devise-rust/src/confirmable.rs tests` | honors the skip flag |
| `skip_reconfirmation_in_callback!` (protected) | method | `models/confirmable.rb:175` | `Confirmable::consume_reconfirmation_bypass` (`crates/devise-rust/src/confirmable.rs`) | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_skip_reconfirmation_applies_email_directly)` | explicit consume replaces the after_create callback |
| `send_confirmation_instructions` (class) | method | `models/confirmable.rb:318` | class-level send on `Confirmable` | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_class_send_finds_unconfirmed_first_and_paranoid_stays_silent)` | reconfirmable: tries unconfirmed_email first; paranoid stays silent |
| `confirm_by_token` | method | `models/confirmable.rb:331` | `Confirmable::confirm_by_token` (`crates/devise-rust/src/confirmable.rs`) | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_tracer_blank_token_touches_no_adapter, confirmable_digest_legacy_row_confirms_through_raw_lookup)` | blank token guard; raw-first then digested (legacy) lookup |
| `find_by_unconfirmed_email_with_errors` (class, protected) | method | `models/confirmable.rb:359` | folded into the class-level send on `Confirmable` | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_class_send_finds_unconfirmed_first_and_paranoid_stays_silent)` | unsaved record carrying errors |
| `humanize_period` helper | method | `devise/lib/devise/models/confirmable.rb` `TimeInflector` use | `confirmable::humanize_period` (`crates/devise-rust/src/confirmable.rs`) | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_humanize_period_renders_devise_windows)` | renders the `confirmation_period_expired` period |
| `confirmation_token` / `confirmed_at` / `confirmation_sent_at` / `unconfirmed_email` | column | `models/confirmable.rb:70` | `crates/devise-rust-migrations` DDL | ported | `crates/devise-rust-migrations/tests/snapshots.rs (reconfirmable_off_omits_unconfirmed_email)` | `unconfirmed_email` gated on reconfirmable |

### lockable

Mirrors `Devise::Models::Lockable` (`devise/lib/devise/models/lockable.rb`).

| devise name | kind | devise source | Rust counterpart | status | test evidence | notes |
|---|---|---|---|---|---|---|
| `lock_access!` | method | `models/lockable.rb:42` | `Lockable::lock_access` plus `lock_access_with_options` (`crates/devise-rust/src/lockable.rs`) | ported | `crates/devise-rust/src/lockable.rs tests (lockable_lock_access_mails_raw_stores_digest, lockable_lock_access_opt_out_skips_mail)` | `send_instructions: false` opt kept through the options variant |
| `unlock_access!` | method | `models/lockable.rb:53` | `Lockable::unlock_access` (`crates/devise-rust/src/lockable.rs`) | ported | `crates/devise-rust/src/lockable.rs tests` | clears all three fields |
| `reset_failed_attempts!` | method | `models/lockable.rb:61` | `Lockable::reset_failed_attempts` (`crates/devise-rust/src/lockable.rs`) | ported | `crates/devise-rust/src/lockable.rs tests (lockable_reset_failed_attempts_writes_zero)` | writes zero without model validations; warden hook parity via `reset_failed_attempts_hook` |
| `access_locked?` | method | `models/lockable.rb:69` | `Lockable::access_locked` (`crates/devise-rust/src/lockable.rs`) | ported | `crates/devise-rust/src/lockable.rs tests (lockable_expired_time_lock_releases_live_lock_holds)` | locked_at present and not expired |
| `send_unlock_instructions` | method | `models/lockable.rb:74` | `Lockable::send_unlock_instructions` (`crates/devise-rust/src/lockable.rs`) | ported | `crates/devise-rust/src/lockable.rs tests (lockable_lock_access_mails_raw_stores_digest)` | returns the raw token, digest stored |
| `resend_unlock_instructions` | method | `models/lockable.rb:83` | resend path on `Lockable` | ported | `crates/devise-rust/src/lockable.rs tests (lockable_resend_refuses_unlocked_record)` | refuses unlocked records |
| `active_for_authentication?` | method | `models/lockable.rb:89` | `Lockable::lock_gate_active` (`crates/devise-rust/src/lockable.rs`) | ported | `crates/devise-rust/src/model.rs tests (test_gate_chain_confirmable_before_lockable)` | super && !access_locked |
| `inactive_message` | method | `models/lockable.rb:95` | `Lockable::lock_inactive_message` (`crates/devise-rust/src/lockable.rs`) | ported | `crates/devise-rust/src/lockable.rs tests (lockable_paranoid_suppresses_lock_messages)` | `:locked`; suppressed under paranoid |
| `valid_for_authentication?` | method | `models/lockable.rb:102` | lockable chain path (`crates/devise-rust/src/lockable.rs`) | ported | `crates/devise-rust/src/lockable.rs tests (lockable_chain_locks_at_threshold_and_counts_when_locked, lockable_chain_releases_expired_lock, lockable_chain_reads_counter_from_store, lockable_chain_skips_unpersisted_and_none_strategy)` | auto-unlock on expired lock, increment and lock at threshold, save otherwise |
| `increment_failed_attempts` (protected) | method | `models/lockable.rb:122` | `Lockable::increment_failed_attempts` (`crates/devise-rust/src/lockable.rs`) | ported | `crates/devise-rust/src/lockable.rs tests` | counter write plus re-read on the same pooled connection |
| `unauthenticated_message` | method | `models/lockable.rb:127` | `Lockable` unauthenticated message path (`crates/devise-rust/src/lockable.rs`) | ported | `crates/devise-rust/src/lockable.rs tests (lockable_last_attempt_matrix, lockable_paranoid_suppresses_lock_messages)` | paranoid-aware `:locked` / `:last_attempt` / super |
| `attempts_exceeded?` (protected) | method | `models/lockable.rb:143` | `Lockable::attempts_exceeded` (`crates/devise-rust/src/lockable.rs`) | ported | `crates/devise-rust/src/lockable.rs tests (lockable_tracer_counter_to_lock)` | `failed_attempts >= maximum_attempts` |
| `last_attempt?` (protected) | method | `models/lockable.rb:147` | `Lockable::last_attempt` (`crates/devise-rust/src/lockable.rs`) | ported | `crates/devise-rust/src/lockable.rs tests (lockable_last_attempt_matrix)` | equals maximum minus one; honors `last_attempt_warning` |
| `lock_expired?` (protected) | method | `models/lockable.rb:152` | `Lockable::lock_expired` (`crates/devise-rust/src/lockable.rs`) | ported | `crates/devise-rust/src/lockable.rs tests (lockable_expired_time_lock_releases_live_lock_holds)` | time strategy only |
| `if_access_locked` (protected) | method | `models/lockable.rb:162` | locked guard inside the send path | ported | `crates/devise-rust/src/lockable.rs tests (lockable_resend_refuses_unlocked_record)` | instructions only for locked records |
| `send_unlock_instructions` (class) | method | `models/lockable.rb:179` | class-level send on `Lockable` | ported | `crates/devise-rust/src/lockable.rs tests (lockable_class_send_unlock_instructions, lockable_class_send_requires_all_unlock_keys)` | `unlock_keys` required in full |
| `unlock_access_by_token` | method | `models/lockable.rb:189` | `Lockable::unlock_access_by_token` (`crates/devise-rust/src/lockable.rs`) | ported | `crates/devise-rust/src/lockable.rs tests (lockable_unlock_access_by_token_round_trip, lockable_unlock_access_by_token_blank_touches_no_adapter, lockable_unlock_access_by_token_invalid)` | digest lookup; raw token restored on the returned record |
| `unlock_strategy_enabled?` | method | `models/lockable.rb:200` | `Lockable::unlock_strategy_enabled` (`crates/devise-rust/src/lockable.rs`) | ported | `crates/devise-rust/src/lockable.rs tests (lockable_unlock_strategy_predicates_and_required_fields)` | both/email/time/none matrix |
| `lock_strategy_enabled?` | method | `models/lockable.rb:206` | `Lockable::lock_strategy_enabled` (`crates/devise-rust/src/lockable.rs`) | ported | `crates/devise-rust/src/lockable.rs tests (lockable_tracer_none_strategy_no_side_effects)` | failed_attempts/none |
| `failed_attempts` / `locked_at` / `unlock_token` | column | `models/lockable.rb:29` | `crates/devise-rust-migrations` DDL | ported | `crates/devise-rust-migrations/tests/snapshots.rs (lockable_none_strategies_emit_only_locked_at)` | columns follow the configured strategies |

### timeoutable

Mirrors `Devise::Models::Timeoutable` (`devise/lib/devise/models/timeoutable.rb`) plus the warden hook (`devise/lib/devise/hooks/timeoutable.rb`).

| devise name | kind | devise source | Rust counterpart | status | test evidence | notes |
|---|---|---|---|---|---|---|
| `timedout?` | method | `models/timeoutable.rb:30` | `timeoutable::check_timeout` plus `tick_expired` (`crates/devise-rust/src/timeoutable.rs:210,260`) | ported | `crates/devise-rust/src/timeoutable.rs tests (timeoutable_matrix_config_fallback_and_zero_window)` | last_access within `timeout_in` window; zero window never times out |
| `timeout_in` | method | `models/timeoutable.rb:34` | per-scope override through `DeviseConfigOverride::resolve` plus the config fallback | ported | `crates/devise-rust/src/timeoutable.rs tests (timeoutable_matrix_config_fallback_and_zero_window)` | per-scope overrides cascade like `Devise::Models.config` |
| last_request_at tick hook | method | `devise/lib/devise/hooks/timeoutable.rb` | `timeoutable` tick hook (`crates/devise-rust/src/hooks.rs`) | ported | `crates/devise-rust/src/hooks.rs tests (test_timeoutable_tick_hook_stale_signs_out_all_scopes, test_timeoutable_tick_hook_live_ticks_and_exempt_stays)` | updates `last_request_at` per request; remember-active sessions exempt |
| `last_request_at` parsing | method | `devise/lib/devise/hooks/timeoutable.rb` | `timeoutable::parse_last_request_at` plus `classify_last_request` (`crates/devise-rust/src/timeoutable.rs:136,179`) | ported | `crates/devise-rust/src/timeoutable.rs tests` | integer epoch or parseable string; malformed fails closed to expired |
| timeout sign-out path | method | `devise/lib/devise/hooks/timeoutable.rb` | `HookProxy::sign_out_for_timeout` (`crates/devise-rust/src/hooks.rs`) | ported | `crates/devise-rust/src/hooks.rs tests (test_timeoutable_tick_hook_stale_signs_out_all_scopes)` | routes through real sign-out so logout hooks clear the remember cookie |
| skip flags (`devise.skip_timeoutable`) | method | `devise/lib/devise/hooks/timeoutable.rb` | `RequestFlags` skip on `AuthRequest` (`crates/devise-rust/src/request.rs`) | ported | `crates/devise-rust-axum/tests/devise_flows.rs` plus `crates/devise-rust/src/timeoutable.rs tests` | sign-in and sign-out requests skip the tick |

### trackable

Mirrors `Devise::Models::Trackable` (`devise/lib/devise/models/trackable.rb`) plus the warden hook (`devise/lib/devise/hooks/trackable.rb`).

| devise name | kind | devise source | Rust counterpart | status | test evidence | notes |
|---|---|---|---|---|---|---|
| `update_tracked_fields` | method | `models/trackable.rb:20` | `Trackable::update_tracked_fields` (`crates/devise-rust/src/trackable.rs`) | ported | `crates/devise-rust/src/trackable.rs tests (trackable_matrix_shift_sets_without_saving)` | sets attributes without saving |
| `update_tracked_fields!` | method | `models/trackable.rb:33` | tracked-fields persist path (`crates/devise-rust/src/trackable.rs`) | ported | `crates/devise-rust/src/trackable.rs tests (trackable_matrix_bang_skips_unpersisted_and_validates_nothing)` | skips unpersisted records (issue 4673 parity); save without validation |
| `extract_ip_from` (protected) | method | `models/trackable.rb:45` | `Trackable::extract_ip_from` (`crates/devise-rust/src/trackable.rs`) | ported | `crates/devise-rust/src/trackable.rs tests (trackable_matrix_extract_ip_overridable)` | overridable; peer address source |
| trackable hook | method | `devise/lib/devise/hooks/trackable.rb` | trackable hook (`crates/devise-rust/src/hooks.rs`) | ported | `crates/devise-rust/src/hooks.rs tests (test_trackable_hook_shifts_memo_and_honors_skip)` | after_set_user except fetch; `devise.skip_trackable` honored |
| `sign_in_count` / `current_sign_in_at` / `last_sign_in_at` / `current_sign_in_ip` / `last_sign_in_ip` | column | `models/trackable.rb:16` | `crates/devise-rust-migrations` DDL | ported | `crates/devise-rust-migrations/tests/snapshots.rs (matrix_full_create)` | shift current to last on each sign-in |

## Configuration options

Every option from `Devise.setup` (`devise/lib/devise.rb` mattr_accessor lines cited) maps to a `DeviseConfig` field (`crates/devise-rust/src/config.rs:86-217`) with the same name and Devise 5.0.4 default. Per-scope overrides cascade through `DeviseConfigOverride::resolve` the way `Devise::Models.config` does.

| devise name | kind | devise source | Rust counterpart | status | test evidence | notes |
|---|---|---|---|---|---|---|
| `secret_key` | option | `lib/devise.rb:65` | `DeviseConfig::secret_key` (`config.rs:89`) | ported | `crates/devise-rust/src/crypto.rs tests (test_token_generator_digest)` | HMAC key for token digests |
| `rememberable_options` | option | `lib/devise.rb:69` | `DeviseConfig::rememberable_options` (`config.rs:128`) | ported | `crates/devise-rust/src/rememberable.rs tests` | cookie options map, includes the `key` override |
| `stretches` | option | `lib/devise.rb:73` | `DeviseConfig::stretches` (`config.rs:93`) | ported | `crates/devise-rust/src/crypto.rs tests (test_encryptor_with_pepper)` | bcrypt cost, default 12 |
| `http_authentication_key` | option | `lib/devise.rb:77` | `DeviseConfig::http_authentication_key` (`config.rs:107`) | ported | `crates/devise-rust/src/strategy.rs tests (test_http_basic_strategy_success)` | HTTP Basic header name |
| `authentication_keys` | option | `lib/devise.rb:81` | `DeviseConfig::authentication_keys` (`config.rs:97`) | ported | `crates/devise-rust/src/strategy.rs tests` | default `[email]` |
| `request_keys` | option | `lib/devise.rb:85` | `DeviseConfig::request_keys` (`config.rs:99`) | ported | `crates/devise-rust/src/strategy.rs tests (test_strategy_chain_order)` | extra request-derived keys |
| `case_insensitive_keys` | option | `lib/devise.rb:89` | `DeviseConfig::case_insensitive_keys` (`config.rs:101`) | ported | `crates/devise-rust/src/parameter.rs tests (test_parameter_filter_downcase)` | default `[email]` |
| `strip_whitespace_keys` | option | `lib/devise.rb:93` | `DeviseConfig::strip_whitespace_keys` (`config.rs:103`) | ported | `crates/devise-rust/src/parameter.rs tests (test_parameter_filter_strip_whitespace)` | default `[email]` |
| `http_authenticatable` | option | `lib/devise.rb:97` | `DeviseConfig::http_authenticatable` (`config.rs:105`) | ported | `crates/devise-rust/src/strategy.rs tests (test_http_basic_strategy_success)` | default false |
| `http_authenticatable_on_xhr` | option | `lib/devise.rb:101` | `DeviseConfig::http_authenticatable_on_xhr` (`config.rs:109`) | ported | `crates/devise-rust/src/request.rs tests (test_is_xhr)` | default true |
| `params_authenticatable` | option | `lib/devise.rb:105` | `DeviseConfig::params_authenticatable` (`config.rs:111`) | ported | `crates/devise-rust/src/strategy.rs tests (test_params_strategy_success)` | default true |
| `http_authentication_realm` | option | `lib/devise.rb:109` | `DeviseConfig::http_authentication_realm` (`config.rs:113`) | ported | `crates/devise-rust/src/failure.rs tests` | default "Application" |
| `email_regexp` | option | `lib/devise.rb:115` | `DeviseConfig::email_regexp` (`config.rs:117`) | ported | `crates/devise-rust/src/config.rs tests (test_email_regexp_matches_devise_matrix)` | Devise's exact pattern |
| `password_length` | option | `lib/devise.rb:119` | `DeviseConfig::password_length` (`config.rs:119`) | ported | `crates/devise-rust/tests/model_validation.rs (password_length_bounds_6_to_128_inclusive)` | 6..128 |
| `remember_for` | option | `lib/devise.rb:123` | `DeviseConfig::remember_for` (`config.rs:124`) | ported | `crates/devise-rust/src/rememberable.rs tests (rememberable_nil_case_older_than_remember_for)` | 2 weeks |
| `extend_remember_period` | option | `lib/devise.rb:127` | `DeviseConfig::extend_remember_period` (`config.rs:126`) | ported | `crates/devise-rust/src/strategy.rs tests (test_strategy_rememberable_extend_reissues_when_enabled)` | default false, fixed expiry |
| `expire_all_remember_me_on_sign_out` | option | `lib/devise.rb:131` | `DeviseConfig::expire_all_remember_me_on_sign_out` (`config.rs:130`) | ported | `crates/devise-rust/src/rememberable.rs tests (rememberable_forget_clears_per_expire_all)` | default true |
| `allow_unconfirmed_access_for` | option | `lib/devise.rb:136` | `DeviseConfig::allow_unconfirmed_access_for` (`config.rs:135`) | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_allow_window_three_way_table)` | default zero |
| `confirm_within` | option | `lib/devise.rb:140` | `DeviseConfig::confirm_within` (`config.rs:138`) | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_confirm_within_none_never_expires)` | nil means no expiry (serde round-trips None) |
| `confirmation_keys` | option | `lib/devise.rb:144` | `DeviseConfig::confirmation_keys` (`config.rs:140`) | ported | `crates/devise-rust/src/confirmable.rs tests` | default `[email]` |
| `reconfirmable` | option | `lib/devise.rb:148` | `DeviseConfig::reconfirmable` (`config.rs:142`) | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_reconfirmation_postpones_with_d05_routing)` | default true; gates the `unconfirmed_email` column |
| `timeout_in` | option | `lib/devise.rb:152` | `DeviseConfig::timeout_in` (`config.rs:171`) | ported | `crates/devise-rust/src/timeoutable.rs tests (timeoutable_matrix_config_fallback_and_zero_window)` | 30 minutes |
| `pepper` | option | `lib/devise.rb:156` | `DeviseConfig::pepper` (`config.rs:91`) | ported | `crates/devise-rust/src/crypto.rs tests (test_encryptor_with_pepper)` | default None |
| `send_email_changed_notification` | option | `lib/devise.rb:160` | `DeviseConfig::send_email_changed_notification` (`config.rs:212`) | ported | `crates/devise-rust/tests/notifications.rs (email_change_notification_goes_to_original_address)` | default false |
| `send_password_change_notification` | option | `lib/devise.rb:164` | `DeviseConfig::send_password_change_notification` (`config.rs:214`) | ported | `crates/devise-rust/tests/notifications.rs (password_change_notification_goes_to_current_address)` | default false |
| `scoped_views` | option | `lib/devise.rb:169` | `DeviseConfig::scoped_views` (`config.rs:193`) | waived | `crates/devise-rust/src/config.rs tests (test_config_defaults)` | reason: devise-rust ships no server-rendered view templates to scope; response rendering is owned by the framework crates and the host app. v1 impact: none, the field is retained for config surface parity and defaults to false. |
| `lock_strategy` | option | `lib/devise.rb:174` | `DeviseConfig::lock_strategy` (`config.rs:146`) | ported | `crates/devise-rust/src/lockable.rs tests (lockable_tracer_none_strategy_no_side_effects)` | failed_attempts or none |
| `unlock_keys` | option | `lib/devise.rb:178` | `DeviseConfig::unlock_keys` (`config.rs:150`) | ported | `crates/devise-rust/src/lockable.rs tests (lockable_class_send_requires_all_unlock_keys)` | default `[email]` |
| `unlock_strategy` | option | `lib/devise.rb:183` | `DeviseConfig::unlock_strategy` (`config.rs:148`) | ported | `crates/devise-rust/src/lockable.rs tests (lockable_unlock_strategy_predicates_and_required_fields)` | time/email/both/none, default both |
| `maximum_attempts` | option | `lib/devise.rb:187` | `DeviseConfig::maximum_attempts` (`config.rs:152`) | ported | `crates/devise-rust/src/lockable.rs tests (lockable_tracer_counter_to_lock)` | default 20 |
| `unlock_in` | option | `lib/devise.rb:191` | `DeviseConfig::unlock_in` (`config.rs:155`) | ported | `crates/devise-rust/src/lockable.rs tests (lockable_expired_time_lock_releases_live_lock_holds)` | 1 hour |
| `last_attempt_warning` | option | `lib/devise.rb:304` | `DeviseConfig::last_attempt_warning` (`config.rs:157`) | ported | `crates/devise-rust/src/lockable.rs tests (lockable_last_attempt_matrix)` | default true |
| `reset_password_keys` | option | `lib/devise.rb:195` | `DeviseConfig::reset_password_keys` (`config.rs:161`) | ported | `crates/devise-rust/src/model.rs tests (send_reset_password_instructions)` | default `[email]` |
| `reset_password_within` | option | `lib/devise.rb:199` | `DeviseConfig::reset_password_within` (`config.rs:164`) | ported | `crates/devise-rust/src/model.rs tests (reset_password_by_token_window)` | 6 hours |
| `sign_in_after_reset_password` | option | `lib/devise.rb:203` | `DeviseConfig::sign_in_after_reset_password` (`config.rs:166`) | ported | `crates/devise-rust/src/model.rs tests` plus flow tests | default true |
| `default_scope` | option | `lib/devise.rb:207` | `DeviseConfig::default_scope` (`config.rs:175`) | ported | `crates/devise-rust/src/scope.rs tests (test_scope_registry)` | Option, Devise has no implicit default either |
| `mailer_sender` | option | `lib/devise.rb:211` | `DeviseConfig::mailer_sender` (`config.rs:189`) | ported | `crates/devise-rust/src/mailer.rs tests (mailer_sender_config_flows_to_from_header)` | flows to the From header |
| `skip_session_storage` | option | `lib/devise.rb:215` | `DeviseConfig::skip_session_storage` (`config.rs:181`) | ported | `crates/devise-rust/src/strategy.rs tests (test_strategy_ids)` | default `[http_auth]` |
| `navigational_formats` | option | `lib/devise.rb:219` | `DeviseConfig::navigational_formats` (`config.rs:195`) | ported | `crates/devise-rust/src/request.rs tests (test_is_navigational_format)` | default html plus turbo_stream plus star |
| `responder` | option | `lib/devise.rb:228` | `DeviseConfig::responder` (`config.rs:197`) | deviated | `crates/devise-rust/src/failure.rs tests` | the class reference is retained for surface parity; the response negotiation (redirect vs 401) is implemented by the framework failure paths, not a swappable responder class |
| `sign_out_all_scopes` | option | `lib/devise.rb:232` | `DeviseConfig::sign_out_all_scopes` (`config.rs:177`) | ported | `crates/devise-rust/src/proxy.rs tests (test_proxy_sign_out_all_scopes)` | default true |
| `sign_out_via` | option | `lib/devise.rb:236` | `DeviseConfig::sign_out_via` (`config.rs:179`) plus `SignOutVia` (`crates/devise-rust/src/scope.rs`) | ported | `crates/devise-rust/src/scope.rs tests (test_sign_out_via)` | delete default; both framework routers enforce the verb |
| `parent_controller` | option | `lib/devise.rb:242` | `DeviseConfig::parent_controller` (`config.rs:185`) | deviated | `crates/devise-rust/src/config.rs tests (test_config_defaults)` | field kept for surface parity; controller inheritance is a Rails concept, the framework crates provide the controllers |
| `parent_mailer` | option | `lib/devise.rb:248` | `DeviseConfig::parent_mailer` (`config.rs:187`) | deviated | `crates/devise-rust/src/mailer.rs tests` | field kept for surface parity; the `Mailer` trait replaces the mailer superclass |
| `router_name` | option | `lib/devise.rb:254` | `DeviseConfig::router_name` (`config.rs:191`) | ported | `crates/devise-rust/src/scope.rs tests (test_mapping_with_prefix)` | namespapes the mounted route group |
| `omniauth_path_prefix` | option | `lib/devise.rb:259` | `DeviseConfig::omniauth_path_prefix` (`config.rs:203`) | ported | `crates/devise-rust/src/scope.rs tests (test_omniauth_route_specs_prefix_override)` | overrides the auth mount |
| `clean_up_csrf_token_on_authentication` | option | `lib/devise.rb:263` | `DeviseConfig::clean_up_csrf_token_on_authentication` (`config.rs:201`) | ported | `crates/devise-rust/src/hooks.rs tests (test_hook_registry_activatable_csrf)` | drives `handle_unverified_request` bridge callback - wired 2026-10-24 (`bridge::handle_unverified_request` in both crates, tested in the session_bridge suites) |
| `reload_routes` | option | `lib/devise.rb:270` | no counterpart | waived | `crates/devise-rust/src/config.rs tests (test_config_defaults)` | reason: Rails reloads routes on code reload in development; Rust routers are compiled, so there is nothing to reload. v1 impact: none, development-workflow concern only. |
| `warden_config` | option | `lib/devise.rb:295` | `AuthProxy::new` construction (`crates/devise-rust/src/proxy.rs:91`) | waived | `crates/devise-rust/src/proxy.rs tests (test_strategy_chain)` | reason: the warden configuration block configures the Warden middleware manager; the Rust port has no external middleware manager to configure, the proxy is built directly. v1 impact: none, every warden behavior the block drives has a ported counterpart. |
| `token_generator` | option | `lib/devise.rb:308` | `crypto::token_generator` (`crates/devise-rust/src/crypto.rs:126`) | deviated | `crates/devise-rust/src/crypto.rs tests (test_token_generator_digest)` | not pluggable in v1: the HMAC-SHA256 generator is the only implementation, keyed `"Devise {column}"` |
| `paranoid` | option | `lib/devise.rb:300` | `DeviseConfig::paranoid` (`config.rs:210`) | ported | `crates/devise-rust/src/strategy.rs tests (test_paranoid_strategy_masks_not_found)` | uniform `:invalid`, dummy bcrypt on unknown account (TEST-03 item 1) |
| `omniauth_providers` | option | `models/omniauthable.rb` plus omniauth config | `DeviseConfig::omniauth_providers` (`config.rs:205`) | ported | `crates/devise-rust/src/omniauthable.rs tests (omniauthable_config_providers_default_empty_and_override_resolves)` | allowlist resolved through `DeviseConfigOverride` |
| `sign_in_after_change_password` | option | `lib/devise.rb:312` | `DeviseConfig::sign_in_after_change_password` (`config.rs:216`) | ported | `crates/devise-rust/src/model.rs tests (registerable_tests)` | drives the bypass sign-in in the registration update flow |

## Migration columns

Mirrors `devise/lib/generators/active_record/devise_generator.rb` and the migration DSL (`t.database_authenticatable` and friends). The `devise-rust-migrations` crate emits the same column names for Postgres, SQLite, and MySQL, for integer/bigint and UUID primary keys.

| devise name | kind | devise source | Rust counterpart | status | test evidence | notes |
|---|---|---|---|---|---|---|
| `email` | column | `generators/active_record/devise_generator.rb` | `crates/devise-rust-migrations/src/ddl.rs` | ported | `crates/devise-rust-migrations/tests/snapshots.rs (matrix_full_create)` | plus unique index |
| `encrypted_password` | column | `generators/active_record/devise_generator.rb` | `crates/devise-rust-migrations/src/ddl.rs` | ported | `crates/devise-rust-migrations/tests/snapshots.rs (matrix_full_create)` | NOT NULL DEFAULT '' parity |
| `reset_password_token` | column | `generators/active_record/devise_generator.rb` | `crates/devise-rust-migrations/src/ddl.rs:149` region | ported | `crates/devise-rust-migrations/tests/snapshots.rs (recoverable_adds_its_index_without_confirmation_index)` | digest only; unique index |
| `reset_password_sent_at` | column | `generators/active_record/devise_generator.rb` | `crates/devise-rust-migrations/src/ddl.rs:149` | ported | `crates/devise-rust-migrations/tests/snapshots.rs (matrix_full_create)` | window anchor |
| `remember_created_at` | column | `generators/active_record/devise_generator.rb` | `crates/devise-rust-migrations/src/ddl.rs:158` | ported | `crates/devise-rust-migrations/tests/snapshots.rs (matrix_full_create)` | salt-mode cookie anchor |
| `remember_token` | column | `generators/active_record/devise_generator.rb` (optional) | `crates/devise-rust-migrations/src/ddl.rs` | ported | `crates/devise-rust-migrations/tests/snapshots.rs (remember_token_opt_in)` | opt-in DB-token mode |
| `sign_in_count` | column | `generators/active_record/devise_generator.rb` | `crates/devise-rust-migrations/src/ddl.rs` | ported | `crates/devise-rust-migrations/tests/snapshots.rs (matrix_full_create)` | default 0 |
| `current_sign_in_at` | column | `generators/active_record/devise_generator.rb` | `crates/devise-rust-migrations/src/ddl.rs` | ported | `crates/devise-rust-migrations/tests/snapshots.rs (matrix_full_create)` | |
| `last_sign_in_at` | column | `generators/active_record/devise_generator.rb` | `crates/devise-rust-migrations/src/ddl.rs` | ported | `crates/devise-rust-migrations/tests/snapshots.rs (matrix_full_create)` | |
| `current_sign_in_ip` | column | `generators/active_record/devise_generator.rb` | `crates/devise-rust-migrations/src/ddl.rs` | ported | `crates/devise-rust-migrations/tests/snapshots.rs (matrix_full_create)` | INET on Postgres, TEXT elsewhere |
| `last_sign_in_ip` | column | `generators/active_record/devise_generator.rb` | `crates/devise-rust-migrations/src/ddl.rs` | ported | `crates/devise-rust-migrations/tests/snapshots.rs (matrix_full_create)` | |
| `confirmation_token` | column | `generators/active_record/devise_generator.rb` | `crates/devise-rust-migrations/src/ddl.rs` | ported | `crates/devise-rust-migrations/tests/snapshots.rs (matrix_full_create)` | digest only; unique index |
| `confirmed_at` | column | `generators/active_record/devise_generator.rb` | `crates/devise-rust-migrations/src/ddl.rs` | ported | `crates/devise-rust-migrations/tests/snapshots.rs (matrix_full_create)` | |
| `confirmation_sent_at` | column | `generators/active_record/devise_generator.rb` | `crates/devise-rust-migrations/src/ddl.rs` | ported | `crates/devise-rust-migrations/tests/snapshots.rs (matrix_full_create)` | |
| `unconfirmed_email` | column | `generators/active_record/devise_generator.rb` | `crates/devise-rust-migrations/src/ddl.rs` | ported | `crates/devise-rust-migrations/tests/snapshots.rs (reconfirmable_off_omits_unconfirmed_email)` | emitted only when reconfirmable |
| `failed_attempts` | column | `generators/active_record/devise_generator.rb` | `crates/devise-rust-migrations/src/ddl.rs` | ported | `crates/devise-rust-migrations/tests/snapshots.rs (lockable_none_strategies_emit_only_locked_at)` | strategy-gated |
| `locked_at` | column | `generators/active_record/devise_generator.rb` | `crates/devise-rust-migrations/src/ddl.rs` | ported | `crates/devise-rust-migrations/tests/snapshots.rs (lockable_none_strategies_emit_only_locked_at)` | strategy-gated |
| `unlock_token` | column | `generators/active_record/devise_generator.rb` | `crates/devise-rust-migrations/src/ddl.rs` | ported | `crates/devise-rust-migrations/tests/snapshots.rs (lockable_none_strategies_emit_only_locked_at)` | emitted for email unlock strategies; digest only |
| `provider` | column | `generators/active_record/devise_generator.rb` | `crates/devise-rust-migrations/src/ddl.rs` | ported | `crates/devise-rust-migrations/tests/snapshots.rs (omniauthable_block_emits_provider_and_uid_and_no_token_column)` | identity pair only; OAuth tokens stay session-resident (D-11/D-12) |
| `uid` | column | `generators/active_record/devise_generator.rb` | `crates/devise-rust-migrations/src/ddl.rs` | ported | `crates/devise-rust-migrations/tests/snapshots.rs (omniauthable_block_emits_provider_and_uid_and_no_token_column)` | unique with provider |

## I18n message keys

The embedded catalog (`crates/devise-rust/locales/en.yml`) carries Devise's exact key space and copy from `devise/config/locales/en.yml`; `crates/devise-rust/src/i18n.rs` resolves them with Devise's interpolation variables.

| devise name | kind | devise source | Rust counterpart | status | test evidence | notes |
|---|---|---|---|---|---|---|
| `devise.confirmations.confirmed` | message | `config/locales/en.yml` | `locales/en.yml` plus `i18n` lookup | ported | `crates/devise-rust/src/i18n.rs tests (test_translate_simple)` | |
| `devise.confirmations.send_instructions` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust/src/i18n.rs tests` | |
| `devise.confirmations.send_paranoid_instructions` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_class_send_finds_unconfirmed_first_and_paranoid_stays_silent)` | paranoid mode keeps this copy |
| `devise.failure.already_authenticated` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust-{actix,axum}/tests/devise_flows.rs (flow_sign_in_while_signed_in_reports_already_authenticated)` | require_no_authentication path - wired 2026-10-24 in both bridges' `sessions#create` |
| `devise.failure.inactive` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust/src/model.rs tests` | `:inactive` default |
| `devise.failure.invalid` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_sign_in_failure_formats)` | interpolates `%{authentication_keys}` |
| `devise.failure.locked` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust/src/lockable.rs tests (lockable_paranoid_suppresses_lock_messages)` | suppressed under paranoid |
| `devise.failure.last_attempt` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust/src/lockable.rs tests (lockable_last_attempt_matrix)` | honors `last_attempt_warning` |
| `devise.failure.not_found_in_database` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust/src/strategy.rs tests (test_unknown_account_failure_keys, test_not_found_reason_flash_key)`; both frameworks assert the flash in `tests/devise_flows.rs (flow_sign_in_unknown_email_reports_not_found)` | non-paranoid failure message - reachable on the HTTP path since 2026-10-24 |
| `devise.failure.timeout` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust/src/timeoutable.rs tests` | timeout redirect and 401 body |
| `devise.failure.unauthenticated` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust/src/failure.rs tests` | |
| `devise.failure.unconfirmed` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_allow_window_three_way_table)` | unsuppressed under paranoid |
| `devise.mailer.confirmation_instructions.subject` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust/src/mailer.rs tests (test_mailer_confirmation)` | |
| `devise.mailer.reset_password_instructions.subject` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust/tests/notifications.rs (mailer_context_carries_template_vars)` | |
| `devise.mailer.unlock_instructions.subject` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust/src/lockable.rs tests (lockable_lock_access_mails_raw_stores_digest)` | |
| `devise.mailer.email_changed.subject` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust/tests/notifications.rs (email_change_notification_goes_to_original_address)` | subject "Email Changed" |
| `devise.mailer.password_change.subject` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust/tests/notifications.rs (password_change_notification_goes_to_current_address)` | subject "Password Changed" |
| `devise.omniauth_callbacks.failure` | message | `config/locales/en.yml` | `locales/en.yml` plus `omniauthable::failure_message` | ported | `crates/devise-rust/src/omniauthable.rs tests (omniauthable_failure_message_renders_devise_template)` | interpolates `%{kind}` and `%{reason}` |
| `devise.omniauth_callbacks.success` | message | `config/locales/en.yml` | `locales/en.yml` plus `omniauthable::success_message` | ported | `crates/devise-rust/src/omniauthable.rs tests (omniauthable_success_message_renders_devise_template)` | interpolates `%{kind}` |
| `devise.passwords.no_token` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_reset_token_errors)` | blank token guard on the edit page |
| `devise.passwords.send_instructions` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust/src/model.rs tests (send_reset_password_instructions)` | |
| `devise.passwords.send_paranoid_instructions` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust/src/model.rs tests (send_reset_password_instructions)` | paranoid copy |
| `devise.passwords.updated` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_reset_token_errors)` | |
| `devise.passwords.updated_not_active` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust/src/model.rs tests` | inactive account reset path |
| `devise.registrations.destroyed` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust-axum/tests/devise_flows.rs` | account cancellation |
| `devise.registrations.signed_up` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_sign_up_failure_clears_passwords_and_keeps_errors)` negative path plus journey | |
| `devise.registrations.signed_up_but_inactive` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust/src/model.rs tests (post_sign_up_message)` | message selection follows `active_for_authentication` |
| `devise.registrations.signed_up_but_locked` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust/src/model.rs tests (post_sign_up_message)` | |
| `devise.registrations.signed_up_but_unconfirmed` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust/src/model.rs tests (post_sign_up_message)` | |
| `devise.registrations.update_needs_confirmation` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_reconfirmation_postpones_with_d05_routing)` | reconfirmable update path |
| `devise.registrations.updated` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_account_update_requires_current_password)` | |
| `devise.registrations.updated_but_not_signed_in` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust/src/model.rs tests (registerable_tests)` | password change without bypass |
| `devise.sessions.signed_in` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_sign_in_and_sign_out_with_flashes)` | |
| `devise.sessions.signed_out` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_sign_in_and_sign_out_with_flashes)` | |
| `devise.sessions.already_signed_out` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust-actix/tests/routes.rs` plus flow tests | idempotent sign-out |
| `devise.unlocks.send_instructions` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust/src/lockable.rs tests (lockable_class_send_unlock_instructions)` | |
| `devise.unlocks.send_paranoid_instructions` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust/src/lockable.rs tests` | paranoid copy |
| `devise.unlocks.unlocked` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_unlock_by_token)` | |
| `errors.messages.already_confirmed` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_resend_on_confirmed_errors_already_confirmed)` | |
| `errors.messages.confirmation_period_expired` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_humanize_period_renders_devise_windows)` | interpolates `%{period}` via `humanize_period` |
| `errors.messages.expired` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust/src/model.rs tests (reset_password_by_token_window)` | reset window expiry |
| `errors.messages.not_found` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust/src/model.rs tests` | |
| `errors.messages.not_locked` | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust/src/lockable.rs tests` | unlock of an unlocked record |
| `errors.messages.not_saved` (one/other) | message | `config/locales/en.yml` | `locales/en.yml` | ported | `crates/devise-rust/src/error.rs tests (test_validation_errors)` | singular and plural forms |

## Unsafe serialization attributes

`UNSAFE_ATTRIBUTES_FOR_SERIALIZATION` (`devise/lib/devise/models/authenticatable.rb:58`, 18 attributes) maps to `UNSAFE_ATTRIBUTES` in `crates/devise-rust/src/error.rs`; `serializable_hash` and the app-facing serializers exclude them everywhere.

| devise name | kind | devise source | Rust counterpart | status | test evidence | notes |
|---|---|---|---|---|---|---|
| `encrypted_password` | method | `models/authenticatable.rb:58` | `UNSAFE_ATTRIBUTES` (`crates/devise-rust/src/error.rs`) | ported | `crates/devise-rust/src/error.rs tests (test_unsafe_attributes)` and `crates/devise-rust/src/model.rs tests (test_serializable_hash_excludes_password)` | never serialized or logged |
| `reset_password_token` | method | `models/authenticatable.rb:58` | `UNSAFE_ATTRIBUTES` | ported | `crates/devise-rust/src/error.rs tests (test_unsafe_attributes)` | digest excluded |
| `reset_password_sent_at` | method | `models/authenticatable.rb:58` | `UNSAFE_ATTRIBUTES` | ported | `crates/devise-rust/src/error.rs tests (test_unsafe_attributes)` | |
| `remember_created_at` | method | `models/authenticatable.rb:58` | `UNSAFE_ATTRIBUTES` | ported | `crates/devise-rust/src/error.rs tests (test_unsafe_attributes)` | |
| `sign_in_count` | method | `models/authenticatable.rb:59` | `UNSAFE_ATTRIBUTES` | ported | `crates/devise-rust/src/error.rs tests (test_unsafe_attributes)` | |
| `current_sign_in_at` | method | `models/authenticatable.rb:59` | `UNSAFE_ATTRIBUTES` | ported | `crates/devise-rust/src/error.rs tests (test_unsafe_attributes)` | |
| `last_sign_in_at` | method | `models/authenticatable.rb:59` | `UNSAFE_ATTRIBUTES` | ported | `crates/devise-rust/src/error.rs tests (test_unsafe_attributes)` | |
| `current_sign_in_ip` | method | `models/authenticatable.rb:59` | `UNSAFE_ATTRIBUTES` | ported | `crates/devise-rust/src/error.rs tests (test_unsafe_attributes)` | |
| `last_sign_in_ip` | method | `models/authenticatable.rb:59` | `UNSAFE_ATTRIBUTES` | ported | `crates/devise-rust/src/error.rs tests (test_unsafe_attributes)` | |
| `password_salt` | method | `models/authenticatable.rb:60` | `UNSAFE_ATTRIBUTES` | ported | `crates/devise-rust/src/error.rs tests (test_unsafe_attributes)` | bcrypt salt segment of the digest; restored to the filter in the 10-05 gap closure (was omitted while marked ported) |
| `confirmation_token` | method | `models/authenticatable.rb:60` | `UNSAFE_ATTRIBUTES` | ported | `crates/devise-rust/src/error.rs tests (test_unsafe_attributes)` and `confirmable.rs tests (confirmable_unsafe_attributes_cover_confirmation_columns)` | |
| `confirmed_at` | method | `models/authenticatable.rb:60` | `UNSAFE_ATTRIBUTES` | ported | `crates/devise-rust/src/error.rs tests (test_unsafe_attributes)` | |
| `confirmation_sent_at` | method | `models/authenticatable.rb:60` | `UNSAFE_ATTRIBUTES` | ported | `crates/devise-rust/src/error.rs tests (test_unsafe_attributes)` | |
| `remember_token` | method | `models/authenticatable.rb:61` | `UNSAFE_ATTRIBUTES` | ported | `crates/devise-rust/src/error.rs tests (test_unsafe_attributes)` | stored unhashed in the DB-token rememberable mode; restored to the filter in the 10-05 gap closure (was omitted while marked ported) |
| `unconfirmed_email` | method | `models/authenticatable.rb:61` | `UNSAFE_ATTRIBUTES` | ported | `crates/devise-rust/src/error.rs tests (test_unsafe_attributes)` | |
| `failed_attempts` | method | `models/authenticatable.rb:61` | `UNSAFE_ATTRIBUTES` | ported | `crates/devise-rust/src/error.rs tests (test_unsafe_attributes)` | |
| `unlock_token` | method | `models/authenticatable.rb:61` | `UNSAFE_ATTRIBUTES` | ported | `crates/devise-rust/src/error.rs tests (test_unsafe_attributes)` | |
| `locked_at` | method | `models/authenticatable.rb:61` | `UNSAFE_ATTRIBUTES` | ported | `crates/devise-rust/src/error.rs tests (test_unsafe_attributes_count)` | 18th attribute, count pinned |

## Routes (devise_for table)

The full `devise_for` route table (`devise/lib/devise/rails/routes.rb`, rows shown for a scope named `user` mounted at `users`) renders from `Mapping::route_specs` (`crates/devise-rust/src/scope.rs:287`) and `omniauth_route_specs` (`scope.rs:656`); both framework crates mount the same rows (`devise_for_users` in the actix crate, `devise_for_router` in the axum crate).

| devise name | kind | devise source | Rust counterpart | status | test evidence | notes |
|---|---|---|---|---|---|---|
| `GET /users/sign_in` (new_session) | route | `rails/routes.rb` session block | `RouteSpec` new_session row (`crates/devise-rust/src/scope.rs:308`) | ported | `crates/devise-rust/src/scope.rs tests (test_route_specs_database_authenticatable)` plus `crates/devise-rust-axum/tests/routes.rs` | |
| `POST /users/sign_in` (create_session) | route | `rails/routes.rb` session block | `RouteSpec` create_session row | ported | `crates/devise-rust/src/scope.rs tests (test_route_specs_database_authenticatable)` | |
| `DELETE /users/sign_out` (destroy_session) | route | `rails/routes.rb` session block | `RouteSpec` destroy_session row honoring `sign_out_via` | ported | `crates/devise-rust/src/scope.rs tests (test_sign_out_via)` plus framework routes tests | verb enforced per scope config |
| `GET /users/sign_up` (new_registration) | route | `rails/routes.rb` registration block | `RouteSpec` new_registration row (`scope.rs:340`) | ported | `crates/devise-rust/src/scope.rs tests (test_route_specs_registerable)` | |
| `POST /users` (create_registration) | route | `rails/routes.rb` registration block | `RouteSpec` create_registration row | ported | `crates/devise-rust/src/scope.rs tests (test_route_specs_registerable)` | |
| `GET /users/cancel` (cancel_registration) | route | `rails/routes.rb` registration block | `RouteSpec` cancel row | ported | `crates/devise-rust/src/scope.rs tests (test_route_specs_registerable)` | expires OAuth session data |
| `GET /users/edit` (edit_registration) | route | `rails/routes.rb` registration block | `RouteSpec` edit row | ported | `crates/devise-rust/src/scope.rs tests (test_route_specs_registerable)` | skipped when the edit path name is cleared |
| `PATCH /users` and `PUT /users` (update_registration) | route | `rails/routes.rb` registration block | `RouteSpec` update rows for both verbs | ported | `crates/devise-rust/src/scope.rs tests (test_route_specs_registerable)` | |
| `DELETE /users` (destroy_registration) | route | `rails/routes.rb` registration block | `RouteSpec` destroy row | ported | `crates/devise-rust/src/scope.rs tests (test_route_specs_registerable)` | |
| `GET /users/password/new` (new_password) | route | `rails/routes.rb` password block | `RouteSpec` new_password row (`scope.rs` push_password_routes) | ported | `crates/devise-rust/src/scope.rs tests (test_all_route_specs)` | |
| `POST /users/password` (create_password) | route | `rails/routes.rb` password block | `RouteSpec` create_password row | ported | `crates/devise-rust/src/scope.rs tests (test_all_route_specs)` | |
| `GET /users/password/edit` (edit_password) | route | `rails/routes.rb` password block | `RouteSpec` edit_password row | ported | `crates/devise-rust/src/scope.rs tests (test_all_route_specs)` | blank token redirects with `no_token` |
| `PATCH /users/password` and `PUT /users/password` (update_password) | route | `rails/routes.rb` password block | `RouteSpec` update_password rows | ported | `crates/devise-rust/src/scope.rs tests (test_all_route_specs)` | |
| `GET /users/confirmation/new` (new_confirmation) | route | `rails/routes.rb` confirmation block | `RouteSpec` new_confirmation row | ported | `crates/devise-rust/src/scope.rs tests (test_all_route_specs)` | |
| `POST /users/confirmation` (create_confirmation) | route | `rails/routes.rb` confirmation block | `RouteSpec` create_confirmation row | ported | `crates/devise-rust/src/scope.rs tests (test_all_route_specs)` | |
| `GET /users/confirmation` (show_confirmation) | route | `rails/routes.rb` confirmation block | `RouteSpec` show_confirmation row | ported | `crates/devise-rust/src/scope.rs tests (test_all_route_specs)` | token query param |
| `GET /users/unlock/new` (new_unlock) | route | `rails/routes.rb` unlock block | `RouteSpec` new_unlock row | ported | `crates/devise-rust/src/scope.rs tests (test_all_route_specs)` | routed only when the unlock strategy includes email |
| `POST /users/unlock` (create_unlock) | route | `rails/routes.rb` unlock block | `RouteSpec` create_unlock row | ported | `crates/devise-rust/src/scope.rs tests (test_all_route_specs)` | |
| `GET /users/unlock` (show_unlock) | route | `rails/routes.rb` unlock block | `RouteSpec` show_unlock row | ported | `crates/devise-rust/src/scope.rs tests (test_all_route_specs)` | token query param |
| `POST /users/auth/{provider}` (authorize) | route | `rails/routes.rb` omniauth block | `omniauth_route_specs` authorize row (`scope.rs:656`) | ported | `crates/devise-rust/src/scope.rs tests (test_route_specs_omniauthable_emits_post_authorize_get_or_post_callback)` | POST only (devise 5.0.4 amendment) |
| `GET /users/auth/{provider}/callback` and `POST` (callback) | route | `rails/routes.rb` omniauth block | `omniauth_route_specs` callback row via both verbs | ported | `crates/devise-rust/src/scope.rs tests (test_omniauth_callback_path_substitutes_provider)` | `{provider}` capture rendered natively by both routers |
| `devise_scope` / `as` block | route | `rails/routes.rb:290` region | `Mapping` registry plus `ScopeRegistry` (`crates/devise-rust/src/scope.rs`) | ported | `crates/devise-rust/src/scope.rs tests (test_scope_registry, test_scope_mount)` | sets the scope for a route group |
| `authenticate(scope)` constraint | route | `rails/routes.rb` constraint helpers | `RequireAuth` extractor (`crates/devise-rust-{actix,axum}/src/extractors.rs`) | ported | `crates/devise-rust-axum/tests/extractors.rs` | per-scope guard with active_for_authentication honored |
| `authenticated(scope)` constraint | route | `rails/routes.rb` constraint helpers | `Auth` extractor (optional current user) | ported | `crates/devise-rust-axum/tests/extractors.rs` | anonymous access allowed |
| `unauthenticated(scope)` constraint | route | `rails/routes.rb` constraint helpers | signed-in check helpers on the framework crates | ported | `crates/devise-rust-axum/tests/extractors.rs` | |
| path name overrides (`path_names`) | option | `rails/routes.rb` | `Mapping::path_names` (`crates/devise-rust/src/scope.rs`) | ported | `crates/devise-rust/src/scope.rs tests (test_path_names_defaults)` | sign_in, sign_out, sign_up, password, confirmation, unlock, registration, edit, cancel |
| `only:` / `skip:` route selection | option | `rails/routes.rb` | `Mapping::only` / `Mapping::skip` (`crates/devise-rust/src/scope.rs`) | ported | `crates/devise-rust/src/scope.rs tests (test_mapping_effective_modules)` | used_routes semantics |
| `path_prefix` / `path` / `singular` / `class_name` / `format` | option | `rails/routes.rb` | `Mapping` fields (`crates/devise-rust/src/scope.rs`) | ported | `crates/devise-rust/src/scope.rs tests (test_mapping_full_path, test_mapping_with_prefix)` | |
| `constraints` / `defaults` | option | `rails/routes.rb` | `Mapping` fields | ported | `crates/devise-rust/src/scope.rs tests (test_mapping_full_path)` | carried on the mapping, applied by the host router |
| `failure_app` per scope | option | `rails/routes.rb` | `Mapping::failure_app` (`crates/devise-rust/src/scope.rs`) | ported | `crates/devise-rust/src/failure.rs tests (test_failure_decision)` | per-scope failure decision honored |

## Controller and helper surface

`devise/lib/devise/controllers/helpers.rb` and `sign_in_out.rb` map to the framework crates' extractors and helpers; the warden-equivalent proxy (`crates/devise-rust/src/proxy.rs`) owns `sign_in`, `sign_out`, and `bypass_sign_in`.

| devise name | kind | devise source | Rust counterpart | status | test evidence | notes |
|---|---|---|---|---|---|---|
| `authenticate_<scope>!` | method | `controllers/helpers.rb:117` | `RequireAuth` extractor (both framework crates) plus `authenticate` guard | ported | `crates/devise-rust-axum/tests/extractors.rs`, `crates/devise-rust-actix/tests/extractors.rs` | per-scope; force option for devise controllers |
| `<scope>_signed_in?` | method | `controllers/helpers.rb:123` | `signed_in` helpers on the framework crates plus `AuthProxy::authenticated` (`proxy.rs:220`) | ported | `crates/devise-rust/src/proxy.rs tests (test_helpers_authenticate_signed_in)` | |
| `current_<scope>` | method | `controllers/helpers.rb:127` | `Auth` extractor plus `current_user` helpers | ported | `crates/devise-rust-axum/tests/extractors.rs` | memoized per request in the bridge |
| `<scope>_session` | method | `controllers/helpers.rb:131` | scope session key helpers (`crates/devise-rust/src/session.rs:70`) | ported | `crates/devise-rust/src/session.rs tests (test_key_naming)` | |
| `devise_group` | method | `controllers/helpers.rb:39` | no counterpart | waived | `crates/devise-rust-axum/tests/extractors.rs` | reason: devise_group metaprograms a family of helper methods over multiple scopes at load time; Rust handlers take the extractors directly per scope, so the metaprogramming helper has no runtime role. v1 impact: none, per-scope guards cover the group semantics with explicit code. |
| `warden` (proxy access) | method | `controllers/helpers.rb:144` | `AuthProxy` (`crates/devise-rust/src/proxy.rs:91`) | ported | `crates/devise-rust/src/proxy.rs tests` | the proxy is the warden equivalent |
| `devise_parameter_sanitizer` | method | `controllers/helpers.rb:160` | `ParameterSanitizer` (`crates/devise-rust/src/parameter.rs`) | ported | `crates/devise-rust/src/parameter.rs tests (test_parameter_sanitizer_defaults)` | defaults per action mirror devise |
| `allow_params_authentication!` | method | `controllers/helpers.rb:165` | `RequestFlags::allow_params_authentication` (`crates/devise-rust/src/request.rs`) | ported | `crates/devise-rust/tests/notifications.rs (after_database_authentication_fires_on_password_strategies)` | request-scoped flag |
| `signed_in_root_path` | method | `controllers/helpers.rb:171` | framework redirect hooks (`after_sign_in_path` seam in the crate controllers) | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_stored_location_get_only)` | per-app override seam |
| `after_sign_in_path_for` | method | `controllers/helpers.rb:217` | stored-location resolution (`crates/devise-rust/src/failure.rs stored_location` plus framework redirect) | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_stored_location_get_only)` | stored_location first, else scope root, else root |
| `after_sign_out_path_for` | method | `controllers/helpers.rb:227` | framework sign-out redirect | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_sign_in_and_sign_out_with_flashes)` | |
| `sign_in_and_redirect` | method | `controllers/helpers.rb:237` | sign-in plus redirect in the omniauth callback handlers | ported | `crates/devise-rust-axum/tests/omniauth_flows.rs` | |
| `sign_out_and_redirect` | method | `controllers/helpers.rb:247` | sign-out plus redirect in the framework helpers | ported | `crates/devise-rust-actix/tests/devise_flows.rs` | |
| `handle_unverified_request` | method | `controllers/helpers.rb:256` | `clean_up_csrf` hook (`crates/devise-rust/src/hooks.rs`) | ported | `crates/devise-rust/src/hooks.rs tests (test_hook_registry_activatable_csrf)` | signs out on CSRF failure when configured |
| `is_navigational_format?` | method | `controllers/helpers.rb:266` | `is_navigational_format` (`crates/devise-rust/src/failure.rs:379`) | ported | `crates/devise-rust/src/request.rs tests (test_is_navigational_format)` | |
| `is_flashing_format?` | method | `controllers/helpers.rb:272` | flash decision on the framework failure paths | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_sign_in_and_sign_out_with_flashes)` | |
| `expire_data_after_sign_out!` | method | `controllers/helpers.rb:278` | `session::expire_devise_keys` (`crates/devise-rust/src/session.rs:203`) | ported | `crates/devise-rust/src/session.rs tests` | |
| `signed_in?` | method | `controllers/sign_in_out.rb:13` | `AuthProxy::authenticated` (`proxy.rs:220`) | ported | `crates/devise-rust/src/proxy.rs tests (test_helpers_authenticate_signed_in)` | |
| `sign_in` | method | `controllers/sign_in_out.rb:33` | `AuthProxy::sign_in` (`proxy.rs:298`) | ported | `crates/devise-rust/src/proxy.rs tests (test_proxy_sign_in_out, test_proxy_sign_in_noop)` | expires devise session keys, no-op when same resource without force |
| `bypass_sign_in` | method | `controllers/sign_in_out.rb:56` | `AuthProxy::bypass_sign_in` (`proxy.rs:324`) | ported | `crates/devise-rust/src/proxy.rs tests (test_proxy_bypass_sign_in)` | stores without callbacks |
| `sign_out` | method | `controllers/sign_in_out.rb:71` | `AuthProxy::sign_out` (`proxy.rs:338`) | ported | `crates/devise-rust/src/proxy.rs tests` | |
| `sign_out_all_scopes` | method | `controllers/sign_in_out.rb:86` | `AuthProxy::sign_out_all_scopes` (`proxy.rs:361`) | ported | `crates/devise-rust/src/proxy.rs tests (test_proxy_sign_out_all_scopes)` | lock parameter kept |
| `expire_data_after_sign_in!` | method | `controllers/sign_in_out.rb:99` | expire path inside `sign_in` | ported | `crates/devise-rust/src/proxy.rs tests (test_proxy_sign_in_out)` | |
| `stored_location_for` | method | `controllers/store_location.rb:18` | `stored_location` resolution (`crates/devise-rust/src/failure.rs:130` plus session keys) | ported | `crates/devise-rust/src/failure.rs tests (test_stored_location)` | same-host path validation |
| `store_location_for` | method | `controllers/store_location.rb:36` | store path (`crates/devise-rust/src/session.rs:78` key plus framework store call) | ported | `crates/devise-rust/src/failure.rs tests (test_stored_location)` and `crates/devise-rust-axum/tests/devise_flows.rs (flow_stored_location_get_only)` | GET-only storage (devise behavior) |
| `parse_uri` / `extract_path_from_location` (protected) | method | `controllers/store_location.rb:45,56` | URI parse guard on stored locations (`crates/devise-rust/src/request.rs tests (test_parse_stored_uri)`) | ported | `crates/devise-rust/src/request.rs tests (test_parse_stored_uri)` | external hosts rejected |
| URL helpers (`new_user_session_path` family) | method | `controllers/url_helpers.rb:37` | route spec paths on `RouteSpec` (`crates/devise-rust/src/scope.rs:681`) | deviated | `crates/devise-rust/src/scope.rs tests (test_all_route_specs)` | Rails metaprograms named helper methods; Rust exposes the path from the shared route specs and both routers' path functions, not generated global methods |
| sessions controller (`new`, `create`, `destroy`) | method | `app/controllers/devise/sessions_controller.rb` | session handlers in `crates/devise-rust-{actix,axum}/src/routes.rs` | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_sign_in_and_sign_out_with_flashes, flow_sign_in_failure_formats)` | flash keys, already_signed_out, skip timeout flags |
| registrations controller (`new`, `create`, `edit`, `update`, `destroy`, `cancel`) | method | `app/controllers/devise/registrations_controller.rb` | registration handlers in both framework crates | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_sign_up_failure_clears_passwords_and_keeps_errors, flow_account_update_requires_current_password)` | update_resource default is update_with_password; bypass_sign_in per `sign_in_after_change_password` |
| passwords controller (`new`, `create`, `edit`, `update`) | method | `app/controllers/devise/passwords_controller.rb` | password handlers in both framework crates | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_reset_token_errors)` | assert_reset_token_passed, unlock on reset, sign-in after reset per config |
| confirmations controller (`new`, `create`, `show`) | method | `app/controllers/devise/confirmations_controller.rb` | confirmation handlers in both framework crates | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_confirm_by_token_blank_and_legacy_paths)` | |
| unlocks controller (`new`, `create`, `show`) | method | `app/controllers/devise/unlocks_controller.rb` | unlock handlers in both framework crates | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_unlock_by_token)` | |
| omniauth callbacks controller | method | `app/controllers/devise/omniauth_callbacks_controller.rb` | omniauth handlers in both framework crates | ported | `crates/devise-rust-axum/tests/omniauth_flows.rs` | per-provider dispatch with the shared stub-provider harness |

## Strategies (warden layer)

`devise/lib/devise/strategies/*.rb` map to the strategy layer in `crates/devise-rust/src/strategy.rs`, dispatched by `AuthProxy::authenticate` in Devise's order (no-input rememberable first, then params, then HTTP Basic).

| devise name | kind | devise source | Rust counterpart | status | test evidence | notes |
|---|---|---|---|---|---|---|
| `Base#store?` | method | `strategies/base.rb:8` | store decision on the strategies (`strategy.rs`) | ported | `crates/devise-rust/src/strategy.rs tests (test_strategy_ids)` | honors `skip_session_storage` |
| `Authenticatable#valid?` | method | `strategies/authenticatable.rb:17` | `valid` on the strategy chain (`strategy.rs`) | ported | `crates/devise-rust/src/strategy.rs tests (test_strategy_chain_order)` | params or http present |
| `Authenticatable#validate` | method | `strategies/authenticatable.rb:37` | validate step calling `valid_for_authentication` | ported | `crates/devise-rust/src/lockable.rs tests (lockable_chain_locks_at_threshold_and_counts_when_locked)` | fail carries `unauthenticated_message` |
| `Authenticatable#remember_me` / `remember_me?` | method | `strategies/authenticatable.rb:51,56` | remember flag stamp (`strategy.rs test_params_strategy_stamps_remember_flag`) | ported | `crates/devise-rust/src/strategy.rs tests (test_params_strategy_stamps_remember_flag)` | TRUE_VALUES parsing of the form field |
| `Authenticatable#valid_for_http_auth?` / `valid_for_params_auth?` | method | `strategies/authenticatable.rb:66,77` | per-strategy validity checks (`strategy.rs`) | ported | `crates/devise-rust/src/strategy.rs tests (test_http_basic_strategy_success)` | |
| `Authenticatable#params_auth_hash` / `http_auth_hash` | method | `strategies/authenticatable.rb:93,98` | auth hash assembly honoring required keys | ported | `crates/devise-rust/src/strategy.rs tests (test_params_strategy_success)` | |
| `Authenticatable#valid_password?` presence guard | method | `strategies/authenticatable.rb:117` | password presence check before the adapter lookup | ported | `crates/devise-rust/src/strategy.rs tests (test_params_strategy_wrong_password)` | |
| `Authenticatable#request_keys` handling | method | `strategies/authenticatable.rb:147` | request-key extraction (`request.rs`) | ported | `crates/devise-rust/src/strategy.rs tests (test_strategy_chain_order)` | missing request keys abort authentication |
| `DatabaseAuthenticatable#authenticate!` | method | `strategies/database_authenticatable.rb:9` | `DatabaseAuthenticatableStrategy::authenticate` (`strategy.rs`) | ported | `crates/devise-rust/src/strategy.rs tests (test_params_strategy_success, test_params_strategy_unknown_user, test_paranoid_strategy_masks_not_found)` | paranoid mode hashes against a blank record on miss (TEST-03 item 1), fails `:invalid` vs `:not_found_in_database` per config |
| `Rememberable#valid?` | method | `strategies/rememberable.rb:13` | cookie presence check (`strategy.rs`) | ported | `crates/devise-rust/src/proxy.rs tests (test_proxy_rememberable_stale_cookie_clears_and_passes)` | |
| `Rememberable#authenticate!` | method | `strategies/rememberable.rb:21` | `RememberableStrategy::authenticate` (`strategy.rs`) | ported | `crates/devise-rust/src/strategy.rs tests (test_strategy_rememberable_round_trip_success, test_strategy_rememberable_rejects_inactive_record)` | delete cookie plus pass on miss; validate; optional re-remember; `after_remembered`; success |
| `Rememberable#clean_up_csrf?` | method | `strategies/rememberable.rb:41` | no CSRF cleanup on the remember strategy | ported | `crates/devise-rust/src/hooks.rs tests` | GET-triggered by design |
| `Rememberable#extend_remember_me?` / `remember_key` / `remember_cookie` | method | `strategies/rememberable.rb:47,55,59` | extension decision plus cookie key resolution (`crates/devise-rust/src/session.rs:86`) | ported | `crates/devise-rust/src/rememberable.rs tests (rememberable_set_hook_emits_hardened_cookie)` | `rememberable_options[:key]` override honored |

## Failure app

`devise/lib/devise/failure_app.rb` maps to the failure decision layer (`crates/devise-rust/src/failure.rs`) plus the per-framework failure responders.

| devise name | kind | devise source | Rust counterpart | status | test evidence | notes |
|---|---|---|---|---|---|---|
| `respond` (dispatch) | method | `failure_app.rb:42` | `build_failure` decision (`crates/devise-rust/src/failure.rs:403`) | ported | `crates/devise-rust/src/failure.rs tests (test_failure_decision, test_failure_decision_nav_api_recall)` | navigational vs 401 vs recall |
| `http_auth` | method | `failure_app.rb:52` | `http_auth` (`crates/devise-rust/src/failure.rs:390`) | ported | `crates/devise-rust/src/failure.rs tests` | 401 plus WWW-Authenticate plus realm |
| `recall` | method | `failure_app.rb:59` | simplified to the redirect plus 401 split (`crates/devise-rust/src/failure.rs:111`) | waived | `crates/devise-rust/src/failure.rs tests (test_failure_decision_nav_api_recall)` | reason: devise re-dispatches the original controller action on recall for input-strategy failures; the port simplifies recall to the documented redirect plus 401 split, so the re-dispatch leg is out of v1. v1 impact: failed params sign-ins render the sign-in page via redirect (navigational) or 401 (API) instead of re-running the original action; the failure decision itself stays tested. |
| `redirect` | method | `failure_app.rb:86` | redirect target with i18n message and flash key | ported | `crates/devise-rust/src/failure.rs tests (test_failure_decision)` | scope sign-in path target |
| `i18n_message` / `i18n_options` / `i18n_locale` | method | `failure_app.rb:101,105,131` | `i18n` lookup with interpolation (`crates/devise-rust/src/i18n.rs`) | ported | `crates/devise-rust/src/i18n.rs tests (test_translate_with_interpolation)` | locale option honored |
| `http_auth_body` | method | `failure_app.rb:208` | 401 body carrying the message | ported | `crates/devise-rust/src/failure.rs tests (test_failure_decision_nav_api_recall)` | |
| `http_auth?` / `http_auth_header?` | method | `failure_app.rb:194,204` | `is_api_unauthorized` plus `www_authenticate` (`failure.rs:103,155`) | ported | `crates/devise-rust/src/failure.rs tests` | header only when the model allows http auth |
| `store_location!` / `attempted_path` | method | `failure_app.rb:247,255` | stored location write (`crates/devise-rust/src/failure.rs:130`) | ported | `crates/devise-rust/src/failure.rs tests (test_stored_location)` | GET-only |
| `is_navigational_format?` / `is_flashing_format?` | method | `failure_app.rb:259,265` | format classification (`failure.rs:95,379`) | ported | `crates/devise-rust/src/request.rs tests (test_is_navigational_format)` | |
| `scope` / `warden_options` / `warden_message` | method | `failure_app.rb:239,231,235` | fields on the failure decision struct (`crates/devise-rust/src/failure.rs`) | ported | `crates/devise-rust/src/failure.rs tests (test_failure_variants)` | |
| `Delegator` (per-scope failure app) | method | `lib/devise/delegator.rb` | `Mapping::failure_app` honored by `build_failure` | ported | `crates/devise-rust/src/failure.rs tests (test_failure_decision)` | default when no scope option |

## Crypto and tokens

| devise name | kind | devise source | Rust counterpart | status | test evidence | notes |
|---|---|---|---|---|---|---|
| `Devise::Encryptor.digest` | method | `lib/devise/encryptor.rb:7` | `crypto::encryptor::digest` (`crates/devise-rust/src/crypto.rs:66`) | ported | `crates/devise-rust/src/crypto.rs tests (test_encryptor_digest_compare, test_encryptor_with_pepper)` | bcrypt with pepper and stretches; digest and compare run synchronously on the caller's thread (no runtime offload) |
| `Devise::Encryptor.compare` | method | `lib/devise/encryptor.rb:14` | `crypto::encryptor::compare` (`crates/devise-rust/src/crypto.rs:94`) | ported | `crates/devise-rust/src/crypto.rs tests (test_encryptor_digest_compare)` | re-hash plus constant-time compare, never `==` |
| `Devise::TokenGenerator#digest` | method | `lib/devise/token_generator.rb:12` | `crypto::token_generator::digest` (`crates/devise-rust/src/crypto.rs:126`) | ported | `crates/devise-rust/src/crypto.rs tests (test_token_generator_digest)` | HMAC-SHA256 keyed `"Devise {column}"` |
| `Devise::TokenGenerator#generate` | method | `lib/devise/token_generator.rb:16` | `crypto::token_generator::generate` (`crates/devise-rust/src/crypto.rs:162`) | ported | `crates/devise-rust/src/crypto.rs tests` | raw plus digest pair, uniqueness loop against the adapter |
| `Devise.friendly_token` | method | `lib/devise.rb` | `crypto::friendly_token` (`crates/devise-rust/src/crypto.rs:194`) | ported | `crates/devise-rust/src/crypto.rs tests (test_friendly_token_length, test_friendly_token_charset_parity)` | urlsafe base64, `lIO0` to `sxyz` substitution |
| `Devise.secure_compare` | method | `lib/devise.rb` | `crypto::secure_compare` (`crates/devise-rust/src/crypto.rs:173`) | ported | `crates/devise-rust/src/crypto.rs tests (test_secure_compare)` | constant-time, nil-safe |
| `Devise.add_module` | method | `lib/devise.rb:397` | module registry on `ScopeRegistry` plus `Module` enum (`crates/devise-rust/src/scope.rs`) | deviated | `crates/devise-rust/src/scope.rs tests (test_module_order, test_all_route_specs)` | Devise's runtime registration seam for third-party modules becomes the compile-time `Module` enum; third-party route blocks are not a v1 extension point |
| `Devise.add_mapping` | method | `lib/devise.rb` | `ScopeRegistry::register` plus `Mapping` (`crates/devise-rust/src/scope.rs`) | ported | `crates/devise-rust/src/scope.rs tests (test_scope_registry)` | |

## Parameter filtering and sanitizing

| devise name | kind | devise source | Rust counterpart | status | test evidence | notes |
|---|---|---|---|---|---|---|
| `Devise::ParameterFilter#filter` | method | `lib/devise/parameter_filter.rb:10` | `ParameterFilter` (`crates/devise-rust/src/parameter.rs`) | ported | `crates/devise-rust/src/parameter.rs tests (test_parameter_filter_downcase, test_parameter_filter_strip_whitespace, test_parameter_filter_nested)` | downcase, strip, stringify scalars (UUID-safe) |
| `Devise::ParameterSanitizer#sanitize` | method | `lib/devise/parameter_sanitizer.rb:70` | `ParameterSanitizer::sanitize` (`crates/devise-rust/src/parameter.rs`) | ported | `crates/devise-rust/src/parameter.rs tests (test_parameter_sanitizer_sanitize)` | sign_in, sign_up, account_update defaults |
| `Devise::ParameterSanitizer#permit` | method | `lib/devise/parameter_sanitizer.rb:110` | `ParameterSanitizer::permit` with keys, except, and block | ported | `crates/devise-rust/src/parameter.rs tests (test_parameter_sanitizer_permit_except)` | extension point kept |
| `unknown_action!` | method | `lib/devise/parameter_sanitizer.rb:162` | unknown-action error (`crates/devise-rust/src/parameter.rs`) | ported | `crates/devise-rust/src/parameter.rs tests (test_parameter_sanitizer_unknown_action)` | |

## Mailer

`devise/app/mailers/devise_mailer.rb` plus the five notification templates map to the `Mailer` trait (`crates/devise-rust/src/mailer.rs`) with Tera templates mirroring the Devise copy.

| devise name | kind | devise source | Rust counterpart | status | test evidence | notes |
|---|---|---|---|---|---|---|
| `confirmation_instructions` | method | `app/mailers/devise_mailer.rb` | `Mailer::confirmation_instructions` (`crates/devise-rust/src/mailer.rs`) | ported | `crates/devise-rust/src/mailer.rs tests (test_mailer_confirmation)` and `crates/devise-rust/tests/notifications.rs` | subject from i18n, token in body |
| `reset_password_instructions` | method | `app/mailers/devise_mailer.rb` | `Mailer::reset_password_instructions` | ported | `crates/devise-rust/tests/notifications.rs (mailer_context_carries_template_vars)` | |
| `unlock_instructions` | method | `app/mailers/devise_mailer.rb` | `Mailer::unlock_instructions` | ported | `crates/devise-rust/src/lockable.rs tests (lockable_lock_access_mails_raw_stores_digest)` | raw token only in the mail |
| `email_changed` | method | `app/mailers/devise_mailer.rb` | `Mailer::email_changed` | ported | `crates/devise-rust/tests/notifications.rs (email_change_notification_goes_to_original_address)` | original recipient |
| `password_change` | method | `app/mailers/devise_mailer.rb` | `Mailer::password_change` | ported | `crates/devise-rust/tests/notifications.rs (password_change_notification_goes_to_current_address)` | current recipient |
| `devise_mailer` customization | method | `models/authenticatable.rb:129` | app-supplied `Mailer` implementation | ported | `crates/devise-rust/src/mailer.rs tests (mailer_trait_compiles)` | trait replaces the class reference |

## Status summary

| Status | Count |
|---|---|
| ported | 362 |
| deviated | 10 |
| waived | 7 |

Deviated rows are documented divergences with the reason and the documenting artifact named in the notes column; every waived row carries its reason and v1 impact both here and in [parity-checklist.md](parity-checklist.md). The reversal cost of this table's shape and of the waiver set is flagged in the phase SUMMARY: this table is the audit artifact reviewers cite, so changing its shape invalidates completed audit rows (D-04), and reversing a waiver reopens the corresponding test work (D-12).


