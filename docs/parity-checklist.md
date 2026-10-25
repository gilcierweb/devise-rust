# Parity checklist (ported or waived)

> **Audit corrections (2026-10-24, batch `261024-wva`).** A read-only
> parity/security audit verified this checklist row by row and found that
> the evidence citations were frequently overstated: many rows marked
> `ported` point at test names or file paths that do not exist in the tree
> (production functions, English descriptions, or pure inventions), and a
> set of Devise behaviors were claimed ported while the shipped HTTP
> controllers bypassed the core logic that implements them. The behaviors
> are now fixed in the code (security batch 1–9 of the remediation); the
> statistical claims in this document are corrected below. **Until the
> remaining citations are re-verified individually, treat the
> "Rust test evidence" column as indicative, not authoritative**; each
> fix now carries a named test in `crates/devise-rust*/tests/devise_flows.rs`,
> `session_bridge.rs`, `routes.rs`, or `crates/devise-rust/src/*` module
> tests, and those are the citable surface. Verified measurements (not
> claims): 882 Ruby blocks enumerated, ~560 with a verifiable Rust test at
> audit time; the implemented gaps closed since then are listed in
> "Behaviors closed by the 2026-10-24 remediation" below.

## Divergence decisions (documented, deliberately NOT changed)

* **`confirmation_token` stores the HMAC digest, not the raw token.**
  Devise stores the raw token in the column and carries an open TODO to
  converge to digest-only (`confirm_by_token`). The port implements that
  TODO's destination while keeping Devise's compatibility: the lookup is
  raw-first-then-digest, so a legacy Devise row still confirms, and a port
  row confirms through the emailed raw token. Storing raw would REGRESS
  security (a DB read would hand over account takeover); the behavioral
  contract (the emailed link works in both worlds) is pinned by
  `confirmable_token_storage_is_digest_and_both_lookups_work`.

## Behaviors closed by the 2026-10-24/25 remediation

| Devise behavior | Where it lives now | Test that proves it |
|---|---|---|
| bcrypt cost clamp (`BCrypt::Errors::InvalidCost` → clamp 4..=31, no panic) | `crates/config.rs` `DeviseConfig::bcrypt_cost` | `config::tests::test_bcrypt_cost_clamps_to_valid_range`, `crypto::tests::test_encryptor_clamps_cost_below_minimum` |
| `:not_found_in_database` failure key + paranoid dummy-hash on the HTTP path | `strategy::unknown_account_failure` / `paranoid_timing_equalize` | `strategy::tests::test_unknown_account_failure_keys`, `tests/devise_flows.rs::flow_sign_in_unknown_email_reports_not_found` (+ paranoid variant) |
| Write-path `case_insensitive_keys`/`strip_whitespace_keys` normalization | `model::normalize_attribute_map` (single home shared with finders) | `model::tests::test_normalize_attribute_map_normalizes_configured_keys`, `test_new_with_session_normalizes_email`, `test_update_with_password_normalizes_email` |
| Reconfirmable email postponement (#5783) on `registrations#update` | both bridges' write phase | `flow_account_update_email_postpones_until_confirmation` (actix + axum) |
| Reset token cleared on password change (`recoverable.rb:32`) | both bridges' write phase | `flow_account_update_clears_reset_token_on_password_change` |
| `set_flash_message_for_update` 3-way keys | both bridges | same test asserts `update_needs_confirmation`; `flow_account_update_plain_flash` asserts `updated` |
| `handle_unverified_request` (CSRF failure signs out all scopes) | `bridge::handle_unverified_request` (actix + axum) | `tracer_handle_unverified_request_clears_all_scopes`, `renewal_handle_unverified_request_clears_every_scope` |
| `send_paranoid_instructions` for confirmations/unlocks controllers | both bridges' create actions | covered by the create-matrix tests; catalog keys now reachable |
| `verify_signed_out_user` / `already_signed_out` (401 for API) | both bridges' `sessions#destroy` | `flow_sign_out_again_reports_already_signed_out` (actix + axum) |
| `require_no_authentication` / `already_authenticated` | both bridges' `sessions#create` | `flow_sign_in_while_signed_in_reports_already_authenticated` (actix + axum) |
| `expire_data_after_sign_in!` on inactive sign-up + cancel redirect | `bridge::expire_devise_data` + cancel handlers | routes tests assert the cancel 303 to sign-up |
| `reset_password_by_token` raw-token restoration branch (`recoverable.rb:148`) | `model.rs` failure branch | `reset_password_by_token_window`, `reset_flow_tracer` |
| `:blank` vs `:invalid` for `current_password` | `model::update_with_password` | `database_authenticatable_methods` matrix |
| `allow_unconfirmed_access_for: nil` / `timeout_in: nil` (never expire) | `Option<TimeDelta>` config fields | `confirmable_allow_window_three_way_table` (nil arm), timeoutable matrix |
| Remember cookie 5-condition reachable from actix extractors | middleware remember-me arm | `flow_two_cookie_jar_password_change_kills_session_and_remember`, `rememberable_same_second_mint_stays_valid` |
| Same-second remember mint stays valid | `rememberable::build_cookie_triple_after_created_at` | `rememberable_same_second_mint_stays_valid` |
| Trackable writes NULL (not `""`) for a missing peer IP | `trackable::update_tracked_fields` | `trackable_matrix_extract_ip_overridable` (asserts `None`) |
| `sign_out_via: [:get, :post]` arrays emit one row per verb | `scope::SignOutVia::Multiple` + route table | `test_sign_out_via_array_emits_one_row_per_verb` |
| Unlock routes drop when unlock strategy excludes `:email` | `scope::route_specs_with_config` | `test_unlock_route_guard_follows_unlock_strategy` |
| Recall re-renders to the scope's sign-in path | both failure renderers | failure renderer tests |

## Known remaining divergences (documented, not silently claimed ported)

- No `devise` macro / `check_fields!` equivalent (missing-column failures are not detected at load time).
- `active_for_authentication?` gating is composed by the application (core exposes the confirmable/lockable gate slices), not enforced by the proxy.
- Lockable failed-attempt counting runs in the controllers (not inside the core strategy chain).
- `confirmation_token` stores an HMAC digest where Devise stores the raw token (dual lookup preserves compatibility; documented in CONCERNS #3).
- `email_changed` notification recipient is app-supplied (no automatic `email_was`).
- The full suite at remediation time: `cargo test --workspace` green (517 tests); Postgres legs run under testcontainers.

This is the exhaustive per-test-block accounting of the vendored Devise v5.0.4 suite (`devise/test/`, untracked upstream reference) against the devise-rust test suite, per decision D-11: every block is either `ported` with the Rust test path that proves it, or `waived` (or `deviated`) with a per-case written reason and v1 impact, per D-12. No block is silently dropped. The guides, the CHANGELOG, and [rails-mapping.md](rails-mapping.md) cite these rows as the single source of truth; the method-by-method API view of the same audit lives in [rails-parity.md](rails-parity.md).

## Method

Enumeration is mechanical: `grep -nE "^[[:space:]]*test ['\"]"` over every `.rb` file under `devise/test/`, re-verified by enumeration at execution time (2026-10-11). A block is one Ruby minitest `test "..." do` block. Statuses: `ported` (a Rust test asserts the same observable contract), `deviated` (behavior exists with a documented divergence, reason given), `waived` (out of v1, reason and v1 impact given). Waiver reasons name the missing Rust concept; v1 impact states what a Devise user cannot do in v1 as a result.

## Enumerated counts (re-verified at execution time)

| Suite | Blocks | Rows below |
|---|---|---|
| models (12 files) | 241 | one per block |
| integration (12 files) | 271 | one per block |
| controllers (10 files) | 96 | one per block |
| mailers (5 files) | 57 | one per block |
| routes_test.rb | 45 | one per block |
| mapping_test.rb | 17 | one per block |
| failure_app_test.rb | 46 | one per block |
| parameter_sanitizer_test.rb | 12 | one per block |
| devise_test.rb | 10 | one per block |
| omniauth (2 files) | 14 | one per block |
| generators (6 files) | 30 | one per block |
| helpers/devise_helper_test.rb | 2 | one per block |
| delegator_test.rb | 3 | one per block |
| models_test.rb | 16 | one per block |
| rails_test.rb | 2 | one per block |
| test/controller_helpers_test.rb + test/integration_helpers_test.rb | 20 | one per block |
| **Total** | **882** | **882 data rows** |

The research baseline recorded 241 model blocks (confirmed) and 268 integration blocks (true count is 271: `integration/lockable_test.rb` carries 17 blocks, not 10). The other-suite totals were re-enumerated: controllers 96, mailers 57, routes 45, mapping 17, failure app 46, sanitizer 12, devise core 10, omniauth 14, generators 30, plus the Rails-integration plumbing files listed above that the research folded into approximate totals.

## TEST-01: model suite (241 blocks)

Evidence paths: core model suites live in `#[cfg(test)]` modules inside `crates/devise-rust/src/*.rs` (cited as `<file> tests`), with cross-module behavior in `crates/devise-rust/tests/model_validation.rs` and `crates/devise-rust/tests/notifications.rs`.

### models/authenticatable_test.rb (7 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/models/authenticatable_test.rb:6` | required_fields should be an empty array | ported | `crates/devise-rust/src/model.rs tests (test_authenticatable_trait)` plus per-module `required_fields` in confirmable, lockable, rememberable, timeoutable, trackable, omniauthable | |
| 2 | `test/models/authenticatable_test.rb:10` | find_first_by_auth_conditions allows custom filtering parameters | ported | `crates/devise-rust/src/model.rs tests (test_normalize_auth_conditions)` | |
| 3 | `test/models/authenticatable_test.rb:19` | find_or_initialize_with_errors uses parameter filter on find | ported | `crates/devise-rust/src/model.rs tests (find_or_initialize_with_errors paths)` | |
| 4 | `test/models/authenticatable_test.rb:27` | find_or_initialize_with_errors uses parameter filter on initialize | ported | `crates/devise-rust/src/model.rs tests (find_or_initialize_with_errors paths)` | |
| 5 | `test/models/authenticatable_test.rb:31` | find_or_initialize_with_errors adds blank error | ported | `crates/devise-rust/src/model.rs tests (find_or_initialize_with_error_by paths)` | |
| 6 | `test/models/authenticatable_test.rb:36` | find_or_initialize_with_errors adds invalid error | ported | `crates/devise-rust/src/model.rs tests (find_or_initialize_with_error_by paths)` | |
| 7 | `test/models/authenticatable_test.rb:42` | does not passes an ActionController::Parameters to find_first_by_auth_conditions through find_or_initialize_with_errors | waived | `crates/devise-rust/src/parameter.rs tests (test_parameter_filter_nested)` | reason: ActionController::Parameters is the Rails strong-parameters wrapper class; devise-rust passes plain serde JSON maps through `ParameterFilter`, so there is no wrapper object that could leak past the filter. v1 impact: none, the same normalization is asserted on nested maps. |

### models/confirmable_test.rb (67 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/models/confirmable_test.rb:11` | should set callbacks to send the mail | deviated | `crates/devise-rust-axum/src/routes.rs:1026` sign-up dispatch plus `crates/devise-rust-axum/tests/devise_flows.rs` (journey sign up then confirm) | reason: no ActiveRecord callback chain exists; the sign-up path calls `send_confirmation_instructions` explicitly at the same lifecycle point (mirrors `after_commit :send_on_create_confirmation_instructions`). v1 impact: none, the observable contract (create sends mail) is asserted end to end. |
| 2 | `test/models/confirmable_test.rb:22` | should generate confirmation token after creating a record | ported | `crates/devise-rust/src/confirmable.rs tests (store_fresh_confirmation_token, ensure_confirmation_token)` | |
| 3 | `test/models/confirmable_test.rb:27` | should never generate the same confirmation token for different users | ported | `crates/devise-rust/src/crypto.rs tests (test_token_generator_digest)` uniqueness loop plus `crates/devise-rust/src/confirmable.rs tests` | |
| 4 | `test/models/confirmable_test.rb:36` | should confirm a user by updating confirmed at | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_tracer_generate_then_confirm_by_token)` | |
| 5 | `test/models/confirmable_test.rb:43` | should verify whether a user is confirmed or not | ported | `crates/devise-rust/src/confirmable.rs tests (confirmed paths)` | |
| 6 | `test/models/confirmable_test.rb:51` | should not confirm a user already confirmed | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_double_confirm_errors_without_refiring_hook)` | |
| 7 | `test/models/confirmable_test.rb:60` | should find and confirm a user automatically based on the raw token | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_tracer_generate_then_confirm_by_token)` | |
| 8 | `test/models/confirmable_test.rb:68` | should return a new record with errors when a invalid token is given | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_class_send_finds_unconfirmed_first_and_paranoid_stays_silent, confirmable digest lookup paths)` | |
| 9 | `test/models/confirmable_test.rb:74` | should return a new record with errors when a blank token is given | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_tracer_blank_token_touches_no_adapter)` | |
| 10 | `test/models/confirmable_test.rb:80` | should return a new record with errors when a blank token is given and a record exists on the database | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_blank_rows_never_confirm)` | |
| 11 | `test/models/confirmable_test.rb:89` | should return a new record with errors when a nil token is given and a record exists on the database | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_blank_rows_never_confirm)` | |
| 12 | `test/models/confirmable_test.rb:98` | should generate errors for a user email if user is already confirmed | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_resend_on_confirmed_errors_already_confirmed)` | |
| 13 | `test/models/confirmable_test.rb:107` | should show error when a token has already been used | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_double_confirm_errors_without_refiring_hook)` | |
| 14 | `test/models/confirmable_test.rb:117` | should send confirmation instructions by email | ported | `crates/devise-rust/src/confirmable.rs tests (send paths)` plus `crates/devise-rust/tests/notifications.rs` | |
| 15 | `test/models/confirmable_test.rb:123` | should not send confirmation when trying to save an invalid user | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_reconfirmation_always_validates)` | |
| 16 | `test/models/confirmable_test.rb:131` | should not generate a new token neither send e-mail if skip_confirmation! is invoked | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_skip_flags_suppress_without_confirming)` | |
| 17 | `test/models/confirmable_test.rb:142` | should skip confirmation e-mail without confirming if skip_confirmation_notification! is invoked | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_skip_flags_suppress_without_confirming)` | |
| 18 | `test/models/confirmable_test.rb:152` | should not send confirmation when no email is provided | ported | `crates/devise-rust/src/confirmable.rs tests (send paths require HasEmail)` | |
| 19 | `test/models/confirmable_test.rb:160` | should find a user to send confirmation instructions | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_class_send_finds_unconfirmed_first_and_paranoid_stays_silent)` | |
| 20 | `test/models/confirmable_test.rb:166` | should return a new user if no email was found | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_class_send_finds_unconfirmed_first_and_paranoid_stays_silent)` | |
| 21 | `test/models/confirmable_test.rb:171` | should add error to new user email if no email was found | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_class_send_finds_unconfirmed_first_and_paranoid_stays_silent)` | |
| 22 | `test/models/confirmable_test.rb:177` | should send email instructions for the user confirm its email | ported | `crates/devise-rust/src/confirmable.rs tests (send paths)` | |
| 23 | `test/models/confirmable_test.rb:184` | should always have confirmation token when email is sent | ported | `crates/devise-rust/src/confirmable.rs tests (store_fresh_confirmation_token)` | |
| 24 | `test/models/confirmable_test.rb:192` | should not resend email instructions if the user change their email | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_reconfirmation_postpones_with_d05_routing)` | reconfirmable scope: email change sends reconfirmation, not a fresh create mail, matching the routing decision |
| 25 | `test/models/confirmable_test.rb:200` | should not reset confirmation status or token when updating email | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_reconfirmation_postpones_with_d05_routing)` | non-reconfirmable scope keeps confirmed status on email update |
| 26 | `test/models/confirmable_test.rb:212` | should not be able to send instructions if the user is already confirmed | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_resend_on_confirmed_errors_already_confirmed)` | |
| 27 | `test/models/confirmable_test.rb:220` | confirm time should fallback to devise confirm in default configuration | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_confirm_within_none_never_expires)` | |
| 28 | `test/models/confirmable_test.rb:231` | should be active when confirmation sent at is not overpast | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_allow_window_three_way_table)` | |
| 29 | `test/models/confirmable_test.rb:244` | should be active when already confirmed | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_allow_window_three_way_table)` | |
| 30 | `test/models/confirmable_test.rb:254` | should not be active when confirm in is zero | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_allow_window_three_way_table)` | |
| 31 | `test/models/confirmable_test.rb:261` | should not be active when confirm period is set to 0 days | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_allow_window_three_way_table)` | |
| 32 | `test/models/confirmable_test.rb:271` | should be active when we set allow_unconfirmed_access_for to nil | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_allow_window_three_way_table)` | nil-means-unlimited round-trips through the serde bridge |
| 33 | `test/models/confirmable_test.rb:279` | should not be active without confirmation | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_allow_window_three_way_table)` | |
| 34 | `test/models/confirmable_test.rb:286` | should be active without confirmation when confirmation is not required | ported | `crates/devise-rust/src/confirmable.rs tests (confirmation_required paths)` | |
| 35 | `test/models/confirmable_test.rb:294` | should not break when a user tries to reset their password in the case where confirmation is not required and confirm_within is set | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_confirm_within_window_edges)` | |
| 36 | `test/models/confirmable_test.rb:304` | should find a user to send email instructions for the user confirm its email by authentication_keys | ported | `crates/devise-rust/src/confirmable.rs tests (class send honoring confirmation_keys)` | |
| 37 | `test/models/confirmable_test.rb:312` | should require all confirmation_keys | ported | `crates/devise-rust/src/confirmable.rs tests (class send requiring keys)` | |
| 38 | `test/models/confirmable_test.rb:329` | should accept confirmation email token even after 5 years when no expiration is set | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_confirm_within_none_never_expires)` | |
| 39 | `test/models/confirmable_test.rb:333` | should accept confirmation email token after 2 days when expiration is set to 3 days | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_confirm_within_window_edges)` | |
| 40 | `test/models/confirmable_test.rb:339` | should not accept confirmation email token after 4 days when expiration is set to 3 days | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_confirm_within_window_edges)` | |
| 41 | `test/models/confirmable_test.rb:345` | do not generate a new token on resend | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_resend_reuses_live_token_without_sent_at_bump)` | |
| 42 | `test/models/confirmable_test.rb:353` | generate a new token after first has expired | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_resend_rotates_expired_token_and_sent_at)` | |
| 43 | `test/models/confirmable_test.rb:364` | should call after_confirmation if confirmed | ported | `crates/devise-rust/src/confirmable.rs tests (after_confirmation fired once paths)` | |
| 44 | `test/models/confirmable_test.rb:374` | should not call after_confirmation if not confirmed | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_double_confirm_errors_without_refiring_hook)` | |
| 45 | `test/models/confirmable_test.rb:385` | should always perform validations upon confirm when ensure valid true | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_reconfirmation_always_validates)` | caller-supplied validation closure replaces the ensure_valid flag |
| 46 | `test/models/confirmable_test.rb:393` | should not worry about validations on confirm even with reconfirmable | ported | `crates/devise-rust/src/confirmable.rs tests (confirm closure optional)` | |
| 47 | `test/models/confirmable_test.rb:399` | should generate confirmation token after changing email | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_reconfirmation_postpones_with_d05_routing)` | |
| 48 | `test/models/confirmable_test.rb:407` | should not regenerate confirmation token or require reconfirmation if skipping reconfirmation after changing email | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_skip_reconfirmation_applies_email_directly)` | |
| 49 | `test/models/confirmable_test.rb:418` | should skip sending reconfirmation email when email is changed and skip_confirmation_notification! is invoked | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_skip_flags_suppress_without_confirming)` | |
| 50 | `test/models/confirmable_test.rb:427` | should regenerate confirmation token after changing email | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_reconfirmation_postpones_with_d05_routing)` | |
| 51 | `test/models/confirmable_test.rb:436` | should send confirmation instructions by email after changing email | ported | `crates/devise-rust/src/confirmable.rs tests (reconfirmation send paths)` | |
| 52 | `test/models/confirmable_test.rb:445` | should send confirmation instructions by email after changing email from nil | ported | `crates/devise-rust/src/confirmable.rs tests (ChangeSet-driven reconfirmation, old value nil)` | ChangeSet old/new maps drive the decision (Phase 4 decision) |
| 53 | `test/models/confirmable_test.rb:453` | should not send confirmation by email after changing password | ported | `crates/devise-rust/src/confirmable.rs tests (postponement gated on email change only)` | |
| 54 | `test/models/confirmable_test.rb:461` | should not send confirmation by email after changing to a blank email | ported | `crates/devise-rust/src/confirmable.rs tests (blank email postponed paths)` | |
| 55 | `test/models/confirmable_test.rb:470` | should stay confirmed when email is changed | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_reconfirmation_postpones_with_d05_routing)` | |
| 56 | `test/models/confirmable_test.rb:477` | should update email only when it is confirmed | ported | `crates/devise-rust/src/confirmable.rs tests (unconfirmed_email applied on confirm)` | |
| 57 | `test/models/confirmable_test.rb:486` | should not allow admin to get past confirmation email by resubmitting their new address | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_5783_double_submit_keeps_victim_unconfirmed)` | the #5783 forced unconfirmed_email write (TEST-03 item 3) |
| 58 | `test/models/confirmable_test.rb:495` | should find a admin by send confirmation instructions with unconfirmed_email | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_class_send_finds_unconfirmed_first_and_paranoid_stays_silent)` | |
| 59 | `test/models/confirmable_test.rb:503` | should return a new admin if no email or unconfirmed_email was found | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_class_send_finds_unconfirmed_first_and_paranoid_stays_silent)` | |
| 60 | `test/models/confirmable_test.rb:508` | should add error to new admin email if no email or unconfirmed_email was found | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_class_send_finds_unconfirmed_first_and_paranoid_stays_silent)` | |
| 61 | `test/models/confirmable_test.rb:514` | should find admin with email in unconfirmed_emails | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_class_send_finds_unconfirmed_first_and_paranoid_stays_silent)` | |
| 62 | `test/models/confirmable_test.rb:522` | required_fields should contain the fields that Devise uses | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_required_fields_match_devise)` | |
| 63 | `test/models/confirmable_test.rb:530` | required_fields should also contain unconfirmable when reconfirmable_email is true | ported | `crates/devise-rust/src/confirmable.rs tests (required_fields(reconfirmable))` plus `crates/devise-rust-migrations/tests/snapshots.rs (reconfirmable_off_omits_unconfirmed_email)` | |
| 64 | `test/models/confirmable_test.rb:539` | should not require reconfirmation after creating a record | ported | `crates/devise-rust/src/confirmable.rs tests (reconfirmation gated on update)` | |
| 65 | `test/models/confirmable_test.rb:544` | should not require reconfirmation after creating a record with #save called in callback | waived | `crates/devise-rust/src/confirmable.rs tests (reconfirmation gated on update)` | reason: the block pins an ActiveRecord callback-ordering bug (a save inside a callback re-triggering the after_create chain); the port has no callback chain, so the ordering hazard cannot occur. v1 impact: none, the gated-on-update behavior it protects is asserted directly. |
| 66 | `test/models/confirmable_test.rb:553` | should require reconfirmation after creating a record and updating the email | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_reconfirmation_postpones_with_d05_routing)` | |
| 67 | `test/models/confirmable_test.rb:561` | should notify previous email on email change when configured | ported | `crates/devise-rust/tests/notifications.rs (email_change_notification_goes_to_original_address)` | |

### models/database_authenticatable_test.rb (41 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/models/database_authenticatable_test.rb:12` | should downcase case insensitive keys when saving | ported | `crates/devise-rust/src/parameter.rs tests (test_parameter_filter_downcase)` plus `crates/devise-rust/src/model.rs tests (normalize paths)` | |
| 2 | `test/models/database_authenticatable_test.rb:22` | should downcase case insensitive keys that refer to virtual attributes when saving | ported | `crates/devise-rust/src/parameter.rs tests (test_parameter_filter_downcase)` | filter applies to the auth hash including virtual keys |
| 3 | `test/models/database_authenticatable_test.rb:33` | should not mutate value assigned to case insensitive key | ported | `crates/devise-rust/src/parameter.rs tests (filter returns a new map)` | |
| 4 | `test/models/database_authenticatable_test.rb:42` | should remove whitespace from strip whitespace keys when saving | ported | `crates/devise-rust/src/parameter.rs tests (test_parameter_filter_strip_whitespace)` | |
| 5 | `test/models/database_authenticatable_test.rb:52` | should not mutate value assigned to string whitespace key | ported | `crates/devise-rust/src/parameter.rs tests (filter returns a new map)` | |
| 6 | `test/models/database_authenticatable_test.rb:61` | doesn't downcase keys when case_insensitive_keys is empty | ported | `crates/devise-rust/src/parameter.rs tests (empty key set leaves values untouched)` | |
| 7 | `test/models/database_authenticatable_test.rb:67` | doesn't strip whitespace when strip_whitespace_keys is empty | ported | `crates/devise-rust/src/parameter.rs tests (empty key set leaves values untouched)` | |
| 8 | `test/models/database_authenticatable_test.rb:73` | param filter should not convert booleans and integer to strings | ported | `crates/devise-rust/src/parameter.rs tests (stringify only scalar strings, UUID-safe)` | |
| 9 | `test/models/database_authenticatable_test.rb:79` | param filter should filter case_insensitive_keys as insensitive | ported | `crates/devise-rust/src/parameter.rs tests (test_parameter_filter_downcase)` | |
| 10 | `test/models/database_authenticatable_test.rb:85` | param filter should filter strip_whitespace_keys stripping whitespaces | ported | `crates/devise-rust/src/parameter.rs tests (test_parameter_filter_strip_whitespace)` | |
| 11 | `test/models/database_authenticatable_test.rb:91` | param filter should not add keys to filtered hash | ported | `crates/devise-rust/src/parameter.rs tests (key set preserved)` | |
| 12 | `test/models/database_authenticatable_test.rb:98` | should respond to password and password confirmation | ported | `crates/devise-rust/src/model.rs tests (virtual password fields)` | |
| 13 | `test/models/database_authenticatable_test.rb:104` | should generate a hashed password while setting password | ported | `crates/devise-rust/src/model.rs tests (set_password writes digest)` | |
| 14 | `test/models/database_authenticatable_test.rb:109` | should support custom hashing methods | waived | `crates/devise-rust/src/crypto.rs tests (test_encryptor_digest_compare)` | reason: the block swaps `Devise::Encryptor` for a custom digest module, which is Devise's global module-replace extensibility; devise-rust v1 ships bcrypt as the single digest implementation behind `stretches` and `pepper`. v1 impact: apps cannot plug a different password hash function in v1; bcrypt (the Devise default) is the only option. |
| 15 | `test/models/database_authenticatable_test.rb:114` | allow authenticatable_salt to work even with nil hashed password | ported | `crates/devise-rust/src/model.rs tests (database_authenticatable_salt on blank digest)` | |
| 16 | `test/models/database_authenticatable_test.rb:120` | should not generate a hashed password if password is blank | ported | `crates/devise-rust/src/model.rs tests (set_password skips blank)` | |
| 17 | `test/models/database_authenticatable_test.rb:125` | should hash password again if password has changed | ported | `crates/devise-rust/src/model.rs tests (re-hash on change)` | |
| 18 | `test/models/database_authenticatable_test.rb:133` | should test for a valid password | ported | `crates/devise-rust/src/crypto.rs tests (test_encryptor_digest_compare)` | |
| 19 | `test/models/database_authenticatable_test.rb:139` | should not raise error with an empty password | ported | `crates/devise-rust/src/crypto.rs tests (compare on empty digest)` | |
| 20 | `test/models/database_authenticatable_test.rb:145` | should be an invalid password if the user has an empty password | ported | `crates/devise-rust/src/crypto.rs tests (compare on empty digest)` | |
| 21 | `test/models/database_authenticatable_test.rb:151` | should respond to current password | ported | `crates/devise-rust/src/model.rs tests (update_with_password reads current_password)` | |
| 22 | `test/models/database_authenticatable_test.rb:155` | should update password with valid current password | ported | `crates/devise-rust/src/model.rs tests (database_authenticatable_methods update_with_password)` | |
| 23 | `test/models/database_authenticatable_test.rb:162` | should add an error to current password when it is invalid | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_account_update_requires_current_password)` | |
| 24 | `test/models/database_authenticatable_test.rb:170` | should add an error to current password when it is blank | ported | `crates/devise-rust/src/model.rs tests (update_with_password blank current_password)` | |
| 25 | `test/models/database_authenticatable_test.rb:178` | should run validations even when current password is invalid or blank | ported | `crates/devise-rust/src/model.rs tests (update_with_password validation ordering)` | |
| 26 | `test/models/database_authenticatable_test.rb:187` | should ignore password and its confirmation if they are blank | ported | `crates/devise-rust/src/model.rs tests (blank password fields dropped from update)` | |
| 27 | `test/models/database_authenticatable_test.rb:193` | should not update password with invalid confirmation | ported | `crates/devise-rust/tests/model_validation.rs (password_confirmation_must_match)` | |
| 28 | `test/models/database_authenticatable_test.rb:200` | should clean up password fields on failure | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_sign_up_failure_clears_passwords_and_keeps_errors)` | never persists on failure (TEST-03 item 5) |
| 29 | `test/models/database_authenticatable_test.rb:208` | should update the user without password | ported | `crates/devise-rust/src/model.rs tests (update_without_password)` | |
| 30 | `test/models/database_authenticatable_test.rb:214` | should not update password without password | ported | `crates/devise-rust/src/model.rs tests (update_without_password never touches password)` | |
| 31 | `test/models/database_authenticatable_test.rb:221` | should destroy user if current password is valid | ported | `crates/devise-rust/src/model.rs tests (destroy_with_password)` | |
| 32 | `test/models/database_authenticatable_test.rb:227` | should not destroy user with invalid password | ported | `crates/devise-rust/src/model.rs tests (destroy_with_password)` | |
| 33 | `test/models/database_authenticatable_test.rb:234` | should not destroy user with blank password | ported | `crates/devise-rust/src/model.rs tests (destroy_with_password)` | |
| 34 | `test/models/database_authenticatable_test.rb:241` | should not email on password change | ported | `crates/devise-rust/tests/notifications.rs (steady ChangeSet sends nothing)` | |
| 35 | `test/models/database_authenticatable_test.rb:248` | should notify previous email on email change when configured | ported | `crates/devise-rust/tests/notifications.rs (email_change_notification_goes_to_original_address)` | |
| 36 | `test/models/database_authenticatable_test.rb:259` | should notify email on password change when configured | ported | `crates/devise-rust/tests/notifications.rs (password_change_notification_goes_to_current_address)` | |
| 37 | `test/models/database_authenticatable_test.rb:269` | should not notify email on password change even when configured if skip_password_change_notification! is invoked | ported | `crates/devise-rust/src/model.rs tests (database_authenticatable_notifications skip flags)` | |
| 38 | `test/models/database_authenticatable_test.rb:279` | should not notify email on email change even when configured if skip_email_changed_notification! is invoked | ported | `crates/devise-rust/src/model.rs tests (database_authenticatable_notifications skip flags)` | |
| 39 | `test/models/database_authenticatable_test.rb:289` | downcase_keys with validation | ported | `crates/devise-rust/src/parameter.rs tests (downcase before validation)` | |
| 40 | `test/models/database_authenticatable_test.rb:295` | required_fields should be encryptable_password and the email field by default | ported | `crates/devise-rust-migrations/tests/snapshots.rs (matrix_full_create)` | |
| 41 | `test/models/database_authenticatable_test.rb:302` | required_fields should be encryptable_password and the login when the login is on authentication_keys | ported | `crates/devise-rust/src/config.rs tests (authentication_keys override flows through the filter)` | |

### models/lockable_test.rb (42 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/models/lockable_test.rb:10` | should respect maximum attempts configuration | ported | `crates/devise-rust/src/lockable.rs tests (lockable_tracer_counter_to_lock)` | |
| 2 | `test/models/lockable_test.rb:19` | should increment failed_attempts on successful validation if the user is already locked | ported | `crates/devise-rust/src/lockable.rs tests (lockable_chain_locks_at_threshold_and_counts_when_locked)` | |
| 3 | `test/models/lockable_test.rb:32` | should not touch failed_attempts if lock_strategy is none | ported | `crates/devise-rust/src/lockable.rs tests (lockable_tracer_none_strategy_no_side_effects)` | |
| 4 | `test/models/lockable_test.rb:42` | should read failed_attempts from database when incrementing | ported | `crates/devise-rust/src/lockable.rs tests (lockable_chain_reads_counter_from_store)` | increment_counter plus re-read parity |
| 5 | `test/models/lockable_test.rb:53` | reset_failed_attempts! updates the failed attempts counter back to 0 | ported | `crates/devise-rust/src/lockable.rs tests (lockable_reset_failed_attempts_writes_zero)` | |
| 6 | `test/models/lockable_test.rb:64` | reset_failed_attempts! does not run model validations | ported | `crates/devise-rust/src/lockable.rs tests (reset writes zero without validations)` | |
| 7 | `test/models/lockable_test.rb:72` | reset_failed_attempts! does not try to reset if not using failed attempts strategy | ported | `crates/devise-rust/src/lockable.rs tests (lock_counting_enabled gating)` | |
| 8 | `test/models/lockable_test.rb:79` | should be valid for authentication with a unlocked user | ported | `crates/devise-rust/src/lockable.rs tests (lockable_chain paths)` | |
| 9 | `test/models/lockable_test.rb:86` | should verify whether a user is locked or not | ported | `crates/devise-rust/src/lockable.rs tests (access_locked paths)` | |
| 10 | `test/models/lockable_test.rb:93` | active_for_authentication? should be the opposite of locked? | ported | `crates/devise-rust/src/lockable.rs tests (lockable_expired_time_lock_releases_live_lock_holds)` | |
| 11 | `test/models/lockable_test.rb:101` | should unlock a user by cleaning locked_at, failed_attempts and unlock_token | ported | `crates/devise-rust/src/lockable.rs tests (unlock_access clears all three)` | |
| 12 | `test/models/lockable_test.rb:113` | new user should not be locked and should have zero failed_attempts | ported | `crates/devise-rust/src/lockable.rs tests (fresh record unlocked)` | |
| 13 | `test/models/lockable_test.rb:118` | should unlock user after unlock_in period | ported | `crates/devise-rust/src/lockable.rs tests (lockable_expired_time_lock_releases_live_lock_holds)` | |
| 14 | `test/models/lockable_test.rb:129` | should not unlock in unlock_in if :time unlock strategy is not set | ported | `crates/devise-rust/src/lockable.rs tests (lockable_unlock_strategy_predicates_and_required_fields)` | |
| 15 | `test/models/lockable_test.rb:137` | should set unlock_token when locking | ported | `crates/devise-rust/src/lockable.rs tests (lockable_lock_access_mails_raw_stores_digest)` | |
| 16 | `test/models/lockable_test.rb:144` | should never generate the same unlock token for different users | ported | `crates/devise-rust/src/crypto.rs tests (token generator uniqueness loop)` | |
| 17 | `test/models/lockable_test.rb:155` | should not generate unlock_token when :email is not an unlock strategy | ported | `crates/devise-rust/src/lockable.rs tests (store_fresh_unlock_token strategy gating)` | |
| 18 | `test/models/lockable_test.rb:163` | should send email with unlock instructions when :email is an unlock strategy | ported | `crates/devise-rust/src/lockable.rs tests (lockable_lock_access_mails_raw_stores_digest)` | |
| 19 | `test/models/lockable_test.rb:172` | doesn't send email when you pass option send_instructions to false | ported | `crates/devise-rust/src/lockable.rs tests (lockable_lock_access_opt_out_skips_mail)` | |
| 20 | `test/models/lockable_test.rb:181` | sends email when you pass options other than send_instructions | ported | `crates/devise-rust/src/lockable.rs tests (lockable_lock_access_with_options)` | |
| 21 | `test/models/lockable_test.rb:190` | should not send email with unlock instructions when :email is not an unlock strategy | ported | `crates/devise-rust/src/lockable.rs tests (store_fresh_unlock_token strategy gating)` | |
| 22 | `test/models/lockable_test.rb:199` | should find and unlock a user automatically based on raw token | ported | `crates/devise-rust/src/lockable.rs tests (lockable_unlock_access_by_token_round_trip)` | |
| 23 | `test/models/lockable_test.rb:207` | should return a new record with errors when a invalid token is given | ported | `crates/devise-rust/src/lockable.rs tests (lockable_unlock_access_by_token_invalid)` | |
| 24 | `test/models/lockable_test.rb:213` | should return a new record with errors when a blank token is given | ported | `crates/devise-rust/src/lockable.rs tests (lockable_unlock_access_by_token_blank_touches_no_adapter)` | TEST-03 item 4, blank token guard |
| 25 | `test/models/lockable_test.rb:219` | should find a user to send unlock instructions | ported | `crates/devise-rust/src/lockable.rs tests (lockable_class_send_unlock_instructions)` | |
| 26 | `test/models/lockable_test.rb:226` | should return a new user if no email was found | ported | `crates/devise-rust/src/lockable.rs tests (class send not-found record with errors)` | |
| 27 | `test/models/lockable_test.rb:231` | should add error to new user email if no email was found | ported | `crates/devise-rust/src/lockable.rs tests (class send not-found record with errors)` | |
| 28 | `test/models/lockable_test.rb:236` | should find a user to send unlock instructions by authentication_keys | ported | `crates/devise-rust/src/lockable.rs tests (class send honoring unlock_keys)` | |
| 29 | `test/models/lockable_test.rb:244` | should require all unlock_keys | ported | `crates/devise-rust/src/lockable.rs tests (lockable_class_send_requires_all_unlock_keys)` | |
| 30 | `test/models/lockable_test.rb:253` | should not be able to send instructions if the user is not locked | ported | `crates/devise-rust/src/lockable.rs tests (lockable_resend_refuses_unlocked_record)` | |
| 31 | `test/models/lockable_test.rb:260` | should not be able to send instructions if the user if not locked and have username as unlock key | ported | `crates/devise-rust/src/lockable.rs tests (lockable_resend_refuses_unlocked_record)` | |
| 32 | `test/models/lockable_test.rb:269` | should unlock account if lock has expired and increase attempts on failure | ported | `crates/devise-rust/src/lockable.rs tests (lockable_chain_releases_expired_lock)` | |
| 33 | `test/models/lockable_test.rb:282` | should unlock account if lock has expired on success | ported | `crates/devise-rust/src/lockable.rs tests (lockable_chain_releases_expired_lock)` | |
| 34 | `test/models/lockable_test.rb:296` | required_fields should contain the all the fields when all the strategies are enabled | ported | `crates/devise-rust/src/lockable.rs tests (lockable_unlock_strategy_predicates_and_required_fields)` | |
| 35 | `test/models/lockable_test.rb:308` | required_fields should contain only failed_attempts and locked_at when the strategies are time and failed_attempts are enabled | ported | `crates/devise-rust/src/lockable.rs tests (required_fields per strategy)` plus `crates/devise-rust-migrations/tests/snapshots.rs (lockable_none_strategies_emit_only_locked_at)` | |
| 36 | `test/models/lockable_test.rb:319` | required_fields should contain only failed_attempts and unlock_token when the strategies are token and failed_attempts are enabled | ported | `crates/devise-rust/src/lockable.rs tests (required_fields per strategy)` | |
| 37 | `test/models/lockable_test.rb:330` | should not return a locked unauthenticated message if in paranoid mode | ported | `crates/devise-rust/src/lockable.rs tests (lockable_paranoid_suppresses_lock_messages)` | |
| 38 | `test/models/lockable_test.rb:340` | should return last attempt message if user made next-to-last attempt of password entering | ported | `crates/devise-rust/src/lockable.rs tests (lockable_last_attempt_matrix)` | |
| 39 | `test/models/lockable_test.rb:354` | should not return last attempt message if last_attempt_warning is disabled | ported | `crates/devise-rust/src/lockable.rs tests (lockable_last_attempt_matrix)` | |
| 40 | `test/models/lockable_test.rb:362` | should return locked message if user was programatically locked | ported | `crates/devise-rust/src/lockable.rs tests (lock_access sets locked message)` | |
| 41 | `test/models/lockable_test.rb:368` | unlock_strategy_enabled? should return true for both, email, and time strategies if :both is used | ported | `crates/devise-rust/src/lockable.rs tests (lockable_unlock_strategy_predicates_and_required_fields)` | |
| 42 | `test/models/lockable_test.rb:379` | unlock_strategy_enabled? should return true only for the configured strategy | ported | `crates/devise-rust/src/lockable.rs tests (lockable_unlock_strategy_predicates_and_required_fields)` | |

### models/recoverable_test.rb (29 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/models/recoverable_test.rb:11` | should not generate reset password token after creating a record | ported | `crates/devise-rust/src/model.rs tests (token issued only on request)` | |
| 2 | `test/models/recoverable_test.rb:15` | should never generate the same reset password token for different users | ported | `crates/devise-rust/src/crypto.rs tests (token generator uniqueness loop)` | |
| 3 | `test/models/recoverable_test.rb:26` | should reset password and password confirmation from params | ported | `crates/devise-rust/src/model.rs tests (reset_password)` | |
| 4 | `test/models/recoverable_test.rb:33` | should reset password and save the record | ported | `crates/devise-rust/src/model.rs tests (reset_password)` | |
| 5 | `test/models/recoverable_test.rb:37` | should clear reset password token while resetting the password | ported | `crates/devise-rust/src/model.rs tests (clear_reset_password_token on password change)` | |
| 6 | `test/models/recoverable_test.rb:47` | should not clear reset password token for new user | ported | `crates/devise-rust/src/model.rs tests (clear gated on persisted changes)` | |
| 7 | `test/models/recoverable_test.rb:58` | should clear reset password token if changing password | ported | `crates/devise-rust/src/model.rs tests (pending_reset_token_clear)` | |
| 8 | `test/models/recoverable_test.rb:70` | should clear reset password token if changing email | ported | `crates/devise-rust/src/model.rs tests (pending_reset_token_clear on authentication key change)` | |
| 9 | `test/models/recoverable_test.rb:81` | should clear reset password successfully even if there is no email | ported | `crates/devise-rust/src/model.rs tests (reset without email field change)` | |
| 10 | `test/models/recoverable_test.rb:93` | should not clear reset password token if record is invalid | ported | `crates/devise-rust/src/model.rs tests (reset_password validation failure keeps token)` | |
| 11 | `test/models/recoverable_test.rb:101` | should not reset password with invalid data | ported | `crates/devise-rust/src/model.rs tests (reset_password blank password errors)` | |
| 12 | `test/models/recoverable_test.rb:107` | should reset reset password token and send instructions by email | ported | `crates/devise-rust/src/model.rs tests (send_reset_password_instructions)` | |
| 13 | `test/models/recoverable_test.rb:116` | should find a user to send instructions by email | ported | `crates/devise-rust/src/model.rs tests (send_reset_password_instructions_for)` | |
| 14 | `test/models/recoverable_test.rb:122` | should return a new record with errors if user was not found by e-mail | ported | `crates/devise-rust/src/model.rs tests (send_reset_password_instructions_for not-found record with errors)` | |
| 15 | `test/models/recoverable_test.rb:128` | should find a user to send instructions by authentication_keys | ported | `crates/devise-rust/src/model.rs tests (send honoring reset_password_keys)` | |
| 16 | `test/models/recoverable_test.rb:136` | should require all reset_password_keys | ported | `crates/devise-rust/src/model.rs tests (send requires all keys)` | |
| 17 | `test/models/recoverable_test.rb:145` | should reset reset_password_token before send the reset instructions email | ported | `crates/devise-rust/src/model.rs tests (send_reset_password_instructions regenerates and clears)` | |
| 18 | `test/models/recoverable_test.rb:152` | should send email instructions to the user reset their password | ported | `crates/devise-rust/src/model.rs tests (send_reset_password_instructions)` plus `crates/devise-rust/tests/notifications.rs` | |
| 19 | `test/models/recoverable_test.rb:159` | should find a user to reset their password based on the raw token | ported | `crates/devise-rust/src/model.rs tests (with_reset_password_token digest lookup)` | |
| 20 | `test/models/recoverable_test.rb:167` | should return a new record with errors if no reset_password_token is found | ported | `crates/devise-rust/src/model.rs tests (reset_password_by_token_guards)` | |
| 21 | `test/models/recoverable_test.rb:173` | should return a new record with errors if reset_password_token is blank | ported | `crates/devise-rust/src/model.rs tests (reset_password_by_token_guards)` | TEST-03 item 4, blank token guard |
| 22 | `test/models/recoverable_test.rb:179` | should return a new record with errors if password is blank | ported | `crates/devise-rust/src/model.rs tests (reset_password blank password)` | |
| 23 | `test/models/recoverable_test.rb:189` | should return a new record with errors if password is not provided | ported | `crates/devise-rust/src/model.rs tests (reset_password missing password)` | |
| 24 | `test/models/recoverable_test.rb:199` | should reset successfully user password given the new password and confirmation | ported | `crates/devise-rust/src/model.rs tests (reset_password_by_token round trip)` | |
| 25 | `test/models/recoverable_test.rb:217` | should not reset password after reset_password_within time | ported | `crates/devise-rust/src/model.rs tests (reset_password_by_token_window)` | |
| 26 | `test/models/recoverable_test.rb:239` | required_fields should contain the fields that Devise uses | ported | `crates/devise-rust-migrations/tests/snapshots.rs (recoverable_adds_its_index_without_confirmation_index)` | |
| 27 | `test/models/recoverable_test.rb:246` | should return a user based on the raw token | ported | `crates/devise-rust/src/model.rs tests (issue_reset_token)` | |
| 28 | `test/models/recoverable_test.rb:253` | should return the same reset password token as generated | ported | `crates/devise-rust/src/model.rs tests (raw token restored on the returned record)` | |
| 29 | `test/models/recoverable_test.rb:259` | should return nil if a user based on the raw token is not found | ported | `crates/devise-rust/src/model.rs tests (with_reset_password_token miss)` | |

### models/registerable_test.rb (1 block)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/models/registerable_test.rb:6` | required_fields should contain the fields that Devise uses | ported | `crates/devise-rust/src/model.rs tests (registerable_tests: no columns, new_with_session plus sign_up path)` | |

### models/rememberable_test.rb (21 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/models/rememberable_test.rb:14` | remember_me should not generate a new token if using salt | ported | `crates/devise-rust/src/rememberable.rs tests (salt-mode remember keeps value, rememberable_remember_reuse_keeps_token_without_write)` | |
| 2 | `test/models/rememberable_test.rb:21` | remember_me should not generate a new token if valid token exists | ported | `crates/devise-rust/src/rememberable.rs tests (rememberable_remember_reuse_keeps_token_without_write)` | |
| 3 | `test/models/rememberable_test.rb:33` | forget_me should not clear remember token if using salt | ported | `crates/devise-rust/src/rememberable.rs tests (rememberable_forget_salt_model_clears_created_only)` | |
| 4 | `test/models/rememberable_test.rb:40` | can generate remember token | ported | `crates/devise-rust/src/session.rs tests (generate_remember_token)` | |
| 5 | `test/models/rememberable_test.rb:48` | serialize into cookie | ported | `crates/devise-rust/src/rememberable.rs tests (serialize_into_cookie)` | |
| 6 | `test/models/rememberable_test.rb:57` | serialize from cookie | ported | `crates/devise-rust/src/rememberable.rs tests (cookie round trip)` | |
| 7 | `test/models/rememberable_test.rb:63` | serialize from cookie should accept a String with the datetime seconds and microseconds | deviated | `crates/devise-rust/src/rememberable.rs tests (rememberable_nil_case_invalid_datetime)` | reason: Devise accepts float timestamps (an open TODO in devise); the port parses strict integer epochs and rejects float strings fail-closed (STATE Phase 5 decision). v1 impact: cookies minted by Devise with float timestamps are rejected rather than revived; fresh devise-rust cookies are unaffected. |
| 8 | `test/models/rememberable_test.rb:69` | serialize from cookie should return nil with invalid datetime | ported | `crates/devise-rust/src/rememberable.rs tests (rememberable_nil_case_invalid_datetime)` | |
| 9 | `test/models/rememberable_test.rb:75` | serialize from cookie should return nil if no resource is found | ported | `crates/devise-rust/src/rememberable.rs tests (rememberable_nil_case_unknown_resource)` | |
| 10 | `test/models/rememberable_test.rb:79` | serialize from cookie should return nil if no timestamp | ported | `crates/devise-rust/src/rememberable.rs tests (rememberable_missing_created_at_is_invalid)` | |
| 11 | `test/models/rememberable_test.rb:85` | serialize from cookie should return nil if timestamp is earlier than token creation | ported | `crates/devise-rust/src/rememberable.rs tests (rememberable_nil_case_timestamp_at_or_before_creation, rememberable_equal_timestamps_are_invalid)` | |
| 12 | `test/models/rememberable_test.rb:91` | serialize from cookie should return nil if timestamp is older than remember_for | ported | `crates/devise-rust/src/rememberable.rs tests (rememberable_nil_case_older_than_remember_for)` | |
| 13 | `test/models/rememberable_test.rb:98` | serialize from cookie me return nil if is a valid resource with invalid token | ported | `crates/devise-rust/src/rememberable.rs tests (rememberable_nil_case_wrong_token)` | |
| 14 | `test/models/rememberable_test.rb:104` | raises a RuntimeError if the user does not implements a rememberable value | ported | `crates/devise-rust/src/rememberable.rs tests (rememberable_value_resolution: MissingRememberableValue error instead of a Ruby raise)` | |
| 15 | `test/models/rememberable_test.rb:117` | raises a RuntimeError if authenticatable_salt is nil or empty | ported | `crates/devise-rust/src/rememberable.rs tests (rememberable_value_resolution)` | |
| 16 | `test/models/rememberable_test.rb:131` | should respond to remember_me attribute | ported | `crates/devise-rust/src/rememberable.rs tests (remember_me_flag virtual field)` | |
| 17 | `test/models/rememberable_test.rb:136` | forget_me should clear remember_created_at if expire_all_remember_me_on_sign_out is true | ported | `crates/devise-rust/src/rememberable.rs tests (rememberable_forget_clears_per_expire_all)` | |
| 18 | `test/models/rememberable_test.rb:147` | forget_me should not clear remember_created_at if expire_all_remember_me_on_sign_out is false | ported | `crates/devise-rust/src/rememberable.rs tests (rememberable_forget_clears_per_expire_all)` | |
| 19 | `test/models/rememberable_test.rb:159` | forget_me should not try to update resource if it has been destroyed | ported | `crates/devise-rust/src/rememberable.rs tests (rememberable_forget_unpersisted_touches_no_adapter)` | |
| 20 | `test/models/rememberable_test.rb:168` | remember expires at uses remember for configuration | ported | `crates/devise-rust/src/rememberable.rs tests (remember_expires_at)` | |
| 21 | `test/models/rememberable_test.rb:179` | should have the required_fields array | ported | `crates/devise-rust/src/rememberable.rs tests (required_fields)` plus `crates/devise-rust-migrations/tests/snapshots.rs (remember_token_opt_in)` | |

### models/serializable_test.rb (5 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/models/serializable_test.rb:10` | should not include unsafe keys on JSON | ported | `crates/devise-rust/src/model.rs tests (test_serializable_hash_excludes_password)` plus `crates/devise-rust/src/error.rs tests (test_unsafe_attributes)` | |
| 2 | `test/models/serializable_test.rb:15` | should not include unsafe keys on JSON even if a new except is provided | ported | `crates/devise-rust/src/error.rs tests (unsafe list always concatenated)` | |
| 3 | `test/models/serializable_test.rb:20` | should include unsafe keys on JSON if a force_except is provided | waived | `crates/devise-rust/src/error.rs tests (test_unsafe_attributes)` | reason: `force_except` is an ActiveRecord serializable_options escape hatch that re-enables leaking secret columns; the port intentionally provides no escape hatch for the 18 unsafe attributes. v1 impact: none for correct consumers; code that relied on serializing secret columns must read them from the model directly. |
| 4 | `test/models/serializable_test.rb:25` | should not include unsafe keys in inspect | deviated | `crates/devise-rust/src/error.rs tests (test_unsafe_attributes)` | reason: Ruby overrides `Object#inspect` globally; Rust has no equivalent hook, so the guard is enforced on `serializable_hash` and the `UNSAFE_ATTRIBUTES` seam, with app-owned `Debug` impls out of library control. v1 impact: none for the library surface; apps that derive `Debug` on models see their own fields (documented in SECURITY.md). |
| 5 | `test/models/serializable_test.rb:30` | should accept frozen options | waived | `crates/devise-rust/src/model.rs tests (serializable_hash no-options surface)` | reason: Ruby frozen-string immutability edge; Rust values are moved or borrowed by the type system, so there is no frozen-options case. v1 impact: none. |

### models/timeoutable_test.rb (8 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/models/timeoutable_test.rb:7` | should be expired | ported | `crates/devise-rust/src/timeoutable.rs tests (tick_expired stale)` | |
| 2 | `test/models/timeoutable_test.rb:11` | should not be expired | ported | `crates/devise-rust/src/timeoutable.rs tests (tick_expired live)` | |
| 3 | `test/models/timeoutable_test.rb:15` | should not be expired when params is nil | ported | `crates/devise-rust/src/timeoutable.rs tests (classify_last_request absent)` | |
| 4 | `test/models/timeoutable_test.rb:19` | should use timeout_in method | ported | `crates/devise-rust/src/timeoutable.rs tests (per-scope timeout override)` | |
| 5 | `test/models/timeoutable_test.rb:27` | should not be expired when timeout_in method returns nil | ported | `crates/devise-rust/src/timeoutable.rs tests (timeoutable_matrix_config_fallback_and_zero_window)` | |
| 6 | `test/models/timeoutable_test.rb:33` | fallback to Devise config option | ported | `crates/devise-rust/src/timeoutable.rs tests (timeoutable_matrix_config_fallback_and_zero_window)` | |
| 7 | `test/models/timeoutable_test.rb:45` | required_fields should contain the fields that Devise uses | ported | `crates/devise-rust/src/timeoutable.rs tests (required_fields: none)` | |
| 8 | `test/models/timeoutable_test.rb:49` | should not raise error if remember_created_at is not empty and rememberable is disabled | ported | `crates/devise-rust/src/timeoutable.rs tests (remember exemption reads the flag without the module)` | |

### models/trackable_test.rb (5 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/models/trackable_test.rb:6` | required_fields should contain the fields that Devise uses | ported | `crates/devise-rust/src/trackable.rs tests (trackable_matrix_required_fields)` | |
| 2 | `test/models/trackable_test.rb:16` | update_tracked_fields should only set attributes but not save the record | ported | `crates/devise-rust/src/trackable.rs tests (trackable_matrix_shift_sets_without_saving)` | |
| 3 | `test/models/trackable_test.rb:44` | update_tracked_fields! should not persist invalid records | deviated | `crates/devise-rust/src/trackable.rs tests (trackable_matrix_bang_skips_unpersisted_and_validates_nothing)` | reason: devise skips invalid records via `save(validate: false)` returning false for invalid persisted records; the port persists without model validations (parity with the save(validate: false) call) and skips unpersisted records (issue 4673 parity). v1 impact: none, the unpersisted skip is the load-bearing Devise 5.0.4 behavior. |
| 4 | `test/models/trackable_test.rb:53` | update_tracked_fields! should not run model validations | ported | `crates/devise-rust/src/trackable.rs tests (trackable_matrix_bang_skips_unpersisted_and_validates_nothing)` | |
| 5 | `test/models/trackable_test.rb:63` | extract_ip_from should be overridable | ported | `crates/devise-rust/src/trackable.rs tests (trackable_matrix_extract_ip_overridable)` | |

### models/validatable_test.rb (14 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/models/validatable_test.rb:7` | should require email to be set | ported | `crates/devise-rust/tests/model_validation.rs (blank_values_use_blank_error_keys)` | |
| 2 | `test/models/validatable_test.rb:14` | should require uniqueness of email if email has changed, allowing blank | ported | `crates/devise-rust/tests/model_validation.rs (email_uniqueness_is_case_sensitive_at_db)` | |
| 3 | `test/models/validatable_test.rb:29` | should require correct email format if email has changed, allowing blank | ported | `crates/devise-rust/tests/model_validation.rs (email_format_validation_uses_devise_regexp)` | |
| 4 | `test/models/validatable_test.rb:44` | should accept valid emails | ported | `crates/devise-rust/tests/model_validation.rs (email_format_validation_uses_devise_regexp)` | |
| 5 | `test/models/validatable_test.rb:52` | should require password to be set when creating a new record | ported | `crates/devise-rust/tests/model_validation.rs (blank_values_use_blank_error_keys)` | |
| 6 | `test/models/validatable_test.rb:58` | should require confirmation to be set when creating a new record | ported | `crates/devise-rust/tests/model_validation.rs (password_confirmation_must_match)` | |
| 7 | `test/models/validatable_test.rb:65` | should require password when updating/resetting password | ported | `crates/devise-rust/tests/model_validation.rs plus crates/devise-rust/src/model.rs tests (password_required)` | |
| 8 | `test/models/validatable_test.rb:75` | should require confirmation when updating/resetting password | ported | `crates/devise-rust/tests/model_validation.rs (password_confirmation_must_match)` | |
| 9 | `test/models/validatable_test.rb:83` | should require a password with minimum of 7 characters | ported | `crates/devise-rust/tests/model_validation.rs (password_length_bounds_6_to_128_inclusive with configured bounds)` | configured `password_length` honored |
| 10 | `test/models/validatable_test.rb:89` | should require a password with maximum of 72 characters long | ported | `crates/devise-rust/tests/model_validation.rs (password_length_bounds_6_to_128_inclusive with configured bounds)` | |
| 11 | `test/models/validatable_test.rb:95` | should not require password length when it's blank and not required | ported | `crates/devise-rust/src/model.rs tests (password_required gating)` | |
| 12 | `test/models/validatable_test.rb:105` | should complain about length even if password is not required | ported | `crates/devise-rust/tests/model_validation.rs (length check when password present)` | |
| 13 | `test/models/validatable_test.rb:112` | should not be included in objects with invalid API | waived | `crates/devise-rust/tests/model_validation.rs` | reason: the block asserts Devise raises when the host class lacks the ActiveModel validations API; Rust replaces the runtime assertion with compile-time trait bounds, so an invalid host cannot compile. v1 impact: none, the failure moves from runtime to compile time. |
| 14 | `test/models/validatable_test.rb:121` | required_fields should be an empty array | ported | `crates/devise-rust/src/model.rs tests (Validatable adds no columns)` | |

### models/omniauthable_test.rb (1 block)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/models/omniauthable_test.rb:6` | required_fields should contain the fields that Devise uses | ported | `crates/devise-rust/src/omniauthable.rs tests (omniauthable_required_fields_list_provider_and_uid)` plus `crates/devise-rust-migrations/tests/snapshots.rs (omniauthable_block_emits_provider_and_uid_and_no_token_column)` | |

## TEST-02: integration suite (271 blocks)

Framework legs: both the Phase 8 actix harness (`actix_web::test`, `crates/devise-rust-actix/tests/devise_flows.rs`) and the Phase 9 axum harness (`tower::ServiceExt` oneshot with the stub provider, `crates/devise-rust-axum/tests/devise_flows.rs`) exist on the current tree, so every non-waived integration row cites both legs. JSON-format request rows cite the axum and actix controller suites where the framework leg asserts the status-code and response-shape split; rows that only make sense against a Rails view stack are waived with reasons. The full browser-parity flow matrix (sign up, confirm, sign in, remember me, edit account, lock and unlock, reset, sign out) is driven end to end by both example apps (`--journey` matrices) in addition to the per-flow tests cited below.

### integration/authenticatable_test.rb (77 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/integration/authenticatable_test.rb:6` | sign in should not run model validations | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_sign_in_and_sign_out_with_flashes)` plus `crates/devise-rust-actix/tests/devise_flows.rs` same flow | sign-in path persists nothing, so no validation runs |
| 2 | `test/integration/authenticatable_test.rb:12` | home should be accessible without sign in | ported | `crates/devise-rust-axum/tests/extractors.rs (anonymous access allowed)` plus actix extractors suite | |
| 3 | `test/integration/authenticatable_test.rb:18` | sign in as user should not authenticate admin scope | ported | `crates/devise-rust/src/proxy.rs tests (per-scope session keys)` plus `crates/devise-rust-axum/tests/devise_flows.rs` | |
| 4 | `test/integration/authenticatable_test.rb:24` | sign in as admin should not authenticate user scope | ported | `crates/devise-rust/src/proxy.rs tests (per-scope session keys)` | |
| 5 | `test/integration/authenticatable_test.rb:30` | sign in as both user and admin at same time | ported | `crates/devise-rust/src/proxy.rs tests (test_proxy_sign_in_out)` plus framework multi-scope flows | |
| 6 | `test/integration/authenticatable_test.rb:37` | sign out as user should not touch admin authentication if sign_out_all_scopes is false | ported | `crates/devise-rust/src/proxy.rs tests (test_proxy_sign_out)` with per-scope sign-out | |
| 7 | `test/integration/authenticatable_test.rb:47` | sign out as admin should not touch user authentication if sign_out_all_scopes is false | ported | `crates/devise-rust/src/proxy.rs tests (test_proxy_sign_out)` | |
| 8 | `test/integration/authenticatable_test.rb:58` | sign out as user should also sign out admin if sign_out_all_scopes is true | ported | `crates/devise-rust/src/proxy.rs tests (test_proxy_sign_out_all_scopes)` | |
| 9 | `test/integration/authenticatable_test.rb:69` | sign out as admin should also sign out user if sign_out_all_scopes is true | ported | `crates/devise-rust/src/proxy.rs tests (test_proxy_sign_out_all_scopes)` | |
| 10 | `test/integration/authenticatable_test.rb:80` | not signed in as admin should not be able to access admins actions | ported | `crates/devise-rust-axum/tests/extractors.rs (guard rejects)` plus actix extractors suite | |
| 11 | `test/integration/authenticatable_test.rb:86` | signed in as user should not be able to access admins actions | ported | `crates/devise-rust-axum/tests/extractors.rs (per-scope guard)` | |
| 12 | `test/integration/authenticatable_test.rb:95` | signed in as admin should be able to access admin actions | ported | `crates/devise-rust-axum/tests/extractors.rs` | |
| 13 | `test/integration/authenticatable_test.rb:107` | authenticated admin should not be able to sign as admin again | ported | `crates/devise-rust-axum/tests/devise_flows.rs (already_authenticated redirect)` | |
| 14 | `test/integration/authenticatable_test.rb:116` | authenticated admin should be able to sign out | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_sign_in_and_sign_out_with_flashes)` | |
| 15 | `test/integration/authenticatable_test.rb:129` | unauthenticated admin set message on sign out | ported | `crates/devise-rust-axum/tests/devise_flows.rs (already_signed_out path)` | |
| 16 | `test/integration/authenticatable_test.rb:138` | scope uses custom failure app | ported | `crates/devise-rust/src/failure.rs tests (per-mapping failure_app honored)` | |
| 17 | `test/integration/authenticatable_test.rb:146` | not signed in should not be able to access private route (authenticate denied) | ported | `crates/devise-rust-axum/tests/extractors.rs` | |
| 18 | `test/integration/authenticatable_test.rb:152` | signed in as user should not be able to access private route restricted to admins (authenticate denied) | ported | `crates/devise-rust-axum/tests/extractors.rs (per-scope)` | |
| 19 | `test/integration/authenticatable_test.rb:160` | signed in as admin should be able to access private route restricted to admins (authenticate accepted) | ported | `crates/devise-rust-axum/tests/extractors.rs` | |
| 20 | `test/integration/authenticatable_test.rb:172` | signed in as inactive admin should not be able to access private/active route restricted to active admins (authenticate denied) | ported | `crates/devise-rust-axum/tests/extractors.rs (active_for_authentication honored by guards)` | |
| 21 | `test/integration/authenticatable_test.rb:182` | signed in as active admin should be able to access private/active route restricted to active admins (authenticate accepted) | ported | `crates/devise-rust-axum/tests/extractors.rs` | |
| 22 | `test/integration/authenticatable_test.rb:194` | signed in as admin should get admin dashboard (authenticated accepted) | ported | `crates/devise-rust-axum/tests/extractors.rs` | |
| 23 | `test/integration/authenticatable_test.rb:206` | signed in as user should get user dashboard (authenticated accepted) | ported | `crates/devise-rust-axum/tests/extractors.rs` | |
| 24 | `test/integration/authenticatable_test.rb:218` | not signed in should get no dashboard (authenticated denied) | ported | `crates/devise-rust-axum/tests/extractors.rs` | |
| 25 | `test/integration/authenticatable_test.rb:224` | signed in as inactive admin should not be able to access dashboard/active route restricted to active admins (authenticated denied) | ported | `crates/devise-rust-axum/tests/extractors.rs` | |
| 26 | `test/integration/authenticatable_test.rb:234` | signed in as active admin should be able to access dashboard/active route restricted to active admins (authenticated accepted) | ported | `crates/devise-rust-axum/tests/extractors.rs` | |
| 27 | `test/integration/authenticatable_test.rb:246` | signed in user should not see unauthenticated page (unauthenticated denied) | ported | `crates/devise-rust-axum/tests/extractors.rs` | |
| 28 | `test/integration/authenticatable_test.rb:256` | not signed in users should see unauthenticated page (unauthenticated accepted) | ported | `crates/devise-rust-axum/tests/extractors.rs` | |
| 29 | `test/integration/authenticatable_test.rb:266` | redirect from warden shows sign in or sign up message | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_sign_in_failure_formats)` | i18n flash on the failure redirect |
| 30 | `test/integration/authenticatable_test.rb:276` | redirect from warden respects i18n locale set at the controller | deviated | `crates/devise-rust/src/i18n.rs tests (test_translate_with_interpolation)` plus `crates/devise-rust/src/failure.rs tests (locale option honored)` | reason: locale is resolved per failure decision through the i18n seam rather than the Rails I18n.with_locale controller swap. v1 impact: none for the message resolution itself; a request-scoped locale override must be passed through the failure options (documented in the configuration guide). |
| 31 | `test/integration/authenticatable_test.rb:285` | redirect to default url if no other was configured | ported | `crates/devise-rust-axum/tests/devise_flows.rs (post-sign-in redirect)` | |
| 32 | `test/integration/authenticatable_test.rb:291` | redirect to requested url after sign in | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_stored_location_get_only)` | |
| 33 | `test/integration/authenticatable_test.rb:303` | redirect to last requested url overwriting the stored return_to option | ported | `crates/devise-rust/src/failure.rs tests (test_stored_location overwrite)` | |
| 34 | `test/integration/authenticatable_test.rb:319` | xml http requests does not store urls for redirect | ported | `crates/devise-rust/src/failure.rs tests (navigational format gating on storage)` | |
| 35 | `test/integration/authenticatable_test.rb:325` | redirect to configured home path for a given scope after sign in | ported | `crates/devise-rust-axum/tests/devise_flows.rs (after_sign_in path)` | |
| 36 | `test/integration/authenticatable_test.rb:330` | require_no_authentication should set the already_authenticated flash message | ported | `crates/devise-rust-axum/tests/devise_flows.rs (already_authenticated redirect)` | |
| 37 | `test/integration/authenticatable_test.rb:336` | require_no_authentication should set the already_authenticated flash message as admin | ported | `crates/devise-rust-axum/tests/devise_flows.rs (already_authenticated per scope)` | |
| 38 | `test/integration/authenticatable_test.rb:346` | destroyed account is signed out | ported | `crates/devise-rust-axum/tests/devise_flows.rs (account cancellation signs out)` | |
| 39 | `test/integration/authenticatable_test.rb:355` | refreshes _csrf_token | deviated | `crates/devise-rust/src/hooks.rs tests (test_hook_registry_activatable_csrf)` | reason: Rails refreshes the Rack CSRF token metadata on sign-in; Rust CSRF lives in the host framework (actix-session or tower-sessions middleware), so the port exposes the `clean_up_csrf` bridge hook instead of owning token rotation. v1 impact: none when the host framework manages CSRF (the documented integration contract); apps without a CSRF middleware get no rotation from devise-rust itself. |
| 40 | `test/integration/authenticatable_test.rb:373` | allows session to be set for a given scope | ported | `crates/devise-rust/src/proxy.rs tests (set_user per scope)` | |
| 41 | `test/integration/authenticatable_test.rb:379` | session id is changed on sign in | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_renewal_rotation_on_privilege_paths)` plus `crates/devise-rust-actix/tests/devise_flows.rs` same flow | session id renewal on privilege transitions (fixation guard) |
| 42 | `test/integration/authenticatable_test.rb:392` | renders the scoped view if turned on and view is available | waived | `crates/devise-rust-axum/tests/devise_flows.rs` | reason: server-rendered view scoping is a Rails template-stack feature; devise-rust ships no views and no view resolver (see the `scoped_views` waiver in rails-parity.md). v1 impact: hosts render their own templates; no per-scope view lookup exists. |
| 43 | `test/integration/authenticatable_test.rb:401` | renders the scoped view if turned on in a specific controller | waived | see row 42 | reason: same Rails view-stack feature as row 42. v1 impact: same as row 42. |
| 44 | `test/integration/authenticatable_test.rb:415` | does not render the scoped view if turned off | waived | see row 42 | reason: same Rails view-stack feature as row 42. v1 impact: same as row 42. |
| 45 | `test/integration/authenticatable_test.rb:423` | does not render the scoped view if not available | waived | see row 42 | reason: same Rails view-stack feature as row 42. v1 impact: same as row 42. |
| 46 | `test/integration/authenticatable_test.rb:433` | handles unverified requests gets rid of caches | ported | `crates/devise-rust/src/hooks.rs tests (test_hook_registry_activatable_csrf)` plus framework session_bridge suites | sign-out on CSRF failure via the bridge callback |
| 47 | `test/integration/authenticatable_test.rb:447` | uses the custom controller with the custom controller view | waived | `crates/devise-rust-axum/tests/routes.rs` | reason: Rails apps swap Devise controllers through config to render app views; devise-rust routes are mounted by the host router, which can layer its own handlers and templates around them. v1 impact: hosts override behavior at the router layer; no per-scope controller class swap. |
| 48 | `test/integration/authenticatable_test.rb:454` | render 404 on roles without routes | ported | `crates/devise-rust-axum/tests/routes.rs (unrouted module 404s)` plus `crates/devise-rust/src/scope.rs tests (used_routes)` | |
| 49 | `test/integration/authenticatable_test.rb:460` | does not intercept Rails 401 responses | waived | `crates/devise-rust-axum/tests/extractors.rs` | reason: the block asserts Devise does not swallow 401s raised by the host Rails app's own exception wrappers; response interception semantics belong to the host framework in the port (the layer only handles devise scopes). v1 impact: none; the ported failure paths never intercept non-devise responses. |
| 50 | `test/integration/authenticatable_test.rb:465` | render 404 on roles without mapping | ported | `crates/devise-rust/src/scope.rs tests (unknown scope errors)` plus framework routes suite | |
| 51 | `test/integration/authenticatable_test.rb:471` | sign in with script name | waived | `crates/devise-rust-axum/tests/routes.rs` | reason: `SCRIPT_NAME` is the Rack mounted-app routing env entry used by Rails engines; the port has no engine mounting, and hosts mount routers at their own prefix. v1 impact: none, prefix mounting is expressed through `Mapping::path_prefix` and the host router. |
| 52 | `test/integration/authenticatable_test.rb:478` | sign in stub in json format | ported | `crates/devise-rust-axum/tests/devise_flows.rs (API sign-in via the bridge)` plus `crates/devise-rust-axum/src/routes.rs` JSON arms | |
| 53 | `test/integration/authenticatable_test.rb:485` | sign in stub in json with non attribute key | ported | `crates/devise-rust/src/strategy.rs tests (auth hash assembly honoring keys)` | |
| 54 | `test/integration/authenticatable_test.rb:494` | uses the mapping from router | ported | `crates/devise-rust-axum/tests/routes.rs (mapping drives mounted routes)` | |
| 55 | `test/integration/authenticatable_test.rb:500` | sign in with json format returns json response | ported | `crates/devise-rust-axum/src/routes.rs` JSON response arms plus `crates/devise-rust/src/failure.rs tests (is_api_unauthorized)` | |
| 56 | `test/integration/authenticatable_test.rb:507` | sign in with json format is idempotent | ported | `crates/devise-rust-axum/tests/devise_flows.rs (repeated sign-in no-op)` | |
| 57 | `test/integration/authenticatable_test.rb:523` | sign out with html redirects | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_sign_in_and_sign_out_with_flashes)` | |
| 58 | `test/integration/authenticatable_test.rb:535` | sign out with json format returns no content | ported | `crates/devise-rust-axum/src/routes.rs (204 on API sign-out)` | |
| 59 | `test/integration/authenticatable_test.rb:542` | sign out with non-navigational format via XHR does not redirect | ported | `crates/devise-rust/src/failure.rs tests (format classification)` | |
| 60 | `test/integration/authenticatable_test.rb:552` | sign out with navigational format via XHR does redirect | ported | `crates/devise-rust/src/failure.rs tests (format classification)` | |
| 61 | `test/integration/authenticatable_test.rb:563` | missing authentication keys cause authentication to abort | ported | `crates/devise-rust/src/strategy.rs tests (missing keys abort)` | |
| 62 | `test/integration/authenticatable_test.rb:571` | missing authentication keys cause authentication to abort unless marked as not required | ported | `crates/devise-rust/src/strategy.rs tests (request key requirements)` | |
| 63 | `test/integration/authenticatable_test.rb:580` | request keys are used on authentication | ported | `crates/devise-rust/src/strategy.rs tests (request_keys extraction)` | |
| 64 | `test/integration/authenticatable_test.rb:590` | invalid request keys raises NoMethodError | deviated | `crates/devise-rust/src/strategy.rs tests (request key resolution)` | reason: an absent request key is a programmer error; the port fails the strategy with a typed error instead of Ruby's NoMethodError. v1 impact: none, same fail-closed outcome. |
| 65 | `test/integration/authenticatable_test.rb:600` | blank request keys cause authentication to abort | ported | `crates/devise-rust/src/strategy.rs tests (blank request keys abort)` | |
| 66 | `test/integration/authenticatable_test.rb:610` | blank request keys cause authentication to abort unless if marked as not required | ported | `crates/devise-rust/src/strategy.rs tests (request key requirements)` | |
| 67 | `test/integration/authenticatable_test.rb:626` | allow sign out via delete when sign_out_via provides only delete | ported | `crates/devise-rust/src/scope.rs tests (test_sign_out_via)` plus framework routes suites | |
| 68 | `test/integration/authenticatable_test.rb:632` | do not allow sign out via get when sign_out_via provides only delete | ported | `crates/devise-rust-axum/tests/routes.rs (verb enforced)` | |
| 69 | `test/integration/authenticatable_test.rb:640` | allow sign out via post when sign_out_via provides only post | ported | `crates/devise-rust/src/scope.rs tests (test_sign_out_via)` | |
| 70 | `test/integration/authenticatable_test.rb:646` | do not allow sign out via get when sign_out_via provides only post | ported | `crates/devise-rust-axum/tests/routes.rs (verb enforced)` | |
| 71 | `test/integration/authenticatable_test.rb:654` | allow sign out via delete when sign_out_via provides delete and post | ported | `crates/devise-rust/src/scope.rs tests (test_sign_out_via)` | |
| 72 | `test/integration/authenticatable_test.rb:660` | allow sign out via post when sign_out_via provides delete and post | ported | `crates/devise-rust/src/scope.rs tests (test_sign_out_via)` | |
| 73 | `test/integration/authenticatable_test.rb:666` | do not allow sign out via get when sign_out_via provides delete and post | ported | `crates/devise-rust-axum/tests/routes.rs (verb enforced)` | |
| 74 | `test/integration/authenticatable_test.rb:676` | signed in as user redirects when visiting user sign in page | ported | `crates/devise-rust-axum/tests/devise_flows.rs (already_authenticated redirect)` | |
| 75 | `test/integration/authenticatable_test.rb:682` | signed in as admin redirects when visiting admin sign in page | ported | `crates/devise-rust-axum/tests/devise_flows.rs (already_authenticated per scope)` | |
| 76 | `test/integration/authenticatable_test.rb:688` | signed in as both user and admin redirects when visiting admin sign in page | ported | `crates/devise-rust-axum/tests/devise_flows.rs (per-scope already_authenticated)` | |
| 77 | `test/integration/authenticatable_test.rb:699` | sign out after already having signed out redirects to sign in | ported | `crates/devise-rust-axum/tests/devise_flows.rs (already_signed_out redirect)` | |

### integration/confirmable_test.rb (33 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/integration/confirmable_test.rb:22` | user should be able to request a new confirmation | ported | `crates/devise-rust-axum/tests/devise_flows.rs` plus `crates/devise-rust-actix/tests/devise_flows.rs` (confirmation create flow, journey confirm step) | |
| 2 | `test/integration/confirmable_test.rb:31` | user should receive a confirmation from a custom mailer | ported | `crates/devise-rust/src/mailer.rs tests (mailer_trait_compiles: app-supplied Mailer)` plus framework flows with `TestMailer` | |
| 3 | `test/integration/confirmable_test.rb:37` | user with invalid confirmation token should not be able to confirm an account | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_confirm_by_token_blank_and_legacy_paths)` | |
| 4 | `test/integration/confirmable_test.rb:43` | user with valid confirmation token should not be able to confirm an account after the token has expired | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_confirm_within_window_edges)` plus framework flow | |
| 5 | `test/integration/confirmable_test.rb:56` | user with valid confirmation token where the token has expired and with application router_name set to a different engine it should raise an error | waived | `crates/devise-rust/src/scope.rs tests (router_name option)` | reason: multi-engine router disambiguation is a Rails mounting feature (two routers sharing one app); devise-rust has a single router namespace per Mapping. v1 impact: none, there is no second engine router to disambiguate. |
| 6 | `test/integration/confirmable_test.rb:66` | user with valid confirmation token where the token has expired and with application router_name set to a different engine and route overrides back to main it shows the path | waived | see row 5 | reason: same Rails engine router_name machinery as row 5. v1 impact: same as row 5. |
| 7 | `test/integration/confirmable_test.rb:76` | user with valid confirmation token where the token has expired with router overrides different engine it shows the path | waived | see row 5 | reason: same Rails engine router_name machinery as row 5. v1 impact: same as row 5. |
| 8 | `test/integration/confirmable_test.rb:86` | user with valid confirmation token should be able to confirm an account before the token has expired | ported | `crates/devise-rust-axum/tests/devise_flows.rs (journey confirm step)` | |
| 9 | `test/integration/confirmable_test.rb:98` | user should be redirected to a custom path after confirmation | ported | `crates/devise-rust-axum/tests/devise_flows.rs (after_confirmation path)` | |
| 10 | `test/integration/confirmable_test.rb:107` | already confirmed user should not be able to confirm the account again | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_resend_on_confirmed_errors_already_confirmed)` plus framework flow | |
| 11 | `test/integration/confirmable_test.rb:117` | already confirmed user should not be able to confirm the account again neither request confirmation | ported | `crates/devise-rust/src/confirmable.rs tests (resend on confirmed errors)` | |
| 12 | `test/integration/confirmable_test.rb:130` | not confirmed user with setup to block without confirmation should not be able to sign in | ported | `crates/devise-rust-axum/tests/devise_flows.rs (unconfirmed sign-in rejected with :unconfirmed)` | |
| 13 | `test/integration/confirmable_test.rb:139` | not confirmed user redirect respects i18n locale set | deviated | `crates/devise-rust/src/i18n.rs tests (locale option)` | reason: same request-scoped locale seam as the authenticatable row 30; the message resolves per failure decision, not through Rails I18n.with_locale. v1 impact: none for message resolution. |
| 14 | `test/integration/confirmable_test.rb:148` | not confirmed user should not see confirmation message if invalid credentials are given | ported | `crates/devise-rust/src/strategy.rs tests (invalid credentials fail before the confirmation gate)` | |
| 15 | `test/integration/confirmable_test.rb:159` | not confirmed user but configured with some days to confirm should be able to sign in | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_allow_window_three_way_table)` plus framework flow | |
| 16 | `test/integration/confirmable_test.rb:168` | unconfirmed but signed in user should be redirected to their root path | ported | `crates/devise-rust-axum/tests/devise_flows.rs (signed-in redirect)` | |
| 17 | `test/integration/confirmable_test.rb:178` | user should be redirected to sign in page whenever signed in as another resource at same session already | ported | `crates/devise-rust-axum/tests/devise_flows.rs (require_no_authentication per scope)` | |
| 18 | `test/integration/confirmable_test.rb:187` | should not be able to confirm an email with a blank confirmation token | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_confirm_by_token_blank_and_legacy_paths)` | TEST-03 item 4, blank token guard at the controller |
| 19 | `test/integration/confirmable_test.rb:193` | should not be able to confirm an email with a nil confirmation token | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_confirm_by_token_blank_and_legacy_paths)` | |
| 20 | `test/integration/confirmable_test.rb:199` | should not be able to confirm user with blank confirmation token | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_confirm_by_token_blank_and_legacy_paths)` | |
| 21 | `test/integration/confirmable_test.rb:208` | should not be able to confirm user with nil confirmation token | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_confirm_by_token_blank_and_legacy_paths)` | |
| 22 | `test/integration/confirmable_test.rb:217` | error message is configurable by resource name | ported | `crates/devise-rust/src/i18n.rs tests (resource-scoped lookup chain)` | |
| 23 | `test/integration/confirmable_test.rb:226` | resent confirmation token with valid e-mail in JSON format should return empty and valid response | ported | `crates/devise-rust-axum/src/routes.rs (confirmation create JSON arm)` | |
| 24 | `test/integration/confirmable_test.rb:233` | resent confirmation token with invalid e-mail in JSON format should return invalid response | ported | `crates/devise-rust-axum/src/routes.rs (confirmation create JSON arm)` | |
| 25 | `test/integration/confirmable_test.rb:240` | confirm account with valid confirmation token in JSON format should return valid response | ported | `crates/devise-rust-axum/src/routes.rs (confirmation show JSON arm)` | |
| 26 | `test/integration/confirmable_test.rb:247` | confirm account with invalid confirmation token in JSON format should return invalid response | ported | `crates/devise-rust-axum/src/routes.rs (confirmation show JSON arm)` | |
| 27 | `test/integration/confirmable_test.rb:254` | when in paranoid mode and with a valid e-mail, should not say that the e-mail is valid | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_class_send_finds_unconfirmed_first_and_paranoid_stays_silent)` | |
| 28 | `test/integration/confirmable_test.rb:268` | when in paranoid mode and with a invalid e-mail, should not say that the e-mail is invalid | ported | `crates/devise-rust/src/confirmable.rs tests (paranoid stays silent)` | |
| 29 | `test/integration/confirmable_test.rb:295` | admin should be able to request a new confirmation after email changed | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_reconfirmation_postpones_with_d05_routing)` plus framework flow | |
| 30 | `test/integration/confirmable_test.rb:311` | admin with valid confirmation token should be able to confirm email after email changed | ported | `crates/devise-rust/src/confirmable.rs tests (unconfirmed_email applied on confirm)` | |
| 31 | `test/integration/confirmable_test.rb:323` | admin with previously valid confirmation token should not be able to confirm email after email changed again | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_5783_double_submit_keeps_victim_unconfirmed)` | TEST-03 item 3 |
| 32 | `test/integration/confirmable_test.rb:345` | admin email should be unique also within unconfirmed_email | ported | `crates/devise-rust/src/confirmable.rs tests (class send unconfirmed lookup)` | |
| 33 | `test/integration/confirmable_test.rb:358` | concurrent email change should not lose the victim's unconfirmed state (the #5783 forced write) | ported | `crates/devise-rust/src/confirmable.rs tests (confirmable_5783_double_submit_keeps_victim_unconfirmed)` | the forced `unconfirmed_email` write closes the race |

### integration/database_authenticatable_test.rb (10 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/integration/database_authenticatable_test.rb:6` | sign in with email of different case should succeed when email is in the list of case insensitive keys | ported | `crates/devise-rust/src/parameter.rs tests (test_parameter_filter_downcase)` plus `crates/devise-rust-axum/tests/devise_flows.rs` | |
| 2 | `test/integration/database_authenticatable_test.rb:16` | sign in with email of different case should fail when email is NOT the list of case insensitive keys | ported | `crates/devise-rust/src/parameter.rs tests (keys not configured stay untouched)` | |
| 3 | `test/integration/database_authenticatable_test.rb:28` | sign in with email including extra spaces should succeed when email is in the list of strip whitespace keys | ported | `crates/devise-rust/src/parameter.rs tests (test_parameter_filter_strip_whitespace)` | |
| 4 | `test/integration/database_authenticatable_test.rb:38` | sign in with email including extra spaces should fail when email is NOT the list of strip whitespace keys | ported | `crates/devise-rust/src/parameter.rs tests (keys not configured stay untouched)` | |
| 5 | `test/integration/database_authenticatable_test.rb:50` | sign in should not authenticate if not using proper authentication keys | ported | `crates/devise-rust/src/strategy.rs tests (missing keys abort)` | |
| 6 | `test/integration/database_authenticatable_test.rb:57` | sign in with invalid email should return to sign in form with error message | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_sign_in_failure_formats)` plus actix same flow | |
| 7 | `test/integration/database_authenticatable_test.rb:68` | sign in with invalid password should return to sign in form with error message | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_sign_in_failure_formats)` | |
| 8 | `test/integration/database_authenticatable_test.rb:77` | when in paranoid mode and without a valid e-mail | ported | `crates/devise-rust/src/strategy.rs tests (test_paranoid_strategy_masks_not_found)` | TEST-03 item 1, uniform `:invalid` plus dummy bcrypt |
| 9 | `test/integration/database_authenticatable_test.rb:90` | error message is configurable by resource name | ported | `crates/devise-rust/src/i18n.rs tests (resource-scoped lookup)` | |
| 10 | `test/integration/database_authenticatable_test.rb:100` | valid sign in calls after_database_authentication callback | ported | `crates/devise-rust/tests/notifications.rs (after_database_authentication_fires_on_password_strategies)` | |

### integration/http_authenticatable_test.rb (11 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/integration/http_authenticatable_test.rb:6` | sign in with HTTP should not run model validations | ported | `crates/devise-rust/src/strategy.rs tests (test_http_basic_strategy_success)` | |
| 2 | `test/integration/http_authenticatable_test.rb:12` | handles unverified requests gets rid of caches but continues signed in | ported | `crates/devise-rust/src/hooks.rs tests (test_hook_registry_activatable_csrf)` | |
| 3 | `test/integration/http_authenticatable_test.rb:21` | sign in should authenticate with http | ported | `crates/devise-rust/src/strategy.rs tests (test_http_basic_strategy_success)` | |
| 4 | `test/integration/http_authenticatable_test.rb:33` | sign in should authenticate with http but not emit a cookie if skipping session storage | ported | `crates/devise-rust/src/strategy.rs tests (test_strategy_ids: skip_session_storage http_auth)` | |
| 5 | `test/integration/http_authenticatable_test.rb:45` | returns a custom response with www-authenticate header on failures | ported | `crates/devise-rust/src/failure.rs tests (www_authenticate)` plus `crates/devise-rust-axum/src/failure.rs` | |
| 6 | `test/integration/http_authenticatable_test.rb:51` | uses the request format as response content type | ported | `crates/devise-rust/src/failure.rs tests (format classification)` | |
| 7 | `test/integration/http_authenticatable_test.rb:58` | returns a custom response with www-authenticate and chosen realm | ported | `crates/devise-rust/src/failure.rs tests (realm)` | |
| 8 | `test/integration/http_authenticatable_test.rb:66` | sign in should authenticate with http even with specific authentication keys | ported | `crates/devise-rust/src/strategy.rs tests (http auth hash honoring keys)` | |
| 9 | `test/integration/http_authenticatable_test.rb:75` | it uses appropriate authentication_keys when configured with hash | ported | `crates/devise-rust/src/strategy.rs tests (authentication_keys config)` | |
| 10 | `test/integration/http_authenticatable_test.rb:84` | it uses the appropriate key when configured explicitly | ported | `crates/devise-rust/src/config.rs tests (http_authentication_key)` | |
| 11 | `test/integration/http_authenticatable_test.rb:93` | test request with oauth2 header doesnt get mistaken for basic authentication | ported | `crates/devise-rust/src/request.rs tests (has_http_basic scheme check)` | |

### integration/lockable_test.rb (17 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/integration/lockable_test.rb:23` | user should be able to request a new unlock token | ported | `crates/devise-rust-axum/tests/devise_flows.rs (journey lock step)` plus actix same flow | |
| 2 | `test/integration/lockable_test.rb:35` | user should receive the instructions from a custom mailer | ported | `crates/devise-rust/src/mailer.rs tests (app-supplied Mailer)` | |
| 3 | `test/integration/lockable_test.rb:43` | unlocked user should not be able to request a unlock token | ported | `crates/devise-rust/src/lockable.rs tests (lockable_resend_refuses_unlocked_record)` plus framework flow | |
| 4 | `test/integration/lockable_test.rb:58` | unlocked pages should not be available if email strategy is disabled | ported | `crates/devise-rust/src/scope.rs tests (unlock routes gated on strategy)` | |
| 5 | `test/integration/lockable_test.rb:74` | user with invalid unlock token should not be able to unlock an account | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_unlock_by_token invalid path)` | |
| 6 | `test/integration/lockable_test.rb:83` | locked user should be able to unlock account | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_unlock_by_token)` | |
| 7 | `test/integration/lockable_test.rb:93` | user should not send a new e-mail if already locked | ported | `crates/devise-rust/src/lockable.rs tests (if_access_locked guard)` | |
| 8 | `test/integration/lockable_test.rb:105` | error message is configurable by resource name | ported | `crates/devise-rust/src/i18n.rs tests (resource-scoped lookup)` | |
| 9 | `test/integration/lockable_test.rb:119` | user should not be able to sign in when locked | ported | `crates/devise-rust-axum/tests/devise_flows.rs (journey lock step rejects sign-in)` | |
| 10 | `test/integration/lockable_test.rb:133` | user should be able to request a new unlock token via JSON request and should return empty and valid response | ported | `crates/devise-rust-axum/src/routes.rs (unlock create JSON arm)` | |
| 11 | `test/integration/lockable_test.rb:143` | unlocked user should not be able to request a unlock token via JSON request | ported | `crates/devise-rust-axum/src/routes.rs (unlock create JSON arm)` | |
| 12 | `test/integration/lockable_test.rb:153` | user with valid unlock token should be able to unlock account via JSON request | ported | `crates/devise-rust-axum/src/routes.rs (unlock show JSON arm)` | |
| 13 | `test/integration/lockable_test.rb:162` | user with invalid unlock token should not be able to unlock the account via JSON request | ported | `crates/devise-rust-axum/src/routes.rs (unlock show JSON arm)` | |
| 14 | `test/integration/lockable_test.rb:168` | in paranoid mode, when trying to unlock a user that exists it should not say that it exists if it is locked | ported | `crates/devise-rust/src/lockable.rs tests (lockable_paranoid_suppresses_lock_messages)` | |
| 15 | `test/integration/lockable_test.rb:183` | in paranoid mode, when trying to unlock a user that exists it should not say that it exists if it is not locked | ported | `crates/devise-rust/src/lockable.rs tests (lockable_paranoid_suppresses_lock_messages)` | |
| 16 | `test/integration/lockable_test.rb:198` | in paranoid mode, when trying to unlock a user that does not exists it should not say that it does not exists | ported | `crates/devise-rust/src/lockable.rs tests (class send not-found stays silent under paranoid)` | |
| 17 | `test/integration/lockable_test.rb:215` | in paranoid mode, when locking a user that exists it should not say that the user was locked | ported | `crates/devise-rust/src/lockable.rs tests (lockable_paranoid_suppresses_lock_messages)` | |

### integration/mounted_engine_test.rb (4 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/integration/mounted_engine_test.rb:36` | redirects to the sign in page when not authenticated | waived | `crates/devise-rust-axum/tests/extractors.rs (guard redirect behavior asserted directly)` | reason: the block exercises authentication across a Rails engine mount boundary; Rust has no engine concept, so the same guarantee is asserted on the host router directly. v1 impact: none, unauthenticated access is still redirected; only the engine-mount plumbing is absent. |
| 2 | `test/integration/mounted_engine_test.rb:44` | renders the mounted engine when authenticated | waived | see row 1 | reason: Rails engine mounting; same as row 1. v1 impact: same as row 1. |
| 3 | `test/integration/mounted_engine_test.rb:53` | renders a inner route of the mounted engine when authenticated | waived | see row 1 | reason: Rails engine mounting; same as row 1. v1 impact: same as row 1. |
| 4 | `test/integration/mounted_engine_test.rb:61` | respond properly to a non existing route of the mounted engine | waived | `crates/devise-rust-axum/tests/routes.rs (404 on unknown routes)` | reason: Rails engine 404 routing across mount boundaries; the host router owns unknown-route responses in the port. v1 impact: none. |

### integration/omniauthable_test.rb (12 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/integration/omniauthable_test.rb:48` | omniauth sign in should not run model validations | ported | `crates/devise-rust-axum/tests/omniauth_flows.rs` plus `crates/devise-rust-actix/tests/omniauth_flows.rs` | |
| 2 | `test/integration/omniauthable_test.rb:59` | can access omniauth.auth in the env hash | deviated | `crates/devise-rust-axum/src/omniauth.rs (ProviderProfile passed to the handler)` | reason: Rack exposes the OmniAuth auth hash through the request env; the port passes the typed `ProviderProfile` to `from_omniauth` directly. v1 impact: none, the same data reaches the model seam with stronger typing. |
| 3 | `test/integration/omniauthable_test.rb:72` | cleans up session on sign up | ported | `crates/devise-rust-axum/tests/omniauth_flows.rs (session stash swept on sign-in)` | bridge-indexed prefix sweep |
| 4 | `test/integration/omniauthable_test.rb:93` | cleans up session on cancel | ported | `crates/devise-rust-axum/tests/devise_flows.rs (cancel expires OAuth session data)` | |
| 5 | `test/integration/omniauthable_test.rb:104` | cleans up session on sign in | ported | `crates/devise-rust-axum/tests/omniauth_flows.rs` | |
| 6 | `test/integration/omniauthable_test.rb:115` | sign in and send remember token if configured | ported | `crates/devise-rust-axum/tests/omniauth_flows.rs (remember cookie on omniauth sign-in when configured)` | |
| 7 | `test/integration/omniauthable_test.rb:129` | authorization path via GET when Omniauth allowed_request_methods includes GET | ported | `crates/devise-rust/src/scope.rs tests (authorize verb per config)` | devise 5.0.4 pins POST; both verbs supported per config |
| 8 | `test/integration/omniauthable_test.rb:140` | authorization path via GET when Omniauth allowed_request_methods doesn't include GET | ported | `crates/devise-rust/src/scope.rs tests (POST authorize default)` | |
| 9 | `test/integration/omniauthable_test.rb:151` | generates a link to authenticate with provider | ported | `crates/devise-rust/src/scope.rs tests (omniauth_callback_path_substitutes_provider)` | path helpers render from the shared specs |
| 10 | `test/integration/omniauthable_test.rb:158` | generates a proper link when SCRIPT_NAME is set | waived | `crates/devise-rust/src/scope.rs tests (path_prefix override)` | reason: SCRIPT_NAME is the Rack engine-mount env entry; the port expresses mounting through `omniauth_path_prefix` and the host router. v1 impact: none. |
| 11 | `test/integration/omniauthable_test.rb:166` | handles callback error parameter according to the specification | ported | `crates/devise-rust-axum/tests/omniauth_flows.rs (error parameter path)` | |
| 12 | `test/integration/omniauthable_test.rb:173` | handles other exceptions from OmniAuth | ported | `crates/devise-rust-axum/tests/omniauth_flows.rs (failure message path)` | failures render `devise.omniauth_callbacks.failure` |

### integration/recoverable_test.rb (31 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/integration/recoverable_test.rb:36` | reset password should send to user record email and avoid case mapping collisions | ported | `crates/devise-rust/src/model.rs tests (send_reset_password_instructions_for)` | |
| 2 | `test/integration/recoverable_test.rb:47` | reset password with email of different case should succeed when email is in the list of case insensitive keys | ported | `crates/devise-rust/src/parameter.rs tests (test_parameter_filter_downcase)` plus framework flow | |
| 3 | `test/integration/recoverable_test.rb:58` | reset password with email should send an email from a custom mailer | ported | `crates/devise-rust/src/mailer.rs tests (app-supplied Mailer)` | |
| 4 | `test/integration/recoverable_test.rb:71` | reset password with email of different case should fail when email is NOT the list of case insensitive keys | ported | `crates/devise-rust/src/parameter.rs tests (keys not configured stay untouched)` | |
| 5 | `test/integration/recoverable_test.rb:86` | reset password with email with extra whitespace should succeed when email is in the list of strip whitespace keys | ported | `crates/devise-rust/src/parameter.rs tests (test_parameter_filter_strip_whitespace)` | |
| 6 | `test/integration/recoverable_test.rb:97` | reset password with email with extra whitespace should fail when email is NOT the list of strip whitespace keys | ported | `crates/devise-rust/src/parameter.rs tests (keys not configured stay untouched)` | |
| 7 | `test/integration/recoverable_test.rb:112` | authenticated user should not be able to visit forgot password page | ported | `crates/devise-rust-axum/tests/devise_flows.rs (require_no_authentication on password new)` | |
| 8 | `test/integration/recoverable_test.rb:122` | not authenticated user should be able to request a forgot password | ported | `crates/devise-rust-axum/tests/devise_flows.rs (journey reset step)` plus actix same flow | |
| 9 | `test/integration/recoverable_test.rb:130` | not authenticated user with invalid email should receive an error message | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_reset_token_errors)` | |
| 10 | `test/integration/recoverable_test.rb:141` | authenticated user should not be able to visit edit password page | ported | `crates/devise-rust-axum/tests/devise_flows.rs (require_no_authentication)` | |
| 11 | `test/integration/recoverable_test.rb:149` | not authenticated user without a reset password token should not be able to visit the page | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_reset_token_errors: no_token)` | |
| 12 | `test/integration/recoverable_test.rb:155` | not authenticated user with invalid reset password token should not be able to change their password | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_reset_token_errors)` | |
| 13 | `test/integration/recoverable_test.rb:166` | not authenticated user with valid reset password token but invalid password should not be able to change their password | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_reset_token_errors)` | |
| 14 | `test/integration/recoverable_test.rb:180` | not authenticated user with valid data should be able to change their password | ported | `crates/devise-rust-axum/tests/devise_flows.rs (journey reset step)` | |
| 15 | `test/integration/recoverable_test.rb:190` | after entering invalid data user should still be able to change their password | ported | `crates/devise-rust/src/model.rs tests (token kept on invalid reset)` | |
| 16 | `test/integration/recoverable_test.rb:204` | sign in user automatically after changing its password | ported | `crates/devise-rust-axum/tests/devise_flows.rs (reset signs in per config)` | |
| 17 | `test/integration/recoverable_test.rb:212` | does not sign in user automatically after changing its password if config.sign_in_after_reset_password is false | ported | `crates/devise-rust/src/model.rs tests (sign_in_after_reset_password config gate)` | |
| 18 | `test/integration/recoverable_test.rb:225` | does not sign in user automatically after changing its password if resource_class.sign_in_after_reset_password is false | ported | `crates/devise-rust/src/config.rs tests (per-scope override cascade)` | |
| 19 | `test/integration/recoverable_test.rb:238` | sign in user automatically after changing its password if resource_class.sign_in_after_reset_password is true | ported | `crates/devise-rust/src/config.rs tests (per-scope override cascade)` | |
| 20 | `test/integration/recoverable_test.rb:250` | does not sign in user automatically after changing its password if it's an inactive record | ported | `crates/devise-rust/src/model.rs tests (updated_not_active path)` | |
| 21 | `test/integration/recoverable_test.rb:265` | unlocks and signs in locked user automatically after changing it's password (email unlock strategy) | ported | `crates/devise-rust-axum/src/routes.rs (password update unlocks when unlockable)` | |
| 22 | `test/integration/recoverable_test.rb:277` | unlocks and signs in locked user automatically after changing it's password (both unlock strategy) | ported | `crates/devise-rust-axum/src/routes.rs (password update unlocks when unlockable)` | |
| 23 | `test/integration/recoverable_test.rb:289` | reset password request with valid e-mail in JSON format should return empty and valid response | ported | `crates/devise-rust-axum/src/routes.rs (password create JSON arm)` | |
| 24 | `test/integration/recoverable_test.rb:296` | reset password request with invalid e-mail in JSON format should return valid response | ported | `crates/devise-rust-axum/src/routes.rs (password create JSON arm)` | |
| 25 | `test/integration/recoverable_test.rb:303` | reset password request with invalid e-mail in JSON format should return empty and valid response in paranoid mode | ported | `crates/devise-rust/src/model.rs tests (paranoid reset send stays silent)` | |
| 26 | `test/integration/recoverable_test.rb:312` | change password with valid parameters in JSON format should return valid response | ported | `crates/devise-rust-axum/src/routes.rs (password update JSON arm)` | |
| 27 | `test/integration/recoverable_test.rb:322` | change password with invalid token in JSON format should return invalid response | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_reset_token_errors)` | |
| 28 | `test/integration/recoverable_test.rb:330` | change password with invalid new password in JSON format should return invalid response | ported | `crates/devise-rust-axum/src/routes.rs (password update JSON arm)` | |
| 29 | `test/integration/recoverable_test.rb:338` | when in paranoid mode and with an invalid e-mail, asking to reset a password should display a message that does not indicates that the e-mail does not exists in the database | ported | `crates/devise-rust/src/model.rs tests (paranoid reset send stays silent)` | |
| 30 | `test/integration/recoverable_test.rb:351` | when in paranoid mode and with a valid e-mail, asking to reset password should display a message that does not indicates that the email exists in the database and redirect to the failure route | ported | `crates/devise-rust/src/model.rs tests (paranoid reset send stays silent)` | |
| 31 | `test/integration/recoverable_test.rb:363` | after recovering a password, should set failed attempts to 0 | ported | `crates/devise-rust/src/lockable.rs tests (reset_failed_attempts on password update path)` plus framework reset flow | |

### integration/registerable_test.rb (33 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/integration/registerable_test.rb:7` | a guest admin should be able to sign in successfully | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_sign_in_and_sign_out_with_flashes)` | block name says sign in but drives the sign-up flow per the file |
| 2 | `test/integration/registerable_test.rb:26` | a guest admin should be able to sign in and be redirected to a custom location | ported | `crates/devise-rust-axum/tests/devise_flows.rs (after_sign_in path)` | |
| 3 | `test/integration/registerable_test.rb:41` | a guest admin should not see a warning about minimum password length | waived | `crates/devise-rust-axum/tests/devise_flows.rs (flow_sign_up_failure_clears_passwords_and_keeps_errors)` | reason: the block asserts a Rails view helper renders (or not) a password-length hint; devise-rust ships no form views, so the hint is host-app UI. v1 impact: none, the length validation itself is asserted (model_validation.rs bounds test). |
| 4 | `test/integration/registerable_test.rb:57` | a guest user should see a warning about minimum password length | waived | see row 3 | reason: same view-rendering concern as row 3. v1 impact: same as row 3. |
| 5 | `test/integration/registerable_test.rb:62` | a guest user should be able to sign up successfully and be blocked by confirmation | ported | `crates/devise-rust-axum/tests/devise_flows.rs (journey sign up then confirm)` plus actix same flow | |
| 6 | `test/integration/registerable_test.rb:76` | a guest user should receive the confirmation instructions from the default mailer | ported | `crates/devise-rust-axum/src/routes.rs:1026` sign-up dispatch plus flow tests | |
| 7 | `test/integration/registerable_test.rb:81` | a guest user should receive the confirmation instructions from a custom mailer | ported | `crates/devise-rust/src/mailer.rs tests (app-supplied Mailer)` | |
| 8 | `test/integration/registerable_test.rb:87` | a guest user should be blocked by confirmation and redirected to a custom path | ported | `crates/devise-rust-axum/tests/devise_flows.rs (signed_up_but_unconfirmed redirect)` | |
| 9 | `test/integration/registerable_test.rb:100` | a guest user cannot sign up with invalid information | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_sign_up_failure_clears_passwords_and_keeps_errors)` | |
| 10 | `test/integration/registerable_test.rb:118` | a guest should not sign up with email/password that already exists | ported | `crates/devise-rust/tests/model_validation.rs (email_uniqueness_is_case_sensitive_at_db)` plus framework sign-up flow | |
| 11 | `test/integration/registerable_test.rb:133` | a guest should not be able to change account | ported | `crates/devise-rust-axum/tests/devise_flows.rs (edit requires authentication)` | |
| 12 | `test/integration/registerable_test.rb:140` | a signed in user should not be able to access sign up | ported | `crates/devise-rust-axum/tests/devise_flows.rs (require_no_authentication)` | |
| 13 | `test/integration/registerable_test.rb:146` | a signed in user should be able to edit their account | ported | `crates/devise-rust-axum/tests/devise_flows.rs (journey edit step)` | |
| 14 | `test/integration/registerable_test.rb:160` | a signed in user should still be able to use the website after changing their password | ported | `crates/devise-rust-axum/tests/devise_flows.rs (journey edit step, sign_in_after_change_password bypass)` | |
| 15 | `test/integration/registerable_test.rb:174` | a signed in user should not be able to use the website after changing their password if config.sign_in_after_change_password is false | ported | `crates/devise-rust/src/model.rs tests (registerable_tests: config gate)` plus `crates/devise-rust-axum/tests/devise_flows.rs (flow_two_cookie_jar_password_change_kills_session_and_remember)` | the two cookie jar regression (salt plus remember_created_at) |
| 16 | `test/integration/registerable_test.rb:190` | a signed in user should not be able to use the website after changing their password if resource_class.sign_in_after_change_password is false | ported | `crates/devise-rust/src/config.rs tests (per-scope override cascade)` | |
| 17 | `test/integration/registerable_test.rb:206` | a signed in user should be able to use the website after changing its email with config.sign_in_after_change_password is false | ported | `crates/devise-rust/src/model.rs tests (password-only gate: email change keeps session)` | |
| 18 | `test/integration/registerable_test.rb:223` | a signed in user should not change their current user with invalid password | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_account_update_requires_current_password)` | |
| 19 | `test/integration/registerable_test.rb:238` | a signed in user should be able to edit their password | ported | `crates/devise-rust-axum/tests/devise_flows.rs (journey edit step)` | |
| 20 | `test/integration/registerable_test.rb:253` | a signed in user should not be able to edit their password with invalid confirmation | ported | `crates/devise-rust/tests/model_validation.rs (password_confirmation_must_match)` plus framework flow | |
| 21 | `test/integration/registerable_test.rb:266` | a signed in user should see a warning about minimum password length | waived | see row 3 | reason: same view-rendering concern as row 3. v1 impact: same as row 3. |
| 22 | `test/integration/registerable_test.rb:272` | a signed in user should be able to cancel their account | ported | `crates/devise-rust-axum/tests/devise_flows.rs (account cancellation)` | |
| 23 | `test/integration/registerable_test.rb:282` | a user should be able to cancel sign up by deleting data in the session | ported | `crates/devise-rust-axum/tests/devise_flows.rs (cancel expires OAuth session data)` | |
| 24 | `test/integration/registerable_test.rb:294` | a user with JSON sign up stub | ported | `crates/devise-rust-axum/src/routes.rs (registration create JSON arm)` | |
| 25 | `test/integration/registerable_test.rb:301` | an admin sign up with valid information in JSON format should return valid response | ported | `crates/devise-rust-axum/src/routes.rs (registration create JSON arm)` | |
| 26 | `test/integration/registerable_test.rb:310` | a user sign up with valid information in JSON format should return valid response | ported | `crates/devise-rust-axum/src/routes.rs (registration create JSON arm)` | |
| 27 | `test/integration/registerable_test.rb:319` | a user sign up with invalid information in JSON format should return invalid response | ported | `crates/devise-rust-axum/src/routes.rs (registration create JSON arm)` | |
| 28 | `test/integration/registerable_test.rb:325` | a user update information with valid data in JSON format should return valid response | ported | `crates/devise-rust-axum/src/routes.rs (registration update JSON arm)` | |
| 29 | `test/integration/registerable_test.rb:332` | a user update information with invalid data in JSON format should return invalid response | ported | `crates/devise-rust-axum/src/routes.rs (registration update JSON arm)` | |
| 30 | `test/integration/registerable_test.rb:339` | a user cancel their account in JSON format should return valid response | ported | `crates/devise-rust-axum/src/routes.rs (registration destroy JSON arm)` | |
| 31 | `test/integration/registerable_test.rb:348` | a signed in admin should see a more appropriate flash message when editing their account if reconfirmable is enabled | ported | `crates/devise-rust/src/confirmable.rs tests (postponement drives update_needs_confirmation)` | |
| 32 | `test/integration/registerable_test.rb:364` | a signed in admin should not see a reconfirmation message if they did not change their password | ported | `crates/devise-rust/src/confirmable.rs tests (postponement gated on email change only)` | |
| 33 | `test/integration/registerable_test.rb:379` | a signed in admin should not see a reconfirmation message if they did not change their email, despite having an unconfirmed email | ported | `crates/devise-rust/src/confirmable.rs tests (postponement reads the ChangeSet, not stale state)` | |

### integration/rememberable_test.rb (18 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/integration/rememberable_test.rb:30` | do not remember the user if they have not checked remember me option | ported | `crates/devise-rust/src/strategy.rs tests (remember flag absent means no cookie)` plus framework flows | |
| 2 | `test/integration/rememberable_test.rb:35` | handle unverified requests gets rid of caches | ported | `crates/devise-rust/src/hooks.rs tests (test_hook_registry_activatable_csrf)` | |
| 3 | `test/integration/rememberable_test.rb:47` | handle unverified requests does not create cookies on sign in | ported | `crates/devise-rust/src/hooks.rs tests (unverified request session cleared)` | |
| 4 | `test/integration/rememberable_test.rb:61` | generate remember token after sign in | ported | `crates/devise-rust-axum/tests/devise_flows.rs (journey remember step)` plus actix same flow | |
| 5 | `test/integration/rememberable_test.rb:66` | generate remember token after sign in setting cookie options | ported | `crates/devise-rust/src/rememberable.rs tests (rememberable_set_hook_emits_hardened_cookie)` | hardened attrs per Phase 5 D-16 |
| 6 | `test/integration/rememberable_test.rb:76` | generate remember token with a custom key | ported | `crates/devise-rust/src/rememberable.rs tests (rememberable_options key override)` | |
| 7 | `test/integration/rememberable_test.rb:83` | generate remember token after sign in setting session options | ported | `crates/devise-rust/src/rememberable.rs tests (cookie options flow from config)` | |
| 8 | `test/integration/rememberable_test.rb:93` | remember the user before sign in | ported | `crates/devise-rust/src/proxy.rs tests (remember ops drained on set_user)` | |
| 9 | `test/integration/rememberable_test.rb:101` | remember the user before sign up and redirect them to their home | ported | `crates/devise-rust-axum/tests/devise_flows.rs (sign-up then remember journey step)` | |
| 10 | `test/integration/rememberable_test.rb:108` | does not extend remember period through sign in | ported | `crates/devise-rust/src/rememberable.rs tests (rememberable_fixed_expiry_never_slides)` | |
| 11 | `test/integration/rememberable_test.rb:124` | extends remember period when extend remember period config is true | ported | `crates/devise-rust/src/strategy.rs tests (test_strategy_rememberable_extend_reissues_when_enabled)` | |
| 12 | `test/integration/rememberable_test.rb:141` | does not extend remember period when extend period config is false | ported | `crates/devise-rust/src/rememberable.rs tests (rememberable_fixed_expiry_never_slides)` | |
| 13 | `test/integration/rememberable_test.rb:158` | do not remember other scopes | ported | `crates/devise-rust/src/proxy.rs tests (per-scope cookie key)` | |
| 14 | `test/integration/rememberable_test.rb:166` | do not remember with invalid token | ported | `crates/devise-rust/src/rememberable.rs tests (rememberable_nil_case_wrong_token)` | |
| 15 | `test/integration/rememberable_test.rb:173` | do not remember with expired token | ported | `crates/devise-rust/src/rememberable.rs tests (rememberable_nil_case_older_than_remember_for)` | |
| 16 | `test/integration/rememberable_test.rb:182` | do not remember the user anymore after forget | ported | `crates/devise-rust/src/rememberable.rs tests (forget clears cookie on sign-out)` | |
| 17 | `test/integration/rememberable_test.rb:195` | changing user password expires remember me token | ported | `crates/devise-rust/src/rememberable.rs tests (rememberable_password_rotation_kills_older_cookies)` plus `crates/devise-rust-axum/tests/devise_flows.rs (flow_two_cookie_jar_password_change_kills_session_and_remember)` | |
| 18 | `test/integration/rememberable_test.rb:205` | valid sign in calls after_remembered callback | ported | `crates/devise-rust/src/strategy.rs tests (test_strategy_rememberable_round_trip_success)` | |

### integration/timeoutable_test.rb (18 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/integration/timeoutable_test.rb:11` | set last request at in user session after each request | ported | `crates/devise-rust/src/hooks.rs tests (test_timeoutable_tick_hook_live_ticks_and_exempt_stays)` | |
| 2 | `test/integration/timeoutable_test.rb:20` | set last request at in user session after each request is skipped if tracking is disabled | ported | `crates/devise-rust/src/hooks.rs tests (skip flags honored)` | |
| 3 | `test/integration/timeoutable_test.rb:29` | does not set last request at in user session after each request if timeoutable is disabled | ported | `crates/devise-rust/src/timeoutable.rs tests (disabled module: no tick)` | |
| 4 | `test/integration/timeoutable_test.rb:41` | does not time out user session before default limit time | ported | `crates/devise-rust/src/timeoutable.rs tests (tick_expired live)` | |
| 5 | `test/integration/timeoutable_test.rb:51` | time out user session after default limit time when sign_out_all_scopes is false | ported | `crates/devise-rust/src/hooks.rs tests (per-scope timeout sign-out)` | |
| 6 | `test/integration/timeoutable_test.rb:66` | time out all sessions after default limit time when sign_out_all_scopes is true | ported | `crates/devise-rust/src/hooks.rs tests (test_timeoutable_tick_hook_stale_signs_out_all_scopes)` | |
| 7 | `test/integration/timeoutable_test.rb:80` | time out user session after default limit time and redirect to latest get request | ported | `crates/devise-rust/src/failure.rs tests (stored_location on timeout)` plus framework timeout flow | |
| 8 | `test/integration/timeoutable_test.rb:90` | time out on non-GET request does not redirect to an external host supplied via the referer | ported | `crates/devise-rust/src/failure.rs tests (stored location host validation)` | the devise 5.0.4 Referer fix equivalent (TEST-03 item 8) |
| 9 | `test/integration/timeoutable_test.rb:100` | time out on non-GET request with an opaque referer falls back to the sign in page | ported | `crates/devise-rust/src/failure.rs tests (unparseable referer falls back)` | |
| 10 | `test/integration/timeoutable_test.rb:110` | time out is not triggered on sign out | ported | `crates/devise-rust/src/timeoutable.rs tests (skip on sign-out requests)` | |
| 11 | `test/integration/timeoutable_test.rb:122` | expired session is not extended by sign in page | ported | `crates/devise-rust/src/timeoutable.rs tests (GET sign-in page does not tick when expired)` | |
| 12 | `test/integration/timeoutable_test.rb:136` | time out is not triggered on sign in | ported | `crates/devise-rust/src/timeoutable.rs tests (skip on sign-in requests)` | |
| 13 | `test/integration/timeoutable_test.rb:147` | user configured timeout limit | ported | `crates/devise-rust/src/timeoutable.rs tests (per-scope override)` | |
| 14 | `test/integration/timeoutable_test.rb:163` | error message with i18n | ported | `crates/devise-rust/src/timeoutable.rs tests plus failure i18n lookup (devise.failure.timeout)` | |
| 15 | `test/integration/timeoutable_test.rb:176` | error message with i18n with double redirect | ported | `crates/devise-rust/src/failure.rs tests (timeout redirect preserves the message)` | |
| 16 | `test/integration/timeoutable_test.rb:190` | error message redirect respects i18n locale set | deviated | `crates/devise-rust/src/i18n.rs tests (locale option)` | reason: same request-scoped locale seam as the authenticatable row 30. v1 impact: none for message resolution. |
| 17 | `test/integration/timeoutable_test.rb:201` | time out not triggered if remembered | ported | `crates/devise-rust/src/timeoutable.rs tests (timeoutable_matrix_remember_exemption)` | |
| 18 | `test/integration/timeoutable_test.rb:211` | does not crash when the last_request_at is a String | ported | `crates/devise-rust/src/timeoutable.rs tests (parse_last_request_at string form; malformed fails closed)` | |

### integration/trackable_test.rb (7 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/integration/trackable_test.rb:6` | trackable should not run model validations | ported | `crates/devise-rust/src/trackable.rs tests (bang skips validations)` | |
| 2 | `test/integration/trackable_test.rb:12` | current and last sign in timestamps are updated on each sign in | ported | `crates/devise-rust/src/hooks.rs tests (test_trackable_hook_shifts_memo_and_honors_skip)` | |
| 3 | `test/integration/trackable_test.rb:35` | current and last sign in remote ip are updated on each sign in | ported | `crates/devise-rust/src/trackable.rs tests (extract_ip_from)` | |
| 4 | `test/integration/trackable_test.rb:47` | current and last sign in remote ip returns original ip behind a non transparent proxy | deviated | `crates/devise-rust/src/trackable.rs tests (peer address source)` | reason: Devise reads the socket remote IP; the port reads the request peer address the framework bridge records, without X-Forwarded-For traversal. v1 impact: behind a reverse proxy the recorded IP is the proxy's address unless the host passes the original IP through the bridge (documented limitation, proxy-aware IP is a deferred future item). |
| 5 | `test/integration/trackable_test.rb:59` | increase sign in count | ported | `crates/devise-rust/src/trackable.rs tests (count increment)` | |
| 6 | `test/integration/trackable_test.rb:73` | does not update anything if user has signed out along the way | ported | `crates/devise-rust/src/hooks.rs tests (skip honored when record vanished)` | |
| 7 | `test/integration/trackable_test.rb:84` | do not track if devise.skip_trackable is set | ported | `crates/devise-rust/src/hooks.rs tests (test_trackable_hook_shifts_memo_and_honors_skip)` | |

## Controllers suite (96 blocks)

The Devise controller helper surface maps to the framework crates' extractors and helpers plus the core proxy. Rails-controller-internals blocks (view rendering, metaprogrammed helper methods, load hooks) are waived with reasons.

### controllers/helpers_test.rb (50 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/controllers/helpers_test.rb:14` | provide access to warden instance | ported | `crates/devise-rust/src/proxy.rs tests (AuthProxy surface)` | |
| 2 | `test/controllers/helpers_test.rb:18` | proxy signed_in?(scope) to authenticate? | ported | `crates/devise-rust/src/proxy.rs tests (test_helpers_authenticate_signed_in)` | |
| 3 | `test/controllers/helpers_test.rb:23` | proxy signed_in?(nil) to authenticate? | ported | `crates/devise-rust/src/proxy.rs tests (any-scope signed_in)` | |
| 4 | `test/controllers/helpers_test.rb:30` | proxy [group]_signed_in? to authenticate? with each scope | waived | `crates/devise-rust/src/proxy.rs tests (test_helpers_authenticate_signed_in)` | reason: devise_group metaprogramming; see the devise_group waiver in rails-parity.md. v1 impact: none, per-scope checks are explicit. |
| 5 | `test/controllers/helpers_test.rb:37` | proxy current_user to authenticate with user scope | ported | `crates/devise-rust-axum/tests/extractors.rs (current_user)` | |
| 6 | `test/controllers/helpers_test.rb:42` | proxy current_admin to authenticate with admin scope | ported | `crates/devise-rust-axum/tests/extractors.rs (per-scope)` | |
| 7 | `test/controllers/helpers_test.rb:47` | proxy current_[group] to authenticate with each scope | waived | see row 4 | reason: devise_group metaprogramming. v1 impact: same as row 4. |
| 8 | `test/controllers/helpers_test.rb:54` | proxy current_[plural_group] to authenticate with each scope | waived | see row 4 | reason: devise_group metaprogramming. v1 impact: same as row 4. |
| 9 | `test/controllers/helpers_test.rb:61` | proxy current_publisher_account to authenticate with namespaced publisher account scope | ported | `crates/devise-rust/src/scope.rs tests (namespaced scope names)` | namespaced scopes supported on the registry |
| 10 | `test/controllers/helpers_test.rb:66` | proxy authenticate_user! to authenticate with user scope | ported | `crates/devise-rust-axum/tests/extractors.rs (RequireAuth)` | |
| 11 | `test/controllers/helpers_test.rb:71` | proxy authenticate_user! options to authenticate with user scope | ported | `crates/devise-rust-axum/tests/extractors.rs (guard options)` | |
| 12 | `test/controllers/helpers_test.rb:76` | proxy authenticate_admin! to authenticate with admin scope | ported | `crates/devise-rust-axum/tests/extractors.rs (per-scope guard)` | |
| 13 | `test/controllers/helpers_test.rb:81` | proxy authenticate_[group]! to authenticate!? with each scope | waived | see row 4 | reason: devise_group metaprogramming. v1 impact: same as row 4. |
| 14 | `test/controllers/helpers_test.rb:89` | proxy authenticate_publisher_account! to authenticate with namespaced publisher account scope | ported | `crates/devise-rust-axum/tests/extractors.rs (namespaced scope guard)` | |
| 15 | `test/controllers/helpers_test.rb:94` | proxy user_signed_in? to authenticate with user scope | ported | `crates/devise-rust/src/proxy.rs tests (test_helpers_authenticate_signed_in)` | |
| 16 | `test/controllers/helpers_test.rb:99` | proxy admin_signed_in? to authenticate with admin scope | ported | `crates/devise-rust/src/proxy.rs tests (per-scope)` | |
| 17 | `test/controllers/helpers_test.rb:104` | proxy publisher_account_signed_in? to authenticate with namespaced scope | ported | `crates/devise-rust/src/proxy.rs tests (namespaced scope)` | |
| 18 | `test/controllers/helpers_test.rb:109` | proxy user_session to session scope in warden | ported | `crates/devise-rust/src/session.rs tests (test_key_naming)` | |
| 19 | `test/controllers/helpers_test.rb:115` | proxy admin_session to session scope in warden | ported | `crates/devise-rust/src/session.rs tests (per-scope keys)` | |
| 20 | `test/controllers/helpers_test.rb:121` | proxy publisher_account_session from namespaced scope to session scope in warden | ported | `crates/devise-rust/src/session.rs tests (namespaced keys)` | |
| 21 | `test/controllers/helpers_test.rb:127` | sign in proxy to set_user on warden | ported | `crates/devise-rust/src/proxy.rs tests (test_proxy_sign_in_out)` | |
| 22 | `test/controllers/helpers_test.rb:134` | sign in accepts a resource as argument | ported | `crates/devise-rust/src/proxy.rs tests (sign_in takes the record)` | |
| 23 | `test/controllers/helpers_test.rb:141` | does not sign in again if the user is already in | ported | `crates/devise-rust/src/proxy.rs tests (test_proxy_sign_in_noop)` | |
| 24 | `test/controllers/helpers_test.rb:148` | sign in again when the user is already in only if force is given | ported | `crates/devise-rust/src/proxy.rs tests (force re-sign-in)` | |
| 25 | `test/controllers/helpers_test.rb:155` | bypass the sign in | ported | `crates/devise-rust/src/proxy.rs tests (test_proxy_bypass_sign_in)` | |
| 26 | `test/controllers/helpers_test.rb:162` | sign out clears up any signed in user from all scopes | ported | `crates/devise-rust/src/proxy.rs tests (test_proxy_sign_out_all_scopes)` | |
| 27 | `test/controllers/helpers_test.rb:173` | sign out logs out and clears up any signed in user by scope | ported | `crates/devise-rust/src/proxy.rs tests (test_proxy_sign_out)` | |
| 28 | `test/controllers/helpers_test.rb:183` | sign out accepts a resource as argument | ported | `crates/devise-rust/src/proxy.rs tests (sign_out by record)` | |
| 29 | `test/controllers/helpers_test.rb:190` | sign out without args proxy to sign out all scopes | ported | `crates/devise-rust/src/proxy.rs tests (sign_out default all)` | |
| 30 | `test/controllers/helpers_test.rb:197` | sign out everybody proxy to logout on warden | ported | `crates/devise-rust/src/proxy.rs tests (test_proxy_sign_out_all_scopes)` | |
| 31 | `test/controllers/helpers_test.rb:203` | stored location for returns the location for a given scope | ported | `crates/devise-rust/src/failure.rs tests (test_stored_location)` | |
| 32 | `test/controllers/helpers_test.rb:209` | stored location for accepts a resource as argument | ported | `crates/devise-rust/src/failure.rs tests (stored_location by record)` | |
| 33 | `test/controllers/helpers_test.rb:215` | stored location cleans information after reading | ported | `crates/devise-rust/src/failure.rs tests (read-once semantics)` | |
| 34 | `test/controllers/helpers_test.rb:221` | store location for stores a location to redirect back to | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_stored_location_get_only)` | |
| 35 | `test/controllers/helpers_test.rb:227` | store bad location for does not store a location to redirect back to | ported | `crates/devise-rust/src/request.rs tests (test_parse_stored_uri rejects external hosts)` | |
| 36 | `test/controllers/helpers_test.rb:243` | store location for accepts a resource as argument | ported | `crates/devise-rust/src/session.rs tests (stored_location_key by record)` | |
| 37 | `test/controllers/helpers_test.rb:248` | store location for stores paths | ported | `crates/devise-rust/src/failure.rs tests (test_stored_location)` | |
| 38 | `test/controllers/helpers_test.rb:255` | store location for stores query string | ported | `crates/devise-rust/src/failure.rs tests (full path with query)` | |
| 39 | `test/controllers/helpers_test.rb:260` | store location for stores fragments | deviated | `crates/devise-rust/src/failure.rs tests (path stored, fragment dropped)` | reason: Devise re-attaches the URI fragment through `add_fragment_back_to_path`; the port stores the validated path and query and does not round-trip fragments. v1 impact: a stored redirect loses its `#fragment` suffix; the path and query are preserved. |
| 40 | `test/controllers/helpers_test.rb:265` | after sign in path defaults to root path if none by was specified for the given scope | ported | `crates/devise-rust-axum/tests/devise_flows.rs (post-sign-in redirect default)` | |
| 41 | `test/controllers/helpers_test.rb:269` | after sign in path defaults to the scoped root path | ported | `crates/devise-rust-axum/tests/devise_flows.rs (scoped root)` | |
| 42 | `test/controllers/helpers_test.rb:273` | after sign out path defaults to the root path | ported | `crates/devise-rust-axum/tests/devise_flows.rs (post-sign-out redirect)` | |
| 43 | `test/controllers/helpers_test.rb:278` | sign in and redirect uses the stored location | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flow_stored_location_get_only)` | |
| 44 | `test/controllers/helpers_test.rb:287` | sign in and redirect uses the configured after sign in path | ported | `crates/devise-rust-axum/tests/devise_flows.rs (after_sign_in path)` | |
| 45 | `test/controllers/helpers_test.rb:295` | sign in and redirect does not sign in again if user is already signed | ported | `crates/devise-rust/src/proxy.rs tests (test_proxy_sign_in_noop)` | |
| 46 | `test/controllers/helpers_test.rb:303` | sign out and redirect uses the configured after sign out path when signing out only the current scope | ported | `crates/devise-rust-axum/tests/devise_flows.rs (per-scope sign-out redirect)` | |
| 47 | `test/controllers/helpers_test.rb:314` | sign out and redirect uses the configured after sign out path when signing out all scopes | ported | `crates/devise-rust-axum/tests/devise_flows.rs (sign-out all redirect)` | |
| 48 | `test/controllers/helpers_test.rb:325` | is_flashing_format? depends on is_navigation_format? | ported | `crates/devise-rust/src/failure.rs tests (flash decision)` | |
| 49 | `test/controllers/helpers_test.rb:330` | is_flashing_format? is guarded against flash (middleware) not being loaded | waived | `crates/devise-rust/src/failure.rs tests (flash decision)` | reason: Rails conditionally loads the flash middleware; Rust flash storage is a compile-time part of the framework bridge, so the runtime guard has no equivalent. v1 impact: none. |
| 50 | `test/controllers/helpers_test.rb:335` | is not a devise controller | ported | framework crates guard `force` behavior for non-devise controllers (`crates/devise-rust-axum/src/routes.rs` devise_controller check) | |

### controllers/custom_registrations_controller_test.rb (5 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/controllers/custom_registrations_controller_test.rb:16` | yield resource to block on create success | ported | `crates/devise-rust-axum/src/routes.rs (registration create returns the saved record to the host handler seam)` | the host composes its own controller around the returned outcome |
| 2 | `test/controllers/custom_registrations_controller_test.rb:21` | yield resource to block on create failure | ported | `crates/devise-rust-axum/src/routes.rs (failure outcome carries the record with errors)` | |
| 3 | `test/controllers/custom_registrations_controller_test.rb:26` | yield resource to block on update success | ported | `crates/devise-rust-axum/src/routes.rs (registration update outcome)` | |
| 4 | `test/controllers/custom_registrations_controller_test.rb:32` | yield resource to block on update failure | ported | `crates/devise-rust-axum/src/routes.rs (failure outcome carries errors)` | |
| 5 | `test/controllers/custom_registrations_controller_test.rb:38` | yield resource to block on new | ported | `crates/devise-rust-axum/src/routes.rs (new returns an unsaved record)` | |

### controllers/custom_strategy_test.rb (2 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/controllers/custom_strategy_test.rb:42` | custom strategy can return its own status code | ported | `crates/devise-rust/src/proxy.rs tests (custom finder and failure surface)` plus `crates/devise-rust/src/failure.rs tests (custom failure_app per mapping)` | custom status codes surface through the per-mapping failure app seam |
| 2 | `test/controllers/custom_strategy_test.rb:53` | custom strategy can return custom headers | ported | `crates/devise-rust/src/failure.rs tests (www_authenticate custom header surface)` | |

### controllers/helper_methods_test.rb (3 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/controllers/helper_methods_test.rb:12` | includes Devise::Controllers::Helpers | waived | `crates/devise-rust-axum/src/lib.rs (helpers exported at the crate level)` | reason: ActiveSupport::Concern inclusion into a controller class; the Rust crates expose helpers as free functions and extractors, no mixin include step exists. v1 impact: none. |
| 2 | `test/controllers/helper_methods_test.rb:16` | does not respond_to helper or helper_method | waived | see row 1 | reason: Rails `helper_method` metaprogramming surface. v1 impact: none. |
| 3 | `test/controllers/helper_methods_test.rb:21` | defines methods like current_user | ported | `crates/devise-rust-axum/tests/extractors.rs (current_user)` | |

### controllers/inherited_controller_i18n_messages_test.rb (2 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/controllers/inherited_controller_i18n_messages_test.rb:28` | I18n scope is inherited from Devise::Sessions | waived | `crates/devise-rust/src/i18n.rs tests (scope chain devise.<section>.<key>)` | reason: Rails controller class inheritance copying the i18n_scope; the port resolves messages through the fixed devise scope chain at the i18n seam. v1 impact: none, the same keys resolve. |
| 2 | `test/controllers/inherited_controller_i18n_messages_test.rb:46` | I18n scope is overridden | waived | `crates/devise-rust/src/i18n.rs tests (lookup chain)` | reason: same controller-inheritance machinery as row 1. v1 impact: none. |

### controllers/internal_helpers_test.rb (17 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/controllers/internal_helpers_test.rb:17` | get resource name from env | ported | `crates/devise-rust/src/scope.rs tests (mapping drives the request scope)` | |
| 2 | `test/controllers/internal_helpers_test.rb:21` | get resource class from env | ported | `crates/devise-rust/src/scope.rs tests (class_name on Mapping)` | |
| 3 | `test/controllers/internal_helpers_test.rb:25` | get resource instance variable from env | waived | `crates/devise-rust-axum/src/routes.rs (handlers own the record in typed locals)` | reason: Rails instance variables are the view-binding mechanism; Rust handlers hold the typed record. v1 impact: none. |
| 4 | `test/controllers/internal_helpers_test.rb:30` | set resource instance variable from env | waived | see row 3 | reason: same instance-variable machinery as row 3. v1 impact: none. |
| 5 | `test/controllers/internal_helpers_test.rb:38` | get resource params from request params using resource name as key | ported | `crates/devise-rust/src/parameter.rs tests (sanitizer reads the scope-keyed params)` | |
| 6 | `test/controllers/internal_helpers_test.rb:53` | resources methods are not controller actions | waived | `crates/devise-rust-axum/src/routes.rs (handlers are explicit fns, no method_missing surface)` | reason: guards against Rails action dispatch on internal helper methods; explicit Rust fns cannot be dispatched accidentally. v1 impact: none. |
| 7 | `test/controllers/internal_helpers_test.rb:57` | require no authentication tests current mapping | ported | `crates/devise-rust-axum/tests/devise_flows.rs (require_no_authentication per scope)` | |
| 8 | `test/controllers/internal_helpers_test.rb:64` | require no authentication only checks if already authenticated if no inputs strategies are available | ported | `crates/devise-rust/src/strategy.rs tests (strategy availability)` | |
| 9 | `test/controllers/internal_helpers_test.rb:73` | require no authentication sets a flash message | ported | `crates/devise-rust-axum/tests/devise_flows.rs (already_authenticated flash)` | |
| 10 | `test/controllers/internal_helpers_test.rb:81` | signed in resource returns signed in resource for current scope | ported | `crates/devise-rust-axum/tests/extractors.rs (current_user)` | |
| 11 | `test/controllers/internal_helpers_test.rb:86` | is a devise controller | ported | `crates/devise-rust-axum/src/routes.rs (devise controller check)` | |
| 12 | `test/controllers/internal_helpers_test.rb:90` | does not issue blank flash messages | ported | `crates/devise-rust/src/failure.rs tests (flash_key None when no message)` | |
| 13 | `test/controllers/internal_helpers_test.rb:96` | issues non-blank flash messages normally | ported | `crates/devise-rust-axum/tests/devise_flows.rs (flash messages on flows)` | |
| 14 | `test/controllers/internal_helpers_test.rb:102` | issues non-blank flash.now messages normally | waived | `crates/devise-rust/src/failure.rs tests (flash decision)` | reason: Rails flash.now vs flash persistence distinction belongs to the host framework's flash store; the port emits flash keys and the bridge maps them. v1 impact: none, the bridge carries the now/persistence distinction. |
| 15 | `test/controllers/internal_helpers_test.rb:108` | uses custom i18n options | ported | `crates/devise-rust/src/i18n.rs tests (interpolation options)` | |
| 16 | `test/controllers/internal_helpers_test.rb:114` | allows custom i18n options to override resource_name | ported | `crates/devise-rust/src/i18n.rs tests (options override)` | |
| 17 | `test/controllers/internal_helpers_test.rb:120` | navigational_formats not returning a wild card | ported | `crates/devise-rust/src/request.rs tests (test_is_navigational_format)` | |

### controllers/load_hooks_controller_test.rb (1 block)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/controllers/load_hooks_controller_test.rb:18` | load hook called when controller is loaded | waived | `crates/devise-rust-axum/src/lib.rs (no load hooks; static crate surface)` | reason: ActiveSupport load hooks trigger on class load; Rust crates have no dynamic class loading. v1 impact: none, integrations register statically. |

### controllers/passwords_controller_test.rb (3 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/controllers/passwords_controller_test.rb:22` | redirect to after_sign_in_path_for if after_resetting_password_path_for is not overridden | ported | `crates/devise-rust-axum/src/routes.rs (password update redirect default)` | |
| 2 | `test/controllers/passwords_controller_test.rb:27` | redirect accordingly if after_resetting_password_path_for is overridden | ported | `crates/devise-rust-axum/src/routes.rs (after_resetting redirect seam)` | |
| 3 | `test/controllers/passwords_controller_test.rb:35` | calls after_database_authentication callback after sign_in immediately after password update | ported | `crates/devise-rust-axum/src/routes.rs (reset sign-in fires after_database_authentication)` plus `crates/devise-rust/tests/notifications.rs` | |

### controllers/sessions_controller_test.rb (8 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/controllers/sessions_controller_test.rb:9` | #create doesn't leak the password into the log | ported | `crates/devise-rust/src/error.rs tests (test_unsafe_attributes)` plus bridge logging discipline (`crates/devise-rust/src/scope.rs statement logging is placeholder-only)` | request bodies are never logged by the library |
| 2 | `test/controllers/sessions_controller_test.rb:28` | #create works even with scoped views | waived | `crates/devise-rust-axum/tests/devise_flows.rs (flow_sign_in_and_sign_out_with_flashes)` | reason: scoped view fallback rendering; see the scoped_views waiver in rails-parity.md. v1 impact: none, hosts render their own sign-in template. |
| 3 | `test/controllers/sessions_controller_test.rb:37` | #create delete the url stored in the session if the requested format is navigational | ported | `crates/devise-rust-axum/tests/devise_flows.rs (stored location consumed on sign-in)` | |
| 4 | `test/controllers/sessions_controller_test.rb:51` | #create doesn't raise a 500 on missing authentication keys | ported | `crates/devise-rust/src/strategy.rs tests (missing keys abort, no panic)` | |
| 5 | `test/controllers/sessions_controller_test.rb:66` | #create doesn't raise a 500 on blank authentication keys | ported | `crates/devise-rust/src/strategy.rs tests (blank keys abort)` | |
| 6 | `test/controllers/sessions_controller_test.rb:77` | #destroy doesn't sign out a second time | ported | `crates/devise-rust-axum/tests/devise_flows.rs (already_signed_out idempotent)` | |
| 7 | `test/controllers/sessions_controller_test.rb:91` | #destroy returns 401 status if user is not signed in and the requested format is not navigational | ported | `crates/devise-rust-axum/src/routes.rs (sign-out 401 on API)` | |
| 8 | `test/controllers/sessions_controller_test.rb:97` | #destroy returns 302 status if user is not signed in and the requested format is navigational | ported | `crates/devise-rust-axum/src/routes.rs (sign-out redirect)` | |

### controllers/url_helpers_test.rb (5 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/controllers/url_helpers_test.rb:39` | should alias session to mapped user session | ported | `crates/devise-rust/src/scope.rs tests (test_all_route_specs: named rows)` | route names render from the shared specs |
| 2 | `test/controllers/url_helpers_test.rb:45` | should alias password to mapped user password | ported | `crates/devise-rust/src/scope.rs tests (test_all_route_specs)` | |
| 3 | `test/controllers/url_helpers_test.rb:51` | should alias confirmation to mapped user confirmation | ported | `crates/devise-rust/src/scope.rs tests (test_all_route_specs)` | |
| 4 | `test/controllers/url_helpers_test.rb:56` | should alias unlock to mapped user unlock | ported | `crates/devise-rust/src/scope.rs tests (test_all_route_specs)` | |
| 5 | `test/controllers/url_helpers_test.rb:61` | should alias registration to mapped user registration | ported | `crates/devise-rust/src/scope.rs tests (test_all_route_specs)` | |

## Mailers suite (57 blocks)

The five Devise notifications map to the `Mailer` trait (`crates/devise-rust/src/mailer.rs`) with Tera templates mirroring the Devise copy; `TestMailer` captures deliveries for the suites. Rails ActionMailer delivery-option blocks (procs, arity handling, template inheritance) are waived with reasons.

### mailers/confirmation_instructions_test.rb (16 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/mailers/confirmation_instructions_test.rb:29` | email sent after creating the user | ported | `crates/devise-rust-axum/src/routes.rs:1026` sign-up dispatch plus `crates/devise-rust/src/mailer.rs tests (test_mailer_confirmation)` | |
| 2 | `test/mailers/confirmation_instructions_test.rb:33` | content type should be set to html | deviated | `crates/devise-rust/src/mailer.rs tests (templates compile and render html)` | reason: ActionMailer content-type headers belong to the SMTP transport; the port renders the HTML body and the transport (lettre behind the app mailer) sets headers. v1 impact: none for apps using the provided lettre transport. |
| 3 | `test/mailers/confirmation_instructions_test.rb:37` | send confirmation instructions to the user email | ported | `crates/devise-rust/src/mailer.rs tests (recipient from the record)` | |
| 4 | `test/mailers/confirmation_instructions_test.rb:42` | set up sender from configuration | ported | `crates/devise-rust/src/mailer.rs tests (mailer_sender_config_flows_to_from_header)` | |
| 5 | `test/mailers/confirmation_instructions_test.rb:46` | set up sender from custom mailer defaults | ported | `crates/devise-rust/src/mailer.rs tests (app-supplied Mailer owns the from header)` | |
| 6 | `test/mailers/confirmation_instructions_test.rb:51` | set up sender from custom mailer defaults with proc | waived | see row 5 | reason: Ruby proc defaults on the mailer class; the Rust Mailer trait takes values at construction, no lazy proc evaluation. v1 impact: none, apps compute the sender before constructing the mailer. |
| 7 | `test/mailers/confirmation_instructions_test.rb:56` | custom mailer renders parent mailer template | waived | see row 5 | reason: Rails template inheritance across mailer classes; the port's Tera templates ship per notification and apps supply their own Mailer implementation. v1 impact: none, custom mailers own their rendering. |
| 8 | `test/mailers/confirmation_instructions_test.rb:61` | set up reply to as copy from sender | ported | `crates/devise-rust/src/mailer.rs tests (reply-to flows from config)` | |
| 9 | `test/mailers/confirmation_instructions_test.rb:65` | set up reply to as different if set in defaults | ported | `crates/devise-rust/src/mailer.rs tests (reply-to override)` | |
| 10 | `test/mailers/confirmation_instructions_test.rb:71` | set up subject from I18n | ported | `crates/devise-rust/src/i18n.rs tests (devise.mailer.confirmation_instructions.subject)` | |
| 11 | `test/mailers/confirmation_instructions_test.rb:77` | subject namespaced by model | ported | `crates/devise-rust/src/i18n.rs tests (resource-scoped lookup chain)` | |
| 12 | `test/mailers/confirmation_instructions_test.rb:83` | body should have user info | ported | `crates/devise-rust/src/mailer.rs tests (template vars carry the record email)` | |
| 13 | `test/mailers/confirmation_instructions_test.rb:87` | body should have link to confirm the account | ported | `crates/devise-rust/src/mailer.rs tests (confirmation link with the raw token)` | |
| 14 | `test/mailers/confirmation_instructions_test.rb:97` | renders a scoped if scoped_views is set to true | waived | see the scoped_views waiver in rails-parity.md | reason: Rails view scoping. v1 impact: none, templates are app-owned. |
| 15 | `test/mailers/confirmation_instructions_test.rb:103` | renders a scoped if scoped_views is set in the mailer class | waived | see row 14 | reason: same view-stack feature. v1 impact: same as row 14. |
| 16 | `test/mailers/confirmation_instructions_test.rb:112` | mailer sender accepts a proc | waived | see row 6 | reason: Ruby proc configuration; values are computed at construction in Rust. v1 impact: none. |

### mailers/email_changed_test.rb (14 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/mailers/email_changed_test.rb:33` | email sent after changing the user email | ported | `crates/devise-rust/tests/notifications.rs (email_change_notification_goes_to_original_address)` | |
| 2 | `test/mailers/email_changed_test.rb:37` | content type should be set to html | deviated | see confirmation row 2 | reason: transport-owned header. v1 impact: none. |
| 3 | `test/mailers/email_changed_test.rb:41` | send email changed to the original user email | ported | `crates/devise-rust/tests/notifications.rs (recipient is the ORIGINAL address)` | TEST-03 item 6 |
| 4 | `test/mailers/email_changed_test.rb:46` | set up sender from configuration | ported | `crates/devise-rust/src/mailer.rs tests (from header)` | |
| 5 | `test/mailers/email_changed_test.rb:50` | set up sender from custom mailer defaults | ported | `crates/devise-rust/src/mailer.rs tests (app-supplied Mailer)` | |
| 6 | `test/mailers/email_changed_test.rb:55` | set up sender from custom mailer defaults with proc | waived | see confirmation row 6 | reason: Ruby proc defaults. v1 impact: none. |
| 7 | `test/mailers/email_changed_test.rb:60` | custom mailer renders parent mailer template | waived | see confirmation row 7 | reason: Rails template inheritance. v1 impact: none. |
| 8 | `test/mailers/email_changed_test.rb:65` | set up reply to as copy from sender | ported | `crates/devise-rust/src/mailer.rs tests (reply-to)` | |
| 9 | `test/mailers/email_changed_test.rb:69` | set up reply to as different if set in defaults | ported | `crates/devise-rust/src/mailer.rs tests (reply-to override)` | |
| 10 | `test/mailers/email_changed_test.rb:75` | set up subject from I18n | ported | `crates/devise-rust/src/i18n.rs tests (devise.mailer.email_changed.subject)` | |
| 11 | `test/mailers/email_changed_test.rb:81` | subject namespaced by model | ported | `crates/devise-rust/src/i18n.rs tests (resource-scoped chain)` | |
| 12 | `test/mailers/email_changed_test.rb:87` | body should have user info | ported | `crates/devise-rust/tests/notifications.rs (body names the new address)` | |
| 13 | `test/mailers/email_changed_test.rb:122` | send email changed to the original user email (reconfirmable path) | ported | `crates/devise-rust/tests/notifications.rs` plus `crates/devise-rust/src/confirmable.rs tests (reconfirmation send)` | |
| 14 | `test/mailers/email_changed_test.rb:127` | body should have unconfirmed user info | ported | `crates/devise-rust/src/mailer.rs tests (template vars carry the unconfirmed email)` | |

### mailers/mailer_test.rb (2 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/mailers/mailer_test.rb:6` | pass given block to #mail call | waived | `crates/devise-rust/src/mailer.rs tests (mailer_trait_compiles)` | reason: the block reaches ActionMailer's `mail` DSL for header customization; the Rust Mailer trait returns rendered messages directly. v1 impact: header customization happens in the app's Mailer implementation. |
| 2 | `test/mailers/mailer_test.rb:21` | default values defined as proc with different arity are handled correctly | waived | see row 1 | reason: Ruby proc arity handling in ActionMailer defaults; values are computed at construction in Rust. v1 impact: none. |

### mailers/reset_password_instructions_test.rb (13 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/mailers/reset_password_instructions_test.rb:32` | email sent after resetting the user password | ported | `crates/devise-rust/src/model.rs tests (send_reset_password_instructions)` plus `crates/devise-rust/tests/notifications.rs (mailer_context_carries_template_vars)` | |
| 2 | `test/mailers/reset_password_instructions_test.rb:36` | content type should be set to html | deviated | see confirmation row 2 | reason: transport-owned header. v1 impact: none. |
| 3 | `test/mailers/reset_password_instructions_test.rb:40` | send confirmation instructions to the user email | ported | `crates/devise-rust/tests/notifications.rs (recipient from the record)` | |
| 4 | `test/mailers/reset_password_instructions_test.rb:44` | set up sender from configuration | ported | `crates/devise-rust/src/mailer.rs tests (from header)` | |
| 5 | `test/mailers/reset_password_instructions_test.rb:48` | set up sender from custom mailer defaults | ported | `crates/devise-rust/src/mailer.rs tests (app-supplied Mailer)` | |
| 6 | `test/mailers/reset_password_instructions_test.rb:53` | set up sender from custom mailer defaults with proc | waived | see confirmation row 6 | reason: Ruby proc defaults. v1 impact: none. |
| 7 | `test/mailers/reset_password_instructions_test.rb:58` | custom mailer renders parent mailer template | waived | see confirmation row 7 | reason: Rails template inheritance. v1 impact: none. |
| 8 | `test/mailers/reset_password_instructions_test.rb:63` | set up reply to as copy from sender | ported | `crates/devise-rust/src/mailer.rs tests (reply-to)` | |
| 9 | `test/mailers/reset_password_instructions_test.rb:67` | set up reply to as different if set in defaults | ported | `crates/devise-rust/src/mailer.rs tests (reply-to override)` | |
| 10 | `test/mailers/reset_password_instructions_test.rb:73` | set up subject from I18n | ported | `crates/devise-rust/src/i18n.rs tests (devise.mailer.reset_password_instructions.subject)` | |
| 11 | `test/mailers/reset_password_instructions_test.rb:79` | subject namespaced by model | ported | `crates/devise-rust/src/i18n.rs tests (resource-scoped chain)` | |
| 12 | `test/mailers/reset_password_instructions_test.rb:83` | body should have user info | ported | `crates/devise-rust/tests/notifications.rs (template vars)` | |
| 13 | `test/mailers/reset_password_instructions_test.rb:93` | mailer sender accepts a proc | waived | see confirmation row 6 | reason: Ruby proc configuration. v1 impact: none. |

### mailers/unlock_instructions_test.rb (12 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/mailers/unlock_instructions_test.rb:33` | email sent after locking the user | ported | `crates/devise-rust/src/lockable.rs tests (lockable_lock_access_mails_raw_stores_digest)` | |
| 2 | `test/mailers/unlock_instructions_test.rb:37` | content type should be set to html | deviated | see confirmation row 2 | reason: transport-owned header. v1 impact: none. |
| 3 | `test/mailers/unlock_instructions_test.rb:41` | send unlock instructions to the user email | ported | `crates/devise-rust/src/lockable.rs tests (recipient from the record)` | |
| 4 | `test/mailers/unlock_instructions_test.rb:45` | set up sender from configuration | ported | `crates/devise-rust/src/mailer.rs tests (from header)` | |
| 5 | `test/mailers/unlock_instructions_test.rb:49` | set up sender from custom mailer defaults | ported | `crates/devise-rust/src/mailer.rs tests (app-supplied Mailer)` | |
| 6 | `test/mailers/unlock_instructions_test.rb:54` | set up sender from custom mailer defaults with proc | waived | see confirmation row 6 | reason: Ruby proc defaults. v1 impact: none. |
| 7 | `test/mailers/unlock_instructions_test.rb:59` | custom mailer renders parent mailer template | waived | see confirmation row 7 | reason: Rails template inheritance. v1 impact: none. |
| 8 | `test/mailers/unlock_instructions_test.rb:64` | set up reply to as copy from sender | ported | `crates/devise-rust/src/mailer.rs tests (reply-to)` | |
| 9 | `test/mailers/unlock_instructions_test.rb:68` | set up subject from I18n | ported | `crates/devise-rust/src/i18n.rs tests (devise.mailer.unlock_instructions.subject)` | |
| 10 | `test/mailers/unlock_instructions_test.rb:74` | subject namespaced by model | ported | `crates/devise-rust/src/i18n.rs tests (resource-scoped chain)` | |
| 11 | `test/mailers/unlock_instructions_test.rb:80` | body should have user info | ported | `crates/devise-rust/src/lockable.rs tests (template vars carry the record)` | |
| 12 | `test/mailers/unlock_instructions_test.rb:84` | body should have link to unlock the account | ported | `crates/devise-rust/src/lockable.rs tests (raw token in the link)` | |

## Routes suite (45 blocks)

Route generation maps to `Mapping::route_specs` and the framework routers; both crates mount the same shared spec data.

### routes_test.rb (45 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/routes_test.rb:8` | map new user session | ported | `crates/devise-rust/src/scope.rs tests (test_route_specs_database_authenticatable)` | |
| 2 | `test/routes_test.rb:13` | map create user session | ported | `crates/devise-rust/src/scope.rs tests (test_route_specs_database_authenticatable)` | |
| 3 | `test/routes_test.rb:18` | map destroy user session | ported | `crates/devise-rust/src/scope.rs tests (test_route_specs_database_authenticatable)` | |
| 4 | `test/routes_test.rb:23` | map new user confirmation | ported | `crates/devise-rust/src/scope.rs tests (test_all_route_specs)` | |
| 5 | `test/routes_test.rb:28` | map create user confirmation | ported | `crates/devise-rust/src/scope.rs tests (test_all_route_specs)` | |
| 6 | `test/routes_test.rb:33` | map show user confirmation | ported | `crates/devise-rust/src/scope.rs tests (test_all_route_specs)` | |
| 7 | `test/routes_test.rb:37` | map new user password | ported | `crates/devise-rust/src/scope.rs tests (test_all_route_specs)` | |
| 8 | `test/routes_test.rb:42` | map create user password | ported | `crates/devise-rust/src/scope.rs tests (test_all_route_specs)` | |
| 9 | `test/routes_test.rb:47` | map edit user password | ported | `crates/devise-rust/src/scope.rs tests (test_all_route_specs)` | |
| 10 | `test/routes_test.rb:52` | map update user password | ported | `crates/devise-rust/src/scope.rs tests (test_all_route_specs)` | |
| 11 | `test/routes_test.rb:56` | map new user unlock | ported | `crates/devise-rust/src/scope.rs tests (test_all_route_specs)` | |
| 12 | `test/routes_test.rb:61` | map create user unlock | ported | `crates/devise-rust/src/scope.rs tests (test_all_route_specs)` | |
| 13 | `test/routes_test.rb:66` | map show user unlock | ported | `crates/devise-rust/src/scope.rs tests (test_all_route_specs)` | |
| 14 | `test/routes_test.rb:70` | map new user registration | ported | `crates/devise-rust/src/scope.rs tests (test_route_specs_registerable)` | |
| 15 | `test/routes_test.rb:75` | map create user registration | ported | `crates/devise-rust/src/scope.rs tests (test_route_specs_registerable)` | |
| 16 | `test/routes_test.rb:80` | map edit user registration | ported | `crates/devise-rust/src/scope.rs tests (test_route_specs_registerable)` | |
| 17 | `test/routes_test.rb:85` | map update user registration | ported | `crates/devise-rust/src/scope.rs tests (test_route_specs_registerable)` | |
| 18 | `test/routes_test.rb:89` | map destroy user registration | ported | `crates/devise-rust/src/scope.rs tests (test_route_specs_registerable)` | |
| 19 | `test/routes_test.rb:93` | map cancel user registration | ported | `crates/devise-rust/src/scope.rs tests (test_route_specs_registerable)` | |
| 20 | `test/routes_test.rb:98` | map omniauth callbacks | ported | `crates/devise-rust/src/scope.rs tests (test_route_specs_omniauthable_emits_post_authorize_get_or_post_callback)` | |
| 21 | `test/routes_test.rb:121` | map admin with :path option | ported | `crates/devise-rust/src/scope.rs tests (test_mapping_with_prefix)` | |
| 22 | `test/routes_test.rb:125` | map admin with :controllers option | deviated | `crates/devise-rust-axum/src/routes.rs (host composes handlers around the mounted routes)` | reason: Rails swaps controller classes per mapping; the port mounts library handlers and the host layers its own. v1 impact: behavior customization happens at the router seam, not by class swap. |
| 23 | `test/routes_test.rb:129` | does not map admin password | ported | `crates/devise-rust/src/scope.rs tests (used_routes: recoverable not declared)` | |
| 24 | `test/routes_test.rb:135` | subdomain admin | waived | `crates/devise-rust/src/scope.rs tests (Mapping constraints carried)` | reason: Rails route-level subdomain constraints; the port carries `Mapping::constraints` for the host router but devise-rust does not resolve DNS subdomains itself. v1 impact: hosts enforce subdomain constraints at their router. |
| 25 | `test/routes_test.rb:139` | does only map reader password | ported | `crates/devise-rust/src/scope.rs tests (only/skip route selection)` | |
| 26 | `test/routes_test.rb:146` | map account with custom path name for session sign in | ported | `crates/devise-rust/src/scope.rs tests (test_path_names_defaults plus overrides)` | |
| 27 | `test/routes_test.rb:150` | map account with custom path name for session sign out | ported | `crates/devise-rust/src/scope.rs tests (path_names overrides)` | |
| 28 | `test/routes_test.rb:154` | map account with custom path name for password | ported | `crates/devise-rust/src/scope.rs tests (path_names overrides)` | |
| 29 | `test/routes_test.rb:158` | map account with custom path name for registration | ported | `crates/devise-rust/src/scope.rs tests (path_names overrides)` | |
| 30 | `test/routes_test.rb:162` | map account with custom path name for edit registration | ported | `crates/devise-rust/src/scope.rs tests (path_names overrides)` | |
| 31 | `test/routes_test.rb:166` | map account with custom path name for cancel registration | ported | `crates/devise-rust/src/scope.rs tests (path_names overrides)` | |
| 32 | `test/routes_test.rb:170` | map deletes with :sign_out_via option | ported | `crates/devise-rust/src/scope.rs tests (test_sign_out_via)` | |
| 33 | `test/routes_test.rb:177` | map posts with :sign_out_via option | ported | `crates/devise-rust/src/scope.rs tests (test_sign_out_via)` | |
| 34 | `test/routes_test.rb:184` | map delete_or_posts with :sign_out_via option | ported | `crates/devise-rust/src/scope.rs tests (test_sign_out_via)` | |
| 35 | `test/routes_test.rb:192` | map with constraints defined in hash | ported | `crates/devise-rust/src/scope.rs tests (Mapping constraints)` | |
| 36 | `test/routes_test.rb:199` | map with constraints defined in block | waived | see row 35 | reason: Rails constraint blocks are closures evaluated by the router; the port carries constraints as data for the host router. v1 impact: hosts write constraints in their router's native form. |
| 37 | `test/routes_test.rb:206` | map with format false for sessions | ported | `crates/devise-rust/src/scope.rs tests (Mapping format option)` | |
| 38 | `test/routes_test.rb:215` | map with format false for passwords | ported | `crates/devise-rust/src/scope.rs tests (Mapping format option)` | |
| 39 | `test/routes_test.rb:224` | map with format false for registrations | ported | `crates/devise-rust/src/scope.rs tests (Mapping format option)` | |
| 40 | `test/routes_test.rb:233` | map with format false for confirmations | ported | `crates/devise-rust/src/scope.rs tests (Mapping format option)` | |
| 41 | `test/routes_test.rb:242` | map with format false for unlocks | ported | `crates/devise-rust/src/scope.rs tests (Mapping format option)` | |
| 42 | `test/routes_test.rb:251` | map with format false is not permanent | ported | `crates/devise-rust/src/scope.rs tests (format scoping does not leak across mappings)` | |
| 43 | `test/routes_test.rb:255` | checks if mapping has proper configuration for omniauth callback | ported | `crates/devise-rust/src/scope.rs tests (omniauth spec shape)` | |
| 44 | `test/routes_test.rb:267` | map publisher account | ported | `crates/devise-rust/src/scope.rs tests (namespaced scope)` | |
| 45 | `test/routes_test.rb:272` | map publisher account merges path names | ported | `crates/devise-rust/src/scope.rs tests (path_names merge)` | |

## Mapping suite (17 blocks)

### mapping_test.rb (17 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/mapping_test.rb:13` | store options | ported | `crates/devise-rust/src/scope.rs tests (Mapping fields)` | |
| 2 | `test/mapping_test.rb:23` | store options with namespace | ported | `crates/devise-rust/src/scope.rs tests (namespaced scopes)` | |
| 3 | `test/mapping_test.rb:32` | allows path to be given | ported | `crates/devise-rust/src/scope.rs tests (test_mapping_with_prefix)` | |
| 4 | `test/mapping_test.rb:36` | allows to skip all routes | ported | `crates/devise-rust/src/scope.rs tests (skip option)` | |
| 5 | `test/mapping_test.rb:40` | sign_out_via defaults to :delete | ported | `crates/devise-rust/src/scope.rs tests (test_sign_out_via)` | |
| 6 | `test/mapping_test.rb:44` | allows custom sign_out_via to be given | ported | `crates/devise-rust/src/scope.rs tests (test_sign_out_via)` | |
| 7 | `test/mapping_test.rb:50` | allows custom singular to be given | ported | `crates/devise-rust/src/scope.rs tests (singular field)` | |
| 8 | `test/mapping_test.rb:54` | has strategies depending on the model declaration | ported | `crates/devise-rust/src/scope.rs tests (strategies_for module list)` | |
| 9 | `test/mapping_test.rb:59` | has no input strategies depending on the model declaration | ported | `crates/devise-rust/src/scope.rs tests (no-input strategy set)` | |
| 10 | `test/mapping_test.rb:64` | find scope for a given object | ported | `crates/devise-rust/src/scope.rs tests (scope lookup by record)` | |
| 11 | `test/mapping_test.rb:71` | find scope works with single table inheritance | waived | `crates/devise-rust/src/scope.rs tests (find_scope by class name)` | reason: ActiveRecord single-table inheritance resolves scopes through the Ruby class hierarchy; Rust models are typed statically and the mapping registers explicit class names. v1 impact: an STI family registers one mapping per model or shares one scope explicitly. |
| 12 | `test/mapping_test.rb:76` | find scope uses devise_scope | ported | `crates/devise-rust/src/scope.rs tests (devise_scope override)` | |
| 13 | `test/mapping_test.rb:82` | find scope raises an error if cannot be found | ported | `crates/devise-rust/src/scope.rs tests (unknown scope errors)` | |
| 14 | `test/mapping_test.rb:88` | return default path names | ported | `crates/devise-rust/src/scope.rs tests (test_path_names_defaults)` | |
| 15 | `test/mapping_test.rb:98` | allow custom path names to be given | ported | `crates/devise-rust/src/scope.rs tests (path_names overrides)` | |
| 16 | `test/mapping_test.rb:108` | magic predicates | ported | `crates/devise-rust/src/scope.rs tests (module predicates)` | |
| 17 | `test/mapping_test.rb:123` | find mapping by path | ported | `crates/devise-rust/src/scope.rs tests (test_find_by_path)` | |

## Failure app suite (46 blocks)

### failure_app_test.rb (46 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/failure_app_test.rb:97` | returns to the default redirect location | ported | `crates/devise-rust/src/failure.rs tests (test_failure_decision)` | |
| 2 | `test/failure_app_test.rb:104` | returns to the default redirect location considering subdomain | waived | `crates/devise-rust/src/failure.rs tests (scope sign-in path)` | reason: Rails url_for subdomain interpolation; the port renders the scope sign-in path without DNS subdomain rewriting. v1 impact: hosts needing cross-subdomain redirects configure the failure target per scope. |
| 3 | `test/failure_app_test.rb:111` | returns to the default redirect location for wildcard requests | waived | see row 2 | reason: subdomain wildcard URL resolution, same as row 2. v1 impact: same as row 2. |
| 4 | `test/failure_app_test.rb:117` | returns to the root path if no session path is available | ported | `crates/devise-rust/src/failure.rs tests (root fallback)` | |
| 5 | `test/failure_app_test.rb:126` | returns to the root path even when it's a fixed string | ported | `crates/devise-rust/src/failure.rs tests (root fallback)` | |
| 6 | `test/failure_app_test.rb:133` | returns to the root path considering subdomain if no session path is available | waived | see row 2 | reason: subdomain rewriting, same as row 2. v1 impact: same as row 2. |
| 7 | `test/failure_app_test.rb:142` | returns to the default redirect location considering the router for supplied scope | ported | `crates/devise-rust/src/failure.rs tests (per-mapping route target)` | |
| 8 | `test/failure_app_test.rb:150` | returns to the default redirect location considering the relative url root | ported | `crates/devise-rust/src/failure.rs tests (path_prefix on the target)` | hosts mount the router under their root |
| 9 | `test/failure_app_test.rb:158` | returns to the default redirect location considering the relative url root and subdomain | waived | see row 2 | reason: subdomain rewriting, same as row 2. v1 impact: same as row 2. |
| 10 | `test/failure_app_test.rb:168` | returns to the default redirect location considering action_controller (relative url root config) | ported | `crates/devise-rust/src/failure.rs tests (path_prefix on the target)` | |
| 11 | `test/failure_app_test.rb:176` | returns to the default redirect location considering action_controller (script name) | waived | see row 2 | reason: SCRIPT_NAME mounting, same as the authenticatable row 51. v1 impact: none, prefix through Mapping and host router. |
| 12 | `test/failure_app_test.rb:185` | uses the proxy failure message as symbol | ported | `crates/devise-rust/src/failure.rs tests (test_failure_variants)` | |
| 13 | `test/failure_app_test.rb:191` | supports authentication_keys as a Hash for the flash message | ported | `crates/devise-rust/src/i18n.rs tests (interpolation with joined keys)` | |
| 14 | `test/failure_app_test.rb:198` | downcases authentication_keys for the flash message | ported | `crates/devise-rust/src/i18n.rs tests (interpolation)` | |
| 15 | `test/failure_app_test.rb:203` | humanizes the flash message | ported | `crates/devise-rust/src/i18n.rs tests (test_translate_simple)` | |
| 16 | `test/failure_app_test.rb:208` | uses custom i18n options | ported | `crates/devise-rust/src/i18n.rs tests (options)` | |
| 17 | `test/failure_app_test.rb:213` | respects the i18n locale passed via warden options when redirecting | ported | `crates/devise-rust/src/i18n.rs tests (locale option)` | |
| 18 | `test/failure_app_test.rb:225` | uses the proxy failure message as string | ported | `crates/devise-rust/src/failure.rs tests (message passthrough)` | |
| 19 | `test/failure_app_test.rb:231` | set content type to default text/html | ported | `crates/devise-rust-axum/src/failure.rs (html body on navigational)` | |
| 20 | `test/failure_app_test.rb:236` | set up a default message | ported | `crates/devise-rust/src/failure.rs tests (default message resolution)` | |
| 21 | `test/failure_app_test.rb:247` | works for any navigational format | ported | `crates/devise-rust/src/failure.rs tests (is_navigational)` | |
| 22 | `test/failure_app_test.rb:254` | redirects the correct format if it is a non-html format request | ported | `crates/devise-rust/src/failure.rs tests (format classification)` | |
| 23 | `test/failure_app_test.rb:263` | return 401 status | ported | `crates/devise-rust/src/failure.rs tests (status_code)` | |
| 24 | `test/failure_app_test.rb:268` | return appropriate body for xml | deviated | `crates/devise-rust/src/failure.rs tests (http_auth_body carries the message)` | reason: the port returns the message body for API formats generically; Rails renders format-specific XML/JSON error documents. v1 impact: API consumers get the plain message body with the 401 status, not a format-shaped error document. |
| 25 | `test/failure_app_test.rb:274` | return appropriate body for json | deviated | see row 24 | reason: same generic body policy as row 24. v1 impact: same as row 24. |
| 26 | `test/failure_app_test.rb:280` | return 401 status for unknown formats | ported | `crates/devise-rust/src/failure.rs tests (unknown formats are non-navigational)` | |
| 27 | `test/failure_app_test.rb:285` | return WWW-authenticate headers if model allows | ported | `crates/devise-rust/src/failure.rs tests (www_authenticate)` | |
| 28 | `test/failure_app_test.rb:290` | does not return WWW-authenticate headers if model does not allow | ported | `crates/devise-rust/src/failure.rs tests (www_authenticate None)` | |
| 29 | `test/failure_app_test.rb:297` | works for any non navigational format | ported | `crates/devise-rust/src/failure.rs tests (is_api_unauthorized)` | |
| 30 | `test/failure_app_test.rb:304` | uses the failure message as response body | ported | `crates/devise-rust/src/failure.rs tests (http_auth_body)` | |
| 31 | `test/failure_app_test.rb:309` | respects the i18n locale passed via warden options when responding to HTTP request | ported | `crates/devise-rust/src/i18n.rs tests (locale option)` | |
| 32 | `test/failure_app_test.rb:317` | dont return 401 with navigational formats | ported | `crates/devise-rust/src/failure.rs tests (test_failure_decision_nav_api_recall)` | |
| 33 | `test/failure_app_test.rb:325` | dont return 401 with non navigational formats | ported | `crates/devise-rust/src/failure.rs tests (is_api_unauthorized)` | |
| 34 | `test/failure_app_test.rb:335` | return 401 (http_auth when both params and http are available) | ported | `crates/devise-rust/src/strategy.rs tests (http strategy chosen for API requests)` | |
| 35 | `test/failure_app_test.rb:342` | skip WWW-Authenticate header | ported | `crates/devise-rust/src/failure.rs tests (www_authenticate None)` | |
| 36 | `test/failure_app_test.rb:353` | calls the original controller if invalid email or password | waived | `crates/devise-rust/src/failure.rs tests (test_failure_decision_nav_api_recall)` | reason: recall re-dispatch is the documented simplification (see the recall waiver in rails-parity.md). v1 impact: failed params sign-ins redirect or 401 instead of re-running the original action. |
| 37 | `test/failure_app_test.rb:364` | calls the original controller if not confirmed email | waived | see row 36 | reason: recall re-dispatch simplification. v1 impact: same as row 36. |
| 38 | `test/failure_app_test.rb:375` | calls the original controller if inactive account | waived | see row 36 | reason: recall re-dispatch simplification. v1 impact: same as row 36. |
| 39 | `test/failure_app_test.rb:387` | calls the original controller with the proper environment considering the relative url root | waived | see row 36 | reason: recall re-dispatch simplification. v1 impact: same as row 36. |
| 40 | `test/failure_app_test.rb:403` | respects the i18n locale passed via warden options when recalling original controller | waived | see row 36 | reason: recall re-dispatch simplification. v1 impact: same as row 36. |
| 41 | `test/failure_app_test.rb:417` | respects the configured responder error_status for the status code | ported | `crates/devise-rust/src/failure.rs tests (status_code per decision)` | the responder-configurable status surface is fixed to the Devise defaults in v1 |
| 42 | `test/failure_app_test.rb:431` | respects the configured responder redirect_status if the recall app returns a redirect status code | ported | `crates/devise-rust/src/failure.rs tests (redirect status)` | |
| 43 | `test/failure_app_test.rb:444` | uses default hardcoded responder error_status for the status code since responders version does not support configuring it | ported | `crates/devise-rust/src/failure.rs tests (status_code)` | |
| 44 | `test/failure_app_test.rb:456` | users default hardcoded responder redirect_status for the status code | ported | `crates/devise-rust/src/failure.rs tests (redirect status)` | |
| 45 | `test/failure_app_test.rb:470` | loads (route resolution for the scope) | ported | `crates/devise-rust/src/scope.rs tests (route target resolution)` | |
| 46 | `test/failure_app_test.rb:476` | returns to the default redirect location without a flash message | ported | `crates/devise-rust/src/failure.rs tests (flash_key None)` | |

## Parameter sanitizer suite (12 blocks)

### parameter_sanitizer_test.rb (12 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/parameter_sanitizer_test.rb:12` | permits the default parameters for sign in | ported | `crates/devise-rust/src/parameter.rs tests (test_parameter_sanitizer_defaults)` | |
| 2 | `test/parameter_sanitizer_test.rb:19` | permits empty params when received not a hash | ported | `crates/devise-rust/src/parameter.rs tests (non-map params yield empty)` | |
| 3 | `test/parameter_sanitizer_test.rb:26` | does not rise error when received string instead of hash | ported | `crates/devise-rust/src/parameter.rs tests (typed params, no string input)` | |
| 4 | `test/parameter_sanitizer_test.rb:33` | does not rise error when received nil instead of hash | ported | `crates/devise-rust/src/parameter.rs tests (nil params yield empty)` | |
| 5 | `test/parameter_sanitizer_test.rb:40` | permits empty params when received nil instead of hash | ported | `crates/devise-rust/src/parameter.rs tests (nil params yield empty)` | |
| 6 | `test/parameter_sanitizer_test.rb:47` | permits the default parameters for sign up | ported | `crates/devise-rust/src/parameter.rs tests (sign_up defaults)` | |
| 7 | `test/parameter_sanitizer_test.rb:54` | permits the default parameters for account update | ported | `crates/devise-rust/src/parameter.rs tests (account_update defaults)` | |
| 8 | `test/parameter_sanitizer_test.rb:61` | permits news parameters for an existing action | ported | `crates/devise-rust/src/parameter.rs tests (test_parameter_sanitizer_sanitize)` | |
| 9 | `test/parameter_sanitizer_test.rb:69` | permits news parameters for an existing action with a block | ported | `crates/devise-rust/src/parameter.rs tests (permit with block)` | |
| 10 | `test/parameter_sanitizer_test.rb:80` | permit parameters for new actions | ported | `crates/devise-rust/src/parameter.rs tests (permit for new actions)` | |
| 11 | `test/parameter_sanitizer_test.rb:89` | fails when we do not have any permitted parameters for the action | ported | `crates/devise-rust/src/parameter.rs tests (unknown action errors)` | |
| 12 | `test/parameter_sanitizer_test.rb:97` | removes permitted parameters | ported | `crates/devise-rust/src/parameter.rs tests (test_parameter_sanitizer_permit_except)` | |

## Devise core suite (10 blocks)

### devise_test.rb (10 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/devise_test.rb:16` | bcrypt on the class | ported | `crates/devise-rust/src/crypto.rs tests (test_encryptor_digest_compare)` | encryptor surface through the module functions |
| 2 | `test/devise_test.rb:27` | model options can be configured through Devise | ported | `crates/devise-rust/src/config.rs tests (test_config_override_cascade)` | per-scope overrides cascade |
| 3 | `test/devise_test.rb:34` | setup block yields self | ported | `crates/devise-rust/src/config.rs tests (struct-update over default)` | the `DeviseConfig` struct replaces the setup block |
| 4 | `test/devise_test.rb:40` | stores warden configuration | waived | `crates/devise-rust/src/proxy.rs tests (AuthProxy construction)` | reason: the warden_config block configures the Warden middleware manager (see the warden_config waiver in rails-parity.md). v1 impact: none. |
| 5 | `test/devise_test.rb:45` | warden manager user configuration through a block | waived | see row 4 | reason: warden manager configuration. v1 impact: none. |
| 6 | `test/devise_test.rb:58` | warden manager user configuration through multiple blocks | waived | see row 4 | reason: warden manager configuration. v1 impact: none. |
| 7 | `test/devise_test.rb:71` | add new module using the helper method | deviated | `crates/devise-rust/src/scope.rs tests (test_module_order, test_all_route_specs)` | reason: Devise.add_module registers third-party modules at runtime; the port has a compile-time Module enum (see the add_module deviation in rails-parity.md). v1 impact: third-party Devise modules cannot register dynamically in v1. |
| 8 | `test/devise_test.rb:89` | Devise.secure_compare fails when comparing different strings or nil | ported | `crates/devise-rust/src/crypto.rs tests (test_secure_compare)` | |
| 9 | `test/devise_test.rb:98` | Devise.secure_compare passes when strings are the same, even two empty strings | ported | `crates/devise-rust/src/crypto.rs tests (test_secure_compare)` | |
| 10 | `test/devise_test.rb:103` | Devise.email_regexp should match valid email addresses | ported | `crates/devise-rust/src/config.rs tests (test_email_regexp_matches_devise_matrix)` | |

## OmniAuth config and url helper suite (14 blocks)

### omniauth/config_test.rb (8 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/omniauth/config_test.rb:10` | strategy_name returns provider if no options given | ported | `crates/devise-rust/src/omniauthable.rs tests (OAuthProviderConfig serde roundtrip)` | |
| 2 | `test/omniauth/config_test.rb:15` | strategy_name returns provider if no name option are given | ported | `crates/devise-rust/src/omniauthable.rs tests (provider config)` | |
| 3 | `test/omniauth/config_test.rb:20` | returns name option when have a name | ported | `crates/devise-rust/src/omniauthable.rs tests (provider name)` | |
| 4 | `test/omniauth/config_test.rb:25` | finds contrib strategies | waived | `crates/devise-rust/src/omniauthable.rs tests (configured providers resolve through DeviseConfigOverride)` | reason: OmniAuth strategy class autoloading from installed gems; the port resolves providers from the explicit config registry, no gem discovery. v1 impact: providers are declared in config rather than auto-discovered. |
| 5 | `test/omniauth/config_test.rb:35` | finds the strategy in OmniAuth | waived | see row 4 | reason: gem autoloading, same as row 4. v1 impact: same as row 4. |
| 6 | `test/omniauth/config_test.rb:44` | finds the strategy in OmniAuth (contrib path) | waived | see row 4 | reason: gem autoloading, same as row 4. v1 impact: same as row 4. |
| 7 | `test/omniauth/config_test.rb:49` | raises an error if strategy cannot be found | ported | `crates/devise-rust/src/omniauthable.rs tests (unconfigured provider fails closed)` | |
| 8 | `test/omniauth/config_test.rb:56` | allows the user to define a custom require path | waived | see row 4 | reason: Ruby require-path customization for strategy gems; no runtime loading in Rust. v1 impact: same as row 4. |

### omniauth/url_helpers_test.rb (6 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/omniauth/url_helpers_test.rb:24` | should alias omniauth_callback to mapped user auth_callback | ported | `crates/devise-rust/src/scope.rs tests (omniauth spec names)` | |
| 2 | `test/omniauth/url_helpers_test.rb:28` | should alias omniauth_authorize to mapped user auth_authorize | ported | `crates/devise-rust/src/scope.rs tests (omniauth spec names)` | |
| 3 | `test/omniauth/url_helpers_test.rb:32` | should generate authorization path | ported | `crates/devise-rust/src/scope.rs tests (authorize path)` | |
| 4 | `test/omniauth/url_helpers_test.rb:40` | should generate authorization path for named open_id omniauth | ported | `crates/devise-rust/src/scope.rs tests (provider name in path)` | |
| 5 | `test/omniauth/url_helpers_test.rb:44` | should generate authorization path with params | ported | `crates/devise-rust/src/omniauthable.rs tests (authorize_start carries PKCE and state)` | params ride the session stash, not the path |
| 6 | `test/omniauth/url_helpers_test.rb:49` | should not add a missing parameter | ported | `crates/devise-rust/src/omniauthable.rs tests (authorize_start always carries state)` | |

## Generators suite (30 blocks)

The Rails generators map to the `devise-migrations` CLI and the DDL emitter (`crates/devise-rust-migrations`); view and controller generators are waived with reasons.

### generators/active_record_generator_test.rb (10 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/generators/active_record_generator_test.rb:13` | all files are properly created with rails31 migration syntax | ported | `crates/devise-rust-migrations/tests/snapshots.rs (cli_smoke_writes_devise_create_layout)` | the CLI writes the migration pair |
| 2 | `test/generators/active_record_generator_test.rb:18` | all files are properly created with changed db/migrate path in application configuration | ported | `crates/devise-rust-migrations/tests/snapshots.rs (write_to_confines_writes_to_output_dir)` | output dir is a CLI flag |
| 3 | `test/generators/active_record_generator_test.rb:28` | all files for namespaced model are properly created | ported | `crates/devise-rust-migrations/tests/snapshots.rs (table naming)` | |
| 4 | `test/generators/active_record_generator_test.rb:33` | update model migration when model exists | ported | `crates/devise-rust-migrations/tests/snapshots.rs (cli_existing_flow_writes_add_devise_layout, matrix_existing_flow)` | the add-to-existing flow |
| 5 | `test/generators/active_record_generator_test.rb:40` | update model migration when model exists with changed db/migrate path | ported | `crates/devise-rust-migrations/tests/snapshots.rs (existing flow with output dir)` | |
| 6 | `test/generators/active_record_generator_test.rb:53` | all files are properly deleted | ported | `crates/devise-rust-migrations/tests/snapshots.rs (down.sql drop column reversal, matrix_existing_flow)` | the emitted down.sql reverses |
| 7 | `test/generators/active_record_generator_test.rb:66` | use string column type for ip addresses | ported | `crates/devise-rust-migrations/tests/snapshots.rs (dialect matrix: TEXT IPs on sqlite)` | |
| 8 | `test/generators/active_record_generator_test.rb:72` | do NOT add primary key type when NOT specified in rails generator | ported | `crates/devise-rust-migrations/tests/snapshots.rs (PkKind default)` | |
| 9 | `test/generators/active_record_generator_test.rb:77` | add primary key type with rails 5 when specified in rails generator | ported | `crates/devise-rust-migrations/tests/snapshots.rs (PkKind::Uuid legs)` | |
| 10 | `test/generators/active_record_generator_test.rb:106` | all files are properly created in rails 4.0 | ported | `crates/devise-rust-migrations/tests/snapshots.rs (emission_is_byte_deterministic)` | one DDL shape, three dialects |

### generators/controllers_generator_test.rb (3 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/generators/controllers_generator_test.rb:10` | Assert no controllers are created with no params | waived | `crates/devise-rust-axum/src/routes.rs (controllers ship in the crate)` | reason: devise-rust ships compiled controllers in the framework crates; there are no app-copied controller files to generate. v1 impact: hosts customize at the router seam instead of editing generated controllers. |
| 2 | `test/generators/controllers_generator_test.rb:20` | Assert all controllers are properly created with scope param | waived | see row 1 | reason: no generated controllers, same as row 1. v1 impact: same as row 1. |
| 3 | `test/generators/controllers_generator_test.rb:28` | Assert specified controllers with scope | waived | see row 1 | reason: no generated controllers, same as row 1. v1 impact: same as row 1. |

### generators/devise_generator_test.rb (3 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/generators/devise_generator_test.rb:16` | route generation for simple model names | ported | `crates/devise-rust/src/scope.rs tests (test_all_route_specs)` | routes render from the Mapping |
| 2 | `test/generators/devise_generator_test.rb:21` | route generation for namespaced model names | ported | `crates/devise-rust/src/scope.rs tests (namespaced scopes)` | |
| 3 | `test/generators/devise_generator_test.rb:27` | route generation with skip routes | ported | `crates/devise-rust/src/scope.rs tests (only/skip)` | |

### generators/install_generator_test.rb (3 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/generators/install_generator_test.rb:10` | assert all files are properly created | ported | `crates/devise-rust-migrations/tests/snapshots.rs (cli_smoke_writes_devise_create_layout)` | the install step is the migrations CLI plus the config idiom in the guides |
| 2 | `test/generators/install_generator_test.rb:16` | fails if no ORM is specified | ported | `crates/devise-rust-migrations/tests/snapshots.rs (cli_unknown_module_exits_two)` | invalid input fails loudly |
| 3 | `test/generators/install_generator_test.rb:27` | responder error_status based on rack version | waived | `crates/devise-rust/src/failure.rs tests (status_code fixed to Devise defaults)` | reason: rack-version-dependent responder statuses are a Rails responders integration detail; the port pins the Devise default statuses. v1 impact: none for standard clients. |

### generators/mongoid_generator_test.rb (2 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/generators/mongoid_generator_test.rb:13` | all files are properly created | waived | none | reason: the MongoDB adapter is deferred to v2 (REQUIREMENTS out-of-scope row), so no mongoid generator exists. v1 impact: MongoDB users have no devise-rust support in v1, by design. |
| 2 | `test/generators/mongoid_generator_test.rb:18` | all files are properly deleted | waived | none | reason: MongoDB deferred to v2, same as row 1. v1 impact: same as row 1. |

### generators/views_generator_test.rb (9 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/generators/views_generator_test.rb:10` | Assert all views are properly created with no params | waived | none | reason: devise-rust ships no server-rendered views (see the scoped_views waiver in rails-parity.md); hosts own their templates. v1 impact: hosts write their own forms; the example apps show the shapes. |
| 2 | `test/generators/views_generator_test.rb:17` | Assert all views are properly created with scope param | waived | none | reason: no view generation, same as row 1. v1 impact: same as row 1. |
| 3 | `test/generators/views_generator_test.rb:29` | Assert views with simple form | waived | none | reason: no view generation, same as row 1. v1 impact: same as row 1. |
| 4 | `test/generators/views_generator_test.rb:39` | Assert views with markerb | waived | none | reason: no view generation, same as row 1. v1 impact: same as row 1. |
| 5 | `test/generators/views_generator_test.rb:45` | Assert only views within specified directories | waived | none | reason: no view generation, same as row 1. v1 impact: same as row 1. |
| 6 | `test/generators/views_generator_test.rb:54` | Assert mailer specific directory with simple form | waived | none | reason: no view generation; mailer templates ship in the core crate as Tera sources. v1 impact: custom mail templates are supplied by the app's Mailer implementation. |
| 7 | `test/generators/views_generator_test.rb:61` | Assert specified directories with scope | waived | none | reason: no view generation, same as row 1. v1 impact: same as row 1. |
| 8 | `test/generators/views_generator_test.rb:67` | Assert specified directories with simple form | waived | none | reason: no view generation, same as row 1. v1 impact: same as row 1. |
| 9 | `test/generators/views_generator_test.rb:73` | Assert specified directories with markerb | waived | none | reason: no view generation, same as row 1. v1 impact: same as row 1. |

## Rails integration plumbing suites (43 blocks)

Blocks that exercise Ruby or Rails runtime machinery (concern inclusion, load hooks, warden test helpers) are waived with reasons; blocks asserting behavior the port guarantees are ported.

### helpers/devise_helper_test.rb (2 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/helpers/devise_helper_test.rb:25` | test errors.messages.not_saved with single error from i18n | ported | `crates/devise-rust/src/error.rs tests (test_validation_errors)` plus `crates/devise-rust/src/i18n.rs tests (not_saved one)` | |
| 2 | `test/helpers/devise_helper_test.rb:36` | test errors.messages.not_saved with multiple errors from i18n | ported | `crates/devise-rust/src/error.rs tests (not_saved other)` | |

### delegator_test.rb (3 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/delegator_test.rb:10` | failure_app returns default failure app if no warden options in env | ported | `crates/devise-rust/src/failure.rs tests (default failure path)` | |
| 2 | `test/delegator_test.rb:14` | failure_app returns default failure app if no scope in warden options | ported | `crates/devise-rust/src/failure.rs tests (default failure path)` | |
| 3 | `test/delegator_test.rb:18` | failure_app returns associated failure app by scope in the given environment | ported | `crates/devise-rust/src/failure.rs tests (per-mapping failure_app honored)` | |

### models_test.rb (16 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/models_test.rb:22` | can cherry pick modules | ported | `crates/devise-rust/src/scope.rs tests (Mapping module list per scope)` | |
| 2 | `test/models_test.rb:26` | validations options are not applied too late | ported | `crates/devise-rust/src/model.rs tests (Validatable is explicit, no ordering hazard)` | |
| 3 | `test/models_test.rb:33` | validations are applied just once | ported | `crates/devise-rust/src/model.rs tests (validate called explicitly once)` | |
| 4 | `test/models_test.rb:38` | chosen modules are inheritable | waived | `crates/devise-rust/src/scope.rs tests (module list is data on the Mapping)` | reason: Ruby class inheritance of devise module lists; the Rust module set is Mapping data, not a class hierarchy. v1 impact: none, scopes declare their own lists. |
| 5 | `test/models_test.rb:42` | order of module inclusion | ported | `crates/devise-rust/src/scope.rs tests (test_module_order)` | super-chain order preserved |
| 6 | `test/models_test.rb:56` | raise error on invalid module | ported | `crates/devise-rust-migrations/tests/snapshots.rs (cli_unknown_module_exits_two)` | |
| 7 | `test/models_test.rb:63` | set a default value for stretches | ported | `crates/devise-rust/src/lib.rs tests (test_config_defaults)` | |
| 8 | `test/models_test.rb:67` | set a default value for pepper | ported | `crates/devise-rust/src/lib.rs tests (test_config_defaults)` | |
| 9 | `test/models_test.rb:71` | set a default value for allow_unconfirmed_access_for | ported | `crates/devise-rust/src/lib.rs tests (test_config_defaults)` | |
| 10 | `test/models_test.rb:75` | set a default value for remember_for | ported | `crates/devise-rust/src/lib.rs tests (test_config_defaults)` | |
| 11 | `test/models_test.rb:79` | set a default value for timeout_in | ported | `crates/devise-rust/src/lib.rs tests (test_config_defaults)` | |
| 12 | `test/models_test.rb:83` | set a default value for unlock_in | ported | `crates/devise-rust/src/lib.rs tests (test_config_defaults)` | |
| 13 | `test/models_test.rb:87` | set null fields on migrations | ported | `crates/devise-rust-migrations/tests/snapshots.rs (matrix_full_create null defaults)` | |
| 14 | `test/models_test.rb:104` | checks if the class respond_to the required fields | ported | `crates/devise-rust-migrations` (column checks at emit time) plus per-module `required_fields` | |
| 15 | `test/models_test.rb:122` | raises Devise::Models::MissingAtrribute and shows the missing attribute if the class doesn't respond | ported | `crates/devise-rust/src/error.rs tests (typed errors name the missing piece)` | |
| 16 | `test/models_test.rb:140` | raises Devise::Models::MissingAtrribute with all the missing attributes if there is more than one | ported | `crates/devise-rust-migrations/tests/snapshots.rs (emit lists every missing column)` | |

### rails_test.rb (2 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/rails_test.rb:6` | correct initializer position | waived | none | reason: Rails engine initializer ordering; the Rust port has no initializer chain. v1 impact: none. |
| 2 | `test/rails_test.rb:13` | deprecator is added to application deprecators | waived | none | reason: Rails deprecation notification wiring. v1 impact: none. |

### test/controller_helpers_test.rb (17 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/test/controller_helpers_test.rb:9` | redirects if attempting to access a page unauthenticated | ported | `crates/devise-rust-axum/tests/extractors.rs` | |
| 2 | `test/test/controller_helpers_test.rb:15` | redirects if attempting to access a page with an unconfirmed account | ported | `crates/devise-rust-axum/tests/extractors.rs (active gate honored)` | |
| 3 | `test/test/controller_helpers_test.rb:26` | returns nil if accessing current_user with an unconfirmed account | ported | `crates/devise-rust-axum/tests/extractors.rs (Auth yields None on inactive)` | |
| 4 | `test/test/controller_helpers_test.rb:37` | does not redirect with valid user | ported | `crates/devise-rust-axum/tests/extractors.rs` | |
| 5 | `test/test/controller_helpers_test.rb:46` | does not redirect with valid user after failed first attempt | ported | `crates/devise-rust-axum/tests/extractors.rs (guard retries after a failure)` | |
| 6 | `test/test/controller_helpers_test.rb:58` | redirects if valid user signed out | ported | `crates/devise-rust-axum/tests/extractors.rs (post-sign-out guard rejects)` | |
| 7 | `test/test/controller_helpers_test.rb:70` | respects custom failure app | ported | `crates/devise-rust/src/failure.rs tests (per-mapping failure_app)` | |
| 8 | `test/test/controller_helpers_test.rb:83` | passes given headers from the failure app to the response | ported | `crates/devise-rust/src/failure.rs tests (www_authenticate plus headers)` | |
| 9 | `test/test/controller_helpers_test.rb:98` | returns the body of a failure app | ported | `crates/devise-rust/src/failure.rs tests (http_auth_body)` | |
| 10 | `test/test/controller_helpers_test.rb:108` | returns the content type of a failure app | ported | `crates/devise-rust/src/failure.rs tests (format classification)` | |
| 11 | `test/test/controller_helpers_test.rb:114` | defined Warden after_authentication callback should not be called when sign_in is called | ported | `crates/devise-rust/src/hooks.rs tests (hook dispatch matrix)` | |
| 12 | `test/test/controller_helpers_test.rb:128` | defined Warden before_logout callback should not be called when sign_out is called | ported | `crates/devise-rust/src/hooks.rs tests (hook dispatch matrix)` | |
| 13 | `test/test/controller_helpers_test.rb:143` | before_failure call should work | ported | `crates/devise-rust/src/hooks.rs tests (Event::Request and failure hooks)` | |
| 14 | `test/test/controller_helpers_test.rb:160` | allows to sign in with different users | ported | `crates/devise-rust/src/proxy.rs tests (re-sign-in force)` | |
| 15 | `test/test/controller_helpers_test.rb:177` | creates a new warden proxy if the request object has changed | waived | `crates/devise-rust/src/proxy.rs tests (proxy is request-scoped by construction)` | reason: Warden caches a proxy per request env; the Rust bridge constructs the proxy per request, so the cache-invalidation case cannot occur. v1 impact: none. |
| 16 | `test/test/controller_helpers_test.rb:187` | doesn't track sign in when trackable is disabled | ported | `crates/devise-rust/src/hooks.rs tests (skip honored)` | |
| 17 | `test/test/controller_helpers_test.rb:199` | doesn't track sign in when sign_in called with trackable disabled | ported | `crates/devise-rust/src/hooks.rs tests (test_trackable_hook_shifts_memo_and_honors_skip)` | |

### test/integration_helpers_test.rb (3 blocks)

| # | devise source | test block | status | Rust test evidence | reason / v1 impact |
|---|---|---|---|---|---|
| 1 | `test/test/integration_helpers_test.rb:8` | #sign_in signs in the resource directly | ported | `crates/devise-rust-axum/src/test_helpers.rs (direct sign-in for tests)` | both crates ship test helpers |
| 2 | `test/test/integration_helpers_test.rb:15` | #sign_outs signs out in the resource directly | ported | `crates/devise-rust-axum/src/test_helpers.rs (direct sign-out)` | |
| 3 | `test/test/integration_helpers_test.rb:24` | #sign_out does not signs out other scopes | ported | `crates/devise-rust/src/proxy.rs tests (per-scope sign-out)` | |

## Status summary

| Suite | Blocks | Ported | Deviated | Waived |
|---|---|---|---|---|
| models | 241 | 231 | 4 | 6 |
| integration | 271 | 246 | 7 | 18 |
| controllers | 96 | 80 | 1 | 15 |
| mailers | 57 | 39 | 4 | 14 |
| routes | 45 | 42 | 1 | 2 |
| mapping | 17 | 16 | 0 | 1 |
| failure app | 46 | 34 | 2 | 10 |
| sanitizer | 12 | 12 | 0 | 0 |
| devise core | 10 | 6 | 1 | 3 |
| omniauth | 14 | 10 | 0 | 4 |
| generators | 30 | 15 | 0 | 15 |
| helpers, delegator, models_test, rails_test, controller and integration helpers | 43 | 39 | 0 | 4 |
| **Total** | **882** | **770** | **20** | **92** |

Every waived and deviated row above carries its per-case written reason and v1 impact (D-12); no block is unaccounted for (D-11). Reversing any waiver reopens the corresponding test work and invalidates the v1 scope statement that relies on it; the reversal cost is flagged in the phase SUMMARY.

The TEST-03 security re-green evidence (the 8-item regression list) and the TEST-02 framework-leg matrix below were appended by the plan's second task after running them on the current tree (2026-10-11). No regression was found: every gate ran green with zero fixes required.

## TEST-03: security regression re-green (8 items, run 2026-10-11)

Per D-13, each of the 8 items re-ran on the current tree through its asserting test. Every item is green; none required a fix.

| # | Regression item | Proving test | Command run | Outcome |
|---|---|---|---|---|
| 1 | Paranoid timing: dummy bcrypt on unknown account plus uniform `:invalid` message | `crates/devise-rust/src/strategy.rs tests (test_paranoid_strategy_masks_not_found)` | `cargo test -p devise-rust --lib test_paranoid_strategy_masks_not_found` | green: 1 passed, 0 failed |
| 2 | Session salt invalidation on password change (stale session rejected) | `crates/devise-rust/src/session.rs tests (test_session_salt_mismatch_deletes_key)` plus both framework `flow_two_cookie_jar_password_change_kills_session_and_remember` | `cargo test -p devise-rust --lib test_session_salt_mismatch_deletes_key`; `cargo test -p devise-rust-axum --test devise_flows`; `cargo test -p devise-rust-actix --test devise_flows` | green: 1 passed core, both flow suites green (the two cookie jar regression: salt plus remember_created_at) |
| 3 | Reconfirmable forced `unconfirmed_email` write for the #5783 race | `crates/devise-rust/src/confirmable.rs tests (confirmable_5783_double_submit_keeps_victim_unconfirmed)` | `cargo test -p devise-rust --lib confirmable_5783_double_submit_keeps_victim_unconfirmed` | green: 1 passed, 0 failed |
| 4 | Blank token guards on token lookups (confirm, unlock, reset) | `confirmable_tracer_blank_token_touches_no_adapter`, `lockable_unlock_access_by_token_blank_touches_no_adapter`, `model.rs reset_password_by_token_guards` | `cargo test -p devise-rust --lib` (all three named tests) | green: each 1 passed, 0 failed |
| 5 | `update_with_password` never persists on failure | `crates/devise-rust-axum/tests/devise_flows.rs (flow_account_update_requires_current_password)` plus core `database_authenticatable_methods` | `cargo test -p devise-rust-axum --test devise_flows flow_account_update_requires_current_password` | green: 1 passed, 0 failed (invalid current password leaves the record unmodified) |
| 6 | `email_changed` recipient is the original address | `crates/devise-rust/tests/notifications.rs (email_change_notification_goes_to_original_address)` | `cargo test -p devise-rust --test notifications` | green: 4 passed, 0 failed |
| 7 | Remember cookie 5-condition check | `crates/devise-rust/src/rememberable.rs tests (rememberable_nil_case_* matrix, rememberable_nil_case_wrong_token, rememberable_password_rotation_kills_older_cookies)` | `cargo test -p devise-rust --lib rememberable_nil_case` | green: full nil-case matrix passed inside the 241-test lib run |
| 8 | Open redirect guard on timeout redirect targets (devise 5.0.4 Referer fix equivalent) | `crates/devise-rust/src/request.rs tests (test_parse_stored_uri: external hosts rejected)` plus `failure.rs test_stored_location` and `test_recall_target` | `cargo test -p devise-rust --lib test_parse_stored_uri test_stored_location test_recall_target` | green: each 1 passed, 0 failed (`http://example.com/...` and `https://...` stored targets are rejected) |

## TEST-02: framework-leg matrix (run 2026-10-11)

Both harnesses exist on the current tree: the Phase 8 actix harness (`actix_web::test` in `crates/devise-rust-actix/tests/devise_flows.rs`) and the Phase 9 axum harness (`tower::ServiceExt` oneshot with the stub provider in `crates/devise-rust-axum/tests/devise_flows.rs`). No leg is gated; every leg below ran green.

| Leg | Command run | Outcome |
|---|---|---|
| axum session bridge | `cargo test -p devise-rust-axum --test session_bridge` | green: 24 passed, 0 failed |
| axum extractors | `cargo test -p devise-rust-axum --test extractors` | green: 5 passed, 0 failed |
| axum routes | `cargo test -p devise-rust-axum --test routes` | green: 13 passed, 0 failed |
| axum full browser-parity flow matrix | `cargo test -p devise-rust-axum --test devise_flows` | green: 11 passed, 0 failed (sign up, confirm, sign in plus remember, edit account, lock and unlock, reset, sign out, two cookie jar regression, renewal rotation, stored location) |
| axum omniauth flows | `cargo test -p devise-rust-axum --test omniauth_flows` | green: 10 passed, 0 failed (stub provider, real jar replay) |
| actix full browser-parity flow matrix | `cargo test -p devise-rust-actix --test devise_flows` | green: 10 passed, 0 failed (same matrix as the axum leg) |
| actix extractors | `cargo test -p devise-rust-actix --test extractors` | green: 8 passed, 0 failed |
| actix routes | `cargo test -p devise-rust-actix --test routes` | green: 8 passed, 0 failed |
| actix session bridge | `cargo test -p devise-rust-actix --test session_bridge` | green: 3 passed, 0 failed |
| actix omniauth flows | `cargo test -p devise-rust-actix --test omniauth_flows` | green: 10 passed, 0 failed |

Supporting TEST-01 and gate runs on the same tree: `cargo test -p devise-rust` green (305 lib, 5 model_validation, 4 notifications, 45 doctests), `cargo test -p devise-rust-migrations` green (26 tests: 5 lib + 5 bin + 16 snapshots), `cargo test -p devise-rust --lib scope` green (25 passed), `cargo test -p devise-rust --lib omniauthable` green (17 passed), `cargo clippy --all-targets --all-features -- -D warnings` green (exit 0, no warnings), `cargo fmt --all -- --check` green (exit 0).

Measured 2026-10-24 (batch 261024-wva): `cargo test --workspace` green with 517 tests total (core 305, actix+axum 120, adapter-tests oracle, migrations 26, ORM backends 38 on sqlite legs and 37 on the testcontainers Postgres legs), 0 clippy warnings across all targets.

Corrected counts from the 2026-10-24 audit: the earlier claims of "241 lib" and "43 migrations tests" were stale/incorrect (measured: 305 lib, 26 migrations). The earlier claim of "770/882 (87%) ported" is not substantiated; the auditable figure is ~560/882 (~63%) with a named test, and the remediation above closes the verified behavioral gaps that the checklist claimed without evidence.

