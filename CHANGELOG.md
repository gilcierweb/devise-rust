# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-11

Initial release: a faithful Rust port of the Devise Ruby gem (v5.0.4),
preserving Devise's module surface, method names, database column names,
configuration option names, I18n message keys, and route table.

The v1 parity claim is a scope statement, not a version number. Parity
with Devise v5.0.4 is the delivered v1 scope, proven by the exhaustive
audit artifacts shipped in this repo: `docs/rails-parity.md` (379 rows
covering every public method, config option, migration column, message
key, unsafe serialization attribute, and `devise_for` route) and
`docs/parity-checklist.md` (all 882 vendored Devise test blocks
accounted for: 770 ported, 20 deviated, 92 waived, every waiver
carrying a written reason and v1 impact). The crates.io version stays
0.1.0 until post-release hardening earns 1.0: 0.1.0 is the first
crates.io release version and does not carry long-term stability
guarantees. Every entry below cites the Devise behavior it mirrors.

### Added

- **Phase 1, Core foundation:** the `devise-rust` crate with
  `DeviseConfig` carrying every Devise option name and default, the
  bcrypt `Encryptor` (mirrors `Devise::Encryptor`), the HMAC-SHA256
  `TokenGenerator` (mirrors `Devise::TokenGenerator`: the database stores
  digests, emails carry raw tokens), `secure_compare`
  (mirrors `Devise.secure_compare`), `friendly_token` (mirrors
  `Devise.friendly_token`), the embedded I18n catalog with Devise's exact
  message keys, the `ParameterFilter` and `ParameterSanitizer`, and the
  `OrmAdapter` trait mirroring devise's orm_adapter seam.
- **Phase 2, Diesel backend and schema tooling:** the
  `devise-rust-diesel` crate with `DieselOrmAdapter` over diesel-async
  and deadpool, plus `devise-rust-migrations`, the per-module migration
  generator emitting Devise's exact column set for Postgres, SQLite, and
  MySQL with integer and UUID primary keys.
- **Phase 3, Warden core:** the session serialization
  `serialize_into_session` as Devise's `[key, authenticatable_salt]`
  pair, the strategy chain (params, HTTP Basic, rememberable, paranoid
  dummy-hash timing mitigation), the hook pipeline
  (mirrors devise's warden hooks), failure semantics (302 plus flash for
  navigational formats, 401 plus `WWW-Authenticate` for API requests,
  `stored_location` recall), the scope registry and the `devise_for`
  route spec table.
- **Phase 4, Mailer and authentication modules I:** the `Mailer` trait
  with Devise's five notifications (`confirmation_instructions`,
  `reset_password_instructions`, `unlock_instructions`, `email_changed`,
  `password_change`) over Tera templates with Devise's subject and copy
  keys, plus the `database_authenticatable` (mirrors
  `Devise::Models::DatabaseAuthenticatable`: `password=`, `valid_password`,
  `update_with_password`, `update_without_password`,
  `destroy_with_password`, `authenticatable_salt`), `validatable`,
  `registerable`, and `recoverable` modules with Devise's exact public
  method names.
- **Phase 5, Account-hygiene modules II:** the `confirmable` module
  (mirrors `Devise::Models::Confirmable`: `confirm`, `confirm_by_token`
  with raw-then-digest lookup, reconfirmable postponement including the
  issue #5783 forced write, resend token reuse), `lockable` (mirrors
  `Devise::Models::Lockable`: `lock_access`, `unlock_access`,
  `unlock_access_by_token`, the failed-attempt counter with
  `maximum_attempts`, time/email/both unlock strategies), `rememberable`
  (mirrors `Devise::Models::Rememberable`: the five-condition cookie
  validity check, the `[key, value, timestamp]` cookie codec),
  `timeoutable` (mirrors `Devise::Models::Timeoutable`: the
  `last_request_at` epoch tick with the Devise-exact boundary and the
  remember-me exemption), and `trackable` (mirrors
  `Devise::Models::Trackable`: field shifting plus the issue #4673
  new-record guard).
- **Phase 6, sqlx backend:** the shared adapter contract suite
  (`devise-rust-adapter-tests`) and the `devise-rust-sqlx` backend on
  SQLite and Postgres, proving the `OrmAdapter` trait is
  backend-portable.
- **Phase 7, sea-orm backend:** the `devise-rust-sea-orm` backend on the
  shared suite with full cross-backend matrix closure.
- **Phase 8, Actix-web integration:** the `devise-rust-actix` crate:
  the actix-session bridge, `DeviseMiddleware`, the `Auth`/`RequireAuth`
  extractors (the `current_user` and `authenticate_user!` shapes), the
  signed remember-cookie transport, `devise_for_users` route
  registration, and the `actix-demo` example app driving the full
  browser-parity Devise journey.
- **Phase 9, Axum integration and omniauthable:** the `devise-rust-axum`
  crate: the tower-sessions bridge, `DeviseLayer`, the same extractor
  names as the actix crate, `devise_for_router` route registration, the
  `axum-demo` example app, and the `omniauthable` module in core
  (mirrors `Devise::Models::Omniauthable`): generic OAuth2 provider
  config, always-on PKCE and CSRF state, the required `from_omniauth`
  seam with the verified-email find-link-create default policy, and the
  authorize plus callback route pairs in both framework crates.
- **Phase 10, Documentation:** the flat-markdown guide corpus under
  `docs/` (getting started for both frameworks, configuration reference,
  per-module pages, Rails concept mapping), the README reshaped as the
  documentation hub, the rustdoc parity sweep naming the Devise item
  every public item mirrors, and the blocking docs gate (rustdoc
  warnings, link checks, prose lint).

### Security

- Digest-only token storage: confirmation, unlock, and reset tokens are
  stored as HMAC-SHA256 digests keyed `"Devise {column}"`; raw tokens
  exist only in email links (mirrors `Devise::TokenGenerator`).
- Constant-time comparisons for tokens and digests through
  `secure_compare` over `subtle::ConstantTimeEq`, and bcrypt verification
  through re-hash plus compare (mirrors `Devise::Encryptor.compare`).
- Paranoid mode: uniform failure messages plus a dummy bcrypt hash on
  unknown accounts, closing the user-enumeration timing oracle.
- Session salt invalidation: the session carries
  `authenticatable_salt` from `encrypted_password`, so a password change
  rejects old sessions (mirrors Devise's session serializer).
- Reconfirmable race fix: the forced `unconfirmed_email` write plus token
  regeneration from Devise issue #5783.
- Blank-token guards on every token lookup (`confirm_by_token`,
  `unlock_access_by_token`, `reset_password_by_token`) fail closed.
- `update_with_password` never persists when the current-password check
  fails.
- `email_changed` notifications go to the ORIGINAL address.
- The remember-cookie validity check enforces all five Devise conditions
  with constant-time comparison.
- The unsafe-attribute filter keeps secrets out of `Debug` and
  serialization output (mirrors
  `UNSAFE_ATTRIBUTES_FOR_SERIALIZATION`).
