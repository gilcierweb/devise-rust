//! devise-rust - Faithful Rust port of the Devise Ruby gem
//!
//! A modular, full-featured authentication solution for Rust web applications.
//! Preserves Devise's public API: the same 10 modules, method names, DB column
//! names, config options, I18n message keys, and route/action surface - adapted
//! to idiomatic, DRY, high-quality Rust.
//!
//! # Crate Structure
//!
//! - `config` - `DeviseConfig` with all Devise options and per-scope overrides
//! - `crypto` - `Encryptor` (bcrypt), `TokenGenerator` (HMAC-SHA256), `secure_compare`
//! - `i18n` - Embedded Devise I18n catalog with key-based lookup
//! - `parameter` - `ParameterFilter` and `ParameterSanitizer`
//! - `adapter` - `OrmAdapter` trait (`get`/`find_first`/`create`+`insert` alias/`update`/`update_columns`/`increment_counter`/`delete` + defaults), `OrmError`, `Conditions`, `ChangeSet`, `DeviseKey`, in-memory adapter
//! - `time` - `Clock` trait for time abstraction
//! - `error` - `DeviseError`, `ValidationErrors`, `ResourceWithErrors`, `BlankRecord`
//! - `failure` - `Failure` enum, `AuthOutcome`, `AnyDeviseModel` trait
//! - `helpers` - per-scope auth helpers, path helpers, groups, `devise_helpers!`
//! - `hooks` - `HookRegistry`, `HookFilter`, `Event`, bridge traits
//! - `model` - `Authenticatable` base, `DatabaseAuthenticatable` (password handling + notifications decisions), `Validatable`, `Registerable`, `PasswordVerifiable`, `ModelFinder` bridge
//! - `confirmable` - `Confirmable` email confirmation (chain position 6, before `Lockable`): digest-only tokens, reconfirmable postponement, resend reuse, paranoid uniformity
//! - `lockable` - `Lockable` attempt counting (chain position 7, after `Confirmable`): counter-to-lock, time/email/both strategies, digest-only unlock tokens, paranoid suppression
//! - `mailer` - `Mailer` trait (5 actions), `MailerContext`, `TestMailer`, Tera templates
//! - `proxy` - `AuthProxy` session and strategy execution
//! - `rememberable` - `Rememberable` persistent sessions (chain position 1, after `DatabaseAuthenticatable`): cookie codec, 5-condition check, hardened attributes
//! - `request` - `AuthRequest`, `RequestFlags`, `HttpMethod`
//! - `routes` - scope route tables and guard descriptors for bridges
//! - `scope` - `Module`, `Mapping`, `ScopeRegistry`, `RouteSpec`
//! - `session` - `SessionStore` trait, serializer, key naming
//! - `strategy` - `Strategy` chain: params, HTTP Basic, rememberable, paranoid
//! - `time` - `Clock` trait for time abstraction
//! - `timeoutable` - `Timeoutable` inactivity timeout (chain position 8, after `Lockable`): `<=` boundary, epoch tick, remember exemption
//! - `trackable` - `Trackable` sign-in auditing (chain position 9, last): field shift, socket-peer IP, new-record guard

#![warn(clippy::all, clippy::pedantic, unsafe_code)]

// Initialize rust-i18n at crate root - loads translations from `locales/*.yml`
// (vendored Devise catalog, adapted to `_version: 1` layout where filename = locale)
rust_i18n::i18n!("locales", fallback = "en");

pub mod adapter;
pub mod config;
pub mod confirmable;
pub mod crypto;
pub mod error;
pub mod failure;
pub mod helpers;
pub mod hooks;
pub mod i18n;
pub mod lockable;
pub mod mailer;
pub mod model;
pub mod parameter;
pub mod proxy;
pub mod rememberable;
pub mod request;
pub mod routes;
pub mod scope;
pub mod session;
pub mod strategy;
pub mod time;
pub mod timeoutable;
pub mod trackable;

#[cfg(feature = "test-utils")]
pub mod test_utils;

#[cfg(test)]
mod tests {
    use crate::config::DeviseConfig;

    #[test]
    fn test_config_defaults() {
        let config = DeviseConfig::default();
        assert_eq!(config.stretches, 12);
        assert_eq!(config.remember_for, chrono::TimeDelta::weeks(2));
        assert_eq!(config.timeout_in, chrono::TimeDelta::minutes(30));
        assert_eq!(config.reset_password_within, chrono::TimeDelta::hours(6));
        // Devise 5.0.4 defaults (devise/lib/devise.rb): paranoid = false, default_scope = nil
        assert!(!config.paranoid);
        assert_eq!(config.default_scope, None);
        assert_eq!(config.email_regexp, r"\A[^@\s]+@[^@\s]+\z");
        assert_eq!(config.password_length, 6..128);
    }
}
