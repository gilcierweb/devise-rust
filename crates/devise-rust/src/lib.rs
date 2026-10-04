//! devise-rust — Faithful Rust port of the Devise Ruby gem
//!
//! A modular, full-featured authentication solution for Rust web applications.
//! Preserves Devise's public API: the same 10 modules, method names, DB column
//! names, config options, I18n message keys, and route/action surface — adapted
//! to idiomatic, DRY, high-quality Rust.
//!
//! # Crate Structure
//!
//! - `config` — `DeviseConfig` with all Devise options and per-scope overrides
//! - `crypto` — `Encryptor` (bcrypt), `TokenGenerator` (HMAC-SHA256), `secure_compare`
//! - `i18n` — Embedded Devise I18n catalog with key-based lookup
//! - `parameter` — `ParameterFilter` and `ParameterSanitizer`
//! - `adapter` — `OrmAdapter` trait, `Conditions`, `ChangeSet`, `DeviseKey`, in-memory adapter
//! - `time` — `Clock` trait for time abstraction

#![warn(clippy::all, clippy::pedantic, unsafe_code)]

// Modules land in follow-up plans:
//   01-02 → config, crypto, i18n, parameter
//   01-03 → adapter, time
