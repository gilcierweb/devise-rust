//! I18n catalog - Devise message keys via `rust-i18n` (compile-time YAML codegen)
//!
//! Mirrors devise's I18n catalog (`devise/config/locales/en.yml`): message keys, placeholders, and copy are identical.
//!
//! Translations live in `crates/devise-rust/locales/en.yml` - the vendored Devise
//! catalog adapted to rust-i18n `_version: 1` layout (filename = locale, no
//! top-level `en:` wrapper). Message keys, `%{placeholder}` interpolation, and
//! copy are identical to Devise's `config/locales/en.yml`.
//!
//! # Options
//!
//! Devise performs interpolation of `%{key}` placeholders via I18n; this module
//! exposes the same behavior through [`translate`].
//!
//! # Examples
//!
//! ```
//! use devise_rust::i18n::translate;
//!
//! let msg = translate("devise.failure.invalid", &[("authentication_keys", "Email")]);
//! assert_eq!(msg, "Invalid Email or password.");
//!
//! let msg = translate("devise.sessions.signed_in", &[]);
//! assert_eq!(msg, "Signed in successfully.");
//! ```

pub use rust_i18n::t;

/// Translate a Devise I18n key with `%{placeholder}` interpolation.
///
/// Missing keys return the key itself (rust-i18n behavior), matching how Devise
/// surfaces `translation missing: ...` for absent keys while staying lossless.
///
/// Mirrors `I18n.t` scoped lookup: the `devise.*` key chain with interpolation values like `%{period}` and `%{count}`.
#[must_use]
pub fn translate(key: &str, interpolations: &[(&str, &str)]) -> String {
    let mut result = t!(key).to_string();
    for (placeholder, value) in interpolations {
        result = result.replace(&format!("%{{{placeholder}}}"), value);
    }
    result
}

/// Translate a Devise I18n key without interpolation.
///
/// Flat-key lookup over the embedded catalog; the storage mirror of devise's locale YAML.
#[must_use]
pub fn translate_simple(key: &str) -> String {
    t!(key).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_translate_simple() {
        let msg = translate_simple("devise.sessions.signed_in");
        assert_eq!(msg, "Signed in successfully.");

        let msg = translate_simple("devise.failure.locked");
        assert_eq!(msg, "Your account is locked.");
    }

    #[test]
    fn test_translate_with_interpolation() {
        let msg = translate(
            "devise.failure.invalid",
            &[("authentication_keys", "Email")],
        );
        assert_eq!(msg, "Invalid Email or password.");

        let msg = translate(
            "errors.messages.confirmation_period_expired",
            &[("period", "2 weeks")],
        );
        assert_eq!(
            msg,
            "needs to be confirmed within 2 weeks, please request a new one"
        );
    }

    #[test]
    fn test_missing_key_returns_key() {
        // rust-i18n returns the key itself for missing translations
        let msg = translate_simple("nonexistent.key");
        assert_eq!(msg, "nonexistent.key");
    }
}
