//! Crypto primitives - bcrypt Encryptor, HMAC-SHA256 `TokenGenerator`, `secure_compare`, `friendly_token`

use crate::config::DeviseConfig;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bcrypt::{hash, verify};
use getrandom::getrandom;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Bcrypt password Encryptor with pepper support.
///
/// Mirrors `Devise::Encryptor` (`devise/lib/devise/encryptor.rb`):
/// `digest` hashes the pepper-appended password with bcrypt at the
/// `stretches` cost, exactly like `Devise::Encryptor.digest`, and
/// `compare` verifies a candidate password the way
/// `Devise::Encryptor.compare` does: re-hash with the same pepper and
/// match against the stored digest.
///
/// == Options
///
/// * `pepper` - secret appended to the password before hashing
///   (default `None`, matching Devise's `Devise.pepper`)
/// * `stretches` - bcrypt cost factor (default 12, matching Devise's
///   `Devise.stretches`)
///
/// == Examples
///
/// ```
/// use devise_rust::config::DeviseConfig;
/// use devise_rust::crypto::encryptor;
///
/// let config = DeviseConfig::default();
/// let hashed = encryptor::digest("password", &config);
/// assert!(encryptor::compare("password", &hashed, &config));
/// assert!(!encryptor::compare("wrong", &hashed, &config));
/// ```
pub mod encryptor {
    use super::{DeviseConfig, hash, verify};

    /// Hash a password with bcrypt using `config.stretches` and `config.pepper`.
    ///
    /// Mirrors `Devise::Encryptor.digest`: the pepper is appended to the
    /// password before hashing and the bcrypt cost is `stretches`, clamped
    /// to bcrypt's maximum of 31.
    ///
    /// == Examples
    ///
    /// ```
    /// use devise_rust::config::DeviseConfig;
    /// use devise_rust::crypto::encryptor;
    ///
    /// let config = DeviseConfig::default();
    /// let hashed = encryptor::digest("password", &config);
    /// assert!(hashed.starts_with("$2"));
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if bcrypt fails with the clamped cost (should not happen - cost is clamped to ≤ 31).
    #[must_use]
    pub fn digest(password: &str, config: &DeviseConfig) -> String {
        let mut password_with_pepper = password.to_string();
        if let Some(pepper) = &config.pepper {
            password_with_pepper.push_str(pepper);
        }
        let cost = config.stretches.min(31); // bcrypt max cost is 31
        hash(password_with_pepper, cost).expect("bcrypt hash should not fail with valid cost")
    }

    /// Verify a password against a bcrypt hash.
    ///
    /// Mirrors `Devise::Encryptor.compare`: the candidate password is
    /// re-hashed with the same pepper and checked against the stored
    /// digest. A malformed stored digest or a failed verification returns
    /// `false` instead of raising, so strategies can treat both alike.
    ///
    /// == Examples
    ///
    /// ```
    /// use devise_rust::config::DeviseConfig;
    /// use devise_rust::crypto::encryptor;
    ///
    /// let config = DeviseConfig::default();
    /// let hashed = encryptor::digest("password", &config);
    /// assert!(encryptor::compare("password", &hashed, &config));
    /// assert!(!encryptor::compare("wrong", &hashed, &config));
    /// ```
    #[must_use]
    pub fn compare(password: &str, hashed: &str, config: &DeviseConfig) -> bool {
        let mut password_with_pepper = password.to_string();
        if let Some(pepper) = &config.pepper {
            password_with_pepper.push_str(pepper);
        }
        verify(password_with_pepper, hashed).unwrap_or(false)
    }
}

/// HMAC-SHA256 token generation - stores only digest, emails carry raw token
pub mod token_generator {
    use super::{HmacSha256, KeyInit, Mac};

    /// Derive a per-column key from the `secret_key`
    fn column_key(secret_key: &str, column: &str) -> Vec<u8> {
        let mut mac =
            HmacSha256::new_from_slice(secret_key.as_bytes()).expect("HMAC key should be valid");
        mac.update(b"Devise ");
        mac.update(column.as_bytes());
        mac.finalize().into_bytes().to_vec()
    }

    /// Generate HMAC-SHA256 digest of a value for a given column
    ///
    /// # Panics
    ///
    /// Panics if the HMAC key is rejected (should not happen - HMAC accepts any key length).
    #[must_use]
    pub fn digest(secret_key: &str, column: &str, value: &str) -> String {
        let key = column_key(secret_key, column);
        let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC key should be valid");
        mac.update(value.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    /// Generate a raw token and its digest.
    ///
    /// The caller is responsible for uniqueness: Devise loops
    /// `generate` until the digest is unused in the DB. This function
    /// takes that check as a closure so adapters own the lookup.
    #[must_use]
    pub fn generate_with(
        secret_key: &str,
        column: &str,
        mut is_unique: impl FnMut(&str) -> bool,
    ) -> (String, String) {
        loop {
            let raw = super::friendly_token(20);
            let enc = digest(secret_key, column, &raw);
            if is_unique(&enc) {
                return (raw, enc);
            }
        }
    }

    /// Generate a raw token and its digest without a uniqueness check.
    ///
    /// Suitable when the column has enough entropy that collisions are
    /// negligible (Devise default: 160-bit URL-safe tokens).
    #[must_use]
    pub fn generate(secret_key: &str, column: &str) -> (String, String) {
        let raw = super::friendly_token(20);
        let enc = digest(secret_key, column, &raw);
        (raw, enc)
    }
}

/// Constant-time string comparison using `subtle::ConstantTimeEq`
#[must_use]
pub fn secure_compare(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    if a_bytes.len() != b_bytes.len() {
        // Still do a dummy comparison to avoid timing leak on length
        let _ = a_bytes.ct_eq(b_bytes);
        return false;
    }
    a_bytes.ct_eq(b_bytes).into()
}

/// Generate a URL-safe base64 token with Devise's exact character translation:
/// `SecureRandom.urlsafe_base64(len*3/4).tr('lIO0', 'sxyz')` - i.e. l→s, I→x, O→y, 0→z.
/// `_` is preserved, matching Devise (`tr` only remaps the four ambiguous alphanumerics).
///
/// # Panics
///
/// Panics if the OS random source fails (matches `getrandom` semantics).
#[must_use]
pub fn friendly_token(length: usize) -> String {
    let random_bytes = {
        let mut bytes = vec![0u8; (length * 3) / 4 + 1];
        getrandom(&mut bytes).expect("getrandom should not fail");
        bytes
    };
    let encoded = URL_SAFE_NO_PAD.encode(&random_bytes);
    let mut result = encoded
        .chars()
        .map(|c| match c {
            'l' => 's',
            'I' => 'x',
            'O' => 'y',
            '0' => 'z',
            _ => c,
        })
        .take(length)
        .collect::<String>();
    // Ensure exact length by padding if needed (shouldn't happen with proper sizing)
    if result.len() < length {
        let extra = friendly_token(length - result.len());
        result.push_str(&extra);
    }
    result.truncate(length);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DeviseConfig;

    #[test]
    fn test_encryptor_digest_compare() {
        let config = DeviseConfig::default();
        let password = "test-password-123";
        let hashed = encryptor::digest(password, &config);
        assert!(encryptor::compare(password, &hashed, &config));
        assert!(!encryptor::compare("wrong-password", &hashed, &config));
    }

    #[test]
    fn test_encryptor_with_pepper() {
        let config = DeviseConfig {
            pepper: Some("secret-pepper".to_string()),
            ..DeviseConfig::default()
        };
        let password = "test-password";
        let hashed = encryptor::digest(password, &config);
        assert!(encryptor::compare(password, &hashed, &config));
        // Without pepper, compare should fail
        let config_no_pepper = DeviseConfig::default();
        assert!(!encryptor::compare(password, &hashed, &config_no_pepper));
    }

    #[test]
    fn test_token_generator_digest() {
        let secret = "test-secret-key";
        let column = "reset_password_token";
        let value = "raw-token-value";
        let digest1 = token_generator::digest(secret, column, value);
        let digest2 = token_generator::digest(secret, column, value);
        assert_eq!(digest1, digest2);
        // Different value produces different digest
        let digest3 = token_generator::digest(secret, column, "different-value");
        assert_ne!(digest1, digest3);
    }

    #[test]
    fn test_secure_compare() {
        assert!(secure_compare("same", "same"));
        assert!(!secure_compare("same", "diff"));
        assert!(!secure_compare("short", "longer"));
    }

    #[test]
    fn test_friendly_token_length() {
        // Parity with Devise: urlsafe_base64 preserves '_' and '-'; only l/I/O/0 are remapped
        let token = friendly_token(20);
        assert_eq!(token.len(), 20);
        assert!(!token.contains('l'));
        assert!(!token.contains('I'));
        assert!(!token.contains('O'));
        assert!(!token.contains('0'));
    }

    #[test]
    fn test_friendly_token_charset_parity() {
        // Devise: SecureRandom.urlsafe_base64(...).tr('lIO0', 'sxyz')
        // Every output char must be URL-safe base64 or an s/x/y/z replacement.
        for _ in 0..1000 {
            let token = friendly_token(32);
            assert!(
                token
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_')),
                "unexpected char in token: {token}"
            );
        }
    }

    #[test]
    fn test_friendly_token_uniqueness() {
        let tokens: std::collections::HashSet<_> = (0..100).map(|_| friendly_token(20)).collect();
        // Should have very high uniqueness (birthday paradox: ~100^2/2^120 ≈ 0)
        assert_eq!(tokens.len(), 100);
    }
}
