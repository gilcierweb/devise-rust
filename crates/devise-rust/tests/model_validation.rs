//! Validatable integration tests (Task 4): email format, password
//! confirmation/length, blank-value error keys, and uniqueness - exercised
//! through the crate's public API the way downstream apps will use it.

use devise_rust::adapter::memory::MemoryAdapter;
use devise_rust::adapter::{DeviseKey, OrmAdapter};
use devise_rust::config::DeviseConfig;
use devise_rust::error::ValidationErrors;
use devise_rust::failure::AnyDeviseModel;
use devise_rust::model::{Authenticatable, DatabaseAuthenticatable, Validatable};
use serde_json::Value as JsonValue;

#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
struct User {
    id: i64,
    email: String,
    encrypted_password: String,
    #[serde(skip)]
    password: Option<String>,
    #[serde(skip)]
    password_confirmation: Option<String>,
}

impl AnyDeviseModel for User {
    fn to_key(&self) -> DeviseKey {
        DeviseKey::from_i64(self.id)
    }

    fn authenticatable_salt(&self) -> Option<String> {
        DatabaseAuthenticatable::database_authenticatable_salt(self)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl Authenticatable for User {
    fn serializable_hash(&self) -> JsonValue {
        serde_json::json!({ "id": self.id, "email": self.email })
    }
}

#[async_trait::async_trait]
impl DatabaseAuthenticatable for User {
    fn encrypted_password(&self) -> Option<&str> {
        if self.encrypted_password.is_empty() {
            None
        } else {
            Some(&self.encrypted_password)
        }
    }

    fn set_encrypted_password(&mut self, value: Option<String>) {
        self.encrypted_password = value.unwrap_or_default();
    }

    fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    fn set_password_virtual(&mut self, password: Option<String>) {
        self.password = password;
    }

    fn password_confirmation(&self) -> Option<&str> {
        self.password_confirmation.as_deref()
    }

    fn set_password_confirmation(&mut self, value: Option<String>) {
        self.password_confirmation = value;
    }

    fn persisted(&self) -> bool {
        self.id != 0
    }

    fn assign_attributes(&mut self, attrs: &serde_json::Map<String, JsonValue>) {
        if let Some(JsonValue::String(email)) = attrs.get("email") {
            self.email.clone_from(email);
        }
    }
}

impl Validatable for User {
    fn email_value(&self) -> Option<&str> {
        Some(&self.email)
    }

    fn uniqueness_scope_id(&self) -> Option<String> {
        self.persisted().then(|| self.id.to_string())
    }
}

fn test_config() -> DeviseConfig {
    DeviseConfig {
        stretches: 4,
        ..DeviseConfig::default()
    }
}

fn user_with(email: &str) -> User {
    User {
        email: email.to_string(),
        password: Some("secret123".to_string()),
        password_confirmation: Some("secret123".to_string()),
        ..User::default()
    }
}

#[test]
fn email_format_validation_uses_devise_regexp() {
    let config = test_config();
    for valid in ["a@b.com", "user+tag@example.org", "x@y.z"] {
        let errors = Validatable::validate(&user_with(valid), &config);
        assert!(errors.get("email").is_none(), "{valid} should be valid");
    }
    for invalid in ["not-an-email", "missing@", "@example.com", "sp ace@x.com"] {
        let errors = Validatable::validate(&user_with(invalid), &config);
        assert_eq!(
            errors.get("email").map(Vec::as_slice),
            Some(&[":invalid".to_string()][..]),
            "{invalid} should be :invalid"
        );
    }
}

#[test]
fn password_confirmation_must_match() {
    let config = test_config();
    let mut user = user_with("fresh@example.com");
    DatabaseAuthenticatable::set_password_confirmation(&mut user, Some("other".to_string()));
    let errors = Validatable::validate(&user, &config);
    assert_eq!(
        errors.get("password_confirmation").map(Vec::as_slice),
        Some(&[":confirmation".to_string()][..])
    );
}

#[test]
fn password_length_bounds_6_to_128_inclusive() {
    let config = test_config();
    let cases = [
        (5usize, Some(":too_short")),
        (6, None),
        (128, None),
        (129, Some(":too_long")),
    ];
    for (len, expected) in cases {
        let user = User {
            password: Some("x".repeat(len)),
            password_confirmation: Some("x".repeat(len)),
            ..user_with("bounds@example.com")
        };
        let errors = Validatable::validate(&user, &config);
        match expected {
            Some(key) => assert_eq!(
                errors.get("password").map(Vec::as_slice),
                Some(&[key.to_string()][..]),
                "length {len} should be {key}"
            ),
            None => assert!(errors.is_empty(), "length {len} should pass: {errors:?}"),
        }
    }
}

#[test]
fn blank_values_use_blank_error_keys() {
    let config = test_config();
    let errors = Validatable::validate(&User::default(), &config);
    assert_eq!(
        errors.get("email").map(Vec::as_slice),
        Some(&[":blank".to_string()][..])
    );
    assert_eq!(
        errors.get("password").map(Vec::as_slice),
        Some(&[":blank".to_string()][..])
    );
    assert_eq!(errors.get("password_confirmation"), None);
}

#[tokio::test]
async fn email_uniqueness_is_case_sensitive_at_db() {
    let config = test_config();
    let adapter = MemoryAdapter::<User>::new();

    let mut existing = user_with("taken@example.com");
    existing.id = 1;
    DatabaseAuthenticatable::set_encrypted_password(
        &mut existing,
        Some(devise_rust::crypto::encryptor::digest("secret123", &config)),
    );
    adapter.create(existing).await.unwrap();

    // A second record with the same address is flagged :taken.
    let dupe = user_with("taken@example.com");
    let mut errors = ValidationErrors::new();
    Validatable::validate_email_uniqueness(&dupe, &adapter, &mut errors).await;
    assert_eq!(
        errors.get("email").map(Vec::as_slice),
        Some(&[":taken".to_string()][..])
    );

    // The same record updating other fields is not a violation (self-exclusion).
    let mut self_user = {
        let mut u = user_with("taken@example.com");
        u.id = 1;
        u
    };
    DatabaseAuthenticatable::set_encrypted_password(&mut self_user, Some("something".to_string()));
    let mut errors = ValidationErrors::new();
    Validatable::validate_email_uniqueness(&self_user, &adapter, &mut errors).await;
    assert!(errors.is_empty(), "self must be excluded from :taken");

    // Case-sensitive: differently-cased address is a distinct DB key; the
    // parameter filter (AUTH-06) normalizes before persistence instead.
    let cased = user_with("TAKEN@example.com");
    let mut errors = ValidationErrors::new();
    Validatable::validate_email_uniqueness(&cased, &adapter, &mut errors).await;
    assert!(errors.is_empty(), "DB-level lookup stays case-sensitive");
}
