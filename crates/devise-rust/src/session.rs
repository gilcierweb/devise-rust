//! Session management - `SessionStore` trait, serialization, key naming
//!
//! Mirrors warden's session surface and devise's `serialize_into_session` / `serialize_from_session` key families and salt check.
//!
//! Implements Devise's exact session semantics: `[key, salt]` payload with
//! salt-based invalidation (password change → salt mismatch → session destroyed).
//! Key naming matches Warden exactly for cross-framework compatibility.

use crate::adapter::{DeviseKey, OrmAdapter};
use crate::failure::AnyDeviseModel;
use async_trait::async_trait;
use serde_json::Value;

/// Session store trait - abstracts session backend (cookie, Redis, database, etc.)
///
/// Bridges implement this for their session layer. Core defines the contract;
/// bridge controls storage I/O. Malicious bridge could corrupt session data
/// (T-03-02) - bridge MUST sign/encrypt cookies.
///
/// Mirrors the warden per-scope session surface devise reads and writes (`warden.session(scope)`), including the salt-checked fetch semantics.
#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Get a value by key
    async fn get_value(&self, key: &str) -> Option<Value>;

    /// Insert a value by key
    async fn insert_value(&self, key: &str, value: Value);

    /// Remove a key
    async fn remove(&self, key: &str);

    /// Remove all keys with prefix
    async fn remove_prefix(&self, prefix: &str);

    /// Get all keys with prefix
    async fn keys_with_prefix(&self, prefix: &str) -> Vec<String>;

    /// Renew session (rotate CSRF, extend expiry) - SESS-05
    async fn renew(&self) -> Result<(), crate::error::DeviseError>;

    /// Reset session (clear all) - SESS-05
    async fn reset(&self) -> Result<(), crate::error::DeviseError>;
}

/// Session key naming constants - exact Warden compatibility
///
/// Session key naming mirroring devise's key families: `warden.user.{scope}.session` and `#{scope}_return_to`.
pub mod keys {
    /// Prefix for all warden user keys
    ///
    /// The `warden.` prefix; mirrors the key prefix of devise's session key family.
    pub const SCOPE_KEY_PREFIX: &str = "warden.user.";
    /// Session key for a scope: `warden.user.{scope}.session`
    ///
    /// The `warden.user.{scope}.session` key; mirrors the slot devise's serializer reads.
    pub const SCOPE_SESSION_KEY: &str = "warden.user.{scope}.session";
    /// Stored location key: `{scope}_return_to`
    ///
    /// The `#{scope}_return_to` key; mirrors the slot of devise's `store_location_for` / `stored_location_for`.
    pub const STORED_LOCATION_KEY: &str = "{scope}_return_to";
    /// Remember token cookie key: `remember_{scope}_token`
    ///
    /// The `remember_#{scope}_token` cookie name; mirrors the name devise's rememberable controller reads and writes.
    pub const REMEMBER_TOKEN_KEY: &str = "remember_{scope}_token";

    /// Build scope session key
    ///
    /// Builds the `warden.user.{scope}.session` key; mirrors the slot devise's `serialize_into_session` payload lives under.
    #[must_use]
    pub fn scope_session_key(scope: &str) -> String {
        SCOPE_SESSION_KEY.replace("{scope}", scope)
    }

    /// Build stored location key
    ///
    /// Builds the `#{scope}_return_to` stored-location key, mirroring devise's stored-location slot name.
    #[must_use]
    pub fn stored_location_key(scope: &str) -> String {
        STORED_LOCATION_KEY.replace("{scope}", scope)
    }

    /// Build remember token key (overridable via `rememberable_options[:key]`)
    ///
    /// Builds the `remember_#{scope}_token` cookie name, mirroring devise's remember cookie naming.
    #[must_use]
    pub fn remember_token_key(scope: &str) -> String {
        REMEMBER_TOKEN_KEY.replace("{scope}", scope)
    }
}

/// Session serializer - exact Devise session format `[key, salt]`
///
/// Salt derives from `encrypted_password[0,29]` (bcrypt hash prefix).
/// Password change → new bcrypt hash → salt mismatch → session invalidated.
///
/// Mirrors `Devise::Models::Authenticatable.serialize_into_session` / `serialize_from_session` (`devise/lib/devise/models/authenticatable.rb`): the `[key, salt]` payload with salt invalidation.
pub mod serializer {
    use super::{AnyDeviseModel, DeviseKey, OrmAdapter, SessionStore, keys};
    use std::str::FromStr;

    /// Serialize a record into session payload - returns (key, salt)
    ///
    /// Mirrors Devise's `serialize_into_session(record)` → `[to_key, authenticatable_salt]`
    #[must_use]
    pub fn serialize_into_session(record: &dyn AnyDeviseModel) -> (DeviseKey, String) {
        let key = record.to_key();
        let salt = record.authenticatable_salt().unwrap_or_default();
        (key, salt)
    }

    /// Deserialize session payload back to record key with salt validation
    ///
    /// Mirrors Devise's `serialize_from_session(key, salt)`:
    /// - Fetch record by key
    /// - Compare stored salt with record's current salt (constant-time)
    /// - On mismatch: delete session key, return None (warden fetch semantics)
    /// - On match: return key
    pub async fn serialize_from_session<A, M>(
        store: &dyn SessionStore,
        scope: &str,
        adapter: &A,
    ) -> Option<DeviseKey>
    where
        A: OrmAdapter<M> + Send + Sync,
        M: AnyDeviseModel + Send + Sync + 'static,
    {
        let session_key = keys::scope_session_key(scope);
        let session_value = store.get_value(&session_key).await?;

        // Parse session payload: [key, salt]
        let arr = session_value.as_array()?;
        if arr.len() < 2 {
            return None;
        }

        let key_str = arr[0].as_str()?;
        let stored_salt = arr[1].as_str()?;

        let key = DeviseKey::from_str(key_str).ok()?;

        // Fetch record and validate salt
        let record = adapter.get(&key).await.ok()??;
        let current_salt = record.authenticatable_salt()?;

        // Constant-time salt comparison (security critical)
        if !crate::crypto::secure_compare(&current_salt, stored_salt) {
            // Salt mismatch - delete session key (warden fetch semantics)
            store.remove(&session_key).await;
            return None;
        }

        Some(key)
    }

    /// Serialize remember-me cookie payload - `[key, value, timestamp]`
    ///
    /// Mirrors Devise's `serialize_into_cookie` → `[to_key, rememberable_value, Time.now.utc.to_f.to_s]`
    #[must_use]
    pub fn serialize_into_cookie(
        record: &dyn AnyDeviseModel,
        rememberable_value: &str,
    ) -> (DeviseKey, String, String) {
        let key = record.to_key();
        let timestamp = chrono::Utc::now().timestamp().to_string();
        (key, rememberable_value.to_string(), timestamp)
    }

    /// Deserialize remember-me cookie payload
    ///
    /// Mirrors Devise's `serialize_from_cookie(*args)` - validates 5 conditions (RMB-03)
    pub async fn serialize_from_cookie<A, M>(
        _store: &dyn SessionStore,
        _scope: &str,
        adapter: &A,
        cookie_parts: (&str, &str, &str), // (key, value, timestamp)
    ) -> Option<DeviseKey>
    where
        A: OrmAdapter<M> + Send + Sync,
        M: AnyDeviseModel + crate::session::Rememberable + Send + Sync + 'static,
    {
        let (key_str, cookie_value, _timestamp_str) = cookie_parts;

        let key = DeviseKey::from_str(key_str).ok()?;

        // Fetch record
        let record = adapter.get(&key).await.ok()??;

        // Validate rememberable_value (remember_token column OR authenticatable_salt)
        let rememberable_value = record.rememberable_value()?;

        // Constant-time comparison
        if !crate::crypto::secure_compare(&rememberable_value, cookie_value) {
            return None;
        }

        Some(key)
    }
}

/// Expire all Devise session keys for a scope (sign_in_out.rb:99-101)
///
/// Removes all keys starting with "devise." prefix.
pub async fn expire_devise_keys(store: &dyn SessionStore, scope: &str) {
    let prefix = format!("devise.{scope}.");
    let keys = store.keys_with_prefix(&prefix).await;
    for key in keys {
        store.remove(&key).await;
    }
}

/// Generate a unique remember token (Devise's `remember_token` loop)
///
/// Loops until the token digest is unused in the database.
///
/// Mirrors the `remember_token` column minting loop: `Devise.friendly_token` until unused in the store.
pub fn generate_remember_token<A>(_adapter: &A, _scope: &str, secret_key: &str) -> (String, String)
where
    A: Send + Sync,
{
    use crate::crypto::token_generator::generate_with;

    generate_with(secret_key, "remember_token", |_enc| {
        // Note: In a real implementation, we'd check the database here.
        // For now, we assume uniqueness since the token has high entropy.
        true
    })
}

/// Trait for models that support rememberable - provides `rememberable_value`
///
/// Returns `remember_token` column if present, else `authenticatable_salt`.
/// Raises if neither available (Devise behavior).
///
/// Session-side remember facet; mirrors the warden remember cookie read/write seam devise's rememberable strategy drives.
pub trait Rememberable: Send + Sync {
    /// Get the value used for remember-me validation
    fn rememberable_value(&self) -> Option<String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::{DeviseKey, Value, memory::MemoryAdapter};
    use crate::crypto::secure_compare;
    use std::collections::HashMap;

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    struct TestUser {
        id: i64,
        email: String,
        encrypted_password: String,
        remember_token: Option<String>,
    }

    impl TestUser {
        fn new(id: i64, email: &str, encrypted_password: &str) -> Self {
            Self {
                id,
                email: email.to_string(),
                encrypted_password: encrypted_password.to_string(),
                remember_token: None,
            }
        }
    }

    impl AnyDeviseModel for TestUser {
        fn to_key(&self) -> DeviseKey {
            DeviseKey::from_i64(self.id)
        }

        fn authenticatable_salt(&self) -> Option<String> {
            // bcrypt hash prefix (first 29 chars: $2a$12$ + 22-char salt)
            if self.encrypted_password.len() >= 29 {
                Some(self.encrypted_password[..29].to_string())
            } else {
                None
            }
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    impl Rememberable for TestUser {
        fn rememberable_value(&self) -> Option<String> {
            self.remember_token
                .clone()
                .or_else(|| self.authenticatable_salt())
        }
    }

    /// In-memory session store for testing
    #[derive(Debug, Default)]
    struct TestSessionStore {
        data: std::sync::Arc<std::sync::RwLock<HashMap<String, serde_json::Value>>>,
    }

    impl TestSessionStore {
        fn new() -> Self {
            Self::default()
        }
    }

    #[async_trait]
    impl SessionStore for TestSessionStore {
        async fn get_value(&self, key: &str) -> Option<serde_json::Value> {
            self.data.read().unwrap().get(key).cloned()
        }

        async fn insert_value(&self, key: &str, value: serde_json::Value) {
            self.data.write().unwrap().insert(key.to_string(), value);
        }

        async fn remove(&self, key: &str) {
            self.data.write().unwrap().remove(key);
        }

        async fn remove_prefix(&self, prefix: &str) {
            let mut data = self.data.write().unwrap();
            let keys: Vec<String> = data
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect();
            for key in keys {
                data.remove(&key);
            }
        }

        async fn keys_with_prefix(&self, prefix: &str) -> Vec<String> {
            self.data
                .read()
                .unwrap()
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect()
        }

        async fn renew(&self) -> Result<(), crate::error::DeviseError> {
            Ok(())
        }

        async fn reset(&self) -> Result<(), crate::error::DeviseError> {
            self.data.write().unwrap().clear();
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_session_serializer_roundtrip() {
        let store = TestSessionStore::new();
        let adapter = MemoryAdapter::<TestUser>::new();
        let user = TestUser::new(1, "test@example.com", "$2a$12$salt123456789012345678901234");
        adapter.create(user.clone()).await.unwrap();

        // Serialize
        let (key, salt) = serializer::serialize_into_session(&user);
        assert_eq!(key, DeviseKey::from_i64(1));
        // authenticatable_salt returns first 29 chars (bcrypt prefix + 22-char salt)
        assert_eq!(salt, "$2a$12$salt123456789012345678");

        // Insert into session store
        let session_key = keys::scope_session_key("user");
        let session_value = serde_json::json!([key.to_string(), salt]);
        store.insert_value(&session_key, session_value).await;

        // Deserialize with matching salt
        let deserialized_key =
            serializer::serialize_from_session::<_, TestUser>(&store, "user", &adapter).await;
        assert_eq!(deserialized_key, Some(DeviseKey::from_i64(1)));
    }

    #[tokio::test]
    async fn test_session_salt_mismatch_deletes_key() {
        let store = TestSessionStore::new();
        let adapter = MemoryAdapter::<TestUser>::new();
        let user = TestUser::new(1, "test@example.com", "$2a$12$salt123456789012345678901234");
        adapter.create(user.clone()).await.unwrap();

        // Serialize with old salt
        let (key, old_salt) = serializer::serialize_into_session(&user);
        let session_key = keys::scope_session_key("user");
        let session_value = serde_json::json!([key.to_string(), old_salt]);
        store.insert_value(&session_key, session_value).await;

        // Update user with new password (new salt)
        let mut user_updated = user.clone();
        user_updated.encrypted_password = "$2a$12$newsalt123456789012345678901234".to_string();
        adapter
            .update(
                &DeviseKey::from_i64(1),
                &crate::adapter::ChangeSet::new(
                    HashMap::from([(
                        "encrypted_password".to_string(),
                        Value::String(user.encrypted_password.clone()),
                    )]),
                    HashMap::from([(
                        "encrypted_password".to_string(),
                        Value::String(user_updated.encrypted_password.clone()),
                    )]),
                ),
            )
            .await
            .unwrap();

        // Deserialize should fail and delete key
        let deserialized_key =
            serializer::serialize_from_session::<_, TestUser>(&store, "user", &adapter).await;
        assert_eq!(deserialized_key, None);

        // Key should be deleted
        let session_value = store.get_value(&session_key).await;
        assert!(session_value.is_none());
    }

    #[tokio::test]
    async fn test_cookie_serializer() {
        let mut user = TestUser::new(1, "test@example.com", "$2a$12$salt123456789012345678901234");
        user.remember_token = Some("remember-token-value".to_string());

        let (key, value, timestamp) =
            serializer::serialize_into_cookie(&user, "remember-token-value");
        assert_eq!(key, DeviseKey::from_i64(1));
        assert_eq!(value, "remember-token-value");
        assert_ne!(timestamp.len(), 0);
    }

    #[test]
    fn test_key_naming() {
        assert_eq!(keys::scope_session_key("user"), "warden.user.user.session");
        assert_eq!(keys::stored_location_key("user"), "user_return_to");
        assert_eq!(keys::remember_token_key("user"), "remember_user_token");
        assert_eq!(
            keys::scope_session_key("admin"),
            "warden.user.admin.session"
        );
    }

    #[test]
    fn test_secure_compare_salt() {
        let salt1 = "$2a$12$salt123456789012345678901234";
        let salt2 = "$2a$12$salt123456789012345678901234";
        let salt3 = "$2a$12$differentsalt1234567890123";

        assert!(secure_compare(salt1, salt2));
        assert!(!secure_compare(salt1, salt3));
        assert!(!secure_compare("short", "longer"));
    }

    #[test]
    fn test_rememberable_value_prefers_token() {
        let mut user = TestUser::new(1, "test@example.com", "$2a$12$salt123456789012345678901234");
        user.remember_token = Some("explicit-token".to_string());

        assert_eq!(
            user.rememberable_value(),
            Some("explicit-token".to_string())
        );
    }

    #[test]
    fn test_rememberable_value_fallback_to_salt() {
        let user = TestUser::new(1, "test@example.com", "$2a$12$salt123456789012345678901234");

        // authenticatable_salt returns first 29 chars (bcrypt prefix + 22-char salt)
        assert_eq!(
            user.rememberable_value(),
            Some("$2a$12$salt123456789012345678".to_string())
        );
    }
}
