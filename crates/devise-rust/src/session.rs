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
/// == Deviation: the shipped bridges sign but do not encrypt
///
/// Transport truth: with a client-side cookie store (actix-session's
/// `CookieSessionStore` with its default signed content security;
/// tower-sessions `CookieStore` over `SignedCookie`) the session payload is
/// integrity protected but client readable. The payload carries the
/// bcrypt-derived `authenticatable_salt` (CONCERNS row 5), so that salt is
/// exposed to the holder of the cookie; the full digest never travels and
/// the salt alone cannot verify a password, but confidentiality is the app's
/// store choice. The axum default is the server-side `MemoryStore`, where
/// only a signed session id crosses the wire. The Rails reference rides an
/// encrypted cookie store by default, so an app wanting that posture chooses
/// an encrypted or server-side store.
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

    /// Build the omniauth CSRF-state stash key for one (scope, provider)
    /// authorize attempt.
    ///
    /// The `devise.{scope}.` prefix means core `expire_devise_keys`
    /// clears the stash on sign-in; the value is single-use (removed on
    /// callback read). Previously duplicated verbatim in both framework
    /// omniauth modules; core owns the grammar now.
    ///
    /// Mirrors the omniauth session-stash key family (`devise.{scope}.omniauth.{provider}.*`) devise's callbacks stash state and verifier under.
    #[must_use]
    pub fn omniauth_state_key(scope: &str, provider: &str) -> String {
        format!("devise.{scope}.omniauth.{provider}.state")
    }

    /// Build the omniauth PKCE-verifier stash key for one (scope,
    /// provider) authorize attempt (single-use; removed on callback
    /// read).
    ///
    /// Previously duplicated verbatim in both framework omniauth modules;
    /// core owns the grammar now.
    ///
    /// Mirrors the omniauth session-stash key family (`devise.{scope}.omniauth.{provider}.*`) devise's callbacks stash state and verifier under.
    #[must_use]
    pub fn omniauth_verifier_key(scope: &str, provider: &str) -> String {
        format!("devise.{scope}.omniauth.{provider}.pkce_verifier")
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
        // WR-06 closure (261026-ghl): `None` compares as the empty string
        // under the constant-time compare, so a saltless record
        // (omniauth-only models) fetches from the `""`-salt payload this
        // module's `serialize_into_session` persisted - matching the
        // core proxy, the typed model path, and the framework S6
        // semantics. A PRESENT salt on either side still mismatches.
        let current_salt = record.authenticatable_salt().unwrap_or_default();

        // Constant-time salt comparison (security critical)
        if !crate::crypto::secure_compare(&current_salt, stored_salt) {
            // Salt mismatch - delete session key (warden fetch semantics)
            store.remove(&session_key).await;
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

    /// WR-06 closure (261026-ghl): a record whose salt is `None`
    /// (omniauth-only models) fetches from the `""`-salt payload the session
    /// helpers persist — `None` compares as the empty string under the
    /// constant-time compare, matching the core proxy and the framework
    /// S6 semantics. A present salt on either side still mismatches and
    /// deletes the session key.
    #[tokio::test]
    async fn test_session_serializer_accepts_saltless_records() {
        let store = TestSessionStore::new();
        let adapter = MemoryAdapter::<TestUser>::new();
        let saltless = TestUser::new(1, "saltless@example.com", "");
        adapter.create(saltless.clone()).await.unwrap();

        let (key, salt) = serializer::serialize_into_session(&saltless);
        assert_eq!(salt, "", "a saltless record serializes an empty salt");
        let session_key = keys::scope_session_key("user");
        store
            .insert_value(&session_key, serde_json::json!([key.to_string(), salt]))
            .await;

        let fetched =
            serializer::serialize_from_session::<_, TestUser>(&store, "user", &adapter).await;
        assert_eq!(
            fetched,
            Some(DeviseKey::from_i64(1)),
            "a saltless record fetches from the empty-salt payload (WR-06)"
        );
        assert!(
            store.get_value(&session_key).await.is_some(),
            "the saltless session survives the fetch"
        );

        // A present stored salt against the saltless record: mismatch,
        // key deleted.
        store
            .insert_value(&session_key, serde_json::json!(["1", "stored-salt"]))
            .await;
        let fetched =
            serializer::serialize_from_session::<_, TestUser>(&store, "user", &adapter).await;
        assert_eq!(fetched, None, "a present salt mismatches a saltless record");
        assert!(
            store.get_value(&session_key).await.is_none(),
            "the mismatch deletes the session key"
        );
    }

    /// The `[key, value, timestamp]` remember-cookie triple lives in exactly
    /// one place: `rememberable.rs`'s `Rememberable::serialize_into_cookie` /
    /// `serialize_from_cookie`, which enforce Devise's five conditions. The
    /// session module owns the key NAMES (this module's `keys::remember_token_key`)
    /// and the session payload only; the second, weaker cookie serializer that
    /// used to live here was deleted rather than left to drift from the real
    /// one. This test pins the surviving seam: the value the production
    /// serializer carries resolves through [`Rememberable`].
    #[tokio::test]
    async fn session_remember_facet_feeds_the_production_cookie_serializer() {
        let mut tokenized =
            TestUser::new(1, "user@example.com", "$2a$12$salt123456789012345678901234");
        tokenized.remember_token = Some("remember-token-value".to_string());
        assert_eq!(
            tokenized.rememberable_value(),
            Some("remember-token-value".to_string()),
            "the remember_token column wins for the cookie value"
        );

        let hashed = TestUser::new(1, "user@example.com", "$2a$12$salt123456789012345678901234");
        assert_eq!(
            hashed.rememberable_value(),
            Some("$2a$12$salt123456789012345678".to_string()),
            "without the column the authenticatable salt carries the cookie value"
        );
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

    /// The omniauth stash keys emit the exact strings both frameworks
    /// previously defined verbatim (actix omniauth.rs and axum omniauth.rs
    /// duplicated the grammar; the tests pin it before the routers
    /// rewire onto core).
    #[test]
    fn test_omniauth_key_naming_pins_the_existing_strings() {
        assert_eq!(
            keys::omniauth_state_key("user", "stub"),
            "devise.user.omniauth.stub.state"
        );
        assert_eq!(
            keys::omniauth_verifier_key("user", "stub"),
            "devise.user.omniauth.stub.pkce_verifier"
        );
        assert_eq!(
            keys::omniauth_state_key("admin", "google_oauth2"),
            "devise.admin.omniauth.google_oauth2.state"
        );
        assert_eq!(
            keys::omniauth_verifier_key("admin", "google_oauth2"),
            "devise.admin.omniauth.google_oauth2.pkce_verifier"
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
