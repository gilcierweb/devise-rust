//! Persistence abstractions — `OrmAdapter` trait, Conditions, `ChangeSet`, `DeviseKey`, in-memory adapter

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

/// Errors for adapter operations
#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("Record not found")]
    NotFound,
    #[error("Multiple records found")]
    MultipleFound,
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Key type for session serialization — supports both i64 and UUID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DeviseKey {
    Integer(i64),
    Uuid(Uuid),
}

impl DeviseKey {
    /// Create from i64
    #[must_use]
    pub fn from_i64(id: i64) -> Self {
        DeviseKey::Integer(id)
    }

    /// Create from UUID
    #[must_use]
    pub fn from_uuid(id: Uuid) -> Self {
        DeviseKey::Uuid(id)
    }

    /// Try to get as i64
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            DeviseKey::Integer(i) => Some(*i),
            DeviseKey::Uuid(_) => None,
        }
    }

    /// Try to get as UUID
    #[must_use]
    pub fn as_uuid(&self) -> Option<Uuid> {
        match self {
            DeviseKey::Integer(_) => None,
            DeviseKey::Uuid(u) => Some(*u),
        }
    }
}

impl std::fmt::Display for DeviseKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviseKey::Integer(i) => write!(f, "{i}"),
            DeviseKey::Uuid(u) => write!(f, "{u}"),
        }
    }
}

/// Error parsing a [`DeviseKey`] from its session string form.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid devise session key: {0}")]
pub struct ParseDeviseKeyError(String);

impl std::str::FromStr for DeviseKey {
    type Err = ParseDeviseKeyError;

    /// Parse either an `i64` or a UUID — the two session-serializable key forms.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(i) = s.parse::<i64>() {
            return Ok(DeviseKey::Integer(i));
        }
        if let Ok(u) = s.parse::<Uuid>() {
            return Ok(DeviseKey::Uuid(u));
        }
        Err(ParseDeviseKeyError(s.to_string()))
    }
}

/// JSON value wrapper for conditions
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Value {
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    Null,
    Array(Vec<Value>),
    Object(HashMap<String, Value>),
}

macro_rules! impl_from_for_value {
    ($($ty:ty => $variant:ident),* $(,)?) => {
        $(
            impl From<$ty> for Value {
                fn from(v: $ty) -> Self {
                    Value::$variant(v)
                }
            }
        )*
    };
}

impl_from_for_value! {
    String => String,
    i64 => Integer,
    f64 => Float,
    bool => Boolean,
}

impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Value::String(v.to_string())
    }
}

impl From<i32> for Value {
    fn from(v: i32) -> Self {
        Value::Integer(i64::from(v))
    }
}

/// Type-safe container for query conditions
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Conditions {
    inner: HashMap<String, Value>,
}

impl Conditions {
    /// Create empty conditions
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a key-value pair
    pub fn insert<K, V>(&mut self, key: K, value: V) -> &mut Self
    where
        K: Into<String>,
        V: Into<Value>,
    {
        self.inner.insert(key.into(), value.into());
        self
    }

    /// Get a typed value
    #[must_use]
    pub fn get<T>(&self, key: &str) -> Option<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        self.inner.get(key).and_then(|v| {
            serde_json::to_value(v)
                .ok()
                .and_then(|v| serde_json::from_value(v).ok())
        })
    }

    /// Check if key exists
    #[must_use]
    pub fn contains_key(&self, key: &str) -> bool {
        self.inner.contains_key(key)
    }

    /// Get raw value
    #[must_use]
    pub fn get_raw(&self, key: &str) -> Option<&Value> {
        self.inner.get(key)
    }

    /// Iterate over conditions
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Value)> {
        self.inner.iter()
    }

    /// Convert to `HashMap` for SQL generation
    #[must_use]
    pub fn to_hashmap(&self) -> &HashMap<String, Value> {
        &self.inner
    }
}

impl From<HashMap<String, Value>> for Conditions {
    fn from(map: HashMap<String, Value>) -> Self {
        Self { inner: map }
    }
}

#[allow(clippy::implicit_hasher)]
impl From<&Conditions> for HashMap<String, Value> {
    fn from(conditions: &Conditions) -> Self {
        conditions.inner.clone()
    }
}

impl std::fmt::Display for Conditions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            serde_json::to_string(&self.inner).unwrap_or_default()
        )
    }
}

/// Snapshot of record state for change tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeSet {
    /// Previous values before change
    previous: HashMap<String, Value>,
    /// Current values
    current: HashMap<String, Value>,
}

impl ChangeSet {
    /// Create a new change set from previous and current state
    #[must_use]
    pub fn new(previous: HashMap<String, Value>, current: HashMap<String, Value>) -> Self {
        Self { previous, current }
    }

    /// Check if a field has changed
    #[must_use]
    pub fn has_changed(&self, field: &str) -> bool {
        self.previous.get(field) != self.current.get(field)
    }

    /// Get previous value of a field
    #[must_use]
    pub fn previous_value(&self, field: &str) -> Option<&Value> {
        self.previous.get(field)
    }

    /// Get current value of a field
    #[must_use]
    pub fn current_value(&self, field: &str) -> Option<&Value> {
        self.current.get(field)
    }

    /// Get all changed fields
    #[must_use]
    pub fn changed_fields(&self) -> Vec<String> {
        self.current
            .keys()
            .filter(|k| self.has_changed(k))
            .cloned()
            .collect()
    }
}

/// Core adapter trait — all backends implement this
#[async_trait]
pub trait OrmAdapter<M: Send + Sync + 'static>: Send + Sync {
    /// Get record by primary key
    async fn get(&self, id: &DeviseKey) -> Result<Option<M>, AdapterError>;

    /// Get record by primary key, error if not found
    async fn get_strict(&self, id: &DeviseKey) -> Result<M, AdapterError> {
        self.get(id).await?.ok_or(AdapterError::NotFound)
    }

    /// Find first record matching conditions
    async fn find_first(&self, conditions: &Conditions) -> Result<Option<M>, AdapterError>;

    /// Find first record matching conditions, error if not found
    async fn find_first_strict(&self, conditions: &Conditions) -> Result<M, AdapterError> {
        self.find_first(conditions)
            .await?
            .ok_or(AdapterError::NotFound)
    }

    /// Create a new record
    async fn create(&self, model: M) -> Result<M, AdapterError>;

    /// Update an existing record
    async fn update(&self, model: M) -> Result<M, AdapterError>;

    /// Delete a record
    async fn delete(&self, id: &DeviseKey) -> Result<(), AdapterError>;
}

/// In-memory adapter for testing
pub mod memory {
    use super::{AdapterError, Conditions, DeviseKey, HashMap, OrmAdapter, async_trait};
    use std::sync::{Arc, RwLock};

    #[derive(Debug, Clone)]
    pub struct MemoryAdapter<M> {
        storage: Arc<RwLock<HashMap<DeviseKey, M>>>,
        id_counter: Arc<std::sync::atomic::AtomicI64>,
    }

    impl<M> Default for MemoryAdapter<M> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<M> MemoryAdapter<M> {
        #[must_use]
        pub fn new() -> Self {
            Self {
                storage: Arc::new(RwLock::new(HashMap::new())),
                id_counter: Arc::new(std::sync::atomic::AtomicI64::new(1)),
            }
        }

        fn next_id(&self) -> i64 {
            self.id_counter
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl<M: Send + Sync + Clone + 'static> OrmAdapter<M> for MemoryAdapter<M> {
        async fn get(&self, id: &DeviseKey) -> Result<Option<M>, AdapterError> {
            let storage = self.storage.read().unwrap();
            Ok(storage.get(id).cloned())
        }

        async fn find_first(&self, conditions: &Conditions) -> Result<Option<M>, AdapterError> {
            let storage = self.storage.read().unwrap();
            for model in storage.values() {
                if matches_conditions(model, conditions) {
                    return Ok(Some(model.clone()));
                }
            }
            Ok(None)
        }

        async fn create(&self, model: M) -> Result<M, AdapterError> {
            let mut storage = self.storage.write().unwrap();
            let id = DeviseKey::from_i64(self.next_id());
            storage.insert(id, model.clone());
            Ok(model)
        }

        async fn update(&self, model: M) -> Result<M, AdapterError> {
            // In real implementation, would extract ID from model
            // For memory adapter, assume model has an ID field we can't access generically
            Ok(model)
        }

        async fn delete(&self, id: &DeviseKey) -> Result<(), AdapterError> {
            let mut storage = self.storage.write().unwrap();
            storage.remove(id);
            Ok(())
        }
    }

    fn matches_conditions<M>(_: &M, _conditions: &Conditions) -> bool {
        // Simplified - in real impl would use reflection or trait
        true
    }
}

// Time abstraction lives in the top-level `time` module (single definition — DRY).
pub use crate::time::{Clock, FixedClock, SystemClock};

#[cfg(test)]
mod tests {
    use super::{AdapterError, ChangeSet, Conditions, DeviseKey, OrmAdapter, Value};
    use crate::time::{Clock, FixedClock, SystemClock};
    use chrono::{TimeDelta, Utc};
    use std::collections::HashMap;
    use uuid::Uuid;

    #[test]
    fn test_devise_key_integer() {
        let key = DeviseKey::from_i64(42);
        assert_eq!(key.as_i64(), Some(42));
        assert_eq!(key.as_uuid(), None);
        assert_eq!(key.to_string(), "42");
    }

    #[test]
    fn test_devise_key_uuid() {
        let uuid = Uuid::new_v4();
        let key = DeviseKey::from_uuid(uuid);
        assert_eq!(key.as_i64(), None);
        assert_eq!(key.as_uuid(), Some(uuid));
        assert_eq!(key.to_string(), uuid.to_string());
    }

    #[test]
    fn test_devise_key_roundtrip_integer() {
        use std::str::FromStr;
        let key = DeviseKey::from_i64(42);
        let session_string = key.to_string();
        assert_eq!(DeviseKey::from_str(&session_string).unwrap(), key);
    }

    #[test]
    fn test_devise_key_roundtrip_uuid() {
        use std::str::FromStr;
        let key = DeviseKey::from_uuid(Uuid::new_v4());
        let session_string = key.to_string();
        assert_eq!(DeviseKey::from_str(&session_string).unwrap(), key);
    }

    #[test]
    fn test_devise_key_parse_rejects_garbage() {
        use std::str::FromStr;
        assert!(DeviseKey::from_str("not-a-key!!").is_err());
    }

    #[tokio::test]
    async fn test_memory_adapter_crud_roundtrip() {
        use crate::adapter::memory::MemoryAdapter;

        let adapter: MemoryAdapter<String> = MemoryAdapter::new();

        // create → get via returned position is implicit (memory adapter assigns ids);
        // exercise the trait surface: create, list via get-after-insert, delete.
        let created = adapter.create("first".to_string()).await.unwrap();
        assert_eq!(created, "first");

        // The memory adapter assigns sequential integer ids starting at 1.
        let fetched = adapter.get(&DeviseKey::from_i64(1)).await.unwrap();
        assert_eq!(fetched, Some("first".to_string()));

        let missing = adapter.get(&DeviseKey::from_i64(999)).await.unwrap();
        assert_eq!(missing, None);

        // find_first uses the (documented) permissive matcher stub in-memory
        let found = adapter.find_first(&Conditions::new()).await.unwrap();
        assert_eq!(found, Some("first".to_string()));

        adapter.delete(&DeviseKey::from_i64(1)).await.unwrap();
        assert_eq!(adapter.get(&DeviseKey::from_i64(1)).await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_memory_adapter_get_strict_errors_on_missing() {
        use crate::adapter::memory::MemoryAdapter;

        let adapter: MemoryAdapter<String> = MemoryAdapter::new();
        let err = adapter
            .get_strict(&DeviseKey::from_i64(1))
            .await
            .unwrap_err();
        assert!(matches!(err, AdapterError::NotFound));
    }

    #[test]
    fn test_conditions() {
        let mut cond = Conditions::new();
        cond.insert("email", "test@example.com");
        cond.insert("active", true);

        assert!(cond.contains_key("email"));
        assert_eq!(
            cond.get_raw("email"),
            Some(&Value::String("test@example.com".to_string()))
        );
        assert_eq!(
            cond.get::<String>("email"),
            Some("test@example.com".to_string())
        );
        assert_eq!(cond.get::<bool>("active"), Some(true));
    }

    #[test]
    fn test_change_set() {
        let mut prev = HashMap::new();
        prev.insert(
            "email".to_string(),
            Value::String("old@example.com".to_string()),
        );

        let mut curr = HashMap::new();
        curr.insert(
            "email".to_string(),
            Value::String("new@example.com".to_string()),
        );

        let changeset = ChangeSet::new(prev, curr);
        assert!(changeset.has_changed("email"));
        assert_eq!(
            changeset.previous_value("email"),
            Some(&Value::String("old@example.com".to_string()))
        );
        assert_eq!(
            changeset.current_value("email"),
            Some(&Value::String("new@example.com".to_string()))
        );
    }

    #[test]
    fn test_system_clock() {
        let clock = SystemClock;
        let now = clock.now();
        assert!((Utc::now() - now).num_seconds() < 2);
    }

    #[test]
    fn test_fixed_clock() {
        let fixed_time = Utc::now();
        let clock = FixedClock::new(fixed_time);
        assert_eq!(clock.now(), fixed_time);

        let mut clock = FixedClock::now();
        let before = clock.now();
        clock.advance(TimeDelta::seconds(10));
        assert_eq!(clock.now(), before + TimeDelta::seconds(10));
    }
}
