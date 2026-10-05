//! Persistence abstractions — `OrmAdapter` trait, `OrmError`, `Conditions`, `ChangeSet`, `DeviseKey`, in-memory adapter
//!
//! Mirrors the `orm_adapter` gem layer Devise programs against
//! (`to_adapter.get`, `to_adapter.find_first`): every persistence call a Devise
//! module needs crosses this trait, so backends (diesel here; sqlx/sea-orm
//! later) stay interchangeable behind one contract.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

/// Backend failure taxonomy — every adapter maps its driver errors into this enum.
///
/// Renamed from `AdapterError` (the Phase-1 shipped name) to `OrmError` per the
/// locked Phase-1 error-model decision (D-20): core never names
/// diesel/sqlx/sea-orm types, and the token generator's uniqueness loop keys on
/// [`OrmError::UniqueViolation`].
///
/// # Privacy contract
///
/// `Display` output carries category and constraint/column metadata only —
/// never a record field value (email, token) nor a connection URL. The diesel
/// backend's error mapper (plan 02-03) is specified against this contract and
/// its tests assert value-absence.
#[derive(Debug, Error)]
pub enum OrmError {
    /// No record matched (`get_strict` / `find_first_strict`).
    NotFound,
    /// Reserved for strict single-row fetchers that must refuse ambiguity.
    MultipleFound,
    /// A uniqueness constraint rejected the write (duplicate email, token
    /// collision). Carries the constraint/index name when the driver reports
    /// one — never the conflicting value.
    UniqueViolation {
        /// Database constraint or index name, when the driver reports one.
        constraint: Option<String>,
    },
    /// The query reached the database but failed (bad column, type mismatch,
    /// rejected predicate). `message` is a category-level description, never a
    /// record value.
    Query {
        /// Category-level failure description (no record values).
        message: String,
        /// Underlying driver error, for diagnostics only.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },
    /// The database could not be reached (pool exhaustion, refused socket,
    /// TLS failure). `message` names the failure class, never the URL.
    Connection {
        /// Failure class description (no connection URL).
        message: String,
        /// Underlying driver error, for diagnostics only.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },
    /// The key could not identify a record (unknown id shape for the backend).
    InvalidKey(String),
    /// A model could not cross the serde bridge (memory adapter) or a JSON
    /// payload failed to (de)serialize.
    Serialization(#[from] serde_json::Error),
}

impl std::fmt::Display for OrmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "Record not found"),
            Self::MultipleFound => write!(f, "Multiple records found"),
            Self::UniqueViolation { constraint } => {
                write!(f, "Unique constraint violation")?;
                if let Some(name) = constraint {
                    write!(f, ": {name}")?;
                }
                Ok(())
            }
            Self::Query { message, .. } => write!(f, "Query failed: {message}"),
            Self::Connection { message, .. } => write!(f, "Connection failed: {message}"),
            Self::InvalidKey(key) => write!(f, "Invalid key: {key}"),
            Self::Serialization(err) => write!(f, "Serialization error: {err}"),
        }
    }
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

/// Core persistence contract — every backend implements this.
///
/// Mirrors the `orm_adapter` gem surface Devise programs against
/// (`to_adapter.get`, `to_adapter.get!`, `to_adapter.find_first`): `get` is the
/// primary-key fetch, `find_first` the conditional finder, and the write verbs
/// below the `save(validate: false)`-style persistence Devise modules rely on.
///
/// `blank_record` is deliberately NOT part of this trait (D-14): constructing
/// an empty record is construction, not persistence — it lands with Phase 3's
/// authenticatable model trait, which the paranoid-mode dummy hash consumes.
#[async_trait]
pub trait OrmAdapter<M: Send + Sync + 'static>: Send + Sync {
    /// The insert shape consumed by [`create`](OrmAdapter::create) (D-03) —
    /// e.g. a diesel `Insertable` struct without id/timestamps (`NewUser` for
    /// `User`). Kept separate from `M` because the database owns generated
    /// columns; the caller never supplies them.
    type New: Send + Sync + 'static;

    /// Fetch a record by primary key — mirrors `to_adapter.get`.
    ///
    /// # Errors
    ///
    /// Returns [`OrmError`] when the backend fails; a missing record is
    /// `Ok(None)`, never an error.
    async fn get(&self, id: &DeviseKey) -> Result<Option<M>, OrmError>;

    /// Fetch a record by primary key, refusing absence — mirrors
    /// `to_adapter.get!` (which raises on a miss).
    ///
    /// # Errors
    ///
    /// Returns [`OrmError::NotFound`] when no record matches; backend failures
    /// propagate unchanged.
    async fn get_strict(&self, id: &DeviseKey) -> Result<M, OrmError> {
        self.get(id).await?.ok_or(OrmError::NotFound)
    }

    /// Find the first record matching `conditions` — mirrors `orm_adapter`'s
    /// `find_first`, the finder behind Devise's
    /// `find_for_database_authentication` and every `*_by_token` lookup
    /// (recoverable, confirmable, lockable).
    ///
    /// # Errors
    ///
    /// Returns [`OrmError`] when the backend fails; no match is `Ok(None)`.
    async fn find_first(&self, conditions: &Conditions) -> Result<Option<M>, OrmError>;

    /// Find the first record matching `conditions`, refusing absence.
    ///
    /// # Errors
    ///
    /// Returns [`OrmError::NotFound`] when nothing matches; backend failures
    /// propagate unchanged.
    async fn find_first_strict(&self, conditions: &Conditions) -> Result<M, OrmError> {
        self.find_first(conditions).await?.ok_or(OrmError::NotFound)
    }

    /// Persist a new record from its insert shape — mirrors
    /// `to_adapter.create!`, Devise's registration path.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use devise_rust::adapter::{OrmAdapter, memory::MemoryAdapter};
    ///
    /// let rt = tokio::runtime::Builder::new_current_thread()
    ///     .build()
    ///     .expect("test runtime builds");
    /// rt.block_on(async {
    ///     let adapter = MemoryAdapter::<String>::new();
    ///     let created = adapter.create("hello".to_owned()).await.expect("create works");
    ///     assert_eq!(created, "hello");
    /// });
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`OrmError::UniqueViolation`] when a uniqueness constraint
    /// rejects the row; other backend failures surface as their [`OrmError`]
    /// mapping.
    async fn create(&self, model: Self::New) -> Result<M, OrmError>;

    /// Alias of [`create`](OrmAdapter::create) (D-15): reconciles the roadmap's
    /// `insert` wording with `ActiveRecord` parity, where the canonical write
    /// verb stays `create`. Free default — backends implement `create` only.
    ///
    /// # Errors
    ///
    /// Same as [`create`](OrmAdapter::create).
    async fn insert(&self, model: Self::New) -> Result<M, OrmError> {
        self.create(model).await
    }

    /// Partial update writing only the [`ChangeSet`] diff (D-04/D-12) —
    /// Devise's `save(validate: false)` path: lockable counters, token
    /// clearing, and every module persistence that must not run validations.
    /// Identity travels as [`DeviseKey`] so core needs no key-extraction glue;
    /// the backend translates the diff into its `SET` clause.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use devise_rust::adapter::{ChangeSet, Conditions, DeviseKey, OrmAdapter, Value, memory::MemoryAdapter};
    /// use std::collections::HashMap;
    ///
    /// #[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    /// struct Widget { id: i64, name: String }
    ///
    /// let rt = tokio::runtime::Builder::new_current_thread()
    ///     .build()
    ///     .expect("test runtime builds");
    /// rt.block_on(async {
    ///     let adapter = MemoryAdapter::<Widget>::new();
    ///     adapter.create(Widget { id: 0, name: "a".into() }).await.expect("create works");
    ///     let changes = ChangeSet::new(
    ///         HashMap::from([("name".to_owned(), Value::from("a"))]),
    ///         HashMap::from([("name".to_owned(), Value::from("b"))]),
    ///     );
    ///     let updated = adapter.update(&DeviseKey::from_i64(1), &changes).await.expect("update works");
    ///     assert_eq!(updated.name, "b");
    /// });
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`OrmError::NotFound`] when `key` matches nothing; backend
    /// failures propagate unchanged.
    async fn update(&self, key: &DeviseKey, changes: &ChangeSet) -> Result<M, OrmError>;

    /// Always writes the named fields regardless of diff — mirrors
    /// `ActiveRecord::Persistence#update_columns` (D-12): skips validations
    /// and callbacks, and never touches `updated_at`. This is the verb for
    /// forced re-writes of an unchanged value (devise #5783) and for
    /// lockable/trackable counters; the [`ChangeSet`]-diff [`update`](OrmAdapter::update)
    /// is the `save(validate: false)` path where touching `updated_at` belongs
    /// to the backend/model layer instead.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use devise_rust::adapter::{DeviseKey, OrmAdapter, Value, memory::MemoryAdapter};
    /// use std::collections::HashMap;
    ///
    /// #[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    /// struct Widget { id: i64, name: String }
    ///
    /// let rt = tokio::runtime::Builder::new_current_thread()
    ///     .build()
    ///     .expect("test runtime builds");
    /// rt.block_on(async {
    ///     let adapter = MemoryAdapter::<Widget>::new();
    ///     adapter.create(Widget { id: 0, name: "a".into() }).await.expect("create works");
    ///     // Same value, still written — the #5783 force-write.
    ///     let fields = HashMap::from([("name".to_owned(), Value::from("a"))]);
    ///     let updated = adapter.update_columns(&DeviseKey::from_i64(1), &fields).await.expect("update_columns works");
    ///     assert_eq!(updated.name, "a");
    /// });
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`OrmError::NotFound`] when `key` matches nothing; backend
    /// failures propagate unchanged.
    async fn update_columns(
        &self,
        key: &DeviseKey,
        fields: &HashMap<String, Value>,
    ) -> Result<M, OrmError>;

    /// Reports whether `column = value` matches no record (D-13) — the
    /// uniqueness probe behind `crypto::token_generator::generate_with`'s
    /// `is_unique` loop (PLAT-06). Default method composed from
    /// [`find_first`](OrmAdapter::find_first), so no backend implements it
    /// twice; lookup errors propagate, never swallowed.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use devise_rust::adapter::{DeviseKey, OrmAdapter, Value, memory::MemoryAdapter};
    ///
    /// #[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    /// struct Widget { id: i64, name: String }
    ///
    /// let rt = tokio::runtime::Builder::new_current_thread()
    ///     .build()
    ///     .expect("test runtime builds");
    /// rt.block_on(async {
    ///     let adapter = MemoryAdapter::<Widget>::new();
    ///     assert!(adapter.column_value_unused("name", &Value::from("nobody")).await.expect("probe works"));
    ///     adapter.create(Widget { id: 0, name: "taken".into() }).await.expect("create works");
    ///     assert!(!adapter.column_value_unused("name", &Value::from("taken")).await.expect("probe works"));
    /// });
    /// ```
    ///
    /// # Errors
    ///
    /// Propagates the underlying [`find_first`](OrmAdapter::find_first) failure.
    async fn column_value_unused(&self, column: &str, value: &Value) -> Result<bool, OrmError> {
        Ok(self
            .find_first(&Conditions::from(HashMap::from([(
                column.to_owned(),
                value.clone(),
            )])))
            .await?
            .is_none())
    }

    /// Delete the record under `key`; deleting a missing key is a no-op —
    /// mirrors `to_adapter.destroy`.
    ///
    /// # Errors
    ///
    /// Returns [`OrmError`] when the backend fails.
    async fn delete(&self, id: &DeviseKey) -> Result<(), OrmError>;
}

/// In-memory adapter for testing — the behavioral oracle later backends are
/// checked against.
pub mod memory {
    use super::{
        ChangeSet, Conditions, DeviseKey, HashMap, OrmAdapter, OrmError, Value, async_trait,
    };
    use serde::Serialize;
    use serde::de::DeserializeOwned;
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

    impl<M> MemoryAdapter<M>
    where
        M: Clone + Serialize + DeserializeOwned,
    {
        /// Merge `fields` into the record stored under `key` through a
        /// `serde_json` round-trip and return the merged record.
        ///
        /// # Errors
        ///
        /// Returns [`OrmError::NotFound`] when `key` matches nothing, or
        /// [`OrmError::Serialization`] when the model does not round-trip
        /// through a JSON object.
        ///
        /// # Panics
        ///
        /// Panics when the storage lock is poisoned (a prior holder panicked
        /// while holding it — unrecoverable by design in this test oracle).
        fn apply_fields(
            &self,
            key: &DeviseKey,
            fields: &HashMap<String, Value>,
        ) -> Result<M, OrmError> {
            let mut storage = self.storage.write().unwrap();
            let stored = storage.get(key).cloned().ok_or(OrmError::NotFound)?;
            let mut json = serde_json::to_value(&stored)?;
            let record = json.as_object_mut().ok_or_else(|| {
                <serde_json::Error as serde::de::Error>::custom(
                    "memory adapter models must serialize to a JSON object",
                )
            })?;
            for (field, value) in fields {
                record.insert(field.clone(), serde_json::to_value(value)?);
            }
            let merged: M = serde_json::from_value(json)?;
            storage.insert(key.clone(), merged.clone());
            Ok(merged)
        }
    }

    /// True when every `conditions` entry equals the model's serialized field.
    /// Empty conditions match any record.
    ///
    /// # Errors
    ///
    /// Returns [`OrmError::Serialization`] when the model or a condition value
    /// fails to serialize.
    fn record_matches<M: Serialize>(model: &M, conditions: &Conditions) -> Result<bool, OrmError> {
        let json = serde_json::to_value(model)?;
        let serde_json::Value::Object(map) = &json else {
            return Ok(conditions.to_hashmap().is_empty());
        };
        for (column, expected) in conditions.iter() {
            let expected_json = serde_json::to_value(expected)?;
            if map.get(column) != Some(&expected_json) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    #[async_trait]
    impl<M> OrmAdapter<M> for MemoryAdapter<M>
    where
        M: Send + Sync + Clone + Serialize + DeserializeOwned + 'static,
    {
        type New = M;

        async fn get(&self, id: &DeviseKey) -> Result<Option<M>, OrmError> {
            let storage = self.storage.read().unwrap();
            Ok(storage.get(id).cloned())
        }

        async fn find_first(&self, conditions: &Conditions) -> Result<Option<M>, OrmError> {
            let storage = self.storage.read().unwrap();
            for model in storage.values() {
                if record_matches(model, conditions)? {
                    return Ok(Some(model.clone()));
                }
            }
            Ok(None)
        }

        async fn create(&self, model: M) -> Result<M, OrmError> {
            let mut storage = self.storage.write().unwrap();
            let id = DeviseKey::from_i64(self.next_id());
            storage.insert(id, model.clone());
            Ok(model)
        }

        async fn update(&self, key: &DeviseKey, changes: &ChangeSet) -> Result<M, OrmError> {
            let mut fields = HashMap::new();
            for field in changes.changed_fields() {
                if let Some(value) = changes.current_value(&field) {
                    fields.insert(field, value.clone());
                }
            }
            self.apply_fields(key, &fields)
        }

        async fn update_columns(
            &self,
            key: &DeviseKey,
            fields: &HashMap<String, Value>,
        ) -> Result<M, OrmError> {
            self.apply_fields(key, fields)
        }

        async fn delete(&self, id: &DeviseKey) -> Result<(), OrmError> {
            let mut storage = self.storage.write().unwrap();
            storage.remove(id);
            Ok(())
        }
    }
}

// Time abstraction lives in the top-level `time` module (single definition — DRY).
pub use crate::time::{Clock, FixedClock, SystemClock};

#[cfg(test)]
mod tests {
    use super::{
        ChangeSet, Conditions, Deserialize, DeviseKey, OrmAdapter, OrmError, Serialize, Value,
    };
    use crate::time::{Clock, FixedClock, SystemClock};
    use chrono::{TimeDelta, Utc};
    use std::collections::HashMap;
    use uuid::Uuid;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct MemUser {
        id: i64,
        email: String,
        token: Option<String>,
    }

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

        // Empty conditions match any stored record.
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
        assert!(matches!(err, OrmError::NotFound));
    }

    #[tokio::test]
    async fn test_memory_adapter_full_surface_roundtrip() {
        use crate::adapter::memory::MemoryAdapter;

        let adapter = MemoryAdapter::<MemUser>::new();
        let alice = MemUser {
            id: 0,
            email: "alice@example.com".to_owned(),
            token: Some("tok-alice".to_owned()),
        };

        // Uniqueness probe is true on an empty store.
        assert!(
            adapter
                .column_value_unused("email", &Value::from("alice@example.com"))
                .await
                .unwrap()
        );

        // `create` plus the `insert` alias (D-15); synthetic ids 1, 2 in order.
        let created = adapter.create(alice.clone()).await.unwrap();
        assert_eq!(created, alice);
        let bob = MemUser {
            id: 0,
            email: "bob@example.com".to_owned(),
            token: None,
        };
        let inserted = adapter.insert(bob.clone()).await.unwrap();
        assert_eq!(inserted, bob);

        // `get` / `get_strict`, hit and miss.
        assert_eq!(
            adapter.get(&DeviseKey::from_i64(1)).await.unwrap(),
            Some(alice.clone())
        );
        assert_eq!(
            adapter.get_strict(&DeviseKey::from_i64(2)).await.unwrap(),
            bob
        );
        assert_eq!(adapter.get(&DeviseKey::from_i64(999)).await.unwrap(), None);
        assert!(matches!(
            adapter
                .get_strict(&DeviseKey::from_i64(999))
                .await
                .unwrap_err(),
            OrmError::NotFound
        ));

        // `find_first` / `find_first_strict` filter on real field values.
        let mut cond = Conditions::new();
        cond.insert("email", "alice@example.com");
        assert_eq!(
            adapter.find_first(&cond).await.unwrap(),
            Some(alice.clone())
        );
        assert_eq!(adapter.find_first_strict(&cond).await.unwrap(), alice);
        let mut missing = Conditions::new();
        missing.insert("email", "nobody@example.com");
        assert_eq!(adapter.find_first(&missing).await.unwrap(), None);
        assert!(matches!(
            adapter.find_first_strict(&missing).await.unwrap_err(),
            OrmError::NotFound
        ));

        // `update` rewrites only the `ChangeSet` diff (token untouched).
        let changes = ChangeSet::new(
            HashMap::from([
                ("email".to_owned(), Value::from("alice@example.com")),
                ("token".to_owned(), Value::from("tok-alice")),
            ]),
            HashMap::from([
                ("email".to_owned(), Value::from("alice2@example.com")),
                ("token".to_owned(), Value::from("tok-alice")),
            ]),
        );
        let updated = adapter
            .update(&DeviseKey::from_i64(1), &changes)
            .await
            .unwrap();
        assert_eq!(updated.email, "alice2@example.com");
        assert_eq!(updated.token.as_deref(), Some("tok-alice"));

        // `update_columns` writes named fields even when unchanged (devise #5783).
        let force = HashMap::from([("token".to_owned(), Value::from("tok-alice"))]);
        let forced = adapter
            .update_columns(&DeviseKey::from_i64(1), &force)
            .await
            .unwrap();
        assert_eq!(forced.token.as_deref(), Some("tok-alice"));

        // Both write verbs refuse missing keys.
        let empty = ChangeSet::new(HashMap::new(), HashMap::new());
        assert!(matches!(
            adapter
                .update(&DeviseKey::from_i64(999), &empty)
                .await
                .unwrap_err(),
            OrmError::NotFound
        ));
        assert!(matches!(
            adapter
                .update_columns(&DeviseKey::from_i64(999), &force)
                .await
                .unwrap_err(),
            OrmError::NotFound
        ));
    }

    #[tokio::test]
    async fn test_memory_adapter_uniqueness_probe_and_delete() {
        use crate::adapter::memory::MemoryAdapter;

        let adapter = MemoryAdapter::<MemUser>::new();

        // Probe is true on an empty store, flips per value after a create.
        assert!(
            adapter
                .column_value_unused("email", &Value::from("carol@example.com"))
                .await
                .unwrap()
        );
        adapter
            .create(MemUser {
                id: 0,
                email: "carol@example.com".to_owned(),
                token: None,
            })
            .await
            .unwrap();
        assert!(
            !adapter
                .column_value_unused("email", &Value::from("carol@example.com"))
                .await
                .unwrap()
        );
        assert!(
            adapter
                .column_value_unused("email", &Value::from("fresh@example.com"))
                .await
                .unwrap()
        );

        // `delete`, then `get` → `None`.
        adapter.delete(&DeviseKey::from_i64(1)).await.unwrap();
        assert_eq!(adapter.get(&DeviseKey::from_i64(1)).await.unwrap(), None);
    }

    #[test]
    fn test_orm_error_variants_are_discriminated() {
        assert!(matches!(OrmError::NotFound, OrmError::NotFound));
        assert!(matches!(OrmError::MultipleFound, OrmError::MultipleFound));

        // The PLAT-06 discriminator: Display names the constraint, never a value.
        let unique = OrmError::UniqueViolation {
            constraint: Some("index_users_on_email".to_owned()),
        };
        assert!(matches!(unique, OrmError::UniqueViolation { .. }));
        let rendered = unique.to_string();
        assert!(
            rendered.contains("index_users_on_email"),
            "Display must name the constraint: {rendered}"
        );
        assert!(
            !rendered.contains('@'),
            "Display must not leak values: {rendered}"
        );
        assert!(format!("{unique:?}").contains("UniqueViolation"));

        let bare = OrmError::UniqueViolation { constraint: None };
        assert!(bare.to_string().contains("Unique constraint violation"));

        let query = OrmError::Query {
            message: "column does not exist".to_owned(),
            source: None,
        };
        assert!(query.to_string().contains("Query"));

        let conn = OrmError::Connection {
            message: "connection refused".to_owned(),
            source: None,
        };
        assert!(conn.to_string().contains("Connection"));

        assert!(matches!(
            OrmError::InvalidKey("bogus".to_owned()),
            OrmError::InvalidKey(_)
        ));

        let bad: Result<MemUser, serde_json::Error> =
            serde_json::from_value(serde_json::Value::Null);
        let ser_err = OrmError::from(bad.unwrap_err());
        assert!(matches!(ser_err, OrmError::Serialization(_)));

        // `std::error::Error` plumbing: sources surface, units carry none.
        let with_source = OrmError::Query {
            message: "m".to_owned(),
            source: Some(Box::new(std::io::Error::other("boom"))),
        };
        assert!(std::error::Error::source(&with_source).is_some());
        assert!(std::error::Error::source(&OrmError::NotFound).is_none());
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
