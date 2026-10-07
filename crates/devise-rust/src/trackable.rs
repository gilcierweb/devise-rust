//! Trackable module - sign-in counters, timestamps, and IPs (TRK-01).
//!
//! Mirrors `devise/lib/devise/models/trackable.rb` plus
//! `devise/lib/devise/hooks/trackable.rb`: `update_tracked_fields` shifting
//! current into last, stamping the current time plus the socket-peer IP,
//! bumping `sign_in_count` (first sign-in sets last equal to current), and
//! `update_tracked_fields_bang` persisting validation-free through
//! `update_columns` after probing the adapter for the record key, returning
//! without writing when the record is absent (the issue #4673 new-record
//! guard, D-21).
//!
//! The IP input is the socket peer address carried on
//! [`AuthRequest::peer_addr`](crate::request::AuthRequest::peer_addr).
//! `X-Forwarded-For` and every other proxy header are NEVER read here (D-20,
//! threat T-05-08): only the framework-supplied socket address enters the
//! sign-in record.
//!
//! == Options
//!
//! Trackable adds no options.
//!
//! == Examples
//!
//! ```ignore
//! user.update_tracked_fields(clock.now(), "127.0.0.1");
//! assert_eq!(user.sign_in_count(), 1);
//! user.update_tracked_fields_bang(Some("127.0.0.1"), &adapter, &clock).await?;
//! ```

use crate::adapter::{OrmAdapter, OrmError, Value};
use crate::model::Authenticatable;
use crate::time::Clock;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// `sign_in_count` column.
pub const SIGN_IN_COUNT_COLUMN: &str = "sign_in_count";
/// `current_sign_in_at` column.
pub const CURRENT_SIGN_IN_AT_COLUMN: &str = "current_sign_in_at";
/// `last_sign_in_at` column.
pub const LAST_SIGN_IN_AT_COLUMN: &str = "last_sign_in_at";
/// `current_sign_in_ip` column.
pub const CURRENT_SIGN_IN_IP_COLUMN: &str = "current_sign_in_ip";
/// `last_sign_in_ip` column.
pub const LAST_SIGN_IN_IP_COLUMN: &str = "last_sign_in_ip";

/// Required model fields for Trackable, mirroring Devise's
/// `Trackable.required_fields`.
///
/// == Examples
///
/// ```
/// use devise_rust::trackable::required_fields;
///
/// assert_eq!(
///     required_fields(),
///     vec![
///         "current_sign_in_at",
///         "current_sign_in_ip",
///         "last_sign_in_at",
///         "last_sign_in_ip",
///         "sign_in_count"
///     ]
/// );
/// ```
#[must_use]
pub fn required_fields() -> Vec<&'static str> {
    vec![
        CURRENT_SIGN_IN_AT_COLUMN,
        CURRENT_SIGN_IN_IP_COLUMN,
        LAST_SIGN_IN_AT_COLUMN,
        LAST_SIGN_IN_IP_COLUMN,
        SIGN_IN_COUNT_COLUMN,
    ]
}

/// `Trackable` module - sign-in auditing over the five Devise columns.
///
/// The shift itself ([`update_tracked_fields`](Self::update_tracked_fields))
/// is pure and never touches the adapter; the persisting entry point is
/// [`update_tracked_fields_bang`](Self::update_tracked_fields_bang), which
/// probes for the record first and returns `Ok(false)` with zero writes when
/// the record is absent (D-21).
///
/// == Examples
///
/// ```ignore
/// impl Trackable for User {
///     fn sign_in_count(&self) -> u64 { self.sign_in_count }
///     // ... column accessors ...
/// }
/// ```
#[async_trait]
pub trait Trackable: Authenticatable {
    /// Stored `sign_in_count` column.
    fn sign_in_count(&self) -> u64;
    /// Write the `sign_in_count` column.
    fn set_sign_in_count(&mut self, count: u64);
    /// Stored `current_sign_in_at` column.
    fn current_sign_in_at(&self) -> Option<DateTime<Utc>>;
    /// Write the `current_sign_in_at` column.
    fn set_current_sign_in_at(&mut self, at: Option<DateTime<Utc>>);
    /// Stored `last_sign_in_at` column.
    fn last_sign_in_at(&self) -> Option<DateTime<Utc>>;
    /// Write the `last_sign_in_at` column.
    fn set_last_sign_in_at(&mut self, at: Option<DateTime<Utc>>);
    /// Stored `current_sign_in_ip` column.
    fn current_sign_in_ip(&self) -> Option<&str>;
    /// Write the `current_sign_in_ip` column.
    fn set_current_sign_in_ip(&mut self, ip: Option<String>);
    /// Stored `last_sign_in_ip` column.
    fn last_sign_in_ip(&self) -> Option<&str>;
    /// Write the `last_sign_in_ip` column.
    fn set_last_sign_in_ip(&mut self, ip: Option<String>);
    /// Whether the record is persisted (Devise `persisted?` / `new_record?`
    /// complement). Unpersisted records never write (issue #4673).
    fn persisted(&self) -> bool;

    /// Devise `extract_ip_from(request)`: resolve the sign-in IP from the
    /// socket peer address.
    ///
    /// The default returns the peer address as-is (empty and missing peers
    /// yield `None`); override for custom resolution. Proxy headers are
    /// never consulted here (D-20).
    fn extract_ip_from(&self, peer_addr: Option<&str>) -> Option<String> {
        peer_addr.filter(|ip| !ip.is_empty()).map(str::to_string)
    }

    /// Devise `update_tracked_fields`: shift current into last, stamp the
    /// current time plus `peer_ip`, bump the count.
    ///
    /// First sign-in sets last equal to current (the `||` fallback when no
    /// previous value exists).
    fn update_tracked_fields(&mut self, now: DateTime<Utc>, peer_ip: &str) {
        let previous_at = self.current_sign_in_at();
        self.set_last_sign_in_at(Some(previous_at.unwrap_or(now)));
        self.set_current_sign_in_at(Some(now));

        let previous_ip = self.current_sign_in_ip().map(str::to_string);
        self.set_last_sign_in_ip(Some(previous_ip.unwrap_or_else(|| peer_ip.to_string())));
        self.set_current_sign_in_ip(Some(peer_ip.to_string()));

        self.set_sign_in_count(self.sign_in_count().saturating_add(1));
    }

    /// Snapshot entry point: extract the IP from the socket peer, then shift.
    ///
    /// Pure (no adapter); the hook body and tests share this path.
    fn update_tracked_fields_from_peer(&mut self, peer_addr: Option<&str>, clock: &dyn Clock) {
        let now = clock.now();
        let peer_ip = self.extract_ip_from(peer_addr).unwrap_or_default();
        self.update_tracked_fields(now, &peer_ip);
    }

    /// Devise `update_tracked_fields!` (TRK-01, D-21): probe the adapter for
    /// the record key first and return `Ok(false)` without writing when the
    /// record is absent (the #4673 new-record guard); otherwise shift and
    /// persist validation-free through `update_columns`.
    ///
    /// Returns `Ok(true)` when the shift was persisted.
    ///
    /// # Errors
    ///
    /// `OrmError` when the probe or persistence fails.
    async fn update_tracked_fields_bang<A>(
        &mut self,
        peer_addr: Option<&str>,
        adapter: &A,
        clock: &dyn Clock,
    ) -> Result<bool, OrmError>
    where
        Self: Sized,
        A: OrmAdapter<Self> + Send + Sync,
    {
        if adapter.get(&self.to_key()).await?.is_none() {
            return Ok(false);
        }
        self.update_tracked_fields_from_peer(peer_addr, clock);
        let fields = HashMap::from([
            (
                SIGN_IN_COUNT_COLUMN.to_string(),
                Value::Integer(i64::try_from(self.sign_in_count()).unwrap_or(i64::MAX)),
            ),
            (
                CURRENT_SIGN_IN_AT_COLUMN.to_string(),
                self.current_sign_in_at()
                    .map_or(Value::Null, |at| Value::String(at.to_rfc3339())),
            ),
            (
                LAST_SIGN_IN_AT_COLUMN.to_string(),
                self.last_sign_in_at()
                    .map_or(Value::Null, |at| Value::String(at.to_rfc3339())),
            ),
            (
                CURRENT_SIGN_IN_IP_COLUMN.to_string(),
                self.current_sign_in_ip()
                    .map_or(Value::Null, |ip| Value::String(ip.to_string())),
            ),
            (
                LAST_SIGN_IN_IP_COLUMN.to_string(),
                self.last_sign_in_ip()
                    .map_or(Value::Null, |ip| Value::String(ip.to_string())),
            ),
        ]);
        let updated = adapter.update_columns(&self.to_key(), &fields).await?;
        *self = updated;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::memory::MemoryAdapter;
    use crate::failure::AnyDeviseModel;
    use crate::time::FixedClock;
    use serde::{Deserialize, Serialize};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    struct TestUser {
        id: i64,
        sign_in_count: u64,
        current_sign_in_at: Option<DateTime<Utc>>,
        last_sign_in_at: Option<DateTime<Utc>>,
        current_sign_in_ip: Option<String>,
        last_sign_in_ip: Option<String>,
    }

    impl TestUser {
        fn fresh(id: i64) -> Self {
            Self {
                id,
                ..Self::default()
            }
        }
    }

    impl AnyDeviseModel for TestUser {
        fn to_key(&self) -> crate::adapter::DeviseKey {
            crate::adapter::DeviseKey::from_i64(self.id)
        }

        fn apply_tracked_fields_hook(&mut self, now: DateTime<Utc>, peer_ip: &str) -> bool {
            self.update_tracked_fields(now, peer_ip);
            true
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[async_trait]
    impl Authenticatable for TestUser {}

    #[async_trait]
    impl Trackable for TestUser {
        fn sign_in_count(&self) -> u64 {
            self.sign_in_count
        }

        fn set_sign_in_count(&mut self, count: u64) {
            self.sign_in_count = count;
        }

        fn current_sign_in_at(&self) -> Option<DateTime<Utc>> {
            self.current_sign_in_at
        }

        fn set_current_sign_in_at(&mut self, at: Option<DateTime<Utc>>) {
            self.current_sign_in_at = at;
        }

        fn last_sign_in_at(&self) -> Option<DateTime<Utc>> {
            self.last_sign_in_at
        }

        fn set_last_sign_in_at(&mut self, at: Option<DateTime<Utc>>) {
            self.last_sign_in_at = at;
        }

        fn current_sign_in_ip(&self) -> Option<&str> {
            self.current_sign_in_ip.as_deref()
        }

        fn set_current_sign_in_ip(&mut self, ip: Option<String>) {
            self.current_sign_in_ip = ip;
        }

        fn last_sign_in_ip(&self) -> Option<&str> {
            self.last_sign_in_ip.as_deref()
        }

        fn set_last_sign_in_ip(&mut self, ip: Option<String>) {
            self.last_sign_in_ip = ip;
        }

        fn persisted(&self) -> bool {
            self.id != 0
        }
    }

    /// Adapter wrapper with separate read/write counters, proving the
    /// new-record probe performs zero writes.
    struct CountingAdapter<'a> {
        inner: &'a MemoryAdapter<TestUser>,
        reads: Arc<AtomicUsize>,
        writes: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl crate::adapter::OrmAdapter<TestUser> for CountingAdapter<'_> {
        type New = TestUser;

        async fn get(
            &self,
            id: &crate::adapter::DeviseKey,
        ) -> Result<Option<TestUser>, crate::adapter::OrmError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.inner.get(id).await
        }

        async fn find_first(
            &self,
            conditions: &crate::adapter::Conditions,
        ) -> Result<Option<TestUser>, crate::adapter::OrmError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.inner.find_first(conditions).await
        }

        async fn create(&self, model: TestUser) -> Result<TestUser, crate::adapter::OrmError> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            self.inner.create(model).await
        }

        async fn update(
            &self,
            key: &crate::adapter::DeviseKey,
            changes: &crate::adapter::ChangeSet,
        ) -> Result<TestUser, crate::adapter::OrmError> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            self.inner.update(key, changes).await
        }

        async fn update_columns(
            &self,
            key: &crate::adapter::DeviseKey,
            fields: &HashMap<String, Value>,
        ) -> Result<TestUser, crate::adapter::OrmError> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            self.inner.update_columns(key, fields).await
        }

        async fn delete(
            &self,
            id: &crate::adapter::DeviseKey,
        ) -> Result<(), crate::adapter::OrmError> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            self.inner.delete(id).await
        }
    }

    fn fixed_clock() -> FixedClock {
        FixedClock::new(DateTime::from_timestamp(1_700_000_000, 0).expect("valid epoch"))
    }

    #[tokio::test]
    async fn timeout_trackable_tracer_first_sign_in_shift() {
        let clock = fixed_clock();
        let adapter = MemoryAdapter::<TestUser>::new();
        let mut user = TestUser::fresh(1);
        adapter.create(user.clone()).await.unwrap();

        // Pure shift: count bumps, last equals current on first sign-in.
        user.update_tracked_fields(clock.now(), "127.0.0.1");
        assert_eq!(user.sign_in_count(), 1);
        assert_eq!(user.current_sign_in_at(), user.last_sign_in_at());
        assert!(user.current_sign_in_at().is_some());
        assert_eq!(user.current_sign_in_ip(), Some("127.0.0.1"));
        assert_eq!(user.last_sign_in_ip(), Some("127.0.0.1"));

        // Persisted bang: the store reflects the shift.
        let persisted = user
            .update_tracked_fields_bang(Some("10.0.0.2"), &adapter, &clock)
            .await
            .unwrap();
        assert!(persisted);
        let reloaded = adapter
            .get(&crate::adapter::DeviseKey::from_i64(1))
            .await
            .unwrap()
            .expect("record is stored");
        assert_eq!(reloaded.sign_in_count(), 2);
        assert_eq!(reloaded.current_sign_in_ip(), Some("10.0.0.2"));
        assert_eq!(reloaded.last_sign_in_ip(), Some("127.0.0.1"));
        assert_eq!(reloaded.last_sign_in_at(), user.last_sign_in_at());

        // Absent record (the #4673 guard): no write, in-memory shift skipped.
        let inner = MemoryAdapter::<TestUser>::new();
        let reads = Arc::new(AtomicUsize::new(0));
        let writes = Arc::new(AtomicUsize::new(0));
        let counting = CountingAdapter {
            inner: &inner,
            reads: Arc::clone(&reads),
            writes: Arc::clone(&writes),
        };
        let mut ghost = TestUser::fresh(99);
        let persisted = ghost
            .update_tracked_fields_bang(Some("127.0.0.1"), &counting, &clock)
            .await
            .unwrap();
        assert!(!persisted);
        assert_eq!(
            writes.load(Ordering::SeqCst),
            0,
            "the new-record probe performs zero writes"
        );
        assert_eq!(ghost.sign_in_count(), 0);
    }
}
