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
//! // Ignored doctest: requires a live adapter and an async runtime; the compiled equivalent lives in the crate tests and the example apps.
//! user.update_tracked_fields(clock.now(), Some("127.0.0.1"));
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
///
/// Mirrors the `sign_in_count` trackable column.
pub const SIGN_IN_COUNT_COLUMN: &str = "sign_in_count";
/// `current_sign_in_at` column.
///
/// Mirrors the `current_sign_in_at` trackable column.
pub const CURRENT_SIGN_IN_AT_COLUMN: &str = "current_sign_in_at";
/// `last_sign_in_at` column.
///
/// Mirrors the `last_sign_in_at` trackable column.
pub const LAST_SIGN_IN_AT_COLUMN: &str = "last_sign_in_at";
/// `current_sign_in_ip` column.
///
/// Mirrors the `current_sign_in_ip` trackable column.
pub const CURRENT_SIGN_IN_IP_COLUMN: &str = "current_sign_in_ip";
/// `last_sign_in_ip` column.
///
/// Mirrors the `last_sign_in_ip` trackable column.
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

/// Build the five-field durable sign-in changeset from the record's
/// PRE-shift state, without mutating the record.
///
/// This is the single trackable definition of the sign-in bookkeeping
/// write (261026-ghl): the framework controllers persist this map and the
/// `Event::Authentication` memo hook (axum) or the caller itself (actix)
/// owns the single in-memory shift, so a sign-in increments
/// `sign_in_count` exactly once in the record copy and once in the DB.
/// The framework string-literal copies this replaces had drifted from
/// the core column constants and lost the new-record guard.
///
/// The map mirrors what [`Trackable::update_tracked_fields`] would leave
/// on the record: count + 1, `current_*` stamped with `now` and
/// `peer_ip`, the previous `current_*` shifted into `last_*` (first
/// sign-in sets last equal to current; a missing peer leaves the IP
/// columns NULL, never an empty string).
///
/// == Examples
///
/// ```
/// use devise_rust::time::FixedClock;
/// use chrono::DateTime;
/// // The builder is pure: it reads the pre-shift state and never writes.
/// // Compiled call shapes live in the crate tests and the framework
/// // sign-in bookkeeping (tests compare the map field by field).
/// let clock = FixedClock::new(DateTime::from_timestamp(1_700_000_000, 0).unwrap());
/// let _now = clock.now();
/// ```
#[must_use]
pub fn tracked_fields_changeset<T>(
    record: &T,
    now: DateTime<Utc>,
    peer_ip: Option<&str>,
) -> HashMap<String, Value>
where
    T: Trackable + ?Sized,
{
    // The same shift `update_tracked_fields` applies, computed instead of
    // applied: last receives the previous current (first sign-in falls
    // back to now), and a missing peer stays NULL (never "").
    let last_at = record.current_sign_in_at().unwrap_or(now);
    let last_ip = record
        .current_sign_in_ip()
        .map(str::to_string)
        .or_else(|| peer_ip.map(str::to_string));
    HashMap::from([
        (
            SIGN_IN_COUNT_COLUMN.to_string(),
            Value::Integer(
                i64::try_from(record.sign_in_count().saturating_add(1)).unwrap_or(i64::MAX),
            ),
        ),
        (
            CURRENT_SIGN_IN_AT_COLUMN.to_string(),
            Value::String(now.to_rfc3339()),
        ),
        (
            LAST_SIGN_IN_AT_COLUMN.to_string(),
            Value::String(last_at.to_rfc3339()),
        ),
        (
            CURRENT_SIGN_IN_IP_COLUMN.to_string(),
            peer_ip.map_or(Value::Null, |ip| Value::String(ip.to_string())),
        ),
        (
            LAST_SIGN_IN_IP_COLUMN.to_string(),
            last_ip.map_or(Value::Null, Value::String),
        ),
    ])
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
/// // Ignored doctest: requires a live adapter and an async runtime; the compiled equivalent lives in the crate tests and the example apps.
/// impl Trackable for User {
///     fn sign_in_count(&self) -> u64 { self.sign_in_count }
///     // ... column accessors ...
/// }
/// ```
///
/// Mirrors `Devise::Models::Trackable` (`devise/lib/devise/models/trackable.rb`) as the trait surface: `update_tracked_fields` field shifting and the persisting variant.
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
    fn extract_ip_from<'a>(&self, peer_addr: Option<&'a str>) -> Option<&'a str> {
        peer_addr.filter(|ip| !ip.is_empty())
    }

    /// Devise `update_tracked_fields`: shift current into last, stamp the
    /// current time plus `peer_ip`, bump the count.
    ///
    /// First sign-in sets last equal to current (the `||` fallback when no
    /// previous value exists).
    fn update_tracked_fields(&mut self, now: DateTime<Utc>, peer_ip: Option<&str>) {
        let previous_at = self.current_sign_in_at();
        self.set_last_sign_in_at(Some(previous_at.unwrap_or(now)));
        self.set_current_sign_in_at(Some(now));

        // Devise (`trackable.rb:45-47`) assigns `request.remote_ip` directly:
        // a missing peer leaves the columns NULL. The port never fabricates
        // an empty string (a NULL column vs '' differ for queries/I18n).
        let previous_ip = self.current_sign_in_ip().map(str::to_string);
        self.set_last_sign_in_ip(previous_ip.or_else(|| peer_ip.map(str::to_string)));
        self.set_current_sign_in_ip(peer_ip.map(str::to_string));

        self.set_sign_in_count(self.sign_in_count().saturating_add(1));
    }

    /// Snapshot entry point: extract the IP from the socket peer, then shift.
    ///
    /// Pure (no adapter); the hook body and tests share this path.
    fn update_tracked_fields_from_peer(&mut self, peer_addr: Option<&str>, clock: &dyn Clock) {
        let now = clock.now();
        let peer_ip = self.extract_ip_from(peer_addr);
        self.update_tracked_fields(now, peer_ip);
    }

    /// Devise `update_tracked_fields!` (TRK-01, D-21): probe the adapter for
    /// the record key first and return `Ok(false)` without writing when the
    /// record is absent (the #4673 new-record guard); otherwise build the
    /// tracked-fields changeset through the single core definition
    /// ([`tracked_fields_changeset`]) and persist validation-free through
    /// `update_columns`, replacing `self` with the stored row.
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
        let peer_ip = self.extract_ip_from(peer_addr);
        let fields = tracked_fields_changeset(self, clock.now(), peer_ip);
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

        fn apply_tracked_fields_hook(&mut self, now: DateTime<Utc>, peer_ip: Option<&str>) -> bool {
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

        async fn increment_counter(
            &self,
            key: &crate::adapter::DeviseKey,
            column: &'static str,
        ) -> Result<TestUser, crate::adapter::OrmError> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            self.inner.increment_counter(key, column).await
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
        user.update_tracked_fields(clock.now(), Some("127.0.0.1"));
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

    #[test]
    fn trackable_matrix_required_fields() {
        assert_eq!(
            required_fields(),
            vec![
                "current_sign_in_at",
                "current_sign_in_ip",
                "last_sign_in_at",
                "last_sign_in_ip",
                "sign_in_count"
            ]
        );
    }

    #[tokio::test]
    async fn trackable_matrix_shift_sets_without_saving() {
        let clock = fixed_clock();
        let adapter = MemoryAdapter::<TestUser>::new();
        let mut user = TestUser::fresh(1);
        adapter.create(user.clone()).await.unwrap();

        user.update_tracked_fields(clock.now(), Some("127.0.0.1"));
        assert_eq!(user.current_sign_in_ip(), Some("127.0.0.1"));
        assert_eq!(user.sign_in_count(), 1);

        // The pure shift never wrote: the store still holds the pristine row.
        let reloaded = adapter
            .get(&crate::adapter::DeviseKey::from_i64(1))
            .await
            .unwrap()
            .expect("record is stored");
        assert_eq!(reloaded.current_sign_in_ip(), None);
        assert_eq!(reloaded.last_sign_in_ip(), None);
        assert_eq!(reloaded.current_sign_in_at(), None);
        assert_eq!(reloaded.last_sign_in_at(), None);
        assert_eq!(reloaded.sign_in_count(), 0);
    }

    #[tokio::test]
    async fn trackable_matrix_bang_skips_unpersisted_and_validates_nothing() {
        let clock = fixed_clock();
        let adapter = MemoryAdapter::<TestUser>::new();

        // Unpersisted record (issue #4673 shape): no write, falsy return.
        let mut fresh = TestUser::fresh(0);
        assert!(!fresh.persisted());
        let persisted = fresh
            .update_tracked_fields_bang(Some("127.0.0.1"), &adapter, &clock)
            .await
            .unwrap();
        assert!(!persisted);
        assert_eq!(fresh.sign_in_count(), 0);

        // The bang path never validates: a record no validator would accept
        // still persists through `update_columns`.
        let seed = TestUser::fresh(1);
        adapter.create(seed).await.unwrap();
        let mut stored = adapter
            .get(&crate::adapter::DeviseKey::from_i64(1))
            .await
            .unwrap()
            .expect("record is stored");
        let persisted = stored
            .update_tracked_fields_bang(None, &adapter, &clock)
            .await
            .unwrap();
        assert!(persisted);
        assert_eq!(stored.sign_in_count(), 1);
        // Devise NULL semantics: a missing peer IP never becomes "".
        assert_eq!(stored.current_sign_in_ip(), None);
    }

    /// Override model proving `extract_ip_from` is an override point.
    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    struct OverridingUser {
        inner: TestUser,
    }

    impl AnyDeviseModel for OverridingUser {
        fn to_key(&self) -> crate::adapter::DeviseKey {
            self.inner.to_key()
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[async_trait]
    impl Authenticatable for OverridingUser {}

    #[async_trait]
    impl Trackable for OverridingUser {
        fn sign_in_count(&self) -> u64 {
            self.inner.sign_in_count()
        }

        fn set_sign_in_count(&mut self, count: u64) {
            self.inner.set_sign_in_count(count);
        }

        fn current_sign_in_at(&self) -> Option<DateTime<Utc>> {
            self.inner.current_sign_in_at()
        }

        fn set_current_sign_in_at(&mut self, at: Option<DateTime<Utc>>) {
            self.inner.set_current_sign_in_at(at);
        }

        fn last_sign_in_at(&self) -> Option<DateTime<Utc>> {
            self.inner.last_sign_in_at()
        }

        fn set_last_sign_in_at(&mut self, at: Option<DateTime<Utc>>) {
            self.inner.set_last_sign_in_at(at);
        }

        fn current_sign_in_ip(&self) -> Option<&str> {
            self.inner.current_sign_in_ip()
        }

        fn set_current_sign_in_ip(&mut self, ip: Option<String>) {
            self.inner.set_current_sign_in_ip(ip);
        }

        fn last_sign_in_ip(&self) -> Option<&str> {
            self.inner.last_sign_in_ip()
        }

        fn set_last_sign_in_ip(&mut self, ip: Option<String>) {
            self.inner.set_last_sign_in_ip(ip);
        }

        fn persisted(&self) -> bool {
            self.inner.persisted()
        }

        fn extract_ip_from<'a>(&self, _peer_addr: Option<&'a str>) -> Option<&'a str> {
            Some("127.0.0.2")
        }
    }

    /// 261026-ghl parity pin: the core changeset builder must produce the
    /// byte-identical five-field map the framework sign-in bookkeeping
    /// blocks used to build (shift a copy in memory, then read the five
    /// fields), computed instead from the record's PRE-shift state so the
    /// controller write never needs to mutate the record.
    #[test]
    fn tracked_fields_changeset_pins_the_framework_block_parity() {
        let clock = fixed_clock();
        let now = clock.now();

        // A record with one prior sign-in so the current-to-last shift has
        // real values to move (count 1, current IP 127.0.0.1).
        let mut seeded = TestUser::fresh(1);
        seeded.update_tracked_fields(now, Some("127.0.0.1"));

        // The deleted framework shape: shift a copy, then read the five
        // fields into the map with the same value rendering.
        let mut shifted = seeded.clone();
        shifted.update_tracked_fields(now, Some("10.0.0.4"));
        let expected = HashMap::from([
            (
                SIGN_IN_COUNT_COLUMN.to_string(),
                Value::Integer(i64::try_from(shifted.sign_in_count()).unwrap_or(i64::MAX)),
            ),
            (
                CURRENT_SIGN_IN_AT_COLUMN.to_string(),
                shifted
                    .current_sign_in_at()
                    .map_or(Value::Null, |at| Value::String(at.to_rfc3339())),
            ),
            (
                LAST_SIGN_IN_AT_COLUMN.to_string(),
                shifted
                    .last_sign_in_at()
                    .map_or(Value::Null, |at| Value::String(at.to_rfc3339())),
            ),
            (
                CURRENT_SIGN_IN_IP_COLUMN.to_string(),
                shifted
                    .current_sign_in_ip()
                    .map_or(Value::Null, |ip| Value::String(ip.to_string())),
            ),
            (
                LAST_SIGN_IN_IP_COLUMN.to_string(),
                shifted
                    .last_sign_in_ip()
                    .map_or(Value::Null, |ip| Value::String(ip.to_string())),
            ),
        ]);

        // The core builder produces the identical map from the PRE-shift
        // state, without mutating the source record.
        let built = tracked_fields_changeset(&seeded, now, Some("10.0.0.4"));
        assert_eq!(built, expected);
        assert_eq!(
            seeded.sign_in_count(),
            1,
            "the builder is pure: the source record keeps its pre-shift state"
        );
        assert_eq!(seeded.current_sign_in_ip(), Some("127.0.0.1"));

        // A pristine record (no prior sign-in, no peer) shifts to
        // last == current == now with NULL IPs and count 1.
        let fresh = TestUser::fresh(2);
        let built = tracked_fields_changeset(&fresh, now, None);
        assert_eq!(
            built.get(SIGN_IN_COUNT_COLUMN),
            Some(&Value::Integer(1)),
            "a pristine record shifts to count 1"
        );
        assert_eq!(
            built.get(CURRENT_SIGN_IN_IP_COLUMN),
            Some(&Value::Null),
            "a missing peer leaves the IP columns NULL (D-20)"
        );
        assert_eq!(built.get(LAST_SIGN_IN_IP_COLUMN), Some(&Value::Null));
        assert_eq!(
            built.get(LAST_SIGN_IN_AT_COLUMN),
            built.get(CURRENT_SIGN_IN_AT_COLUMN),
            "the first sign-in sets last equal to current"
        );
    }

    #[test]
    fn trackable_matrix_extract_ip_overridable() {
        let clock = fixed_clock();
        let mut user = OverridingUser {
            inner: TestUser::fresh(1),
        };
        user.update_tracked_fields_from_peer(Some("127.0.0.1"), &clock);
        assert_eq!(user.current_sign_in_ip(), Some("127.0.0.2"));
        assert_eq!(user.last_sign_in_ip(), Some("127.0.0.2"));

        let mut plain = TestUser::fresh(1);
        plain.update_tracked_fields_from_peer(Some("127.0.0.1"), &clock);
        assert_eq!(plain.current_sign_in_ip(), Some("127.0.0.1"));

        // Devise parity (`trackable.rb:45-47`): a missing peer leaves the
        // IP columns NULL - the port never fabricates an empty string.
        let mut missing = TestUser::fresh(1);
        missing.update_tracked_fields_from_peer(None, &clock);
        assert_eq!(missing.current_sign_in_ip(), None);
        assert_eq!(missing.last_sign_in_ip(), None);
    }
}

// TEST-03 security regression sweep (Phase 05 gate).
//
// End-to-end inventory over one user carrying every Phase 05 column family:
// paranoid uniformity plus the dummy-hash timing path, session-salt
// invalidation, the two-cookie-jar rotation kill, the #5783 forced write,
// blank-token guards, the five-condition negatives, the D-05 recipient split,
// proxy-header spoof rejection, and the constant-time source audit.

#[cfg(test)]
mod security_regression {
    use crate::adapter::memory::MemoryAdapter;
    use crate::adapter::{Conditions, OrmAdapter, Value};
    use crate::config::DeviseConfig;
    use crate::confirmable::Confirmable;
    use crate::error::ValidationErrors;
    use crate::failure::AnyDeviseModel;
    use crate::lockable::Lockable;
    use crate::mailer::{HasEmail, TestMailer};
    use crate::model::{Authenticatable, DatabaseAuthenticatable, Validatable};
    use crate::rememberable::Rememberable;
    use crate::request::{AuthRequest, HttpMethod};
    use crate::session::SessionStore;
    use crate::time::{Clock, FixedClock};
    use crate::trackable::Trackable;
    use async_trait::async_trait;
    use chrono::{DateTime, TimeDelta, Utc};
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Sweep user carrying every Phase 05 column family at once.
    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    struct SweepUser {
        id: i64,
        email: String,
        encrypted_password: String,
        #[serde(skip)]
        password: Option<String>,
        #[serde(skip)]
        password_confirmation: Option<String>,
        confirmation_token: Option<String>,
        confirmed_at: Option<DateTime<Utc>>,
        confirmation_sent_at: Option<DateTime<Utc>>,
        unconfirmed_email: Option<String>,
        #[serde(skip)]
        raw_confirmation_token: Option<String>,
        #[serde(skip)]
        bypass_postpone: bool,
        failed_attempts: u32,
        locked_at: Option<DateTime<Utc>>,
        unlock_token: Option<String>,
        #[serde(skip)]
        raw_unlock_token: Option<String>,
        remember_token: Option<String>,
        remember_created_at: Option<DateTime<Utc>>,
        #[serde(skip)]
        remember_flag: Option<bool>,
        sign_in_count: u64,
        current_sign_in_at: Option<DateTime<Utc>>,
        last_sign_in_at: Option<DateTime<Utc>>,
        current_sign_in_ip: Option<String>,
        last_sign_in_ip: Option<String>,
    }

    impl SweepUser {
        fn fresh(id: i64, email: &str, config: &DeviseConfig) -> Self {
            let mut user = Self {
                id,
                email: email.to_string(),
                ..Self::default()
            };
            user.set_password(Some("password123".to_string()), config);
            user.clean_up_passwords();
            user
        }
    }

    impl AnyDeviseModel for SweepUser {
        fn to_key(&self) -> crate::adapter::DeviseKey {
            crate::adapter::DeviseKey::from_i64(self.id)
        }

        fn authenticatable_salt(&self) -> Option<String> {
            self.encrypted_password.get(..29).map(str::to_string)
        }

        fn apply_tracked_fields_hook(&mut self, now: DateTime<Utc>, peer_ip: Option<&str>) -> bool {
            Trackable::update_tracked_fields(self, now, peer_ip);
            true
        }

        fn rememberable_value_opt(&self) -> Option<String> {
            Some(self.remember_token.clone().unwrap_or_default())
        }

        fn remember_created_at_opt(&self) -> Option<DateTime<Utc>> {
            self.remember_created_at
        }

        fn remember_me_flag_opt(&self) -> Option<bool> {
            self.remember_flag
        }

        fn set_remember_me_flag(&mut self, flag: bool) {
            self.remember_flag = Some(flag);
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    impl HasEmail for SweepUser {
        fn email(&self) -> &str {
            &self.email
        }
    }

    #[async_trait]
    impl Authenticatable for SweepUser {
        fn serializable_hash(&self) -> serde_json::Value {
            let mut map = serde_json::json!({ "id": self.id, "email": self.email });
            if let Some(unconfirmed) = &self.unconfirmed_email {
                map["unconfirmed_email"] = serde_json::Value::String(unconfirmed.clone());
            }
            map
        }
    }

    #[async_trait]
    impl DatabaseAuthenticatable for SweepUser {
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

        fn assign_attributes(&mut self, attrs: &serde_json::Map<String, serde_json::Value>) {
            if let Some(serde_json::Value::String(email)) = attrs.get("email") {
                self.email = email.clone();
            }
        }
    }

    #[async_trait]
    impl Validatable for SweepUser {
        fn email_value(&self) -> Option<&str> {
            Some(&self.email)
        }

        fn uniqueness_scope_id(&self) -> Option<String> {
            DatabaseAuthenticatable::persisted(self).then(|| self.id.to_string())
        }
    }

    #[async_trait]
    impl Confirmable for SweepUser {
        fn confirmation_token(&self) -> Option<&str> {
            self.confirmation_token.as_deref()
        }

        fn set_confirmation_token(&mut self, token: Option<String>) {
            self.confirmation_token = token;
        }

        fn confirmed_at(&self) -> Option<DateTime<Utc>> {
            self.confirmed_at
        }

        fn set_confirmed_at(&mut self, at: Option<DateTime<Utc>>) {
            self.confirmed_at = at;
        }

        fn confirmation_sent_at(&self) -> Option<DateTime<Utc>> {
            self.confirmation_sent_at
        }

        fn set_confirmation_sent_at(&mut self, at: Option<DateTime<Utc>>) {
            self.confirmation_sent_at = at;
        }

        fn unconfirmed_email(&self) -> Option<&str> {
            self.unconfirmed_email.as_deref()
        }

        fn set_unconfirmed_email(&mut self, email: Option<String>) {
            self.unconfirmed_email = email;
        }

        fn set_email_address(&mut self, email: String) {
            self.email = email;
        }

        fn raw_confirmation_token(&self) -> Option<&str> {
            self.raw_confirmation_token.as_deref()
        }

        fn set_raw_confirmation_token(&mut self, raw: Option<String>) {
            self.raw_confirmation_token = raw;
        }

        fn consume_reconfirmation_bypass(&mut self) -> bool {
            std::mem::take(&mut self.bypass_postpone)
        }
    }

    #[async_trait]
    impl Lockable for SweepUser {
        fn failed_attempts(&self) -> u32 {
            self.failed_attempts
        }

        fn set_failed_attempts(&mut self, count: u32) {
            self.failed_attempts = count;
        }

        fn locked_at(&self) -> Option<DateTime<Utc>> {
            self.locked_at
        }

        fn set_locked_at(&mut self, at: Option<DateTime<Utc>>) {
            self.locked_at = at;
        }

        fn unlock_token(&self) -> Option<&str> {
            self.unlock_token.as_deref()
        }

        fn set_unlock_token(&mut self, token: Option<String>) {
            self.unlock_token = token;
        }

        fn persisted(&self) -> bool {
            self.id != 0
        }

        fn raw_unlock_token(&self) -> Option<&str> {
            self.raw_unlock_token.as_deref()
        }

        fn set_raw_unlock_token(&mut self, raw: Option<String>) {
            self.raw_unlock_token = raw;
        }
    }

    #[async_trait]
    impl Rememberable for SweepUser {
        fn remember_created_at(&self) -> Option<DateTime<Utc>> {
            self.remember_created_at
        }

        fn set_remember_created_at(&mut self, at: Option<DateTime<Utc>>) {
            self.remember_created_at = at;
        }

        fn remember_token(&self) -> Option<&str> {
            self.remember_token.as_deref()
        }

        fn set_remember_token(&mut self, token: Option<String>) {
            self.remember_token = token;
        }

        fn has_remember_token_column(&self) -> bool {
            true
        }

        fn persisted(&self) -> bool {
            self.id != 0
        }
    }

    #[async_trait]
    impl Trackable for SweepUser {
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

    /// Adapter wrapper counting every call, proving guarded paths perform
    /// zero adapter calls.
    struct CountingAdapter<'a> {
        inner: &'a MemoryAdapter<SweepUser>,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl crate::adapter::OrmAdapter<SweepUser> for CountingAdapter<'_> {
        type New = SweepUser;

        async fn get(
            &self,
            id: &crate::adapter::DeviseKey,
        ) -> Result<Option<SweepUser>, crate::adapter::OrmError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.get(id).await
        }

        async fn find_first(
            &self,
            conditions: &crate::adapter::Conditions,
        ) -> Result<Option<SweepUser>, crate::adapter::OrmError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.find_first(conditions).await
        }

        async fn create(&self, model: SweepUser) -> Result<SweepUser, crate::adapter::OrmError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.create(model).await
        }

        async fn update(
            &self,
            key: &crate::adapter::DeviseKey,
            changes: &crate::adapter::ChangeSet,
        ) -> Result<SweepUser, crate::adapter::OrmError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.update(key, changes).await
        }

        async fn update_columns(
            &self,
            key: &crate::adapter::DeviseKey,
            fields: &HashMap<String, Value>,
        ) -> Result<SweepUser, crate::adapter::OrmError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.update_columns(key, fields).await
        }

        async fn increment_counter(
            &self,
            key: &crate::adapter::DeviseKey,
            column: &'static str,
        ) -> Result<SweepUser, crate::adapter::OrmError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.increment_counter(key, column).await
        }

        async fn delete(
            &self,
            id: &crate::adapter::DeviseKey,
        ) -> Result<(), crate::adapter::OrmError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.delete(id).await
        }
    }

    /// Minimal in-memory session store for the salt-invalidation test.
    #[derive(Debug, Default)]
    struct SweepStore {
        data: std::sync::Arc<std::sync::RwLock<HashMap<String, serde_json::Value>>>,
    }

    #[async_trait]
    impl crate::session::SessionStore for SweepStore {
        async fn get_value(&self, key: &str) -> Option<serde_json::Value> {
            self.data
                .read()
                .expect("lock is readable")
                .get(key)
                .cloned()
        }

        async fn insert_value(&self, key: &str, value: serde_json::Value) {
            self.data
                .write()
                .expect("lock is writable")
                .insert(key.to_string(), value);
        }

        async fn remove(&self, key: &str) {
            self.data.write().expect("lock is writable").remove(key);
        }

        async fn remove_prefix(&self, prefix: &str) {
            let mut data = self.data.write().expect("lock is writable");
            let doomed: Vec<String> = data
                .keys()
                .filter(|key| key.starts_with(prefix))
                .cloned()
                .collect();
            for key in doomed {
                data.remove(&key);
            }
        }

        async fn keys_with_prefix(&self, prefix: &str) -> Vec<String> {
            self.data
                .read()
                .expect("lock is readable")
                .keys()
                .filter(|key| key.starts_with(prefix))
                .cloned()
                .collect()
        }

        async fn renew(&self) -> Result<(), crate::error::DeviseError> {
            Ok(())
        }

        async fn reset(&self) -> Result<(), crate::error::DeviseError> {
            self.data.write().expect("lock is writable").clear();
            Ok(())
        }
    }

    fn sweep_config() -> DeviseConfig {
        DeviseConfig {
            secret_key: "test-secret-key".to_string(),
            stretches: 4,
            ..DeviseConfig::default()
        }
    }

    fn sweep_clock() -> FixedClock {
        FixedClock::new(DateTime::from_timestamp(1_700_000_000, 0).expect("valid epoch"))
    }

    fn email_attrs(email: &str) -> serde_json::Map<String, serde_json::Value> {
        let mut attrs = serde_json::Map::new();
        attrs.insert(
            "email".to_string(),
            serde_json::Value::String(email.to_string()),
        );
        attrs
    }

    #[tokio::test]
    async fn security_regression_paranoid_uniform_invalid_and_unconfirmed_exact() {
        let config = sweep_config();
        let clock = sweep_clock();
        let adapter = MemoryAdapter::<SweepUser>::new();
        let mailer = TestMailer::default();

        // Locked record: suppressed to uniform invalid under paranoid.
        let mut locked = SweepUser::fresh(1, "locked@example.com", &config);
        locked.set_failed_attempts(config.maximum_attempts);
        locked.set_locked_at(Some(clock.now()));
        adapter.create(locked.clone()).await.unwrap();
        assert_eq!(
            locked.lock_unauthenticated_message(&config, &clock),
            "locked"
        );
        let paranoid = DeviseConfig {
            paranoid: true,
            ..sweep_config()
        };
        assert_eq!(
            locked.lock_unauthenticated_message(&paranoid, &clock),
            "invalid"
        );

        // Unknown confirmation request: uniform success, nothing sent (D-08).
        let outcome = SweepUser::send_confirmation_instructions_for(
            &email_attrs("ghost@example.com"),
            &adapter,
            &mailer,
            &paranoid,
            &clock,
        )
        .await
        .unwrap();
        assert!(outcome.is_valid());
        assert!(mailer.sent_mails().is_empty());

        // Same request without paranoid: :not_found, still nothing sent.
        let outcome = SweepUser::send_confirmation_instructions_for(
            &email_attrs("ghost@example.com"),
            &adapter,
            &mailer,
            &config,
            &clock,
        )
        .await
        .unwrap();
        assert!(!outcome.is_valid());
        assert_eq!(
            outcome.errors.get("email"),
            Some(&vec![":not_found".to_string()])
        );
        assert!(mailer.sent_mails().is_empty());

        // Unknown unlock request: Devise-exact, no suppression even under
        // paranoid (lockable carries no paranoid branch on this path, unlike
        // the message branch above).
        let outcome = SweepUser::send_unlock_instructions_for(
            &email_attrs("ghost@example.com"),
            &adapter,
            &mailer,
            &paranoid,
            &clock,
        )
        .await
        .unwrap();
        assert!(!outcome.is_valid());
        assert!(mailer.sent_mails().is_empty());

        // The dummy-hash timing path runs for unknown users (the strategy
        // wrapper converts the miss to uniform invalid; the primitive below
        // is the timing mitigation itself).
        let _dummy = crate::crypto::encryptor::digest("", &paranoid);

        // Unconfirmed inactive message is NOT suppressed under paranoid
        // (Devise-exact: confirmable.rb carries no paranoid branch, unlike
        // lockable.rb). Uniformity covers the request paths, not this gate.
        let unconfirmed = SweepUser::fresh(2, "new@example.com", &config);
        assert_eq!(
            unconfirmed.confirmation_inactive_message(),
            Some("unconfirmed")
        );
    }

    #[tokio::test]
    async fn security_regression_session_salt_invalidates_on_password_change() {
        let config = sweep_config();
        let adapter = MemoryAdapter::<SweepUser>::new();
        let store = SweepStore::default();
        let user = SweepUser::fresh(1, "salt@example.com", &config);
        adapter.create(user.clone()).await.unwrap();

        let (key, salt) = user.serialize_into_session();
        let session_key = crate::session::keys::scope_session_key("user");
        store
            .insert_value(&session_key, serde_json::json!([key.to_string(), salt]))
            .await;
        let found = crate::session::serializer::serialize_from_session::<_, SweepUser>(
            &store, "user", &adapter,
        )
        .await;
        assert_eq!(found, Some(key.clone()));

        // Password change rotates the salt; the old session dies and its key
        // is deleted (warden fetch semantics).
        let mut rotated = user.clone();
        rotated.set_password(Some("new-password-456".to_string()), &config);
        let rotated_salt = rotated
            .database_authenticatable_salt()
            .expect("salt rotates");
        assert_ne!(rotated_salt, salt);
        let fields = HashMap::from([(
            "encrypted_password".to_string(),
            Value::String(rotated.encrypted_password.clone()),
        )]);
        adapter
            .update_columns(&rotated.to_key(), &fields)
            .await
            .unwrap();
        let found = crate::session::serializer::serialize_from_session::<_, SweepUser>(
            &store, "user", &adapter,
        )
        .await;
        assert!(found.is_none());
        assert!(store.get_value(&session_key).await.is_none());
    }

    #[tokio::test]
    async fn security_regression_two_cookie_jars_rotation_kills_both() {
        let config = sweep_config();
        let mut clock = sweep_clock();
        let adapter = MemoryAdapter::<SweepUser>::new();
        let mut user = SweepUser::fresh(1, "jars@example.com", &config);
        adapter.create(user.clone()).await.unwrap();

        user.remember_me(&adapter, &clock).await.unwrap();
        let value = user.rememberable_value().expect("value resolves");
        let old_salt = user.database_authenticatable_salt().expect("salt exists");

        // Epoch-second granularity plus strict greater-than: the cookie must
        // postdate the creation second to validate.
        clock.advance(TimeDelta::seconds(2));
        let generated = clock.now().timestamp().to_string();
        assert!(user.remember_me_valid(&value, &generated, &config, &clock));

        // Credential rotation: new password (new salt) plus a refreshed
        // remember creation instant, both persisted.
        user.set_password(Some("rotated-password".to_string()), &config);
        clock.advance(TimeDelta::hours(1));
        user.set_remember_created_at(Some(clock.now()));
        let fields = HashMap::from([
            (
                "encrypted_password".to_string(),
                Value::String(user.encrypted_password.clone()),
            ),
            (
                "remember_created_at".to_string(),
                Value::String(user.remember_created_at().expect("refreshed").to_rfc3339()),
            ),
        ]);
        adapter
            .update_columns(&user.to_key(), &fields)
            .await
            .unwrap();

        // Jar one (session salt): the old salt no longer matches.
        let fresh = adapter
            .get(&user.to_key())
            .await
            .unwrap()
            .expect("record is stored");
        assert_ne!(
            fresh.database_authenticatable_salt().expect("salt exists"),
            old_salt
        );

        // Jar two (remember cookie): the pre-rotation cookie predates the
        // refreshed creation instant, so the strict greater-than kills it
        // (RMB-05). A cookie minted after the rotation validates.
        assert!(!fresh.remember_me_valid(&value, &generated, &config, &clock));
        clock.advance(TimeDelta::seconds(2));
        let rotated_generated = clock.now().timestamp().to_string();
        assert!(fresh.remember_me_valid(&value, &rotated_generated, &config, &clock));

        // Sign-out with expire_all (D-15) clears the creation instant, which
        // kills every remaining cookie fail-closed.
        let mut signed_out = fresh.clone();
        signed_out.forget_me(&adapter, &config).await.unwrap();
        assert!(signed_out.remember_created_at().is_none());
        assert!(!signed_out.remember_me_valid(&value, &rotated_generated, &config, &clock));
    }

    #[tokio::test]
    async fn security_regression_5783_double_submit_force_writes() {
        let config = sweep_config();
        let clock = sweep_clock();
        let adapter = MemoryAdapter::<SweepUser>::new();
        let mailer = TestMailer::default();
        let mut user = SweepUser::fresh(1, "owner@example.com", &config);
        user.set_confirmed_at(Some(clock.now()));
        adapter.create(user.clone()).await.unwrap();

        let first = user
            .change_email_with_reconfirmation(
                "victim@example.com",
                &adapter,
                &mailer,
                &config,
                &clock,
            )
            .await
            .unwrap()
            .expect("first submit postpones");
        assert_ne!(user.email(), "victim@example.com");

        let second = user
            .change_email_with_reconfirmation(
                "victim@example.com",
                &adapter,
                &mailer,
                &config,
                &clock,
            )
            .await
            .unwrap()
            .expect("unchanged resubmit still force-writes");
        assert_ne!(user.email(), "victim@example.com");
        assert_eq!(user.unconfirmed_email(), Some("victim@example.com"));
        assert_ne!(first, second);

        let mut pending = Conditions::new();
        pending.insert(
            "unconfirmed_email",
            Value::String("victim@example.com".to_string()),
        );
        let stored = adapter.find_first(&pending).await.unwrap();
        assert!(stored.is_some());
    }

    #[tokio::test]
    async fn security_regression_blank_tokens_touch_no_adapter() {
        let config = sweep_config();
        let clock = sweep_clock();
        let inner = MemoryAdapter::<SweepUser>::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let adapter = CountingAdapter {
            inner: &inner,
            calls: Arc::clone(&calls),
        };
        let validate = |_: &SweepUser| ValidationErrors::new();

        for blank in [None, Some(""), Some("   ")] {
            let outcome = SweepUser::confirm_by_token(blank, &adapter, &config, &clock, &validate)
                .await
                .unwrap();
            assert!(!outcome.is_valid());
            assert_eq!(
                outcome.errors.get("confirmation_token"),
                Some(&vec![":blank".to_string()])
            );
        }
        for blank in [None, Some(""), Some("   ")] {
            let outcome = SweepUser::unlock_access_by_token(blank, &adapter, &config)
                .await
                .unwrap();
            assert!(!outcome.is_valid());
            assert_eq!(
                outcome.errors.get("unlock_token"),
                Some(&vec![":blank".to_string()])
            );
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "blank tokens never reach the adapter"
        );
    }

    #[tokio::test]
    async fn security_regression_five_condition_negatives() {
        let config = sweep_config();
        let mut clock = sweep_clock();
        let adapter = MemoryAdapter::<SweepUser>::new();
        let mut user = SweepUser::fresh(1, "conditions@example.com", &config);
        adapter.create(user.clone()).await.unwrap();
        user.remember_me(&adapter, &clock).await.unwrap();
        let value = user.rememberable_value().expect("value resolves");
        let key = user.to_key().to_string();

        // Epoch-second granularity plus strict greater-than: valid cookies
        // postdate the creation second.
        clock.advance(TimeDelta::seconds(2));
        let generated = clock.now().timestamp().to_string();
        let found =
            SweepUser::serialize_from_cookie(&key, &value, &generated, &adapter, &config, &clock)
                .await;
        assert!(found.is_some());

        // 1. Unparseable generation instant.
        let found =
            SweepUser::serialize_from_cookie(&key, &value, "not-a-time", &adapter, &config, &clock)
                .await;
        assert!(found.is_none());

        // 2. Unknown record key.
        let found =
            SweepUser::serialize_from_cookie("999", &value, &generated, &adapter, &config, &clock)
                .await;
        assert!(found.is_none());

        // 3. Missing timestamp.
        let found =
            SweepUser::serialize_from_cookie(&key, &value, "", &adapter, &config, &clock).await;
        assert!(found.is_none());

        // 4. Timestamp earlier than the creation instant.
        let earlier = (user.remember_created_at().expect("created is set") - TimeDelta::hours(1))
            .timestamp()
            .to_string();
        let found =
            SweepUser::serialize_from_cookie(&key, &value, &earlier, &adapter, &config, &clock)
                .await;
        assert!(found.is_none());

        // 5. Timestamp older than remember_for.
        let stale = (clock.now() - config.remember_for - TimeDelta::hours(1))
            .timestamp()
            .to_string();
        let found =
            SweepUser::serialize_from_cookie(&key, &value, &stale, &adapter, &config, &clock).await;
        assert!(found.is_none());

        // 6. Wrong token (constant-time mismatch).
        let found =
            SweepUser::serialize_from_cookie(&key, "wrong", &generated, &adapter, &config, &clock)
                .await;
        assert!(found.is_none());

        // 7. Missing creation instant fails closed.
        let mut dateless = user.clone();
        dateless.set_remember_created_at(None);
        assert!(!dateless.remember_me_valid(&value, &generated, &config, &clock));
    }

    #[tokio::test]
    async fn security_regression_d05_recipient_split() {
        let config = DeviseConfig {
            send_email_changed_notification: true,
            ..sweep_config()
        };
        let clock = sweep_clock();
        let adapter = MemoryAdapter::<SweepUser>::new();
        let mailer = TestMailer::default();
        let mut user = SweepUser::fresh(1, "original@example.com", &config);
        user.set_confirmed_at(Some(clock.now()));
        adapter.create(user.clone()).await.unwrap();

        let raw = user
            .change_email_with_reconfirmation("new@example.com", &adapter, &mailer, &config, &clock)
            .await
            .unwrap()
            .expect("postpones with instructions");
        assert_ne!(raw.len(), 0);

        let sent = mailer.sent_mails();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].to, "original@example.com");
        assert!(sent[0].template_vars.token.is_none());
        assert_eq!(sent[1].to, "new@example.com");
        assert_eq!(sent[1].template_vars.token.as_deref(), Some(raw.as_str()));
    }

    #[tokio::test]
    async fn security_regression_proxy_spoof_never_reaches_record() {
        let config = sweep_config();
        let clock = sweep_clock();
        let adapter = MemoryAdapter::<SweepUser>::new();
        let mut user = SweepUser::fresh(1, "spoof@example.com", &config);
        adapter.create(user.clone()).await.unwrap();

        // Forged proxy headers ride alongside the socket peer. The shift path
        // accepts the peer only; headers are not even readable there.
        let mut request = AuthRequest::new(HttpMethod::Post, "/users/sign_in".to_string())
            .peer_addr("10.0.0.5".to_string());
        request
            .headers
            .insert("x-forwarded-for".to_string(), "9.9.9.9".to_string());
        request
            .headers
            .insert("x-real-ip".to_string(), "9.9.9.9".to_string());
        let persisted = user
            .update_tracked_fields_bang(request.peer_addr.as_deref(), &adapter, &clock)
            .await
            .unwrap();
        assert!(persisted);
        let reloaded = adapter
            .get(&user.to_key())
            .await
            .unwrap()
            .expect("record is stored");
        assert_eq!(reloaded.current_sign_in_ip(), Some("10.0.0.5"));
        assert_eq!(reloaded.last_sign_in_ip(), Some("10.0.0.5"));
    }

    /// Shipped (non-test) source with doc comments stripped, so prose naming
    /// a forbidden header cannot trip the audit.
    fn shipped_source(source: &str) -> String {
        let without_tests = source.split("#[cfg(test)]").next().unwrap_or(source);
        without_tests
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn security_regression_constant_time_audit() {
        const CONFIRMABLE: &str = include_str!("confirmable.rs");
        const LOCKABLE: &str = include_str!("lockable.rs");
        const REMEMBERABLE: &str = include_str!("rememberable.rs");
        const TIMEOUTABLE: &str = include_str!("timeoutable.rs");
        const TRACKABLE: &str = include_str!("trackable.rs");

        // Every secret equality in the five modules goes through an approved
        // primitive: `secure_compare` for presented-value checks (remember
        // cookie), `token_generator::digest` for stored-token lookups
        // (confirmation and unlock tokens are HMAC-bound and never compared
        // raw, exactly as Devise stores digests and looks them up).
        for (name, source) in [("confirmable", CONFIRMABLE), ("lockable", LOCKABLE)] {
            assert!(
                shipped_source(source).contains("token_generator::digest"),
                "{name} binds stored tokens through the HMAC digest, never raw"
            );
        }
        assert!(
            shipped_source(REMEMBERABLE).contains("secure_compare"),
            "rememberable routes secret compares through the constant-time helper"
        );

        // No shipped module parses proxy headers (threat T-05-08, D-20).
        for (name, source) in [
            ("confirmable", CONFIRMABLE),
            ("lockable", LOCKABLE),
            ("rememberable", REMEMBERABLE),
            ("timeoutable", TIMEOUTABLE),
            ("trackable", TRACKABLE),
        ] {
            let shipped = shipped_source(source).to_lowercase();
            assert!(
                !shipped.contains("forwarded"),
                "{name} never parses proxy headers"
            );
            assert!(
                !shipped.contains("x-real-ip"),
                "{name} never parses proxy headers"
            );
        }

        // The helper itself: equal matches, mismatches and length leaks fail
        // closed without panicking.
        assert!(crate::crypto::secure_compare(
            "cookie-token",
            "cookie-token"
        ));
        assert!(!crate::crypto::secure_compare(
            "cookie-token",
            "wrong-token!"
        ));
        assert!(!crate::crypto::secure_compare("short", "much-longer-value"));
        assert!(!crate::crypto::secure_compare("", "cookie-token"));
    }
}
