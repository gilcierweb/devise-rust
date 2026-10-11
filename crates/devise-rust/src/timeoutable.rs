//! Timeoutable module - inactivity timeout over the session `last_request_at` epoch (TMO-01, TMO-02).
//!
//! Mirrors `devise/lib/devise/models/timeoutable.rb` plus
//! `devise/lib/devise/hooks/timeoutable.rb`: `timedout` with the Devise-exact
//! less-than-or-equal boundary against now minus `timeout_in`, the per-request
//! `last_request_at` Integer-epoch tick, the live remember-me exemption
//! (D-18), all-scopes sign-out with the `:timeout` failure (D-19), and the
//! `skip_timeout` / `skip_timeoutable` bypass flags (D-17).
//!
//! The session slot holds an Integer epoch (D-17). Readers accept a strict
//! integer-epoch string defensively (legacy JSON stores); anything else is
//! malformed and fails closed to expired, never rescued toward valid.
//!
//! == Options
//!
//! * `timeout_in` - inactivity window before the session expires
//!   (default 30 minutes, D-17)
//! * `sign_out_all_scopes` - timeout signs out every scope (default true, D-19)
//!
//! == Examples
//!
//! ```ignore
//! // Ignored doctest: requires a live adapter and an async runtime; the compiled equivalent lives in the crate tests and the example apps.
//! assert!(user.timedout(Some(clock.now() - config.timeout_in - TimeDelta::minutes(1)), &config, &clock));
//! assert!(!user.timedout(None, &config, &clock));
//! ```

use crate::config::DeviseConfig;
use crate::model::Authenticatable;
use crate::request::{AuthRequest, RequestFlags};
use crate::time::Clock;
use chrono::{DateTime, TimeDelta, Utc};

/// Session field holding the last-request epoch (Devise `last_request_at`).
///
/// Mirrors the session `last_request_at` slot devise's timeoutable hook reads and writes per request.
pub const LAST_REQUEST_AT_FIELD: &str = "last_request_at";

/// Required model fields for Timeoutable, mirroring Devise's
/// `Timeoutable.required_fields` (session-based: none).
///
/// == Examples
///
/// ```
/// use devise_rust::timeoutable::required_fields;
///
/// assert!(required_fields().is_empty());
/// ```
#[must_use]
pub fn required_fields() -> Vec<&'static str> {
    Vec::new()
}

/// Session-store key for the scoped `last_request_at` tick.
///
/// Devise keeps the tick inside `warden.session(scope)`; the flat
/// `SessionStore` maps that slot to one namespaced key per scope.
///
/// == Examples
///
/// ```
/// use devise_rust::timeoutable::last_request_at_key;
///
/// assert_eq!(last_request_at_key("user"), "warden.user.user.last_request_at");
/// ```
///
/// Namespaced session key for the tick; mirrors the slot devise keeps inside `warden.session(scope)`.
#[must_use]
pub fn last_request_at_key(scope: &str) -> String {
    format!("warden.user.{scope}.{LAST_REQUEST_AT_FIELD}")
}

/// `Timeoutable` module - session expiry over inactivity.
///
/// Timeoutable carries no columns: every decision reads the session tick.
/// `timedout` is the model predicate; [`check_timeout`] is the session-value
/// entry point the hook body uses; [`remember_active_for_timeout`] is the
/// live remember-me exemption (D-18).
///
/// == Options
///
/// See the module-level docs: `timeout_in`.
///
/// == Examples
///
/// ```ignore
/// // Ignored doctest: requires a live adapter and an async runtime; the compiled equivalent lives in the crate tests and the example apps.
/// impl Timeoutable for User {}
/// ```
///
/// Mirrors `Devise::Models::Timeoutable` (`devise/lib/devise/models/timeoutable.rb`) as the trait surface: `timedout` with the Devise-exact boundary.
pub trait Timeoutable: Authenticatable {
    /// Per-model `timeout_in` window (Devise `timeout_in`): defaults to the
    /// global config so apps override per model by overriding this method
    /// (mirrors the Devise test overriding `timeout_in` on the instance).
    fn timeout_in(&self, config: &DeviseConfig) -> TimeDelta {
        config.timeout_in
    }

    /// `timedout?` (TMO-01): true only when a last-access instant exists and
    /// sits on or before now minus `timeout_in`.
    ///
    /// The `<=` boundary is Devise-exact: a tick exactly `timeout_in` old
    /// counts as timed out. A missing instant (first request, no tick yet)
    /// is never timed out.
    fn timedout(
        &self,
        last_access: Option<DateTime<Utc>>,
        config: &DeviseConfig,
        clock: &dyn Clock,
    ) -> bool {
        last_access.is_some_and(|at| at <= clock.now() - self.timeout_in(config))
    }
}

/// Strict parse of a stored `last_request_at` value into an instant.
///
/// Accepts Integer epochs and strict integer-epoch strings (legacy JSON
/// stores); float strings, free-form dates, and every other JSON shape
/// return `None` so the caller fails closed instead of rescuing toward valid.
///
/// == Examples
///
/// ```
/// use devise_rust::timeoutable::parse_last_request_at;
///
/// assert!(parse_last_request_at(&serde_json::json!(1_700_000_000)).is_some());
/// assert!(parse_last_request_at(&serde_json::json!("1700000000")).is_some());
/// assert!(parse_last_request_at(&serde_json::json!("1700000000.5")).is_none());
/// assert!(parse_last_request_at(&serde_json::json!("yesterday")).is_none());
/// assert!(parse_last_request_at(&serde_json::Value::Null).is_none());
/// ```
///
/// Strict parse of the stored tick; mirrors devise's permissive string parse hardened to fail closed on malformed values.
#[must_use]
pub fn parse_last_request_at(value: &serde_json::Value) -> Option<DateTime<Utc>> {
    if let Some(epoch) = value.as_i64() {
        return DateTime::from_timestamp(epoch, 0);
    }
    if let Some(raw) = value.as_str() {
        let epoch: i64 = raw.trim().parse().ok()?;
        return DateTime::from_timestamp(epoch, 0);
    }
    None
}

/// Classified shape of the stored tick.
///
/// Classification of the stored tick (Missing, Malformed, At); mirrors devise's timedout read with the fail-closed posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LastRequestTick {
    /// No tick stored yet (first request): live, tick it.
    Missing,
    /// Stored value present but unparseable: fail closed to expired.
    Malformed,
    /// Parsed instant to compare against the window.
    At(DateTime<Utc>),
}

/// Classify the stored session value (D-17, threat T-05-09).
///
/// `None` (absent key) is `Missing`; a present value that parses is `At`;
/// anything else is `Malformed`.
///
/// == Examples
///
/// ```
/// use devise_rust::timeoutable::{LastRequestTick, classify_last_request};
///
/// assert_eq!(classify_last_request(None), LastRequestTick::Missing);
/// assert_eq!(
///     classify_last_request(Some(&serde_json::json!("oops"))),
///     LastRequestTick::Malformed
/// );
/// ```
///
/// Classifies the stored session value into the tick taxonomy; the typed mirror of devise's defensive parse.
#[must_use]
pub fn classify_last_request(stored: Option<&serde_json::Value>) -> LastRequestTick {
    match stored {
        None => LastRequestTick::Missing,
        Some(value) => match parse_last_request_at(value) {
            Some(at) => LastRequestTick::At(at),
            None => LastRequestTick::Malformed,
        },
    }
}

/// Whether a classified tick counts as expired.
///
/// `Missing` is live (Devise `timedout?(nil)` is falsy); `Malformed` fails
/// closed to expired (threat T-05-09); `At` uses the Devise-exact `<=`
/// boundary.
///
/// Mirrors the Devise-exact less-than-or-equal boundary of `timedout?`; `Missing` stays live and `Malformed` fails closed to expired.
///
/// == Examples
///
/// ```
/// use chrono::TimeDelta;
/// use devise_rust::time::FixedClock;
/// use devise_rust::timeoutable::{LastRequestTick, tick_expired};
///
/// let clock = FixedClock::new(chrono::Utc::now());
/// let window = TimeDelta::minutes(30);
/// assert!(!tick_expired(LastRequestTick::Missing, window, &clock));
/// assert!(tick_expired(LastRequestTick::Malformed, window, &clock));
/// ```
#[must_use]
pub fn tick_expired(tick: LastRequestTick, timeout_in: TimeDelta, clock: &dyn Clock) -> bool {
    match tick {
        LastRequestTick::Missing => false,
        LastRequestTick::Malformed => true,
        LastRequestTick::At(at) => at <= clock.now() - timeout_in,
    }
}

/// Hook decision for one request (D-17).
///
/// The hook's verdict (Skipped, Live, Expired) mirroring the outcomes of `devise/lib/devise/hooks/timeoutable.rb`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutDecision {
    /// A skip flag bypassed the check entirely: no expiry, no tick.
    Skipped,
    /// Session is live: tick the epoch (unless `skip_trackable`).
    Live,
    /// Session expired (or malformed): sign out, fail `:timeout`.
    Expired,
}

/// Evaluate the timeout check for one request (TMO-01, D-17).
///
/// `skip_timeoutable` or `skip_timeout` bypasses everything (`Skipped`).
/// Otherwise the stored tick classifies to `Live` or `Expired`; the
/// remember-me exemption is NOT evaluated here (it needs the live record
/// plus cookie, see [`remember_active_for_timeout`]).
///
/// == Examples
///
/// ```
/// use devise_rust::config::DeviseConfig;
/// use devise_rust::request::RequestFlags;
/// use devise_rust::time::{Clock, FixedClock};
/// use devise_rust::timeoutable::{TimeoutDecision, check_timeout};
/// use chrono::DateTime;
///
/// let clock = FixedClock::new(DateTime::from_timestamp(1_700_000_000, 0).expect("valid epoch"));
/// let config = DeviseConfig::default();
/// let flags = RequestFlags::default();
/// let stale = serde_json::json!(1_700_000_000 - 31 * 60);
/// assert_eq!(
///     check_timeout(Some(&stale), &flags, config.timeout_in, &clock),
///     TimeoutDecision::Expired
/// );
/// assert_eq!(check_timeout(None, &flags, config.timeout_in, &clock), TimeoutDecision::Live);
/// ```
///
/// Per-request timeout evaluation mirroring the devise timeoutable hook: skip flags, classification, and the tick refresh.
#[must_use]
pub fn check_timeout(
    stored: Option<&serde_json::Value>,
    flags: &RequestFlags,
    timeout_in: TimeDelta,
    clock: &dyn Clock,
) -> TimeoutDecision {
    if flags.skip_timeoutable || flags.skip_timeout {
        return TimeoutDecision::Skipped;
    }
    if tick_expired(classify_last_request(stored), timeout_in, clock) {
        TimeoutDecision::Expired
    } else {
        TimeoutDecision::Live
    }
}

/// Live remember-me exemption (TMO-02, D-18, threat T-05-09).
///
/// Revalidates the cookie triple NOW against the live record: the jar entry
/// under the scope cookie key must decode, its key segment must name this
/// record, and the five-condition [`remember_cookie_valid`](crate::rememberable::remember_cookie_valid)
/// check must pass over the record's current value plus `remember_created_at`.
/// A stale flag is never trusted; any miss (no request, no record value, no
/// cookie, undecodable triple, failed check) returns false.
///
/// == Examples
///
/// ```ignore
/// // Ignored doctest: requires a live adapter and an async runtime; the compiled equivalent lives in the crate tests and the example apps.
/// if crate::timeoutable::remember_active_for_timeout(record, request, scope, config, clock) {
///     // Exempt: tick and continue.
/// }
/// ```
///
/// The live remember-me exemption mirroring the one devise's timeoutable hook honors before failing a request as timed out.
#[must_use]
pub fn remember_active_for_timeout(
    record: &dyn crate::failure::AnyDeviseModel,
    request: &AuthRequest,
    scope: &str,
    config: &DeviseConfig,
    clock: &dyn Clock,
) -> bool {
    let key = crate::rememberable::remember_cookie_key(scope, config);
    let Some(jar) = request.cookies.get(&key) else {
        return false;
    };
    let Some((cookie_key, token, generated_at)) = crate::rememberable::decode_cookie_value(jar)
    else {
        return false;
    };
    if cookie_key != record.to_key().to_string() {
        return false;
    }
    let Some(stored) = record.rememberable_value_opt() else {
        return false;
    };
    if stored.is_empty() {
        return false;
    }
    let generated = crate::rememberable::parse_generated_at(&generated_at);
    crate::rememberable::remember_cookie_valid(
        &stored,
        &token,
        generated,
        record.remember_created_at_opt(),
        config,
        clock,
    )
}

/// Read the stored tick for `scope` (hook plumbing).
pub async fn read_last_request_at(
    store: &dyn crate::session::SessionStore,
    scope: &str,
) -> Option<serde_json::Value> {
    store.get_value(&last_request_at_key(scope)).await
}

/// Tick the stored epoch for `scope` to now (hook plumbing, D-17).
///
/// The tick honors no flag itself; the caller skips it under
/// `skip_trackable` (Devise shares that flag for the tick write).
pub async fn tick_last_request_at(
    store: &dyn crate::session::SessionStore,
    scope: &str,
    clock: &dyn Clock,
) {
    store
        .insert_value(
            &last_request_at_key(scope),
            serde_json::Value::Number(serde_json::Number::from(clock.now().timestamp())),
        )
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::failure::AnyDeviseModel;
    use crate::time::FixedClock;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    struct TestUser {
        id: i64,
    }

    impl AnyDeviseModel for TestUser {
        fn to_key(&self) -> crate::adapter::DeviseKey {
            crate::adapter::DeviseKey::from_i64(self.id)
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[async_trait::async_trait]
    impl Authenticatable for TestUser {}

    impl Timeoutable for TestUser {}

    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    struct CustomTimeoutUser {
        id: i64,
    }

    impl AnyDeviseModel for CustomTimeoutUser {
        fn to_key(&self) -> crate::adapter::DeviseKey {
            crate::adapter::DeviseKey::from_i64(self.id)
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[async_trait::async_trait]
    impl Authenticatable for CustomTimeoutUser {}

    impl Timeoutable for CustomTimeoutUser {
        fn timeout_in(&self, _config: &DeviseConfig) -> TimeDelta {
            TimeDelta::minutes(10)
        }
    }

    fn test_config() -> DeviseConfig {
        DeviseConfig::default()
    }

    fn fixed_clock() -> FixedClock {
        FixedClock::new(DateTime::from_timestamp(1_700_000_000, 0).expect("valid epoch"))
    }

    fn epoch_offset(seconds_ago: i64) -> serde_json::Value {
        serde_json::json!(1_700_000_000 - seconds_ago)
    }
    #[tokio::test]
    async fn timeout_trackable_tracer_stale_tick_times_out() {
        let config = test_config();
        let clock = fixed_clock();
        let user = TestUser { id: 1 };
        let flags = RequestFlags::default();

        // Stale tick (31 minutes, past the 30-minute default): expired.
        let stale = epoch_offset(31 * 60);
        assert!(user.timedout(parse_last_request_at(&stale), &config, &clock));
        assert_eq!(
            check_timeout(Some(&stale), &flags, config.timeout_in, &clock),
            TimeoutDecision::Expired
        );

        // Fresh tick (29 minutes): live.
        let fresh = epoch_offset(29 * 60);
        assert!(!user.timedout(parse_last_request_at(&fresh), &config, &clock));
        assert_eq!(
            check_timeout(Some(&fresh), &flags, config.timeout_in, &clock),
            TimeoutDecision::Live
        );

        // Missing tick (first request, Devise nil): live, tick it.
        assert!(!user.timedout(None, &config, &clock));
        assert_eq!(
            check_timeout(None, &flags, config.timeout_in, &clock),
            TimeoutDecision::Live
        );

        // Devise-exact boundary: exactly timeout_in old counts timed out (<=).
        let boundary = epoch_offset(30 * 60);
        assert!(user.timedout(parse_last_request_at(&boundary), &config, &clock));
        assert_eq!(
            check_timeout(Some(&boundary), &flags, config.timeout_in, &clock),
            TimeoutDecision::Expired
        );

        // Skip flags bypass the check entirely, even for a stale tick.
        let skipping = RequestFlags {
            skip_timeoutable: true,
            ..RequestFlags::default()
        };
        assert_eq!(
            check_timeout(Some(&stale), &skipping, config.timeout_in, &clock),
            TimeoutDecision::Skipped
        );
        let skipping = RequestFlags {
            skip_timeout: true,
            ..RequestFlags::default()
        };
        assert_eq!(
            check_timeout(Some(&stale), &skipping, config.timeout_in, &clock),
            TimeoutDecision::Skipped
        );

        // Malformed stored values fail closed to expired.
        for malformed in [
            serde_json::json!("not-a-time"),
            serde_json::json!("1700000000.5"),
            serde_json::json!(serde_json::json!({"epoch": 1})),
            serde_json::Value::Null,
            serde_json::json!(true),
        ] {
            assert_eq!(
                classify_last_request(Some(&malformed)),
                LastRequestTick::Malformed,
                "value {malformed} must classify malformed"
            );
            assert_eq!(
                check_timeout(Some(&malformed), &flags, config.timeout_in, &clock),
                TimeoutDecision::Expired,
                "value {malformed} must fail closed"
            );
        }

        // Per-model timeout_in override (Devise "should use timeout_in method").
        let custom = CustomTimeoutUser { id: 2 };
        let twelve = clock.now() - TimeDelta::minutes(12);
        let eight = clock.now() - TimeDelta::minutes(8);
        assert!(custom.timedout(Some(twelve), &config, &clock));
        assert!(!custom.timedout(Some(eight), &config, &clock));

        // Session I/O round-trip through the tick helpers.
        let store = TickStore::default();
        tick_last_request_at(&store, "user", &clock).await;
        let stored = read_last_request_at(&store, "user").await;
        assert_eq!(
            check_timeout(stored.as_ref(), &flags, config.timeout_in, &clock),
            TimeoutDecision::Live
        );
    }

    #[test]
    fn timeoutable_matrix_config_fallback_and_zero_window() {
        let clock = fixed_clock();
        let user = TestUser { id: 1 };

        // Fallback to the config option (Devise `swap Devise, timeout_in:`).
        let narrow = DeviseConfig {
            timeout_in: TimeDelta::minutes(1),
            ..DeviseConfig::default()
        };
        assert!(user.timedout(parse_last_request_at(&epoch_offset(120)), &narrow, &clock));
        assert!(!user.timedout(parse_last_request_at(&epoch_offset(30)), &narrow, &clock));

        let wide = DeviseConfig {
            timeout_in: TimeDelta::minutes(5),
            ..DeviseConfig::default()
        };
        assert!(!user.timedout(parse_last_request_at(&epoch_offset(120)), &wide, &clock));
        assert!(user.timedout(parse_last_request_at(&epoch_offset(360)), &wide, &clock));

        // A zero window expires every past tick (Devise `0.ago` is now, and
        // every stored tick is `<=` now). Devise's nil-window (never expires)
        // has no `TimeDelta` representation, so it is intentionally not
        // ported; the per-model `timeout_in` override stays the opt-out seam.
        let zero = DeviseConfig {
            timeout_in: TimeDelta::zero(),
            ..DeviseConfig::default()
        };
        assert!(user.timedout(parse_last_request_at(&epoch_offset(1)), &zero, &clock));
        assert!(!user.timedout(None, &zero, &clock));

        assert!(required_fields().is_empty());
    }

    /// Record carrying remember state for the exemption matrix.
    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    struct RememberingUser {
        id: i64,
        value: Option<String>,
        created_at: Option<DateTime<Utc>>,
    }

    impl AnyDeviseModel for RememberingUser {
        fn to_key(&self) -> crate::adapter::DeviseKey {
            crate::adapter::DeviseKey::from_i64(self.id)
        }

        fn rememberable_value_opt(&self) -> Option<String> {
            self.value.clone()
        }

        fn remember_created_at_opt(&self) -> Option<DateTime<Utc>> {
            self.created_at
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[async_trait::async_trait]
    impl Authenticatable for RememberingUser {}

    fn exemption_request(cookie: Option<String>) -> AuthRequest {
        let mut request =
            AuthRequest::new(crate::request::HttpMethod::Get, "/protected".to_string());
        if let Some(jar) = cookie {
            request.cookies.insert(
                crate::rememberable::remember_cookie_key("user", &DeviseConfig::default()),
                jar,
            );
        }
        request
    }

    fn exemption_user(config: &DeviseConfig, clock: &FixedClock) -> (RememberingUser, String) {
        let created = clock.now() - TimeDelta::hours(1);
        let user = RememberingUser {
            id: 1,
            value: Some("cookie-token".to_string()),
            created_at: Some(created),
        };
        // Epoch-second granularity plus strict greater-than: the cookie must
        // postdate the creation second to validate.
        let generated = (clock.now() - TimeDelta::minutes(30))
            .timestamp()
            .to_string();
        let jar = crate::rememberable::encode_cookie_value("1", "cookie-token", &generated);
        let _ = config;
        (user, jar)
    }

    #[test]
    fn timeoutable_matrix_remember_exemption() {
        let config = test_config();
        let clock = fixed_clock();

        // Live remember-me session with a stale tick stays exempt.
        let (user, jar) = exemption_user(&config, &clock);
        let request = exemption_request(Some(jar));
        assert!(remember_active_for_timeout(
            &user, &request, "user", &config, &clock
        ));

        // Every miss shape loses the exemption (stale flags never trusted).
        let (user, _) = exemption_user(&config, &clock);
        assert!(!remember_active_for_timeout(
            &user,
            &exemption_request(None),
            "user",
            &config,
            &clock
        ));

        let stale_generated = (clock.now() - config.remember_for - TimeDelta::hours(1))
            .timestamp()
            .to_string();
        let stale_jar =
            crate::rememberable::encode_cookie_value("1", "cookie-token", &stale_generated);
        assert!(!remember_active_for_timeout(
            &user,
            &exemption_request(Some(stale_jar)),
            "user",
            &config,
            &clock
        ));

        let wrong_jar = crate::rememberable::encode_cookie_value(
            "1",
            "wrong",
            &(clock.now() - TimeDelta::minutes(30))
                .timestamp()
                .to_string(),
        );
        assert!(!remember_active_for_timeout(
            &user,
            &exemption_request(Some(wrong_jar)),
            "user",
            &config,
            &clock
        ));

        let equal_generated = user
            .created_at
            .expect("created is set")
            .timestamp()
            .to_string();
        let equal_jar =
            crate::rememberable::encode_cookie_value("1", "cookie-token", &equal_generated);
        assert!(!remember_active_for_timeout(
            &user,
            &exemption_request(Some(equal_jar)),
            "user",
            &config,
            &clock
        ));

        let foreign_jar = crate::rememberable::encode_cookie_value(
            "2",
            "cookie-token",
            &(clock.now() - TimeDelta::minutes(30))
                .timestamp()
                .to_string(),
        );
        assert!(!remember_active_for_timeout(
            &user,
            &exemption_request(Some(foreign_jar)),
            "user",
            &config,
            &clock
        ));

        let valueless = RememberingUser {
            value: None,
            ..user.clone()
        };
        let (_, jar) = exemption_user(&config, &clock);
        assert!(!remember_active_for_timeout(
            &valueless,
            &exemption_request(Some(jar)),
            "user",
            &config,
            &clock
        ));

        let dateless = RememberingUser {
            created_at: None,
            ..user.clone()
        };
        let (_, jar) = exemption_user(&config, &clock);
        assert!(!remember_active_for_timeout(
            &dateless,
            &exemption_request(Some(jar)),
            "user",
            &config,
            &clock
        ));

        assert!(!remember_active_for_timeout(
            &user,
            &exemption_request(Some("not json".to_string())),
            "user",
            &config,
            &clock
        ));
    }

    /// Minimal in-memory session store for the tick round-trip test.
    #[derive(Debug, Default)]
    struct TickStore {
        data:
            std::sync::Arc<std::sync::RwLock<std::collections::HashMap<String, serde_json::Value>>>,
    }

    #[async_trait::async_trait]
    impl crate::session::SessionStore for TickStore {
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
}
