//! Time abstraction - Clock trait with `SystemClock` and `FixedClock` implementations
//!
//! Mirrors devise's `Time.now` window reads (`confirm_within`, `unlock_in`, `timeout_in`) behind an injectable clock; devise's tests freeze time with timecop, the port injects `Clock`.

use chrono::{DateTime, TimeDelta, Utc};

/// Clock trait for time operations - enables time-freezing in tests
///
/// Mirrors devise's `Time.now` reads so window logic (`confirm_within`, `unlock_in`, `timeout_in`) is testable; devise freezes time with timecop where the port injects a clock.
pub trait Clock: Send + Sync {
    /// Get current UTC time
    fn now(&self) -> DateTime<Utc>;

    /// Get current time minus duration (convenience method)
    fn ago(&self, duration: TimeDelta) -> DateTime<Utc> {
        self.now() - duration
    }
}

/// System clock using real time
///
/// The wall-clock clock; the production mirror of devise's direct time reads.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// Fixed clock for testing (time freezing / time travel)
///
/// The frozen clock mirroring devise's `travel_to` test posture.
#[derive(Debug, Clone)]
pub struct FixedClock {
    time: DateTime<Utc>,
}

impl FixedClock {
    /// Create a fixed clock at a specific time
    ///
    /// Constructs the frozen clock at an instant; mirrors devise's `travel_to` test setup.
    #[must_use]
    pub fn new(time: DateTime<Utc>) -> Self {
        Self { time }
    }

    /// Create a fixed clock at current time
    ///
    /// Reads the current instant; the injectable mirror of `Time.now`.
    #[must_use]
    pub fn now() -> Self {
        Self::new(Utc::now())
    }

    /// Advance the clock by a duration
    ///
    /// Advances the frozen clock, mirroring `travel` in devise's tests.
    pub fn advance(&mut self, duration: TimeDelta) {
        self.time += duration;
    }

    /// Set the clock to a specific time
    ///
    /// Sets the frozen clock to an instant, mirroring `travel_to`.
    pub fn set(&mut self, time: DateTime<Utc>) {
        self.time = time;
    }
}

impl Clock for FixedClock {
    fn now(&self) -> DateTime<Utc> {
        self.time
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_clock_ago() {
        let clock = FixedClock::new(Utc::now());
        let ten_minutes_ago = clock.ago(TimeDelta::minutes(10));
        assert_eq!(ten_minutes_ago, clock.now() - TimeDelta::minutes(10));
    }
}
