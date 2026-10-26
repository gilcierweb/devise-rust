//! Failed-attempt accounting seam - the object-safe bridge that lets the
//! STRATEGY CHAIN persist Devise's `valid_for_authentication?` side effects.
//!
//! In Devise, the failed-attempt counter lives inside
//! `Lockable#valid_for_authentication?`, which the `database_authenticatable`
//! strategy triggers through `Authenticatable#validate` - so locking works
//! on every authentication path, not only in `SessionsController#create`.
//! The port's controllers accounting runs in the framework handlers; this
//! seam closes the remaining gap for the strategy-chain path
//! (`AuthProxy::authenticate`, rememberable/params/HTTP-Basic chain).
//!
//! The threshold/window/message rules stay in core
//! ([`Lockable::apply_failed_attempt`](crate::lockable::Lockable::apply_failed_attempt));
//! the seam only carries the persistence the strategy layer cannot express
//! (`OrmAdapter<M>` is not object-safe). Applications register a typed sink
//! per scope on their [`AuthProxy`](crate::proxy::AuthProxy); the strategies
//! then account exactly where Devise does.

use crate::adapter::DeviseKey;

/// Verdict of one recorded attempt: the Devise failure key to fail with, or
/// `None` when the attempt does not fail the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptVerdict {
    /// The attempt failed with this I18n failure key (`locked`,
    /// `last_attempt`, `invalid`).
    Failed(&'static str),
    /// The attempt was recorded without failing the request.
    Recorded,
}

/// Object-safe persistence for strategy-chain failed-attempt accounting.
///
/// Implementations are typed per model (they own the adapter, mailer,
/// config, and clock); the strategies only see this erased trait.
#[async_trait::async_trait]
pub trait FailedAttemptSink: Send + Sync {
    /// Record one evaluated password attempt against the record under `key`.
    ///
    /// `password_ok` is the credential result. The implementation runs the
    /// core accounting (counter, auto-unlock, threshold lock, unlock mail)
    /// and returns the Devise failure key when the attempt must fail the
    /// request, or [`AttemptVerdict::Recorded`] otherwise. A record that is
    /// absent, unpersisted, or lockable-disabled records nothing.
    async fn record(&self, key: &DeviseKey, password_ok: bool) -> AttemptVerdict;
}

/// Default sink: records nothing (chain paths without lockable persistence
/// behave exactly as before the seam existed).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopFailedAttemptSink;

#[async_trait::async_trait]
impl FailedAttemptSink for NoopFailedAttemptSink {
    async fn record(&self, _key: &DeviseKey, _password_ok: bool) -> AttemptVerdict {
        AttemptVerdict::Recorded
    }
}

/// Ready-made sink over the application's adapter/mailer/clock: the
/// framework-agnostic registration any bridge makes (both integrations
/// share it, so neither hand-rolls the accounting).
///
/// The rules stay in
/// [`Lockable::apply_failed_attempt`](crate::lockable::Lockable::apply_failed_attempt);
/// this type only
/// adapts it to the object-safe seam.
#[derive(Debug, Clone)]
pub struct LockableFailedAttemptSink<M, A, L> {
    adapter: std::sync::Arc<A>,
    mailer: std::sync::Arc<L>,
    config: std::sync::Arc<crate::config::DeviseConfig>,
    clock: std::sync::Arc<crate::time::SystemClock>,
    _model: std::marker::PhantomData<fn() -> M>,
}

impl<M, A, L> LockableFailedAttemptSink<M, A, L> {
    /// Build the sink over the app's collaborators (the same Arc the
    /// handlers already share).
    #[must_use]
    pub fn new(
        adapter: std::sync::Arc<A>,
        mailer: std::sync::Arc<L>,
        config: std::sync::Arc<crate::config::DeviseConfig>,
        clock: std::sync::Arc<crate::time::SystemClock>,
    ) -> Self {
        Self {
            adapter,
            mailer,
            config,
            clock,
            _model: std::marker::PhantomData,
        }
    }
}

#[async_trait::async_trait]
impl<M, A, L> FailedAttemptSink for LockableFailedAttemptSink<M, A, L>
where
    M: crate::lockable::Lockable + Send + Sync + 'static,
    A: crate::adapter::OrmAdapter<M> + Send + Sync,
    L: crate::mailer::Mailer<M> + Send + Sync,
{
    async fn record(&self, key: &DeviseKey, password_ok: bool) -> AttemptVerdict {
        use crate::lockable::LockAttemptOutcome;
        let Ok(Some(mut record)) = self.adapter.get(key).await else {
            return AttemptVerdict::Recorded;
        };
        match record
            .apply_failed_attempt(
                password_ok,
                self.adapter.as_ref(),
                self.mailer.as_ref(),
                &self.config,
                self.clock.as_ref(),
            )
            .await
        {
            Ok(LockAttemptOutcome::Locked | LockAttemptOutcome::FailedIncremented) => {
                AttemptVerdict::Failed(
                    record.lock_unauthenticated_message(&self.config, self.clock.as_ref()),
                )
            }
            Ok(LockAttemptOutcome::Authenticated) => AttemptVerdict::Recorded,
            // Fail closed: Devise lets the persistence error raise (a 500)
            // because the counter write IS the brute-force accounting -
            // proceeding as "recorded" is how unlimited guessing slips
            // past a lockout exactly when the backend is unhealthy.
            Err(_) => AttemptVerdict::Failed("invalid"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::memory::MemoryAdapter;
    use crate::adapter::{Conditions, OrmAdapter, OrmError, Value};
    use crate::config::DeviseConfig;
    use crate::failure::AnyDeviseModel;
    use crate::lockable::Lockable;
    use crate::mailer::HasEmail;
    use crate::mailer::TestMailer;
    use crate::model::Authenticatable;
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::sync::Arc;

    /// Minimal lockable model exercising the sink seam.
    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    struct SinkUser {
        id: i64,
        email: String,
        #[serde(default)]
        failed_attempts: u32,
        locked_at: Option<DateTime<Utc>>,
        unlock_token: Option<String>,
    }

    impl SinkUser {
        fn fresh(id: i64, email: &str) -> Self {
            Self {
                id,
                email: email.to_string(),
                ..Self::default()
            }
        }
    }

    #[async_trait::async_trait]
    impl Authenticatable for SinkUser {}

    impl HasEmail for SinkUser {
        fn email(&self) -> &str {
            &self.email
        }
    }

    impl Lockable for SinkUser {
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
    }

    impl AnyDeviseModel for SinkUser {
        fn to_key(&self) -> DeviseKey {
            DeviseKey::from_i64(self.id)
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    /// Adapter wrapper whose counter verb fails: simulates a DB outage at
    /// the exact moment lockable must persist the failed-attempt accounting.
    struct FailingCounterAdapter<'a> {
        inner: &'a MemoryAdapter<SinkUser>,
    }

    #[async_trait::async_trait]
    impl OrmAdapter<SinkUser> for FailingCounterAdapter<'_> {
        type New = SinkUser;

        async fn get(&self, id: &DeviseKey) -> Result<Option<SinkUser>, OrmError> {
            self.inner.get(id).await
        }
        async fn find_first(&self, conditions: &Conditions) -> Result<Option<SinkUser>, OrmError> {
            self.inner.find_first(conditions).await
        }
        async fn create(&self, model: SinkUser) -> Result<SinkUser, OrmError> {
            self.inner.create(model).await
        }
        async fn update(
            &self,
            key: &DeviseKey,
            changes: &crate::adapter::ChangeSet,
        ) -> Result<SinkUser, OrmError> {
            self.inner.update(key, changes).await
        }
        async fn update_columns(
            &self,
            key: &DeviseKey,
            fields: &HashMap<String, Value>,
        ) -> Result<SinkUser, OrmError> {
            self.inner.update_columns(key, fields).await
        }
        async fn increment_counter(
            &self,
            _key: &DeviseKey,
            _column: &'static str,
        ) -> Result<SinkUser, OrmError> {
            Err(OrmError::Query {
                message: "counter backend unavailable".to_string(),
                source: None,
            })
        }
        async fn delete(&self, id: &DeviseKey) -> Result<(), OrmError> {
            self.inner.delete(id).await
        }
    }

    /// Devise's `valid_for_authentication?` lets a persistence error raise
    /// (a 500): the counter write is load-bearing security accounting. The
    /// sink must FAIL CLOSED when it cannot record - never proceed as if
    /// the attempt had been recorded (that is how brute force slips past a
    /// lockout during a backend hiccup).
    #[tokio::test]
    async fn sink_fails_closed_when_the_counter_write_errors() {
        let memory = MemoryAdapter::<SinkUser>::new();
        let user = SinkUser::fresh(1, "sink@example.com");
        let key = user.to_key();
        let _ = memory.create(user).await;

        let failing = FailingCounterAdapter { inner: &memory };
        let config = Arc::new(DeviseConfig {
            secret_key: "test-secret-key".to_string(),
            ..DeviseConfig::default()
        });
        let sink =
            LockableFailedAttemptSink::<SinkUser, FailingCounterAdapter<'_>, TestMailer>::new(
                Arc::new(failing),
                Arc::new(TestMailer::default()),
                config,
                Arc::new(crate::time::SystemClock),
            );

        let verdict = sink.record(&key, false).await;
        assert!(
            matches!(verdict, AttemptVerdict::Failed(_)),
            "a failed counter write must fail closed, got {verdict:?}"
        );
    }
}
