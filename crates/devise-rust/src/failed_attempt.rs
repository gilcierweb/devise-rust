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
            Ok(LockAttemptOutcome::Authenticated) | Err(_) => AttemptVerdict::Recorded,
        }
    }
}
