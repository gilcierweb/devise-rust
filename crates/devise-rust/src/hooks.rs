//! Hooks - Warden-compatible hook registry and event dispatch
//!
//! Mirrors devise's warden hooks (`devise/lib/devise/hooks/*`): the same events, filters, and registration shape.
//!
//! Implements Devise's hook system: `after_set_user`, `after_authentication`,
//! `before_logout`, `after_fetch`, `on_request` with Warden's `only`/`except`
//! filtering semantics. Phase 3 delivers the registry and stub hooks; Phase 5
//! fills in module-specific hook bodies.

use crate::config::DeviseConfig;
use crate::failure::Failure;
use crate::rememberable::RememberCookieOp;
use crate::request::AuthRequest;
use crate::time::{Clock, SystemClock};
use async_trait::async_trait;
use std::fmt::Debug;

/// Hook event types - mirrors Warden's hook events
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Event {
    /// User was set in session (sign in, sign up, etc.)
    SetUser,
    /// Authentication succeeded
    Authentication,
    /// User fetched from session (on each request)
    Fetch,
    /// User signed out
    Logout,
    /// Each request (for timeoutable, etc.)
    Request,
}

impl Event {
    /// All events in Devise execution order
    ///
    /// Lists the hook events mirroring warden's callback vocabulary: `after_set_user` and `before_logout` (`devise/lib/devise/hooks/*`).
    #[must_use]
    pub fn all() -> Vec<Event> {
        vec![
            Event::SetUser,
            Event::Authentication,
            Event::Fetch,
            Event::Logout,
            Event::Request,
        ]
    }
}

/// Hook filter - matches Warden's `only`/`except`/`scope` semantics exactly
///
/// Mirrors warden callback filters: the `only`, `except`, and per-scope options devise's hook declarations carry.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct HookFilter {
    /// Scope to match (None = all scopes)
    pub scope: Option<String>,
    /// Events to match (empty = all events; alias for `only`)
    pub events: Vec<Event>,
    /// Events that trigger this hook (explicit `only`)
    pub only: Vec<Event>,
    /// Events that skip this hook (`except`)
    pub except: Vec<Event>,
}

impl HookFilter {
    /// Create a new filter for all scopes and events
    ///
    /// Constructs the filter with devise's default (no restriction), mirroring a bare warden callback.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set scope filter
    ///
    /// The per-scope filter, mirroring `Warden::Manager.before_logout scope: :user`.
    #[must_use]
    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// Set only filter (events that trigger)
    ///
    /// The `only` filter, mirroring warden's `only: [:fetch]`.
    #[must_use]
    pub fn only(mut self, events: Vec<Event>) -> Self {
        self.only = events;
        self
    }

    /// Set except filter (events that skip)
    ///
    /// The `except` filter, mirroring warden's `except: :fetch`.
    #[must_use]
    pub fn except(mut self, events: Vec<Event>) -> Self {
        self.except = events;
        self
    }

    /// Check if this filter matches the given context
    ///
    /// Warden logic (hooks.rb:53-63):
    /// - scope matches (or None)
    /// - event in `only` (if `only` non-empty) AND event not in `except`
    ///
    /// Mirrors warden's applicability decision: whether a callback runs for this request.
    #[must_use]
    pub fn matches(&self, ctx: &HookContext<'_>) -> bool {
        // Scope check
        if let Some(ref filter_scope) = self.scope {
            if filter_scope != ctx.scope {
                return false;
            }
        }

        // Only check (if specified)
        if !self.only.is_empty() && !self.only.contains(&ctx.event) {
            return false;
        }

        // Events check (alias for only)
        if !self.events.is_empty() && !self.events.contains(&ctx.event) {
            return false;
        }

        // Except check
        if self.except.contains(&ctx.event) {
            return false;
        }

        true
    }
}

/// Context passed to hook functions
///
/// Mirrors the payload warden hands hooks: request, session, and the record under `after_set_user`.
pub struct HookContext<'a> {
    /// `AuthProxy` reference for session/user manipulation
    pub proxy: &'a mut dyn HookProxy,
    /// Current scope
    pub scope: &'a str,
    /// Event that triggered the hook
    pub event: Event,
    /// `AuthRequest` snapshot (None for Fetch/Logout without request)
    pub request: Option<&'a AuthRequest>,
    /// Current user record (None for Fetch before user loaded, Logout after cleared)
    pub record: Option<&'a dyn AnyDeviseModel>,
}

/// Trait for hook functions - must be Send + Sync for dyn compatibility
///
/// The hook signature; the typed mirror of warden's callback blocks.
pub type HookFn = dyn for<'a> Fn(
        &'a mut HookContext<'_>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), Failure>> + Send + 'a>,
    > + Send
    + Sync;

/// Internal hook entry for ordering
struct HookEntry {
    filter: HookFilter,
    hook: Box<HookFn>,
}

/// Proxy trait for hook context - abstracts `AuthProxy` for hook access
///
/// Bridge trait owning the framework side effects (cookie writes, session renewal, CSRF rotation) that mirror what devise performs on the warden proxy directly.
#[async_trait]
pub trait HookProxy: Send + Sync {
    /// Get the session store
    fn session_store(&self) -> &dyn crate::session::SessionStore;
    /// Get the scope registry
    fn scope_registry(&self) -> &crate::scope::ScopeRegistry;
    /// Get the Devise config (rememberable cookie attributes and expiry).
    ///
    /// Proxies serving Rememberable mappings must override this; the
    /// default panics, matching the other test-only accessors.
    fn devise_config(&self) -> &DeviseConfig {
        unimplemented!("hook proxies serving rememberable mappings must expose the config")
    }
    /// Whether CSRF cleanup may run after authentication
    /// (`Devise.clean_up_csrf_token_on_authentication`,
    /// `hooks/csrf_cleaner.rb:3-13`). Safe default: enabled, matching
    /// Devise's default `true`.
    fn csrf_cleanup_enabled(&self) -> bool {
        true
    }
    /// Whether the request's winning strategy was rememberable: a
    /// GET-triggered auto sign-in must NOT rotate the CSRF token
    /// (`strategies/rememberable.rb:36-43`). Safe default: never exempt.
    fn won_by_rememberable(&self) -> bool {
        false
    }
    /// Queue a remember-cookie intent for the bridge outbox.
    ///
    /// `AuthProxy` records it for draining after authentication; the default
    /// drops the op, which suits test-only proxies that never trigger
    /// rememberable bodies. Proxies serving Rememberable mappings must
    /// override this.
    fn push_remember_cookie_op(&mut self, _op: RememberCookieOp) {}
    /// Get mutable access to user map (for `sign_out`, lock, etc.)
    fn user_mut(&mut self, scope: &str) -> Option<&mut Option<Box<dyn AnyDeviseModel>>>;
    /// Lock the proxy (blocks further auth this request)
    fn lock(&mut self);
    /// Sign out after a timeout (hook plumbing, TMO-02/D-19).
    ///
    /// Clears memos plus session keys (and the timeout tick keys) for every
    /// scope when `sign_out_all` holds, else for `scope` alone. The default
    /// covers every registered scope; `AuthProxy` overrides to cover every
    /// memoized scope through its real `sign_out` paths (which also run the
    /// logout hooks, so the remember cookie is cleared exactly as Devise's
    /// warden-logout timeout path does).
    async fn sign_out_for_timeout(&mut self, scope: &str, sign_out_all: bool) {
        let mut scopes = if sign_out_all {
            self.scope_registry().scope_names()
        } else {
            Vec::new()
        };
        if !scopes.iter().any(|name| name == scope) {
            scopes.push(scope.to_string());
        }
        for timed_out in &scopes {
            if let Some(slot) = self.user_mut(timed_out) {
                *slot = None;
            }
            let session_key = crate::session::keys::scope_session_key(timed_out);
            self.session_store().remove(&session_key).await;
            let tick_key = crate::timeoutable::last_request_at_key(timed_out);
            self.session_store().remove(&tick_key).await;
        }
    }
}

/// Trait for any Devise model - re-exported for hook context
pub use crate::failure::AnyDeviseModel;

/// Hook registry - manages hook registration and dispatch
///
/// Thread-safe for concurrent request handling. Hooks are registered at startup
/// and dispatched per-request via `run_hooks`.
///
/// Mirrors `Warden::Manager`'s callback storage: the registry devise's hooks register themselves into at load time.
pub struct HookRegistry {
    hooks: Vec<HookEntry>,
}

impl HookRegistry {
    /// Create a new empty hook registry
    ///
    /// Constructs an empty registry; mirrors the pre-registration state of warden's manager.
    #[must_use]
    pub fn new() -> Self {
        Self { hooks: Vec::new() }
    }

    /// Add a hook with filter and prepend/append ordering
    ///
    /// `prepend = true` inserts at front (runs first), `false` appends (runs last).
    ///
    /// Registers one hook with its filter; mirrors `Warden::Manager.before_logout do ... end`.
    pub fn add_hook(&mut self, filter: HookFilter, hook: Box<HookFn>, prepend: bool) {
        let entry = HookEntry { filter, hook };
        if prepend {
            self.hooks.insert(0, entry);
        } else {
            self.hooks.push(entry);
        }
    }

    /// Run all matching hooks for the given context
    ///
    /// Stops on first `Err(Failure)` (Warden halts on throw).
    ///
    /// # Errors
    ///
    /// Returns the first hook's `Failure`; hooks that pass return `Ok(())`.
    pub async fn run_hooks(&self, ctx: &mut HookContext<'_>) -> Result<(), Failure> {
        for entry in &self.hooks {
            if entry.filter.matches(ctx) {
                (entry.hook)(ctx).await?;
            }
        }
        Ok(())
    }

    /// Get number of registered hooks
    ///
    /// Registry size, used by diagnostics; collection ergonomics over the warden-mirror registry.
    #[must_use]
    pub fn len(&self) -> usize {
        self.hooks.len()
    }

    /// Check if registry is empty
    ///
    /// Registry emptiness check; collection ergonomics over the warden-mirror registry.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hooks.is_empty()
    }
}

impl Default for HookRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl Debug for HookRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HookRegistry")
            .field("hook_count", &self.hooks.len())
            .finish()
    }
}

/// Register the 7 core Devise hooks in canonical order
///
/// Order (from devise/lib/devise/modules.rb reverse + hook files):
/// 1. Activatable (`activatable.rb`) - rechecks `valid_for_authentication`
/// 2. CSRF Cleaner (`csrf_cleaner.rb`) - renews session + rotates CSRF
/// 3. Trackable (`trackable.rb`) - updates sign-in tracking fields
/// 4. Rememberable Set (`rememberable.rb`) - sets remember-me cookie
/// 5. Forgetable (`forgetable.rb`) - clears remember-me cookie
/// 6. Lockable Reset (`lockable.rb`) - resets `failed_attempts`
/// 7. Timeoutable Tick (`timeoutable.rb`) - checks session timeout
///
/// Only adds hooks for modules present in `mapping.modules`.
///
/// Mirrors `devise/lib/devise/hooks/*` exactly: registers activatable, `csrf_cleaner`, rememberable, forgetable, lockable, timeoutable, and trackable.
pub fn register_devise_hooks(registry: &mut HookRegistry, mapping: &crate::scope::Mapping) {
    use crate::scope::Module;

    // 1. Activatable - runs on SetUser + Authentication + Fetch for all scopes
    registry.add_hook(
        HookFilter::new().only(vec![Event::SetUser, Event::Authentication, Event::Fetch]),
        Box::new(|ctx| {
            Box::pin(async move {
                // Devise `hooks/activatable.rb` registers a bare
                // `after_set_user` with no event exclusion: the reference
                // comment says the gate exists to validate the user activity
                // on each request, so the hook runs on every `after_set_user`
                // action, the session fetch included. A record that fails
                // `active_for_authentication?` fails the transition with its
                // `inactive_message` (`unconfirmed` / `locked` / `inactive`).
                // On the fetch path `proxy.rs` deletes the scope session key
                // and fails the request, which is the reference's
                // `warden.logout(scope)` followed by `throw :warden`.
                //
                // The gate pair is read through the object-safe Activatable
                // view, so the hook enforces the very same composition the
                // typed controllers check - no app-side wiring required
                // (divergence closed 2026-10-25, fetch arm 2026-10-26).
                if let Some(record) = ctx.record {
                    if let Some(gate) = record.as_activatable() {
                        if !gate.active_for_authentication() {
                            return Err(crate::failure::inactive_failure(gate.inactive_message()));
                        }
                    }
                }
                Ok(())
            })
        }),
        false,
    );

    // 2. CSRF Cleaner - runs on Authentication for all scopes
    registry.add_hook(
        HookFilter::new().only(vec![Event::Authentication]),
        Box::new(|ctx| {
            Box::pin(async move {
                // Devise `hooks/csrf_cleaner.rb:3-13`: renewal is gated on
                // `Devise.clean_up_csrf_token_on_authentication` AND the
                // winning strategy - a rememberable win is a GET-triggered
                // auto sign-in, and rotating the CSRF token there would
                // expire every token embedded in the rendered page
                // (`strategies/rememberable.rb:36-43` opts out).
                if !ctx.proxy.csrf_cleanup_enabled() {
                    return Ok(());
                }
                if ctx.proxy.won_by_rememberable() {
                    return Ok(());
                }
                // Session renewal and CSRF rotation happen here.
                // Framework bridges rotate their CSRF token inside renew().
                let _ = ctx.proxy.session_store().renew().await;
                Ok(())
            })
        }),
        false,
    );

    // 3. Trackable - runs on Authentication for scopes with Trackable module
    if mapping.modules.contains(&Module::Trackable) {
        registry.add_hook(
            HookFilter::new()
                .only(vec![Event::Authentication])
                .except(vec![Event::Fetch]),
            trackable_hook(),
            false,
        );
    }

    // 4. Rememberable Set - runs on Authentication for scopes with Rememberable module
    if mapping.modules.contains(&Module::Rememberable) {
        registry.add_hook(
            HookFilter::new().only(vec![Event::Authentication]),
            rememberable_set_hook(),
            false,
        );
    }

    // 5. Forgetable - runs on Logout for scopes with Rememberable module
    if mapping.modules.contains(&Module::Rememberable) {
        registry.add_hook(
            HookFilter::new().only(vec![Event::Logout]),
            forgetable_hook(),
            false,
        );
    }

    // 6. Lockable Reset - runs on Authentication for scopes with Lockable module
    if mapping.modules.contains(&Module::Lockable) {
        registry.add_hook(
            HookFilter::new()
                .only(vec![Event::Authentication])
                .except(vec![Event::Fetch]),
            Box::new(|ctx| {
                Box::pin(async move {
                    // LCK-06 / D-11: the warden `after_set_user except: :fetch`
                    // equivalent. `Event::Fetch` exists, so the `except`
                    // exclusion is explicit here: `only(Authentication)`
                    // already rejects fetch events at the filter, and
                    // `AuthProxy::set_user` never dispatches hooks on the
                    // fetch path at all (it returns before hook dispatch for
                    // `SetUserEvent::Fetch`). The `ctx.event == Fetch` return
                    // below records that second guarantee at the body level.
                    //
                    // The hook zeroes the memoized record's counter through
                    // the object-safe `AnyDeviseModel::reset_failed_attempts_hook`
                    // seam (the typed `Lockable` trait is not object-safe, so
                    // the body cannot name it). Durable callers persist
                    // through the typed `Lockable::reset_failed_attempts`
                    // with their adapter; the hook keeps the in-request copy
                    // consistent.
                    if ctx.event == Event::Fetch {
                        return Ok(());
                    }
                    let scope = ctx.scope.to_string();
                    if let Some(slot) = ctx.proxy.user_mut(&scope) {
                        if let Some(record) = slot.as_mut() {
                            record.reset_failed_attempts_hook();
                        }
                    }
                    Ok(())
                })
            }),
            false,
        );
    }

    // 7. Timeoutable Tick - runs on Request for scopes with Timeoutable module
    if mapping.modules.contains(&Module::Timeoutable) {
        registry.add_hook(
            HookFilter::new().only(vec![Event::Request]),
            timeoutable_tick_hook(),
            false,
        );
    }
}

/// Trackable hook body (hook 3): shift the memoized record's sign-in fields.
///
/// Devise `hooks/trackable.rb` runs `after_set_user except: :fetch`. The
/// filter carries that exclusion; the body repeats it defensively (the
/// lockable-reset precedent). The body honors `skip_trackable` (D-21, shared
/// with the timeout tick) and applies the in-memory shift through the
/// object-safe `AnyDeviseModel::apply_tracked_fields_hook` seam, feeding it
/// the socket peer from `AuthRequest.peer_addr` (D-20: proxy headers are
/// never consulted).
///
/// Durable persistence is NOT here: hooks own no adapter, and the typed
/// `Trackable::update_tracked_fields_bang` (with the #4673 new-record probe)
/// is the bridge-called verb. This mirrors the lockable-reset split (hook
/// memo-consistency versus typed durable path).
fn trackable_hook() -> Box<HookFn> {
    Box::new(|ctx| {
        Box::pin(async move {
            if ctx.event == Event::Fetch {
                return Ok(());
            }
            let Some(request) = ctx.request else {
                return Ok(());
            };
            if request.flags.skip_trackable {
                return Ok(());
            }
            let peer = request.peer_addr.as_deref();
            let now = SystemClock.now();
            let scope = ctx.scope.to_string();
            if let Some(slot) = ctx.proxy.user_mut(&scope) {
                if let Some(record) = slot.as_mut() {
                    record.apply_tracked_fields_hook(now, peer);
                }
            }
            Ok(())
        })
    })
}

/// Timeoutable-tick hook body (hook 7): expiry check plus epoch tick.
///
/// Devise `hooks/timeoutable.rb` runs on every request the user is set:
/// skip entirely under `skip_timeoutable` or `skip_timeout` (D-17); read the
/// session `last_request_at` Integer epoch; when the tick is stale AND no
/// live remember-me session exempts it (D-18, revalidated from the current
/// cookie triple, never a stale flag), sign out (all scopes when
/// `sign_out_all_scopes`, D-19) and fail `:timeout`; otherwise tick the
/// epoch unless `skip_trackable`.
///
/// Anonymous requests (no memoized record) are a no-op: there is no session
/// to time out, and ticking would mint session keys for strangers.
///
/// The sign-out runs through [`HookProxy::sign_out_for_timeout`]: `AuthProxy`
/// routes through its real `sign_out` paths, so logout hooks fire and the
/// remember cookie is cleared exactly as Devise's warden-logout timeout path
/// does.
fn timeoutable_tick_hook() -> Box<HookFn> {
    Box::new(|ctx| {
        Box::pin(async move {
            let flags = ctx.request.map(|request| request.flags).unwrap_or_default();
            if flags.skip_timeoutable || flags.skip_timeout {
                return Ok(());
            }
            if ctx.record.is_none() {
                return Ok(());
            }
            let clock = SystemClock;
            let scope = ctx.scope.to_string();
            let stored =
                crate::timeoutable::read_last_request_at(ctx.proxy.session_store(), &scope).await;
            let timeout_in = ctx.proxy.devise_config().timeout_in;
            match crate::timeoutable::check_timeout(stored.as_ref(), &flags, timeout_in, &clock) {
                crate::timeoutable::TimeoutDecision::Skipped => Ok(()),
                crate::timeoutable::TimeoutDecision::Live => {
                    if !flags.skip_trackable {
                        crate::timeoutable::tick_last_request_at(
                            ctx.proxy.session_store(),
                            &scope,
                            &clock,
                        )
                        .await;
                    }
                    Ok(())
                }
                crate::timeoutable::TimeoutDecision::Expired => {
                    let exempt = match (ctx.record, ctx.request) {
                        (Some(record), Some(request)) => {
                            let config = ctx.proxy.devise_config().clone();
                            crate::timeoutable::remember_active_for_timeout(
                                record, request, &scope, &config, &clock,
                            )
                        }
                        _ => false,
                    };
                    if exempt {
                        if !flags.skip_trackable {
                            crate::timeoutable::tick_last_request_at(
                                ctx.proxy.session_store(),
                                &scope,
                                &clock,
                            )
                            .await;
                        }
                        return Ok(());
                    }
                    let sign_out_all = ctx.proxy.devise_config().sign_out_all_scopes;
                    ctx.proxy.sign_out_for_timeout(&scope, sign_out_all).await;
                    ctx.proxy.lock();
                    Err(Failure::Timeout)
                }
            }
        })
    })
}

/// Rememberable-set hook body (hook 4): queue the `Set` cookie intent when
/// the virtual `remember_me` flag is set and the record offers a value.
///
/// Devise `hooks/rememberable.rb` runs `after_set_user` except fetch. The
/// params strategy stamps the flag from the sign-in params (Devise
/// `Authenticatable#remember_me`); `ctx.request` is a fallback source when
/// hooks run outside that flow. Durable persistence (`remember_me` through
/// the adapter) runs in the bridge sign-in before `set_user`, since hooks
/// own no adapter; the hook owns the cookie intent.
fn rememberable_set_hook() -> Box<HookFn> {
    Box::new(|ctx| {
        Box::pin(async move {
            let flag = ctx
                .record
                .is_some_and(|record| record.remember_me_flag_opt() == Some(true))
                || ctx.request.is_some_and(|request| {
                    crate::rememberable::remember_flag_set(request, ctx.scope)
                });
            if !flag {
                return Ok(());
            }
            let Some(record) = ctx.record else {
                return Ok(());
            };
            let Some(value) = record.rememberable_value_opt() else {
                return Ok(());
            };
            if value.is_empty() {
                // Column present but never minted (or a valueless model):
                // encoding an empty token would only produce a cookie the
                // check rejects, so stay silent.
                return Ok(());
            }
            let key = record.to_key().to_string();
            let (op_key, attrs, jar) = {
                let config = ctx.proxy.devise_config();
                // The durable mint stamps `remember_created_at` with the
                // request clock; the hook must mint from the SAME clock, or
                // a same-second cookie would fail condition 4 until the
                // clock ticks (S6.3).
                let clock = crate::time::SystemClock;
                let triple = crate::rememberable::build_cookie_triple_after_created_at(
                    &key,
                    &value,
                    &clock,
                    record.remember_created_at_opt(),
                );
                let jar = crate::rememberable::encode_cookie_value(&triple.0, &triple.1, &triple.2);
                let attrs = crate::rememberable::RememberableCookieAttrs::for_scope(
                    ctx.scope, config, &clock,
                );
                let op_key = attrs.key.clone();
                (op_key, attrs, jar)
            };
            ctx.proxy.push_remember_cookie_op(RememberCookieOp::Set {
                scope: ctx.scope.to_string(),
                key: op_key,
                value: jar,
                attrs,
            });
            Ok(())
        })
    })
}

/// Forgetable hook body (hook 5): queue the `Clear` cookie intent on logout.
///
/// Devise `hooks/forgetable.rb` runs `before_logout`, forgetting the user and
/// clearing the cookie. The typed `forget_me` (adapter persistence) runs in
/// the bridge sign-out before `sign_out`, since hooks own no adapter and the
/// memo is already detached here; the hook owns the cookie delete alone.
fn forgetable_hook() -> Box<HookFn> {
    Box::new(|ctx| {
        Box::pin(async move {
            let scope = ctx.scope.to_string();
            let key = {
                let config = ctx.proxy.devise_config();
                crate::rememberable::remember_cookie_key(&scope, config)
            };
            ctx.proxy
                .push_remember_cookie_op(RememberCookieOp::Clear { scope, key });
            Ok(())
        })
    })
}

/// Bridge trait for session renewal (SESS-05)
///
/// Mirrors warden's session rotation on `after_set_user`, the session-fixation guard devise inherits from warden.
#[async_trait]
pub trait SessionRenewal: Send + Sync {
    /// Renew the session (rotate CSRF, extend expiry).
    ///
    /// # Errors
    ///
    /// Returns [`DeviseError`](crate::error::DeviseError) when renewal fails.
    async fn renew(&self) -> Result<(), crate::error::DeviseError>;
    /// Reset the session (clear all).
    ///
    /// # Errors
    ///
    /// Returns [`DeviseError`](crate::error::DeviseError) when reset fails.
    async fn reset(&self) -> Result<(), crate::error::DeviseError>;
}

/// Bridge trait for CSRF token rotation (SESS-05)
///
/// Mirrors `Devise.clean_up_csrf_token_on_authentication`: rotating the CSRF token on sign in.
#[async_trait]
pub trait CsrfRotation: Send + Sync {
    /// Rotate the CSRF token held by the session store.
    ///
    /// # Errors
    ///
    /// Returns [`DeviseError`](crate::error::DeviseError) when rotation fails.
    async fn rotate(
        store: &dyn crate::session::SessionStore,
    ) -> Result<(), crate::error::DeviseError>;
}

/// Bridge trait for remember-me cookie management (Phase 5)
///
/// Cookie side-effect bridge for the rememberable and forgetable hooks; mirrors the cookies devise writes inline, queued as ops for the framework transport.
#[async_trait]
pub trait RememberableBridge: Send + Sync {
    /// Set the remember-me cookie for `scope`.
    ///
    /// # Errors
    ///
    /// Returns [`DeviseError`](crate::error::DeviseError) when the cookie cannot be set.
    async fn set_cookie(
        store: &dyn crate::session::SessionStore,
        scope: &str,
        value: &str,
        expires: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), crate::error::DeviseError>;

    /// Clear the remember-me cookie for `scope`.
    ///
    /// # Errors
    ///
    /// Returns [`DeviseError`](crate::error::DeviseError) when the cookie cannot be cleared.
    async fn clear_cookie(
        store: &dyn crate::session::SessionStore,
        scope: &str,
    ) -> Result<(), crate::error::DeviseError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::{SetUserEvent, SetUserOpts};
    use crate::scope::{Mapping, Module, PathNames, SignOutVia};
    use crate::session::SessionStore;
    use std::collections::HashMap;
    use std::sync::Arc;

    struct MockProxy;
    impl HookProxy for MockProxy {
        fn session_store(&self) -> &dyn crate::session::SessionStore {
            unimplemented!()
        }
        fn scope_registry(&self) -> &crate::scope::ScopeRegistry {
            unimplemented!()
        }
        fn user_mut(&mut self, _scope: &str) -> Option<&mut Option<Box<dyn AnyDeviseModel>>> {
            None
        }
        fn lock(&mut self) {}
    }

    /// Counting store: records `renew()` calls so hook bodies can be
    /// asserted without a full proxy.
    struct CountingStore {
        renewed: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }
    #[async_trait]
    impl SessionStore for CountingStore {
        async fn get_value(&self, _key: &str) -> Option<serde_json::Value> {
            None
        }
        async fn insert_value(&self, _key: &str, _value: serde_json::Value) {}
        async fn remove(&self, _key: &str) {}
        async fn remove_prefix(&self, _prefix: &str) {}
        async fn keys_with_prefix(&self, _prefix: &str) -> Vec<String> {
            Vec::new()
        }
        async fn renew(&self) -> Result<(), crate::error::DeviseError> {
            self.renewed
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
        async fn reset(&self) -> Result<(), crate::error::DeviseError> {
            Ok(())
        }
    }

    /// Proxy stub with overridable CSRF gates, mirroring what real proxies
    /// must expose: `Devise.clean_up_csrf_token_on_authentication` and the
    /// winning-strategy exemption (`hooks/csrf_cleaner.rb`).
    struct GateProxy {
        store: Arc<CountingStore>,
        csrf_enabled: bool,
        rememberable_win: bool,
    }
    #[async_trait]
    impl HookProxy for GateProxy {
        fn session_store(&self) -> &dyn SessionStore {
            self.store.as_ref()
        }
        fn scope_registry(&self) -> &crate::scope::ScopeRegistry {
            unimplemented!()
        }
        fn user_mut(&mut self, _scope: &str) -> Option<&mut Option<Box<dyn AnyDeviseModel>>> {
            None
        }
        fn lock(&mut self) {}
        fn csrf_cleanup_enabled(&self) -> bool {
            self.csrf_enabled
        }
        fn won_by_rememberable(&self) -> bool {
            self.rememberable_win
        }
    }

    /// `hooks/csrf_cleaner.rb:3-13` gates session renewal on
    /// `Devise.clean_up_csrf_token_on_authentication` AND the winning
    /// strategy: a rememberable win (a GET-triggered auto sign-in) must NOT
    /// rotate the CSRF token, or every token embedded in the rendered page
    /// dies.
    #[tokio::test]
    async fn test_csrf_hook_honors_config_and_rememberable_win() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        for (csrf_enabled, rememberable_win, expect_renew) in
            [(false, false, 0), (true, false, 1), (true, true, 0)]
        {
            let store = Arc::new(CountingStore {
                renewed: Arc::new(AtomicUsize::new(0)),
            });
            let mut proxy = GateProxy {
                store: store.clone(),
                csrf_enabled,
                rememberable_win,
            };
            let mut hooks = HookRegistry::new();
            register_devise_hooks(&mut hooks, &test_mapping());
            let mut ctx = HookContext {
                proxy: &mut proxy,
                scope: "user",
                event: Event::Authentication,
                request: None,
                record: None,
            };
            hooks.run_hooks(&mut ctx).await.expect("hooks must run");
            assert_eq!(
                store.renewed.load(Ordering::SeqCst),
                expect_renew,
                "csrf_enabled={csrf_enabled} rememberable_win={rememberable_win}"
            );
        }
    }

    #[derive(Debug, Clone)]
    struct HookUser {
        id: i64,
        valid: bool,
    }

    impl AnyDeviseModel for HookUser {
        fn to_key(&self) -> crate::adapter::DeviseKey {
            crate::adapter::DeviseKey::from_i64(self.id)
        }

        fn authenticatable_salt(&self) -> Option<String> {
            Some("$2a$12$hooktestsalt123456789012".to_string())
        }

        fn valid_for_authentication(&self, _rules: Option<&crate::failure::AuthRules>) -> bool {
            self.valid
        }

        fn as_activatable(&self) -> Option<&dyn crate::model::Activatable> {
            Some(self)
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[async_trait::async_trait]
    impl crate::model::Authenticatable for HookUser {
        fn active_for_authentication(&self) -> bool {
            self.valid
        }

        fn inactive_message(&self) -> &'static str {
            "inactive"
        }
    }

    /// Full-module gate model for the activatable hook and the composers.
    #[derive(Debug, Clone, Default)]
    struct GateUser {
        id: i64,
        confirmed: bool,
        locked_at: Option<chrono::DateTime<chrono::Utc>>,
        failed_attempts: i64,
        confirmation_sent_at: Option<chrono::DateTime<chrono::Utc>>,
        confirmation_required: bool,
    }

    impl GateUser {
        fn gate(id: i64, confirmed: bool, locked: bool) -> Self {
            Self {
                id,
                confirmed,
                locked_at: locked.then(chrono::Utc::now),
                failed_attempts: if locked { 99 } else { 0 },
                confirmation_sent_at: Some(chrono::Utc::now()),
                confirmation_required: true,
            }
        }
    }

    impl AnyDeviseModel for GateUser {
        fn to_key(&self) -> crate::adapter::DeviseKey {
            crate::adapter::DeviseKey::from_i64(self.id)
        }

        fn as_activatable(&self) -> Option<&dyn crate::model::Activatable> {
            Some(self)
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    impl crate::mailer::HasEmail for GateUser {
        fn email(&self) -> &'static str {
            "gate@example.com"
        }
    }

    #[async_trait::async_trait]
    impl crate::model::Authenticatable for GateUser {
        fn active_for_authentication(&self) -> bool {
            crate::model::compose_active_for_authentication(
                self,
                &crate::config::DeviseConfig::default(),
                &SystemClock,
            )
        }

        fn inactive_message(&self) -> &'static str {
            crate::model::compose_inactive_message(
                self,
                &crate::config::DeviseConfig::default(),
                &SystemClock,
            )
        }
    }

    #[async_trait::async_trait]
    impl crate::confirmable::Confirmable for GateUser {
        fn confirmation_token(&self) -> Option<&str> {
            None
        }

        fn set_confirmation_token(&mut self, _token: Option<String>) {}

        fn confirmed_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
            self.confirmed.then(chrono::Utc::now)
        }

        fn set_confirmed_at(&mut self, _at: Option<chrono::DateTime<chrono::Utc>>) {}

        fn confirmation_sent_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
            self.confirmation_sent_at
        }

        fn set_confirmation_sent_at(&mut self, at: Option<chrono::DateTime<chrono::Utc>>) {
            self.confirmation_sent_at = at;
        }

        fn unconfirmed_email(&self) -> Option<&str> {
            None
        }

        fn set_unconfirmed_email(&mut self, _email: Option<String>) {}

        fn set_email_address(&mut self, _email: String) {}

        fn confirmed(&self) -> bool {
            self.confirmed
        }

        fn confirmation_required(&self) -> bool {
            self.confirmation_required
        }
    }

    #[async_trait::async_trait]
    impl crate::lockable::Lockable for GateUser {
        fn failed_attempts(&self) -> u32 {
            u32::try_from(self.failed_attempts).unwrap_or(u32::MAX)
        }

        fn set_failed_attempts(&mut self, count: u32) {
            self.failed_attempts = i64::from(count);
        }

        fn locked_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
            self.locked_at
        }

        fn set_locked_at(&mut self, at: Option<chrono::DateTime<chrono::Utc>>) {
            self.locked_at = at;
        }

        fn unlock_token(&self) -> Option<&str> {
            None
        }

        fn set_unlock_token(&mut self, _token: Option<String>) {}

        fn persisted(&self) -> bool {
            true
        }
    }

    #[derive(Debug, Default)]
    struct TrackingStore {
        data: std::sync::Arc<std::sync::RwLock<HashMap<String, serde_json::Value>>>,
        renewed: Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait::async_trait]
    impl crate::session::SessionStore for TrackingStore {
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
                .unwrap()
                .keys()
                .filter(|key| key.starts_with(prefix))
                .cloned()
                .collect()
        }

        async fn renew(&self) -> Result<(), crate::error::DeviseError> {
            self.renewed
                .store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        async fn reset(&self) -> Result<(), crate::error::DeviseError> {
            self.data.write().unwrap().clear();
            Ok(())
        }
    }

    fn hook_test_proxy(
        renewed: &Arc<std::sync::atomic::AtomicBool>,
        modules: Vec<Module>,
    ) -> (crate::proxy::AuthProxy, Arc<TrackingStore>) {
        let store = Arc::new(TrackingStore {
            data: std::sync::Arc::new(std::sync::RwLock::new(HashMap::new())),
            renewed: renewed.clone(),
        });
        let mut scope_registry = crate::scope::ScopeRegistry::new();
        let mapping = Mapping {
            name: "user".to_string(),
            class_name: "User".to_string(),
            path: "users".to_string(),
            path_prefix: None,
            singular: "user".to_string(),
            path_names: PathNames::default(),
            controllers: HashMap::new(),
            modules,
            only: vec![],
            skip: vec![],
            constraints: HashMap::new(),
            defaults: HashMap::new(),
            format: None,
            router_name: None,
            sign_out_via: SignOutVia::Delete,
            failure_app: None,
        };
        let mut hooks = HookRegistry::new();
        register_devise_hooks(&mut hooks, &mapping);
        scope_registry.register(mapping);
        let proxy = crate::proxy::AuthProxy::new(
            store.clone(),
            Arc::new(scope_registry),
            Arc::new(hooks),
            Arc::new(crate::config::DeviseConfig::default()),
        );
        (proxy, store)
    }

    fn test_mapping() -> Mapping {
        Mapping {
            name: "user".to_string(),
            class_name: "User".to_string(),
            path: "users".to_string(),
            path_prefix: None,
            singular: "user".to_string(),
            path_names: PathNames::default(),
            controllers: HashMap::new(),
            modules: vec![Module::DatabaseAuthenticatable, Module::Trackable],
            only: vec![],
            skip: vec![],
            constraints: HashMap::new(),
            defaults: HashMap::new(),
            format: None,
            router_name: None,
            sign_out_via: SignOutVia::Delete,
            failure_app: None,
        }
    }

    #[test]
    fn test_hook_filter_matches() {
        let filter = HookFilter::new()
            .scope("user")
            .only(vec![Event::Authentication]);

        // Just test filter matching logic
        let ctx = HookContext {
            proxy: &mut MockProxy,
            scope: "user",
            event: Event::Authentication,
            request: None,
            record: None,
        };
        assert!(filter.matches(&ctx));

        let ctx2 = HookContext {
            proxy: &mut MockProxy,
            scope: "admin",
            event: Event::Authentication,
            request: None,
            record: None,
        };
        assert!(!filter.matches(&ctx2));

        let ctx3 = HookContext {
            proxy: &mut MockProxy,
            scope: "user",
            event: Event::Fetch,
            request: None,
            record: None,
        };
        assert!(!filter.matches(&ctx3));
    }

    #[tokio::test]
    async fn test_hook_registry_dispatch() {
        let mut registry = HookRegistry::new();
        let called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let called_clone = called.clone();

        registry.add_hook(
            HookFilter::new().only(vec![Event::Authentication]),
            Box::new(move |_ctx| {
                let called = called_clone.clone();
                Box::pin(async move {
                    called.store(true, std::sync::atomic::Ordering::SeqCst);
                    Ok(())
                })
            }),
            false,
        );

        let mut ctx = HookContext {
            proxy: &mut MockProxy,
            scope: "user",
            event: Event::Authentication,
            request: None,
            record: None,
        };
        registry.run_hooks(&mut ctx).await.unwrap();
        assert!(called.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn test_register_devise_hooks() {
        let mut registry = HookRegistry::new();
        let mapping = test_mapping();

        register_devise_hooks(&mut registry, &mapping);

        // Should have activatable + csrf + trackable (3 hooks for this mapping)
        assert_eq!(registry.len(), 3);
    }

    #[test]
    fn test_hook_registry_all_hooks() {
        // Full module list registers all 7 hooks in Devise order.
        let mut full_mapping = test_mapping();
        full_mapping.modules = Module::all();
        let mut full = HookRegistry::new();
        register_devise_hooks(&mut full, &full_mapping);
        assert_eq!(full.len(), 7);

        // Database-only mapping gets activatable + csrf.
        let mut minimal_mapping = test_mapping();
        minimal_mapping.modules = vec![Module::DatabaseAuthenticatable];
        let mut minimal = HookRegistry::new();
        register_devise_hooks(&mut minimal, &minimal_mapping);
        assert_eq!(minimal.len(), 2);

        // Rememberable adds set + forget hooks.
        let mut remember_mapping = test_mapping();
        remember_mapping.modules = vec![Module::DatabaseAuthenticatable, Module::Rememberable];
        let mut remember = HookRegistry::new();
        register_devise_hooks(&mut remember, &remember_mapping);
        assert_eq!(remember.len(), 4);
    }

    #[tokio::test]
    async fn test_hook_registry_activatable_csrf() {
        use crate::proxy::{SetUserEvent, SetUserOpts};
        use std::sync::atomic::Ordering;

        let renewed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (mut proxy, store) = hook_test_proxy(&renewed, vec![Module::DatabaseAuthenticatable]);
        assert_eq!(proxy.hooks().len(), 2);

        // Invalid user: activatable rejects before anything is persisted.
        let rejected = proxy
            .set_user(
                "user",
                Some(Box::new(HookUser {
                    id: 1,
                    valid: false,
                })),
                SetUserOpts {
                    event: SetUserEvent::Authentication,
                    store: true,
                    run_callbacks: true,
                    force: false,
                },
            )
            .await;
        assert!(matches!(
            rejected,
            Err(crate::error::DeviseError::Internal(_))
        ));
        let session_key = crate::session::keys::scope_session_key("user");
        assert!(store.get_value(&session_key).await.is_none());
        assert!(!renewed.load(Ordering::SeqCst));

        // Valid user: activatable passes, csrf renews, session persists.
        let accepted = proxy
            .set_user(
                "user",
                Some(Box::new(HookUser { id: 1, valid: true })),
                SetUserOpts {
                    event: SetUserEvent::Authentication,
                    store: true,
                    run_callbacks: true,
                    force: false,
                },
            )
            .await;
        assert!(accepted.expect("valid user is set"));
        assert!(renewed.load(Ordering::SeqCst));
        assert!(store.get_value(&session_key).await.is_some());
        assert!(proxy.authenticated("user"));
    }

    #[test]
    fn test_event_variants() {
        assert_eq!(Event::SetUser as u8, 0);
        assert_eq!(Event::Authentication as u8, 1);
        assert_eq!(Event::Fetch as u8, 2);
        assert_eq!(Event::Logout as u8, 3);
        assert_eq!(Event::Request as u8, 4);
    }

    /// Memo-tracked user for the trackable and timeout hook tests.
    #[derive(Debug, Clone)]
    struct TrackedHookUser {
        id: i64,
        sign_in_count: u64,
        current_sign_in_ip: Option<String>,
        last_sign_in_ip: Option<String>,
        remember_value: Option<String>,
        remember_created_at: Option<chrono::DateTime<chrono::Utc>>,
    }

    impl TrackedHookUser {
        fn signed_in(id: i64) -> Self {
            Self {
                id,
                sign_in_count: 0,
                current_sign_in_ip: None,
                last_sign_in_ip: None,
                remember_value: None,
                remember_created_at: None,
            }
        }
    }

    impl AnyDeviseModel for TrackedHookUser {
        fn to_key(&self) -> crate::adapter::DeviseKey {
            crate::adapter::DeviseKey::from_i64(self.id)
        }

        fn authenticatable_salt(&self) -> Option<String> {
            Some("$2a$12$hooktestsalt123456789012".to_string())
        }

        fn apply_tracked_fields_hook(
            &mut self,
            _now: chrono::DateTime<chrono::Utc>,
            peer_ip: Option<&str>,
        ) -> bool {
            self.last_sign_in_ip = self.current_sign_in_ip.clone();
            self.current_sign_in_ip = peer_ip.map(str::to_string);
            self.sign_in_count += 1;
            true
        }

        fn rememberable_value_opt(&self) -> Option<String> {
            self.remember_value.clone()
        }

        fn remember_created_at_opt(&self) -> Option<chrono::DateTime<chrono::Utc>> {
            self.remember_created_at
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    /// Build a proxy plus a dispatch registry for the hook bodies under test.
    fn timeout_trackable_harness(
        modules: Vec<Module>,
    ) -> (
        crate::proxy::AuthProxy,
        Arc<TrackingStore>,
        HookRegistry,
        crate::scope::Mapping,
    ) {
        let renewed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (proxy, store) = hook_test_proxy(&renewed, modules.clone());
        let mapping = Mapping {
            name: "user".to_string(),
            class_name: "User".to_string(),
            path: "users".to_string(),
            path_prefix: None,
            singular: "user".to_string(),
            path_names: PathNames::default(),
            controllers: HashMap::new(),
            modules,
            only: vec![],
            skip: vec![],
            constraints: HashMap::new(),
            defaults: HashMap::new(),
            format: None,
            router_name: None,
            sign_out_via: SignOutVia::Delete,
            failure_app: None,
        };
        let mut registry = HookRegistry::new();
        register_devise_hooks(&mut registry, &mapping);
        (proxy, store, registry, mapping)
    }

    fn hook_request_with_peer(peer: &str) -> AuthRequest {
        AuthRequest::new(crate::request::HttpMethod::Get, "/protected".to_string())
            .peer_addr(peer.to_string())
    }

    #[tokio::test]
    async fn test_trackable_hook_shifts_memo_and_honors_skip() {
        let (mut proxy, _store, registry, _mapping) =
            timeout_trackable_harness(vec![Module::DatabaseAuthenticatable, Module::Trackable]);
        proxy
            .sign_in("user", Box::new(TrackedHookUser::signed_in(1)), false)
            .await;
        assert!(proxy.authenticated("user"));

        let owned: TrackedHookUser = proxy.user("user").cloned().expect("memoized");
        assert_eq!(owned.sign_in_count, 0);

        // Authentication with a socket peer shifts the memo.
        let request = hook_request_with_peer("10.1.2.3");
        let mut ctx = HookContext {
            proxy: &mut proxy,
            scope: "user",
            event: Event::Authentication,
            request: Some(&request),
            record: Some(&owned),
        };
        registry.run_hooks(&mut ctx).await.expect("hook passes");
        let shifted: TrackedHookUser = proxy.user("user").cloned().expect("memoized");
        assert_eq!(shifted.sign_in_count, 1);
        assert_eq!(shifted.current_sign_in_ip.as_deref(), Some("10.1.2.3"));

        // skip_trackable freezes the memo.
        let mut skipping = hook_request_with_peer("10.9.9.9");
        skipping.flags.skip_trackable = true;
        let owned: TrackedHookUser = proxy.user("user").cloned().expect("memoized");
        let mut ctx = HookContext {
            proxy: &mut proxy,
            scope: "user",
            event: Event::Authentication,
            request: Some(&skipping),
            record: Some(&owned),
        };
        registry.run_hooks(&mut ctx).await.expect("hook passes");
        let frozen: TrackedHookUser = proxy.user("user").cloned().expect("memoized");
        assert_eq!(frozen.sign_in_count, 1);
        assert_eq!(frozen.current_sign_in_ip.as_deref(), Some("10.1.2.3"));

        // Fetch events never shift (Devise except: :fetch).
        let request = hook_request_with_peer("10.9.9.9");
        let owned: TrackedHookUser = proxy.user("user").cloned().expect("memoized");
        let mut ctx = HookContext {
            proxy: &mut proxy,
            scope: "user",
            event: Event::Fetch,
            request: Some(&request),
            record: Some(&owned),
        };
        registry.run_hooks(&mut ctx).await.expect("hook passes");
        let unfetched: TrackedHookUser = proxy.user("user").cloned().expect("memoized");
        assert_eq!(unfetched.sign_in_count, 1);
    }

    #[tokio::test]
    async fn test_timeoutable_tick_hook_stale_signs_out_all_scopes() {
        let (mut proxy, store, registry, _mapping) =
            timeout_trackable_harness(vec![Module::DatabaseAuthenticatable, Module::Timeoutable]);
        proxy
            .sign_in("user", Box::new(TrackedHookUser::signed_in(1)), false)
            .await;
        proxy
            .sign_in("admin", Box::new(TrackedHookUser::signed_in(2)), false)
            .await;
        assert!(proxy.authenticated("user"));
        assert!(proxy.authenticated("admin"));

        // Stale tick for the requesting scope (one hour past the window).
        let stale =
            chrono::Utc::now() - chrono::TimeDelta::minutes(30) - chrono::TimeDelta::hours(1);
        store
            .insert_value(
                &crate::timeoutable::last_request_at_key("user"),
                serde_json::Value::Number(serde_json::Number::from(stale.timestamp())),
            )
            .await;

        let request = AuthRequest::new(crate::request::HttpMethod::Get, "/protected".to_string());
        let owned: TrackedHookUser = proxy.user("user").cloned().expect("memoized");
        let mut ctx = HookContext {
            proxy: &mut proxy,
            scope: "user",
            event: Event::Request,
            request: Some(&request),
            record: Some(&owned),
        };
        let outcome = registry.run_hooks(&mut ctx).await;
        assert_eq!(outcome, Err(Failure::Timeout));
        assert!(!proxy.authenticated("user"));
        assert!(!proxy.authenticated("admin"));
        assert!(proxy.locked());
        let session_key = crate::session::keys::scope_session_key("user");
        assert!(store.get_value(&session_key).await.is_none());
        let admin_key = crate::session::keys::scope_session_key("admin");
        assert!(store.get_value(&admin_key).await.is_none());
        let tick_key = crate::timeoutable::last_request_at_key("user");
        assert!(store.get_value(&tick_key).await.is_none());
    }

    #[tokio::test]
    async fn test_timeoutable_tick_hook_live_ticks_and_exempt_stays() {
        let (mut proxy, store, registry, _mapping) =
            timeout_trackable_harness(vec![Module::DatabaseAuthenticatable, Module::Timeoutable]);
        let mut user = TrackedHookUser::signed_in(1);
        user.remember_value = Some("cookie-token".to_string());
        user.remember_created_at = Some(chrono::Utc::now() - chrono::TimeDelta::hours(1));
        proxy.sign_in("user", Box::new(user), false).await;

        // Live tick: passes and refreshes the epoch.
        let tick_key = crate::timeoutable::last_request_at_key("user");
        let fresh = chrono::Utc::now() - chrono::TimeDelta::minutes(5);
        store
            .insert_value(
                &tick_key,
                serde_json::Value::Number(serde_json::Number::from(fresh.timestamp())),
            )
            .await;
        let request = AuthRequest::new(crate::request::HttpMethod::Get, "/protected".to_string());
        let owned: TrackedHookUser = proxy.user("user").cloned().expect("memoized");
        let mut ctx = HookContext {
            proxy: &mut proxy,
            scope: "user",
            event: Event::Request,
            request: Some(&request),
            record: Some(&owned),
        };
        registry
            .run_hooks(&mut ctx)
            .await
            .expect("live tick passes");
        assert!(proxy.authenticated("user"));
        let ticked = store.get_value(&tick_key).await.expect("tick stored");
        let ticked_epoch = ticked.as_i64().expect("integer epoch");
        assert!(ticked_epoch >= fresh.timestamp());

        // skip_trackable freezes the tick on the live path.
        let mut freezing =
            AuthRequest::new(crate::request::HttpMethod::Get, "/protected".to_string());
        freezing.flags.skip_trackable = true;
        let owned: TrackedHookUser = proxy.user("user").cloned().expect("memoized");
        let mut ctx = HookContext {
            proxy: &mut proxy,
            scope: "user",
            event: Event::Request,
            request: Some(&freezing),
            record: Some(&owned),
        };
        registry
            .run_hooks(&mut ctx)
            .await
            .expect("live tick passes");
        let frozen = store.get_value(&tick_key).await.expect("tick stored");
        assert_eq!(frozen, ticked);

        // Stale tick plus a live remember cookie stays signed in (D-18).
        let stale = chrono::Utc::now() - chrono::TimeDelta::hours(2);
        store
            .insert_value(
                &tick_key,
                serde_json::Value::Number(serde_json::Number::from(stale.timestamp())),
            )
            .await;
        let generated = (chrono::Utc::now() - chrono::TimeDelta::minutes(30))
            .timestamp()
            .to_string();
        let jar = crate::rememberable::encode_cookie_value("1", "cookie-token", &generated);
        let mut exempt =
            AuthRequest::new(crate::request::HttpMethod::Get, "/protected".to_string());
        exempt.cookies.insert(
            crate::rememberable::remember_cookie_key("user", proxy.config()),
            jar,
        );
        let owned: TrackedHookUser = proxy.user("user").cloned().expect("memoized");
        let mut ctx = HookContext {
            proxy: &mut proxy,
            scope: "user",
            event: Event::Request,
            request: Some(&exempt),
            record: Some(&owned),
        };
        registry
            .run_hooks(&mut ctx)
            .await
            .expect("exempt session passes");
        assert!(proxy.authenticated("user"));
        assert!(!proxy.locked());

        // Skip flags bypass the check entirely, even for a stale tick.
        let mut skipping =
            AuthRequest::new(crate::request::HttpMethod::Get, "/protected".to_string());
        skipping.flags.skip_timeout = true;
        let owned: TrackedHookUser = proxy.user("user").cloned().expect("memoized");
        let mut ctx = HookContext {
            proxy: &mut proxy,
            scope: "user",
            event: Event::Request,
            request: Some(&skipping),
            record: Some(&owned),
        };
        registry
            .run_hooks(&mut ctx)
            .await
            .expect("skipped check passes");
        assert!(proxy.authenticated("user"));
    }

    fn gate_mapping() -> Mapping {
        let mut mapping = Mapping {
            name: "user".to_string(),
            class_name: "GateUser".to_string(),
            path: "users".to_string(),
            path_prefix: None,
            singular: "user".to_string(),
            path_names: PathNames::default(),
            controllers: HashMap::new(),
            modules: vec![
                Module::DatabaseAuthenticatable,
                Module::Confirmable,
                Module::Lockable,
            ],
            only: vec![],
            skip: vec![],
            constraints: HashMap::new(),
            defaults: HashMap::new(),
            format: None,
            router_name: None,
            sign_out_via: SignOutVia::Delete,
            failure_app: None,
        };
        mapping.modules.sort();
        mapping
    }

    /// The core composers must agree with the chain arithmetic on the same
    /// record, for both the gate and the message (single home).
    #[tokio::test]
    async fn compose_gate_and_message_match_the_chain() {
        let config = crate::config::DeviseConfig::default();
        let clock = SystemClock;

        let ok = GateUser::gate(1, true, false);
        assert!(crate::model::compose_active_for_authentication(
            &ok, &config, &clock
        ));
        assert_eq!(
            crate::model::compose_inactive_message(&ok, &config, &clock),
            "inactive"
        );

        let unconfirmed = GateUser::gate(2, false, false);
        assert!(!crate::model::compose_active_for_authentication(
            &unconfirmed,
            &config,
            &clock
        ));
        assert_eq!(
            crate::model::compose_inactive_message(&unconfirmed, &config, &clock),
            "unconfirmed"
        );

        let locked = GateUser::gate(3, true, true);
        assert!(!crate::model::compose_active_for_authentication(
            &locked, &config, &clock
        ));
        assert_eq!(
            crate::model::compose_inactive_message(&locked, &config, &clock),
            "locked"
        );

        // Lockable is the outermost link (modules.rb order: lockable is
        // included after confirmable), so an unconfirmed-plus-locked
        // record reports `locked` (Devise's super-chain: `lockable.rb:95-97`
        // checks `access_locked?` before deferring via `super`).
        let both = GateUser::gate(4, false, true);
        assert_eq!(
            crate::model::compose_inactive_message(&both, &config, &clock),
            "locked"
        );
    }

    /// Devise `hooks/activatable.rb` parity end-to-end: the core hook
    /// pipeline rejects a gated record on the sign-in transition with its
    /// `inactive_message` - the app no longer composes the gates by hand.
    #[tokio::test]
    async fn activatable_hook_rejects_gated_record() {
        let store = Arc::new(TrackingStore {
            data: std::sync::Arc::new(std::sync::RwLock::new(HashMap::new())),
            renewed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        });
        let mapping = gate_mapping();
        let mut registry = crate::scope::ScopeRegistry::new();
        registry.register(mapping.clone());
        let mut hooks = crate::hooks::HookRegistry::new();
        crate::hooks::register_devise_hooks(&mut hooks, &mapping);
        let store_trait: Arc<dyn crate::session::SessionStore> = store.clone();
        let mut proxy = crate::proxy::AuthProxy::new(
            store_trait,
            Arc::new(registry),
            Arc::new(hooks),
            Arc::new(crate::config::DeviseConfig::default()),
        );

        let unconfirmed = GateUser::gate(7, false, false);
        let rejected = proxy
            .set_user(
                "user",
                Some(Box::new(unconfirmed)),
                SetUserOpts {
                    event: SetUserEvent::Authentication,
                    store: true,
                    run_callbacks: true,
                    force: false,
                },
            )
            .await;
        assert!(
            matches!(&rejected, Err(crate::error::DeviseError::Internal(message)) if message.contains("unconfirmed")),
            "hook must reject with the inactive message: {rejected:?}"
        );
        let session_key = crate::session::keys::scope_session_key("user");
        assert!(
            store.get_value(&session_key).await.is_none(),
            "no session is persisted for a gated record"
        );

        // A gated record must not authenticate through the strategy path
        // either (the Authentication event runs the same hook).
        let locked = GateUser::gate(8, true, true);
        let rejected_locked = proxy
            .set_user(
                "user",
                Some(Box::new(locked)),
                SetUserOpts {
                    event: SetUserEvent::Authentication,
                    store: true,
                    run_callbacks: true,
                    force: true,
                },
            )
            .await;
        assert!(
            matches!(&rejected_locked, Err(crate::error::DeviseError::Internal(message)) if message.contains("locked")),
            "locked record must be rejected with `locked`: {rejected_locked:?}"
        );
    }
}
