//! Hooks - Warden-compatible hook registry and event dispatch
//!
//! Implements Devise's hook system: `after_set_user`, `after_authentication`,
//! `before_logout`, `after_fetch`, `on_request` with Warden's `only`/`except`
//! filtering semantics. Phase 3 delivers the registry and stub hooks; Phase 5
//! fills in module-specific hook bodies.

use crate::failure::Failure;
use crate::request::AuthRequest;
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
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set scope filter
    #[must_use]
    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// Set only filter (events that trigger)
    #[must_use]
    pub fn only(mut self, events: Vec<Event>) -> Self {
        self.only = events;
        self
    }

    /// Set except filter (events that skip)
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
pub trait HookProxy: Send + Sync {
    /// Get the session store
    fn session_store(&self) -> &dyn crate::session::SessionStore;
    /// Get the scope registry
    fn scope_registry(&self) -> &crate::scope::ScopeRegistry;
    /// Get mutable access to user map (for `sign_out`, lock, etc.)
    fn user_mut(&mut self, scope: &str) -> Option<&mut Option<Box<dyn AnyDeviseModel>>>;
    /// Lock the proxy (blocks further auth this request)
    fn lock(&mut self);
}

/// Trait for any Devise model - re-exported for hook context
pub use crate::failure::AnyDeviseModel;

/// Hook registry - manages hook registration and dispatch
///
/// Thread-safe for concurrent request handling. Hooks are registered at startup
/// and dispatched per-request via `run_hooks`.
pub struct HookRegistry {
    hooks: Vec<HookEntry>,
}

impl HookRegistry {
    /// Create a new empty hook registry
    #[must_use]
    pub fn new() -> Self {
        Self { hooks: Vec::new() }
    }

    /// Add a hook with filter and prepend/append ordering
    ///
    /// `prepend = true` inserts at front (runs first), `false` appends (runs last).
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
    #[must_use]
    pub fn len(&self) -> usize {
        self.hooks.len()
    }

    /// Check if registry is empty
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
pub fn register_devise_hooks(registry: &mut HookRegistry, mapping: &crate::scope::Mapping) {
    use crate::scope::Module;

    // 1. Activatable - runs on SetUser + Authentication for all scopes
    registry.add_hook(
        HookFilter::new().only(vec![Event::SetUser, Event::Authentication]),
        Box::new(|ctx| {
            Box::pin(async move {
                if let Some(record) = ctx.record {
                    if !record.valid_for_authentication(None) {
                        return Err(Failure::Unauthenticated {
                            message: record.unauthenticated_message(),
                        });
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
            HookFilter::new().only(vec![Event::Authentication]),
            Box::new(|_ctx| {
                Box::pin(async move {
                    // TODO Phase 5: record.update_tracked_fields(ctx.request.unwrap())
                    Ok(())
                })
            }),
            false,
        );
    }

    // 4. Rememberable Set - runs on Authentication for scopes with Rememberable module
    if mapping.modules.contains(&Module::Rememberable) {
        registry.add_hook(
            HookFilter::new().only(vec![Event::Authentication]),
            Box::new(|_ctx| {
                Box::pin(async move {
                    // TODO Phase 5: if remember_me_flag { record.remember_me!(); RememberableBridge::set_cookie(...) }
                    Ok(())
                })
            }),
            false,
        );
    }

    // 5. Forgetable - runs on Logout for scopes with Rememberable module
    if mapping.modules.contains(&Module::Rememberable) {
        registry.add_hook(
            HookFilter::new().only(vec![Event::Logout]),
            Box::new(|_ctx| {
                Box::pin(async move {
                    // TODO Phase 5: record.forget_me!(); RememberableBridge::clear_cookie(...)
                    Ok(())
                })
            }),
            false,
        );
    }

    // 6. Lockable Reset - runs on Authentication for scopes with Lockable module
    if mapping.modules.contains(&Module::Lockable) {
        registry.add_hook(
            HookFilter::new().only(vec![Event::Authentication]),
            Box::new(|_ctx| {
                Box::pin(async move {
                    // TODO Phase 5: record.reset_failed_attempts!()
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
            Box::new(|_ctx| {
                Box::pin(async move {
                    // TODO Phase 5: update last_request_at; if record.timedout?(last) { return Err(Failure::Timeout) }
                    Ok(())
                })
            }),
            false,
        );
    }
}

/// Bridge trait for session renewal (SESS-05)
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
    use crate::scope::{Mapping, Module, PathNames, SignOutVia};
    use std::collections::HashMap;

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
    fn test_event_variants() {
        assert_eq!(Event::SetUser as u8, 0);
        assert_eq!(Event::Authentication as u8, 1);
        assert_eq!(Event::Fetch as u8, 2);
        assert_eq!(Event::Logout as u8, 3);
        assert_eq!(Event::Request as u8, 4);
    }
}
