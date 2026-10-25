//! `AuthProxy` - warden Proxy port for session and strategy execution
//!
//! Mirrors `Warden::Proxy` (`warden/lib/warden/proxy.rb`): the per-request authentication state devise's controllers reach through `warden`.
//!
//! Manages per-scope memoized users, runs the strategy chain in Devise
//! order (rememberable, params, HTTP Basic), persists `[key, salt]` session
//! payloads, and dispatches hooks through `HookRegistry`.
//!
//! Ordering note: `set_user` runs hooks *before* persisting the session and
//! memoizing the user. When a hook rejects (e.g. activatable), nothing is
//! persisted, so a rejection never leaves a half-written session behind.
//! Hook observers receive the incoming record through `HookContext.record`.

use crate::adapter::DeviseKey;
use crate::config::DeviseConfig;
use crate::error::DeviseError;
use crate::failure::{AnyDeviseModel, AuthOutcome, Failure};
use crate::hooks::{Event, HookContext, HookRegistry};
use crate::model::ModelFinder;
use crate::rememberable::RememberCookieOp;
use crate::request::AuthRequest;
use crate::scope::ScopeRegistry;
use crate::session::{self, SessionStore};
use crate::strategy::Strategy;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;

/// Event that triggered `set_user`.
///
/// Mirrors warden's `event:` option on `set_user`: :authentication, :fetch, and friends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetUserEvent {
    /// User authenticated (sign in, sign up).
    Authentication,
    /// User fetched from session.
    Fetch,
    /// User explicitly assigned.
    SetUser,
}

/// Options for [`AuthProxy::set_user`].
///
/// Mirrors warden's `set_user` options: store, event, and the run-callbacks toggle.
#[derive(Debug, Clone)]
pub struct SetUserOpts {
    /// Event that triggered the call.
    pub event: SetUserEvent,
    /// Persist the session (ignored for `Fetch`).
    pub store: bool,
    /// Run `HookRegistry` hooks.
    pub run_callbacks: bool,
    /// Sign in even when the same user is already present.
    pub force: bool,
}

impl Default for SetUserOpts {
    fn default() -> Self {
        Self {
            event: SetUserEvent::Authentication,
            store: true,
            run_callbacks: true,
            force: false,
        }
    }
}

/// Central authentication state for one request.
///
/// Mirrors `Warden::Proxy` (`warden/lib/warden/proxy.rb`): the per-request authentication state holding session, strategies, config, and the memoized user.
pub struct AuthProxy {
    users: HashMap<String, Option<Box<dyn AnyDeviseModel>>>,
    performed: HashMap<String, HashSet<String>>,
    locked: bool,
    session_store: Arc<dyn SessionStore>,
    registry: Arc<ScopeRegistry>,
    hooks: Arc<HookRegistry>,
    finders: HashMap<String, Arc<dyn ModelFinder>>,
    failed_attempt_sinks: HashMap<String, Arc<dyn crate::failed_attempt::FailedAttemptSink>>,
    config: Arc<DeviseConfig>,
    remember_cookie_ops: Vec<RememberCookieOp>,
}

impl AuthProxy {
    /// Create a proxy over shared request-scoped collaborators.
    ///
    /// Per-scope [`ModelFinder`]s are registered separately with
    /// [`register_finder`](Self::register_finder).
    ///
    /// Constructs the proxy, mirroring warden's per-request proxy initialization.
    #[must_use]
    pub fn new(
        session_store: Arc<dyn SessionStore>,
        registry: Arc<ScopeRegistry>,
        hooks: Arc<HookRegistry>,
        config: Arc<DeviseConfig>,
    ) -> Self {
        Self {
            users: HashMap::new(),
            performed: HashMap::new(),
            locked: false,
            session_store,
            registry,
            hooks,
            finders: HashMap::new(),
            failed_attempt_sinks: HashMap::new(),
            config,
            remember_cookie_ops: Vec::new(),
        }
    }

    /// Register the model finder backing one scope.
    ///
    /// Registers the scope's finder, the typed mirror of warden's config-referenced user class.
    pub fn register_finder(&mut self, scope: &str, finder: Arc<dyn ModelFinder>) {
        self.finders.insert(scope.to_string(), finder);
    }

    /// Register the failed-attempt accounting sink for one scope.
    ///
    /// Devise runs the lockable counter side effects inside the strategy
    /// chain (`valid_for_authentication?`); this is the port's seam for that
    /// path - the rules stay in core, the persistence comes from the app's
    /// typed sink. Without a registration the chain keeps its pre-seam
    /// behavior (the controllers account on the sign-in POST path).
    pub fn register_failed_attempt_sink(
        &mut self,
        scope: &str,
        sink: Arc<dyn crate::failed_attempt::FailedAttemptSink>,
    ) {
        self.failed_attempt_sinks.insert(scope.to_string(), sink);
    }

    /// Borrow the scope registry.
    ///
    /// Borrows the scope registry; the `Devise.mappings` mirror the proxy reads.
    #[must_use]
    pub fn scope_registry(&self) -> &ScopeRegistry {
        &self.registry
    }

    /// Borrow the session store.
    ///
    /// Borrows the session store; the warden session surface mirror.
    #[must_use]
    pub fn session_store(&self) -> &dyn SessionStore {
        self.session_store.as_ref()
    }

    /// Borrow the hook registry.
    ///
    /// Borrows the hook registry; the warden callback storage mirror.
    #[must_use]
    pub fn hooks(&self) -> &HookRegistry {
        &self.hooks
    }

    /// Borrow the Devise config.
    ///
    /// Borrows the configuration; the `Devise` module mirror.
    #[must_use]
    pub fn config(&self) -> &DeviseConfig {
        &self.config
    }

    /// Pending remember-cookie intents (Devise jar writes, core side).
    ///
    /// Strategies and hooks push [`RememberCookieOp`]s here; framework
    /// bridges drain them after authentication and execute `Set` through
    /// `RememberableBridge::set_cookie` plus `Clear` through
    /// `RememberableBridge::clear_cookie`.
    ///
    /// The remember-cookie outbox the hooks fill; mirrors the cookies devise writes inline, queued as ops for the framework transport.
    #[must_use]
    pub fn remember_cookie_ops(&self) -> &[RememberCookieOp] {
        &self.remember_cookie_ops
    }

    /// Drain the pending remember-cookie intents for the bridge.
    ///
    /// Drains the queued remember ops; mirrors the cookie writes warden performs inline, handed off to the framework transport.
    #[must_use]
    pub fn take_remember_cookie_ops(&mut self) -> Vec<RememberCookieOp> {
        std::mem::take(&mut self.remember_cookie_ops)
    }

    /// Whether the proxy is locked for this request.
    ///
    /// Mirrors `Warden::Proxy#authenticated?` state probing.
    #[must_use]
    pub fn locked(&self) -> bool {
        self.locked
    }

    /// Lock the proxy, blocking further authentication this request.
    ///
    /// Mirrors `Warden::Proxy#lock!`: pinning the proxy to one scope for the request.
    pub fn lock(&mut self) {
        self.locked = true;
    }

    /// Authenticate a scope, running session fetch then strategies as needed.
    ///
    /// Returns the memoized user, or `None` when unauthenticated.
    pub async fn authenticate(
        &mut self,
        scope: &str,
        request: &AuthRequest,
    ) -> Option<&dyn AnyDeviseModel> {
        match self.try_authenticate(scope, request).await {
            Ok(()) => self.users.get(scope).and_then(|slot| slot.as_deref()),
            Err(_) => None,
        }
    }

    /// Authenticate strictly, propagating the real `Failure`.
    ///
    /// # Errors
    ///
    /// Returns the strategy or hook `Failure` when authentication fails.
    pub async fn authenticate_strict(
        &mut self,
        scope: &str,
        request: &AuthRequest,
    ) -> Result<&dyn AnyDeviseModel, Failure> {
        self.try_authenticate(scope, request).await?;
        self.users
            .get(scope)
            .and_then(|slot| slot.as_deref())
            .ok_or(Failure::Unauthenticated { message: "invalid" })
    }

    /// Check authentication without running strategies (memo or nothing).
    ///
    /// Mirrors `Warden::Proxy#authenticated?(scope)`: resolve and validate the signed-in record for a scope.
    #[must_use]
    pub fn authenticated(&self, scope: &str) -> bool {
        self.users
            .get(scope)
            .and_then(|slot| slot.as_deref())
            .is_some()
    }

    /// Downcast the memoized user to its concrete model type.
    ///
    /// Mirrors `Warden::Proxy#user(scope)`: the memoized current-user read.
    #[must_use]
    pub fn user<M: 'static>(&self, scope: &str) -> Option<&M> {
        self.users
            .get(scope)
            .and_then(|slot| slot.as_deref())
            .and_then(|user| user.as_any().downcast_ref::<M>())
    }

    /// Core warden `set_user` semantics.
    ///
    /// Hooks run before persistence: a rejection leaves no session behind.
    /// No-ops when the same user is already present unless `force` is set.
    ///
    /// # Errors
    ///
    /// Returns [`DeviseError`] when session renewal or a hook fails.
    pub async fn set_user(
        &mut self,
        scope: &str,
        user: Option<Box<dyn AnyDeviseModel>>,
        opts: SetUserOpts,
    ) -> Result<bool, DeviseError> {
        let current = self.users.get(scope).and_then(|slot| slot.as_deref());
        let incoming = user.as_deref();
        let same = matches!((current, incoming), (Some(old), Some(new)) if old.is_same(new));
        if same && !opts.force && opts.event == SetUserEvent::Authentication {
            return Ok(false);
        }

        if opts.run_callbacks && opts.event != SetUserEvent::Fetch {
            let hooks = self.hooks.clone();
            let event = match opts.event {
                SetUserEvent::Authentication => Event::Authentication,
                SetUserEvent::SetUser => Event::SetUser,
                SetUserEvent::Fetch => Event::Fetch,
            };
            let mut ctx = HookContext {
                proxy: self as &mut dyn crate::hooks::HookProxy,
                scope,
                event,
                request: None,
                record: incoming,
            };
            hooks.run_hooks(&mut ctx).await.map_err(DeviseError::from)?;
        }

        if opts.event != SetUserEvent::Fetch {
            session::expire_devise_keys(self.session_store.as_ref(), scope).await;
        }
        if opts.store && opts.event != SetUserEvent::Fetch {
            if let Some(ref record) = user {
                let (key, salt) = record.as_ref().session_pair();
                let session_key = session::keys::scope_session_key(scope);
                let session_value = serde_json::json!([key.to_string(), salt]);
                self.session_store
                    .insert_value(&session_key, session_value)
                    .await;
                // SESS-05: rotate CSRF and extend expiry on sign in.
                self.session_store.renew().await?;
            }
        }
        self.users.insert(scope.to_string(), user);
        Ok(true)
    }

    /// Sign in a user, expiring stale devise keys first (SESS-02).
    ///
    /// No-ops when the same user is present unless `force` is set.
    pub async fn sign_in(
        &mut self,
        scope: &str,
        user: Box<dyn AnyDeviseModel>,
        force: bool,
    ) -> bool {
        let same = self
            .users
            .get(scope)
            .and_then(|slot| slot.as_deref())
            .is_some_and(|old| old.is_same(user.as_ref()));
        if same && !force {
            return true;
        }
        let opts = SetUserOpts {
            event: SetUserEvent::Authentication,
            store: true,
            run_callbacks: true,
            force,
        };
        self.set_user(scope, Some(user), opts).await.is_ok()
    }

    /// Store a session directly without callbacks (SESS-02).
    ///
    /// Used after password changes where re-running hooks would be wrong.
    pub async fn bypass_sign_in(&mut self, scope: &str, user: Box<dyn AnyDeviseModel>) {
        session::expire_devise_keys(self.session_store.as_ref(), scope).await;
        let (key, salt) = user.as_ref().session_pair();
        let session_key = session::keys::scope_session_key(scope);
        let session_value = serde_json::json!([key.to_string(), salt]);
        self.session_store
            .insert_value(&session_key, session_value)
            .await;
        self.users.insert(scope.to_string(), Some(user));
    }

    /// Sign out one scope: logout hooks, session clear, memo clear.
    ///
    /// Returns whether a user was present.
    pub async fn sign_out(&mut self, scope: &str) -> bool {
        let record = self.users.remove(scope);
        let had_user = record.as_ref().is_some_and(Option::is_some);
        if had_user {
            let hooks = self.hooks.clone();
            let mut ctx = HookContext {
                proxy: self as &mut dyn crate::hooks::HookProxy,
                scope,
                event: Event::Logout,
                request: None,
                record: record.as_ref().and_then(|slot| slot.as_deref()),
            };
            let _ = hooks.run_hooks(&mut ctx).await;
        }
        let session_key = session::keys::scope_session_key(scope);
        self.session_store.remove(&session_key).await;
        self.performed.remove(scope);
        had_user
    }

    /// Sign out every scope, optionally locking the proxy.
    ///
    /// Returns whether any user was present.
    pub async fn sign_out_all_scopes(&mut self, lock: bool) -> bool {
        let scopes: Vec<String> = self.users.keys().cloned().collect();
        let mut any_user = false;
        for scope in &scopes {
            if self.sign_out(scope).await {
                any_user = true;
            }
        }
        if lock {
            self.lock();
        }
        any_user
    }

    /// Shared authentication flow returning the real failure on error.
    async fn try_authenticate(
        &mut self,
        scope: &str,
        request: &AuthRequest,
    ) -> Result<(), Failure> {
        if self.locked {
            return Err(Failure::Config("proxy locked".to_string()));
        }
        if self
            .users
            .get(scope)
            .and_then(|slot| slot.as_deref())
            .is_some()
        {
            return Ok(());
        }
        if let Some(user) = self.fetch_from_session(scope).await {
            let opts = SetUserOpts {
                event: SetUserEvent::Fetch,
                store: false,
                run_callbacks: false,
                force: false,
            };
            self.set_user(scope, Some(user), opts)
                .await
                .map_err(Failure::from)?;
            return Ok(());
        }
        let (user, store) = self.authenticate_via_strategies(scope, request).await?;
        let opts = SetUserOpts {
            event: SetUserEvent::Authentication,
            store,
            run_callbacks: true,
            force: false,
        };
        self.set_user(scope, Some(user), opts)
            .await
            .map_err(Failure::from)?;
        Ok(())
    }

    /// Fetch the session user with salt validation (warden fetch semantics).
    ///
    /// A salt mismatch deletes the session key and yields `None`.
    async fn fetch_from_session(&mut self, scope: &str) -> Option<Box<dyn AnyDeviseModel>> {
        let finder = self.finders.get(scope).cloned()?;
        let session_key = session::keys::scope_session_key(scope);
        let session_value = self.session_store.get_value(&session_key).await?;
        let payload = session_value.as_array()?;
        if payload.len() < 2 {
            return None;
        }
        let key = DeviseKey::from_str(payload[0].as_str()?).ok()?;
        let stored_salt = payload[1].as_str()?;
        let record = finder.get_boxed(&key).await.ok()??;
        let current_salt = record.as_ref().authenticatable_salt()?;
        if !crate::crypto::secure_compare(&current_salt, stored_salt) {
            self.session_store.remove(&session_key).await;
            return None;
        }
        let hooks = self.hooks.clone();
        let mut ctx = HookContext {
            proxy: self as &mut dyn crate::hooks::HookProxy,
            scope,
            event: Event::Fetch,
            request: None,
            record: Some(record.as_ref()),
        };
        let _ = hooks.run_hooks(&mut ctx).await;
        Some(record)
    }

    /// Run the strategy chain in Devise order.
    async fn authenticate_via_strategies(
        &mut self,
        scope: &str,
        request: &AuthRequest,
    ) -> Result<(Box<dyn AnyDeviseModel>, bool), Failure> {
        let mapping = self
            .registry
            .get(scope)
            .ok_or_else(|| Failure::Config(format!("unknown scope '{scope}'")))?
            .clone();
        let finder = self
            .finders
            .get(scope)
            .cloned()
            .ok_or_else(|| Failure::Config(format!("no finder for scope '{scope}'")))?;
        let config = self.config.clone();
        let mut strategies = crate::strategy::strategies_for(&mapping, &config);
        if let Some(sink) = self.failed_attempt_sinks.get(scope).cloned() {
            for strategy in &mut strategies {
                strategy.with_failed_attempt_sink(sink.clone());
            }
        }

        for strategy in &strategies {
            let strategy_id = strategy.id();
            if self.locked {
                return Err(Failure::Config("proxy locked".to_string()));
            }
            if self
                .performed
                .get(scope)
                .is_some_and(|done| done.contains(strategy_id))
            {
                continue;
            }
            if !strategy.valid(request, &mapping).await {
                continue;
            }
            match strategy
                .authenticate(request, &mapping, finder.as_ref(), &config)
                .await
            {
                Ok(AuthOutcome::Success(user)) => {
                    self.performed
                        .entry(scope.to_string())
                        .or_default()
                        .insert(strategy_id.to_string());
                    return Ok((user, strategy.store()));
                }
                Ok(AuthOutcome::SuccessWithCookieRefresh {
                    user,
                    cookie_key,
                    cookie_value,
                    expires,
                }) => {
                    self.performed
                        .entry(scope.to_string())
                        .or_default()
                        .insert(strategy_id.to_string());
                    // Extend re-issue (D-14): queue the refreshed cookie with
                    // the hardened attributes, then proceed as success.
                    let mut attrs = crate::rememberable::RememberableCookieAttrs::for_scope(
                        scope,
                        &config,
                        &crate::time::SystemClock,
                    );
                    attrs.expires = expires;
                    self.remember_cookie_ops.push(RememberCookieOp::Set {
                        scope: scope.to_string(),
                        key: cookie_key,
                        value: cookie_value,
                        attrs,
                    });
                    return Ok((user, strategy.store()));
                }
                Ok(AuthOutcome::ClearCookieAndPass { cookie_key }) => {
                    // Stale cookie (RMB-04): queue the delete for the bridge
                    // (its `RememberableBridge::clear_cookie` equivalent) and
                    // continue the chain with pass-through semantics.
                    self.remember_cookie_ops.push(RememberCookieOp::Clear {
                        scope: scope.to_string(),
                        key: cookie_key,
                    });
                }
                Ok(AuthOutcome::Pass) => {}
                Err(failure) => {
                    self.performed
                        .entry(scope.to_string())
                        .or_default()
                        .insert(strategy_id.to_string());
                    return Err(failure);
                }
            }
        }
        Err(Failure::Unauthenticated { message: "invalid" })
    }
}

#[async_trait::async_trait]
impl crate::hooks::HookProxy for AuthProxy {
    fn session_store(&self) -> &dyn SessionStore {
        self.session_store.as_ref()
    }

    fn scope_registry(&self) -> &ScopeRegistry {
        &self.registry
    }

    fn devise_config(&self) -> &DeviseConfig {
        &self.config
    }

    fn push_remember_cookie_op(&mut self, op: RememberCookieOp) {
        self.remember_cookie_ops.push(op);
    }

    fn user_mut(&mut self, scope: &str) -> Option<&mut Option<Box<dyn AnyDeviseModel>>> {
        self.users.get_mut(scope)
    }

    fn lock(&mut self) {
        self.locked = true;
    }

    async fn sign_out_for_timeout(&mut self, scope: &str, sign_out_all: bool) {
        if sign_out_all {
            let scopes: Vec<String> = self.users.keys().cloned().collect();
            self.sign_out_all_scopes(true).await;
            for timed_out in &scopes {
                self.session_store
                    .remove(&crate::timeoutable::last_request_at_key(timed_out))
                    .await;
            }
        } else {
            self.sign_out(scope).await;
            self.session_store
                .remove(&crate::timeoutable::last_request_at_key(scope))
                .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::OrmAdapter;
    use crate::adapter::memory::MemoryAdapter;
    use crate::config::DeviseConfig;
    use crate::hooks::HookRegistry;
    use crate::hooks::RememberableBridge;
    use crate::model::{AdapterBridge, PasswordVerifiable};
    use crate::request::HttpMethod;
    use crate::scope::{Mapping, PathNames, SignOutVia};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
    struct ProxyUser {
        id: i64,
        email: String,
        encrypted_password: String,
    }

    impl AnyDeviseModel for ProxyUser {
        fn to_key(&self) -> DeviseKey {
            DeviseKey::from_i64(self.id)
        }

        fn authenticatable_salt(&self) -> Option<String> {
            self.encrypted_password.get(..29).map(str::to_string)
        }

        fn as_password_verifiable(&self) -> Option<&dyn PasswordVerifiable> {
            Some(self)
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    impl PasswordVerifiable for ProxyUser {
        fn valid_password(&self, password: &str, config: &DeviseConfig) -> bool {
            crate::crypto::encryptor::compare(password, &self.encrypted_password, config)
        }
    }

    #[derive(Debug, Default)]
    struct ProxySessionStore {
        data: std::sync::Arc<std::sync::RwLock<HashMap<String, serde_json::Value>>>,
        renewed: Arc<AtomicBool>,
    }

    #[async_trait::async_trait]
    impl SessionStore for ProxySessionStore {
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

        async fn renew(&self) -> Result<(), DeviseError> {
            self.renewed.store(true, Ordering::SeqCst);
            Ok(())
        }

        async fn reset(&self) -> Result<(), DeviseError> {
            self.data.write().unwrap().clear();
            Ok(())
        }
    }

    fn test_config() -> DeviseConfig {
        DeviseConfig {
            stretches: 4,
            ..DeviseConfig::default()
        }
    }

    fn test_proxy(renewed: &Arc<AtomicBool>) -> (AuthProxy, Arc<ProxySessionStore>) {
        let store = Arc::new(ProxySessionStore {
            data: std::sync::Arc::new(std::sync::RwLock::new(HashMap::new())),
            renewed: renewed.clone(),
        });
        let mut registry = ScopeRegistry::new();
        registry.register(Mapping {
            name: "user".to_string(),
            class_name: "User".to_string(),
            path: "users".to_string(),
            path_prefix: None,
            singular: "user".to_string(),
            path_names: PathNames::default(),
            controllers: HashMap::new(),
            modules: vec![crate::scope::Module::DatabaseAuthenticatable],
            only: vec![],
            skip: vec![],
            constraints: HashMap::new(),
            defaults: HashMap::new(),
            format: None,
            router_name: None,
            sign_out_via: SignOutVia::Delete,
            failure_app: None,
        });
        let proxy = AuthProxy::new(
            store.clone(),
            Arc::new(registry),
            Arc::new(HookRegistry::new()),
            Arc::new(test_config()),
        );
        (proxy, store)
    }

    async fn seeded_bridge(
        config: &DeviseConfig,
    ) -> AdapterBridge<MemoryAdapter<ProxyUser>, ProxyUser> {
        let adapter = MemoryAdapter::<ProxyUser>::new();
        adapter
            .create(ProxyUser {
                id: 1,
                email: "test@example.com".to_string(),
                encrypted_password: crate::crypto::encryptor::digest("secret123", config),
            })
            .await
            .unwrap();
        AdapterBridge::new(adapter)
    }

    fn sign_in_request() -> AuthRequest {
        let mut request = AuthRequest::new(HttpMethod::Post, "/users/sign_in");
        request
            .params
            .insert("user_email".to_string(), "test@example.com".to_string());
        request
            .params
            .insert("user_password".to_string(), "secret123".to_string());
        request.flags.allow_params_authentication = true;
        request
    }

    #[tokio::test]
    async fn test_params_strategy_happy_path() {
        let renewed = Arc::new(AtomicBool::new(false));
        let (mut proxy, store) = test_proxy(&renewed);
        let config = test_config();
        proxy.register_finder("user", Arc::new(seeded_bridge(&config).await));

        let request = sign_in_request();
        proxy
            .authenticate_strict("user", &request)
            .await
            .expect("params auth succeeds");

        let session_key = session::keys::scope_session_key("user");
        let payload = store.get_value(&session_key).await.expect("session stored");
        let pair = payload.as_array().expect("pair payload");
        assert_eq!(pair.len(), 2);
        assert!(renewed.load(Ordering::SeqCst), "renew called");
        assert!(proxy.authenticated("user"));
        assert!(proxy.user::<ProxyUser>("user").is_some());
    }

    #[tokio::test]
    async fn test_proxy_sign_in_out() {
        let renewed = Arc::new(AtomicBool::new(false));
        let (mut proxy, _) = test_proxy(&renewed);
        let user: Box<dyn AnyDeviseModel> = Box::new(ProxyUser {
            id: 1,
            email: "test@example.com".to_string(),
            encrypted_password: String::new(),
        });
        assert!(proxy.sign_in("user", user, false).await);
        assert!(proxy.authenticated("user"));
        assert!(proxy.sign_out("user").await);
        assert!(!proxy.authenticated("user"));
        assert!(!proxy.sign_out("user").await);
    }

    #[tokio::test]
    async fn test_proxy_sign_in_noop() {
        let renewed = Arc::new(AtomicBool::new(false));
        let (mut proxy, store) = test_proxy(&renewed);
        let make = || {
            Box::new(ProxyUser {
                id: 1,
                email: "test@example.com".to_string(),
                encrypted_password: String::new(),
            }) as Box<dyn AnyDeviseModel>
        };
        assert!(proxy.sign_in("user", make(), false).await);
        let session_key = session::keys::scope_session_key("user");
        let first = store.get_value(&session_key).await;
        assert!(proxy.sign_in("user", make(), false).await);
        let second = store.get_value(&session_key).await;
        assert_eq!(first, second);
        assert!(proxy.authenticated("user"));
    }

    #[tokio::test]
    async fn test_proxy_bypass_sign_in() {
        let renewed = Arc::new(AtomicBool::new(false));
        let (mut proxy, _) = test_proxy(&renewed);
        proxy
            .bypass_sign_in(
                "user",
                Box::new(ProxyUser {
                    id: 7,
                    email: "bypass@example.com".to_string(),
                    encrypted_password: String::new(),
                }),
            )
            .await;
        assert!(proxy.authenticated("user"));
        // Bypass skips callbacks: renew is only invoked by set_user.
        assert!(!renewed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_proxy_sign_out_all_scopes() {
        let renewed = Arc::new(AtomicBool::new(false));
        let (mut proxy, _) = test_proxy(&renewed);
        proxy
            .sign_in(
                "user",
                Box::new(ProxyUser {
                    id: 1,
                    email: "test@example.com".to_string(),
                    encrypted_password: String::new(),
                }),
                false,
            )
            .await;
        assert!(proxy.sign_out_all_scopes(false).await);
        assert!(!proxy.authenticated("user"));
        assert!(!proxy.locked());
    }

    #[tokio::test]
    async fn test_proxy_lock_blocks_auth() {
        let renewed = Arc::new(AtomicBool::new(false));
        let (mut proxy, _) = test_proxy(&renewed);
        proxy.lock();
        assert!(proxy.locked());
        let request = sign_in_request();
        assert!(proxy.authenticate("user", &request).await.is_none());
    }

    #[tokio::test]
    async fn test_strategy_chain() {
        let renewed = Arc::new(AtomicBool::new(false));
        let (mut proxy, _) = test_proxy(&renewed);
        let config = test_config();
        proxy.register_finder("user", Arc::new(seeded_bridge(&config).await));
        let mut bad = sign_in_request();
        bad.params
            .insert("user_password".to_string(), "wrong".to_string());
        assert!(proxy.authenticate("user", &bad).await.is_none());
    }

    #[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
    struct RememberProxyUser {
        id: i64,
        email: String,
        encrypted_password: String,
        remember_token: Option<String>,
        remember_created_at: Option<chrono::DateTime<chrono::Utc>>,
        #[serde(skip)]
        remember_flag: Option<bool>,
    }

    impl AnyDeviseModel for RememberProxyUser {
        fn to_key(&self) -> DeviseKey {
            DeviseKey::from_i64(self.id)
        }

        fn authenticatable_salt(&self) -> Option<String> {
            self.encrypted_password.get(..29).map(str::to_string)
        }

        fn rememberable_value_opt(&self) -> Option<String> {
            Some(self.remember_token.clone().unwrap_or_default())
        }

        fn remember_created_at_opt(&self) -> Option<chrono::DateTime<chrono::Utc>> {
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

    /// Test bridge proving the proxy outbox drains into real bridge calls.
    struct RecordingBridge;

    #[async_trait::async_trait]
    impl crate::hooks::RememberableBridge for RecordingBridge {
        async fn set_cookie(
            store: &dyn SessionStore,
            scope: &str,
            value: &str,
            expires: chrono::DateTime<chrono::Utc>,
        ) -> Result<(), DeviseError> {
            store
                .insert_value(
                    &format!("remember_cookie_set:{scope}"),
                    serde_json::json!([value, expires.to_rfc3339()]),
                )
                .await;
            Ok(())
        }

        async fn clear_cookie(store: &dyn SessionStore, scope: &str) -> Result<(), DeviseError> {
            store
                .insert_value(
                    &format!("remember_cookie_cleared:{scope}"),
                    serde_json::Value::Bool(true),
                )
                .await;
            Ok(())
        }
    }

    fn remember_test_proxy(
        renewed: &Arc<AtomicBool>,
        config: DeviseConfig,
    ) -> (AuthProxy, Arc<ProxySessionStore>) {
        let store = Arc::new(ProxySessionStore {
            data: std::sync::Arc::new(std::sync::RwLock::new(HashMap::new())),
            renewed: renewed.clone(),
        });
        let mut registry = ScopeRegistry::new();
        registry.register(Mapping {
            name: "user".to_string(),
            class_name: "User".to_string(),
            path: "users".to_string(),
            path_prefix: None,
            singular: "user".to_string(),
            path_names: PathNames::default(),
            controllers: HashMap::new(),
            modules: vec![
                crate::scope::Module::DatabaseAuthenticatable,
                crate::scope::Module::Rememberable,
            ],
            only: vec![],
            skip: vec![],
            constraints: HashMap::new(),
            defaults: HashMap::new(),
            format: None,
            router_name: None,
            sign_out_via: SignOutVia::Delete,
            failure_app: None,
        });
        let proxy = AuthProxy::new(
            store.clone(),
            Arc::new(registry),
            Arc::new(HookRegistry::new()),
            Arc::new(config),
        );
        (proxy, store)
    }

    async fn seeded_remember_proxy_bridge()
    -> AdapterBridge<MemoryAdapter<RememberProxyUser>, RememberProxyUser> {
        // Live instants (SystemClock drives the chain-built strategy): the
        // creation hour and the cookie minute both sit inside the window
        // with strict ordering between them.
        let now = chrono::Utc::now();
        let adapter = MemoryAdapter::<RememberProxyUser>::new();
        adapter
            .create(RememberProxyUser {
                id: 1,
                email: "remember@example.com".to_string(),
                encrypted_password: String::new(),
                remember_token: Some("cookie-token".to_string()),
                remember_created_at: Some(now - chrono::TimeDelta::hours(1)),
                remember_flag: None,
            })
            .await
            .unwrap();
        AdapterBridge::new(adapter)
    }

    fn remember_cookie_request(jar: &str) -> AuthRequest {
        let mut request = AuthRequest::new(HttpMethod::Get, "/");
        request
            .cookies
            .insert("remember_user_token".to_string(), jar.to_string());
        request
    }

    fn live_cookie_jar() -> String {
        let generated = (chrono::Utc::now() - chrono::TimeDelta::seconds(60)).timestamp();
        crate::rememberable::encode_cookie_value("1", "cookie-token", &generated.to_string())
    }

    #[tokio::test]
    async fn test_proxy_rememberable_stale_cookie_clears_and_passes() {
        let renewed = Arc::new(AtomicBool::new(false));
        let (mut proxy, store) = remember_test_proxy(&renewed, test_config());
        proxy.register_finder("user", Arc::new(seeded_remember_proxy_bridge().await));

        // Stale jar: the chain passes through (no params follow), so auth
        // yields nothing, but the delete signal is queued, never a failure.
        let request = remember_cookie_request("garbage");
        assert!(proxy.authenticate("user", &request).await.is_none());
        let ops = proxy.take_remember_cookie_ops();
        assert_eq!(ops.len(), 1);
        assert!(matches!(
            &ops[0],
            crate::rememberable::RememberCookieOp::Clear { scope, key }
            if scope == "user" && key == "remember_user_token"
        ));

        // The drained signal reaches the bridge contract.
        for op in &ops {
            if let crate::rememberable::RememberCookieOp::Clear { scope, .. } = op {
                RecordingBridge::clear_cookie(store.as_ref(), scope)
                    .await
                    .unwrap();
            }
        }
        assert_eq!(
            store.get_value("remember_cookie_cleared:user").await,
            Some(serde_json::Value::Bool(true))
        );
    }

    #[tokio::test]
    async fn test_proxy_rememberable_success_sets_session_without_ops() {
        let renewed = Arc::new(AtomicBool::new(false));
        let (mut proxy, store) = remember_test_proxy(&renewed, test_config());
        proxy.register_finder("user", Arc::new(seeded_remember_proxy_bridge().await));

        let request = remember_cookie_request(&live_cookie_jar());
        let user = proxy
            .authenticate("user", &request)
            .await
            .expect("remember hit authenticates");
        assert_eq!(user.to_key(), DeviseKey::from_i64(1));
        assert_eq!(proxy.take_remember_cookie_ops().len(), 0);
        let session_key = session::keys::scope_session_key("user");
        assert!(store.get_value(&session_key).await.is_some());
    }

    #[tokio::test]
    async fn test_proxy_rememberable_extend_queues_hardened_set_op() {
        let renewed = Arc::new(AtomicBool::new(false));
        let config = DeviseConfig {
            extend_remember_period: true,
            ..test_config()
        };
        let (mut proxy, store) = remember_test_proxy(&renewed, config);
        proxy.register_finder("user", Arc::new(seeded_remember_proxy_bridge().await));

        let request = remember_cookie_request(&live_cookie_jar());
        assert!(proxy.authenticate("user", &request).await.is_some());
        let ops = proxy.take_remember_cookie_ops();
        assert_eq!(ops.len(), 1);
        let crate::rememberable::RememberCookieOp::Set {
            scope,
            key,
            value,
            attrs,
        } = &ops[0]
        else {
            panic!("extend re-issue queues a Set op, got {:?}", ops[0]);
        };
        assert_eq!(scope, "user");
        assert_eq!(key, "remember_user_token");
        assert!(crate::rememberable::decode_cookie_value(value).is_some());
        assert!(attrs.httponly && attrs.secure);
        assert_eq!(attrs.same_site, crate::rememberable::SameSite::Lax);

        RecordingBridge::set_cookie(store.as_ref(), scope, value, attrs.expires)
            .await
            .unwrap();
        assert!(store.get_value("remember_cookie_set:user").await.is_some());
    }
}
