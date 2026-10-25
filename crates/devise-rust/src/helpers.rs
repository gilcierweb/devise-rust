//! Controller helpers - per-scope auth functions over `AuthProxy`
//!
//! Mirrors `devise/lib/devise/controllers/helpers.rb`
//! (`authenticate_<scope>!`, `<scope>_signed_in?`, `current_<scope>`,
//! `<scope>_session`), `sign_in_out.rb` path helpers, `store_location.rb`,
//! and the `devise_group` multi-scope support. Framework crates
//! (actix/axum) call these from their extractors and implement
//! [`DeviseHelpersExt`] for their request types.

use crate::failure::{Failure, FailureReason, build_failure, stored_location_for};
use crate::proxy::AuthProxy;
use crate::request::AuthRequest;
use crate::scope::Mapping;

/// Options for [`authenticate`] and [`authenticate_strict`].
///
/// Options of the `authenticate_<scope>!` helper: force, scope, and message, mirroring the arguments of `Devise::Controllers::Helpers#authenticate_user!`.
#[derive(Debug, Clone, Default)]
pub struct AuthenticateOpts {
    /// Force authentication even when the same user is memoized.
    pub force: bool,
    /// Persist the session on success.
    pub store: bool,
    /// Run `HookRegistry` hooks on success.
    pub run_callbacks: bool,
}

/// Authenticate a scope, returning the user or `None`.
pub async fn authenticate<'a>(
    scope: &str,
    proxy: &'a mut AuthProxy,
    request: &AuthRequest,
    _opts: &AuthenticateOpts,
) -> Option<&'a dyn crate::failure::AnyDeviseModel> {
    proxy.authenticate(scope, request).await
}

/// Authenticate strictly, propagating the real `Failure`.
///
/// # Errors
///
/// Returns the strategy or hook `Failure` when authentication fails.
pub async fn authenticate_strict<'a>(
    scope: &str,
    proxy: &'a mut AuthProxy,
    request: &AuthRequest,
    _opts: &AuthenticateOpts,
) -> Result<&'a dyn crate::failure::AnyDeviseModel, Failure> {
    proxy.authenticate_strict(scope, request).await
}

/// Whether `scope` is signed in.
///
/// Mirrors `signed_in?(scope)` from `Devise::Controllers::SignInOut`.
#[must_use]
pub fn signed_in(scope: &str, proxy: &AuthProxy) -> bool {
    proxy.authenticated(scope)
}

/// Typed current user for `scope`, if present.
///
/// Mirrors the memoized `current_<scope>` helper `Devise::Controllers::Helpers` generates per mapping.
#[must_use]
pub fn current_user<'a, M: 'static>(scope: &str, proxy: &'a AuthProxy) -> Option<&'a M> {
    proxy.user::<M>(scope)
}

/// Raw session payload for `scope`, if stored.
pub async fn session_data(scope: &str, proxy: &AuthProxy) -> Option<serde_json::Value> {
    proxy
        .session_store()
        .get_value(&crate::session::keys::scope_session_key(scope))
        .await
}

/// Scope root path, falling back to `/` for unmapped scopes.
///
/// Mirrors `signed_in_root_path`: where a signed-in request lands instead of the sign-in page.
#[must_use]
pub fn signed_in_root_path(scope: &str, proxy: &AuthProxy) -> String {
    proxy
        .scope_registry()
        .get(scope)
        .map_or_else(|| "/".to_string(), Mapping::full_path)
}

/// Post-sign-in path: stored location, else scope root, else `/`.
pub async fn after_sign_in_path_for(
    scope: &str,
    proxy: &AuthProxy,
    _request: &AuthRequest,
) -> String {
    if let Some(location) = stored_location_for(scope, proxy.session_store()).await {
        return location;
    }
    signed_in_root_path(scope, proxy)
}

/// Post-sign-out path: scope root, else `/`.
///
/// Mirrors `after_sign_out_path_for(scope)` from `Devise::Controllers::Helpers`.
#[must_use]
pub fn after_sign_out_path_for(scope: &str, proxy: &AuthProxy) -> String {
    signed_in_root_path(scope, proxy)
}

/// Reject already-signed-in users from sign-in pages (SESS-08).
///
/// # Errors
///
/// Returns a navigational redirect with the `already_authenticated` flash
/// when `scope` is signed in.
pub async fn require_no_authentication(
    scope: &str,
    proxy: &AuthProxy,
    request: &AuthRequest,
) -> Result<(), Failure> {
    if !signed_in(scope, proxy) {
        return Ok(());
    }
    let mapping = proxy
        .scope_registry()
        .get(scope)
        .ok_or_else(|| Failure::Config(format!("unknown scope '{scope}'")))?;
    let reason = FailureReason::AlreadyAuthenticated;
    let mut failure = build_failure(request, mapping, proxy.config(), reason);
    if let Failure::NavigationalRedirect {
        ref mut location, ..
    } = failure
    {
        *location = after_sign_in_path_for(scope, proxy, request).await;
    }
    Err(failure)
}

/// Multi-scope group, mirroring `devise_group`.
#[derive(Debug, Clone)]
pub struct Group {
    /// Group name (e.g. `"blogger"`).
    pub name: String,
    /// Scopes tried in order.
    pub scopes: Vec<String>,
}

impl Group {
    /// Create a group from a name and scope list.
    ///
    /// Constructs a group, mirroring `devise_group`'s scope list.
    #[must_use]
    pub fn new(name: impl Into<String>, scopes: Vec<String>) -> Self {
        Self {
            name: name.into(),
            scopes,
        }
    }
}

/// Authenticate every scope in the group, returning the ones that succeeded.
pub async fn authenticate_group(
    group: &Group,
    proxy: &mut AuthProxy,
    request: &AuthRequest,
    opts: &AuthenticateOpts,
) -> Vec<String> {
    let mut authenticated = Vec::new();
    for scope in &group.scopes {
        if authenticate(scope, proxy, request, opts).await.is_some() {
            authenticated.push(scope.clone());
        }
    }
    authenticated
}

/// Whether any group scope is signed in.
///
/// Mirrors the group helpers `devise_group` generates (`blogger_signed_in?`).
#[must_use]
pub fn group_signed_in(group: &Group, proxy: &AuthProxy) -> bool {
    group.scopes.iter().any(|scope| signed_in(scope, proxy))
}

/// Extension contract for framework request types.
///
/// Bridges implement `proxy`/`proxy_mut` against their request extensions;
/// every helper above is then available as a provided method.
///
/// Mirrors the per-scope helper surface `Devise::Controllers::Helpers` generates for every mapping, as an extension trait on framework request contexts.
pub trait DeviseHelpersExt {
    /// Access the request's `AuthProxy`.
    fn proxy(&self) -> &AuthProxy;
    /// Mutably access the request's `AuthProxy`.
    fn proxy_mut(&mut self) -> &mut AuthProxy;

    /// Whether `scope` is signed in.
    fn scope_signed_in(&self, scope: &str) -> bool {
        signed_in(scope, self.proxy())
    }
}

/// Generate per-scope helpers for one model and scope.
///
/// Emits `authenticate_<scope>`, `<scope>_signed_in`, `current_<scope>`,
/// and `<scope>_session` on the target type, which must implement
/// [`DeviseHelpersExt`].
#[macro_export]
macro_rules! devise_helpers {
    ($target:ty, $model:ty, $scope:literal) => {
        impl $target {
            /// Authenticate `scope`, returning the failure on error.
            pub async fn authenticate_scope(
                &mut self,
                request: &$crate::request::AuthRequest,
                opts: &$crate::helpers::AuthenticateOpts,
            ) -> Result<&$model, $crate::failure::Failure> {
                $crate::helpers::authenticate_strict($scope, self.proxy_mut(), request, opts)
                    .await?
                    .as_any()
                    .downcast_ref::<$model>()
                    .ok_or($crate::failure::Failure::Unauthenticated { message: "invalid" })
            }

            /// Whether `scope` is signed in.
            ///
            /// Arbitrary-scope `signed_in?` helper, mirroring the generated `<scope>_signed_in?` for any registered scope.
            #[must_use]
            pub fn scope_signed_in(&self) -> bool {
                $crate::helpers::DeviseHelpersExt::scope_signed_in(self, $scope)
            }

            /// Typed current user for `scope`, if present.
            ///
            /// Arbitrary-scope `current_<scope>` helper, mirroring the generated memoized current user accessor.
            #[must_use]
            pub fn current_scoped_user(&self) -> Option<&$model> {
                $crate::helpers::current_user::<$model>($scope, self.proxy())
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::memory::MemoryAdapter;
    use crate::config::DeviseConfig;
    use crate::failure::AnyDeviseModel;
    use crate::hooks::HookRegistry;
    use crate::model::{AdapterBridge, PasswordVerifiable};
    use crate::request::HttpMethod;
    use crate::scope::{Mapping, Module, PathNames, ScopeRegistry, SignOutVia};
    use std::collections::HashMap;
    use std::sync::Arc;

    #[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
    struct HelperUser {
        id: i64,
        email: String,
        encrypted_password: String,
    }

    impl AnyDeviseModel for HelperUser {
        fn to_key(&self) -> crate::adapter::DeviseKey {
            crate::adapter::DeviseKey::from_i64(self.id)
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

    impl PasswordVerifiable for HelperUser {
        fn valid_password(&self, password: &str, config: &DeviseConfig) -> bool {
            crate::crypto::encryptor::compare(password, &self.encrypted_password, config)
        }
    }

    #[derive(Debug, Default)]
    struct HelperStore {
        data: std::sync::Arc<std::sync::RwLock<HashMap<String, serde_json::Value>>>,
    }

    #[async_trait::async_trait]
    impl crate::session::SessionStore for HelperStore {
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
            Ok(())
        }

        async fn reset(&self) -> Result<(), crate::error::DeviseError> {
            self.data.write().unwrap().clear();
            Ok(())
        }
    }

    struct HelperHolder {
        proxy: AuthProxy,
    }

    impl DeviseHelpersExt for HelperHolder {
        fn proxy(&self) -> &AuthProxy {
            &self.proxy
        }

        fn proxy_mut(&mut self) -> &mut AuthProxy {
            &mut self.proxy
        }
    }

    crate::devise_helpers!(HelperHolder, HelperUser, "user");

    fn helper_proxy() -> (AuthProxy, DeviseConfig) {
        let config = DeviseConfig {
            stretches: 4,
            ..DeviseConfig::default()
        };
        let mut registry = ScopeRegistry::new();
        registry.register(Mapping {
            name: "user".to_string(),
            class_name: "User".to_string(),
            path: "users".to_string(),
            path_prefix: None,
            singular: "user".to_string(),
            path_names: PathNames::default(),
            controllers: HashMap::new(),
            modules: vec![Module::DatabaseAuthenticatable],
            only: vec![],
            skip: vec![],
            constraints: HashMap::new(),
            defaults: HashMap::new(),
            format: None,
            router_name: None,
            sign_out_via: SignOutVia::Delete,
            failure_app: None,
        });
        let store = Arc::new(HelperStore::default());
        let mut proxy = AuthProxy::new(
            store,
            Arc::new(registry),
            Arc::new(HookRegistry::new()),
            Arc::new(config.clone()),
        );
        let adapter = MemoryAdapter::<HelperUser>::new();
        proxy.register_finder("user", Arc::new(AdapterBridge::new(adapter)));
        (proxy, config)
    }

    fn helper_sign_in_request() -> AuthRequest {
        let mut request = AuthRequest::new(HttpMethod::Post, "/users/sign_in".to_string());
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
    async fn test_helpers_authenticate_signed_in() {
        let (mut proxy, _) = helper_proxy();
        let opts = AuthenticateOpts::default();
        let request = helper_sign_in_request();
        // Unknown user: not signed in.
        assert!(!signed_in("user", &proxy));
        assert!(
            authenticate("user", &mut proxy, &request, &opts)
                .await
                .is_none()
        );

        // Signed out users pass the sign-in-page guard.
        assert!(
            require_no_authentication("user", &proxy, &request)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_helpers_paths_and_groups() {
        let (mut proxy, _) = helper_proxy();
        let request = AuthRequest::new(HttpMethod::Get, "/protected".to_string());
        assert_eq!(signed_in_root_path("user", &proxy), "/users");
        assert_eq!(signed_in_root_path("ghost", &proxy), "/");
        assert_eq!(after_sign_out_path_for("user", &proxy), "/users");
        // No stored location: falls back to scope root.
        assert_eq!(
            after_sign_in_path_for("user", &proxy, &request).await,
            "/users"
        );

        // Stored location wins over the scope root, then is consumed.
        crate::failure::store_location(
            &AuthRequest::new(HttpMethod::Get, "/protected".to_string()),
            "user",
            &crate::config::DeviseConfig::default(),
            proxy.session_store(),
        )
        .await;
        assert_eq!(
            after_sign_in_path_for("user", &proxy, &request).await,
            "/protected"
        );
        assert_eq!(
            after_sign_in_path_for("user", &proxy, &request).await,
            "/users"
        );

        let group = Group::new("blogger", vec!["user".to_string(), "admin".to_string()]);
        assert!(!group_signed_in(&group, &proxy));
        let opts = AuthenticateOpts::default();
        let done = authenticate_group(&group, &mut proxy, &request, &opts).await;
        assert_eq!(done.len(), 0);
    }

    #[tokio::test]
    async fn test_helpers_require_no_authentication() {
        let (mut proxy, _) = helper_proxy();
        let mut request = AuthRequest::new(HttpMethod::Get, "/users/sign_in".to_string());
        request
            .headers
            .insert("accept".to_string(), "text/html".to_string());
        // Signed out: passes.
        assert!(
            require_no_authentication("user", &proxy, &request)
                .await
                .is_ok()
        );
        // Signed in: redirects with already_authenticated.
        proxy
            .sign_in(
                "user",
                Box::new(HelperUser {
                    id: 1,
                    email: "test@example.com".to_string(),
                    encrypted_password: String::new(),
                }),
                false,
            )
            .await;
        let err = require_no_authentication("user", &proxy, &request)
            .await
            .expect_err("signed-in user is redirected");
        assert_eq!(err.flash_key(), Some("already_authenticated"));
    }

    #[tokio::test]
    async fn test_helpers_macro_and_current_user() {
        let (proxy, _) = helper_proxy();
        let mut holder = HelperHolder { proxy };
        assert!(!holder.scope_signed_in());
        assert!(holder.current_scoped_user().is_none());

        holder
            .proxy_mut()
            .sign_in(
                "user",
                Box::new(HelperUser {
                    id: 1,
                    email: "test@example.com".to_string(),
                    encrypted_password: String::new(),
                }),
                false,
            )
            .await;
        assert!(holder.scope_signed_in());
        assert_eq!(
            current_user::<HelperUser>("user", holder.proxy()).map(|u| u.id),
            Some(1)
        );
        assert!(session_data("user", holder.proxy()).await.is_some());

        // Macro-generated strict auth resolves through the memoized user.
        let request = AuthRequest::new(HttpMethod::Get, "/".to_string());
        let opts = AuthenticateOpts::default();
        let authed = holder.authenticate_scope(&request, &opts).await;
        assert!(authed.is_ok());
    }
}
