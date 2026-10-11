//! Scope & routing - Module enum, Mapping, `ScopeRegistry`, `RouteSpec`
//!
//! Drives route generation, failure-app scope resolution, and module ordering.
//! Canonical module order from `devise/lib/devise/modules.rb` preserved.

use crate::config::DeviseConfig;
use crate::error::DeviseError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Devise modules in canonical order (devise/lib/devise/modules.rb)
///
/// This order determines:
/// - Strategy chain execution (Rememberable first as no-input)
/// - Hook registration order
/// - Route generation order
/// - `active_for_authentication?` super-chain evaluation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Module {
    /// `database_authicatable` - base auth with `encrypted_password`
    DatabaseAuthenticatable = 0,
    /// `rememberable` - remember-me cookie
    Rememberable = 1,
    /// `omniauthable` - `OmniAuth` integration
    Omniauthable = 2,
    /// `recoverable` - password reset
    Recoverable = 3,
    /// `registerable` - sign up
    Registerable = 4,
    /// `validatable` - email/password validations
    Validatable = 5,
    /// `confirmable` - email confirmation
    Confirmable = 6,
    /// `lockable` - account locking
    Lockable = 7,
    /// `timeoutable` - session timeout
    Timeoutable = 8,
    /// `trackable` - sign-in tracking
    Trackable = 9,
}

impl Module {
    /// All modules in canonical order
    #[must_use]
    pub fn all() -> Vec<Module> {
        vec![
            Module::DatabaseAuthenticatable,
            Module::Rememberable,
            Module::Omniauthable,
            Module::Recoverable,
            Module::Registerable,
            Module::Validatable,
            Module::Confirmable,
            Module::Lockable,
            Module::Timeoutable,
            Module::Trackable,
        ]
    }

    /// Module name as Devise expects it (`snake_case`)
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Module::DatabaseAuthenticatable => "database_authenticatable",
            Module::Rememberable => "rememberable",
            Module::Omniauthable => "omniauthable",
            Module::Recoverable => "recoverable",
            Module::Registerable => "registerable",
            Module::Validatable => "validatable",
            Module::Confirmable => "confirmable",
            Module::Lockable => "lockable",
            Module::Timeoutable => "timeoutable",
            Module::Trackable => "trackable",
        }
    }
}

impl std::fmt::Display for Module {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Path name overrides for `devise_for` routes
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PathNames {
    pub sign_in: String,
    pub sign_out: String,
    pub sign_up: String,
    pub password: String,
    pub confirmation: String,
    pub unlock: String,
    pub registration: String,
    pub edit: String,
    pub cancel: String,
}

impl Default for PathNames {
    fn default() -> Self {
        Self {
            sign_in: "sign_in".to_string(),
            sign_out: "sign_out".to_string(),
            sign_up: "sign_up".to_string(),
            password: "password".to_string(),
            confirmation: "confirmation".to_string(),
            unlock: "unlock".to_string(),
            registration: String::new(),
            edit: "edit".to_string(),
            cancel: "cancel".to_string(),
        }
    }
}

/// Sign-out HTTP method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SignOutVia {
    #[default]
    Delete,
    Get,
    Post,
}

impl std::fmt::Display for SignOutVia {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignOutVia::Delete => write!(f, "DELETE"),
            SignOutVia::Get => write!(f, "GET"),
            SignOutVia::Post => write!(f, "POST"),
        }
    }
}

/// Scope mapping - configuration for a single authentication scope
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Mapping {
    /// Scope name (singular, e.g., "user", "admin")
    pub name: String,
    /// Model class name (e.g., "User", "Admin")
    pub class_name: String,
    /// Route path (e.g., "users", "admins")
    pub path: String,
    /// Path prefix (optional, e.g., "api")
    pub path_prefix: Option<String>,
    /// Singular name for route helpers
    pub singular: String,
    /// Path name overrides
    pub path_names: PathNames,
    /// Controller overrides per action
    pub controllers: HashMap<String, String>,
    /// Enabled modules (sorted by canonical order)
    pub modules: Vec<Module>,
    /// Only these modules (empty = all)
    pub only: Vec<Module>,
    /// Skip these modules (empty = none)
    pub skip: Vec<Module>,
    /// Route constraints
    pub constraints: HashMap<String, String>,
    /// Route defaults
    pub defaults: HashMap<String, String>,
    /// Format constraint (e.g., "json")
    pub format: Option<String>,
    /// Router name
    pub router_name: Option<String>,
    /// Sign-out HTTP method
    pub sign_out_via: SignOutVia,
    /// Failure app override
    pub failure_app: Option<String>,
}

impl Mapping {
    /// Get the full path prefix for this scope
    #[must_use]
    pub fn full_path(&self) -> String {
        match &self.path_prefix {
            Some(prefix) => format!("/{prefix}/{}", self.path),
            None => format!("/{}", self.path),
        }
    }

    /// Get the scoped path for nested routes
    #[must_use]
    pub fn scoped_path(&self) -> String {
        self.full_path()
    }

    /// Get sign-in path for this scope
    #[must_use]
    pub fn sign_in_path(&self) -> String {
        format!("{}/{}", self.full_path(), self.path_names.sign_in)
    }

    /// Get sign-out path for this scope
    #[must_use]
    pub fn sign_out_path(&self) -> String {
        format!("{}/{}", self.full_path(), self.path_names.sign_out)
    }

    /// Get sign-up path for this scope
    #[must_use]
    pub fn sign_up_path(&self) -> String {
        format!("{}/{}", self.full_path(), self.path_names.sign_up)
    }

    /// Get password path for this scope
    #[must_use]
    pub fn password_path(&self) -> String {
        format!("{}/{}", self.full_path(), self.path_names.password)
    }

    /// Get confirmation path for this scope
    #[must_use]
    pub fn confirmation_path(&self) -> String {
        format!("{}/{}", self.full_path(), self.path_names.confirmation)
    }

    /// Get unlock path for this scope
    #[must_use]
    pub fn unlock_path(&self) -> String {
        format!("{}/{}", self.full_path(), self.path_names.unlock)
    }

    /// Get the effective modules list (applying only/skip)
    #[must_use]
    pub fn effective_modules(&self) -> Vec<Module> {
        let mut modules = self.modules.clone();

        // Apply only filter
        if !self.only.is_empty() {
            modules.retain(|m| self.only.contains(m));
        }

        // Apply skip filter
        if !self.skip.is_empty() {
            modules.retain(|m| !self.skip.contains(m));
        }

        // Sort by canonical order
        modules.sort();
        modules
    }

    /// Check if a module is enabled for this mapping
    #[must_use]
    pub fn has_module(&self, module: Module) -> bool {
        self.effective_modules().contains(&module)
    }

    /// Generate `RouteSpec` table for this mapping
    ///
    /// Mirrors `devise/lib/devise/rails/routes.rb:376-418` - generates
    /// the full `devise_for` route table with only/skip filtering.
    #[must_use]
    pub fn route_specs(&self) -> Vec<RouteSpec> {
        let mut specs = Vec::new();
        for module in self.effective_modules() {
            match module {
                Module::DatabaseAuthenticatable => self.push_session_routes(&mut specs),
                Module::Registerable => self.push_registration_routes(&mut specs),
                Module::Recoverable => self.push_password_routes(&mut specs),
                Module::Confirmable => self.push_confirmation_routes(&mut specs),
                Module::Lockable => self.push_unlock_routes(&mut specs),
                Module::Omniauthable => self.push_omniauth_routes(&mut specs),
                // Validatable, Trackable, Timeoutable, Rememberable don't add routes
                Module::Validatable
                | Module::Trackable
                | Module::Timeoutable
                | Module::Rememberable => {}
            }
        }
        specs
    }

    fn scoped(&self, name: &str) -> String {
        format!("{}/{name}", self.full_path())
    }

    fn named(&self, stem: &str) -> String {
        format!("{}_{}", self.singular, stem)
    }

    fn push_session_routes(&self, specs: &mut Vec<RouteSpec>) {
        let sign_in = self.scoped(&self.path_names.sign_in);
        specs.push(RouteSpec::new(
            sign_in.clone(),
            "GET",
            "new",
            format!("new_{}", self.named("session")),
        ));
        specs.push(RouteSpec::new(
            sign_in,
            "POST",
            "create",
            self.named("session"),
        ));
        specs.push(RouteSpec::new(
            self.scoped(&self.path_names.sign_out),
            self.sign_out_via.to_string(),
            "destroy",
            format!("destroy_{}", self.named("session")),
        ));
    }

    fn push_registration_routes(&self, specs: &mut Vec<RouteSpec>) {
        let base = self.full_path();
        specs.push(RouteSpec::new(
            self.scoped(&self.path_names.sign_up),
            "GET",
            "new",
            format!("new_{}", self.named("registration")),
        ));
        specs.push(RouteSpec::new(
            base.clone(),
            "POST",
            "create",
            self.named("registration"),
        ));
        specs.push(RouteSpec::new(
            self.scoped(&self.path_names.cancel),
            "GET",
            "cancel",
            format!("cancel_{}", self.named("registration")),
        ));
        if self.path_names.edit.is_empty() {
            return;
        }
        specs.push(RouteSpec::new(
            self.scoped(&self.path_names.edit),
            "GET",
            "edit",
            format!("edit_{}", self.named("registration")),
        ));
        for method in ["PATCH", "PUT"] {
            specs.push(RouteSpec::new(
                self.scoped(&self.path_names.registration),
                method,
                "update",
                self.named("registration"),
            ));
        }
        specs.push(RouteSpec::new(
            base,
            "DELETE",
            "destroy",
            self.named("registration"),
        ));
    }

    fn push_password_routes(&self, specs: &mut Vec<RouteSpec>) {
        let password = self.scoped(&self.path_names.password);
        let name = self.named("password");
        for (path, method, action, route_name) in [
            (
                format!("{password}/new"),
                "GET",
                "new",
                format!("new_{name}"),
            ),
            (password.clone(), "POST", "create", name.clone()),
            (
                format!("{password}/edit"),
                "GET",
                "edit",
                format!("edit_{name}"),
            ),
            (password.clone(), "PATCH", "update", name.clone()),
            (password, "PUT", "update", name.clone()),
        ] {
            specs.push(RouteSpec::new(path, method, action, route_name));
        }
    }

    fn push_confirmation_routes(&self, specs: &mut Vec<RouteSpec>) {
        let confirmation = self.scoped(&self.path_names.confirmation);
        let name = self.named("confirmation");
        specs.push(RouteSpec::new(
            format!("{confirmation}/new"),
            "GET",
            "new",
            format!("new_{name}"),
        ));
        specs.push(RouteSpec::new(
            confirmation.clone(),
            "GET",
            "show",
            name.clone(),
        ));
        specs.push(RouteSpec::new(confirmation, "POST", "create", name));
    }

    fn push_unlock_routes(&self, specs: &mut Vec<RouteSpec>) {
        // Unlocks routes (only when unlock_strategy includes :email)
        let unlock = self.scoped(&self.path_names.unlock);
        let name = self.named("unlock");
        specs.push(RouteSpec::new(
            format!("{unlock}/new"),
            "GET",
            "new",
            format!("new_{name}"),
        ));
        specs.push(RouteSpec::new(unlock.clone(), "GET", "show", name.clone()));
        specs.push(RouteSpec::new(unlock, "POST", "create", name));
    }

    fn push_omniauth_routes(&self, specs: &mut Vec<RouteSpec>) {
        // Cross-phase note (09-04 amendment, shared with the Phase 8 actix
        // crate): this spec is core data consumed by BOTH framework crates.
        // Phase 8 froze around the GET/GET placeholder; this amendment to
        // POST-only authorize (OMN-03, `OmniAuth` 2 `allowed_request_methods`
        // semantics) plus GET|POST callback (Devise routes the callback
        // `via: [:get, :post]`) is the single coordinated fix both crates
        // render from. Framework crates must NOT re-amend the methods.
        specs.extend(omniauth_route_specs(
            &self.omniauth_base_default(),
            &self.singular,
        ));
    }

    /// The config-free default omniauth base: `{full_path}/auth` with
    /// Devise's `.squeeze("/")` slash collapsing (devise/lib/devise/rails/
    /// routes.rb `devise_omniauth_callback`).
    fn omniauth_base_default(&self) -> String {
        squeezed_slashes(&format!("{}/auth", self.full_path()))
    }

    /// The resolved omniauth base for this mapping: the global
    /// `omniauth_path_prefix` override when set (Devise's single global
    /// prefix), else the mapping default `{full_path}/auth`.
    ///
    /// A configured prefix is normalized to a leading slash with doubled
    /// slashes collapsed, mirroring Devise's `.squeeze("/")`.
    #[must_use]
    pub fn omniauth_base(&self, config: &DeviseConfig) -> String {
        match &config.omniauth_path_prefix {
            Some(prefix) => squeezed_slashes(prefix),
            None => self.omniauth_base_default(),
        }
    }

    /// The omniauth route specs for this mapping resolved through the
    /// config (the `omniauth_path_prefix` override honored).
    ///
    /// Registration MUST also run [`Mapping::validate_omniauth_paths`] so
    /// the dynamic-segment ban surfaces as a `Config` error at
    /// registration time; the framework mount functions call it.
    #[must_use]
    pub fn omniauth_route_specs_for(&self, config: &DeviseConfig) -> Vec<RouteSpec> {
        omniauth_route_specs(&self.omniauth_base(config), &self.singular)
    }

    /// The concrete callback path for one provider, derived from the
    /// shared spec table (never hand-built by the framework handlers):
    /// the `callback` spec's path with the `{provider}` capture
    /// substituted.
    ///
    /// == Examples
    ///
    /// ```
    /// use devise_rust::config::DeviseConfig;
    /// use devise_rust::scope::{Mapping, Module};
    /// # fn omniauthable_mapping() -> Mapping {
    /// #     Mapping {
    /// #         name: "user".to_string(),
    /// #         class_name: "User".to_string(),
    /// #         path: "users".to_string(),
    /// #         path_prefix: None,
    /// #         singular: "user".to_string(),
    /// #         path_names: Default::default(),
    /// #         controllers: Default::default(),
    /// #         modules: vec![Module::Omniauthable],
    /// #         only: vec![],
    /// #         skip: vec![],
    /// #         constraints: Default::default(),
    /// #         defaults: Default::default(),
    /// #         format: None,
    /// #         router_name: None,
    /// #         sign_out_via: Default::default(),
    /// #         failure_app: None,
    /// #     }
    /// # }
    /// let mapping = omniauthable_mapping();
    /// let path = mapping.omniauth_callback_path(&DeviseConfig::default(), "github");
    /// assert_eq!(path, "/users/auth/github/callback");
    /// ```
    #[must_use]
    pub fn omniauth_callback_path(&self, config: &DeviseConfig, provider: &str) -> String {
        self.omniauth_route_specs_for(config)
            .iter()
            .find(|spec| spec.action == "callback")
            .map_or_else(
                || format!("{}/{provider}", self.omniauth_base(config)),
                |spec| spec.path.replace("{provider}", provider),
            )
    }

    /// The full route table with the omniauth legs resolved through the
    /// config: every non-omniauth spec exactly as
    /// [`Mapping::route_specs`] emits it, plus the omniauth specs resolved
    /// through [`Mapping::omniauth_route_specs_for`] when the mapping is
    /// omniauthable (the `omniauth_path_prefix` override honored).
    ///
    /// Registration MUST also run [`Mapping::validate_omniauth_paths`] so
    /// the dynamic-segment ban surfaces as a `Config` error at
    /// registration time; the framework mount functions call it.
    #[must_use]
    pub fn route_specs_for(&self, config: &DeviseConfig) -> Vec<RouteSpec> {
        let mut specs: Vec<RouteSpec> = self
            .route_specs()
            .into_iter()
            .filter(|spec| !spec.name.contains("omniauth"))
            .collect();
        if self.has_module(Module::Omniauthable) {
            specs.extend(self.omniauth_route_specs_for(config));
        }
        specs
    }

    /// Devise's dynamic-segment ban for omniauthable mappings
    /// (`devise_omniauth_callback` in devise/lib/devise/rails/routes.rb):
    /// scoping `OmniAuth` callbacks under a dynamic segment is
    /// unsupported.
    ///
    /// Registration-time check: returns [`DeviseError::Config`] mirroring
    /// Devise's raise text when the mapping is omniauthable and its full
    /// path carries a dynamic segment (either `:segment` or `{segment}`
    /// shape). Non-omniauthable mappings always pass.
    ///
    /// # Errors
    ///
    /// Returns [`DeviseError::Config`] when the mapping is omniauthable
    /// and its scope path contains a dynamic segment.
    pub fn validate_omniauth_paths(&self) -> Result<(), DeviseError> {
        if !self.has_module(Module::Omniauthable) {
            return Ok(());
        }
        let full_path = self.full_path();
        if full_path.contains(':') || full_path.contains('{') {
            return Err(DeviseError::Config(format!(
                "Devise does not support scoping OmniAuth callbacks under a dynamic segment \
                 and you have set {full_path:?}. You can work around by passing \
                 `skip: :omniauth_callbacks` to the `devise_for` call and extract omniauth \
                 options to another `devise_for` call outside the scope."
            )));
        }
        Ok(())
    }
}

/// Normalize a path prefix: guarantee a leading slash and collapse
/// consecutive slashes (Devise's `"/#{...}".squeeze("/")`).
fn squeezed_slashes(path: &str) -> String {
    let owned;
    let path = if path.starts_with('/') {
        path
    } else {
        owned = format!("/{path}");
        &owned
    };
    let mut out = String::with_capacity(path.len());
    let mut prev_slash = false;
    for ch in path.chars() {
        if ch == '/' {
            if !prev_slash {
                out.push(ch);
            }
            prev_slash = true;
        } else {
            out.push(ch);
            prev_slash = false;
        }
    }
    out
}

/// Build the omniauth route-spec triple for one mapping — the ONE shared
/// constructor both framework crates and tests build their omniauth route
/// expectations from (OMN-01, no per-framework route tables).
///
/// Exactly three specs per omniauthable mapping, mirroring Devise's
/// `devise_omniauth_callback` route block under `OmniAuth` 2 semantics:
///
/// * `POST {base}/{provider}` — action `passthru` (authorize),
///   POST-only per `OmniAuth.config.allowed_request_methods` (OMN-03).
/// * `GET {base}/{provider}/callback` and `POST {base}/{provider}/callback`
///   — action `callback`, matching Devise's `via: [:get, :post]`.
///
/// `base` is the RESOLVED omniauth base — the `omniauth_path_prefix`
/// override or the mapping default `{full_path}/auth` (see
/// [`Mapping::omniauth_base`]). The generic `{provider}` capture is a
/// single table row pair: the per-provider allowlist check runs at
/// REQUEST time against
/// [`omniauth_providers`](crate::config::DeviseConfig::omniauth_providers)
/// (unknown provider -> 404 passthru parity), so no per-provider rows
/// ever appear in the table.
///
/// == Examples
///
/// ```
/// use devise_rust::scope::omniauth_route_specs;
///
/// let specs = omniauth_route_specs("/users/auth", "user");
/// assert_eq!(specs.len(), 3);
/// // POST-only authorize (OMN-03).
/// assert_eq!(specs[0].path, "/users/auth/{provider}");
/// assert_eq!(specs[0].method, "POST");
/// assert_eq!(specs[0].action, "passthru");
/// assert_eq!(specs[0].name, "user_omniauth_authorize");
/// // GET|POST callback (Devise `via: [:get, :post]`).
/// assert_eq!(specs[1].path, "/users/auth/{provider}/callback");
/// assert_eq!(specs[1].method, "GET");
/// assert_eq!(specs[1].action, "callback");
/// assert_eq!(specs[1].name, "user_omniauth_callback");
/// assert_eq!(specs[2].path, "/users/auth/{provider}/callback");
/// assert_eq!(specs[2].method, "POST");
/// ```
#[must_use]
pub fn omniauth_route_specs(omniauth_base: &str, singular: &str) -> Vec<RouteSpec> {
    let authorize_name = format!("{singular}_omniauth_authorize");
    let callback_name = format!("{singular}_omniauth_callback");
    let callback_path = format!("{omniauth_base}/{{provider}}/callback");
    vec![
        RouteSpec::new(
            format!("{omniauth_base}/{{provider}}"),
            "POST",
            "passthru",
            authorize_name,
        ),
        RouteSpec::new(
            callback_path.clone(),
            "GET",
            "callback",
            callback_name.clone(),
        ),
        RouteSpec::new(callback_path, "POST", "callback", callback_name),
    ]
}

/// Route specification - data structure for framework route registration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteSpec {
    /// Route path (e.g., `/users/sign_in`)
    pub path: String,
    /// HTTP method (GET, POST, etc.)
    pub method: String,
    /// Controller action (e.g., "new", "create")
    pub action: String,
    /// Route name (e.g., `new_user_session`)
    pub name: String,
    /// Additional options
    pub options: HashMap<String, String>,
}
impl RouteSpec {
    /// Create a new route spec
    #[must_use]
    pub fn new(
        path: impl Into<String>,
        method: impl Into<String>,
        action: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            method: method.into(),
            action: action.into(),
            name: name.into(),
            options: HashMap::new(),
        }
    }

    /// Add an option
    #[must_use]
    pub fn with_option(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.options.insert(key.into(), value.into());
        self
    }
}

/// Scope registry - manages all registered scopes
///
/// Built at startup, immutable after. Used for:
/// - Route generation (`RouteSpec` table)
/// - Failure app scope resolution (`find_by_path`)
/// - Per-scope config lookup
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScopeRegistry {
    scopes: HashMap<String, Mapping>,
}

impl ScopeRegistry {
    /// Create a new empty scope registry
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a scope mapping
    pub fn register(&mut self, mut mapping: Mapping) {
        let name = mapping.name.clone();
        // Sort modules by canonical order at registration
        mapping.modules.sort();
        self.scopes.insert(name, mapping);
    }

    /// Get a mapping by scope name
    #[must_use]
    pub fn get(&self, scope: &str) -> Option<&Mapping> {
        self.scopes.get(scope)
    }

    /// Get mutable mapping by scope name
    pub fn get_mut(&mut self, scope: &str) -> Option<&mut Mapping> {
        self.scopes.get_mut(scope)
    }

    /// Find scope by request path (for failure app)
    ///
    /// Matches the longest path prefix - e.g., `/users/sign_in` maps to the `user` scope.
    #[must_use]
    pub fn find_by_path(&self, path: &str) -> Option<&Mapping> {
        let mut best_match: Option<&Mapping> = None;
        let mut best_len = 0;

        for mapping in self.scopes.values() {
            let full_path = mapping.full_path();
            if path.starts_with(&full_path) && full_path.len() > best_len {
                best_len = full_path.len();
                best_match = Some(mapping);
            }
        }

        best_match
    }

    /// Get all registered scope names
    #[must_use]
    pub fn scope_names(&self) -> Vec<String> {
        self.scopes.keys().cloned().collect()
    }

    /// Get all route specs for all scopes
    #[must_use]
    pub fn all_route_specs(&self) -> Vec<RouteSpec> {
        self.scopes
            .values()
            .flat_map(Mapping::route_specs)
            .collect()
    }

    /// Get count of registered scopes
    #[must_use]
    pub fn len(&self) -> usize {
        self.scopes.len()
    }

    /// Check if registry is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.scopes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_order() {
        let modules = Module::all();
        assert_eq!(modules[0], Module::DatabaseAuthenticatable);
        assert_eq!(modules[1], Module::Rememberable);
        assert_eq!(modules[2], Module::Omniauthable);
        assert_eq!(modules[3], Module::Recoverable);
        assert_eq!(modules[4], Module::Registerable);
        assert_eq!(modules[5], Module::Validatable);
        assert_eq!(modules[6], Module::Confirmable);
        assert_eq!(modules[7], Module::Lockable);
        assert_eq!(modules[8], Module::Timeoutable);
        assert_eq!(modules[9], Module::Trackable);
    }

    #[test]
    fn test_module_display() {
        assert_eq!(
            Module::DatabaseAuthenticatable.to_string(),
            "database_authenticatable"
        );
        assert_eq!(Module::Rememberable.to_string(), "rememberable");
    }

    #[test]
    fn test_path_names_defaults() {
        let names = PathNames::default();
        assert_eq!(names.sign_in, "sign_in");
        assert_eq!(names.sign_out, "sign_out");
        assert_eq!(names.sign_up, "sign_up");
        assert_eq!(names.registration, "");
    }

    #[test]
    fn test_sign_out_via() {
        assert_eq!(SignOutVia::Delete.to_string(), "DELETE");
        assert_eq!(SignOutVia::Get.to_string(), "GET");
        assert_eq!(SignOutVia::Post.to_string(), "POST");
    }

    #[test]
    fn test_mapping_full_path() {
        let mapping = Mapping {
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
        };

        assert_eq!(mapping.full_path(), "/users");
        assert_eq!(mapping.sign_in_path(), "/users/sign_in");
        assert_eq!(mapping.sign_out_path(), "/users/sign_out");
    }

    #[test]
    fn test_mapping_with_prefix() {
        let mapping = Mapping {
            name: "user".to_string(),
            class_name: "User".to_string(),
            path: "users".to_string(),
            path_prefix: Some("api".to_string()),
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
        };

        assert_eq!(mapping.full_path(), "/api/users");
        assert_eq!(mapping.sign_in_path(), "/api/users/sign_in");
    }

    #[test]
    fn test_mapping_effective_modules() {
        let mut mapping = Mapping {
            name: "user".to_string(),
            class_name: "User".to_string(),
            path: "users".to_string(),
            path_prefix: None,
            singular: "user".to_string(),
            path_names: PathNames::default(),
            controllers: HashMap::new(),
            modules: Module::all(),
            only: vec![],
            skip: vec![],
            constraints: HashMap::new(),
            defaults: HashMap::new(),
            format: None,
            router_name: None,
            sign_out_via: SignOutVia::Delete,
            failure_app: None,
        };

        // All modules by default
        assert_eq!(mapping.effective_modules().len(), 10);

        // Only specific modules
        mapping.only = vec![Module::DatabaseAuthenticatable, Module::Registerable];
        let effective = mapping.effective_modules();
        assert_eq!(effective.len(), 2);
        assert!(effective.contains(&Module::DatabaseAuthenticatable));
        assert!(effective.contains(&Module::Registerable));

        // Skip modules
        mapping.only = vec![];
        mapping.skip = vec![Module::Omniauthable, Module::Confirmable];
        let effective = mapping.effective_modules();
        assert_eq!(effective.len(), 8);
        assert!(!effective.contains(&Module::Omniauthable));
        assert!(!effective.contains(&Module::Confirmable));
    }

    #[test]
    fn test_route_specs_database_authenticatable() {
        let mapping = Mapping {
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
        };

        let specs = mapping.route_specs();
        assert_eq!(specs.len(), 3); // sign_in GET, sign_in POST, sign_out DELETE

        let paths: Vec<_> = specs.iter().map(|s| s.path.as_str()).collect();
        assert!(paths.contains(&"/users/sign_in"));
        assert!(paths.contains(&"/users/sign_out"));

        let methods: Vec<_> = specs.iter().map(|s| s.method.as_str()).collect();
        assert!(methods.contains(&"GET"));
        assert!(methods.contains(&"POST"));
        assert!(methods.contains(&"DELETE"));
    }

    #[test]
    fn test_route_specs_registerable() {
        let mapping = Mapping {
            name: "user".to_string(),
            class_name: "User".to_string(),
            path: "users".to_string(),
            path_prefix: None,
            singular: "user".to_string(),
            path_names: PathNames::default(),
            controllers: HashMap::new(),
            modules: vec![Module::Registerable],
            only: vec![],
            skip: vec![],
            constraints: HashMap::new(),
            defaults: HashMap::new(),
            format: None,
            router_name: None,
            sign_out_via: SignOutVia::Delete,
            failure_app: None,
        };

        let specs = mapping.route_specs();
        // sign_up GET, create POST, cancel GET, edit GET, update PATCH/PUT, destroy DELETE
        assert_eq!(specs.len(), 7);
    }

    #[test]
    fn test_scope_registry() {
        let mut registry = ScopeRegistry::new();
        assert!(registry.is_empty());

        let mapping = Mapping {
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
        };

        registry.register(mapping);
        assert_eq!(registry.len(), 1);
        assert!(registry.get("user").is_some());
        assert!(registry.get("admin").is_none());
        assert_eq!(registry.scope_names(), vec!["user"]);
    }

    #[test]
    fn test_find_by_path() {
        let mut registry = ScopeRegistry::new();

        let user_mapping = Mapping {
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
        };

        let admin_mapping = Mapping {
            name: "admin".to_string(),
            class_name: "Admin".to_string(),
            path: "admins".to_string(),
            path_prefix: None,
            singular: "admin".to_string(),
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
        };

        registry.register(user_mapping);
        registry.register(admin_mapping);

        assert_eq!(
            registry.find_by_path("/users/sign_in").unwrap().name,
            "user"
        );
        assert_eq!(
            registry.find_by_path("/admins/sign_in").unwrap().name,
            "admin"
        );
        assert_eq!(registry.find_by_path("/api/users/sign_in"), None);
    }

    #[test]
    fn test_all_route_specs() {
        let mut registry = ScopeRegistry::new();

        let user_mapping = Mapping {
            name: "user".to_string(),
            class_name: "User".to_string(),
            path: "users".to_string(),
            path_prefix: None,
            singular: "user".to_string(),
            path_names: PathNames::default(),
            controllers: HashMap::new(),
            modules: vec![Module::DatabaseAuthenticatable, Module::Registerable],
            only: vec![],
            skip: vec![],
            constraints: HashMap::new(),
            defaults: HashMap::new(),
            format: None,
            router_name: None,
            sign_out_via: SignOutVia::Delete,
            failure_app: None,
        };

        registry.register(user_mapping);

        let all_specs = registry.all_route_specs();
        // 3 (database_authenticatable) + 7 (registerable) = 10
        assert_eq!(all_specs.len(), 10);
    }

    // ====================================================================
    // Omniauth spec amendment (09-04, shared with the Phase 8 actix crate)
    // ====================================================================

    fn omniauthable_mapping() -> Mapping {
        Mapping {
            name: "user".to_string(),
            class_name: "User".to_string(),
            path: "users".to_string(),
            path_prefix: None,
            singular: "user".to_string(),
            path_names: PathNames::default(),
            controllers: HashMap::new(),
            modules: vec![Module::DatabaseAuthenticatable, Module::Omniauthable],
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
    fn test_route_specs_omniauthable_emits_post_authorize_get_or_post_callback() {
        let mapping = omniauthable_mapping();
        let specs = mapping.route_specs();
        let omniauth: Vec<_> = specs
            .iter()
            .filter(|spec| spec.name.contains("omniauth"))
            .collect();
        // Exactly the shared triple per omniauthable mapping.
        assert_eq!(omniauth.len(), 3);

        // POST-only authorize on the brace-provider path (OMN-03).
        assert_eq!(omniauth[0].path, "/users/auth/{provider}");
        assert_eq!(omniauth[0].method, "POST");
        assert_eq!(omniauth[0].action, "passthru");
        assert_eq!(omniauth[0].name, "user_omniauth_authorize");

        // GET + POST callback on the brace-provider callback path.
        assert_eq!(omniauth[1].path, "/users/auth/{provider}/callback");
        assert_eq!(omniauth[1].method, "GET");
        assert_eq!(omniauth[1].action, "callback");
        assert_eq!(omniauth[1].name, "user_omniauth_callback");
        assert_eq!(omniauth[2].path, "/users/auth/{provider}/callback");
        assert_eq!(omniauth[2].method, "POST");
        assert_eq!(omniauth[2].action, "callback");
        assert_eq!(omniauth[2].name, "user_omniauth_callback");

        // The old GET/GET placeholder is gone: no GET authorize row exists.
        assert!(
            omniauth
                .iter()
                .all(|spec| !(spec.method == "GET" && spec.action == "passthru"))
        );
    }

    #[test]
    fn test_omniauth_route_specs_prefix_override() {
        use crate::config::{DeviseConfig, DeviseConfigOverride};

        let mapping = omniauthable_mapping();

        // Default base: {full_path}/auth.
        let default_specs = mapping.omniauth_route_specs_for(&DeviseConfig::default());
        assert_eq!(
            default_specs[0].path, "/users/auth/{provider}",
            "default omniauth base is the mapping path plus /auth"
        );

        // omniauth_path_prefix override replaces the whole base (single
        // global prefix, Devise's set_omniauth_path_prefix! semantics).
        let global = DeviseConfig::default();
        let r#override = DeviseConfigOverride {
            omniauth_path_prefix: Some("/oauth".to_string()),
            ..DeviseConfigOverride::default()
        };
        let resolved = r#override.resolve(&global);
        let override_specs = mapping.omniauth_route_specs_for(&resolved);
        assert_eq!(override_specs[0].path, "/oauth/{provider}");
        assert_eq!(override_specs[1].path, "/oauth/{provider}/callback");
        assert_eq!(override_specs[2].path, "/oauth/{provider}/callback");

        // route_specs_for composes the same override into the full table:
        // the omniauth legs move, every other leg stays.
        let table = mapping.route_specs_for(&resolved);
        assert!(table.iter().any(|spec| spec.path == "/oauth/{provider}"));
        assert!(
            !table
                .iter()
                .any(|spec| spec.path == "/users/auth/{provider}")
        );
        assert!(table.iter().any(|spec| spec.path == "/users/sign_in"));
        // Prefix normalization: a slashless or doubled-slash prefix still
        // resolves to a clean leading-slash base.
        let r#override = DeviseConfigOverride {
            omniauth_path_prefix: Some("extra//oauth".to_string()),
            ..DeviseConfigOverride::default()
        };
        let resolved = r#override.resolve(&global);
        assert_eq!(mapping.omniauth_base(&resolved), "/extra/oauth");
    }

    #[test]
    fn test_omniauth_unknown_providers_never_appear_as_rows() {
        use crate::config::{DeviseConfig, DeviseConfigOverride};

        // The allowlist is REQUEST-time (framework handlers 404 unknown
        // providers with passthru parity); the table carries only the
        // generic {provider} capture, never per-provider rows.
        let global = DeviseConfig::default();
        let r#override = DeviseConfigOverride {
            omniauth_providers: Some(vec!["github".to_string(), "stub".to_string()]),
            ..DeviseConfigOverride::default()
        };
        let config = r#override.resolve(&global);
        assert_eq!(config.omniauth_providers.len(), 2);

        let mapping = omniauthable_mapping();
        for spec in mapping.route_specs_for(&config) {
            assert!(
                !spec.path.contains("github") && !spec.path.contains("stub"),
                "no per-provider row may appear in the shared table: {}",
                spec.path
            );
        }
    }

    #[test]
    fn test_omniauth_dynamic_segment_scope_path_rejected_at_registration() {
        let mut mapping = omniauthable_mapping();
        mapping.path = "{locale}/users".to_string();
        let err = mapping
            .validate_omniauth_paths()
            .expect_err("dynamic-segment scope path must be rejected");
        assert!(matches!(err, DeviseError::Config(_)));
        assert!(err.to_string().contains("dynamic segment"));

        // The actix-shaped dynamic segment is rejected identically.
        mapping.path = ":locale/users".to_string();
        assert!(mapping.validate_omniauth_paths().is_err());

        // Non-omniauthable mappings are exempt (Devise raises only inside
        // the omniauth route block).
        let mut plain = omniauthable_mapping();
        plain.modules = vec![Module::DatabaseAuthenticatable];
        plain.path = "{locale}/users".to_string();
        assert!(plain.validate_omniauth_paths().is_ok());

        // Plain scope paths pass.
        assert!(omniauthable_mapping().validate_omniauth_paths().is_ok());
    }

    #[test]
    fn test_route_specs_for_matches_route_specs_without_omniauthable() {
        use crate::config::DeviseConfig;

        // Without the omniauthable module the config-aware table is the
        // config-free table verbatim (identity, no filtering drift).
        let mut plain = omniauthable_mapping();
        plain.modules = vec![Module::DatabaseAuthenticatable, Module::Registerable];
        assert_eq!(
            plain.route_specs_for(&DeviseConfig::default()),
            plain.route_specs()
        );
    }

    #[test]
    fn test_omniauth_callback_path_substitutes_provider() {
        use crate::config::{DeviseConfig, DeviseConfigOverride};

        let mapping = omniauthable_mapping();
        assert_eq!(
            mapping.omniauth_callback_path(&DeviseConfig::default(), "stub"),
            "/users/auth/stub/callback"
        );

        // The path rides the config-resolved base, never a hand-built
        // string in the framework handlers.
        let global = DeviseConfig::default();
        let r#override = DeviseConfigOverride {
            omniauth_path_prefix: Some("/oauth".to_string()),
            ..DeviseConfigOverride::default()
        };
        let resolved = r#override.resolve(&global);
        assert_eq!(
            mapping.omniauth_callback_path(&resolved, "stub"),
            "/oauth/stub/callback"
        );
    }
}
