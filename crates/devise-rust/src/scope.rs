//! Scope & routing - Module enum, Mapping, `ScopeRegistry`, `RouteSpec`
//!
//! Drives route generation, failure-app scope resolution, and module ordering.
//! Canonical module order from `devise/lib/devise/modules.rb` preserved.

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
        for (method, action, route_name) in [
            ("GET", "new", format!("new_{name}")),
            ("POST", "create", name.clone()),
            ("GET", "edit", format!("edit_{name}")),
            ("PATCH", "update", name.clone()),
            ("PUT", "update", name.clone()),
        ] {
            specs.push(RouteSpec::new(password.clone(), method, action, route_name));
        }
    }

    fn push_confirmation_routes(&self, specs: &mut Vec<RouteSpec>) {
        let confirmation = self.scoped(&self.path_names.confirmation);
        let name = self.named("confirmation");
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
        specs.push(RouteSpec::new(unlock.clone(), "GET", "show", name.clone()));
        specs.push(RouteSpec::new(unlock, "POST", "create", name));
    }

    fn push_omniauth_routes(&self, specs: &mut Vec<RouteSpec>) {
        let base = self.full_path();
        specs.push(RouteSpec::new(
            format!("{base}/auth/{{provider}}"),
            "GET",
            "passthru",
            format!("{}_omniauth_authorize", self.singular),
        ));
        specs.push(RouteSpec::new(
            format!("{base}/auth/{{provider}}/callback"),
            "GET",
            "callback",
            format!("{}_omniauth_callback", self.singular),
        ));
    }
}

/// Route specification - data structure for framework route registration
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}
