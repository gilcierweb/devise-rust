//! Route consumption - framework-facing views over `Mapping::route_specs`
//!
//! The canonical table lives in [`Mapping::route_specs`](crate::scope::Mapping::route_specs)
//! (`scope.rs`); this module adds the thin consumption layer bridges need:
//! scope route tables plus guard descriptors for `authenticate(scope)`,
//! `authenticated(scope)`, `unauthenticated(scope)`, and `devise_scope(scope)`
//! router helpers. Core never touches framework router types.

use crate::scope::{Mapping, RouteSpec};

/// Route table for one scope mapping.
///
/// Delegates to [`Mapping::route_specs`](crate::scope::Mapping::route_specs);
/// kept as a free function so bridges can pass mappings without importing
/// the whole `scope` surface.
#[must_use]
pub fn devise_scope_routes(mapping: &Mapping) -> Vec<RouteSpec> {
    mapping.route_specs()
}

/// Router guard kind, mirroring the `authenticate` / `authenticated` /
/// `unauthenticated` route constraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardMode {
    /// Run the strategy chain; render failure otherwise.
    Authenticate,
    /// Allow only signed-in requests.
    Authenticated,
    /// Allow only signed-out requests.
    Unauthenticated,
}

/// Data descriptor for a scope guard a bridge registers on its router.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeGuard {
    /// Scope the guard applies to.
    pub scope: String,
    /// Guard behavior.
    pub mode: GuardMode,
}

impl ScopeGuard {
    /// Guard running authentication for `scope`.
    #[must_use]
    pub fn authenticate(scope: impl Into<String>) -> Self {
        Self {
            scope: scope.into(),
            mode: GuardMode::Authenticate,
        }
    }

    /// Guard allowing only signed-in `scope` requests.
    #[must_use]
    pub fn authenticated(scope: impl Into<String>) -> Self {
        Self {
            scope: scope.into(),
            mode: GuardMode::Authenticated,
        }
    }

    /// Guard allowing only signed-out `scope` requests.
    #[must_use]
    pub fn unauthenticated(scope: impl Into<String>) -> Self {
        Self {
            scope: scope.into(),
            mode: GuardMode::Unauthenticated,
        }
    }
}

/// Data descriptor for a `devise_scope` mount point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeMount {
    /// Scope whose mapping applies under this path.
    pub scope: String,
    /// Mount path (the mapping's full path).
    pub path: String,
}

impl ScopeMount {
    /// Mount descriptor derived from a mapping.
    #[must_use]
    pub fn new(mapping: &Mapping) -> Self {
        Self {
            scope: mapping.name.clone(),
            path: mapping.full_path(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::{Module, PathNames, ScopeRegistry, SignOutVia};
    use std::collections::HashMap;

    fn routes_mapping() -> Mapping {
        Mapping {
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
        }
    }

    #[test]
    fn test_devise_scope_routes() {
        let mapping = routes_mapping();
        let specs = devise_scope_routes(&mapping);
        assert_eq!(specs.len(), mapping.route_specs().len());
        assert_eq!(specs.len(), 10);

        let mut registry = ScopeRegistry::new();
        registry.register(mapping);
        assert_eq!(registry.all_route_specs().len(), 10);
    }

    #[test]
    fn test_scope_guards() {
        let guard = ScopeGuard::authenticate("user");
        assert_eq!(guard.scope, "user");
        assert_eq!(guard.mode, GuardMode::Authenticate);

        let guard = ScopeGuard::authenticated("admin");
        assert_eq!(guard.mode, GuardMode::Authenticated);

        let guard = ScopeGuard::unauthenticated("user");
        assert_eq!(guard.mode, GuardMode::Unauthenticated);
    }

    #[test]
    fn test_scope_mount() {
        let mapping = routes_mapping();
        let mount = ScopeMount::new(&mapping);
        assert_eq!(mount.scope, "user");
        assert_eq!(mount.path, "/users");
    }
}
