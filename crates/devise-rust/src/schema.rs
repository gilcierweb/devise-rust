//! Schema checking — the port of Devise's `check_fields!` /
//! `Devise::Models::MissingAttribute`.
//!
//! Devise fails loudly at model-load time when a model does not respond to
//! each selected module's `required_fields`
//! (`devise/lib/devise/models.rb:53-69`):
//!
//! ```ruby
//! def self.check_fields!(klass)
//!   failed_attributes = []
//!   instance = klass.new
//!   klass.devise_modules.each do |mod|
//!     constant = const_get(mod.to_s.classify)
//!     constant.required_fields(klass).each do |field|
//!       failed_attributes << field unless instance.respond_to?(field)
//!     end
//!   end
//!   fail Devise::Models::MissingAttribute.new(failed_attributes) if failed_attributes.any?
//! end
//! ```
//!
//! In Rust the "model responds to the accessor" half is enforced at COMPILE
//! time (the module traits declare the accessors), so the port's runtime
//! check covers the remaining failure mode: a model whose columns are
//! missing from the DATABASE. Without it, a stale schema surfaces as an
//! opaque write error deep inside a sign-in flow; with it, the application
//! fails at startup with Devise's own message:
//!
//! ```text
//! The following attribute(s) is (are) missing on your model: confirmation_token, confirmed_at
//! ```
//!
//! The probe delegates to [`OrmAdapter::column_exists`], whose permissive
//! default keeps the in-memory oracle and the experimental MySQL arm
//! unchanged; the SQL backends answer from their catalog.

use crate::adapter::OrmAdapter;
use crate::config::DeviseConfig;
use crate::error::DeviseError;
use crate::scope::{Mapping, Module};

/// Every column the mapping's modules require, in Devise's
/// `required_fields` order, plus the configured authentication keys.
///
/// Mirrors the per-module `required_fields` tables Devise consults inside
/// `check_fields!` (`database_authenticatable`, `recoverable`,
/// `confirmable`, `lockable`, `rememberable`, `trackable`, `omniauthable`).
#[must_use]
pub fn required_columns(mapping: &Mapping, config: &DeviseConfig) -> Vec<String> {
    let mut columns: Vec<String> = Vec::new();
    let mut push = |name: &str| {
        if !columns.iter().any(|c| c == name) {
            columns.push(name.to_string());
        }
    };

    for module in &mapping.effective_modules() {
        match module {
            Module::DatabaseAuthenticatable => {
                push("encrypted_password");
                for key in &config.authentication_keys {
                    push(key);
                }
            }
            Module::Recoverable => {
                push("reset_password_token");
                push("reset_password_sent_at");
            }
            Module::Confirmable => {
                for field in crate::confirmable::required_fields(config.reconfirmable) {
                    push(field);
                }
            }
            Module::Lockable => {
                for field in crate::lockable::required_fields(config) {
                    push(field);
                }
            }
            Module::Rememberable => {
                // Devise's `required_fields` names ONLY `remember_created_at`:
                // `remember_token` is the optional DB-token column (models
                // without it fall back to the authenticatable salt), so it is
                // NOT required here.
                for field in crate::rememberable::required_fields() {
                    push(field);
                }
            }
            Module::Trackable => {
                for field in crate::trackable::required_fields() {
                    push(field);
                }
            }
            Module::Omniauthable => {
                for field in crate::omniauthable::required_fields() {
                    push(field);
                }
            }
            // `validatable` and `registerable` add no columns of their own;
            // `timeoutable` is session-based.
            Module::Validatable | Module::Registerable | Module::Timeoutable => {}
        }
    }
    columns
}

/// Devise's `check_fields!`: probe the adapter for every required column
/// and report the missing ones as a [`DeviseError::MissingAttribute`].
///
/// Call this once at application startup (after wiring the adapter, before
/// serving traffic). Applications call it directly; the framework
/// integrations do the same inside their route-registration entry points
/// via `assert_model_schema`.
///
/// == Examples
///
/// ```
/// use devise_rust::schema::check_fields;
/// # use devise_rust::adapter::memory::MemoryAdapter;
/// # use devise_rust::config::DeviseConfig;
/// # use devise_rust::scope::{Mapping, Module, PathNames, SignOutVia};
/// # use std::collections::HashMap;
/// # let mapping = Mapping {
/// #     name: "user".to_string(),
/// #     class_name: "User".to_string(),
/// #     path: "users".to_string(),
/// #     path_prefix: None,
/// #     singular: "user".to_string(),
/// #     path_names: PathNames::default(),
/// #     controllers: HashMap::new(),
/// #     modules: vec![Module::DatabaseAuthenticatable],
/// #     only: vec![],
/// #     skip: vec![],
/// #     constraints: HashMap::new(),
/// #     defaults: HashMap::new(),
/// #     format: None,
/// #     router_name: None,
/// #     sign_out_via: SignOutVia::Delete,
/// #     failure_app: None,
/// # };
/// #[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize, PartialEq)]
/// struct User { id: i64, email: String, encrypted_password: String }
///
/// let rt = tokio::runtime::Builder::new_current_thread()
///     .build()
///     .expect("test runtime builds");
/// rt.block_on(async {
///     let adapter = MemoryAdapter::<User>::new();
///     // The in-memory oracle has no reachable schema, so the permissive
///     // default answers every probe — no false startup failures.
///     check_fields(&adapter, &mapping, &DeviseConfig::default())
///         .await
///         .expect("in-memory adapter passes");
/// });
/// ```
///
/// # Errors
///
/// Returns [`DeviseError::MissingAttribute`] listing every missing column
/// (Devise's exact message), or propagates the adapter's catalog failure as
/// [`DeviseError::Adapter`].
pub async fn check_fields<A, M>(
    adapter: &A,
    mapping: &Mapping,
    config: &DeviseConfig,
) -> Result<(), DeviseError>
where
    A: OrmAdapter<M> + Send + Sync,
    M: Send + Sync + 'static,
{
    let mut missing = Vec::new();
    for column in required_columns(mapping, config) {
        if !adapter.column_exists(&column).await? {
            missing.push(column);
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(DeviseError::MissingAttribute(missing.join(", ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::PathNames;

    fn full_mapping() -> Mapping {
        let mut mapping = Mapping {
            name: "user".to_string(),
            class_name: "User".to_string(),
            path: "users".to_string(),
            path_prefix: None,
            singular: "user".to_string(),
            path_names: PathNames::default(),
            controllers: std::collections::HashMap::new(),
            modules: vec![
                Module::DatabaseAuthenticatable,
                Module::Recoverable,
                Module::Confirmable,
                Module::Lockable,
                Module::Rememberable,
                Module::Trackable,
                Module::Omniauthable,
            ],
            only: vec![],
            skip: vec![],
            constraints: std::collections::HashMap::new(),
            defaults: std::collections::HashMap::new(),
            format: None,
            router_name: None,
            sign_out_via: crate::scope::SignOutVia::Delete,
            failure_app: None,
        };
        mapping.modules.sort();
        mapping
    }

    #[test]
    fn required_columns_covers_every_module_table() {
        let config = DeviseConfig::default();
        let columns = required_columns(&full_mapping(), &config);
        for expected in [
            "encrypted_password",
            "email",
            "reset_password_token",
            "reset_password_sent_at",
            "confirmation_token",
            "confirmed_at",
            "confirmation_sent_at",
            "unconfirmed_email",
            "failed_attempts",
            "locked_at",
            "unlock_token",
            "remember_created_at",
            "sign_in_count",
            "current_sign_in_at",
            "last_sign_in_at",
            "current_sign_in_ip",
            "last_sign_in_ip",
            "provider",
            "uid",
        ] {
            assert!(
                columns.iter().any(|c| c == expected),
                "missing required column: {expected}"
            );
        }
        // `remember_token` is optional in Devise (`required_fields` names
        // only `remember_created_at`), so it must NOT be demanded.
        assert!(
            !columns.iter().any(|c| c == "remember_token"),
            "remember_token is the optional DB-token column"
        );

        // No duplicates.
        let mut sorted = columns.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), columns.len(), "duplicate columns reported");
    }

    /// A sub-set mapping only demands its own modules' columns (the
    /// `skip`/`only` filtering Devise's `devise_modules` applies).
    #[test]
    fn required_columns_respects_only_and_skip() {
        let config = DeviseConfig::default();
        let mut mapping = full_mapping();
        mapping.only = vec![Module::DatabaseAuthenticatable, Module::Recoverable];
        let columns = required_columns(&mapping, &config);
        assert!(columns.iter().any(|c| c == "encrypted_password"));
        assert!(columns.iter().any(|c| c == "reset_password_token"));
        assert!(!columns.iter().any(|c| c == "confirmation_token"));
    }
}
