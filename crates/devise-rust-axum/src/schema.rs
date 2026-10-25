//! Axum startup gate — the framework-facing wrapper over
//! [`devise_rust::schema::check_fields`] (Devise's `check_fields!`).
//!
//! Applications call `assert_model_schema` next to their adapter wiring,
//! before the app serves traffic: a model whose Devise columns are missing
//! from the database fails loudly with Devise's own message instead of
//! surfacing later as an opaque write error inside a sign-in flow.

use devise_rust::adapter::OrmAdapter;
use devise_rust::config::DeviseConfig;
use devise_rust::error::DeviseError;
use devise_rust::scope::Mapping;

/// Devise's `check_fields!`, as an axum startup assertion.
///
/// # Errors
///
/// Returns [`DeviseError::MissingAttribute`] listing every missing column,
/// or propagates the adapter's catalog failure as [`DeviseError::Adapter`].
pub async fn assert_model_schema<A, M>(
    adapter: &A,
    mapping: &Mapping,
    config: &DeviseConfig,
) -> Result<(), DeviseError>
where
    A: OrmAdapter<M> + Send + Sync,
    M: Send + Sync + 'static,
{
    devise_rust::schema::check_fields(adapter, mapping, config).await
}
