//! Model modules - the Devise module layout, one file per module, in the
//! `devise/*modules` super-chain order the framework macro applies.
//!
//! Reading order follows `devise/lib/devise/models/`: the
//! [`Authenticatable`] base first, then [`DatabaseAuthenticatable`],
//! [`Registerable`], [`Recoverable`], and [`Validatable`]. Every public path that
//! resolved through `devise_rust::model::` before the split resolves
//! through this module unchanged (the glob re-exports below keep the
//! public API source-compatible).

pub mod authenticatable;
pub mod database_authenticatable;
pub mod recoverable;
pub mod registerable;
pub mod validatable;

#[cfg(test)]
mod test_support;

pub use authenticatable::*;
pub use database_authenticatable::*;
pub use recoverable::*;
pub use registerable::*;
pub use validatable::*;
