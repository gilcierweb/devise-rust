//! Test utilities - available with `test-utils` feature

use crate::adapter::memory::MemoryAdapter;
use crate::config::DeviseConfig;

/// Create a test `DeviseConfig` with sensible defaults for testing
#[must_use]
pub fn test_config() -> DeviseConfig {
    DeviseConfig {
        secret_key: "test-secret-key-for-testing-only".to_string(),
        stretches: 4, // Lower cost for faster tests
        ..DeviseConfig::default()
    }
}

/// Create an in-memory adapter for testing
#[must_use]
pub fn test_adapter<M: Send + Sync + Clone + 'static>() -> MemoryAdapter<M> {
    MemoryAdapter::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_test_config() {
        let config = test_config();
        assert_eq!(config.stretches, 4);
        assert!(!config.secret_key.is_empty());
    }
}
