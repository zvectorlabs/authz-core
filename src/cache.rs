//! Generic cache abstraction for authz resolution caches.
//!
//! Provides `AuthzCache<V>` trait and a `NoopCache` implementation that never
//! stores entries.  The trait is intentionally minimal so that `authz-core`
//! stays dependency-light — concrete backends (e.g. moka) live in downstream
//! crates.

use std::sync::Arc;

/// Cache performance metrics.
pub trait CacheMetrics: Send + Sync {
    /// Total number of cache hits.
    fn hits(&self) -> u64;

    /// Total number of cache misses.
    fn misses(&self) -> u64;

    /// Hit rate as a percentage (0.0 to 100.0).
    fn hit_rate(&self) -> f64 {
        let total = self.hits() + self.misses();
        if total == 0 {
            0.0
        } else {
            (self.hits() as f64 / total as f64) * 100.0
        }
    }
}

/// Generic cache abstraction for authz resolution caches.
///
/// Implementations must be `Send + Sync` so they can be shared across threads
/// and stored behind `Arc`.
pub trait AuthzCache<V: Clone + Send + Sync>: Send + Sync {
    /// Look up a cached value by key.  Returns `None` on miss.
    fn get(&self, key: &str) -> Option<V>;

    /// Insert a value into the cache.
    fn insert(&self, key: &str, value: V);

    /// Remove a single entry by key.
    fn invalidate(&self, key: &str);

    /// Remove all entries from the cache.
    fn invalidate_all(&self);

    /// Get cache performance metrics.
    fn metrics(&self) -> Box<dyn CacheMetrics>;
}

/// A cache that never stores anything — every `get` returns `None`.
///
/// Used as the default when caching is disabled (TTL = 0) and in unit tests.
pub struct NoopCache;

/// Metrics for NoopCache (always returns zeros).
struct NoopMetrics;

impl CacheMetrics for NoopMetrics {
    fn hits(&self) -> u64 {
        0
    }

    fn misses(&self) -> u64 {
        0
    }
}

impl<V: Clone + Send + Sync> AuthzCache<V> for NoopCache {
    fn get(&self, _key: &str) -> Option<V> {
        None
    }

    fn insert(&self, _key: &str, _value: V) {}

    fn invalidate(&self, _key: &str) {}

    fn invalidate_all(&self) {}

    fn metrics(&self) -> Box<dyn CacheMetrics> {
        Box::new(NoopMetrics)
    }
}

/// Convenience helper: create a `NoopCache` wrapped in an `Arc`.
pub fn noop_cache<V: Clone + Send + Sync + 'static>() -> Arc<dyn AuthzCache<V>> {
    Arc::new(NoopCache)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_cache_always_misses() {
        let cache: Arc<dyn AuthzCache<String>> = noop_cache();
        cache.insert("key", "value".to_string());
        assert_eq!(cache.get("key"), None);
    }

    #[test]
    fn noop_cache_invalidate_is_safe() {
        let cache: Arc<dyn AuthzCache<i32>> = noop_cache();
        cache.invalidate_all(); // should not panic
    }
}
