//! CheckResolver trait and CheckResult enum.

use crate::error::AuthzError;
use crate::traits::Tuple;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

/// Result of a check resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckResult {
    Allowed,
    Denied,
    ConditionRequired(Vec<String>),
}

/// Strategy for recursive resolution algorithms.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum RecursionStrategy {
    #[default]
    DepthFirst, // Fast, memory-efficient, good for shallow hierarchies
    BreadthFirst, // Optimal paths, memory-intensive, good for deep hierarchies
}

/// Configuration for recursion behavior.
#[derive(Debug, Clone)]
pub struct RecursionConfig {
    pub strategy: RecursionStrategy,
    pub max_depth: u32,
    pub enable_cycle_detection: bool,
}

impl Default for RecursionConfig {
    fn default() -> Self {
        Self {
            strategy: RecursionStrategy::DepthFirst,
            max_depth: 25,
            enable_cycle_detection: true,
        }
    }
}

impl RecursionConfig {
    /// Create a config for depth-first strategy (default).
    pub fn depth_first() -> Self {
        Self::default()
    }

    /// Create a config for breadth-first strategy.
    pub fn breadth_first() -> Self {
        Self {
            strategy: RecursionStrategy::BreadthFirst,
            max_depth: 50,
            enable_cycle_detection: true,
        }
    }

    /// Set maximum recursion depth.
    pub fn max_depth(mut self, depth: u32) -> Self {
        self.max_depth = depth;
        self
    }

    /// Enable or disable cycle detection.
    pub fn cycle_detection(mut self, enabled: bool) -> Self {
        self.enable_cycle_detection = enabled;
        self
    }

    /// Set the recursion strategy.
    pub fn strategy(mut self, strategy: RecursionStrategy) -> Self {
        self.strategy = strategy;
        self
    }
}

/// Consistency mode for check requests.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Consistency {
    #[default]
    FullyConsistent, // Latest data
    AtLeastAsFresh(String), // At revision token
    MinimizeLatency,        // Quantized revision
}

/// Shared counters for tracking resolver performance across recursive dispatches.
///
/// Uses `Arc<AtomicU32>` so that child requests created via `child_request()`
/// share the same counters and increments are visible to the caller.
#[derive(Debug, Clone)]
pub struct ResolverMetadata {
    pub dispatch_count: Arc<AtomicU32>,
    pub datastore_queries: Arc<AtomicU32>,
    pub cache_hits: Arc<AtomicU32>,
    pub max_depth_reached: Arc<AtomicU32>,
}

impl Default for ResolverMetadata {
    fn default() -> Self {
        Self {
            dispatch_count: Arc::new(AtomicU32::new(0)),
            datastore_queries: Arc::new(AtomicU32::new(0)),
            cache_hits: Arc::new(AtomicU32::new(0)),
            max_depth_reached: Arc::new(AtomicU32::new(0)),
        }
    }
}

impl ResolverMetadata {
    /// Read the current dispatch count.
    pub fn get_dispatch_count(&self) -> u32 {
        self.dispatch_count.load(Ordering::Relaxed)
    }

    /// Read the current datastore query count.
    pub fn get_datastore_queries(&self) -> u32 {
        self.datastore_queries.load(Ordering::Relaxed)
    }

    /// Read the current cache hit count.
    pub fn get_cache_hits(&self) -> u32 {
        self.cache_hits.load(Ordering::Relaxed)
    }

    /// Read the maximum resolution depth reached.
    pub fn get_max_depth_reached(&self) -> u32 {
        self.max_depth_reached.load(Ordering::Relaxed)
    }
}

/// Request to resolve a check.
#[derive(Debug, Clone)]
pub struct ResolveCheckRequest {
    pub object_type: String,
    pub object_id: String,
    pub relation: String,
    pub subject_type: String,
    pub subject_id: String,
    pub contextual_tuples: Vec<Tuple>,
    pub depth_remaining: u32,
    pub consistency: Consistency,
    pub metadata: ResolverMetadata,
    pub recursion_config: RecursionConfig,
    /// Track visited (object_type, object_id, relation) tuples for cycle detection
    pub visited: Vec<(String, String, String)>,
    /// Context values for CEL condition evaluation (key → JSON-compatible value).
    pub context: HashMap<String, serde_json::Value>,
    /// Revision at which this check is evaluated. Included in cache keys so that
    /// stale entries from older revisions are never served. Empty string means
    /// "latest/unknown" (cache keys still work but won't benefit from revision-based
    /// natural expiry). This is typically a quantized ULID or timestamp.
    pub at_revision: String,
}

impl ResolveCheckRequest {
    /// Create a new check request with default values.
    pub fn new(
        object_type: String,
        object_id: String,
        relation: String,
        subject_type: String,
        subject_id: String,
    ) -> Self {
        Self {
            object_type,
            object_id,
            relation,
            subject_type,
            subject_id,
            contextual_tuples: Vec::new(),
            depth_remaining: 25, // Default max depth
            consistency: Consistency::default(),
            metadata: ResolverMetadata::default(),
            recursion_config: RecursionConfig::default(),
            visited: Vec::new(),
            context: HashMap::new(),
            at_revision: String::new(),
        }
    }

    /// Create a new check request with custom recursion config.
    pub fn with_config(
        object_type: String,
        object_id: String,
        relation: String,
        subject_type: String,
        subject_id: String,
        recursion_config: RecursionConfig,
    ) -> Self {
        Self {
            object_type,
            object_id,
            relation,
            subject_type,
            subject_id,
            contextual_tuples: Vec::new(),
            depth_remaining: recursion_config.max_depth,
            consistency: Consistency::default(),
            metadata: ResolverMetadata::default(),
            recursion_config,
            visited: Vec::new(),
            context: HashMap::new(),
            at_revision: String::new(),
        }
    }

    /// Create a child request with decremented depth.
    ///
    /// The child shares the same `ResolverMetadata` atomic counters so that
    /// increments in recursive dispatches are visible to the top-level caller.
    pub fn child_request(
        &self,
        object_type: String,
        object_id: String,
        relation: String,
        subject_type: String,
        subject_id: String,
    ) -> Self {
        Self {
            object_type,
            object_id,
            relation,
            subject_type,
            subject_id,
            contextual_tuples: self.contextual_tuples.clone(),
            depth_remaining: self.depth_remaining.saturating_sub(1),
            consistency: self.consistency.clone(),
            metadata: self.metadata.clone(), // Arc::clone — shares counters
            recursion_config: self.recursion_config.clone(),
            visited: self.visited.clone(),
            context: self.context.clone(),
            at_revision: self.at_revision.clone(),
        }
    }
}

/// Node in the expand tree for debugging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpandNode {
    pub object_type: String,
    pub object_id: String,
    pub relation: String,
    pub result: CheckResult,
    pub children: Vec<ExpandNode>,
}

/// Resolves check requests by walking the authorization model.
#[async_trait]
pub trait CheckResolver: Send + Sync {
    async fn resolve_check(&self, request: ResolveCheckRequest) -> Result<CheckResult, AuthzError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_result_variants() {
        let _ = CheckResult::Allowed;
        let _ = CheckResult::Denied;
        let _ = CheckResult::ConditionRequired(vec!["param".into()]);
    }
}
