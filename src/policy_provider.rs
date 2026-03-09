//! PolicyProvider trait — abstracts authorization policy (TypeSystem) loading.
//!
//! `CoreResolver` accepts any `PolicyProvider` so that:
//!   - `pgauthz` / `sqliteauthz` use `StaticPolicyProvider` (one global policy, loaded once)
//!   - `authz-saas` implements a dynamic provider that resolves per-tenant policies

use std::sync::Arc;

use async_trait::async_trait;

use crate::error::AuthzError;
use crate::type_system::TypeSystem;

/// Provides the active authorization policy (as a compiled `TypeSystem`) to the resolver.
///
/// Implementations decide how the policy is loaded, cached, and scoped.
/// The `CoreResolver` never interprets *why* a particular `TypeSystem` is returned —
/// tenant routing, model versioning, and caching are entirely the provider's concern.
#[async_trait]
pub trait PolicyProvider: Send + Sync {
    async fn get_policy(&self) -> Result<Arc<TypeSystem>, AuthzError>;
}

/// A `PolicyProvider` backed by a single pre-loaded `TypeSystem`.
///
/// Used by single-tenant deployments (`pgauthz`, `sqliteauthz`) where the policy is
/// loaded once (or cached externally) before the resolver is constructed.
#[derive(Clone)]
pub struct StaticPolicyProvider(Arc<TypeSystem>);

impl StaticPolicyProvider {
    /// Create from an owned `TypeSystem`.
    pub fn new(type_system: TypeSystem) -> Self {
        Self(Arc::new(type_system))
    }

    /// Create from an already-shared `Arc<TypeSystem>` (e.g. from a cache layer).
    pub fn from_arc(type_system: Arc<TypeSystem>) -> Self {
        Self(type_system)
    }
}

#[async_trait]
impl PolicyProvider for StaticPolicyProvider {
    async fn get_policy(&self) -> Result<Arc<TypeSystem>, AuthzError> {
        Ok(self.0.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model_parser::parse_dsl;

    #[tokio::test]
    async fn static_provider_returns_type_system() {
        let model = parse_dsl("type user {}").unwrap();
        let ts = TypeSystem::new(model);
        let provider = StaticPolicyProvider::new(ts);
        let result = provider.get_policy().await.unwrap();
        assert!(result.get_type("user").is_some());
    }

    #[tokio::test]
    async fn from_arc_returns_same_type_system() {
        let model = parse_dsl("type document { relations define viewer: [user] }").unwrap();
        let ts = Arc::new(TypeSystem::new(model));
        let provider = StaticPolicyProvider::from_arc(ts.clone());
        let result = provider.get_policy().await.unwrap();
        assert!(result.get_relation("document", "viewer").is_some());
    }
}
