//! Dispatcher trait and LocalDispatcher stub.

use async_trait::async_trait;

use crate::error::AuthzError;
use crate::resolver::{CheckResult, ResolveCheckRequest};

/// Dispatches check, list_objects, and list_subjects requests.
#[async_trait]
pub trait Dispatcher: Send + Sync {
    async fn dispatch_check(&self, request: ResolveCheckRequest)
    -> Result<CheckResult, AuthzError>;
    async fn dispatch_list_objects(
        &self,
        _subject_type: &str,
        _subject_id: &str,
        _relation: &str,
        _object_type: &str,
    ) -> Result<Vec<String>, AuthzError>;
    async fn dispatch_list_subjects(
        &self,
        _object_type: &str,
        _object_id: &str,
        _relation: &str,
        _subject_type: &str,
    ) -> Result<Vec<String>, AuthzError>;
}

/// Local dispatcher that calls resolver directly.
pub struct LocalDispatcher<R> {
    resolver: R,
}

impl<R> LocalDispatcher<R> {
    pub fn new(resolver: R) -> Self {
        Self { resolver }
    }
}

#[async_trait]
impl<R> Dispatcher for LocalDispatcher<R>
where
    R: crate::resolver::CheckResolver + Send + Sync,
{
    async fn dispatch_check(
        &self,
        request: ResolveCheckRequest,
    ) -> Result<CheckResult, AuthzError> {
        self.resolver.resolve_check(request).await
    }

    async fn dispatch_list_objects(
        &self,
        _subject_type: &str,
        _subject_id: &str,
        _relation: &str,
        _object_type: &str,
    ) -> Result<Vec<String>, AuthzError> {
        Ok(vec![])
    }

    async fn dispatch_list_subjects(
        &self,
        _object_type: &str,
        _object_id: &str,
        _relation: &str,
        _subject_type: &str,
    ) -> Result<Vec<String>, AuthzError> {
        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolver::{CheckResolver, CheckResult, ResolveCheckRequest};

    struct StubResolver;
    #[async_trait::async_trait]
    impl CheckResolver for StubResolver {
        async fn resolve_check(&self, _: ResolveCheckRequest) -> Result<CheckResult, AuthzError> {
            Ok(CheckResult::Allowed)
        }
    }

    #[tokio::test]
    async fn local_dispatcher_dispatch_check() {
        let d = LocalDispatcher::new(StubResolver);
        let req = ResolveCheckRequest::new(
            "doc".into(),
            "1".into(),
            "viewer".into(),
            "user".into(),
            "alice".into(),
        );
        let r = d.dispatch_check(req).await.unwrap();
        assert_eq!(r, CheckResult::Allowed);
    }

    struct DeniedResolver;
    #[async_trait::async_trait]
    impl CheckResolver for DeniedResolver {
        async fn resolve_check(&self, _: ResolveCheckRequest) -> Result<CheckResult, AuthzError> {
            Ok(CheckResult::Denied)
        }
    }

    #[tokio::test]
    async fn test_local_dispatcher_denied() {
        let d = LocalDispatcher::new(DeniedResolver);
        let req = ResolveCheckRequest::new(
            "doc".into(),
            "1".into(),
            "viewer".into(),
            "user".into(),
            "bob".into(),
        );
        let r = d.dispatch_check(req).await.unwrap();
        assert_eq!(r, CheckResult::Denied);
    }

    #[tokio::test]
    async fn test_local_dispatcher_list_objects_stub() {
        let d = LocalDispatcher::new(StubResolver);
        let result = d
            .dispatch_list_objects("user", "alice", "viewer", "document")
            .await
            .unwrap();
        assert_eq!(result, Vec::<String>::new());
    }
}
