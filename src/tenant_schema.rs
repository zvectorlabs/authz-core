//! ChangelogReader trait for Watch API.

use async_trait::async_trait;

use crate::error::AuthzError;

/// A changelog entry for the Watch API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangelogEntry {
    pub object_type: String,
    pub object_id: String,
    pub relation: String,
    pub subject_type: String,
    pub subject_id: String,
    pub operation: String,
    pub ulid: String,
}

/// Reads changelog entries for Watch API.
#[async_trait]
pub trait ChangelogReader: Send + Sync {
    async fn read_changes(
        &self,
        object_type: &str,
        after_ulid: Option<&str>,
        page_size: usize,
    ) -> Result<Vec<ChangelogEntry>, AuthzError>;
}
