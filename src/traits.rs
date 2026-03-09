//! Core datastore traits — TupleReader, TupleWriter, PolicyReader, PolicyWriter.

use async_trait::async_trait;

use crate::error::AuthzError;

/// A relationship tuple: object#relation@subject (optionally with condition).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tuple {
    pub object_type: String,
    pub object_id: String,
    pub relation: String,
    pub subject_type: String,
    pub subject_id: String,
    pub condition: Option<String>,
}

/// Filter for tuple queries. All fields are optional.
#[derive(Debug, Clone, Default)]
pub struct TupleFilter {
    pub object_type: Option<String>,
    pub object_id: Option<String>,
    pub relation: Option<String>,
    pub subject_type: Option<String>,
    pub subject_id: Option<String>,
}

/// Authorization policy (DSL definition).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationPolicy {
    pub id: String,
    pub definition: String,
}

/// Pagination for list operations.
#[derive(Debug, Clone, Default)]
pub struct Pagination {
    pub page_size: usize,
    pub continuation_token: Option<String>,
}

/// Reads tuples from the datastore.
#[async_trait]
pub trait TupleReader: Send + Sync {
    async fn read_tuples(&self, filter: &TupleFilter) -> Result<Vec<Tuple>, AuthzError>;
    async fn read_user_tuple(
        &self,
        object_type: &str,
        object_id: &str,
        relation: &str,
        subject_type: &str,
        subject_id: &str,
    ) -> Result<Option<Tuple>, AuthzError>;
    async fn read_userset_tuples(
        &self,
        object_type: &str,
        object_id: &str,
        relation: &str,
    ) -> Result<Vec<Tuple>, AuthzError>;
    async fn read_starting_with_user(
        &self,
        subject_type: &str,
        subject_id: &str,
    ) -> Result<Vec<Tuple>, AuthzError>;

    /// Batch read: check if any of the given relations match for a user.
    /// Returns the first matching tuple, or None if no match found.
    async fn read_user_tuple_batch(
        &self,
        object_type: &str,
        object_id: &str,
        relations: &[String],
        subject_type: &str,
        subject_id: &str,
    ) -> Result<Option<Tuple>, AuthzError>;
}

/// Writes tuples to the datastore.
#[async_trait]
pub trait TupleWriter: Send + Sync {
    async fn write_tuples(&self, writes: &[Tuple], deletes: &[Tuple])
    -> Result<String, AuthzError>;
}

/// Reads authorization policies.
#[async_trait]
pub trait PolicyReader: Send + Sync {
    async fn read_authorization_policy(
        &self,
        id: &str,
    ) -> Result<Option<AuthorizationPolicy>, AuthzError>;
    async fn read_latest_authorization_policy(
        &self,
    ) -> Result<Option<AuthorizationPolicy>, AuthzError>;
    async fn list_authorization_policies(
        &self,
        pagination: &Pagination,
    ) -> Result<Vec<AuthorizationPolicy>, AuthzError>;
}

/// Writes authorization policies.
#[async_trait]
pub trait PolicyWriter: Send + Sync {
    async fn write_authorization_policy(
        &self,
        policy: &AuthorizationPolicy,
    ) -> Result<String, AuthzError>;
}

/// Reads revision information from the datastore.
#[async_trait]
pub trait RevisionReader: Send + Sync {
    /// Read the latest revision ID from the datastore.
    /// Returns "0" if no revisions exist yet (bootstrap case).
    async fn read_latest_revision(&self) -> Result<String, AuthzError>;
}
