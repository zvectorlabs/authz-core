//! Structured error types for authz-core.

use thiserror::Error;

/// Core error type for all authz operations.
#[derive(Error, Debug, Clone)]
pub enum AuthzError {
    // --- Validation (input) ---
    #[error("validation: {field} — {message}")]
    Validation { field: String, message: String },

    // --- Model errors ---
    #[error("model parse error: {0}")]
    ModelParse(String),

    #[error("model validation: {0}")]
    ModelValidation(String),

    #[error("no authorization model found")]
    ModelNotFound,

    // --- Relationship errors ---
    #[error("relationship validation: {0}")]
    RelationshipValidation(String),

    // --- Resolution errors ---
    #[error("relation '{relation}' not found on type '{object_type}'")]
    RelationNotFound {
        object_type: String,
        relation: String,
    },

    #[error("max recursion depth exceeded")]
    MaxDepthExceeded,

    #[error("resolution failed: {0}")]
    ResolutionError(String),

    // --- Datastore / infrastructure ---
    #[error("datastore error: {0}")]
    Datastore(String),

    #[error("cache lock poisoned")]
    CachePoisoned,

    // --- Internal / catch-all ---
    #[error("internal error: {0}")]
    Internal(String),
}
