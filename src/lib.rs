//! `authz-core` — Zanzibar-style Fine-Grained Authorization engine.
//!
//! This crate is the database- and transport-agnostic core of an authorization system.
//! It provides everything needed to define, parse, and evaluate an authorization model
//! without depending on any specific datastore or runtime.
//!
//! # Overview
//!
//! The main workflow:
//!
//! 1. **Write a model** in the built-in DSL (OpenFGA-inspired syntax).
//! 2. **Parse** it with [`model_parser::parse_dsl`] into a [`model_ast::ModelFile`].
//! 3. **Build** a [`type_system::TypeSystem`] from the parsed model.
//! 4. **Implement** the [`traits::TupleReader`] trait for your datastore.
//! 5. **Construct** a [`core_resolver::CoreResolver`] and call
//!    [`resolver::CheckResolver::resolve_check`] to evaluate permissions.
//!
//! # Example
//!
//! ```rust,no_run
//! use authz_core::model_parser::parse_dsl;
//! use authz_core::type_system::TypeSystem;
//! use authz_core::policy_provider::StaticPolicyProvider;
//! use authz_core::core_resolver::CoreResolver;
//! use authz_core::resolver::{CheckResolver, CheckResult, ResolveCheckRequest};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let model = parse_dsl(r#"
//!     type user {}
//!     type document {
//!         relations
//!             define owner:  [user]
//!             define viewer: [user]
//!         permissions
//!             define can_view = viewer + owner
//!     }
//! "#)?;
//!
//! let type_system = TypeSystem::new(model);
//! let provider    = StaticPolicyProvider::new(type_system);
//!
//! // `MyStore` implements TupleReader — connect to your real datastore here.
//! # use authz_core::traits::{Tuple, TupleFilter, TupleReader};
//! # use authz_core::error::AuthzError;
//! # #[derive(Clone)]
//! # struct MyStore;
//! # #[async_trait::async_trait]
//! # impl TupleReader for MyStore {
//! #     async fn read_tuples(&self, _: &TupleFilter) -> Result<Vec<Tuple>, AuthzError> { Ok(vec![]) }
//! #     async fn read_user_tuple(&self, _: &str, _: &str, _: &str, _: &str, _: &str) -> Result<Option<Tuple>, AuthzError> { Ok(None) }
//! #     async fn read_userset_tuples(&self, _: &str, _: &str, _: &str) -> Result<Vec<Tuple>, AuthzError> { Ok(vec![]) }
//! #     async fn read_starting_with_user(&self, _: &str, _: &str) -> Result<Vec<Tuple>, AuthzError> { Ok(vec![]) }
//! #     async fn read_user_tuple_batch(&self, _: &str, _: &str, _: &[String], _: &str, _: &str) -> Result<Option<Tuple>, AuthzError> { Ok(None) }
//! # }
//! let resolver = CoreResolver::new(MyStore, provider);
//!
//! let req = ResolveCheckRequest::new(
//!     "document".into(), "doc-42".into(), "can_view".into(),
//!     "user".into(),     "alice".into(),
//! );
//!
//! match resolver.resolve_check(req).await? {
//!     CheckResult::Allowed                   => println!("allowed"),
//!     CheckResult::Denied                    => println!("denied"),
//!     CheckResult::ConditionRequired(params) => println!("need: {:?}", params),
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Modules
//!
//! | Module | Purpose |
//! |---|---|
//! | [`model_ast`] | AST types produced by the parser |
//! | [`model_parser`] | Parse the model DSL into a [`model_ast::ModelFile`] |
//! | [`model_validator`] | Semantic validation of a parsed model |
//! | [`type_system`] | In-memory model index; tuple validation |
//! | [`traits`] | Core data types and async datastore traits |
//! | [`resolver`] | [`resolver::CheckResolver`] trait and request/result types |
//! | [`core_resolver`] | Built-in graph-walking resolver implementation |
//! | [`policy_provider`] | Policy loading abstraction + [`policy_provider::StaticPolicyProvider`] |
//! | [`dispatcher`] | Fan-out dispatcher trait + [`dispatcher::LocalDispatcher`] |
//! | [`cache`] | Pluggable cache abstraction + [`cache::NoopCache`] |
//! | [`cel`] | CEL (Common Expression Language) condition evaluation |
//! | [`tenant_schema`] | [`tenant_schema::ChangelogReader`] for the Watch API |
//! | [`error`] | [`error::AuthzError`] — all error variants |
//!
//! # Feature flags
//!
//! This crate has no optional feature flags. All components are always compiled.
//!
//! # MSRV
//!
//! Rust **1.85** or later (edition 2024).

pub mod cache;
pub mod cel;
pub mod core_resolver;
pub mod dispatcher;
pub mod error;
pub mod model_ast;
pub mod model_parser;
pub mod model_validator;
pub mod policy_provider;
pub mod resolver;
pub mod tenant_schema;
pub mod traits;
pub mod type_system;
