# authz-core

[![Crates.io](https://img.shields.io/crates/v/authz-core.svg)](https://crates.io/crates/authz-core)
[![Docs.rs](https://docs.rs/authz-core/badge.svg)](https://docs.rs/authz-core)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](#license)

A [Zanzibar](https://research.google/pubs/zanzibar-googles-consistent-global-authorization-system/)-inspired Fine-Grained Authorization engine for Rust, based on Google's globally consistent authorization system.

`authz-core` is the database- and transport-agnostic heart of an authorization system. It provides:

- A **model DSL** for declaring types, relations, and permissions
- A **type system** for validating tuples against the parsed model
- **Datastore traits** (`TupleReader`, `TupleWriter`, `PolicyReader`, `PolicyWriter`) that you implement against any backend
- A **`CoreResolver`** that walks the authorization graph, resolving `Check` requests via depth-first or breadth-first traversal with configurable cycle detection
- **CEL condition evaluation** for attribute-based access control (ABAC)
- A **cache abstraction** (`AuthzCache`) for pluggable caching backends
- A **dispatcher** abstraction for fan-out to multiple resolvers

No database or transport dependencies are included — those live in downstream implementations (e.g. [`pgauthz`](https://github.com/zvectorlabs/pgauthz)).

---

## Quick start

```toml
[dependencies]
authz-core = "0.1"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

### 1. Define your model

```text
type user {}

type organization {
    relations
        define member: [user]
        define admin:  [user]
}

type document {
    relations
        define owner:  [user]
        define editor: [user | organization#member]
        define viewer: [user | organization#member]
    permissions
        define can_view = viewer + editor + owner
        define can_edit = editor + owner
}
```

### 2. Parse and build a TypeSystem

```rust
use authz_core::model_parser::parse_dsl;
use authz_core::type_system::TypeSystem;

let model = parse_dsl(include_str!("model.fga")).expect("invalid model");
let type_system = TypeSystem::new(model);
```

### 3. Wire up the resolver

```rust
use authz_core::core_resolver::CoreResolver;
use authz_core::policy_provider::StaticPolicyProvider;
use authz_core::resolver::{CheckResolver, CheckResult, ResolveCheckRequest};

let provider = StaticPolicyProvider::new(type_system);
let resolver = CoreResolver::new(
    my_tuple_store,  // impl TupleReader + Clone
    provider,
);

let req = ResolveCheckRequest::new(
    "document".into(), "doc-42".into(), "can_view".into(),
    "user".into(),     "alice".into(),
);

match resolver.resolve_check(req).await? {
    CheckResult::Allowed                   => println!("access granted"),
    CheckResult::Denied                    => println!("access denied"),
    CheckResult::ConditionRequired(params) => println!("need context: {:?}", params),
}
```

---

## Model DSL

The DSL is a superset of the OpenFGA syntax.

### Types and relations

```text
type <name> {
    relations
        define <relation>: <expression>
    permissions
        define <permission> = <expression>
}
```

Relations are stored as tuples in the datastore.
Permissions are derived — they cannot be the subject of a write tuple.

### Relation expressions

| Syntax | Meaning |
|---|---|
| `[user]` | Direct assignment — only `user` subjects |
| `[user \| group#member]` | Union of direct types and usersets |
| `[user:*]` | Public / wildcard — any `user` subject |
| `[user with ip_check]` | Conditional on a named CEL condition |
| `editor` | Computed userset — inherit from another relation |
| `parent->viewer` | Tuple-to-userset — traverse a relation, then check `viewer` on the target |
| `a + b` | Union |
| `a & b` | Intersection |
| `a - b` | Exclusion (a minus b) |

Operator precedence: `+` (union) binds tighter than `&`, which binds tighter than `-`.

### Conditions (ABAC)

```text
condition ip_check(allowed_cidrs: list<string>, request_ip: string) {
    request_ip in allowed_cidrs
}
```

Supported parameter types: `string`, `int`, `bool`, `list<string>`, `list<int>`, `list<bool>`, `map<string, string>`.

The condition expression is a [CEL](https://cel.dev) expression evaluated at check time when the `context` map is populated in `ResolveCheckRequest`.

---

## Module overview

| Module | Contents |
|---|---|
| `model_ast` | AST types: `ModelFile`, `TypeDef`, `RelationDef`, `RelationExpr`, `ConditionDef` |
| `model_parser` | `parse_dsl(src)` — parses the DSL into a `ModelFile` |
| `model_validator` | Post-parse semantic validation |
| `type_system` | `TypeSystem` — query types/relations, validate tuples |
| `traits` | `Tuple`, `TupleFilter`, `TupleReader`, `TupleWriter`, `PolicyReader`, `PolicyWriter`, `RevisionReader` |
| `resolver` | `CheckResolver` trait, `ResolveCheckRequest`, `CheckResult`, `RecursionConfig` |
| `core_resolver` | `CoreResolver` — the actual graph-walking engine |
| `policy_provider` | `PolicyProvider` trait + `StaticPolicyProvider` |
| `dispatcher` | `Dispatcher` trait + `LocalDispatcher` |
| `cache` | `AuthzCache<V>` trait + `NoopCache` + `noop_cache()` helper |
| `cel` | CEL expression compilation and evaluation |
| `tenant_schema` | `ChangelogReader` trait for the Watch API |
| `error` | `AuthzError` — all error variants |

---

## Implementing the datastore traits

There are two categories of traits to implement:

- **Tuple traits** — `TupleReader` / `TupleWriter`: read and write relationship tuples (e.g. `document:42#viewer@user:alice`). Used directly by `CoreResolver`.
- **Policy traits** — `PolicyReader` / `PolicyWriter`: read and write the authorization policy (the DSL source stored in the datastore). Used by your service layer to load and persist model definitions.

### TupleReader

```rust
use async_trait::async_trait;
use authz_core::traits::{Tuple, TupleFilter, TupleReader};
use authz_core::error::AuthzError;

struct MyStore { /* db pool */ }

#[async_trait]
impl TupleReader for MyStore {
    async fn read_tuples(&self, filter: &TupleFilter) -> Result<Vec<Tuple>, AuthzError> {
        // SELECT * FROM tuples WHERE ...
        todo!()
    }

    async fn read_user_tuple(
        &self,
        object_type: &str, object_id: &str, relation: &str,
        subject_type: &str, subject_id: &str,
    ) -> Result<Option<Tuple>, AuthzError> {
        todo!()
    }

    async fn read_userset_tuples(
        &self,
        object_type: &str, object_id: &str, relation: &str,
    ) -> Result<Vec<Tuple>, AuthzError> {
        todo!()
    }

    async fn read_starting_with_user(
        &self,
        subject_type: &str, subject_id: &str,
    ) -> Result<Vec<Tuple>, AuthzError> {
        todo!()
    }

    async fn read_user_tuple_batch(
        &self,
        object_type: &str, object_id: &str, relations: &[String],
        subject_type: &str, subject_id: &str,
    ) -> Result<Option<Tuple>, AuthzError> {
        todo!()
    }
}
```

### PolicyReader

```rust
use async_trait::async_trait;
use authz_core::traits::{AuthorizationPolicy, Pagination, PolicyReader};
use authz_core::error::AuthzError;

#[async_trait]
impl PolicyReader for MyStore {
    async fn read_authorization_policy(&self, id: &str) -> Result<Option<AuthorizationPolicy>, AuthzError> {
        // SELECT * FROM policies WHERE id = $1
        todo!()
    }

    async fn read_latest_authorization_policy(&self) -> Result<Option<AuthorizationPolicy>, AuthzError> {
        // SELECT * FROM policies ORDER BY created_at DESC LIMIT 1
        todo!()
    }

    async fn list_authorization_policies(&self, pagination: &Pagination) -> Result<Vec<AuthorizationPolicy>, AuthzError> {
        todo!()
    }
}
```

---

## Recursion and performance

`ResolveCheckRequest` accepts a `RecursionConfig` to tune resolution behaviour:

```rust
use authz_core::resolver::{RecursionConfig, RecursionStrategy};

// Depth-first (default) — fast, memory-efficient
let cfg = RecursionConfig::depth_first().max_depth(30);

// Breadth-first — finds shortest path, higher memory
let cfg = RecursionConfig::breadth_first().cycle_detection(true);
```

`ResolverMetadata` (shared via `Arc<AtomicU32>`) tracks dispatch count, datastore queries, cache hits, and max depth reached across recursive calls — useful for observability.

---

## Plugging in a cache

Implement `AuthzCache<CheckResult>` and pass it to `CoreResolver`:

```rust
use authz_core::cache::AuthzCache;
use authz_core::resolver::CheckResult;

struct MokaCache(moka::sync::Cache<String, CheckResult>);

impl AuthzCache<CheckResult> for MokaCache {
    fn get(&self, key: &str)               -> Option<CheckResult> { self.0.get(key) }
    fn insert(&self, key: &str, v: CheckResult)                    { self.0.insert(key.to_string(), v); }
    fn invalidate(&self, key: &str)                                { self.0.invalidate(key); }
    fn invalidate_all(&self)                                       { self.0.invalidate_all(); }
    fn metrics(&self) -> Box<dyn authz_core::cache::CacheMetrics>  { todo!() }
}
```

---

## MSRV

Rust **1.85** or later (edition 2024).

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
