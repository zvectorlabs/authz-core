# Changelog

All notable changes to `authz-core` will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-03-09

### Added

- **Model DSL parser** — parse OpenFGA-inspired authorization model definitions into a typed AST (`model_ast`, `model_parser`)
- **Model validator** — semantic validation: duplicate types/relations, undefined references, cycle detection (`model_validator`)
- **TypeSystem** — in-memory model index with tuple validation and relation/permission lookup (`type_system`)
- **CoreResolver** — async authorization graph walker supporting depth-first and breadth-first traversal, configurable recursion depth, cycle detection, and batch tuple queries (`core_resolver`)
- **CEL condition evaluation** — attribute-based access control (ABAC) via Common Expression Language conditions (`cel`)
- **Datastore traits** — `TupleReader`, `TupleWriter`, `PolicyReader`, `PolicyWriter`, `RevisionReader` (`traits`)
- **PolicyProvider** trait and `StaticPolicyProvider` for single-tenant deployments (`policy_provider`)
- **Dispatcher** trait and `LocalDispatcher` for in-process resolution (`dispatcher`)
- **Cache abstraction** — `AuthzCache<V>` trait and `NoopCache` implementation (`cache`)
- **ChangelogReader** trait for Watch API support (`tenant_schema`)
- **Structured errors** — `AuthzError` covering validation, model, resolution, datastore, and cache failures (`error`)
- Full test suite: 89 unit tests + 1 doctest
