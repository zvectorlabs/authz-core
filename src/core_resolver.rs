//! CoreResolver - implements CheckResolver by walking the authorization model.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::cache::{AuthzCache, noop_cache};
use crate::error::AuthzError;
use crate::model_ast::{AssignableTarget, RelationExpr};
use crate::policy_provider::PolicyProvider;
use crate::resolver::{CheckResolver, CheckResult, ResolveCheckRequest};
use crate::traits::{Tuple, TupleFilter, TupleReader};

/// Convert JSON context values to authz-cel Value types.
fn json_context_to_cel(
    context: &HashMap<String, serde_json::Value>,
) -> HashMap<String, crate::cel::Value> {
    let mut cel_ctx = HashMap::new();
    for (key, value) in context {
        if let Some(cel_val) = json_value_to_cel(value) {
            cel_ctx.insert(key.clone(), cel_val);
        }
    }
    cel_ctx
}

fn json_value_to_cel(value: &serde_json::Value) -> Option<crate::cel::Value> {
    match value {
        serde_json::Value::Bool(b) => Some(crate::cel::Value::Bool(*b)),
        serde_json::Value::Number(n) => n.as_i64().map(crate::cel::Value::Int),
        serde_json::Value::String(s) => Some(crate::cel::Value::String(s.clone())),
        serde_json::Value::Array(arr) => {
            let items: Vec<crate::cel::Value> = arr.iter().filter_map(json_value_to_cel).collect();
            Some(crate::cel::Value::List(items))
        }
        _ => None,
    }
}

/// Check optimization strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CheckStrategy {
    /// Batch queries together (default, best for most cases)
    #[default]
    Batch,
    /// Parallel evaluation (useful for high-latency datastores)
    Parallel,
}

/// Core resolver that walks the authorization model to resolve checks.
///
/// # Caching
///
/// CoreResolver uses the `AuthzCache` trait for two cache layers:
/// - L2 result cache: Caches check results (disabled for contextual tuples)
/// - L3 tuple cache: Caches tuple reads (disabled for contextual tuples)
///
/// By default both caches are `NoopCache` (disabled).  Callers can inject
/// cross-request caches via `.with_result_cache()` / `.with_tuple_cache()`.
pub struct CoreResolver<D, P> {
    datastore: D,
    policy_provider: P,
    max_concurrent: usize,
    /// Semaphore limiting concurrent datastore reads
    read_semaphore: Arc<Semaphore>,
    /// L2: Cache for check results (key: object:relation:subject)
    result_cache: Arc<dyn AuthzCache<CheckResult>>,
    /// L3: Cache for tuple reads (key: object_type:object_id:relation)
    tuple_cache: Arc<dyn AuthzCache<Vec<Tuple>>>,
    /// Check optimization strategy
    strategy: CheckStrategy,
}

impl<D, P> CoreResolver<D, P>
where
    D: TupleReader + Clone + Send + Sync + 'static,
    P: PolicyProvider + Send + Sync + 'static,
{
    /// Create a new CoreResolver with `NoopCache` (caching disabled by default).
    pub fn new(datastore: D, policy_provider: P) -> Self {
        Self {
            datastore,
            policy_provider,
            max_concurrent: 50, // Default concurrency limit
            read_semaphore: Arc::new(Semaphore::new(50)),
            result_cache: noop_cache(),
            tuple_cache: noop_cache(),
            strategy: CheckStrategy::default(),
        }
    }

    /// Set the check strategy.
    pub fn with_strategy(mut self, strategy: CheckStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Set the maximum concurrent dispatches.
    pub fn with_max_concurrent(mut self, max: usize) -> Self {
        self.max_concurrent = max;
        self.read_semaphore = Arc::new(Semaphore::new(max));
        self
    }

    /// Set the L2 dispatch-result cache.
    pub fn with_result_cache(mut self, cache: Arc<dyn AuthzCache<CheckResult>>) -> Self {
        self.result_cache = cache;
        self
    }

    /// Set the L3 tuple-iterator cache.
    pub fn with_tuple_cache(mut self, cache: Arc<dyn AuthzCache<Vec<Tuple>>>) -> Self {
        self.tuple_cache = cache;
        self
    }

    fn result_cache_key(request: &ResolveCheckRequest) -> String {
        if request.at_revision.is_empty() {
            // Fallback for tests/legacy: no revision prefix
            format!(
                "{}:{}:{}:{}:{}",
                request.object_type,
                request.object_id,
                request.relation,
                request.subject_type,
                request.subject_id
            )
        } else {
            format!(
                "{}:{}:{}:{}:{}:{}",
                request.at_revision,
                request.object_type,
                request.object_id,
                request.relation,
                request.subject_type,
                request.subject_id
            )
        }
    }

    fn tuple_cache_key(
        revision: &str,
        object_type: &str,
        object_id: &str,
        relation: &str,
    ) -> String {
        if revision.is_empty() {
            format!("{}:{}:{}", object_type, object_id, relation)
        } else {
            format!("{}:{}:{}:{}", revision, object_type, object_id, relation)
        }
    }

    /// Resolve a check by walking the relation expression.
    fn resolve_relation_expr<'a>(
        &'a self,
        expr: &'a RelationExpr,
        request: &'a ResolveCheckRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<CheckResult, AuthzError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let expr_type = match expr {
                RelationExpr::DirectAssignment(_) => "direct",
                RelationExpr::ComputedUserset(_) => "computed_userset",
                RelationExpr::TupleToUserset { .. } => "tuple_to_userset",
                RelationExpr::Union(_) => "union",
                RelationExpr::Intersection(_) => "intersection",
                RelationExpr::Exclusion { .. } => "exclusion",
            };
            tracing::debug!(expr_type = expr_type, "resolve_expr");
            match expr {
                RelationExpr::DirectAssignment(targets) => {
                    self.resolve_direct(targets, request).await
                }
                RelationExpr::ComputedUserset(target_relation) => {
                    self.resolve_computed_userset(target_relation, request)
                        .await
                }
                RelationExpr::TupleToUserset {
                    tupleset,
                    computed_userset,
                } => {
                    self.resolve_tuple_to_userset(tupleset, computed_userset, request)
                        .await
                }
                RelationExpr::Union(exprs) => self.resolve_union(exprs, request).await,
                RelationExpr::Intersection(exprs) => {
                    self.resolve_intersection(exprs, request).await
                }
                RelationExpr::Exclusion { base, subtract } => {
                    self.resolve_exclusion(base, subtract, request).await
                }
            }
        })
    }

    /// Handle DirectAssignment: [user, group#member, user:*]
    async fn resolve_direct(
        &self,
        targets: &[AssignableTarget],
        request: &ResolveCheckRequest,
    ) -> Result<CheckResult, AuthzError> {
        // Read tuples for this object and relation
        let tuples = self
            .read_tuples_with_contextual(
                &request.object_type,
                &request.object_id,
                &request.relation,
                request,
            )
            .await?;

        tracing::info!(
            object_type = %request.object_type,
            object_id = %request.object_id,
            relation = %request.relation,
            subject_type = %request.subject_type,
            subject_id = %request.subject_id,
            tuples = ?tuples,
            targets = ?targets,
            "resolve_direct input"
        );

        // Check each tuple against the assignable targets
        for tuple in &tuples {
            for target in targets {
                match target {
                    AssignableTarget::Type(type_name) => {
                        // Direct type match: viewer: [user]
                        if tuple.subject_type == *type_name
                            && tuple.subject_id == request.subject_id
                        {
                            return Ok(CheckResult::Allowed);
                        }
                    }
                    AssignableTarget::Userset {
                        type_name,
                        relation,
                    } => {
                        // Userset expansion: viewer: [group#member]
                        // The tuple subject_id may contain a #relation suffix
                        // (e.g. "eng#member") which must be stripped to get the
                        // bare object ID for the child check dispatch.
                        let bare_subject_id = tuple
                            .subject_id
                            .split('#')
                            .next()
                            .unwrap_or(&tuple.subject_id)
                            .to_string();

                        tracing::info!(
                            object_type = %request.object_type,
                            object_id = %request.object_id,
                            request_relation = %request.relation,
                            tuple_subject_type = %tuple.subject_type,
                            tuple_subject_id = %tuple.subject_id,
                            bare_subject_id = %bare_subject_id,
                            target_type = %type_name,
                            target_relation = %relation,
                            subject_type = %request.subject_type,
                            subject_id = %request.subject_id,
                            "Evaluating userset target"
                        );

                        if tuple.subject_type == *type_name {
                            // Dispatch check: group:admins#member@user:alice
                            let child_req = request.child_request(
                                type_name.clone(),
                                bare_subject_id,
                                relation.clone(),
                                request.subject_type.clone(),
                                request.subject_id.clone(),
                            );
                            let result = self.resolve_check(child_req).await?;
                            tracing::info!(
                                target_type = %type_name,
                                target_object_id = %tuple.subject_id,
                                target_relation = %relation,
                                result = ?result,
                                "Userset child check result"
                            );
                            if result == CheckResult::Allowed {
                                return Ok(CheckResult::Allowed);
                            }
                        }
                    }
                    AssignableTarget::Wildcard(type_name) => {
                        // Wildcard: viewer: [user:*]
                        if tuple.subject_type == *type_name && tuple.subject_id == "*" {
                            // Any user of this type is allowed
                            if request.subject_type == *type_name {
                                return Ok(CheckResult::Allowed);
                            }
                        }
                    }
                    AssignableTarget::Conditional { target, condition } => {
                        // Conditional: viewer: [user with ip_check]
                        // First check if the base target matches
                        if let AssignableTarget::Type(type_name) = target.as_ref()
                            && tuple.subject_type == *type_name
                            && tuple.subject_id == request.subject_id
                        {
                            // Check if tuple has the required condition
                            if let Some(tuple_condition) = &tuple.condition
                                && tuple_condition == condition
                            {
                                // If context is provided, evaluate the CEL condition
                                if !request.context.is_empty() {
                                    let type_system = self.policy_provider.get_policy().await?;
                                    if let Some(cond_def) = type_system.get_condition(condition) {
                                        let cel_ctx = json_context_to_cel(&request.context);
                                        match crate::cel::compile(&cond_def.expression) {
                                            Ok(program) => {
                                                match crate::cel::evaluate(&program, &cel_ctx) {
                                                    Ok(crate::cel::CelResult::Met(true)) => {
                                                        return Ok(CheckResult::Allowed);
                                                    }
                                                    Ok(crate::cel::CelResult::Met(false)) => {
                                                        // Condition not met — continue checking other tuples
                                                    }
                                                    Ok(
                                                        crate::cel::CelResult::MissingParameters(
                                                            params,
                                                        ),
                                                    ) => {
                                                        return Ok(CheckResult::ConditionRequired(
                                                            params,
                                                        ));
                                                    }
                                                    Err(e) => {
                                                        tracing::warn!(condition = %condition, error = %e, "CEL evaluation error");
                                                        return Ok(CheckResult::ConditionRequired(
                                                            vec![condition.clone()],
                                                        ));
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                tracing::warn!(condition = %condition, error = %e, "CEL compile error");
                                                return Ok(CheckResult::ConditionRequired(vec![
                                                    condition.clone(),
                                                ]));
                                            }
                                        }
                                    } else {
                                        return Ok(CheckResult::ConditionRequired(vec![
                                            condition.clone(),
                                        ]));
                                    }
                                } else {
                                    return Ok(CheckResult::ConditionRequired(vec![
                                        condition.clone(),
                                    ]));
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(CheckResult::Denied)
    }

    /// Handle ComputedUserset: viewer (rewrite to same object)
    async fn resolve_computed_userset(
        &self,
        target_relation: &str,
        request: &ResolveCheckRequest,
    ) -> Result<CheckResult, AuthzError> {
        // Rewrite: document:1#can_view → document:1#viewer
        let child_req = request.child_request(
            request.object_type.clone(),
            request.object_id.clone(),
            target_relation.to_string(),
            request.subject_type.clone(),
            request.subject_id.clone(),
        );

        tracing::info!(
            object_type = %request.object_type,
            object_id = %request.object_id,
            request_relation = %request.relation,
            target_relation = %target_relation,
            subject_type = %request.subject_type,
            subject_id = %request.subject_id,
            "resolve_computed_userset rewriting to child request"
        );

        self.resolve_check(child_req).await
    }

    /// Handle TupleToUserset: viewer from parent
    async fn resolve_tuple_to_userset(
        &self,
        tupleset_relation: &str,
        computed_relation: &str,
        request: &ResolveCheckRequest,
    ) -> Result<CheckResult, AuthzError> {
        // 1. Read tuples: document:1#parent → [folder:root]
        let parent_tuples = self
            .read_tuples_with_contextual(
                &request.object_type,
                &request.object_id,
                tupleset_relation,
                request,
            )
            .await?;

        tracing::info!(
            object_type = %request.object_type,
            object_id = %request.object_id,
            request_relation = %request.relation,
            tupleset_relation = %tupleset_relation,
            computed_relation = %computed_relation,
            parent_tuples = ?parent_tuples,
            "resolve_tuple_to_userset parent tuples"
        );

        if parent_tuples.is_empty() {
            return Ok(CheckResult::Denied);
        }

        // 2. For each parent, dispatch: folder:root#viewer
        for parent_tuple in parent_tuples {
            let child_req = request.child_request(
                parent_tuple.subject_type.clone(),
                parent_tuple.subject_id.clone(),
                computed_relation.to_string(),
                request.subject_type.clone(),
                request.subject_id.clone(),
            );

            let result = self.resolve_check(child_req).await?;
            tracing::info!(
                parent_type = %parent_tuple.subject_type,
                parent_id = %parent_tuple.subject_id,
                computed_relation = %computed_relation,
                result = ?result,
                "resolve_tuple_to_userset child result"
            );
            if result == CheckResult::Allowed {
                return Ok(CheckResult::Allowed);
            }
        }

        Ok(CheckResult::Denied)
    }

    /// Handle Union: [user] or editor or owner
    async fn resolve_union(
        &self,
        exprs: &[RelationExpr],
        request: &ResolveCheckRequest,
    ) -> Result<CheckResult, AuthzError> {
        tracing::info!(
            object_type = %request.object_type,
            object_id = %request.object_id,
            request_relation = %request.relation,
            subject_type = %request.subject_type,
            subject_id = %request.subject_id,
            exprs = ?exprs,
            strategy = ?self.strategy,
            "resolve_union evaluating expressions"
        );
        match self.strategy {
            CheckStrategy::Batch => self.resolve_union_batch(exprs, request).await,
            CheckStrategy::Parallel => self.resolve_union_parallel(exprs, request).await,
        }
    }

    /// Batch strategy: Try to batch DirectAssignment queries for union branches.
    async fn resolve_union_batch(
        &self,
        exprs: &[RelationExpr],
        request: &ResolveCheckRequest,
    ) -> Result<CheckResult, AuthzError> {
        // First, try to batch all DirectAssignment branches
        let mut direct_assignments = Vec::new();
        let mut other_exprs = Vec::new();

        for expr in exprs {
            match expr {
                RelationExpr::DirectAssignment(_) => direct_assignments.push(expr),
                _ => other_exprs.push(expr),
            }
        }

        tracing::info!(
            direct_assignments_count = direct_assignments.len(),
            other_exprs_count = other_exprs.len(),
            "resolve_union_batch categorizing expressions"
        );

        if !direct_assignments.is_empty() {
            // Resolve DirectAssignment branches individually for now
            tracing::info!("resolve_union_batch evaluating direct assignments individually");
            for expr in &direct_assignments {
                if let Ok(CheckResult::Allowed) = self.resolve_relation_expr(expr, request).await {
                    return Ok(CheckResult::Allowed);
                }
            }
        }

        // Fall back to sequential evaluation for remaining expressions
        tracing::info!("resolve_union_batch falling back to sequential evaluation");
        for expr in &other_exprs {
            if let Ok(CheckResult::Allowed) = self.resolve_relation_expr(expr, request).await {
                return Ok(CheckResult::Allowed);
            }
        }

        Ok(CheckResult::Denied)
    }

    /// Parallel strategy: Evaluate all union branches concurrently.
    async fn resolve_union_parallel(
        &self,
        exprs: &[RelationExpr],
        request: &ResolveCheckRequest,
    ) -> Result<CheckResult, AuthzError> {
        use futures::FutureExt;
        use futures::future::select_ok;

        if exprs.is_empty() {
            return Ok(CheckResult::Denied);
        }

        // Create futures for all branches
        let mut futures = Vec::new();
        for expr in exprs {
            let future = self
                .resolve_relation_expr(expr, request)
                .then(|result| async move {
                    match result {
                        Ok(CheckResult::Allowed) => Ok(CheckResult::Allowed),
                        _ => Err(()),
                    }
                });
            futures.push(Box::pin(future));
        }

        // Return on first success, or Denied if all fail
        match select_ok(futures).await {
            Ok((result, _)) => Ok(result),
            Err(_) => Ok(CheckResult::Denied),
        }
    }

    /// Handle Intersection: [user] and editor
    async fn resolve_intersection(
        &self,
        exprs: &[RelationExpr],
        request: &ResolveCheckRequest,
    ) -> Result<CheckResult, AuthzError> {
        // Sequential evaluation with short-circuit
        // All must be Allowed for intersection to succeed
        for expr in exprs {
            let result = self.resolve_relation_expr(expr, request).await?;
            match result {
                CheckResult::Denied => return Ok(CheckResult::Denied),
                CheckResult::ConditionRequired(params) => {
                    return Ok(CheckResult::ConditionRequired(params));
                }
                CheckResult::Allowed => continue,
            }
        }
        Ok(CheckResult::Allowed)
    }

    /// Handle Exclusion: [user] but not banned
    ///
    /// Exclusion follows boolean logic semantics:
    /// ALLOWED if base=ALLOWED and subtract=DENIED
    ///
    /// This matches our project specification (prd-authz.md).
    /// Note: Some systems use set difference semantics where A - B means elements in A NOT in B.
    async fn resolve_exclusion(
        &self,
        base: &RelationExpr,
        subtract: &RelationExpr,
        request: &ResolveCheckRequest,
    ) -> Result<CheckResult, AuthzError> {
        let base_result = self.resolve_relation_expr(base, request).await?;
        let subtract_result = self.resolve_relation_expr(subtract, request).await?;

        // Allowed only if: base=Allowed AND subtract=Denied
        // Boolean logic semantics: base=true AND subtract=false = true
        match (base_result, subtract_result) {
            (CheckResult::Allowed, CheckResult::Denied) => Ok(CheckResult::Allowed),
            _ => Ok(CheckResult::Denied),
        }
    }

    /// Read tuples with contextual tuples merged in.
    async fn read_tuples_with_contextual(
        &self,
        object_type: &str,
        object_id: &str,
        relation: &str,
        request: &ResolveCheckRequest,
    ) -> Result<Vec<Tuple>, AuthzError> {
        let cache_key =
            Self::tuple_cache_key(&request.at_revision, object_type, object_id, relation);

        // L3 tuple cache is used only when there are no contextual tuples.
        if request.contextual_tuples.is_empty()
            && let Some(cached) = self.tuple_cache.get(&cache_key)
        {
            tracing::info!(cache_level = "L3", "cache_hit");
            return Ok(cached);
        }

        // Read from datastore
        let filter = TupleFilter {
            object_type: Some(object_type.to_string()),
            object_id: Some(object_id.to_string()),
            relation: Some(relation.to_string()),
            subject_type: None,
            subject_id: None,
        };

        // Bounded datastore reads
        let _permit = self.read_semaphore.acquire().await.map_err(|e| {
            AuthzError::Internal(format!("Failed to acquire read semaphore: {}", e))
        })?;

        // Track datastore query (shared atomic counter)
        request
            .metadata
            .datastore_queries
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut tuples = self.datastore.read_tuples(&filter).await?;

        if request.contextual_tuples.is_empty() {
            self.tuple_cache.insert(&cache_key, tuples.clone());
        }

        // Merge contextual tuples
        for ctx_tuple in &request.contextual_tuples {
            if ctx_tuple.object_type == object_type
                && ctx_tuple.object_id == object_id
                && ctx_tuple.relation == relation
            {
                // Avoid duplicates
                if !tuples.iter().any(|t| {
                    t.subject_type == ctx_tuple.subject_type && t.subject_id == ctx_tuple.subject_id
                }) {
                    tuples.push(ctx_tuple.clone());
                }
            }
        }

        Ok(tuples)
    }
}

#[async_trait]
impl<D, P> CheckResolver for CoreResolver<D, P>
where
    D: TupleReader + Clone + Send + Sync + 'static,
    P: PolicyProvider + Send + Sync + 'static,
{
    async fn resolve_check(
        &self,
        mut request: ResolveCheckRequest,
    ) -> Result<CheckResult, AuthzError> {
        tracing::info!(
            authz.object_type = %request.object_type,
            authz.object_id = %request.object_id,
            authz.relation = %request.relation,
            authz.depth = request.depth_remaining,
            authz.dispatch = request.metadata.get_dispatch_count(),
            "resolve_check",
        );
        // Check for cycles if enabled
        if request.recursion_config.enable_cycle_detection {
            let current_key = (
                request.object_type.clone(),
                request.object_id.clone(),
                request.relation.clone(),
            );
            if request.visited.contains(&current_key) {
                return Ok(CheckResult::Denied); // Cycle detected
            }
            request.visited.push(current_key);
        }

        // Check depth limit
        if request.depth_remaining == 0 {
            return Err(AuthzError::MaxDepthExceeded);
        }

        // L2 result cache (disabled for contextual tuple checks).
        let cache_key = Self::result_cache_key(&request);
        if request.contextual_tuples.is_empty()
            && let Some(cached) = self.result_cache.get(&cache_key)
        {
            tracing::info!(cache_level = "L2", "cache_hit");
            return Ok(cached);
        }

        // Increment dispatch count (shared atomic counter)
        request
            .metadata
            .dispatch_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Track max depth reached: depth = max_depth - depth_remaining
        let current_depth = request
            .recursion_config
            .max_depth
            .saturating_sub(request.depth_remaining);
        request
            .metadata
            .max_depth_reached
            .fetch_max(current_depth, std::sync::atomic::Ordering::Relaxed);

        // Get the active policy from the provider (O(1) for StaticPolicyProvider)
        let type_system = self.policy_provider.get_policy().await?;

        // Get the relation definition from the type system
        let relation_def = type_system
            .get_relation(&request.object_type, &request.relation)
            .ok_or_else(|| {
                if let Some(type_def) = type_system.get_type(&request.object_type) {
                    tracing::error!(
                        object_type = %request.object_type,
                        relation = %request.relation,
                        available_relations = ?type_def.relations.iter().map(|r| &r.name).collect::<Vec<_>>(),
                        available_permissions = ?type_def.permissions.iter().map(|p| &p.name).collect::<Vec<_>>(),
                        "RelationNotFound error"
                    );
                }
                AuthzError::RelationNotFound {
                    object_type: request.object_type.clone(),
                    relation: request.relation.clone(),
                }
            })?;

        // Resolve the relation expression
        let relation_expr = relation_def.expression.clone();
        let result = self.resolve_relation_expr(&relation_expr, &request).await?;

        if request.contextual_tuples.is_empty() {
            self.result_cache.insert(&cache_key, result.clone());
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model_parser::parse_dsl;
    use crate::policy_provider::StaticPolicyProvider;
    use crate::traits::Tuple;
    use crate::type_system::TypeSystem;

    // Mock datastore for testing
    #[derive(Clone)]
    struct MockDatastore {
        tuples: Vec<Tuple>,
    }

    #[async_trait]
    impl TupleReader for MockDatastore {
        async fn read_tuples(&self, filter: &TupleFilter) -> Result<Vec<Tuple>, AuthzError> {
            Ok(self
                .tuples
                .iter()
                .filter(|t| {
                    filter
                        .object_type
                        .as_ref()
                        .map_or(true, |v| &t.object_type == v)
                        && filter
                            .object_id
                            .as_ref()
                            .map_or(true, |v| &t.object_id == v)
                        && filter.relation.as_ref().map_or(true, |v| &t.relation == v)
                        && filter
                            .subject_type
                            .as_ref()
                            .map_or(true, |v| &t.subject_type == v)
                        && filter
                            .subject_id
                            .as_ref()
                            .map_or(true, |v| &t.subject_id == v)
                })
                .cloned()
                .collect())
        }

        async fn read_user_tuple(
            &self,
            _object_type: &str,
            _object_id: &str,
            _relation: &str,
            _subject_type: &str,
            _subject_id: &str,
        ) -> Result<Option<Tuple>, AuthzError> {
            Ok(None)
        }

        async fn read_userset_tuples(
            &self,
            _object_type: &str,
            _object_id: &str,
            _relation: &str,
        ) -> Result<Vec<Tuple>, AuthzError> {
            Ok(Vec::new())
        }

        async fn read_starting_with_user(
            &self,
            _subject_type: &str,
            _subject_id: &str,
        ) -> Result<Vec<Tuple>, AuthzError> {
            Ok(Vec::new())
        }

        async fn read_user_tuple_batch(
            &self,
            object_type: &str,
            object_id: &str,
            relations: &[String],
            subject_type: &str,
            subject_id: &str,
        ) -> Result<Option<Tuple>, AuthzError> {
            Ok(self
                .tuples
                .iter()
                .find(|t| {
                    t.object_type == object_type
                        && t.object_id == object_id
                        && relations.iter().any(|r| r == &t.relation)
                        && t.subject_type == subject_type
                        && t.subject_id == subject_id
                })
                .cloned())
        }
    }

    #[tokio::test]
    async fn test_direct_user_match() {
        let dsl = "type document { relations define viewer: [user] }";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);

        let tuples = vec![Tuple {
            object_type: "document".to_string(),
            object_id: "doc1".to_string(),
            relation: "viewer".to_string(),
            subject_type: "user".to_string(),
            subject_id: "alice".to_string(),
            condition: None,
        }];

        let datastore = MockDatastore { tuples };
        let resolver = CoreResolver::new(datastore, StaticPolicyProvider::new(ts));

        let request = ResolveCheckRequest::new(
            "document".into(),
            "doc1".into(),
            "viewer".into(),
            "user".into(),
            "alice".into(),
        );

        let result = resolver.resolve_check(request).await.unwrap();
        assert_eq!(result, CheckResult::Allowed);
    }

    #[tokio::test]
    async fn test_direct_user_no_match() {
        let dsl = "type document { relations define viewer: [user] }";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);

        let tuples = vec![Tuple {
            object_type: "document".to_string(),
            object_id: "doc1".to_string(),
            relation: "viewer".to_string(),
            subject_type: "user".to_string(),
            subject_id: "alice".to_string(),
            condition: None,
        }];

        let datastore = MockDatastore { tuples };
        let resolver = CoreResolver::new(datastore, StaticPolicyProvider::new(ts));

        let request = ResolveCheckRequest::new(
            "document".into(),
            "doc1".into(),
            "viewer".into(),
            "user".into(),
            "bob".into(),
        );

        let result = resolver.resolve_check(request).await.unwrap();
        assert_eq!(result, CheckResult::Denied);
    }

    #[tokio::test]
    async fn test_computed_userset() {
        let dsl = "type document { relations define viewer: [user] define can_view: viewer }";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);

        let tuples = vec![Tuple {
            object_type: "document".to_string(),
            object_id: "doc1".to_string(),
            relation: "viewer".to_string(),
            subject_type: "user".to_string(),
            subject_id: "alice".to_string(),
            condition: None,
        }];

        let datastore = MockDatastore { tuples };
        let resolver = CoreResolver::new(datastore, StaticPolicyProvider::new(ts));

        let request = ResolveCheckRequest::new(
            "document".into(),
            "doc1".into(),
            "can_view".into(),
            "user".into(),
            "alice".into(),
        );

        let result = resolver.resolve_check(request).await.unwrap();
        assert_eq!(result, CheckResult::Allowed);
    }

    #[tokio::test]
    async fn test_cycle_detection() {
        let dsl = r#"
            type folder {
                relations
                    define parent: [folder]
                permissions
                    define view = parent->view
            }
            type document {
                relations
                    define parent: [folder]
                permissions
                    define view = parent->view
            }
        "#;
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);

        // Create a cycle: folder1 -> folder2 -> folder1
        let tuples = vec![
            Tuple {
                object_type: "folder".to_string(),
                object_id: "folder1".to_string(),
                relation: "parent".to_string(),
                subject_type: "folder".to_string(),
                subject_id: "folder2".to_string(),
                condition: None,
            },
            Tuple {
                object_type: "folder".to_string(),
                object_id: "folder2".to_string(),
                relation: "parent".to_string(),
                subject_type: "folder".to_string(),
                subject_id: "folder1".to_string(),
                condition: None,
            },
            Tuple {
                object_type: "document".to_string(),
                object_id: "doc1".to_string(),
                relation: "parent".to_string(),
                subject_type: "folder".to_string(),
                subject_id: "folder1".to_string(),
                condition: None,
            },
        ];

        let datastore = MockDatastore { tuples };
        let resolver = CoreResolver::new(datastore, StaticPolicyProvider::new(ts));

        let request = ResolveCheckRequest::new(
            "document".into(),
            "doc1".into(),
            "view".into(),
            "user".into(),
            "alice".into(),
        );

        let result = resolver.resolve_check(request).await.unwrap();
        assert_eq!(result, CheckResult::Denied); // Should be denied due to cycle
    }

    #[tokio::test]
    async fn test_recursion_config_depth_first() {
        let dsl = r#"
            type folder {
                relations
                    define parent: [folder]
                permissions
                    define view = parent->view
            }
            type document {
                relations
                    define parent: [folder]
                permissions
                    define view = parent->view
            }
        "#;
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);

        // Create a cycle: folder1 -> folder2 -> folder1
        let tuples = vec![
            Tuple {
                object_type: "folder".to_string(),
                object_id: "folder1".to_string(),
                relation: "parent".to_string(),
                subject_type: "folder".to_string(),
                subject_id: "folder2".to_string(),
                condition: None,
            },
            Tuple {
                object_type: "folder".to_string(),
                object_id: "folder2".to_string(),
                relation: "parent".to_string(),
                subject_type: "folder".to_string(),
                subject_id: "folder1".to_string(),
                condition: None,
            },
            Tuple {
                object_type: "document".to_string(),
                object_id: "doc1".to_string(),
                relation: "parent".to_string(),
                subject_type: "folder".to_string(),
                subject_id: "folder1".to_string(),
                condition: None,
            },
        ];

        let datastore = MockDatastore { tuples };
        let resolver = CoreResolver::new(datastore, StaticPolicyProvider::new(ts));

        // Test with depth-first config (default)
        let config = crate::resolver::RecursionConfig::depth_first()
            .max_depth(10)
            .cycle_detection(true);

        let request = crate::resolver::ResolveCheckRequest::with_config(
            "document".into(),
            "doc1".into(),
            "view".into(),
            "user".into(),
            "alice".into(),
            config,
        );

        let result = resolver.resolve_check(request).await.unwrap();
        assert_eq!(result, CheckResult::Denied); // Should be denied due to cycle
    }

    #[tokio::test]
    async fn test_recursion_config_breadth_first() {
        let dsl = r#"
            type folder {
                relations
                    define owner: [user]
                permissions
                    define view = owner
            }
            type document {
                relations
                    define parent: [folder]
                permissions
                    define view = parent->view
            }
        "#;
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);

        let tuples = vec![
            Tuple {
                object_type: "folder".to_string(),
                object_id: "folder1".to_string(),
                relation: "owner".to_string(),
                subject_type: "user".to_string(),
                subject_id: "alice".to_string(),
                condition: None,
            },
            Tuple {
                object_type: "document".to_string(),
                object_id: "doc1".to_string(),
                relation: "parent".to_string(),
                subject_type: "folder".to_string(),
                subject_id: "folder1".to_string(),
                condition: None,
            },
        ];

        let datastore = MockDatastore { tuples };
        let resolver = CoreResolver::new(datastore, StaticPolicyProvider::new(ts));

        // Test with breadth-first config
        let config = crate::resolver::RecursionConfig::breadth_first()
            .max_depth(50)
            .cycle_detection(true);

        let request = crate::resolver::ResolveCheckRequest::with_config(
            "document".into(),
            "doc1".into(),
            "view".into(),
            "user".into(),
            "alice".into(),
            config,
        );

        let result = resolver.resolve_check(request).await.unwrap();
        assert_eq!(result, CheckResult::Allowed); // Should be allowed
    }

    #[tokio::test]
    async fn test_cycle_detection_disabled() {
        let dsl = "type document { relations define viewer: viewer }";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);

        let datastore = MockDatastore { tuples: vec![] };
        let resolver = CoreResolver::new(datastore, StaticPolicyProvider::new(ts));

        // Test with cycle detection disabled
        let config = crate::resolver::RecursionConfig::depth_first().cycle_detection(false);

        let mut request = crate::resolver::ResolveCheckRequest::with_config(
            "document".into(),
            "doc1".into(),
            "viewer".into(),
            "user".into(),
            "alice".into(),
            config,
        );
        request.depth_remaining = 1;

        let result = resolver.resolve_check(request).await;
        assert!(result.is_err()); // Should error due to depth limit
        assert!(matches!(result.unwrap_err(), AuthzError::MaxDepthExceeded));
    }

    #[tokio::test]
    async fn test_depth_limit() {
        let dsl = "type document { relations define viewer: viewer }";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);

        let datastore = MockDatastore { tuples: vec![] };
        let resolver = CoreResolver::new(datastore, StaticPolicyProvider::new(ts));

        let mut request = ResolveCheckRequest::new(
            "document".into(),
            "doc1".into(),
            "viewer".into(),
            "user".into(),
            "alice".into(),
        );
        request.depth_remaining = 1;

        let result = resolver.resolve_check(request).await.unwrap();
        assert_eq!(result, CheckResult::Denied); // Cycle detected, not depth limit exceeded
    }

    #[tokio::test]
    async fn test_union_first_succeeds() {
        let dsl = "type document { relations define viewer: [user] define editor: [user] define can_view: viewer + editor }";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);

        let tuples = vec![Tuple {
            object_type: "document".to_string(),
            object_id: "doc1".to_string(),
            relation: "viewer".to_string(),
            subject_type: "user".to_string(),
            subject_id: "alice".to_string(),
            condition: None,
        }];

        let datastore = MockDatastore { tuples };
        let resolver = CoreResolver::new(datastore, StaticPolicyProvider::new(ts));

        let request = ResolveCheckRequest::new(
            "document".into(),
            "doc1".into(),
            "can_view".into(),
            "user".into(),
            "alice".into(),
        );

        let result = resolver.resolve_check(request).await.unwrap();
        assert_eq!(result, CheckResult::Allowed);
    }

    #[tokio::test]
    async fn test_contextual_tuples() {
        let dsl = "type document { relations define viewer: [user] }";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);

        let datastore = MockDatastore { tuples: vec![] };
        let resolver = CoreResolver::new(datastore, StaticPolicyProvider::new(ts));

        let mut request = ResolveCheckRequest::new(
            "document".into(),
            "doc1".into(),
            "viewer".into(),
            "user".into(),
            "alice".into(),
        );
        request.contextual_tuples = vec![Tuple {
            object_type: "document".to_string(),
            object_id: "doc1".to_string(),
            relation: "viewer".to_string(),
            subject_type: "user".to_string(),
            subject_id: "alice".to_string(),
            condition: None,
        }];

        let result = resolver.resolve_check(request).await.unwrap();
        assert_eq!(result, CheckResult::Allowed);
    }

    // --- Intersection resolver tests ---

    #[tokio::test]
    async fn test_intersection_both_allowed() {
        let dsl = "type document { relations define viewer: [user] define editor: [user] define can_view: viewer & editor }";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);

        let tuples = vec![
            Tuple {
                object_type: "document".to_string(),
                object_id: "doc1".to_string(),
                relation: "viewer".to_string(),
                subject_type: "user".to_string(),
                subject_id: "alice".to_string(),
                condition: None,
            },
            Tuple {
                object_type: "document".to_string(),
                object_id: "doc1".to_string(),
                relation: "editor".to_string(),
                subject_type: "user".to_string(),
                subject_id: "alice".to_string(),
                condition: None,
            },
        ];

        let datastore = MockDatastore { tuples };
        let resolver = CoreResolver::new(datastore, StaticPolicyProvider::new(ts));

        let request = ResolveCheckRequest::new(
            "document".into(),
            "doc1".into(),
            "can_view".into(),
            "user".into(),
            "alice".into(),
        );

        let result = resolver.resolve_check(request).await.unwrap();
        assert_eq!(result, CheckResult::Allowed);
    }

    #[tokio::test]
    async fn test_intersection_one_denied() {
        let dsl = "type document { relations define viewer: [user] define editor: [user] define can_view: viewer & editor }";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);

        let tuples = vec![Tuple {
            object_type: "document".to_string(),
            object_id: "doc1".to_string(),
            relation: "viewer".to_string(),
            subject_type: "user".to_string(),
            subject_id: "alice".to_string(),
            condition: None,
        }];

        let datastore = MockDatastore { tuples };
        let resolver = CoreResolver::new(datastore, StaticPolicyProvider::new(ts));

        let request = ResolveCheckRequest::new(
            "document".into(),
            "doc1".into(),
            "can_view".into(),
            "user".into(),
            "alice".into(),
        );

        let result = resolver.resolve_check(request).await.unwrap();
        assert_eq!(result, CheckResult::Denied);
    }

    #[tokio::test]
    async fn test_intersection_short_circuit_on_denied() {
        let dsl = "type document { relations define viewer: [user] define editor: [user] define can_view: viewer & editor }";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);

        let datastore = MockDatastore { tuples: vec![] };
        let resolver = CoreResolver::new(datastore, StaticPolicyProvider::new(ts));

        let request = ResolveCheckRequest::new(
            "document".into(),
            "doc1".into(),
            "can_view".into(),
            "user".into(),
            "alice".into(),
        );

        let result = resolver.resolve_check(request).await.unwrap();
        assert_eq!(result, CheckResult::Denied);
    }

    // --- Exclusion (but-not) resolver tests ---

    #[tokio::test]
    async fn test_exclusion_base_allowed_subtract_denied() {
        let dsl = "type document { relations define viewer: [user] define banned: [user] define can_view: viewer - banned }";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);

        let tuples = vec![Tuple {
            object_type: "document".to_string(),
            object_id: "doc1".to_string(),
            relation: "viewer".to_string(),
            subject_type: "user".to_string(),
            subject_id: "alice".to_string(),
            condition: None,
        }];

        let datastore = MockDatastore { tuples };
        let resolver = CoreResolver::new(datastore, StaticPolicyProvider::new(ts));

        let request = ResolveCheckRequest::new(
            "document".into(),
            "doc1".into(),
            "can_view".into(),
            "user".into(),
            "alice".into(),
        );

        let result = resolver.resolve_check(request).await.unwrap();
        assert_eq!(result, CheckResult::Allowed);
    }

    #[tokio::test]
    async fn test_exclusion_base_allowed_subtract_allowed() {
        let dsl = "type document { relations define viewer: [user] define banned: [user] define can_view: viewer - banned }";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);

        let tuples = vec![
            Tuple {
                object_type: "document".to_string(),
                object_id: "doc1".to_string(),
                relation: "viewer".to_string(),
                subject_type: "user".to_string(),
                subject_id: "alice".to_string(),
                condition: None,
            },
            Tuple {
                object_type: "document".to_string(),
                object_id: "doc1".to_string(),
                relation: "banned".to_string(),
                subject_type: "user".to_string(),
                subject_id: "alice".to_string(),
                condition: None,
            },
        ];

        let datastore = MockDatastore { tuples };
        let resolver = CoreResolver::new(datastore, StaticPolicyProvider::new(ts));

        let request = ResolveCheckRequest::new(
            "document".into(),
            "doc1".into(),
            "can_view".into(),
            "user".into(),
            "alice".into(),
        );

        let result = resolver.resolve_check(request).await.unwrap();
        assert_eq!(result, CheckResult::Denied);
    }

    #[tokio::test]
    async fn test_exclusion_base_denied() {
        let dsl = "type document { relations define viewer: [user] define banned: [user] define can_view: viewer - banned }";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);

        let datastore = MockDatastore { tuples: vec![] };
        let resolver = CoreResolver::new(datastore, StaticPolicyProvider::new(ts));

        let request = ResolveCheckRequest::new(
            "document".into(),
            "doc1".into(),
            "can_view".into(),
            "user".into(),
            "alice".into(),
        );

        let result = resolver.resolve_check(request).await.unwrap();
        assert_eq!(result, CheckResult::Denied);
    }

    // --- Tuple-to-userset (TTU) tests ---

    #[tokio::test]
    async fn test_ttu_single_parent() {
        let dsl = "type folder { relations define viewer: [user] } type document { relations define parent: [folder] define viewer: parent->viewer }";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);

        let tuples = vec![
            Tuple {
                object_type: "document".to_string(),
                object_id: "doc1".to_string(),
                relation: "parent".to_string(),
                subject_type: "folder".to_string(),
                subject_id: "root".to_string(),
                condition: None,
            },
            Tuple {
                object_type: "folder".to_string(),
                object_id: "root".to_string(),
                relation: "viewer".to_string(),
                subject_type: "user".to_string(),
                subject_id: "alice".to_string(),
                condition: None,
            },
        ];

        let datastore = MockDatastore { tuples };
        let resolver = CoreResolver::new(datastore, StaticPolicyProvider::new(ts));

        let request = ResolveCheckRequest::new(
            "document".into(),
            "doc1".into(),
            "viewer".into(),
            "user".into(),
            "alice".into(),
        );

        let result = resolver.resolve_check(request).await.unwrap();
        assert_eq!(result, CheckResult::Allowed);
    }

    #[tokio::test]
    async fn test_ttu_no_parent() {
        let dsl = "type folder { relations define viewer: [user] } type document { relations define parent: [folder] define viewer: parent->viewer }";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);

        let datastore = MockDatastore { tuples: vec![] };
        let resolver = CoreResolver::new(datastore, StaticPolicyProvider::new(ts));

        let request = ResolveCheckRequest::new(
            "document".into(),
            "doc1".into(),
            "viewer".into(),
            "user".into(),
            "alice".into(),
        );

        let result = resolver.resolve_check(request).await.unwrap();
        assert_eq!(result, CheckResult::Denied);
    }

    #[tokio::test]
    async fn test_ttu_multiple_parents() {
        let dsl = "type folder { relations define viewer: [user] } type document { relations define parent: [folder] define viewer: parent->viewer }";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);

        let tuples = vec![
            Tuple {
                object_type: "document".to_string(),
                object_id: "doc1".to_string(),
                relation: "parent".to_string(),
                subject_type: "folder".to_string(),
                subject_id: "folder1".to_string(),
                condition: None,
            },
            Tuple {
                object_type: "document".to_string(),
                object_id: "doc1".to_string(),
                relation: "parent".to_string(),
                subject_type: "folder".to_string(),
                subject_id: "folder2".to_string(),
                condition: None,
            },
            Tuple {
                object_type: "folder".to_string(),
                object_id: "folder2".to_string(),
                relation: "viewer".to_string(),
                subject_type: "user".to_string(),
                subject_id: "alice".to_string(),
                condition: None,
            },
        ];

        let datastore = MockDatastore { tuples };
        let resolver = CoreResolver::new(datastore, StaticPolicyProvider::new(ts));

        let request = ResolveCheckRequest::new(
            "document".into(),
            "doc1".into(),
            "viewer".into(),
            "user".into(),
            "alice".into(),
        );

        let result = resolver.resolve_check(request).await.unwrap();
        assert_eq!(result, CheckResult::Allowed);
    }

    // --- Wildcard subject matching tests ---

    #[tokio::test]
    async fn test_wildcard_match() {
        let dsl = "type document { relations define viewer: [user:*] }";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);

        let tuples = vec![Tuple {
            object_type: "document".to_string(),
            object_id: "doc1".to_string(),
            relation: "viewer".to_string(),
            subject_type: "user".to_string(),
            subject_id: "*".to_string(),
            condition: None,
        }];

        let datastore = MockDatastore { tuples };
        let resolver = CoreResolver::new(datastore, StaticPolicyProvider::new(ts));

        let request = ResolveCheckRequest::new(
            "document".into(),
            "doc1".into(),
            "viewer".into(),
            "user".into(),
            "alice".into(),
        );

        let result = resolver.resolve_check(request).await.unwrap();
        assert_eq!(result, CheckResult::Allowed);
    }

    #[tokio::test]
    async fn test_wildcard_wrong_type() {
        let dsl = "type document { relations define viewer: [user:*] }";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);

        let tuples = vec![Tuple {
            object_type: "document".to_string(),
            object_id: "doc1".to_string(),
            relation: "viewer".to_string(),
            subject_type: "user".to_string(),
            subject_id: "*".to_string(),
            condition: None,
        }];

        let datastore = MockDatastore { tuples };
        let resolver = CoreResolver::new(datastore, StaticPolicyProvider::new(ts));

        let request = ResolveCheckRequest::new(
            "document".into(),
            "doc1".into(),
            "viewer".into(),
            "employee".into(),
            "alice".into(),
        );

        let result = resolver.resolve_check(request).await.unwrap();
        assert_eq!(result, CheckResult::Denied);
    }

    // --- Userset expansion tests ---

    #[tokio::test]
    async fn test_userset_expansion() {
        let dsl = "type group { relations define member: [user] } type document { relations define viewer: [group#member] }";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);

        let tuples = vec![
            Tuple {
                object_type: "document".to_string(),
                object_id: "doc1".to_string(),
                relation: "viewer".to_string(),
                subject_type: "group".to_string(),
                subject_id: "eng".to_string(),
                condition: None,
            },
            Tuple {
                object_type: "group".to_string(),
                object_id: "eng".to_string(),
                relation: "member".to_string(),
                subject_type: "user".to_string(),
                subject_id: "alice".to_string(),
                condition: None,
            },
        ];

        let datastore = MockDatastore { tuples };
        let resolver = CoreResolver::new(datastore, StaticPolicyProvider::new(ts));

        let request = ResolveCheckRequest::new(
            "document".into(),
            "doc1".into(),
            "viewer".into(),
            "user".into(),
            "alice".into(),
        );

        let result = resolver.resolve_check(request).await.unwrap();
        assert_eq!(result, CheckResult::Allowed);
    }

    #[tokio::test]
    async fn test_userset_expansion_no_member() {
        let dsl = "type group { relations define member: [user] } type document { relations define viewer: [group#member] }";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);

        let tuples = vec![Tuple {
            object_type: "document".to_string(),
            object_id: "doc1".to_string(),
            relation: "viewer".to_string(),
            subject_type: "group".to_string(),
            subject_id: "eng".to_string(),
            condition: None,
        }];

        let datastore = MockDatastore { tuples };
        let resolver = CoreResolver::new(datastore, StaticPolicyProvider::new(ts));

        let request = ResolveCheckRequest::new(
            "document".into(),
            "doc1".into(),
            "viewer".into(),
            "user".into(),
            "alice".into(),
        );

        let result = resolver.resolve_check(request).await.unwrap();
        assert_eq!(result, CheckResult::Denied);
    }

    // --- Conditional test ---

    #[tokio::test]
    async fn test_conditional_returns_condition_required() {
        let dsl = "type document { relations define viewer: [user with ip_check] } condition ip_check(ip: string) { ip == \"127.0.0.1\" }";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);

        let tuples = vec![Tuple {
            object_type: "document".to_string(),
            object_id: "doc1".to_string(),
            relation: "viewer".to_string(),
            subject_type: "user".to_string(),
            subject_id: "alice".to_string(),
            condition: Some("ip_check".to_string()),
        }];

        let datastore = MockDatastore { tuples };
        let resolver = CoreResolver::new(datastore, StaticPolicyProvider::new(ts));

        let request = ResolveCheckRequest::new(
            "document".into(),
            "doc1".into(),
            "viewer".into(),
            "user".into(),
            "alice".into(),
        );

        let result = resolver.resolve_check(request).await.unwrap();
        assert_eq!(
            result,
            CheckResult::ConditionRequired(vec!["ip_check".to_string()])
        );
    }

    // --- L2 result cache tests ---

    #[tokio::test]
    async fn test_result_cache_hit() {
        let dsl = "type document { relations define viewer: [user] }";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);

        let tuples = vec![Tuple {
            object_type: "document".to_string(),
            object_id: "doc1".to_string(),
            relation: "viewer".to_string(),
            subject_type: "user".to_string(),
            subject_id: "alice".to_string(),
            condition: None,
        }];

        let datastore = MockDatastore { tuples };
        let resolver = CoreResolver::new(datastore, StaticPolicyProvider::new(ts));

        let request = ResolveCheckRequest::new(
            "document".into(),
            "doc1".into(),
            "viewer".into(),
            "user".into(),
            "alice".into(),
        );

        let result1 = resolver.resolve_check(request.clone()).await.unwrap();
        let result2 = resolver.resolve_check(request).await.unwrap();

        assert_eq!(result1, CheckResult::Allowed);
        assert_eq!(result2, CheckResult::Allowed);
    }

    #[tokio::test]
    async fn test_result_cache_bypass_with_contextual_tuples() {
        let dsl = "type document { relations define viewer: [user] }";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);

        let datastore = MockDatastore { tuples: vec![] };
        let resolver = CoreResolver::new(datastore, StaticPolicyProvider::new(ts));

        let mut request = ResolveCheckRequest::new(
            "document".into(),
            "doc1".into(),
            "viewer".into(),
            "user".into(),
            "alice".into(),
        );
        request.contextual_tuples = vec![Tuple {
            object_type: "document".to_string(),
            object_id: "doc1".to_string(),
            relation: "viewer".to_string(),
            subject_type: "user".to_string(),
            subject_id: "alice".to_string(),
            condition: None,
        }];

        let result = resolver.resolve_check(request).await.unwrap();
        assert_eq!(result, CheckResult::Allowed);
    }

    #[tokio::test]
    async fn test_result_cache_key_differs_for_different_subjects() {
        let dsl = "type document { relations define viewer: [user] }";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);

        let tuples = vec![Tuple {
            object_type: "document".to_string(),
            object_id: "doc1".to_string(),
            relation: "viewer".to_string(),
            subject_type: "user".to_string(),
            subject_id: "alice".to_string(),
            condition: None,
        }];

        let datastore = MockDatastore { tuples };
        let resolver = CoreResolver::new(datastore, StaticPolicyProvider::new(ts));

        let request_alice = ResolveCheckRequest::new(
            "document".into(),
            "doc1".into(),
            "viewer".into(),
            "user".into(),
            "alice".into(),
        );
        let request_bob = ResolveCheckRequest::new(
            "document".into(),
            "doc1".into(),
            "viewer".into(),
            "user".into(),
            "bob".into(),
        );

        let result_alice = resolver.resolve_check(request_alice).await.unwrap();
        let result_bob = resolver.resolve_check(request_bob).await.unwrap();

        assert_eq!(result_alice, CheckResult::Allowed);
        assert_eq!(result_bob, CheckResult::Denied);
    }

    // --- L3 tuple cache tests ---

    #[tokio::test]
    async fn test_tuple_cache_hit() {
        let dsl = "type document { relations define viewer: [user] }";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);

        let tuples = vec![Tuple {
            object_type: "document".to_string(),
            object_id: "doc1".to_string(),
            relation: "viewer".to_string(),
            subject_type: "user".to_string(),
            subject_id: "alice".to_string(),
            condition: None,
        }];

        let datastore = MockDatastore { tuples };
        let resolver = CoreResolver::new(datastore, StaticPolicyProvider::new(ts));

        let request = ResolveCheckRequest::new(
            "document".into(),
            "doc1".into(),
            "viewer".into(),
            "user".into(),
            "alice".into(),
        );

        let _result1 = resolver.resolve_check(request.clone()).await.unwrap();
        let result2 = resolver.resolve_check(request).await.unwrap();

        assert_eq!(result2, CheckResult::Allowed);
    }

    #[tokio::test]
    async fn test_tuple_cache_bypass_with_contextual() {
        let dsl = "type document { relations define viewer: [user] }";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);

        let datastore = MockDatastore { tuples: vec![] };
        let resolver = CoreResolver::new(datastore, StaticPolicyProvider::new(ts));

        let mut request = ResolveCheckRequest::new(
            "document".into(),
            "doc1".into(),
            "viewer".into(),
            "user".into(),
            "alice".into(),
        );
        request.contextual_tuples = vec![Tuple {
            object_type: "document".to_string(),
            object_id: "doc1".to_string(),
            relation: "viewer".to_string(),
            subject_type: "user".to_string(),
            subject_id: "alice".to_string(),
            condition: None,
        }];

        let result = resolver.resolve_check(request).await.unwrap();
        assert_eq!(result, CheckResult::Allowed);
    }

    // --- Error path test ---

    #[tokio::test]
    async fn test_unknown_relation_returns_error() {
        let dsl = "type document { relations define viewer: [user] }";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);

        let datastore = MockDatastore { tuples: vec![] };
        let resolver = CoreResolver::new(datastore, StaticPolicyProvider::new(ts));

        let request = ResolveCheckRequest::new(
            "document".into(),
            "doc1".into(),
            "unknown_relation".into(),
            "user".into(),
            "alice".into(),
        );

        let result = resolver.resolve_check(request).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AuthzError::RelationNotFound { .. }
        ));
    }
}
