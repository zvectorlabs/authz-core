//! Model semantic validation — checks for duplicate types, undefined relations, cycles, etc.

use crate::model_ast::{AssignableTarget, ModelFile, RelationExpr};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy, PartialEq, Eq)]
enum VisitState {
    Unvisited,
    Visiting,
    Visited,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationCategory {
    DuplicateType,
    DuplicateRelation,
    UndefinedRelation,
    UndefinedType,
    UndefinedCondition,
    CycleDetected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    pub category: ValidationCategory,
    pub message: String,
}

fn check_computed_userset_cycles(model: &ModelFile, errors: &mut Vec<ValidationError>) {
    for type_def in &model.type_defs {
        let graph = build_relation_dependency_graph(type_def);

        let mut state: HashMap<String, VisitState> = graph
            .keys()
            .map(|k| (k.clone(), VisitState::Unvisited))
            .collect();

        for relation in graph.keys() {
            if state.get(relation) == Some(&VisitState::Unvisited) {
                let mut stack = Vec::new();
                detect_cycle_dfs(type_def, relation, &graph, &mut state, &mut stack, errors);
            }
        }
    }
}

fn build_relation_dependency_graph(
    type_def: &crate::model_ast::TypeDef,
) -> HashMap<String, Vec<String>> {
    let mut graph = HashMap::new();

    for relation in &type_def.relations {
        let deps = extract_computed_userset_dependencies(&relation.expression);
        graph.insert(relation.name.clone(), deps);
    }

    graph
}

fn extract_computed_userset_dependencies(expr: &RelationExpr) -> Vec<String> {
    match expr {
        RelationExpr::ComputedUserset(relation_name) => vec![relation_name.clone()],
        RelationExpr::Union(exprs) | RelationExpr::Intersection(exprs) => exprs
            .iter()
            .flat_map(extract_computed_userset_dependencies)
            .collect(),
        RelationExpr::Exclusion { base, subtract } => {
            let mut deps = extract_computed_userset_dependencies(base);
            deps.extend(extract_computed_userset_dependencies(subtract));
            deps
        }
        RelationExpr::DirectAssignment(_) | RelationExpr::TupleToUserset { .. } => Vec::new(),
    }
}

fn detect_cycle_dfs(
    type_def: &crate::model_ast::TypeDef,
    relation: &str,
    graph: &HashMap<String, Vec<String>>,
    state: &mut HashMap<String, VisitState>,
    stack: &mut Vec<String>,
    errors: &mut Vec<ValidationError>,
) {
    state.insert(relation.to_string(), VisitState::Visiting);
    stack.push(relation.to_string());

    if let Some(neighbors) = graph.get(relation) {
        for next in neighbors {
            // Ignore unresolved relation names here; undefined relation checks handle them.
            if !graph.contains_key(next) {
                continue;
            }

            let next_state = state.get(next).copied();
            if next_state == Some(VisitState::Visiting) {
                if let Some(start_idx) = stack.iter().position(|r| r == next) {
                    let mut cycle_nodes = stack[start_idx..].to_vec();
                    cycle_nodes.push(next.clone());
                    let cycle_path = cycle_nodes
                        .iter()
                        .map(|r| format!("{}#{}", type_def.name, r))
                        .collect::<Vec<_>>()
                        .join(" -> ");
                    errors.push(ValidationError::new(
                        ValidationCategory::CycleDetected,
                        format!("Cycle detected in computed usersets: {}", cycle_path),
                    ));
                }
                continue;
            }

            if next_state != Some(VisitState::Visited) {
                detect_cycle_dfs(type_def, next, graph, state, stack, errors);
            }
        }
    }

    stack.pop();
    state.insert(relation.to_string(), VisitState::Visited);
}

impl ValidationError {
    fn new(category: ValidationCategory, message: impl Into<String>) -> Self {
        Self {
            category,
            message: message.into(),
        }
    }
}

/// Validate a parsed model for semantic correctness.
/// Returns Ok(()) if valid, or Err with a list of validation errors.
pub fn validate_model(model: &ModelFile) -> Result<(), Vec<ValidationError>> {
    let mut errors = Vec::new();

    // Check for duplicate type names
    check_duplicate_types(model, &mut errors);

    // Check for duplicate relation names within each type
    check_duplicate_relations(model, &mut errors);

    // Check for undefined relations in computed usersets and TTU
    check_undefined_relations(model, &mut errors);

    // Check for undefined types in direct assignments
    check_undefined_types(model, &mut errors);

    // Check for undefined condition references
    check_undefined_conditions(model, &mut errors);

    // Check for cycles in computed usersets
    check_computed_userset_cycles(model, &mut errors);

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn check_duplicate_types(model: &ModelFile, errors: &mut Vec<ValidationError>) {
    let mut seen = HashSet::new();
    for type_def in &model.type_defs {
        if !seen.insert(&type_def.name) {
            errors.push(ValidationError::new(
                ValidationCategory::DuplicateType,
                format!("Duplicate type definition: '{}'", type_def.name),
            ));
        }
    }
}

fn check_duplicate_relations(model: &ModelFile, errors: &mut Vec<ValidationError>) {
    for type_def in &model.type_defs {
        let mut seen = HashSet::new();
        for relation in &type_def.relations {
            if !seen.insert(&relation.name) {
                errors.push(ValidationError::new(
                    ValidationCategory::DuplicateRelation,
                    format!(
                        "Duplicate relation '{}' in type '{}'",
                        relation.name, type_def.name
                    ),
                ));
            }
        }
    }
}

fn check_undefined_relations(model: &ModelFile, errors: &mut Vec<ValidationError>) {
    // Build a map of type -> set of relation names
    let type_relations: HashMap<&str, HashSet<&str>> = model
        .type_defs
        .iter()
        .map(|t| {
            let relations: HashSet<&str> = t.relations.iter().map(|r| r.name.as_str()).collect();
            (t.name.as_str(), relations)
        })
        .collect();

    for type_def in &model.type_defs {
        for relation in &type_def.relations {
            check_expr_for_undefined_relations(
                &relation.expression,
                &type_def.name,
                &type_relations,
                errors,
            );
        }
    }
}

fn check_expr_for_undefined_relations(
    expr: &RelationExpr,
    current_type: &str,
    type_relations: &HashMap<&str, HashSet<&str>>,
    errors: &mut Vec<ValidationError>,
) {
    match expr {
        RelationExpr::ComputedUserset(relation_name) => {
            if let Some(relations) = type_relations.get(current_type)
                && !relations.contains(relation_name.as_str())
            {
                errors.push(ValidationError::new(
                    ValidationCategory::UndefinedRelation,
                    format!(
                        "Undefined relation '{}' in computed userset for type '{}'",
                        relation_name, current_type
                    ),
                ));
            }
        }
        RelationExpr::TupleToUserset {
            computed_userset: _,
            tupleset,
        } => {
            // Check that tupleset relation exists on current type
            if let Some(relations) = type_relations.get(current_type)
                && !relations.contains(tupleset.as_str())
            {
                errors.push(ValidationError::new(
                    ValidationCategory::UndefinedRelation,
                    format!(
                        "Undefined relation '{}' in tuple-to-userset tupleset for type '{}'",
                        tupleset, current_type
                    ),
                ));
            }
            // Note: We can't validate computed_userset here without knowing the target type
            // That would require full type resolution (Phase 3)
        }
        RelationExpr::Union(exprs) | RelationExpr::Intersection(exprs) => {
            for e in exprs {
                check_expr_for_undefined_relations(e, current_type, type_relations, errors);
            }
        }
        RelationExpr::Exclusion { base, subtract } => {
            check_expr_for_undefined_relations(base, current_type, type_relations, errors);
            check_expr_for_undefined_relations(subtract, current_type, type_relations, errors);
        }
        RelationExpr::DirectAssignment(_) => {
            // Handled by check_undefined_types
        }
    }
}

fn check_undefined_types(model: &ModelFile, errors: &mut Vec<ValidationError>) {
    let type_names: HashSet<&str> = model.type_defs.iter().map(|t| t.name.as_str()).collect();

    for type_def in &model.type_defs {
        for relation in &type_def.relations {
            check_expr_for_undefined_types(
                &relation.expression,
                &type_names,
                &type_def.name,
                &relation.name,
                errors,
            );
        }
    }
}

fn check_expr_for_undefined_types(
    expr: &RelationExpr,
    type_names: &HashSet<&str>,
    current_type: &str,
    relation_name: &str,
    errors: &mut Vec<ValidationError>,
) {
    match expr {
        RelationExpr::DirectAssignment(targets) => {
            for target in targets {
                check_target_for_undefined_types(
                    target,
                    type_names,
                    current_type,
                    relation_name,
                    errors,
                );
            }
        }
        RelationExpr::Union(exprs) | RelationExpr::Intersection(exprs) => {
            for e in exprs {
                check_expr_for_undefined_types(e, type_names, current_type, relation_name, errors);
            }
        }
        RelationExpr::Exclusion { base, subtract } => {
            check_expr_for_undefined_types(base, type_names, current_type, relation_name, errors);
            check_expr_for_undefined_types(
                subtract,
                type_names,
                current_type,
                relation_name,
                errors,
            );
        }
        RelationExpr::ComputedUserset(_) | RelationExpr::TupleToUserset { .. } => {
            // No type references to check
        }
    }
}

fn check_target_for_undefined_types(
    target: &AssignableTarget,
    type_names: &HashSet<&str>,
    current_type: &str,
    relation_name: &str,
    errors: &mut Vec<ValidationError>,
) {
    let is_known_type = |type_name: &str| type_name == "user" || type_names.contains(type_name);

    match target {
        AssignableTarget::Type(type_name) | AssignableTarget::Wildcard(type_name) => {
            if !is_known_type(type_name.as_str()) {
                errors.push(ValidationError::new(
                    ValidationCategory::UndefinedType,
                    format!(
                        "Undefined type '{}' in relation '{}' of type '{}'",
                        type_name, relation_name, current_type
                    ),
                ));
            }
        }
        AssignableTarget::Userset { type_name, .. } => {
            if !is_known_type(type_name.as_str()) {
                errors.push(ValidationError::new(
                    ValidationCategory::UndefinedType,
                    format!(
                        "Undefined type '{}' in userset for relation '{}' of type '{}'",
                        type_name, relation_name, current_type
                    ),
                ));
            }
        }
        AssignableTarget::Conditional { target, .. } => {
            check_target_for_undefined_types(
                target,
                type_names,
                current_type,
                relation_name,
                errors,
            );
        }
    }
}

fn check_undefined_conditions(model: &ModelFile, errors: &mut Vec<ValidationError>) {
    let condition_names: HashSet<&str> = model
        .condition_defs
        .iter()
        .map(|c| c.name.as_str())
        .collect();

    for type_def in &model.type_defs {
        for relation in &type_def.relations {
            check_expr_for_undefined_conditions(
                &relation.expression,
                &condition_names,
                &type_def.name,
                &relation.name,
                errors,
            );
        }
    }
}

fn check_expr_for_undefined_conditions(
    expr: &RelationExpr,
    condition_names: &HashSet<&str>,
    current_type: &str,
    relation_name: &str,
    errors: &mut Vec<ValidationError>,
) {
    match expr {
        RelationExpr::DirectAssignment(targets) => {
            for target in targets {
                check_target_for_undefined_conditions(
                    target,
                    condition_names,
                    current_type,
                    relation_name,
                    errors,
                );
            }
        }
        RelationExpr::Union(exprs) | RelationExpr::Intersection(exprs) => {
            for e in exprs {
                check_expr_for_undefined_conditions(
                    e,
                    condition_names,
                    current_type,
                    relation_name,
                    errors,
                );
            }
        }
        RelationExpr::Exclusion { base, subtract } => {
            check_expr_for_undefined_conditions(
                base,
                condition_names,
                current_type,
                relation_name,
                errors,
            );
            check_expr_for_undefined_conditions(
                subtract,
                condition_names,
                current_type,
                relation_name,
                errors,
            );
        }
        RelationExpr::ComputedUserset(_) | RelationExpr::TupleToUserset { .. } => {
            // No condition references
        }
    }
}

fn check_target_for_undefined_conditions(
    target: &AssignableTarget,
    condition_names: &HashSet<&str>,
    current_type: &str,
    relation_name: &str,
    errors: &mut Vec<ValidationError>,
) {
    if let AssignableTarget::Conditional { target, condition } = target {
        if !condition_names.contains(condition.as_str()) {
            errors.push(ValidationError::new(
                ValidationCategory::UndefinedCondition,
                format!(
                    "Undefined condition '{}' in relation '{}' of type '{}'",
                    condition, relation_name, current_type
                ),
            ));
        }
        // Recursively check nested target
        check_target_for_undefined_conditions(
            target,
            condition_names,
            current_type,
            relation_name,
            errors,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model_parser::parse_dsl;

    #[test]
    fn test_reject_duplicate_type_names() {
        let dsl = r#"
            type user {}
            type user {}
        "#;
        let model = parse_dsl(dsl).unwrap();
        let result = validate_model(&model);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert_eq!(errors.len(), 1);
        assert!(
            errors[0]
                .message
                .contains("Duplicate type definition: 'user'")
        );
    }

    #[test]
    fn test_reject_undefined_relation_in_computed_userset() {
        let dsl = r#"
            type document {
                relations
                    define viewer: editors
            }
        "#;
        let model = parse_dsl(dsl).unwrap();
        let result = validate_model(&model);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.message.contains("Undefined relation 'editors'"))
        );
    }

    #[test]
    fn test_reject_undefined_relation_in_ttu() {
        let dsl = r#"
            type document {
                relations
                    define viewer: parents->viewer
            }
        "#;
        let model = parse_dsl(dsl).unwrap();
        let result = validate_model(&model);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.message.contains("Undefined relation 'parents'"))
        );
    }

    #[test]
    fn test_reject_undefined_type_in_direct_assignment() {
        let dsl = r#"
            type document {
                relations
                    define viewer: [nonexistent]
            }
        "#;
        let model = parse_dsl(dsl).unwrap();
        let result = validate_model(&model);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.message.contains("Undefined type 'nonexistent'"))
        );
    }

    #[test]
    fn test_reject_invalid_condition_reference() {
        let dsl = r#"
            type document {
                relations
                    define viewer: [user with unknown_cond]
            }
        "#;
        let model = parse_dsl(dsl).unwrap();
        let result = validate_model(&model);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.message.contains("Undefined condition 'unknown_cond'"))
        );
    }

    #[test]
    fn test_reject_duplicate_relation_names() {
        let dsl = r#"
            type document {
                relations
                    define viewer: [user]
                    define viewer: [user]
            }
        "#;
        let model = parse_dsl(dsl).unwrap();
        let result = validate_model(&model);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.message.contains("Duplicate relation 'viewer'"))
        );
    }

    #[test]
    fn test_valid_complex_model_passes() {
        let dsl = r#"
            type user {}
            
            type folder {
                relations
                    define parent: [folder]
                    define owner: [user]
                    define viewer: [user]
            }
            
            type document {
                relations
                    define parent: [folder]
                    define owner: [user]
                    define viewer: [user]
                    define can_view: viewer + owner + parent->can_view
            }
            
            condition ip_check(ip: string) {
                ip == "127.0.0.1"
            }
        "#;
        let model = parse_dsl(dsl).unwrap();
        let result = validate_model(&model);
        assert!(
            result.is_ok(),
            "Expected valid model to pass, got: {:?}",
            result
        );
    }

    #[test]
    fn test_reject_self_cycle_in_computed_userset() {
        let dsl = r#"
            type document {
                relations
                    define viewer: viewer
            }
        "#;
        let model = parse_dsl(dsl).unwrap();
        let result = validate_model(&model);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.message.contains("Cycle detected in computed usersets"))
        );
    }

    #[test]
    fn test_reject_two_node_cycle_in_computed_userset() {
        let dsl = r#"
            type document {
                relations
                    define viewer: editor
                    define editor: viewer
            }
        "#;
        let model = parse_dsl(dsl).unwrap();
        let result = validate_model(&model);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.message.contains("Cycle detected in computed usersets"))
        );
    }

    #[test]
    fn test_accept_acyclic_computed_userset_chain() {
        let dsl = r#"
            type document {
                relations
                    define owner: [user]
                    define editor: owner
                    define viewer: editor
            }

            type user {}
        "#;
        let model = parse_dsl(dsl).unwrap();
        let result = validate_model(&model);
        assert!(
            result.is_ok(),
            "Expected acyclic model to pass, got: {:?}",
            result
        );
    }
}
