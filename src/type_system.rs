//! TypeSystem — in-memory representation of a parsed authorization model.
//! Provides query methods for type/relation lookups and tuple validation.

use crate::model_ast::{
    AssignableTarget, ConditionDef, ModelFile, RelationDef, RelationExpr, TypeDef,
};
use crate::traits::Tuple;

/// TypeSystem wraps a parsed ModelFile and provides query methods.
#[derive(Debug, Clone)]
pub struct TypeSystem {
    model: ModelFile,
}

impl TypeSystem {
    /// Create a new TypeSystem from a parsed ModelFile.
    pub fn new(model: ModelFile) -> Self {
        Self { model }
    }

    /// Get all type definitions.
    pub fn get_all_types(&self) -> &[TypeDef] {
        &self.model.type_defs
    }

    /// Get a type definition by name.
    pub fn get_type(&self, name: &str) -> Option<&TypeDef> {
        self.model.type_defs.iter().find(|t| t.name == name)
    }

    /// Get a relation definition on a specific type.
    /// Searches both relations and permissions (since permissions are also relations for lookup purposes).
    pub fn get_relation(&self, type_name: &str, relation: &str) -> Option<&RelationDef> {
        let type_def = self.get_type(type_name)?;

        // First search in relations
        if let Some(relation_def) = type_def.relations.iter().find(|r| r.name == relation) {
            return Some(relation_def);
        }

        // Then search in permissions
        type_def.permissions.iter().find(|p| p.name == relation)
    }

    /// Check if a relation name is a permission (not a relation) on a specific type.
    pub fn is_permission(&self, type_name: &str, relation: &str) -> bool {
        let type_def = match self.get_type(type_name) {
            Some(t) => t,
            None => return false,
        };

        type_def.permissions.iter().any(|p| p.name == relation)
    }

    /// Look up a condition definition by name.
    pub fn get_condition(&self, name: &str) -> Option<&ConditionDef> {
        self.model.condition_defs.iter().find(|c| c.name == name)
    }

    /// Get the directly related types for a relation (types that can be assigned).
    /// Returns all AssignableTargets found in DirectAssignment expressions.
    pub fn get_directly_related_types(
        &self,
        type_name: &str,
        relation: &str,
    ) -> Vec<AssignableTarget> {
        let relation_def = match self.get_relation(type_name, relation) {
            Some(r) => r,
            None => return Vec::new(),
        };

        extract_assignable_targets(&relation_def.expression)
    }

    /// Validate a tuple against the model.
    /// Returns Ok(()) if valid, Err(message) if invalid.
    pub fn is_valid_tuple(&self, tuple: &Tuple) -> Result<(), String> {
        // Check if the object type exists
        let type_def = self.get_type(&tuple.object_type).ok_or_else(|| {
            format!(
                "object_type '{}' not defined in authorization model",
                tuple.object_type
            )
        })?;

        // Check if the relation exists on this type
        let relation_def = type_def
            .relations
            .iter()
            .find(|r| r.name == tuple.relation)
            .ok_or_else(|| {
                format!(
                    "relation '{}' not defined for type '{}' in authorization model",
                    tuple.relation, tuple.object_type
                )
            })?;

        // Get allowed subject types from the relation expression
        let allowed_targets = extract_assignable_targets(&relation_def.expression);

        // If the relation is a computed userset or TTU (no direct assignments), allow any subject
        if allowed_targets.is_empty() {
            return Ok(());
        }

        // Check if the subject_type is in the allowed list
        let subject_allowed = allowed_targets.iter().any(|target| match target {
            AssignableTarget::Type(type_name) => type_name == &tuple.subject_type,
            AssignableTarget::Userset { type_name, .. } => type_name == &tuple.subject_type,
            AssignableTarget::Wildcard(type_name) => type_name == &tuple.subject_type,
            AssignableTarget::Conditional { target, .. } => match target.as_ref() {
                AssignableTarget::Type(type_name) => type_name == &tuple.subject_type,
                _ => false,
            },
        });

        if !subject_allowed {
            let allowed_type_names: Vec<String> = allowed_targets
                .iter()
                .map(|t| match t {
                    AssignableTarget::Type(name) => name.clone(),
                    AssignableTarget::Userset {
                        type_name,
                        relation,
                    } => {
                        format!("{}#{}", type_name, relation)
                    }
                    AssignableTarget::Wildcard(name) => format!("{}:*", name),
                    AssignableTarget::Conditional { target, condition } => match target.as_ref() {
                        AssignableTarget::Type(name) => format!("{} with {}", name, condition),
                        _ => "conditional".to_string(),
                    },
                })
                .collect();

            return Err(format!(
                "subject_type '{}' not allowed for relation '{}' on type '{}'. Allowed types: {:?}",
                tuple.subject_type, tuple.relation, tuple.object_type, allowed_type_names
            ));
        }

        Ok(())
    }
}

/// Extract all AssignableTargets from a RelationExpr (recursively).
fn extract_assignable_targets(expr: &RelationExpr) -> Vec<AssignableTarget> {
    match expr {
        RelationExpr::DirectAssignment(targets) => targets.clone(),
        RelationExpr::Union(exprs) => exprs.iter().flat_map(extract_assignable_targets).collect(),
        RelationExpr::Intersection(exprs) => {
            exprs.iter().flat_map(extract_assignable_targets).collect()
        }
        RelationExpr::Exclusion { base, .. } => extract_assignable_targets(base),
        RelationExpr::ComputedUserset(_) | RelationExpr::TupleToUserset { .. } => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model_parser::parse_dsl;

    #[test]
    fn test_get_type_found() {
        let dsl = "type user {}";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);
        assert!(ts.get_type("user").is_some());
    }

    #[test]
    fn test_get_type_not_found() {
        let dsl = "type user {}";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);
        assert!(ts.get_type("document").is_none());
    }

    #[test]
    fn test_get_relation_found() {
        let dsl = "type document { relations define viewer: [user] }";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);
        assert!(ts.get_relation("document", "viewer").is_some());
    }

    #[test]
    fn test_get_relation_not_found() {
        let dsl = "type document { relations define viewer: [user] }";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);
        assert!(ts.get_relation("document", "editor").is_none());
    }

    #[test]
    fn test_get_directly_related_types() {
        let dsl = "type document { relations define viewer: [user] }";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);
        let targets = ts.get_directly_related_types("document", "viewer");
        assert_eq!(targets.len(), 1);
        assert!(matches!(targets[0], AssignableTarget::Type(ref name) if name == "user"));
    }

    #[test]
    fn test_get_directly_related_userset() {
        let dsl = "type document { relations define viewer: [group#member] }";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);
        let targets = ts.get_directly_related_types("document", "viewer");
        assert_eq!(targets.len(), 1);
        assert!(matches!(
            targets[0],
            AssignableTarget::Userset { ref type_name, ref relation }
            if type_name == "group" && relation == "member"
        ));
    }

    #[test]
    fn test_is_valid_tuple_ok() {
        let dsl = "type document { relations define viewer: [user] }";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);
        let tuple = Tuple {
            object_type: "document".to_string(),
            object_id: "doc1".to_string(),
            relation: "viewer".to_string(),
            subject_type: "user".to_string(),
            subject_id: "alice".to_string(),
            condition: None,
        };
        assert!(ts.is_valid_tuple(&tuple).is_ok());
    }

    #[test]
    fn test_is_valid_tuple_bad_object_type() {
        let dsl = "type document { relations define viewer: [user] }";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);
        let tuple = Tuple {
            object_type: "folder".to_string(),
            object_id: "folder1".to_string(),
            relation: "viewer".to_string(),
            subject_type: "user".to_string(),
            subject_id: "alice".to_string(),
            condition: None,
        };
        let result = ts.is_valid_tuple(&tuple);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("object_type 'folder' not defined")
        );
    }

    #[test]
    fn test_is_valid_tuple_bad_relation() {
        let dsl = "type document { relations define viewer: [user] }";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);
        let tuple = Tuple {
            object_type: "document".to_string(),
            object_id: "doc1".to_string(),
            relation: "editor".to_string(),
            subject_type: "user".to_string(),
            subject_id: "alice".to_string(),
            condition: None,
        };
        let result = ts.is_valid_tuple(&tuple);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("relation 'editor' not defined for type 'document'")
        );
    }

    #[test]
    fn test_is_valid_tuple_bad_subject_type() {
        let dsl = "type document { relations define viewer: [user] }";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);
        let tuple = Tuple {
            object_type: "document".to_string(),
            object_id: "doc1".to_string(),
            relation: "viewer".to_string(),
            subject_type: "group".to_string(),
            subject_id: "admins".to_string(),
            condition: None,
        };
        let result = ts.is_valid_tuple(&tuple);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("subject_type 'group' not allowed")
        );
    }

    #[test]
    fn test_is_valid_tuple_computed_userset_allows_any() {
        let dsl = "type document { relations define can_view: viewer }";
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);
        let tuple = Tuple {
            object_type: "document".to_string(),
            object_id: "doc1".to_string(),
            relation: "can_view".to_string(),
            subject_type: "user".to_string(),
            subject_id: "alice".to_string(),
            condition: None,
        };
        // ComputedUserset has no direct assignments, so any subject is allowed
        assert!(ts.is_valid_tuple(&tuple).is_ok());
    }

    #[test]
    fn test_is_permission() {
        let dsl = r#"
            type document {
                relations
                    define owner: [user]
                    define editor: [user]
                permissions
                    define view = owner
                    define edit = editor + owner
            }
        "#;
        let model = parse_dsl(dsl).unwrap();
        let ts = TypeSystem::new(model);

        // Test relations
        assert!(!ts.is_permission("document", "owner"));
        assert!(!ts.is_permission("document", "editor"));

        // Test permissions
        assert!(ts.is_permission("document", "view"));
        assert!(ts.is_permission("document", "edit"));

        // Test non-existent relations
        assert!(!ts.is_permission("document", "nonexistent"));
        assert!(!ts.is_permission("nonexistent_type", "view"));
    }
}
