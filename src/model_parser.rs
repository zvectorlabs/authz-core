//! Parser for the authorization model DSL.

use crate::model_ast::{
    AssignableTarget, ConditionDef, ConditionParam, ModelFile, RelationDef, RelationExpr, TypeDef,
};
use pest::Parser;
use pest::iterators::Pair;
use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "model.pest"]
pub struct ModelParser;

/// Parses the authorization model DSL into an AST.
pub fn parse_dsl(dsl: &str) -> Result<ModelFile, pest::error::Error<Rule>> {
    let mut pairs = ModelParser::parse(Rule::file, dsl)?;
    let file = pairs.next().expect("parser should return file root");
    let mut type_defs = Vec::new();
    let mut condition_defs = Vec::new();

    for pair in file.into_inner() {
        match pair.as_rule() {
            Rule::type_def => type_defs.push(build_type_def(pair)?),
            Rule::condition_def => condition_defs.push(build_condition_def(pair)?),
            Rule::EOI => (),
            _ => unreachable!("Unexpected rule: {:?}", pair.as_rule()),
        }
    }

    Ok(ModelFile {
        type_defs,
        condition_defs,
    })
}

fn build_type_def(pair: Pair<Rule>) -> Result<TypeDef, pest::error::Error<Rule>> {
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let mut relations = Vec::new();
    let mut permissions = Vec::new();

    for pair in inner {
        match pair.as_rule() {
            Rule::relations_block => relations = build_relations_block(pair)?,
            Rule::permissions_block => permissions = build_permissions_block(pair)?,
            _ => {}
        }
    }

    Ok(TypeDef {
        name,
        relations,
        permissions,
    })
}

fn build_relations_block(pair: Pair<Rule>) -> Result<Vec<RelationDef>, pest::error::Error<Rule>> {
    pair.into_inner().map(build_relation_def).collect()
}

fn build_permissions_block(pair: Pair<Rule>) -> Result<Vec<RelationDef>, pest::error::Error<Rule>> {
    pair.into_inner().map(build_permission_def).collect()
}

fn build_relation_def(pair: Pair<Rule>) -> Result<RelationDef, pest::error::Error<Rule>> {
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let expression = build_relation_expr(inner.next().unwrap())?;
    Ok(RelationDef { name, expression })
}

fn build_permission_def(pair: Pair<Rule>) -> Result<RelationDef, pest::error::Error<Rule>> {
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let expression = build_relation_expr(inner.next().unwrap())?;
    Ok(RelationDef { name, expression })
}

fn build_relation_expr(pair: Pair<Rule>) -> Result<RelationExpr, pest::error::Error<Rule>> {
    // relation_expr wraps exclusion_expr, so unwrap it first
    let exclusion_pair = pair.into_inner().next().unwrap();
    build_exclusion_expr(exclusion_pair)
}

fn build_union_expr(pair: Pair<Rule>) -> Result<RelationExpr, pest::error::Error<Rule>> {
    let mut exprs = Vec::new();
    for p in pair.into_inner() {
        if p.as_rule() == Rule::primary_expr {
            exprs.push(build_primary_expr(p)?);
        }
    }
    if exprs.len() > 1 {
        Ok(RelationExpr::Union(exprs))
    } else {
        Ok(exprs.pop().unwrap())
    }
}

fn build_intersection_expr(pair: Pair<Rule>) -> Result<RelationExpr, pest::error::Error<Rule>> {
    let mut exprs = Vec::new();
    for p in pair.into_inner() {
        if p.as_rule() == Rule::union_expr {
            exprs.push(build_union_expr(p)?);
        }
    }
    if exprs.len() > 1 {
        Ok(RelationExpr::Intersection(exprs))
    } else {
        Ok(exprs.pop().unwrap())
    }
}

fn build_exclusion_expr(pair: Pair<Rule>) -> Result<RelationExpr, pest::error::Error<Rule>> {
    let mut inner = pair.into_inner();
    let base = build_intersection_expr(inner.next().unwrap())?;
    if let Some(subtract) = inner.next() {
        Ok(RelationExpr::Exclusion {
            base: Box::new(base),
            subtract: Box::new(build_intersection_expr(subtract)?),
        })
    } else {
        Ok(base)
    }
}

fn build_primary_expr(pair: Pair<Rule>) -> Result<RelationExpr, pest::error::Error<Rule>> {
    let inner = pair.into_inner().next().unwrap();
    match inner.as_rule() {
        Rule::computed_userset => Ok(RelationExpr::ComputedUserset(inner.as_str().to_string())),
        Rule::tuple_to_userset => {
            let mut parts = inner.into_inner();
            let tupleset = parts.next().unwrap().as_str().to_string();
            let computed_userset = parts.next().unwrap().as_str().to_string();
            Ok(RelationExpr::TupleToUserset {
                computed_userset,
                tupleset,
            })
        }
        Rule::direct_assignment => {
            let targets = inner
                .into_inner()
                .map(build_assignable_target)
                .collect::<Result<_, _>>()?;
            Ok(RelationExpr::DirectAssignment(targets))
        }
        _ => unreachable!(),
    }
}

fn build_assignable_target(pair: Pair<Rule>) -> Result<AssignableTarget, pest::error::Error<Rule>> {
    let span = pair.as_span();
    let text = span.as_str();
    let mut inner = pair.into_inner();
    let type_spec = inner.next().unwrap();
    let type_name = type_spec.as_str().to_string();

    // Check what comes after type_spec
    // The grammar is: type_spec ~ "#" ~ identifier | type_spec ~ ":*" | type_spec ~ "with" ~ identifier | type_spec

    // Check the original text to determine the variant
    if text.ends_with(":*") {
        // Wildcard: user:*
        Ok(AssignableTarget::Wildcard(type_name))
    } else if let Some(next) = inner.next() {
        // We have a second token
        if text.contains(" with ") {
            // Conditional: user with condition_name
            let condition = next.as_str().to_string();
            Ok(AssignableTarget::Conditional {
                target: Box::new(AssignableTarget::Type(type_name)),
                condition,
            })
        } else {
            // Userset: group#member
            let relation = next.as_str().to_string();
            Ok(AssignableTarget::Userset {
                type_name,
                relation,
            })
        }
    } else {
        // Just a plain type
        Ok(AssignableTarget::Type(type_name))
    }
}

fn build_condition_def(pair: Pair<Rule>) -> Result<ConditionDef, pest::error::Error<Rule>> {
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let mut params = Vec::new();
    let mut expression = "".to_string();

    for part in inner {
        match part.as_rule() {
            Rule::condition_param => params.push(build_condition_param(part)?),
            Rule::condition_expr => expression = part.as_str().to_string(),
            _ => (),
        }
    }

    Ok(ConditionDef {
        name,
        params,
        expression,
    })
}

fn build_condition_param(pair: Pair<Rule>) -> Result<ConditionParam, pest::error::Error<Rule>> {
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let param_type = inner.next().unwrap().as_str().to_string();
    Ok(ConditionParam { name, param_type })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_parse_simple_type() {
        let dsl = "type user {}";
        let expected = ModelFile {
            type_defs: vec![TypeDef {
                name: "user".to_string(),
                relations: vec![],
                permissions: vec![],
            }],
            condition_defs: vec![],
        };
        assert_eq!(parse_dsl(dsl).unwrap(), expected);
    }

    #[test]
    fn test_parse_type_with_relations() {
        let dsl = r#"
            type document {
                relations
                    define viewer: [user]
                    define editor: [user | group#member]
            }
        "#;
        let expected = ModelFile {
            type_defs: vec![TypeDef {
                name: "document".to_string(),
                relations: vec![
                    RelationDef {
                        name: "viewer".to_string(),
                        expression: RelationExpr::DirectAssignment(vec![AssignableTarget::Type(
                            "user".to_string(),
                        )]),
                    },
                    RelationDef {
                        name: "editor".to_string(),
                        expression: RelationExpr::DirectAssignment(vec![
                            AssignableTarget::Type("user".to_string()),
                            AssignableTarget::Userset {
                                type_name: "group".to_string(),
                                relation: "member".to_string(),
                            },
                        ]),
                    },
                ],
                permissions: vec![],
            }],
            condition_defs: vec![],
        };
        assert_eq!(parse_dsl(dsl).unwrap(), expected);
    }

    #[test]
    fn test_parse_computed_userset() {
        let dsl = "type folder { relations define can_view: owner }";
        let expected = ModelFile {
            type_defs: vec![TypeDef {
                name: "folder".to_string(),
                relations: vec![RelationDef {
                    name: "can_view".to_string(),
                    expression: RelationExpr::ComputedUserset("owner".to_string()),
                }],
                permissions: vec![],
            }],
            condition_defs: vec![],
        };
        assert_eq!(parse_dsl(dsl).unwrap(), expected);
    }

    #[test]
    fn test_parse_ttu() {
        let dsl = "type document { relations define viewer: parent->viewer }";
        let expected = ModelFile {
            type_defs: vec![TypeDef {
                name: "document".to_string(),
                relations: vec![RelationDef {
                    name: "viewer".to_string(),
                    expression: RelationExpr::TupleToUserset {
                        computed_userset: "viewer".to_string(),
                        tupleset: "parent".to_string(),
                    },
                }],
                permissions: vec![],
            }],
            condition_defs: vec![],
        };
        assert_eq!(parse_dsl(dsl).unwrap(), expected);
    }

    #[test]
    fn test_parse_union() {
        let dsl = "type document { relations define viewer: [user] + editor }";
        let expected = RelationExpr::Union(vec![
            RelationExpr::DirectAssignment(vec![AssignableTarget::Type("user".to_string())]),
            RelationExpr::ComputedUserset("editor".to_string()),
        ]);
        let model = parse_dsl(dsl).unwrap();
        assert_eq!(model.type_defs[0].relations[0].expression, expected);
    }

    #[test]
    fn test_parse_whitespace_only() {
        let whitespace_model = "   \n\t   ";
        let result = parse_dsl(whitespace_model);
        assert!(
            result.is_ok(),
            "Whitespace-only model should parse successfully as empty model"
        );

        let model = result.unwrap();
        assert_eq!(
            model.type_defs.len(),
            0,
            "Empty model should have no type definitions"
        );
        assert_eq!(
            model.condition_defs.len(),
            0,
            "Empty model should have no condition definitions"
        );
    }

    #[test]
    fn test_parse_comment_only() {
        let comment_model = "// This is just a comment\n/* Another comment */";
        let result = parse_dsl(comment_model);
        assert!(
            result.is_ok(),
            "Comment-only model should parse successfully as empty model"
        );

        let model = result.unwrap();
        assert_eq!(
            model.type_defs.len(),
            0,
            "Comment-only model should have no type definitions"
        );
        assert_eq!(
            model.condition_defs.len(),
            0,
            "Comment-only model should have no condition definitions"
        );
    }

    #[test]
    fn test_parse_invalid_syntax() {
        let invalid_model = "type user { relations define viewer: [ }";
        let result = parse_dsl(invalid_model);
        assert!(result.is_err(), "Invalid syntax should fail to parse");
    }

    #[test]
    fn test_parse_condition() {
        let dsl = r#"
            condition ip_check(allowed_cidrs: list<string>, request_ip: string) {
                request_ip in allowed_cidrs
            }
        "#;
        let expected = ModelFile {
            type_defs: vec![],
            condition_defs: vec![ConditionDef {
                name: "ip_check".to_string(),
                params: vec![
                    ConditionParam {
                        name: "allowed_cidrs".to_string(),
                        param_type: "list<string>".to_string(),
                    },
                    ConditionParam {
                        name: "request_ip".to_string(),
                        param_type: "string".to_string(),
                    },
                ],
                expression: "request_ip in allowed_cidrs".to_string(),
            }],
        };
        assert_eq!(parse_dsl(dsl).unwrap(), expected);
    }

    #[test]
    fn test_parse_intersection() {
        let dsl = "type document { relations define viewer: [user] & editor }";
        let expected = RelationExpr::Intersection(vec![
            RelationExpr::DirectAssignment(vec![AssignableTarget::Type("user".to_string())]),
            RelationExpr::ComputedUserset("editor".to_string()),
        ]);
        let model = parse_dsl(dsl).unwrap();
        assert_eq!(model.type_defs[0].relations[0].expression, expected);
    }

    #[test]
    fn test_parse_exclusion() {
        let dsl = "type document { relations define viewer: [user] - banned }";
        let expected = RelationExpr::Exclusion {
            base: Box::new(RelationExpr::DirectAssignment(vec![
                AssignableTarget::Type("user".to_string()),
            ])),
            subtract: Box::new(RelationExpr::ComputedUserset("banned".to_string())),
        };
        let model = parse_dsl(dsl).unwrap();
        assert_eq!(model.type_defs[0].relations[0].expression, expected);
    }

    #[test]
    fn test_parse_nested_set_ops() {
        // Test union with exclusion.
        // With arrow syntax precedence, union binds tighter than exclusion.
        // So: [user] + editor - banned
        // Parses as: ([user] + editor) - banned
        let dsl = "type document { relations define viewer: [user] + editor - banned }";
        let model = parse_dsl(dsl).unwrap();

        // Should be: Exclusion(Union([DirectAssignment([user]), ComputedUserset(editor)]), ComputedUserset(banned))
        match &model.type_defs[0].relations[0].expression {
            RelationExpr::Exclusion { base, subtract } => {
                match &**base {
                    RelationExpr::Union(exprs) => {
                        assert_eq!(exprs.len(), 2);
                        assert!(matches!(exprs[0], RelationExpr::DirectAssignment(_)));
                        assert!(matches!(exprs[1], RelationExpr::ComputedUserset(_)));
                    }
                    _ => panic!("Expected Union expression"),
                }
                assert!(matches!(**subtract, RelationExpr::ComputedUserset(_)));
            }
            _ => panic!("Expected Exclusion expression"),
        }
    }

    #[test]
    fn test_parse_wildcard() {
        let dsl = "type document { relations define viewer: [user:*] }";
        let expected = ModelFile {
            type_defs: vec![TypeDef {
                name: "document".to_string(),
                relations: vec![RelationDef {
                    name: "viewer".to_string(),
                    expression: RelationExpr::DirectAssignment(vec![AssignableTarget::Wildcard(
                        "user".to_string(),
                    )]),
                }],
                permissions: vec![],
            }],
            condition_defs: vec![],
        };
        assert_eq!(parse_dsl(dsl).unwrap(), expected);
    }

    #[test]
    fn test_parse_conditional_type() {
        let dsl = "type document { relations define viewer: [user with ip_check] }";
        let expected = ModelFile {
            type_defs: vec![TypeDef {
                name: "document".to_string(),
                relations: vec![RelationDef {
                    name: "viewer".to_string(),
                    expression: RelationExpr::DirectAssignment(vec![
                        AssignableTarget::Conditional {
                            target: Box::new(AssignableTarget::Type("user".to_string())),
                            condition: "ip_check".to_string(),
                        },
                    ]),
                }],
                permissions: vec![],
            }],
            condition_defs: vec![],
        };
        assert_eq!(parse_dsl(dsl).unwrap(), expected);
    }

    #[test]
    fn test_parse_multiple_types() {
        let dsl = r#"
            type user {}
            type document {
                relations
                    define viewer: [user]
            }
            type folder {
                relations
                    define parent: [folder]
            }
        "#;
        let model = parse_dsl(dsl).unwrap();
        assert_eq!(model.type_defs.len(), 3);
        assert_eq!(model.type_defs[0].name, "user");
        assert_eq!(model.type_defs[1].name, "document");
        assert_eq!(model.type_defs[2].name, "folder");
    }

    #[test]
    fn test_parse_complex_real_world() {
        // Google Drive-like schema with 10+ relations
        let dsl = r#"
            type user {}
            
            type organization {
                relations
                    define member: [user]
                    define admin: [user]
            }
            
            type folder {
                relations
                    define parent: [folder]
                    define owner: [user]
                    define editor: [user | organization#member]
                    define viewer: [user | organization#member]
                    define can_view: viewer + editor + owner
                    define can_edit: editor + owner
                    define can_delete: owner
                    define can_share: owner
            }
            
            type document {
                relations
                    define parent: [folder]
                    define owner: [user]
                    define editor: [user | group#member | team#member]
                    define viewer: [user | group#member]
                    define can_view: viewer + editor + owner + parent->can_view
                    define can_edit: editor + owner + parent->can_edit
                    define can_delete: owner
                    define can_comment: can_view
            }
        "#;
        let model = parse_dsl(dsl).unwrap();
        assert_eq!(model.type_defs.len(), 4);

        // Verify folder has 8 relations
        let folder = model.type_defs.iter().find(|t| t.name == "folder").unwrap();
        assert_eq!(folder.relations.len(), 8);

        // Verify document has 8 relations
        let document = model
            .type_defs
            .iter()
            .find(|t| t.name == "document")
            .unwrap();
        assert_eq!(document.relations.len(), 8);
    }

    #[test]
    fn test_parse_empty_string() {
        let dsl = "";
        let result = parse_dsl(dsl).unwrap();
        assert_eq!(result.type_defs.len(), 0);
        assert_eq!(result.condition_defs.len(), 0);
    }
}

#[test]
fn test_parse_mixed_precedence_first_and_second_plus_third() {
    // Test: first & second + third
    // According to grammar: union binds tighter than intersection
    // Should parse as: first & (second + third)
    let dsl = "type document {
      relations
        define first: [user]
        define second: [user]
        define third: [user]
      permissions
        define mixed_precedence2 = first & second + third
    }";

    let model = parse_dsl(dsl).unwrap();

    // Should be: Intersection([ComputedUserset(first)], Union([ComputedUserset(second), ComputedUserset(third)]))
    match &model.type_defs[0].permissions[0].expression {
        RelationExpr::Intersection(exprs) => {
            assert_eq!(exprs.len(), 2);
            assert!(matches!(&exprs[0], RelationExpr::ComputedUserset(name) if name == "first"));
            match &exprs[1] {
                RelationExpr::Union(union_exprs) => {
                    assert_eq!(union_exprs.len(), 2);
                    assert!(
                        matches!(&union_exprs[0], RelationExpr::ComputedUserset(name) if name == "second")
                    );
                    assert!(
                        matches!(&union_exprs[1], RelationExpr::ComputedUserset(name) if name == "third")
                    );
                }
                _ => panic!("Expected Union expression as second operand of Intersection"),
            }
        }
        _ => panic!(
            "Expected Intersection expression, got: {:?}",
            model.type_defs[0].permissions[0].expression
        ),
    }
}
