//! Abstract Syntax Tree (AST) for the authorization model DSL.

#[derive(Debug, PartialEq, Clone, serde::Serialize)]
pub struct ModelFile {
    pub type_defs: Vec<TypeDef>,
    pub condition_defs: Vec<ConditionDef>,
}

#[derive(Debug, PartialEq, Clone, serde::Serialize)]
pub struct TypeDef {
    pub name: String,
    pub relations: Vec<RelationDef>,
    pub permissions: Vec<RelationDef>, // Use RelationDef for both relations and permissions
}

#[derive(Debug, PartialEq, Clone, serde::Serialize)]
pub struct RelationDef {
    pub name: String,
    pub expression: RelationExpr,
}

#[derive(Debug, PartialEq, Clone, serde::Serialize)]
pub enum RelationExpr {
    Union(Vec<RelationExpr>),
    Intersection(Vec<RelationExpr>),
    Exclusion {
        base: Box<RelationExpr>,
        subtract: Box<RelationExpr>,
    },
    ComputedUserset(String),
    TupleToUserset {
        computed_userset: String,
        tupleset: String,
    },
    DirectAssignment(Vec<AssignableTarget>),
}

#[derive(Debug, PartialEq, Clone, serde::Serialize)]
pub enum AssignableTarget {
    Type(String),
    Userset {
        type_name: String,
        relation: String,
    },
    Wildcard(String),
    Conditional {
        target: Box<AssignableTarget>,
        condition: String,
    },
}

#[derive(Debug, PartialEq, Clone, serde::Serialize)]
pub struct ConditionDef {
    pub name: String,
    pub params: Vec<ConditionParam>,
    pub expression: String,
}

#[derive(Debug, PartialEq, Clone, serde::Serialize)]
pub struct ConditionParam {
    pub name: String,
    pub param_type: String,
}
