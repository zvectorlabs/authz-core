//! CEL condition compilation and evaluation.

use cel::Program;
use std::collections::HashMap;

#[derive(Debug)]
pub enum CelError {
    CompileError(String),
    EvalError(String),
}

impl std::fmt::Display for CelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CelError::CompileError(msg) => write!(f, "CEL compile error: {}", msg),
            CelError::EvalError(msg) => write!(f, "CEL eval error: {}", msg),
        }
    }
}

impl std::error::Error for CelError {}

#[derive(Debug, Clone, PartialEq)]
pub enum CelResult {
    Met(bool),
    MissingParameters(Vec<String>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Bool(bool),
    Int(i64),
    String(String),
    List(Vec<Value>),
}

/// Compile a CEL expression into a Program.
pub fn compile(expr: &str) -> Result<Program, CelError> {
    Program::compile(expr).map_err(|e| CelError::CompileError(e.to_string()))
}

/// Evaluate a compiled CEL program with the given context.
/// Returns CelResult::Met(bool) if evaluation succeeds,
/// or CelResult::MissingParameters if required parameters are missing.
pub fn evaluate(
    program: &Program,
    context: &HashMap<String, Value>,
) -> Result<CelResult, CelError> {
    // Convert our Value type to cel::Value
    let mut cel_context = cel::Context::default();
    for (key, value) in context {
        let cel_value = match value {
            Value::Bool(b) => cel::Value::Bool(*b),
            Value::Int(i) => cel::Value::Int(*i),
            Value::String(s) => cel::Value::String(s.clone().into()),
            Value::List(items) => {
                let cel_items: Vec<cel::Value> = items
                    .iter()
                    .map(|v| match v {
                        Value::Bool(b) => cel::Value::Bool(*b),
                        Value::Int(i) => cel::Value::Int(*i),
                        Value::String(s) => cel::Value::String(s.clone().into()),
                        Value::List(_) => cel::Value::Null, // nested lists not supported
                    })
                    .collect();
                cel::Value::List(cel_items.into())
            }
        };
        let _ = cel_context.add_variable(key, cel_value);
    }

    // Execute the program
    match program.execute(&cel_context) {
        Ok(value) => {
            // Convert result to boolean
            match value {
                cel::Value::Bool(b) => Ok(CelResult::Met(b)),
                _ => Err(CelError::EvalError(format!(
                    "CEL expression must evaluate to boolean, got: {:?}",
                    value
                ))),
            }
        }
        Err(e) => {
            let err_msg = e.to_string();
            // Check if error is due to missing variable (case-insensitive check)
            let err_lower = err_msg.to_lowercase();
            if err_lower.contains("undeclared") || err_lower.contains("not found") {
                // Extract variable name from error message
                let missing = extract_missing_variable(&err_msg);
                Ok(CelResult::MissingParameters(vec![missing]))
            } else {
                Err(CelError::EvalError(err_msg))
            }
        }
    }
}

fn extract_missing_variable(err_msg: &str) -> String {
    // Try to extract variable name from error message
    // Example: "undeclared reference to 'x'"
    if let Some(start) = err_msg.find('\'')
        && let Some(end) = err_msg[start + 1..].find('\'')
    {
        return err_msg[start + 1..start + 1 + end].to_string();
    }
    // Try without quotes
    if let Some(idx) = err_msg.find("undeclared") {
        let rest = &err_msg[idx..];
        if let Some(word_start) = rest.rfind(' ') {
            return rest[word_start + 1..].trim().to_string();
        }
    }
    "unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile_valid_expression() {
        let result = compile("x == 42");
        assert!(result.is_ok());
    }

    #[test]
    fn test_compile_invalid_expression() {
        let result = compile("x ==");
        assert!(result.is_err());
    }

    #[test]
    fn test_eval_true() {
        let program = compile("x == 42").unwrap();
        let mut context = HashMap::new();
        context.insert("x".to_string(), Value::Int(42));
        let result = evaluate(&program, &context).unwrap();
        assert_eq!(result, CelResult::Met(true));
    }

    #[test]
    fn test_eval_false() {
        let program = compile("x == 42").unwrap();
        let mut context = HashMap::new();
        context.insert("x".to_string(), Value::Int(99));
        let result = evaluate(&program, &context).unwrap();
        assert_eq!(result, CelResult::Met(false));
    }

    #[test]
    fn test_eval_missing_params() {
        let program = compile("x == 42").unwrap();
        let context = HashMap::new(); // Empty context
        let result = evaluate(&program, &context).unwrap();
        match result {
            CelResult::MissingParameters(params) => {
                assert!(!params.is_empty());
            }
            _ => panic!("Expected MissingParameters"),
        }
    }

    #[test]
    fn test_eval_string_comparison() {
        let program = compile("name == \"alice\"").unwrap();
        let mut context = HashMap::new();
        context.insert(
            "name".to_string(),
            Value::String("alice".to_string().into()),
        );
        let result = evaluate(&program, &context).unwrap();
        assert_eq!(result, CelResult::Met(true));
    }

    #[test]
    fn test_eval_list_contains() {
        let program = compile("x in [1, 2, 3]").unwrap();
        let mut context = HashMap::new();
        context.insert("x".to_string(), Value::Int(2));
        let result = evaluate(&program, &context).unwrap();
        assert_eq!(result, CelResult::Met(true));
    }

    #[test]
    fn test_eval_boolean_logic() {
        let program = compile("x > 0 && y < 10").unwrap();
        let mut context = HashMap::new();
        context.insert("x".to_string(), Value::Int(5));
        context.insert("y".to_string(), Value::Int(3));
        let result = evaluate(&program, &context).unwrap();
        assert_eq!(result, CelResult::Met(true));
    }

    #[test]
    fn test_eval_boolean_logic_edge() {
        let program = compile("x > 0 && y < 10").unwrap();
        let mut context = HashMap::new();
        context.insert("x".to_string(), Value::Int(5));
        context.insert("y".to_string(), Value::Int(8));
        let result = evaluate(&program, &context).unwrap();
        assert_eq!(result, CelResult::Met(true));
    }

    #[test]
    fn test_eval_nested_logic() {
        let program = compile("(x > 0 && y < 10) || z == true").unwrap();
        let mut context = HashMap::new();
        context.insert("x".to_string(), Value::Int(-1));
        context.insert("y".to_string(), Value::Int(5));
        context.insert("z".to_string(), Value::Bool(true));
        let result = evaluate(&program, &context).unwrap();
        assert_eq!(result, CelResult::Met(true));
    }

    #[test]
    fn test_eval_empty_expression() {
        let result = compile("");
        assert!(result.is_err());
    }
}
