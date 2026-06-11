//! KDL parser for application schemas.  See `docs/schema.md` for the
//! user-facing reference.
//!
//! Translates a `.kdl` schema file into the [`SchemaBundle`] shape so
//! the import pipeline can populate authenticated state.  Action
//! assertions and ACL predicates use the predicate grammar in
//! `backend/acl-types/src/predicate.pest`.
//!
//! Top-level KDL nodes recognised here:
//!   - `table "<name>" auto_increment=#false? {
//!         column "<col>" type="..." plaintext=... indexed=...
//!         rules {
//!             allow write|delete "<predicate>"
//!             only_via_actions write|delete "<name>" ...
//!             action "<name>" {
//!                 assert "<expr>"
//!                 insert | update cols="..." | delete
//!                 cascade_delete table="<other>" where="row.<col> == self.<col>"
//!             }
//!         }
//!     }`
//!
//! Tables can omit the `rules { }` block (default-open).  The primary
//! leg of an `action` (`insert` / `update` / `delete`) implicitly
//! targets the enclosing table; `cascade_delete` legs name a cross-
//! table target via `table="..."`.
//!
//! The initial merk root (data commitment) is computed at build time
//! by `sdk-codegen` from the parsed schema; it is *not* declared in
//! the schema KDL.

use crate::app_schema::{SchemaBundle, SchemaTable};
use crate::error::{Result, SdkError};
use crate::internal_schemas::ACCESS_CONTROL_TABLE_NAME;
use crate::schema::{ColumnDefinition, ColumnType, Schema};
use encrypted_spaces_acl_types::{
    parse_access_rule, parse_assertion, AccessOperation, AccessRule, Action, ActionLeg, Assertion,
    ColumnNamespace, ComparisonOp, RuleValue,
};
use kdl::{KdlDocument, KdlNode};
use serde_json::{json, Value};

pub fn parse_schema_bundle(text: &str) -> Result<SchemaBundle> {
    let doc = KdlDocument::parse(text)
        .map_err(|e| SdkError::SchemaParsingError(format!("Invalid KDL: {e}")))?;

    let mut acl_rows: Vec<Value> = Vec::new();
    let mut tables: Vec<SchemaTable> = Vec::new();
    let mut actions: Vec<Action> = Vec::new();
    let mut acl_only_via_actions: std::collections::BTreeMap<(String, String), Vec<String>> =
        std::collections::BTreeMap::new();
    let mut seen_action_names: std::collections::HashSet<String> = std::collections::HashSet::new();

    for node in doc.nodes() {
        match node.name().value() {
            "table" => parse_table_node(
                node,
                &mut tables,
                &mut acl_rows,
                &mut acl_only_via_actions,
                &mut actions,
                &mut seen_action_names,
            )?,
            other => {
                return Err(SdkError::SchemaParsingError(format!(
                    "Unknown top-level node '{other}' in schema (only `table` is allowed at the \
                     top level; ACL clauses and actions nest inside a table's `rules` block)"
                )));
            }
        }
    }

    // Actions can only target auto-increment tables.  With client-
    // chosen ids, a delete + insert at the same id sidesteps update
    // actions' invariants (cols= allowlists, assertions) and silently
    // re-points any external row references.  This check covers
    // cascade legs (which can target other tables) and re-validates
    // the primary leg's table.
    for action in &actions {
        for leg in &action.legs {
            let target = leg.table();
            let schema_entry = tables.iter().find(|t| t.table == target).ok_or_else(|| {
                SdkError::SchemaParsingError(format!(
                    "action \"{}\" leg targets table \"{}\" which is not declared in the schema",
                    action.name, target
                ))
            })?;
            let schema = schema_entry.schema.as_ref().ok_or_else(|| {
                SdkError::SchemaParsingError(format!(
                    "action \"{}\" leg targets table \"{}\" which has no schema body",
                    action.name, target
                ))
            })?;
            if !schema.auto_increment {
                return Err(SdkError::SchemaParsingError(format!(
                    "action \"{}\" leg targets table \"{}\", which is not auto-increment.  \
                     Actions can only touch auto-increment tables: a non-auto-increment client \
                     picks row ids itself, and a delete + insert at the same id can bypass the \
                     action's update rules and silently re-point any references that name the row.",
                    action.name, target
                )));
            }
        }
    }

    validate_hash_backed_semantic_refs(&tables, &acl_rows, &actions)?;

    let mut all_tables = Vec::with_capacity(tables.len() + 1);
    if !acl_rows.is_empty() {
        all_tables.push(SchemaTable {
            table: ACCESS_CONTROL_TABLE_NAME.to_string(),
            schema: None,
            rows: acl_rows,
        });
    }
    all_tables.extend(tables);

    Ok(SchemaBundle {
        tables: all_tables,
        actions,
        acl_only_via_actions,
    })
}

fn validate_hash_backed_semantic_refs(
    tables: &[SchemaTable],
    acl_rows: &[Value],
    actions: &[Action],
) -> Result<()> {
    let schemas: std::collections::BTreeMap<&str, &Schema> = tables
        .iter()
        .filter_map(|t| t.schema.as_ref().map(|s| (t.table.as_str(), s)))
        .collect();

    for row in acl_rows {
        let table = row
            .get("resource_name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let operation = row
            .get("operation")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let rule_json = row
            .get("rule_json")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let rule: AccessRule = serde_json::from_str(rule_json).map_err(|e| {
            SdkError::SchemaParsingError(format!(
                "table \"{table}\" allow {operation}: stored ACL rule failed to decode: {e}"
            ))
        })?;
        let context = format!("ACL allow {operation} predicate");
        validate_rule_hash_refs(&rule, table, table, &context, &schemas)?;
    }

    for action in actions {
        let Some(primary_table) = action.legs.first().map(ActionLeg::table) else {
            continue;
        };
        for assertion in &action.asserts {
            let context = format!("action \"{}\" assert", action.name);
            validate_assertion_hash_refs(assertion, primary_table, &context, &schemas)?;
        }
        for leg in &action.legs {
            if let ActionLeg::CascadeDelete {
                table,
                where_column,
                where_self_column,
            } = leg
            {
                reject_hash_backed_column(
                    &schemas,
                    table,
                    where_column,
                    &format!("action \"{}\" cascade_delete row predicate", action.name),
                )?;
                reject_hash_backed_column(
                    &schemas,
                    primary_table,
                    where_self_column,
                    &format!("action \"{}\" cascade_delete self predicate", action.name),
                )?;
            }
        }
    }

    Ok(())
}

fn validate_assertion_hash_refs(
    assertion: &Assertion,
    primary_table: &str,
    context: &str,
    schemas: &std::collections::BTreeMap<&str, &Schema>,
) -> Result<()> {
    match assertion {
        Assertion::Rule(rule) => {
            validate_rule_hash_refs(rule, primary_table, primary_table, context, schemas)
        }
        Assertion::Exists { table, predicate } => {
            validate_rule_hash_refs(predicate, table, primary_table, context, schemas)
        }
        Assertion::And(a, b) | Assertion::Or(a, b) => {
            validate_assertion_hash_refs(a, primary_table, context, schemas)?;
            validate_assertion_hash_refs(b, primary_table, context, schemas)
        }
        Assertion::Not(inner) => {
            validate_assertion_hash_refs(inner, primary_table, context, schemas)
        }
    }
}

fn validate_rule_hash_refs(
    rule: &AccessRule,
    resource_table: &str,
    self_table: &str,
    context: &str,
    schemas: &std::collections::BTreeMap<&str, &Schema>,
) -> Result<()> {
    match rule {
        AccessRule::Comparison { left, right, .. } => {
            validate_rule_value_hash_ref(left, resource_table, self_table, context, schemas)?;
            validate_rule_value_hash_ref(right, resource_table, self_table, context, schemas)
        }
        AccessRule::And(a, b) | AccessRule::Or(a, b) => {
            validate_rule_hash_refs(a, resource_table, self_table, context, schemas)?;
            validate_rule_hash_refs(b, resource_table, self_table, context, schemas)
        }
        AccessRule::Not(inner) => {
            validate_rule_hash_refs(inner, resource_table, self_table, context, schemas)
        }
    }
}

fn validate_rule_value_hash_ref(
    value: &RuleValue,
    resource_table: &str,
    self_table: &str,
    context: &str,
    schemas: &std::collections::BTreeMap<&str, &Schema>,
) -> Result<()> {
    let RuleValue::Column { namespace, name } = value else {
        return Ok(());
    };
    let table = match namespace {
        ColumnNamespace::Resource => resource_table,
        ColumnNamespace::SelfRow => self_table,
    };
    reject_hash_backed_column(schemas, table, name, context)
}

fn reject_hash_backed_column(
    schemas: &std::collections::BTreeMap<&str, &Schema>,
    table: &str,
    column: &str,
    context: &str,
) -> Result<()> {
    let Some(schema) = schemas.get(table) else {
        return Ok(());
    };
    let Some(column_def) = schema.columns.iter().find(|c| c.name == column) else {
        return Ok(());
    };
    if column_def.column_type.is_hash_backed() {
        return Err(SdkError::SchemaParsingError(format!(
            "table \"{table}\" column \"{column}\": hash-backed columns cannot be referenced by {context}"
        )));
    }
    Ok(())
}

fn parse_table_node(
    node: &KdlNode,
    tables: &mut Vec<SchemaTable>,
    acl_rows: &mut Vec<Value>,
    acl_only_via_actions: &mut std::collections::BTreeMap<(String, String), Vec<String>>,
    actions: &mut Vec<Action>,
    seen_action_names: &mut std::collections::HashSet<String>,
) -> Result<()> {
    let name = string_arg(node, "table")?.to_string();

    let auto_increment = node
        .entry("auto_increment")
        .map(|e| {
            e.value().as_bool().ok_or_else(|| {
                SdkError::SchemaParsingError(format!(
                    "table \"{name}\": auto_increment must be #true or #false"
                ))
            })
        })
        .transpose()?
        .unwrap_or(true);

    let children = node.children().ok_or_else(|| {
        SdkError::SchemaParsingError(format!(
            "table \"{name}\" must have a child block defining columns"
        ))
    })?;

    let mut columns = Vec::new();
    let mut saw_rules = false;
    for child in children.nodes() {
        match child.name().value() {
            "column" => columns.push(parse_column_node(child, &name)?),
            "rules" => {
                if saw_rules {
                    return Err(SdkError::SchemaParsingError(format!(
                        "table \"{name}\": only one `rules` block is allowed"
                    )));
                }
                saw_rules = true;
                parse_rules_block(
                    child,
                    &name,
                    acl_rows,
                    acl_only_via_actions,
                    actions,
                    seen_action_names,
                )?;
            }
            other => {
                return Err(SdkError::SchemaParsingError(format!(
                    "table \"{name}\": unexpected `{other}` node (expected `column` or `rules`)"
                )));
            }
        }
    }

    tables.push(SchemaTable {
        table: name.clone(),
        schema: Some(Schema {
            name,
            columns,
            auto_increment,
        }),
        rows: Vec::new(),
    });
    Ok(())
}

/// Parse the `rules { ... }` sub-block of a table.  Children are an
/// ordered mix of:
///
///   - `allow write|delete "<predicate>"` — ACL clause.
///   - `only_via_actions write|delete "<name>" ...` — action-gating.
///   - `action "<name>" { ... }` — action definition whose primary leg
///     implicitly targets the enclosing table.
fn parse_rules_block(
    node: &KdlNode,
    table: &str,
    acl_rows: &mut Vec<Value>,
    acl_only_via_actions: &mut std::collections::BTreeMap<(String, String), Vec<String>>,
    actions: &mut Vec<Action>,
    seen_action_names: &mut std::collections::HashSet<String>,
) -> Result<()> {
    let children = match node.children() {
        Some(c) => c,
        None => return Ok(()), // empty `rules { }` is legal
    };

    for child in children.nodes() {
        match child.name().value() {
            "allow" => parse_allow_clause(child, table, acl_rows)?,
            "only_via_actions" => {
                parse_only_via_actions_clause(child, table, acl_only_via_actions)?
            }
            "action" => {
                let action = parse_action_node(child, table)?;
                if !seen_action_names.insert(action.name.clone()) {
                    return Err(SdkError::SchemaParsingError(format!(
                        "action \"{}\" is declared more than once; action names must be unique \
                         across the whole schema (the name is the signed identifier for app-\
                         defined ops)",
                        action.name
                    )));
                }
                actions.push(action);
            }
            other => {
                return Err(SdkError::SchemaParsingError(format!(
                    "table \"{table}\" rules: unexpected `{other}` node (expected `allow`, \
                     `only_via_actions`, or `action`)"
                )));
            }
        }
    }
    Ok(())
}

/// Parse `allow write|delete "<predicate>"` and append the row to
/// `acl_rows` for `_access_control`.
fn parse_allow_clause(node: &KdlNode, table: &str, acl_rows: &mut Vec<Value>) -> Result<()> {
    let mut positional = node.entries().iter().filter(|e| e.name().is_none());
    let op_arg = positional.next().ok_or_else(|| {
        SdkError::SchemaParsingError(format!(
            "table \"{table}\" rules: `allow` requires a verb (write|delete) as its first \
             positional argument"
        ))
    })?;
    let op_str = op_arg.value().as_string().ok_or_else(|| {
        SdkError::SchemaParsingError(format!(
            "table \"{table}\" rules: `allow` verb must be a string (write|delete)"
        ))
    })?;
    let operation = match op_str {
        "write" => AccessOperation::Write,
        "delete" => AccessOperation::Delete,
        other => {
            return Err(SdkError::SchemaParsingError(format!(
                "table \"{table}\" rules: unknown `allow` verb '{other}' (expected write or \
                 delete)"
            )));
        }
    };
    let expr_arg = positional.next().ok_or_else(|| {
        SdkError::SchemaParsingError(format!(
            "table \"{table}\" rules: `allow {op_str}` requires a predicate string"
        ))
    })?;
    let expr = expr_arg.value().as_string().ok_or_else(|| {
        SdkError::SchemaParsingError(format!(
            "table \"{table}\" rules: `allow {op_str}` predicate must be a string"
        ))
    })?;
    if positional.next().is_some() {
        return Err(SdkError::SchemaParsingError(format!(
            "table \"{table}\" rules: `allow {op_str}` takes exactly one predicate"
        )));
    }
    let rule = parse_predicate(expr)?;
    let rule_json = serde_json::to_string(&rule)
        .map_err(|e| SdkError::SchemaParsingError(format!("Failed to serialize ACL rule: {e}")))?;
    acl_rows.push(json!({
        "operation": operation.to_string(),
        "resource_name": table,
        "rule_json": rule_json,
    }));
    Ok(())
}

/// Parse `only_via_actions write|delete "<name>" ...` and record the
/// list of allowed action names under `(table, op)`.
fn parse_only_via_actions_clause(
    node: &KdlNode,
    table: &str,
    acl_only_via_actions: &mut std::collections::BTreeMap<(String, String), Vec<String>>,
) -> Result<()> {
    let mut positional = node.entries().iter().filter(|e| e.name().is_none());
    let op_arg = positional.next().ok_or_else(|| {
        SdkError::SchemaParsingError(format!(
            "table \"{table}\" rules: `only_via_actions` requires a verb (write|delete) as its \
             first positional argument"
        ))
    })?;
    let op_str = op_arg.value().as_string().ok_or_else(|| {
        SdkError::SchemaParsingError(format!(
            "table \"{table}\" rules: `only_via_actions` verb must be a string (write|delete)"
        ))
    })?;
    if !matches!(op_str, "write" | "delete") {
        return Err(SdkError::SchemaParsingError(format!(
            "table \"{table}\" rules: unknown `only_via_actions` verb '{op_str}' (expected write \
             or delete)"
        )));
    }
    let names: Vec<String> = positional
        .map(|e| e.value().as_string().map(str::to_string))
        .collect::<Option<Vec<String>>>()
        .ok_or_else(|| {
            SdkError::SchemaParsingError(format!(
                "table \"{table}\" rules: `only_via_actions {op_str}` action names must be strings"
            ))
        })?;
    if names.is_empty() {
        return Err(SdkError::SchemaParsingError(format!(
            "table \"{table}\" rules: `only_via_actions {op_str}` must list at least one action"
        )));
    }
    acl_only_via_actions.insert((table.to_string(), op_str.to_string()), names);
    Ok(())
}

fn parse_column_node(node: &KdlNode, table_name: &str) -> Result<ColumnDefinition> {
    let name = string_arg(node, "column")?.to_string();
    let type_str = node
        .entry("type")
        .and_then(|e| e.value().as_string())
        .ok_or_else(|| {
            SdkError::SchemaParsingError(format!(
                "table \"{table_name}\" column \"{name}\": missing type= attribute"
            ))
        })?;
    let column_type = match type_str {
        "int" => ColumnType::Integer,
        "string" => ColumnType::String,
        "real" => ColumnType::Real,
        "text" => ColumnType::Text,
        "blob" => ColumnType::Blob,
        "fileref" => ColumnType::FileRef,
        "list" => ColumnType::List,
        other => {
            return Err(SdkError::SchemaParsingError(format!(
                "table \"{table_name}\" column \"{name}\": unknown type '{other}'"
            )));
        }
    };
    let plaintext = bool_attr(node, "plaintext")?.unwrap_or(matches!(
        column_type,
        ColumnType::FileRef | ColumnType::List
    ));
    let indexed = bool_attr(node, "indexed")?.unwrap_or(false);
    if column_type.is_hash_backed() && indexed {
        return Err(SdkError::SchemaParsingError(format!(
            "table \"{table_name}\" column \"{name}\": hash-backed columns cannot be indexed"
        )));
    }
    Ok(ColumnDefinition {
        name,
        column_type,
        plaintext,
        indexed,
    })
}

fn string_arg<'a>(node: &'a KdlNode, kind: &str) -> Result<&'a str> {
    node.entries()
        .iter()
        .find(|e| e.name().is_none())
        .and_then(|e| e.value().as_string())
        .ok_or_else(|| {
            SdkError::SchemaParsingError(format!("{kind} node missing required string argument"))
        })
}

fn bool_attr(node: &KdlNode, key: &str) -> Result<Option<bool>> {
    node.entry(key)
        .map(|e| {
            e.value().as_bool().ok_or_else(|| {
                SdkError::SchemaParsingError(format!("{key} must be #true or #false"))
            })
        })
        .transpose()
}

fn parse_predicate(expr: &str) -> Result<AccessRule> {
    parse_access_rule(expr)
        .map_err(|e| SdkError::SchemaParsingError(format!("ACL predicate '{expr}': {e}")))
}

/// Parse an `action "<name>" { ... }` node nested inside a table's
/// `rules` block.  Children are an ordered mix of `assert "<expr>"`
/// predicates and primitive-op legs.  The primary leg
/// (`insert`/`update`/`delete`) implicitly targets `primary_table` —
/// the table whose `rules` block contains this action.  Cascade legs
/// name a cross-table target via `table="..."`.
fn parse_action_node(node: &KdlNode, primary_table: &str) -> Result<Action> {
    let name = string_arg(node, "action")?.to_string();
    let children = node.children().ok_or_else(|| {
        SdkError::SchemaParsingError(format!(
            "action \"{name}\" must have a child block defining its legs"
        ))
    })?;

    let mut asserts: Vec<Assertion> = Vec::new();
    let mut legs: Vec<ActionLeg> = Vec::new();
    for child in children.nodes() {
        match child.name().value() {
            "assert" => {
                let expr = string_arg(child, &format!("action \"{name}\": assert"))?;
                let assertion = parse_assertion(expr).map_err(|e| {
                    SdkError::SchemaParsingError(format!(
                        "action \"{name}\": failed to parse assert `{expr}`: {e}"
                    ))
                })?;
                asserts.push(assertion);
            }
            "insert" => {
                reject_unexpected_attrs(child, &name, "insert", &[])?;
                legs.push(ActionLeg::Insert {
                    table: primary_table.to_string(),
                });
            }
            "update" => {
                reject_unexpected_attrs(child, &name, "update", &["cols"])?;
                legs.push(ActionLeg::Update {
                    table: primary_table.to_string(),
                    cols: parse_update_cols_attr(child, &name)?,
                });
            }
            "delete" => {
                reject_unexpected_attrs(child, &name, "delete", &[])?;
                legs.push(ActionLeg::Delete {
                    table: primary_table.to_string(),
                });
            }
            "cascade_delete" => legs.push(parse_cascade_delete_leg(child, &name)?),
            other => {
                return Err(SdkError::SchemaParsingError(format!(
                    "action \"{name}\": unsupported child node '{other}' \
                     (supported: `assert`, `insert`, `update`, `delete`, `cascade_delete`)"
                )));
            }
        }
    }

    if legs.is_empty() {
        return Err(SdkError::SchemaParsingError(format!(
            "action \"{name}\" must have at least one leg"
        )));
    }

    if let Some((leg_index, _)) = legs
        .iter()
        .enumerate()
        .skip(1)
        .find(|(_, leg)| !matches!(leg, ActionLeg::CascadeDelete { .. }))
    {
        return Err(SdkError::SchemaParsingError(format!(
            "action \"{name}\": leg {leg_index} is not a `cascade_delete` \
             (only cascade legs are allowed after the primary leg)"
        )));
    }

    Ok(Action {
        name,
        asserts,
        legs,
    })
}

/// Reject any attribute on a primary leg that isn't in `allowed`.
/// Primary-leg `table="..."` is no longer accepted — the table is
/// implicit from the enclosing `table` block.
fn reject_unexpected_attrs(
    node: &KdlNode,
    action_name: &str,
    leg_name: &str,
    allowed: &[&str],
) -> Result<()> {
    for entry in node.entries() {
        let Some(key) = entry.name() else { continue };
        let key_str = key.value();
        if key_str == "table" {
            return Err(SdkError::SchemaParsingError(format!(
                "action \"{action_name}\": `{leg_name}` leg must not carry `table=...` \
                 (the primary leg's table is the enclosing `table` block)"
            )));
        }
        if !allowed.contains(&key_str) {
            return Err(SdkError::SchemaParsingError(format!(
                "action \"{action_name}\": unexpected attribute `{key_str}` on `{leg_name}` leg"
            )));
        }
    }
    Ok(())
}

/// Parse `cascade_delete table="..." where="row.<col> == self.<col>"`.
///
/// The `where` clause is restricted to a single `row.<x> == self.<y>`
/// equality; the cascade reads the secondary index on `<x>` against the
/// primary leg's `self.<y>` value.  Anything more expressive belongs in
/// an action `assert` block instead.
fn parse_cascade_delete_leg(node: &KdlNode, action_name: &str) -> Result<ActionLeg> {
    let table = required_string_attr(node, "table")
        .ok_or_else(|| {
            SdkError::SchemaParsingError(format!(
                "action \"{action_name}\": `cascade_delete` leg missing required `table=...`"
            ))
        })?
        .to_string();
    let where_expr = required_string_attr(node, "where").ok_or_else(|| {
        SdkError::SchemaParsingError(format!(
            "action \"{action_name}\": `cascade_delete` on \"{table}\" missing required \
             `where=\"row.<col> == self.<col>\"`"
        ))
    })?;

    let rule = parse_predicate(where_expr).map_err(|e| {
        SdkError::SchemaParsingError(format!(
            "action \"{action_name}\": `cascade_delete` where=`{where_expr}`: {e}"
        ))
    })?;
    let (where_column, where_self_column) = cascade_where_columns(&rule).ok_or_else(|| {
        SdkError::SchemaParsingError(format!(
            "action \"{action_name}\": `cascade_delete` on \"{table}\": `where` must be a \
                 simple `row.<col> == self.<col>` equality (got `{where_expr}`)"
        ))
    })?;

    Ok(ActionLeg::CascadeDelete {
        table,
        where_column,
        where_self_column,
    })
}

/// Extract `(row_col, self_col)` from a `row.<row_col> == self.<self_col>`
/// equality.  Returns `None` for any other shape.
fn cascade_where_columns(rule: &AccessRule) -> Option<(String, String)> {
    let AccessRule::Comparison { left, op, right } = rule else {
        return None;
    };
    if !matches!(op, ComparisonOp::Equal) {
        return None;
    }
    let row_name = column_name(left, ColumnNamespace::Resource)
        .or_else(|| column_name(right, ColumnNamespace::Resource))?;
    let self_name = column_name(left, ColumnNamespace::SelfRow)
        .or_else(|| column_name(right, ColumnNamespace::SelfRow))?;
    Some((row_name, self_name))
}

fn column_name(value: &RuleValue, want: ColumnNamespace) -> Option<String> {
    match value {
        RuleValue::Column { namespace, name } if *namespace == want => Some(name.clone()),
        _ => None,
    }
}

fn required_string_attr<'a>(node: &'a KdlNode, key: &str) -> Option<&'a str> {
    node.entry(key).and_then(|e| e.value().as_string())
}

/// Parse an optional `cols="a,b,c"` attribute on an update leg.  When
/// present, the verifier rejects any kv whose column isn't in the
/// list.  Absence means "no restriction beyond the table's schema."
fn parse_update_cols_attr(node: &KdlNode, action_name: &str) -> Result<Option<Vec<String>>> {
    let Some(raw) = required_string_attr(node, "cols") else {
        return Ok(None);
    };
    let cols: Vec<String> = raw
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if cols.is_empty() {
        return Err(SdkError::SchemaParsingError(format!(
            "action \"{action_name}\": update leg `cols=` allowlist must list at least one column"
        )));
    }
    Ok(Some(cols))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_table_with_defaults() {
        let kdl = r#"
            table "channels" {
                column "id" type="int" plaintext=#true
                column "name" type="text"
                column "notes" type="list"
            }
        "#;
        let bundle = parse_schema_bundle(kdl).unwrap();
        assert_eq!(bundle.tables.len(), 1);
        let t = &bundle.tables[0];
        assert_eq!(t.table, "channels");
        let schema = t.schema.as_ref().unwrap();
        assert_eq!(schema.name, "channels");
        assert!(schema.auto_increment);
        assert_eq!(schema.columns.len(), 3);
        assert!(schema.columns[0].plaintext);
        assert!(!schema.columns[1].plaintext);
        assert!(schema.columns[2].plaintext); // list implicitly plaintext
        assert!(!schema.columns[2].indexed);
    }

    #[test]
    fn parses_allow_clauses_into_access_control_rows() {
        let kdl = r#"
            table "messages" {
                column "id" type="int" plaintext=#true
                column "user_id" type="int" plaintext=#true indexed=#true
                rules {
                    allow write  "auth.user_id == row.user_id"
                    allow delete "auth.user_id == row.user_id"
                }
            }
        "#;
        let bundle = parse_schema_bundle(kdl).unwrap();
        let acl_table = bundle
            .tables
            .iter()
            .find(|t| t.table == ACCESS_CONTROL_TABLE_NAME)
            .expect("_access_control table emitted");
        assert_eq!(acl_table.rows.len(), 2);
        let ops: Vec<String> = acl_table
            .rows
            .iter()
            .map(|r| r.get("operation").unwrap().as_str().unwrap().to_string())
            .collect();
        assert!(ops.iter().any(|op| op == "write"));
        assert!(ops.iter().any(|op| op == "delete"));
    }

    #[test]
    fn parses_allow_with_logical_operators() {
        let kdl = r#"
            table "messages" {
                column "id" type="int" plaintext=#true
                column "user_id" type="int" plaintext=#true indexed=#true
                rules {
                    allow write "auth.user_id == row.user_id && row.user_id > 0"
                }
            }
        "#;
        let bundle = parse_schema_bundle(kdl).unwrap();
        let acl_table = bundle
            .tables
            .iter()
            .find(|t| t.table == ACCESS_CONTROL_TABLE_NAME)
            .unwrap();
        assert_eq!(acl_table.rows.len(), 1);
    }

    #[test]
    fn parses_auto_increment_false() {
        let kdl = r#"
            table "users_meta" auto_increment=#false {
                column "id" type="int" plaintext=#true
                column "name" type="text"
            }
        "#;
        let bundle = parse_schema_bundle(kdl).unwrap();
        let t = &bundle.tables[0];
        assert!(!t.schema.as_ref().unwrap().auto_increment);
    }

    #[test]
    fn rejects_top_level_acl_node() {
        let kdl = r#"
            acl "messages" {
                allow write "auth.user_id == row.user_id"
            }
        "#;
        let err = parse_schema_bundle(kdl).unwrap_err().to_string();
        assert!(err.contains("Unknown top-level node 'acl'"), "got: {err}");
    }

    #[test]
    fn rejects_top_level_action_node() {
        let kdl = r#"
            action "send_message" {
                insert table="messages"
            }
        "#;
        let err = parse_schema_bundle(kdl).unwrap_err().to_string();
        assert!(
            err.contains("Unknown top-level node 'action'"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_missing_type() {
        let kdl = r#"
            table "x" {
                column "y"
            }
        "#;
        assert!(parse_schema_bundle(kdl).is_err());
    }

    #[test]
    fn parses_action_with_assert_and_legs() {
        let kdl = r#"
            table "messages" {
                column "id" type="int" plaintext=#true
                rules {
                    action "send_message" {
                        assert "self.thread_id == 0 || exists(messages, row.id == self.thread_id)"
                        insert
                    }
                }
            }
        "#;
        let bundle = parse_schema_bundle(kdl).unwrap();
        assert_eq!(bundle.actions.len(), 1);
        let action = &bundle.actions[0];
        assert_eq!(action.name, "send_message");
        assert_eq!(action.asserts.len(), 1);
        assert_eq!(action.legs.len(), 1);
        match &action.legs[0] {
            ActionLeg::Insert { table } => assert_eq!(table, "messages"),
            other => panic!("expected Insert, got {other:?}"),
        }
    }

    #[test]
    fn parses_delete_with_cascade() {
        let kdl = r#"
            table "messages" { column "id" type="int" plaintext=#true }
            table "reactions" {
                column "id" type="int" plaintext=#true
                rules {
                    action "delete_message" {
                        delete
                        cascade_delete table="messages" where="row.thread_id == self.id"
                    }
                }
            }
        "#;
        // delete_message's primary leg is on reactions per nesting.
        let bundle = parse_schema_bundle(kdl).unwrap();
        let action = &bundle.actions[0];
        assert_eq!(action.legs.len(), 2);
        match &action.legs[0] {
            ActionLeg::Delete { table } => assert_eq!(table, "reactions"),
            other => panic!("expected Delete, got {other:?}"),
        }
        match &action.legs[1] {
            ActionLeg::CascadeDelete {
                table,
                where_column,
                where_self_column,
            } => {
                assert_eq!(table, "messages");
                assert_eq!(where_column, "thread_id");
                assert_eq!(where_self_column, "id");
            }
            other => panic!("expected CascadeDelete, got {other:?}"),
        }
    }

    #[test]
    fn rejects_action_with_no_legs() {
        let kdl = r#"
            table "messages" {
                column "id" type="int" plaintext=#true
                rules {
                    action "empty" {
                        assert "auth.user_id == 1"
                    }
                }
            }
        "#;
        assert!(parse_schema_bundle(kdl).is_err());
    }

    #[test]
    fn rejects_cascade_with_non_equality_where() {
        let kdl = r#"
            table "t" { column "id" type="int" plaintext=#true }
            table "c" {
                column "id" type="int" plaintext=#true
                rules {
                    action "bad" {
                        delete
                        cascade_delete table="t" where="row.x > self.y"
                    }
                }
            }
        "#;
        let err = parse_schema_bundle(kdl).unwrap_err().to_string();
        assert!(err.contains("simple"), "got: {err}");
    }

    #[test]
    fn rejects_primary_leg_with_table_attr() {
        let kdl = r#"
            table "messages" {
                column "id" type="int" plaintext=#true
                rules {
                    action "bad" {
                        insert table="messages"
                    }
                }
            }
        "#;
        let err = parse_schema_bundle(kdl).unwrap_err().to_string();
        assert!(err.contains("must not carry `table=...`"), "got: {err}");
    }

    #[test]
    fn rejects_only_via_actions_with_no_actions() {
        let kdl = r#"
            table "messages" {
                column "id" type="int" plaintext=#true
                rules {
                    only_via_actions write
                }
            }
        "#;
        let err = parse_schema_bundle(kdl).unwrap_err().to_string();
        assert!(err.contains("must list at least one action"), "got: {err}");
    }

    #[test]
    fn parses_only_via_actions_write_and_delete() {
        let kdl = r#"
            table "messages" {
                column "id" type="int" plaintext=#true
                rules {
                    only_via_actions write  "send_message" "update_message"
                    only_via_actions delete "delete_message"
                    action "send_message" { insert }
                    action "update_message" { update cols="id" }
                    action "delete_message" { delete }
                }
            }
        "#;
        let bundle = parse_schema_bundle(kdl).unwrap();
        let write_gate = bundle
            .acl_only_via_actions
            .get(&("messages".to_string(), "write".to_string()))
            .expect("write gate");
        assert_eq!(write_gate, &vec!["send_message", "update_message"]);
        let delete_gate = bundle
            .acl_only_via_actions
            .get(&("messages".to_string(), "delete".to_string()))
            .expect("delete gate");
        assert_eq!(delete_gate, &vec!["delete_message"]);
    }

    #[test]
    fn accepts_long_action_name() {
        let name = "a".repeat(8192);
        let kdl = format!(
            r#"
            table "t" {{
                column "id" type="int" plaintext=#true
                rules {{
                    action "{name}" {{ insert }}
                }}
            }}
        "#
        );
        parse_schema_bundle(&kdl).expect("name one byte below threshold must parse");
    }

    #[test]
    fn rejects_duplicate_action_names() {
        let kdl = r#"
            table "messages" {
                column "id" type="int" plaintext=#true
                rules {
                    action "send_message" { insert }
                }
            }
            table "other" {
                column "id" type="int" plaintext=#true
                rules {
                    action "send_message" { insert }
                }
            }
        "#;
        let err = parse_schema_bundle(kdl).unwrap_err().to_string();
        assert!(err.contains("declared more than once"), "got: {err}");
    }

    #[test]
    fn rejects_action_on_non_auto_increment_table() {
        let kdl = r#"
            table "users_meta" auto_increment=#false {
                column "id" type="int" plaintext=#true
                column "name" type="text"
                rules {
                    action "set_user_name" { insert }
                }
            }
        "#;
        let err = parse_schema_bundle(kdl).unwrap_err().to_string();
        assert!(
            err.contains("not auto-increment") || err.contains("delete + insert"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_cascade_targeting_undeclared_table() {
        let kdl = r#"
            table "messages" {
                column "id" type="int" plaintext=#true
                rules {
                    action "delete_message" {
                        delete
                        cascade_delete table="ghost" where="row.message_id == self.id"
                    }
                }
            }
        "#;
        let err = parse_schema_bundle(kdl).unwrap_err().to_string();
        assert!(
            err.contains("not declared") || err.contains("ghost"),
            "got: {err}"
        );
    }

    #[test]
    fn rules_block_is_optional() {
        let kdl = r#"
            table "open_table" {
                column "id" type="int" plaintext=#true
                column "value" type="text"
            }
        "#;
        let bundle = parse_schema_bundle(kdl).unwrap();
        assert_eq!(bundle.tables.len(), 1);
        assert!(bundle.actions.is_empty());
        assert!(bundle.acl_only_via_actions.is_empty());
    }

    #[test]
    fn parses_rules_block_with_only_actions_no_acl() {
        let kdl = r#"
            table "messages" {
                column "id" type="int" plaintext=#true
                rules {
                    action "send_message" { insert }
                }
            }
        "#;
        let bundle = parse_schema_bundle(kdl).unwrap();
        assert_eq!(bundle.actions.len(), 1);
        let acl_table = bundle
            .tables
            .iter()
            .find(|t| t.table == ACCESS_CONTROL_TABLE_NAME);
        assert!(
            acl_table.is_none(),
            "no ACL rows means no _access_control table"
        );
    }

    #[test]
    fn parses_rules_block_with_only_acl_no_actions() {
        let kdl = r#"
            table "users_meta" auto_increment=#false {
                column "id" type="int" plaintext=#true
                column "name" type="text"
                rules {
                    allow write "auth.user_id == row.id"
                    allow delete "auth.user_id == row.id"
                }
            }
        "#;
        let bundle = parse_schema_bundle(kdl).unwrap();
        assert!(bundle.actions.is_empty());
        let acl_table = bundle
            .tables
            .iter()
            .find(|t| t.table == ACCESS_CONTROL_TABLE_NAME)
            .unwrap();
        assert_eq!(acl_table.rows.len(), 2);
    }

    #[test]
    fn parses_text_column() {
        let kdl = r#"
            table "messages" {
                column "id" type="int" plaintext=#true
                column "content" type="text"
            }
        "#;
        let bundle = parse_schema_bundle(kdl).unwrap();
        let schema = bundle.tables[0].schema.as_ref().unwrap();
        assert_eq!(schema.columns[1].column_type, ColumnType::Text);
        assert!(!schema.columns[1].plaintext);
    }

    #[test]
    fn parses_blob_column() {
        let kdl = r#"
            table "files" {
                column "id" type="int" plaintext=#true
                column "data" type="blob"
            }
        "#;
        let bundle = parse_schema_bundle(kdl).unwrap();
        let schema = bundle.tables[0].schema.as_ref().unwrap();
        assert_eq!(schema.columns[1].column_type, ColumnType::Blob);
    }

    #[test]
    fn accepts_text_with_plaintext() {
        let kdl = r#"
            table "t" {
                column "id" type="int" plaintext=#true
                column "name" type="text" plaintext=#true
            }
        "#;
        let bundle = parse_schema_bundle(kdl).unwrap();
        let schema = bundle.tables[0].schema.as_ref().unwrap();
        assert_eq!(schema.columns[1].column_type, ColumnType::Text);
        assert!(schema.columns[1].plaintext);
    }

    #[test]
    fn accepts_blob_with_plaintext() {
        let kdl = r#"
            table "t" {
                column "id" type="int" plaintext=#true
                column "data" type="blob" plaintext=#true
            }
        "#;
        let bundle = parse_schema_bundle(kdl).unwrap();
        let schema = bundle.tables[0].schema.as_ref().unwrap();
        assert_eq!(schema.columns[1].column_type, ColumnType::Blob);
        assert!(schema.columns[1].plaintext);
    }

    #[test]
    fn rejects_blob_with_indexed() {
        let kdl = r#"
            table "t" {
                column "id" type="int" plaintext=#true
                column "data" type="blob" indexed=#true
            }
        "#;
        let err = parse_schema_bundle(kdl).unwrap_err().to_string();
        assert!(
            err.contains("hash-backed columns cannot be indexed"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_text_with_indexed() {
        let kdl = r#"
            table "t" {
                column "id" type="int" plaintext=#true
                column "name" type="text" indexed=#true
            }
        "#;
        let err = parse_schema_bundle(kdl).unwrap_err().to_string();
        assert!(
            err.contains("hash-backed columns cannot be indexed"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_text_in_acl_rule() {
        let kdl = r#"
            table "messages" {
                column "id" type="int" plaintext=#true
                column "content" type="text"
                rules {
                    allow write "row.content == 1"
                }
            }
        "#;
        let err = parse_schema_bundle(kdl).unwrap_err().to_string();
        assert!(
            err.contains("hash-backed columns cannot be referenced by ACL allow write predicate"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_text_in_action_self_assert() {
        let kdl = r#"
            table "messages" {
                column "id" type="int" plaintext=#true
                column "content" type="text"
                rules {
                    action "delete_message" {
                        assert "self.content == 1"
                        delete
                    }
                }
            }
        "#;
        let err = parse_schema_bundle(kdl).unwrap_err().to_string();
        assert!(
            err.contains(
                "hash-backed columns cannot be referenced by action \"delete_message\" assert"
            ),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_text_in_action_exists_assert() {
        let kdl = r#"
            table "users" {
                column "id" type="int" plaintext=#true
                rules {
                    action "remove_user" {
                        assert "exists(messages, row.content == self.id)"
                        delete
                    }
                }
            }
            table "messages" {
                column "id" type="int" plaintext=#true
                column "content" type="text"
            }
        "#;
        let err = parse_schema_bundle(kdl).unwrap_err().to_string();
        assert!(
            err.contains("table \"messages\" column \"content\": hash-backed columns cannot be referenced by action \"remove_user\" assert"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_text_in_cascade_self_column() {
        let kdl = r#"
            table "messages" {
                column "id" type="int" plaintext=#true
                column "content" type="text"
                rules {
                    action "delete_message" {
                        delete
                        cascade_delete table="reactions" where="row.message_id == self.content"
                    }
                }
            }
            table "reactions" {
                column "id" type="int" plaintext=#true
                column "message_id" type="int" plaintext=#true indexed=#true
            }
        "#;
        let err = parse_schema_bundle(kdl).unwrap_err().to_string();
        assert!(
            err.contains("hash-backed columns cannot be referenced by action \"delete_message\" cascade_delete self predicate"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_two_rules_blocks_in_one_table() {
        let kdl = r#"
            table "messages" {
                column "id" type="int" plaintext=#true
                rules { allow write "auth.user_id == 1" }
                rules { allow delete "auth.user_id == 1" }
            }
        "#;
        let err = parse_schema_bundle(kdl).unwrap_err().to_string();
        assert!(err.contains("only one `rules` block"), "got: {err}");
    }

    #[test]
    fn cascade_into_self_table_works() {
        // The demo's `delete_message` cascades back into its own
        // `messages` table to remove thread replies.
        let kdl = r#"
            table "messages" {
                column "id"        type="int" plaintext=#true
                column "thread_id" type="int" plaintext=#true indexed=#true
                rules {
                    action "delete_message" {
                        delete
                        cascade_delete table="messages" where="row.thread_id == self.id"
                    }
                }
            }
        "#;
        let bundle = parse_schema_bundle(kdl).unwrap();
        let action = &bundle.actions[0];
        assert_eq!(action.legs.len(), 2);
        assert!(
            matches!(&action.legs[1], ActionLeg::CascadeDelete { table, .. } if table == "messages")
        );
    }

    #[test]
    fn rejects_unknown_node_in_rules_block() {
        let kdl = r#"
            table "messages" {
                column "id" type="int" plaintext=#true
                rules {
                    wat "huh"
                }
            }
        "#;
        let err = parse_schema_bundle(kdl).unwrap_err().to_string();
        assert!(err.contains("unexpected `wat` node"), "got: {err}");
    }
}
