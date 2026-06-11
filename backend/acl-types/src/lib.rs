//! Shared access-control types and evaluation logic.
//!
//! Single source of truth for the predicate AST (`AccessRule`,
//! `Assertion`, `RuleValue`, `ColumnNamespace`, `ComparisonOp`,
//! `AccessOperation`), the action shapes (`Action`, `ActionLeg`), and the
//! pure `AccessRule::evaluate*` methods.  Both the backend and
//! `changelog_core` depend on it.
//!
//! ## Extension points
//!
//! - **New column namespaces** (e.g. `new.<col>`, `param.<name>`): add a
//!   variant to [`ColumnNamespace`], a grammar rule in `predicate.pest`,
//!   an arm in `ast_build`, and a case in `resolve_value`. The four-way
//!   coupling is intentional — every new namespace needs evaluator
//!   support, not just parse support.
//! - **New call shapes** (e.g. `lookup(...)`, `count(...)`): extend
//!   [`Assertion`] with a new variant alongside `Exists`, add a grammar
//!   alternative under `primary`, and dispatch in `ast_build`. The
//!   action interpreter in `ffproof/changelog_core/src/ops/action_op.rs`
//!   is where evaluator support lives.
//! - **New operators**: extend the precedence ladder in `predicate.pest`
//!   (`or` < `and` < `unary` < `primary`). Each operator slots in
//!   without restructuring.
//! - **New literal types** (string, timestamp, ...): add a [`RuleValue`]
//!   variant and a `ColumnType`-aware comparison in `resolve_value`.
//!   Resolution currently returns `Option<i64>`; a richer type will
//!   require lifting that to a tagged `RuleScalar`.
//!
//! Things deliberately left out, with reasons: regex / arbitrary user
//! code in predicates (zkVM cycle cost is unbounded with regex
//! backtracking), and recursive custom functions (call depth must be
//! statically bounded for proof-cost predictability). Cross-table reads
//! via `exists()` each cost a sparse-Merkle witness in the tracer proof,
//! so the grammar caps them at one per assertion leg today.

pub mod ast_build;
pub use ast_build::{parse_access_rule, parse_assertion, ParseError};

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

// ─── Types ───────────────────────────────────────────────────────────────────

/// Access control operations.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessOperation {
    Write,
    Delete,
}

impl std::fmt::Display for AccessOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccessOperation::Write => write!(f, "write"),
            AccessOperation::Delete => write!(f, "delete"),
        }
    }
}

/// Comparison operators for integer values.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ComparisonOp {
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
}

impl std::fmt::Display for ComparisonOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComparisonOp::Equal => write!(f, "=="),
            ComparisonOp::NotEqual => write!(f, "!="),
            ComparisonOp::Less => write!(f, "<"),
            ComparisonOp::LessEqual => write!(f, "<="),
            ComparisonOp::Greater => write!(f, ">"),
            ComparisonOp::GreaterEqual => write!(f, ">="),
        }
    }
}

/// Which "row" a `RuleValue::Column` reaches into.
///
/// Adding a future namespace (e.g. `new.<col>` for proposed-update
/// values, `param.<name>` for action params) is one new variant here
/// plus one branch in `resolve_value`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ColumnNamespace {
    /// `row.<col>` — the row the predicate is evaluated against.
    /// Inside an `exists()` body this is the foreign-table row; outside
    /// it is the row the ACL/assertion applies to.
    Resource,
    /// `self.<col>` — the action's outer (primary-leg) row.  Only
    /// meaningful inside an action-assertion context; ACL evaluation
    /// without a self-row binding raises an error.
    SelfRow,
}

impl ColumnNamespace {
    fn prefix(&self) -> &'static str {
        match self {
            ColumnNamespace::Resource => "row",
            ColumnNamespace::SelfRow => "self",
        }
    }
}

/// Values that can appear on either side of a comparison.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RuleValue {
    /// Integer literal.
    Int(i64),
    /// Authenticated caller's user id.
    AuthUserId,
    /// A column reference, scoped by its [`ColumnNamespace`].
    Column {
        namespace: ColumnNamespace,
        name: String,
    },
}

impl RuleValue {
    /// Construct a `Column` reference under the given namespace.
    pub fn column(namespace: ColumnNamespace, name: impl Into<String>) -> Self {
        RuleValue::Column {
            namespace,
            name: name.into(),
        }
    }
}

/// Boolean predicate over a single row's columns + the auth context.
///
/// Used as an ACL rule (`write` / `delete` clauses on a table) and as
/// the body of an `exists(...)` inside an [`Assertion`].  No cross-table
/// reads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AccessRule {
    Comparison {
        left: RuleValue,
        op: ComparisonOp,
        right: RuleValue,
    },
    And(Box<AccessRule>, Box<AccessRule>),
    Or(Box<AccessRule>, Box<AccessRule>),
    Not(Box<AccessRule>),
}

/// Action-level assertion.  An `Assertion` extends [`AccessRule`] with
/// cross-table call forms.  Action `assert "..."` blocks parse into
/// this shape; ACL clauses parse into the strictly smaller
/// [`AccessRule`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Assertion {
    /// A basic predicate with no cross-table reads.
    Rule(AccessRule),
    /// True iff at least one row in `table` satisfies `predicate`.  The
    /// body is an [`AccessRule`] (not another `Assertion`), so nested
    /// `exists(A, exists(B, ...))` is not representable.
    Exists {
        table: String,
        predicate: AccessRule,
    },
    And(Box<Assertion>, Box<Assertion>),
    Or(Box<Assertion>, Box<Assertion>),
    Not(Box<Assertion>),
}

impl Assertion {
    pub fn and(self, other: Self) -> Self {
        Self::And(Box::new(self), Box::new(other))
    }

    pub fn or(self, other: Self) -> Self {
        Self::Or(Box::new(self), Box::new(other))
    }

    #[allow(clippy::should_implement_trait)]
    pub fn not(self) -> Self {
        Self::Not(Box::new(self))
    }
}

impl AccessRule {
    pub fn comparison(left: RuleValue, op: ComparisonOp, right: RuleValue) -> Self {
        Self::Comparison { left, op, right }
    }

    pub fn and(self, other: Self) -> Self {
        Self::And(Box::new(self), Box::new(other))
    }

    pub fn or(self, other: Self) -> Self {
        Self::Or(Box::new(self), Box::new(other))
    }

    #[allow(clippy::should_implement_trait)]
    pub fn not(self) -> Self {
        Self::Not(Box::new(self))
    }

    /// Evaluate this rule against a user id and optional resource data.
    /// ACL rules don't carry a self-row context, so `self.<col>`
    /// references raise an error.
    pub fn evaluate(
        &self,
        uid: Option<i64>,
        resource_data: Option<&JsonValue>,
    ) -> Result<bool, String> {
        self.evaluate_with_self(uid, resource_data, None)
    }

    /// Like [`evaluate`] but with an outer-row column map.  Action
    /// assertions pass the action's primary-leg row; plain ACL
    /// evaluation passes `None`.
    pub fn evaluate_with_self(
        &self,
        uid: Option<i64>,
        resource_data: Option<&JsonValue>,
        self_row: Option<&serde_json::Map<String, JsonValue>>,
    ) -> Result<bool, String> {
        match self {
            AccessRule::Comparison { left, op, right } => {
                let left_val = resolve_value(left, uid, resource_data, self_row)?;
                let right_val = resolve_value(right, uid, resource_data, self_row)?;

                let result = match (left_val, right_val) {
                    (Some(l), Some(r)) => match op {
                        ComparisonOp::Equal => l == r,
                        ComparisonOp::NotEqual => l != r,
                        ComparisonOp::Greater => l > r,
                        ComparisonOp::GreaterEqual => l >= r,
                        ComparisonOp::Less => l < r,
                        ComparisonOp::LessEqual => l <= r,
                    },
                    // Any missing operand → deny (matches SQL NULL semantics)
                    _ => false,
                };
                Ok(result)
            }
            AccessRule::And(left, right) => {
                if !left.evaluate_with_self(uid, resource_data, self_row)? {
                    return Ok(false);
                }
                right.evaluate_with_self(uid, resource_data, self_row)
            }
            AccessRule::Or(left, right) => {
                if left.evaluate_with_self(uid, resource_data, self_row)? {
                    return Ok(true);
                }
                right.evaluate_with_self(uid, resource_data, self_row)
            }
            AccessRule::Not(inner) => {
                let result = inner.evaluate_with_self(uid, resource_data, self_row)?;
                Ok(!result)
            }
        }
    }

    /// Collect all `row.<col>` (resource-namespace) names referenced in
    /// this rule.  Used by the verifier to schedule per-column reads.
    pub fn collect_resource_columns(&self, out: &mut Vec<String>) {
        match self {
            AccessRule::Comparison { left, right, .. } => {
                for v in [left, right] {
                    if let RuleValue::Column {
                        namespace: ColumnNamespace::Resource,
                        name,
                    } = v
                    {
                        out.push(name.clone());
                    }
                }
            }
            AccessRule::And(a, b) | AccessRule::Or(a, b) => {
                a.collect_resource_columns(out);
                b.collect_resource_columns(out);
            }
            AccessRule::Not(r) => r.collect_resource_columns(out),
        }
    }
}

// ─── Actions ─────────────────────────────────────────────────────────────────

/// A schema-declared op action.  At op time, the runtime resolves the
/// action by name from authenticated state and dispatches each leg to
/// the matching primitive op.  The action does **not** dictate per-
/// column values; the underlying primitive (`InsertOp` etc.) validates
/// the row's contents per the table's schema and ACL.  What the action
/// adds is:
///
/// - `asserts` — predicates evaluated against (`auth`, self-row
///   plaintext columns) before any leg runs.  Anything `false` aborts.
/// - `legs` — the ordered dispatch list: which primitive op runs on
///   which target table.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Action {
    pub name: String,
    /// `#[serde(default)]` only; don't `skip_serializing_if` empty.
    /// Postcard (the on-wire format for action storage) is positional
    /// and refuses to deserialize a missing field.
    #[serde(default)]
    pub asserts: Vec<Assertion>,
    pub legs: Vec<ActionLeg>,
}

/// On-merk serialization shape for an [`Action`].  The action's `name`
/// is the storage key (`action_storage_key(name)`), so storing it in
/// the value too is redundant.  Encoders write an `ActionBody`; decoders
/// reattach the name from the lookup key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ActionBody {
    #[serde(default)]
    pub asserts: Vec<Assertion>,
    pub legs: Vec<ActionLeg>,
}

impl Action {
    /// Return the name-less storage shape for this action.
    pub fn body(&self) -> ActionBody {
        ActionBody {
            asserts: self.asserts.clone(),
            legs: self.legs.clone(),
        }
    }
}

impl ActionBody {
    /// Reattach the name (sourced from the storage key) and return a
    /// full [`Action`].
    pub fn into_action(self, name: String) -> Action {
        Action {
            name,
            asserts: self.asserts,
            legs: self.legs,
        }
    }
}

/// One leg of an action.  Each variant names a primitive op the
/// `ActionOp` interpreter dispatches the leg's slice of the
/// signed entry to.  The leg only declares the target table — the
/// underlying primitive (`InsertOp` / `UpdateOp` / `DeleteOp`)
/// validates the row's contents per schema, ACL, and the action's
/// assertions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ActionLeg {
    Insert {
        table: String,
    },
    /// `cols` is the allowlist of columns the update may touch.  Any
    /// kv whose column isn't listed is rejected at dispatch.  `None`
    /// means "any column the table's schema declares" — useful for
    /// actions that aren't trying to lock down specific columns.
    Update {
        table: String,
        #[serde(default)]
        cols: Option<Vec<String>>,
    },
    Delete {
        table: String,
    },
    /// Cascade-delete every row in `table` whose `where_column`
    /// integer value equals the primary leg's `self.<where_self_column>`.
    /// The verifier proves completeness with a secondary-index range
    /// read and skips per-row ACL — authorization is inherited from
    /// the action's primary delete leg.
    CascadeDelete {
        table: String,
        where_column: String,
        where_self_column: String,
    },
}

impl ActionLeg {
    pub fn table(&self) -> &str {
        match self {
            ActionLeg::Insert { table }
            | ActionLeg::Update { table, .. }
            | ActionLeg::Delete { table }
            | ActionLeg::CascadeDelete { table, .. } => table,
        }
    }
}

// ─── Internals ───────────────────────────────────────────────────────────────

fn resolve_value(
    value: &RuleValue,
    uid: Option<i64>,
    resource_data: Option<&JsonValue>,
    self_row: Option<&serde_json::Map<String, JsonValue>>,
) -> Result<Option<i64>, String> {
    match value {
        RuleValue::Int(i) => Ok(Some(*i)),
        RuleValue::AuthUserId => Ok(uid),
        RuleValue::Column { namespace, name } => match namespace {
            ColumnNamespace::Resource => {
                let resource = match resource_data {
                    Some(r) => r,
                    None => {
                        return Err(format!(
                            "resource data not available for `{}.{name}`",
                            namespace.prefix()
                        ))
                    }
                };
                match resource.get(name) {
                    Some(v) if v.is_null() => Ok(None),
                    Some(v) => v
                        .as_i64()
                        .map(Some)
                        .ok_or_else(|| format!("resource column '{name}' is not an integer")),
                    None => Ok(None),
                }
            }
            ColumnNamespace::SelfRow => match self_row {
                Some(row) => match row.get(name) {
                    Some(v) if v.is_null() => Ok(None),
                    Some(v) => v
                        .as_i64()
                        .map(Some)
                        .ok_or_else(|| format!("self.{name} is not an integer")),
                    None => Ok(None),
                },
                None => Err(format!(
                    "`self.{name}` referenced outside an action-assertion context"
                )),
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uid_equals_int() {
        let rule = AccessRule::comparison(
            RuleValue::AuthUserId,
            ComparisonOp::Equal,
            RuleValue::Int(42),
        );
        assert!(rule.evaluate(Some(42), None).unwrap());
        assert!(!rule.evaluate(Some(99), None).unwrap());
    }

    #[test]
    fn test_resource_column() {
        let rule = AccessRule::comparison(
            RuleValue::column(ColumnNamespace::Resource, "author_id"),
            ComparisonOp::Equal,
            RuleValue::AuthUserId,
        );
        let data = serde_json::json!({"author_id": 5});
        assert!(rule.evaluate(Some(5), Some(&data)).unwrap());
        assert!(!rule.evaluate(Some(99), Some(&data)).unwrap());
    }

    #[test]
    fn test_missing_column_is_none() {
        let rule = AccessRule::comparison(
            RuleValue::column(ColumnNamespace::Resource, "author_id"),
            ComparisonOp::Equal,
            RuleValue::AuthUserId,
        );
        let data = serde_json::json!({});
        assert!(!rule.evaluate(Some(5), Some(&data)).unwrap());
    }

    #[test]
    fn test_resource_column_without_resource_data_is_error() {
        let rule = AccessRule::comparison(
            RuleValue::column(ColumnNamespace::Resource, "author_id"),
            ComparisonOp::Equal,
            RuleValue::AuthUserId,
        );
        let result = rule.evaluate(Some(5), None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("resource data not available"));
    }

    #[test]
    fn test_comparison_operators() {
        let gt =
            AccessRule::comparison(RuleValue::Int(10), ComparisonOp::Greater, RuleValue::Int(5));
        assert!(gt.evaluate(None, None).unwrap());

        let lt = AccessRule::comparison(RuleValue::Int(3), ComparisonOp::Less, RuleValue::Int(5));
        assert!(lt.evaluate(None, None).unwrap());

        let ne =
            AccessRule::comparison(RuleValue::Int(1), ComparisonOp::NotEqual, RuleValue::Int(2));
        assert!(ne.evaluate(None, None).unwrap());
    }

    #[test]
    fn test_and_or_not() {
        let always_true =
            AccessRule::comparison(RuleValue::Int(1), ComparisonOp::Equal, RuleValue::Int(1));
        let always_false =
            AccessRule::comparison(RuleValue::Int(1), ComparisonOp::Equal, RuleValue::Int(2));

        let and_rule = always_true.clone().and(always_false.clone());
        assert!(!and_rule.evaluate(None, None).unwrap());

        let or_rule = always_true.clone().or(always_false.clone());
        assert!(or_rule.evaluate(None, None).unwrap());

        let not_rule = always_false.not();
        assert!(not_rule.evaluate(None, None).unwrap());
    }

    #[test]
    fn test_collect_resource_columns() {
        let rule = AccessRule::comparison(
            RuleValue::column(ColumnNamespace::Resource, "author_id"),
            ComparisonOp::Equal,
            RuleValue::AuthUserId,
        )
        .and(AccessRule::comparison(
            RuleValue::column(ColumnNamespace::Resource, "dept_id"),
            ComparisonOp::Greater,
            RuleValue::Int(0),
        ));
        let mut cols = Vec::new();
        rule.collect_resource_columns(&mut cols);
        cols.sort();
        assert_eq!(cols, vec!["author_id", "dept_id"]);
    }

    #[test]
    fn test_null_handling() {
        let rule = AccessRule::comparison(
            RuleValue::AuthUserId,
            ComparisonOp::Equal,
            RuleValue::column(ColumnNamespace::Resource, "author_id"),
        );
        // null vs null → deny
        let data = serde_json::json!({"author_id": null});
        assert!(!rule.evaluate(None, Some(&data)).unwrap());
        // null vs value → deny
        let data = serde_json::json!({"author_id": 100});
        assert!(!rule.evaluate(None, Some(&data)).unwrap());
    }

    #[test]
    fn evaluate_with_self_resolves_self_column_refs() {
        let rule = AccessRule::comparison(
            RuleValue::AuthUserId,
            ComparisonOp::Equal,
            RuleValue::column(ColumnNamespace::SelfRow, "sender_id"),
        );
        let mut self_row = serde_json::Map::new();
        self_row.insert("sender_id".to_string(), serde_json::json!(42));

        assert!(rule
            .evaluate_with_self(Some(42), None, Some(&self_row))
            .unwrap());
        assert!(!rule
            .evaluate_with_self(Some(99), None, Some(&self_row))
            .unwrap());

        // No self_row → error.
        assert!(rule.evaluate(Some(42), None).is_err());
    }

    #[test]
    fn evaluate_with_self_missing_column_is_deny() {
        let rule = AccessRule::comparison(
            RuleValue::AuthUserId,
            ComparisonOp::Equal,
            RuleValue::column(ColumnNamespace::SelfRow, "missing"),
        );
        let self_row = serde_json::Map::new();
        // Missing self column resolves to None → deny.
        assert!(!rule
            .evaluate_with_self(Some(42), None, Some(&self_row))
            .unwrap());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let rule = AccessRule::comparison(
            RuleValue::AuthUserId,
            ComparisonOp::Equal,
            RuleValue::column(ColumnNamespace::Resource, "author_id"),
        )
        .and(AccessRule::comparison(
            RuleValue::Int(1),
            ComparisonOp::Equal,
            RuleValue::Int(1),
        ));

        let json_str = serde_json::to_string(&rule).unwrap();
        let deserialized: AccessRule = serde_json::from_str(&json_str).unwrap();
        assert_eq!(rule, deserialized);
    }

    #[test]
    fn action_postcard_roundtrip() {
        // Postcard isn't a workspace dep for acl-types, so just test
        // serde_json roundtrip for the action shape.  Postcard is
        // exercised in the action storage tests downstream.
        let action = Action {
            name: "send_message".to_string(),
            asserts: vec![],
            legs: vec![
                ActionLeg::Insert {
                    table: "messages".to_string(),
                },
                ActionLeg::CascadeDelete {
                    table: "reactions".to_string(),
                    where_column: "message_id".to_string(),
                    where_self_column: "id".to_string(),
                },
            ],
        };
        let s = serde_json::to_string(&action).unwrap();
        let back: Action = serde_json::from_str(&s).unwrap();
        assert_eq!(action, back);
    }

    #[test]
    fn assertion_serialization_roundtrip() {
        let assertion = Assertion::Or(
            Box::new(Assertion::Rule(AccessRule::comparison(
                RuleValue::column(ColumnNamespace::SelfRow, "thread_id"),
                ComparisonOp::Equal,
                RuleValue::Int(0),
            ))),
            Box::new(Assertion::Exists {
                table: "messages".to_string(),
                predicate: AccessRule::comparison(
                    RuleValue::column(ColumnNamespace::Resource, "id"),
                    ComparisonOp::Equal,
                    RuleValue::column(ColumnNamespace::SelfRow, "thread_id"),
                ),
            }),
        );
        let s = serde_json::to_string(&assertion).unwrap();
        let back: Assertion = serde_json::from_str(&s).unwrap();
        assert_eq!(assertion, back);
    }
}
