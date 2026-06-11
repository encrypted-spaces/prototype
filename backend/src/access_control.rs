use crate::error::{Result, SdkError};
use crate::query::{ComparisonOperator, Predicate, Query, QueryOperation, QueryParam};
use crate::storage::Storage;
use crate::SpaceId;
use serde::{Deserialize, Serialize};

pub use crate::internal_schemas::ACCESS_CONTROL_TABLE_NAME;

// Re-export shared ACL types from the acl-types crate.
pub use encrypted_spaces_acl_types::{
    AccessOperation, AccessRule, ColumnNamespace, ComparisonOp, RuleValue,
};

/// Authentication context for database operations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthContext {
    pub uid: Option<i64>,
    pub space_id: SpaceId,
}

impl AuthContext {
    pub fn new(uid: Option<i64>, space_id: SpaceId) -> Self {
        Self { uid, space_id }
    }

    pub fn anonymous(space_id: SpaceId) -> Self {
        Self {
            uid: None,
            space_id,
        }
    }
}

// ─── Backend-specific extensions ─────────────────────────────────────────────

/// Determine the access operation enforced for a write-path query.
pub fn operation_from_query(query: &Query) -> AccessOperation {
    match &query.operation {
        QueryOperation::Insert(_) | QueryOperation::Update(_) => AccessOperation::Write,
        QueryOperation::Delete => AccessOperation::Delete,
        QueryOperation::Select(_) => {
            unreachable!("operation_from_query called with a Select query")
        }
    }
}

/// Convert an access rule to a SQL WHERE clause and parameters.
pub fn rule_to_sql_where_clause(
    rule: &AccessRule,
    auth_context: &AuthContext,
) -> Result<(String, Vec<QueryParam>)> {
    match rule {
        AccessRule::Comparison { left, op, right } => {
            let (left_sql, left_params) = rule_value_to_sql(left, auth_context)?;
            let (right_sql, right_params) = rule_value_to_sql(right, auth_context)?;

            let op_sql = match op {
                ComparisonOp::Equal => "=",
                ComparisonOp::NotEqual => "!=",
                ComparisonOp::Greater => ">",
                ComparisonOp::GreaterEqual => ">=",
                ComparisonOp::Less => "<",
                ComparisonOp::LessEqual => "<=",
            };

            let sql = format!("{left_sql} {op_sql} {right_sql}");
            let mut params = left_params;
            params.extend(right_params);
            Ok((sql, params))
        }
        AccessRule::And(left, right) => {
            let (left_sql, left_params) = rule_to_sql_where_clause(left, auth_context)?;
            let (right_sql, right_params) = rule_to_sql_where_clause(right, auth_context)?;

            let sql = format!("({left_sql}) AND ({right_sql})");
            let mut params = left_params;
            params.extend(right_params);
            Ok((sql, params))
        }
        AccessRule::Or(left, right) => {
            let (left_sql, left_params) = rule_to_sql_where_clause(left, auth_context)?;
            let (right_sql, right_params) = rule_to_sql_where_clause(right, auth_context)?;

            let sql = format!("({left_sql}) OR ({right_sql})");
            let mut params = left_params;
            params.extend(right_params);
            Ok((sql, params))
        }
        AccessRule::Not(inner) => {
            let (inner_sql, inner_params) = rule_to_sql_where_clause(inner, auth_context)?;
            let sql = format!("NOT ({inner_sql})");
            Ok((sql, inner_params))
        }
    }
}

fn rule_value_to_sql(
    value: &RuleValue,
    auth_context: &AuthContext,
) -> Result<(String, Vec<QueryParam>)> {
    match value {
        RuleValue::Int(v) => Ok(("?".to_string(), vec![QueryParam::Integer(*v)])),
        RuleValue::AuthUserId => {
            let user_id = auth_context.uid.unwrap_or(0);
            Ok(("?".to_string(), vec![QueryParam::Integer(user_id)]))
        }
        RuleValue::Column {
            namespace: ColumnNamespace::Resource,
            name,
        } => Ok((name.clone(), vec![])),
        RuleValue::Column {
            namespace: ColumnNamespace::SelfRow,
            name,
        } => Err(SdkError::InvalidQuery(format!(
            "ACL evaluation cannot reference `self.{name}` outside an action-assertion context"
        ))),
    }
}

/// Access control rule record stored in access control table
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlRecord {
    pub id: Option<i64>,
    pub resource_name: String,
    pub operation: AccessOperation,
    #[serde(
        rename = "rule_json",
        serialize_with = "serialize_rule_as_json",
        deserialize_with = "deserialize_rule_from_json"
    )]
    pub rule: AccessRule,
}

fn serialize_rule_as_json<S>(
    rule: &AccessRule,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let json_string = serde_json::to_string(rule).map_err(serde::ser::Error::custom)?;
    serializer.serialize_str(&json_string)
}

fn deserialize_rule_from_json<'de, D>(deserializer: D) -> std::result::Result<AccessRule, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let json_string: String = serde::Deserialize::deserialize(deserializer)?;
    serde_json::from_str(&json_string).map_err(serde::de::Error::custom)
}

pub async fn read_access_rule<T: Storage>(
    storage: &T,
    query: &Query,
) -> Result<Option<AccessRule>> {
    // Convert operation to string for database query
    let operation = operation_from_query(query);

    // Query the access control table using the resource_name index.
    // Post-filter by operation since we only support a single predicate.
    let mut rule_query = Query::new(
        ACCESS_CONTROL_TABLE_NAME.to_string(),
        QueryOperation::Select(vec!["operation".to_string(), "rule_json".to_string()]),
    );
    rule_query.predicate = Some(Predicate {
        column: "resource_name".to_string(),
        operator: ComparisonOperator::Equal,
        values: vec![QueryParam::Text(query.table.to_string())],
        cursor_id: None,
    });

    let rule_rows: Vec<serde_json::Value> = storage.select_all(rule_query).await?;

    if rule_rows.is_empty() {
        return Ok(None);
    }

    // Post-filter by operation (predicate already filtered by resource_name).
    let operation_str = operation.to_string();
    let mut combined_rule: Option<AccessRule> = None;

    for row in rule_rows {
        let row_op = row.get("operation").and_then(|v| v.as_str());
        if row_op != Some(&operation_str) {
            continue;
        }

        if let Some(rule_json_str) = row
            .get("rule_json")
            .and_then(|v| v.as_str())
            .map(String::from)
        {
            let rule: AccessRule = match serde_json::from_str(&rule_json_str) {
                Ok(r) => r,
                Err(e) => {
                    return Err(SdkError::SerializationError(format!(
                        "Failed to deserialize access rule: {} (input: {})",
                        e, rule_json_str
                    )));
                }
            };

            combined_rule = Some(match combined_rule {
                None => rule,
                Some(existing) => existing.and(rule),
            });
        }
    }

    Ok(combined_rule)
}

/// Load the access rule for a query, skipping the _access_control table.
/// This is the common pattern used by storage implementations.
pub async fn load_access_rule<T: Storage>(
    storage: &T,
    query: &Query,
) -> Result<Option<AccessRule>> {
    if query.table == ACCESS_CONTROL_TABLE_NAME {
        return Ok(None);
    }
    read_access_rule(storage, query).await
}
