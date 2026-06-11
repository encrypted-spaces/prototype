pub mod action_op;
pub mod create_space_op;
pub mod delete_op;
pub mod extend_op;
pub mod insert_op;
pub mod invite_user_op;
pub mod list_op;
#[cfg(test)]
mod op_tests;
pub mod reduce_op;
pub mod refresh_keys_op;
pub mod rekey_op;
pub mod remove_user_op;
pub mod update_op;

use crate::changelog::{ChangelogEntry, ChangelogError, KvData, OpType, MAX_LOGMSG_ENTRIES};
use crate::{BatchOp, ProvenRead, ReadOp, TraceStep};
use encrypted_spaces_acl_types::{AccessRule, Action, ActionBody};
use encrypted_spaces_storage_encoding::keys::{
    acl_only_via_actions_key, acl_rule_key, action_storage_key, column_key, decode_action_value,
    index_key, index_value_prefix, parse_column_key_ref, parse_key, row_id_to_bytes, row_key,
    schema_columns_key, schema_id_mode_key, schema_indexes_key, schema_list_columns_key,
    schema_next_id_key, ParsedKey, TupleConversionError, KEY_HISTORY_TABLE, RETENTION_TABLE,
    USERS_TABLE,
};
use encrypted_spaces_storage_encoding::stored_value::{bytes_to_value, value_to_bytes};
use encrypted_spaces_storage_encoding::{decode_column_names, TupleElement};
use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

// Re-export key types from sub-modules
pub use action_op::ActionOp;
pub use create_space_op::CreateSpaceOp;
pub use delete_op::DeleteOp;
pub use extend_op::ExtendOp;
pub use insert_op::InsertOp;
pub use invite_user_op::InviteUserOp;
pub use list_op::{ListAppendOp, ListDeleteOp, ListInsertOp, ListUpdateOp};
pub use reduce_op::ReduceOp;
pub use refresh_keys_op::{RefreshKeysOp, REFRESH_KEYS_ALLOWED_COLUMNS};
pub use rekey_op::RekeyOp;
pub use remove_user_op::RemoveUserOp;
pub use update_op::UpdateOp;

// ─── Shared column-op validation helpers ─────────────────────────────────────

/// Validate that the entry count does not exceed `MAX_LOGMSG_ENTRIES`.
pub(crate) fn validate_max_entries(
    entry: &ChangelogEntry,
    op_name: &str,
) -> Result<(), ChangelogError> {
    let num_entries = entry.message.entries.len();
    if num_entries > MAX_LOGMSG_ENTRIES {
        return Err(ChangelogError::Generic(format!(
            "{op_name}: entry count {num_entries} exceeds MAX_LOGMSG_ENTRIES={MAX_LOGMSG_ENTRIES}"
        )));
    }
    Ok(())
}

/// Validate that the changelog entry's keys are in strictly ascending order.
pub(crate) fn validate_sorted_entries(
    entry: &ChangelogEntry,
    op_name: &str,
) -> Result<(), ChangelogError> {
    for w in entry.message.entries.windows(2) {
        if w[0].key >= w[1].key {
            return Err(ChangelogError::Generic(format!(
                "{op_name}: entries must be sorted by key"
            )));
        }
    }
    Ok(())
}

/// Reject operations that target a reserved/internal table (name beginning with `_`).
///
/// Internal tables (`_users`, `_access_control`, `_key_history`, `_retention`) may
/// only be mutated via dedicated ops (`RefreshKeysOp`, `CreateSpaceOp`, `InviteUserOp`,
/// `RemoveUserOp`). Regular insert/update/delete must refuse them.
pub(crate) fn validate_not_internal_table(
    table: &str,
    op_name: &str,
) -> Result<(), ChangelogError> {
    if table.starts_with('_') {
        return Err(ChangelogError::Generic(format!(
            "{op_name}: table '{table}' is reserved and cannot \
             be modified by {op_name} — use the dedicated op instead"
        )));
    }
    Ok(())
}

/// Clone the per-entry keys out of a changelog entry.
///
/// For row update/delete ops (and any op whose changelog entry already
/// carries the real row_id), this is the trusted source of column keys
/// the verifier should use.
pub fn column_keys_from_entry(entry: &ChangelogEntry) -> Vec<Vec<u8>> {
    entry
        .message
        .entries
        .iter()
        .map(|kv| kv.key.clone())
        .collect()
}

/// Parsed view of a changelog kv whose key has the exact table-column shape.
pub(crate) struct ParsedColumnEntry<'a> {
    pub kv: &'a KvData,
    pub key: &'a [u8],
    pub table: Cow<'a, str>,
    pub row_id: i64,
    pub column: Cow<'a, str>,
}

/// Parse each changelog entry key once for insert/update table validation.
pub(crate) fn parse_column_entries<'a>(
    entry: &'a ChangelogEntry,
    op_name: &str,
) -> Result<Vec<ParsedColumnEntry<'a>>, ChangelogError> {
    entry
        .message
        .entries
        .iter()
        .enumerate()
        .map(|(i, kv)| {
            let parsed = parse_column_key_ref(&kv.key).map_err(|e| {
                ChangelogError::KeyMismatch(format!(
                    "{op_name}: entry[{i}] is not a column key: {e}"
                ))
            })?;
            Ok(ParsedColumnEntry {
                kv,
                key: kv.key.as_slice(),
                table: parsed.table,
                row_id: parsed.row_id,
                column: parsed.column,
            })
        })
        .collect()
}

pub(crate) fn validate_same_table<'e, 'a>(
    entries: &'e [ParsedColumnEntry<'a>],
    op_name: &str,
) -> Result<&'e str, ChangelogError> {
    let first = entries.first().ok_or_else(|| {
        ChangelogError::KeyMismatch(format!("{op_name}: no column keys provided"))
    })?;
    let table = first.table.as_ref();
    for (i, entry) in entries.iter().enumerate().skip(1) {
        let t = entry.table.as_ref();
        if t != table {
            return Err(ChangelogError::KeyMismatch(format!(
                "{op_name}: column_key[{i}] has table '{t}' \
                 but expected '{table}' — all column_keys must refer to the same table"
            )));
        }
    }
    Ok(table)
}

pub(crate) fn validate_same_table_row<'e, 'a>(
    entries: &'e [ParsedColumnEntry<'a>],
    op_name: &str,
    label: &str,
) -> Result<(&'e str, i64), ChangelogError> {
    let first = entries.first().ok_or_else(|| {
        ChangelogError::Generic(format!("{op_name}: {label} proof has no column keys"))
    })?;
    let table = first.table.as_ref();
    let row_id = first.row_id;
    for (i, entry) in entries.iter().enumerate().skip(1) {
        let t = entry.table.as_ref();
        let r = entry.row_id;
        if t != table || r != row_id {
            return Err(ChangelogError::Generic(format!(
                "{op_name}: {label} proof key[{i}] targets \
                 ({t}, {r}) but key[0] targets ({table}, {row_id}) — \
                 one insert must bind all columns to a single (table, row_id)"
            )));
        }
    }
    Ok((table, row_id))
}

pub(crate) fn column_name_set<'e, 'a>(entries: &'e [ParsedColumnEntry<'a>]) -> BTreeSet<&'e str> {
    entries.iter().map(|entry| entry.column.as_ref()).collect()
}

pub(crate) fn unique_row_ids(entries: &[ParsedColumnEntry<'_>]) -> Vec<i64> {
    entries
        .iter()
        .map(|entry| entry.row_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Replace the placeholder `row_id` in a column key with the
/// (server-assigned, verifier-trusted) `new_row_id`.
///
/// Used by insert-flavoured ops (Insert AutoAssign, CreateSpace,
/// InviteUser, RefreshKeys/RemoveUser key_history insert,
/// Extend/Reduce/Rekey/RemoveUser retention chain) to derive the real
/// per-column keys from the placeholder keys carried by the signed entry.
pub(crate) fn rebuild_column_key_with_row_id(
    entry_key: &[u8],
    new_row_id: i64,
    op_name: &str,
) -> Result<Vec<u8>, ChangelogError> {
    match parse_key(entry_key) {
        Ok(ParsedKey::Column {
            table,
            row_id,
            column,
        }) => {
            if row_id != 0 {
                return Err(ChangelogError::KeyMismatch(format!(
                    "{op_name}: entry key for \
                     column '{column}' on table '{table}' has row_id={row_id} \
                     but expected the placeholder row_id=0"
                )));
            }
            Ok(column_key(&table, new_row_id, &column))
        }
        _ => Err(ChangelogError::KeyMismatch(format!(
            "{op_name}: entry key is not a column key"
        ))),
    }
}

/// Derive a slice of per-column keys from a sub-slice of `KvData` entries
/// by substituting the placeholder `row_id = 0` with `new_row_id`.
pub(crate) fn derive_column_keys_with_row_id(
    entries: &[KvData],
    new_row_id: i64,
    op_name: &str,
) -> Result<Vec<Vec<u8>>, ChangelogError> {
    entries
        .iter()
        .map(|kv| rebuild_column_key_with_row_id(&kv.key, new_row_id, op_name))
        .collect()
}

/// Derive per-column keys for a chain of inserted rows by substituting
/// the placeholder `row_id = 0` with consecutive ids drawn from the
/// authenticated next-id counter (`counter, counter+1, ...`).
///
/// Entries are globally sorted by key, so repeated placeholder columns for
/// multiple rows appear grouped by column (`key,key,value,value`), not by row.
/// The occurrence index within each column group determines the row offset.
pub(crate) fn derive_column_keys_for_chain(
    entries: &[KvData],
    counter: i64,
    col_count: usize,
    op_name: &str,
) -> Result<Vec<Vec<u8>>, ChangelogError> {
    if col_count == 0 {
        return Err(ChangelogError::Generic(format!(
            "{op_name}: col_count must be non-zero"
        )));
    }
    if !entries.len().is_multiple_of(col_count) {
        return Err(ChangelogError::Generic(format!(
            "{op_name}: entry count {} is not a multiple of col_count={col_count}",
            entries.len()
        )));
    }
    let num_rows = entries.len() / col_count;
    let mut column_counts = std::collections::BTreeMap::<String, usize>::new();
    let mut keys = Vec::with_capacity(entries.len());
    for kv in entries {
        let column = match parse_key(&kv.key) {
            Ok(ParsedKey::Column { column, .. }) => column,
            _ => {
                return Err(ChangelogError::KeyMismatch(format!(
                    "{op_name}: entry key is not a column key"
                )));
            }
        };
        let occurrence_idx = column_counts.entry(column).or_insert(0);
        if *occurrence_idx >= num_rows {
            return Err(ChangelogError::Generic(format!(
                "{op_name}: column appears more than {num_rows} times"
            )));
        }
        let row_id = counter.checked_add(*occurrence_idx as i64).ok_or_else(|| {
            ChangelogError::Generic(format!(
                "{op_name}: row_id chain overflowed at counter={counter}+{occurrence_idx}"
            ))
        })?;
        keys.push(rebuild_column_key_with_row_id(&kv.key, row_id, op_name)?);
        *occurrence_idx += 1;
    }
    if column_counts.len() != col_count || column_counts.values().any(|count| *count != num_rows) {
        return Err(ChangelogError::Generic(format!(
            "{op_name}: entries do not contain {num_rows} values for each of {col_count} columns"
        )));
    }
    Ok(keys)
}

/// Result of partitioning a composite changelog entry by destination table.
///
/// Field ordering reflects the canonical sort order of the changelog
/// entry keys: `_key_history` < `_retention` < `_users` (alphabetical on
/// the table name segment of the key).
pub(crate) struct PartitionedCompositeEntry {
    /// `(entry_index_within_entry, kv)` pairs targeting `_key_history`.
    pub key_history: Vec<KvData>,
    /// `(entry_index_within_entry, kv)` pairs targeting `_retention`.
    pub retention: Vec<KvData>,
    /// `(entry_index_within_entry, kv)` pairs targeting `_users`.
    pub users: Vec<KvData>,
}

/// Partition a composite op's changelog entries by table.
///
/// Used by CreateSpace, InviteUser, RemoveUser, and RefreshKeys whose
/// signed `entries` mix writes targeting `_users`, `_retention`, and
/// `_key_history`.  Entries that don't match any of those tables are
/// rejected.
pub(crate) fn partition_composite_entry(
    entry: &ChangelogEntry,
    op_name: &str,
) -> Result<PartitionedCompositeEntry, ChangelogError> {
    let mut users = Vec::new();
    let mut retention = Vec::new();
    let mut key_history = Vec::new();
    for (i, kv) in entry.message.entries.iter().enumerate() {
        match parse_key(&kv.key) {
            Ok(ParsedKey::Column { table, .. }) => match table.as_str() {
                USERS_TABLE => users.push(kv.clone()),
                RETENTION_TABLE => retention.push(kv.clone()),
                KEY_HISTORY_TABLE => key_history.push(kv.clone()),
                other => {
                    return Err(ChangelogError::KeyMismatch(format!(
                        "{op_name}: entry[{i}] targets unexpected table '{other}'"
                    )));
                }
            },
            _ => {
                return Err(ChangelogError::KeyMismatch(format!(
                    "{op_name}: entry[{i}] is not a column key"
                )));
            }
        }
    }
    Ok(PartitionedCompositeEntry {
        key_history,
        retention,
        users,
    })
}

pub(crate) fn is_provisional_status(status: i64) -> bool {
    status == 0
}

fn parse_i64_column_value(value: &[u8]) -> Option<i64> {
    bytes_to_value(value).ok().and_then(|v| v.as_i64())
}

pub(crate) fn decode_i64_column_value(
    value: &[u8],
    op_name: &str,
    label: &str,
) -> Result<i64, ChangelogError> {
    parse_i64_column_value(value).ok_or_else(|| {
        ChangelogError::Generic(format!(
            "{op_name}: failed to decode {label}: value is not a valid integer"
        ))
    })
}

pub(crate) fn read_user_status(
    uid: u32,
    op_name: &str,
    reader: &mut dyn OpReader,
) -> Result<Option<i64>, ChangelogError> {
    let status_key = column_key(USERS_TABLE, uid as i64, "status");
    let status_read = reader.read(ReadOp::Key(status_key))?;
    let (_, status_value) = status_read.results.first().ok_or_else(|| {
        ChangelogError::Generic(format!("{op_name}: user {uid} not found in users table"))
    })?;

    Ok(parse_i64_column_value(status_value))
}

pub(crate) fn extract_i64_column_from_entry(
    entry: &ChangelogEntry,
    table: &str,
    column_name: &str,
    op_name: &str,
) -> Result<i64, ChangelogError> {
    let value = entry
        .message
        .entries
        .iter()
        .find_map(|kv| match parse_key(&kv.key) {
            Ok(ParsedKey::Column {
                table: key_table,
                column,
                ..
            }) if key_table == table && column == column_name => Some(kv.value.as_slice()),
            _ => None,
        })
        .ok_or_else(|| {
            ChangelogError::Generic(format!(
                "{op_name}: {table} insert is missing {column_name} column"
            ))
        })?;

    decode_i64_column_value(value, op_name, &format!("{table}.{column_name}"))
}

/// Read the user's status column via `reader`, verify the user exists, and
/// enforce provisional user restrictions: provisional users (status == 0)
/// may only perform `RefreshKeys`.
pub(crate) fn validate_user_access(
    entry: &ChangelogEntry,
    op_type: OpType,
    op_name: &str,
    reader: &mut dyn OpReader,
) -> Result<(), ChangelogError> {
    let is_provisional = read_user_status(entry.uid, op_name, reader)?
        .map(is_provisional_status)
        .unwrap_or(false);

    if is_provisional && op_type != OpType::RefreshKeys {
        return Err(ChangelogError::Generic(format!(
            "{op_name}: provisional user {} may only perform RefreshKeys",
            entry.uid
        )));
    }

    Ok(())
}

/// Evaluate an ACL rule against resource_data built from (column_name, value_bytes) pairs.
/// Used by InsertOp (new values), UpdateOp (existing + new), DeleteOp (existing from tree).
pub(crate) fn evaluate_acl(
    acl: &AclCheck,
    uid: u32,
    column_values: &[(String, Vec<u8>)],
    check_label: &str,
) -> Result<(), ChangelogError> {
    let mut resource_map = serde_json::Map::new();
    for (col_name, bytes) in column_values {
        if acl.needed_columns.iter().any(|c| c == col_name) {
            let val = bytes_to_value(bytes).map_err(|e| {
                ChangelogError::AclDenied(format!(
                    "fail-closed: column '{col_name}' for {check_label} could not be decoded: {e}"
                ))
            })?;
            resource_map.insert(col_name.clone(), val);
        }
    }
    let resource_data = serde_json::Value::Object(resource_map);

    match acl.rule.evaluate(Some(uid as i64), Some(&resource_data)) {
        Ok(true) => Ok(()),
        Ok(false) => Err(ChangelogError::AclDenied(format!(
            "{check_label}: uid={uid} resource={}",
            acl.resource_name
        ))),
        Err(e) => Err(ChangelogError::AclDenied(format!(
            "{check_label} evaluation error: {e}"
        ))),
    }
}

/// Read a list of semantic column values from the tree for a given row.
/// Returns `(column_name, value_bytes)` pairs for the needed columns.
///
/// `id` is synthesized from `row_id` rather than read from the tree:
/// the SDK never stores `id` as a separate column value (see
/// `backend/src/merk_storage/mod.rs::get_row_data_from_query`, which skips
/// `ID_FIELD`). The SDK's ACL evaluation sees `id` because SELECT
/// reassembles it from the column key prefix; the prover must do the same
/// or `ResourceColumn("id")` rules diverge.
pub(crate) fn read_columns_from_tree(
    table: &str,
    row_id: i64,
    needed_columns: &[String],
    reader: &mut dyn OpReader,
) -> Result<Vec<(String, Vec<u8>)>, ChangelogError> {
    let mut values = Vec::new();
    for col_name in needed_columns {
        if col_name == "id" {
            let bytes = value_to_bytes(&serde_json::Value::from(row_id)).map_err(|e| {
                ChangelogError::Generic(format!("encode synthesized id for row {row_id}: {e}"))
            })?;
            values.push((col_name.clone(), bytes));
            continue;
        }
        let key = column_key(table, row_id, col_name);
        let proven = reader.read(ReadOp::Key(key))?;
        if let Some((_, val_bytes)) = proven.results.first() {
            values.push((col_name.clone(), val_bytes.clone()));
        }
    }
    Ok(values)
}

/// Extract `(column_name, value_bytes)` pairs from a changelog entry's
/// `KvData` for the columns referenced by an ACL rule.
///
/// This is **ACL-specific** — callers must pass `AclCheck.needed_columns`.
///
/// `id` is synthesized from the entry's row id rather than read from a
/// column entry — `id` is never stored as a separate column value, it is
/// encoded into each column key's prefix. This mirrors
/// `read_columns_from_tree`'s handling of `id` for Update/Delete/List ACL
/// paths and what SELECT reassembles when the SDK evaluates ACL rules
/// against fetched rows. Without this, any ACL referencing
/// `ResourceColumn("id")` resolves to NULL on insert and is denied.
///
/// Note: this function does not require every needed column to be present
/// in the entry — partial updates may legitimately touch only a subset.
/// Insert-shaped callers, where every column is always written, must
/// additionally call [`require_all_acl_columns_present`] to fail closed
/// on absence.
///
pub(crate) fn extract_acl_columns_from_entry(
    entry: &ChangelogEntry,
    table: &str,
    row_id_filter: Option<i64>,
    id_value: Option<i64>,
    needed_columns: &[String],
) -> Result<Vec<(String, Vec<u8>)>, ChangelogError> {
    let mut values = Vec::new();

    if needed_columns.iter().any(|c| c == "id") {
        let synthesized = id_value.or_else(|| {
            entry
                .message
                .entries
                .iter()
                .find_map(|kv| match parse_key(&kv.key) {
                    Ok(ParsedKey::Column {
                        table: key_table,
                        row_id,
                        ..
                    }) if key_table == table && row_id_filter.is_none_or(|want| want == row_id) => {
                        Some(row_id)
                    }
                    _ => None,
                })
        });
        if let Some(row_id) = synthesized {
            if let Ok(bytes) = value_to_bytes(&serde_json::Value::from(row_id)) {
                values.push(("id".to_string(), bytes));
            }
        }
    }

    for kv in &entry.message.entries {
        if let Ok(ParsedKey::Column {
            table: key_table,
            row_id,
            column,
        }) = parse_key(&kv.key)
        {
            if key_table != table || row_id_filter.is_some_and(|want| want != row_id) {
                continue;
            }
            if column == "id" {
                // `id` is synthesized above; no per-column kv carries it.
                continue;
            }
            if needed_columns.iter().any(|c| c == &column) {
                values.push((column, kv.value.clone()));
            }
        }
    }
    Ok(values)
}

/// Strict-mode check for op shapes where every ACL-needed column **must**
/// be present in the entry
/// (Insert, where the writer supplies the full row). Returns `AclDenied`
/// if any needed column is absent — without this guard, a `Not(...)`-
/// shaped rule would silently evaluate to true on an omitted column.
pub(crate) fn require_all_acl_columns_present(
    extracted: &[(String, Vec<u8>)],
    needed_columns: &[String],
) -> Result<(), ChangelogError> {
    for needed in needed_columns {
        if !extracted.iter().any(|(c, _)| c == needed) {
            return Err(ChangelogError::AclDenied(format!(
                "fail-closed: column '{needed}' is required for ACL \
                 evaluation but is not present in the changelog entry"
            )));
        }
    }
    Ok(())
}

/// Read the ACL rule for a single `(table, op)` from authenticated
/// state.  Returns `Ok(None)` if no rule was declared for this pair
/// (default-open semantics).  `Err` if the stored blob fails to
/// deserialize.
pub(crate) fn read_acl_rule(
    reader: &mut dyn OpReader,
    table: &str,
    op: &str,
    ctx: &OpContext,
) -> Result<Option<AccessRule>, ChangelogError> {
    let cache_key = (table.to_string(), op.to_string());
    if let Some(cached) = ctx.static_cache.state.borrow().acl_rules.get(&cache_key) {
        return Ok(cached.clone());
    }
    let key = acl_rule_key(table, op);
    let read = reader.read(ReadOp::Key(key))?;
    let result = match read.results.first() {
        None => None,
        Some((_, blob_bytes)) => {
            let rule = postcard::from_bytes(blob_bytes).map_err(|e| {
                ChangelogError::Generic(format!(
                    "ACL rule for ({table}, {op}) deserialization failed: {e}"
                ))
            })?;
            Some(rule)
        }
    };
    ctx.static_cache
        .state
        .borrow_mut()
        .acl_rules
        .insert(cache_key, result.clone());
    Ok(result)
}

/// Resolve an `exists(table, predicate)` clause inside an
/// [`Assertion::Exists`].  The predicate must be a conjunction of
/// `row.<col> == <value>` equalities; each conjunct compiles to one
/// indexed read against `table`, and the result is the intersection of
/// those reads.  `id` is handled specially via a row-prefix scan rather
/// than a secondary index lookup.
///
/// `<value>` may be an integer literal, `auth.user_id`, or
/// `self.<name>`.  References to `row.<col>` only make sense as the
/// left-hand side of each comparison (the foreign-table row);
/// nesting `exists()` inside `exists()` was already rejected at parse
/// time so we don't see it here.
#[allow(dead_code)] // used by ActionOp interpreter
pub(crate) fn resolve_exists_in_op(
    table: &str,
    inner: &AccessRule,
    self_uid: u32,
    self_row: &BTreeMap<String, i64>,
    reader: &mut dyn OpReader,
    op_name: &str,
) -> Result<bool, ChangelogError> {
    use encrypted_spaces_acl_types::{ColumnNamespace, ComparisonOp, RuleValue};

    fn collect_conjuncts<'a>(rule: &'a AccessRule, out: &mut Vec<&'a AccessRule>) {
        match rule {
            AccessRule::And(a, b) => {
                collect_conjuncts(a, out);
                collect_conjuncts(b, out);
            }
            _ => out.push(rule),
        }
    }

    let mut conjuncts: Vec<&AccessRule> = Vec::new();
    collect_conjuncts(inner, &mut conjuncts);

    let is_row_col = |v: &RuleValue| {
        matches!(
            v,
            RuleValue::Column {
                namespace: ColumnNamespace::Resource,
                ..
            }
        )
    };
    let row_col_name = |v: &RuleValue| match v {
        RuleValue::Column {
            namespace: ColumnNamespace::Resource,
            name,
        } => Some(name.clone()),
        _ => None,
    };

    let mut constraints: Vec<(String, i64)> = Vec::new();
    for conj in conjuncts {
        let (left, right) = match conj {
            AccessRule::Comparison {
                left,
                op: ComparisonOp::Equal,
                right,
            } => (left, right),
            _ => {
                return Err(ChangelogError::Generic(format!(
                    "{op_name}: exists({table}, ...) inner predicate must be \
                     `row.<col> == <value>` (got {conj:?})"
                )))
            }
        };
        let (col, value_expr) = match (is_row_col(left), is_row_col(right)) {
            (true, false) => (row_col_name(left).unwrap(), right),
            (false, true) => (row_col_name(right).unwrap(), left),
            _ => {
                return Err(ChangelogError::Generic(format!(
                    "{op_name}: exists({table}, ...) conjunct must have \
                     `row.<col>` on exactly one side"
                )))
            }
        };
        let value = match value_expr {
            RuleValue::Int(n) => *n,
            RuleValue::AuthUserId => self_uid as i64,
            RuleValue::Column {
                namespace: ColumnNamespace::SelfRow,
                name,
            } => self_row.get(name).copied().ok_or_else(|| {
                ChangelogError::Generic(format!(
                    "{op_name}: exists({table}, ...) references `self.{name}` \
                     but the self row has no integer value for that column"
                ))
            })?,
            RuleValue::Column {
                namespace: ColumnNamespace::Resource,
                ..
            } => unreachable!("ruled out by the side-selection above"),
        };
        constraints.push((col, value));
    }

    if constraints.is_empty() {
        return Err(ChangelogError::Generic(format!(
            "{op_name}: exists({table}, ...) needs at least one constraint"
        )));
    }

    // Partition on `id`.  Predicates that pin a primary-key value (the
    // common shape: `row.id == self.thread_id && row.<col> == ...`)
    // resolve to a single candidate row, so we can verify each
    // remaining conjunct with one column-key read instead of scanning
    // its secondary index and intersecting.
    let mut id_value: Option<i64> = None;
    let mut other_constraints: Vec<(String, i64)> = Vec::new();
    for (col, value) in constraints {
        if col == "id" {
            match id_value {
                None => id_value = Some(value),
                Some(prev) if prev != value => return Ok(false),
                Some(_) => {}
            }
        } else {
            other_constraints.push((col, value));
        }
    }

    if let Some(row_id) = id_value {
        if row_id == 0 {
            return Ok(false);
        }
        if other_constraints.is_empty() {
            let rk = row_key(table, row_id);
            let read = reader.read(ReadOp::Prefix(rk))?;
            return Ok(!read.results.is_empty());
        }
        for (col, expected) in &other_constraints {
            let key = column_key(table, row_id, col);
            let read = reader.read(ReadOp::Key(key))?;
            let Some((_, value_bytes)) = read.results.first() else {
                return Ok(false);
            };
            let actual = decode_i64_column_value(
                value_bytes,
                op_name,
                &format!("{table}.{col} (row {row_id})"),
            )?;
            if actual != *expected {
                return Ok(false);
            }
        }
        return Ok(true);
    }

    // No id constraint — fall back to secondary-index intersection.
    let mut matching: Option<BTreeSet<i64>> = None;
    for (col, value) in other_constraints {
        let row_ids = read_indexed_row_ids(table, &col, value, reader, op_name)?;
        let s: BTreeSet<i64> = row_ids.into_iter().collect();
        matching = Some(match matching {
            None => s,
            Some(prev) => prev.intersection(&s).copied().collect(),
        });
    }
    Ok(matching.map(|s| !s.is_empty()).unwrap_or(false))
}

/// Read the action-gating list for a single `(table, op)` from
/// authenticated state.  Returns `Ok(None)` if no gating clause is
/// declared (default-open semantics: no clause means no constraint).
pub(crate) fn read_only_via_actions(
    reader: &mut dyn OpReader,
    table: &str,
    op: &str,
    ctx: &OpContext,
) -> Result<Option<Vec<String>>, ChangelogError> {
    let cache_key = (table.to_string(), op.to_string());
    if let Some(cached) = ctx
        .static_cache
        .state
        .borrow()
        .only_via_actions
        .get(&cache_key)
    {
        return Ok(cached.clone());
    }
    let key = acl_only_via_actions_key(table, op);
    let read = reader.read(ReadOp::Key(key))?;
    let result = match read.results.first() {
        None => None,
        Some((_, bytes)) => {
            let actions: Vec<String> = postcard::from_bytes(bytes).map_err(|e| {
                ChangelogError::Generic(format!(
                    "only_via_actions for ({table}, {op}) deserialization failed: {e}"
                ))
            })?;
            Some(actions)
        }
    };
    ctx.static_cache
        .state
        .borrow_mut()
        .only_via_actions
        .insert(cache_key, result.clone());
    Ok(result)
}

/// Enforce `*_only_via_actions` on a primitive op.  If `(table, op_str)`
/// has a gating list, the caller must be inside an `OpType::Action`
/// dispatch whose action name is in the list.
pub(crate) fn enforce_only_via_actions(
    table: &str,
    op_str: &str,
    op_name: &str,
    ctx: &OpContext,
    reader: &mut dyn OpReader,
) -> Result<(), ChangelogError> {
    let Some(allowed) = read_only_via_actions(reader, table, op_str, ctx)? else {
        return Ok(());
    };
    let Some(action_name) = &ctx.action_name else {
        return Err(ChangelogError::Generic(format!(
            "{op_name}: table '{table}' is action-gated for {op_str}; direct ops are not \
             allowed (entry must be an Action op via one of {allowed:?})"
        )));
    };
    if !allowed.iter().any(|n| n == action_name) {
        return Err(ChangelogError::Generic(format!(
            "{op_name}: table '{table}' is action-gated for {op_str}; action \
             '{action_name}' is not in the allowed list {allowed:?}"
        )));
    }
    Ok(())
}

/// Check `*_only_via_actions` at the dispatch site, before handing off
/// to the primitive op verifier.  Only runs for direct primitive ops
/// (`Insert` / `Update` / `Delete`); other op types either don't target
/// app tables or carry their own dispatch (`Action`'s
/// leg-by-leg gating).
fn enforce_dispatch_gating(
    entry: &ChangelogEntry,
    ctx: &OpContext,
    reader: &mut dyn OpReader,
) -> Result<(), ChangelogError> {
    let (op_str, op_name) = match entry.message.op_type {
        OpType::Insert => ("write", "insert"),
        OpType::Update => ("write", "update"),
        OpType::Delete => ("delete", "delete"),
        _ => return Ok(()),
    };
    let column_keys = column_keys_from_entry(entry);
    if column_keys.is_empty() {
        return Ok(());
    }
    let table = table_from_column_keys(&column_keys, op_name)?;
    if is_internal_table(&table) {
        return Ok(());
    }
    enforce_only_via_actions(&table, op_str, op_name, ctx, reader)
}

fn is_internal_table(name: &str) -> bool {
    matches!(
        name,
        USERS_TABLE | RETENTION_TABLE | KEY_HISTORY_TABLE | "_access_control" | "_lists"
    )
}

/// Read an action by primary-leg table and name from authenticated
/// state via `OpReader`.
///
/// Returns `Ok(None)` if no action is stored under
/// `(primary_table, name)` (the schema did not declare one).  Returns
/// `Err` if the stored value's version byte is unknown or the postcard
/// body fails to decode.
pub(crate) fn read_action(
    reader: &mut dyn OpReader,
    primary_table: &str,
    name: &str,
    ctx: &OpContext,
) -> Result<Option<Action>, ChangelogError> {
    let cache_key = (primary_table.to_string(), name.to_string());
    if let Some(cached) = ctx.static_cache.state.borrow().actions.get(&cache_key) {
        return Ok(cached.clone());
    }
    let key = action_storage_key(primary_table, name);
    let read = reader.read(ReadOp::Key(key))?;
    let result = match read.results.first() {
        None => None,
        Some((_, bytes)) => {
            let body_bytes = decode_action_value(bytes)
                .map_err(|e| ChangelogError::Generic(format!("action '{name}': {e}")))?;
            let body: ActionBody = postcard::from_bytes(body_bytes).map_err(|e| {
                ChangelogError::Generic(format!("action '{name}' deserialization failed: {e}"))
            })?;
            Some(body.into_action(name.to_string()))
        }
    };
    ctx.static_cache
        .state
        .borrow_mut()
        .actions
        .insert(cache_key, result.clone());
    Ok(result)
}

/// Extract the common table name from `column_keys`.
///
/// Errors if the slice is empty, any key is not a column key, or if the keys
/// do not all refer to the same table. The same-table check prevents callers
/// (and downstream validators like `validate_not_internal_table`) from being
/// fooled by a mixed-table key list whose first element looks benign.
pub fn table_from_column_keys(
    column_keys: &[Vec<u8>],
    op_name: &str,
) -> Result<String, ChangelogError> {
    let mut table: Option<String> = None;
    for (i, key) in column_keys.iter().enumerate() {
        let t = match parse_key(key) {
            Ok(ParsedKey::Column { table, .. }) => table,
            _ => {
                return Err(ChangelogError::KeyMismatch(format!(
                    "{op_name}: column_key[{i}] is not a column key"
                )));
            }
        };
        match &table {
            None => table = Some(t),
            Some(expected) if expected != &t => {
                return Err(ChangelogError::KeyMismatch(format!(
                    "{op_name}: column_key[{i}] has table '{t}' \
                     but expected '{expected}' — all column_keys must refer to the same table"
                )));
            }
            Some(_) => {}
        }
    }
    table.ok_or_else(|| ChangelogError::KeyMismatch(format!("{op_name}: no column keys provided")))
}

/// Read the compact column-names list from the tree.
///
/// Reads `schema_columns_key(table)` which stores a null-separated UTF-8
/// list of non-id column names (~11 bytes for a 3-column table vs ~430
/// bytes for the full schema JSON).
pub(crate) fn read_schema_columns(
    table: &str,
    op_name: &str,
    reader: &mut dyn OpReader,
    ctx: &OpContext,
) -> Result<BTreeSet<String>, ChangelogError> {
    if let Some(cols) = ctx.static_cache.state.borrow().schema_columns.get(table) {
        return Ok(cols.clone());
    }
    let read = reader.read(ReadOp::Key(schema_columns_key(table)))?;
    let (_, col_bytes) = read.results.first().ok_or_else(|| {
        ChangelogError::Generic(format!(
            "{op_name}: schema columns not found for table '{table}'"
        ))
    })?;
    let cols = decode_column_names(col_bytes).ok_or_else(|| {
        ChangelogError::Generic(format!(
            "{op_name}: failed to decode column names for table '{table}'"
        ))
    })?;
    ctx.static_cache
        .state
        .borrow_mut()
        .schema_columns
        .insert(table.to_string(), cols.clone());
    Ok(cols)
}

/// Read the compact indexed-column-names list from the tree.
///
/// Reads `schema_indexes_key(table)` which stores a null-separated UTF-8
/// list of indexed column names.  Returns an empty set if the key is not
/// found (table has no indexes).
pub(crate) fn read_schema_indexes(
    table: &str,
    reader: &mut dyn OpReader,
    ctx: &OpContext,
) -> Result<BTreeSet<String>, ChangelogError> {
    if let Some(idx) = ctx.static_cache.state.borrow().schema_indexes.get(table) {
        return Ok(idx.clone());
    }
    let read = reader.read(ReadOp::Key(schema_indexes_key(table)))?;
    let idx = match read.results.first() {
        Some((_, idx_bytes)) => decode_column_names(idx_bytes).ok_or_else(|| {
            ChangelogError::Generic(format!(
                "failed to decode index column names for table '{table}'"
            ))
        })?,
        None => BTreeSet::new(),
    };
    ctx.static_cache
        .state
        .borrow_mut()
        .schema_indexes
        .insert(table.to_string(), idx.clone());
    Ok(idx)
}

/// Read the authenticated next-row-id counter for a table.
///
/// Reads `schema_next_id_key(table)`.  The stored value is a big-endian
/// `i64`.  Absence is treated as the initial value `1` (row IDs start at 1).
///
/// Binding the row_id assigned by the server to this counter is what lets
/// the client verify that an inserted row_id is provably unused.
pub(crate) fn read_next_id(
    table: &str,
    op_name: &str,
    reader: &mut dyn OpReader,
) -> Result<i64, ChangelogError> {
    let key = schema_next_id_key(table);
    let read = reader.read(ReadOp::Key(key))?;
    let Some((_, bytes)) = read.results.first() else {
        return Ok(1);
    };
    if bytes.len() != 8 {
        return Err(ChangelogError::Generic(format!(
            "{op_name}: next_id for table '{table}' has {} bytes, \
             expected 8 (big-endian i64)",
            bytes.len()
        )));
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(bytes);
    Ok(i64::from_be_bytes(buf))
}

/// Verify that `row_key(table, row_id)` has no existing columns.
///
/// Used by explicit-ID inserts.  The client signs the changelog entry with
/// the explicit row_id baked into every column key; if that row_id
/// collides with an existing row (whether the client is malicious or just
/// buggy), the server would otherwise obediently write `Op::Put` at the
/// same column keys and silently overwrite the existing row.  This check
/// forces the verifier to reject such a proof.
/// Mirrors the `Prefix(row_prefix(_users))` absence check in CreateSpaceOp.
#[allow(dead_code)]
pub(crate) fn verify_row_absent(
    table: &str,
    row_id: i64,
    op_name: &str,
    reader: &mut dyn OpReader,
) -> Result<(), ChangelogError> {
    let row_key_val = row_key(table, row_id);
    let read = reader.read(ReadOp::Prefix(row_key_val))?;
    if !read.results.is_empty() {
        return Err(ChangelogError::Generic(format!(
            "{op_name}: {table} row_id={row_id} already \
             exists — explicit-ID insert would overwrite"
        )));
    }
    Ok(())
}

/// Verify that `row_key(table, row_id)` has at least one existing column.
///
/// Used by Update.  Clients resolve WHERE clauses to concrete `row_id`s
/// before signing, so the signed entry's column keys carry the row_id
/// directly.  Without this check, an entry naming a row_id that does not
/// exist would still pass: the writer would emit phantom column entries
/// (effectively an Insert at an arbitrary id, bypassing the
/// auto-increment counter and any explicit-id absence check).  The
/// presence read forces the verifier to reject such proofs.
#[allow(dead_code)]
pub(crate) fn verify_row_present(
    table: &str,
    row_id: i64,
    op_name: &str,
    reader: &mut dyn OpReader,
) -> Result<(), ChangelogError> {
    let row_key_val = row_key(table, row_id);
    let read = reader.read(ReadOp::Prefix(row_key_val))?;
    if read.results.is_empty() {
        return Err(ChangelogError::Generic(format!(
            "{op_name}: {table} row_id={row_id} does \
             not exist"
        )));
    }
    Ok(())
}

/// Verify that a specific column key exists in the tree.
///
/// Proves row existence under the dense-row invariant: inserts write
/// every schema column and deletes remove the entire row, so if any
/// column of a row exists the row exists. One representative updated
/// column key read is cheaper than prefix-scanning all columns under
/// `row_key(table, row_id)`.
#[allow(dead_code)]
pub(crate) fn verify_column_present(
    key: Vec<u8>,
    table: &str,
    row_id: i64,
    column: &str,
    op_name: &str,
    reader: &mut dyn OpReader,
) -> Result<(), ChangelogError> {
    let read = reader.read(ReadOp::Key(key))?;
    if read.results.is_empty() {
        return Err(ChangelogError::Generic(format!(
            "{op_name}: {table} row_id={row_id} does not exist; \
             representative column '{column}' is absent"
        )));
    }
    Ok(())
}

/// Verify that a specific column key does not exist in the tree.
///
/// Proves row absence under the dense-row invariant: if the row
/// exists then every schema column exists, so any single column key
/// suffices as an absence witness.
pub(crate) fn verify_column_absent(
    key: Vec<u8>,
    table: &str,
    row_id: i64,
    column: &str,
    op_name: &str,
    reader: &mut dyn OpReader,
) -> Result<(), ChangelogError> {
    let read = reader.read(ReadOp::Key(key))?;
    if !read.results.is_empty() {
        return Err(ChangelogError::Generic(format!(
            "{op_name}: {table} row_id={row_id} already exists; \
             representative column '{column}' is present"
        )));
    }
    Ok(())
}

/// Read the authenticated `auto_increment` flag for a table.
///
/// Returns `true` when the table allocates ids from `schema_next_id_key`
/// and `false` when clients supply explicit ids.
pub(crate) fn read_auto_increment(
    table: &str,
    op_name: &str,
    reader: &mut dyn OpReader,
    ctx: &OpContext,
) -> Result<bool, ChangelogError> {
    if let Some(&cached) = ctx.static_cache.state.borrow().auto_increment.get(table) {
        return Ok(cached);
    }
    let key = schema_id_mode_key(table);
    let read = reader.read(ReadOp::Key(key))?;
    let Some((_, bytes)) = read.results.first() else {
        return Err(ChangelogError::Generic(format!(
            "{op_name}: id_mode for table '{table}' is missing"
        )));
    };
    let result = match bytes.as_slice() {
        [0] => true,
        [1] => false,
        other => {
            return Err(ChangelogError::Generic(format!(
                "{op_name}: id_mode for table '{table}' has \
                 {} bytes / value {:?}, expected a single byte 0 or 1",
                other.len(),
                other
            )))
        }
    };
    ctx.static_cache
        .state
        .borrow_mut()
        .auto_increment
        .insert(table.to_string(), result);
    Ok(result)
}

/// Bump the next-id counter after a chain insert that derived row_ids
/// `[counter, counter + num_rows - 1]` from the authenticated counter.
///
/// Companion to [`derive_column_keys_for_chain`] (and the single-row
/// `derive_column_keys_with_row_id` for `num_rows == 1`).  No-op when
/// `num_rows == 0`, mirroring the server's behaviour of omitting the
/// counter `Put` for empty chain inserts.
pub(crate) fn bump_next_id_after_chain(
    batch_ops: &mut Vec<BatchOp>,
    table: &str,
    counter: i64,
    num_rows: i64,
    op_name: &str,
) -> Result<(), ChangelogError> {
    if num_rows == 0 {
        return Ok(());
    }
    let last_row_id = counter.checked_add(num_rows - 1).ok_or_else(|| {
        ChangelogError::Generic(format!(
            "{op_name}: {table} next_id chain \
                 overflowed at counter={counter}+{num_rows}"
        ))
    })?;
    let next = next_id_after(last_row_id, table, op_name)?;
    batch_ops.push(next_id_put(table, next));
    Ok(())
}

/// Return `row_id + 1` or a counter-exhaustion error.
///
/// Used by every path that advances the next-id counter so every call
/// site reports overflow with one consistent error.
pub(crate) fn next_id_after(
    row_id: i64,
    table: &str,
    op_name: &str,
) -> Result<i64, ChangelogError> {
    row_id.checked_add(1).ok_or_else(|| {
        ChangelogError::Generic(format!(
            "{op_name}: {table} next_id counter \
             exhausted at row_id={row_id}"
        ))
    })
}

/// Build a `BatchOp::Put` that writes the new next_id value for a table.
pub(crate) fn next_id_put(table: &str, next_id: i64) -> BatchOp {
    BatchOp::Put {
        key: schema_next_id_key(table),
        value: next_id.to_be_bytes().to_vec(),
    }
}

/// Read the compact list-column-names list from the tree.
///
/// Returns an empty set if the key is authenticated as absent (no List columns).
/// Propagates errors on read failures or decode failures.
pub(crate) fn read_schema_list_columns(
    table: &str,
    reader: &mut dyn OpReader,
    ctx: &OpContext,
) -> Result<BTreeSet<String>, ChangelogError> {
    if let Some(lc) = ctx
        .static_cache
        .state
        .borrow()
        .schema_list_columns
        .get(table)
    {
        return Ok(lc.clone());
    }
    let key = schema_list_columns_key(table);
    let read = reader.read(ReadOp::Key(key))?;
    let lc = match read.results.first() {
        Some((_, bytes)) => decode_column_names(bytes).ok_or_else(|| {
            ChangelogError::Generic(format!(
                "failed to decode list column names for table '{table}'"
            ))
        })?,
        None => BTreeSet::new(),
    };
    ctx.static_cache
        .state
        .borrow_mut()
        .schema_list_columns
        .insert(table.to_string(), lc.clone());
    Ok(lc)
}

/// Build a `BatchOp::Put` for an index entry from a raw column value.
///
/// Parses `value_bytes` as JSON, converts to `TupleElement`, constructs the
/// index key, and returns a Put with the row_id as the value.
pub(crate) fn make_index_put(
    table: &str,
    column: &str,
    value_bytes: &[u8],
    row_id: i64,
    op_name: &str,
) -> Result<BatchOp, ChangelogError> {
    let idx_key = build_index_key(table, column, value_bytes, row_id, op_name)?;
    let row_id_bytes = row_id_to_bytes(row_id);
    Ok(BatchOp::Put {
        key: idx_key,
        value: row_id_bytes.to_vec(),
    })
}

/// Build a `BatchOp::Delete` for an index entry from a raw column value.
pub(crate) fn make_index_delete(
    table: &str,
    column: &str,
    value_bytes: &[u8],
    row_id: i64,
    op_name: &str,
) -> Result<BatchOp, ChangelogError> {
    let idx_key = build_index_key(table, column, value_bytes, row_id, op_name)?;
    Ok(BatchOp::Delete { key: idx_key })
}

/// Construct an index key from raw JSON column value bytes.
fn build_index_key(
    table: &str,
    column: &str,
    value_bytes: &[u8],
    row_id: i64,
    op_name: &str,
) -> Result<Vec<u8>, ChangelogError> {
    let json_val = bytes_to_value(value_bytes).map_err(|e| {
        ChangelogError::Generic(format!(
            "{op_name}: failed to decode indexed column '{column}': {e}"
        ))
    })?;
    let tuple_elem = TupleElement::try_from(&json_val).map_err(|e| {
        ChangelogError::Generic(format!(
            "{op_name}: failed to convert indexed column '{column}' to TupleElement: {e}"
        ))
    })?;
    index_key(table, column, tuple_elem, row_id).map_err(|e| {
        ChangelogError::Generic(format!(
            "{op_name}: failed to build index key for '{column}': {e}"
        ))
    })
}

/// Verify that every key in `column_keys` is a column key targeting the same
/// `(table, row_id)` pair, and return that pair.
///
/// An insert proof fragments one logical row across per-column Merk keys.
/// Without this check, a malicious proof could claim to insert
/// `users/5/name` and `users/6/age` as one logical insert, splitting the row
/// across two physical rows (and binding index entries to the wrong one).
pub(crate) fn validate_consistent_column_key_row_id(
    column_keys: &[Vec<u8>],
    op_name: &str,
    label: &str,
) -> Result<(String, i64), ChangelogError> {
    let mut iter = column_keys.iter();
    let first = iter.next().ok_or_else(|| {
        ChangelogError::Generic(format!("{op_name}: {label} proof has no column keys"))
    })?;
    let (table, row_id) = match parse_key(first) {
        Ok(ParsedKey::Column { table, row_id, .. }) => (table, row_id),
        _ => {
            return Err(ChangelogError::Generic(format!(
                "{op_name}: {label} proof key[0] is not a column key"
            )))
        }
    };
    for (i, key) in iter.enumerate() {
        match parse_key(key) {
            Ok(ParsedKey::Column {
                table: t,
                row_id: r,
                ..
            }) => {
                if t != table || r != row_id {
                    return Err(ChangelogError::Generic(format!(
                        "{op_name}: {label} proof key[{}] targets \
                         ({t}, {r}) but key[0] targets ({table}, {row_id}) — \
                         one insert must bind all columns to a single (table, row_id)",
                        i + 1
                    )));
                }
            }
            _ => {
                return Err(ChangelogError::Generic(format!(
                    "{op_name}: {label} proof key[{}] is not a column key",
                    i + 1
                )));
            }
        }
    }
    Ok((table, row_id))
}

fn inline_values_by_column<'a>(
    entries: &'a [KvData],
    indexed_columns: &BTreeSet<String>,
) -> Result<BTreeMap<String, &'a [u8]>, ChangelogError> {
    entries
        .iter()
        .filter_map(|kv| match parse_key(&kv.key) {
            Ok(ParsedKey::Column { column, .. }) if indexed_columns.contains(&column) => {
                Some(Ok((column, kv.value.as_slice())))
            }
            _ => None,
        })
        .collect::<Result<_, _>>()
}

/// Emit index Puts for an insert that targets a single `(table, row_id)`.
///
/// Callers must pass in the `row_id` already validated by
/// [`validate_consistent_column_key_row_id`] (or equivalent) so that index
/// entries can never be bound to a row_id different from the column writes.
pub(crate) fn append_insert_index_puts(
    batch_ops: &mut Vec<BatchOp>,
    table: &str,
    row_id: i64,
    entries: &[KvData],
    op_name: &str,
    reader: &mut dyn OpReader,
    ctx: &OpContext,
) -> Result<(), ChangelogError> {
    append_insert_index_puts_skip(
        batch_ops,
        table,
        row_id,
        entries,
        op_name,
        reader,
        ctx,
        &BTreeSet::new(),
    )
}

/// Like [`append_insert_index_puts`] but skips the given columns (e.g. List
/// columns whose signed placeholder value differs from the stored value).
#[allow(clippy::too_many_arguments)]
pub(crate) fn append_insert_index_puts_skip(
    batch_ops: &mut Vec<BatchOp>,
    table: &str,
    row_id: i64,
    entries: &[KvData],
    op_name: &str,
    reader: &mut dyn OpReader,
    ctx: &OpContext,
    skip_columns: &BTreeSet<String>,
) -> Result<(), ChangelogError> {
    let indexed_columns = read_schema_indexes(table, reader, ctx)?;
    if indexed_columns.is_empty() {
        return Ok(());
    }

    let values_by_column = inline_values_by_column(entries, &indexed_columns)?;

    for indexed_column in &indexed_columns {
        if skip_columns.contains(indexed_column) {
            continue;
        }
        let value_bytes = values_by_column.get(indexed_column).ok_or_else(|| {
            ChangelogError::Generic(format!(
                "{op_name}: missing indexed {table} column '{indexed_column}'"
            ))
        })?;
        batch_ops.push(make_index_put(
            table,
            indexed_column,
            value_bytes,
            row_id,
            op_name,
        )?);
    }

    Ok(())
}

/// Like [`append_insert_index_puts`] but handles multiple rows.
///
/// Chunks column keys by schema column count and delegates each chunk
/// to [`append_insert_index_puts`], validating row_id consistency per chunk.
pub(crate) fn append_multi_row_insert_index_puts(
    batch_ops: &mut Vec<BatchOp>,
    table: &str,
    column_keys: &[Vec<u8>],
    entries: &[KvData],
    op_name: &str,
    reader: &mut dyn OpReader,
    ctx: &OpContext,
) -> Result<(), ChangelogError> {
    let schema_col_count = {
        let cols = read_schema_columns(table, op_name, reader, ctx)?;
        cols.len()
    };
    if schema_col_count == 0 {
        return Ok(());
    }

    for chunk_start in (0..column_keys.len()).step_by(schema_col_count) {
        let chunk_end = (chunk_start + schema_col_count).min(column_keys.len());
        let (chunk_table, row_id) = validate_consistent_column_key_row_id(
            &column_keys[chunk_start..chunk_end],
            op_name,
            table,
        )?;
        if chunk_table != table {
            return Err(ChangelogError::Generic(format!(
                "{op_name}: {table} chunk starting at \
                 key[{chunk_start}] targets table '{chunk_table}'"
            )));
        }
        append_insert_index_puts(
            batch_ops,
            table,
            row_id,
            &entries[chunk_start..chunk_end],
            op_name,
            reader,
            ctx,
        )?;
    }

    Ok(())
}

/// Extract column names from a set of column keys.
pub(crate) fn column_names_from_keys(column_keys: &[Vec<u8>]) -> BTreeSet<String> {
    column_keys
        .iter()
        .filter_map(|k| match parse_key(k) {
            Ok(ParsedKey::Column { column, .. }) => Some(column),
            _ => None,
        })
        .collect()
}

/// Required columns in a `_key_history` insert (shared by RefreshKeys and RemoveUser).
pub const KEY_HISTORY_REQUIRED_COLUMNS: &[&str] = &[
    "old_auth_key",
    "uid",
    "valid_from_change_id",
    "valid_to_change_id",
];

/// Validate `_key_history` insert entries in a changelog.
///
/// Shared validation for both RefreshKeys and RemoveUser:
/// - column keys match changelog entries (table, column) tuples
/// - target table is `_key_history`
/// - all required columns are present
/// - `uid` value matches `expected_uid` and is stored inline (not hashed)
pub(crate) fn validate_key_history_entries(
    kh_column_keys: &[Vec<u8>],
    kh_entries: &[KvData],
    expected_uid: u32,
    op_name: &str,
) -> Result<i64, ChangelogError> {
    let mut kh_row_id: Option<i64> = None;

    // Compare (table, column) tuples — the proof has actual row IDs
    // while the changelog uses placeholder row_id=0.
    for (i, (col_key, kv)) in kh_column_keys.iter().zip(kh_entries.iter()).enumerate() {
        let proof_col = match parse_key(col_key) {
            Ok(ParsedKey::Column {
                table,
                column,
                row_id,
                ..
            }) => {
                match kh_row_id {
                    None => kh_row_id = Some(row_id),
                    Some(prev) if prev != row_id => {
                        return Err(ChangelogError::Generic(format!(
                            "{op_name}: _key_history proof must contain \
                             exactly one row id, got multiple"
                        )));
                    }
                    Some(_) => {}
                }
                (table, column)
            }
            _ => {
                return Err(ChangelogError::KeyMismatch(format!(
                    "{op_name}: kh proof key[{i}] is not a column key"
                )));
            }
        };
        let entry_col = match parse_key(&kv.key) {
            Ok(ParsedKey::Column { table, column, .. }) => (table, column),
            _ => {
                return Err(ChangelogError::KeyMismatch(format!(
                    "{op_name}: kh entry key[{i}] is not a column key"
                )));
            }
        };
        if proof_col != entry_col {
            return Err(ChangelogError::KeyMismatch(format!(
                "{op_name}: \
                 key_history column mismatch at [{i}]: \
                 proof=({}, {}), entry=({}, {})",
                proof_col.0, proof_col.1, entry_col.0, entry_col.1
            )));
        }
    }

    if kh_row_id.is_none() {
        return Err(ChangelogError::Generic(format!(
            "{op_name}: _key_history proof has no column keys"
        )));
    }

    let kh_table = table_from_column_keys(kh_column_keys, &format!("{op_name}/_key_history"))?;
    if kh_table != KEY_HISTORY_TABLE {
        return Err(ChangelogError::Generic(format!(
            "{op_name}: key_history columns target \
             table '{kh_table}', expected '{KEY_HISTORY_TABLE}'"
        )));
    }

    // Verify all required columns are present
    let kh_actual = column_names_from_keys(kh_column_keys);
    for required in KEY_HISTORY_REQUIRED_COLUMNS {
        if !kh_actual.iter().any(|c| c == required) {
            return Err(ChangelogError::Generic(format!(
                "{op_name}: _key_history insert \
                 is missing required column '{required}'"
            )));
        }
    }

    // Verify `uid` in the _key_history insert matches the expected user.
    for (col_key, kv) in kh_column_keys.iter().zip(kh_entries.iter()) {
        if let Ok(ParsedKey::Column { column, .. }) = parse_key(col_key) {
            if column == "uid" {
                let uid_int = bytes_to_value(&kv.value)
                    .ok()
                    .and_then(|v| v.as_u64().or_else(|| v.as_i64().map(|i| i as u64)))
                    .ok_or_else(|| {
                        ChangelogError::Generic(format!(
                            "{op_name}: _key_history uid value is not a valid integer"
                        ))
                    })?;
                if uid_int != expected_uid as u64 {
                    return Err(ChangelogError::Generic(format!(
                        "{op_name}: _key_history uid={uid_int} does not match \
                         expected uid={expected_uid}",
                    )));
                }
            }
        }
    }

    // Safe: kh_row_id.is_none() was rejected above.
    Ok(kh_row_id.expect("kh_row_id checked non-None above"))
}

/// Extract an i64 column value from a slice of _key_history KvData entries.
pub(crate) fn extract_i64_from_kh_entries(
    kh_entries: &[KvData],
    column_name: &str,
    op_name: &str,
) -> Result<i64, ChangelogError> {
    for kv in kh_entries {
        if let Ok(ParsedKey::Column { column, .. }) = parse_key(&kv.key) {
            if column == column_name {
                return decode_i64_column_value(
                    &kv.value,
                    op_name,
                    &format!("_key_history.{column_name}"),
                );
            }
        }
    }
    Err(ChangelogError::Generic(format!(
        "{op_name}: \
         _key_history.{column_name} not found in entries"
    )))
}

/// Extract raw column bytes from a slice of _key_history KvData entries.
pub(crate) fn extract_value_from_kh_entries(
    kh_entries: &[KvData],
    column_name: &str,
    op_name: &str,
) -> Result<Vec<u8>, ChangelogError> {
    for kv in kh_entries {
        if let Ok(ParsedKey::Column { column, .. }) = parse_key(&kv.key) {
            if column == column_name {
                return Ok(kv.value.clone());
            }
        }
    }
    Err(ChangelogError::Generic(format!(
        "{op_name}: \
         _key_history.{column_name} not found in entries"
    )))
}

pub(crate) fn read_indexed_row_ids<V>(
    table: &str,
    column: &str,
    value: V,
    reader: &mut dyn OpReader,
    op_name: &str,
) -> Result<Vec<i64>, ChangelogError>
where
    V: TryInto<TupleElement>,
    V::Error: Into<TupleConversionError>,
{
    let index_prefix = index_value_prefix(table, column, value).map_err(|e| {
        ChangelogError::Generic(format!(
            "{op_name}: failed to build {table}.{column} index prefix: {e}"
        ))
    })?;
    let index_read = reader.read(ReadOp::Prefix(index_prefix))?;

    let mut row_ids = BTreeSet::new();
    for (key, value) in &index_read.results {
        let parsed = parse_key(key).map_err(|e| {
            ChangelogError::Generic(format!(
                "{op_name}: failed to parse {table}.{column} index key: {e}"
            ))
        })?;
        let row_id = match parsed {
            ParsedKey::Index {
                table: key_table,
                column: key_column,
                row_id,
                ..
            } if key_table == table && key_column == column => row_id,
            other => {
                return Err(ChangelogError::Generic(format!(
                    "{op_name}: unexpected key in {table}.{column} index scan: {other:?}"
                )))
            }
        };

        let encoded_row_id = row_id_to_bytes(row_id);
        if value.as_slice() != &encoded_row_id[..] {
            return Err(ChangelogError::Generic(format!(
                "{op_name}: {table}.{column} index value for row_id={row_id} is malformed"
            )));
        }

        row_ids.insert(row_id);
    }

    Ok(row_ids.into_iter().collect())
}

pub(crate) fn read_kh_ranges_indexed(
    uid: u32,
    reader: &mut dyn OpReader,
    op_name: &str,
) -> Result<Vec<(i64, i64)>, ChangelogError> {
    let row_ids = read_indexed_row_ids(KEY_HISTORY_TABLE, "uid", uid as i64, reader, op_name)?;

    let mut ranges = Vec::with_capacity(row_ids.len());
    for row_id in row_ids {
        let valid_from_key = column_key(KEY_HISTORY_TABLE, row_id, "valid_from_change_id");
        let valid_to_key = column_key(KEY_HISTORY_TABLE, row_id, "valid_to_change_id");

        let valid_from_read = reader.read(ReadOp::Key(valid_from_key.clone()))?;
        let valid_to_read = reader.read(ReadOp::Key(valid_to_key.clone()))?;

        let (_, valid_from_bytes) = valid_from_read.results.first().ok_or_else(|| {
            ChangelogError::Generic(format!(
                "{op_name}: _key_history.valid_from_change_id not found for row_id={row_id}"
            ))
        })?;
        let (_, valid_to_bytes) = valid_to_read.results.first().ok_or_else(|| {
            ChangelogError::Generic(format!(
                "{op_name}: _key_history.valid_to_change_id not found for row_id={row_id}"
            ))
        })?;

        let valid_from = decode_i64_column_value(
            valid_from_bytes,
            op_name,
            "_key_history.valid_from_change_id",
        )?;
        let valid_to =
            decode_i64_column_value(valid_to_bytes, op_name, "_key_history.valid_to_change_id")?;
        ranges.push((valid_from, valid_to));
    }

    Ok(ranges)
}

// ─── OpReader: callback-based read interface ────────────────────────────────

/// Trait for reading from the tree during op validation.
///
/// Operations call `reader.read(op)` inline to request data.  Two implementations
/// exist:
///
/// * **`ProverReader`** — logs each `ReadOp` and resolves it via a
///   caller-provided function, returning a real `ProvenRead` with tree data.
///   This enables adaptive reads (inspect one result to decide the next).
///   The logged reads are later emitted as `InputStep::Read` entries for
///   `create_trace`.
///
/// * **`VerifierReader`** — replays pre-resolved `ProvenRead` entries from the
///   tracer proof, verifying that the op requests the same reads in the same
///   order.  Returns an error on mismatch.
///
/// This design allows ops to perform adaptive, multi-round reads (read →
/// compute → read again) without declaring them statically up front.
pub trait OpReader {
    /// Perform a read operation, returning the proven result.
    fn read(&mut self, op: ReadOp) -> Result<ProvenRead, ChangelogError>;
}

/// Prover-side reader: logs `ReadOp`s and resolves them via a caller-provided
/// function.
///
/// The resolver receives the `ReadOp` and returns a `ProvenRead` with real
/// data from the tree.  This allows ops to perform adaptive reads (inspect
/// the result of one read to decide the next) during the prover's discovery
/// pass.  The logged reads are later emitted as `InputStep::Read` entries
/// for `create_trace`.
pub struct ProverReader<F>
where
    F: FnMut(&ReadOp) -> Result<ProvenRead, ChangelogError>,
{
    /// Logged reads, in the order they were requested.
    pub logged_reads: Vec<ReadOp>,
    resolver: F,
}

impl<F> ProverReader<F>
where
    F: FnMut(&ReadOp) -> Result<ProvenRead, ChangelogError>,
{
    pub fn new(resolver: F) -> Self {
        Self {
            logged_reads: Vec::new(),
            resolver,
        }
    }
}

impl<F> OpReader for ProverReader<F>
where
    F: FnMut(&ReadOp) -> Result<ProvenRead, ChangelogError>,
{
    fn read(&mut self, op: ReadOp) -> Result<ProvenRead, ChangelogError> {
        self.logged_reads.push(op.clone());
        (self.resolver)(&op)
    }
}

/// Verifier-side reader: replays pre-extracted `ProvenRead` entries.
///
/// The outer loop in `verify_op_sequence` extracts consecutive Read
/// trace-steps and flattens them into a `&[ProvenRead]` slice.  This
/// reader simply walks that slice, verifying that the op requests reads
/// in the same order.
///
/// After `extract_and_validate` returns, call `assert_all_consumed()`
/// to verify no reads were left unread.
pub struct VerifierReader<'a> {
    /// Pre-extracted proven reads for this op.
    reads: &'a [ProvenRead],
    /// Current position in `reads`.
    cursor: usize,
}

impl<'a> VerifierReader<'a> {
    pub fn new(reads: &'a [ProvenRead]) -> Self {
        Self { reads, cursor: 0 }
    }

    /// Assert that every proven read was consumed.  Returns an error if
    /// any reads remain unconsumed.
    pub fn assert_all_consumed(&self) -> Result<(), ChangelogError> {
        if self.cursor < self.reads.len() {
            Err(ChangelogError::Generic(format!(
                "VerifierReader: {} proven read(s) remaining unconsumed (consumed {}/{})",
                self.reads.len() - self.cursor,
                self.cursor,
                self.reads.len(),
            )))
        } else {
            Ok(())
        }
    }
}

impl OpReader for VerifierReader<'_> {
    fn read(&mut self, op: ReadOp) -> Result<ProvenRead, ChangelogError> {
        if self.cursor >= self.reads.len() {
            return Err(ChangelogError::Generic(format!(
                "VerifierReader: proven reads exhausted at position {} while reading {:?}",
                self.cursor, op
            )));
        }
        let proven = &self.reads[self.cursor];
        if proven.op != op {
            return Err(ChangelogError::Generic(format!(
                "VerifierReader: read at position {} expected {:?}, got {:?}",
                self.cursor, proven.op, op
            )));
        }
        self.cursor += 1;
        Ok(proven.clone())
    }
}

// ─── OpVerifyResult & OpVerifier trait ──────────────────────────────────────

/// Result of per-op validation. Returned by OpVerifier::extract_and_validate.
#[derive(Debug)]
pub struct OpVerifyResult {
    /// Tree write operations produced by this op, constructed from the
    /// changelog entry and the input's row_key.
    pub write_steps: Vec<TraceStep>,
}

// ─── StaticMetadataCache ────────────────────────────────────────────────────

#[derive(Default)]
struct StaticMetadataCacheState {
    schema_columns: BTreeMap<String, BTreeSet<String>>,
    schema_list_columns: BTreeMap<String, BTreeSet<String>>,
    schema_indexes: BTreeMap<String, BTreeSet<String>>,
    acl_rules: BTreeMap<(String, String), Option<AccessRule>>,
    actions: BTreeMap<(String, String), Option<Action>>,
    only_via_actions: BTreeMap<(String, String), Option<Vec<String>>>,
    auto_increment: BTreeMap<String, bool>,
}

impl StaticMetadataCacheState {
    fn clear(&mut self) {
        self.schema_columns.clear();
        self.schema_list_columns.clear();
        self.schema_indexes.clear();
        self.acl_rules.clear();
        self.actions.clear();
        self.only_via_actions.clear();
        self.auto_increment.clear();
    }
}

#[derive(Clone, Default)]
struct StaticMetadataCache {
    state: Rc<RefCell<StaticMetadataCacheState>>,
}

impl StaticMetadataCache {
    fn clear(&self) {
        self.state.borrow_mut().clear();
    }
}

fn static_metadata_cache_invalidated_by(op_type: OpType) -> bool {
    matches!(
        op_type,
        OpType::CreateSpace
            | OpType::InviteUser
            | OpType::RemoveUser
            | OpType::RefreshKeys
            | OpType::Extend
            | OpType::Reduce
            | OpType::Rekey
    )
}

// ─── OpContext: global per-entry data passed to each op ────────────────────

/// Per-entry data passed to each op's `extract_and_validate`.
#[derive(Default)]
pub struct OpContext {
    /// The 1-based change_id of the current entry being verified.
    /// Set by `verify_op_sequence` (FF proof) and the prover; 0 when unknown
    /// (e.g. in `verify_proof_and_validate` which runs per-entry on the server).
    pub current_change_id: usize,
    /// Set by [`ActionOp::extract_and_validate`] before it dispatches an
    /// action leg to a primitive op verifier.  `None` for direct ops.
    ///
    /// Primitive ops use this to validate the table's
    /// `write_only_via_actions` / `delete_only_via_actions` gating: a
    /// gated table rejects any entry without a matching action context.
    pub action_name: Option<String>,
    static_cache: StaticMetadataCache,
}

impl OpContext {
    pub fn for_change_id(current_change_id: usize) -> Self {
        Self {
            current_change_id,
            action_name: None,
            static_cache: StaticMetadataCache::default(),
        }
    }

    pub fn for_change_sequence() -> Self {
        Self::for_change_id(0)
    }

    pub fn begin_change(&mut self, current_change_id: usize) {
        self.current_change_id = current_change_id;
        self.action_name = None;
    }

    pub fn finish_change(&mut self, op_type: OpType) {
        if static_metadata_cache_invalidated_by(op_type) {
            self.static_cache.clear();
        }
    }

    pub(crate) fn for_action_leg(&self, action_name: String) -> Self {
        Self {
            current_change_id: self.current_change_id,
            action_name: Some(action_name),
            static_cache: self.static_cache.clone(),
        }
    }
}

/// Pre-computed ACL check data for a single changelog entry.
pub struct AclCheck {
    /// The matching access rule (cloned from the ACL blob BTreeMap).
    pub rule: AccessRule,
    /// Table or list name this rule applies to.
    pub resource_name: String,
    /// Column names referenced by `ResourceColumn` in the rule.
    pub needed_columns: Vec<String>,
}

// ─── OpVerifier trait ──────────────────────────────────────────────────────

/// Trait defining the per-OpType verification contract.
/// Each OpType (Insert, Update, Delete, ...) implements this with its own Input type.
///
/// Operations request reads inline via the `reader` callback, enabling adaptive
/// reads (read → compute → read again).  The same `extract_and_validate`
/// function runs on both the prover (with `ProverReader`) and the verifier
/// (with `VerifierReader`).
pub trait OpVerifier {
    fn extract_and_validate(
        entry: &ChangelogEntry,
        reader: &mut dyn OpReader,
        ctx: &OpContext,
    ) -> Result<OpVerifyResult, ChangelogError>;
}

pub fn dispatch_extract_and_validate(
    entry: &ChangelogEntry,
    reader: &mut dyn OpReader,
    ctx: &OpContext,
) -> Result<OpVerifyResult, ChangelogError> {
    // Action-gating: tables declared with `write_only_via_actions` /
    // `delete_only_via_actions` reject direct primitive ops here.
    // Action dispatch (below) enforces the same constraint on each
    // leg, with `ctx.action_name` set to the invoking action.
    enforce_dispatch_gating(entry, ctx, reader)?;

    match entry.message.op_type {
        OpType::Insert => InsertOp::extract_and_validate(entry, reader, ctx),
        OpType::Update => UpdateOp::extract_and_validate(entry, reader, ctx),
        OpType::Delete => DeleteOp::extract_and_validate(entry, reader, ctx),
        OpType::ListInsert => ListInsertOp::extract_and_validate(entry, reader, ctx),
        OpType::ListUpdate => ListUpdateOp::extract_and_validate(entry, reader, ctx),
        OpType::ListDelete => ListDeleteOp::extract_and_validate(entry, reader, ctx),
        OpType::ListAppend => ListAppendOp::extract_and_validate(entry, reader, ctx),
        OpType::CreateSpace => CreateSpaceOp::extract_and_validate(entry, reader, ctx),
        OpType::RefreshKeys => RefreshKeysOp::extract_and_validate(entry, reader, ctx),
        OpType::InviteUser => InviteUserOp::extract_and_validate(entry, reader, ctx),
        OpType::RemoveUser => RemoveUserOp::extract_and_validate(entry, reader, ctx),
        OpType::Extend => ExtendOp::extract_and_validate(entry, reader, ctx),
        OpType::Reduce => ReduceOp::extract_and_validate(entry, reader, ctx),
        OpType::Rekey => RekeyOp::extract_and_validate(entry, reader, ctx),
        OpType::Action => ActionOp::extract_and_validate(entry, reader, ctx),
        OpType::Noop => Ok(OpVerifyResult {
            write_steps: Vec::new(),
        }),
    }
}

/// Verify an InviteUser single-change proof and return the server-assigned
/// `_users` row id.
pub fn extract_row_id_from_invite_user_proof(
    change: &ChangelogEntry,
    proof_bytes: &[u8],
    old_root: &[u8; 32],
    new_root: &[u8; 32],
    current_change_id: usize,
) -> Result<i64, ChangelogError> {
    if change.message.op_type != OpType::InviteUser {
        return Err(ChangelogError::Generic(format!(
            "Expected InviteUser proof, got {:?}",
            change.message.op_type
        )));
    }

    let writes = crate::changelog::ChangeLog::verify_proof_and_validate(
        change,
        proof_bytes,
        old_root,
        new_root,
        current_change_id,
    )?;

    let mut row_ids = BTreeSet::new();
    for op in &writes {
        let key = match op {
            BatchOp::Put { key, .. } => key,
            BatchOp::Delete { .. } => continue,
        };
        match parse_key(key) {
            Ok(ParsedKey::Column { table, row_id, .. }) if table == USERS_TABLE => {
                row_ids.insert(row_id);
            }
            _ => {}
        }
    }

    let mut row_ids = row_ids.into_iter();
    let Some(row_id) = row_ids.next() else {
        return Err(ChangelogError::Generic(
            "InviteUser proof did not write any _users row".to_string(),
        ));
    };
    if row_ids.next().is_some() {
        return Err(ChangelogError::Generic(
            "InviteUser proof wrote multiple _users rows".to_string(),
        ));
    }
    Ok(row_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use encrypted_spaces_acl_types::{ColumnNamespace, ComparisonOp, RuleValue};
    use encrypted_spaces_storage_encoding::encode_column_names;
    use encrypted_spaces_storage_encoding::keys::encode_action_value;

    #[test]
    fn test_validate_not_internal_table() {
        let err = validate_not_internal_table("_users", "insert").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("reserved"), "unexpected error: {msg}");
        assert!(msg.contains("_users"), "unexpected error: {msg}");
        assert!(msg.contains("insert"), "unexpected error: {msg}");

        assert!(validate_not_internal_table("photos", "update").is_ok());
        assert!(validate_not_internal_table("", "delete").is_ok());
    }

    #[test]
    fn test_derive_column_keys_for_chain_preserves_sorted_multi_row_groups() {
        let entries = vec![
            KvData {
                key: column_key(KEY_HISTORY_TABLE, 0, "key"),
                value: vec![0; 32],
            },
            KvData {
                key: column_key(KEY_HISTORY_TABLE, 0, "key"),
                value: vec![1; 32],
            },
            KvData {
                key: column_key(KEY_HISTORY_TABLE, 0, "value"),
                value: vec![2; 32],
            },
            KvData {
                key: column_key(KEY_HISTORY_TABLE, 0, "value"),
                value: vec![3; 32],
            },
        ];

        let keys = derive_column_keys_for_chain(&entries, 10, 2, "test").unwrap();

        assert_eq!(
            keys,
            vec![
                column_key(KEY_HISTORY_TABLE, 10, "key"),
                column_key(KEY_HISTORY_TABLE, 11, "key"),
                column_key(KEY_HISTORY_TABLE, 10, "value"),
                column_key(KEY_HISTORY_TABLE, 11, "value"),
            ]
        );
    }

    // ─── OpReader tests ─────────────────────────────────────────────────

    #[test]
    fn test_prover_reader_logs_reads() {
        let mut reader = ProverReader::new(|op: &ReadOp| {
            Ok(ProvenRead {
                op: op.clone(),
                results: vec![(vec![], vec![])],
            })
        });
        let op1 = ReadOp::Key(vec![1, 2, 3]);
        let op2 = ReadOp::Key(vec![4, 5, 6]);

        let r1 = reader.read(op1.clone()).unwrap();
        assert_eq!(r1.op, op1);
        assert_eq!(r1.results.len(), 1); // dummy non-empty result

        let r2 = reader.read(op2.clone()).unwrap();
        assert_eq!(r2.op, op2);

        assert_eq!(reader.logged_reads.len(), 2);
        assert_eq!(reader.logged_reads[0], op1);
        assert_eq!(reader.logged_reads[1], op2);
    }

    #[test]
    fn test_verifier_reader_replays_reads() {
        let proven = ProvenRead {
            op: ReadOp::Key(vec![1, 2, 3]),
            results: vec![(vec![10], vec![20])],
        };
        let reads = vec![proven.clone()];
        let mut reader = VerifierReader::new(&reads);

        let result = reader.read(ReadOp::Key(vec![1, 2, 3])).unwrap();
        assert_eq!(result.op, proven.op);
        assert_eq!(result.results, proven.results);
        assert!(reader.assert_all_consumed().is_ok());
    }

    #[test]
    fn test_verifier_reader_rejects_mismatched_read() {
        let proven = ProvenRead {
            op: ReadOp::Key(vec![1, 2, 3]),
            results: vec![],
        };
        let reads = vec![proven];
        let mut reader = VerifierReader::new(&reads);

        let err = reader.read(ReadOp::Key(vec![99, 99])); // wrong key
        assert!(err.is_err());
    }

    #[test]
    fn test_verifier_reader_rejects_when_exhausted() {
        let reads: Vec<ProvenRead> = vec![];
        let mut reader = VerifierReader::new(&reads);

        let err = reader.read(ReadOp::Key(vec![1]));
        assert!(err.is_err());
    }

    #[test]
    fn test_verifier_reader_assert_all_consumed_fails_with_remaining() {
        let reads = vec![
            ProvenRead {
                op: ReadOp::Key(vec![1]),
                results: vec![],
            },
            ProvenRead {
                op: ReadOp::Key(vec![2]),
                results: vec![],
            },
        ];
        let mut reader = VerifierReader::new(&reads);

        // Consume only one
        reader.read(ReadOp::Key(vec![1])).unwrap();

        let err = reader.assert_all_consumed();
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("1 proven read(s) remaining unconsumed"));
    }

    #[test]
    fn test_read_acl_rule_present() {
        let rule = AccessRule::comparison(
            RuleValue::column(ColumnNamespace::Resource, "owner_id"),
            ComparisonOp::Equal,
            RuleValue::AuthUserId,
        );
        let blob = postcard::to_allocvec(&rule).unwrap();
        let key = acl_rule_key("posts", "write");

        let reads = vec![ProvenRead {
            op: ReadOp::Key(key.clone()),
            results: vec![(key, blob)],
        }];
        let mut reader = VerifierReader::new(&reads);
        let ctx = OpContext::default();
        let result = read_acl_rule(&mut reader, "posts", "write", &ctx).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn test_read_acl_rule_missing_returns_none() {
        let key = acl_rule_key("posts", "write");
        let reads = vec![ProvenRead {
            op: ReadOp::Key(key),
            results: vec![],
        }];
        let mut reader = VerifierReader::new(&reads);
        let ctx = OpContext::default();
        let result = read_acl_rule(&mut reader, "posts", "write", &ctx).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_read_acl_rule_malformed_blob_errors() {
        let key = acl_rule_key("posts", "write");
        let reads = vec![ProvenRead {
            op: ReadOp::Key(key.clone()),
            results: vec![(key, vec![0xFF, 0xFE, 0xFD])],
        }];
        let mut reader = VerifierReader::new(&reads);
        let ctx = OpContext::default();
        let err = read_acl_rule(&mut reader, "posts", "write", &ctx);
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("deserialization failed"),
            "unexpected error: {msg}"
        );
    }

    // ─── Action-gating tests ────────────────────────────────────────────────

    fn gating_reader(table: &str, op: &str, actions: &[&str]) -> Vec<ProvenRead> {
        let key = acl_only_via_actions_key(table, op);
        let names: Vec<String> = actions.iter().map(|s| s.to_string()).collect();
        let blob = postcard::to_allocvec(&names).unwrap();
        vec![ProvenRead {
            op: ReadOp::Key(key.clone()),
            results: vec![(key, blob)],
        }]
    }

    fn no_gating_reader(table: &str, op: &str) -> Vec<ProvenRead> {
        let key = acl_only_via_actions_key(table, op);
        vec![ProvenRead {
            op: ReadOp::Key(key),
            results: vec![],
        }]
    }

    #[test]
    fn enforce_only_via_actions_passes_when_no_gating_exists() {
        let reads = no_gating_reader("messages", "write");
        let mut reader = VerifierReader::new(&reads);
        let ctx = OpContext::default();
        enforce_only_via_actions("messages", "write", "insert", &ctx, &mut reader).unwrap();
    }

    #[test]
    fn enforce_only_via_actions_rejects_direct_op_on_gated_table() {
        let reads = gating_reader("messages", "write", &["send_message"]);
        let mut reader = VerifierReader::new(&reads);
        let ctx = OpContext::default();
        let err =
            enforce_only_via_actions("messages", "write", "insert", &ctx, &mut reader).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("action-gated") && msg.contains("direct ops are not allowed"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn enforce_only_via_actions_rejects_action_not_in_allowed_list() {
        let reads = gating_reader("messages", "write", &["send_message"]);
        let mut reader = VerifierReader::new(&reads);
        let ctx = OpContext {
            action_name: Some("rogue_action".to_string()),
            ..Default::default()
        };
        let err =
            enforce_only_via_actions("messages", "write", "insert", &ctx, &mut reader).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("rogue_action") && msg.contains("not in the allowed list"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn enforce_only_via_actions_accepts_listed_action() {
        let reads = gating_reader("messages", "write", &["send_message", "edit_message"]);
        let mut reader = VerifierReader::new(&reads);
        let ctx = OpContext {
            action_name: Some("edit_message".to_string()),
            ..Default::default()
        };
        enforce_only_via_actions("messages", "write", "update", &ctx, &mut reader).unwrap();
    }

    #[test]
    fn enforce_only_via_actions_ignores_gating_on_different_op() {
        let reads = no_gating_reader("messages", "delete");
        let mut reader = VerifierReader::new(&reads);
        let ctx = OpContext::default();
        enforce_only_via_actions("messages", "delete", "delete", &ctx, &mut reader).unwrap();
    }

    // ─── read_action tests ──────────────────────────────────────────────────

    #[test]
    fn read_action_returns_none_when_not_stored() {
        let key = action_storage_key("t", "missing");
        let reads = vec![ProvenRead {
            op: ReadOp::Key(key),
            results: vec![],
        }];
        let mut reader = VerifierReader::new(&reads);
        let ctx = OpContext::default();
        assert!(read_action(&mut reader, "t", "missing", &ctx)
            .unwrap()
            .is_none());
    }

    #[test]
    fn read_action_returns_stored_action() {
        use encrypted_spaces_acl_types::ActionLeg;
        let action = Action {
            name: "noop".to_string(),
            legs: vec![ActionLeg::Insert {
                table: "t".to_string(),
            }],
            asserts: vec![],
        };
        let body = postcard::to_allocvec(&action.body()).unwrap();
        let value = encode_action_value(body);
        let key = action_storage_key("t", "noop");
        let reads = vec![ProvenRead {
            op: ReadOp::Key(key.clone()),
            results: vec![(key, value)],
        }];
        let mut reader = VerifierReader::new(&reads);
        let ctx = OpContext::default();
        let got = read_action(&mut reader, "t", "noop", &ctx)
            .unwrap()
            .unwrap();
        assert_eq!(got.name, "noop");
        assert_eq!(got.legs.len(), 1);
    }

    #[test]
    fn read_action_rejects_unknown_version_byte() {
        let key = action_storage_key("t", "noop");
        let mut value = vec![0xFFu8]; // unknown version
        value.extend_from_slice(b"any-body");
        let reads = vec![ProvenRead {
            op: ReadOp::Key(key.clone()),
            results: vec![(key, value)],
        }];
        let mut reader = VerifierReader::new(&reads);
        let ctx = OpContext::default();
        let err = read_action(&mut reader, "t", "noop", &ctx).unwrap_err();
        assert!(format!("{err}").contains("unsupported action storage version"));
    }

    // ─── resolve_exists_in_op tests ─────────────────────────────────────────

    fn i64_bytes(v: i64) -> Vec<u8> {
        value_to_bytes(&serde_json::Value::Number(serde_json::Number::from(v))).unwrap()
    }

    fn row_col_eq(col: &str, value: RuleValue) -> AccessRule {
        AccessRule::comparison(
            RuleValue::column(ColumnNamespace::Resource, col),
            ComparisonOp::Equal,
            value,
        )
    }

    #[test]
    fn exists_id_only_returns_true_when_row_present() {
        // `exists(messages, row.id == 7)` — single id constraint reads
        // row_key prefix to confirm presence.
        let inner = row_col_eq("id", RuleValue::Int(7));
        let rk = row_key("messages", 7);
        let reads = vec![ProvenRead {
            op: ReadOp::Prefix(rk.clone()),
            results: vec![(column_key("messages", 7, "id"), i64_bytes(7))],
        }];
        let mut reader = VerifierReader::new(&reads);
        let result =
            resolve_exists_in_op("messages", &inner, 1, &BTreeMap::new(), &mut reader, "test")
                .unwrap();
        assert!(result);
    }

    #[test]
    fn exists_id_only_returns_false_when_row_absent() {
        let inner = row_col_eq("id", RuleValue::Int(7));
        let rk = row_key("messages", 7);
        let reads = vec![ProvenRead {
            op: ReadOp::Prefix(rk),
            results: vec![],
        }];
        let mut reader = VerifierReader::new(&reads);
        let result =
            resolve_exists_in_op("messages", &inner, 1, &BTreeMap::new(), &mut reader, "test")
                .unwrap();
        assert!(!result);
    }

    #[test]
    fn exists_id_zero_short_circuits_without_reads() {
        // row.id == 0 is never present; verifier issues no reads.
        let inner = row_col_eq("id", RuleValue::Int(0));
        let reads: Vec<ProvenRead> = vec![];
        let mut reader = VerifierReader::new(&reads);
        let result =
            resolve_exists_in_op("messages", &inner, 1, &BTreeMap::new(), &mut reader, "test")
                .unwrap();
        assert!(!result);
    }

    #[test]
    fn exists_id_plus_other_uses_direct_column_read_when_matching() {
        // `exists(messages, row.id == 5 && row.channel_id == 3)` — with
        // an id constraint, the verifier reads channel_id at row 5
        // directly instead of scanning the channel_id index.
        let inner =
            row_col_eq("id", RuleValue::Int(5)).and(row_col_eq("channel_id", RuleValue::Int(3)));
        let ck = column_key("messages", 5, "channel_id");
        let reads = vec![ProvenRead {
            op: ReadOp::Key(ck.clone()),
            results: vec![(ck, i64_bytes(3))],
        }];
        let mut reader = VerifierReader::new(&reads);
        let result =
            resolve_exists_in_op("messages", &inner, 1, &BTreeMap::new(), &mut reader, "test")
                .unwrap();
        assert!(result);
    }

    #[test]
    fn exists_id_plus_other_returns_false_when_column_value_mismatches() {
        let inner =
            row_col_eq("id", RuleValue::Int(5)).and(row_col_eq("channel_id", RuleValue::Int(3)));
        let ck = column_key("messages", 5, "channel_id");
        let reads = vec![ProvenRead {
            op: ReadOp::Key(ck.clone()),
            results: vec![(ck, i64_bytes(99))],
        }];
        let mut reader = VerifierReader::new(&reads);
        let result =
            resolve_exists_in_op("messages", &inner, 1, &BTreeMap::new(), &mut reader, "test")
                .unwrap();
        assert!(!result);
    }

    #[test]
    fn exists_id_plus_other_returns_false_when_row_absent() {
        // Column key returns empty → row doesn't exist.  No fallback
        // index scan; the id constraint pinned the candidate row.
        let inner =
            row_col_eq("id", RuleValue::Int(5)).and(row_col_eq("channel_id", RuleValue::Int(3)));
        let ck = column_key("messages", 5, "channel_id");
        let reads = vec![ProvenRead {
            op: ReadOp::Key(ck),
            results: vec![],
        }];
        let mut reader = VerifierReader::new(&reads);
        let result =
            resolve_exists_in_op("messages", &inner, 1, &BTreeMap::new(), &mut reader, "test")
                .unwrap();
        assert!(!result);
    }

    #[test]
    fn exists_conflicting_id_constraints_short_circuit_without_reads() {
        let inner = row_col_eq("id", RuleValue::Int(5)).and(row_col_eq("id", RuleValue::Int(6)));
        let reads: Vec<ProvenRead> = vec![];
        let mut reader = VerifierReader::new(&reads);
        let result =
            resolve_exists_in_op("messages", &inner, 1, &BTreeMap::new(), &mut reader, "test")
                .unwrap();
        assert!(!result);
    }

    // ─── StaticMetadataCache tests ─────────────────────────────────────────

    fn cached_ctx() -> OpContext {
        OpContext::for_change_id(0)
    }

    fn col_names_bytes(names: &[&str]) -> Vec<u8> {
        let set: BTreeSet<String> = names.iter().map(|s| s.to_string()).collect();
        encode_column_names(&set)
    }

    #[test]
    fn cache_schema_columns_returns_same_as_fresh_context() {
        let col_bytes = col_names_bytes(&["age", "name"]);
        let key = schema_columns_key("products");

        let reads = vec![ProvenRead {
            op: ReadOp::Key(key.clone()),
            results: vec![(key.clone(), col_bytes.clone())],
        }];
        let mut fresh_reader = VerifierReader::new(&reads);
        let fresh = read_schema_columns(
            "products",
            "test",
            &mut fresh_reader,
            &OpContext::for_change_id(0),
        )
        .unwrap();

        let reads2 = vec![ProvenRead {
            op: ReadOp::Key(key.clone()),
            results: vec![(key, col_bytes)],
        }];
        let mut cached_reader = VerifierReader::new(&reads2);
        let ctx = cached_ctx();
        let cached = read_schema_columns("products", "test", &mut cached_reader, &ctx).unwrap();

        assert_eq!(fresh, cached);
    }

    #[test]
    fn cache_schema_columns_second_read_skips_reader() {
        let col_bytes = col_names_bytes(&["age", "name"]);
        let key = schema_columns_key("products");

        // Only one proven read: the second call must come from cache.
        let reads = vec![ProvenRead {
            op: ReadOp::Key(key.clone()),
            results: vec![(key, col_bytes)],
        }];
        let mut reader = VerifierReader::new(&reads);
        let ctx = cached_ctx();

        let first = read_schema_columns("products", "test", &mut reader, &ctx).unwrap();
        // Reader is exhausted after one read — a second reader call would panic.
        let second = read_schema_columns("products", "test", &mut reader, &ctx).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn cache_schema_indexes_empty_set_when_absent() {
        let key = schema_indexes_key("products");
        let reads = vec![ProvenRead {
            op: ReadOp::Key(key),
            results: vec![], // key absent
        }];
        let mut reader = VerifierReader::new(&reads);
        let ctx = cached_ctx();

        let first = read_schema_indexes("products", &mut reader, &ctx).unwrap();
        assert!(first.is_empty());
        // Second call from cache — reader exhausted.
        let second = read_schema_indexes("products", &mut reader, &ctx).unwrap();
        assert!(second.is_empty());
    }

    #[test]
    fn cache_schema_list_columns_empty_set_when_absent() {
        let key = schema_list_columns_key("products");
        let reads = vec![ProvenRead {
            op: ReadOp::Key(key),
            results: vec![], // key absent
        }];
        let mut reader = VerifierReader::new(&reads);
        let ctx = cached_ctx();

        let first = read_schema_list_columns("products", &mut reader, &ctx).unwrap();
        assert!(first.is_empty());
        // Second call from cache.
        let second = read_schema_list_columns("products", &mut reader, &ctx).unwrap();
        assert!(second.is_empty());
    }

    #[test]
    fn cache_acl_rule_decodes_once() {
        let rule = AccessRule::comparison(
            RuleValue::column(ColumnNamespace::Resource, "owner_id"),
            ComparisonOp::Equal,
            RuleValue::AuthUserId,
        );
        let blob = postcard::to_allocvec(&rule).unwrap();
        let key = acl_rule_key("posts", "write");

        let reads = vec![ProvenRead {
            op: ReadOp::Key(key.clone()),
            results: vec![(key, blob)],
        }];
        let mut reader = VerifierReader::new(&reads);
        let ctx = cached_ctx();

        let first = read_acl_rule(&mut reader, "posts", "write", &ctx).unwrap();
        assert!(first.is_some());
        // Reader exhausted — second call must come from cache.
        let second = read_acl_rule(&mut reader, "posts", "write", &ctx).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn cache_acl_rule_missing_caches_none() {
        let key = acl_rule_key("posts", "write");
        let reads = vec![ProvenRead {
            op: ReadOp::Key(key),
            results: vec![],
        }];
        let mut reader = VerifierReader::new(&reads);
        let ctx = cached_ctx();

        let first = read_acl_rule(&mut reader, "posts", "write", &ctx).unwrap();
        assert!(first.is_none());
        // Cached None — reader exhausted.
        let second = read_acl_rule(&mut reader, "posts", "write", &ctx).unwrap();
        assert!(second.is_none());
    }

    #[test]
    fn cache_clear_forces_reread() {
        let col_bytes = col_names_bytes(&["age", "name"]);
        let key = schema_columns_key("products");

        // Two identical proven reads: first populates cache, clear invalidates,
        // second re-reads from the reader.
        let reads = vec![
            ProvenRead {
                op: ReadOp::Key(key.clone()),
                results: vec![(key.clone(), col_bytes.clone())],
            },
            ProvenRead {
                op: ReadOp::Key(key.clone()),
                results: vec![(key, col_bytes)],
            },
        ];
        let mut reader = VerifierReader::new(&reads);
        let mut ctx = OpContext::for_change_id(0);

        let first = read_schema_columns("products", "test", &mut reader, &ctx).unwrap();

        // Clear the cache.
        ctx.finish_change(OpType::CreateSpace);

        // Must re-read from reader (consuming the second proven read).
        let second = read_schema_columns("products", "test", &mut reader, &ctx).unwrap();
        assert_eq!(first, second);
        // Both proven reads consumed.
        assert!(reader.assert_all_consumed().is_ok());
    }

    #[test]
    fn default_ctx_still_works() {
        let col_bytes = col_names_bytes(&["x"]);
        let key = schema_columns_key("t");
        let reads = vec![ProvenRead {
            op: ReadOp::Key(key.clone()),
            results: vec![(key, col_bytes)],
        }];
        let mut reader = VerifierReader::new(&reads);
        let ctx = OpContext::default();
        let result = read_schema_columns("t", "test", &mut reader, &ctx).unwrap();
        assert!(result.contains("x"));
    }
}
