//! Action op: schema-declared actions that wrap calls to primitive ops.
//!
//! An app schema declares a named action like
//!
//! ```text
//! action "send_message" {
//!     assert "self.thread_id == 0 || exists(messages, row.id == self.thread_id)"
//!     insert table="messages"
//! }
//! ```
//!
//! The signed entry carries an [`action_marker_key(primary_table)`] kv
//! at the front of its `entries` (value = the action's UTF-8 name) plus
//! the normal column kvs for each leg.  The verifier extracts both
//! `primary_table` and `action_name` from the marker, then reads the
//! action storage at `action_storage_key(primary_table, action_name)`.
//! Actions don't dictate per-column values;
//! each leg's primitive op (`InsertOp::extract_and_validate` etc.)
//! validates the row per the table's schema and ACL.  What actions add
//! on top of primitive ops:
//!
//! - Auditability: the action identity is part of the user-signed intent.
//! - Cross-op invariants: `asserts` can run `exists(...)` against
//!   foreign tables, which a single primitive op can't.
//! - Cascade-delete fan-out: secondary `cascade_delete` legs delete
//!   child rows in lockstep with the primary delete, with FK
//!   completeness proved via a secondary-index range read.
//!
//! Per-leg ACL: each primary leg inherits the leg's table's ACL by
//! virtue of dispatching to the table's primitive op verifier (which
//! reads the ACL inline).  `cascade_delete` legs skip per-row ACL —
//! authorization is inherited from the primary delete leg.

use super::{
    enforce_only_via_actions, make_index_delete, read_action, read_indexed_row_ids,
    read_schema_columns, read_schema_indexes, resolve_exists_in_op, DeleteOp, InsertOp, OpContext,
    OpReader, OpVerifier, OpVerifyResult, UpdateOp,
};
use crate::changelog::{ChangelogEntry, ChangelogError, KvData};
use crate::{BatchOp, ReadOp, TraceStep};
use encrypted_spaces_acl_types::{
    AccessRule, ActionLeg, Assertion, ColumnNamespace, ComparisonOp, RuleValue,
};
use encrypted_spaces_storage_encoding::keys::column_key;
use encrypted_spaces_storage_encoding::stored_value::bytes_to_value;
use encrypted_spaces_storage_encoding::{parse_key, ParsedKey};
use std::collections::{BTreeMap, BTreeSet};

/// Action op verifier.
pub struct ActionOp;

impl OpVerifier for ActionOp {
    fn extract_and_validate(
        entry: &ChangelogEntry,
        reader: &mut dyn OpReader,
        ctx: &OpContext,
    ) -> Result<OpVerifyResult, ChangelogError> {
        let (primary_table, action_name) = extract_action_marker(entry)?;
        reject_stray_markers(entry, &action_name)?;

        let action = read_action(reader, &primary_table, &action_name, ctx)?.ok_or_else(|| {
            ChangelogError::Generic(format!(
                "action '{action_name}' is not declared on table '{primary_table}'"
            ))
        })?;

        if action.legs.is_empty() {
            return Err(ChangelogError::Generic(format!(
                "action '{action_name}': declares no legs"
            )));
        }

        // Group leg indices by their target table.  A table may be
        // referenced by multiple legs only if the first is a non-cascade
        // primary and the rest are cascade_delete.
        let mut legs_per_table: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
        for (idx, leg) in action.legs.iter().enumerate() {
            legs_per_table.entry(leg.table()).or_default().push(idx);
        }
        for (table, indices) in &legs_per_table {
            if indices.len() == 1 {
                continue;
            }
            if matches!(&action.legs[indices[0]], ActionLeg::CascadeDelete { .. }) {
                return Err(ChangelogError::Generic(format!(
                    "action '{action_name}': table '{table}' is referenced by multiple \
                     legs but the first one is a cascade_delete; the first leg must be a \
                     primary insert/update/delete"
                )));
            }
            for &i in &indices[1..] {
                if !matches!(&action.legs[i], ActionLeg::CascadeDelete { .. }) {
                    return Err(ChangelogError::Generic(format!(
                        "action '{action_name}': table '{table}' is referenced by \
                         multiple legs but leg {i} is not a cascade_delete; same-table \
                         multi-leg actions only support a primary leg followed by \
                         cascade_delete legs"
                    )));
                }
            }
        }

        // Partition the entry's column kvs (everything after the marker)
        // by table.  Reject kvs whose table no leg names.
        let mut per_table: BTreeMap<String, Vec<KvData>> = BTreeMap::new();
        for kv in entry.message.entries.iter().skip(1).cloned() {
            let table = match parse_key(&kv.key) {
                Ok(ParsedKey::Column { table, .. }) => table,
                _ => {
                    return Err(ChangelogError::Generic(format!(
                        "action '{action_name}': non-column kv found beyond the action \
                         marker"
                    )));
                }
            };
            if !legs_per_table.contains_key(table.as_str()) {
                return Err(ChangelogError::Generic(format!(
                    "action '{action_name}': kv targets table '{table}' but no leg of \
                     the action writes there"
                )));
            }
            per_table.entry(table).or_default().push(kv);
        }

        // Split each table's kvs across the legs that target it.
        let mut per_leg_kvs: Vec<Vec<KvData>> = vec![Vec::new(); action.legs.len()];
        for (table, indices) in &legs_per_table {
            let table_kvs = per_table.remove(*table).unwrap_or_default();
            if indices.len() == 1 {
                per_leg_kvs[indices[0]] = table_kvs;
                continue;
            }
            partition_same_table_kvs(
                &action_name,
                table,
                indices,
                &action.legs,
                table_kvs,
                &mut per_leg_kvs,
            )?;
        }

        // Assertions and cascade FK lookups evaluate against the primary
        // (first) leg's self-row context.
        let primary_kvs = &per_leg_kvs[0];
        let self_row = self_row_from_leg_kvs(primary_kvs);
        evaluate_action_asserts(&action_name, &action.asserts, &self_row, entry.uid, reader)?;

        // Each primary leg dispatches to its primitive op verifier
        // against a fresh `OpContext` that names the action — this is
        // how `enforce_only_via_actions` learns the action identity
        // when a table is action-gated.
        let leg_ctx = ctx.for_action_leg(action_name.clone());

        // Dispatch each leg in declared order, accumulating write steps.
        let mut combined = OpVerifyResult {
            write_steps: Vec::new(),
        };
        for (leg_idx, leg) in action.legs.iter().enumerate() {
            let leg_kvs = std::mem::take(&mut per_leg_kvs[leg_idx]);
            let leg_result = match leg {
                ActionLeg::Insert { table } => {
                    enforce_only_via_actions(table, "write", "action", &leg_ctx, reader)?;
                    let sub_entry = subset_entry(entry, leg_kvs);
                    InsertOp::extract_and_validate(&sub_entry, reader, &leg_ctx)?
                }
                ActionLeg::Update { table, cols } => {
                    enforce_only_via_actions(table, "write", "action", &leg_ctx, reader)?;
                    if let Some(allow) = cols {
                        enforce_update_cols_allowlist(&action_name, table, allow, &leg_kvs)?;
                    }
                    let sub_entry = subset_entry(entry, leg_kvs);
                    UpdateOp::extract_and_validate(&sub_entry, reader, &leg_ctx)?
                }
                ActionLeg::Delete { table } => {
                    enforce_only_via_actions(table, "delete", "action", &leg_ctx, reader)?;
                    let sub_entry = subset_entry(entry, leg_kvs);
                    DeleteOp::extract_and_validate(&sub_entry, reader, &leg_ctx)?
                }
                ActionLeg::CascadeDelete {
                    table,
                    where_column,
                    where_self_column,
                } => {
                    if !leg_kvs.is_empty() {
                        return Err(ChangelogError::Generic(format!(
                            "action '{action_name}': cascade_delete leg on '{table}' \
                             carries {} kvs in the signed entry, but cascade rows are \
                             enumerated server-side from the FK index — the entry must not \
                             pre-bundle them",
                            leg_kvs.len()
                        )));
                    }
                    dispatch_cascade_delete(
                        &action_name,
                        table,
                        where_column,
                        where_self_column,
                        &self_row,
                        reader,
                        &leg_ctx,
                    )?
                }
            };
            combined.write_steps.extend(leg_result.write_steps);
        }

        Ok(combined)
    }
}

/// Build a `ChangelogEntry` view containing only the leg's kvs (drops
/// the marker and unrelated rows).  The marker remains in the original
/// entry; the sub-entry just inherits the entry's metadata.
fn subset_entry(entry: &ChangelogEntry, leg_kvs: Vec<KvData>) -> ChangelogEntry {
    let mut sub = entry.clone();
    sub.message.entries = leg_kvs;
    sub
}

/// Parse the action-marker kv at entry position 0.  Returns the
/// `(primary_table, action_name)` pair the verifier needs to look up
/// the action's storage entry.
fn extract_action_marker(entry: &ChangelogEntry) -> Result<(String, String), ChangelogError> {
    let marker_kv = entry
        .message
        .entries
        .first()
        .ok_or_else(|| ChangelogError::Generic("action: entry has no kvs".to_string()))?;
    let parsed = parse_key(&marker_kv.key).map_err(|e| {
        ChangelogError::Generic(format!("action: first kv key failed to parse: {e}"))
    })?;
    let primary_table = match parsed {
        ParsedKey::ActionMarker { primary_table } => primary_table,
        _ => {
            return Err(ChangelogError::Generic(
                "action: first kv is not an action marker".to_string(),
            ));
        }
    };
    let name = std::str::from_utf8(&marker_kv.value)
        .map(str::to_string)
        .map_err(|e| {
            ChangelogError::Generic(format!("action: action marker value is not UTF-8: {e}"))
        })?;
    Ok((primary_table, name))
}

fn reject_stray_markers(entry: &ChangelogEntry, action_name: &str) -> Result<(), ChangelogError> {
    for (idx, kv) in entry.message.entries.iter().enumerate().skip(1) {
        if matches!(parse_key(&kv.key), Ok(ParsedKey::ActionMarker { .. })) {
            return Err(ChangelogError::Generic(format!(
                "action '{action_name}': duplicate action marker at position {idx}"
            )));
        }
    }
    Ok(())
}

/// Extract the integer-column self-row from a leg's kvs.  Action
/// assertions only see `i64`s, so non-integer columns silently drop;
/// any assertion that references them gets a clear "missing self col"
/// error at evaluation time.
///
/// `id` is special: insert legs use the placeholder row_id (0) until
/// the verifier assigns one, while update/delete kvs encode the real
/// row_id in the column key.  If every kv shares the same row_id we
/// expose it as `self.id`.
fn self_row_from_leg_kvs(leg_kvs: &[KvData]) -> BTreeMap<String, i64> {
    let mut out = BTreeMap::new();
    let mut common_row_id: Option<i64> = None;
    let mut row_id_inconsistent = false;
    for kv in leg_kvs {
        let Ok(ParsedKey::Column { column, row_id, .. }) = parse_key(&kv.key) else {
            continue;
        };
        match common_row_id {
            None => common_row_id = Some(row_id),
            Some(prev) if prev != row_id => row_id_inconsistent = true,
            _ => {}
        }
        if let Ok(value) = bytes_to_value(&kv.value) {
            if let Some(i) = value.as_i64() {
                out.insert(column, i);
            }
        }
    }
    if let (Some(id), false) = (common_row_id, row_id_inconsistent) {
        out.insert("id".to_string(), id);
    }
    out
}

fn evaluate_action_asserts(
    action_name: &str,
    asserts: &[Assertion],
    self_row: &BTreeMap<String, i64>,
    self_uid: u32,
    reader: &mut dyn OpReader,
) -> Result<(), ChangelogError> {
    for (idx, assertion) in asserts.iter().enumerate() {
        let ok = evaluate_assertion(assertion, self_uid, self_row, reader, action_name)?;
        if !ok {
            return Err(ChangelogError::Generic(format!(
                "action '{action_name}': assertion #{idx} evaluated to false"
            )));
        }
    }
    Ok(())
}

fn evaluate_assertion(
    assertion: &Assertion,
    self_uid: u32,
    self_row: &BTreeMap<String, i64>,
    reader: &mut dyn OpReader,
    op_name: &str,
) -> Result<bool, ChangelogError> {
    match assertion {
        Assertion::Rule(rule) => evaluate_access_rule(rule, self_uid, self_row, op_name),
        Assertion::Exists { table, predicate } => {
            resolve_exists_in_op(table, predicate, self_uid, self_row, reader, op_name)
        }
        Assertion::And(a, b) => Ok(evaluate_assertion(a, self_uid, self_row, reader, op_name)?
            && evaluate_assertion(b, self_uid, self_row, reader, op_name)?),
        Assertion::Or(a, b) => Ok(evaluate_assertion(a, self_uid, self_row, reader, op_name)?
            || evaluate_assertion(b, self_uid, self_row, reader, op_name)?),
        Assertion::Not(inner) => Ok(!evaluate_assertion(
            inner, self_uid, self_row, reader, op_name,
        )?),
    }
}

/// Reject the update leg if any of its column kvs targets a column
/// not in the action's `cols=` allowlist.  Lock-by-default: an
/// authoring mistake (or a malicious client) trying to mutate a
/// column the action didn't bless surfaces here.
fn enforce_update_cols_allowlist(
    action_name: &str,
    table: &str,
    allow: &[String],
    leg_kvs: &[KvData],
) -> Result<(), ChangelogError> {
    for kv in leg_kvs {
        let Ok(ParsedKey::Column { column, .. }) = parse_key(&kv.key) else {
            continue;
        };
        if !allow.iter().any(|a| a == &column) {
            return Err(ChangelogError::Generic(format!(
                "action '{action_name}': update leg on '{table}' touches column \
                 '{column}', which is not in the action's cols allowlist {allow:?}"
            )));
        }
    }
    Ok(())
}

/// Evaluate a basic predicate against the self-row context.  `row.<col>`
/// references would only be meaningful inside an `exists()` body —
/// outside of one, the action author meant `self.<col>` and we say so.
fn evaluate_access_rule(
    rule: &AccessRule,
    self_uid: u32,
    self_row: &BTreeMap<String, i64>,
    op_name: &str,
) -> Result<bool, ChangelogError> {
    match rule {
        AccessRule::Comparison { left, op, right } => {
            let l = resolve_self_value(left, self_uid, self_row, op_name)?;
            let r = resolve_self_value(right, self_uid, self_row, op_name)?;
            Ok(match op {
                ComparisonOp::Equal => l == r,
                ComparisonOp::NotEqual => l != r,
                ComparisonOp::Less => l < r,
                ComparisonOp::Greater => l > r,
                ComparisonOp::LessEqual => l <= r,
                ComparisonOp::GreaterEqual => l >= r,
            })
        }
        AccessRule::And(a, b) => Ok(evaluate_access_rule(a, self_uid, self_row, op_name)?
            && evaluate_access_rule(b, self_uid, self_row, op_name)?),
        AccessRule::Or(a, b) => Ok(evaluate_access_rule(a, self_uid, self_row, op_name)?
            || evaluate_access_rule(b, self_uid, self_row, op_name)?),
        AccessRule::Not(inner) => Ok(!evaluate_access_rule(inner, self_uid, self_row, op_name)?),
    }
}

fn resolve_self_value(
    value: &RuleValue,
    self_uid: u32,
    self_row: &BTreeMap<String, i64>,
    op_name: &str,
) -> Result<i64, ChangelogError> {
    match value {
        RuleValue::Int(n) => Ok(*n),
        RuleValue::AuthUserId => Ok(self_uid as i64),
        RuleValue::Column {
            namespace: ColumnNamespace::SelfRow,
            name,
        } => self_row.get(name).copied().ok_or_else(|| {
            ChangelogError::Generic(format!(
                "{op_name}: assertion references `self.{name}` but the self row has no \
                 integer value for that column"
            ))
        }),
        RuleValue::Column {
            namespace: ColumnNamespace::Resource,
            name,
        } => Err(ChangelogError::Generic(format!(
            "{op_name}: assertion references `row.{name}` outside an exists() body; use \
             `self.{name}` for the action's outer row"
        ))),
    }
}

/// Cascade-delete leg.  Reads the secondary index on `where_column` for
/// the FK value taken from the primary leg's `self.<where_self_column>`,
/// requires the leg's kvs to cover exactly those row_ids, validates
/// per-row column completeness, and emits the column + index deletes.
/// No per-row ACL — authorization comes from the primary delete leg.
fn dispatch_cascade_delete(
    action_name: &str,
    table: &str,
    where_column: &str,
    where_self_column: &str,
    self_row: &BTreeMap<String, i64>,
    reader: &mut dyn OpReader,
    ctx: &OpContext,
) -> Result<OpVerifyResult, ChangelogError> {
    let fk_value = self_row.get(where_self_column).copied().ok_or_else(|| {
        ChangelogError::Generic(format!(
            "action '{action_name}': cascade_delete on '{table}' needs \
             `self.{where_self_column}` but the primary leg's self row has no integer value \
             for that column"
        ))
    })?;
    let op_name = "action.cascade_delete";

    // The FK index IS the cascade.  Read it once; whatever it returns
    // is exactly the set of rows to delete.
    let row_ids = read_indexed_row_ids(table, where_column, fk_value, reader, op_name)?;
    if row_ids.is_empty() {
        return Ok(OpVerifyResult {
            write_steps: Vec::new(),
        });
    }

    let schema_columns = read_schema_columns(table, op_name, reader, ctx)?;
    let indexed_columns = read_schema_indexes(table, reader, ctx)?;

    let mut delete_ops: Vec<BatchOp> = Vec::new();
    for row_id in &row_ids {
        // Column-key deletes are derivable directly from the schema —
        // no row-content read needed.
        for col in &schema_columns {
            delete_ops.push(BatchOp::Delete {
                key: column_key(table, *row_id, col),
            });
        }
        // Index-key deletes do need the indexed column's value to
        // construct the key; one read per indexed column per row.
        for idx_col in &indexed_columns {
            let col_key = column_key(table, *row_id, idx_col);
            let col_read = reader.read(ReadOp::Key(col_key))?;
            if let Some((_, val)) = col_read.results.first() {
                delete_ops.push(make_index_delete(table, idx_col, val, *row_id, op_name)?);
            }
        }
    }

    Ok(OpVerifyResult {
        write_steps: vec![TraceStep::Write(delete_ops)],
    })
}

/// Partition kvs for a single table that's referenced by multiple
/// legs (one primary + N cascade_delete) into per-leg buckets.
///
/// The primary row is identified by reading each row's cascade FK
/// column(s) and finding the unique row whose `id` is the FK target
/// of the others.  Today we only support cascades whose
/// `where_self_column == "id"` (the primary row's id is the FK
/// target); other self columns would need an extra read of the
/// primary's column value and are rejected here.
fn partition_same_table_kvs(
    action_name: &str,
    table: &str,
    leg_indices: &[usize],
    legs: &[ActionLeg],
    table_kvs: Vec<KvData>,
    per_leg_kvs: &mut [Vec<KvData>],
) -> Result<(), ChangelogError> {
    let op_name = "action.partition";

    let mut cascade_legs: Vec<(usize, String)> = Vec::new();
    for &i in &leg_indices[1..] {
        let ActionLeg::CascadeDelete {
            where_column,
            where_self_column,
            ..
        } = &legs[i]
        else {
            unreachable!("caller validated leg shapes");
        };
        if where_self_column != "id" {
            return Err(ChangelogError::Generic(format!(
                "{op_name} for action '{action_name}': cascade_delete on '{table}' \
                 references `self.{where_self_column}`, but same-table cascade currently \
                 only supports `self.id`"
            )));
        }
        cascade_legs.push((i, where_column.clone()));
    }

    let mut rows: BTreeMap<i64, Vec<KvData>> = BTreeMap::new();
    for kv in table_kvs {
        let row_id = match parse_key(&kv.key) {
            Ok(ParsedKey::Column { row_id, .. }) => row_id,
            _ => {
                return Err(ChangelogError::Generic(format!(
                    "{op_name} for action '{action_name}': non-column kv in '{table}' bucket"
                )));
            }
        };
        rows.entry(row_id).or_default().push(kv);
    }
    let bucket_ids: BTreeSet<i64> = rows.keys().copied().collect();
    if bucket_ids.is_empty() {
        return Ok(());
    }

    // Cascade rows are derived by the verifier from the FK index at
    // dispatch time, so only the primary row should appear here.  If
    // a client bundled multiple rows, reject — we don't try to
    // identify the primary by reading FK columns anymore.
    if bucket_ids.len() != 1 {
        return Err(ChangelogError::Generic(format!(
            "{op_name} for action '{action_name}': '{table}' bucket has {} rows, but \
             same-table multi-leg actions (primary + cascade_delete) accept only the \
             primary row's kvs — cascade rows are derived server-side from the FK index",
            bucket_ids.len()
        )));
    }

    let primary_id = *bucket_ids.iter().next().unwrap();
    let primary_leg_idx = leg_indices[0];
    let primary_row_kvs = rows
        .remove(&primary_id)
        .expect("bucket_ids derived from rows");
    per_leg_kvs[primary_leg_idx] = primary_row_kvs;
    // Cascade legs get no kvs (handled by the dispatcher post-condition).
    let _ = cascade_legs;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::changelog::{ChangelogEntry, LogMessage, OpType};
    use encrypted_spaces_storage_encoding::keys::{action_marker_key, column_key};

    // ─── Helpers ────────────────────────────────────────────────────────────

    fn marker_kv(primary_table: &str, name: &str) -> KvData {
        KvData {
            key: action_marker_key(primary_table),
            value: name.as_bytes().to_vec(),
        }
    }

    fn col_kv(table: &str, row_id: i64, column: &str, value: Vec<u8>) -> KvData {
        KvData {
            key: column_key(table, row_id, column),
            value,
        }
    }

    fn entry_with_kvs(kvs: Vec<KvData>) -> ChangelogEntry {
        ChangelogEntry {
            timestamp: 1000,
            uid: 1,
            parent_change: 0,
            message: LogMessage {
                op_type: OpType::Action,
                tree_path: vec![],
                entries: kvs,
            },
            sig_ref: 0,
            parent_clc: [0u8; 32],
            signature: vec![],
        }
    }

    // ─── extract_action_marker ──────────────────────────────────────────────

    #[test]
    fn extract_action_marker_rejects_entry_with_no_kvs() {
        let entry = entry_with_kvs(vec![]);
        let err = extract_action_marker(&entry).unwrap_err();
        assert!(format!("{err}").contains("entry has no kvs"));
    }

    #[test]
    fn extract_action_marker_rejects_non_marker_first_kv() {
        let entry = entry_with_kvs(vec![col_kv("messages", 1, "content", b"hi".to_vec())]);
        let err = extract_action_marker(&entry).unwrap_err();
        assert!(format!("{err}").contains("first kv is not an action marker"));
    }

    #[test]
    fn extract_action_marker_rejects_non_utf8_marker_value() {
        let entry = entry_with_kvs(vec![KvData {
            key: action_marker_key("messages"),
            value: vec![0xFF, 0xFE, 0xFD],
        }]);
        let err = extract_action_marker(&entry).unwrap_err();
        assert!(format!("{err}").contains("action marker value is not UTF-8"));
    }

    #[test]
    fn extract_action_marker_accepts_valid_marker() {
        let entry = entry_with_kvs(vec![marker_kv("messages", "send_message")]);
        let (primary_table, name) = extract_action_marker(&entry).unwrap();
        assert_eq!(primary_table, "messages");
        assert_eq!(name, "send_message");
    }

    // ─── reject_stray_markers ───────────────────────────────────────────────

    #[test]
    fn reject_stray_markers_rejects_duplicate_marker() {
        let entry = entry_with_kvs(vec![
            marker_kv("messages", "send_message"),
            col_kv("messages", 1, "content", b"hi".to_vec()),
            marker_kv("messages", "send_message"),
        ]);
        let err = reject_stray_markers(&entry, "send_message").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("duplicate action marker") && msg.contains("position 2"));
    }

    #[test]
    fn reject_stray_markers_accepts_single_marker() {
        let entry = entry_with_kvs(vec![
            marker_kv("messages", "send_message"),
            col_kv("messages", 1, "content", b"hi".to_vec()),
        ]);
        reject_stray_markers(&entry, "send_message").unwrap();
    }
}
