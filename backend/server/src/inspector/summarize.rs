//! Turns database / changelog state into the inspector's event payloads:
//! per-entry summaries, table schemas, op labels, and query descriptions.
//! Kept out of `db.rs` so the operation code there only has to *emit*
//! events, not build them.

use crate::inspector;
use encrypted_spaces_backend::internal_schemas::is_internal_table;
use encrypted_spaces_backend::merk_storage::{parse_key, stored_value, MerkStorage, ParsedKey};
use encrypted_spaces_backend::query::{
    ComparisonOperator, Order, Query, QueryOperation, QueryParam,
};
use encrypted_spaces_changelog_core::changelog::{Change, OpType};
use std::collections::BTreeSet;

fn column_type_label(t: &encrypted_spaces_backend::schema::ColumnType) -> &'static str {
    use encrypted_spaces_backend::schema::ColumnType::*;
    match t {
        Integer => "int",
        String => "string",
        Text => "text",
        Real => "real",
        Blob => "blob",
        FileRef => "fileref",
        List => "list",
    }
}

/// Best-effort inline preview for a column value. `bytes` is the
/// postcard-encoded `StoredValue` as it sits in the tree. We never panic on
/// malformed bytes — preview is observability, not validation.
fn render_value_preview(bytes: &[u8], encrypted: bool) -> String {
    const MAX_PLAINTEXT_LEN: usize = 80;
    const HEX_PREFIX_BYTES: usize = 8;
    let hex_prefix = || -> String {
        let take = bytes.len().min(HEX_PREFIX_BYTES);
        let mut out = hex::encode(&bytes[..take]);
        if bytes.len() > take {
            out.push('…');
        }
        out
    };
    if encrypted {
        return format!("🔒 {} B · {}", bytes.len(), hex_prefix());
    }
    match stored_value::bytes_to_value(bytes) {
        Ok(v) => {
            let s = match &v {
                serde_json::Value::String(s) => format!("\"{s}\""),
                other => other.to_string(),
            };
            if s.chars().count() > MAX_PLAINTEXT_LEN {
                let truncated: String = s.chars().take(MAX_PLAINTEXT_LEN).collect();
                format!("{truncated}…")
            } else {
                s
            }
        }
        Err(_) => format!("({} B) {}", bytes.len(), hex_prefix()),
    }
}

/// Build inspector `TableInfo` for every table in `names` that has a
/// schema in the tree. Unknown / unparseable tables are skipped silently —
/// the inspector is best-effort, never the source of truth.
pub(crate) fn build_schema_tables(
    names: &BTreeSet<String>,
    db: &MerkStorage,
) -> Vec<inspector::TableInfo> {
    names
        .iter()
        .filter_map(|name| {
            let s = db.get_schema(name).ok()?;
            Some(inspector::TableInfo {
                name: s.name.clone(),
                internal: is_internal_table(&s.name),
                auto_increment: s.auto_increment,
                columns: s
                    .columns
                    .iter()
                    .map(|c| inspector::ColumnInfo {
                        name: c.name.clone(),
                        type_label: column_type_label(&c.column_type).to_string(),
                        plaintext: c.plaintext,
                        indexed: c.indexed,
                    })
                    .collect(),
            })
        })
        .collect()
}

/// Build the inspector `EntrySummary` list from a `Change`'s signed entries.
/// Each entry is parsed; column entries get a plaintext/encrypted
/// classification from the table schema. Missing schemas (e.g. internal
/// tables touched before init completes) default to "encrypted" — never
/// claim cleartext we can't verify.
pub(crate) fn build_entry_summaries(
    change: &Change,
    db: &MerkStorage,
) -> Vec<inspector::EntrySummary> {
    let mut out = Vec::with_capacity(change.entry.message.entries.len());
    for kv in &change.entry.message.entries {
        let value_bytes: &[u8] = kv.value.as_slice();
        let value_size = value_bytes.len();

        let parsed = match parse_key(&kv.key) {
            Ok(p) => p,
            Err(_) => {
                out.push(inspector::EntrySummary::Other {
                    label: format!("unparseable key ({} B)", kv.key.len()),
                    value_size,
                });
                continue;
            }
        };

        match parsed {
            ParsedKey::Column {
                table,
                row_id,
                column,
            } => {
                let plaintext = db
                    .get_schema(&table)
                    .ok()
                    .and_then(|s| {
                        s.columns
                            .iter()
                            .find(|c| c.name == column)
                            .map(|c| c.plaintext)
                    })
                    .unwrap_or(false);
                let preview = render_value_preview(value_bytes, !plaintext);
                out.push(inspector::EntrySummary::Column {
                    table,
                    row_id,
                    column,
                    encrypted: !plaintext,
                    value_size,
                    value_preview: preview,
                });
            }
            ParsedKey::Row { table, row_id } => {
                out.push(inspector::EntrySummary::Row {
                    table,
                    row_id,
                    value_size,
                });
            }
            ParsedKey::Index {
                table,
                column,
                row_id,
                ..
            } => {
                out.push(inspector::EntrySummary::Index {
                    table,
                    column,
                    row_id,
                    value_size,
                });
            }
            ParsedKey::RowPrefix { table } => {
                out.push(inspector::EntrySummary::Other {
                    label: format!("row prefix on {table}"),
                    value_size,
                });
            }
            ParsedKey::Schema { table }
            | ParsedKey::SchemaColumns { table }
            | ParsedKey::SchemaNextId { table }
            | ParsedKey::SchemaIdMode { table } => {
                out.push(inspector::EntrySummary::Other {
                    label: format!("schema metadata for {table}"),
                    value_size,
                });
            }
            ParsedKey::AclRule { table, op } => {
                out.push(inspector::EntrySummary::Other {
                    label: format!("acl rule {table}/{op}"),
                    value_size,
                });
            }
            ParsedKey::OnlyViaActions { table, op } => {
                out.push(inspector::EntrySummary::Other {
                    label: format!("action gating {table}/{op}"),
                    value_size,
                });
            }
            ParsedKey::Action {
                primary_table,
                name,
            } => {
                out.push(inspector::EntrySummary::Other {
                    label: format!("action {primary_table}/{name}"),
                    value_size,
                });
            }
            ParsedKey::ActionMarker { primary_table } => {
                // The marker value is the invoked action's name (UTF-8).
                let name = std::str::from_utf8(value_bytes).unwrap_or("<non-utf8>");
                out.push(inspector::EntrySummary::Other {
                    label: format!("action: {name} → {primary_table}"),
                    value_size,
                });
            }
            ParsedKey::StoreSchema { store } => {
                out.push(inspector::EntrySummary::Other {
                    label: format!("store schema for {store}"),
                    value_size,
                });
            }
            ParsedKey::StoreEntry { store, key } => {
                let k = hex::encode(&key[..key.len().min(8)]);
                out.push(inspector::EntrySummary::Other {
                    label: format!("store {store} key {k}"),
                    value_size,
                });
            }
            ParsedKey::StorePrefix { store } => {
                out.push(inspector::EntrySummary::Other {
                    label: format!("store prefix on {store}"),
                    value_size,
                });
            }
        }
    }
    out
}

fn op_type_label(op: OpType) -> &'static str {
    use OpType::*;
    match op {
        Insert => "Insert",
        Update => "Update",
        Delete => "Delete",
        ListInsert => "ListInsert",
        ListUpdate => "ListUpdate",
        ListDelete => "ListDelete",
        CreateSpace => "CreateSpace",
        RefreshKeys => "RefreshKeys",
        InviteUser => "InviteUser",
        RemoveUser => "RemoveUser",
        Extend => "Extend",
        Reduce => "Reduce",
        Rekey => "Rekey",
        ListAppend => "ListAppend",
        Action => "Action",
        Noop => "Noop",
        StorePut => "StorePut",
        StoreDelete => "StoreDelete",
    }
}

/// For an `Action` op the signed entry's first kv is the action marker: its
/// key is `ActionMarker { primary_table }` and its value is the invoked
/// action's name as UTF-8 (e.g. `send_message`). Returns
/// `(primary_table, action_name)` when the change is a well-formed action.
fn action_invocation(change: &Change) -> Option<(String, String)> {
    let marker = change.entry.message.entries.first()?;
    let primary_table = match parse_key(&marker.key) {
        Ok(ParsedKey::ActionMarker { primary_table }) => primary_table,
        _ => return None,
    };
    let name = std::str::from_utf8(&marker.value).ok()?.to_string();
    Some((primary_table, name))
}

/// Human-facing operation label for inspector events. Mirrors
/// [`op_type_label`] but, for `Action` ops, appends the invoked action's
/// name (e.g. `Action:send_message`) so the ops/wire/MMR views show what the
/// action does rather than a bare `Action`.
pub(crate) fn op_display_label(change: &Change) -> String {
    let op = change.entry.message.op_type;
    let base = op_type_label(op);
    if op == OpType::Action {
        if let Some((_table, name)) = action_invocation(change) {
            return format!("{base}:{name}");
        }
    }
    base.to_string()
}

/// One-line, SQL-ish summary of a query for the inspector's Proofs panel.
/// Surfaces exactly what a `Select` proof attests to; the predicate/limit
/// also explain size — a point lookup proves one row, a wide range or high
/// limit proves many and yields a larger proof.
pub(crate) fn describe_query(query: &Query) -> String {
    fn fmt_param(p: &QueryParam) -> String {
        match p {
            QueryParam::Null => "null".to_string(),
            QueryParam::Integer(i) => i.to_string(),
            QueryParam::Real(r) => r.to_string(),
            QueryParam::Text(s) => format!("\"{s}\""),
            QueryParam::Blob(b) => format!("<{} B blob>", b.len()),
            QueryParam::Boolean(b) => b.to_string(),
        }
    }

    let cols = match &query.operation {
        QueryOperation::Select(cols) if !cols.is_empty() => cols.join(", "),
        _ => "*".to_string(),
    };
    let mut s = format!("SELECT {cols} FROM {}", query.table);

    if let Some(j) = &query.join {
        s.push_str(&format!(
            " JOIN {} ON {}={}",
            j.table, j.on_condition.0, j.on_condition.1
        ));
    }

    if let Some(pred) = &query.predicate {
        let op = match pred.operator {
            ComparisonOperator::Equal => "==",
            ComparisonOperator::In => "IN",
            ComparisonOperator::GreaterThan => ">",
            ComparisonOperator::GreaterThanOrEqual => ">=",
            ComparisonOperator::LessThan => "<",
            ComparisonOperator::LessThanOrEqual => "<=",
            ComparisonOperator::Between => "BETWEEN",
        };
        let vals = match pred.operator {
            ComparisonOperator::In => format!(
                "({})",
                pred.values
                    .iter()
                    .map(fmt_param)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            ComparisonOperator::Between => format!(
                "{} AND {}",
                pred.values.first().map(fmt_param).unwrap_or_default(),
                pred.values.get(1).map(fmt_param).unwrap_or_default(),
            ),
            _ => pred.values.first().map(fmt_param).unwrap_or_default(),
        };
        s.push_str(&format!(" WHERE {} {op} {vals}", pred.column));
        if let Some(cursor) = pred.cursor_id {
            s.push_str(&format!(" [after id {cursor}]"));
        }
    }

    if query.order == Order::Desc {
        s.push_str(" ORDER DESC");
    }
    if let Some(limit) = query.limit {
        s.push_str(&format!(" LIMIT {limit}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use encrypted_spaces_changelog_core::changelog::ROOT_TREE_PATH;

    #[test]
    fn action_display_surfaces_the_invoked_action_name() {
        use encrypted_spaces_storage_encoding::keys::{action_marker_key, column_key};

        let marker_key = action_marker_key("messages");
        let content_key = column_key("messages", 1, "content");
        let change = Change::new(
            OpType::Action,
            1,
            ROOT_TREE_PATH,
            &[marker_key.as_slice(), content_key.as_slice()],
            &[b"send_message", b"hello"],
            0,
            0,
            [0u8; 32],
        )
        .unwrap();

        // The action name is decoded from the marker kv's value.
        let (table, name) = action_invocation(&change).expect("action invocation");
        assert_eq!(table, "messages");
        assert_eq!(name, "send_message");

        // Ops/wire/MMR views show "Action:send_message" rather than "Action".
        assert_eq!(op_display_label(&change), "Action:send_message");

        // A non-action op keeps its plain label.
        let insert = Change::new(
            OpType::Insert,
            1,
            ROOT_TREE_PATH,
            &[column_key("messages", 1, "content").as_slice()],
            &[b"hi"],
            0,
            0,
            [0u8; 32],
        )
        .unwrap();
        assert_eq!(action_invocation(&insert), None);
        assert_eq!(op_display_label(&insert), "Insert");
    }
}
