//! Invariant assertions called by the executor after each op.
//!
//! Panics on violation — the outer fuzz loop's panic hook prints seed and
//! op-index for reproduction.

use std::collections::BTreeSet;

use encrypted_spaces_backend::error::SdkError;
use serde_json::Value;

/// Compare two row JSON values for logical equality, ignoring the `id`
/// field (which is server-assigned on insert and may differ from the
/// `Null` sentinel we passed in).
///
/// `ColumnType::List` cells are skipped because the echoed value is a
/// hydrated list handle (enriched object with `_li`, `_lc`, `_lt`, `_lr`)
/// that differs from the placeholder `0` used at insert time. List
/// content is verified separately by `list_get_all` / `textarea_snapshot`.
pub fn assert_round_trip(inserted: &Value, echoed: &Value, ctx: &str) {
    let i = inserted.as_object().expect("inserted row must be object");
    let e = echoed.as_object().expect("echoed row must be object");

    for (key, want) in i {
        if key == "id" {
            continue;
        }
        let got = e
            .get(key)
            .unwrap_or_else(|| panic!("{ctx}: echoed row missing column '{key}': echoed={echoed}"));
        if unwrap_list_handle(got).is_some() {
            continue;
        }
        if !values_logically_equal(want, got) {
            panic!(
                "{ctx}: round-trip mismatch on column '{key}': inserted={want} echoed={got}\n  full inserted={inserted}\n  full echoed={echoed}"
            );
        }
    }
}

/// JSON `Number` round-trips can shift between int/float reps; treat any
/// numeric pair with equal `as_f64` as equal.
///
/// `ColumnType::List` cells round-trip through `select` as a hydrated
/// `{ "_li": <list_number>, "_lc": <col>, "_lt": <table>, "_lr": <row_id> }`
/// object even though insert took the placeholder integer `0`. Treat the
/// wrapper as equal to its inner `_li`.
fn values_logically_equal(a: &Value, b: &Value) -> bool {
    if let Some(unwrapped_b) = unwrap_list_handle(b) {
        return values_logically_equal(a, unwrapped_b);
    }
    if let Some(unwrapped_a) = unwrap_list_handle(a) {
        return values_logically_equal(unwrapped_a, b);
    }
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => match (x.as_f64(), y.as_f64()) {
            (Some(xf), Some(yf)) => xf == yf,
            _ => x == y,
        },
        _ => a == b,
    }
}

fn unwrap_list_handle(v: &Value) -> Option<&Value> {
    let obj = v.as_object()?;
    if obj.contains_key("_li")
        && obj.contains_key("_lc")
        && obj.contains_key("_lt")
        && obj.contains_key("_lr")
    {
        obj.get("_li")
    } else {
        None
    }
}

/// Negative-op assertion: the result must be an `Err`. Acceptable variants:
/// `ValidationError` (the schema-create path), `DatabaseError` (the CRUD
/// path, which wraps the changelog-layer rejection via
/// `LocalTransport::submit_change`), or `InvalidQuery` (the SDK pre-checks
/// that the table is registered locally before any other validation).
/// Anything else — `Ok`, panic, or a different `SdkError` variant — is a bug.
pub fn assert_reserved_name_rejected<T: std::fmt::Debug>(
    result: &Result<T, SdkError>,
    op_label: &str,
) {
    match result {
        Ok(v) => panic!("{op_label}: reserved-name op unexpectedly succeeded: result={v:?}"),
        Err(SdkError::ValidationError(_))
        | Err(SdkError::DatabaseError(_))
        | Err(SdkError::InvalidQuery(_)) => {}
        Err(other) => {
            panic!("{op_label}: reserved-name op returned unexpected error variant: {other:?}")
        }
    }
}

pub fn assert_affected_count(pre_select_len: usize, affected: usize, op_label: &str) {
    if pre_select_len != affected {
        panic!(
            "{op_label}: affected-count mismatch: select-pre={pre_select_len} affected={affected}"
        );
    }
}

/// Predicate-match parity: the set of ids returned by the SDK for a predicate
/// query must equal the set computed model-side with the same predicate.
pub fn assert_predicate_parity(model_ids: &BTreeSet<i64>, server_rows: &[Value], op_label: &str) {
    let server_ids: BTreeSet<i64> = server_rows
        .iter()
        .filter_map(|row| row.get("id").and_then(|v| v.as_i64()))
        .collect();
    if server_ids != *model_ids {
        let only_model: Vec<i64> = model_ids.difference(&server_ids).copied().collect();
        let only_server: Vec<i64> = server_ids.difference(model_ids).copied().collect();
        panic!(
            "{op_label}: predicate-match parity mismatch: model_ids={model_ids:?} server_ids={server_ids:?} \
             only_in_model={only_model:?} only_in_server={only_server:?}"
        );
    }
}

/// Join-result parity: the row count returned by the SDK must equal the count
/// of matching (left, right) pairs in the shadow state, where matching is
/// stringified-JSON equality on (left[fk_col], right[pk_col]) per the SDK's
/// `assemble_join` convention (`sdk/src/table.rs:241-279`). Rows where the
/// `fk_col` is null are omitted (mirroring the SDK's `filter(!is_null())` at
/// `sdk/src/table.rs:259`).
pub fn assert_join_row_count(expected_pairs: usize, server_rows: &[Value], op_label: &str) {
    if server_rows.len() != expected_pairs {
        panic!(
            "{op_label}: join-result parity mismatch: model_expected={expected_pairs} server_returned={} \
             first_server_row={}",
            server_rows.len(),
            server_rows.first().map(ToString::to_string).unwrap_or_default()
        );
    }
}
