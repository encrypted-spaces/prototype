//! Stateful seeded-RNG fuzzer for `encrypted-spaces-sdk`.
//!
//! Drives a multi-actor `World` of `Space<LocalTransport>`s through random
//! schema / CRUD / invite / remove-user sequences against a shared in-memory
//! backend, asserting round-trip, reserved-name, typed-error,
//! predicate-match, and affected-count invariants on every step.
//!
//! See `src/main.rs` for the CLI binary and `tests/smoke.rs` for the
//! fixed-seed smoke test.

pub mod executor;
pub mod gen;
pub mod invariants;
pub mod model;

use encrypted_spaces_backend::error::SdkError;
use encrypted_spaces_backend::schema::{ColumnType, Schema};
use serde_json::Value;

use crate::gen::RandomPredicate;

// ─── Logging helpers ─────────────────────────────────────────────────────
//
// Each `do_*` op in `executor` prints a one-liner via these helpers before
// it issues the SDK call, so a panic later leaves a trail of exactly which
// schemas / rows / predicates / actors were in play.

/// Single-line schema description: `name(col:Type[*][i], …)` where `*`
/// marks plaintext columns and `[i]` marks indexed columns.
pub fn format_schema(schema: &Schema) -> String {
    let cols: Vec<String> = schema
        .columns
        .iter()
        .map(|c| {
            let ty = match c.column_type {
                ColumnType::Integer => "Int",
                ColumnType::String => "String",
                ColumnType::Real => "Real",
                ColumnType::FileRef => "File",
                ColumnType::List => "List",
                ColumnType::Text => "Text",
                ColumnType::Blob => "Blob",
            };
            let mut s = format!("{}:{}", c.name, ty);
            if c.plaintext {
                s.push('*');
            }
            if c.indexed {
                s.push_str("[i]");
            }
            s
        })
        .collect();
    format!("{}({})", schema.name, cols.join(", "))
}

/// Compact representation of a generated row, used in `insert` logs.
pub fn format_row(row: &Value) -> String {
    serde_json::to_string(row).unwrap_or_else(|_| "<unprintable row>".to_string())
}

/// Compact representation of a single value, used in `update set …` logs.
pub fn format_value(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "<unprintable value>".to_string())
}

/// Compact representation of a predicate, e.g. `age GreaterThan 5` or
/// `id Between [1, 10]`.
pub fn format_predicate(pred: &RandomPredicate) -> String {
    let vals: Vec<String> = pred.values.iter().map(format_value).collect();
    let rhs = if vals.len() == 1 {
        vals.into_iter().next().unwrap()
    } else {
        format!("[{}]", vals.join(", "))
    };
    format!("{} {:?} {}", pred.column, pred.operator, rhs)
}

/// Pre-existing ACL infrastructure bugs that cause prover/verifier desync
/// or model/server ACL evaluation disagreement. These are outside the
/// fuzzer's control and outside the list-refactor scope.
pub fn is_known_acl_infra_error(e: &SdkError) -> bool {
    let msg = match e {
        SdkError::DatabaseError(m) => m.as_str(),
        _ => return false,
    };
    // VerifierReader mismatch: prover/verifier disagree on ACL read count.
    if msg.contains("VerifierReader: read at position") {
        return true;
    }
    // Insert ACL fail-closed: ResourceColumn("id") rule can't read `id`
    // from the changelog entry because auto-increment inserts don't carry
    // the assigned id in the signed entry.
    if msg.contains("fail-closed: column") && msg.contains("is required for ACL evaluation") {
        return true;
    }
    false
}
