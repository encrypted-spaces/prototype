//! JSON fixture loading utilities for tracer tests and benchmarks.

use ffproof_tracer_shared::{BatchOp, InputStep, ReadOp};
use merk::{InMemoryMerk, Op};
use serde::Deserialize;
use std::collections::BTreeMap;

/// JSON fixture format — supports both legacy (operations) and new (steps) formats.
#[derive(Deserialize)]
pub struct JsonFixture {
    pub initial_entries: Vec<JsonEntry>,
    /// Legacy format: flat list of write operations → single Write step
    pub operations: Option<Vec<JsonOp>>,
    /// New format: ordered list of Read/Write steps
    pub steps: Option<Vec<JsonStep>>,
}

#[derive(Deserialize)]
pub struct JsonEntry {
    pub key: String,   // hex-encoded
    pub value: String, // hex-encoded
}

#[derive(Deserialize)]
#[serde(untagged)]
#[allow(non_snake_case)]
pub enum JsonOp {
    Put { Put: JsonPutOp },
    Delete { Delete: JsonDeleteOp },
}

#[derive(Deserialize)]
pub struct JsonPutOp {
    pub key: String,
    pub value: String,
}

#[derive(Deserialize)]
pub struct JsonDeleteOp {
    pub key: String,
}

/// A step in the new fixture format
#[derive(Deserialize)]
pub enum JsonStep {
    Read(Vec<JsonReadOp>),
    Write(Vec<JsonOp>),
}

/// A read operation in JSON format
#[derive(Deserialize)]
pub enum JsonReadOp {
    Key(String),
    Prefix(String),
    Range { start: String, end: String },
}

/// Convert a hex-encoded string to a Vec<u8>.
pub fn hex_to_key(s: &str) -> Vec<u8> {
    hex::decode(s).expect("invalid hex for key")
}

/// Convert a hex-encoded string to a Vec<u8>.
pub fn hex_to_value(s: &str) -> Vec<u8> {
    hex::decode(s).expect("invalid hex for value")
}

fn convert_json_op(op: &JsonOp) -> BatchOp {
    match op {
        JsonOp::Put { Put: p } => BatchOp::Put {
            key: hex_to_key(&p.key),
            value: hex_to_value(&p.value),
        },
        JsonOp::Delete { Delete: d } => BatchOp::Delete {
            key: hex_to_key(&d.key),
        },
    }
}

fn convert_json_read_op(op: &JsonReadOp) -> ReadOp {
    match op {
        JsonReadOp::Key(k) => ReadOp::Key(hex_to_key(k)),
        JsonReadOp::Prefix(p) => ReadOp::Prefix(hex_to_key(p)),
        JsonReadOp::Range { start, end } => ReadOp::Range {
            start: hex_to_key(start),
            end: hex_to_key(end),
        },
    }
}

/// Load a fixture from a JSON file, returning the full tree and input steps.
pub fn load_from_file(path: &str) -> (merk::Node, Vec<InputStep>) {
    println!("Loading fixture from {path}...");
    let json_content = std::fs::read_to_string(path).expect("Failed to read fixture file");
    let fixture_json: JsonFixture =
        serde_json::from_str(&json_content).expect("Failed to parse fixture JSON");

    // Convert to steps (backward-compat: operations → single Write step)
    let steps = if let Some(json_steps) = &fixture_json.steps {
        println!(
            "Loaded {} initial entries, {} steps",
            fixture_json.initial_entries.len(),
            json_steps.len()
        );
        json_steps
            .iter()
            .map(|step| match step {
                JsonStep::Read(read_ops) => {
                    InputStep::Read(read_ops.iter().map(convert_json_read_op).collect())
                }
                JsonStep::Write(ops) => InputStep::Write(ops.iter().map(convert_json_op).collect()),
            })
            .collect()
    } else if let Some(operations) = &fixture_json.operations {
        println!(
            "Loaded {} initial entries, {} operations",
            fixture_json.initial_entries.len(),
            operations.len()
        );
        vec![InputStep::Write(
            operations.iter().map(convert_json_op).collect(),
        )]
    } else {
        panic!("Fixture must have either 'steps' or 'operations' field");
    };

    // Sort and dedupe initial_entries (BTreeMap, last-write-wins)
    let mut initial_kvs: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    for entry in &fixture_json.initial_entries {
        let key = hex_to_key(&entry.key);
        let value = hex_to_value(&entry.value);
        initial_kvs.insert(key, value);
    }

    let merk = InMemoryMerk::new();
    let batch: Vec<_> = initial_kvs
        .into_iter()
        .map(|(k, v)| (k, Op::Put(v)))
        .collect();
    merk.apply_batch(&batch)
        .expect("Failed to build initial tree");

    let full_tree = merk.snapshot().expect("Tree should not be empty");

    (full_tree, steps)
}
