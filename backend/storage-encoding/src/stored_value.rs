//! Column-value serialization that preserves f64 bits and i64/u64 typing.
//!
//! serde_json's text round-trip loses 1 ULP for certain f64 bit patterns
//! (e.g. `-506890.07170427835` ↔ `-506890.0717042783`) because its parser
//! does not always inverse its own formatter. That round-trip was exposed by
//! the SDK fuzzer as findings #3 and #4 — #3 being the direct precision
//! drop, #4 the downstream effect where an `Integer` column read back as
//! `Number(f64)` failed `as_i64()` during join verification.
//!
//! Column values are stored via postcard against the typed `StoredValue`
//! enum below so every numeric variant round-trips bit-exactly and retains
//! its original integer vs float signedness. postcard cannot deserialize
//! `serde_json::Value` directly because its `Deserialize` impl uses
//! `deserialize_any`; `StoredValue` mirrors `Value`'s shape with explicit
//! numeric variants to avoid that requirement.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};

/// Error returned when postcard encoding or decoding of a column value fails.
#[derive(Debug)]
pub struct StoredValueError(pub String);

impl std::fmt::Display for StoredValueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StoredValueError {}

type Result<T> = std::result::Result<T, StoredValueError>;

#[derive(Serialize, Deserialize)]
pub enum StoredValue {
    Null,
    Bool(bool),
    I64(i64),
    U64(u64),
    F64(f64),
    String(String),
    Array(Vec<StoredValue>),
    Object(Vec<(String, StoredValue)>),
}

impl From<Value> for StoredValue {
    fn from(v: Value) -> Self {
        match v {
            Value::Null => StoredValue::Null,
            Value::Bool(b) => StoredValue::Bool(b),
            Value::Number(n) => number_to_stored(&n),
            Value::String(s) => StoredValue::String(s),
            Value::Array(arr) => StoredValue::Array(arr.into_iter().map(Into::into).collect()),
            Value::Object(m) => {
                StoredValue::Object(m.into_iter().map(|(k, v)| (k, v.into())).collect())
            }
        }
    }
}

impl From<StoredValue> for Value {
    fn from(s: StoredValue) -> Self {
        match s {
            StoredValue::Null => Value::Null,
            StoredValue::Bool(b) => Value::Bool(b),
            StoredValue::I64(i) => Value::Number(Number::from(i)),
            StoredValue::U64(u) => Value::Number(Number::from(u)),
            StoredValue::F64(f) => Number::from_f64(f)
                .map(Value::Number)
                .unwrap_or(Value::Null),
            StoredValue::String(s) => Value::String(s),
            StoredValue::Array(arr) => Value::Array(arr.into_iter().map(Into::into).collect()),
            StoredValue::Object(entries) => {
                let mut m = Map::new();
                for (k, v) in entries {
                    m.insert(k, v.into());
                }
                Value::Object(m)
            }
        }
    }
}

fn number_to_stored(n: &Number) -> StoredValue {
    if let Some(i) = n.as_i64() {
        StoredValue::I64(i)
    } else if let Some(u) = n.as_u64() {
        StoredValue::U64(u)
    } else if let Some(f) = n.as_f64() {
        StoredValue::F64(f)
    } else {
        // Number is finite-guaranteed by serde_json construction paths;
        // this branch is effectively unreachable.
        StoredValue::Null
    }
}

/// Serialize a column `Value` to its on-merk byte form.
pub fn value_to_bytes(value: &Value) -> Result<Vec<u8>> {
    let stored: StoredValue = value.clone().into();
    postcard::to_allocvec(&stored)
        .map_err(|e| StoredValueError(format!("postcard column-value encode failed: {e}")))
}

/// Deserialize a column value from its on-merk byte form.
pub fn bytes_to_value(bytes: &[u8]) -> Result<Value> {
    let stored: StoredValue = postcard::from_bytes(bytes)
        .map_err(|e| StoredValueError(format!("postcard column-value decode failed: {e}")))?;
    Ok(stored.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn f64_lossy_bit_pattern_roundtrip_is_exact() {
        let v: f64 = -506890.07170427835_f64;
        let value = Value::Number(Number::from_f64(v).unwrap());
        let bytes = value_to_bytes(&value).unwrap();
        let back = bytes_to_value(&bytes).unwrap();
        let got = back.as_f64().unwrap();
        assert_eq!(v.to_bits(), got.to_bits());
    }

    #[test]
    fn i64_preserved_as_integer() {
        let v: i64 = -123456789;
        let value = Value::Number(Number::from(v));
        let bytes = value_to_bytes(&value).unwrap();
        let back = bytes_to_value(&bytes).unwrap();
        assert_eq!(back.as_i64(), Some(v));
        assert!(back.is_i64(), "must round-trip as integer, not float");
    }

    #[test]
    fn u64_large_preserved_as_unsigned() {
        let v: u64 = i64::MAX as u64 + 1;
        let value = Value::Number(Number::from(v));
        let bytes = value_to_bytes(&value).unwrap();
        let back = bytes_to_value(&bytes).unwrap();
        assert_eq!(back.as_u64(), Some(v));
    }

    #[test]
    fn nested_object_with_mixed_numbers_roundtrips() {
        let v = serde_json::json!({
            "i": -42_i64,
            "u": 9_223_372_036_854_775_808_u64,
            "f": -506890.07170427835_f64,
            "s": "hi",
            "arr": [1, 2.5, "three", null],
            "nested": {"inner": 7},
        });
        let bytes = value_to_bytes(&v).unwrap();
        let back = bytes_to_value(&bytes).unwrap();
        assert_eq!(back["i"].as_i64(), Some(-42), "negative integer preserved");
        assert_eq!(
            back["u"].as_u64(),
            Some(9_223_372_036_854_775_808_u64),
            "u64 over i64::MAX preserved"
        );
        assert_eq!(
            back["f"].as_f64().unwrap().to_bits(),
            (-506890.07170427835_f64).to_bits(),
            "f64 bit-exact"
        );
        assert_eq!(back["arr"][0].as_i64(), Some(1));
        assert_eq!(back["arr"][1].as_f64(), Some(2.5));
        assert_eq!(back["nested"]["inner"].as_i64(), Some(7));
    }
}
