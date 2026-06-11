//! Key encoding and decoding utilities for the single-Merk storage backend.
//!
//! Uses FoundationDB-style tuple encoding for order-preserving serialization.
//! See `tuple.rs` for the encoding implementation.
//!
//! ## Key Structure
//!
//! All keys are tuples with a type tag as the first element:
//!
//! | Key Type | Tuple Format |
//! |----------|--------------|
//! | Schema   | `("S", table)` |
//! | Row      | `("R", table, row_id)` |
//! | Index    | `("I", table, column, value, row_id)` |
//!
//! This design ensures:
//! - Keys of different types are naturally separated
//! - Row keys for the same table sort by row_id
//! - Index keys sort by (table, column, value, row_id)
//! - Prefix scans work correctly for range queries

use crate::tuple::{decode_tuple, encode_tuple, DecodeError, TupleElement};
use std::borrow::Cow;
use std::fmt;

/// Error type for converting values to `TupleElement`.
///
/// Returned when a value (e.g. a JSON array or object) cannot be represented
/// as a tuple element for index encoding.
#[derive(Debug, Clone)]
pub struct TupleConversionError(pub String);

impl fmt::Display for TupleConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for TupleConversionError {}

impl From<std::convert::Infallible> for TupleConversionError {
    fn from(_: std::convert::Infallible) -> Self {
        unreachable!()
    }
}

/// Convert a JSON value to a `TupleElement` for index encoding.
///
/// This preserves type-specific sort ordering:
/// - Null -> TupleElement::Null (sorts first)
/// - Integers -> TupleElement::Int (sorts numerically)
/// - Floats -> TupleElement::Double (sorts with IEEE 754 encoding)
/// - Strings -> TupleElement::String (sorts lexicographically)
/// - Booleans -> TupleElement::Bool (false < true)
///
/// Returns an error for arrays and objects which are not indexable.
impl TryFrom<&serde_json::Value> for TupleElement {
    type Error = TupleConversionError;

    fn try_from(value: &serde_json::Value) -> Result<Self, Self::Error> {
        json_to_tuple_element(value, false)
    }
}

/// Convert a JSON value to a TupleElement. When `force_double` is true,
/// numeric values are always encoded as `Double` even when representable
/// as i64. Use this for Real-typed columns to avoid type-code mismatches
/// between index keys and query predicates.
pub fn json_to_tuple_element(
    value: &serde_json::Value,
    force_double: bool,
) -> Result<TupleElement, TupleConversionError> {
    match value {
        serde_json::Value::Null => Ok(TupleElement::Null),
        serde_json::Value::String(s) => Ok(TupleElement::String(s.clone())),
        serde_json::Value::Number(n) => {
            if force_double {
                if let Some(f) = n.as_f64() {
                    Ok(TupleElement::Double(f))
                } else {
                    Ok(TupleElement::Double(0.0))
                }
            } else if let Some(i) = n.as_i64() {
                Ok(TupleElement::Int(i))
            } else if let Some(f) = n.as_f64() {
                Ok(TupleElement::Double(f))
            } else {
                Ok(TupleElement::Int(0))
            }
        }
        serde_json::Value::Bool(b) => Ok(TupleElement::Bool(*b)),
        serde_json::Value::Array(_) => Err(TupleConversionError(
            "Arrays cannot be used as index values".to_string(),
        )),
        serde_json::Value::Object(_) => Err(TupleConversionError(
            "Objects cannot be used as index values".to_string(),
        )),
    }
}

/// Identity conversion for TupleElement references (for tests and direct usage).
impl TryFrom<&TupleElement> for TupleElement {
    type Error = TupleConversionError;

    fn try_from(elem: &TupleElement) -> Result<Self, Self::Error> {
        Ok(elem.clone())
    }
}

/// Key type tag for schema keys
const TAG_SCHEMA: &str = "S";

/// Key type tag for row keys
const TAG_ROW: &str = "R";

/// Key type tag for index keys
const TAG_INDEX: &str = "I";

/// Key type tag for entry-level markers (e.g. the action marker kv
/// prepended to `OpType::Action` signed entries).  Markers are wire-
/// format tokens, not stored in authenticated state.
const TAG_MARKER: &str = "M";

/// On-wire format version for the action storage value.
///
/// The stored bytes are `[ACTION_STORAGE_VERSION, postcard(ActionBody)...]`.
/// The action's `name` is the storage key and is reattached at decode
/// time, so the body itself omits it.  Callers prepend / strip the
/// version byte.
pub const ACTION_STORAGE_VERSION: u8 = 1;

/// The table name for the users system table.
pub const USERS_TABLE: &str = "_users";

/// The table name for the key history system table.
pub const KEY_HISTORY_TABLE: &str = "_key_history";

/// The table name for the retention key-value system table.
pub const RETENTION_TABLE: &str = "_retention";

/// The table name for the lists system table.
pub const LISTS_TABLE: &str = "_lists";

/// Error type for key encoding/decoding operations.
#[derive(Debug, Clone)]
pub struct KeyError(pub String);

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for KeyError {}

impl From<DecodeError> for KeyError {
    fn from(e: DecodeError) -> Self {
        KeyError(format!("Failed to decode key: {e}"))
    }
}

/// Build a prefix for iterating all schema keys.
///
/// Format: `tuple("S")` — all schema keys start with this prefix.
pub fn schema_prefix() -> Vec<u8> {
    encode_tuple(&[TAG_SCHEMA.into()])
}

/// Build a key for storing table schema.
///
/// Format: `tuple("S", table)`
pub fn schema_key(table: &str) -> Vec<u8> {
    encode_tuple(&[TAG_SCHEMA.into(), table.into()])
}

/// Build a key for storing the compact column-names list for a table.
///
/// Format: `tuple("S", table, "columns")`
///
/// The value is a null-separated UTF-8 string of non-id column names,
/// e.g. `"name\0price"`.  This is much smaller than the full schema JSON
/// and cheap to parse inside the zkVM guest.
pub fn schema_columns_key(table: &str) -> Vec<u8> {
    encode_tuple(&[TAG_SCHEMA.into(), table.into(), "columns".into()])
}

/// Build a key for storing the compact indexed-column-names list for a table.
///
/// Format: `tuple("S", table, "indexes")`
///
/// The value is a null-separated UTF-8 string of indexed column names,
/// e.g. `"email\0age"`.  This is parallel to `schema_columns_key`.
pub fn schema_indexes_key(table: &str) -> Vec<u8> {
    encode_tuple(&[TAG_SCHEMA.into(), table.into(), "indexes".into()])
}

/// Build a key for storing the compact list-column-names list for a table.
///
/// Format: `tuple("S", table, "list_columns")`
///
/// The value is a null-separated UTF-8 string of column names that have
/// `ColumnType::List`, e.g. `"tasks\0notes"`.
pub fn schema_list_columns_key(table: &str) -> Vec<u8> {
    encode_tuple(&[TAG_SCHEMA.into(), table.into(), "list_columns".into()])
}

/// Build a key for storing the next auto-assigned row ID for a table.
///
/// Format: `tuple("S", table, "next_id")`
///
/// The value is a big-endian `i64`: the row_id the server must assign to
/// the next auto-ID insert.  Absence of this key is treated as the initial
/// value `1`.  Authenticating `next_id` inside Merk is what lets the client
/// verify that an inserted row_id is provably unused.
///
/// Only written for tables with `auto_increment = true`.  Tables with
/// `auto_increment = false` never touch this key.
pub fn schema_next_id_key(table: &str) -> Vec<u8> {
    encode_tuple(&[TAG_SCHEMA.into(), table.into(), "next_id".into()])
}

/// Build a key for storing the id-allocation mode of a table.
///
/// Format: `tuple("S", table, "id_mode")`
///
/// The value is a single byte: `0 = AutoIncrement`, `1 = Explicit`.
/// Written by `create_table`; read by the insert verifier to dispatch
/// between auto-ID and explicit-ID code paths.  Absence of this key is
/// treated as `AutoIncrement` for backward compatibility with tables
/// created before this key existed.
pub fn schema_id_mode_key(table: &str) -> Vec<u8> {
    encode_tuple(&[TAG_SCHEMA.into(), table.into(), "id_mode".into()])
}

/// Build a key for storing the global next-list-number counter.
///
/// Format: `tuple("S", "_lists", "next_list_number")`
///
/// The value is `i64::to_be_bytes(next_list_number)`.
/// Missing key means `next_list_number = 1`.
/// This key only allocates logical list numbers; `_lists` item row ids
/// still use `schema_next_id_key("_lists")`.
pub fn schema_next_list_number_key() -> Vec<u8> {
    encode_tuple(&[
        TAG_SCHEMA.into(),
        LISTS_TABLE.into(),
        "next_list_number".into(),
    ])
}

/// Build a key for storing the head pointer of a specific list.
///
/// Format: `tuple("S", "_lists", "head", list_number)`
///
/// The value is `i64::to_be_bytes(head_id)` where `head_id` is the
/// `_lists.id` of the current head element, or `0` for an empty list.
/// Initialized to `0` by parent InsertOp at allocation time.
/// Missing key is an error — every valid list has this key initialized.
pub fn list_head_key(list_number: i64) -> Vec<u8> {
    encode_tuple(&[
        TAG_SCHEMA.into(),
        LISTS_TABLE.into(),
        "head".into(),
        list_number.into(),
    ])
}

/// Build a key for storing the tail pointer of a specific list.
///
/// Format: `tuple("S", "_lists", "tail", list_number)`
///
/// The value is `i64::to_be_bytes(tail_id)` where `tail_id` is the
/// `_lists.id` of the current tail element, or `0` for an empty list.
/// Initialized to `0` by parent InsertOp at allocation time.
/// Missing key is an error — every valid list has this key initialized.
pub fn list_tail_key(list_number: i64) -> Vec<u8> {
    encode_tuple(&[
        TAG_SCHEMA.into(),
        LISTS_TABLE.into(),
        "tail".into(),
        list_number.into(),
    ])
}

/// `tuple("S", "_lists", "parent", list_number)` — value is the parent
/// `(table, row_id, column)` triple encoded via `encode_list_parent`.
pub fn list_parent_key(list_number: i64) -> Vec<u8> {
    encode_tuple(&[
        TAG_SCHEMA.into(),
        LISTS_TABLE.into(),
        "parent".into(),
        list_number.into(),
    ])
}

/// Prefix shared by every `list_parent_key`; useful for finding the
/// list_parent read inside a proven-reads slice without knowing the
/// list_number ahead of time.
pub fn list_parent_key_prefix() -> Vec<u8> {
    encode_tuple(&[TAG_SCHEMA.into(), LISTS_TABLE.into(), "parent".into()])
}

pub fn encode_list_parent(parent_table: &str, parent_row_id: i64, parent_column: &str) -> Vec<u8> {
    encode_tuple(&[
        parent_table.into(),
        parent_row_id.into(),
        parent_column.into(),
    ])
}

pub fn decode_list_parent(bytes: &[u8]) -> Result<(String, i64, String), KeyError> {
    let elements = decode_tuple(bytes)?;
    if elements.len() != 3 {
        return Err(KeyError(format!(
            "list_parent value must have 3 elements, got {}",
            elements.len()
        )));
    }
    Ok((
        element_to_string(&elements[0])?,
        element_to_int(&elements[1])?,
        element_to_string(&elements[2])?,
    ))
}

/// Build a key prefix for a row (all columns of this row start with this prefix).
///
/// Format: `tuple("R", table, row_id)`
///
/// With per-column storage, individual columns are stored at using a `column_key`.
/// This 3-element key serves as a prefix for scanning all columns of a specific row.
pub fn row_key(table: &str, row_id: i64) -> Vec<u8> {
    encode_tuple(&[TAG_ROW.into(), table.into(), row_id.into()])
}

/// Build a key for storing a single column value of a row.
///
/// Format: `tuple("R", table, row_id, column_name)`
///
/// Each column of a row is stored as a separate key-value entry in the merk tree.
/// The value is the individual column value serialized as JSON.
pub fn column_key(table: &str, row_id: i64, column: &str) -> Vec<u8> {
    encode_tuple(&[TAG_ROW.into(), table.into(), row_id.into(), column.into()])
}

/// Build a placeholder column key for use in changelog entries when the row_id
/// is not yet known (e.g. INSERT, where the server assigns the ID).
///
/// Format: `tuple("R", table, 0, column_name)`
///
/// The verifier matches these against actual column keys by comparing the
/// (table, column) components and ignoring the row_id.
pub fn column_key_placeholder(table: &str, column: &str) -> Vec<u8> {
    column_key(table, 0, column)
}

/// Build a key prefix for iterating all rows in a table.
///
/// Format: `tuple("R", table)` - all row keys for this table start with this prefix
pub fn row_prefix(table: &str) -> Vec<u8> {
    encode_tuple(&[TAG_ROW.into(), table.into()])
}

/// Build a key for an index entry.
///
/// Format: `tuple("I", table, column, value, row_id)`
///
/// The value preserves type-specific sort order:
/// - Integers sort numerically
/// - Strings sort lexicographically
/// - Floats/doubles sort with IEEE 754 encoding
/// - Booleans sort as false < true
/// - Null values sort before all other values
///
/// Returns an error if the value cannot be converted to a TupleElement.
pub fn index_key<V>(
    table: &str,
    column: &str,
    value: V,
    row_id: i64,
) -> Result<Vec<u8>, TupleConversionError>
where
    V: TryInto<TupleElement>,
    V::Error: Into<TupleConversionError>,
{
    let value_elem: TupleElement = value.try_into().map_err(|e| e.into())?;
    Ok(encode_tuple(&[
        TAG_INDEX.into(),
        table.into(),
        column.into(),
        value_elem,
        row_id.into(),
    ]))
}

/// Build a key prefix for iterating all index entries for a column value.
///
/// Format: `tuple("I", table, column, value)` - matches all row_ids for this value
///
/// Returns an error if the value cannot be converted to a TupleElement.
pub fn index_value_prefix<V>(
    table: &str,
    column: &str,
    value: V,
) -> Result<Vec<u8>, TupleConversionError>
where
    V: TryInto<TupleElement>,
    V::Error: Into<TupleConversionError>,
{
    let value_elem: TupleElement = value.try_into().map_err(|e| e.into())?;
    Ok(encode_tuple(&[
        TAG_INDEX.into(),
        table.into(),
        column.into(),
        value_elem,
    ]))
}

/// Build a key prefix for iterating all index entries for a column.
///
/// Format: `tuple("I", table, column)` - matches all values and row_ids for this column
pub fn index_column_prefix(table: &str, column: &str) -> Vec<u8> {
    encode_tuple(&[TAG_INDEX.into(), table.into(), column.into()])
}

/// Build the merk row key for a user in the `_users` table.
///
/// This is a convenience wrapper around `row_key("_users", uid as i64)`.
pub fn users_row_key(uid: u32) -> Vec<u8> {
    row_key(USERS_TABLE, uid as i64)
}

/// Parsed components of a `/list_col/{table}/{row_id}/{column}` tree_path.
#[derive(Debug, Clone)]
pub struct ListColAddress {
    pub table: String,
    pub row_id: i64,
    pub column: String,
}

/// Parse a tree_path byte slice into a `ListColAddress`.
///
/// Expects the format `/list_col/{table}/{row_id}/{column}`.
/// Returns `None` if the path doesn't match this format.
pub fn parse_list_col_tree_path(tree_path: &[u8]) -> Option<ListColAddress> {
    let s = std::str::from_utf8(tree_path).ok()?;
    let s = s.strip_prefix('/')?;
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 4 || parts[0] != "list_col" {
        return None;
    }
    let row_id: i64 = parts[2].parse().ok()?;
    Some(ListColAddress {
        table: parts[1].to_string(),
        row_id,
        column: parts[3].to_string(),
    })
}

/// Build the key for a single ACL rule.
///
/// Format: `tuple("S", table, "acl", op)` where `op` is `"write"` or
/// `"delete"`.  The value is a postcard-encoded `AccessRule`.  Each
/// (table, op) pair has its own merk entry, so a primitive op reads
/// only its applicable rule, not the whole ACL map.
pub fn acl_rule_key(table: &str, op: &str) -> Vec<u8> {
    encode_tuple(&[TAG_SCHEMA.into(), table.into(), "acl".into(), op.into()])
}

/// Build the key for the action-gating list for a single (table, op).
///
/// Format: `tuple("S", table, "only_via_actions", op)` where `op` is
/// `"write"` or `"delete"`.  The value is a postcard-encoded
/// `Vec<String>` of action names allowed to perform `op` on `table`.
/// When this key is present, direct insert/update/delete on the table
/// is rejected; only `OpType::Action` entries naming a listed action
/// pass.
pub fn acl_only_via_actions_key(table: &str, op: &str) -> Vec<u8> {
    encode_tuple(&[
        TAG_SCHEMA.into(),
        table.into(),
        "only_via_actions".into(),
        op.into(),
    ])
}

/// Build the storage key for a single app-defined action, keyed by
/// the action's primary leg's table and its name.
///
/// Format: `tuple("S", primary_table, "action", name)`.
///
/// The value is `[ACTION_STORAGE_VERSION, postcard(ActionBody)]`.  The
/// `name` is the key; the body omits it.  Callers (the schema importer
/// on write; the verifier's `read_action` on read) handle the version
/// byte explicitly.
pub fn action_storage_key(primary_table: &str, name: &str) -> Vec<u8> {
    encode_tuple(&[
        TAG_SCHEMA.into(),
        primary_table.into(),
        "action".into(),
        name.into(),
    ])
}

/// The key the SDK prepends to a `OpType::Action` signed entry as the
/// action marker.  The associated value is the action name as UTF-8
/// bytes.  The verifier reads this first kv to identify both the
/// primary table (from the key) and the action (from the value), then
/// looks up the action storage at
/// `action_storage_key(primary_table, action_name)`.
///
/// Format: `tuple("M", "action_marker", primary_table)`
pub fn action_marker_key(primary_table: &str) -> Vec<u8> {
    encode_tuple(&[
        TAG_MARKER.into(),
        "action_marker".into(),
        primary_table.into(),
    ])
}

/// Prepend [`ACTION_STORAGE_VERSION`] to a serialized action body.
pub fn encode_action_value(body: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(ACTION_STORAGE_VERSION);
    out.extend(body);
    out
}

/// Verify an action storage value's version byte and return the body.
pub fn decode_action_value(bytes: &[u8]) -> Result<&[u8], KeyError> {
    let Some((&version, body)) = bytes.split_first() else {
        return Err(KeyError("action storage value is empty".into()));
    };
    if version != ACTION_STORAGE_VERSION {
        return Err(KeyError(format!(
            "unsupported action storage version {version} (expected {ACTION_STORAGE_VERSION})"
        )));
    }
    Ok(body)
}

/// Parsed key representation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedKey {
    Schema {
        table: String,
    },
    /// `tuple("S", table, "columns")` — compact column-names key.
    SchemaColumns {
        table: String,
    },
    /// `tuple("S", table, "next_id")` — authenticated next-row-id counter.
    SchemaNextId {
        table: String,
    },
    /// `tuple("S", table, "id_mode")` — authenticated id-allocation mode.
    SchemaIdMode {
        table: String,
    },
    Row {
        table: String,
        row_id: i64,
    },
    Column {
        table: String,
        row_id: i64,
        column: String,
    },
    RowPrefix {
        table: String,
    },
    Index {
        table: String,
        column: String,
        value: TupleElement,
        row_id: i64,
    },
    /// `tuple("S", table, "acl", op)` — per-(table, op) ACL rule.
    AclRule {
        table: String,
        op: String,
    },
    /// `tuple("S", table, "only_via_actions", op)` — per-(table, op)
    /// action-gating list.
    OnlyViaActions {
        table: String,
        op: String,
    },
    /// `tuple("S", primary_table, "action", name)` — stored Action.
    Action {
        primary_table: String,
        name: String,
    },
    /// `tuple("M", "action_marker", primary_table)` — the marker kv
    /// key prepended to `OpType::Action` entries.  The value is the
    /// action name.
    ActionMarker {
        primary_table: String,
    },
}

/// Borrowed view of an exact `tuple("R", table, row_id, column)` key.
///
/// Normal table and column names borrow directly from the key bytes. Names
/// containing escaped null bytes are decoded into owned strings so this parser
/// preserves the same semantics as [`parse_key`] without changing the public
/// tuple encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColumnKeyRef<'a> {
    pub table: Cow<'a, str>,
    pub row_id: i64,
    pub column: Cow<'a, str>,
}

/// Parse a key back to its components.
pub fn parse_key(key: &[u8]) -> Result<ParsedKey, KeyError> {
    let elements = decode_tuple(key)?;

    if elements.is_empty() {
        return Err(KeyError("Empty key tuple".into()));
    }

    // First element should be the type tag
    let tag = match &elements[0] {
        TupleElement::Bytes(b) => String::from_utf8_lossy(b).to_string(),
        TupleElement::String(s) => s.clone(),
        _ => return Err(KeyError("Key type tag must be a string".into())),
    };

    match tag.as_str() {
        TAG_SCHEMA => parse_schema_elements(&elements),
        TAG_ROW => parse_row_elements(&elements),
        TAG_INDEX => parse_index_elements(&elements),
        TAG_MARKER => parse_marker_elements(&elements),
        _ => Err(KeyError(format!("Unknown key type: {tag}"))),
    }
}

/// Parse exactly one column key without allocating for normal table/column
/// names.
///
/// This is intentionally narrower than [`parse_key`]: it only accepts the
/// exact four-element column-key shape `("R", table, row_id, column)` and
/// rejects row prefixes, row keys, index keys, schema keys, and any trailing
/// tuple elements.
pub fn parse_column_key_ref(key: &[u8]) -> Result<ColumnKeyRef<'_>, KeyError> {
    let mut pos = 0;
    let tag = decode_string_ref(key, &mut pos, "key type tag")?;
    if tag.as_ref() != TAG_ROW {
        return Err(KeyError(format!(
            "Expected column key tag '{TAG_ROW}', got '{}'",
            tag.as_ref()
        )));
    }

    let table = decode_string_ref(key, &mut pos, "table name")?;
    let row_id = decode_i64_ref(key, &mut pos, "row id")?;
    let column = decode_string_ref(key, &mut pos, "column name")?;

    if pos != key.len() {
        return Err(KeyError(format!(
            "Column key has trailing tuple data: {} bytes",
            key.len() - pos
        )));
    }

    Ok(ColumnKeyRef {
        table,
        row_id,
        column,
    })
}

const TUPLE_BYTES_CODE: u8 = 0x01;
const TUPLE_INT_ZERO_CODE: u8 = 0x14;
const TUPLE_POS_INT_END: u8 = 0x1c;
const TUPLE_NEG_INT_START: u8 = 0x0c;

fn decode_string_ref<'a>(
    bytes: &'a [u8],
    pos: &mut usize,
    label: &str,
) -> Result<Cow<'a, str>, KeyError> {
    let Some(&code) = bytes.get(*pos) else {
        return Err(KeyError(format!("Column key missing {label}")));
    };
    if code != TUPLE_BYTES_CODE {
        return Err(KeyError(format!(
            "Column key {label} must be a string element"
        )));
    }

    let start = *pos + 1;
    let mut i = start;
    let mut segment_start = start;
    let mut decoded: Option<Vec<u8>> = None;

    while i < bytes.len() {
        if bytes[i] == 0x00 {
            if i + 1 < bytes.len() && bytes[i + 1] == 0xFF {
                let out = decoded.get_or_insert_with(|| Vec::with_capacity(i - start + 1));
                out.extend_from_slice(&bytes[segment_start..i]);
                out.push(0x00);
                i += 2;
                segment_start = i;
            } else {
                *pos = i + 1;
                if let Some(mut out) = decoded {
                    out.extend_from_slice(&bytes[segment_start..i]);
                    let s = String::from_utf8(out)
                        .map_err(|e| KeyError(format!("Invalid UTF-8 in {label}: {e}")))?;
                    return Ok(Cow::Owned(s));
                }
                let s = std::str::from_utf8(&bytes[start..i])
                    .map_err(|e| KeyError(format!("Invalid UTF-8 in {label}: {e}")))?;
                return Ok(Cow::Borrowed(s));
            }
        } else {
            i += 1;
        }
    }

    Err(KeyError(format!("Unterminated string element for {label}")))
}

fn decode_i64_ref(bytes: &[u8], pos: &mut usize, label: &str) -> Result<i64, KeyError> {
    let Some(&code) = bytes.get(*pos) else {
        return Err(KeyError(format!("Column key missing {label}")));
    };

    match code {
        TUPLE_INT_ZERO_CODE => {
            *pos += 1;
            Ok(0)
        }
        c if c > TUPLE_INT_ZERO_CODE && c <= TUPLE_POS_INT_END => {
            let n = (c - TUPLE_INT_ZERO_CODE) as usize;
            if bytes.len() < *pos + 1 + n {
                return Err(KeyError(format!("Unexpected end while decoding {label}")));
            }
            let mut value_bytes = [0u8; 8];
            value_bytes[8 - n..].copy_from_slice(&bytes[*pos + 1..*pos + 1 + n]);
            *pos += 1 + n;
            Ok(i64::from_be_bytes(value_bytes))
        }
        c if (TUPLE_NEG_INT_START..TUPLE_INT_ZERO_CODE).contains(&c) => {
            let n = (TUPLE_INT_ZERO_CODE - c) as usize;
            if bytes.len() < *pos + 1 + n {
                return Err(KeyError(format!("Unexpected end while decoding {label}")));
            }
            let mut comp_bytes = [0xFFu8; 8];
            comp_bytes[8 - n..].copy_from_slice(&bytes[*pos + 1..*pos + 1 + n]);
            let complement = u64::from_be_bytes(comp_bytes);
            let abs_val = !complement;
            *pos += 1 + n;
            if abs_val == 1u64 << 63 {
                Ok(i64::MIN)
            } else {
                Ok(-(abs_val as i64))
            }
        }
        _ => Err(KeyError(format!(
            "Column key {label} must be an integer element"
        ))),
    }
}

fn parse_marker_elements(elements: &[TupleElement]) -> Result<ParsedKey, KeyError> {
    if elements.len() < 2 {
        return Err(KeyError("Marker key missing sub-tag".into()));
    }
    let sub = element_to_string(&elements[1])?;
    match sub.as_str() {
        "action_marker" => {
            if elements.len() < 3 {
                return Err(KeyError("action_marker key missing primary_table".into()));
            }
            let primary_table = element_to_string(&elements[2])?;
            Ok(ParsedKey::ActionMarker { primary_table })
        }
        other => Err(KeyError(format!("Unknown marker sub-tag: {other}"))),
    }
}

fn parse_schema_elements(elements: &[TupleElement]) -> Result<ParsedKey, KeyError> {
    if elements.len() < 2 {
        return Err(KeyError("Schema key missing table name".into()));
    }

    let table = element_to_string(&elements[1])?;

    if elements.len() >= 3 {
        if let Ok(sub) = element_to_string(&elements[2]) {
            match sub.as_str() {
                "columns" => return Ok(ParsedKey::SchemaColumns { table }),
                "next_id" => return Ok(ParsedKey::SchemaNextId { table }),
                "id_mode" => return Ok(ParsedKey::SchemaIdMode { table }),
                "acl" => {
                    if elements.len() < 4 {
                        return Err(KeyError("acl key missing op".into()));
                    }
                    let op = element_to_string(&elements[3])?;
                    return Ok(ParsedKey::AclRule { table, op });
                }
                "only_via_actions" => {
                    if elements.len() < 4 {
                        return Err(KeyError("only_via_actions key missing op".into()));
                    }
                    let op = element_to_string(&elements[3])?;
                    return Ok(ParsedKey::OnlyViaActions { table, op });
                }
                "action" => {
                    if elements.len() < 4 {
                        return Err(KeyError("action key missing name".into()));
                    }
                    let name = element_to_string(&elements[3])?;
                    return Ok(ParsedKey::Action {
                        primary_table: table,
                        name,
                    });
                }
                _ => {}
            }
        }
    }

    Ok(ParsedKey::Schema { table })
}

fn parse_row_elements(elements: &[TupleElement]) -> Result<ParsedKey, KeyError> {
    if elements.len() < 2 {
        return Err(KeyError("Row key missing table name".into()));
    }

    let table = element_to_string(&elements[1])?;

    if elements.len() < 3 {
        return Ok(ParsedKey::RowPrefix { table });
    }

    let row_id = match element_to_int(&elements[2]) {
        Ok(id) => id,
        Err(_) => return Ok(ParsedKey::RowPrefix { table }),
    };

    // 4-element key: ("R", table, row_id, column_name) -> Column
    if elements.len() >= 4 {
        let column = element_to_string(&elements[3])?;
        return Ok(ParsedKey::Column {
            table,
            row_id,
            column,
        });
    }

    Ok(ParsedKey::Row { table, row_id })
}

fn parse_index_elements(elements: &[TupleElement]) -> Result<ParsedKey, KeyError> {
    if elements.len() < 5 {
        return Err(KeyError("Index key missing elements".into()));
    }

    let table = element_to_string(&elements[1])?;
    let column = element_to_string(&elements[2])?;
    let value = elements[3].clone();
    let row_id = element_to_int(&elements[4])?;

    Ok(ParsedKey::Index {
        table,
        column,
        value,
        row_id,
    })
}

fn element_to_string(elem: &TupleElement) -> Result<String, KeyError> {
    match elem {
        TupleElement::Bytes(b) => {
            String::from_utf8(b.clone()).map_err(|e| KeyError(format!("Invalid UTF-8 string: {e}")))
        }
        TupleElement::String(s) => Ok(s.clone()),
        _ => Err(KeyError("Expected string element".into())),
    }
}

fn element_to_int(elem: &TupleElement) -> Result<i64, KeyError> {
    match elem {
        TupleElement::Int(i) => Ok(*i),
        _ => Err(KeyError("Expected integer element".into())),
    }
}

/// Convert row ID bytes to i64 (for compatibility with existing code).
/// Note: With tuple encoding, row IDs are encoded as integers directly,
/// but this function is kept for any legacy 8-byte row ID handling.
pub fn bytes_to_row_id(key: &[u8]) -> Result<i64, KeyError> {
    if key.len() != 8 {
        return Err(KeyError(format!(
            "Expected 8-byte key for row ID, got {} bytes",
            key.len()
        )));
    }

    let mut id_bytes = [0u8; 8];
    id_bytes.copy_from_slice(key);
    Ok(u64::from_be_bytes(id_bytes) as i64)
}

/// Convert row ID to 8-byte big-endian representation.
/// Note: With tuple encoding, this is mainly used for storing row_id in index values.
pub fn row_id_to_bytes(row_id: i64) -> [u8; 8] {
    assert!(row_id >= 0, "Row IDs must never be negative");
    (row_id as u64).to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_key_roundtrip() {
        let table = "users";
        let key = schema_key(table);
        let parsed = parse_key(&key).unwrap();

        assert_eq!(
            parsed,
            ParsedKey::Schema {
                table: table.to_string()
            }
        );
    }

    #[test]
    fn test_row_key_roundtrip() {
        let table = "users";
        let row_id = 12345i64;
        let key = row_key(table, row_id);
        let parsed = parse_key(&key).unwrap();

        assert_eq!(
            parsed,
            ParsedKey::Row {
                table: table.to_string(),
                row_id
            }
        );
    }

    #[test]
    fn test_index_key_roundtrip() {
        let table = "users";
        let column = "email";
        let value = TupleElement::String("test@example.com".to_string());
        let row_id = 42i64;
        let key = index_key(table, column, value.clone(), row_id).unwrap();
        let parsed = parse_key(&key).unwrap();

        assert_eq!(
            parsed,
            ParsedKey::Index {
                table: table.to_string(),
                column: column.to_string(),
                value: TupleElement::Bytes(b"test@example.com".to_vec()), // Strings decode as Bytes
                row_id
            }
        );
    }

    #[test]
    fn test_index_key_integer_roundtrip() {
        let table = "users";
        let column = "age";
        let value = TupleElement::Int(42);
        let row_id = 1i64;
        let key = index_key(table, column, value.clone(), row_id).unwrap();
        let parsed = parse_key(&key).unwrap();

        assert_eq!(
            parsed,
            ParsedKey::Index {
                table: table.to_string(),
                column: column.to_string(),
                value: TupleElement::Int(42),
                row_id
            }
        );
    }

    #[test]
    fn test_parse_column_key_ref_roundtrip_borrowed() {
        let key = column_key("products", 123, "name");
        let parsed = parse_column_key_ref(&key).unwrap();

        assert_eq!(parsed.table.as_ref(), "products");
        assert_eq!(parsed.row_id, 123);
        assert_eq!(parsed.column.as_ref(), "name");
        assert!(matches!(parsed.table, Cow::Borrowed(_)));
        assert!(matches!(parsed.column, Cow::Borrowed(_)));
    }

    #[test]
    fn test_parse_column_key_ref_rejects_non_column_keys() {
        assert!(parse_column_key_ref(&schema_key("products")).is_err());
        assert!(parse_column_key_ref(&row_prefix("products")).is_err());
        assert!(parse_column_key_ref(&row_key("products", 123)).is_err());
        assert!(parse_column_key_ref(
            &index_key("products", "name", TupleElement::String("hat".into()), 123).unwrap()
        )
        .is_err());
    }

    #[test]
    fn test_parse_column_key_ref_rejects_trailing_tuple_elements() {
        let key = encode_tuple(&[
            TAG_ROW.into(),
            "products".into(),
            123i64.into(),
            "name".into(),
            "extra".into(),
        ]);

        assert!(parse_column_key_ref(&key).is_err());
    }

    #[test]
    fn test_parse_column_key_ref_matches_parse_key_for_column_keys() {
        for row_id in [i64::MIN, -1, 0, 1, i64::MAX] {
            let key = column_key("products", row_id, "name");
            let borrowed = parse_column_key_ref(&key).unwrap();
            let owned = parse_key(&key).unwrap();

            assert_eq!(
                owned,
                ParsedKey::Column {
                    table: borrowed.table.into_owned(),
                    row_id: borrowed.row_id,
                    column: borrowed.column.into_owned(),
                }
            );
        }
    }

    #[test]
    fn test_parse_column_key_ref_preserves_escaped_null_names() {
        let key = column_key("products\0archive", 7, "display\0name");
        let parsed = parse_column_key_ref(&key).unwrap();

        assert_eq!(parsed.table.as_ref(), "products\0archive");
        assert_eq!(parsed.row_id, 7);
        assert_eq!(parsed.column.as_ref(), "display\0name");
        assert!(matches!(parsed.table, Cow::Owned(_)));
        assert!(matches!(parsed.column, Cow::Owned(_)));
    }

    #[test]
    fn test_row_key_sort_order() {
        let key1 = row_key("users", 1);
        let key2 = row_key("users", 2);
        let key10 = row_key("users", 10);
        let key100 = row_key("users", 100);

        assert!(key1 < key2);
        assert!(key2 < key10);
        assert!(key10 < key100);
    }

    #[test]
    fn test_index_key_integer_sort_order() {
        let key1 = index_key("users", "age", TupleElement::Int(1), 1).unwrap();
        let key2 = index_key("users", "age", TupleElement::Int(2), 1).unwrap();
        let key10 = index_key("users", "age", TupleElement::Int(10), 1).unwrap();
        let key100 = index_key("users", "age", TupleElement::Int(100), 1).unwrap();

        assert!(key1 < key2);
        assert!(key2 < key10);
        assert!(key10 < key100);
    }

    #[test]
    fn test_index_key_negative_integer_sort_order() {
        let key_neg2 = index_key("users", "balance", TupleElement::Int(-2), 1).unwrap();
        let key_neg1 = index_key("users", "balance", TupleElement::Int(-1), 1).unwrap();
        let key_0 = index_key("users", "balance", TupleElement::Int(0), 1).unwrap();
        let key_1 = index_key("users", "balance", TupleElement::Int(1), 1).unwrap();

        assert!(key_neg2 < key_neg1);
        assert!(key_neg1 < key_0);
        assert!(key_0 < key_1);
    }

    #[test]
    fn test_row_prefix() {
        let prefix = row_prefix("users");
        let key1 = row_key("users", 1);
        let key2 = row_key("users", 100);

        assert!(key1.starts_with(&prefix));
        assert!(key2.starts_with(&prefix));

        let other_key = row_key("posts", 1);
        assert!(!other_key.starts_with(&prefix));
    }

    #[test]
    fn test_index_value_prefix() {
        let value = TupleElement::String("test@example.com".to_string());
        let prefix = index_value_prefix("users", "email", value.clone()).unwrap();
        let key1 = index_key("users", "email", value.clone(), 1).unwrap();
        let key2 = index_key("users", "email", value.clone(), 100).unwrap();

        assert!(key1.starts_with(&prefix));
        assert!(key2.starts_with(&prefix));

        let other_value = TupleElement::String("other@example.com".to_string());
        let other_key = index_key("users", "email", other_value, 1).unwrap();
        assert!(!other_key.starts_with(&prefix));
    }

    #[test]
    fn test_key_type_separation() {
        let schema = schema_key("users");
        let row = row_key("users", 1);
        let index = index_key(
            "users",
            "email",
            TupleElement::String("test".to_string()),
            1,
        )
        .unwrap();

        assert!(!row.starts_with(&schema));
        assert!(!index.starts_with(&schema));

        let row_pfx = row_prefix("users");
        assert!(!index.starts_with(&row_pfx));
    }

    #[test]
    fn test_table_with_special_chars() {
        let table = "my_table\x00with\x00nulls";
        let key = schema_key(table);
        let parsed = parse_key(&key).unwrap();

        assert_eq!(
            parsed,
            ParsedKey::Schema {
                table: table.to_string()
            }
        );
    }

    #[test]
    fn test_index_with_null_value() {
        let key = index_key("users", "data", TupleElement::Null, 1).unwrap();
        let parsed = parse_key(&key).unwrap();

        match parsed {
            ParsedKey::Index { value, .. } => {
                assert_eq!(value, TupleElement::Null);
            }
            _ => panic!("Expected Index key"),
        }
    }

    #[test]
    fn test_cross_table_sort_order() {
        let apple1 = row_key("apple", 1);
        let apple2 = row_key("apple", 2);
        let banana1 = row_key("banana", 1);

        assert!(apple1 < apple2);
        assert!(apple2 < banana1);
    }

    #[test]
    fn test_users_row_key_uid_1() {
        let key = users_row_key(1);
        assert_eq!(
            key,
            vec![0x01, 0x52, 0x00, 0x01, 0x5f, 0x75, 0x73, 0x65, 0x72, 0x73, 0x00, 0x15, 0x01]
        );
    }

    #[test]
    fn test_users_row_key_uid_0() {
        let key = users_row_key(0);
        assert_eq!(
            key,
            vec![0x01, 0x52, 0x00, 0x01, 0x5f, 0x75, 0x73, 0x65, 0x72, 0x73, 0x00, 0x14]
        );
    }

    #[test]
    fn test_users_row_key_uid_256() {
        let key = users_row_key(256);
        assert_eq!(
            key,
            vec![
                0x01, 0x52, 0x00, 0x01, 0x5f, 0x75, 0x73, 0x65, 0x72, 0x73, 0x00, 0x16, 0x01, 0x00
            ]
        );
    }

    #[test]
    fn test_column_key_roundtrip() {
        let table = "users";
        let row_id = 42i64;
        let column = "name";
        let key = column_key(table, row_id, column);
        let parsed = parse_key(&key).unwrap();

        assert_eq!(
            parsed,
            ParsedKey::Column {
                table: table.to_string(),
                row_id,
                column: column.to_string(),
            }
        );
    }

    #[test]
    fn test_column_key_prefix_property() {
        // All column keys for a row should start with the row_key prefix
        let prefix = row_key("users", 1);
        let col1 = column_key("users", 1, "age");
        let col2 = column_key("users", 1, "name");
        let col3 = column_key("users", 1, "email");

        assert!(col1.starts_with(&prefix));
        assert!(col2.starts_with(&prefix));
        assert!(col3.starts_with(&prefix));

        // Column keys for different row should NOT match
        let other_row = column_key("users", 2, "age");
        assert!(!other_row.starts_with(&prefix));
    }

    #[test]
    fn test_column_key_sort_order() {
        // Same row: columns sort lexicographically by column name
        let col_age = column_key("users", 1, "age");
        let col_name = column_key("users", 1, "name");
        assert!(col_age < col_name);

        // Different rows: row_id takes precedence
        let col_name_r1 = column_key("users", 1, "name");
        let col_age_r2 = column_key("users", 2, "age");
        assert!(col_name_r1 < col_age_r2);
    }

    #[test]
    fn test_row_prefix_matches_column_keys() {
        // row_prefix(table) should match all column keys for all rows in that table
        let prefix = row_prefix("users");
        let col1 = column_key("users", 1, "name");
        let col2 = column_key("users", 100, "age");

        assert!(col1.starts_with(&prefix));
        assert!(col2.starts_with(&prefix));

        let other_table = column_key("posts", 1, "title");
        assert!(!other_table.starts_with(&prefix));
    }

    #[test]
    fn test_row_key_matches_tuple_encoding() {
        let key = row_key("products", 42);
        let expected = encode_tuple(&[
            TupleElement::String("R".to_string()),
            TupleElement::String("products".to_string()),
            TupleElement::Int(42),
        ]);
        assert_eq!(key, expected);
    }

    #[test]
    fn encode_decode_action_value_roundtrip() {
        let body = b"action-postcard-body".to_vec();
        let encoded = encode_action_value(body.clone());
        assert_eq!(encoded[0], ACTION_STORAGE_VERSION);
        let decoded = decode_action_value(&encoded).unwrap();
        assert_eq!(decoded, body.as_slice());
    }

    #[test]
    fn decode_action_value_rejects_empty_bytes() {
        let err = decode_action_value(&[]).unwrap_err();
        assert!(format!("{err:?}").contains("empty"));
    }

    #[test]
    fn decode_action_value_rejects_unknown_version() {
        let mut bytes = vec![ACTION_STORAGE_VERSION + 1];
        bytes.extend_from_slice(b"any-body");
        let err = decode_action_value(&bytes).unwrap_err();
        assert!(format!("{err:?}").contains("unsupported action storage version"));
    }

    #[test]
    fn decode_action_value_returns_empty_body_when_only_version_byte() {
        let bytes = vec![ACTION_STORAGE_VERSION];
        let body = decode_action_value(&bytes).unwrap();
        assert!(body.is_empty());
    }

    #[test]
    fn action_storage_key_shape() {
        let key = action_storage_key("messages", "send_message");
        let expected = encode_tuple(&[
            TupleElement::String("S".to_string()),
            TupleElement::String("messages".to_string()),
            TupleElement::String("action".to_string()),
            TupleElement::String("send_message".to_string()),
        ]);
        assert_eq!(key, expected);

        let parsed = parse_key(&key).unwrap();
        match parsed {
            ParsedKey::Action {
                primary_table,
                name,
            } => {
                assert_eq!(primary_table, "messages");
                assert_eq!(name, "send_message");
            }
            other => panic!("expected Action, got {other:?}"),
        }
    }

    #[test]
    fn action_marker_key_shape() {
        let key = action_marker_key("messages");
        let expected = encode_tuple(&[
            TupleElement::String("M".to_string()),
            TupleElement::String("action_marker".to_string()),
            TupleElement::String("messages".to_string()),
        ]);
        assert_eq!(key, expected);

        let parsed = parse_key(&key).unwrap();
        match parsed {
            ParsedKey::ActionMarker { primary_table } => {
                assert_eq!(primary_table, "messages");
            }
            other => panic!("expected ActionMarker, got {other:?}"),
        }
    }

    #[test]
    fn acl_rule_key_shape() {
        let key = acl_rule_key("messages", "write");
        let expected = encode_tuple(&[
            TupleElement::String("S".to_string()),
            TupleElement::String("messages".to_string()),
            TupleElement::String("acl".to_string()),
            TupleElement::String("write".to_string()),
        ]);
        assert_eq!(key, expected);

        let parsed = parse_key(&key).unwrap();
        match parsed {
            ParsedKey::AclRule { table, op } => {
                assert_eq!(table, "messages");
                assert_eq!(op, "write");
            }
            other => panic!("expected AclRule, got {other:?}"),
        }
    }

    #[test]
    fn acl_only_via_actions_key_shape() {
        let key = acl_only_via_actions_key("messages", "delete");
        let expected = encode_tuple(&[
            TupleElement::String("S".to_string()),
            TupleElement::String("messages".to_string()),
            TupleElement::String("only_via_actions".to_string()),
            TupleElement::String("delete".to_string()),
        ]);
        assert_eq!(key, expected);

        let parsed = parse_key(&key).unwrap();
        match parsed {
            ParsedKey::OnlyViaActions { table, op } => {
                assert_eq!(table, "messages");
                assert_eq!(op, "delete");
            }
            other => panic!("expected OnlyViaActions, got {other:?}"),
        }
    }
}
