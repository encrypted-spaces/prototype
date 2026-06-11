//! Key encoding utilities for the Merk storage backend.
//!
//! Re-exports the core key encoding from `encrypted-spaces-storage-encoding` and adds
//! backend-specific conversion functions for `QueryParam`.

// Re-export everything from storage-encoding
pub use encrypted_spaces_storage_encoding::keys::*;
#[cfg(any(feature = "merk", feature = "merk_verify"))]
pub use encrypted_spaces_storage_encoding::tuple::TupleElement;

#[cfg(any(feature = "merk", feature = "merk_verify"))]
use crate::query::QueryParam;
/// Convert a QueryParam to a TupleElement for index encoding.
///
/// All QueryParam variants can be converted to TupleElement.
#[cfg(any(feature = "merk", feature = "merk_verify"))]
pub fn query_param_to_tuple_element(param: &QueryParam) -> TupleElement {
    match param {
        QueryParam::Text(s) => TupleElement::String(s.clone()),
        QueryParam::Integer(i) => TupleElement::Int(*i),
        QueryParam::Boolean(b) => TupleElement::Bool(*b),
        QueryParam::Real(f) => TupleElement::Double(*f),
        QueryParam::Null => TupleElement::Null,
        QueryParam::Blob(b) => TupleElement::Bytes(b.clone()),
    }
}

/// Build an index key using the column's declared type to select the correct
/// tuple encoding. Real columns always use TupleElement::Double so storage and
/// query range bounds share the same tuple type code.
#[cfg(any(feature = "merk", feature = "merk_verify"))]
pub fn typed_index_key(
    table: &str,
    column: &str,
    value: &serde_json::Value,
    row_id: i64,
    column_type: &crate::schema::ColumnType,
) -> Result<Vec<u8>, TupleConversionError> {
    let force_double = matches!(column_type, crate::schema::ColumnType::Real);
    let value_elem = json_to_tuple_element(value, force_double)?;
    index_key(table, column, value_elem, row_id)
}

#[cfg(all(test, feature = "merk"))]
mod tests {
    use super::*;

    #[test]
    fn test_json_to_tuple_element() {
        let elem: TupleElement = (&serde_json::json!("hello")).try_into().unwrap();
        assert_eq!(elem, TupleElement::String("hello".to_string()));

        let elem: TupleElement = (&serde_json::json!(42)).try_into().unwrap();
        assert_eq!(elem, TupleElement::Int(42));

        let elem: TupleElement = (&serde_json::json!(-100)).try_into().unwrap();
        assert_eq!(elem, TupleElement::Int(-100));

        let elem: TupleElement = (&serde_json::json!(true)).try_into().unwrap();
        assert_eq!(elem, TupleElement::Bool(true));

        let elem: TupleElement = (&serde_json::json!(false)).try_into().unwrap();
        assert_eq!(elem, TupleElement::Bool(false));

        let elem: TupleElement = (&serde_json::Value::Null).try_into().unwrap();
        assert_eq!(elem, TupleElement::Null);
    }

    #[test]
    fn test_json_to_tuple_element_array_error() {
        let result: Result<TupleElement, _> = (&serde_json::json!([1, 2, 3])).try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_json_to_tuple_element_object_error() {
        let result: Result<TupleElement, _> = (&serde_json::json!({"key": "value"})).try_into();
        assert!(result.is_err());
    }
}
