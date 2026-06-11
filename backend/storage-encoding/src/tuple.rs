//! FoundationDB-style tuple encoding for keys.
//!
//! This module implements a subset of the FoundationDB tuple layer encoding,
//! which provides order-preserving serialization of typed values.
//!
//! See: https://github.com/apple/foundationdb/blob/main/design/tuple.md
//!
//! ## Type Codes
//!
//! | Type | Code |
//! |------|------|
//! | Null | 0x00 |
//! | Byte String | 0x01 |
//! | Negative integers | 0x0c-0x13 |
//! | Zero | 0x14 |
//! | Positive integers | 0x15-0x1c |
//! | Float (32-bit) | 0x20 |
//! | Double (64-bit) | 0x21 |
//! | False | 0x26 |
//! | True | 0x26 |
//!
//! ## Encoding Rules
//!
//! - **Strings**: Null-terminated with `0x00` → `0x00 0xFF` escaping
//! - **Integers**: Variable-length big-endian, with sign handling for ordering
//! - **Floats/Doubles**: IEEE 754 with bit manipulation for sort ordering
//! - **Booleans**: Encoded as 0-byte False/True, False sorts before True

/// Type code for null value
const NULL_CODE: u8 = 0x00;

/// Type code for byte string
const BYTES_CODE: u8 = 0x01;

/// Type code for integer zero
const INT_ZERO_CODE: u8 = 0x14;

/// End marker for positive integers (8-byte max)
const POS_INT_END: u8 = 0x1c;

/// Start marker for negative integers (8-byte min)
const NEG_INT_START: u8 = 0x0c;

/// Type code for 32-bit float
const FLOAT_CODE: u8 = 0x20;

/// Type code for 64-bit double
const DOUBLE_CODE: u8 = 0x21;

/// Type code for boolean false
const BOOL_FALSE_CODE: u8 = 0x26;

/// Type code for boolean true
const BOOL_TRUE_CODE: u8 = 0x27;

/// A tuple element that can be encoded.
#[derive(Debug, Clone)]
pub enum TupleElement {
    Null,
    Bytes(Vec<u8>),
    String(String),
    Int(i64),
    Float(f32),
    Double(f64),
    Bool(bool),
}

// Manual PartialEq to handle float comparison (using total ordering)
impl PartialEq for TupleElement {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (TupleElement::Null, TupleElement::Null) => true,
            (TupleElement::Bytes(a), TupleElement::Bytes(b)) => a == b,
            (TupleElement::String(a), TupleElement::String(b)) => a == b,
            (TupleElement::Int(a), TupleElement::Int(b)) => a == b,
            (TupleElement::Float(a), TupleElement::Float(b)) => a.to_bits() == b.to_bits(),
            (TupleElement::Double(a), TupleElement::Double(b)) => a.to_bits() == b.to_bits(),
            (TupleElement::Bool(a), TupleElement::Bool(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for TupleElement {}

impl From<&str> for TupleElement {
    fn from(s: &str) -> Self {
        TupleElement::String(s.to_string())
    }
}

impl From<String> for TupleElement {
    fn from(s: String) -> Self {
        TupleElement::String(s)
    }
}

impl From<&[u8]> for TupleElement {
    fn from(b: &[u8]) -> Self {
        TupleElement::Bytes(b.to_vec())
    }
}

impl From<Vec<u8>> for TupleElement {
    fn from(b: Vec<u8>) -> Self {
        TupleElement::Bytes(b)
    }
}

impl From<i64> for TupleElement {
    fn from(i: i64) -> Self {
        TupleElement::Int(i)
    }
}

impl From<f32> for TupleElement {
    fn from(f: f32) -> Self {
        TupleElement::Float(f)
    }
}

impl From<f64> for TupleElement {
    fn from(f: f64) -> Self {
        TupleElement::Double(f)
    }
}

impl From<bool> for TupleElement {
    fn from(b: bool) -> Self {
        TupleElement::Bool(b)
    }
}

/// Encode a tuple of elements into bytes.
///
/// Elements are encoded sequentially with type-prefixed encoding.
/// The resulting bytes sort lexicographically in tuple order.
pub fn encode_tuple(elements: &[TupleElement]) -> Vec<u8> {
    let mut result = Vec::new();
    for elem in elements {
        encode_element(&mut result, elem);
    }
    result
}

/// Encode a single element into the buffer.
fn encode_element(buf: &mut Vec<u8>, elem: &TupleElement) {
    match elem {
        TupleElement::Null => {
            buf.push(NULL_CODE);
        }
        TupleElement::Bytes(bytes) => {
            buf.push(BYTES_CODE);
            encode_bytes_value(buf, bytes);
            buf.push(0x00); // Null terminator
        }
        TupleElement::String(s) => {
            buf.push(BYTES_CODE);
            encode_bytes_value(buf, s.as_bytes());
            buf.push(0x00); // Null terminator
        }
        TupleElement::Int(i) => {
            encode_int(buf, *i);
        }
        TupleElement::Float(f) => {
            encode_float(buf, *f);
        }
        TupleElement::Double(d) => {
            encode_double(buf, *d);
        }
        TupleElement::Bool(b) => {
            buf.push(if *b { BOOL_TRUE_CODE } else { BOOL_FALSE_CODE });
        }
    }
}

/// Encode bytes with null-byte escaping.
///
/// Every `0x00` in the input is encoded as `0x00 0xFF`.
fn encode_bytes_value(buf: &mut Vec<u8>, bytes: &[u8]) {
    for &b in bytes {
        buf.push(b);
        if b == 0x00 {
            buf.push(0xFF);
        }
    }
}

/// Encode an integer with variable-length representation.
///
/// - Zero: Just the type code 0x14
/// - Positive: Type code (0x14 + n) + n big-endian bytes
/// - Negative: Type code (0x14 - n) + n one's complement bytes
fn encode_int(buf: &mut Vec<u8>, value: i64) {
    if value == 0 {
        buf.push(INT_ZERO_CODE);
        return;
    }

    if value > 0 {
        let bytes = value.to_be_bytes();
        let n = 8 - bytes.iter().position(|&b| b != 0).unwrap_or(7);
        buf.push(INT_ZERO_CODE + n as u8);
        buf.extend_from_slice(&bytes[8 - n..]);
    } else {
        // Negative: use one's complement of |value|
        let abs_val = (value as i128).unsigned_abs() as u64;
        let abs_bytes = abs_val.to_be_bytes();
        let n = 8 - abs_bytes.iter().position(|&b| b != 0).unwrap_or(7);

        buf.push(INT_ZERO_CODE - n as u8);

        let complement = !abs_val;
        let comp_bytes = complement.to_be_bytes();
        buf.extend_from_slice(&comp_bytes[8 - n..]);
    }
}

/// Encode a 32-bit float using IEEE 754 with sort-preserving transformation.
///
/// Transformation for lexicographic ordering:
/// - Negative: flip all bits
/// - Non-negative: flip only sign bit
fn encode_float(buf: &mut Vec<u8>, value: f32) {
    buf.push(FLOAT_CODE);
    let mut bytes = value.to_be_bytes();
    adjust_float_bytes(&mut bytes, true);
    buf.extend_from_slice(&bytes);
}

/// Encode a 64-bit double using IEEE 754 with sort-preserving transformation.
///
/// Transformation for lexicographic ordering:
/// - Negative: flip all bits
/// - Non-negative: flip only sign bit
fn encode_double(buf: &mut Vec<u8>, value: f64) {
    buf.push(DOUBLE_CODE);
    let mut bytes = value.to_be_bytes();
    adjust_float_bytes(&mut bytes, true);
    buf.extend_from_slice(&bytes);
}

/// Transform IEEE 754 float bytes for lexicographic sort ordering.
///
/// When encoding:
/// - If sign bit is set (negative): flip all bits
/// - If sign bit is clear (non-negative): flip only sign bit
///
/// When decoding, the inverse transformation is applied.
fn adjust_float_bytes(bytes: &mut [u8], encode: bool) {
    if (encode && bytes[0] & 0x80 != 0) || (!encode && bytes[0] & 0x80 == 0) {
        // Negative (when encoding) or was negative (when decoding): flip all bits
        for b in bytes.iter_mut() {
            *b ^= 0xFF;
        }
    } else {
        // Non-negative: flip only sign bit
        bytes[0] ^= 0x80;
    }
}

/// Decode a tuple from bytes.
pub fn decode_tuple(bytes: &[u8]) -> Result<Vec<TupleElement>, DecodeError> {
    let mut elements = Vec::new();
    let mut pos = 0;

    while pos < bytes.len() {
        let (elem, consumed) = decode_element(&bytes[pos..])?;
        elements.push(elem);
        pos += consumed;
    }

    Ok(elements)
}

/// Decode a single element from bytes.
fn decode_element(bytes: &[u8]) -> Result<(TupleElement, usize), DecodeError> {
    if bytes.is_empty() {
        return Err(DecodeError::UnexpectedEnd);
    }

    let code = bytes[0];

    match code {
        NULL_CODE => Ok((TupleElement::Null, 1)),

        BYTES_CODE => {
            let (data, consumed) = decode_bytes_value(&bytes[1..])?;
            Ok((TupleElement::Bytes(data), 1 + consumed))
        }

        INT_ZERO_CODE => Ok((TupleElement::Int(0), 1)),

        // Positive integers: codes 0x15..=0x1c
        c if c > INT_ZERO_CODE && c <= POS_INT_END => {
            let n = (c - INT_ZERO_CODE) as usize;
            if bytes.len() < 1 + n {
                return Err(DecodeError::UnexpectedEnd);
            }

            let mut value_bytes = [0u8; 8];
            value_bytes[8 - n..].copy_from_slice(&bytes[1..1 + n]);
            let value = i64::from_be_bytes(value_bytes);

            Ok((TupleElement::Int(value), 1 + n))
        }

        // Negative integers: codes 0x0c..=0x13
        c if (NEG_INT_START..INT_ZERO_CODE).contains(&c) => {
            let n = (INT_ZERO_CODE - c) as usize;
            if bytes.len() < 1 + n {
                return Err(DecodeError::UnexpectedEnd);
            }

            // Decode one's complement with sign extension
            let mut comp_bytes = [0xFFu8; 8];
            comp_bytes[8 - n..].copy_from_slice(&bytes[1..1 + n]);
            let complement = u64::from_be_bytes(comp_bytes);
            let abs_val = !complement;
            let value = if abs_val == 1u64 << 63 {
                i64::MIN
            } else {
                -(abs_val as i64)
            };

            Ok((TupleElement::Int(value), 1 + n))
        }

        FLOAT_CODE => {
            if bytes.len() < 5 {
                return Err(DecodeError::UnexpectedEnd);
            }
            let mut float_bytes = [0u8; 4];
            float_bytes.copy_from_slice(&bytes[1..5]);
            adjust_float_bytes(&mut float_bytes, false);
            let value = f32::from_be_bytes(float_bytes);
            Ok((TupleElement::Float(value), 5))
        }

        DOUBLE_CODE => {
            if bytes.len() < 9 {
                return Err(DecodeError::UnexpectedEnd);
            }
            let mut double_bytes = [0u8; 8];
            double_bytes.copy_from_slice(&bytes[1..9]);
            adjust_float_bytes(&mut double_bytes, false);
            let value = f64::from_be_bytes(double_bytes);
            Ok((TupleElement::Double(value), 9))
        }

        BOOL_FALSE_CODE => Ok((TupleElement::Bool(false), 1)),

        BOOL_TRUE_CODE => Ok((TupleElement::Bool(true), 1)),

        _ => Err(DecodeError::UnknownTypeCode(code)),
    }
}

/// Decode bytes value with null-byte unescaping.
fn decode_bytes_value(bytes: &[u8]) -> Result<(Vec<u8>, usize), DecodeError> {
    let mut result = Vec::new();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == 0x00 {
            if i + 1 < bytes.len() && bytes[i + 1] == 0xFF {
                // Escaped null byte
                result.push(0x00);
                i += 2;
            } else {
                // Null terminator
                return Ok((result, i + 1));
            }
        } else {
            result.push(bytes[i]);
            i += 1;
        }
    }

    Err(DecodeError::UnterminatedString)
}

/// Error during tuple decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    UnexpectedEnd,
    UnknownTypeCode(u8),
    UnterminatedString,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::UnexpectedEnd => write!(f, "Unexpected end of input"),
            DecodeError::UnknownTypeCode(code) => write!(f, "Unknown type code: 0x{code:02x}"),
            DecodeError::UnterminatedString => write!(f, "Unterminated string"),
        }
    }
}

impl std::error::Error for DecodeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_string() {
        let encoded = encode_tuple(&["hello".into()]);
        assert_eq!(encoded, vec![0x01, b'h', b'e', b'l', b'l', b'o', 0x00]);
    }

    #[test]
    fn test_encode_string_with_null() {
        let encoded = encode_tuple(&[TupleElement::Bytes(b"foo\x00bar".to_vec())]);
        assert_eq!(
            encoded,
            vec![0x01, b'f', b'o', b'o', 0x00, 0xFF, b'b', b'a', b'r', 0x00]
        );
    }

    #[test]
    fn test_encode_positive_int() {
        assert_eq!(encode_tuple(&[0i64.into()]), vec![0x14]);
        assert_eq!(encode_tuple(&[1i64.into()]), vec![0x15, 0x01]);
        assert_eq!(encode_tuple(&[255i64.into()]), vec![0x15, 0xFF]);
        assert_eq!(encode_tuple(&[256i64.into()]), vec![0x16, 0x01, 0x00]);
        assert_eq!(
            encode_tuple(&[0x0102030405060708i64.into()]),
            vec![0x1c, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }

    #[test]
    fn test_encode_negative_int() {
        // -1: one's complement of 1 is 0xFE
        assert_eq!(encode_tuple(&[(-1i64).into()]), vec![0x13, 0xFE]);
        // -255: one's complement of 255 is 0x00
        assert_eq!(encode_tuple(&[(-255i64).into()]), vec![0x13, 0x00]);
        // -256: one's complement of 256 is 0xFEFF
        assert_eq!(encode_tuple(&[(-256i64).into()]), vec![0x12, 0xFE, 0xFF]);
    }

    #[test]
    fn test_encode_float() {
        // Test encoding of -42.0f32
        // IEEE 754: -42.0f32 = 0xC2280000
        // After transformation (flip all bits for negative): 0x3DD7FFFF
        let encoded = encode_tuple(&[TupleElement::Float(-42.0)]);
        assert_eq!(encoded, vec![0x20, 0x3d, 0xd7, 0xff, 0xff]);
    }

    #[test]
    fn test_encode_double() {
        // Test encoding of 0.0
        // IEEE 754: 0.0f64 = 0x0000000000000000
        // After transformation (flip sign bit): 0x8000000000000000
        let encoded = encode_tuple(&[TupleElement::Double(0.0)]);
        assert_eq!(
            encoded,
            vec![0x21, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn test_encode_tuple_multiple() {
        let encoded = encode_tuple(&["table".into(), 42i64.into()]);
        assert_eq!(
            encoded,
            vec![0x01, b't', b'a', b'b', b'l', b'e', 0x00, 0x15, 0x2a]
        );
    }

    #[test]
    fn test_decode_string() {
        let encoded = vec![0x01, b'h', b'e', b'l', b'l', b'o', 0x00];
        let decoded = decode_tuple(&encoded).unwrap();
        assert_eq!(decoded, vec![TupleElement::Bytes(b"hello".to_vec())]);
    }

    #[test]
    fn test_decode_string_with_null() {
        let encoded = vec![0x01, b'f', b'o', b'o', 0x00, 0xFF, b'b', b'a', b'r', 0x00];
        let decoded = decode_tuple(&encoded).unwrap();
        assert_eq!(decoded, vec![TupleElement::Bytes(b"foo\x00bar".to_vec())]);
    }

    #[test]
    fn test_decode_int() {
        assert_eq!(decode_tuple(&[0x14]).unwrap(), vec![TupleElement::Int(0)]);
        assert_eq!(
            decode_tuple(&[0x15, 0x2a]).unwrap(),
            vec![TupleElement::Int(42)]
        );
        assert_eq!(
            decode_tuple(&[0x13, 0xFE]).unwrap(),
            vec![TupleElement::Int(-1)]
        );

        let encoded_min = encode_tuple(&[i64::MIN.into()]);
        assert_eq!(
            decode_tuple(&encoded_min).unwrap(),
            vec![TupleElement::Int(i64::MIN)]
        );
    }

    #[test]
    fn test_float_roundtrip() {
        let values = [
            0.0f32,
            -0.0,
            1.0,
            -1.0,
            42.5,
            -42.5,
            f32::INFINITY,
            f32::NEG_INFINITY,
        ];
        for &v in &values {
            let encoded = encode_tuple(&[TupleElement::Float(v)]);
            let decoded = decode_tuple(&encoded).unwrap();
            match &decoded[0] {
                TupleElement::Float(f) => {
                    assert_eq!(f.to_bits(), v.to_bits(), "Float roundtrip failed for {v}");
                }
                _ => panic!("Expected Float"),
            }
        }
    }

    #[test]
    fn test_double_roundtrip() {
        let values = [
            0.0f64,
            -0.0,
            1.0,
            -1.0,
            42.5,
            -42.5,
            f64::INFINITY,
            f64::NEG_INFINITY,
        ];
        for &v in &values {
            let encoded = encode_tuple(&[TupleElement::Double(v)]);
            let decoded = decode_tuple(&encoded).unwrap();
            match &decoded[0] {
                TupleElement::Double(d) => {
                    assert_eq!(d.to_bits(), v.to_bits(), "Double roundtrip failed for {v}");
                }
                _ => panic!("Expected Double"),
            }
        }
    }

    #[test]
    fn test_float_nan_roundtrip() {
        let nan = f32::NAN;
        let encoded = encode_tuple(&[TupleElement::Float(nan)]);
        let decoded = decode_tuple(&encoded).unwrap();
        match &decoded[0] {
            TupleElement::Float(f) => assert!(f.is_nan()),
            _ => panic!("Expected Float"),
        }
    }

    #[test]
    fn test_double_nan_roundtrip() {
        let nan = f64::NAN;
        let encoded = encode_tuple(&[TupleElement::Double(nan)]);
        let decoded = decode_tuple(&encoded).unwrap();
        match &decoded[0] {
            TupleElement::Double(d) => assert!(d.is_nan()),
            _ => panic!("Expected Double"),
        }
    }

    #[test]
    fn test_encode_bool() {
        // False encodes as type code 0x26
        let encoded_false = encode_tuple(&[TupleElement::Bool(false)]);
        assert_eq!(encoded_false, vec![BOOL_FALSE_CODE]);

        // True encodes as type code 0x27
        let encoded_true = encode_tuple(&[TupleElement::Bool(true)]);
        assert_eq!(encoded_true, vec![BOOL_TRUE_CODE]);
    }

    #[test]
    fn test_decode_bool() {
        let decoded_false = decode_tuple(&[BOOL_FALSE_CODE]).unwrap();
        assert_eq!(decoded_false, vec![TupleElement::Bool(false)]);

        let decoded_true = decode_tuple(&[BOOL_TRUE_CODE]).unwrap();
        assert_eq!(decoded_true, vec![TupleElement::Bool(true)]);
    }

    #[test]
    fn test_bool_roundtrip() {
        for b in [false, true] {
            let encoded = encode_tuple(&[TupleElement::Bool(b)]);
            let decoded = decode_tuple(&encoded).unwrap();
            assert_eq!(decoded, vec![TupleElement::Bool(b)]);
        }
    }

    #[test]
    fn test_bool_from_trait() {
        // Test the From<bool> trait implementation
        let false_elem: TupleElement = false.into();
        let true_elem: TupleElement = true.into();

        assert_eq!(false_elem, TupleElement::Bool(false));
        assert_eq!(true_elem, TupleElement::Bool(true));
    }

    #[test]
    fn test_sort_order_bools() {
        let false_encoded = encode_tuple(&[TupleElement::Bool(false)]);
        let true_encoded = encode_tuple(&[TupleElement::Bool(true)]);

        // False (0x26) should sort before True (0x27)
        assert!(false_encoded < true_encoded);
    }

    #[test]
    fn test_roundtrip() {
        let original = vec![
            TupleElement::String("users".to_string()),
            TupleElement::Int(12345),
            TupleElement::Bytes(b"data\x00with\x00nulls".to_vec()),
        ];

        let encoded = encode_tuple(&original);
        let decoded = decode_tuple(&encoded).unwrap();

        // Strings decode as Bytes
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0], TupleElement::Bytes(b"users".to_vec()));
        assert_eq!(decoded[1], TupleElement::Int(12345));
        assert_eq!(
            decoded[2],
            TupleElement::Bytes(b"data\x00with\x00nulls".to_vec())
        );
    }

    #[test]
    fn test_sort_order_strings() {
        let a = encode_tuple(&["apple".into()]);
        let b = encode_tuple(&["banana".into()]);
        let c = encode_tuple(&["cherry".into()]);

        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn test_sort_order_ints() {
        let neg2 = encode_tuple(&[(-2i64).into()]);
        let neg1 = encode_tuple(&[(-1i64).into()]);
        let zero = encode_tuple(&[0i64.into()]);
        let pos1 = encode_tuple(&[1i64.into()]);
        let pos2 = encode_tuple(&[2i64.into()]);

        assert!(neg2 < neg1);
        assert!(neg1 < zero);
        assert!(zero < pos1);
        assert!(pos1 < pos2);
    }

    #[test]
    fn test_sort_order_floats() {
        let values_in_order: Vec<TupleElement> = vec![
            TupleElement::Float(f32::NEG_INFINITY),
            TupleElement::Float(-1000.0),
            TupleElement::Float(-1.0),
            TupleElement::Float(-0.0),
            TupleElement::Float(0.0),
            TupleElement::Float(1.0),
            TupleElement::Float(1000.0),
            TupleElement::Float(f32::INFINITY),
        ];

        let encoded: Vec<Vec<u8>> = values_in_order
            .iter()
            .map(|v| encode_tuple(std::slice::from_ref(v)))
            .collect();

        for i in 0..encoded.len() - 1 {
            assert!(
                encoded[i] < encoded[i + 1],
                "Float sort order violated at index {i}: {:?} should be < {:?}",
                values_in_order[i],
                values_in_order[i + 1]
            );
        }
    }

    #[test]
    fn test_sort_order_doubles() {
        let values_in_order: Vec<TupleElement> = vec![
            TupleElement::Double(f64::NEG_INFINITY),
            TupleElement::Double(-1e100),
            TupleElement::Double(-1.0),
            TupleElement::Double(-1e-100),
            TupleElement::Double(-0.0),
            TupleElement::Double(0.0),
            TupleElement::Double(1e-100),
            TupleElement::Double(1.0),
            TupleElement::Double(1e100),
            TupleElement::Double(f64::INFINITY),
        ];

        let encoded: Vec<Vec<u8>> = values_in_order
            .iter()
            .map(|v| encode_tuple(std::slice::from_ref(v)))
            .collect();

        for i in 0..encoded.len() - 1 {
            assert!(
                encoded[i] < encoded[i + 1],
                "Double sort order violated at index {i}: {:?} should be < {:?}",
                values_in_order[i],
                values_in_order[i + 1]
            );
        }
    }

    #[test]
    fn test_sort_order_mixed_tuple() {
        let t1 = encode_tuple(&["users".into(), 1i64.into()]);
        let t2 = encode_tuple(&["users".into(), 2i64.into()]);
        let t3 = encode_tuple(&["users".into(), 10i64.into()]);

        assert!(t1 < t2);
        assert!(t2 < t3);
    }

    #[test]
    fn test_prefix_property() {
        let prefix = encode_tuple(&["a".into()]);
        let full = encode_tuple(&["a".into(), 1i64.into()]);

        assert!(full.starts_with(&prefix));
    }

    #[test]
    fn test_sort_order_comprehensive() {
        // Build a list of tuples that should sort in this exact order
        let tuples_in_expected_order: Vec<Vec<TupleElement>> = vec![
            // Null comes first (type code 0x00)
            vec![TupleElement::Null],
            // Bytes/strings come next (type code 0x01), sorted lexicographically
            vec!["".into()],
            vec![TupleElement::Bytes(vec![0x00])], // null byte in string
            vec![TupleElement::Bytes(vec![0x00, 0x00])],
            vec!["A".into()],
            vec!["B".into()],
            vec!["a".into()],
            vec!["aa".into()],
            vec!["ab".into()],
            vec!["b".into()],
            // Negative integers (type codes 0x0c-0x13), larger magnitude = smaller value
            vec![i64::MIN.into()],
            vec![(-0x0102030405060708i64).into()],
            vec![(-1000000i64).into()],
            vec![(-65536i64).into()],
            vec![(-256i64).into()],
            vec![(-255i64).into()],
            vec![(-2i64).into()],
            vec![(-1i64).into()],
            // Zero (type code 0x14)
            vec![0i64.into()],
            // Positive integers (type codes 0x15-0x1c)
            vec![1i64.into()],
            vec![2i64.into()],
            vec![255i64.into()],
            vec![256i64.into()],
            vec![65535i64.into()],
            vec![65536i64.into()],
            vec![1000000i64.into()],
            vec![0x0102030405060708i64.into()],
            vec![i64::MAX.into()],
            // Floats (type code 0x20)
            vec![TupleElement::Float(f32::NEG_INFINITY)],
            vec![TupleElement::Float(-1.0)],
            vec![TupleElement::Float(0.0)],
            vec![TupleElement::Float(1.0)],
            vec![TupleElement::Float(f32::INFINITY)],
            // Doubles (type code 0x21)
            vec![TupleElement::Double(f64::NEG_INFINITY)],
            vec![TupleElement::Double(-1.0)],
            vec![TupleElement::Double(0.0)],
            vec![TupleElement::Double(1.0)],
            vec![TupleElement::Double(f64::INFINITY)],
            // Booleans (type codes 0x26-0x27)
            vec![TupleElement::Bool(false)],
            vec![TupleElement::Bool(true)],
        ];

        // Encode all tuples
        let encoded: Vec<Vec<u8>> = tuples_in_expected_order
            .iter()
            .map(|t| encode_tuple(t))
            .collect();

        // Verify each consecutive pair is in order
        for i in 0..encoded.len() - 1 {
            assert!(
                encoded[i] < encoded[i + 1],
                "Sort order violated at index {i}: {:?} should be < {:?}\n\
                 Encoded: {:02x?} should be < {:02x?}",
                tuples_in_expected_order[i],
                tuples_in_expected_order[i + 1],
                encoded[i],
                encoded[i + 1]
            );
        }

        // Also verify by sorting and comparing
        let mut sorted = encoded.clone();
        sorted.sort();
        assert_eq!(encoded, sorted, "Encoded tuples should already be sorted");
    }

    #[test]
    fn test_sort_order_multi_element_tuples() {
        // Test that multi-element tuples sort correctly (first by first element, then second, etc.)
        let tuples_in_expected_order: Vec<Vec<TupleElement>> = vec![
            vec!["a".into()],
            vec!["a".into(), (-1i64).into()],
            vec!["a".into(), 0i64.into()],
            vec!["a".into(), 1i64.into()],
            vec!["a".into(), 1i64.into(), "x".into()],
            vec!["a".into(), 1i64.into(), "y".into()],
            vec!["a".into(), 2i64.into()],
            vec!["b".into()],
            vec!["b".into(), 0i64.into()],
        ];

        let encoded: Vec<Vec<u8>> = tuples_in_expected_order
            .iter()
            .map(|t| encode_tuple(t))
            .collect();

        for i in 0..encoded.len() - 1 {
            assert!(
                encoded[i] < encoded[i + 1],
                "Sort order violated at index {i}: {:?} should be < {:?}",
                tuples_in_expected_order[i],
                tuples_in_expected_order[i + 1]
            );
        }
    }

    #[test]
    fn test_sort_order_integer_boundaries() {
        // Test integer encoding at byte-length boundaries
        let tuples_in_expected_order: Vec<Vec<TupleElement>> = vec![
            // 1-byte boundary: 255 -> 256
            vec![255i64.into()],
            vec![256i64.into()],
            // 2-byte boundary: 65535 -> 65536
            vec![65535i64.into()],
            vec![65536i64.into()],
            // 3-byte boundary: 16777215 -> 16777216
            vec![16777215i64.into()],
            vec![16777216i64.into()],
            // 4-byte boundary: 4294967295 -> 4294967296
            vec![4294967295i64.into()],
            vec![4294967296i64.into()],
        ];

        let encoded: Vec<Vec<u8>> = tuples_in_expected_order
            .iter()
            .map(|t| encode_tuple(t))
            .collect();

        for i in 0..encoded.len() - 1 {
            assert!(
                encoded[i] < encoded[i + 1],
                "Sort order violated at boundary {i}: {:?} should be < {:?}",
                tuples_in_expected_order[i][0],
                tuples_in_expected_order[i + 1][0]
            );
        }
    }

    #[test]
    fn test_sort_order_negative_integer_boundaries() {
        // Test negative integer encoding at byte-length boundaries
        let tuples_in_expected_order: Vec<Vec<TupleElement>> = vec![
            // More negative = smaller, needs more bytes = smaller type code
            vec![(-4294967297i64).into()], // needs 5 bytes
            vec![(-4294967296i64).into()], // needs 5 bytes
            vec![(-4294967295i64).into()], // needs 4 bytes
            vec![(-16777217i64).into()],   // needs 4 bytes
            vec![(-16777216i64).into()],   // needs 4 bytes
            vec![(-16777215i64).into()],   // needs 3 bytes
            vec![(-65537i64).into()],      // needs 3 bytes
            vec![(-65536i64).into()],      // needs 3 bytes
            vec![(-65535i64).into()],      // needs 2 bytes
            vec![(-257i64).into()],        // needs 2 bytes
            vec![(-256i64).into()],        // needs 2 bytes
            vec![(-255i64).into()],        // needs 1 byte
            vec![(-1i64).into()],          // needs 1 byte
        ];

        let encoded: Vec<Vec<u8>> = tuples_in_expected_order
            .iter()
            .map(|t| encode_tuple(t))
            .collect();

        for i in 0..encoded.len() - 1 {
            assert!(
                encoded[i] < encoded[i + 1],
                "Sort order violated at index {i}: {:?} should be < {:?}\n\
                 Encoded: {:02x?} should be < {:02x?}",
                tuples_in_expected_order[i][0],
                tuples_in_expected_order[i + 1][0],
                encoded[i],
                encoded[i + 1]
            );
        }
    }
}
