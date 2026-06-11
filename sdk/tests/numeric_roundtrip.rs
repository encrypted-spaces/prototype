//! Minimal deterministic reproducers for findings #3 and #4.
//!
//! #3: `Real` column values lose f64 precision through the SDK round-trip.
//! #4: `Integer` column values come back as `Number(f64)` rather than
//!     `Number(i64)` — `as_i64()` returns None at join time.
//!
//! These tests pin the exact layer where the loss happens so we can pick a
//! targeted fix.

#![cfg(feature = "local-transport")]

use encrypted_spaces_sdk::{ColumnType, LocalTransport, SchemaBuilder, Space};
use serde_json::Value;

/// A specific f64 that our fuzzer observed as lossy: inserted
/// `-506890.07170427835`, echoed `-506890.0717042783`.
const LOSSY_REAL: f64 = -506890.07170427835_f64;

async fn fresh_space() -> Space {
    let transport = LocalTransport::in_memory().await.expect("in_memory");
    let space = Space::new(transport).await.expect("Space::new");
    space.authenticate_as_id(1).await.expect("authenticate");
    space
}

/// Pins the serde_json quirk that motivated the switch to postcard for
/// column storage: for this specific f64, serde_json's parser returns a
/// different bit pattern than the one its own formatter just wrote. If
/// upstream serde_json ever fixes this, the test will start failing and
/// we'll be able to reconsider the targeted fix vs the format migration.
#[test]
fn serde_json_f64_roundtrip_is_lossy() {
    let v: Value = Value::Number(serde_json::Number::from_f64(LOSSY_REAL).unwrap());
    let bytes = serde_json::to_vec(&v).unwrap();
    let back: Value = serde_json::from_slice(&bytes).unwrap();
    let got = back.as_f64().unwrap();
    assert_ne!(
        LOSSY_REAL.to_bits(),
        got.to_bits(),
        "serde_json f64 round-trip appears fixed upstream; revisit whether \
         the postcard column format is still needed"
    );
}

#[tokio::test]
async fn real_plaintext_roundtrip_preserves_f64_bits() {
    let space = fresh_space().await;
    let schema = SchemaBuilder::new("t")
        .column("id", ColumnType::Integer)
        .plaintext_primary_key()
        .column("v", ColumnType::Real)
        .unwrap()
        .plaintext()
        .build()
        .unwrap();
    space.create_table(&schema).await.unwrap();

    let row = serde_json::json!({ "id": Value::Null, "v": LOSSY_REAL });
    let id = space
        .table::<Value>("t")
        .insert(&row)
        .execute()
        .await
        .unwrap();

    let echoed = space
        .table::<Value>("t")
        .select()
        .where_eq("id", id)
        .first()
        .await
        .unwrap()
        .expect("row exists");

    let got = echoed
        .get("v")
        .and_then(|v| v.as_f64())
        .expect("v present and numeric");
    assert_eq!(
        LOSSY_REAL.to_bits(),
        got.to_bits(),
        "plaintext Real round-trip lossy: inserted={LOSSY_REAL} ({:016x}) got={got} ({:016x})",
        LOSSY_REAL.to_bits(),
        got.to_bits(),
    );
}

#[tokio::test]
async fn real_encrypted_roundtrip_preserves_f64_bits() {
    let space = fresh_space().await;
    let schema = SchemaBuilder::new("t")
        .column("id", ColumnType::Integer)
        .plaintext_primary_key()
        .column("v", ColumnType::Real)
        .unwrap()
        .encrypted()
        .build()
        .unwrap();
    space.create_table(&schema).await.unwrap();

    let row = serde_json::json!({ "id": Value::Null, "v": LOSSY_REAL });
    let id = space
        .table::<Value>("t")
        .insert(&row)
        .execute()
        .await
        .unwrap();

    let echoed = space
        .table::<Value>("t")
        .select()
        .where_eq("id", id)
        .first()
        .await
        .unwrap()
        .expect("row exists");

    let got = echoed
        .get("v")
        .and_then(|v| v.as_f64())
        .expect("v present and numeric");
    assert_eq!(
        LOSSY_REAL.to_bits(),
        got.to_bits(),
        "encrypted Real round-trip lossy: inserted={LOSSY_REAL} ({:016x}) got={got} ({:016x})",
        LOSSY_REAL.to_bits(),
        got.to_bits(),
    );
}

#[tokio::test]
async fn integer_plaintext_roundtrip_preserves_i64_typing() {
    let space = fresh_space().await;
    let schema = SchemaBuilder::new("t")
        .column("id", ColumnType::Integer)
        .plaintext_primary_key()
        .column("v", ColumnType::Integer)
        .unwrap()
        .plaintext()
        .build()
        .unwrap();
    space.create_table(&schema).await.unwrap();

    let original: i64 = 726303;
    let row = serde_json::json!({ "id": Value::Null, "v": original });
    let id = space
        .table::<Value>("t")
        .insert(&row)
        .execute()
        .await
        .unwrap();

    let echoed = space
        .table::<Value>("t")
        .select()
        .where_eq("id", id)
        .first()
        .await
        .unwrap()
        .expect("row exists");

    let v = echoed.get("v").expect("v present");
    let as_i = v.as_i64();
    assert!(
        as_i.is_some(),
        "plaintext Integer round-trip dropped i64 typing: value={v:?}",
    );
    assert_eq!(as_i, Some(original));
}

/// Finding #4: an Integer column inserted with a fresh integer value, then
/// read back through the join read path, must have `as_i64()` succeed.
#[tokio::test]
async fn integer_column_in_join_fk_preserves_i64_typing() {
    let space = fresh_space().await;
    let left = SchemaBuilder::new("l")
        .column("id", ColumnType::Integer)
        .plaintext_primary_key()
        .column("fk", ColumnType::Integer)
        .unwrap()
        .plaintext()
        .index()
        .build()
        .unwrap();
    let right = SchemaBuilder::new("r")
        .column("id", ColumnType::Integer)
        .plaintext_primary_key()
        .column("payload", ColumnType::String)
        .unwrap()
        .plaintext()
        .build()
        .unwrap();
    space.create_table(&left).await.unwrap();
    space.create_table(&right).await.unwrap();

    // One right row with id=1, one left row whose fk points to it.
    let r_id: i64 = space
        .table::<Value>("r")
        .insert(&serde_json::json!({"id": Value::Null, "payload": "p"}))
        .execute()
        .await
        .unwrap();
    assert_eq!(r_id, 1, "server assigns first row id=1");
    space
        .table::<Value>("l")
        .insert(&serde_json::json!({"id": Value::Null, "fk": r_id}))
        .execute()
        .await
        .unwrap();

    // Should return 1 joined row with no error.
    let rows = space
        .table::<Value>("l")
        .select()
        .join("r", "fk", "id")
        .all()
        .await
        .expect("join must not fail on Integer/Integer");
    assert_eq!(rows.len(), 1, "join should return one row");
}

#[tokio::test]
async fn integer_encrypted_roundtrip_preserves_i64_typing() {
    let space = fresh_space().await;
    let schema = SchemaBuilder::new("t")
        .column("id", ColumnType::Integer)
        .plaintext_primary_key()
        .column("v", ColumnType::Integer)
        .unwrap()
        .encrypted()
        .build()
        .unwrap();
    space.create_table(&schema).await.unwrap();

    let original: i64 = 726303;
    let row = serde_json::json!({ "id": Value::Null, "v": original });
    let id = space
        .table::<Value>("t")
        .insert(&row)
        .execute()
        .await
        .unwrap();

    let echoed = space
        .table::<Value>("t")
        .select()
        .where_eq("id", id)
        .first()
        .await
        .unwrap()
        .expect("row exists");

    let v = echoed.get("v").expect("v present");
    let as_i = v.as_i64();
    assert!(
        as_i.is_some(),
        "encrypted Integer round-trip dropped i64 typing: value={v:?}",
    );
    assert_eq!(as_i, Some(original));
}
