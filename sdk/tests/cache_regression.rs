//! Black-box cache hit/miss regression tests.
//!
//! Uses [`cache_common::CountingTransport`] to count select calls. The
//! pattern is `let before = snapshot(&t); query(); assert!(was_cache_hit(before, &t));`
//! — a hit means the second query was served from the local KV cache
//! without a transport round-trip.
//!
//! Curated minimal coverage of the shapes Trevor's full
//! `cache_regression.rs` exercises: full-table reread, eq/limit/join,
//! insert/update/delete then reread, indexed predicate, full-table
//! fallback. Property tests and exhaustive operator coverage live in
//! the cache crate's unit tests.

#![cfg(feature = "local-transport")]

mod cache_common;

use cache_common::{setup_space, setup_two_actors, snapshot, was_cache_hit};
use encrypted_spaces_sdk::QueryParam;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Deserialize, Serialize)]
struct Item {
    id: Option<i64>,
    category: i64,
    price: f64,
    name: String,
    secret: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Tag {
    id: Option<i64>,
    item_id: i64,
    label: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ItemWithTag {
    name: String,
    label: String,
}

#[tokio::test]
async fn full_table_reread_hits() -> Result<(), Box<dyn std::error::Error>> {
    let (space, transport) = setup_space(5).await?;
    let items = space.table::<Item>("items");
    // Prime
    let _: Vec<Item> = items.select().all().await?;
    let before = snapshot(&transport);
    // Reread — must hit
    let rows: Vec<Item> = items.select().all().await?;
    assert_eq!(rows.len(), 5);
    assert!(
        was_cache_hit(before, &transport),
        "second full-table read should hit"
    );
    Ok(())
}

#[tokio::test]
async fn eq_predicate_reread_hits() -> Result<(), Box<dyn std::error::Error>> {
    let (space, transport) = setup_space(5).await?;
    let items = space.table::<Item>("items");
    let _: Vec<Item> = items.select().where_eq("category", 1).all().await?;
    let before = snapshot(&transport);
    let rows: Vec<Item> = items.select().where_eq("category", 1).all().await?;
    assert!(rows.iter().all(|r| r.category == 1));
    assert!(
        was_cache_hit(before, &transport),
        "indexed eq reread should hit"
    );
    Ok(())
}

#[tokio::test]
async fn id_reread_after_insert_hits() -> Result<(), Box<dyn std::error::Error>> {
    // The bug-3 / full-row-coverage regression: an insert must extend
    // coverage of the row so a subsequent id-read hits.
    let (space, transport) = setup_space(0).await?;
    let items = space.table::<Item>("items");
    let id = items
        .insert(&Item {
            id: None,
            category: 1,
            price: 2.5,
            name: "fresh".into(),
            secret: Some("s".into()),
        })
        .execute()
        .await?;
    let before = snapshot(&transport);
    let rows: Vec<Item> = items.select().where_eq("id", id).all().await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].name, "fresh");
    assert!(
        was_cache_hit(before, &transport),
        "id read of a freshly inserted row should hit the cache"
    );
    Ok(())
}

#[tokio::test]
async fn limit_reread_hits_on_partial_coverage() -> Result<(), Box<dyn std::error::Error>> {
    let (space, transport) = setup_space(10).await?;
    let items = space.table::<Item>("items");
    // Prime with a full-table scan so the cache covers everything.
    let _: Vec<Item> = items.select().all().await?;
    let before = snapshot(&transport);
    let rows: Vec<Item> = items.select().limit(3).all().await?;
    assert_eq!(rows.len(), 3);
    assert!(
        was_cache_hit(before, &transport),
        "limit reread on covered table should hit"
    );
    Ok(())
}

#[tokio::test]
async fn pk_join_reread_hits() -> Result<(), Box<dyn std::error::Error>> {
    let (space, transport) = setup_space(5).await?;
    let tags = space.table::<Tag>("tags");
    let _: Vec<ItemWithTag> = tags
        .select()
        .columns(&["tags.label", "items.name"])
        .join("items", "item_id", "id")
        .all_as()
        .await?;
    let before = snapshot(&transport);
    let rows: Vec<ItemWithTag> = tags
        .select()
        .columns(&["tags.label", "items.name"])
        .join("items", "item_id", "id")
        .all_as()
        .await?;
    assert_eq!(rows.len(), 10);
    assert!(
        was_cache_hit(before, &transport),
        "PK join reread should hit"
    );
    Ok(())
}

#[tokio::test]
async fn update_then_id_read_hits() -> Result<(), Box<dyn std::error::Error>> {
    // Update is a full-column-spec replacement so it extends row coverage;
    // the post-update id read should hit.
    let (space, transport) = setup_space(3).await?;
    let items = space.table::<Item>("items");
    items
        .update()
        .set("category", 9)
        .set("price", 100.0)
        .set("name", "updated")
        .where_eq("id", 1)
        .execute()
        .await?;
    let before = snapshot(&transport);
    let rows: Vec<Item> = items.select().where_eq("id", 1).all().await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].name, "updated");
    assert_eq!(rows[0].category, 9);
    assert!(
        was_cache_hit(before, &transport),
        "id read after a full-row update should hit"
    );
    Ok(())
}

#[tokio::test]
async fn delete_then_full_table_reread_hits() -> Result<(), Box<dyn std::error::Error>> {
    // A full-row delete extends coverage just like a full-row insert.
    // After the delete, a subsequent full-table read must hit and the
    // deleted row must be gone from the result.
    let (space, transport) = setup_space(5).await?;
    let items = space.table::<Item>("items");
    // Prime full-table coverage.
    let _: Vec<Item> = items.select().all().await?;
    items.delete().where_eq("id", 3).execute().await?;

    let before = snapshot(&transport);
    let rows: Vec<Item> = items.select().all().await?;
    assert_eq!(rows.len(), 4);
    assert!(rows.iter().all(|r| r.id != Some(3)));
    assert!(
        was_cache_hit(before, &transport),
        "full-table read after a full-row delete should hit"
    );

    // And the id read of the deleted row must be an authenticated absence
    // (cache hit returning zero rows) since the row range stays covered.
    let before = snapshot(&transport);
    let rows: Vec<Item> = items.select().where_eq("id", 3).all().await?;
    assert!(rows.is_empty());
    assert!(
        was_cache_hit(before, &transport),
        "id read of a deleted row must hit (authenticated absence)"
    );
    Ok(())
}

#[tokio::test]
async fn indexed_range_reread_hits() -> Result<(), Box<dyn std::error::Error>> {
    // category is indexed. Prime a between scan, then reread — must hit.
    let (space, transport) = setup_space(10).await?;
    let items = space.table::<Item>("items");
    let _: Vec<Item> = items.select().where_between("category", 2, 4).all().await?;
    let before = snapshot(&transport);
    let rows: Vec<Item> = items.select().where_between("category", 2, 4).all().await?;
    assert!(rows.iter().all(|r| (2..=4).contains(&r.category)));
    assert!(
        was_cache_hit(before, &transport),
        "indexed Between reread should hit"
    );
    Ok(())
}

#[tokio::test]
async fn full_table_fallback_hits_on_non_indexed_predicate(
) -> Result<(), Box<dyn std::error::Error>> {
    // `name` is not indexed in items_schema. With the full table primed,
    // a where_eq on `name` must serve from cache via the fallback path.
    let (space, transport) = setup_space(5).await?;
    let items = space.table::<Item>("items");
    let _: Vec<Item> = items.select().all().await?;
    let before = snapshot(&transport);
    let rows: Vec<Item> = items
        .select()
        .filter("name", |v| v.as_str() == Some("item_3"))
        .all()
        .await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].name, "item_3");
    assert!(
        was_cache_hit(before, &transport),
        "non-indexed filter on a fully-cached table should hit"
    );
    Ok(())
}

// ---------- Tests ported from trev/kvcache2 ----------

fn row_id(row: &Value) -> i64 {
    row.get("id").and_then(Value::as_i64).expect("row id")
}

fn sorted_ids(rows: &[Value]) -> Vec<i64> {
    let mut ids: Vec<i64> = rows.iter().map(row_id).collect();
    ids.sort();
    ids
}

fn has_name(rows: &[Value], name: &str) -> bool {
    rows.iter()
        .any(|row| row.get("name").and_then(Value::as_str) == Some(name))
}

#[tokio::test]
async fn gt_after_full_table_prime() -> Result<(), Box<dyn std::error::Error>> {
    let (space, transport) = setup_space(50).await?;
    let items = space.table::<Value>("items");
    assert_eq!(items.select().all().await?.len(), 50);

    let before = snapshot(&transport);
    let rows = items.select().where_gt("category", 2).all().await?;
    assert!(was_cache_hit(before, &transport));
    assert!(!rows.is_empty());
    assert!(rows
        .iter()
        .all(|row| row.get("category").and_then(Value::as_i64).unwrap() > 2));

    Ok(())
}

#[tokio::test]
async fn gte_reread() -> Result<(), Box<dyn std::error::Error>> {
    let (space, transport) = setup_space(50).await?;
    let items = space.table::<Value>("items");

    let rows1 = items.select().where_gte("price", 10.0).all().await?;
    assert!(!rows1.is_empty());

    let before = snapshot(&transport);
    let rows2 = items.select().where_gte("price", 10.0).all().await?;
    assert!(was_cache_hit(before, &transport));
    assert_eq!(sorted_ids(&rows1), sorted_ids(&rows2));

    Ok(())
}

#[tokio::test]
async fn lt_reread() -> Result<(), Box<dyn std::error::Error>> {
    let (space, transport) = setup_space(50).await?;
    let items = space.table::<Value>("items");

    let rows1 = items.select().where_lt("category", 3).all().await?;
    assert!(!rows1.is_empty());

    let before = snapshot(&transport);
    let rows2 = items.select().where_lt("category", 3).all().await?;
    assert!(was_cache_hit(before, &transport));
    assert_eq!(sorted_ids(&rows1), sorted_ids(&rows2));

    Ok(())
}

#[tokio::test]
async fn between_reread() -> Result<(), Box<dyn std::error::Error>> {
    let (space, transport) = setup_space(50).await?;
    let items = space.table::<Value>("items");

    let rows1 = items
        .select()
        .where_between("price", 5.0, 20.0)
        .all()
        .await?;
    assert!(!rows1.is_empty());

    let before = snapshot(&transport);
    let rows2 = items
        .select()
        .where_between("price", 5.0, 20.0)
        .all()
        .await?;
    assert!(was_cache_hit(before, &transport));
    assert_eq!(sorted_ids(&rows1), sorted_ids(&rows2));

    Ok(())
}

#[tokio::test]
async fn range_after_eq_prime_misses() -> Result<(), Box<dyn std::error::Error>> {
    let (space, transport) = setup_space(50).await?;
    let items = space.table::<Value>("items");

    let _eq_rows = items.select().where_eq("category", 2).all().await?;

    let before = snapshot(&transport);
    let rows = items.select().where_gt("category", 1).all().await?;
    assert!(!was_cache_hit(before, &transport));
    assert!(!rows.is_empty());

    Ok(())
}

#[tokio::test]
async fn in_predicate_reread() -> Result<(), Box<dyn std::error::Error>> {
    let (space, transport) = setup_space(50).await?;
    let items = space.table::<Value>("items");
    let categories = &[QueryParam::Integer(1), QueryParam::Integer(3)];

    let rows1 = items
        .select()
        .where_in("category", categories)
        .all()
        .await?;
    assert!(!rows1.is_empty());

    let before = snapshot(&transport);
    let rows2 = items
        .select()
        .where_in("category", categories)
        .all()
        .await?;
    assert!(was_cache_hit(before, &transport));
    assert_eq!(sorted_ids(&rows1), sorted_ids(&rows2));

    Ok(())
}

#[tokio::test]
async fn in_subset_after_full_prime() -> Result<(), Box<dyn std::error::Error>> {
    let (space, transport) = setup_space(50).await?;
    let items = space.table::<Value>("items");

    let all_rows = items.select().all().await?;
    assert_eq!(all_rows.len(), 50);
    let id1 = row_id(&all_rows[0]);
    let id2 = row_id(&all_rows[1]);

    let before = snapshot(&transport);
    let rows = items
        .select()
        .where_in("id", &[QueryParam::Integer(id1), QueryParam::Integer(id2)])
        .all()
        .await?;
    assert!(was_cache_hit(before, &transport));
    assert_eq!(rows.len(), 2);

    Ok(())
}

#[tokio::test]
async fn first_reread() -> Result<(), Box<dyn std::error::Error>> {
    let (space, transport) = setup_space(50).await?;
    let items = space.table::<Value>("items");

    let row1 = items.select().first().await?.expect("row");
    let before = snapshot(&transport);
    let row2 = items.select().first().await?.expect("cached row");
    assert!(was_cache_hit(before, &transport));
    assert_eq!(row2, row1);

    Ok(())
}

#[tokio::test]
async fn ascending_limit_after_full_prime() -> Result<(), Box<dyn std::error::Error>> {
    let (space, transport) = setup_space(50).await?;
    let items = space.table::<Value>("items");
    assert_eq!(items.select().all().await?.len(), 50);

    let before = snapshot(&transport);
    let rows = items.select().ascending().limit(3).all().await?;
    assert!(was_cache_hit(before, &transport));
    assert_eq!(rows.len(), 3);
    assert!(rows
        .windows(2)
        .all(|pair| row_id(&pair[0]) <= row_id(&pair[1])));

    Ok(())
}

#[tokio::test]
async fn join_after_main_table_prime() -> Result<(), Box<dyn std::error::Error>> {
    let (space, transport) = setup_space(50).await?;
    let items = space.table::<Value>("items");
    assert_eq!(items.select().all().await?.len(), 50);

    let before = snapshot(&transport);
    let rows = items.select().join("tags", "id", "item_id").all().await?;
    assert!(!was_cache_hit(before, &transport));
    assert!(!rows.is_empty());

    Ok(())
}

#[tokio::test]
async fn insert_then_full_table_reread() -> Result<(), Box<dyn std::error::Error>> {
    let (space, transport) = setup_space(50).await?;
    let items = space.table::<Value>("items");

    let _rows1 = items.select().all().await?;
    items
        .insert(&serde_json::json!({
            "id": Value::Null,
            "category": 1i64,
            "price": 99.0,
            "name": "new",
            "secret": "s",
        }))
        .execute()
        .await?;

    let before = snapshot(&transport);
    let rows2 = items.select().all().await?;
    assert!(was_cache_hit(before, &transport));
    assert_eq!(rows2.len(), 51);
    assert!(has_name(&rows2, "new"));

    Ok(())
}

#[tokio::test]
async fn update_then_full_table_reread() -> Result<(), Box<dyn std::error::Error>> {
    let (space, transport) = setup_space(50).await?;
    let items = space.table::<Value>("items");

    assert_eq!(items.select().all().await?.len(), 50);
    let id = row_id(&items.select().first().await?.expect("row"));
    items
        .update()
        .set("name", "updated")
        .where_eq("id", id)
        .execute()
        .await?;

    let before = snapshot(&transport);
    let rows = items.select().all().await?;
    assert!(was_cache_hit(before, &transport));
    assert_eq!(rows.len(), 50);
    let updated = rows
        .iter()
        .find(|row| row_id(row) == id)
        .expect("updated row");
    assert_eq!(updated.get("name").and_then(Value::as_str), Some("updated"));

    Ok(())
}

#[tokio::test]
async fn delete_then_reread() -> Result<(), Box<dyn std::error::Error>> {
    let (space, transport) = setup_space(50).await?;
    let items = space.table::<Value>("items");

    assert_eq!(items.select().all().await?.len(), 50);
    let id = row_id(&items.select().first().await?.expect("row"));
    items.delete().where_eq("id", id).execute().await?;

    let before = snapshot(&transport);
    let rows = items.select().all().await?;
    assert!(was_cache_hit(before, &transport));
    assert_eq!(rows.len(), 49);
    assert!(!rows.iter().any(|row| row_id(row) == id));

    Ok(())
}

#[tokio::test]
async fn eq_after_full_table_prime() -> Result<(), Box<dyn std::error::Error>> {
    let (space, transport) = setup_space(50).await?;
    let items = space.table::<Value>("items");
    assert_eq!(items.select().all().await?.len(), 50);

    let before = snapshot(&transport);
    let rows = items.select().where_eq("category", 2).all().await?;
    assert!(was_cache_hit(before, &transport));
    assert!(!rows.is_empty());
    assert!(rows
        .iter()
        .all(|row| row.get("category").and_then(Value::as_i64) == Some(2)));

    Ok(())
}

#[tokio::test]
async fn full_table_after_eq_prime_misses() -> Result<(), Box<dyn std::error::Error>> {
    let (space, transport) = setup_space(50).await?;
    let items = space.table::<Value>("items");
    assert!(!items
        .select()
        .where_eq("category", 1)
        .all()
        .await?
        .is_empty());

    let before = snapshot(&transport);
    let rows = items.select().all().await?;
    assert!(!was_cache_hit(before, &transport));
    assert_eq!(rows.len(), 50);

    Ok(())
}

#[tokio::test]
async fn different_eq_after_eq_prime_misses() -> Result<(), Box<dyn std::error::Error>> {
    let (space, transport) = setup_space(50).await?;
    let items = space.table::<Value>("items");
    assert!(!items
        .select()
        .where_eq("category", 1)
        .all()
        .await?
        .is_empty());

    let before = snapshot(&transport);
    let rows = items.select().where_eq("category", 2).all().await?;
    assert!(!was_cache_hit(before, &transport));
    assert!(!rows.is_empty());

    Ok(())
}

#[tokio::test]
async fn overlapping_range_queries() -> Result<(), Box<dyn std::error::Error>> {
    let (space, transport) = setup_space(50).await?;
    let items = space.table::<Value>("items");

    let _rows1 = items.select().where_gte("price", 5.0).all().await?;

    let before = snapshot(&transport);
    let rows2 = items.select().where_gte("price", 10.0).all().await?;
    assert!(was_cache_hit(before, &transport));
    assert!(!rows2.is_empty());
    assert!(rows2
        .iter()
        .all(|row| row.get("price").and_then(Value::as_f64).unwrap() >= 10.0));

    Ok(())
}

#[tokio::test]
async fn encrypted_column_reread() -> Result<(), Box<dyn std::error::Error>> {
    let (space, transport) = setup_space(50).await?;
    let items = space.table::<Value>("items");

    let rows1 = items.select().columns(&["name", "secret"]).all().await?;
    assert_eq!(rows1.len(), 50);
    for row in &rows1 {
        let name = row.get("name").and_then(Value::as_str).expect("name");
        let suffix = name.strip_prefix("item_").expect("item suffix");
        let expected = format!("secret_{suffix}");
        assert_eq!(
            row.get("secret").and_then(Value::as_str),
            Some(expected.as_str())
        );
    }

    let before = snapshot(&transport);
    let rows2 = items.select().columns(&["name", "secret"]).all().await?;
    assert!(was_cache_hit(before, &transport));
    assert_eq!(rows2, rows1);

    Ok(())
}

#[tokio::test]
async fn remote_insert_ff_recovery() -> Result<(), Box<dyn std::error::Error>> {
    let (alice_space, bob_space, transport) = setup_two_actors(50).await?;
    let alice_items = alice_space.table::<Value>("items");
    let bob_items = bob_space.table::<Value>("items");

    alice_items
        .insert(&serde_json::json!({
            "id": Value::Null,
            "category": 1i64,
            "price": 999.0,
            "name": "alice_new",
            "secret": "alice_secret",
        }))
        .execute()
        .await?;

    let bob_rows1 = bob_items.select().all().await?;
    assert_eq!(bob_rows1.len(), 51);

    let before = snapshot(&transport);
    let bob_rows2 = bob_items.select().all().await?;
    assert!(was_cache_hit(before, &transport));
    assert_eq!(bob_rows2.len(), 51);

    Ok(())
}

#[tokio::test]
async fn cache_cleared_on_ff() -> Result<(), Box<dyn std::error::Error>> {
    let (alice_space, bob_space, transport) = setup_two_actors(50).await?;
    let alice_items = alice_space.table::<Value>("items");
    let bob_items = bob_space.table::<Value>("items");

    alice_items
        .insert(&serde_json::json!({
            "id": Value::Null,
            "category": 2i64,
            "price": 888.0,
            "name": "alice_first",
            "secret": "s1",
        }))
        .execute()
        .await?;
    assert_eq!(bob_items.select().all().await?.len(), 51);

    alice_items
        .insert(&serde_json::json!({
            "id": Value::Null,
            "category": 3i64,
            "price": 777.0,
            "name": "alice_second",
            "secret": "s2",
        }))
        .execute()
        .await?;

    bob_space.sync().await?;
    let before = snapshot(&transport);
    let bob_rows2 = bob_items.select().all().await?;
    assert!(!was_cache_hit(before, &transport));
    assert_eq!(bob_rows2.len(), 52);
    assert!(has_name(&bob_rows2, "alice_second"));

    Ok(())
}

#[tokio::test]
async fn empty_table_reread() -> Result<(), Box<dyn std::error::Error>> {
    let (space, transport) = setup_space(0).await?;
    let items = space.table::<Value>("items");

    let rows1 = items.select().all().await?;
    assert!(rows1.is_empty());

    let before = snapshot(&transport);
    let rows2 = items.select().all().await?;
    assert!(was_cache_hit(before, &transport));
    assert!(rows2.is_empty());

    Ok(())
}

#[tokio::test]
async fn single_row_predicates() -> Result<(), Box<dyn std::error::Error>> {
    let (space, _transport) = setup_space(1).await?;
    let items = space.table::<Value>("items");

    let row = items.select().first().await?.expect("row");
    let category = row
        .get("category")
        .and_then(Value::as_i64)
        .expect("category");
    assert_eq!(
        items
            .select()
            .where_eq("category", category)
            .all()
            .await?
            .len(),
        1
    );
    assert_eq!(
        items
            .select()
            .where_gt("category", category)
            .all()
            .await?
            .len(),
        0
    );

    Ok(())
}

#[tokio::test]
async fn real_index_integer_normalization() -> Result<(), Box<dyn std::error::Error>> {
    let (space, transport) = setup_space(0).await?;
    let items = space.table::<Value>("items");

    items
        .insert(&serde_json::json!({
            "id": Value::Null,
            "category": 1i64,
            "price": 10.0,
            "name": "ten_price",
            "secret": "secret_ten",
        }))
        .execute()
        .await?;

    let results = items
        .select()
        .where_eq("price", QueryParam::Integer(10))
        .all()
        .await?;
    assert_eq!(results.len(), 1);

    let before = snapshot(&transport);
    let results2 = items
        .select()
        .where_eq("price", QueryParam::Integer(10))
        .all()
        .await?;
    assert!(was_cache_hit(before, &transport));
    assert_eq!(results2.len(), 1);

    Ok(())
}

#[tokio::test]
async fn large_result_set() -> Result<(), Box<dyn std::error::Error>> {
    let (space, transport) = setup_space(500).await?;
    let items = space.table::<Value>("items");

    assert_eq!(items.select().all().await?.len(), 500);
    let before = snapshot(&transport);
    let rows2 = items.select().all().await?;
    assert!(was_cache_hit(before, &transport));
    assert_eq!(rows2.len(), 500);

    Ok(())
}

#[tokio::test]
async fn null_value_handling() -> Result<(), Box<dyn std::error::Error>> {
    let (space, _transport) = setup_space(0).await?;
    let items = space.table::<Value>("items");

    items
        .insert(&serde_json::json!({
            "id": Value::Null,
            "category": 7i64,
            "price": 1.0,
            "name": Value::Null,
            "secret": Value::Null,
        }))
        .execute()
        .await?;

    let results = items.select().where_eq("category", 7).all().await?;
    assert_eq!(results.len(), 1);
    assert!(results[0].get("name").unwrap().is_null());

    Ok(())
}

#[tokio::test]
async fn full_table_prime_then_index_eq_hits() -> Result<(), Box<dyn std::error::Error>> {
    let (space, transport) = setup_space(50).await?;
    let items = space.table::<Value>("items");

    let all_rows = items.select().all().await?;
    assert_eq!(all_rows.len(), 50);

    let before = snapshot(&transport);
    let rows = items.select().where_eq("category", 2).all().await?;
    assert!(was_cache_hit(before, &transport));
    let expected: Vec<Value> = all_rows
        .into_iter()
        .filter(|row| row.get("category").and_then(Value::as_i64) == Some(2))
        .collect();
    assert_eq!(sorted_ids(&rows), sorted_ids(&expected));

    Ok(())
}

#[tokio::test]
async fn full_table_prime_then_index_range_hits() -> Result<(), Box<dyn std::error::Error>> {
    let (space, transport) = setup_space(50).await?;
    let items = space.table::<Value>("items");

    let all_rows = items.select().all().await?;
    assert_eq!(all_rows.len(), 50);

    let before = snapshot(&transport);
    let rows = items.select().where_gt("category", 2).all().await?;
    assert!(was_cache_hit(before, &transport));
    let expected: Vec<Value> = all_rows
        .into_iter()
        .filter(|row| row.get("category").and_then(Value::as_i64).unwrap() > 2)
        .collect();
    assert_eq!(sorted_ids(&rows), sorted_ids(&expected));

    Ok(())
}

#[tokio::test]
async fn full_table_prime_insert_then_predicate_hits() -> Result<(), Box<dyn std::error::Error>> {
    let (space, transport) = setup_space(10).await?;
    let items = space.table::<Value>("items");

    let _all_rows = items.select().all().await?;

    items
        .insert(&serde_json::json!({
            "id": Value::Null,
            "category": 2i64,
            "price": 42.0,
            "name": "inserted_match",
            "secret": "s_inserted",
        }))
        .execute()
        .await?;

    let before = snapshot(&transport);
    let rows = items.select().where_eq("category", 2).all().await?;
    assert!(was_cache_hit(before, &transport));
    assert!(rows
        .iter()
        .all(|row| row.get("category").and_then(Value::as_i64) == Some(2)));
    assert!(has_name(&rows, "inserted_match"));

    Ok(())
}

#[tokio::test]
#[should_panic(expected = "must be the primary key or an indexed column")]
async fn non_indexed_server_predicate_still_invalid() {
    let (space, _transport) = setup_space(10).await.expect("setup");
    let items = space.table::<Value>("items");

    items.select().all().await.expect("prime");
    items
        .select()
        .where_eq("name", "item_1")
        .all()
        .await
        .expect("non-indexed predicate should fail");
}
