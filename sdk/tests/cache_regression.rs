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

use cache_common::{setup_space, snapshot, was_cache_hit};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
struct Item {
    id: Option<i64>,
    category: i64,
    price: f64,
    name: String,
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
        })?
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
