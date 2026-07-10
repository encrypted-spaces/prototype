//! Key-value store example — demonstrates the Store API: put/delete writes and
//! the `get()` read builder (key / prefix / range selectors, ascending /
//! descending order, and provable `limit` / `first` / `last`).
//!
//! A `store` is a namespaced, open key-value map: any space member can read,
//! write, overwrite, or delete any key. Values are encrypted client-side by
//! default. Keys and values are opaque bytes; this demo uses UTF-8 strings.
//!
//! Reads are backed by a tracer proof, so a limited read (`first`/`last`/
//! `limit`) proves and transfers only the keys it returns — not the whole store.
//!
//! Run with:
//!   cargo run --example key_value_store -p encrypted-spaces-sdk --features local-transport,testing

use encrypted_spaces_backend::app_schema::SchemaStore;
use encrypted_spaces_sdk::testing::initial_internal_data_commitment;
use encrypted_spaces_sdk::{ApplicationSchema, LocalTransport, Space};

/// Render a `(key, value)` pair as readable text.
fn show(pair: &(Vec<u8>, Vec<u8>)) -> String {
    format!(
        "{} = {}",
        String::from_utf8_lossy(&pair.0),
        String::from_utf8_lossy(&pair.1),
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Key-Value Store Demo");
    println!("====================");
    println!();

    let transport = LocalTransport::in_memory().await?;
    let dc = initial_internal_data_commitment();
    let space = Space::create(transport, ApplicationSchema::for_testing(vec![], dc)).await?;

    // Declare a store named "prefs" (values encrypted client-side by default).
    space
        .create_store(&SchemaStore {
            name: "prefs".to_string(),
            encrypted_values: true,
        })
        .await?;

    let store = space.store("prefs")?;

    // -----------------------
    // PUT & POINT READ
    // -----------------------
    println!("=== Put & point read ===");
    store.put("theme", b"dark".to_vec()).await?;
    println!("  put theme = dark");
    let theme = store.get().key("theme").first().await?;
    println!("  get key theme -> {:?}", theme.as_ref().map(show));
    println!();

    // -----------------------
    // OVERWRITE
    // -----------------------
    println!("=== Overwrite (latest value wins) ===");
    store.put("theme", b"light".to_vec()).await?;
    let theme = store.get().key("theme").first().await?;
    println!(
        "  put theme = light; get key theme -> {:?}",
        theme.as_ref().map(show)
    );
    println!();

    // -----------------------
    // MISSING KEY
    // -----------------------
    println!("=== Missing key ===");
    let absent = store.get().key("absent").first().await?;
    println!("  get key absent -> {absent:?}");
    println!();

    // -----------------------
    // PREFIX SCAN
    // -----------------------
    println!("=== Prefix scan ===");
    store.put("ui/theme", b"light".to_vec()).await?;
    store.put("ui/lang", b"en".to_vec()).await?;
    store.put("net/proxy", b"none".to_vec()).await?;
    println!("  put ui/theme, ui/lang, net/proxy");
    println!("  get prefix \"ui/\" all:");
    for pair in store.get().prefix("ui/").all().await? {
        println!("    {}", show(&pair));
    }
    println!();

    // -----------------------
    // RANGE + LIMIT (provable)
    // -----------------------
    println!("=== Range & limit ===");
    for k in ["a", "b", "c", "d", "e"] {
        store.put(k, format!("v-{k}").into_bytes()).await?;
    }
    println!("  put a, b, c, d, e");
    println!("  get range [a, d) all:");
    for pair in store.get().range("a", "d").all().await? {
        println!("    {}", show(&pair));
    }
    println!("  get range [a, e) limit 2 (proof covers only these two):");
    for pair in store.get().range("a", "e").limit(2).all().await? {
        println!("    {}", show(&pair));
    }
    println!();

    // -----------------------
    // FIRST / LAST
    // -----------------------
    println!("=== First & last ===");
    let first = store.get().range("a", "e").first().await?;
    let last = store.get().range("a", "e").last().await?;
    println!("  first key in [a, e) -> {:?}", first.as_ref().map(show));
    println!("  last key in  [a, e) -> {:?}", last.as_ref().map(show));
    println!();

    // -----------------------
    // DELETE
    // -----------------------
    println!("=== Delete ===");
    store.delete("theme").await?;
    let theme = store.get().key("theme").first().await?;
    println!("  delete theme; get key theme -> {theme:?}");
    println!();

    Ok(())
}
