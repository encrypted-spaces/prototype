//! Key-value store example — demonstrates the Store API (put/get/delete/list_prefix).
//!
//! A `store` is a namespaced, open key-value map: any space member can read,
//! write, overwrite, or delete any key. Values are encrypted client-side by
//! default. Keys and values are opaque bytes; this demo uses UTF-8 strings.
//!
//! Run with:
//!   cargo run --example key_value_store -p encrypted-spaces-sdk --features local-transport,testing

use encrypted_spaces_backend::app_schema::SchemaStore;
use encrypted_spaces_sdk::testing::initial_internal_data_commitment;
use encrypted_spaces_sdk::{ApplicationSchema, LocalTransport, Space};

/// Render an optional store value as readable text.
fn show(value: &Option<Vec<u8>>) -> String {
    match value {
        Some(bytes) => format!("Some({:?})", String::from_utf8_lossy(bytes)),
        None => "None".to_string(),
    }
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
    // PUT & GET
    // -----------------------
    println!("=== Put & get ===");
    store.put("theme", b"dark".to_vec()).await?;
    println!("  put theme = dark");
    println!("  get theme -> {}", show(&store.get("theme").await?));
    println!();

    // -----------------------
    // OVERWRITE
    // -----------------------
    println!("=== Overwrite (latest value wins) ===");
    store.put("theme", b"light".to_vec()).await?;
    println!("  put theme = light");
    println!("  get theme -> {}", show(&store.get("theme").await?));
    println!();

    // -----------------------
    // MISSING KEY
    // -----------------------
    println!("=== Missing key returns None ===");
    println!("  get absent -> {}", show(&store.get("absent").await?));
    println!();

    // -----------------------
    // PREFIX SCAN
    // -----------------------
    println!("=== Prefix scan (list_prefix) ===");
    store.put("ui/theme", b"light".to_vec()).await?;
    store.put("ui/lang", b"en".to_vec()).await?;
    store.put("net/proxy", b"none".to_vec()).await?;
    println!("  put ui/theme, ui/lang, net/proxy");
    println!("  list_prefix(\"ui/\") in key order:");
    for (key, value) in store.list_prefix("ui/").await? {
        println!(
            "    {} = {}",
            String::from_utf8_lossy(&key),
            String::from_utf8_lossy(&value),
        );
    }
    println!();

    // -----------------------
    // DELETE
    // -----------------------
    println!("=== Delete ===");
    store.delete("theme").await?;
    println!("  delete theme");
    println!("  get theme -> {}", show(&store.get("theme").await?));
    println!();

    Ok(())
}
