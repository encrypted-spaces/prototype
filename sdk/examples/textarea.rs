/// TextArea example — demonstrates collaborative text editing with the
/// positional TextArea API.
///
/// TextArea is now a column type within tables. Each row with a List column
/// can be used as a TextArea for chunk-based text editing.
use encrypted_spaces_sdk::{ColumnType, LocalTransport, SchemaBuilder, Space, TextArea};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Document {
    id: Option<i64>,
    title: String,
    body: TextArea,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("TextArea Demo");
    println!("=============");
    println!();

    let space = Space::new(LocalTransport::in_memory().await?).await?;

    let schema = SchemaBuilder::new("documents")
        .column("id", ColumnType::Integer)
        .plaintext_primary_key()
        .column("title", ColumnType::String)?
        .column("body", ColumnType::List)?
        .build()?;
    space.create_table(&schema).await?;

    // Insert a document row — the List column is auto-initialized.
    let docs = space.table::<Document>("documents");
    let doc_id = docs
        .insert(&Document {
            id: None,
            title: "My Document".into(),
            body: TextArea::empty(),
        })
        .execute()
        .await?;

    // Get a hydrated textarea handle for the document's body column.
    let doc = space.textarea("documents", doc_id, "body");

    // --------------------------------------------------
    // 1. TYPE "Hello"
    // --------------------------------------------------
    println!("=== Type \"Hello\" ===");
    doc.append_string("Hello").await?;
    println!("  text: {:?}", doc.snapshot().await?);
    println!();

    // --------------------------------------------------
    // 2. INSERT " World" AFTER THE 'o'
    // --------------------------------------------------
    println!("=== Insert \" World\" at position 5 ===");
    doc.insert_string(5, " World").await?;
    println!("  text: {:?}", doc.snapshot().await?);
    println!();

    // --------------------------------------------------
    // 3. INSERT IN THE MIDDLE
    // --------------------------------------------------
    println!("=== Insert ',' after 'o' (position 5) ===");
    doc.insert(5, ',').await?;
    println!("  text: {:?}", doc.snapshot().await?);
    println!();

    // --------------------------------------------------
    // 4. REPLACE 'W' WITH 'w'
    // --------------------------------------------------
    println!("=== Replace 'W' with 'w' ===");
    doc.replace(7, 'w').await?;
    println!("  text: {:?}", doc.snapshot().await?);
    println!();

    // --------------------------------------------------
    // 5. DELETE A SINGLE CHARACTER (the comma)
    // --------------------------------------------------
    println!("=== Delete ',' ===");
    doc.delete(5).await?;
    println!("  text: {:?}", doc.snapshot().await?);
    println!();

    // --------------------------------------------------
    // 6. DELETE A RANGE (" world")
    // --------------------------------------------------
    println!("=== Delete range [5..11) — removes \" world\" ===");
    doc.delete_range(5, 11).await?;
    println!("  text: {:?}", doc.snapshot().await?);
    println!();

    // --------------------------------------------------
    // 7. READ OPERATIONS
    // --------------------------------------------------
    println!("=== Read operations ===");
    println!("  len:        {}", doc.len().await?);
    println!("  char_at(0): {:?}", doc.char_at(0).await?);
    println!("  range(0,3): {:?}", doc.text_range(0, 3).await?);
    println!();

    // --------------------------------------------------
    // 8. UNICODE
    // --------------------------------------------------
    println!("=== Append emoji ===");
    doc.append_string(" 🎉🌍").await?;
    println!("  text: {:?}", doc.snapshot().await?);
    println!("  len:  {}", doc.len().await?);
    println!();

    // --------------------------------------------------
    // 9. SYNC — re-fetch from server
    // --------------------------------------------------
    println!("=== Sync from server ===");
    doc.sync().await?;
    println!("  text: {:?}", doc.snapshot().await?);

    Ok(())
}
