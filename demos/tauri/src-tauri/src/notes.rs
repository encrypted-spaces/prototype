use anyhow::Result;
use encrypted_spaces_sdk::TextArea;

pub async fn get_notes_text(doc: &TextArea) -> Result<String> {
    log::debug!("[notes] get_notes_text: syncing...");
    doc.sync().await?;
    let text = doc.snapshot().await?;
    log::debug!(
        "[notes] get_notes_text: len={} text={:?}",
        text.len(),
        &text[..text.len().min(80)]
    );
    Ok(text)
}

pub async fn notes_insert(doc: &TextArea, pos: usize, text: &str) -> Result<()> {
    let len = doc.len().await?;
    log::debug!(
        "[notes] notes_insert: pos={} text={:?} doc_len={}",
        pos,
        &text[..text.len().min(40)],
        len
    );
    if pos == len {
        doc.append_string(text).await?;
    } else {
        doc.insert_string(pos, text).await?;
    }
    log::debug!("[notes] notes_insert: done, new_len={}", doc.len().await?);
    Ok(())
}

pub async fn notes_delete(doc: &TextArea, pos: usize, count: usize) -> Result<()> {
    log::debug!(
        "[notes] notes_delete: pos={} count={} doc_len={}",
        pos,
        count,
        doc.len().await?
    );
    doc.delete_range(pos, pos + count).await?;
    log::debug!("[notes] notes_delete: done, new_len={}", doc.len().await?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use encrypted_spaces_sdk::{
        local_transport::LocalTransport,
        schema::{ApplicationSchema, ColumnType, SchemaBuilder},
        Space, TextArea,
    };
    use serde::{Deserialize, Serialize};

    const TABLE: &str = "test_table";
    const COL: &str = "notes";

    #[derive(Debug, Serialize, Deserialize)]
    struct Row {
        id: Option<i64>,
        name: String,
        notes: TextArea,
    }

    async fn create_textarea() -> anyhow::Result<TextArea> {
        let schema = SchemaBuilder::new(TABLE)
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("name", ColumnType::String)?
            .column(COL, ColumnType::List)?
            .build()?;
        let transport = LocalTransport::new(std::slice::from_ref(&schema), None, None).await?;
        let root = transport.get_root_hash().await?;
        let app_schema = ApplicationSchema::for_testing(vec![schema], root);
        let space = Space::create(transport, app_schema).await?;
        let row_id = space
            .table::<Row>(TABLE)
            .insert(&Row {
                id: None,
                name: "test".into(),
                notes: TextArea::empty(),
            })
            .execute()
            .await?;
        Ok(space.textarea(TABLE, row_id, COL))
    }

    #[tokio::test]
    async fn test_empty_notes() -> anyhow::Result<()> {
        let doc = create_textarea().await?;
        let text = get_notes_text(&doc).await?;
        assert_eq!(text, "");
        Ok(())
    }

    #[tokio::test]
    async fn test_insert_and_snapshot() -> anyhow::Result<()> {
        let doc = create_textarea().await?;
        notes_insert(&doc, 0, "Hello").await?;
        let text = get_notes_text(&doc).await?;
        assert_eq!(text, "Hello");
        Ok(())
    }

    #[tokio::test]
    async fn test_append_via_insert_at_end() -> anyhow::Result<()> {
        let doc = create_textarea().await?;
        notes_insert(&doc, 0, "Hello").await?;
        notes_insert(&doc, 5, " World").await?;
        let text = get_notes_text(&doc).await?;
        assert_eq!(text, "Hello World");
        Ok(())
    }

    #[tokio::test]
    async fn test_insert_middle() -> anyhow::Result<()> {
        let doc = create_textarea().await?;
        notes_insert(&doc, 0, "Hllo").await?;
        notes_insert(&doc, 1, "e").await?;
        let text = get_notes_text(&doc).await?;
        assert_eq!(text, "Hello");
        Ok(())
    }

    #[tokio::test]
    async fn test_delete() -> anyhow::Result<()> {
        let doc = create_textarea().await?;
        notes_insert(&doc, 0, "Hello World").await?;
        notes_delete(&doc, 5, 6).await?;
        let text = get_notes_text(&doc).await?;
        assert_eq!(text, "Hello");
        Ok(())
    }

    #[tokio::test]
    async fn test_insert_then_delete_then_insert() -> anyhow::Result<()> {
        let doc = create_textarea().await?;
        notes_insert(&doc, 0, "abc").await?;
        notes_delete(&doc, 1, 1).await?;
        let text = get_notes_text(&doc).await?;
        assert_eq!(text, "ac");
        notes_insert(&doc, 1, "B").await?;
        let text = get_notes_text(&doc).await?;
        assert_eq!(text, "aBc");
        Ok(())
    }
}
