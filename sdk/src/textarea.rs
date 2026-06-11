use crate::list::{take_list_space_ctx, List, ListContext};
use crate::Space;
use encrypted_spaces_backend::error::{Result, SdkError};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::sync::{Arc, Mutex};

/// Maximum number of characters per chunk node.
pub const MAX_CHUNK_SIZE: usize = 16;

/// A chunk of text stored in a single list node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chunk {
    pub text: String,
}

/// A collaborative text document backed by a chunked positional list.
///
/// Use this type in your row structs for `ColumnType::List` columns where
/// the list items are text chunks. When deserialized via a table select,
/// the textarea is automatically hydrated and ready to use:
///
/// ```ignore
/// #[derive(Serialize, Deserialize)]
/// struct Document {
///     id: Option<i64>,
///     title: String,
///     body: TextArea,
/// }
///
/// let doc: Document = table.select().first().await?.unwrap();
/// doc.body.insert_string(0, "Hello world").await?;
/// ```
pub struct TextArea {
    list: List<Chunk>,
    /// Local view: ordered (key, chunk_text) pairs mirroring the server state.
    view: Mutex<Vec<(Vec<u8>, String)>>,
    /// Whether the local view has been populated from the server.
    initialized: Mutex<bool>,
}

impl std::fmt::Debug for TextArea {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TextArea")
            .field("list_number", &self.list.list_number())
            .field("hydrated", &self.list.is_hydrated())
            .finish()
    }
}

impl TextArea {
    /// Create an empty textarea reference (for use when inserting rows).
    pub fn empty() -> Self {
        Self {
            list: List::empty(),
            view: Mutex::new(Vec::new()),
            initialized: Mutex::new(false),
        }
    }

    /// Returns true if this textarea has been hydrated with a space context.
    pub fn is_hydrated(&self) -> bool {
        self.list.is_hydrated()
    }

    /// Get the list_number.
    pub fn list_number(&self) -> i64 {
        self.list.list_number()
    }

    /// Hydrate this textarea with a space context.
    pub(crate) fn hydrate(
        &mut self,
        space: Arc<Space>,
        table: String,
        row_id: i64,
        column: String,
    ) {
        self.list.hydrate(space, table, row_id, column);
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    fn total_chars(view: &[(Vec<u8>, String)]) -> usize {
        view.iter().map(|(_, t)| t.chars().count()).sum()
    }

    fn resolve_position(view: &[(Vec<u8>, String)], pos: usize) -> Result<(usize, usize)> {
        let mut remaining = pos;
        for (i, (_, text)) in view.iter().enumerate() {
            let chunk_len = text.chars().count();
            if remaining < chunk_len {
                return Ok((i, remaining));
            }
            remaining -= chunk_len;
        }
        if remaining == 0 {
            if view.is_empty() {
                return Ok((0, 0));
            }
            let last = view.len() - 1;
            return Ok((last, view[last].1.chars().count()));
        }
        Err(SdkError::NotFound)
    }

    fn split_text_into_chunks(text: &str) -> Vec<String> {
        let chars: Vec<char> = text.chars().collect();
        if chars.is_empty() {
            return vec![];
        }
        chars
            .chunks(MAX_CHUNK_SIZE)
            .map(|c| c.iter().collect())
            .collect()
    }

    fn char_offset_to_byte(text: &str, char_offset: usize) -> usize {
        text.char_indices()
            .nth(char_offset)
            .map(|(i, _)| i)
            .unwrap_or(text.len())
    }

    // ------------------------------------------------------------------
    // Sync
    // ------------------------------------------------------------------

    /// Re-fetch the full document from the server and rebuild the local view.
    pub async fn sync(&self) -> Result<()> {
        let entries = self.list.get_all().await?;
        let new_view: Vec<(Vec<u8>, String)> =
            entries.into_iter().map(|e| (e.key, e.value.text)).collect();
        *self.view.lock().unwrap() = new_view;
        *self.initialized.lock().unwrap() = true;
        Ok(())
    }

    async fn ensure_initialized(&self) -> Result<()> {
        if !*self.initialized.lock().unwrap() {
            self.sync().await?;
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Read operations
    // ------------------------------------------------------------------

    /// Number of characters in the document.
    pub async fn len(&self) -> Result<usize> {
        self.ensure_initialized().await?;
        Ok(Self::total_chars(&self.view.lock().unwrap()))
    }

    /// Whether the document is empty.
    pub async fn is_empty(&self) -> Result<bool> {
        Ok(self.len().await? == 0)
    }

    /// Materialise the full document as a `String`.
    pub async fn snapshot(&self) -> Result<String> {
        self.ensure_initialized().await?;
        Ok(self
            .view
            .lock()
            .unwrap()
            .iter()
            .map(|(_, t)| t.as_str())
            .collect())
    }

    /// Return the character at a given position.
    pub async fn char_at(&self, pos: usize) -> Result<char> {
        self.ensure_initialized().await?;
        let view = self.view.lock().unwrap();
        let total = Self::total_chars(&view);
        if pos >= total {
            return Err(SdkError::NotFound);
        }
        let (chunk_idx, offset) = Self::resolve_position(&view, pos)?;
        view[chunk_idx]
            .1
            .chars()
            .nth(offset)
            .ok_or(SdkError::NotFound)
    }

    /// Return a substring for the range `[start, end)`.
    pub async fn text_range(&self, start: usize, end: usize) -> Result<String> {
        self.ensure_initialized().await?;
        let view = self.view.lock().unwrap();
        let total = Self::total_chars(&view);
        if start > total || end > total || start > end {
            return Err(SdkError::NotFound);
        }
        let mut result = String::new();
        let mut char_pos = 0;
        for (_, text) in view.iter() {
            let chunk_len = text.chars().count();
            let chunk_end = char_pos + chunk_len;
            if chunk_end <= start {
                char_pos = chunk_end;
                continue;
            }
            if char_pos >= end {
                break;
            }
            let skip = start.saturating_sub(char_pos);
            let take = end.min(chunk_end) - start.max(char_pos);
            result.extend(text.chars().skip(skip).take(take));
            char_pos = chunk_end;
        }
        Ok(result)
    }

    // ------------------------------------------------------------------
    // Write operations
    // ------------------------------------------------------------------

    /// Insert a character before position `pos`.
    pub async fn insert(&self, pos: usize, ch: char) -> Result<()> {
        self.insert_string(pos, &ch.to_string()).await
    }

    /// Insert a string before position `pos`.
    pub async fn insert_string(&self, pos: usize, s: &str) -> Result<()> {
        if s.is_empty() {
            return Ok(());
        }
        self.ensure_initialized().await?;

        let (is_empty, total) = {
            let view = self.view.lock().unwrap();
            (view.is_empty(), Self::total_chars(&view))
        };
        if pos > total {
            return Err(SdkError::NotFound);
        }

        if is_empty {
            let chunks = Self::split_text_into_chunks(s);
            let first_key = self
                .list
                .append(&Chunk {
                    text: chunks[0].clone(),
                })
                .await?;
            let mut last_key = first_key.clone();
            let mut new_entries = vec![(first_key, chunks[0].clone())];
            for chunk_text in &chunks[1..] {
                let key = self
                    .list
                    .insert_after_key(
                        &last_key,
                        &Chunk {
                            text: chunk_text.clone(),
                        },
                    )
                    .await?;
                new_entries.push((key.clone(), chunk_text.clone()));
                last_key = key;
            }
            *self.view.lock().unwrap() = new_entries;
            return Ok(());
        }

        let (chunk_idx, offset) = {
            let view = self.view.lock().unwrap();
            Self::resolve_position(&view, pos)?
        };

        let (chunk_key, chunk_text) = {
            let view = self.view.lock().unwrap();
            view[chunk_idx].clone()
        };

        let byte_offset = Self::char_offset_to_byte(&chunk_text, offset);
        let mut new_text = chunk_text;
        new_text.insert_str(byte_offset, s);

        if new_text.chars().count() <= MAX_CHUNK_SIZE {
            self.list
                .update_by_key(
                    &chunk_key,
                    &Chunk {
                        text: new_text.clone(),
                    },
                )
                .await?;
            self.view.lock().unwrap()[chunk_idx].1 = new_text;
        } else {
            let chunks = Self::split_text_into_chunks(&new_text);
            self.list
                .update_by_key(
                    &chunk_key,
                    &Chunk {
                        text: chunks[0].clone(),
                    },
                )
                .await?;
            let mut last_key = chunk_key;
            let mut new_entries = Vec::new();
            for chunk_text in &chunks[1..] {
                let key = self
                    .list
                    .insert_after_key(
                        &last_key,
                        &Chunk {
                            text: chunk_text.clone(),
                        },
                    )
                    .await?;
                new_entries.push((key.clone(), chunk_text.clone()));
                last_key = key;
            }
            let mut view = self.view.lock().unwrap();
            view[chunk_idx].1 = chunks[0].clone();
            for (i, entry) in new_entries.into_iter().enumerate() {
                view.insert(chunk_idx + 1 + i, entry);
            }
        }

        Ok(())
    }

    /// Append a character at the end of the document.
    pub async fn append(&self, ch: char) -> Result<()> {
        self.ensure_initialized().await?;

        let (is_empty, last_idx, last_key, last_text) = {
            let view = self.view.lock().unwrap();
            if view.is_empty() {
                (true, 0, vec![], String::new())
            } else {
                let idx = view.len() - 1;
                let (key, text) = view[idx].clone();
                (false, idx, key, text)
            }
        };

        if is_empty {
            let chunk = Chunk {
                text: ch.to_string(),
            };
            let key = self.list.append(&chunk).await?;
            self.view.lock().unwrap().push((key, ch.to_string()));
            return Ok(());
        }

        let mut new_text = last_text;
        new_text.push(ch);

        if new_text.chars().count() <= MAX_CHUNK_SIZE {
            self.list
                .update_by_key(
                    &last_key,
                    &Chunk {
                        text: new_text.clone(),
                    },
                )
                .await?;
            self.view.lock().unwrap()[last_idx].1 = new_text;
        } else {
            let chars: Vec<char> = new_text.chars().collect();
            let first: String = chars[..MAX_CHUNK_SIZE].iter().collect();
            let second: String = chars[MAX_CHUNK_SIZE..].iter().collect();

            self.list
                .update_by_key(
                    &last_key,
                    &Chunk {
                        text: first.clone(),
                    },
                )
                .await?;
            let new_key = self
                .list
                .insert_after_key(
                    &last_key,
                    &Chunk {
                        text: second.clone(),
                    },
                )
                .await?;

            let mut view = self.view.lock().unwrap();
            view[last_idx].1 = first;
            view.push((new_key, second));
        }

        Ok(())
    }

    /// Append a string at the end of the document.
    pub async fn append_string(&self, s: &str) -> Result<()> {
        if s.is_empty() {
            return Ok(());
        }
        let len = self.len().await?;
        self.insert_string(len, s).await
    }

    /// Delete the character at position `pos`.
    pub async fn delete(&self, pos: usize) -> Result<()> {
        self.ensure_initialized().await?;

        let (chunk_idx, offset, chunk_key, chunk_text) = {
            let view = self.view.lock().unwrap();
            let total = Self::total_chars(&view);
            if pos >= total {
                return Err(SdkError::NotFound);
            }
            let (ci, off) = Self::resolve_position(&view, pos)?;
            let (key, text) = view[ci].clone();
            (ci, off, key, text)
        };

        let mut chars: Vec<char> = chunk_text.chars().collect();
        chars.remove(offset);

        if chars.is_empty() {
            self.list.delete_by_key(&chunk_key).await?;
            self.view.lock().unwrap().remove(chunk_idx);
        } else {
            let new_text: String = chars.into_iter().collect();
            self.list
                .update_by_key(
                    &chunk_key,
                    &Chunk {
                        text: new_text.clone(),
                    },
                )
                .await?;
            self.view.lock().unwrap()[chunk_idx].1 = new_text;
        }

        Ok(())
    }

    /// Delete characters in the range `[start, end)`.
    pub async fn delete_range(&self, start: usize, end: usize) -> Result<()> {
        self.ensure_initialized().await?;
        {
            let view = self.view.lock().unwrap();
            let total = Self::total_chars(&view);
            if start > total || end > total || start > end {
                return Err(SdkError::NotFound);
            }
        }
        if start == end {
            return Ok(());
        }

        let (start_chunk, start_offset, end_chunk, end_offset) = {
            let view = self.view.lock().unwrap();
            let (sc, so) = Self::resolve_position(&view, start)?;
            let (ec, eo_last) = Self::resolve_position(&view, end - 1)?;
            (sc, so, ec, eo_last + 1)
        };

        if start_chunk == end_chunk {
            let (key, text) = {
                let view = self.view.lock().unwrap();
                view[start_chunk].clone()
            };
            let chars: Vec<char> = text.chars().collect();
            let new_text: String = chars[..start_offset]
                .iter()
                .chain(chars[end_offset..].iter())
                .collect();

            if new_text.is_empty() {
                self.list.delete_by_key(&key).await?;
                self.view.lock().unwrap().remove(start_chunk);
            } else {
                self.list
                    .update_by_key(
                        &key,
                        &Chunk {
                            text: new_text.clone(),
                        },
                    )
                    .await?;
                self.view.lock().unwrap()[start_chunk].1 = new_text;
            }
        } else {
            // Multi-chunk delete: process end → intermediates → start
            let (end_key, end_text) = {
                let view = self.view.lock().unwrap();
                view[end_chunk].clone()
            };
            let end_remaining: String = end_text.chars().skip(end_offset).collect();
            if end_remaining.is_empty() {
                self.list.delete_by_key(&end_key).await?;
                self.view.lock().unwrap().remove(end_chunk);
            } else {
                self.list
                    .update_by_key(
                        &end_key,
                        &Chunk {
                            text: end_remaining.clone(),
                        },
                    )
                    .await?;
                self.view.lock().unwrap()[end_chunk].1 = end_remaining;
            }

            for idx in (start_chunk + 1..end_chunk).rev() {
                let key = self.view.lock().unwrap()[idx].0.clone();
                self.list.delete_by_key(&key).await?;
                self.view.lock().unwrap().remove(idx);
            }

            let (start_key, start_text) = {
                let view = self.view.lock().unwrap();
                view[start_chunk].clone()
            };
            let start_remaining: String = start_text.chars().take(start_offset).collect();
            if start_remaining.is_empty() {
                self.list.delete_by_key(&start_key).await?;
                self.view.lock().unwrap().remove(start_chunk);
            } else {
                self.list
                    .update_by_key(
                        &start_key,
                        &Chunk {
                            text: start_remaining.clone(),
                        },
                    )
                    .await?;
                self.view.lock().unwrap()[start_chunk].1 = start_remaining;
            }
        }

        Ok(())
    }

    /// Replace the character at position `pos` with `ch`.
    pub async fn replace(&self, pos: usize, ch: char) -> Result<()> {
        self.ensure_initialized().await?;

        let (chunk_idx, offset, chunk_key, chunk_text) = {
            let view = self.view.lock().unwrap();
            let total = Self::total_chars(&view);
            if pos >= total {
                return Err(SdkError::NotFound);
            }
            let (ci, off) = Self::resolve_position(&view, pos)?;
            let (key, text) = view[ci].clone();
            (ci, off, key, text)
        };

        let mut chars: Vec<char> = chunk_text.chars().collect();
        chars[offset] = ch;
        let new_text: String = chars.into_iter().collect();

        self.list
            .update_by_key(
                &chunk_key,
                &Chunk {
                    text: new_text.clone(),
                },
            )
            .await?;
        self.view.lock().unwrap()[chunk_idx].1 = new_text;
        Ok(())
    }
}

// -- Serialize / Deserialize ------------------------------------------------

impl Serialize for TextArea {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_i64(self.list.list_number())
    }
}

impl<'de> Deserialize<'de> for TextArea {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;

        match value {
            serde_json::Value::Number(ref n) => {
                let list_number = n
                    .as_i64()
                    .ok_or_else(|| serde::de::Error::custom("expected integer for TextArea"))?;
                Ok(TextArea {
                    list: List {
                        list_number,
                        ctx: None,
                        _phantom: std::marker::PhantomData,
                    },
                    view: Mutex::new(Vec::new()),
                    initialized: Mutex::new(false),
                })
            }
            serde_json::Value::Object(ref map) => {
                let list_number = map
                    .get("_li")
                    .and_then(|v| v.as_i64())
                    .ok_or_else(|| serde::de::Error::custom("missing _li in textarea object"))?;
                let table = map
                    .get("_lt")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| serde::de::Error::custom("missing _lt in textarea object"))?
                    .to_string();
                let row_id = map
                    .get("_lr")
                    .and_then(|v| v.as_i64())
                    .ok_or_else(|| serde::de::Error::custom("missing _lr in textarea object"))?;
                let column = map
                    .get("_lc")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| serde::de::Error::custom("missing _lc in textarea object"))?
                    .to_string();

                let ctx = take_list_space_ctx().map(|space| {
                    ListContext::with_known_list_number(space, table, row_id, column, list_number)
                });

                Ok(TextArea {
                    list: List {
                        list_number,
                        ctx,
                        _phantom: std::marker::PhantomData,
                    },
                    view: Mutex::new(Vec::new()),
                    initialized: Mutex::new(false),
                })
            }
            _ => Err(serde::de::Error::custom(
                "expected integer or object for TextArea",
            )),
        }
    }
}

#[cfg(all(test, feature = "local-transport"))]
mod tests {
    use super::*;
    use crate::local_transport::LocalTransport;
    use crate::schema::{ApplicationSchema, ColumnType, SchemaBuilder};
    use crate::Space;
    use encrypted_spaces_backend::error::Result;
    use encrypted_spaces_backend_server::SpaceState;
    use serde::{Deserialize, Serialize};

    const TABLE: &str = "test_table";
    const COL: &str = "doc";

    #[derive(Debug, Serialize, Deserialize)]
    struct Row {
        id: Option<i64>,
        name: String,
        doc: TextArea,
    }

    async fn create_textarea() -> Result<TextArea> {
        let schema = SchemaBuilder::new(TABLE)
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("name", ColumnType::String)?
            .column(COL, ColumnType::List)?
            .build()?;
        let transport = LocalTransport::new(
            std::slice::from_ref(&schema),
            None,
            Some(SpaceState::DEFAULT_FF_BATCH_SIZE),
        )
        .await?;
        let root = transport.get_root_hash().await?;
        let app_schema = ApplicationSchema::for_testing(vec![schema], root);
        let space = Space::create(transport, app_schema).await?;
        let row_id = space
            .table::<Row>(TABLE)
            .insert(&Row {
                id: None,
                name: "test".into(),
                doc: TextArea::empty(),
            })
            .execute()
            .await?;
        Ok(space.textarea(TABLE, row_id, COL))
    }

    #[tokio::test]
    async fn test_textarea_empty() -> Result<()> {
        let ta = create_textarea().await?;
        assert_eq!(ta.len().await?, 0);
        assert!(ta.is_empty().await?);
        assert_eq!(ta.snapshot().await?, "");
        Ok(())
    }

    #[tokio::test]
    async fn test_textarea_append_and_snapshot() -> Result<()> {
        let ta = create_textarea().await?;
        ta.append('H').await?;
        ta.append('i').await?;
        ta.append('!').await?;
        assert_eq!(ta.snapshot().await?, "Hi!");
        assert_eq!(ta.len().await?, 3);
        assert!(!ta.is_empty().await?);
        Ok(())
    }

    #[tokio::test]
    async fn test_textarea_append_string() -> Result<()> {
        let ta = create_textarea().await?;
        ta.append_string("Hello").await?;
        assert_eq!(ta.snapshot().await?, "Hello");
        assert_eq!(ta.len().await?, 5);
        Ok(())
    }

    #[tokio::test]
    async fn test_textarea_insert_middle() -> Result<()> {
        let ta = create_textarea().await?;
        ta.append_string("AC").await?;
        ta.insert(1, 'B').await?;
        assert_eq!(ta.snapshot().await?, "ABC");
        Ok(())
    }

    #[tokio::test]
    async fn test_textarea_insert_at_head_empty() -> Result<()> {
        let ta = create_textarea().await?;
        ta.insert(0, 'A').await?;
        assert_eq!(ta.snapshot().await?, "A");
        Ok(())
    }

    #[tokio::test]
    async fn test_textarea_insert_at_end() -> Result<()> {
        let ta = create_textarea().await?;
        ta.append_string("Hi").await?;
        ta.insert(2, '!').await?;
        assert_eq!(ta.snapshot().await?, "Hi!");
        Ok(())
    }

    #[tokio::test]
    async fn test_textarea_insert_string() -> Result<()> {
        let ta = create_textarea().await?;
        ta.append_string("AD").await?;
        ta.insert_string(1, "BC").await?;
        assert_eq!(ta.snapshot().await?, "ABCD");
        Ok(())
    }

    #[tokio::test]
    async fn test_textarea_char_at() -> Result<()> {
        let ta = create_textarea().await?;
        ta.append_string("XY").await?;
        assert_eq!(ta.char_at(0).await?, 'X');
        assert_eq!(ta.char_at(1).await?, 'Y');
        Ok(())
    }

    #[tokio::test]
    async fn test_textarea_text_range() -> Result<()> {
        let ta = create_textarea().await?;
        ta.append_string("Hello World").await?;
        assert_eq!(ta.text_range(0, 5).await?, "Hello");
        assert_eq!(ta.text_range(6, 11).await?, "World");
        assert_eq!(ta.text_range(5, 6).await?, " ");
        Ok(())
    }

    #[tokio::test]
    async fn test_textarea_delete() -> Result<()> {
        let ta = create_textarea().await?;
        ta.append_string("ABC").await?;
        ta.delete(1).await?;
        assert_eq!(ta.snapshot().await?, "AC");
        assert_eq!(ta.len().await?, 2);
        Ok(())
    }

    #[tokio::test]
    async fn test_textarea_delete_range() -> Result<()> {
        let ta = create_textarea().await?;
        ta.append_string("ABCDE").await?;
        ta.delete_range(1, 4).await?;
        assert_eq!(ta.snapshot().await?, "AE");
        Ok(())
    }

    #[tokio::test]
    async fn test_textarea_replace() -> Result<()> {
        let ta = create_textarea().await?;
        ta.append_string("ABC").await?;
        ta.replace(1, 'X').await?;
        assert_eq!(ta.snapshot().await?, "AXC");
        Ok(())
    }

    #[tokio::test]
    async fn test_textarea_unicode() -> Result<()> {
        let ta = create_textarea().await?;
        ta.append_string("Héllo 🌍").await?;
        assert_eq!(ta.snapshot().await?, "Héllo 🌍");
        assert_eq!(ta.len().await?, 7);
        Ok(())
    }

    #[tokio::test]
    async fn test_textarea_sync() -> Result<()> {
        let ta = create_textarea().await?;
        ta.append_string("Hello").await?;
        assert_eq!(ta.snapshot().await?, "Hello");
        ta.sync().await?;
        assert_eq!(ta.snapshot().await?, "Hello");
        assert_eq!(ta.len().await?, 5);
        Ok(())
    }

    #[tokio::test]
    async fn test_textarea_insert_on_empty() -> Result<()> {
        let ta = create_textarea().await?;
        ta.insert(0, 'A').await?;
        assert_eq!(ta.snapshot().await?, "A");
        Ok(())
    }

    #[tokio::test]
    async fn test_textarea_out_of_bounds() -> Result<()> {
        let ta = create_textarea().await?;
        ta.append_string("Hi").await?;
        assert!(ta.insert(5, 'X').await.is_err());
        assert!(ta.delete(5).await.is_err());
        assert!(ta.replace(5, 'X').await.is_err());
        assert!(ta.char_at(5).await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn test_textarea_head_insert_nonempty() -> Result<()> {
        let ta = create_textarea().await?;
        ta.append_string("ello").await?;
        ta.insert(0, 'H').await?;
        assert_eq!(ta.snapshot().await?, "Hello");
        Ok(())
    }

    #[tokio::test]
    async fn test_textarea_multiple_inserts() -> Result<()> {
        let ta = create_textarea().await?;
        ta.append_string("Hello").await?;
        ta.insert(2, 'X').await?;
        ta.insert(5, 'Y').await?;
        assert_eq!(ta.snapshot().await?, "HeXllYo");
        Ok(())
    }

    #[tokio::test]
    async fn test_textarea_chunk_splitting() -> Result<()> {
        let ta = create_textarea().await?;
        // MAX_CHUNK_SIZE is 16, so a string of 16 chars fits in one chunk
        ta.append_string("ABCDEFGHIJKLMNOP").await?;
        assert_eq!(ta.len().await?, 16);
        assert_eq!(ta.snapshot().await?, "ABCDEFGHIJKLMNOP");
        Ok(())
    }

    #[tokio::test]
    async fn test_textarea_insert_triggers_split() -> Result<()> {
        let ta = create_textarea().await?;
        ta.append_string("ABCDEFGHIJKLMNOP").await?;
        // Inserting into a full chunk should trigger a split
        ta.insert(8, 'X').await?;
        assert_eq!(ta.snapshot().await?, "ABCDEFGHXIJKLMNOP");
        assert_eq!(ta.len().await?, 17);
        Ok(())
    }

    #[tokio::test]
    async fn test_textarea_delete_across_chunks() -> Result<()> {
        let ta = create_textarea().await?;
        // Create content that spans multiple chunks
        ta.append_string("ABCDEFGHIJKLMNOPQRSTUVWX").await?;
        // Delete a range that crosses chunk boundary
        ta.delete_range(14, 18).await?;
        assert_eq!(ta.snapshot().await?, "ABCDEFGHIJKLMNSTUVWX");
        Ok(())
    }

    #[tokio::test]
    async fn test_textarea_delete_entire_document() -> Result<()> {
        let ta = create_textarea().await?;
        ta.append_string("Hello").await?;
        ta.delete_range(0, 5).await?;
        assert_eq!(ta.snapshot().await?, "");
        assert!(ta.is_empty().await?);
        Ok(())
    }

    #[tokio::test]
    async fn test_textarea_text_range_across_chunks() -> Result<()> {
        let ta = create_textarea().await?;
        ta.append_string("ABCDEFGHIJKLMNOPQRST").await?;
        // Range that spans the chunk boundary at 16
        let range = ta.text_range(14, 18).await?;
        assert_eq!(range, "OPQR");
        Ok(())
    }

    #[tokio::test]
    async fn test_textarea_replace_across_chunks() -> Result<()> {
        let ta = create_textarea().await?;
        ta.append_string("ABCDEFGHIJKLMNOPQRST").await?;
        // Replace in second chunk
        ta.replace(17, 'X').await?;
        let snap = ta.snapshot().await?;
        assert_eq!(snap.chars().nth(17).unwrap(), 'X');
        Ok(())
    }

    #[tokio::test]
    async fn test_textarea_large_string_insert() -> Result<()> {
        let ta = create_textarea().await?;
        // Insert a string larger than MAX_CHUNK_SIZE
        let long_str = "A".repeat(40);
        ta.insert_string(0, &long_str).await?;
        assert_eq!(ta.snapshot().await?, long_str);
        assert_eq!(ta.len().await?, 40);
        Ok(())
    }

    #[tokio::test]
    async fn test_textarea_append_fills_and_splits() -> Result<()> {
        let ta = create_textarea().await?;
        // Append characters one by one past MAX_CHUNK_SIZE
        for i in 0..20 {
            let ch = char::from(b'A' + (i % 26));
            ta.append(ch).await?;
        }
        assert_eq!(ta.len().await?, 20);
        let snap = ta.snapshot().await?;
        assert_eq!(snap.len(), 20);
        Ok(())
    }

    #[tokio::test]
    async fn test_textarea_delete_empties_chunk() -> Result<()> {
        let ta = create_textarea().await?;
        ta.append('A').await?;
        ta.delete(0).await?;
        assert!(ta.is_empty().await?);
        assert_eq!(ta.snapshot().await?, "");
        Ok(())
    }
}
