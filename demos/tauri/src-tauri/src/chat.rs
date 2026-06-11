use anyhow::Result;
use encrypted_spaces_sdk::{File, List, Space, TextArea};
use serde::{Deserialize, Serialize};

pub use crate::sdk_codegen::Actions;

#[derive(Debug, Serialize, Deserialize)]
pub struct Channel {
    pub id: Option<i64>,
    pub name: String,
    pub description: Option<String>,
    pub tasks: List<crate::tasks::Task>,
    pub notes: TextArea,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Message {
    pub id: Option<i64>,
    pub channel_id: i64,
    pub user_id: i64,
    pub content: String,
    pub timestamp: i64,
    pub thread_id: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Reaction {
    pub id: Option<i64>,
    pub channel_id: i64,
    pub message_id: i64,
    pub user_id: i64,
    pub emoji: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UsersMeta {
    pub id: Option<i64>,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MessageWithUser {
    pub id: Option<i64>,
    pub content: String,
    pub timestamp: i64,
    pub author: String,
    pub user_id: i64,
    pub thread_id: i64,
    pub is_deleted_user: bool,
}

/// Joined message + user name from a .join() query.
#[derive(Debug, Deserialize)]
struct MessageJoined {
    id: Option<i64>,
    content: String,
    timestamp: i64,
    user_id: i64,
    thread_id: i64,
    name: String,
}

pub async fn get_or_create_channel(space: &Space, name: &str) -> Result<i64> {
    // Channel name is encrypted — client-side filter
    let name_owned = name.to_string();
    let c: Option<Channel> = space
        .table::<Channel>("channels")
        .select()
        .filter("name", move |v| v.as_str() == Some(&name_owned))
        .first()
        .await?;
    if let Some(c) = c {
        return Ok(c.id.unwrap());
    }
    Ok(space
        .table::<Channel>("channels")
        .insert(&Channel {
            id: None,
            name: name.to_string(),
            description: None,
            tasks: List::empty(),
            notes: TextArea::empty(),
        })
        .execute()
        .await?)
}

pub async fn update_channel_description(
    space: &Space,
    channel_id: i64,
    description: Option<String>,
) -> Result<bool> {
    let updated = space
        .table::<Channel>("channels")
        .update()
        .set("description", description.unwrap_or_default())
        .where_eq("id", channel_id)
        .execute()
        .await?;
    Ok(updated > 0)
}

pub async fn send_message(
    space: &Space,
    channel_id: i64,
    user_id: i64,
    text: &str,
    thread_id: i64,
) -> Result<i64> {
    let ts = chrono::Utc::now().timestamp();
    space
        .send_message(&Message {
            id: None,
            channel_id,
            user_id,
            content: text.to_string(),
            timestamp: ts,
            thread_id,
        })
        .await
        .map_err(|e| anyhow::anyhow!("failed to send message to channel {channel_id}: {e}"))
}

pub async fn edit_message(space: &Space, message_id: i64, new_content: &str) -> Result<bool> {
    let updated = space
        .update_message(message_id)
        .content(new_content.to_string())
        .execute()
        .await?;
    Ok(updated > 0)
}

pub async fn delete_message(space: &Space, message_id: i64) -> Result<bool> {
    // The `delete_message` action's cascade legs cover reactions,
    // attachments, and threaded replies in a single signed entry;
    // the verifier proves FK completeness on each cascade leg.
    let deleted = space
        .delete_message(message_id)
        .await
        .map_err(|e| anyhow::anyhow!("failed to delete message {message_id}: {e}"))?;
    Ok(deleted > 0)
}

pub enum ReactionChange {
    Added,
    Removed,
}

pub async fn set_reaction(
    space: &Space,
    channel_id: i64,
    message_id: i64,
    user_id: i64,
    emoji: &str,
) -> Result<ReactionChange> {
    // Server-side: filter by message_id (indexed). Client-side: filter user_id + emoji.
    //
    // NOTE: we deliberately use `.all()` + `.into_iter().next()` rather than
    // `.first()` here. `.first()` applies `LIMIT 1` *server-side*, which is
    // applied before the client-side `filter(...)` predicates run. If another
    // reaction (different emoji or user) on the same message has a smaller
    // row id, the server would return that single row, the client filter
    // would reject it, and we'd incorrectly conclude no matching reaction
    // exists — causing duplicate inserts on repeated clicks of a second
    // emoji.
    let emoji_owned = emoji.to_string();
    let existing: Option<Reaction> = space
        .table::<Reaction>("reactions")
        .select()
        .where_eq("message_id", message_id)
        .filter("user_id", move |v| v.as_i64() == Some(user_id))
        .filter("emoji", move |v| v.as_str() == Some(&emoji_owned))
        .all()
        .await?
        .into_iter()
        .next();

    if let Some(existing) = existing {
        if let Some(id) = existing.id {
            space
                .table::<Reaction>("reactions")
                .delete()
                .where_eq("id", id)
                .execute()
                .await?;
        }
        Ok(ReactionChange::Removed)
    } else {
        space
            .add_reaction(&Reaction {
                id: None,
                channel_id,
                message_id,
                user_id,
                emoji: emoji.to_string(),
            })
            .await?;
        Ok(ReactionChange::Added)
    }
}

pub async fn load_channels(space: &Space) -> Result<Vec<Channel>> {
    // Returned in row-id order (insertion order) — predicate-less queries
    // can no longer ask for column-based sorting.
    let channels: Vec<Channel> = space.table::<Channel>("channels").select().all().await?;
    Ok(channels)
}

pub async fn load_messages(space: &Space, channel_id: i64) -> Result<Vec<MessageWithUser>> {
    // Join messages with users to get author names in one query
    let joined: Vec<MessageJoined> = space
        .table::<Message>("messages")
        .select()
        .columns(&[
            "messages.id",
            "messages.content",
            "messages.timestamp",
            "messages.user_id",
            "messages.thread_id",
            "users_meta.name",
        ])
        .where_eq("channel_id", channel_id)
        .join("users_meta", "user_id", "id")
        .ascending()
        .all_as()
        .await?;

    Ok(joined
        .into_iter()
        .map(|m| MessageWithUser {
            id: m.id,
            content: m.content,
            timestamp: m.timestamp,
            user_id: m.user_id,
            thread_id: m.thread_id,
            author: m.name,
            is_deleted_user: false,
        })
        .collect())
}

pub async fn load_thread_messages(space: &Space, thread_id: i64) -> Result<Vec<MessageWithUser>> {
    // Join thread replies with users
    let joined: Vec<MessageJoined> = space
        .table::<Message>("messages")
        .select()
        .columns(&[
            "messages.id",
            "messages.content",
            "messages.timestamp",
            "messages.user_id",
            "messages.thread_id",
            "users_meta.name",
        ])
        .where_eq("thread_id", thread_id)
        .join("users_meta", "user_id", "id")
        .ascending()
        .all_as()
        .await?;

    Ok(joined
        .into_iter()
        .map(|m| MessageWithUser {
            id: m.id,
            content: m.content,
            timestamp: m.timestamp,
            user_id: m.user_id,
            thread_id: m.thread_id,
            author: m.name,
            is_deleted_user: false,
        })
        .collect())
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ReactionInfo {
    pub count: usize,
    pub users: Vec<String>,
}

pub async fn load_reaction_details(
    space: &Space,
    channel_id: i64,
) -> Result<std::collections::HashMap<i64, std::collections::HashMap<String, ReactionInfo>>> {
    // Join reactions with users to get reactor names
    #[derive(Deserialize)]
    struct ReactionJoined {
        message_id: i64,
        emoji: String,
        name: String,
    }

    let joined: Vec<ReactionJoined> = space
        .table::<Reaction>("reactions")
        .select()
        .columns(&["reactions.message_id", "reactions.emoji", "users_meta.name"])
        .where_eq("channel_id", channel_id)
        .join("users_meta", "user_id", "id")
        .all_as()
        .await?;

    let mut map: std::collections::HashMap<i64, std::collections::HashMap<String, ReactionInfo>> =
        std::collections::HashMap::new();
    for r in joined {
        let entry = map
            .entry(r.message_id)
            .or_default()
            .entry(r.emoji)
            .or_insert_with(|| ReactionInfo {
                count: 0,
                users: Vec::new(),
            });
        entry.count += 1;
        entry.users.push(r.name);
    }
    Ok(map)
}

/// Lightweight user record for frontend display
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct UserInfo {
    pub id: i64,
    pub name: String,
    pub status: String,
}

pub async fn get_users(space: &Space) -> Result<Vec<UserInfo>> {
    if let Err(error) = space.sync().await {
        log::debug!("[demo] get_users: sync before member load failed: {error}");
    }

    use encrypted_spaces_sdk::{UserRecord, UserStatus};
    let records: Vec<UserRecord> = space.users().select().all().await?;
    let meta_records: Vec<UsersMeta> = space
        .table::<UsersMeta>("users_meta")
        .select()
        .all()
        .await?;
    let name_map: std::collections::HashMap<i64, String> = meta_records
        .into_iter()
        .map(|m| (m.id.unwrap(), m.name))
        .collect();
    Ok(records
        .into_iter()
        .map(|u| {
            let uid = u.id.unwrap_or(0);
            UserInfo {
                id: uid,
                name: name_map
                    .get(&uid)
                    .cloned()
                    .unwrap_or_else(|| format!("user_{uid}")),
                status: match u.status {
                    UserStatus::Provisional => "pending".to_string(),
                    UserStatus::Full => "member".to_string(),
                },
            }
        })
        .collect())
}

/// Insert a name for a user into the `users_meta` table.
pub async fn set_user_name(space: &Space, user_id: i64, name: &str) -> Result<i64> {
    let meta = UsersMeta {
        id: Some(user_id),
        name: name.to_string(),
    };
    let id = space
        .table::<UsersMeta>("users_meta")
        .insert(&meta)
        .execute()
        .await?;
    Ok(id)
}

// ─── Attachments ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    pub id: Option<i64>,
    pub message_id: i64,
    pub file_hash: File,
    pub filename: String,
    pub mime_type: String,
    pub size: i64,
}

/// A file to be attached to a message (before upload).
pub struct PendingAttachment {
    pub data: Vec<u8>,
    pub filename: String,
    pub mime_type: String,
}

/// Send a message with file attachments.
///
/// Uploads each file to the file store, inserts the message row, then
/// inserts attachment rows with the file hashes.
pub async fn send_message_with_attachments(
    space: &Space,
    channel_id: i64,
    user_id: i64,
    text: &str,
    thread_id: i64,
    files: Vec<PendingAttachment>,
) -> Result<i64> {
    let handle = space.file();

    // Upload all files first
    let mut uploaded = Vec::new();
    for file in files {
        let size = file.data.len() as i64;
        let file_hash = handle.upload(File::from_data(file.data)).await?;
        uploaded.push((file_hash, file.filename, file.mime_type, size));
    }

    // Insert message
    let message_id = send_message(space, channel_id, user_id, text, thread_id).await?;

    // Insert attachment rows
    for (file_hash, filename, mime_type, size) in uploaded {
        space
            .add_attachment(&Attachment {
                id: None,
                message_id,
                file_hash,
                filename,
                mime_type,
                size,
            })
            .await?;
    }

    Ok(message_id)
}

/// Load attachments for a specific message.
pub async fn get_attachments(space: &Space, message_id: i64) -> Result<Vec<Attachment>> {
    space
        .table::<Attachment>("attachments")
        .select()
        .where_eq("message_id", message_id)
        .all()
        .await
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use encrypted_spaces_sdk::{ApplicationSchema, LocalTransport, Schema, Space};

    const TEST_SCHEMA_BYTES: &[u8] = include_bytes!("../../app_schema.kdl");

    async fn create_test_space() -> Space {
        let text = std::str::from_utf8(TEST_SCHEMA_BYTES).expect("schema is utf-8");
        let bundle = encrypted_spaces_sdk::testing::parse_schema_bundle(text).expect("valid KDL");
        let schemas: Vec<Schema> = bundle
            .tables
            .iter()
            .filter_map(|t| t.schema.clone())
            .collect();
        let actions = bundle.actions.clone();
        let only_via = bundle.acl_only_via_actions.clone();

        std::env::set_var("RISC0_DEV_MODE", "1"); // Tests always use dev mode
        let transport = LocalTransport::new(&schemas, None, Some(10_000))
            .await
            .unwrap();
        // LocalTransport::new only initializes table schemas + ACL
        // predicates; actions and action-gating need an explicit
        // import before the commitment snapshot so the resulting root
        // matches what the SDK sees.
        transport.import_actions(&actions, &only_via).await.unwrap();

        let commitment = transport.get_root_hash().await.unwrap();

        let space = Space::create(
            transport,
            ApplicationSchema::for_testing(schemas, commitment),
        )
        .await
        .unwrap();

        // `for_testing` uses the explicit-schemas `ApplicationSchema`
        // variant, which doesn't carry actions; register them manually
        // so the codegen-emitted `Actions` trait dispatch can resolve
        // them.
        for action in actions {
            space.register_action(action);
        }

        // Insert a users_meta row for the creator
        let uid = space.uid().unwrap() as i64;
        set_user_name(&space, uid, "test_user").await.unwrap();

        space
    }

    // ── Channel tests ───────────────────────────────────────────────────

    #[tokio::test]
    async fn create_channel() {
        let space = create_test_space().await;
        let id = get_or_create_channel(&space, "general").await.unwrap();
        assert!(id > 0);
    }

    #[tokio::test]
    async fn get_existing_channel() {
        let space = create_test_space().await;
        let id1 = get_or_create_channel(&space, "general").await.unwrap();
        let id2 = get_or_create_channel(&space, "general").await.unwrap();
        assert_eq!(id1, id2);
    }

    #[tokio::test]
    async fn load_channels_returns_all() {
        let space = create_test_space().await;
        get_or_create_channel(&space, "alpha").await.unwrap();
        get_or_create_channel(&space, "beta").await.unwrap();
        let channels = load_channels(&space).await.unwrap();
        assert_eq!(channels.len(), 2);
        let names: Vec<&str> = channels.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"alpha"));
        assert!(names.contains(&"beta"));
    }

    #[tokio::test]
    async fn update_channel_description_test() {
        let space = create_test_space().await;
        let id = get_or_create_channel(&space, "general").await.unwrap();
        let ok = update_channel_description(&space, id, Some("A general channel".into()))
            .await
            .unwrap();
        assert!(ok);
        let channels = load_channels(&space).await.unwrap();
        let ch = channels.iter().find(|c| c.id == Some(id)).unwrap();
        assert_eq!(ch.description.as_deref(), Some("A general channel"));
    }

    #[tokio::test]
    async fn update_description_nonexistent_channel() {
        let space = create_test_space().await;
        let ok = update_channel_description(&space, 9999, Some("nope".into()))
            .await
            .unwrap();
        assert!(!ok);
    }

    // ── Message tests ───────────────────────────────────────────────────

    #[tokio::test]
    async fn send_and_load_message() {
        let space = create_test_space().await;
        let ch = get_or_create_channel(&space, "general").await.unwrap();
        let uid = space.uid().unwrap() as i64;
        let msg_id = send_message(&space, ch, uid, "hello world", 0)
            .await
            .unwrap();
        assert!(msg_id > 0);

        let msgs = load_messages(&space, ch).await.unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].content, "hello world");
        assert_eq!(msgs[0].author, "test_user");
    }

    #[tokio::test]
    async fn send_multiple_messages_ordered() {
        let space = create_test_space().await;
        let ch = get_or_create_channel(&space, "general").await.unwrap();
        let uid = space.uid().unwrap() as i64;
        send_message(&space, ch, uid, "first", 0).await.unwrap();
        send_message(&space, ch, uid, "second", 0).await.unwrap();
        send_message(&space, ch, uid, "third", 0).await.unwrap();

        let msgs = load_messages(&space, ch).await.unwrap();
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0].content, "first");
        assert_eq!(msgs[1].content, "second");
        assert_eq!(msgs[2].content, "third");
    }

    #[tokio::test]
    async fn edit_message_test() {
        let space = create_test_space().await;
        let ch = get_or_create_channel(&space, "general").await.unwrap();
        let uid = space.uid().unwrap() as i64;
        let msg_id = send_message(&space, ch, uid, "original", 0).await.unwrap();

        let ok = edit_message(&space, msg_id, "edited").await.unwrap();
        assert!(ok);

        let msgs = load_messages(&space, ch).await.unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].content, "edited");
    }

    #[tokio::test]
    async fn edit_nonexistent_message() {
        let space = create_test_space().await;
        let ok = edit_message(&space, 9999, "nope").await.unwrap();
        assert!(!ok);
    }

    #[tokio::test]
    async fn delete_message_test() {
        let space = create_test_space().await;
        let ch = get_or_create_channel(&space, "general").await.unwrap();
        let uid = space.uid().unwrap() as i64;
        let msg_id = send_message(&space, ch, uid, "to delete", 0).await.unwrap();

        let ok = delete_message(&space, msg_id).await.unwrap();
        assert!(ok);

        let msgs = load_messages(&space, ch).await.unwrap();
        assert!(msgs.is_empty());
    }

    #[tokio::test]
    async fn delete_nonexistent_message() {
        let space = create_test_space().await;
        let ok = delete_message(&space, 9999).await.unwrap();
        assert!(!ok);
    }

    #[tokio::test]
    async fn update_message_rejects_channel_id_change() {
        // `update_message` action asserts `unchanged(channel_id)`; the
        // codegen builder exposes a `.channel_id(...)` setter so the
        // SDK can construct the would-be-malicious entry, but the
        // verifier must reject it.
        let space = create_test_space().await;
        let ch = get_or_create_channel(&space, "general").await.unwrap();
        let uid = space.uid().unwrap() as i64;
        let msg_id = send_message(&space, ch, uid, "original", 0).await.unwrap();

        let err = space
            .update_message(msg_id)
            .channel_id(ch + 999)
            .execute()
            .await
            .expect_err("changing channel_id must be rejected by cols= allowlist");
        let msg = format!("{err}");
        assert!(
            msg.contains("cols allowlist") || msg.contains("not in the action"),
            "expected cols-allowlist error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn update_message_accepts_content_only_update() {
        // `update_message`'s `cols="content"` allowlist permits only
        // `content` to change; other columns aren't allowed in the kvs.
        let space = create_test_space().await;
        let ch = get_or_create_channel(&space, "general").await.unwrap();
        let uid = space.uid().unwrap() as i64;
        let msg_id = send_message(&space, ch, uid, "first draft", 0)
            .await
            .unwrap();

        let ok = edit_message(&space, msg_id, "final draft").await.unwrap();
        assert!(ok);
        let msgs = load_messages(&space, ch).await.unwrap();
        assert_eq!(msgs[0].content, "final draft");
    }

    #[tokio::test]
    async fn thread_messages() {
        let space = create_test_space().await;
        let ch = get_or_create_channel(&space, "general").await.unwrap();
        let uid = space.uid().unwrap() as i64;

        let parent_id = send_message(&space, ch, uid, "parent", 0).await.unwrap();
        send_message(&space, ch, uid, "reply", parent_id)
            .await
            .unwrap();

        let thread = load_thread_messages(&space, parent_id).await.unwrap();
        assert_eq!(thread.len(), 1);
        assert_eq!(thread[0].content, "reply");
    }

    #[tokio::test]
    async fn delete_message_cascades_reactions() {
        let space = create_test_space().await;
        let ch = get_or_create_channel(&space, "general").await.unwrap();
        let uid = space.uid().unwrap() as i64;
        let msg_id = send_message(&space, ch, uid, "react to me", 0)
            .await
            .unwrap();

        set_reaction(&space, ch, msg_id, uid, "thumbsup")
            .await
            .unwrap();

        delete_message(&space, msg_id).await.unwrap();

        let details = load_reaction_details(&space, ch).await.unwrap();
        assert!(details.is_empty());
    }

    #[tokio::test]
    async fn delete_message_cascades_thread_replies() {
        let space = create_test_space().await;
        let ch = get_or_create_channel(&space, "general").await.unwrap();
        let uid = space.uid().unwrap() as i64;

        let parent_id = send_message(&space, ch, uid, "parent", 0).await.unwrap();
        send_message(&space, ch, uid, "reply", parent_id)
            .await
            .unwrap();

        delete_message(&space, parent_id).await.unwrap();

        let thread = load_thread_messages(&space, parent_id).await.unwrap();
        assert!(thread.is_empty());
    }

    // ── Reaction tests ──────────────────────────────────────────────────

    #[tokio::test]
    async fn toggle_reaction_adds() {
        let space = create_test_space().await;
        let ch = get_or_create_channel(&space, "general").await.unwrap();
        let uid = space.uid().unwrap() as i64;
        let msg_id = send_message(&space, ch, uid, "react", 0).await.unwrap();

        let change = set_reaction(&space, ch, msg_id, uid, "heart")
            .await
            .unwrap();
        assert!(matches!(change, ReactionChange::Added));
    }

    #[tokio::test]
    async fn toggle_reaction_removes() {
        let space = create_test_space().await;
        let ch = get_or_create_channel(&space, "general").await.unwrap();
        let uid = space.uid().unwrap() as i64;
        let msg_id = send_message(&space, ch, uid, "react", 0).await.unwrap();

        set_reaction(&space, ch, msg_id, uid, "heart")
            .await
            .unwrap();
        let change = set_reaction(&space, ch, msg_id, uid, "heart")
            .await
            .unwrap();
        assert!(matches!(change, ReactionChange::Removed));
    }

    #[tokio::test]
    async fn reaction_details_aggregation() {
        let space = create_test_space().await;
        let ch = get_or_create_channel(&space, "general").await.unwrap();
        let uid = space.uid().unwrap() as i64;
        let msg_id = send_message(&space, ch, uid, "react", 0).await.unwrap();

        set_reaction(&space, ch, msg_id, uid, "thumbsup")
            .await
            .unwrap();

        let details = load_reaction_details(&space, ch).await.unwrap();
        let msg_reactions = details.get(&msg_id).unwrap();
        let info = msg_reactions.get("thumbsup").unwrap();
        assert_eq!(info.count, 1);
        assert_eq!(info.users, vec!["test_user"]);
    }

    #[tokio::test]
    async fn reaction_details_empty() {
        let space = create_test_space().await;
        let ch = get_or_create_channel(&space, "general").await.unwrap();
        let details = load_reaction_details(&space, ch).await.unwrap();
        assert!(details.is_empty());
    }

    // ── User tests ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn get_users_returns_creator() {
        let space = create_test_space().await;
        let users = get_users(&space).await.unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].name, "test_user");
        assert_eq!(users[0].status, "member");
    }
}
