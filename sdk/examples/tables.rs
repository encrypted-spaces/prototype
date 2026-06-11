use encrypted_spaces_sdk::{
    ColumnType, LocalTransport, SchemaBuilder, Space, UserRecord, UserStatus,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Channel {
    id: Option<i64>,
    name: String,
    description: Option<String>,
    is_private: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Message {
    id: Option<i64>,
    channel_id: i64,
    user_id: i64,
    content: String,
    timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Reaction {
    id: Option<i64>,
    message_id: i64,
    user_id: i64,
    emoji: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChannelMember {
    id: Option<i64>,
    channel_id: i64,
    user_id: i64,
}

async fn create_channel(
    space: &Space,
    name: &str,
    description: Option<&str>,
    is_private: bool,
) -> Result<i64, Box<dyn std::error::Error>> {
    let channel = Channel {
        id: None,
        name: name.to_string(),
        description: description.map(|s| s.to_string()),
        is_private,
    };

    let channels_table = space.table::<Channel>("channels");
    let channel_id = channels_table.insert(&channel).execute().await?;
    Ok(channel_id)
}

async fn add_member_to_channel(
    space: &Space,
    channel_id: i64,
    user_id: i64,
) -> Result<i64, Box<dyn std::error::Error>> {
    let member = ChannelMember {
        id: None,
        channel_id,
        user_id,
    };

    let members_table = space.table::<ChannelMember>("channel_members");
    let member_id = members_table.insert(&member).execute().await?;
    Ok(member_id)
}

async fn write_message(
    space: &Space,
    channel_id: i64,
    user_id: i64,
    content: &str,
    timestamp: i64,
) -> Result<i64, Box<dyn std::error::Error>> {
    let message = Message {
        id: None,
        channel_id,
        user_id,
        content: content.to_string(),
        timestamp,
    };

    let messages_table = space.table::<Message>("messages");
    let message_id = messages_table.insert(&message).execute().await?;
    Ok(message_id)
}

async fn react_to_message(
    space: &Space,
    message_id: i64,
    user_id: i64,
    emoji: &str,
) -> Result<i64, Box<dyn std::error::Error>> {
    let reaction = Reaction {
        id: None,
        message_id,
        user_id,
        emoji: emoji.to_string(),
    };

    let reactions_table = space.table::<Reaction>("reactions");
    let reaction_id = reactions_table.insert(&reaction).execute().await?;
    Ok(reaction_id)
}

async fn initialize_tables(space: &Space) -> Result<(), Box<dyn std::error::Error>> {
    // Channels table
    let channel_schema = SchemaBuilder::new("channels")
        .column("id", ColumnType::Integer)
        .plaintext_primary_key()
        .column("name", ColumnType::String)?
        .plaintext()
        .index()
        .column("description", ColumnType::String)?
        .column("is_private", ColumnType::Integer)?
        .plaintext()
        .build()?;

    // Messages table
    let message_schema = SchemaBuilder::new("messages")
        .column("id", ColumnType::Integer)
        .plaintext_primary_key()
        .column("channel_id", ColumnType::Integer)?
        .plaintext()
        .index()
        .column("user_id", ColumnType::Integer)?
        .plaintext()
        .column("content", ColumnType::String)?
        .column("timestamp", ColumnType::Integer)?
        .plaintext()
        .index()
        .build()?;

    // Reactions table
    let reaction_schema = SchemaBuilder::new("reactions")
        .column("id", ColumnType::Integer)
        .plaintext_primary_key()
        .column("message_id", ColumnType::Integer)?
        .plaintext()
        .index()
        .column("user_id", ColumnType::Integer)?
        .plaintext()
        .column("emoji", ColumnType::String)?
        .plaintext()
        .build()?;

    // Channel members table
    let channel_member_schema = SchemaBuilder::new("channel_members")
        .column("id", ColumnType::Integer)
        .plaintext_primary_key()
        .column("channel_id", ColumnType::Integer)?
        .plaintext()
        .index()
        .column("user_id", ColumnType::Integer)?
        .plaintext()
        .index()
        .build()?;

    // Create all tables
    space.create_table(&channel_schema).await?;
    space.create_table(&message_schema).await?;
    space.create_table(&reaction_schema).await?;
    space.create_table(&channel_member_schema).await?;

    Ok(())
}

async fn display_chat_state(
    space: &Space,
    channel_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let channels_table = space.table::<Channel>("channels");
    let messages_table = space.table::<Message>("messages");
    let reactions_table = space.table::<Reaction>("reactions");
    let members_table = space.table::<ChannelMember>("channel_members");

    // Get the channel
    let channel = channels_table
        .select()
        .where_eq("name", channel_name.to_string())
        .first()
        .await?
        .ok_or_else(|| format!("Channel '{channel_name}' not found"))?;

    println!("#{}", channel.name);
    if let Some(desc) = &channel.description {
        println!("  {desc}");
    }

    // Get channel members using a join - fetch members with user info in one query.
    // (The join isn't strictly needed to print `@user_{id}`, but it shows the syntax.)
    let member_data: Vec<UserRecord> = members_table
        .select()
        .columns(&[
            "channel_members.channel_id",
            "channel_members.user_id",
            "users.id",
            "users.update_key",
            "users.auth_key",
            "users.status",
        ])
        .join(
            &format!("{} as users", space.users().name()),
            "user_id",
            "id",
        )
        .where_eq("channel_id", channel.id.unwrap())
        .all_as()
        .await?;

    println!(
        "  Members: {}",
        member_data
            .iter()
            .map(|m| format!("@user_{}", m.id.unwrap()))
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!();

    // Get messages joined with users so each message shows the author's status.
    // This is the example's demonstration of `.join()` syntax.
    #[derive(serde::Deserialize)]
    struct MessageWithUser {
        id: Option<i64>,
        user_id: i64,
        content: String,
        timestamp: i64,
        status: UserStatus,
    }

    let message_data: Vec<MessageWithUser> = messages_table
        .select()
        .columns(&[
            "messages.id",
            "messages.channel_id",
            "messages.user_id",
            "messages.content",
            "messages.timestamp",
            "users.status",
        ])
        .join(
            &format!("{} as users", space.users().name()),
            "user_id",
            "id",
        )
        .where_eq("channel_id", channel.id.unwrap())
        .ascending()
        .all_as()
        .await?;

    for message in &message_data {
        // Format timestamp (simplified)
        let time = format!(
            "{:02}:{:02}",
            (message.timestamp % 86400) / 3600,
            (message.timestamp % 3600) / 60
        );

        println!(
            "  [{}] user_{} [{:?}]: {}",
            time, message.user_id, message.status, message.content
        );

        // Get reactions with user info using a join - fetch reactions with user data in one query.
        // (The join isn't strictly needed here either, but it shows the syntax.)
        #[derive(serde::Deserialize)]
        struct ReactionWithUser {
            emoji: String,
            user_id: i64,
        }

        let reaction_data: Vec<ReactionWithUser> = reactions_table
            .select()
            .columns(&[
                "reactions.message_id",
                "reactions.user_id",
                "reactions.emoji",
            ])
            .join(
                &format!("{} as users", space.users().name()),
                "user_id",
                "id",
            )
            .where_eq("message_id", message.id.unwrap())
            .all_as()
            .await?;

        if !reaction_data.is_empty() {
            print!("    ");
            for reaction in &reaction_data {
                print!("{} by user_{} ", reaction.emoji, reaction.user_id);
            }
            println!();
        }
    }
    println!();

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Chat App Demo");
    println!("=============");
    println!();

    let space = Space::new(LocalTransport::in_memory().await?).await?;
    initialize_tables(&space).await?;

    // Create users dynamically and get their IDs
    let alice_id = space.invite_user().await?.id().unwrap();
    let bob_id = space.invite_user().await?.id().unwrap();
    let charlie_id = space.invite_user().await?.id().unwrap();

    println!("Created users: alice ({alice_id}), bob ({bob_id}), charlie ({charlie_id})");

    // Create channels and get their IDs
    let general_id = create_channel(&space, "general", Some("General discussion"), false).await?;
    let dev_id = create_channel(&space, "dev", Some("Development talk"), false).await?;

    println!("Created channels: general ({general_id}), dev ({dev_id})");

    // Add members to channels
    add_member_to_channel(&space, general_id, alice_id).await?;
    add_member_to_channel(&space, general_id, bob_id).await?;
    add_member_to_channel(&space, general_id, charlie_id).await?;
    add_member_to_channel(&space, dev_id, alice_id).await?;
    add_member_to_channel(&space, dev_id, charlie_id).await?;

    println!("Added members to channels");
    println!();

    // Write some messages and get their IDs
    let msg1_id =
        write_message(&space, general_id, alice_id, "Hello everyone!", 1640995600).await?;
    let msg2_id = write_message(
        &space,
        general_id,
        bob_id,
        "Hey Alice! How's it going?",
        1640995700,
    )
    .await?;
    let msg3_id = write_message(
        &space,
        dev_id,
        charlie_id,
        "Anyone working on the new feature?",
        1640995800,
    )
    .await?;
    let msg4_id = write_message(
        &space,
        general_id,
        charlie_id,
        "Good morning team!",
        1640995900,
    )
    .await?;

    println!("Wrote messages: {msg1_id} {msg2_id} {msg3_id} {msg4_id}");

    // Add some reactions
    let reaction1_id = react_to_message(&space, msg1_id, bob_id, "👋").await?;
    let reaction2_id = react_to_message(&space, msg4_id, alice_id, "☀️").await?;
    let reaction3_id = react_to_message(&space, msg4_id, bob_id, "☀️").await?;

    println!("Added reactions: {reaction1_id} {reaction2_id} {reaction3_id}");
    println!();

    // Display initial state
    display_chat_state(&space, "general").await?;
    display_chat_state(&space, "dev").await?;

    // Add more messages and reactions dynamically
    let msg5_id = write_message(
        &space,
        general_id,
        bob_id,
        "Great to see everyone here!",
        1640996000,
    )
    .await?;
    let msg6_id = write_message(
        &space,
        dev_id,
        alice_id,
        "I can help with that feature",
        1640996100,
    )
    .await?;

    let reaction4_id = react_to_message(&space, msg5_id, charlie_id, "👍").await?;

    println!("--- After adding more messages ---");
    println!("Added message {msg6_id} and reaction {reaction4_id}");
    println!();

    // Display updated state
    display_chat_state(&space, "general").await?;
    display_chat_state(&space, "dev").await?;

    // ─── Delete demonstrations ─────────────────────────────────────────────
    println!("--- Demonstrating DELETE operations ---");
    println!();

    // Delete a message by id (single-row)
    let deleted_msg = space
        .table::<Message>("messages")
        .delete()
        .where_eq("id", msg4_id)
        .execute()
        .await?;
    println!("Deleted {deleted_msg} message (id={msg4_id})");

    // Cascade: delete all reactions for the deleted message (multi-row)
    let deleted_reactions = space
        .table::<Reaction>("reactions")
        .delete()
        .where_eq("message_id", msg4_id)
        .execute()
        .await?;
    println!("Cascade-deleted {deleted_reactions} reaction(s) for message id={msg4_id}");

    println!();
    println!("--- After deletes ---");
    display_chat_state(&space, "general").await?;

    Ok(())
}
