//! Per-actor handle: a [`Space`] over [`LocalTransport`] plus the bookkeeping
//! the harness needs to support "operate on the last X" actions.

use std::collections::HashMap;
use std::sync::Arc;

use encrypted_spaces_sdk::Space;

/// "Last X" memory that is meaningful only inside a specific channel.
/// Messages and tasks belong to a channel, so when an actor switches channels
/// their previously-remembered IDs in the prior channel must remain valid for
/// when they switch back — we cannot just use a flat `Option`.
#[derive(Debug, Default, Clone)]
pub struct ChannelMemory {
    pub last_message_id: Option<i64>,
    pub last_task_key: Option<String>,
}

/// Tracks the most recent IDs/keys an actor produced, so subsequent actions
/// such as `EditLastMessage` or `ToggleLastTask` can resolve a target.
///
/// Channel-scoped memory is keyed by `channel_id`. Calendar events and
/// inodes are space-wide (not per-channel) so they live at the top level.
#[derive(Debug, Default, Clone)]
pub struct ActorMemory {
    pub per_channel: HashMap<i64, ChannelMemory>,
    pub last_calendar_event_id: Option<i64>,
    pub last_inode_id: Option<i64>,
    pub last_file_bytes: Option<Vec<u8>>,
}

impl ActorMemory {
    /// Snapshot of the channel's memory (defaults if never touched).
    pub fn channel(&self, channel_id: i64) -> ChannelMemory {
        self.per_channel
            .get(&channel_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Mutable handle to the channel's memory, inserting a default entry
    /// if this is the first write.
    pub fn channel_mut(&mut self, channel_id: i64) -> &mut ChannelMemory {
        self.per_channel.entry(channel_id).or_default()
    }
}

/// One actor in a [`crate::World`].
pub struct Actor {
    pub name: String,
    pub user_id: i64,
    pub space: Arc<Space>,
    pub current_channel_id: i64,
    pub current_channel_name: String,
    pub memory: ActorMemory,
}

impl Actor {
    pub fn new(
        name: String,
        user_id: i64,
        space: Arc<Space>,
        current_channel_id: i64,
        current_channel_name: String,
    ) -> Self {
        Self {
            name,
            user_id,
            space,
            current_channel_id,
            current_channel_name,
            memory: ActorMemory::default(),
        }
    }
}
