//! [`Action`] — every operation the harness can perform on behalf of an actor.
//!
//! Actions are JSON-serialisable so scenarios can be authored as data files
//! and replayed by the `demo-harness` CLI.

use serde::{Deserialize, Serialize};

/// One step in a [`Scenario`]: which actor performs which action.
///
/// Stored as a tagged JSON object: `{ "actor": "alice", "action": { ... } }`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    pub actor: String,
    #[serde(flatten)]
    pub action: Action,
}

/// A scripted scenario: an ordered list of [`Step`]s.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Scenario {
    pub steps: Vec<Step>,
}

impl Scenario {
    /// Build a scenario from `(actor, action)` pairs.
    pub fn new(steps: Vec<(String, Action)>) -> Self {
        Self {
            steps: steps
                .into_iter()
                .map(|(actor, action)| Step { actor, action })
                .collect(),
        }
    }

    pub fn push(&mut self, actor: impl Into<String>, action: Action) {
        self.steps.push(Step {
            actor: actor.into(),
            action,
        });
    }

    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    pub fn from_json(s: &str) -> serde_json::Result<Self> {
        serde_json::from_str(s)
    }
}

/// Operations the harness can perform on behalf of an actor.
///
/// Tagged as `{ "type": "...", ... }` in JSON for readability.
//
// Note: no `SendEphemeral` variant — `LocalTransport` doesn't implement
// `Transport::send_ephemeral` (see `sdk/src/transport.rs`, which returns
// `"send_ephemeral is not supported by this transport"` from the trait
// default). Add when a broadcast-capable transport is wired into the harness.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Action {
    // ── Space lifecycle ────────────────────────────────────────────────
    /// Create a new space (only valid as the *first* action). The actor
    /// becomes the founding member; an initial channel is created.
    CreateSpace {
        channel: String,
    },

    /// The current actor produces a `SpaceInvite` for the named (not-yet
    /// existing) `invitee`. The invite is stashed in the world and consumed
    /// by a subsequent `Join { from: <inviter> }` step.
    Invite {
        invitee: String,
    },

    /// The current actor joins the space using the invite previously
    /// produced by `from`. Sets the actor's current channel.
    Join {
        from: String,
        channel: String,
    },

    // ── Channels ───────────────────────────────────────────────────────
    /// Create or fetch a channel by name; sets it as the actor's current
    /// channel.
    SwitchChannel {
        name: String,
    },

    UpdateChannelDescription {
        description: Option<String>,
    },

    // ── Messages ───────────────────────────────────────────────────────
    SendMessage {
        text: String,
    },

    /// Edit the most recently sent message by this actor.
    EditLastMessage {
        text: String,
    },

    /// Delete the most recently sent message by this actor.
    DeleteLastMessage,

    /// Reply to the most recent message in the current channel (any author).
    ReplyToLast {
        text: String,
    },

    /// Toggle the given emoji reaction on the most recent message in the
    /// current channel.
    ToggleReactionOnLast {
        emoji: String,
    },

    // ── Tasks ──────────────────────────────────────────────────────────
    AddTask {
        title: String,
    },
    /// Toggle the most recently added task in the current channel.
    ToggleLastTask,
    UpdateLastTaskTitle {
        title: String,
    },
    DeleteLastTask,

    // ── Calendar ───────────────────────────────────────────────────────
    AddCalendarEvent {
        start_time: i64,
        end_time: i64,
        title: String,
        description: String,
    },
    /// Update the most recently added event by this actor.
    UpdateLastCalendarEvent {
        start_time: i64,
        end_time: i64,
        title: String,
        description: String,
    },
    DeleteLastCalendarEvent,

    // ── Notes ──────────────────────────────────────────────────────────
    NotesInsert {
        pos: usize,
        text: String,
    },
    NotesDelete {
        pos: usize,
        count: usize,
    },

    // ── Files (drives the demo's `files` module / `inodes` table) ──────
    /// Upload a file inode under `parent_id` (use `0` for the root).
    UploadFile {
        parent_id: i64,
        name: String,
        content: String,
    },
    /// Create a folder inode under `parent_id` (use `0` for the root).
    CreateFolder {
        parent_id: i64,
        name: String,
    },
    /// Rename the most recently created inode by this actor.
    RenameLastInode {
        name: String,
    },
    /// Move the most recently created inode under `new_parent_id`.
    MoveLastInode {
        new_parent_id: i64,
    },
    /// Recursively delete the most recently created inode by this actor.
    DeleteLastInode,
    /// Download and decrypt the most recently created inode's bytes,
    /// stashing them in `ActorMemory.last_file_bytes` for later assertions.
    ReadLastFile,

    // ── User management ────────────────────────────────────────────────
    /// Remove `target` (by actor name) from the space. Triggers a rekey;
    /// the removed actor is dropped from the world's registry so subsequent
    /// steps that name them fail with "unknown actor".
    RemoveUser {
        target: String,
    },

    // ── Snapshots ──────────────────────────────────────────────────────
    /// Export the actor's current `Space` state into the named slot.
    SaveSnapshot {
        slot: String,
    },
    /// Replace the actor's `Space` with a fresh one rebuilt from the slot's
    /// snapshot. The actor's per-action memory (last_message_id etc.) is
    /// reset to default, but `current_channel_id`/`name` are preserved.
    RestoreSnapshot {
        slot: String,
    },

    // ── Sync ───────────────────────────────────────────────────────────
    /// Force a sync for this actor (catches up with other actors' writes).
    Sync,
    /// Sync every actor in the world (ensures all replicas converge).
    SyncAll,
}

impl Action {
    /// Short, log-friendly label.
    pub fn label(&self) -> &'static str {
        match self {
            Action::CreateSpace { .. } => "create_space",
            Action::Invite { .. } => "invite",
            Action::Join { .. } => "join",
            Action::SwitchChannel { .. } => "switch_channel",
            Action::UpdateChannelDescription { .. } => "update_channel_description",
            Action::SendMessage { .. } => "send_message",
            Action::EditLastMessage { .. } => "edit_last_message",
            Action::DeleteLastMessage => "delete_last_message",
            Action::ReplyToLast { .. } => "reply_to_last",
            Action::ToggleReactionOnLast { .. } => "toggle_reaction_on_last",
            Action::AddTask { .. } => "add_task",
            Action::ToggleLastTask => "toggle_last_task",
            Action::UpdateLastTaskTitle { .. } => "update_last_task_title",
            Action::DeleteLastTask => "delete_last_task",
            Action::AddCalendarEvent { .. } => "add_calendar_event",
            Action::UpdateLastCalendarEvent { .. } => "update_last_calendar_event",
            Action::DeleteLastCalendarEvent => "delete_last_calendar_event",
            Action::NotesInsert { .. } => "notes_insert",
            Action::NotesDelete { .. } => "notes_delete",
            Action::UploadFile { .. } => "upload_file",
            Action::CreateFolder { .. } => "create_folder",
            Action::RenameLastInode { .. } => "rename_last_inode",
            Action::MoveLastInode { .. } => "move_last_inode",
            Action::DeleteLastInode => "delete_last_inode",
            Action::ReadLastFile => "read_last_file",
            Action::RemoveUser { .. } => "remove_user",
            Action::SaveSnapshot { .. } => "save_snapshot",
            Action::RestoreSnapshot { .. } => "restore_snapshot",
            Action::Sync => "sync",
            Action::SyncAll => "sync_all",
        }
    }
}
