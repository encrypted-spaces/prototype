//! [`Runner`] — executes a [`Scenario`] against a [`World`].

use std::path::PathBuf;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::action::{Action, Scenario, Step};
use crate::world::World;
use encrypted_spaces_demo::files::PendingFile;
use encrypted_spaces_demo::{calendar, chat, files, notes, tasks};
use encrypted_spaces_sdk::Space;

#[derive(Debug, Error)]
pub enum RunnerError {
    #[error("step {index} ({label}) by `{actor}` failed: {source}")]
    Step {
        index: usize,
        actor: String,
        label: &'static str,
        #[source]
        source: anyhow::Error,
    },
}

/// Snapshot of a failed run, written to disk by [`Runner`] when
/// [`Runner::failure_dump_path`] is set.
///
/// `successful_prefix` is exactly the steps that ran without error before
/// the failure — replaying it should reproduce the world state up to (but
/// not including) the failing step. `failing_step` is the step that errored.
#[derive(Debug, Serialize, Deserialize)]
pub struct FailureReport {
    pub failing_index: usize,
    pub actor: String,
    pub action_label: String,
    pub error: String,
    pub error_chain: Vec<String>,
    pub failing_step: Step,
    pub successful_prefix: Scenario,
    pub actor_names: Vec<String>,
}

/// Drives a [`World`] through a [`Scenario`] step by step.
pub struct Runner {
    pub world: World,
    /// If true, sync every actor after every mutating step. Default: true.
    /// Set to false to test eventual-consistency behaviour explicitly.
    pub auto_sync: bool,
    /// Trace of executed steps, useful for fuzz-shrinking and debugging.
    pub trace: Vec<Step>,
    /// If set, [`Runner::execute`] writes a [`FailureReport`] to this path
    /// when a step errors. The path is also printed to stderr so callers
    /// (CLI, test harness) surface it without extra plumbing.
    pub failure_dump_path: Option<PathBuf>,
}

impl Runner {
    pub async fn new() -> Result<Self> {
        Ok(Self {
            world: World::new().await?,
            auto_sync: true,
            trace: Vec::new(),
            failure_dump_path: None,
        })
    }

    /// Execute a scenario start-to-finish. Returns the first failing step
    /// (after recording it in `trace`), or `Ok(())` on success.
    ///
    /// On failure, if [`Runner::failure_dump_path`] is set, a
    /// [`FailureReport`] is written there as JSON before the error is
    /// returned.
    pub async fn execute(&mut self, scenario: &Scenario) -> Result<(), RunnerError> {
        for (i, step) in scenario.steps.iter().enumerate() {
            if let Err(source) = self.execute_step(step).await {
                let chain: Vec<String> = source.chain().map(|c| c.to_string()).collect();
                let err = RunnerError::Step {
                    index: i,
                    actor: step.actor.clone(),
                    label: step.action.label(),
                    source,
                };
                if let Some(path) = self.failure_dump_path.clone() {
                    let report = FailureReport {
                        failing_index: i,
                        actor: step.actor.clone(),
                        action_label: step.action.label().to_string(),
                        error: err.to_string(),
                        error_chain: chain,
                        failing_step: step.clone(),
                        successful_prefix: Scenario {
                            steps: self.trace.clone(),
                        },
                        actor_names: self.world.actor_names(),
                    };
                    match serde_json::to_string_pretty(&report)
                        .map_err(anyhow::Error::from)
                        .and_then(|json| Ok(std::fs::write(&path, json)?))
                    {
                        Ok(()) => {
                            eprintln!("[harness] failure report written to {}", path.display())
                        }
                        Err(e) => eprintln!(
                            "[harness] could not write failure report to {}: {e}",
                            path.display()
                        ),
                    }
                }
                return Err(err);
            }
        }
        Ok(())
    }

    /// Execute a single step. Public so fuzzers can drive one action at a
    /// time and capture intermediate state.
    pub async fn execute_step(&mut self, step: &Step) -> Result<()> {
        crate::set_current_step_index(self.trace.len());
        log::debug!(
            "[harness] step {}: {} -> {}",
            self.trace.len(),
            step.actor,
            step.action.label()
        );

        match &step.action {
            Action::CreateSpace { channel } => {
                self.world.create_founder(&step.actor, channel).await?;
            }
            Action::Invite { invitee } => {
                self.world.invite(&step.actor, invitee).await?;
            }
            Action::Join { from, channel } => {
                // `from` is informational; the pending invite is keyed by invitee.
                let _ = from;
                self.world.join(&step.actor, channel).await?;
            }
            Action::SwitchChannel { name } => {
                let space = self.world.actor(&step.actor)?.space.clone();
                let channel_id = chat::get_or_create_channel(&space, name).await?;
                let actor = self.world.actor_mut(&step.actor)?;
                actor.current_channel_id = channel_id;
                actor.current_channel_name = name.clone();
            }
            Action::UpdateChannelDescription { description } => {
                let actor = self.world.actor(&step.actor)?;
                let cid = actor.current_channel_id;
                chat::update_channel_description(&actor.space, cid, description.clone()).await?;
            }
            Action::SendMessage { text } => {
                let (space, cid, uid) = self.cur(&step.actor)?;
                let id = chat::send_message(&space, cid, uid, text, 0).await?;
                self.world
                    .actor_mut(&step.actor)?
                    .memory
                    .channel_mut(cid)
                    .last_message_id = Some(id);
            }
            Action::EditLastMessage { text } => {
                let actor = self.world.actor(&step.actor)?;
                let cid = actor.current_channel_id;
                let id = actor
                    .memory
                    .channel(cid)
                    .last_message_id
                    .ok_or_else(|| anyhow!("no remembered message to edit"))?;
                let space = actor.space.clone();
                if !chat::edit_message(&space, id, text).await? {
                    return Err(anyhow!("edit_message reported no rows changed"));
                }
            }
            Action::DeleteLastMessage => {
                let actor = self.world.actor(&step.actor)?;
                let cid = actor.current_channel_id;
                let id = actor
                    .memory
                    .channel(cid)
                    .last_message_id
                    .ok_or_else(|| anyhow!("no remembered message to delete"))?;
                let space = actor.space.clone();
                if !chat::delete_message(&space, id).await? {
                    return Err(anyhow!("delete_message reported no rows changed"));
                }
                self.world
                    .actor_mut(&step.actor)?
                    .memory
                    .channel_mut(cid)
                    .last_message_id = None;
            }
            Action::ReplyToLast { text } => {
                let (space, cid, uid) = self.cur(&step.actor)?;
                let parent = chat::load_messages(&space, cid)
                    .await?
                    .into_iter()
                    .rfind(|m| m.thread_id == 0)
                    .and_then(|m| m.id);
                let Some(parent) = parent else {
                    log::debug!("[harness] reply_to_last skipped (no parent message)");
                    return Ok(());
                };
                let id = chat::send_message(&space, cid, uid, text, parent).await?;
                self.world
                    .actor_mut(&step.actor)?
                    .memory
                    .channel_mut(cid)
                    .last_message_id = Some(id);
            }
            Action::ToggleReactionOnLast { emoji } => {
                let (space, cid, uid) = self.cur(&step.actor)?;
                let target = chat::load_messages(&space, cid)
                    .await?
                    .into_iter()
                    .last()
                    .and_then(|m| m.id);
                let Some(target) = target else {
                    log::debug!("[harness] toggle_reaction_on_last skipped (no message)");
                    return Ok(());
                };
                chat::set_reaction(&space, cid, target, uid, emoji).await?;
            }
            Action::AddTask { title } => {
                let cid = self.world.actor(&step.actor)?.current_channel_id;
                let channel = self.current_channel(&step.actor).await?;
                let item = tasks::add_task(&channel.tasks, title).await?;
                self.world
                    .actor_mut(&step.actor)?
                    .memory
                    .channel_mut(cid)
                    .last_task_key = Some(item.key);
            }
            Action::ToggleLastTask => {
                let actor = self.world.actor(&step.actor)?;
                let cid = actor.current_channel_id;
                let key = actor
                    .memory
                    .channel(cid)
                    .last_task_key
                    .clone()
                    .ok_or_else(|| anyhow!("no remembered task to toggle"))?;
                let channel = self.current_channel(&step.actor).await?;
                tasks::toggle_task(&channel.tasks, &key).await?;
            }
            Action::UpdateLastTaskTitle { title } => {
                let actor = self.world.actor(&step.actor)?;
                let cid = actor.current_channel_id;
                let key = actor
                    .memory
                    .channel(cid)
                    .last_task_key
                    .clone()
                    .ok_or_else(|| anyhow!("no remembered task to update"))?;
                let channel = self.current_channel(&step.actor).await?;
                tasks::update_task_title(&channel.tasks, &key, title).await?;
            }
            Action::DeleteLastTask => {
                let actor = self.world.actor(&step.actor)?;
                let cid = actor.current_channel_id;
                let key = actor
                    .memory
                    .channel(cid)
                    .last_task_key
                    .clone()
                    .ok_or_else(|| anyhow!("no remembered task to delete"))?;
                let channel = self.current_channel(&step.actor).await?;
                tasks::delete_task(&channel.tasks, &key).await?;
                self.world
                    .actor_mut(&step.actor)?
                    .memory
                    .channel_mut(cid)
                    .last_task_key = None;
            }
            Action::AddCalendarEvent {
                start_time,
                end_time,
                title,
                description,
            } => {
                let space = self.world.actor(&step.actor)?.space.clone();
                let event =
                    calendar::add_event(&space, *start_time, *end_time, title, description).await?;
                self.world
                    .actor_mut(&step.actor)?
                    .memory
                    .last_calendar_event_id = event.id;
            }
            Action::UpdateLastCalendarEvent {
                start_time,
                end_time,
                title,
                description,
            } => {
                let id = self
                    .world
                    .actor(&step.actor)?
                    .memory
                    .last_calendar_event_id
                    .ok_or_else(|| anyhow!("no remembered calendar event"))?;
                let space = self.world.actor(&step.actor)?.space.clone();
                if !calendar::update_event(&space, id, *start_time, *end_time, title, description)
                    .await?
                {
                    return Err(anyhow!("update_event reported no rows changed"));
                }
            }
            Action::DeleteLastCalendarEvent => {
                let id = self
                    .world
                    .actor(&step.actor)?
                    .memory
                    .last_calendar_event_id
                    .ok_or_else(|| anyhow!("no remembered calendar event"))?;
                let space = self.world.actor(&step.actor)?.space.clone();
                if !calendar::delete_event(&space, id).await? {
                    return Err(anyhow!("delete_event reported no rows changed"));
                }
                self.world
                    .actor_mut(&step.actor)?
                    .memory
                    .last_calendar_event_id = None;
            }
            Action::NotesInsert { pos, text } => {
                let channel = self.current_channel(&step.actor).await?;
                notes::notes_insert(&channel.notes, *pos, text).await?;
            }
            Action::NotesDelete { pos, count } => {
                let channel = self.current_channel(&step.actor).await?;
                notes::notes_delete(&channel.notes, *pos, *count).await?;
            }
            Action::UploadFile {
                parent_id,
                name,
                content,
            } => {
                let actor = self.world.actor(&step.actor)?;
                let space = actor.space.clone();
                let author_id = actor.user_id;
                let pending = vec![PendingFile {
                    data: content.clone().into_bytes(),
                    filename: name.clone(),
                    mime_type: "application/octet-stream".to_string(),
                }];
                let mut uploaded =
                    files::upload_files(&space, *parent_id, author_id, pending).await?;
                let id = uploaded
                    .pop()
                    .and_then(|i| i.id)
                    .ok_or_else(|| anyhow!("upload_files returned no inode id"))?;
                self.world.actor_mut(&step.actor)?.memory.last_inode_id = Some(id);
            }
            Action::CreateFolder { parent_id, name } => {
                let actor = self.world.actor(&step.actor)?;
                let space = actor.space.clone();
                let author_id = actor.user_id;
                let inode = files::create_folder(&space, *parent_id, author_id, name).await?;
                let id = inode
                    .id
                    .ok_or_else(|| anyhow!("create_folder returned no inode id"))?;
                self.world.actor_mut(&step.actor)?.memory.last_inode_id = Some(id);
            }
            Action::RenameLastInode { name } => {
                let actor = self.world.actor(&step.actor)?;
                let id = actor
                    .memory
                    .last_inode_id
                    .ok_or_else(|| anyhow!("no remembered inode to rename"))?;
                let space = actor.space.clone();
                if !files::rename_inode(&space, id, name).await? {
                    return Err(anyhow!("rename_inode reported no rows changed"));
                }
            }
            Action::MoveLastInode { new_parent_id } => {
                let actor = self.world.actor(&step.actor)?;
                let id = actor
                    .memory
                    .last_inode_id
                    .ok_or_else(|| anyhow!("no remembered inode to move"))?;
                let space = actor.space.clone();
                if !files::move_inode(&space, id, *new_parent_id).await? {
                    return Err(anyhow!("move_inode reported no rows changed"));
                }
            }
            Action::DeleteLastInode => {
                let actor = self.world.actor(&step.actor)?;
                let id = actor
                    .memory
                    .last_inode_id
                    .ok_or_else(|| anyhow!("no remembered inode to delete"))?;
                let space = actor.space.clone();
                if !files::delete_inode_recursive(&space, id).await? {
                    return Err(anyhow!("delete_inode_recursive removed nothing"));
                }
                self.world.actor_mut(&step.actor)?.memory.last_inode_id = None;
            }
            Action::ReadLastFile => {
                let actor = self.world.actor(&step.actor)?;
                let id = actor
                    .memory
                    .last_inode_id
                    .ok_or_else(|| anyhow!("no remembered inode to read"))?;
                let space = actor.space.clone();
                let bytes = files::download_file(&space, id).await?;
                self.world.actor_mut(&step.actor)?.memory.last_file_bytes = Some(bytes);
            }
            Action::RemoveUser { target } => {
                self.world.remove_user_actor(&step.actor, target).await?;
            }
            Action::SaveSnapshot { slot } => {
                self.world.save_snapshot(&step.actor, slot).await?;
            }
            Action::RestoreSnapshot { slot } => {
                self.world.restore_snapshot(&step.actor, slot).await?;
            }
            Action::Sync => {
                self.world.actor(&step.actor)?.space.sync().await?;
            }
            Action::SyncAll => {
                self.world.sync_all().await?;
            }
        }

        if self.auto_sync && step.action.mutates() {
            self.world.sync_all().await?;
        }

        self.trace.push(step.clone());
        Ok(())
    }

    fn cur(&self, actor_name: &str) -> Result<(std::sync::Arc<Space>, i64, i64)> {
        let actor = self.world.actor(actor_name)?;
        Ok((actor.space.clone(), actor.current_channel_id, actor.user_id))
    }

    /// Reload the actor's current channel row (yielding fresh `tasks` / `notes`
    /// handles bound to the latest state).
    async fn current_channel(&self, actor_name: &str) -> Result<chat::Channel> {
        let actor = self.world.actor(actor_name)?;
        actor
            .space
            .table::<chat::Channel>("channels")
            .select()
            .where_eq("id", actor.current_channel_id)
            .first()
            .await?
            .ok_or_else(|| anyhow!("current channel {} not found", actor.current_channel_id))
    }
}

impl Action {
    /// Whether this action writes to space state (and therefore other
    /// actors should re-sync to observe it).
    ///
    /// `SaveSnapshot` is a pure read; `RestoreSnapshot` only swaps the
    /// actor's local `Space` handle and writes nothing to the backend;
    /// `ReadLastFile` is a pure read. None need a follow-up `sync_all`.
    pub fn mutates(&self) -> bool {
        !matches!(
            self,
            Action::Sync
                | Action::SyncAll
                | Action::SaveSnapshot { .. }
                | Action::RestoreSnapshot { .. }
                | Action::ReadLastFile
        )
    }
}
