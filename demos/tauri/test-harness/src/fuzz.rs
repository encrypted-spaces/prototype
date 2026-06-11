//! Seeded random scenario generator.
//!
//! The fuzzer maintains a *symbolic* model of which actors exist, who has
//! been invited, and what each actor has recently done — so it only emits
//! actions that are valid given the current state. This avoids drowning real
//! bugs in noise from trivially-illegal sequences (e.g. "Bob joins" before
//! anyone invited him).
//!
//! Actions are picked by weighted choice; weights are tunable via
//! [`FuzzConfig`].

use std::collections::{HashMap, HashSet};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

// rand 0.9 renamed: gen_bool -> random_bool, gen_range -> random_range,
// gen -> random. We use the new names throughout.

use crate::action::{Action, Scenario, Step};

/// Boxed builder used by the weighted-choice menu in [`FuzzGenerator`].
/// Aliased to keep clippy's `type_complexity` lint happy.
type ActionBuilder = Box<dyn FnOnce(&mut FuzzGenerator) -> Action>;

/// Tunable weights and bounds for [`FuzzGenerator`].
#[derive(Debug, Clone)]
pub struct FuzzConfig {
    /// Maximum number of distinct actors. Names: alice, bob, charlie, ...
    pub max_actors: usize,
    /// Minimum number of actors before fuzzing starts emitting non-invite
    /// actions in earnest.
    pub min_actors: usize,
    /// How many steps to generate.
    pub steps: usize,
    /// PRNG seed, for reproducibility.
    pub seed: u64,
    /// Probability (0..1) of inviting + joining when below `max_actors`.
    pub invite_probability: f64,
    /// Probability (0..1) of `SyncAll` between content actions, to keep
    /// the model deterministic. Set to 1.0 by `auto_sync` callers; lower
    /// values stress eventual-consistency paths.
    pub sync_all_probability: f64,
}

impl Default for FuzzConfig {
    fn default() -> Self {
        Self {
            max_actors: 4,
            min_actors: 2,
            steps: 50,
            seed: 0,
            invite_probability: 0.15,
            sync_all_probability: 0.05,
        }
    }
}

const ACTOR_POOL: &[&str] = &[
    "alice", "bob", "charlie", "dave", "eve", "frank", "grace", "heidi",
];

const CHANNEL_POOL: &[&str] = &["general", "engineering", "design", "random"];

const EMOJI_POOL: &[&str] = &["thumbsup", "heart", "fire", "tada", "eyes"];

/// Per-channel symbolic state. The runner is the source of truth; this is
/// just enough to gate "is `EditLastMessage` legal in the channel the actor
/// is currently viewing?".
#[derive(Debug, Default, Clone)]
struct ChannelState {
    has_message: bool,
    has_task: bool,
    notes_len: usize,
    /// Whether this actor's `last_message_id` (in this channel) points to a
    /// top-level message rather than a reply. Deleting a reply does not
    /// reduce the channel's top-level message count, so we need to know.
    last_is_top_level: bool,
}

/// Symbolic state mirrored alongside the real run so we only emit valid
/// actions. Kept tiny on purpose; the [`crate::Runner`] holds the
/// authoritative state.
///
/// Channel-scoped state (messages, tasks, notes) is keyed by channel name so
/// that a `SwitchChannel` correctly restores per-channel "last X" eligibility
/// when the actor returns. Calendar events and inodes are space-wide.
#[derive(Debug, Default, Clone)]
struct ModelActor {
    /// Channel the actor is currently "viewing". `""` means uninitialized
    /// (will be set on `CreateSpace` / `Join`).
    current_channel: String,
    channels: HashMap<String, ChannelState>,
    has_calendar_event: bool,
    has_inode: bool,
    /// Whether `has_inode` refers to a file (vs. a folder). Folders share
    /// the same `inodes` table but their `file_hash` is a sentinel — only
    /// files can be downloaded, so `ReadLastFile` is gated on this.
    last_inode_is_file: bool,
    has_snapshot: bool,
}

impl ModelActor {
    fn cur(&self) -> ChannelState {
        self.channels
            .get(&self.current_channel)
            .cloned()
            .unwrap_or_default()
    }

    fn cur_mut(&mut self) -> &mut ChannelState {
        self.channels
            .entry(self.current_channel.clone())
            .or_default()
    }
}

#[derive(Debug, Clone, Default)]
struct Model {
    actors: HashMap<String, ModelActor>,
    pending_invites: HashSet<String>,
    /// Per-channel count of top-level (non-reply) messages, summed across
    /// all actors. Gates `ReplyToLast` and `ToggleReactionOnLast`: when the
    /// count is zero the runner finds no parent and silently no-ops, which
    /// would leave the symbolic model out of sync with `last_message_id`.
    top_level_messages: HashMap<String, usize>,
}

impl Model {
    fn live_actors(&self) -> Vec<String> {
        let mut v: Vec<String> = self.actors.keys().cloned().collect();
        v.sort();
        v
    }
}

/// Seeded random scenario generator.
pub struct FuzzGenerator {
    rng: StdRng,
    config: FuzzConfig,
    model: Model,
}

impl FuzzGenerator {
    pub fn new(config: FuzzConfig) -> Self {
        Self {
            rng: StdRng::seed_from_u64(config.seed),
            config,
            model: Model::default(),
        }
    }

    /// Generate a complete scenario.
    pub fn generate(mut self) -> Scenario {
        let mut steps: Vec<Step> = Vec::with_capacity(self.config.steps);

        // Always start with a CreateSpace by alice.
        let founder = ACTOR_POOL[0].to_string();
        let initial_channel = CHANNEL_POOL[0].to_string();
        steps.push(Step {
            actor: founder.clone(),
            action: Action::CreateSpace {
                channel: initial_channel.clone(),
            },
        });
        let founder_model = ModelActor {
            current_channel: initial_channel,
            ..Default::default()
        };
        self.model.actors.insert(founder, founder_model);

        while steps.len() < self.config.steps {
            if let Some(step) = self.gen_step() {
                steps.push(step);
            }
        }

        Scenario { steps }
    }

    fn gen_step(&mut self) -> Option<Step> {
        // Periodic global sync.
        if self.rng.random_bool(self.config.sync_all_probability) {
            // Use any live actor; SyncAll ignores the actor field semantically.
            let actor = self.pick_actor()?;
            return Some(Step {
                actor,
                action: Action::SyncAll,
            });
        }

        // Try to invite + grow the actor set.
        if self.model.actors.len() < self.config.max_actors
            && self.rng.random_bool(self.config.invite_probability)
        {
            return self.gen_invite_or_join();
        }

        // Below the warm-up threshold, push for more invites first.
        if self.model.actors.len() < self.config.min_actors {
            return self.gen_invite_or_join();
        }

        let actor_name = self.pick_actor()?;
        let action = self.pick_content_action(&actor_name)?;
        Some(Step {
            actor: actor_name,
            action,
        })
    }

    fn gen_invite_or_join(&mut self) -> Option<Step> {
        // If there's a pending invite, prefer joining (consume it).
        if !self.model.pending_invites.is_empty() {
            let invitee = self.model.pending_invites.iter().next().cloned().unwrap();
            self.model.pending_invites.remove(&invitee);
            let inviter = self.pick_actor().unwrap_or_else(|| "alice".into());
            let channel = CHANNEL_POOL[self.rng.random_range(0..CHANNEL_POOL.len())].to_string();
            let joined = ModelActor {
                current_channel: channel.clone(),
                ..Default::default()
            };
            self.model.actors.insert(invitee.clone(), joined);
            return Some(Step {
                actor: invitee,
                action: Action::Join {
                    from: inviter,
                    channel,
                },
            });
        }

        // Otherwise, an existing actor invites a fresh name.
        let inviter = self.pick_actor()?;
        let invitee = self.next_unused_name()?;
        self.model.pending_invites.insert(invitee.clone());
        Some(Step {
            actor: inviter,
            action: Action::Invite { invitee },
        })
    }

    fn pick_content_action(&mut self, actor_name: &str) -> Option<Action> {
        // Build a weighted action menu based on what's currently legal.
        let m = self
            .model
            .actors
            .get(actor_name)
            .cloned()
            .unwrap_or_default();
        let cur_channel_name = m.current_channel.clone();
        let cur = m.cur();
        let any_msg_here = self
            .model
            .top_level_messages
            .get(&cur_channel_name)
            .copied()
            .unwrap_or(0)
            > 0;

        // (weight, builder)
        let mut menu: Vec<(u32, ActionBuilder)> = Vec::new();

        menu.push((
            10,
            Box::new(|s| Action::SendMessage {
                text: s.gen_text("msg"),
            }),
        ));
        if any_msg_here {
            menu.push((
                4,
                Box::new(|s| Action::ReplyToLast {
                    text: s.gen_text("reply"),
                }),
            ));
            menu.push((
                3,
                Box::new(|s| Action::ToggleReactionOnLast {
                    emoji: EMOJI_POOL[s.rng.random_range(0..EMOJI_POOL.len())].into(),
                }),
            ));
        }
        if cur.has_message {
            menu.push((
                2,
                Box::new(|s| Action::EditLastMessage {
                    text: s.gen_text("edit"),
                }),
            ));
            menu.push((2, Box::new(|_| Action::DeleteLastMessage)));
        }

        menu.push((
            6,
            Box::new(|s| Action::AddTask {
                title: s.gen_text("task"),
            }),
        ));
        if cur.has_task {
            menu.push((3, Box::new(|_| Action::ToggleLastTask)));
            menu.push((
                2,
                Box::new(|s| Action::UpdateLastTaskTitle {
                    title: s.gen_text("task"),
                }),
            ));
            menu.push((1, Box::new(|_| Action::DeleteLastTask)));
        }

        menu.push((
            4,
            Box::new(|s| {
                let start = 1_700_000_000 + s.rng.random_range(0..86_400 * 30);
                Action::AddCalendarEvent {
                    start_time: start,
                    end_time: start + s.rng.random_range(900..7200),
                    title: s.gen_text("evt"),
                    description: s.gen_text("desc"),
                }
            }),
        ));
        if m.has_calendar_event {
            menu.push((
                2,
                Box::new(|s| {
                    let start = 1_700_000_000 + s.rng.random_range(0..86_400 * 30);
                    Action::UpdateLastCalendarEvent {
                        start_time: start,
                        end_time: start + 1800,
                        title: s.gen_text("evt"),
                        description: s.gen_text("desc"),
                    }
                }),
            ));
            menu.push((1, Box::new(|_| Action::DeleteLastCalendarEvent)));
        }

        menu.push((
            4,
            Box::new(move |s| Action::NotesInsert {
                pos: if cur.notes_len == 0 {
                    0
                } else {
                    s.rng.random_range(0..=cur.notes_len)
                },
                text: s.gen_text("note"),
            }),
        ));
        if cur.notes_len > 0 {
            menu.push((
                2,
                Box::new(move |s| {
                    let pos = s.rng.random_range(0..cur.notes_len);
                    let max = cur.notes_len - pos;
                    Action::NotesDelete {
                        pos,
                        count: s.rng.random_range(1..=max.max(1)),
                    }
                }),
            ));
        }

        // ── Files (always at root, parent_id = 0; keep symbolic state
        // simple and don't model folder hierarchy).
        menu.push((
            3,
            Box::new(|s| Action::UploadFile {
                parent_id: 0,
                name: format!("{}.bin", s.gen_text("file")),
                content: s.gen_text("data"),
            }),
        ));
        menu.push((
            2,
            Box::new(|s| Action::CreateFolder {
                parent_id: 0,
                name: s.gen_text("folder"),
            }),
        ));
        if m.has_inode {
            menu.push((
                2,
                Box::new(|s| Action::RenameLastInode {
                    name: s.gen_text("renamed"),
                }),
            ));
            menu.push((1, Box::new(|_| Action::DeleteLastInode)));
            if m.last_inode_is_file {
                menu.push((1, Box::new(|_| Action::ReadLastFile)));
            }
        }

        // ── Snapshots (lightweight: each actor uses their own name as
        // the slot; restoring rolls back to the last save).
        let actor_slot = actor_name.to_string();
        let actor_slot_save = actor_slot.clone();
        menu.push((
            1,
            Box::new(move |_| Action::SaveSnapshot {
                slot: actor_slot_save,
            }),
        ));
        if m.has_snapshot {
            let actor_slot_restore = actor_slot.clone();
            menu.push((
                1,
                Box::new(move |_| Action::RestoreSnapshot {
                    slot: actor_slot_restore,
                }),
            ));
        }

        // ── RemoveUser is destructive (drops the target from the world).
        // Only consider it when there are at least 3 live actors so the
        // scenario doesn't collapse to one, and never let `alice` (the
        // founder) be a target — losing her invalidates the world.
        let live = self.model.live_actors();
        let removable: Vec<String> = live
            .iter()
            .filter(|n| n.as_str() != actor_name && n.as_str() != "alice")
            .cloned()
            .collect();
        if live.len() >= 3 && !removable.is_empty() {
            menu.push((
                1,
                Box::new(move |s| {
                    let pick = &removable[s.rng.random_range(0..removable.len())];
                    Action::RemoveUser {
                        target: pick.clone(),
                    }
                }),
            ));
        }

        // Switch to a different channel from the configured pool. Emitted
        // with low weight so most steps still exercise the actor's current
        // channel deeply, but enough to cover stale-handle / cross-channel
        // races (the class of bug fixed in PR #1).
        if CHANNEL_POOL.len() > 1 {
            let cur_name = cur_channel_name.clone();
            menu.push((
                3,
                Box::new(move |s| {
                    // Pick any channel != current.
                    let candidates: Vec<&&str> = CHANNEL_POOL
                        .iter()
                        .filter(|c| **c != cur_name.as_str())
                        .collect();
                    let pick = candidates[s.rng.random_range(0..candidates.len())];
                    Action::SwitchChannel {
                        name: (*pick).to_string(),
                    }
                }),
            ));
        }

        let total: u32 = menu.iter().map(|(w, _)| *w).sum();
        if total == 0 {
            return None;
        }
        let mut pick = self.rng.random_range(0..total);
        let mut chosen: Option<ActionBuilder> = None;
        for (w, builder) in menu {
            if pick < w {
                chosen = Some(builder);
                break;
            }
            pick -= w;
        }
        let action = (chosen?)(self);

        // Update symbolic model.
        let m = self.model.actors.entry(actor_name.to_string()).or_default();
        match &action {
            Action::SendMessage { .. } => {
                let chan = m.current_channel.clone();
                {
                    let cur = m.cur_mut();
                    cur.has_message = true;
                    cur.last_is_top_level = true;
                }
                *self.model.top_level_messages.entry(chan).or_insert(0) += 1;
            }
            Action::ReplyToLast { .. } => {
                let cur = m.cur_mut();
                cur.has_message = true;
                cur.last_is_top_level = false;
            }
            Action::DeleteLastMessage => {
                let chan = m.current_channel.clone();
                let was_top_level = {
                    let cur = m.cur_mut();
                    let was = cur.last_is_top_level;
                    cur.has_message = false;
                    cur.last_is_top_level = false;
                    was
                };
                if was_top_level {
                    if let Some(c) = self.model.top_level_messages.get_mut(&chan) {
                        *c = c.saturating_sub(1);
                    }
                    // The runner's `chat::delete_message` cascade-deletes
                    // any thread replies of the deleted top-level message.
                    // We don't track which top-level each reply belongs to,
                    // so conservatively invalidate every other actor's
                    // remembered reply in this channel — their stale
                    // `last_message_id` may now point at a row that the
                    // cascade nuked. Drop `m`'s borrow first.
                    let _ = m;
                    for (other_name, other) in self.model.actors.iter_mut() {
                        if other_name == actor_name {
                            continue;
                        }
                        if let Some(cs) = other.channels.get_mut(&chan) {
                            if cs.has_message && !cs.last_is_top_level {
                                cs.has_message = false;
                            }
                        }
                    }
                }
            }
            Action::AddTask { .. } => m.cur_mut().has_task = true,
            Action::DeleteLastTask => m.cur_mut().has_task = false,
            Action::AddCalendarEvent { .. } => m.has_calendar_event = true,
            Action::DeleteLastCalendarEvent => m.has_calendar_event = false,
            Action::UploadFile { .. } => {
                m.has_inode = true;
                m.last_inode_is_file = true;
            }
            Action::CreateFolder { .. } => {
                m.has_inode = true;
                m.last_inode_is_file = false;
            }
            Action::DeleteLastInode => {
                m.has_inode = false;
                m.last_inode_is_file = false;
            }
            Action::SaveSnapshot { .. } => m.has_snapshot = true,
            Action::RestoreSnapshot { .. } => {
                // Rolling back invalidates per-channel "last X" memory in
                // the harness runner, so clear it here too.
                m.channels.clear();
                m.has_calendar_event = false;
                m.has_inode = false;
                m.last_inode_is_file = false;
            }
            Action::RemoveUser { target } => {
                // Drop `m`'s borrow on `self.model.actors` first so we can
                // mutate the map.
                let _ = m;
                self.model.actors.remove(target);
                self.model.pending_invites.remove(target);
            }
            Action::NotesInsert { text, .. } => {
                m.cur_mut().notes_len += text.chars().count();
            }
            Action::NotesDelete { count, .. } => {
                let cur = m.cur_mut();
                cur.notes_len = cur.notes_len.saturating_sub(*count);
            }
            Action::SwitchChannel { name } => {
                m.current_channel = name.clone();
            }
            _ => {}
        }
        Some(action)
    }

    fn pick_actor(&mut self) -> Option<String> {
        let actors = self.model.live_actors();
        if actors.is_empty() {
            return None;
        }
        let i = self.rng.random_range(0..actors.len());
        Some(actors[i].clone())
    }

    fn next_unused_name(&self) -> Option<String> {
        for &name in ACTOR_POOL {
            if !self.model.actors.contains_key(name) && !self.model.pending_invites.contains(name) {
                return Some(name.into());
            }
        }
        None
    }

    fn gen_text(&mut self, kind: &str) -> String {
        // Short, distinguishable, ASCII-only — easy on logs and notes math.
        format!("{kind}-{:04x}", self.rng.random::<u16>())
    }
}
