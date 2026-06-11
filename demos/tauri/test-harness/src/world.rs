//! [`World`] — shared state across all [`Actor`]s in a scenario.
//!
//! Owns the in-process [`LocalTransport`] and the application schema, plus
//! a registry of named actors and stashed invites.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use encrypted_spaces_sdk::{
    ApplicationSchema, LocalTransport, Schema, Space, SpaceInvite, UserStatus,
};

use encrypted_spaces_demo::chat::{self, set_user_name};

use crate::actor::Actor;

/// Shared state for a scenario run.
pub struct World {
    pub schemas: Vec<Schema>,
    /// Actions parsed out of the demo schema bundle.  Each newly
    /// constructed `Space` registers them locally so the codegen-emitted
    /// action methods (`send_message`, `delete_message`, ...) can be
    /// dispatched.
    pub actions: Vec<encrypted_spaces_acl_types::Action>,
    pub commitment: [u8; 32],
    pub transport: LocalTransport,
    pub actors: HashMap<String, Actor>,
    /// Invites awaiting a `Join` step, keyed by inviter name.
    pub pending_invites: HashMap<String, SpaceInvite>,
    /// Snapshots produced by `SaveSnapshot { slot }`. Each entry is the raw
    /// JSON the actor's `Space::export_snapshot` returned, so a later
    /// `RestoreSnapshot { slot }` can rebuild a fresh `Space` from it.
    pub snapshots: HashMap<String, serde_json::Value>,
}

impl World {
    /// Build a new world with the Tauri demo's application schema loaded.
    /// Suitable for both scripted scenarios and fuzzing.
    pub async fn new() -> Result<Self> {
        // Tests / harness always use RISC0 dev mode.
        std::env::set_var("RISC0_DEV_MODE", "1");

        let text = std::str::from_utf8(encrypted_spaces_demo::APP_SCHEMA_BYTES)
            .map_err(|e| anyhow!("embedded schema is not utf-8: {e}"))?;
        let bundle = encrypted_spaces_sdk::testing::parse_schema_bundle(text)
            .map_err(|e| anyhow!("invalid embedded schema: {e}"))?;
        let schemas: Vec<Schema> = bundle
            .tables
            .iter()
            .filter_map(|t| t.schema.clone())
            .collect();
        let actions = bundle.actions.clone();
        let only_via = bundle.acl_only_via_actions.clone();

        let transport = LocalTransport::new(&schemas, None, Some(10_000)).await?;
        // `LocalTransport::new` initializes table schemas + ACL
        // predicates; actions and action-gating need an explicit
        // import so the resulting root matches what the SDK sees.
        transport
            .import_actions(&actions, &only_via)
            .await
            .map_err(|e| anyhow!("import_actions failed: {e}"))?;

        let commitment = transport.get_root_hash().await?;

        Ok(Self {
            schemas,
            actions,
            commitment,
            transport,
            actors: HashMap::new(),
            pending_invites: HashMap::new(),
            snapshots: HashMap::new(),
        })
    }

    /// Register the demo actions on a newly created or restored
    /// `Space`.  `ApplicationSchema::for_testing` uses the explicit-
    /// schemas variant which doesn't carry actions, so callers seed
    /// them after the fact.
    fn register_demo_actions(&self, space: &Space) {
        for action in &self.actions {
            space.register_action(action.clone());
        }
    }

    /// Build the [`ApplicationSchema`] bundle used by `Space::create`/`join`.
    pub fn app_schema(&self) -> ApplicationSchema {
        ApplicationSchema::for_testing(self.schemas.clone(), self.commitment)
    }

    /// Create the founding actor: bootstraps a fresh `Space`, sets the
    /// actor's name in `users_meta`, and creates an initial channel.
    pub async fn create_founder(&mut self, actor_name: &str, channel_name: &str) -> Result<()> {
        if self.actors.contains_key(actor_name) {
            return Err(anyhow!("actor `{actor_name}` already exists"));
        }
        let space = Space::create(self.transport.clone(), self.app_schema()).await?;
        self.register_demo_actions(&space);
        let user_id = space.uid().ok_or_else(|| anyhow!("founder has no uid"))? as i64;
        set_user_name(&space, user_id, actor_name).await?;
        let channel_id = chat::get_or_create_channel(&space, channel_name).await?;

        let actor = Actor::new(
            actor_name.to_string(),
            user_id,
            Arc::new(space),
            channel_id,
            channel_name.to_string(),
        );
        self.actors.insert(actor_name.to_string(), actor);
        Ok(())
    }

    /// `inviter` produces a `SpaceInvite` for `invitee` and stashes it.
    pub async fn invite(&mut self, inviter: &str, invitee: &str) -> Result<()> {
        let space = self.actor(inviter)?.space.clone();
        let invite = space.invite_user().await?;
        // Sanity: the invitee record should exist as Provisional.
        debug_assert_eq!(invite.status(), UserStatus::Provisional);
        if self.pending_invites.contains_key(invitee) {
            return Err(anyhow!(
                "an invite for `{invitee}` is already pending; consume it via Join first"
            ));
        }
        self.pending_invites.insert(invitee.to_string(), invite);
        Ok(())
    }

    /// `invitee` joins the space using the previously stashed invite, then
    /// switches into `channel_name` (creating it if missing).
    pub async fn join(&mut self, invitee: &str, channel_name: &str) -> Result<()> {
        if self.actors.contains_key(invitee) {
            return Err(anyhow!("actor `{invitee}` has already joined"));
        }
        let invite = self
            .pending_invites
            .remove(invitee)
            .ok_or_else(|| anyhow!("no pending invite for `{invitee}`"))?;

        let transport = self.transport.clone();
        let space = Space::join(transport, invite, self.app_schema()).await?;
        self.register_demo_actions(&space);
        let user_id = space
            .uid()
            .ok_or_else(|| anyhow!("invitee has no uid after join"))? as i64;
        set_user_name(&space, user_id, invitee).await?;
        let channel_id = chat::get_or_create_channel(&space, channel_name).await?;

        let actor = Actor::new(
            invitee.to_string(),
            user_id,
            Arc::new(space),
            channel_id,
            channel_name.to_string(),
        );
        self.actors.insert(invitee.to_string(), actor);
        Ok(())
    }

    pub fn actor(&self, name: &str) -> Result<&Actor> {
        self.actors
            .get(name)
            .ok_or_else(|| anyhow!("unknown actor `{name}`"))
    }

    pub fn actor_mut(&mut self, name: &str) -> Result<&mut Actor> {
        self.actors
            .get_mut(name)
            .ok_or_else(|| anyhow!("unknown actor `{name}`"))
    }

    /// `remover` evicts `target` from the space (by actor name). The
    /// target's `Space` is invalidated by the rekey, so we drop them from
    /// `actors` — subsequent steps that name them will fail with "unknown
    /// actor", matching the application's expectation that a removed user
    /// can no longer participate.
    pub async fn remove_user_actor(&mut self, remover: &str, target: &str) -> Result<()> {
        if remover == target {
            return Err(anyhow!("actor `{remover}` cannot remove themselves"));
        }
        let target_uid = self.actor(target)?.user_id;
        let space = self.actor(remover)?.space.clone();
        space.remove_user(target_uid).await?;
        self.actors.remove(target);
        Ok(())
    }

    /// Export the actor's `Space` state and stash it under `slot`.
    pub async fn save_snapshot(&mut self, actor_name: &str, slot: &str) -> Result<()> {
        let space = self.actor(actor_name)?.space.clone();
        let value = space.snapshot().await?;
        self.snapshots.insert(slot.to_string(), value);
        Ok(())
    }

    /// Replace `actor_name`'s `Space` with one rebuilt from the snapshot
    /// previously stored at `slot`. Per-action memory (last_message_id,
    /// last_task_key, last_inode_id, last_calendar_event_id) is reset; the
    /// channel-id bookkeeping is preserved on the assumption the channel
    /// row still exists on the backend.
    pub async fn restore_snapshot(&mut self, actor_name: &str, slot: &str) -> Result<()> {
        use encrypted_spaces_sdk::Space;
        let snapshot = self
            .snapshots
            .get(slot)
            .cloned()
            .ok_or_else(|| anyhow!("no snapshot saved at slot `{slot}`"))?;
        let new_space = Space::restore(self.transport.clone(), snapshot).await?;
        self.register_demo_actions(&new_space);
        let actor = self.actor_mut(actor_name)?;
        actor.space = Arc::new(new_space);
        actor.memory = Default::default();
        Ok(())
    }

    /// Sync every actor's state. Called between steps in scripted runs so
    /// "B sees A's write" semantics are deterministic.
    pub async fn sync_all(&self) -> Result<()> {
        for actor in self.actors.values() {
            actor.space.sync().await?;
        }
        Ok(())
    }

    pub fn actor_names(&self) -> Vec<String> {
        let mut v: Vec<String> = self.actors.keys().cloned().collect();
        v.sort();
        v
    }
}
