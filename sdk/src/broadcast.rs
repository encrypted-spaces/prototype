use std::sync::Arc;

use encrypted_spaces_changelog_core::changelog::OpType;

use crate::changelog::BroadcastApplyOutcome;
use crate::websocket_transport::BroadcastEvent;
use crate::Space;

/// Spawn the broadcast listener for this Space.
///
/// Subscribes to transport-level broadcast events, drives each one through
/// [`Space::handle_broadcast`] (signature verification, change application,
/// cache update), then republishes the applied event on the Space's
/// `updates_tx` channel for app consumers.
///
/// Holds a `Weak<dyn Transport>` and re-constructs a temporary `Space` only
/// while processing an event, so the task does not pin the transport. When
/// the user's last `Space` is dropped, the transport drops, `bcast_tx`
/// drops, `rx.recv()` returns `RecvError::Closed`, and the loop exits.
pub(crate) fn start_listener(space: &Space) {
    let mut rx = match space.transport.subscribe_broadcasts() {
        Ok(rx) => rx,
        Err(_) => return,
    };
    let id = space.id();
    let weak_transport = Arc::downgrade(&space.transport);
    let state = Arc::clone(&space.state);
    let key_manager = Arc::clone(&space.key_manager);
    let updates_tx = space.updates_tx.clone();
    let serialize_mutations = Arc::clone(&space.serialize_mutations);
    let ff_in_progress = Arc::clone(&space.ff_in_progress);
    tokio::spawn(async move {
        use tokio::sync::broadcast::error::RecvError;
        loop {
            match rx.recv().await {
                Ok(evt) => {
                    let Some(transport) = weak_transport.upgrade() else {
                        break;
                    };
                    let space = Space {
                        id,
                        transport,
                        state: Arc::clone(&state),
                        key_manager: Arc::clone(&key_manager),
                        updates_tx: updates_tx.clone(),
                        serialize_mutations: Arc::clone(&serialize_mutations),
                        ff_in_progress: Arc::clone(&ff_in_progress),
                    };
                    space.handle_broadcast(evt.clone()).await;
                    drop(space);
                    let _ = updates_tx.send(evt);
                }
                Err(RecvError::Closed) => break,
                Err(RecvError::Lagged(n)) => log::warn!("broadcast listener lagged by {n}"),
            }
        }
    });
}

impl Space {
    /// Drive a broadcast event through the SDK pipeline: delegate the
    /// changelog-side apply to [`Space::apply_broadcast_change`], then
    /// update caches and run the post-apply delivery-slot recovery.
    pub(crate) async fn handle_broadcast(&self, evt: BroadcastEvent) {
        let BroadcastEvent {
            change,
            change_response,
        } = evt;
        let op_type = change.entry.message.op_type;

        // Conservative delivery-slot trigger: ask the SpaceKey whether this
        // op type may need a post-apply slot fetch. The sync tri-state
        // short-circuits cheaply when no fresh group key was introduced.
        let needs_slot_check = crate::SpaceKeyManager::op_may_need_delivery(op_type);

        match self.apply_broadcast_change(change, change_response).await {
            BroadcastApplyOutcome::Skipped => return,
            BroadcastApplyOutcome::Applied { change, writes } => {
                self.apply_broadcast_cache_updates(&change, &writes).await;
            }
            BroadcastApplyOutcome::AppliedCacheInvalidated => {}
        }

        // A failure here means the local HGK is now stale relative to the
        // broadcast; log loudly so it does not pass silently.
        if let Err(e) = self
            .post_apply_delivery_slot_recovery(needs_slot_check)
            .await
        {
            log::warn!(
                "[SDK] handle_broadcast: GK sync failed after {:?} broadcast: {}",
                op_type,
                e
            );
        }
    }

    pub(crate) async fn apply_broadcast_cache_updates(
        &self,
        change: &encrypted_spaces_changelog_core::changelog::Change,
        writes: &[encrypted_spaces_changelog_core::BatchOp],
    ) {
        // Reduce prunes old retention keys — data encrypted with those
        // keys can no longer be decrypted, so just purge all cached
        // plaintext rather than spending time updating it.
        if change.entry.message.op_type == OpType::Reduce {
            self.with_state_mut(|state| state.cache.clear_all());
            return;
        }

        crate::cache::update_cache_from_proven_writes(self, change, writes).await;
    }
}
