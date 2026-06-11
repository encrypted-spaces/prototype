use std::sync::Arc;

use encrypted_spaces_sdk::{BroadcastEvent, EphemeralEvent, OpType, Space, USERS_TABLE_NAME};
use encrypted_spaces_storage_encoding::keys::{parse_key, ParsedKey};
use tauri::{AppHandle, Emitter, Manager};

use crate::state::AppState;

/// Check whether a broadcast event is removing the current user from the space.
///
/// `build_remove_user` in the SDK emits one `Column` entry per non-id column
/// of the `_users` row being deleted, plus entries from `_key_history` and
/// retention writes. Match on `_users` column keys whose `row_id` equals the
/// current uid; the table filter avoids false positives from other tables
/// that happen to write the same row_id.
fn is_current_user_removed(evt: &BroadcastEvent, space: &Space) -> bool {
    if evt.change.entry.message.op_type != OpType::RemoveUser {
        return false;
    }
    let Some(my_uid) = space.uid() else {
        return false;
    };
    evt.change
        .entry
        .message
        .entries
        .iter()
        .any(|entry| match parse_key(&entry.key) {
            Ok(ParsedKey::Column { table, row_id, .. }) => {
                table == USERS_TABLE_NAME && row_id == my_uid as i64
            }
            _ => false,
        })
}

pub fn start_broadcast_listener(app_handle: AppHandle, space: Arc<Space>) {
    let mut rx = space.subscribe_updates();
    tokio::spawn(async move {
        while let Ok(evt) = rx.recv().await {
            if is_current_user_removed(&evt, &space) {
                // Clear app state (same cleanup as the logout command)
                let app_state = app_handle.state::<AppState>();
                {
                    let mut s = app_state.space.lock().await;
                    *s = None;
                }
                {
                    let mut p = app_state.notes.lock().await;
                    *p = None;
                }
                {
                    let mut u = app_state.user_info.lock().await;
                    *u = None;
                }
                let _ = app_handle.emit("logout", ());
                return; // Stop listening — we're no longer a member
            }

            log::debug!("[broadcast] emitting space-updated");
            let _ = app_handle.emit("space-updated", ());
        }
    });
}

/// Forward ephemeral events from the WebSocket to the frontend.
/// Each event is emitted as a Tauri event named "ephemeral:{kind}".
pub fn start_ephemeral_listener(
    app_handle: AppHandle,
    mut rx: tokio::sync::broadcast::Receiver<EphemeralEvent>,
) {
    tokio::spawn(async move {
        while let Ok(evt) = rx.recv().await {
            let event_name = format!("ephemeral:{}", evt.kind);
            let _ = app_handle.emit(&event_name, &evt);
        }
    });
}
