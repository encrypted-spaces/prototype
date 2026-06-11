use std::collections::HashMap;
use std::io::Write;
use std::sync::{Arc, Mutex};

use tauri::{AppHandle, Emitter, Manager, State};

use encrypted_spaces_sdk::{
    load_trust_cert, List, Space, SpaceInvite, TextArea, WebSocketTransport,
};

use crate::broadcast::{start_broadcast_listener, start_ephemeral_listener};
use crate::chat;
use crate::files;
use crate::state::{self, AppState, UserInfo};

/// Shared handle to the optional log file, managed by Tauri.
pub struct LogFile(pub Option<Arc<Mutex<std::fs::File>>>);

/// Retry an SDK write once on `parent_clc mismatch` (concurrent write by
/// another client caused a stale table commitment). Syncs first, then retries.
macro_rules! with_clc_retry {
    ($space:expr, $label:expr, $op:expr) => {
        match $op.await {
            Ok(v) => Ok(v),
            Err(e) if e.to_string().contains("parent_clc mismatch") => {
                log::warn!("[{}] parent_clc mismatch, syncing and retrying", $label);
                $space
                    .sync()
                    .await
                    .map_err(|e| format!("sync failed: {e}"))?;
                $op.await.map_err(|e| format!("{e}"))
            }
            Err(e) => Err(format!("{e}")),
        }
    };
}

fn snapshot_path(app_handle: &AppHandle) -> Result<std::path::PathBuf, String> {
    let dir = app_handle
        .path()
        .app_data_dir()
        .map_err(|e| format!("failed to get app data dir: {e}"))?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("failed to create app data dir: {e}"))?;
    Ok(dir.join("chat_snapshot.json"))
}

async fn init_space_common(
    app_handle: &AppHandle,
    app_state: &AppState,
    space: Space,
    user_name: &str,
    channel_name: &str,
) -> Result<UserInfo, String> {
    let space = Arc::new(space);

    let uid = space.uid().unwrap() as i64;

    // Insert users_meta for this user if not already present
    let existing_meta: Option<chat::UsersMeta> = space
        .table::<chat::UsersMeta>("users_meta")
        .select()
        .where_eq("id", uid)
        .first()
        .await
        .unwrap_or(None);
    if existing_meta.is_none() {
        chat::set_user_name(&space, uid, user_name)
            .await
            .map_err(|e| format!("set user name failed: {e}"))?;
    }

    let channel_id = chat::get_or_create_channel(&space, channel_name)
        .await
        .map_err(|e| format!("channel creation failed: {e}"))?;

    // Select the channel row to get the hydrated TextArea from it.
    let channel: chat::Channel = space
        .table::<chat::Channel>("channels")
        .select()
        .where_eq("id", channel_id)
        .first()
        .await
        .map_err(|e| format!("channel select failed: {e}"))?
        .ok_or("channel not found after creation")?;

    let user_info = UserInfo {
        user_id: uid,
        user_name: user_name.to_string(),
        ws_address: String::new(),
        current_channel_id: channel_id,
        current_channel_name: channel_name.to_string(),
    };

    start_broadcast_listener(app_handle.clone(), Arc::clone(&space));

    let ephemeral_rx = space
        .subscribe_ephemeral()
        .map_err(|e| format!("subscribe ephemeral failed: {e}"))?;
    start_ephemeral_listener(app_handle.clone(), ephemeral_rx);

    let snap_path = snapshot_path(app_handle)?;
    {
        let mut sp = app_state.snapshot_path.lock().await;
        *sp = Some(snap_path.clone());
    }
    {
        let mut s = app_state.space.lock().await;
        *s = Some(Arc::clone(&space));
    }
    {
        let mut p = app_state.notes.lock().await;
        *p = Some(channel.notes);
    }
    {
        let mut u = app_state.user_info.lock().await;
        *u = Some(user_info.clone());
    }

    start_periodic_save(app_handle.clone());

    Ok(user_info)
}

fn start_periodic_save(app_handle: AppHandle) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            let app_state = app_handle.state::<AppState>();
            let space_guard = app_state.space.lock().await;
            let user_guard = app_state.user_info.lock().await;
            let path_guard = app_state.snapshot_path.lock().await;
            if let (Some(space), Some(info), Some(path)) = (
                space_guard.as_ref(),
                user_guard.as_ref(),
                path_guard.as_ref(),
            ) {
                let _ = state::save_snapshot(space, info, path).await;
            }
        }
    });
}

/// Build a `WebSocketTransport` honoring the optional `--trust-cert`
/// flag captured at startup. When no extra anchor was supplied the
/// transport falls back to the OS trust store, matching pre-feature
/// behavior.
async fn build_transport(
    state: &State<'_, AppState>,
    ws_address: &str,
) -> Result<WebSocketTransport, String> {
    let connector = match state.trust_cert_path.as_ref() {
        Some(path) => Some(
            load_trust_cert(path).map_err(|e| format!("--trust-cert {}: {e}", path.display()))?,
        ),
        None => None,
    };
    WebSocketTransport::new_with_trust_connector(ws_address, connector)
        .await
        .map_err(|e| format!("transport init failed: {e}"))
}

// ─── Initialization Commands ─────────────────────────────────────────────────

#[tauri::command]
pub async fn check_snapshot(app_handle: AppHandle) -> Result<bool, String> {
    let path = snapshot_path(&app_handle)?;
    Ok(path.exists())
}

#[tauri::command]
pub async fn create_space(
    app_handle: AppHandle,
    state: State<'_, AppState>,
    ws_address: String,
    username: String,
    channel_name: String,
) -> Result<UserInfo, String> {
    let transport = build_transport(&state, &ws_address)
        .await
        .map_err(|e| format!("connection failed: {e}"))?;
    let space = Space::create(transport, crate::sdk_codegen::application_schema())
        .await
        .map_err(|e| format!("space creation failed: {e}"))?;

    let mut info = init_space_common(&app_handle, &state, space, &username, &channel_name).await?;
    info.ws_address = ws_address;

    {
        let mut u = state.user_info.lock().await;
        *u = Some(info.clone());
    }

    Ok(info)
}

#[tauri::command]
pub async fn join_space(
    app_handle: AppHandle,
    state: State<'_, AppState>,
    ws_address: String,
    invite_json: String,
    username: String,
    channel_name: String,
) -> Result<UserInfo, String> {
    let invite: SpaceInvite =
        serde_json::from_str(&invite_json).map_err(|e| format!("invalid invite: {e}"))?;

    let transport = build_transport(&state, &ws_address)
        .await
        .map_err(|e| format!("connection failed: {e}"))?;
    let space = Space::join(transport, invite, crate::sdk_codegen::application_schema())
        .await
        .map_err(|e| format!("space join failed: {e}"))?;

    let mut info = init_space_common(&app_handle, &state, space, &username, &channel_name).await?;
    info.ws_address = ws_address;

    {
        let mut u = state.user_info.lock().await;
        *u = Some(info.clone());
    }

    Ok(info)
}

#[tauri::command]
pub async fn restore_space(
    app_handle: AppHandle,
    state: State<'_, AppState>,
) -> Result<UserInfo, String> {
    let path = snapshot_path(&app_handle)?;
    let snapshot = state::load_snapshot(&path)
        .await
        .map_err(|e| format!("snapshot load failed: {e}"))?;

    let ws_address = snapshot.user_info.ws_address.clone();
    let transport = build_transport(&state, &ws_address)
        .await
        .map_err(|e| format!("connection failed: {e}"))?;

    let space = Space::restore(transport, snapshot.space_snapshot)
        .await
        .map_err(|e| format!("space restore failed: {e}"))?;

    let info = init_space_common(
        &app_handle,
        &state,
        space,
        &snapshot.user_info.user_name,
        &snapshot.user_info.current_channel_name,
    )
    .await?;

    let restored = UserInfo { ws_address, ..info };
    {
        let mut u = state.user_info.lock().await;
        *u = Some(restored.clone());
    }

    Ok(restored)
}

// ─── Logout Command ─────────────────────────────────────────────────────────

#[tauri::command]
pub async fn logout(app_handle: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    {
        let space_guard = state.space.lock().await;
        let user_guard = state.user_info.lock().await;
        let path_guard = state.snapshot_path.lock().await;
        if let (Some(space), Some(info), Some(path)) = (
            space_guard.as_ref(),
            user_guard.as_ref(),
            path_guard.as_ref(),
        ) {
            let _ = state::save_snapshot(space, info, path).await;
        }
    }
    {
        let mut s = state.space.lock().await;
        *s = None;
    }
    {
        let mut p = state.notes.lock().await;
        *p = None;
    }
    {
        let mut u = state.user_info.lock().await;
        *u = None;
    }
    app_handle
        .emit("logout", ())
        .map_err(|e| format!("emit failed: {e}"))?;
    Ok(())
}

// ─── Channel Commands ────────────────────────────────────────────────────────

#[tauri::command]
pub async fn get_channels(state: State<'_, AppState>) -> Result<Vec<chat::Channel>, String> {
    let space = {
        let guard = state.space.lock().await;
        Arc::clone(guard.as_ref().ok_or("space not initialized")?)
    };
    chat::load_channels(&space)
        .await
        .map_err(|e| format!("load channels failed: {e}"))
}

#[tauri::command]
pub async fn create_channel(
    state: State<'_, AppState>,
    name: String,
) -> Result<chat::Channel, String> {
    let space = {
        let guard = state.space.lock().await;
        Arc::clone(guard.as_ref().ok_or("space not initialized")?)
    };

    let channel_id = chat::get_or_create_channel(&space, &name)
        .await
        .map_err(|e| format!("create channel failed: {e}"))?;

    Ok(chat::Channel {
        id: Some(channel_id),
        name,
        description: None,
        tasks: List::empty(),
        notes: TextArea::empty(),
    })
}

#[tauri::command]
pub async fn update_channel_description(
    state: State<'_, AppState>,
    channel_id: i64,
    description: Option<String>,
) -> Result<bool, String> {
    let space = {
        let guard = state.space.lock().await;
        Arc::clone(guard.as_ref().ok_or("space not initialized")?)
    };
    chat::update_channel_description(&space, channel_id, description)
        .await
        .map_err(|e| format!("update channel description failed: {e}"))
}

#[tauri::command]
pub async fn switch_channel(
    state: State<'_, AppState>,
    channel_id: i64,
    channel_name: String,
) -> Result<(), String> {
    // Update the notes TextArea for the new channel.
    let channel = {
        let space = state.space.lock().await;
        let space = space.as_ref().ok_or("space not initialized")?;
        space
            .table::<chat::Channel>("channels")
            .select()
            .where_eq("id", channel_id)
            .first()
            .await
            .map_err(|e| format!("channel select failed: {e}"))?
            .ok_or("channel not found")?
    };
    {
        let mut p = state.notes.lock().await;
        *p = Some(channel.notes);
    }
    let mut user_guard = state.user_info.lock().await;
    let user = user_guard.as_mut().ok_or("user not initialized")?;
    user.current_channel_id = channel_id;
    user.current_channel_name = channel_name;
    Ok(())
}

// ─── Message Commands ────────────────────────────────────────────────────────

#[tauri::command]
pub async fn get_messages(
    state: State<'_, AppState>,
    channel_id: i64,
) -> Result<Vec<chat::MessageWithUser>, String> {
    let space = {
        let guard = state.space.lock().await;
        Arc::clone(guard.as_ref().ok_or("space not initialized")?)
    };
    chat::load_messages(&space, channel_id)
        .await
        .map_err(|e| format!("load messages failed: {e}"))
}

#[tauri::command]
pub async fn get_thread_messages(
    state: State<'_, AppState>,
    thread_id: i64,
) -> Result<Vec<chat::MessageWithUser>, String> {
    let space = {
        let guard = state.space.lock().await;
        Arc::clone(guard.as_ref().ok_or("space not initialized")?)
    };
    chat::load_thread_messages(&space, thread_id)
        .await
        .map_err(|e| format!("load thread messages failed: {e}"))
}

#[tauri::command]
pub async fn send_message(
    state: State<'_, AppState>,
    channel_id: i64,
    content: String,
    thread_id: i64,
) -> Result<i64, String> {
    let space = {
        let guard = state.space.lock().await;
        Arc::clone(guard.as_ref().ok_or("space not initialized")?)
    };
    let user_id = {
        let user_guard = state.user_info.lock().await;
        user_guard.as_ref().ok_or("user not initialized")?.user_id
    };
    chat::send_message(&space, channel_id, user_id, &content, thread_id)
        .await
        .map_err(|e| format!("send message failed: {e}"))
}

#[tauri::command]
pub async fn edit_message(
    state: State<'_, AppState>,
    message_id: i64,
    content: String,
) -> Result<bool, String> {
    let space = {
        let guard = state.space.lock().await;
        Arc::clone(guard.as_ref().ok_or("space not initialized")?)
    };
    chat::edit_message(&space, message_id, &content)
        .await
        .map_err(|e| format!("edit message failed: {e}"))
}

#[tauri::command]
pub async fn delete_message(state: State<'_, AppState>, message_id: i64) -> Result<bool, String> {
    let space = {
        let guard = state.space.lock().await;
        Arc::clone(guard.as_ref().ok_or("space not initialized")?)
    };
    chat::delete_message(&space, message_id)
        .await
        .map_err(|e| format!("delete message failed: {e}"))
}

// ─── Reaction Commands ───────────────────────────────────────────────────────

#[tauri::command]
pub async fn get_reactions(
    state: State<'_, AppState>,
    channel_id: i64,
) -> Result<HashMap<i64, HashMap<String, chat::ReactionInfo>>, String> {
    let space = {
        let guard = state.space.lock().await;
        Arc::clone(guard.as_ref().ok_or("space not initialized")?)
    };
    chat::load_reaction_details(&space, channel_id)
        .await
        .map_err(|e| format!("load reactions failed: {e}"))
}

#[tauri::command]
pub async fn toggle_reaction(
    state: State<'_, AppState>,
    message_id: i64,
    emoji: String,
) -> Result<String, String> {
    let space = {
        let guard = state.space.lock().await;
        Arc::clone(guard.as_ref().ok_or("space not initialized")?)
    };
    let (user_id, channel_id) = {
        let user_guard = state.user_info.lock().await;
        let user = user_guard.as_ref().ok_or("user not initialized")?;
        (user.user_id, user.current_channel_id)
    };
    let change = chat::set_reaction(&space, channel_id, message_id, user_id, &emoji)
        .await
        .map_err(|e| format!("set reaction failed: {e}"))?;
    match change {
        chat::ReactionChange::Added => Ok("added".into()),
        chat::ReactionChange::Removed => Ok("removed".into()),
    }
}

// ─── Invite Commands ─────────────────────────────────────────────────────────

#[tauri::command]
pub async fn invite_user(state: State<'_, AppState>) -> Result<String, String> {
    let space = {
        let guard = state.space.lock().await;
        Arc::clone(guard.as_ref().ok_or("space not initialized")?)
    };
    let invite = space
        .invite_user()
        .await
        .map_err(|e| format!("invite failed: {e}"))?;
    serde_json::to_string_pretty(&invite).map_err(|e| format!("serialize invite failed: {e}"))
}

#[tauri::command]
pub async fn export_invite_to_file(
    app_handle: AppHandle,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let space = {
        let guard = state.space.lock().await;
        Arc::clone(guard.as_ref().ok_or("space not initialized")?)
    };
    let invite = space
        .invite_user()
        .await
        .map_err(|e| format!("invite failed: {e}"))?;
    let invite_json =
        serde_json::to_string_pretty(&invite).map_err(|e| format!("serialize failed: {e}"))?;

    use tauri_plugin_dialog::DialogExt;
    let (tx, rx) = tokio::sync::oneshot::channel();
    app_handle
        .dialog()
        .file()
        .add_filter("JSON", &["json"])
        .set_file_name("invite.json")
        .save_file(move |path| {
            let _ = tx.send(path);
        });

    let file_path = rx.await.map_err(|_| "dialog error".to_string())?;
    if let Some(path) = file_path {
        let p = path.as_path().ok_or("invalid path")?;
        std::fs::write(p, &invite_json).map_err(|e| format!("write failed: {e}"))?;
        Ok(p.to_string_lossy().to_string())
    } else {
        Err("save cancelled".into())
    }
}

// ─── User Commands ──────────────────────────────────────────────────────────

#[tauri::command]
pub async fn remove_user(state: State<'_, AppState>, user_id: i64) -> Result<(), String> {
    let space = {
        let guard = state.space.lock().await;
        Arc::clone(guard.as_ref().ok_or("space not initialized")?)
    };
    space
        .remove_user(user_id)
        .await
        .map_err(|e| format!("remove user failed: {e}"))
}

#[tauri::command]
pub async fn get_users(state: State<'_, AppState>) -> Result<Vec<chat::UserInfo>, String> {
    let space = {
        let guard = state.space.lock().await;
        Arc::clone(guard.as_ref().ok_or("space not initialized")?)
    };
    chat::get_users(&space)
        .await
        .map_err(|e| format!("get users failed: {e}"))
}

/// Get the current channel by selecting it from the table.
/// Returns the hydrated Channel with its List/TextArea fields ready to use.
async fn current_channel(state: &AppState) -> Result<chat::Channel, String> {
    let space = {
        let guard = state.space.lock().await;
        Arc::clone(guard.as_ref().ok_or("space not initialized")?)
    };
    let channel_id = {
        let guard = state.user_info.lock().await;
        guard
            .as_ref()
            .ok_or("user info not initialized")?
            .current_channel_id
    };
    space
        .table::<chat::Channel>("channels")
        .select()
        .where_eq("id", channel_id)
        .first()
        .await
        .map_err(|e| format!("channel select failed: {e}"))?
        .ok_or_else(|| "current channel not found".to_string())
}

// ─── Task List Commands ─────────────────────────────────────────────────────

#[tauri::command]
pub async fn get_tasks(state: State<'_, AppState>) -> Result<Vec<crate::tasks::TaskItem>, String> {
    let channel = current_channel(&state).await?;
    crate::tasks::load_tasks(&channel.tasks)
        .await
        .map_err(|e| format!("load tasks failed: {e}"))
}

#[tauri::command]
pub async fn add_task(
    state: State<'_, AppState>,
    title: String,
) -> Result<crate::tasks::TaskItem, String> {
    let channel = current_channel(&state).await?;
    crate::tasks::add_task(&channel.tasks, &title)
        .await
        .map_err(|e| format!("add task failed: {e}"))
}

#[tauri::command]
pub async fn toggle_task(state: State<'_, AppState>, key: String) -> Result<bool, String> {
    let channel = current_channel(&state).await?;
    crate::tasks::toggle_task(&channel.tasks, &key)
        .await
        .map_err(|e| format!("toggle task failed: {e}"))
}

#[tauri::command]
pub async fn update_task_title(
    state: State<'_, AppState>,
    key: String,
    title: String,
) -> Result<(), String> {
    let channel = current_channel(&state).await?;
    crate::tasks::update_task_title(&channel.tasks, &key, &title)
        .await
        .map_err(|e| format!("update task title failed: {e}"))
}

#[tauri::command]
pub async fn delete_task(state: State<'_, AppState>, key: String) -> Result<(), String> {
    let channel = current_channel(&state).await?;
    crate::tasks::delete_task(&channel.tasks, &key)
        .await
        .map_err(|e| format!("delete task failed: {e}"))
}

// ─── Shared Notes Commands ─────────────────────────────────────────────────────

#[tauri::command]
pub async fn get_notes(state: State<'_, AppState>) -> Result<String, String> {
    let guard = state.notes.lock().await;
    let doc = guard.as_ref().ok_or("notes not initialized")?;
    crate::notes::get_notes_text(doc)
        .await
        .map_err(|e| format!("get notes failed: {e}"))
}

#[tauri::command]
pub async fn notes_insert(
    state: State<'_, AppState>,
    pos: usize,
    text: String,
) -> Result<(), String> {
    let guard = state.notes.lock().await;
    let doc = guard.as_ref().ok_or("notes not initialized")?;
    crate::notes::notes_insert(doc, pos, &text)
        .await
        .map_err(|e| format!("notes insert failed: {e}"))
}

#[tauri::command]
pub async fn notes_delete(
    state: State<'_, AppState>,
    pos: usize,
    count: usize,
) -> Result<(), String> {
    let guard = state.notes.lock().await;
    let doc = guard.as_ref().ok_or("notes not initialized")?;
    crate::notes::notes_delete(doc, pos, count)
        .await
        .map_err(|e| format!("notes delete failed: {e}"))
}

// ─── Attachments ────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn send_message_with_attachments(
    state: State<'_, AppState>,
    channel_id: i64,
    content: String,
    file_paths: Vec<String>,
    thread_id: i64,
) -> Result<i64, String> {
    let space = {
        let guard = state.space.lock().await;
        Arc::clone(guard.as_ref().ok_or("space not initialized")?)
    };
    let user_id = {
        let user_guard = state.user_info.lock().await;
        user_guard.as_ref().ok_or("user not initialized")?.user_id
    };

    const MAX_FILE_SIZE: u64 = 50 * 1024 * 1024; // 50 MiB, matches server limit

    let mut files = Vec::new();
    for path in &file_paths {
        let metadata =
            std::fs::metadata(path).map_err(|e| format!("failed to read file {path}: {e}"))?;
        if metadata.len() > MAX_FILE_SIZE {
            let size_mb = metadata.len() as f64 / (1024.0 * 1024.0);
            return Err(format!(
                "File too large: {} is {:.1} MB (max 50 MB)",
                std::path::Path::new(path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(path),
                size_mb
            ));
        }
        let data = std::fs::read(path).map_err(|e| format!("failed to read file {path}: {e}"))?;
        let filename = std::path::Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();
        let mime_type = mime_from_extension(&filename);
        files.push(chat::PendingAttachment {
            data,
            filename,
            mime_type,
        });
    }

    chat::send_message_with_attachments(&space, channel_id, user_id, &content, thread_id, files)
        .await
        .map_err(|e| format!("send message with attachments failed: {e}"))
}

#[tauri::command]
pub async fn get_attachments(
    state: State<'_, AppState>,
    message_id: i64,
) -> Result<Vec<chat::Attachment>, String> {
    let space = {
        let guard = state.space.lock().await;
        Arc::clone(guard.as_ref().ok_or("space not initialized")?)
    };
    chat::get_attachments(&space, message_id)
        .await
        .map_err(|e| format!("get attachments failed: {e}"))
}

#[tauri::command]
pub async fn download_file(
    app_handle: AppHandle,
    state: State<'_, AppState>,
    hash: String,
) -> Result<Vec<u8>, String> {
    // Check disk cache first
    let cache_dir = file_cache_dir(&app_handle)?;
    let cached_path = cache_dir.join(&hash);
    if cached_path.exists() {
        return std::fs::read(&cached_path).map_err(|e| format!("failed to read cached file: {e}"));
    }

    // Download and decrypt from server
    let space = {
        let guard = state.space.lock().await;
        Arc::clone(guard.as_ref().ok_or("space not initialized")?)
    };
    let data = files::download_file_by_hash(&space, &hash)
        .await
        .map_err(|e| format!("download file failed: {e}"))?;

    // Write to disk cache (best-effort)
    let _ = std::fs::write(&cached_path, &data);

    Ok(data)
}

fn file_cache_dir(app_handle: &AppHandle) -> Result<std::path::PathBuf, String> {
    let dir = app_handle
        .path()
        .app_data_dir()
        .map_err(|e| format!("failed to get app data dir: {e}"))?
        .join("file_cache");
    std::fs::create_dir_all(&dir).map_err(|e| format!("failed to create file cache dir: {e}"))?;
    Ok(dir)
}

fn mime_from_extension(filename: &str) -> String {
    let ext = filename.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "bmp" => "image/bmp",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "ogg" => "audio/ogg",
        "flac" => "audio/flac",
        "aac" => "audio/aac",
        "m4a" => "audio/mp4",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mov" => "video/quicktime",
        "pdf" => "application/pdf",
        "txt" => "text/plain",
        "json" => "application/json",
        "zip" => "application/zip",
        "gz" | "tar" => "application/gzip",
        _ => "application/octet-stream",
    }
    .to_string()
}

// ─── Calendar Commands ──────────────────────────────────────────────────────

#[tauri::command]
pub async fn get_calendar_events(
    state: State<'_, AppState>,
) -> Result<Vec<crate::calendar::CalendarEvent>, String> {
    let space = {
        let guard = state.space.lock().await;
        Arc::clone(guard.as_ref().ok_or("space not initialized")?)
    };
    crate::calendar::load_events(&space)
        .await
        .map_err(|e| format!("load calendar events failed: {e}"))
}

#[tauri::command]
pub async fn add_calendar_event(
    state: State<'_, AppState>,
    start_time: i64,
    end_time: i64,
    title: String,
    description: String,
) -> Result<crate::calendar::CalendarEvent, String> {
    let space = {
        let guard = state.space.lock().await;
        Arc::clone(guard.as_ref().ok_or("space not initialized")?)
    };
    with_clc_retry!(
        space,
        "calendar",
        crate::calendar::add_event(&space, start_time, end_time, &title, &description)
    )
}

#[tauri::command]
pub async fn update_calendar_event(
    state: State<'_, AppState>,
    event_id: i64,
    start_time: i64,
    end_time: i64,
    title: String,
    description: String,
) -> Result<bool, String> {
    let space = {
        let guard = state.space.lock().await;
        Arc::clone(guard.as_ref().ok_or("space not initialized")?)
    };
    with_clc_retry!(
        space,
        "calendar",
        crate::calendar::update_event(&space, event_id, start_time, end_time, &title, &description,)
    )
}

#[tauri::command]
pub async fn delete_calendar_event(
    state: State<'_, AppState>,
    event_id: i64,
) -> Result<bool, String> {
    let space = {
        let guard = state.space.lock().await;
        Arc::clone(guard.as_ref().ok_or("space not initialized")?)
    };
    with_clc_retry!(
        space,
        "calendar",
        crate::calendar::delete_event(&space, event_id)
    )
}

// ─── Inodes (Files & Folders) Commands ───────────────────────────────────────

#[tauri::command]
pub async fn list_inodes(
    state: State<'_, AppState>,
    parent_id: i64,
) -> Result<Vec<crate::files::InodeWithAuthor>, String> {
    let space = {
        let guard = state.space.lock().await;
        Arc::clone(guard.as_ref().ok_or("space not initialized")?)
    };
    crate::files::list_children(&space, parent_id)
        .await
        .map_err(|e| format!("list inodes failed: {e}"))
}

#[tauri::command]
pub async fn upload_inodes(
    state: State<'_, AppState>,
    file_paths: Vec<String>,
    parent_id: i64,
) -> Result<Vec<crate::files::Inode>, String> {
    let space = {
        let guard = state.space.lock().await;
        Arc::clone(guard.as_ref().ok_or("space not initialized")?)
    };
    let author_id = {
        let user_guard = state.user_info.lock().await;
        user_guard.as_ref().ok_or("user not initialized")?.user_id
    };

    const MAX_FILE_SIZE: u64 = 50 * 1024 * 1024; // 50 MiB

    let mut pending = Vec::new();
    for path in &file_paths {
        let metadata =
            std::fs::metadata(path).map_err(|e| format!("failed to read file {path}: {e}"))?;
        if metadata.len() > MAX_FILE_SIZE {
            let size_mb = metadata.len() as f64 / (1024.0 * 1024.0);
            return Err(format!(
                "File too large: {} is {:.1} MB (max 50 MB)",
                std::path::Path::new(path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(path),
                size_mb
            ));
        }
        let data = std::fs::read(path).map_err(|e| format!("failed to read file {path}: {e}"))?;
        let filename = std::path::Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();
        let mime_type = mime_from_extension(&filename);
        pending.push(crate::files::PendingFile {
            data,
            filename,
            mime_type,
        });
    }

    match crate::files::upload_files(&space, parent_id, author_id, pending).await {
        Ok(inodes) => Ok(inodes),
        Err(e) if e.to_string().contains("parent_clc mismatch") => {
            log::warn!("[inodes] upload: parent_clc mismatch, syncing and retrying");
            space
                .sync()
                .await
                .map_err(|e| format!("sync failed: {e}"))?;
            // Re-read files for retry
            let mut pending2 = Vec::new();
            for path in &file_paths {
                let data =
                    std::fs::read(path).map_err(|e| format!("failed to read file {path}: {e}"))?;
                let filename = std::path::Path::new(path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string();
                let mime_type = mime_from_extension(&filename);
                pending2.push(crate::files::PendingFile {
                    data,
                    filename,
                    mime_type,
                });
            }
            crate::files::upload_files(&space, parent_id, author_id, pending2)
                .await
                .map_err(|e| format!("upload inodes failed after retry: {e}"))
        }
        Err(e) => Err(format!("upload inodes failed: {e}")),
    }
}

#[tauri::command]
pub async fn create_folder_inode(
    state: State<'_, AppState>,
    parent_id: i64,
    name: String,
) -> Result<crate::files::Inode, String> {
    let space = {
        let guard = state.space.lock().await;
        Arc::clone(guard.as_ref().ok_or("space not initialized")?)
    };
    let author_id = {
        let user_guard = state.user_info.lock().await;
        user_guard.as_ref().ok_or("user not initialized")?.user_id
    };
    with_clc_retry!(
        space,
        "inodes",
        crate::files::create_folder(&space, parent_id, author_id, &name)
    )
}

#[tauri::command]
pub async fn delete_inode(state: State<'_, AppState>, inode_id: i64) -> Result<bool, String> {
    let space = {
        let guard = state.space.lock().await;
        Arc::clone(guard.as_ref().ok_or("space not initialized")?)
    };
    with_clc_retry!(
        space,
        "inodes",
        crate::files::delete_inode_recursive(&space, inode_id)
    )
}

#[tauri::command]
pub async fn move_inode(
    state: State<'_, AppState>,
    inode_id: i64,
    new_parent_id: i64,
) -> Result<bool, String> {
    let space = {
        let guard = state.space.lock().await;
        Arc::clone(guard.as_ref().ok_or("space not initialized")?)
    };
    with_clc_retry!(
        space,
        "inodes",
        crate::files::move_inode(&space, inode_id, new_parent_id)
    )
}

#[tauri::command]
pub async fn rename_inode(
    state: State<'_, AppState>,
    inode_id: i64,
    new_name: String,
) -> Result<bool, String> {
    let space = {
        let guard = state.space.lock().await;
        Arc::clone(guard.as_ref().ok_or("space not initialized")?)
    };
    with_clc_retry!(
        space,
        "inodes",
        crate::files::rename_inode(&space, inode_id, &new_name)
    )
}

// ─── Settings ────────────────────────────────────────────────────────────────

#[tauri::command]
pub fn get_default_zoom(state: State<'_, AppState>) -> u32 {
    state.default_zoom
}

// ─── Ephemeral Messaging ─────────────────────────────────────────────────────

#[tauri::command]
pub async fn send_ephemeral(
    state: State<'_, AppState>,
    kind: String,
    payload: String,
) -> Result<(), String> {
    let space = {
        let guard = state.space.lock().await;
        Arc::clone(guard.as_ref().ok_or("space not initialized")?)
    };
    space
        .send_ephemeral(&kind, payload.as_bytes())
        .await
        .map_err(|e| format!("send ephemeral failed: {e}"))
}

// ─── Frontend Logging ────────────────────────────────────────────────────────

#[tauri::command]
pub fn log_message(log_file: State<'_, LogFile>, level: String, message: String) {
    // Always log via the Rust logger (shows in stderr / tee)
    match level.as_str() {
        "error" => log::error!("[frontend] {message}"),
        "warn" => log::warn!("[frontend] {message}"),
        "info" => log::info!("[frontend] {message}"),
        _ => log::debug!("[frontend] {message}"),
    }
    // Also write directly to the log file (in case RUST_LOG filters it out)
    if let Some(ref file) = log_file.0 {
        if let Ok(mut f) = file.lock() {
            let ts = chrono::Local::now().format("%H:%M:%S%.3f");
            let _ = writeln!(f, "{ts} [{level}] [frontend] {message}");
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn app_schema_bytes_parse() {
        let text =
            std::str::from_utf8(crate::APP_SCHEMA_BYTES).expect("APP_SCHEMA_BYTES should be UTF-8");
        let bundle = encrypted_spaces_sdk::testing::parse_schema_bundle(text)
            .expect("APP_SCHEMA_BYTES should parse as valid KDL");
        assert!(
            !bundle.tables.is_empty(),
            "Schema bundle should contain at least one table"
        );
    }
}
