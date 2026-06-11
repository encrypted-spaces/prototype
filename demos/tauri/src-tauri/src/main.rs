#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use encrypted_spaces_demo::{commands, state};
use encrypted_spaces_sdk::load_trust_cert;
use state::AppState;
use tauri::menu::{MenuBuilder, MenuItemBuilder, SubmenuBuilder};
use tauri::{Emitter, Manager};

/// A writer that tees output to stdout and an optional log file.
struct TeeWriter {
    file: Option<Arc<Mutex<std::fs::File>>>,
}

impl Write for TeeWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::io::stdout().write_all(buf)?;
        if let Some(ref file) = self.file {
            if let Ok(mut f) = file.lock() {
                let _ = f.write_all(buf);
            }
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stdout().flush()?;
        if let Some(ref file) = self.file {
            if let Ok(mut f) = file.lock() {
                let _ = f.flush();
            }
        }
        Ok(())
    }
}

fn main() {
    // Parse --logfile=<path> from command-line arguments
    let logfile_path =
        std::env::args().find_map(|arg| arg.strip_prefix("--logfile=").map(|v| v.to_string()));

    let log_file: Option<Arc<Mutex<std::fs::File>>> = logfile_path.as_ref().and_then(|path| {
        std::fs::File::create(path)
            .map(|f| Arc::new(Mutex::new(f)))
            .map_err(|e| eprintln!("Warning: could not create logfile {path}: {e}"))
            .ok()
    });

    let tee = TeeWriter {
        file: log_file.clone(),
    };
    env_logger::Builder::from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    )
    .target(env_logger::Target::Pipe(Box::new(tee)))
    .init();

    if let Some(ref path) = logfile_path {
        log::info!("[main] Logging to file: {path}");
    }

    // Parse --default-zoom=N from command-line arguments
    let default_zoom = std::env::args()
        .find_map(|arg| {
            arg.strip_prefix("--default-zoom=")
                .and_then(|v| v.parse::<u32>().ok())
        })
        .unwrap_or(100)
        .clamp(50, 200);

    // Pick up an extra TLS trust anchor from `--trust-cert=<path>` or
    // the `ENCRYPTED_SPACES_TRUST_CERT` env var. The anchor is added to the
    // OS trust store rather than replacing it, so a dev/test self-signed
    // server cert can be reached over `wss://` / HTTPS without disabling
    // chain or hostname validation. The actual cert loading happens on
    // each WebSocket connect in `commands::build_transport`; we do a
    // one-shot startup probe here so the operator sees an audit log of
    // what got loaded *before* any network activity.
    //
    // Both the CLI flag and the env var take a single path; the CLI
    // flag wins if both are set. The env var is needed under `tauri
    // dev` because that CLI forwards extra tokens to `cargo run`
    // (between `cargo run` and its `--`), so `--trust-cert=...` would
    // be parsed by cargo, not by this binary.
    //
    // Note on cwd: under `tauri dev` the binary's working directory is
    // `<repo>/demos/tauri/src-tauri/`, not whatever the user typed the
    // command from. To make the audit log self-describing (so an
    // operator can see exactly which file we attempted to read) we
    // resolve the trust path to its absolute form before anything else.
    // `std::path::absolute` does not require the file to exist, so a
    // missing file is still reported with the full resolved location
    // instead of the original (potentially misleading) relative form.
    let resolve = |p: PathBuf| -> PathBuf { std::path::absolute(&p).unwrap_or(p) };
    let trust_cert_path: Option<PathBuf> = std::env::args()
        .find_map(|arg| arg.strip_prefix("--trust-cert=").map(PathBuf::from))
        .or_else(|| std::env::var_os("ENCRYPTED_SPACES_TRUST_CERT").map(PathBuf::from))
        .filter(|p| !p.as_os_str().is_empty())
        .map(resolve);
    if let Some(ref path) = trust_cert_path {
        match load_trust_cert(path) {
            Ok(_) => log::info!("[main] extra TLS trust anchor loaded: {}", path.display()),
            Err(e) => log::warn!("[main] --trust-cert {} rejected: {e}", path.display()),
        }
    }

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .manage(commands::LogFile(log_file))
        .manage(AppState::new(default_zoom, trust_cert_path))
        .setup(|app| {
            let logout_item = MenuItemBuilder::with_id("logout", "Logout / Switch Space")
                .accelerator("CmdOrCtrl+Shift+L")
                .build(app)?;

            let file_menu = SubmenuBuilder::new(app, "File")
                .item(&logout_item)
                .separator()
                .close_window()
                .build()?;

            let zoom_in_item = MenuItemBuilder::with_id("zoom_in", "Zoom In")
                .accelerator("CmdOrCtrl+=")
                .build(app)?;
            let zoom_out_item = MenuItemBuilder::with_id("zoom_out", "Zoom Out")
                .accelerator("CmdOrCtrl+-")
                .build(app)?;
            let zoom_reset_item = MenuItemBuilder::with_id("zoom_reset", "Reset Zoom")
                .accelerator("CmdOrCtrl+0")
                .build(app)?;

            let edit_menu = SubmenuBuilder::new(app, "Edit")
                .undo()
                .redo()
                .separator()
                .cut()
                .copy()
                .paste()
                .select_all()
                .separator()
                .item(&zoom_in_item)
                .item(&zoom_out_item)
                .item(&zoom_reset_item)
                .build()?;

            let menu = MenuBuilder::new(app)
                .item(&file_menu)
                .item(&edit_menu)
                .build()?;
            app.set_menu(menu)?;

            let handle = app.handle().clone();
            app.on_menu_event(move |_app, event| {
                let id = event.id().as_ref();
                match id {
                    "zoom_in" | "zoom_out" | "zoom_reset" => {
                        let _ = handle.emit(id, ());
                    }
                    "logout" => {
                        let h = handle.clone();
                        tauri::async_runtime::spawn(async move {
                            let app_state = h.state::<AppState>();
                            // Save before logout
                            {
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
                            // Clear state
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
                            let _ = h.emit("logout", ());
                        });
                    }
                    _ => {}
                }
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::check_snapshot,
            commands::create_space,
            commands::join_space,
            commands::restore_space,
            commands::logout,
            commands::get_channels,
            commands::create_channel,
            commands::update_channel_description,
            commands::switch_channel,
            commands::get_messages,
            commands::get_thread_messages,
            commands::send_message,
            commands::edit_message,
            commands::delete_message,
            commands::get_reactions,
            commands::toggle_reaction,
            commands::invite_user,
            commands::export_invite_to_file,
            commands::get_users,
            commands::get_tasks,
            commands::add_task,
            commands::toggle_task,
            commands::update_task_title,
            commands::delete_task,
            commands::get_notes,
            commands::notes_insert,
            commands::notes_delete,
            commands::remove_user,
            commands::send_message_with_attachments,
            commands::get_attachments,
            commands::download_file,
            commands::get_calendar_events,
            commands::add_calendar_event,
            commands::update_calendar_event,
            commands::delete_calendar_event,
            commands::list_inodes,
            commands::upload_inodes,
            commands::delete_inode,
            commands::move_inode,
            commands::rename_inode,
            commands::create_folder_inode,
            commands::get_default_zoom,
            commands::send_ephemeral,
            commands::log_message,
        ])
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                let handle = window.app_handle().clone();
                tauri::async_runtime::block_on(async {
                    let app_state = handle.state::<AppState>();
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
                });
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
