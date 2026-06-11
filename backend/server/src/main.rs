mod app_config;
mod db;
pub(crate) mod file_store;
mod http;
mod key_delivery;
mod tls;
mod websocket;

use crate::app_config::{AppConfig, CliArgs, ServerConfig};
use clap::Parser;
use http::handle_request;
use hyper::service::service_fn;
use std::io::IsTerminal;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

/// Receiver half of the shutdown watch. Cloned into every spawned task
/// that needs to react to SIGTERM/SIGINT; the value transitions from
/// `false` to `true` exactly once.
pub(crate) type ShutdownRx = watch::Receiver<bool>;

/// Maximum time we'll wait for in-flight WebSocket / TLS connections to
/// drain after the shutdown signal fires before forcibly returning from
/// `main` (and letting the runtime abort whatever's left). Real proofs
/// can take >10s in `add_change`, so callers running this image under
/// Docker should invoke `docker stop -t 60` (or larger) — anything
/// short of `--stop-timeout` plus this drain budget will SIGKILL
/// in-flight work.
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Print a fatal error to stderr in red when stderr is a TTY and `NO_COLOR`
/// is not set; otherwise print it plainly. See https://no-color.org/.
fn eprint_error(err: &(dyn std::error::Error + 'static)) {
    let use_color = std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    if use_color {
        eprintln!("\x1b[1;31mError:\x1b[0m {err}");
    } else {
        eprintln!("Error: {err}");
    }
}

#[tokio::main]
async fn main() {
    match run().await {
        Ok(()) => {
            // The tokio runtime, when dropped, waits for any
            // outstanding `spawn_blocking` task to finish. The
            // interactive stdin console loop (when stdin is a TTY) is
            // exactly that kind of task and can't be cancelled — it
            // sits forever in `stdin.lock().lines()`. Since `run()`
            // has already performed the orderly shutdown (drained WS
            // connections, dropped the SPACES map, etc.), it's safe
            // to terminate the process explicitly here so the
            // blocking thread doesn't keep the runtime alive
            // indefinitely after SIGTERM/SIGINT in interactive
            // sessions. In detached / non-TTY runs the loop isn't
            // spawned at all, so this is effectively a no-op there.
            std::process::exit(0);
        }
        Err(e) => {
            eprint_error(e.as_ref());
            std::process::exit(1);
        }
    }
}

/// Spawn a task that listens for SIGTERM / SIGINT (Unix) or Ctrl-C
/// (other platforms) and flips the shutdown watch to `true` on the
/// first signal. Returns the receiver to be cloned into consumers.
fn install_signal_handler() -> ShutdownRx {
    let (tx, rx) = watch::channel(false);
    tokio::spawn(async move {
        // Wait for the first shutdown-class signal. We rely on the
        // tokio signal driver rather than installing a raw libc handler
        // so the existing async accept loops can observe the change via
        // `watch::Receiver::changed()`.
        //
        // If signal installation fails (rare — fd exhaustion, seccomp
        // restrictions, or non-Linux quirks) we deliberately do NOT
        // return from this task. Returning would drop the watch sender
        // captured by this closure, causing every accept loop's
        // `shutdown_rx.changed()` to immediately resolve with `Err`,
        // making the server quit silently right after startup. Instead
        // we log and park forever; the operator can still kill the
        // container with SIGKILL.
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut term = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    log::error!(
                        "failed to install SIGTERM handler: {e}; \
                         graceful shutdown disabled, use SIGKILL to exit"
                    );
                    std::future::pending::<()>().await;
                    unreachable!();
                }
            };
            let mut int = match signal(SignalKind::interrupt()) {
                Ok(s) => s,
                Err(e) => {
                    log::error!(
                        "failed to install SIGINT handler: {e}; \
                         graceful shutdown disabled, use SIGKILL to exit"
                    );
                    std::future::pending::<()>().await;
                    unreachable!();
                }
            };
            tokio::select! {
                _ = term.recv() => log::info!("received SIGTERM, initiating graceful shutdown"),
                _ = int.recv()  => log::info!("received SIGINT, initiating graceful shutdown"),
            }
        }
        #[cfg(not(unix))]
        {
            if let Err(e) = tokio::signal::ctrl_c().await {
                log::error!(
                    "failed to install Ctrl-C handler: {e}; \
                     graceful shutdown disabled, use process termination to exit"
                );
                std::future::pending::<()>().await;
                unreachable!();
            }
            log::info!("received Ctrl-C, initiating graceful shutdown");
        }
        let _ = tx.send(true);
    });
    rx
}

async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::init();

    // Proof mode (dev vs real) is controlled by the `real-proofs` feature
    // in encrypted-spaces-ffproof.  See ensure_risc0_proof_mode().

    let cli = CliArgs::parse();
    let server_cfg = ServerConfig::from(&cli);
    let app_cfg = Arc::new(AppConfig::from_cli(&cli)?);
    crate::db::ensure_initialized(app_cfg.as_ref())
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
    let registry = websocket::new_connection_registry();
    let shutdown_rx = install_signal_handler();

    // Bind the listening socket before starting the console loop so that a
    // bind failure (e.g. port already in use) returns an error from `main`
    // immediately instead of being swallowed when the runtime tries to wait
    // for the blocking stdin thread on shutdown.
    if let Some((cert_path, key_path)) = server_cfg.tls_config() {
        let bind_addr = SocketAddr::new(server_cfg.bind_host, server_cfg.tls_port);
        let listener = TcpListener::bind(bind_addr)
            .await
            .map_err(|e| format!("failed to bind {bind_addr}: {e}"))?;
        println!("Listening on https://{bind_addr}");
        spawn_console_command_loop(app_cfg.clone());
        run_tls_server(
            listener,
            &cert_path,
            &key_path,
            app_cfg,
            registry,
            shutdown_rx,
        )
        .await?;
    } else {
        let bind_addr = SocketAddr::new(server_cfg.bind_host, server_cfg.port);
        let listener = std::net::TcpListener::bind(bind_addr)
            .map_err(|e| format!("failed to bind {bind_addr}: {e}"))?;
        listener.set_nonblocking(true)?;
        println!("Listening on http://{bind_addr}");
        spawn_console_command_loop(app_cfg.clone());
        run_http_server(listener, app_cfg, registry, shutdown_rx).await?;
    }

    // Both accept loops have exited; drop the per-space state so the
    // in-memory Merk DBs and file-store handles release promptly before
    // the process returns. Any `Arc<Mutex<SpaceState>>` still held by
    // stragglers will drop when those tasks finish.
    crate::db::shutdown_all_spaces().await;
    log::info!("shutdown complete");
    Ok(())
}

async fn run_tls_server(
    listener: TcpListener,
    cert_path: &str,
    key_path: &str,
    app_cfg: Arc<AppConfig>,
    registry: websocket::ConnectionRegistry,
    mut shutdown_rx: ShutdownRx,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let tls_cfg = tls::build_tls_config(cert_path, key_path)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_cfg));
    let mut tasks = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            biased;
            res = shutdown_rx.changed() => {
                // `Err` means the sender was dropped; either way, stop
                // accepting new TLS connections.
                if res.is_err() {
                    log::warn!("shutdown channel closed unexpectedly; exiting TLS accept loop");
                }
                break;
            }
            accept = listener.accept() => {
                let (tcp, _) = match accept {
                    Ok(pair) => pair,
                    Err(e) => {
                        log::warn!("TLS accept error (continuing): {e}");
                        continue;
                    }
                };
                let acceptor = acceptor.clone();
                let app_cfg_conn = app_cfg.clone();
                let reg_conn = registry.clone();
                let conn_shutdown = shutdown_rx.clone();
                tasks.spawn(async move {
                    match acceptor.accept(tcp).await {
                        Ok(tls_stream) => {
                            if let Err(err) = hyper::server::conn::Http::new()
                                .http1_only(true)
                                .http1_keep_alive(true)
                                .serve_connection(
                                    tls_stream,
                                    service_fn(move |req| {
                                        handle_request(
                                            req,
                                            app_cfg_conn.clone(),
                                            reg_conn.clone(),
                                            conn_shutdown.clone(),
                                        )
                                    }),
                                )
                                .with_upgrades()
                                .await
                            {
                                // hyper reports "client disconnect" and similar
                                // as errors here; downgrade to debug to keep
                                // logs readable. Matches the plain-HTTP path.
                                log::debug!("HTTPS connection ended: {err}");
                            }
                        }
                        Err(e) => log::warn!("TLS accept error (continuing): {e}"),
                    }
                });
            }
        }
    }

    drain_join_set(tasks, "TLS").await;
    Ok(())
}

async fn run_http_server(
    listener: std::net::TcpListener,
    app_cfg: Arc<AppConfig>,
    registry: websocket::ConnectionRegistry,
    mut shutdown_rx: ShutdownRx,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Mirror the TLS path: accept connections manually and serve them
    // with `Http::serve_connection` so the accept loop exits as soon as
    // `shutdown_rx` fires (via the biased `tokio::select!` below) instead
    // of waiting for `hyper::Server::serve(...).with_graceful_shutdown(...)`
    // to detect the signal through its own machinery. The per-connection
    // hyper state machines themselves are tracked in `tasks` (a
    // `JoinSet`) so `drain_join_set` can bound how long we wait for them
    // to finish on shutdown.
    //
    // The WebSocket sessions that get spawned *after* upgrade in
    // `http::handle_request` are still bare `tokio::spawn` tasks —
    // they are not currently added to this `JoinSet`. They do observe
    // the cloned `shutdown_rx` and react to it; on shutdown they finish
    // through their own select-on-shutdown path or are aborted by the
    // runtime tear-down at process exit. If we ever want graceful WS
    // close-frame draining at shutdown, those tasks would need to be
    // threaded into this set (or a sibling one) as well.
    listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(listener)?;
    let mut tasks = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            biased;
            res = shutdown_rx.changed() => {
                if res.is_err() {
                    log::warn!("shutdown channel closed unexpectedly; exiting HTTP accept loop");
                }
                break;
            }
            accept = listener.accept() => {
                let (tcp, _) = match accept {
                    Ok(pair) => pair,
                    Err(e) => {
                        log::warn!("HTTP accept error (continuing): {e}");
                        continue;
                    }
                };
                let app_cfg_conn = app_cfg.clone();
                let reg_conn = registry.clone();
                let conn_shutdown = shutdown_rx.clone();
                tasks.spawn(async move {
                    if let Err(err) = hyper::server::conn::Http::new()
                        .http1_only(true)
                        .http1_keep_alive(true)
                        .serve_connection(
                            tcp,
                            service_fn(move |req| {
                                handle_request(
                                    req,
                                    app_cfg_conn.clone(),
                                    reg_conn.clone(),
                                    conn_shutdown.clone(),
                                )
                            }),
                        )
                        .with_upgrades()
                        .await
                    {
                        // hyper reports "client disconnect" and similar
                        // as errors here; downgrade to debug to keep
                        // logs readable.
                        log::debug!("HTTP connection ended: {err}");
                    }
                });
            }
        }
    }

    drain_join_set(tasks, "HTTP").await;
    Ok(())
}

/// Await all spawned connection tasks with a bounded timeout, then
/// abort any stragglers. Logged at info so operators can correlate
/// graceful shutdowns with `docker stop -t N` budgets.
async fn drain_join_set(mut tasks: tokio::task::JoinSet<()>, label: &str) {
    if tasks.is_empty() {
        return;
    }
    log::info!(
        "draining {} in-flight {label} connection(s) (timeout {:?})",
        tasks.len(),
        SHUTDOWN_DRAIN_TIMEOUT,
    );
    let drain = async { while tasks.join_next().await.is_some() {} };
    if tokio::time::timeout(SHUTDOWN_DRAIN_TIMEOUT, drain)
        .await
        .is_err()
    {
        log::warn!(
            "{label} drain timeout exceeded; aborting {} remaining task(s)",
            tasks.len()
        );
        tasks.shutdown().await;
    }
}

fn spawn_console_command_loop(app_cfg: Arc<AppConfig>) {
    // Skip the interactive console entirely when stdin is not a TTY
    // (e.g. running in a detached container or under systemd). The loop
    // exists for operator convenience during local development; in
    // non-interactive contexts it would just sit on a closed pipe.
    if !std::io::stdin().is_terminal() {
        log::debug!("stdin is not a TTY; skipping interactive console command loop");
        return;
    }

    let runtime = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        use std::io::{self, BufRead};

        let stdin = io::stdin();
        let lines = stdin.lock().lines();

        println!(
            "Console command ready: type 'print' (p), 'changelog' (c), 'help' (h), or 'quit' (q)."
        );

        for line_result in lines {
            let line = match line_result {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("Failed to read from stdin: {e}");
                    break;
                }
            };

            let cmd = line.trim();
            match cmd {
                "" => {}
                "print" | "p" => {
                    let cfg = app_cfg.clone();
                    if let Err(e) = runtime.block_on(async move {
                        crate::db::dump_tables_to_console(cfg.as_ref()).await
                    }) {
                        eprintln!("Failed to print tables: {e}");
                    }
                }
                "changelog" | "c" => {
                    let cfg = app_cfg.clone();
                    if let Err(e) = runtime.block_on(async move {
                        crate::db::dump_changelog_to_console(cfg.as_ref()).await
                    }) {
                        eprintln!("Failed to dump changelog: {e}");
                    }
                }
                "quit" | "q" => {
                    println!("Shutting down due to console 'quit' command");
                    std::process::exit(0);
                }
                "help" | "h" => {
                    println!(
                        "Available commands:\n  print     | p  - pretty-print all tables\n  changelog | c  - dump the changelog to the console\n  quit      | q  - stop the server\n  help      | h  - show this list"
                    );
                }
                other => {
                    println!("Unknown command '{other}'. Type 'help' for options.");
                }
            }
        }
    });
}
