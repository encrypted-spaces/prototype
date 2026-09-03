mod app_config;
mod db;
pub(crate) mod file_store;
mod http;
mod inspector;
mod key_delivery;
mod retained_snapshots;
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

/// A persistent accept failure (notably EMFILE/ENFILE) leaves a Tokio listener
/// immediately ready with the same error. Retrying without a delay therefore
/// becomes a single-core busy loop. Back off persistent/resource errors, reset
/// after the next successful accept, and cap the delay so recovery remains
/// prompt. Connection-local abort/reset errors can be retried immediately.
const ACCEPT_BACKOFF_INITIAL: Duration = Duration::from_millis(10);
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
struct AcceptBackoff {
    next: Duration,
}

impl AcceptBackoff {
    fn new() -> Self {
        Self {
            next: ACCEPT_BACKOFF_INITIAL,
        }
    }

    fn next_delay(&mut self) -> Duration {
        let delay = self.next;
        self.next = self
            .next
            .checked_mul(2)
            .unwrap_or(ACCEPT_BACKOFF_MAX)
            .min(ACCEPT_BACKOFF_MAX);
        delay
    }

    fn reset(&mut self) {
        self.next = ACCEPT_BACKOFF_INITIAL;
    }
}

async fn retry_after_accept_error(
    label: &str,
    error: &std::io::Error,
    backoff: &mut AcceptBackoff,
    shutdown_rx: &mut ShutdownRx,
) -> bool {
    if matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::ConnectionReset
    ) {
        log::debug!("{label} accept dropped a connection; retrying immediately: {error}");
        return true;
    }

    let delay = backoff.next_delay();
    log::warn!("{label} accept error; retrying in {delay:?}: {error}");
    tokio::select! {
        biased;
        _ = shutdown_rx.changed() => false,
        _ = tokio::time::sleep(delay) => true,
    }
}

fn log_finished_connection_task(label: &str, result: Result<(), tokio::task::JoinError>) {
    if let Err(error) = result {
        log::warn!("{label} connection task failed: {error}");
    }
}

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
    let mut accept_backoff = AcceptBackoff::new();

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
            task = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(result) = task {
                    log_finished_connection_task("TLS", result);
                }
            }
            accept = listener.accept() => {
                let (tcp, _) = match accept {
                    Ok(pair) => {
                        accept_backoff.reset();
                        pair
                    }
                    Err(e) => {
                        if !retry_after_accept_error(
                            "TLS",
                            &e,
                            &mut accept_backoff,
                            &mut shutdown_rx,
                        ).await {
                            break;
                        }
                        continue;
                    }
                };
                let acceptor = acceptor.clone();
                let app_cfg_conn = app_cfg.clone();
                let reg_conn = registry.clone();
                let conn_shutdown = shutdown_rx.clone();
                tasks.spawn(async move {
                    match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                        Ok(Ok(tls_stream)) => {
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
                        Ok(Err(e)) => log::warn!("TLS handshake failed: {e}"),
                        Err(_) => log::warn!(
                            "TLS handshake timed out after {:?}",
                            TLS_HANDSHAKE_TIMEOUT
                        ),
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
    let mut accept_backoff = AcceptBackoff::new();

    loop {
        tokio::select! {
            biased;
            res = shutdown_rx.changed() => {
                if res.is_err() {
                    log::warn!("shutdown channel closed unexpectedly; exiting HTTP accept loop");
                }
                break;
            }
            task = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(result) = task {
                    log_finished_connection_task("HTTP", result);
                }
            }
            accept = listener.accept() => {
                let (tcp, _) = match accept {
                    Ok(pair) => {
                        accept_backoff.reset();
                        pair
                    }
                    Err(e) => {
                        if !retry_after_accept_error(
                            "HTTP",
                            &e,
                            &mut accept_backoff,
                            &mut shutdown_rx,
                        ).await {
                            break;
                        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_config::BootstrapDataSource;
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpStream};
    use std::time::Instant;

    #[test]
    fn accept_backoff_is_nonzero_bounded_and_resets_after_success() {
        let mut backoff = AcceptBackoff::new();
        let delays: Vec<_> = (0..12).map(|_| backoff.next_delay()).collect();

        assert_eq!(delays[0], Duration::from_millis(10));
        assert_eq!(delays[1], Duration::from_millis(20));
        assert!(delays.iter().all(|delay| !delay.is_zero()));
        assert!(delays.iter().all(|delay| *delay <= ACCEPT_BACKOFF_MAX));
        assert_eq!(*delays.last().unwrap(), ACCEPT_BACKOFF_MAX);

        backoff.reset();
        assert_eq!(backoff.next_delay(), ACCEPT_BACKOFF_INITIAL);
    }

    #[tokio::test]
    async fn connection_local_accept_errors_do_not_advance_backoff() {
        let (_shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let mut backoff = AcceptBackoff::new();

        for kind in [
            std::io::ErrorKind::ConnectionAborted,
            std::io::ErrorKind::ConnectionReset,
        ] {
            assert!(
                retry_after_accept_error(
                    "test",
                    &std::io::Error::from(kind),
                    &mut backoff,
                    &mut shutdown_rx,
                )
                .await
            );
        }

        assert_eq!(backoff.next_delay(), ACCEPT_BACKOFF_INITIAL);
    }

    fn read_http_headers(stream: &mut TcpStream) -> Vec<u8> {
        let mut response = Vec::new();
        let mut buffer = [0_u8; 512];
        while !response.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut buffer).expect("read HTTP response");
            assert!(read > 0, "connection closed before HTTP headers arrived");
            response.extend_from_slice(&buffer[..read]);
            assert!(response.len() < 16 * 1024, "HTTP headers were too large");
        }
        response
    }

    fn open_websocket(address: SocketAddr) -> TcpStream {
        let mut stream = TcpStream::connect(address).expect("connect to test server");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let request = format!(
            "GET /ws?space=00000000000000000000000000000000 HTTP/1.1\r\n\
             Host: {address}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).unwrap();
        let response = read_http_headers(&mut stream);
        assert!(
            response.starts_with(b"HTTP/1.1 101"),
            "WebSocket upgrade failed: {}",
            String::from_utf8_lossy(&response)
        );
        stream
    }

    fn read_websocket_frame(stream: &mut TcpStream) -> (u8, Vec<u8>) {
        let mut header = [0_u8; 2];
        stream.read_exact(&mut header).expect("read frame header");
        let opcode = header[0] & 0x0f;
        let masked = header[1] & 0x80 != 0;
        let mut payload_len = u64::from(header[1] & 0x7f);
        if payload_len == 126 {
            let mut extended = [0_u8; 2];
            stream.read_exact(&mut extended).expect("read frame length");
            payload_len = u64::from(u16::from_be_bytes(extended));
        } else if payload_len == 127 {
            let mut extended = [0_u8; 8];
            stream.read_exact(&mut extended).expect("read frame length");
            payload_len = u64::from_be_bytes(extended);
        }
        let mask = if masked {
            let mut mask = [0_u8; 4];
            stream.read_exact(&mut mask).expect("read frame mask");
            Some(mask)
        } else {
            None
        };
        let mut payload =
            vec![0_u8; usize::try_from(payload_len).expect("frame length fits usize")];
        stream.read_exact(&mut payload).expect("read frame payload");
        if let Some(mask) = mask {
            for (index, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[index % mask.len()];
            }
        }
        (opcode, payload)
    }

    fn close_websocket_normally(mut stream: TcpStream) {
        // Masked client close frame with status code 1000.
        stream
            .write_all(&[0x88, 0x82, 0x11, 0x22, 0x33, 0x44, 0x12, 0xca])
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            assert!(
                Instant::now() < deadline,
                "server did not reply with a close frame"
            );
            let (opcode, _) = read_websocket_frame(&mut stream);
            if opcode == 0x08 {
                return;
            }
        }
    }

    async fn wait_until_registry_stays_empty(registry: &websocket::ConnectionRegistry) {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut empty_since = None;
        loop {
            if registry.lock().await.is_empty() {
                let since = empty_since.get_or_insert_with(Instant::now);
                if since.elapsed() >= Duration::from_millis(100) {
                    return;
                }
            } else {
                empty_since = None;
            }
            assert!(
                Instant::now() < deadline,
                "connection registry did not drain"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn repeated_websocket_disconnects_release_connection_state() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let app_cfg = Arc::new(AppConfig {
            verbose_logfile: None,
            space_root: None,
            bootstrap_data: BootstrapDataSource::None,
        });
        let registry = websocket::new_connection_registry();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_registry = registry.clone();
        let server = tokio::spawn(async move {
            run_http_server(listener, app_cfg, server_registry, shutdown_rx).await
        });

        tokio::task::spawn_blocking(move || {
            for cycle in 0..128 {
                let stream = open_websocket(address);
                if cycle % 2 == 0 {
                    close_websocket_normally(stream);
                } else {
                    // A transport disconnect without a WebSocket close frame.
                    stream.shutdown(Shutdown::Write).unwrap();
                }
            }
        })
        .await
        .unwrap();

        wait_until_registry_stays_empty(&registry).await;
        shutdown_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("server shutdown timed out")
            .expect("server task panicked")
            .expect("server returned an error");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn websocket_ping_emits_exactly_one_pong() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let app_cfg = Arc::new(AppConfig {
            verbose_logfile: None,
            space_root: None,
            bootstrap_data: BootstrapDataSource::None,
        });
        let registry = websocket::new_connection_registry();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_registry = registry.clone();
        let server = tokio::spawn(async move {
            run_http_server(listener, app_cfg, server_registry, shutdown_rx).await
        });

        tokio::task::spawn_blocking(move || {
            let mut stream = open_websocket(address);
            // Masked client ping carrying "hi".
            stream
                .write_all(&[0x89, 0x82, 0x11, 0x22, 0x33, 0x44, 0x79, 0x4b])
                .unwrap();
            let (opcode, payload) = read_websocket_frame(&mut stream);
            assert_eq!(opcode, 0x0a, "server must answer ping with pong");
            assert_eq!(payload, b"hi");

            stream
                .set_read_timeout(Some(Duration::from_millis(150)))
                .unwrap();
            let mut extra = [0_u8; 1];
            match stream.read(&mut extra) {
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Ok(0) => panic!("connection closed while checking for duplicate pong"),
                Ok(_) => panic!("server emitted a second frame for one ping"),
                Err(error) => panic!("unexpected read error: {error}"),
            }
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            close_websocket_normally(stream);
        })
        .await
        .unwrap();

        wait_until_registry_stays_empty(&registry).await;
        shutdown_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("server shutdown timed out")
            .expect("server task panicked")
            .expect("server returned an error");
    }
}
