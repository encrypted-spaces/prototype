//! HTTP + WebSocket endpoints for the inspector SPA.
//!
//! Routes:
//!   GET /_inspect           → index.html
//!   GET /_inspect/          → index.html
//!   GET /_inspect/<path>    → embedded static asset (or index.html for SPA fallback)
//!   GET /_inspect/ws        → WebSocket upgrade; streams JSON events from
//!                             `Inspector::subscribe()` to the client
//!
//! The SPA is embedded at compile time from `backend/inspector-ui/dist`.
//! Run `npm run build` in that directory before `cargo build` if dist is stale.

use super::Inspector;
use futures_util::SinkExt;
use hyper::{Body, Request, Response, StatusCode};
use hyper_tungstenite::{is_upgrade_request, tungstenite::Message, upgrade, HyperWebsocket};
use include_dir::{include_dir, Dir};
use std::convert::Infallible;
use tokio::sync::broadcast::error::RecvError;

/// Forces this module to re-compile when the embedded SPA changes. The
/// `INSPECTOR_SPA_MARKER` env var is set by `build.rs` from a hash of
/// `../inspector-ui/dist`; without this tie-in, cargo's incremental
/// compilation would happily keep using the cached `include_dir!`
/// expansion even after `npm run build` writes new assets.
const _SPA_MARKER: &str = env!("INSPECTOR_SPA_MARKER");

static SPA_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../inspector-ui/dist");

/// Returns true if this request targets the inspector subtree and should be
/// handled here rather than by the main router.
pub fn matches(path: &str) -> bool {
    path == "/_inspect" || path.starts_with("/_inspect/")
}

pub async fn handle(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    let path = req.uri().path();

    if path == "/_inspect/ws" {
        return handle_ws(req).await;
    }

    let rel = match path {
        "/_inspect" | "/_inspect/" => "index.html",
        other => other.strip_prefix("/_inspect/").unwrap_or(other),
    };

    // SPA fallback: unknown paths under /_inspect/ serve index.html so the
    // client-side router (when we add one) can handle them.
    let file = SPA_DIR
        .get_file(rel)
        .or_else(|| SPA_DIR.get_file("index.html"));

    match file {
        Some(f) => {
            let ct = content_type_for(rel);
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", ct)
                .body(Body::from(f.contents()))
                .unwrap())
        }
        None => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from(
                "inspector SPA not built — run `npm run build` in backend/inspector-ui",
            ))
            .unwrap()),
    }
}

async fn handle_ws(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    if !is_upgrade_request(&req) {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("expected WebSocket upgrade"))
            .unwrap());
    }

    let inspector = match Inspector::global() {
        Some(i) => i,
        None => {
            return Ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(Body::from(
                    "inspector disabled — set CYPHERSPACES_INSPECTOR_LOG and restart",
                ))
                .unwrap());
        }
    };

    match upgrade(req, None) {
        Ok((response, websocket)) => {
            tokio::spawn(async move {
                if let Err(e) = stream_events(websocket, inspector).await {
                    log::debug!("inspector ws: stream ended: {e}");
                }
            });
            Ok(response)
        }
        Err(e) => Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from(format!("inspector WS upgrade failed: {e}")))
            .unwrap()),
    }
}

async fn stream_events(
    ws: HyperWebsocket,
    inspector: std::sync::Arc<Inspector>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ws_stream = ws.await?;
    let (mut write, _read) = futures_util::StreamExt::split(ws_stream);

    // Subscribe first, then snapshot the backlog: any event emitted before the
    // subscribe is in the snapshot, anything after is on `rx`, so nothing is
    // lost (a rare event in the overlap is delivered twice, which the frontend
    // reducers tolerate). Replaying the backlog lets this client render state
    // established before it connected — notably the `SchemaSnapshot`.
    let mut rx = inspector.subscribe();
    for ev in inspector.history_snapshot() {
        let line = serde_json::to_string(&ev)?;
        if write.send(Message::Text(line)).await.is_err() {
            return Ok(());
        }
    }

    loop {
        match rx.recv().await {
            Ok(ev) => {
                let line = serde_json::to_string(&ev)?;
                if write.send(Message::Text(line)).await.is_err() {
                    break;
                }
            }
            // Slow consumer: skip the gap and keep going. Inspector is
            // observability, not a durable feed.
            Err(RecvError::Lagged(n)) => {
                log::warn!("inspector ws: client lagged, skipped {n} events");
                continue;
            }
            Err(RecvError::Closed) => break,
        }
    }
    Ok(())
}

fn content_type_for(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("");
    match ext {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        _ => "application/octet-stream",
    }
}
