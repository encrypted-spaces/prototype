use crate::app_config::AppConfig;
use crate::file_store::FileStore;
use crate::websocket::{client_connected, ConnectionRegistry};
use crate::ShutdownRx;
use base64::Engine;
use encrypted_spaces_backend::access_control::AuthContext;
use encrypted_spaces_backend::SpaceId;
use hyper::body::Bytes;
use hyper::{Body, Request, Response, StatusCode};
use hyper_tungstenite::{is_upgrade_request, upgrade};
use std::{convert::Infallible, sync::Arc};

pub async fn handle_request(
    req: Request<Body>,
    app_cfg: Arc<AppConfig>,
    registry: ConnectionRegistry,
    shutdown_rx: ShutdownRx,
) -> Result<Response<Body>, Infallible> {
    let path = req.uri().path().to_string();

    if path.starts_with("/ws") && is_upgrade_request(&req) {
        // Extract auth context from query string (e.g. /ws?auth=<base64url_AuthContext>&space=<32_hex>)
        // TODO: For now, we "authenticate" as a user by passing the auth context as a query string.
        // Eventually, we'll need real authentication (something signed using the user's identity
        // key that the server can verify).
        let auth = parse_auth_from_query(req.uri().query());

        // Parse the required space= query parameter.
        let space_id = req.uri().query().and_then(|q| {
            q.split('&')
                .find_map(|p| p.strip_prefix("space="))
                .and_then(|s| s.parse::<SpaceId>().ok())
        });
        let space_id = match space_id {
            Some(id) => id,
            None => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from(
                        "missing or invalid space id (expected 32 hex chars)",
                    ))
                    .unwrap())
            }
        };

        match upgrade(req, None) {
            Ok((response, websocket)) => {
                let app_cfg2 = app_cfg.clone();
                let reg2 = registry.clone();
                let shutdown_rx2 = shutdown_rx.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        client_connected(websocket, app_cfg2, reg2, auth, space_id, shutdown_rx2)
                            .await
                    {
                        eprintln!("Websocket handling error: {e}");
                    }
                });
                Ok(response)
            }
            Err(err) => {
                eprintln!("Failed to upgrade websocket: {err}");
                Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from("WebSocket upgrade failed"))
                    .unwrap())
            }
        }
    } else if let Some(hash) = path.strip_prefix("/file/") {
        handle_file(req, hash, app_cfg).await
    } else if path == "/healthz" {
        // Liveness/readiness endpoint with a stable contract. Returns
        // 200 with a tiny body without touching any per-space state, so
        // container healthchecks and load-balancer probes can rely on
        // it independently of the banner at `/`.
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain; charset=utf-8")
            .body(Body::from("ok"))
            .unwrap())
    } else if path == "/" {
        Ok(Response::new(Body::from(
            "SDK server (hyper + websockets)\nConnect to /ws for websocket connections.",
        )))
    } else {
        Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("Not found"))
            .unwrap())
    }
}

/// Extract auth context from query string `?auth=<base64url_AuthContext>`.
fn parse_auth_from_query(query: Option<&str>) -> Option<AuthContext> {
    query.and_then(|q| {
        q.split('&')
            .find_map(|p| p.strip_prefix("auth="))
            .and_then(|v| {
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(v)
                    .ok()
            })
            .and_then(|bytes| serde_json::from_slice::<AuthContext>(&bytes).ok())
    })
}

// ─── File store endpoints ──────────────────────────────────────────────────

/// Handle file store requests: PUT/GET /file/{hash}?auth=<base64url_AuthContext>
///
/// Looks up the space's file store from the SPACES map using the auth context.
async fn handle_file(
    req: Request<Body>,
    hash: &str,
    app_cfg: Arc<AppConfig>,
) -> Result<Response<Body>, Infallible> {
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("invalid hash (expected 64 hex chars)"))
            .unwrap());
    }

    let auth = match parse_auth_from_query(req.uri().query()) {
        Some(a) => a,
        None => {
            return Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from("missing or invalid auth context"))
                .unwrap())
        }
    };

    // Look up the space to get its file store
    let space = crate::db::get_or_create_space(auth.space_id, Some(&app_cfg)).await;
    let file_store = {
        let srv = space.lock().await;
        match &srv.file_store {
            Some(store) => store.clone(),
            None => {
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("file store not configured for this space"))
                    .unwrap())
            }
        }
    };

    match *req.method() {
        hyper::Method::PUT => handle_file_put(req, hash, file_store).await,
        hyper::Method::GET => handle_file_get(hash, file_store).await,
        hyper::Method::HEAD => handle_file_head(hash, file_store).await,
        _ => Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Body::from("method not allowed"))
            .unwrap()),
    }
}

async fn handle_file_put(
    req: Request<Body>,
    hash: &str,
    file_store: Arc<FileStore>,
) -> Result<Response<Body>, Infallible> {
    let body_bytes: Bytes = match hyper::body::to_bytes(req.into_body()).await {
        Ok(bytes) => bytes,
        Err(e) => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(format!("failed to read body: {e}")))
                .unwrap())
        }
    };

    match file_store.put(hash, &body_bytes) {
        Ok(()) => Ok(Response::builder()
            .status(StatusCode::CREATED)
            .body(Body::empty())
            .unwrap()),
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from(e.to_string()))
            .unwrap()),
        Err(e) => {
            eprintln!("file put error: {e}");
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("internal error"))
                .unwrap())
        }
    }
}

async fn handle_file_get(
    hash: &str,
    file_store: Arc<FileStore>,
) -> Result<Response<Body>, Infallible> {
    match file_store.get(hash) {
        Ok(Some(data)) => Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/octet-stream")
            .body(Body::from(data))
            .unwrap()),
        Ok(None) => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("file not found"))
            .unwrap()),
        Err(e) => {
            eprintln!("file get error: {e}");
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("internal error"))
                .unwrap())
        }
    }
}

async fn handle_file_head(
    hash: &str,
    file_store: Arc<FileStore>,
) -> Result<Response<Body>, Infallible> {
    if file_store.exists(hash) {
        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap())
    } else {
        Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .unwrap())
    }
}
