use crate::transport::Transport;
use base64::Engine;
use encrypted_spaces_backend::{
    access_control::AuthContext,
    error::{Result, SdkError},
    merk_storage::proofs::{verify_query_proof_with_hashed_values, VerifiedRows},
    proto::{
        db_request, db_response, values_sidecar_from_proto, values_sidecar_to_proto, ws_frame,
        AddMemberRequest, ChangeRequest, DbRequest, DbResponse, Ephemeral, FastForwardRequest,
        RemoveMemberRequest, SelectRequest, WsFrame,
    },
    query::Query,
    schema::Schema,
};
use encrypted_spaces_changelog_core::changelog::{
    Change, ChangeResponse, ChangelogEntry, FastForwardData,
};
use encrypted_spaces_key_manager::{InviteRequest, RekeyRequest};
use prost::Message;
pub(crate) const DEBUG: bool = true;

// Consolidated logging macros (wasm + native)
macro_rules! log_debug {
    ($($arg:tt)*) => {{
        if DEBUG {
            #[cfg(target_arch = "wasm32")]
            {
                web_sys::console::debug_1(
                    &wasm_bindgen::JsValue::from_str(&format!($($arg)*))
                );
            }
            #[cfg(not(target_arch = "wasm32"))]
            {
                log::debug!($($arg)*);
            }
        }
    }};
}

#[derive(Clone, Debug)]
pub struct BroadcastEvent {
    /// Signed change the server just applied. Hash-backed full values travel
    /// with the response material and are mirrored here for cache handling.
    pub change: Change,
    pub change_response: ChangeResponse,
}

/// Response channel type for the pending request table.
enum PendingResponse {
    Db(Result<DbResponse>),
}

pub struct WebSocketTransport {
    // Write half of the WebSocket (binary frames) guarded for sequential writes
    write: tokio::sync::Mutex<
        Option<
            futures_util::stream::SplitSink<
                async_tungstenite::WebSocketStream<async_tungstenite::tokio::ConnectStream>,
                async_tungstenite::tungstenite::Message,
            >,
        >,
    >,
    // Pending request_id -> oneshot sender awaiting the matching DbResponse
    pending: std::sync::Arc<
        tokio::sync::Mutex<
            std::collections::HashMap<String, tokio::sync::oneshot::Sender<PendingResponse>>,
        >,
    >,
    // Broadcast event fan-out (multi-subscriber)
    bcast_tx: tokio::sync::broadcast::Sender<BroadcastEvent>,
    // Ephemeral message fan-out (multi-subscriber)
    ephemeral_tx: tokio::sync::broadcast::Sender<crate::transport::EphemeralEvent>,
    // Background read loop task handle
    read_task: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    // WebSocket URL (base, without space= or auth= query params)
    url: String,
    // Base64url-encoded auth context (set during authenticate, used for file HTTP requests)
    auth_b64: tokio::sync::Mutex<Option<String>>,
    // Shared HTTP client for file-store PUT/GET. Built with hyper-tls so it
    // can dial both `http://` (plaintext server) and `https://` (TLS-fronted
    // server, derived from `wss://` via `ws_url_to_http`). TLS verification
    // uses the OS trust store plus the optional extra anchor supplied
    // through `load_trust_cert`, matching the WebSocket path.
    #[cfg(not(target_arch = "wasm32"))]
    file_client:
        hyper::Client<hyper_tls::HttpsConnector<hyper::client::HttpConnector>, hyper::Body>,
    // Optional extra-trust-anchor TLS connector cloned into each WebSocket
    // upgrade. `None` means "use async-tungstenite's default connector"
    // (OS trust store only), which matches the pre-trust-anchor behavior.
    #[cfg(not(target_arch = "wasm32"))]
    ws_tls_connector: Option<tokio_native_tls::TlsConnector>,
    #[cfg(target_arch = "wasm32")]
    ws: RefCell<Option<web_sys::WebSocket>>,
    #[cfg(target_arch = "wasm32")]
    state: Rc<InnerState>,
}

// Safety: wasm WebSocket isn't Send/Sync but we never share it across threads in wasm;
// native struct fields are Send. We rely on runtime constraints; mark explicitly.
#[cfg(target_arch = "wasm32")]
unsafe impl Send for WebSocketTransport {}
#[cfg(target_arch = "wasm32")]
unsafe impl Sync for WebSocketTransport {}

#[cfg(target_arch = "wasm32")]
struct InnerState {
    // pending request_id -> oneshot sender waiting for DbResponse
    pending: RefCell<HashMap<String, oneshot::Sender<Result<DbResponse>>>>,
    // optional broadcast channel sender (string messages extracted from Broadcast.message)
    broadcast_tx: RefCell<Option<mpsc::UnboundedSender<BroadcastEvent>>>,
}

#[cfg(not(target_arch = "wasm32"))]
impl WebSocketTransport {
    /// Construct a transport that uses only the OS trust store for TLS.
    /// Equivalent to [`Self::new_with_trust_connector`] called with `None`.
    pub async fn new(url: &str) -> Result<Self> {
        Self::new_with_trust_connector(url, None).await
    }

    /// Construct a transport that honors `connector` (if `Some`) on every
    /// WS upgrade and file-store HTTPS connection, in addition to the OS
    /// trust store baked into the connector at build time. Pass `None`
    /// for the default (OS-trust-store-only) behavior.
    ///
    /// Build the connector with [`crate::tls_trust::load_trust_cert`],
    /// which wraps a single PEM/DER cert as an extra root.
    ///
    /// The connector drives:
    /// * the WebSocket upgrade (via
    ///   `async_tungstenite::tokio::connect_async_with_tls_connector`),
    /// * the file-store hyper client (built once here and reused for
    ///   every `file_upload` / `file_download`).
    ///
    /// Hostname verification stays on either way — the anchor only widens
    /// *who* the client trusts to issue a cert for the server, not
    /// *which* cert is acceptable for a given URL.
    pub async fn new_with_trust_connector(
        url: &str,
        ws_tls_connector: Option<tokio_native_tls::TlsConnector>,
    ) -> Result<Self> {
        let pending: std::sync::Arc<
            tokio::sync::Mutex<
                std::collections::HashMap<String, tokio::sync::oneshot::Sender<PendingResponse>>,
            >,
        > = std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
        let (bcast_tx, _) = tokio::sync::broadcast::channel::<BroadcastEvent>(64);
        let (ephemeral_tx, _) =
            tokio::sync::broadcast::channel::<crate::transport::EphemeralEvent>(64);

        // Build a single HTTPS-capable hyper client for the file store and
        // reuse it across uploads/downloads (connection pooling, one-time
        // TLS connector init). When an extra anchor was supplied, wrap
        // the same `tokio_native_tls::TlsConnector` into the hyper-tls
        // `HttpsConnector` so the file path trusts the same root the WS
        // path does.
        let file_client = match ws_tls_connector.as_ref() {
            Some(tls) => {
                let mut http = hyper::client::HttpConnector::new();
                http.enforce_http(false);
                let https = hyper_tls::HttpsConnector::from((http, tls.clone()));
                log::info!("websocket_transport: using extra TLS trust anchor");
                hyper::Client::builder().build(https)
            }
            None => hyper::Client::builder().build(hyper_tls::HttpsConnector::new()),
        };

        Ok(Self {
            write: tokio::sync::Mutex::new(None),
            pending,
            bcast_tx,
            ephemeral_tx,
            read_task: tokio::sync::Mutex::new(None),
            url: url.to_string(),
            auth_b64: tokio::sync::Mutex::new(None),
            file_client,
            ws_tls_connector,
        })
    }

    /// Open (or reopen) the WebSocket connection using the space_id and auth in `auth_context`.
    async fn connect(&self, auth_context: &AuthContext) -> Result<()> {
        use async_tungstenite::tokio::{connect_async, connect_async_with_tls_connector};
        use futures_util::StreamExt;

        // TODO: For now, we "authenticate" as a user by passing the auth context as a query string.
        // Eventually, we'll need real authentication (something signed using the user's identity
        // key that the server can verify).
        let auth_json = serde_json::to_vec(auth_context).map_err(|e| {
            SdkError::ValidationError(format!("failed to serialize auth context: {e}"))
        })?;
        let auth_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(auth_json);
        let separator = if self.url.contains('?') { "&" } else { "?" };
        let connect_url = format!(
            "{}{}space={}&auth={}",
            self.url, separator, auth_context.space_id, auth_b64
        );

        let (stream, _resp) = match self.ws_tls_connector.as_ref() {
            Some(connector) => {
                connect_async_with_tls_connector(&connect_url, Some(connector.clone())).await
            }
            None => connect_async(&connect_url).await,
        }
        .map_err(|e| SdkError::DatabaseError(format!("connect ws failed: {e}")))?;

        let (write, mut read) = stream.split();

        let pending_clone = self.pending.clone();
        let bcast_clone = self.bcast_tx.clone();
        let ephemeral_clone = self.ephemeral_tx.clone();

        // Spawn background read loop
        let task = tokio::spawn(async move {
            use async_tungstenite::tungstenite::Message;
            while let Some(item) = read.next().await {
                match item {
                    Ok(Message::Binary(data)) => match WsFrame::decode(&data[..]) {
                        Ok(frame) => match frame.payload {
                            Some(ws_frame::Payload::DbResponse(resp)) => {
                                let req_id = resp.request_id.clone();
                                let tx_opt = { pending_clone.lock().await.remove(&req_id) };
                                if let Some(tx) = tx_opt {
                                    let result = if resp.status == "ok" {
                                        Ok(resp)
                                    } else if resp.status == "fast_forward_required" {
                                        Err(SdkError::FastForwardRequired {
                                            reason: resp.error.clone(),
                                        })
                                    } else {
                                        Err(SdkError::DatabaseError(format!(
                                            "remote error status='{}' err='{}'",
                                            resp.status, resp.error
                                        )))
                                    };
                                    let _ = tx.send(PendingResponse::Db(result));
                                } else {
                                    log_debug!("read_loop: unmatched DbResponse id={}", req_id);
                                }
                            }
                            Some(ws_frame::Payload::Broadcast(b)) => {
                                if let (Some(ce_proto), Some(cr_proto)) =
                                    (b.change_entry, b.change_response)
                                {
                                    let entry = ChangelogEntry::from(ce_proto);
                                    let change_response = match ChangeResponse::try_from(cr_proto) {
                                        Ok(cr) => cr,
                                        Err(e) => {
                                            log::warn!("dropping broadcast with malformed change response: {e}");
                                            continue;
                                        }
                                    };
                                    let change =
                                        change_from_broadcast_parts(entry, &change_response);
                                    let evt = BroadcastEvent {
                                        change,
                                        change_response,
                                    };
                                    let _ = bcast_clone.send(evt);
                                } else {
                                    log_debug!("read_loop: broadcast missing required fields change_entry/change_response");
                                }
                            }
                            Some(ws_frame::Payload::Ephemeral(e)) => {
                                let evt = crate::transport::EphemeralEvent {
                                    uid: e.uid,
                                    kind: e.kind,
                                    payload: e.payload,
                                };
                                let _ = ephemeral_clone.send(evt);
                            }
                            Some(ws_frame::Payload::DbRequest(_)) => {
                                log_debug!("read_loop: ignoring stray frame");
                            }
                            None => log_debug!("read_loop: empty WsFrame payload"),
                        },
                        Err(e) => log_debug!("read_loop: decode error err={}", e),
                    },
                    Ok(Message::Close(cf)) => {
                        log_debug!("read_loop: connection closed: {:?}", cf);
                        let mut map = pending_clone.lock().await;
                        for (_id, tx) in map.drain() {
                            let _ = tx.send(PendingResponse::Db(Err(SdkError::DatabaseError(
                                "connection closed".into(),
                            ))));
                        }
                        break;
                    }
                    Ok(_other) => {
                        continue;
                    }
                    Err(e) => {
                        log_debug!("read_loop: read error err={}", e);
                        let mut map = pending_clone.lock().await;
                        for (_id, tx) in map.drain() {
                            let _ = tx.send(PendingResponse::Db(Err(SdkError::DatabaseError(
                                format!("read error: {e}"),
                            ))));
                        }
                        break;
                    }
                }
            }
            log_debug!("read_loop: terminated");
        });

        *self.write.lock().await = Some(write);
        *self.read_task.lock().await = Some(task);

        Ok(())
    }

    async fn send_request(&self, req: DbRequest) -> Result<DbResponse> {
        use async_tungstenite::tungstenite::Message;
        use futures_util::SinkExt;
        use tokio::sync::oneshot;

        let request_id = req.request_id.clone();
        let frame = WsFrame {
            payload: Some(ws_frame::Payload::DbRequest(req)),
        };
        let encoded = frame.encode_to_vec();
        log_debug!(
            "native send_request: id={} bytes={}",
            request_id,
            encoded.len()
        );

        // Prepare oneshot before sending
        let (tx, rx) = oneshot::channel::<PendingResponse>();
        {
            let mut map = self.pending.lock().await;
            if map.insert(request_id.clone(), tx).is_some() {
                log_debug!(
                    "native send_request: replaced existing pending id={}",
                    request_id
                );
            }
        }

        // Send frame
        let mut guard = self.write.lock().await;
        let writer = guard.as_mut().ok_or_else(|| {
            SdkError::DatabaseError("not connected — call authenticate() first".into())
        })?;
        if let Err(e) = writer.send(Message::Binary(encoded)).await {
            drop(guard);
            let mut map = self.pending.lock().await;
            map.remove(&request_id);
            return Err(SdkError::DatabaseError(format!("send failed: {e}")));
        }
        drop(guard);

        // Await response delivered by read loop
        let pending_resp = rx
            .await
            .map_err(|_| SdkError::DatabaseError("response channel closed".into()))?;
        match pending_resp {
            PendingResponse::Db(result) => {
                let resp = result?;
                log_debug!(
                    "native send_request: completed id={} status={}",
                    request_id,
                    resp.status
                );
                Ok(resp)
            }
        }
    }
}
#[cfg(target_arch = "wasm32")]
use {
    futures_channel::{mpsc, oneshot},
    std::cell::RefCell,
    std::collections::HashMap,
    std::rc::Rc,
    wasm_bindgen::JsValue,
};

#[cfg(target_arch = "wasm32")]
impl WebSocketTransport {
    pub async fn new(url: &str) -> Result<Self> {
        use wasm_bindgen::JsCast;

        let (opened_tx, opened_rx) = oneshot::channel::<Result<()>>();
        let opened_cell = Rc::new(RefCell::new(Some(opened_tx)));

        let ws = web_sys::WebSocket::new(url)
            .map_err(|e| SdkError::DatabaseError(format!("Create WS failed: {:?}", e)))?;

        let state = Rc::new(InnerState {
            pending: RefCell::new(HashMap::new()),
            broadcast_tx: RefCell::new(None),
        });

        // onopen
        {
            let opened_cell = opened_cell.clone();
            let onopen = wasm_bindgen::closure::Closure::wrap(Box::new(move || {
                if let Some(tx) = opened_cell.borrow_mut().take() {
                    let _ = tx.send(Ok(()));
                }
            }) as Box<dyn FnMut()>);
            ws.set_onopen(Some(onopen.as_ref().unchecked_ref()));
            onopen.forget();
        }
        // onerror
        {
            let opened_cell = opened_cell.clone();
            let onerror =
                wasm_bindgen::closure::Closure::wrap(Box::new(move |e: web_sys::ErrorEvent| {
                    if let Some(tx) = opened_cell.borrow_mut().take() {
                        let _ = tx.send(Err(SdkError::DatabaseError(format!(
                            "WS error: {}",
                            e.message()
                        ))));
                    }
                }) as Box<dyn FnMut(_)>);
            ws.set_onerror(Some(onerror.as_ref().unchecked_ref()));
            onerror.forget();
        }

        // onmessage (shared, dispatching to pending requests OR broadcast channel)
        {
            let state_clone = state.clone();
            let onmessage = wasm_bindgen::closure::Closure::wrap(Box::new(
                move |e: web_sys::MessageEvent| {
                    use wasm_bindgen::JsCast;
                    let data_js = e.data();

                    // Shared frame routing: DbResponse -> fulfill pending; Broadcast -> push to channel.
                    let route_frame = |state_ref: &InnerState, bytes: &[u8], ctx: &str| {
                        log_debug!("onmessage{}: frame len={}B", ctx, bytes.len());
                        match WsFrame::decode(bytes) {
                            Ok(frame) => match frame.payload {
                                Some(ws_frame::Payload::DbResponse(resp)) => {
                                    let req_id = resp.request_id.clone();
                                    if let Some(tx) = state_ref.pending.borrow_mut().remove(&req_id)
                                    {
                                        let is_ok = resp.status == "ok";
                                        let result = if is_ok {
                                            Ok(resp)
                                        } else {
                                            Err(SdkError::DatabaseError("remote error".to_string()))
                                        };
                                        let _ = tx.send(result);
                                    } else {
                                        log_debug!("onmessage: unmatched DbResponse id={}", req_id);
                                    }
                                }
                                Some(ws_frame::Payload::Broadcast(b)) => {
                                    if let Some(btx) = state_ref.broadcast_tx.borrow().as_ref() {
                                        // Require and convert proto fields to domain types
                                        match (b.change_entry, b.change_response) {
                                            (Some(ce_proto), Some(cr_proto)) => {
                                                let entry =
                                                    ChangelogEntry::try_from(ce_proto).unwrap();
                                                let cr =
                                                    ChangeResponse::try_from(cr_proto).unwrap();
                                                let change =
                                                    change_from_broadcast_parts(entry, &cr);
                                                let evt = BroadcastEvent {
                                                    change,
                                                    change_response: cr,
                                                };
                                                let _ = btx.unbounded_send(evt);
                                            }
                                            _ => {
                                                log_debug!(
                                                    "onmessage: broadcast missing required fields change_entry/change_response"
                                                );
                                            }
                                        }
                                    } else {
                                        log_debug!("onmessage: broadcast with no subscriber");
                                    }
                                }
                                Some(ws_frame::Payload::DbRequest(_)) => {
                                    log_debug!("onmessage: ignoring client-sent DbRequest echo");
                                }
                                None => log_debug!("onmessage: empty WsFrame payload"),
                            },
                            Err(e) => {
                                log_debug!("onmessage{}: failed to decode WsFrame err={}", ctx, e)
                            }
                        }
                    };

                    // Normalize all binary representations to a Vec<u8> and process once.
                    if let Ok(blob) = data_js.clone().dyn_into::<web_sys::Blob>() {
                        let state_for_async = state_clone.clone();
                        wasm_bindgen_futures::spawn_local(async move {
                            if let Ok(ab) =
                                wasm_bindgen_futures::JsFuture::from(blob.array_buffer()).await
                            {
                                if let Ok(array_buffer) = ab.dyn_into::<js_sys::ArrayBuffer>() {
                                    let u8 = js_sys::Uint8Array::new(&array_buffer);
                                    let mut data = vec![0; u8.length() as usize];
                                    u8.copy_to(&mut data);
                                    route_frame(&state_for_async, &data, "(blob)");
                                }
                            }
                        });
                        return;
                    }

                    // Try direct ArrayBuffer
                    if let Ok(array_buffer) = data_js.clone().dyn_into::<js_sys::ArrayBuffer>() {
                        let u8 = js_sys::Uint8Array::new(&array_buffer);
                        let mut data = vec![0; u8.length() as usize];
                        u8.copy_to(&mut data);
                        route_frame(&state_clone, &data, "");
                        return;
                    }

                    // Try Uint8Array directly
                    if let Ok(u8arr) = data_js.clone().dyn_into::<js_sys::Uint8Array>() {
                        let mut data = vec![0; u8arr.length() as usize];
                        u8arr.copy_to(&mut data);
                        route_frame(&state_clone, &data, "");
                        return;
                    }

                    // Fallback: has byteLength property (typed array / Buffer-like)
                    if js_sys::Reflect::has(&data_js, &JsValue::from_str("byteLength"))
                        .unwrap_or(false)
                    {
                        let u8 = js_sys::Uint8Array::new(&data_js);
                        let mut data = vec![0; u8.length() as usize];
                        u8.copy_to(&mut data);
                        route_frame(&state_clone, &data, "");
                        return;
                    }

                    log_debug!("onmessage: unsupported frame type");
                },
            )
                as Box<dyn FnMut(_)>);
            ws.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
            onmessage.forget();
        }

        opened_rx
            .await
            .map_err(|_| SdkError::DatabaseError("open channel closed".into()))??;

        Ok(Self {
            url: url.to_string(),
            ws: RefCell::new(Some(ws)),
            state,
        })
    }

    /// Subscribe to broadcast (unsolicited) server messages. Previous subscriber (if any) is replaced.
    pub fn subscribe_broadcasts(&self) -> mpsc::UnboundedReceiver<BroadcastEvent> {
        let (tx, rx) = mpsc::unbounded();
        *self.state.broadcast_tx.borrow_mut() = Some(tx);
        rx
    }

    async fn send_request(&self, req: DbRequest) -> Result<DbResponse> {
        let request_id = req.request_id.clone();
        fn op_name(op: &db_request::Operation) -> &'static str {
            match op {
                db_request::Operation::Select(_) => "Select",
                db_request::Operation::Change(_) => "Change",
                db_request::Operation::FastForward(_) => "FastForward",
                db_request::Operation::AddMember(_) => "AddMember",
                db_request::Operation::RemoveMember(_) => "RemoveMember",
                db_request::Operation::List(_) => "List",
                db_request::Operation::FetchMyKeyDelivery(_) => "FetchMyKeyDelivery",
            }
        }
        let opn = req.operation.as_ref().map(op_name).unwrap_or("<none>");
        let frame = WsFrame {
            payload: Some(ws_frame::Payload::DbRequest(req)),
        };
        let encoded = frame.encode_to_vec();
        log_debug!(
            "send_request: start id={} len={}B op={}",
            request_id,
            encoded.len(),
            opn
        );

        // Prepare oneshot before sending
        let (tx, rx) = oneshot::channel::<Result<DbResponse>>();
        if self
            .state
            .pending
            .borrow_mut()
            .insert(request_id.clone(), tx)
            .is_some()
        {
            // Extremely unlikely (UUID collision) – replace older waiter
            log_debug!(
                "send_request: replaced existing pending entry id={} (collision)",
                request_id
            );
        }

        // Send bytes directly (WsFrame wrapping request)
        let ws_ref = self.ws.borrow();
        let ws = ws_ref
            .as_ref()
            .ok_or_else(|| SdkError::DatabaseError("WebSocket not initialized".into()))?;
        if let Err(e) = ws.send_with_u8_array(&encoded) {
            drop(ws_ref);
            self.state.pending.borrow_mut().remove(&request_id);
            log_debug!("send_request: send failure id={} err={:?}", request_id, e);
            return Err(SdkError::DatabaseError(format!("send failed: {:?}", e)));
        }
        drop(ws_ref);
        log_debug!("send_request: sent id={}", request_id);

        let pending_resp = rx.await.map_err(|_| {
            log_debug!("send_request: oneshot canceled id={}", request_id);
            SdkError::DatabaseError("response channel closed".into())
        })?;
        let resp = pending_resp?;
        log_debug!(
            "send_request: completed id={} status={}",
            request_id,
            resp.status
        );
        Ok(resp)
    }
}

fn change_request_from_change(change: &Change, retention_proofs: Vec<Vec<u8>>) -> ChangeRequest {
    ChangeRequest {
        change: Some((&change.entry).into()),
        values_sidecar: values_sidecar_to_proto(&change.hashed_values),
        retention_proofs,
    }
}

fn change_from_broadcast_parts(entry: ChangelogEntry, response: &ChangeResponse) -> Change {
    Change {
        entry,
        hashed_values: response.hashed_values.clone(),
    }
}

#[cfg_attr(target_arch="wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl Transport for WebSocketTransport {
    async fn submit_change(
        &self,
        change: &Change,
        retention_proofs: Vec<Vec<u8>>,
    ) -> Result<ChangeResponse> {
        let req = DbRequest {
            request_id: uuid::Uuid::new_v4().to_string(),
            operation: Some(db_request::Operation::Change(change_request_from_change(
                change,
                retention_proofs,
            ))),
        };

        let resp = self.send_request(req).await?;
        if let Some(db_response::Result::Change(change_resp)) = resp.result {
            let change_resp = ChangeResponse::try_from(change_resp)?;
            Ok(change_resp)
        } else {
            Err(SdkError::DatabaseError("unexpected response type".into()))
        }
    }

    async fn fast_forward(&self, change_id: u32) -> Result<FastForwardData> {
        self.fast_forward_with_expected(change_id, &[]).await
    }

    async fn fast_forward_with_expected(
        &self,
        change_id: u32,
        expected_change_ids: &[u32],
    ) -> Result<FastForwardData> {
        let req = DbRequest {
            request_id: uuid::Uuid::new_v4().to_string(),
            operation: Some(db_request::Operation::FastForward(FastForwardRequest {
                from_change_id: change_id,
                expected_change_ids: expected_change_ids.to_vec(),
            })),
        };

        // Send and handle response
        let resp = self.send_request(req).await?;
        if let Some(db_response::Result::FastForward(ff_resp)) = resp.result {
            let ff_resp = FastForwardData::try_from(ff_resp)?;
            Ok(ff_resp)
        } else {
            Err(SdkError::DatabaseError("unexpected response type".into()))
        }
    }

    async fn select(
        &self,
        query: Query,
        commitment: &[u8; 32],
        schemas: &std::collections::HashMap<String, Schema>,
    ) -> Result<VerifiedRows> {
        let req = DbRequest {
            request_id: uuid::Uuid::new_v4().to_string(),
            operation: Some(db_request::Operation::Select(SelectRequest {
                query: Some((&query).into()),
                return_one: false,
                commitment: commitment.to_vec(),
            })),
        };

        let resp = self.send_request(req).await?;

        if let Some(db_response::Result::Select(select_resp)) = resp.result {
            let hashed_values = values_sidecar_from_proto(select_resp.values_sidecar);
            verify_query_proof_with_hashed_values(
                &query,
                &select_resp.proof,
                commitment,
                schemas,
                &hashed_values,
            )
        } else {
            Err(SdkError::DatabaseError("unexpected response type".into()))
        }
    }

    #[inline]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn add_member(
        &self,
        request: InviteRequest,
        insert_change: &Change,
        retention_proofs: Vec<Vec<u8>>,
    ) -> Result<ChangeResponse> {
        let payload = serde_json::to_vec(&request).map_err(|e| {
            SdkError::ValidationError(format!("failed to serialize InviteRequest: {e}"))
        })?;

        let insert_change_req = change_request_from_change(insert_change, vec![]);

        let req = DbRequest {
            request_id: uuid::Uuid::new_v4().to_string(),
            operation: Some(db_request::Operation::AddMember(AddMemberRequest {
                payload,
                insert: Some(insert_change_req),
                retention_proofs,
            })),
        };

        let resp = self.send_request(req).await?;

        if let Some(db_response::Result::AddMember(add_resp)) = resp.result {
            let change_response: ChangeResponse = add_resp
                .change
                .ok_or_else(|| SdkError::DatabaseError("missing change response".into()))?
                .try_into()?;
            Ok(change_response)
        } else {
            Err(SdkError::DatabaseError("unexpected response type".into()))
        }
    }

    async fn remove_member(
        &self,
        request: RekeyRequest,
        remaining_uids: &[i64],
        delete_change: &Change,
        retention_proofs: Vec<Vec<u8>>,
    ) -> Result<ChangeResponse> {
        let payload = serde_json::to_vec(&request).map_err(|e| {
            SdkError::ValidationError(format!("failed to serialize RekeyRequest: {e}"))
        })?;

        let delete_change_req = change_request_from_change(delete_change, vec![]);

        let req = DbRequest {
            request_id: uuid::Uuid::new_v4().to_string(),
            operation: Some(db_request::Operation::RemoveMember(RemoveMemberRequest {
                payload,
                remaining_uids: remaining_uids.to_vec(),
                delete: Some(delete_change_req),
                retention_proofs,
            })),
        };

        let resp = self.send_request(req).await?;

        if let Some(db_response::Result::RemoveMember(remove_resp)) = resp.result {
            let change_response: ChangeResponse = remove_resp
                .change
                .ok_or_else(|| SdkError::DatabaseError("missing change response".into()))?
                .try_into()?;
            Ok(change_response)
        } else {
            Err(SdkError::DatabaseError("unexpected response type".into()))
        }
    }

    async fn submit_retention(
        &self,
        change: &Change,
        retention_proofs: Vec<Vec<u8>>,
        rekey_request: Option<RekeyRequest>,
    ) -> Result<ChangeResponse> {
        use encrypted_spaces_backend::proto::RetentionRequest;

        let rekey_payload = match rekey_request {
            Some(req) => {
                let bytes = serde_json::to_vec(&req).map_err(|e| {
                    SdkError::ValidationError(format!("failed to serialize RekeyRequest: {e}"))
                })?;
                Some(bytes)
            }
            None => None,
        };

        let change_req = change_request_from_change(change, vec![]);

        let req = DbRequest {
            request_id: uuid::Uuid::new_v4().to_string(),
            operation: Some(db_request::Operation::Retention(RetentionRequest {
                change: Some(change_req),
                retention_proofs,
                rekey_payload,
            })),
        };

        let resp = self.send_request(req).await?;

        if let Some(db_response::Result::Retention(retention_resp)) = resp.result {
            let change_response: ChangeResponse = retention_resp
                .change
                .ok_or_else(|| SdkError::DatabaseError("missing change response".into()))?
                .try_into()?;
            Ok(change_response)
        } else {
            Err(SdkError::DatabaseError("unexpected response type".into()))
        }
    }

    async fn fetch_my_key_delivery(&self) -> Result<Option<Vec<u8>>> {
        use encrypted_spaces_backend::proto::FetchMyKeyDeliveryRequest;

        let req = DbRequest {
            request_id: uuid::Uuid::new_v4().to_string(),
            operation: Some(db_request::Operation::FetchMyKeyDelivery(
                FetchMyKeyDeliveryRequest {},
            )),
        };

        let resp = self.send_request(req).await?;
        if let Some(db_response::Result::FetchMyKeyDelivery(delivery_resp)) = resp.result {
            if delivery_resp.has_delivery {
                Ok(Some(delivery_resp.payload))
            } else {
                Ok(None)
            }
        } else {
            Err(SdkError::DatabaseError("unexpected response type".into()))
        }
    }

    async fn authenticate(&self, auth_context: &AuthContext) -> Result<()> {
        use async_tungstenite::tungstenite::Message;
        use futures_util::SinkExt;

        // Tear down existing connection and reconnect with the new auth context.
        // auth_context.space_id determines which space the connection is scoped to.
        if let Some(task) = self.read_task.lock().await.take() {
            task.abort();
        }
        {
            let mut guard = self.write.lock().await;
            if let Some(writer) = guard.as_mut() {
                // Send a proper close frame so the server sees a clean close
                // instead of "Connection reset without closing handshake".
                let _ = writer.send(Message::Close(None)).await;
            }
            *guard = None;
        }
        self.pending.lock().await.clear();
        // Store the base64url-encoded auth context for file HTTP requests
        let auth_json = serde_json::to_vec(auth_context).map_err(|e| {
            SdkError::ValidationError(format!("failed to serialize auth context: {e}"))
        })?;
        *self.auth_b64.lock().await =
            Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(auth_json));
        self.connect(auth_context).await
    }

    fn subscribe_ephemeral(&self) -> Result<crate::transport::EphemeralReceiver> {
        Ok(self.ephemeral_tx.subscribe())
    }

    fn subscribe_broadcasts(&self) -> Result<crate::transport::BroadcastReceiver> {
        Ok(self.bcast_tx.subscribe())
    }

    async fn send_ephemeral(&self, uid: u32, kind: &str, payload: &[u8]) -> Result<()> {
        use async_tungstenite::tungstenite::Message;
        use futures_util::SinkExt;

        let frame = WsFrame {
            payload: Some(ws_frame::Payload::Ephemeral(Ephemeral {
                uid,
                kind: kind.to_string(),
                payload: payload.to_vec(),
            })),
        };
        let encoded = frame.encode_to_vec();

        let mut guard = self.write.lock().await;
        let writer = guard.as_mut().ok_or_else(|| {
            SdkError::DatabaseError("not connected — call authenticate() first".into())
        })?;
        writer
            .send(Message::Binary(encoded))
            .await
            .map_err(|e| SdkError::DatabaseError(format!("send ephemeral failed: {e}")))?;
        Ok(())
    }

    async fn file_upload(&self, hash: &str, data: Vec<u8>) -> Result<()> {
        let auth_b64 = self
            .auth_b64
            .lock()
            .await
            .clone()
            .ok_or_else(|| SdkError::ValidationError("not authenticated".into()))?;
        let http_url = ws_url_to_http(&self.url);
        let url = format!("{http_url}/file/{hash}?auth={auth_b64}");

        let req = hyper::Request::builder()
            .method(hyper::Method::PUT)
            .uri(&url)
            .body(hyper::Body::from(data))
            .map_err(|e| SdkError::DatabaseError(format!("file upload request build: {e}")))?;

        let resp = self
            .file_client
            .request(req)
            .await
            .map_err(|e| SdkError::DatabaseError(format!("file upload failed: {e}")))?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let body = hyper::body::to_bytes(resp.into_body())
                .await
                .map(|b| String::from_utf8_lossy(&b).to_string())
                .unwrap_or_default();
            Err(SdkError::DatabaseError(format!(
                "file upload failed: {body}"
            )))
        }
    }

    async fn file_download(&self, hash: &str) -> Result<Vec<u8>> {
        let auth_b64 = self
            .auth_b64
            .lock()
            .await
            .clone()
            .ok_or_else(|| SdkError::ValidationError("not authenticated".into()))?;
        let http_url = ws_url_to_http(&self.url);
        let url: hyper::Uri = format!("{http_url}/file/{hash}?auth={auth_b64}")
            .parse()
            .map_err(|e| SdkError::DatabaseError(format!("file download url parse: {e}")))?;

        let resp = self
            .file_client
            .get(url)
            .await
            .map_err(|e| SdkError::DatabaseError(format!("file download failed: {e}")))?;

        if resp.status().is_success() {
            let bytes = hyper::body::to_bytes(resp.into_body())
                .await
                .map_err(|e| SdkError::DatabaseError(format!("file download body: {e}")))?;
            Ok(bytes.to_vec())
        } else {
            Err(SdkError::DatabaseError(format!("file not found: {hash}")))
        }
    }
}

/// Convert a WebSocket URL (ws://host:port/ws) to the HTTP base URL (http://host:port).
/// Strips the path component so file requests go to the server root.
fn ws_url_to_http(ws_url: &str) -> String {
    let (scheme, rest) = if let Some(rest) = ws_url.strip_prefix("wss://") {
        ("https", rest)
    } else if let Some(rest) = ws_url.strip_prefix("ws://") {
        ("http", rest)
    } else {
        return ws_url.to_string();
    };
    let authority = rest.split('/').next().unwrap_or(rest);
    format!("{scheme}://{authority}")
}

#[cfg(test)]
mod hash_backed_change_request_tests {
    use super::*;
    use encrypted_spaces_changelog_core::changelog::{HashedValues, OpType, ROOT_TREE_PATH};
    use encrypted_spaces_storage_encoding::hashstore_hash;

    #[test]
    fn hash_backed_change_request_proto_carries_material() {
        let mut change = Change::new(
            OpType::Insert,
            7,
            ROOT_TREE_PATH,
            &[b"key"],
            &[b"value"],
            3,
            2,
            [9u8; 32],
        )
        .expect("valid change");
        let full_value = b"full serialized value".to_vec();
        let mut hashed_values = HashedValues::new();
        hashed_values.insert(hashstore_hash(&full_value), full_value.clone());
        change.hashed_values = hashed_values;

        let request = change_request_from_change(&change, vec![b"proof".to_vec()]);

        assert_eq!(request.retention_proofs, vec![b"proof".to_vec()]);
        assert_eq!(request.values_sidecar, vec![full_value]);
    }
}
