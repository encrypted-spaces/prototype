use crate::app_config::AppConfig;
use crate::db::{self, op_name};
use crate::inspector::{self, ConnectionEvent, Inspector, InspectorEvent};
use crate::ShutdownRx;
use encrypted_spaces_backend::access_control::AuthContext;
use encrypted_spaces_backend::proto::{
    db_request, db_response, ws_frame, Broadcast as ProtoBroadcast, ChangeResponse, ChangelogEntry,
    DbRequest, DbResponse, Ephemeral, WsFrame,
};
use encrypted_spaces_backend::SpaceId;
use futures_util::{SinkExt, StreamExt};
use hyper_tungstenite::tungstenite::Message;
use hyper_tungstenite::HyperWebsocket;
use prost::Message as ProstMessage;
use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

type WsStream = hyper_tungstenite::WebSocketStream<hyper::upgrade::Upgraded>;

/// Bound the two places where a connection task could otherwise retain an
/// upgraded socket forever: waiting for Hyper to hand over the connection and
/// waiting for the writer half to flush/close after the reader has stopped.
const WEBSOCKET_UPGRADE_TIMEOUT: Duration = Duration::from_secs(10);
const WEBSOCKET_CLOSE_TIMEOUT: Duration = Duration::from_secs(2);

/// Process-wide monotonic id used to distinguish individual websocket
/// connections so broadcasts can skip the originating client.
static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

/// Opaque per-connection identifier; only meaningful for equality
/// comparisons inside this process.
pub(crate) type ConnectionId = u64;

fn next_connection_id() -> ConnectionId {
    NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed)
}

/// A single client connection within a space.
pub(crate) struct ClientConnection {
    id: ConnectionId,
    sender: mpsc::UnboundedSender<WriterCommand>,
}

/// Commands sent to the single task that owns the WebSocket write half.
/// Keeping close/flush on that task avoids concurrent mutable access to the
/// Tungstenite state shared by the split read and write halves.
#[derive(Debug)]
enum WriterCommand {
    Message(Message),
    Flush,
    Close,
}

/// Registry mapping SpaceId -> list of client connections for broadcasts.
pub type ConnectionRegistry = Arc<tokio::sync::Mutex<HashMap<SpaceId, Vec<ClientConnection>>>>;

pub fn new_connection_registry() -> ConnectionRegistry {
    Arc::new(tokio::sync::Mutex::new(HashMap::new()))
}

// ---------------------------------------------------------------------------
// Broadcast helpers
// ---------------------------------------------------------------------------

struct BroadcastData {
    change_entry: Option<ChangelogEntry>,
    change_response: Option<ChangeResponse>,
}

fn extract_broadcast_data(
    operation: &Option<db_request::Operation>,
    result: &Option<db_response::Result>,
) -> Option<BroadcastData> {
    use encrypted_spaces_backend::proto::{db_request, db_response};
    match (operation, result) {
        (Some(db_request::Operation::Change(req)), Some(db_response::Result::Change(resp))) => {
            Some(BroadcastData {
                change_entry: req.change.clone(),
                change_response: Some(resp.clone()),
            })
        }
        (
            Some(db_request::Operation::AddMember(req)),
            Some(db_response::Result::AddMember(resp)),
        ) => Some(BroadcastData {
            change_entry: req.insert.as_ref().and_then(|ins| ins.change.clone()),
            change_response: resp.change.clone(),
        }),
        (
            Some(db_request::Operation::RemoveMember(req)),
            Some(db_response::Result::RemoveMember(resp)),
        ) => Some(BroadcastData {
            change_entry: req.delete.as_ref().and_then(|d| d.change.clone()),
            change_response: resp.change.clone(),
        }),
        (
            Some(db_request::Operation::Retention(req)),
            Some(db_response::Result::Retention(resp)),
        ) => Some(BroadcastData {
            change_entry: req.change.as_ref().and_then(|c| c.change.clone()),
            change_response: resp.change.clone(),
        }),
        _ => None,
    }
}

/// Strip hashed values from the direct response to the submitting client.
/// The submitter already has the full values in `Change.hashed_values`;
/// only broadcast recipients need the server to echo them back.
fn strip_response_hashed_values(resp: &mut DbResponse) {
    use encrypted_spaces_backend::proto::db_response;
    match &mut resp.result {
        Some(db_response::Result::Change(r)) => r.values_sidecar.clear(),
        Some(db_response::Result::AddMember(r)) => {
            if let Some(c) = &mut r.change {
                c.values_sidecar.clear();
            }
        }
        Some(db_response::Result::RemoveMember(r)) => {
            if let Some(c) = &mut r.change {
                c.values_sidecar.clear();
            }
        }
        Some(db_response::Result::Retention(r)) => {
            if let Some(c) = &mut r.change {
                c.values_sidecar.clear();
            }
        }
        _ => {}
    }
}

fn send_broadcast_to(broadcast: &ProtoBroadcast, connections: &[&ClientConnection]) {
    if connections.is_empty() {
        return;
    }
    let frame = WsFrame {
        payload: Some(ws_frame::Payload::Broadcast(broadcast.clone())),
    }
    .encode_to_vec();
    for conn in connections {
        let _ = conn
            .sender
            .send(WriterCommand::Message(Message::Binary(frame.clone())));
    }
}

/// Relay an ephemeral frame to every connected client in the space.
/// No database writes, no changelog — purely fire-and-forget.
async fn relay_ephemeral(msg: &Ephemeral, conn_registry: &ConnectionRegistry, space_id: SpaceId) {
    let frame = WsFrame {
        payload: Some(ws_frame::Payload::Ephemeral(msg.clone())),
    }
    .encode_to_vec();
    let reg = conn_registry.lock().await;
    if let Some(conns) = reg.get(&space_id) {
        for conn in conns {
            let _ = conn
                .sender
                .send(WriterCommand::Message(Message::Binary(frame.clone())));
        }
    }
}

/// Build and send the same broadcast frame to every connected client in
/// the space, except for the connection identified by `exclude` (the
/// originator of the change).  Passing `None` broadcasts to everyone.
async fn send_broadcast(
    data: BroadcastData,
    conn_registry: &ConnectionRegistry,
    space_id: SpaceId,
    exclude: Option<ConnectionId>,
) {
    let reg = conn_registry.lock().await;
    let connections = match reg.get(&space_id) {
        Some(conns) => conns,
        None => {
            log::debug!("ws: broadcast skipped, no connections for space={space_id}");
            return;
        }
    };

    let broadcast = ProtoBroadcast {
        change_entry: data.change_entry,
        change_response: data.change_response,
    };

    let recipients: Vec<&ClientConnection> = connections
        .iter()
        .filter(|c| Some(c.id) != exclude)
        .collect();
    send_broadcast_to(&broadcast, &recipients);

    log::debug!(
        "ws: broadcasted to {} connection(s) for space={} (excluded={:?})",
        recipients.len(),
        space_id,
        exclude,
    );
}

fn send_direct_response(
    payload: ws_frame::Payload,
    response_tx: &mpsc::UnboundedSender<WriterCommand>,
    space_id: SpaceId,
    label: &str,
) {
    let frame = WsFrame {
        payload: Some(payload),
    };
    let bytes = frame.encode_to_vec();
    log::debug!("ws: {label} response len={}B", bytes.len());
    match response_tx.send(WriterCommand::Message(Message::Binary(bytes))) {
        Ok(_) => log::debug!("ws: queued {label} response to writer"),
        Err(e) => log::error!("space={space_id} ws: {label} response send failed err={e}"),
    }
}

// ---------------------------------------------------------------------------
// Per-connection state
// ---------------------------------------------------------------------------

/// Shared state for a single WebSocket connection, threaded through the read
/// and write halves so helpers can access it without long parameter lists.
struct ConnectionState {
    space_id: SpaceId,
    /// Identifier for *this* connection; used to skip ourselves when
    /// broadcasting changes we just applied.
    connection_id: ConnectionId,
    app_cfg: Arc<AppConfig>,
    auth: Arc<std::sync::Mutex<Option<AuthContext>>>,
    /// Sends encoded frames directly back to this client (responses, notifications).
    ///
    /// This is deliberately moved into the connection state rather than cloned
    /// into it. Once the registry entry is removed, dropping the state must
    /// release the final lifecycle-owned sender so the writer can exit.
    response_tx: mpsc::UnboundedSender<WriterCommand>,
    /// Connection registry for broadcasts.
    conn_registry: ConnectionRegistry,
}

impl ConnectionState {
    fn auth_context(&self) -> AuthContext {
        self.auth
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| AuthContext::anonymous(self.space_id))
    }
}

// ---------------------------------------------------------------------------
// Frame dispatch (read loop)
// ---------------------------------------------------------------------------

async fn handle_db_request(db_msg: DbRequest, state: &ConnectionState) {
    let opn = op_name(&db_msg.operation);
    log::debug!(
        "ws: decoded DbRequest request_id={} op={}",
        db_msg.request_id,
        opn
    );

    let operation_snapshot = db_msg.operation.clone();
    let auth = state.auth_context();
    let mut resp = db::dispatch(db_msg, (*state.app_cfg).clone(), auth).await;

    if let Some(bcast) = extract_broadcast_data(&operation_snapshot, &resp.result) {
        send_broadcast(
            bcast,
            &state.conn_registry,
            state.space_id,
            Some(state.connection_id),
        )
        .await;
    }

    strip_response_hashed_values(&mut resp);
    send_direct_response(
        ws_frame::Payload::DbResponse(resp),
        &state.response_tx,
        state.space_id,
        "db",
    );
}

/// Run an operation in its own task while normally awaiting it inline.
///
/// Dropping the waiter detaches rather than cancels the spawned task. Database
/// dispatch uses this boundary so a writer-side connection failure cannot
/// cancel the post-commit peer broadcast.
async fn run_cancellation_safe<F>(operation: F, label: &'static str)
where
    F: Future<Output = ()> + Send + 'static,
{
    if let Err(error) = tokio::spawn(operation).await {
        log::error!("ws: {label} task failed: {error}");
    }
}

async fn dispatch_frame(frame: WsFrame, state: &Arc<ConnectionState>) {
    match frame.payload {
        Some(ws_frame::Payload::DbRequest(db_msg)) => {
            let request_state = Arc::clone(state);
            run_cancellation_safe(
                async move {
                    handle_db_request(db_msg, &request_state).await;
                },
                "database request",
            )
            .await;
        }
        Some(ws_frame::Payload::DbResponse(_)) => {
            log::warn!(
                "space={} ws: received unsolicited DbResponse from client (ignored)",
                state.space_id
            );
        }
        Some(ws_frame::Payload::Broadcast(_)) => {
            log::warn!(
                "space={} ws: received Broadcast from client (ignored)",
                state.space_id
            );
        }
        Some(ws_frame::Payload::Ephemeral(e)) => {
            relay_ephemeral(&e, &state.conn_registry, state.space_id).await;
        }
        None => {
            log::warn!(
                "space={} ws: received empty WsFrame payload",
                state.space_id
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Read loop
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadLoopExit {
    /// The peer sent a WebSocket close frame, so flush Tungstenite's close reply.
    PeerClosed,
    /// EOF, reset, or another read error: the peer is gone, so just drop our half.
    PeerGone,
    /// Process shutdown: initiate a best-effort WebSocket close.
    Shutdown,
}

async fn run_read_loop(
    mut read: futures_util::stream::SplitStream<WsStream>,
    state: &Arc<ConnectionState>,
    mut shutdown_rx: ShutdownRx,
) -> ReadLoopExit {
    loop {
        tokio::select! {
            biased;
            // Shutdown takes priority: if we've been asked to stop,
            // exit before pulling the next frame so the connection
            // can be closed promptly.
            res = shutdown_rx.changed() => {
                if res.is_err() || *shutdown_rx.borrow() {
                    log::info!(
                        "space={} ws: shutdown requested, exiting read loop",
                        state.space_id
                    );
                    return ReadLoopExit::Shutdown;
                }
            }
            msg = read.next() => {
                let Some(msg) = msg else { return ReadLoopExit::PeerGone };
                match msg {
                    Ok(Message::Binary(data)) => {
                        log::debug!("ws: inbound binary len={}B", data.len());
                        match WsFrame::decode(&data[..]) {
                            Ok(frame) => dispatch_frame(frame, state).await,
                            Err(e) => {
                                log::warn!(
                                    "space={} ws: failed to decode WsFrame err={e}",
                                    state.space_id
                                );
                            }
                        }
                    }
                    Ok(Message::Close(_)) => {
                        log::info!("space={} ws: client requested close", state.space_id);
                        return ReadLoopExit::PeerClosed;
                    }
                    Ok(Message::Ping(_)) => {
                        // Tungstenite queues an automatic pong while reading. Wake
                        // the writer so the shared state is flushed even when the
                        // application has no outbound database response pending.
                        let _ = state.response_tx.send(WriterCommand::Flush);
                    }
                    Ok(Message::Text(_)) => log::debug!("ws: ignoring text frame"),
                    Ok(Message::Pong(_)) => {}
                    Err(e) => {
                        let msg = e.to_string();
                        if msg.contains("Connection reset")
                            || msg.contains("closing handshake")
                            || msg.contains("Connection closed")
                        {
                            log::info!(
                                "space={} ws: client disconnected without close frame: {e}",
                                state.space_id
                            );
                        } else {
                            log::error!(
                                "space={} ws: error reading from websocket err={e}",
                                state.space_id
                            );
                        }
                        return ReadLoopExit::PeerGone;
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Write loop
// ---------------------------------------------------------------------------

async fn run_write_loop(
    mut write: futures_util::stream::SplitSink<WsStream, Message>,
    mut response_rx: mpsc::UnboundedReceiver<WriterCommand>,
    space_id: SpaceId,
    mut shutdown_rx: ShutdownRx,
) {
    log::debug!("ws: writer started");
    loop {
        tokio::select! {
            biased;
            res = shutdown_rx.changed() => {
                if res.is_err() || *shutdown_rx.borrow() {
                    log::debug!(
                        "space={space_id} ws: shutdown requested, sending close frame"
                    );
                    // `SinkExt::close` initiates a close when needed and flushes
                    // an already-queued reply when the peer closed first.
                    let _ = write.close().await;
                    break;
                }
            }
            command = response_rx.recv() => {
                let Some(command) = command else { break };
                match command {
                    WriterCommand::Message(msg) => {
                        log::debug!("ws: writer sending frame len={}B", msg.len());
                        if let Err(e) = write.send(msg).await {
                            let err_msg = e.to_string();
                            if err_msg.contains("Connection closed")
                                || err_msg.contains("closing handshake")
                            {
                                log::info!(
                                    "space={space_id} ws: writer send skipped (connection closing): {e}"
                                );
                            } else {
                                log::error!("space={space_id} ws: error sending frame err={e}");
                            }
                            break;
                        }
                    }
                    WriterCommand::Flush => {
                        if let Err(e) = write.flush().await {
                            log::debug!("space={space_id} ws: writer flush ended: {e}");
                            break;
                        }
                    }
                    WriterCommand::Close => {
                        let _ = write.close().await;
                        break;
                    }
                }
            }
        }
    }
    log::debug!("ws: writer exiting");
}

// ---------------------------------------------------------------------------
// Connection lifecycle
// ---------------------------------------------------------------------------

async fn register_connection(
    registry: &ConnectionRegistry,
    space_id: SpaceId,
    auth: &AuthContext,
    sender: &mpsc::UnboundedSender<WriterCommand>,
) -> ConnectionId {
    let id = next_connection_id();
    let mut reg = registry.lock().await;
    reg.entry(space_id).or_default().push(ClientConnection {
        id,
        sender: sender.clone(),
    });
    log::debug!("ws: registered connection id={id} for uid={:?}", auth.uid);
    id
}

async fn unregister_connection(
    registry: &ConnectionRegistry,
    space_id: SpaceId,
    connection_id: ConnectionId,
) {
    let mut reg = registry.lock().await;
    if let Some(connections) = reg.get_mut(&space_id) {
        // Remove this connection unconditionally. The old implementation only
        // removed senders whose receiver was already closed, but the receiver
        // lived in the writer task and the registry sender was what kept that
        // receiver open. That ownership cycle retained the WebSocket write half
        // (and therefore the accepted TCP socket) forever after client FIN.
        connections.retain(|c| c.id != connection_id);
        if connections.is_empty() {
            reg.remove(&space_id);
        }
    }
    log::debug!("ws: unregistered connection id={connection_id} for space={space_id}");
}

pub async fn client_connected(
    ws: HyperWebsocket,
    app_cfg: Arc<AppConfig>,
    conn_registry: ConnectionRegistry,
    auth: Option<AuthContext>,
    space_id: SpaceId,
    mut shutdown_rx: ShutdownRx,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let uid = auth.as_ref().and_then(|a| a.uid);
    let auth_ctx = auth.unwrap_or_else(|| AuthContext::anonymous(space_id));
    if *shutdown_rx.borrow() {
        return Ok(());
    }
    let ws_stream = tokio::select! {
        biased;
        _ = shutdown_rx.changed() => return Ok(()),
        result = tokio::time::timeout(WEBSOCKET_UPGRADE_TIMEOUT, ws) => {
            match result {
                Ok(result) => result?,
                Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "timed out waiting for WebSocket upgrade",
                    ).into());
                }
            }
        }
    };
    log::info!("space={space_id} ws: client connected uid={:?}", uid);

    if let Some(insp) = Inspector::global() {
        insp.emit(InspectorEvent::Connection {
            ts_ms: inspector::now_ms(),
            space_id: space_id.to_string(),
            uid,
            event: ConnectionEvent::Connect,
        });
    }

    let (write, read) = ws_stream.split();
    let (response_tx, response_rx) = mpsc::unbounded_channel::<WriterCommand>();

    let auth = Arc::new(std::sync::Mutex::new(Some(auth_ctx.clone())));

    let connection_id =
        register_connection(&conn_registry, space_id, &auth_ctx, &response_tx).await;

    let state = Arc::new(ConnectionState {
        space_id,
        connection_id,
        app_cfg,
        auth: auth.clone(),
        response_tx,
        conn_registry: conn_registry.clone(),
    });

    let mut write_handle = tokio::spawn(run_write_loop(
        write,
        response_rx,
        space_id,
        shutdown_rx.clone(),
    ));

    // Whichever half stops first owns connection teardown. Selecting the
    // writer prevents a write error from leaving the reader task and registry
    // alive; selecting the reader covers close, FIN, reset, and read errors.
    let mut read_loop = Box::pin(run_read_loop(read, &state, shutdown_rx));
    let (read_exit, writer_finished) = tokio::select! {
        exit = &mut read_loop => (Some(exit), false),
        result = &mut write_handle => {
            if let Err(e) = result {
                log::error!("space={space_id} ws: write task join error err={e}");
            }
            (None, true)
        }
    };
    // Dropping the losing read future releases its split half. Any database
    // request it was awaiting continues in the cancellation-safe task above,
    // including the post-commit broadcast.
    drop(read_loop);

    // Exact-id removal breaks the registry-sender -> channel-receiver ->
    // writer-task -> WebSocket-write-half ownership chain.
    unregister_connection(&conn_registry, space_id, connection_id).await;

    if !writer_finished {
        if matches!(
            read_exit,
            Some(ReadLoopExit::PeerClosed | ReadLoopExit::Shutdown)
        ) {
            let _ = state.response_tx.send(WriterCommand::Close);
        }
        // Dropping the lifecycle state releases its sender. A database request
        // already in flight may retain one deliberate clone until it completes
        // its broadcast/response path.
        drop(state);

        if tokio::time::timeout(WEBSOCKET_CLOSE_TIMEOUT, &mut write_handle)
            .await
            .is_err()
        {
            log::warn!(
                "space={space_id} ws: writer did not close within {:?}; aborting task",
                WEBSOCKET_CLOSE_TIMEOUT
            );
            write_handle.abort();
            let _ = write_handle.await;
        }
    } else {
        drop(state);
    }
    log::info!("space={space_id} ws: client disconnected");

    if let Some(insp) = Inspector::global() {
        insp.emit(InspectorEvent::Connection {
            ts_ms: inspector::now_ms(),
            space_id: space_id.to_string(),
            uid,
            event: ConnectionEvent::Disconnect,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use encrypted_spaces_backend::proto::{
        db_request, db_response, AddMemberRequest, AddMemberResponse, ChangeRequest,
        ChangeResponse, ChangelogEntry, DbResponse, KvData, LogMessage, Query, SelectRequest,
        SelectResponse,
    };

    fn test_space_id() -> SpaceId {
        SpaceId::from([0u8; 16])
    }

    fn make_query(table: &str) -> Query {
        Query {
            table: table.to_string(),
            ..Default::default()
        }
    }

    fn make_changelog_entry() -> ChangelogEntry {
        ChangelogEntry {
            timestamp: 1,
            uid: 42,
            parent_change: 0,
            message: Some(LogMessage {
                op_type: 1,
                tree_path: vec![],
                entries: vec![KvData {
                    key: b"k".to_vec(),
                    value: vec![],
                }],
            }),
            sig_ref: 0,
            parent_clc: vec![],
            signature: vec![],
        }
    }

    fn make_change_response() -> ChangeResponse {
        ChangeResponse {
            change_id: 7,
            old_root: vec![0],
            new_root: vec![1],
            pruned_merkle_tree: vec![],
            rows_affected: 1,
            values_sidecar: vec![],
            accepted_at_server_time: 1,
        }
    }

    // ---------------------------------------------------------------
    // extract_broadcast_data
    // ---------------------------------------------------------------

    #[test]
    fn extract_broadcast_data_from_change() {
        let entry = make_changelog_entry();
        let op = Some(db_request::Operation::Change(ChangeRequest {
            change: Some(entry.clone()),
            values_sidecar: vec![],
            retention_proofs: vec![],
        }));
        let resp = make_change_response();
        let result = Some(db_response::Result::Change(resp.clone()));

        let bcast = extract_broadcast_data(&op, &result).expect("should produce BroadcastData");
        assert_eq!(bcast.change_entry.as_ref().unwrap().uid, entry.uid);
        assert_eq!(
            bcast.change_response.as_ref().unwrap().change_id,
            resp.change_id
        );
    }

    #[test]
    fn extract_broadcast_data_from_add_member() {
        let entry = make_changelog_entry();
        let change_resp = make_change_response();
        let op = Some(db_request::Operation::AddMember(AddMemberRequest {
            payload: vec![],
            insert: Some(ChangeRequest {
                change: Some(entry.clone()),
                values_sidecar: vec![],
                retention_proofs: vec![],
            }),
            retention_proofs: vec![],
        }));
        let result = Some(db_response::Result::AddMember(AddMemberResponse {
            change: Some(change_resp.clone()),
        }));

        let bcast = extract_broadcast_data(&op, &result).expect("should produce BroadcastData");
        assert_eq!(bcast.change_entry.as_ref().unwrap().uid, entry.uid);
        assert_eq!(
            bcast.change_response.as_ref().unwrap().change_id,
            change_resp.change_id
        );
    }

    #[test]
    fn extract_broadcast_data_returns_none_for_select() {
        let op = Some(db_request::Operation::Select(SelectRequest {
            query: Some(make_query("docs")),
            ..Default::default()
        }));
        let result = Some(db_response::Result::Select(SelectResponse {
            ..Default::default()
        }));
        assert!(extract_broadcast_data(&op, &result).is_none());
    }

    #[test]
    fn extract_broadcast_data_returns_none_for_mismatched_op_result() {
        let op = Some(db_request::Operation::Change(ChangeRequest {
            change: Some(make_changelog_entry()),
            values_sidecar: vec![],
            retention_proofs: vec![],
        }));
        // Result is AddMember, not Change — mismatch
        let result = Some(db_response::Result::AddMember(AddMemberResponse {
            change: Some(make_change_response()),
        }));
        assert!(extract_broadcast_data(&op, &result).is_none());
    }

    #[test]
    fn extract_broadcast_data_returns_none_for_none_inputs() {
        assert!(extract_broadcast_data(&None, &None).is_none());
    }

    #[test]
    fn extract_broadcast_data_add_member_missing_insert() {
        let op = Some(db_request::Operation::AddMember(AddMemberRequest {
            payload: vec![],
            insert: None,
            retention_proofs: vec![],
        }));
        let result = Some(db_response::Result::AddMember(AddMemberResponse {
            change: None,
        }));
        let bcast =
            extract_broadcast_data(&op, &result).expect("should still produce BroadcastData");
        assert!(bcast.change_entry.is_none());
        assert!(bcast.change_response.is_none());
    }

    // ---------------------------------------------------------------
    // send_direct_response
    // ---------------------------------------------------------------

    #[test]
    fn send_direct_response_encodes_ws_frame() {
        let (response_tx, mut response_rx) = mpsc::unbounded_channel();
        let sid = test_space_id();
        let payload = ws_frame::Payload::DbResponse(DbResponse {
            request_id: "r1".to_string(),
            status: "ok".to_string(),
            error: String::new(),
            result: None,
        });

        send_direct_response(payload, &response_tx, sid, "test");

        let bytes = match response_rx
            .try_recv()
            .expect("should have received response")
        {
            WriterCommand::Message(Message::Binary(bytes)) => bytes,
            other => panic!("expected binary writer command, got {other:?}"),
        };
        let frame = WsFrame::decode(&bytes[..]).expect("should decode");
        match frame.payload {
            Some(ws_frame::Payload::DbResponse(resp)) => {
                assert_eq!(resp.request_id, "r1");
                assert_eq!(resp.status, "ok");
            }
            other => panic!("expected DbResponse payload, got {:?}", other),
        }
    }

    #[test]
    fn send_direct_response_on_closed_channel_does_not_panic() {
        let (response_tx, response_rx) = mpsc::unbounded_channel();
        drop(response_rx);
        let sid = test_space_id();
        let payload = ws_frame::Payload::DbResponse(DbResponse {
            request_id: "r1".to_string(),
            status: "ok".to_string(),
            error: String::new(),
            result: None,
        });
        send_direct_response(payload, &response_tx, sid, "test"); // should not panic
    }

    #[tokio::test]
    async fn cancellation_safe_operation_outlives_its_waiter() {
        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let (completed_tx, completed_rx) = tokio::sync::oneshot::channel();
        let operation_started = Arc::clone(&started);
        let operation_release = Arc::clone(&release);

        let waiter = tokio::spawn(run_cancellation_safe(
            async move {
                operation_started.notify_one();
                operation_release.notified().await;
                let _ = completed_tx.send(());
            },
            "cancellation test",
        ));

        started.notified().await;
        waiter.abort();
        let _ = waiter.await;
        release.notify_one();

        tokio::time::timeout(Duration::from_secs(1), completed_rx)
            .await
            .expect("detached operation did not finish")
            .expect("operation dropped its completion signal");
    }

    // ---------------------------------------------------------------
    // register_connection / unregister_connection
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn register_connection_adds_sender() {
        let registry = new_connection_registry();
        let (tx, _rx) = mpsc::unbounded_channel();
        let sid = test_space_id();
        let auth = AuthContext::new(Some(42), sid);

        register_connection(&registry, sid, &auth, &tx).await;

        let reg = registry.lock().await;
        let conns = reg.get(&sid).expect("should have entry");
        assert_eq!(conns.len(), 1);
    }

    #[tokio::test]
    async fn register_connection_works_without_uid() {
        let registry = new_connection_registry();
        let (tx, _rx) = mpsc::unbounded_channel();
        let sid = test_space_id();
        let auth = AuthContext::anonymous(sid);

        register_connection(&registry, sid, &auth, &tx).await;

        let reg = registry.lock().await;
        let conns = reg.get(&sid).expect("should have entry");
        assert_eq!(conns.len(), 1);
    }

    #[tokio::test]
    async fn register_multiple_connections_for_same_space() {
        let registry = new_connection_registry();
        let (tx1, _rx1) = mpsc::unbounded_channel();
        let (tx2, _rx2) = mpsc::unbounded_channel();
        let sid = test_space_id();
        let auth1 = AuthContext::new(Some(10), sid);
        let auth2 = AuthContext::new(Some(10), sid);

        register_connection(&registry, sid, &auth1, &tx1).await;
        register_connection(&registry, sid, &auth2, &tx2).await;

        let reg = registry.lock().await;
        assert_eq!(reg.get(&sid).unwrap().len(), 2);
    }

    #[tokio::test]
    async fn unregister_connection_removes_exact_open_sender_and_closes_channel() {
        let registry = new_connection_registry();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let sid = test_space_id();
        let auth = AuthContext::anonymous(sid);

        let id = register_connection(&registry, sid, &auth, &tx).await;
        drop(tx);

        // The registry clone keeps the writer receiver open before cleanup.
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        unregister_connection(&registry, sid, id).await;

        assert!(rx.recv().await.is_none(), "final sender must be released");
        assert!(registry.lock().await.is_empty());
    }

    #[tokio::test]
    async fn unregister_connection_only_removes_requested_connection() {
        let registry = new_connection_registry();
        let (tx1, mut rx1) = mpsc::unbounded_channel();
        let (tx2, mut rx2) = mpsc::unbounded_channel();
        let sid = test_space_id();
        let auth = AuthContext::anonymous(sid);

        let id1 = register_connection(&registry, sid, &auth, &tx1).await;
        let id2 = register_connection(&registry, sid, &auth, &tx2).await;
        drop((tx1, tx2));

        unregister_connection(&registry, sid, id1).await;

        let reg = registry.lock().await;
        let conns = reg.get(&sid).expect("second connection remains");
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].id, id2);
        drop(reg);
        assert!(rx1.recv().await.is_none());
        assert!(matches!(
            rx2.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        unregister_connection(&registry, sid, id2).await;
        assert!(rx2.recv().await.is_none());
    }

    #[tokio::test]
    async fn unregister_connection_noop_when_no_connections() {
        let registry = new_connection_registry();
        let sid = test_space_id();

        unregister_connection(&registry, sid, next_connection_id()).await;
        assert!(registry.lock().await.is_empty());
    }

    // ---------------------------------------------------------------
    // send_broadcast_to
    // ---------------------------------------------------------------

    fn make_broadcast() -> ProtoBroadcast {
        ProtoBroadcast {
            change_entry: Some(make_changelog_entry()),
            change_response: Some(make_change_response()),
        }
    }

    fn decode_broadcast(command: WriterCommand) -> ProtoBroadcast {
        let WriterCommand::Message(Message::Binary(bytes)) = command else {
            panic!("expected binary writer command")
        };
        let frame = WsFrame::decode(&bytes[..]).expect("should decode WsFrame");
        match frame.payload {
            Some(ws_frame::Payload::Broadcast(b)) => b,
            other => panic!("expected Broadcast payload, got {:?}", other),
        }
    }

    #[test]
    fn send_broadcast_to_delivers_frame_to_all_connections() {
        let (tx1, mut rx1) = mpsc::unbounded_channel();
        let (tx2, mut rx2) = mpsc::unbounded_channel();
        let conn1 = ClientConnection {
            id: next_connection_id(),
            sender: tx1,
        };
        let conn2 = ClientConnection {
            id: next_connection_id(),
            sender: tx2,
        };

        let broadcast = make_broadcast();
        send_broadcast_to(&broadcast, &[&conn1, &conn2]);

        let b1 = decode_broadcast(rx1.try_recv().unwrap());
        let b2 = decode_broadcast(rx2.try_recv().unwrap());
        assert_eq!(b1.change_entry.as_ref().unwrap().uid, 42);
        assert_eq!(b2.change_entry.as_ref().unwrap().uid, 42);
    }

    #[test]
    fn send_broadcast_to_skips_empty_slice() {
        let broadcast = make_broadcast();
        send_broadcast_to(&broadcast, &[]); // should not panic
    }

    #[tokio::test]
    async fn send_broadcast_excludes_originating_connection() {
        let registry = new_connection_registry();
        let sid = test_space_id();
        let (tx1, mut rx1) = mpsc::unbounded_channel();
        let (tx2, mut rx2) = mpsc::unbounded_channel();
        let auth = AuthContext::anonymous(sid);

        let originator_id = register_connection(&registry, sid, &auth, &tx1).await;
        let _other_id = register_connection(&registry, sid, &auth, &tx2).await;

        let data = BroadcastData {
            change_entry: Some(make_changelog_entry()),
            change_response: Some(make_change_response()),
        };
        send_broadcast(data, &registry, sid, Some(originator_id)).await;

        // Originator should not receive a broadcast for its own change.
        assert!(rx1.try_recv().is_err());
        // The other client should.
        let b = decode_broadcast(rx2.try_recv().expect("other client gets broadcast"));
        assert_eq!(b.change_entry.as_ref().unwrap().uid, 42);
    }
}
