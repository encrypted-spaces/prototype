//! Telemetry sink for the inspector UI.
//!
//! Emits structured events to an NDJSON file and to an in-process broadcast
//! channel (consumed by `/_inspect/ws` subscribers). Activation: set
//! `ENCRYPTED_SPACES_INSPECTOR_LOG=/path/to/inspector.ndjson` before starting
//! the server or constructing a `LocalTransport`.
//!
//! See `INSPECTOR_PLAN.md` at the repo root for the full design.

pub mod http;

use once_cell::sync::OnceCell;
use serde::Serialize;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, mpsc};

const BROADCAST_CAPACITY: usize = 1024;

/// Process-wide singleton. Initialized lazily from
/// `ENCRYPTED_SPACES_INSPECTOR_LOG` on first access; subsequent calls return
/// the same handle (or `None` if telemetry is disabled).
static GLOBAL: OnceCell<Option<Arc<Inspector>>> = OnceCell::new();

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind")]
pub enum InspectorEvent {
    SchemaSnapshot {
        ts_ms: u64,
        space_id: String,
        tables: Vec<TableInfo>,
    },
    Connection {
        ts_ms: u64,
        space_id: String,
        uid: Option<i64>,
        event: ConnectionEvent,
    },
    Request {
        ts_ms: u64,
        space_id: String,
        request_id: String,
        op: String,
        uid: Option<i64>,
    },
    MerkUpdate {
        ts_ms: u64,
        space_id: String,
        change_id: u32,
        op_type: String,
        old_root: String,
        new_root: String,
        rows_affected: u64,
        entries: Vec<EntrySummary>,
    },
    /// Structural snapshot of the AVL Merkle tree at this change. Emitted
    /// right after the corresponding `MerkUpdate` so a client can diff
    /// successive snapshots to find changed/added/removed nodes.
    MerkSnapshot {
        ts_ms: u64,
        space_id: String,
        change_id: u32,
        node_count: u32,
        root: Option<MerkTreeNode>,
    },
    ChangelogAppend {
        ts_ms: u64,
        space_id: String,
        change_id: u32,
        op_type: String,
        clc_root: String,
        entry_size_bytes: usize,
    },
    Membership {
        ts_ms: u64,
        space_id: String,
        event: MembershipEvent,
        change_id: u32,
        uid: Option<i64>,
    },
    ProofEmitted {
        ts_ms: u64,
        space_id: String,
        proof_kind: ProofKind,
        proof_size_bytes: usize,
        covers_entries: Option<u32>,
        gen_ms: Option<u64>,
        /// For `Select` proofs, a one-line summary of the proven query
        /// (table, predicate, limit, …). This is what the proof attests to,
        /// and it explains size differences — wider ranges / higher limits
        /// cover more rows and produce larger proofs. `None` for other kinds.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        query: Option<String>,
    },
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionEvent {
    Connect,
    Disconnect,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipEvent {
    Add,
    Remove,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofKind {
    Update,
    Select,
    FastForward,
}

#[derive(Clone, Debug, Serialize)]
pub struct TableInfo {
    pub name: String,
    pub internal: bool,
    pub auto_increment: bool,
    pub columns: Vec<ColumnInfo>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ColumnInfo {
    pub name: String,
    pub type_label: String,
    pub plaintext: bool,
    pub indexed: bool,
}

/// Single AVL+Merkle tree node, serialized recursively. The full tree fits
/// inline because demo recordings stay small (~50–100 leaves); larger
/// workloads would warrant a subtree-only encoding.
#[derive(Clone, Debug, Serialize)]
pub struct MerkTreeNode {
    /// Raw key bytes hex-encoded — used as a stable identity across
    /// snapshots so the UI can diff trees.
    pub key_hex: String,
    /// Short human-readable parsed key (e.g. "messages/1/content") or a
    /// `<schema:...>` / `<idx:...>` fallback when the key isn't a column.
    pub label: String,
    /// One of "column" | "row" | "index" | "schema" | "other".
    pub kind: String,
    /// First 16 hex chars of the node hash (sufficient to visually identify
    /// changed nodes; full hash is recoverable from the recording's raw
    /// merkle proofs if needed).
    pub hash: String,
    pub value_size: usize,
    pub left: Option<Box<MerkTreeNode>>,
    pub right: Option<Box<MerkTreeNode>>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "key_kind", rename_all = "snake_case")]
pub enum EntrySummary {
    /// A column write: `(table, row_id, column) → value`.
    Column {
        table: String,
        row_id: i64,
        column: String,
        encrypted: bool,
        value_size: usize,
        /// Short human-readable preview. JSON-rendered cleartext for
        /// plaintext columns, hex prefix + ciphertext label for encrypted.
        value_preview: String,
    },
    /// A row-level write (typically a delete tombstone).
    Row {
        table: String,
        row_id: i64,
        value_size: usize,
    },
    /// A secondary-index write side-effect.
    Index {
        table: String,
        column: String,
        row_id: i64,
        value_size: usize,
    },
    /// Schema metadata or anything we don't categorize further.
    Other { label: String, value_size: usize },
}

/// Telemetry emitter. Cheap to clone (it's an `Arc` internally) and
/// non-blocking; `emit()` drops the event silently if the writer task has
/// gone away.
pub struct Inspector {
    tx: mpsc::UnboundedSender<InspectorEvent>,
    broadcast_tx: broadcast::Sender<InspectorEvent>,
    /// Every event emitted this run, in order. The broadcast channel only
    /// carries events sent after a subscriber connects, so a Live WS client
    /// that opens mid-session would miss the `SchemaSnapshot` / `MerkSnapshot`
    /// emitted at space creation. Replaying this backlog on connect lets it
    /// render state established before it connected.
    history: Arc<Mutex<Vec<InspectorEvent>>>,
}

impl Inspector {
    /// Construct an inspector that writes NDJSON to `path` and fans out to
    /// any future broadcast subscribers. Opens the file in append mode so
    /// multiple runs accumulate into the same recording when desired.
    pub fn new_with_file(path: PathBuf) -> std::io::Result<Arc<Self>> {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;

        let (tx, mut rx) = mpsc::unbounded_channel::<InspectorEvent>();
        let (broadcast_tx, _) = broadcast::channel::<InspectorEvent>(BROADCAST_CAPACITY);
        let broadcast_tx_writer = broadcast_tx.clone();
        let history: Arc<Mutex<Vec<InspectorEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let history_writer = Arc::clone(&history);

        // Writer task: drains events, appends a JSON line per event, and
        // forwards to live subscribers. Synchronous file I/O is fine here —
        // observability sits off the request critical path.
        tokio::spawn(async move {
            while let Some(ev) = rx.recv().await {
                // Record into history BEFORE broadcasting. A client subscribes
                // and then snapshots history; recording first guarantees every
                // event lands in the snapshot, the broadcast, or both (harmless
                // duplicates) — never neither.
                if let Ok(mut h) = history_writer.lock() {
                    h.push(ev.clone());
                }
                match serde_json::to_string(&ev) {
                    Ok(line) => {
                        if let Err(e) = writeln!(file, "{line}") {
                            log::warn!("inspector: write failed: {e}");
                            break;
                        }
                        let _ = file.flush();
                    }
                    Err(e) => log::warn!("inspector: serialize failed: {e}"),
                }
                let _ = broadcast_tx_writer.send(ev);
            }
        });

        log::info!("inspector: NDJSON sink open at {}", path.display());
        Ok(Arc::new(Self {
            tx,
            broadcast_tx,
            history,
        }))
    }

    /// Construct an inspector from `ENCRYPTED_SPACES_INSPECTOR_LOG` if set,
    /// otherwise return `None`. Failures to open the file are logged and
    /// produce `None` rather than panicking — telemetry must never break
    /// the server.
    pub fn from_env() -> Option<Arc<Self>> {
        let path = std::env::var("ENCRYPTED_SPACES_INSPECTOR_LOG").ok()?;
        match Self::new_with_file(PathBuf::from(path)) {
            Ok(insp) => Some(insp),
            Err(e) => {
                log::warn!("inspector: disabled (failed to open log: {e})");
                None
            }
        }
    }

    /// Return the process-wide inspector, initializing it from
    /// `ENCRYPTED_SPACES_INSPECTOR_LOG` on first access. All call sites share
    /// the same writer task and broadcast channel.
    pub fn global() -> Option<Arc<Inspector>> {
        GLOBAL.get_or_init(Self::from_env).clone()
    }

    /// Send an event to the sink. Never blocks; drops silently if the
    /// writer task has terminated.
    pub fn emit(&self, event: InspectorEvent) {
        let _ = self.tx.send(event);
    }

    /// Subscribe to the live event stream (used by future WS endpoint).
    pub fn subscribe(&self) -> broadcast::Receiver<InspectorEvent> {
        self.broadcast_tx.subscribe()
    }

    /// Snapshot of every event emitted so far this run. A new Live WS client
    /// replays this backlog before tailing `subscribe()`, so it renders state
    /// (schema, Merk tree, membership) that was established before it
    /// connected. Take this *after* subscribing so no event falls in the gap.
    pub fn history_snapshot(&self) -> Vec<InspectorEvent> {
        self.history.lock().map(|h| h.clone()).unwrap_or_default()
    }
}

/// Milliseconds since the unix epoch. Saturates to 0 on clock skew before
/// the epoch (shouldn't happen, but `emit()` is on the hot path so we
/// avoid `unwrap`).
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn round_trip_writes_ndjson() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let insp = Inspector::new_with_file(path.clone()).unwrap();

        insp.emit(InspectorEvent::Connection {
            ts_ms: 1,
            space_id: "abc".into(),
            uid: Some(42),
            event: ConnectionEvent::Connect,
        });
        insp.emit(InspectorEvent::ChangelogAppend {
            ts_ms: 2,
            space_id: "abc".into(),
            change_id: 7,
            op_type: "Insert".into(),
            clc_root: "deadbeef".into(),
            entry_size_bytes: 128,
        });

        // Give the writer task a moment.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"kind\":\"Connection\""));
        assert!(lines[1].contains("\"kind\":\"ChangelogAppend\""));
        assert!(lines[1].contains("\"change_id\":7"));
    }
}
