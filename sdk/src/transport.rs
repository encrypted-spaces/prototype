use encrypted_spaces_backend::{
    access_control::AuthContext,
    error::{Result, SdkError},
    merk_storage::proofs::VerifiedRows,
    query::Query,
    schema::Schema,
};
use encrypted_spaces_changelog_core::changelog::{Change, ChangeResponse, FastForwardData};
use encrypted_spaces_key_manager::{InviteRequest, RekeyRequest};
use std::any::Any;
use std::collections::HashMap;

/// Generic ephemeral event received from another user.
/// The `kind` field discriminates the message type (e.g. "cursor", "typing");
/// `payload` carries the application-defined body.
#[derive(Clone, Debug, serde::Serialize)]
pub struct EphemeralEvent {
    pub uid: u32,
    pub kind: String,
    pub payload: Vec<u8>,
}

/// Receiver for real-time ephemeral events (native only).
#[cfg(not(target_arch = "wasm32"))]
pub type EphemeralReceiver = tokio::sync::broadcast::Receiver<EphemeralEvent>;

/// Receiver for real-time broadcast events applied by the server.
pub type BroadcastReceiver =
    tokio::sync::broadcast::Receiver<crate::websocket_transport::BroadcastEvent>;

/// Transport trait for client-server communication
///
/// This trait defines the interface for sending database operations from the SDK client
/// to a remote (or local) server. Implementations handle the communication layer
/// (e.g., WebSocket, HTTP, in-process calls) but don't implement the actual storage logic.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait Transport: Send + Sync + 'static {
    /// Submit a signed change and any hashed values needed for hash-backed writes.
    ///
    /// The returned `ChangeResponse.hashed_values` may be empty: the wire
    /// transport strips it as a bandwidth optimization since the submitter
    /// already holds the full values in `change.hashed_values`. Callers
    /// must not rely on the response carrying hashed values back.
    async fn submit_change(
        &self,
        change: &Change,
        retention_proofs: Vec<Vec<u8>>,
    ) -> Result<ChangeResponse>;

    /// Fast-forward from a given change ID
    async fn fast_forward(&self, change_id: u32) -> Result<FastForwardData>;

    /// Fast-forward from a given change ID, additionally requesting proof
    /// that the supplied `expected_change_ids` (acknowledged local
    /// submissions) are incorporated. Transports that can carry the extra
    /// request field override this; the default ignores it and delegates to
    /// [`Transport::fast_forward`], which is sufficient for transports/tests
    /// that never drive the issue-#212 discharge path.
    async fn fast_forward_with_expected(
        &self,
        change_id: u32,
        _expected_change_ids: &[u32],
    ) -> Result<FastForwardData> {
        self.fast_forward(change_id).await
    }

    /// Execute SELECT query, verify the Merk proof against the given commitment,
    /// and return raw rows organized by table.
    /// Decryption, filtering, and deserialization are handled by the SDK layer.
    async fn select(
        &self,
        query: Query,
        commitment: &[u8; 32],
        schemas: &HashMap<String, Schema>,
    ) -> Result<VerifiedRows>;

    /// Upcast to `&dyn Any` for runtime downcasts to concrete transport types.
    fn as_any(&self) -> &dyn Any;

    /// Fetch the GK delivery slot bytes for the authenticated user.
    ///
    /// Returns `Some(payload)` if a slot has been written for this user, or
    /// `None` if no slot exists. `None` is intentionally ambiguous between
    /// "no slot has ever been written" and "slot was lost from the in-memory
    /// key-delivery store" (e.g. a server restart without durable slot storage).
    /// Repeated fetches of the same slot are idempotent; new accepted rekeys
    /// overwrite the slot.
    async fn fetch_my_key_delivery(&self) -> Result<Option<Vec<u8>>> {
        Err(SdkError::ValidationError(
            "fetch_my_key_delivery is not supported by this transport".into(),
        ))
    }

    /// Add a new member to the group.
    ///
    /// Atomically inserts the new user record (via the signed `Change`)
    /// and writes the new member's GK delivery slot so they can recover
    /// the current group key on their first `fetch_my_key_delivery`
    /// after join.
    async fn add_member(
        &self,
        request: InviteRequest,
        insert_change: &Change,
        retention_proofs: Vec<Vec<u8>>,
    ) -> Result<ChangeResponse>;

    /// Remove a member from the group.
    ///
    /// Atomically deletes the user record, inserts key history, writes
    /// retention data, overwrites each remaining member's GK delivery slot
    /// with fresh recovery material, and removes the deleted user's slot.
    ///
    /// Returns the `ChangeResponse` from the delete operation.
    async fn remove_member(
        &self,
        request: RekeyRequest,
        remaining_uids: &[i64],
        delete_change: &Change,
        retention_proofs: Vec<Vec<u8>>,
    ) -> Result<ChangeResponse>;

    /// Submit a retention-only operation (Extend, Reduce, or standalone Rekey).
    ///
    /// Optionally carries a `RekeyRequest` for ops that rotate the group
    /// key (so the server can write delivery slots for all members).
    async fn submit_retention(
        &self,
        change: &Change,
        retention_proofs: Vec<Vec<u8>>,
        rekey_request: Option<RekeyRequest>,
    ) -> Result<ChangeResponse>;

    /// Authenticate the transport connection with the given auth context.
    /// The `auth_context.space_id` identifies which space to connect to for
    /// network transports (e.g. WebSocket).
    async fn authenticate(&self, _auth_context: &AuthContext) -> Result<()>;

    /// Send a generic ephemeral message to the server for relay to all peers.
    /// `uid` is the sender's user ID; `kind` discriminates the message type;
    /// `payload` is the application-defined body.
    #[cfg(not(target_arch = "wasm32"))]
    async fn send_ephemeral(&self, _uid: u32, _kind: &str, _payload: &[u8]) -> Result<()> {
        Err(SdkError::ValidationError(
            "send_ephemeral is not supported by this transport".into(),
        ))
    }

    /// Subscribe to ephemeral events from other users.
    /// Returns an error for transports that do not support subscriptions.
    #[cfg(not(target_arch = "wasm32"))]
    fn subscribe_ephemeral(&self) -> Result<EphemeralReceiver> {
        Err(SdkError::ValidationError(
            "subscribe_ephemeral is not supported by this transport".into(),
        ))
    }

    /// Subscribe to server-applied broadcast events.
    /// Returns an error for transports that do not support subscriptions.
    fn subscribe_broadcasts(&self) -> Result<BroadcastReceiver> {
        Err(SdkError::ValidationError(
            "subscribe_broadcasts is not supported by this transport".into(),
        ))
    }

    // --- File operations ---

    /// Upload encrypted file data, addressed by its content hash.
    async fn file_upload(&self, hash: &str, data: Vec<u8>) -> Result<()>;

    /// Download encrypted file data by content hash.
    async fn file_download(&self, hash: &str) -> Result<Vec<u8>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------
    // EphemeralEvent serialization
    // ---------------------------------------------------------------------

    #[test]
    fn ephemeral_event_serializes_with_expected_shape() {
        let evt = EphemeralEvent {
            uid: 42,
            kind: "cursor".to_string(),
            payload: vec![1, 2, 3],
        };
        let v = serde_json::to_value(&evt).unwrap();

        assert_eq!(v.get("uid").and_then(|x| x.as_u64()), Some(42));
        assert_eq!(v.get("kind").and_then(|x| x.as_str()), Some("cursor"));
        let payload = v
            .get("payload")
            .and_then(|x| x.as_array())
            .expect("payload should serialize as an array");
        assert_eq!(payload.len(), 3);
    }

    #[test]
    fn ephemeral_event_serialization_preserves_empty_payload() {
        let evt = EphemeralEvent {
            uid: 0,
            kind: "noop".to_string(),
            payload: Vec::new(),
        };
        let v = serde_json::to_value(&evt).unwrap();
        let payload = v.get("payload").and_then(|x| x.as_array()).unwrap();
        assert!(payload.is_empty());
    }

    // ---------------------------------------------------------------------
    // Transport trait default-method behaviour
    //
    // A minimal stub Transport: every required method is `unimplemented!`
    // because these tests only exercise the trait's *default* method
    // implementations. If a test accidentally calls a required method it
    // panics loudly, which is the desired failure mode.
    // ---------------------------------------------------------------------

    struct StubTransport;

    #[async_trait::async_trait]
    impl Transport for StubTransport {
        async fn submit_change(&self, _: &Change, _: Vec<Vec<u8>>) -> Result<ChangeResponse> {
            unimplemented!("stub")
        }

        async fn fast_forward(&self, _: u32) -> Result<FastForwardData> {
            unimplemented!("stub")
        }

        async fn select(
            &self,
            _: Query,
            _: &[u8; 32],
            _: &HashMap<String, Schema>,
        ) -> Result<VerifiedRows> {
            unimplemented!("stub")
        }

        fn as_any(&self) -> &dyn Any {
            self
        }

        async fn add_member(
            &self,
            _: InviteRequest,
            _: &Change,
            _: Vec<Vec<u8>>,
        ) -> Result<ChangeResponse> {
            unimplemented!("stub")
        }

        async fn remove_member(
            &self,
            _: RekeyRequest,
            _: &[i64],
            _: &Change,
            _: Vec<Vec<u8>>,
        ) -> Result<ChangeResponse> {
            unimplemented!("stub")
        }

        async fn submit_retention(
            &self,
            _: &Change,
            _: Vec<Vec<u8>>,
            _: Option<RekeyRequest>,
        ) -> Result<ChangeResponse> {
            unimplemented!("stub")
        }

        async fn authenticate(&self, _: &AuthContext) -> Result<()> {
            unimplemented!("stub")
        }

        async fn file_upload(&self, _: &str, _: Vec<u8>) -> Result<()> {
            unimplemented!("stub")
        }

        async fn file_download(&self, _: &str) -> Result<Vec<u8>> {
            unimplemented!("stub")
        }
    }

    fn assert_unsupported(err: SdkError, method_name: &str) {
        match err {
            SdkError::ValidationError(msg) => {
                assert!(
                    msg.contains(method_name) && msg.contains("not supported"),
                    "expected error to mention '{method_name}' and 'not supported', got: {msg}"
                );
            }
            other => panic!("expected ValidationError, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn default_fetch_my_key_delivery_returns_unsupported_error() {
        let err = StubTransport
            .fetch_my_key_delivery()
            .await
            .expect_err("default impl should error");
        assert_unsupported(err, "fetch_my_key_delivery");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn default_send_ephemeral_returns_unsupported_error() {
        let err = StubTransport
            .send_ephemeral(0, "cursor", &[])
            .await
            .expect_err("default impl should error");
        assert_unsupported(err, "send_ephemeral");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn default_subscribe_ephemeral_returns_unsupported_error() {
        let err = StubTransport
            .subscribe_ephemeral()
            .expect_err("default impl should error");
        assert_unsupported(err, "subscribe_ephemeral");
    }

    #[test]
    fn default_subscribe_broadcasts_returns_unsupported_error() {
        let err = StubTransport
            .subscribe_broadcasts()
            .expect_err("default impl should error");
        assert_unsupported(err, "subscribe_broadcasts");
    }

    // ---------------------------------------------------------------------
    // as_any upcast
    // ---------------------------------------------------------------------

    #[test]
    fn as_any_allows_downcast_back_to_concrete_type() {
        let t: Box<dyn Transport> = Box::new(StubTransport);
        let any_ref = t.as_any();
        assert!(any_ref.downcast_ref::<StubTransport>().is_some());
    }
}
