//! Test infrastructure for the KV cache integration tests in
//! `sdk/tests/cache_regression.rs`.
//!
//! [`CountingTransport`] wraps a `LocalTransport` and counts `select`
//! calls so tests can assert "this was a cache hit" by checking the
//! counter didn't grow across a select. Modeled after the equivalent
//! helper on Trevor's branch, trimmed to what these tests need.

use std::any::Any;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use encrypted_spaces_backend::access_control::AuthContext;
use encrypted_spaces_backend::error::Result;
use encrypted_spaces_backend::merk_storage::proofs::VerifiedRows;
use encrypted_spaces_backend::query::Query;
use encrypted_spaces_changelog_core::changelog::{Change, ChangeResponse, FastForwardData};
use encrypted_spaces_key_manager::{InviteRequest, RekeyRequest};
use encrypted_spaces_sdk::testing::initial_internal_data_commitment;
use encrypted_spaces_sdk::{
    ApplicationSchema, ColumnType, LocalTransport, Schema, SchemaBuilder, Space, Transport,
};

/// `items` table: id, indexed `category`, indexed `price` (real), `name`,
/// encrypted `secret`.
pub fn items_schema() -> Schema {
    SchemaBuilder::new("items")
        .column("id", ColumnType::Integer)
        .plaintext_primary_key()
        .column("category", ColumnType::Integer)
        .unwrap()
        .plaintext()
        .index()
        .column("price", ColumnType::Real)
        .unwrap()
        .plaintext()
        .index()
        .column("name", ColumnType::Text)
        .unwrap()
        .plaintext()
        .column("secret", ColumnType::Text)
        .unwrap()
        .encrypted()
        .build()
        .unwrap()
}

/// `tags` table: id, indexed FK `item_id`, `label`. Used for join tests.
pub fn tags_schema() -> Schema {
    SchemaBuilder::new("tags")
        .column("id", ColumnType::Integer)
        .plaintext_primary_key()
        .column("item_id", ColumnType::Integer)
        .unwrap()
        .plaintext()
        .index()
        .column("label", ColumnType::Text)
        .unwrap()
        .plaintext()
        .build()
        .unwrap()
}

/// Transport wrapper that counts `select` calls. Cache-hit assertion
/// pattern: `let before = snapshot(&t); query(); assert!(was_cache_hit(before, &t));`.
#[derive(Clone)]
pub struct CountingTransport {
    inner: LocalTransport,
    select_calls: Arc<AtomicUsize>,
}

impl CountingTransport {
    pub fn new(inner: LocalTransport) -> Self {
        Self {
            inner,
            select_calls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[async_trait::async_trait]
impl Transport for CountingTransport {
    async fn submit_change(
        &self,
        change: &Change,
        retention_proofs: Vec<Vec<u8>>,
    ) -> Result<ChangeResponse> {
        self.inner.submit_change(change, retention_proofs).await
    }

    async fn fast_forward(&self, change_id: u32) -> Result<FastForwardData> {
        self.inner.fast_forward(change_id).await
    }

    async fn select(&self, query: Query, commitment: &[u8; 32]) -> Result<VerifiedRows> {
        self.select_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.select(query, commitment).await
    }

    fn as_any(&self) -> &dyn Any {
        self.inner.as_any()
    }

    async fn fetch_my_key_delivery(&self) -> Result<Option<Vec<u8>>> {
        self.inner.fetch_my_key_delivery().await
    }

    async fn add_member(
        &self,
        request: InviteRequest,
        insert_change: &Change,
        retention_proofs: Vec<Vec<u8>>,
    ) -> Result<ChangeResponse> {
        self.inner
            .add_member(request, insert_change, retention_proofs)
            .await
    }

    async fn remove_member(
        &self,
        request: RekeyRequest,
        remaining_uids: &[i64],
        delete_change: &Change,
        retention_proofs: Vec<Vec<u8>>,
    ) -> Result<ChangeResponse> {
        self.inner
            .remove_member(request, remaining_uids, delete_change, retention_proofs)
            .await
    }

    async fn submit_retention(
        &self,
        change: &Change,
        retention_proofs: Vec<Vec<u8>>,
        rekey_request: Option<RekeyRequest>,
    ) -> Result<ChangeResponse> {
        self.inner
            .submit_retention(change, retention_proofs, rekey_request)
            .await
    }

    async fn authenticate(&self, auth_context: &AuthContext) -> Result<()> {
        self.inner.authenticate(auth_context).await
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn send_ephemeral(&self, uid: u32, kind: &str, payload: &[u8]) -> Result<()> {
        self.inner.send_ephemeral(uid, kind, payload).await
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn subscribe_ephemeral(&self) -> Result<encrypted_spaces_sdk::transport::EphemeralReceiver> {
        self.inner.subscribe_ephemeral()
    }

    fn subscribe_broadcasts(&self) -> Result<encrypted_spaces_sdk::transport::BroadcastReceiver> {
        self.inner.subscribe_broadcasts()
    }

    async fn file_upload(&self, hash: &str, data: Vec<u8>) -> Result<()> {
        self.inner.file_upload(hash, data).await
    }

    async fn file_download(&self, hash: &str) -> Result<Vec<u8>> {
        self.inner.file_download(hash).await
    }
}

/// Stand up a fresh Space backed by a [`CountingTransport`] with N items
/// (category cycles 1..=5, price = 2.0 * i) and 2 tags per item.
pub async fn setup_space(
    n_items: usize,
) -> std::result::Result<(Space, CountingTransport), Box<dyn std::error::Error>> {
    let transport = LocalTransport::in_memory().await?;
    let counting = CountingTransport::new(transport);
    let dc = initial_internal_data_commitment();
    let space = Space::create(counting.clone(), ApplicationSchema::for_testing(vec![], dc)).await?;

    space.create_table(&items_schema()).await?;
    space.create_table(&tags_schema()).await?;

    let items = space.table::<serde_json::Value>("items");
    for i in 1..=n_items {
        let category = ((i - 1) % 5) + 1;
        let price = (i as f64) * 2.0;
        let row = serde_json::json!({
            "id": serde_json::Value::Null,
            "category": category as i64,
            "price": price,
            "name": format!("item_{i}"),
            "secret": format!("secret_{i}"),
        });
        items.insert(&row)?.execute().await?;
    }

    let tags = space.table::<serde_json::Value>("tags");
    let tag_count = std::cmp::min(n_items, 10);
    for i in 1..=tag_count {
        for t in 1..=2 {
            let row = serde_json::json!({
                "id": serde_json::Value::Null,
                "item_id": i as i64,
                "label": format!("tag_{i}_{t}"),
            });
            tags.insert(&row)?.execute().await?;
        }
    }

    Ok((space, counting))
}

pub async fn setup_two_actors(
    n_items: usize,
) -> std::result::Result<(Space, Space, CountingTransport), Box<dyn std::error::Error>> {
    let (alice_space, counting) = setup_space(n_items).await?;

    let invite = alice_space.invite_user().await?;
    let dc = initial_internal_data_commitment();
    let bob_space = Space::join(
        counting.clone(),
        invite,
        ApplicationSchema::for_testing(vec![], dc),
    )
    .await?;

    bob_space.register_table_schema(items_schema());
    bob_space.register_table_schema(tags_schema());
    bob_space.sync().await?;

    Ok((alice_space, bob_space, counting))
}

pub fn snapshot(transport: &CountingTransport) -> usize {
    transport.select_calls.load(Ordering::SeqCst)
}

pub fn was_cache_hit(before: usize, transport: &CountingTransport) -> bool {
    transport.select_calls.load(Ordering::SeqCst) == before
}
