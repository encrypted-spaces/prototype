//! End-to-end tests for namespaced key-value stores (`Space::store`).
//!
//! Exercises the full vertical: the runtime `Store` handle and its `get()`
//! read builder (key / prefix / range, order, provable limit / first / last),
//! the `StorePut`/`StoreDelete` verifier ops, and the `KvCache` read path
//! (cache hit after a local write; coverage-aware limited reads; cache miss +
//! proven fetch for a second actor).

mod cache_common;

use cache_common::CountingTransport;
use encrypted_spaces_backend::app_schema::SchemaStore;
use encrypted_spaces_sdk::store::Store;
use encrypted_spaces_sdk::testing::initial_internal_data_commitment;
use encrypted_spaces_sdk::{ApplicationSchema, LocalTransport, Space};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn prefs_store() -> SchemaStore {
    SchemaStore {
        name: "prefs".to_string(),
        encrypted_values: true,
    }
}

async fn setup() -> std::result::Result<(Space, CountingTransport), Box<dyn std::error::Error>> {
    let transport = LocalTransport::in_memory().await?;
    let counting = CountingTransport::new(transport);
    let dc = initial_internal_data_commitment();
    let space = Space::create(counting.clone(), ApplicationSchema::for_testing(vec![], dc)).await?;
    space.create_store(&prefs_store()).await?;
    Ok((space, counting))
}

/// Put each of `keys` with its own bytes as the value.
async fn seed(store: &Store, keys: &[&str]) -> TestResult {
    for k in keys {
        store.put(*k, k.as_bytes().to_vec()).await?;
    }
    Ok(())
}

/// The keys of a read result, dropping the values.
fn keys_of(pairs: Vec<(Vec<u8>, Vec<u8>)>) -> Vec<Vec<u8>> {
    pairs.into_iter().map(|(k, _)| k).collect()
}

#[tokio::test]
async fn put_then_get_roundtrips() -> TestResult {
    let (space, _t) = setup().await?;
    let store = space.store("prefs")?;
    store.put("theme", b"dark".to_vec()).await?;
    assert_eq!(
        store.get().key("theme").first().await?,
        Some((b"theme".to_vec(), b"dark".to_vec())),
    );
    Ok(())
}

#[tokio::test]
async fn overwrite_returns_latest_value() -> TestResult {
    let (space, _t) = setup().await?;
    let store = space.store("prefs")?;
    store.put("theme", b"dark".to_vec()).await?;
    store.put("theme", b"light".to_vec()).await?;
    assert_eq!(
        store.get().key("theme").first().await?,
        Some((b"theme".to_vec(), b"light".to_vec())),
    );
    Ok(())
}

#[tokio::test]
async fn delete_removes_the_key() -> TestResult {
    let (space, _t) = setup().await?;
    let store = space.store("prefs")?;
    store.put("theme", b"dark".to_vec()).await?;
    store.delete("theme").await?;
    assert_eq!(store.get().key("theme").first().await?, None);
    Ok(())
}

#[tokio::test]
async fn get_after_local_write_is_a_cache_hit() -> TestResult {
    let (space, transport) = setup().await?;
    let store = space.store("prefs")?;
    store.put("theme", b"dark".to_vec()).await?;

    let before = transport.store_read_count();
    // The write spliced the point into the cache, so this get needs no fetch.
    assert_eq!(
        store.get().key("theme").first().await?,
        Some((b"theme".to_vec(), b"dark".to_vec())),
    );
    assert_eq!(
        transport.store_read_count(),
        before,
        "get after local write should not hit the server"
    );
    Ok(())
}

#[tokio::test]
async fn prefix_scan_returns_matching_keys_in_order() -> TestResult {
    let (space, _t) = setup().await?;
    let store = space.store("prefs")?;
    store.put("ui/theme", b"dark".to_vec()).await?;
    store.put("ui/lang", b"en".to_vec()).await?;
    store.put("net/proxy", b"none".to_vec()).await?;

    let ui = store.get().prefix("ui/").all().await?;
    let keys: Vec<Vec<u8>> = ui.iter().map(|(k, _)| k.clone()).collect();
    assert_eq!(keys, vec![b"ui/lang".to_vec(), b"ui/theme".to_vec()]);
    Ok(())
}

#[tokio::test]
async fn range_scan_is_half_open() -> TestResult {
    let (space, _t) = setup().await?;
    let store = space.store("prefs")?;
    seed(&store, &["a", "b", "c", "d"]).await?;
    let keys = keys_of(store.get().range("b", "d").all().await?);
    assert_eq!(keys, vec![b"b".to_vec(), b"c".to_vec()]);
    Ok(())
}

#[tokio::test]
async fn first_and_last_pick_the_range_ends() -> TestResult {
    let (space, _t) = setup().await?;
    let store = space.store("prefs")?;
    seed(&store, &["b", "d", "a", "c"]).await?;
    assert_eq!(
        store.get().first().await?,
        Some((b"a".to_vec(), b"a".to_vec())),
    );
    assert_eq!(
        store.get().last().await?,
        Some((b"d".to_vec(), b"d".to_vec())),
    );
    Ok(())
}

#[tokio::test]
async fn descending_limit_returns_largest_keys() -> TestResult {
    let (space, _t) = setup().await?;
    let store = space.store("prefs")?;
    seed(&store, &["a", "b", "c", "d"]).await?;
    let keys = keys_of(store.get().descending().limit(2).all().await?);
    assert_eq!(keys, vec![b"d".to_vec(), b"c".to_vec()]);
    Ok(())
}

#[tokio::test]
async fn repeated_limited_read_is_a_coverage_cache_hit() -> TestResult {
    let (space, transport) = setup().await?;
    let store = space.store("prefs")?;
    seed(&store, &["a", "b", "c", "d", "e"]).await?;

    // The first limited read proves a narrowed range; the repeat is answered
    // from the coverage that fetch established.
    let first = store.get().range("a", "e").limit(2).all().await?;
    let after_first = transport.store_read_count();
    let second = store.get().range("a", "e").limit(2).all().await?;
    assert_eq!(
        transport.store_read_count(),
        after_first,
        "repeat limited read should hit the coverage cache"
    );
    assert_eq!(first, second);
    assert_eq!(keys_of(first), vec![b"a".to_vec(), b"b".to_vec()]);
    Ok(())
}

#[tokio::test]
async fn get_missing_key_returns_none() -> TestResult {
    let (space, _t) = setup().await?;
    let store = space.store("prefs")?;
    store.put("theme", b"dark".to_vec()).await?;
    assert_eq!(store.get().key("absent").first().await?, None);
    Ok(())
}

#[tokio::test]
async fn undeclared_store_is_rejected() -> TestResult {
    let (space, _t) = setup().await?;
    assert!(space.store("nonexistent").is_err());
    Ok(())
}

#[tokio::test]
async fn second_actor_reads_first_actors_write_via_proof() -> TestResult {
    let (alice, counting) = setup().await?;
    let alice_store = alice.store("prefs")?;
    alice_store.put("theme", b"dark".to_vec()).await?;

    // Bob joins, fast-forwards, and reads the key Alice wrote. His cache is
    // cold, so the first get must fetch a proof; a second get is a hit.
    let invite = alice.invite_user().await?;
    let dc = initial_internal_data_commitment();
    let bob = Space::join(
        counting.clone(),
        invite,
        ApplicationSchema::for_testing(vec![], dc),
    )
    .await?;
    bob.register_store(prefs_store());
    bob.sync().await?;

    let bob_store = bob.store("prefs")?;
    let before = counting.store_read_count();
    assert_eq!(
        bob_store.get().key("theme").first().await?,
        Some((b"theme".to_vec(), b"dark".to_vec())),
    );
    assert_eq!(
        counting.store_read_count(),
        before + 1,
        "cold cache should fetch exactly one proof"
    );

    let after_fetch = counting.store_read_count();
    assert_eq!(
        bob_store.get().key("theme").first().await?,
        Some((b"theme".to_vec(), b"dark".to_vec())),
    );
    assert_eq!(
        counting.store_read_count(),
        after_fetch,
        "second get should be served from the cache"
    );
    Ok(())
}
