use encrypted_spaces_crypto::key_derivation::KeyDerivation;
use encrypted_spaces_crypto::KeyMaterial;
use encrypted_spaces_key_manager::error::KeyManagerError;
use encrypted_spaces_key_manager::CollectingOperationBuilder;
use encrypted_spaces_key_manager::MemoryOperationBuilder;
use encrypted_spaces_key_manager::OperationReader;
use encrypted_spaces_key_manager::PendingWritesView;
use encrypted_spaces_key_manager::SimpleKeyId;
use encrypted_spaces_key_manager::SpaceKey;

use encrypted_spaces_crypto::key_derivation::DerivationKoalaBearPoseidon2_16;

use super::super::space_key::*;
use super::super::store::*;
use super::super::DeleteKeysSurvivor;
use super::super::NoProver;

type D = DerivationKoalaBearPoseidon2_16;

/// Use NoProver in tests for speed. StarkProver is tested in dedicated tests.
type TestSpaceKey = SimpleLine2SpaceKey<NoProver>;

fn derivation() -> D {
    D::default()
}

fn noop_collecting_builder() -> CollectingOperationBuilder {
    CollectingOperationBuilder::with_writes(Box::new(|_| Box::pin(async { Ok(None) })), vec![])
}

fn collecting_builder_with_writes(writes: Vec<(String, Vec<u8>)>) -> CollectingOperationBuilder {
    CollectingOperationBuilder::with_writes(Box::new(|_| Box::pin(async { Ok(None) })), writes)
}

// Bulk table loaders (test-only helpers)

async fn load_fgk_table(builder: &dyn OperationReader) -> Result<Vec<FGKRow>, KeyManagerError> {
    let fgk_next = load_fgk_next(builder).await?;
    let mut rows = Vec::with_capacity(fgk_next as usize);
    for ordinal in 0..fgk_next {
        rows.push(load_fgk_row(builder, ordinal).await?);
    }
    Ok(rows)
}

async fn load_dgk_table(builder: &dyn OperationReader) -> Result<Vec<DGKRow>, KeyManagerError> {
    let dgk_next = load_dgk_next(builder).await?;
    let mut rows = Vec::with_capacity(dgk_next as usize);
    for ordinal in 0..dgk_next {
        rows.push(load_dgk_row(builder, ordinal).await?);
    }
    Ok(rows)
}

async fn load_d_table(builder: &dyn OperationReader) -> Result<Vec<DTableRow>, KeyManagerError> {
    let d_min = load_d_min(builder).await?;
    let d_next = load_d_next(builder).await?;
    let mut rows = Vec::with_capacity((d_next - d_min) as usize);
    for seq in d_min..d_next {
        rows.push(load_d_row(builder, seq).await?);
    }
    Ok(rows)
}

/// Test helper: generate a new group key (writes retention state) then apply it locally.
async fn apply_rekey<P: super::super::SimpleLine2RuntimeProver>(
    sk: &mut SimpleLine2SpaceKey<P>,
    _new_hgk: KeyMaterial,
    builder: &mut MemoryOperationBuilder,
) {
    let (commitment, key) = sk.generate_group_key(builder).await.unwrap();
    sk.apply_new_group_key(key, commitment, builder)
        .await
        .unwrap();
}

// ===================================================================
// Constructor tests
// ===================================================================

#[tokio::test]
async fn new_creates_valid_state() {
    let mut builder = MemoryOperationBuilder::new();
    let sk = TestSpaceKey::new(&mut builder).await.unwrap();
    let id = sk.current_key_id(&builder).await.unwrap();
    assert_eq!(id, SimpleKeyId(0));
    validate_storage_shape(&builder).await.unwrap();
}

#[tokio::test]
async fn initialize_writes_valid_state() {
    let mut builder = MemoryOperationBuilder::new();
    let sk = TestSpaceKey::new(&mut builder).await.expect("initialize");

    let fgk_next = load_fgk_next(&builder).await.expect("fgk next");
    assert_eq!(fgk_next, 1);

    let dgk_next = load_dgk_next(&builder).await.expect("dgk next");
    assert_eq!(dgk_next, 0);

    let d_min = load_d_min(&builder).await.expect("d min");
    let d_next = load_d_next(&builder).await.expect("d next");
    assert_eq!(d_min, 0);
    assert_eq!(d_next, 1);

    let fgk = load_fgk_row(&builder, 0).await.expect("fgk row");
    let d = derivation();
    assert_eq!(fgk.commitment, d.commit(&sk.hgk));
    assert_eq!(fgk.d_start, 0);

    let d_row = load_d_row(&builder, 0).await.expect("d row");
    assert_eq!(d_row.seq, 0);

    let gbct = load_gbct_row(&builder, 0, true).await.expect("gbct row");
    assert!(gbct.older_gb_key_ciphertext.is_none());
}

#[tokio::test]
async fn initialize_bulk_load_works() {
    let mut builder = MemoryOperationBuilder::new();
    let _sk = TestSpaceKey::new(&mut builder).await.expect("initialize");

    let fgk_table = load_fgk_table(&builder).await.expect("fgk table");
    assert_eq!(fgk_table.len(), 1);
    assert_eq!(fgk_table[0].d_start, 0);

    let dgk_table = load_dgk_table(&builder).await.expect("dgk table");
    assert!(dgk_table.is_empty());

    let d_table = load_d_table(&builder).await.expect("d table");
    assert_eq!(d_table.len(), 1);
    assert_eq!(d_table[0].seq, 0);
}

// ===================================================================
// Read API tests
// ===================================================================

#[tokio::test]
async fn current_key_id_fresh_state() {
    let mut builder = MemoryOperationBuilder::new();
    let sk = TestSpaceKey::new(&mut builder).await.unwrap();
    assert_eq!(current_key_id(&builder).await.unwrap(), SimpleKeyId(0));
    assert_eq!(sk.current_key_id(&builder).await.unwrap(), SimpleKeyId(0));
}

#[tokio::test]
async fn current_key_id_after_extend() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();
    let id1 = sk.extend(&mut builder).await.unwrap();
    assert_eq!(id1, SimpleKeyId(1));
    assert_eq!(sk.current_key_id(&builder).await.unwrap(), SimpleKeyId(1));
}

#[tokio::test]
async fn current_hgk_commitment_fresh_state() {
    let mut builder = MemoryOperationBuilder::new();
    let sk = TestSpaceKey::new(&mut builder).await.unwrap();
    let d = derivation();
    assert_eq!(
        current_hgk_commitment(&builder).await.unwrap(),
        d.commit(&sk.hgk)
    );
}

#[tokio::test]
async fn resolve_current_hgk_fresh_state() {
    let mut builder = MemoryOperationBuilder::new();
    let sk = TestSpaceKey::new(&mut builder).await.unwrap();
    let resolved = resolve_current_hgk(&sk.hgk, &builder).await.unwrap();
    assert_eq!(resolved, sk.hgk);
}

#[tokio::test]
async fn resolve_d_key_fresh_d0() {
    let mut builder = MemoryOperationBuilder::new();
    let sk = TestSpaceKey::new(&mut builder).await.unwrap();
    let d0 = resolve_d_key(&sk.hgk, 0, &builder).await.unwrap();
    let d = derivation();
    let d_row = load_d_row(&builder, 0).await.unwrap();
    assert_eq!(d.commit(&d0), d_row.commitment);
}

#[tokio::test]
async fn resolve_d_key_out_of_range() {
    let mut builder = MemoryOperationBuilder::new();
    let sk = TestSpaceKey::new(&mut builder).await.unwrap();
    assert!(resolve_d_key(&sk.hgk, 1, &builder).await.is_err());
}

#[tokio::test]
async fn validate_storage_shape_fresh_state() {
    let mut builder = MemoryOperationBuilder::new();
    let _sk = TestSpaceKey::new(&mut builder).await.unwrap();
    validate_storage_shape(&builder).await.unwrap();
}

// ===================================================================
// data_key_for_key_id tests
// ===================================================================

#[tokio::test]
async fn data_key_deterministic() {
    let mut builder = MemoryOperationBuilder::new();
    let sk = TestSpaceKey::new(&mut builder).await.unwrap();
    let id = sk.current_key_id(&builder).await.unwrap();
    let dk1 = sk.data_key_for_key_id(&id, &builder).await.unwrap();
    let dk2 = sk.data_key_for_key_id(&id, &builder).await.unwrap();
    assert_eq!(dk1, dk2);
}

#[tokio::test]
async fn data_key_differs_per_seq() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();
    let id0 = sk.current_key_id(&builder).await.unwrap();
    let dk0 = sk.data_key_for_key_id(&id0, &builder).await.unwrap();

    let id1 = sk.extend(&mut builder).await.unwrap();
    let dk1 = sk.data_key_for_key_id(&id1, &builder).await.unwrap();
    assert_ne!(dk0, dk1);
}

#[tokio::test]
async fn data_key_for_deleted_key_fails() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();
    let id0 = sk.current_key_id(&builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();
    sk.reduce(&SimpleKeyId(1), &mut builder).await.unwrap();
    assert!(sk.data_key_for_key_id(&id0, &builder).await.is_err());
}

#[tokio::test]
async fn data_key_for_future_seq_fails() {
    let mut builder = MemoryOperationBuilder::new();
    let sk = TestSpaceKey::new(&mut builder).await.unwrap();
    assert!(sk
        .data_key_for_key_id(&SimpleKeyId(1), &builder)
        .await
        .is_err());
}

// ===================================================================
// produce_group_key tests
// ===================================================================

#[tokio::test]
async fn produce_group_key_fresh_state() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();
    let (commitment, key) = sk.produce_group_key(&mut builder).await.unwrap();
    let d = derivation();
    assert_eq!(commitment, d.commit(&key));
    assert_eq!(commitment, current_hgk_commitment(&builder).await.unwrap());
}

#[tokio::test]
async fn produce_group_key_syncs_through_dgk() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();
    sk.reduce(&SimpleKeyId(1), &mut builder).await.unwrap();

    let (commitment, _key) = sk.produce_group_key(&mut builder).await.unwrap();
    assert_eq!(commitment, current_hgk_commitment(&builder).await.unwrap());
}

#[tokio::test]
async fn produce_group_key_fails_after_missed_rekey() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();

    // Simulate a fresh rekey that sk doesn't know about
    let new_hgk = KeyMaterial::random();
    let mut sk_other = sk.clone();
    apply_rekey(&mut sk_other, new_hgk, &mut builder).await;
    // sk still has the old HGK — produce_group_key should fail
    assert!(sk.produce_group_key(&mut builder).await.is_err());
}

#[tokio::test]
async fn produce_group_key_after_multiple_reduces() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();

    for _ in 0..4 {
        sk.extend(&mut builder).await.unwrap();
    }

    sk.reduce(&SimpleKeyId(1), &mut builder).await.unwrap();
    sk.reduce(&SimpleKeyId(2), &mut builder).await.unwrap();
    sk.reduce(&SimpleKeyId(3), &mut builder).await.unwrap();

    // produce_group_key should still resolve through 3 DGK derivations
    let (commitment, _key) = sk.produce_group_key(&mut builder).await.unwrap();
    assert_eq!(commitment, current_hgk_commitment(&builder).await.unwrap());
}

// ===================================================================
// Mutation tests — extend
// ===================================================================

#[tokio::test]
async fn extend_appends_d_key() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();

    let new_id = sk.extend(&mut builder).await.unwrap();
    assert_eq!(new_id, SimpleKeyId(1));
    assert_eq!(current_key_id(&builder).await.unwrap(), SimpleKeyId(1));
    validate_storage_shape(&builder).await.unwrap();
}

#[tokio::test]
async fn extend_returns_next_key_id() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();
    assert_eq!(sk.extend(&mut builder).await.unwrap(), SimpleKeyId(1));
    assert_eq!(sk.extend(&mut builder).await.unwrap(), SimpleKeyId(2));
}

#[tokio::test]
async fn extend_d_key_resolves() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();

    sk.extend(&mut builder).await.unwrap();
    let d1 = resolve_d_key(&sk.hgk, 1, &builder).await.unwrap();
    let d = derivation();
    let d_row = load_d_row(&builder, 1).await.unwrap();
    assert_eq!(d.commit(&d1), d_row.commitment);
}

#[tokio::test]
async fn extend_data_keys_resolve() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();

    for seq in 0..=2 {
        sk.data_key_for_key_id(&SimpleKeyId(seq), &builder)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn double_extend() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();

    sk.extend(&mut builder).await.unwrap();
    let id2 = sk.extend(&mut builder).await.unwrap();
    assert_eq!(id2, SimpleKeyId(2));
    validate_storage_shape(&builder).await.unwrap();

    // All three D keys resolve
    resolve_d_key(&sk.hgk, 0, &builder).await.unwrap();
    resolve_d_key(&sk.hgk, 1, &builder).await.unwrap();
    resolve_d_key(&sk.hgk, 2, &builder).await.unwrap();
}

// ===================================================================
// Mutation tests — reduce
// ===================================================================

#[tokio::test]
async fn reduce_advances_d_min() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();

    sk.reduce(&SimpleKeyId(1), &mut builder).await.unwrap();
    assert_eq!(load_d_min(&builder).await.unwrap(), 1);
    assert_eq!(load_d_next(&builder).await.unwrap(), 2);
    validate_storage_shape(&builder).await.unwrap();

    // D1 resolves with new HGK
    let d1 = resolve_d_key(&sk.hgk, 1, &builder).await.unwrap();
    let d = derivation();
    let d_row = load_d_row(&builder, 1).await.unwrap();
    assert_eq!(d.commit(&d1), d_row.commitment);
}

#[tokio::test]
async fn reduce_deleted_key_fails() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();

    sk.reduce(&SimpleKeyId(1), &mut builder).await.unwrap();
    assert!(resolve_d_key(&sk.hgk, 0, &builder).await.is_err());
}

#[tokio::test]
async fn reduce_rejects_no_advance() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();
    assert!(sk.reduce(&SimpleKeyId(0), &mut builder).await.is_err());
}

#[tokio::test]
async fn reduce_rejects_delete_all() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();
    assert!(sk.reduce(&SimpleKeyId(1), &mut builder).await.is_err());
}

#[tokio::test]
async fn reduce_preserves_live_keys() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();

    sk.reduce(&SimpleKeyId(1), &mut builder).await.unwrap();

    assert!(resolve_d_key(&sk.hgk, 0, &builder).await.is_err());
    resolve_d_key(&sk.hgk, 1, &builder).await.unwrap();
    resolve_d_key(&sk.hgk, 2, &builder).await.unwrap();
}

#[tokio::test]
async fn reduce_prunes_old_keys() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();
    sk.reduce(&SimpleKeyId(1), &mut builder).await.unwrap();

    assert!(sk
        .data_key_for_key_id(&SimpleKeyId(0), &builder)
        .await
        .is_err());
    sk.data_key_for_key_id(&SimpleKeyId(1), &builder)
        .await
        .unwrap();
    sk.data_key_for_key_id(&SimpleKeyId(2), &builder)
        .await
        .unwrap();
}

#[tokio::test]
async fn reduce_appends_dgk() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();

    sk.reduce(&SimpleKeyId(1), &mut builder).await.unwrap();
    assert_eq!(load_dgk_next(&builder).await.unwrap(), 1);

    let d = derivation();
    let resolved = resolve_current_hgk(&sk.hgk, &builder).await.unwrap();
    assert_eq!(
        current_hgk_commitment(&builder).await.unwrap(),
        d.commit(&resolved)
    );
}

#[tokio::test]
async fn old_hgk_resolves_through_dgk() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();

    let old_hgk = sk.hgk.clone();
    sk.reduce(&SimpleKeyId(1), &mut builder).await.unwrap();

    // The old HGK can still resolve to the new HGK through DGK derivation
    let resolved = resolve_current_hgk(&old_hgk, &builder).await.unwrap();
    let d = derivation();
    assert_eq!(
        d.commit(&resolved),
        current_hgk_commitment(&builder).await.unwrap()
    );
    assert_ne!(resolved, old_hgk);
}

// ===================================================================
// Mutation tests — fresh rekey
// ===================================================================

#[tokio::test]
async fn fresh_rekey_updates_tables() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();

    let new_hgk = KeyMaterial::random();
    apply_rekey(&mut sk, new_hgk, &mut builder).await;

    let d = derivation();
    assert_eq!(
        current_hgk_commitment(&builder).await.unwrap(),
        d.commit(&sk.hgk)
    );
    assert_eq!(current_key_id(&builder).await.unwrap(), SimpleKeyId(1));
    assert_eq!(load_dgk_next(&builder).await.unwrap(), 0);
    validate_storage_shape(&builder).await.unwrap();
}

#[tokio::test]
async fn apply_new_group_key_updates_hgk() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();
    let (commitment_before, _) = sk.produce_group_key(&mut builder).await.unwrap();

    apply_rekey(&mut sk, KeyMaterial::random(), &mut builder).await;

    let d = derivation();
    let (commitment_after, key_after) = sk.produce_group_key(&mut builder).await.unwrap();
    assert_ne!(commitment_before, commitment_after);
    assert_eq!(commitment_after, d.commit(&key_after));
}

#[tokio::test]
async fn apply_new_group_key_preserves_old_data_keys() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();
    let dk0_before = sk
        .data_key_for_key_id(&SimpleKeyId(0), &builder)
        .await
        .unwrap();

    let new_hgk = KeyMaterial::random();
    apply_rekey(&mut sk, new_hgk, &mut builder).await;

    let dk0_after = sk
        .data_key_for_key_id(&SimpleKeyId(0), &builder)
        .await
        .unwrap();
    assert_eq!(dk0_before, dk0_after);
}

#[tokio::test]
async fn fresh_rekey_preserves_old_d_keys() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();

    let d0_before = resolve_d_key(&sk.hgk, 0, &builder).await.unwrap();

    let new_hgk = KeyMaterial::random();
    apply_rekey(&mut sk, new_hgk, &mut builder).await;

    let d0_after = resolve_d_key(&sk.hgk, 0, &builder).await.unwrap();
    assert_eq!(d0_before, d0_after);
}

#[tokio::test]
async fn fresh_rekey_new_d_head_resolves() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();

    let new_hgk = KeyMaterial::random();
    apply_rekey(&mut sk, new_hgk, &mut builder).await;

    let d1 = resolve_d_key(&sk.hgk, 1, &builder).await.unwrap();
    let d = derivation();
    let d_row = load_d_row(&builder, 1).await.unwrap();
    assert_eq!(d.commit(&d1), d_row.commitment);
}

#[tokio::test]
async fn fresh_rekey_old_hgk_cannot_resolve() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();

    let old_hgk = sk.hgk.clone();
    let new_hgk = KeyMaterial::random();
    apply_rekey(&mut sk, new_hgk, &mut builder).await;

    // Old HGK cannot derive to the new HGK (it's random, not derived)
    assert!(resolve_current_hgk(&old_hgk, &builder).await.is_err());
}

// ===================================================================
// Sequence tests
// ===================================================================

#[tokio::test]
async fn sequence_init_extend_extend() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();

    sk.extend(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();

    assert_eq!(current_key_id(&builder).await.unwrap(), SimpleKeyId(2));
    validate_storage_shape(&builder).await.unwrap();

    for seq in 0..=2 {
        resolve_d_key(&sk.hgk, seq, &builder).await.unwrap();
    }
}

#[tokio::test]
async fn sequence_init_extend_reduce() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();

    sk.extend(&mut builder).await.unwrap();
    sk.reduce(&SimpleKeyId(1), &mut builder).await.unwrap();

    assert_eq!(current_key_id(&builder).await.unwrap(), SimpleKeyId(1));
    validate_storage_shape(&builder).await.unwrap();
    assert!(resolve_d_key(&sk.hgk, 0, &builder).await.is_err());
    resolve_d_key(&sk.hgk, 1, &builder).await.unwrap();
}

#[tokio::test]
async fn sequence_init_extend_reduce_produce() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();

    let old_hgk = sk.hgk.clone();
    sk.extend(&mut builder).await.unwrap();
    sk.reduce(&SimpleKeyId(1), &mut builder).await.unwrap();

    // produce_group_key equivalent: resolve current HGK
    let resolved = resolve_current_hgk(&old_hgk, &builder).await.unwrap();
    let d = derivation();
    assert_eq!(
        d.commit(&resolved),
        current_hgk_commitment(&builder).await.unwrap()
    );
}

#[tokio::test]
async fn sequence_init_rekey_extend() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();

    let new_hgk = KeyMaterial::random();
    apply_rekey(&mut sk, new_hgk, &mut builder).await;
    sk.extend(&mut builder).await.unwrap();

    assert_eq!(current_key_id(&builder).await.unwrap(), SimpleKeyId(2));
    validate_storage_shape(&builder).await.unwrap();

    // All keys resolve
    for seq in 0..=2 {
        resolve_d_key(&sk.hgk, seq, &builder).await.unwrap();
    }
}

#[tokio::test]
async fn sequence_init_extend_rekey_reduce() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();

    sk.extend(&mut builder).await.unwrap();

    let new_hgk = KeyMaterial::random();
    apply_rekey(&mut sk, new_hgk, &mut builder).await;

    sk.reduce(&SimpleKeyId(1), &mut builder).await.unwrap();

    validate_storage_shape(&builder).await.unwrap();
    assert!(resolve_d_key(&sk.hgk, 0, &builder).await.is_err());
    resolve_d_key(&sk.hgk, 1, &builder).await.unwrap();
    resolve_d_key(&sk.hgk, 2, &builder).await.unwrap();
}

#[tokio::test]
async fn sequence_extend_reduce_extend() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();

    sk.extend(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();
    sk.reduce(&SimpleKeyId(1), &mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();

    assert_eq!(sk.current_key_id(&builder).await.unwrap(), SimpleKeyId(3));
    validate_storage_shape(&builder).await.unwrap();

    assert!(sk
        .data_key_for_key_id(&SimpleKeyId(0), &builder)
        .await
        .is_err());
    for seq in 1..=3 {
        sk.data_key_for_key_id(&SimpleKeyId(seq), &builder)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn sequence_rekey_extend_reduce() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();

    let new_hgk = KeyMaterial::random();
    apply_rekey(&mut sk, new_hgk, &mut builder).await;
    sk.extend(&mut builder).await.unwrap();
    sk.reduce(&SimpleKeyId(1), &mut builder).await.unwrap();

    assert_eq!(sk.current_key_id(&builder).await.unwrap(), SimpleKeyId(2));
    validate_storage_shape(&builder).await.unwrap();

    assert!(sk
        .data_key_for_key_id(&SimpleKeyId(0), &builder)
        .await
        .is_err());
    sk.data_key_for_key_id(&SimpleKeyId(1), &builder)
        .await
        .unwrap();
    sk.data_key_for_key_id(&SimpleKeyId(2), &builder)
        .await
        .unwrap();
}

#[tokio::test]
async fn sequence_reduce_rekey_extend() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();

    sk.extend(&mut builder).await.unwrap();
    sk.reduce(&SimpleKeyId(1), &mut builder).await.unwrap();

    let new_hgk = KeyMaterial::random();
    apply_rekey(&mut sk, new_hgk, &mut builder).await;
    sk.extend(&mut builder).await.unwrap();

    assert_eq!(sk.current_key_id(&builder).await.unwrap(), SimpleKeyId(3));
    validate_storage_shape(&builder).await.unwrap();
}

#[tokio::test]
async fn multiple_rekeys() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();

    let dk0 = sk
        .data_key_for_key_id(&SimpleKeyId(0), &builder)
        .await
        .unwrap();

    for _ in 0..3 {
        let new_hgk = KeyMaterial::random();
        apply_rekey(&mut sk, new_hgk, &mut builder).await;
    }

    // Original D0 still accessible through the chain
    let dk0_after = sk
        .data_key_for_key_id(&SimpleKeyId(0), &builder)
        .await
        .unwrap();
    assert_eq!(dk0, dk0_after);

    // Each rekey adds a new D key
    assert_eq!(sk.current_key_id(&builder).await.unwrap(), SimpleKeyId(3));
    validate_storage_shape(&builder).await.unwrap();
}

#[tokio::test]
async fn repeated_deletes_with_historical_resolution() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();

    // Extend 5 times: D0..D5
    for _ in 0..5 {
        sk.extend(&mut builder).await.unwrap();
    }
    assert_eq!(current_key_id(&builder).await.unwrap(), SimpleKeyId(5));

    // Delete to 2
    sk.reduce(&SimpleKeyId(2), &mut builder).await.unwrap();
    // Delete to 4
    sk.reduce(&SimpleKeyId(4), &mut builder).await.unwrap();

    validate_storage_shape(&builder).await.unwrap();

    // D0-D3 should be gone
    for seq in 0..4 {
        assert!(resolve_d_key(&sk.hgk, seq, &builder).await.is_err());
    }
    // D4 and D5 should resolve
    resolve_d_key(&sk.hgk, 4, &builder).await.unwrap();
    resolve_d_key(&sk.hgk, 5, &builder).await.unwrap();
}

// ===================================================================
// Edge cases
// ===================================================================

#[tokio::test]
async fn operations_on_uninitialized_storage_fail() {
    let builder = MemoryOperationBuilder::new();
    assert!(current_key_id(&builder).await.is_err());
    assert!(current_hgk_commitment(&builder).await.is_err());
    assert!(validate_storage_shape(&builder).await.is_err());
    assert!(reconstruct_live_chain(&builder).await.is_err());
}

#[tokio::test]
async fn extend_on_uninitialized_storage_fails() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk: TestSpaceKey = SimpleLine2SpaceKey {
        hgk: KeyMaterial::random(),
        _prover: std::marker::PhantomData,
    };
    assert!(sk.extend(&mut builder).await.is_err());
}

#[tokio::test]
async fn reduce_on_uninitialized_storage_fails() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk: TestSpaceKey = SimpleLine2SpaceKey {
        hgk: KeyMaterial::random(),
        _prover: std::marker::PhantomData,
    };
    assert!(sk.reduce(&SimpleKeyId(1), &mut builder).await.is_err());
}

#[tokio::test]
async fn resolve_d_key_at_d_min_boundary() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();

    // Extend 3 times, reduce to 2
    for _ in 0..3 {
        sk.extend(&mut builder).await.unwrap();
    }
    sk.reduce(&SimpleKeyId(2), &mut builder).await.unwrap();

    // d_min is now 2 — resolving exactly d_min should succeed
    let d2 = resolve_d_key(&sk.hgk, 2, &builder).await.unwrap();
    let d = derivation();
    assert_eq!(
        d.commit(&d2),
        load_d_row(&builder, 2).await.unwrap().commitment
    );

    // d_min - 1 should fail
    assert!(resolve_d_key(&sk.hgk, 1, &builder).await.is_err());
}

#[tokio::test]
async fn resolve_d_key_at_last_seq() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();

    // Last seq is 2
    let d2 = resolve_d_key(&sk.hgk, 2, &builder).await.unwrap();
    let d = derivation();
    assert_eq!(
        d.commit(&d2),
        load_d_row(&builder, 2).await.unwrap().commitment
    );

    // Beyond last seq fails
    assert!(resolve_d_key(&sk.hgk, 3, &builder).await.is_err());
}

#[tokio::test]
async fn reduce_to_boundary_keeps_single_key() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();

    // Reduce to next_d_seq - 1 = 2, keeping only D2
    sk.reduce(&SimpleKeyId(2), &mut builder).await.unwrap();
    assert_eq!(load_d_min(&builder).await.unwrap(), 2);
    assert_eq!(load_d_next(&builder).await.unwrap(), 3);
    validate_storage_shape(&builder).await.unwrap();
    resolve_d_key(&sk.hgk, 2, &builder).await.unwrap();
}

#[tokio::test]
async fn extend_after_reduce() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();

    sk.reduce(&SimpleKeyId(1), &mut builder).await.unwrap();
    let new_id = sk.extend(&mut builder).await.unwrap();

    assert_eq!(new_id, SimpleKeyId(2));
    validate_storage_shape(&builder).await.unwrap();
    resolve_d_key(&sk.hgk, 1, &builder).await.unwrap();
    resolve_d_key(&sk.hgk, 2, &builder).await.unwrap();
}

#[tokio::test]
async fn interleaved_extend_reduce() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();

    // extend, reduce, extend, reduce, extend
    sk.extend(&mut builder).await.unwrap();
    sk.reduce(&SimpleKeyId(1), &mut builder).await.unwrap();

    sk.extend(&mut builder).await.unwrap();
    sk.reduce(&SimpleKeyId(2), &mut builder).await.unwrap();

    sk.extend(&mut builder).await.unwrap();

    assert_eq!(current_key_id(&builder).await.unwrap(), SimpleKeyId(3));
    validate_storage_shape(&builder).await.unwrap();

    assert!(resolve_d_key(&sk.hgk, 0, &builder).await.is_err());
    assert!(resolve_d_key(&sk.hgk, 1, &builder).await.is_err());
    resolve_d_key(&sk.hgk, 2, &builder).await.unwrap();
    resolve_d_key(&sk.hgk, 3, &builder).await.unwrap();
}

#[tokio::test]
async fn repeated_reduce_by_one() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();

    for _ in 0..5 {
        sk.extend(&mut builder).await.unwrap();
    }

    // Delete one at a time
    for before in 1..=4 {
        sk.reduce(&SimpleKeyId(before), &mut builder).await.unwrap();
        validate_storage_shape(&builder).await.unwrap();
    }

    // Only D4, D5 remain
    assert!(resolve_d_key(&sk.hgk, 3, &builder).await.is_err());
    resolve_d_key(&sk.hgk, 4, &builder).await.unwrap();
    resolve_d_key(&sk.hgk, 5, &builder).await.unwrap();
}

#[tokio::test]
async fn data_key_stable_across_reduce() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();

    let d2_before = resolve_d_key(&sk.hgk, 2, &builder).await.unwrap();

    sk.reduce(&SimpleKeyId(1), &mut builder).await.unwrap();

    let d2_after = resolve_d_key(&sk.hgk, 2, &builder).await.unwrap();

    // Same D key material, just accessed through a different HGK
    let d = derivation();
    assert_eq!(d.commit(&d2_before), d.commit(&d2_after));
}

#[tokio::test]
async fn data_key_stable_across_rekey() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();

    let d0_before = resolve_d_key(&sk.hgk, 0, &builder).await.unwrap();
    let d1_before = resolve_d_key(&sk.hgk, 1, &builder).await.unwrap();

    let new_hgk = KeyMaterial::random();
    apply_rekey(&mut sk, new_hgk, &mut builder).await;

    let d0_after = resolve_d_key(&sk.hgk, 0, &builder).await.unwrap();
    let d1_after = resolve_d_key(&sk.hgk, 1, &builder).await.unwrap();

    assert_eq!(d0_before, d0_after);
    assert_eq!(d1_before, d1_after);
}

// ===================================================================
// Invalid state detection
// ===================================================================

#[tokio::test]
async fn validate_rejects_empty_fgk_table() {
    let mut builder = MemoryOperationBuilder::new();
    let _sk = TestSpaceKey::new(&mut builder).await.unwrap();

    // Corrupt: collapse the FGK table to empty
    save_fgk_next(&mut builder, 0).await;
    assert!(validate_storage_shape(&builder).await.is_err());
}

#[tokio::test]
async fn validate_rejects_empty_d_range() {
    let mut builder = MemoryOperationBuilder::new();
    let _sk = TestSpaceKey::new(&mut builder).await.unwrap();

    // Corrupt: collapse the live range to empty (d_min == d_next)
    save_d_next(&mut builder, 0).await;
    assert!(validate_storage_shape(&builder).await.is_err());
}

#[tokio::test]
async fn validate_rejects_inverted_d_range() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();

    // Corrupt: d_min > d_next
    save_d_min(&mut builder, 5).await;
    assert!(validate_storage_shape(&builder).await.is_err());
}

#[tokio::test]
async fn validate_rejects_missing_fgk_row() {
    let mut builder = MemoryOperationBuilder::new();
    let _sk = TestSpaceKey::new(&mut builder).await.unwrap();

    // Corrupt: advance fgk_next past the last written FGK row (ordinal=1 has no row)
    save_fgk_next(&mut builder, 2).await;
    assert!(validate_storage_shape(&builder).await.is_err());
}

#[tokio::test]
async fn validate_rejects_missing_d_row() {
    let mut builder = MemoryOperationBuilder::new();
    let _sk = TestSpaceKey::new(&mut builder).await.unwrap();

    // Corrupt: advance d_next past the last written D row (seq=1 has no row)
    save_d_next(&mut builder, 2).await;
    assert!(validate_storage_shape(&builder).await.is_err());
}

#[tokio::test]
async fn validate_rejects_latest_fgk_above_d_next() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();

    let hgk2 = KeyMaterial::random();
    apply_rekey(&mut sk, hgk2, &mut builder).await;

    // Corrupt: push the latest FGK row's d_start past d_next. Chain
    // reconstruction would skip it, but current_hgk_commitment reads it
    // directly — leaving readers pointing at an unreachable commitment.
    let d = derivation();
    let mut latest = load_fgk_row(&builder, 1).await.unwrap();
    latest.d_start = 99;
    save_fgk_row(
        &mut builder,
        1,
        &FGKRow {
            d_start: latest.d_start,
            commitment: d.commit(&KeyMaterial::random()),
        },
    )
    .await;
    assert!(validate_storage_shape(&builder).await.is_err());
}

#[tokio::test]
async fn validate_rejects_non_monotonic_fgk_d_starts() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();

    let hgk2 = KeyMaterial::random();
    apply_rekey(&mut sk, hgk2, &mut builder).await;

    // Corrupt: overwrite FGK row 0 with a d_start >= row 1's d_start.
    let d = derivation();
    let row1 = load_fgk_row(&builder, 1).await.unwrap();
    save_fgk_row(
        &mut builder,
        0,
        &FGKRow {
            d_start: row1.d_start,
            commitment: d.commit(&KeyMaterial::random()),
        },
    )
    .await;
    assert!(validate_storage_shape(&builder).await.is_err());
}

#[tokio::test]
async fn validate_rejects_missing_gbct_for_live_chain() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();

    let hgk2 = KeyMaterial::random();
    apply_rekey(&mut sk, hgk2, &mut builder).await;

    // Corrupt: remove the gbct row's d_head ciphertext for FGK ordinal 0
    // (the older chain node).
    builder.remove("sl2/gbct/row/0/d_head_ct");
    assert!(validate_storage_shape(&builder).await.is_err());
}

#[tokio::test]
async fn validate_rejects_head_gbct_with_none_chain_link() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();

    let hgk2 = KeyMaterial::random();
    apply_rekey(&mut sk, hgk2, &mut builder).await;

    // Corrupt: remove the head node's chain link bytes (head row at ordinal 1).
    // A non-tail chain node must carry a real older-GB chain-link ciphertext.
    builder.remove("sl2/gbct/row/1/gb_ct");
    assert!(validate_storage_shape(&builder).await.is_err());
}

#[tokio::test]
async fn validate_ignores_tail_gbct_with_some_chain_link() {
    let mut builder = MemoryOperationBuilder::new();
    let _sk = TestSpaceKey::new(&mut builder).await.unwrap();

    // Structural tailness: stray older-link bytes on the tail are ignored.
    let d = derivation();
    let mut gbct = load_gbct_row(&builder, 0, true).await.unwrap();
    gbct.older_gb_key_ciphertext = Some(encrypt_gb_chain_link(
        &d,
        &KeyMaterial::random(),
        &KeyMaterial::random(),
    ));
    save_gbct_row(&mut builder, 0, &gbct).await;

    let normalized = load_gbct_row(&builder, 0, true).await.unwrap();
    assert!(normalized.older_gb_key_ciphertext.is_none());
    assert!(validate_storage_shape(&builder).await.is_ok());
}

// ===================================================================
// Tricky operation sequences
// ===================================================================

#[tokio::test]
async fn many_extends_then_bulk_reduce() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();

    for _ in 0..20 {
        sk.extend(&mut builder).await.unwrap();
    }

    // Reduce most of them at once
    sk.reduce(&SimpleKeyId(18), &mut builder).await.unwrap();
    validate_storage_shape(&builder).await.unwrap();

    for seq in 0..18 {
        assert!(resolve_d_key(&sk.hgk, seq, &builder).await.is_err());
    }
    for seq in 18..=20 {
        resolve_d_key(&sk.hgk, seq, &builder).await.unwrap();
    }
}

#[tokio::test]
async fn reduce_spanning_multiple_chain_nodes() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();

    // Rekey creates a second chain node
    let hgk2 = KeyMaterial::random();
    apply_rekey(&mut sk, hgk2, &mut builder).await;
    sk.extend(&mut builder).await.unwrap();

    // D keys: 0, 1 (under old FGK), 2, 3 (under new FGK)
    // Reduce to 1 — partially deletes the first chain node
    sk.reduce(&SimpleKeyId(1), &mut builder).await.unwrap();
    validate_storage_shape(&builder).await.unwrap();

    assert!(resolve_d_key(&sk.hgk, 0, &builder).await.is_err());
    resolve_d_key(&sk.hgk, 1, &builder).await.unwrap();
    resolve_d_key(&sk.hgk, 2, &builder).await.unwrap();
    resolve_d_key(&sk.hgk, 3, &builder).await.unwrap();
}

#[tokio::test]
async fn reduce_removes_entire_old_chain_node() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();

    // Rekey — D0 under old FGK, D1 under new FGK
    let hgk2 = KeyMaterial::random();
    apply_rekey(&mut sk, hgk2, &mut builder).await;
    sk.extend(&mut builder).await.unwrap();

    // Reduce to 1 — completely removes old chain node
    sk.reduce(&SimpleKeyId(1), &mut builder).await.unwrap();
    validate_storage_shape(&builder).await.unwrap();

    let chain = reconstruct_live_chain(&builder).await.unwrap();
    // Should be a single-node chain now
    assert_eq!(chain.len(), 1);
    resolve_d_key(&sk.hgk, 1, &builder).await.unwrap();
    resolve_d_key(&sk.hgk, 2, &builder).await.unwrap();
}

#[tokio::test]
async fn multiple_rekeys_then_reduce() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();

    let hgk2 = KeyMaterial::random();
    apply_rekey(&mut sk, hgk2, &mut builder).await;
    let hgk3 = KeyMaterial::random();
    apply_rekey(&mut sk, hgk3, &mut builder).await;

    // D0 (fgk0), D1 (fgk1), D2 (fgk2)
    // 3 chain nodes, reduce to 1
    sk.reduce(&SimpleKeyId(1), &mut builder).await.unwrap();
    validate_storage_shape(&builder).await.unwrap();

    assert!(resolve_d_key(&sk.hgk, 0, &builder).await.is_err());
    resolve_d_key(&sk.hgk, 1, &builder).await.unwrap();
    resolve_d_key(&sk.hgk, 2, &builder).await.unwrap();
}

#[tokio::test]
async fn rekey_after_multiple_deletes() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();

    for _ in 0..4 {
        sk.extend(&mut builder).await.unwrap();
    }

    sk.reduce(&SimpleKeyId(2), &mut builder).await.unwrap();
    sk.reduce(&SimpleKeyId(3), &mut builder).await.unwrap();

    // Now rekey
    let new_hgk = KeyMaterial::random();
    apply_rekey(&mut sk, new_hgk, &mut builder).await;
    validate_storage_shape(&builder).await.unwrap();

    // Old keys still accessible through new HGK chain
    resolve_d_key(&sk.hgk, 3, &builder).await.unwrap();
    resolve_d_key(&sk.hgk, 4, &builder).await.unwrap();
    // New D key at rekey position resolves
    resolve_d_key(&sk.hgk, 5, &builder).await.unwrap();
}

#[tokio::test]
async fn rekey_reduce_rekey_reduce() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();

    let hgk2 = KeyMaterial::random();
    apply_rekey(&mut sk, hgk2, &mut builder).await;

    sk.reduce(&SimpleKeyId(1), &mut builder).await.unwrap();

    sk.extend(&mut builder).await.unwrap();
    let hgk3 = KeyMaterial::random();
    apply_rekey(&mut sk, hgk3, &mut builder).await;

    sk.reduce(&SimpleKeyId(3), &mut builder).await.unwrap();

    validate_storage_shape(&builder).await.unwrap();
    assert!(resolve_d_key(&sk.hgk, 2, &builder).await.is_err());
    resolve_d_key(&sk.hgk, 3, &builder).await.unwrap();
    resolve_d_key(&sk.hgk, 4, &builder).await.unwrap();
}

#[tokio::test]
async fn reduce_rejects_second_reduce_at_same_point() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();

    sk.reduce(&SimpleKeyId(1), &mut builder).await.unwrap();
    // Same before value as d_min — should fail
    assert!(sk.reduce(&SimpleKeyId(1), &mut builder).await.is_err());
}

#[tokio::test]
async fn reduce_rejects_before_below_d_min() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();

    sk.reduce(&SimpleKeyId(2), &mut builder).await.unwrap();
    // before=1 < d_min=2 — should fail
    assert!(sk.reduce(&SimpleKeyId(1), &mut builder).await.is_err());
}

#[tokio::test]
async fn double_reduce_with_dgk_accumulation() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();

    for _ in 0..4 {
        sk.extend(&mut builder).await.unwrap();
    }

    sk.reduce(&SimpleKeyId(1), &mut builder).await.unwrap();
    let dgk_len_1 = load_dgk_next(&builder).await.unwrap();

    sk.reduce(&SimpleKeyId(2), &mut builder).await.unwrap();
    let dgk_len_2 = load_dgk_next(&builder).await.unwrap();

    // Two reduces should have accumulated two DGK entries
    assert_eq!(dgk_len_1, 1);
    assert_eq!(dgk_len_2, 2);

    // HGK should be resolvable through two DGK derivation steps
    let resolved = resolve_current_hgk(&sk.hgk, &builder).await.unwrap();
    let d = derivation();
    assert_eq!(
        d.commit(&resolved),
        current_hgk_commitment(&builder).await.unwrap()
    );

    validate_storage_shape(&builder).await.unwrap();
}

#[tokio::test]
async fn rekey_clears_accumulated_dgks() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();

    sk.reduce(&SimpleKeyId(1), &mut builder).await.unwrap();
    sk.reduce(&SimpleKeyId(2), &mut builder).await.unwrap();

    let dgk_before = load_dgk_next(&builder).await.unwrap();
    assert_eq!(dgk_before, 2);

    let new_hgk = KeyMaterial::random();
    apply_rekey(&mut sk, new_hgk, &mut builder).await;

    assert_eq!(load_dgk_next(&builder).await.unwrap(), 0);
}

#[tokio::test]
async fn resolve_with_stale_hgk_through_multiple_dgks() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();

    let original_hgk = sk.hgk.clone();

    // Three reduces, each deriving a new DGK
    sk.reduce(&SimpleKeyId(1), &mut builder).await.unwrap();
    sk.reduce(&SimpleKeyId(2), &mut builder).await.unwrap();
    sk.reduce(&SimpleKeyId(3), &mut builder).await.unwrap();

    // Original HGK should still be able to derive to the current HGK
    let resolved = resolve_current_hgk(&original_hgk, &builder).await.unwrap();
    let d = derivation();
    assert_eq!(
        d.commit(&resolved),
        current_hgk_commitment(&builder).await.unwrap()
    );
    assert_ne!(resolved, original_hgk);
}

// ===================================================================
// Full production path coverage
// ===================================================================

#[tokio::test]
async fn full_production_path() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();

    // Extend
    sk.extend(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();

    // Read paths
    assert_eq!(current_key_id(&builder).await.unwrap(), SimpleKeyId(2));
    let commit = current_hgk_commitment(&builder).await.unwrap();
    let d = derivation();
    assert_eq!(commit, d.commit(&sk.hgk));
    let resolved = resolve_current_hgk(&sk.hgk, &builder).await.unwrap();
    assert_eq!(resolved, sk.hgk);
    validate_storage_shape(&builder).await.unwrap();

    // Resolve all D keys
    for seq in 0..=2 {
        resolve_d_key(&sk.hgk, seq, &builder).await.unwrap();
    }

    // Reduce
    sk.reduce(&SimpleKeyId(1), &mut builder).await.unwrap();
    validate_storage_shape(&builder).await.unwrap();
    assert!(resolve_d_key(&sk.hgk, 0, &builder).await.is_err());
    resolve_d_key(&sk.hgk, 1, &builder).await.unwrap();
    resolve_d_key(&sk.hgk, 2, &builder).await.unwrap();

    // Rekey
    let new_hgk = KeyMaterial::random();
    apply_rekey(&mut sk, new_hgk, &mut builder).await;
    validate_storage_shape(&builder).await.unwrap();
    resolve_d_key(&sk.hgk, 1, &builder).await.unwrap();
    resolve_d_key(&sk.hgk, 2, &builder).await.unwrap();
    resolve_d_key(&sk.hgk, 3, &builder).await.unwrap();

    // Full cycle: init, extend, read, reduce, rekey
}

// ===================================================================
// D-key HKDF contract tests
// ===================================================================

#[test]
fn d_key_hkdf_deterministic() {
    let key = KeyMaterial::random();
    let dk1 = d_key_hkdf(&key, 0).unwrap();
    let dk2 = d_key_hkdf(&key, 0).unwrap();
    assert_eq!(dk1, dk2);
}

#[test]
fn d_key_hkdf_different_seqs_differ() {
    let key = KeyMaterial::random();
    let dk0 = d_key_hkdf(&key, 0).unwrap();
    let dk1 = d_key_hkdf(&key, 1).unwrap();
    assert_ne!(dk0, dk1);
}

#[test]
fn d_key_hkdf_different_keys_differ() {
    let key1 = KeyMaterial::random();
    let key2 = KeyMaterial::random();
    let dk1 = d_key_hkdf(&key1, 0).unwrap();
    let dk2 = d_key_hkdf(&key2, 0).unwrap();
    assert_ne!(dk1, dk2);
}

// ===================================================================
// Proof-recording tests
// ===================================================================
//
// These exercise the prove-before-persist wiring in each mutation path.
// Under the default `NoProver`, every mutation records exactly one empty
// proof payload; the STARK round-trip variant (below, `#[ignore]`d) runs
// the full prove/verify loop through the mutation path.

#[tokio::test]
async fn extend_records_one_proof_payload() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();
    let before = builder.proofs().len();

    sk.extend(&mut builder).await.unwrap();

    assert_eq!(builder.proofs().len(), before + 1);
    assert!(builder.proofs().last().unwrap().is_empty());
}

#[tokio::test]
async fn apply_new_group_key_records_one_proof_payload() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();
    let before = builder.proofs().len();

    let new_hgk = KeyMaterial::random();
    apply_rekey(&mut sk, new_hgk, &mut builder).await;

    assert_eq!(builder.proofs().len(), before + 1);
    assert!(builder.proofs().last().unwrap().is_empty());
}

#[tokio::test]
async fn reduce_records_one_proof_payload() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();
    let before = builder.proofs().len();

    sk.reduce(&SimpleKeyId(1), &mut builder).await.unwrap();

    assert_eq!(builder.proofs().len(), before + 1);
    assert!(builder.proofs().last().unwrap().is_empty());
}

#[tokio::test]
async fn mixed_sequence_records_one_proof_per_mutation() {
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();

    sk.extend(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();
    apply_rekey(&mut sk, KeyMaterial::random(), &mut builder).await;
    sk.extend(&mut builder).await.unwrap();
    sk.reduce(&SimpleKeyId(2), &mut builder).await.unwrap();

    // 3 extends + 1 rekey + 1 reduce = 5 proofs.
    assert_eq!(builder.proofs().len(), 5);
    assert!(builder.proofs().iter().all(|p| p.is_empty()));
}

#[tokio::test]
async fn reduce_with_multi_chain_records_one_proof_payload() {
    // Exercises the delete-keys path that includes fresh B-keys
    // (chain length > 1 at reduce time).
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = TestSpaceKey::new(&mut builder).await.unwrap();
    sk.extend(&mut builder).await.unwrap();
    apply_rekey(&mut sk, KeyMaterial::random(), &mut builder).await; // chain grows
    sk.extend(&mut builder).await.unwrap();
    apply_rekey(&mut sk, KeyMaterial::random(), &mut builder).await; // chain grows again
    sk.extend(&mut builder).await.unwrap();

    let before = builder.proofs().len();
    sk.reduce(&SimpleKeyId(3), &mut builder).await.unwrap();

    assert_eq!(builder.proofs().len(), before + 1);
    assert!(builder.proofs().last().unwrap().is_empty());
    validate_storage_shape(&builder).await.unwrap();
}

// ---- STARK round-trips through the mutation path (slow lane) ----
//
// These exercise the full prove-before-persist wiring in each mutation
// method, then rebuild the matching VerifyInput from storage (for rekey/
// reduce) or from pre-captured commitments (for extend) and run STARK
// verification independently. A wiring bug in the public-input assembly
// inside space_key.rs would be caught here — adapter-level tests in
// stark_proofs.rs would not.

#[tokio::test]
#[ignore = "slow STARK proof coverage; run with cargo test -- --ignored"]
async fn stark_prover_extend_through_mutation_verifies() {
    use super::super::{ExtendVerifyInput, SimpleLine2Proofs, StarkProver};

    let mut builder = MemoryOperationBuilder::new();
    let mut sk = SimpleLine2SpaceKey::<StarkProver>::new(&mut builder)
        .await
        .unwrap();

    // Capture current_d commitment before extend (the prover helper loads the
    // same row at last_seq).
    let current_d_commitment = load_d_row(&builder, 0).await.unwrap().commitment;

    sk.extend(&mut builder).await.unwrap();

    let next_row = load_d_row(&builder, 1).await.unwrap();
    let proof = builder.proofs().last().expect("proof recorded").clone();
    assert!(!proof.is_empty(), "StarkProver should emit non-empty bytes");

    StarkProver
        .verify_extend(
            ExtendVerifyInput {
                current_d_commitment,
                next_row: &next_row,
            },
            &proof,
        )
        .expect("STARK verify_extend");
}

#[tokio::test]
#[ignore = "slow STARK proof coverage; run with cargo test -- --ignored"]
async fn stark_prover_apply_new_group_key_through_mutation_verifies() {
    use super::super::{RekeyVerifyInput, SimpleLine2Proofs, StarkProver};

    let mut builder = MemoryOperationBuilder::new();
    let mut sk = SimpleLine2SpaceKey::<StarkProver>::new(&mut builder)
        .await
        .unwrap();

    // Capture the old HGK commitment before rekey; afterwards it would be
    // the new FGK's commitment instead.
    let old_hgk_commitment = current_hgk_commitment(&builder).await.unwrap();

    let (commitment, new_hgk) = sk.generate_group_key(&mut builder).await.unwrap();
    sk.apply_new_group_key(new_hgk, commitment, &builder)
        .await
        .unwrap();

    let proof = builder.proofs().last().expect("proof recorded").clone();
    assert!(!proof.is_empty());

    // Rebuild verify input from post-mutation storage: the FGK, D and GBCT
    // rows just written live at d_start == 1 (the single rekey bumps next_seq
    // from 0 to 1).
    // A single rekey writes the new FGK row and its GBCT pair at ordinal 1.
    let next_fgk_row = load_fgk_row(&builder, 1).await.unwrap();
    let next_row = load_d_row(&builder, 1).await.unwrap();
    let next_pair = load_gbct_row(&builder, 1, false).await.unwrap();

    StarkProver
        .verify_rekey(
            RekeyVerifyInput {
                old_hgk_commitment,
                next_fgk_row: &next_fgk_row,
                next_row: &next_row,
                next_head_links: &next_pair,
            },
            &proof,
        )
        .expect("STARK verify_rekey");
}

#[tokio::test]
#[ignore = "slow STARK proof coverage; run with cargo test -- --ignored"]
async fn remove_user_verifier_accepts_valid_rekey_after_reduce() {
    use super::super::StarkProver;
    use encrypted_spaces_changelog_core::changelog::OpType;

    let mut pre_builder = noop_collecting_builder();
    let mut sk = SimpleLine2SpaceKey::<StarkProver>::new(&mut pre_builder)
        .await
        .unwrap();

    sk.extend(&mut pre_builder).await.unwrap();
    sk.reduce(&SimpleKeyId(1), &mut pre_builder).await.unwrap();
    let pre_output = pre_builder.finalize();
    let pre_writes_len = pre_output.writes.len();
    let pre_verify_builder = collecting_builder_with_writes(pre_output.writes.clone());

    let mut post_builder = collecting_builder_with_writes(pre_output.writes);
    let (commitment, new_hgk) = sk.generate_group_key(&mut post_builder).await.unwrap();
    sk.apply_new_group_key(new_hgk, commitment, &post_builder)
        .await
        .unwrap();
    let post_output = post_builder.finalize();
    let proof = post_output.proofs.last().expect("proof recorded").clone();
    assert!(!proof.is_empty());
    let pending_writes = &post_output.writes[pre_writes_len..];
    let pending = PendingWritesView::new(pending_writes);

    <SimpleLine2SpaceKey<StarkProver> as SpaceKey>::verify_retention_proofs(
        OpType::RemoveUser,
        std::slice::from_ref(&proof),
        &pre_verify_builder,
        &pending,
    )
    .await
    .expect("RemoveUser verifier should accept rekey after reduce");
}

#[tokio::test]
#[ignore = "slow STARK proof coverage; run with cargo test -- --ignored"]
async fn remove_user_verifier_accepts_valid_rekey_at_genesis() {
    use super::super::StarkProver;
    use encrypted_spaces_changelog_core::changelog::OpType;

    let mut pre_builder = noop_collecting_builder();
    let mut sk = SimpleLine2SpaceKey::<StarkProver>::new(&mut pre_builder)
        .await
        .unwrap();
    let pre_output = pre_builder.finalize();
    let pre_writes_len = pre_output.writes.len();
    let pre_verify_builder = collecting_builder_with_writes(pre_output.writes.clone());

    let mut post_builder = collecting_builder_with_writes(pre_output.writes);
    let (commitment, new_hgk) = sk.generate_group_key(&mut post_builder).await.unwrap();
    sk.apply_new_group_key(new_hgk, commitment, &post_builder)
        .await
        .unwrap();
    let post_output = post_builder.finalize();
    let proof = post_output.proofs.last().expect("proof recorded").clone();
    assert!(!proof.is_empty());
    let pending_writes = &post_output.writes[pre_writes_len..];
    let pending = PendingWritesView::new(pending_writes);

    <SimpleLine2SpaceKey<StarkProver> as SpaceKey>::verify_retention_proofs(
        OpType::RemoveUser,
        std::slice::from_ref(&proof),
        &pre_verify_builder,
        &pending,
    )
    .await
    .expect("RemoveUser verifier should accept first rekey from genesis state");
}

#[tokio::test]
#[ignore = "slow STARK proof coverage; run with cargo test -- --ignored"]
async fn remove_user_verifier_rejects_empty_pending_writes_after_prior_rekey() {
    // Regression: the verifier must not satisfy post-op row reads from
    // pre-state. If it did, an attacker could submit a valid-looking proof
    // with no retention payload and have verification run against the
    // existing canonical rows — removing a member without rotating keys.
    use super::super::StarkProver;
    use encrypted_spaces_changelog_core::changelog::OpType;

    let mut builder = noop_collecting_builder();
    let mut sk = SimpleLine2SpaceKey::<StarkProver>::new(&mut builder)
        .await
        .unwrap();
    let (commitment, new_hgk) = sk.generate_group_key(&mut builder).await.unwrap();
    sk.apply_new_group_key(new_hgk, commitment, &builder)
        .await
        .unwrap();
    let output = builder.finalize();
    let proof = output.proofs.last().expect("proof recorded").clone();
    assert!(!proof.is_empty());
    let pre_verify_builder = collecting_builder_with_writes(output.writes);
    let empty_pending: Vec<(String, Vec<u8>)> = Vec::new();
    let pending = PendingWritesView::new(&empty_pending);

    let result = <SimpleLine2SpaceKey<StarkProver> as SpaceKey>::verify_retention_proofs(
        OpType::RemoveUser,
        std::slice::from_ref(&proof),
        &pre_verify_builder,
        &pending,
    )
    .await;
    assert!(
        result.is_err(),
        "verifier must reject RemoveUser with empty pending_writes"
    );
}

#[tokio::test]
#[ignore = "slow STARK proof coverage; run with cargo test -- --ignored"]
async fn remove_user_verifier_rejects_partial_pending_writes() {
    use super::super::StarkProver;
    use encrypted_spaces_changelog_core::changelog::OpType;

    let mut pre_builder = noop_collecting_builder();
    let mut sk = SimpleLine2SpaceKey::<StarkProver>::new(&mut pre_builder)
        .await
        .unwrap();
    sk.extend(&mut pre_builder).await.unwrap();
    sk.reduce(&SimpleKeyId(1), &mut pre_builder).await.unwrap();
    let pre_output = pre_builder.finalize();
    let pre_writes_len = pre_output.writes.len();
    let pre_verify_builder = collecting_builder_with_writes(pre_output.writes.clone());

    let mut post_builder = collecting_builder_with_writes(pre_output.writes);
    let (commitment, new_hgk) = sk.generate_group_key(&mut post_builder).await.unwrap();
    sk.apply_new_group_key(new_hgk, commitment, &post_builder)
        .await
        .unwrap();
    let post_output = post_builder.finalize();
    let proof = post_output.proofs.last().expect("proof recorded").clone();
    assert!(!proof.is_empty());

    let partial_pending: Vec<(String, Vec<u8>)> = post_output.writes[pre_writes_len..]
        .iter()
        .filter(|(key, _)| !key.starts_with("sl2/gbct/row/"))
        .cloned()
        .collect();
    assert!(
        partial_pending.len() < post_output.writes[pre_writes_len..].len(),
        "expected to drop at least one required GBCT row from pending_writes"
    );

    let pending = PendingWritesView::new(&partial_pending);
    let result = <SimpleLine2SpaceKey<StarkProver> as SpaceKey>::verify_retention_proofs(
        OpType::RemoveUser,
        std::slice::from_ref(&proof),
        &pre_verify_builder,
        &pending,
    )
    .await;
    assert!(
        result.is_err(),
        "verifier must reject RemoveUser when a required pending row is missing"
    );
}

#[tokio::test]
async fn reduce_verify_input_reconstruction_uses_newest_to_oldest_order() {
    let mut pre_builder = noop_collecting_builder();
    let mut sk = TestSpaceKey::new(&mut pre_builder).await.unwrap();

    sk.extend(&mut pre_builder).await.unwrap();
    let (commitment, new_hgk) = sk.generate_group_key(&mut pre_builder).await.unwrap();
    sk.apply_new_group_key(new_hgk, commitment, &pre_builder)
        .await
        .unwrap();
    sk.extend(&mut pre_builder).await.unwrap();
    let (commitment, new_hgk) = sk.generate_group_key(&mut pre_builder).await.unwrap();
    sk.apply_new_group_key(new_hgk, commitment, &pre_builder)
        .await
        .unwrap();
    sk.extend(&mut pre_builder).await.unwrap();

    let chain_before = reconstruct_live_chain(&pre_builder).await.unwrap();
    let before = 3;
    let expected_ordinals: Vec<u64> = chain_before
        .iter()
        .filter(|node| node.d_range.end > before)
        .map(|node| node.fgk_ordinal)
        .collect();
    assert_eq!(
        expected_ordinals,
        vec![2, 1],
        "fragmented fixture should survive in newest-to-oldest order"
    );

    let pre_output = pre_builder.finalize();
    let pre_writes_len = pre_output.writes.len();
    let pre_verify_builder = collecting_builder_with_writes(pre_output.writes.clone());

    let mut post_builder = collecting_builder_with_writes(pre_output.writes);
    sk.reduce(&SimpleKeyId(before), &mut post_builder)
        .await
        .unwrap();
    let post_output = post_builder.finalize();
    let pending = PendingWritesView::new(&post_output.writes[pre_writes_len..]);

    let verify_inputs = collect_reduce_verify_inputs(&pre_verify_builder, &pending)
        .await
        .unwrap();

    let mut expected_survivors = Vec::new();
    let mut expected_links = Vec::new();
    for ordinal in &expected_ordinals {
        let fgk_row = load_fgk_row(&pre_verify_builder, *ordinal).await.unwrap();
        let effective_start = fgk_row.d_start.max(before);
        let d_row = match load_d_row(&pending, effective_start).await {
            Ok(row) => row,
            Err(_) => load_d_row(&pre_verify_builder, effective_start)
                .await
                .unwrap(),
        };
        expected_survivors.push(DeleteKeysSurvivor {
            d_head_seq: effective_start,
            d_head_commitment: d_row.commitment,
        });
        expected_links.push(load_gbct_row(&pending, *ordinal, false).await.unwrap());
    }

    assert_eq!(verify_inputs.survivors, expected_survivors);
    assert_eq!(verify_inputs.next_links, expected_links);

    let mut ascending_ordinals = expected_ordinals.clone();
    ascending_ordinals.sort_unstable();
    assert_ne!(
        ascending_ordinals, expected_ordinals,
        "fixture must differ from ascending ordinal order to catch regressions"
    );
}

#[tokio::test]
#[ignore = "slow STARK proof coverage; run with cargo test -- --ignored"]
async fn stark_public_reduce_verifier_accepts_fragmented_reduce() {
    use super::super::StarkProver;
    use encrypted_spaces_changelog_core::changelog::OpType;

    let mut pre_builder = noop_collecting_builder();
    let mut sk = SimpleLine2SpaceKey::<StarkProver>::new(&mut pre_builder)
        .await
        .unwrap();

    sk.extend(&mut pre_builder).await.unwrap();
    let (commitment, new_hgk) = sk.generate_group_key(&mut pre_builder).await.unwrap();
    sk.apply_new_group_key(new_hgk, commitment, &pre_builder)
        .await
        .unwrap();
    sk.extend(&mut pre_builder).await.unwrap();
    let (commitment, new_hgk) = sk.generate_group_key(&mut pre_builder).await.unwrap();
    sk.apply_new_group_key(new_hgk, commitment, &pre_builder)
        .await
        .unwrap();
    sk.extend(&mut pre_builder).await.unwrap();

    let pre_output = pre_builder.finalize();
    let pre_writes_len = pre_output.writes.len();
    let pre_verify_builder = collecting_builder_with_writes(pre_output.writes.clone());

    let mut post_builder = collecting_builder_with_writes(pre_output.writes);
    sk.reduce(&SimpleKeyId(3), &mut post_builder).await.unwrap();
    let post_output = post_builder.finalize();
    let proof = post_output.proofs.last().expect("proof recorded").clone();
    assert!(!proof.is_empty());

    let pending_writes = &post_output.writes[pre_writes_len..];
    let pending = PendingWritesView::new(pending_writes);
    <SimpleLine2SpaceKey<StarkProver> as SpaceKey>::verify_retention_proofs(
        OpType::Reduce,
        std::slice::from_ref(&proof),
        &pre_verify_builder,
        &pending,
    )
    .await
    .expect("Reduce verifier should accept fragmented reduce proof");
}

#[tokio::test]
#[ignore = "slow STARK proof coverage; run with cargo test -- --ignored"]
async fn stark_prover_reduce_through_mutation_verifies() {
    use super::super::{DeleteKeysSurvivor, DeleteKeysVerifyInput, SimpleLine2Proofs, StarkProver};

    // Build a multi-chain state so the proof covers at least one B-key.
    let mut builder = MemoryOperationBuilder::new();
    let mut sk = SimpleLine2SpaceKey::<StarkProver>::new(&mut builder)
        .await
        .unwrap();
    sk.extend(&mut builder).await.unwrap();
    apply_rekey(&mut sk, KeyMaterial::random(), &mut builder).await;
    sk.extend(&mut builder).await.unwrap();
    apply_rekey(&mut sk, KeyMaterial::random(), &mut builder).await;
    sk.extend(&mut builder).await.unwrap();

    // Capture old HGK commitment before reduce; after reduce the current
    // HGK commitment will be the DGK (== new_hgk commitment).
    let old_hgk_commitment = current_hgk_commitment(&builder).await.unwrap();

    // Record the pre-reduce chain: we need each surviving node's FGK ordinal
    // and orig_d_range_start so we can reconstruct the survivor list below.
    let chain_before = reconstruct_live_chain(&builder).await.unwrap();

    let before = SimpleKeyId(3);
    sk.reduce(&before, &mut builder).await.unwrap();

    let proof = builder.proofs().last().expect("proof recorded").clone();
    assert!(!proof.is_empty());

    // After reduce, the DGK table has one entry whose commitment is the new
    // HGK commitment the prover consumed.
    let dgk_commitment = current_hgk_commitment(&builder).await.unwrap();

    // Reconstruct survivors + next_links in the same newest-to-oldest order
    // the prover used.
    let mut survivors = Vec::new();
    let mut next_links = Vec::new();
    let mut surviving_ordinals = Vec::new();
    for node in &chain_before {
        if before.0 >= node.d_range.end {
            continue;
        }
        surviving_ordinals.push(node.fgk_ordinal);
        let effective_start = node.d_range.start.max(before.0);
        let d_row = load_d_row(&builder, effective_start).await.unwrap();
        survivors.push(DeleteKeysSurvivor {
            d_head_seq: effective_start,
            d_head_commitment: d_row.commitment,
        });
    }
    assert!(survivors.len() >= 2, "expected multi-node chain at reduce");

    for (i, ordinal) in surviving_ordinals.iter().enumerate() {
        // Post-reduce gbct row at this FGK ordinal contains the freshly written
        // link pair matching what the prover witnessed. Tailness is structural,
        // so the final row is normalized to `None` here.
        next_links.push(
            load_gbct_row(&builder, *ordinal, i == surviving_ordinals.len() - 1)
                .await
                .unwrap(),
        );
    }

    StarkProver
        .verify_delete_keys(
            DeleteKeysVerifyInput {
                old_hgk_commitment,
                dgk_commitment,
                survivors: &survivors,
                next_links: &next_links,
            },
            &proof,
        )
        .expect("STARK verify_delete_keys");
}
