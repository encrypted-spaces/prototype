//! SimpleLine2 [`SpaceKey`] implementation and algorithm layer.
//!
//! This module owns cryptographic helpers (derivation tags, encryption),
//! live chain reconstruction, key resolution, and the [`SimpleLine2SpaceKey`]
//! struct that implements [`SpaceKey`] (extend, reduce, fresh rekey).
//! Data access is delegated to `super::store`.

use encrypted_spaces_changelog_core::changelog::OpType;
use encrypted_spaces_crypto::key_derivation::{
    DerivationKoalaBearPoseidon2_16, DerivationTag, KeyDerivation,
};
use encrypted_spaces_crypto::EncryptedKeyMaterial;
use encrypted_spaces_crypto::{KeyCommitment, KeyMaterial};
use encrypted_spaces_key_manager::error::KeyManagerError;
use encrypted_spaces_key_manager::traits::GroupKeySync;
use encrypted_spaces_key_manager::{OperationBuilder, OperationReader};
use encrypted_spaces_key_manager::{SimpleKeyId, SpaceKey};
use serde::{Deserialize, Serialize};

use super::proof::{
    DeleteKeysProofInput, DeleteKeysSurvivor, ExtendProofInput, RekeyProofInput,
    SimpleLine2RuntimeProver,
};
use super::store::*;

type Derivation = DerivationKoalaBearPoseidon2_16;

// =========================================================================
// Derivation tag constants
// =========================================================================

pub(super) const GB_CHAIN_LINK_TAG: &[u8] = b"simpleline2/v1/gb-chain-link";
pub(super) const D_HEAD_ENCRYPT_TAG: &[u8] = b"simpleline2/v1/d-head-encrypt";
pub(super) const D_DERIVE_TAG: &[u8] = b"simpleline2/v1/d-derive";
pub(super) const HGK_DERIVE_TAG: &[u8] = b"simpleline2/v1/hgk-derive";

pub(super) fn tag(bytes: &[u8]) -> DerivationTag {
    DerivationTag::from_bytes(bytes)
}

// =========================================================================
// Encryption helpers
// =========================================================================

/// Encrypt an older GB key under a newer GB key (chain link).
pub(crate) fn encrypt_gb_chain_link<D: KeyDerivation>(
    derivation: &D,
    gb_key: &KeyMaterial,
    older_gb_key: &KeyMaterial,
) -> EncryptedKeyMaterial {
    let enc_key = derivation.derive(gb_key, tag(GB_CHAIN_LINK_TAG));
    EncryptedKeyMaterial::encrypt(enc_key, older_gb_key)
}

/// Encrypt a D head under a GB key.
pub(crate) fn encrypt_d_head<D: KeyDerivation>(
    derivation: &D,
    gb_key: &KeyMaterial,
    d_head: &KeyMaterial,
) -> EncryptedKeyMaterial {
    let enc_key = derivation.derive(gb_key, tag(D_HEAD_ENCRYPT_TAG));
    EncryptedKeyMaterial::encrypt(enc_key, d_head)
}

// =========================================================================
// Live chain reconstruction
// =========================================================================

/// Reconstruct the live FGK chain from storage.
///
/// Returns [`LiveChainNode`]s in newest-to-oldest order, where
/// each node's `d_range` is the D-sequence interval it covers.
pub(crate) async fn reconstruct_live_chain(
    reader: &dyn OperationReader,
) -> Result<Vec<LiveChainNode>, KeyManagerError> {
    let fgk_next = load_fgk_next(reader).await?;
    let d_min = load_d_min(reader).await?;
    let next_d = load_d_next(reader).await?;
    if d_min >= next_d {
        return Err(KeyManagerError);
    }
    if fgk_next == 0 {
        return Err(KeyManagerError);
    }

    // Walk FGK rows newest-to-oldest. Ordinals are dense and append-only, so
    // stepping from fgk_next-1 downwards visits every row in reverse d_start
    // order (older rows may be semantically unreachable but remain in storage).
    let mut result = Vec::new();
    let mut cursor = next_d;
    let mut ordinal = fgk_next;

    while ordinal > 0 && cursor > d_min {
        ordinal -= 1;
        let fgk = load_fgk_row(reader, ordinal).await?;
        if fgk.d_start >= cursor {
            continue;
        }
        let effective_start = fgk.d_start.max(d_min);
        if effective_start >= cursor {
            continue;
        }
        result.push(LiveChainNode {
            fgk_ordinal: ordinal,
            d_range: effective_start..cursor,
        });
        cursor = effective_start;
    }

    Ok(result)
}

// =========================================================================
// Read APIs
// =========================================================================

/// Return the current (latest) key id from storage.
pub(crate) async fn current_key_id(
    reader: &dyn OperationReader,
) -> Result<SimpleKeyId, KeyManagerError> {
    let d_next = load_d_next(reader).await?;
    if d_next == 0 {
        return Err(KeyManagerError);
    }
    Ok(SimpleKeyId(d_next - 1))
}

/// Return the current HGK commitment from storage.
///
/// If the DGK table is non-empty, returns the last DGK commitment.
/// Otherwise returns the last FGK commitment.
pub(crate) async fn current_hgk_commitment(
    reader: &dyn OperationReader,
) -> Result<KeyCommitment, KeyManagerError> {
    let dgk_next = load_dgk_next(reader).await?;
    if dgk_next > 0 {
        let dgk = load_dgk_row(reader, dgk_next - 1).await?;
        return Ok(dgk.commitment);
    }
    let fgk_next = load_fgk_next(reader).await?;
    if fgk_next == 0 {
        return Err(KeyManagerError);
    }
    let fgk = load_fgk_row(reader, fgk_next - 1).await?;
    Ok(fgk.commitment)
}

/// Resolve the current HGK by deriving forward from a locally-held HGK
/// through DGK derivation steps.
///
/// Returns `Err` if the local HGK cannot be derived to match the current
/// HGK commitment (e.g. a fresh rekey was missed).
pub(crate) async fn resolve_current_hgk(
    local_hgk: &KeyMaterial,
    reader: &dyn OperationReader,
) -> Result<KeyMaterial, KeyManagerError> {
    let derivation = Derivation::default();
    let target = current_hgk_commitment(reader).await?;

    let mut key = local_hgk.clone();
    if derivation.commit(&key) == target {
        return Ok(key);
    }

    let dgk_next = load_dgk_next(reader).await?;
    let max_steps = dgk_next as usize + 1;
    for _ in 0..max_steps {
        key = derivation.derive(&key, tag(HGK_DERIVE_TAG));
        if derivation.commit(&key) == target {
            return Ok(key);
        }
    }

    Err(KeyManagerError)
}

/// Resolve the D key at a given sequence number.
///
/// Walks the live chain from the HGK to the chain node covering `d_seq`,
/// decrypts the D head, and derives forward to the target.
pub(crate) async fn resolve_d_key(
    local_hgk: &KeyMaterial,
    d_seq: u64,
    reader: &dyn OperationReader,
) -> Result<KeyMaterial, KeyManagerError> {
    let derivation = Derivation::default();

    let chain = reconstruct_live_chain(reader).await?;
    let node_index = chain
        .iter()
        .position(|node| node.d_range.contains(&d_seq))
        .ok_or(KeyManagerError)?;

    // Walk GB chain from HGK to the target node
    let current_hgk = resolve_current_hgk(local_hgk, reader).await?;
    let mut gb_key = current_hgk;

    for node in &chain[..node_index] {
        let pair = load_gbct_row(reader, node.fgk_ordinal, false).await?;
        let ct = pair
            .older_gb_key_ciphertext
            .as_ref()
            .ok_or(KeyManagerError)?;
        let enc_key = derivation.derive(&gb_key, tag(GB_CHAIN_LINK_TAG));
        gb_key = ct.decrypt(enc_key);
    }

    // Decrypt D head
    let target_node = &chain[node_index];
    let d_head = load_gbct_d_head(reader, target_node.fgk_ordinal).await?;
    let d_head_enc_key = derivation.derive(&gb_key, tag(D_HEAD_ENCRYPT_TAG));
    let mut d_key = d_head.decrypt(d_head_enc_key);

    // Derive forward to the target seq
    let d_range_start = target_node.d_range.start;
    let mut cursor = d_range_start;
    while cursor < d_seq {
        d_key = derivation.derive(&d_key, tag(D_DERIVE_TAG));
        cursor += 1;
    }

    // Verify commitment
    let d_row = load_d_row(reader, d_seq).await?;
    if derivation.commit(&d_key) != d_row.commitment {
        return Err(KeyManagerError);
    }

    Ok(d_key)
}

/// Validate the storage shape for SimpleLine2.
///
/// Checks structural invariants: non-empty FGK/D tables, strictly
/// increasing FGK d_starts, contiguous D seqs, live chain tiling, and
/// ciphertext row consistency.
#[cfg(test)]
pub(crate) async fn validate_storage_shape(
    reader: &dyn OperationReader,
) -> Result<(), KeyManagerError> {
    let fgk_next = load_fgk_next(reader).await?;
    let dgk_next = load_dgk_next(reader).await?;
    let d_min = load_d_min(reader).await?;
    let d_next = load_d_next(reader).await?;

    if fgk_next == 0 {
        return Err(KeyManagerError);
    }
    if d_min >= d_next {
        return Err(KeyManagerError);
    }

    // Load all FGK rows and enforce structural invariants the rest of the
    // code relies on:
    //   1. d_starts are strictly increasing by ordinal (append-only writers
    //      always use `d_start = d_next` at rekey time);
    //   2. the latest FGK row (at `fgk_next - 1`) is part of the live chain,
    //      i.e. its `d_start < d_next`. `current_hgk_commitment()` reads this
    //      row directly; if it fell outside the live range, readers would
    //      target an unreachable commitment while the chain tiled fine from
    //      older rows.
    let mut fgk_rows = Vec::with_capacity(fgk_next as usize);
    for ordinal in 0..fgk_next {
        fgk_rows.push(load_fgk_row(reader, ordinal).await?);
    }
    for pair in fgk_rows.windows(2) {
        if pair[0].d_start >= pair[1].d_start {
            return Err(KeyManagerError);
        }
    }
    if fgk_rows.last().unwrap().d_start >= d_next {
        return Err(KeyManagerError);
    }

    for seq in d_min..d_next {
        load_d_row(reader, seq).await?;
    }
    for ordinal in 0..dgk_next {
        load_dgk_row(reader, ordinal).await?;
    }

    // Live chain must be non-empty and tile [d_min, d_next), and must start
    // at ordinal `fgk_next - 1` so `current_hgk_commitment()` points at the
    // chain head.
    let chain = reconstruct_live_chain(reader).await?;
    if chain.is_empty() {
        return Err(KeyManagerError);
    }
    if chain.first().unwrap().fgk_ordinal != fgk_next - 1 {
        return Err(KeyManagerError);
    }
    if chain.last().unwrap().d_range.start != d_min {
        return Err(KeyManagerError);
    }
    if chain.first().unwrap().d_range.end != d_next {
        return Err(KeyManagerError);
    }

    // Ciphertext row validation: one row per chain node, keyed by FGK ordinal.
    // Tailness is structural, so only non-tail rows require a real
    // `older_gb_key_ciphertext`; the tail row is forced to semantic `None`.
    let n = chain.len();
    for (i, node) in chain.iter().enumerate() {
        let pair = load_gbct_row(reader, node.fgk_ordinal, i == n - 1).await?;
        if i < n - 1 && pair.older_gb_key_ciphertext.is_none() {
            return Err(KeyManagerError);
        }
    }

    Ok(())
}

// =========================================================================
// Reduce helpers
// =========================================================================

/// Info about a surviving chain node during reduce.
struct SurvivingInfo {
    fgk_ordinal: u64,
    orig_d_range_start: u64,
    chain_index: usize,
}

/// Walk the GB chain from old HGK, returning one GB key per chain node.
async fn resolve_chain_gb_keys<D: KeyDerivation>(
    chain: &[LiveChainNode],
    old_hgk: KeyMaterial,
    derivation: &D,
    reader: &dyn OperationReader,
) -> Result<Vec<KeyMaterial>, KeyManagerError> {
    let mut gb_keys = Vec::with_capacity(chain.len());
    let mut key = old_hgk;
    for (i, node) in chain.iter().enumerate() {
        gb_keys.push(key.clone());
        let pair = load_gbct_row(reader, node.fgk_ordinal, i == chain.len() - 1).await?;
        if let Some(ct) = pair.older_gb_key_ciphertext.as_ref() {
            let enc_key = derivation.derive(&key, tag(GB_CHAIN_LINK_TAG));
            key = ct.decrypt(enc_key);
        }
    }
    Ok(gb_keys)
}

/// Result of building the new ciphertext rows for a reduce operation.
///
/// Carries the proof witness material (fresh B keys and advanced D-head keys)
/// alongside the pairs to be persisted, so the caller can prove before persist
/// without redoing any of the crypto.
struct ReduceCiphertexts {
    /// New GBCT pairs, ordered newest-to-oldest matching `surviving`.
    pairs: Vec<GBCiphertextPair>,
    /// Fresh GB keys for the non-head surviving nodes (i.e. `new_gb_keys[1..]`).
    /// Ordered newest-to-oldest matching `surviving[1..]`.
    b_keys: Vec<KeyMaterial>,
    /// Advanced D-head keys for each surviving node, newest-to-oldest.
    d_head_keys: Vec<KeyMaterial>,
}

/// Compute new GB keys, advance D heads, and build new ciphertext pairs.
async fn build_reduce_ciphertexts<D: KeyDerivation>(
    surviving: &[SurvivingInfo],
    old_gb_keys: &[KeyMaterial],
    new_hgk: &KeyMaterial,
    before: u64,
    derivation: &D,
    reader: &dyn OperationReader,
) -> Result<ReduceCiphertexts, KeyManagerError> {
    let n = surviving.len();
    let mut new_gb_keys = Vec::with_capacity(n);
    let mut new_d_heads = Vec::with_capacity(n);

    for (s_idx, info) in surviving.iter().enumerate() {
        let old_gb_key = &old_gb_keys[info.chain_index];

        // Decrypt old D head and derive forward to new effective start
        let d_head = load_gbct_d_head(reader, info.fgk_ordinal).await?;
        let d_head_enc_key = derivation.derive(old_gb_key, tag(D_HEAD_ENCRYPT_TAG));
        let old_d_head = d_head.decrypt(d_head_enc_key);

        let effective_start = info.orig_d_range_start.max(before);
        let mut d_key = old_d_head;
        let mut cursor = info.orig_d_range_start;
        while cursor < effective_start {
            d_key = derivation.derive(&d_key, tag(D_DERIVE_TAG));
            cursor += 1;
        }
        new_d_heads.push(d_key);

        // Head node uses new HGK, others get fresh random B keys
        let new_key = if s_idx == 0 {
            new_hgk.clone()
        } else {
            KeyMaterial::random()
        };
        new_gb_keys.push(new_key);
    }

    // Build ciphertext pairs
    let mut pairs = Vec::with_capacity(n);
    for i in 0..n {
        let older_gb_key_ciphertext = if i + 1 < n {
            Some(encrypt_gb_chain_link(
                derivation,
                &new_gb_keys[i],
                &new_gb_keys[i + 1],
            ))
        } else {
            None
        };
        let d_head_ciphertext = encrypt_d_head(derivation, &new_gb_keys[i], &new_d_heads[i]);
        pairs.push(GBCiphertextPair {
            older_gb_key_ciphertext,
            d_head_ciphertext,
        });
    }

    let b_keys: Vec<KeyMaterial> = new_gb_keys.into_iter().skip(1).collect();
    Ok(ReduceCiphertexts {
        pairs,
        b_keys,
        d_head_keys: new_d_heads,
    })
}

/// Write the reduce results to storage: advance d_min, append DGK, overwrite GBCT pairs.
///
/// Old FGK rows whose d_start falls below the new `d_min` remain in storage as
/// unreachable history — live-chain reconstruction walks back from `fgk_next - 1`
/// and stops covering at `d_min`, so older rows are harmless.
async fn write_reduce_to_storage(
    before: u64,
    new_hgk_commitment: KeyCommitment,
    surviving: &[SurvivingInfo],
    new_gbct_pairs: &[GBCiphertextPair],
    builder: &mut dyn OperationBuilder,
) -> Result<(), KeyManagerError> {
    // Advance d_min: older D rows become unreachable (they remain in storage).
    save_d_min(builder, before).await;

    // Append DGK commitment at the next ordinal, then bump the counter.
    let dgk_next = load_dgk_next(builder).await?;
    save_dgk_row(
        builder,
        dgk_next,
        &DGKRow {
            commitment: new_hgk_commitment,
        },
    )
    .await;
    save_dgk_next(builder, dgk_next + 1).await;

    // Overwrite GBCT pairs for surviving FGK ordinals.
    for (info, pair) in surviving.iter().zip(new_gbct_pairs.iter()) {
        save_gbct_row(builder, info.fgk_ordinal, pair).await;
    }

    Ok(())
}

// =========================================================================
// Proof assembly + recording helpers
// =========================================================================
//
// Ordering invariant for every mutation path below:
//     assemble proof input → prove → record_proof → persist via put()
//
// A failed prove() must not leak partial writes into the builder.

async fn prove_extend_and_record(
    prover: &impl SimpleLine2RuntimeProver,
    derivation: &Derivation,
    current_d_commitment: KeyCommitment,
    next_row: &DTableRow,
    current_d_key: &KeyMaterial,
    next_d_key: &KeyMaterial,
    builder: &mut dyn OperationBuilder,
) -> Result<(), KeyManagerError> {
    let bytes = prover.prove_extend_runtime(ExtendProofInput {
        current_d_commitment,
        next_row,
        derivation,
        current_d_key,
        next_d_key,
    })?;
    builder.record_proof(bytes).await;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn prove_rekey_and_record(
    prover: &impl SimpleLine2RuntimeProver,
    derivation: &Derivation,
    old_hgk_commitment: KeyCommitment,
    next_fgk_row: &FGKRow,
    next_row: &DTableRow,
    next_head_links: &GBCiphertextPair,
    old_hgk: &KeyMaterial,
    new_hgk: &KeyMaterial,
    new_d_head: &KeyMaterial,
    builder: &mut dyn OperationBuilder,
) -> Result<(), KeyManagerError> {
    let bytes = prover.prove_rekey_runtime(RekeyProofInput {
        old_hgk_commitment,
        next_fgk_row,
        next_row,
        next_head_links,
        derivation,
        old_hgk,
        new_hgk,
        new_d_head,
    })?;
    builder.record_proof(bytes).await;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn prove_delete_keys_and_record(
    prover: &impl SimpleLine2RuntimeProver,
    derivation: &Derivation,
    old_hgk_commitment: KeyCommitment,
    dgk_commitment: KeyCommitment,
    survivors: &[DeleteKeysSurvivor],
    next_links: &[GBCiphertextPair],
    old_hgk: &KeyMaterial,
    new_hgk: &KeyMaterial,
    b_keys: &[KeyMaterial],
    d_head_keys: &[KeyMaterial],
    builder: &mut dyn OperationBuilder,
) -> Result<(), KeyManagerError> {
    let bytes = prover.prove_delete_keys_runtime(DeleteKeysProofInput {
        old_hgk_commitment,
        dgk_commitment,
        survivors,
        next_links,
        derivation,
        old_hgk,
        new_hgk,
        b_keys,
        d_head_keys,
    })?;
    builder.record_proof(bytes).await;
    Ok(())
}

#[derive(Debug)]
pub(crate) struct ReduceVerifyInputsOwned {
    pub old_hgk_commitment: KeyCommitment,
    pub dgk_commitment: KeyCommitment,
    pub survivors: Vec<DeleteKeysSurvivor>,
    pub next_links: Vec<GBCiphertextPair>,
}

impl ReduceVerifyInputsOwned {
    fn as_verify_input(&self) -> super::proof::DeleteKeysVerifyInput<'_> {
        super::proof::DeleteKeysVerifyInput {
            old_hgk_commitment: self.old_hgk_commitment,
            dgk_commitment: self.dgk_commitment,
            survivors: &self.survivors,
            next_links: &self.next_links,
        }
    }
}

/// Rebuild reduce public inputs from storage in the same newest-to-oldest
/// chain order the prover uses, while stopping once the walk reaches the new
/// `d_min` cutoff.
pub(crate) async fn collect_reduce_verify_inputs(
    pre_state: &dyn OperationReader,
    pending_writes: &dyn OperationReader,
) -> Result<ReduceVerifyInputsOwned, KeyManagerError> {
    let old_hgk_commitment = current_hgk_commitment(pre_state).await?;

    let dgk_next = load_dgk_next(pending_writes).await?;
    if dgk_next == 0 {
        return Err(KeyManagerError);
    }
    let dgk_commitment = load_dgk_row(pending_writes, dgk_next - 1).await?.commitment;

    let fgk_next = load_fgk_next(pre_state).await?;
    let d_min_old = load_d_min(pre_state).await?;
    let d_min_new = load_d_min(pending_writes).await?;
    let next_d = load_d_next(pre_state).await?;

    if fgk_next == 0 || d_min_old >= next_d || d_min_new >= next_d || d_min_new <= d_min_old {
        return Err(KeyManagerError);
    }

    let mut survivors = Vec::new();
    let mut next_links = Vec::new();
    let mut cursor = next_d;
    let mut ordinal = fgk_next;

    while ordinal > 0 && cursor > d_min_new {
        ordinal -= 1;
        let fgk = load_fgk_row(pre_state, ordinal).await?;
        if fgk.d_start >= cursor {
            continue;
        }

        let range_start = fgk.d_start.max(d_min_old);
        if range_start >= cursor {
            continue;
        }

        let effective_start = range_start.max(d_min_new);
        let d_row = match load_d_row(pending_writes, effective_start).await {
            Ok(row) => row,
            Err(_) => load_d_row(pre_state, effective_start).await?,
        };

        survivors.push(DeleteKeysSurvivor {
            d_head_seq: effective_start,
            d_head_commitment: d_row.commitment,
        });
        next_links.push(load_gbct_row(pending_writes, ordinal, false).await?);
        cursor = range_start;
    }

    if survivors.is_empty() {
        return Err(KeyManagerError);
    }

    Ok(ReduceVerifyInputsOwned {
        old_hgk_commitment,
        dgk_commitment,
        survivors,
        next_links,
    })
}

// =========================================================================
// SpaceKey adapter
// =========================================================================

/// Domain-separation prefix for D-key HKDF. Matches the `retention_client.rs`
/// contract in `sl2_pr5`.
const D_KEY_HKDF_INFO_PREFIX: &str = "encrypted_spaces/retention/simple_line2/d_key_hkdf/v1/d:";

/// A [`SpaceKey`] backed by SimpleLine2 retention over key-value storage.
///
/// Only the current HGK is stored locally. All public retention state
/// (FGK/DGK/D/GB-ciphertext tables) lives in the builder.
///
/// Generic over the prover `P`, which defaults to [`DefaultProver`]
/// (selected at compile time via the `real-proofs` cargo feature).
#[derive(Clone, Serialize, Deserialize)]
pub struct SimpleLine2SpaceKey<P: SimpleLine2RuntimeProver = super::DefaultProver> {
    pub(crate) hgk: KeyMaterial,
    #[serde(skip)]
    pub(crate) _prover: std::marker::PhantomData<P>,
}

impl<P: SimpleLine2RuntimeProver> SimpleLine2SpaceKey<P> {
    /// Create a new `SimpleLine2SpaceKey` and initialize storage with the
    /// first FGK, D key, and GB ciphertext row.
    pub async fn new(builder: &mut dyn OperationBuilder) -> Result<Self, KeyManagerError> {
        let hgk = KeyMaterial::random();
        let derivation = Derivation::default();
        let d0 = KeyMaterial::random();

        let fgk_row = FGKRow {
            d_start: 0,
            commitment: derivation.commit(&hgk),
        };
        let d_row = DTableRow {
            seq: 0,
            commitment: derivation.commit(&d0),
        };
        let gbct_pair = GBCiphertextPair {
            older_gb_key_ciphertext: None,
            d_head_ciphertext: encrypt_d_head(&derivation, &hgk, &d0),
        };

        // Write metadata
        save_fgk_next(builder, 1).await;
        save_dgk_next(builder, 0).await;
        save_d_min(builder, 0).await;
        save_d_next(builder, 1).await;

        // Write rows (FGK and its matching GBCT share ordinal 0)
        save_fgk_row(builder, 0, &fgk_row).await;
        save_d_row(builder, &d_row).await;
        save_gbct_row(builder, 0, &gbct_pair).await;

        Ok(Self {
            hgk,
            _prover: std::marker::PhantomData,
        })
    }
}
impl<P: SimpleLine2RuntimeProver> SimpleLine2SpaceKey<P> {
    /// Extend the current SL2 chain.
    ///
    /// Proves the D-key extension (current_d → next_d derivation + commitments)
    /// and records the proof bytes on the builder **before** any `put()` call,
    /// so a failed prove cannot leak partial writes.
    pub async fn extend(
        &mut self,
        builder: &mut dyn OperationBuilder,
    ) -> Result<SimpleKeyId, KeyManagerError> {
        let derivation = Derivation::default();

        let d_next = load_d_next(builder).await?;
        if d_next == 0 {
            return Err(KeyManagerError);
        }
        let last_seq = d_next - 1;
        let next_seq = d_next;

        // Resolve current tail D key and derive the next one
        let current_d = resolve_d_key(&self.hgk, last_seq, builder).await?;
        let next_d = derivation.derive(&current_d, tag(D_DERIVE_TAG));
        let current_d_commitment = load_d_row(builder, last_seq).await?.commitment;

        let d_row = DTableRow {
            seq: next_seq,
            commitment: derivation.commit(&next_d),
        };

        // Prove before persist
        prove_extend_and_record(
            &P::default(),
            &derivation,
            current_d_commitment,
            &d_row,
            &current_d,
            &next_d,
            builder,
        )
        .await?;

        // Persist
        save_d_row(builder, &d_row).await;
        save_d_next(builder, next_seq + 1).await;

        Ok(SimpleKeyId(next_seq))
    }

    /// Apply a new group key.
    /// Generate a fresh group key and write all retention state (FGK/D/GBCT rows)
    /// to the builder. Returns (commitment, key_material) for MVE distribution.
    pub async fn generate_group_key(
        &self,
        builder: &mut dyn OperationBuilder,
    ) -> Result<(KeyCommitment, KeyMaterial), KeyManagerError> {
        let derivation = Derivation::default();
        let new_group_key = KeyMaterial::random();
        let commitment = derivation.commit(&new_group_key);

        let old_hgk_resolved = resolve_current_hgk(&self.hgk, builder).await?;
        let old_hgk_commitment = current_hgk_commitment(builder).await?;
        let new_d_head = KeyMaterial::random();

        let d_next = load_d_next(builder).await?;
        if d_next == 0 {
            return Err(KeyManagerError);
        }
        let next_seq = d_next;

        // New FGK row
        let next_fgk_row = FGKRow {
            d_start: next_seq,
            commitment,
        };

        // New D row
        let next_d_row = DTableRow {
            seq: next_seq,
            commitment: derivation.commit(&new_d_head),
        };

        // New ciphertext pair: encrypts old HGK as chain link, new D head
        let next_pair = GBCiphertextPair {
            older_gb_key_ciphertext: Some(encrypt_gb_chain_link(
                &derivation,
                &new_group_key,
                &old_hgk_resolved,
            )),
            d_head_ciphertext: encrypt_d_head(&derivation, &new_group_key, &new_d_head),
        };

        // Prove before persist
        prove_rekey_and_record(
            &P::default(),
            &derivation,
            old_hgk_commitment,
            &next_fgk_row,
            &next_d_row,
            &next_pair,
            &old_hgk_resolved,
            &new_group_key,
            &new_d_head,
            builder,
        )
        .await?;

        // --- Persist ---

        // Append FGK row at the next ordinal and its matching GBCT pair.
        let fgk_next = load_fgk_next(builder).await?;
        save_fgk_row(builder, fgk_next, &next_fgk_row).await;
        save_gbct_row(builder, fgk_next, &next_pair).await;
        save_fgk_next(builder, fgk_next + 1).await;

        // Signal that a fresh HGK was written — callers need to fetch
        // the delivery slot to recover the new group key.
        builder.mark_needs_delivery();

        // Clear DGK table (old rows at ordinals < dgk_next are now unreachable).
        save_dgk_next(builder, 0).await;

        // Append D row
        save_d_row(builder, &next_d_row).await;
        save_d_next(builder, next_seq + 1).await;

        Ok((commitment, new_group_key))
    }

    /// Activate a group key locally. Does not write to the builder.
    pub async fn apply_new_group_key(
        &mut self,
        new_group_key: KeyMaterial,
        _commitment: KeyCommitment,
        _reader: &dyn OperationReader,
    ) -> Result<(), KeyManagerError> {
        self.hgk = new_group_key;
        Ok(())
    }

    /// Reduce the current SL2 chain.
    pub async fn reduce(
        &mut self,
        before: &SimpleKeyId,
        builder: &mut dyn OperationBuilder,
    ) -> Result<(), KeyManagerError> {
        let before = before.0;
        let derivation = Derivation::default();

        let d_min = load_d_min(builder).await?;
        let next_d = load_d_next(builder).await?;

        if before <= d_min {
            return Err(KeyManagerError);
        }
        if before >= next_d {
            return Err(KeyManagerError);
        }

        // Resolve old HGK and derive new HGK
        let old_hgk = resolve_current_hgk(&self.hgk, builder).await?;
        let old_hgk_commitment = current_hgk_commitment(builder).await?;
        let new_hgk = derivation.derive(&old_hgk, tag(HGK_DERIVE_TAG));
        let dgk_commitment = derivation.commit(&new_hgk);

        // Get current live chain and filter surviving nodes
        let chain = reconstruct_live_chain(builder).await?;

        let mut surviving = Vec::new();
        for (i, node) in chain.iter().enumerate() {
            if before >= node.d_range.end {
                continue;
            }
            surviving.push(SurvivingInfo {
                fgk_ordinal: node.fgk_ordinal,
                orig_d_range_start: node.d_range.start,
                chain_index: i,
            });
        }
        if surviving.is_empty() {
            return Err(KeyManagerError);
        }

        // Resolve old GB keys and build new ciphertext material
        let old_gb_keys =
            resolve_chain_gb_keys(&chain, old_hgk.clone(), &derivation, builder).await?;
        let ct = build_reduce_ciphertexts(
            &surviving,
            &old_gb_keys,
            &new_hgk,
            before,
            &derivation,
            builder,
        )
        .await?;

        // Assemble proof public inputs
        let mut proof_survivors = Vec::with_capacity(surviving.len());
        let mut proof_links = Vec::with_capacity(surviving.len());
        for (info, pair) in surviving.iter().zip(ct.pairs.iter()) {
            let effective_start = info.orig_d_range_start.max(before);
            let commitment = load_d_row(builder, effective_start).await?.commitment;
            proof_survivors.push(DeleteKeysSurvivor {
                d_head_seq: effective_start,
                d_head_commitment: commitment,
            });
            proof_links.push(pair.clone());
        }

        // Prove before persist
        prove_delete_keys_and_record(
            &P::default(),
            &derivation,
            old_hgk_commitment,
            dgk_commitment,
            &proof_survivors,
            &proof_links,
            &old_hgk,
            &new_hgk,
            &ct.b_keys,
            &ct.d_head_keys,
            builder,
        )
        .await?;

        // Persist
        write_reduce_to_storage(before, dgk_commitment, &surviving, &ct.pairs, builder).await?;

        Ok(())
    }
}

#[async_trait::async_trait]
impl<P: SimpleLine2RuntimeProver + Send + Sync> SpaceKey for SimpleLine2SpaceKey<P> {
    type KeyId = SimpleKeyId;

    fn from_group_key(group_key: KeyMaterial) -> Self {
        Self {
            hgk: group_key,
            _prover: std::marker::PhantomData,
        }
    }

    async fn current_key_id(
        &self,
        reader: &dyn OperationReader,
    ) -> Result<SimpleKeyId, KeyManagerError> {
        current_key_id(reader).await
    }

    async fn data_key_for_key_id(
        &self,
        key_id: &SimpleKeyId,
        reader: &dyn OperationReader,
    ) -> Result<[u8; 32], KeyManagerError> {
        let d_seq = key_id.0;
        let d_key = resolve_d_key(&self.hgk, d_seq, reader).await?;
        d_key_hkdf(&d_key, d_seq)
    }

    async fn produce_group_key(
        &mut self,
        builder: &mut dyn OperationBuilder,
    ) -> Result<(KeyCommitment, KeyMaterial), KeyManagerError> {
        let derivation = Derivation::default();
        let current_hgk = resolve_current_hgk(&self.hgk, builder).await?;
        self.hgk = current_hgk.clone();
        let commitment = derivation.commit(&current_hgk);
        Ok((commitment, current_hgk))
    }

    async fn generate_group_key(
        &self,
        builder: &mut dyn OperationBuilder,
    ) -> Result<(KeyCommitment, KeyMaterial), KeyManagerError> {
        SimpleLine2SpaceKey::generate_group_key(self, builder).await
    }

    async fn apply_new_group_key(
        &mut self,
        new_group_key: KeyMaterial,
        commitment: KeyCommitment,
        reader: &dyn OperationReader,
    ) -> Result<(), KeyManagerError> {
        SimpleLine2SpaceKey::apply_new_group_key(self, new_group_key, commitment, reader).await
    }

    async fn extend(
        &mut self,
        builder: &mut dyn OperationBuilder,
    ) -> Result<SimpleKeyId, KeyManagerError> {
        SimpleLine2SpaceKey::extend(self, builder).await
    }

    async fn reduce(
        &mut self,
        before: &SimpleKeyId,
        builder: &mut dyn OperationBuilder,
    ) -> Result<(), KeyManagerError> {
        SimpleLine2SpaceKey::reduce(self, before, builder).await
    }

    async fn sync_group_key(
        &mut self,
        reader: &dyn OperationReader,
    ) -> Result<GroupKeySync, KeyManagerError> {
        let derivation = Derivation::default();
        let target = current_hgk_commitment(reader).await?;
        if derivation.commit(&self.hgk) == target {
            return Ok(GroupKeySync::AlreadyCurrent);
        }
        match resolve_current_hgk(&self.hgk, reader).await {
            Ok(resolved) => {
                self.hgk = resolved;
                Ok(GroupKeySync::DerivedForward)
            }
            Err(_) => Ok(GroupKeySync::NeedsDelivery),
        }
    }

    async fn recover_group_key_from_candidate(
        &mut self,
        candidate: KeyMaterial,
        reader: &dyn OperationReader,
    ) -> Result<(), KeyManagerError> {
        let resolved = resolve_current_hgk(&candidate, reader).await?;
        self.hgk = resolved;
        Ok(())
    }

    fn op_may_need_delivery(op_type: OpType) -> bool {
        matches!(op_type, OpType::RemoveUser | OpType::Rekey)
    }

    async fn verify_retention_proofs(
        op_type: OpType,
        proofs: &[Vec<u8>],
        pre_state: &dyn OperationReader,
        pending_writes: &dyn OperationReader,
    ) -> Result<(), KeyManagerError> {
        match op_type {
            OpType::CreateSpace => {
                // CreateSpace initializes state — no transition proof needed.
                if !proofs.is_empty() {
                    return Err(KeyManagerError);
                }
                Ok(())
            }
            OpType::InviteUser => {
                // InviteUser doesn't change retention state — no proof needed.
                if !proofs.is_empty() {
                    return Err(KeyManagerError);
                }
                Ok(())
            }
            OpType::RemoveUser | OpType::Rekey => {
                // Rekey generates exactly 1 proof.
                if proofs.len() != 1 {
                    return Err(KeyManagerError);
                }

                // Rekey verification needs the pre-op canonical HGK commitment
                // (read from pre_state) and the new rows written by the rekey
                // (read strictly from pending_writes — no fallback to
                // pre_state, otherwise an empty or partial payload could
                // satisfy verification against stale canonical rows).
                let old_hgk_commitment = current_hgk_commitment(pre_state).await?;

                let fgk_next = load_fgk_next(pending_writes).await?;
                if fgk_next == 0 {
                    return Err(KeyManagerError);
                }
                let new_ordinal = fgk_next - 1;

                let next_fgk_row = load_fgk_row(pending_writes, new_ordinal).await?;
                let next_d_row = load_d_row(pending_writes, next_fgk_row.d_start).await?;
                let next_head_links = load_gbct_row(pending_writes, new_ordinal, false).await?;

                P::default().verify_rekey_runtime(
                    super::proof::RekeyVerifyInput {
                        old_hgk_commitment,
                        next_fgk_row: &next_fgk_row,
                        next_row: &next_d_row,
                        next_head_links: &next_head_links,
                    },
                    &proofs[0],
                )?;

                Ok(())
            }
            OpType::Extend => {
                // Extend generates exactly 1 proof.
                if proofs.len() != 1 {
                    return Err(KeyManagerError);
                }

                // Load current D tail commitment from pre_state and next D row
                // from pending_writes.
                let d_next = load_d_next(pending_writes).await?;
                if d_next == 0 {
                    return Err(KeyManagerError);
                }
                let next_seq = d_next - 1;
                // The previous D commitment (before extend) is at next_seq - 1
                if next_seq == 0 {
                    return Err(KeyManagerError);
                }
                let current_d_commitment = load_d_row(pre_state, next_seq - 1).await?.commitment;
                let next_d_row = load_d_row(pending_writes, next_seq).await?;

                P::default().verify_extend_runtime(
                    super::proof::ExtendVerifyInput {
                        current_d_commitment,
                        next_row: &next_d_row,
                    },
                    &proofs[0],
                )?;

                Ok(())
            }
            OpType::Reduce => {
                // Reduce (delete_keys) generates exactly 1 proof.
                if proofs.len() != 1 {
                    return Err(KeyManagerError);
                }

                let verify_inputs = collect_reduce_verify_inputs(pre_state, pending_writes).await?;

                P::default()
                    .verify_delete_keys_runtime(verify_inputs.as_verify_input(), &proofs[0])?;

                Ok(())
            }
            _ => {
                // Other op types don't have retention proof requirements yet.
                if !proofs.is_empty() {
                    return Err(KeyManagerError);
                }
                Ok(())
            }
        }
    }

    async fn canonical_group_key_commitment(
        reader: &dyn OperationReader,
    ) -> Result<KeyCommitment, KeyManagerError> {
        current_hgk_commitment(reader).await
    }
}

/// Derive a 32-byte AES-256 key from a SimpleLine2 D key via HKDF-SHA256.
pub(crate) fn d_key_hkdf(d_key: &KeyMaterial, d_seq: u64) -> Result<[u8; 32], KeyManagerError> {
    let info = format!("{D_KEY_HKDF_INFO_PREFIX}{d_seq}");
    let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(None, d_key.as_bytes());
    let mut okm = [0u8; 32];
    hkdf.expand(info.as_bytes(), &mut okm)
        .map_err(|_| KeyManagerError)?;
    Ok(okm)
}
