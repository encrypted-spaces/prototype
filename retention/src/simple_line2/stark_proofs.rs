//! STARK proof adapter for SimpleLine2 operations.
//!
//! Implements `SimpleLine2Proofs<DefaultDerivation>` using the
//! `KeyTreeTransition` proof system (STARK over KoalaBear/Poseidon2).
//!
//! Transition shapes are defined purely from the public data carried by the
//! proof input structs; there is no storage access from inside this module.
//! Both the prover and verifier sides must be invoked with matching public
//! inputs.

use std::collections::HashMap;

use encrypted_spaces_crypto::EncryptedKeyMaterial;
use encrypted_spaces_crypto::{KeyCommitment, KeyMaterial};
use encrypted_spaces_key_manager::error::KeyManagerError;
use encrypted_spaces_zkp::transitions::{
    prove_transition, verify_transition, CanonicalPath, KeyTreeTransition,
};

use super::proof::{
    DefaultDerivation, DeleteKeysProofInput, DeleteKeysSurvivor, DeleteKeysVerifyInput,
    ExtendProofInput, ExtendVerifyInput, RekeyProofInput, RekeyVerifyInput, SimpleLine2Proofs,
};
use super::space_key::{tag, D_DERIVE_TAG, D_HEAD_ENCRYPT_TAG, GB_CHAIN_LINK_TAG, HGK_DERIVE_TAG};

// ---------------------------------------------------------------------------
// Transition builders (public data only — shared between prover and verifier)
// ---------------------------------------------------------------------------

fn build_extend_transition(
    current_d_commitment: KeyCommitment,
    next_d_commitment: KeyCommitment,
) -> KeyTreeTransition {
    let root = CanonicalPath::new("/sl2-extend");
    let current_d_id = root.child("current_d");
    let next_d_id = root.child("next_d");

    let mut t = KeyTreeTransition::new();
    t.commit(current_d_id.clone(), current_d_commitment);
    t.derive(current_d_id, next_d_id.clone(), tag(D_DERIVE_TAG));
    t.commit(next_d_id, next_d_commitment);
    t
}

fn build_rekey_transition(
    old_hgk_commitment: KeyCommitment,
    new_hgk_commitment: KeyCommitment,
    chain_link_ct: EncryptedKeyMaterial,
    new_d_commitment: KeyCommitment,
    d_head_ct: EncryptedKeyMaterial,
) -> KeyTreeTransition {
    let root = CanonicalPath::new("/sl2-rekey");
    let old_hgk_id = root.child("old_hgk");
    let new_hgk_id = root.child("new_hgk");
    let new_d_id = root.child("new_d");

    let mut t = KeyTreeTransition::new();
    t.commit(old_hgk_id.clone(), old_hgk_commitment);
    t.commit(new_hgk_id.clone(), new_hgk_commitment);
    t.encrypt(
        old_hgk_id,
        new_hgk_id.clone(),
        tag(GB_CHAIN_LINK_TAG),
        chain_link_ct,
    );
    t.commit(new_d_id.clone(), new_d_commitment);
    t.encrypt(new_d_id, new_hgk_id, tag(D_HEAD_ENCRYPT_TAG), d_head_ct);
    t
}

fn build_delete_transition(
    old_hgk_commitment: KeyCommitment,
    new_hgk_commitment: KeyCommitment,
    d_head_commitments: &[KeyCommitment],
    d_head_seqs: &[u64],
    chain_link_cts: &[EncryptedKeyMaterial],
    d_head_cts: &[EncryptedKeyMaterial],
) -> Result<KeyTreeTransition, KeyManagerError> {
    let n = d_head_commitments.len();
    if n == 0 || d_head_seqs.len() != n || d_head_cts.len() != n || chain_link_cts.len() + 1 != n {
        return Err(KeyManagerError);
    }

    let root = CanonicalPath::new("/sl2-delete");
    let old_hgk_id = root.child("old_hgk");
    let new_hgk_id = root.child("new_hgk");

    let mut t = KeyTreeTransition::new();

    // HGK: commit old, derive new, commit new
    t.commit(old_hgk_id.clone(), old_hgk_commitment);
    t.derive(old_hgk_id, new_hgk_id.clone(), tag(HGK_DERIVE_TAG));
    t.commit(new_hgk_id.clone(), new_hgk_commitment);

    // D head commits
    let d_ids: Vec<CanonicalPath> = d_head_seqs
        .iter()
        .map(|seq| root.child(format!("d{}", seq)))
        .collect();
    for i in 0..n {
        t.commit(d_ids[i].clone(), d_head_commitments[i]);
    }

    // GB chain key IDs: [new_hgk, b0, b1, ...]
    let mut gb_key_ids = Vec::with_capacity(n);
    gb_key_ids.push(new_hgk_id);
    for i in 0..n - 1 {
        gb_key_ids.push(root.child(format!("b{}", i)));
    }

    // Chain link encrypts: gb_keys[i] encrypts gb_keys[i+1]
    for i in 0..n - 1 {
        t.encrypt(
            gb_key_ids[i + 1].clone(),
            gb_key_ids[i].clone(),
            tag(GB_CHAIN_LINK_TAG),
            chain_link_cts[i].clone(),
        );
    }

    // D head re-encrypts: gb_keys[i] encrypts d_head[i]
    for i in 0..n {
        t.encrypt(
            d_ids[i].clone(),
            gb_key_ids[i].clone(),
            tag(D_HEAD_ENCRYPT_TAG),
            d_head_cts[i].clone(),
        );
    }

    Ok(t)
}

// ---------------------------------------------------------------------------
// Witness builders (private key material — prover only)
// ---------------------------------------------------------------------------

fn build_extend_witness(
    current_d_key: &KeyMaterial,
    next_d_key: &KeyMaterial,
) -> HashMap<CanonicalPath, KeyMaterial> {
    let root = CanonicalPath::new("/sl2-extend");
    let mut keys = HashMap::new();
    keys.insert(root.child("current_d"), current_d_key.clone());
    keys.insert(root.child("next_d"), next_d_key.clone());
    keys
}

fn build_rekey_witness(
    old_hgk: &KeyMaterial,
    new_hgk: &KeyMaterial,
    new_d_head: &KeyMaterial,
) -> HashMap<CanonicalPath, KeyMaterial> {
    let root = CanonicalPath::new("/sl2-rekey");
    let mut keys = HashMap::new();
    keys.insert(root.child("old_hgk"), old_hgk.clone());
    keys.insert(root.child("new_hgk"), new_hgk.clone());
    keys.insert(root.child("new_d"), new_d_head.clone());
    keys
}

fn build_delete_witness(
    old_hgk: &KeyMaterial,
    dgk: &KeyMaterial,
    b_keys: &[KeyMaterial],
    d_head_keys: &[KeyMaterial],
    d_head_seqs: &[u64],
) -> HashMap<CanonicalPath, KeyMaterial> {
    let root = CanonicalPath::new("/sl2-delete");
    let mut keys = HashMap::new();
    keys.insert(root.child("old_hgk"), old_hgk.clone());
    keys.insert(root.child("new_hgk"), dgk.clone());
    for (i, b_key) in b_keys.iter().enumerate() {
        keys.insert(root.child(format!("b{}", i)), b_key.clone());
    }
    for (i, d_key) in d_head_keys.iter().enumerate() {
        keys.insert(root.child(format!("d{}", d_head_seqs[i])), d_key.clone());
    }
    keys
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract delete-keys public inputs and build the transition.
///
/// Returns the transition and the D-head sequence numbers (needed by the
/// witness builder on the prove side).
fn delete_transition_from_inputs(
    old_hgk_commitment: KeyCommitment,
    dgk_commitment: KeyCommitment,
    survivors: &[DeleteKeysSurvivor],
    next_links: &[super::store::GBCiphertextPair],
) -> Result<(KeyTreeTransition, Vec<u64>), KeyManagerError> {
    let n = survivors.len();
    if n == 0 || next_links.len() != n {
        return Err(KeyManagerError);
    }

    // The oldest chain node has no older sibling, so the tail link's
    // `older_gb_key_ciphertext` must be `None`. Bind it here so a malformed
    // `Some(_)` cannot slip through the proof's public-input check.
    if next_links[n - 1].older_gb_key_ciphertext.is_some() {
        return Err(KeyManagerError);
    }

    let d_head_commitments: Vec<KeyCommitment> =
        survivors.iter().map(|s| s.d_head_commitment).collect();
    let d_head_seqs: Vec<u64> = survivors.iter().map(|s| s.d_head_seq).collect();

    let mut chain_link_cts = Vec::with_capacity(n.saturating_sub(1));
    for link in next_links.iter().take(n.saturating_sub(1)) {
        chain_link_cts.push(
            link.older_gb_key_ciphertext
                .as_ref()
                .ok_or(KeyManagerError)?
                .clone(),
        );
    }

    let d_head_cts: Vec<EncryptedKeyMaterial> = next_links
        .iter()
        .map(|link| link.d_head_ciphertext.clone())
        .collect();

    let transition = build_delete_transition(
        old_hgk_commitment,
        dgk_commitment,
        &d_head_commitments,
        &d_head_seqs,
        &chain_link_cts,
        &d_head_cts,
    )?;
    Ok((transition, d_head_seqs))
}

// ---------------------------------------------------------------------------
// StarkProver implementation
// ---------------------------------------------------------------------------

/// STARK proof adapter for SimpleLine2 operations.
///
/// Generates and verifies real STARK proofs over KoalaBear/Poseidon2 for
/// Extend, Rekey, and DeleteKeys operations.
#[derive(Clone, Copy, Debug, Default)]
pub struct StarkProver;

impl SimpleLine2Proofs<DefaultDerivation> for StarkProver {
    type ExtendProof = Vec<u8>;
    type RekeyProof = Vec<u8>;
    type DeleteKeysProof = Vec<u8>;
    type Error = KeyManagerError;

    fn prove_extend(
        &self,
        input: ExtendProofInput<'_, DefaultDerivation>,
    ) -> Result<Self::ExtendProof, Self::Error> {
        let transition =
            build_extend_transition(input.current_d_commitment, input.next_row.commitment);
        let keys = build_extend_witness(input.current_d_key, input.next_d_key);
        Ok(prove_transition(input.derivation, &transition, &keys))
    }

    fn verify_extend(&self, input: ExtendVerifyInput<'_>, proof: &[u8]) -> Result<(), Self::Error> {
        let transition =
            build_extend_transition(input.current_d_commitment, input.next_row.commitment);
        verify_transition(&transition, proof).map_err(|_| KeyManagerError)
    }

    fn prove_rekey(
        &self,
        input: RekeyProofInput<'_, DefaultDerivation>,
    ) -> Result<Self::RekeyProof, Self::Error> {
        let chain_ct = input
            .next_head_links
            .older_gb_key_ciphertext
            .as_ref()
            .ok_or(KeyManagerError)?
            .clone();

        let transition = build_rekey_transition(
            input.old_hgk_commitment,
            input.next_fgk_row.commitment,
            chain_ct,
            input.next_row.commitment,
            input.next_head_links.d_head_ciphertext.clone(),
        );
        let keys = build_rekey_witness(input.old_hgk, input.new_hgk, input.new_d_head);
        Ok(prove_transition(input.derivation, &transition, &keys))
    }

    fn verify_rekey(&self, input: RekeyVerifyInput<'_>, proof: &[u8]) -> Result<(), Self::Error> {
        let chain_ct = input
            .next_head_links
            .older_gb_key_ciphertext
            .as_ref()
            .ok_or(KeyManagerError)?
            .clone();

        let transition = build_rekey_transition(
            input.old_hgk_commitment,
            input.next_fgk_row.commitment,
            chain_ct,
            input.next_row.commitment,
            input.next_head_links.d_head_ciphertext.clone(),
        );
        verify_transition(&transition, proof).map_err(|_| KeyManagerError)
    }

    fn prove_delete_keys(
        &self,
        input: DeleteKeysProofInput<'_, DefaultDerivation>,
    ) -> Result<Self::DeleteKeysProof, Self::Error> {
        let (transition, d_head_seqs) = delete_transition_from_inputs(
            input.old_hgk_commitment,
            input.dgk_commitment,
            input.survivors,
            input.next_links,
        )?;
        let keys = build_delete_witness(
            input.old_hgk,
            input.new_hgk,
            input.b_keys,
            input.d_head_keys,
            &d_head_seqs,
        );
        Ok(prove_transition(input.derivation, &transition, &keys))
    }

    fn verify_delete_keys(
        &self,
        input: DeleteKeysVerifyInput<'_>,
        proof: &[u8],
    ) -> Result<(), Self::Error> {
        let (transition, _) = delete_transition_from_inputs(
            input.old_hgk_commitment,
            input.dgk_commitment,
            input.survivors,
            input.next_links,
        )?;
        verify_transition(&transition, proof).map_err(|_| KeyManagerError)
    }
}

impl super::proof::SimpleLine2RuntimeProver for StarkProver {
    fn prove_extend_runtime(
        &self,
        input: ExtendProofInput<'_, DefaultDerivation>,
    ) -> Result<Vec<u8>, KeyManagerError> {
        <Self as SimpleLine2Proofs<DefaultDerivation>>::prove_extend(self, input)
    }

    fn prove_rekey_runtime(
        &self,
        input: RekeyProofInput<'_, DefaultDerivation>,
    ) -> Result<Vec<u8>, KeyManagerError> {
        <Self as SimpleLine2Proofs<DefaultDerivation>>::prove_rekey(self, input)
    }

    fn prove_delete_keys_runtime(
        &self,
        input: DeleteKeysProofInput<'_, DefaultDerivation>,
    ) -> Result<Vec<u8>, KeyManagerError> {
        <Self as SimpleLine2Proofs<DefaultDerivation>>::prove_delete_keys(self, input)
    }

    fn verify_extend_runtime(
        &self,
        input: ExtendVerifyInput<'_>,
        proof: &[u8],
    ) -> Result<(), KeyManagerError> {
        <Self as SimpleLine2Proofs<DefaultDerivation>>::verify_extend(self, input, proof)
    }

    fn verify_rekey_runtime(
        &self,
        input: RekeyVerifyInput<'_>,
        proof: &[u8],
    ) -> Result<(), KeyManagerError> {
        <Self as SimpleLine2Proofs<DefaultDerivation>>::verify_rekey(self, input, proof)
    }

    fn verify_delete_keys_runtime(
        &self,
        input: DeleteKeysVerifyInput<'_>,
        proof: &[u8],
    ) -> Result<(), KeyManagerError> {
        <Self as SimpleLine2Proofs<DefaultDerivation>>::verify_delete_keys(self, input, proof)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use encrypted_spaces_crypto::KeyDerivation;

    fn derivation() -> DefaultDerivation {
        DefaultDerivation::default()
    }

    fn make_enc(
        d: &DefaultDerivation,
        parent: &KeyMaterial,
        child: &KeyMaterial,
        tag_bytes: &[u8],
    ) -> EncryptedKeyMaterial {
        let enc_key = d.derive(parent, tag(tag_bytes));
        EncryptedKeyMaterial::encrypt(enc_key, child)
    }

    // --- Malformed transition inputs (cheap; run in default lane) ---

    #[test]
    fn delete_mismatched_gb_node_count_returns_err() {
        let d = derivation();
        let dummy_ct = EncryptedKeyMaterial::encrypt(KeyMaterial::random(), &KeyMaterial::random());

        // 2 commitments but 0 chain links (should be 1)
        let result = build_delete_transition(
            d.commit(&KeyMaterial::random()),
            d.commit(&KeyMaterial::random()),
            &[
                d.commit(&KeyMaterial::random()),
                d.commit(&KeyMaterial::random()),
            ],
            &[0, 1],
            &[], // wrong: should have 1 entry
            &[dummy_ct.clone(), dummy_ct],
        );
        assert!(result.is_err());
    }

    #[test]
    fn delete_zero_gb_nodes_returns_err() {
        let d = derivation();
        let result = build_delete_transition(
            d.commit(&KeyMaterial::random()),
            d.commit(&KeyMaterial::random()),
            &[],
            &[],
            &[],
            &[],
        );
        assert!(result.is_err());
    }

    #[test]
    fn delete_transition_rejects_tail_older_gb_ciphertext() {
        use super::super::store::GBCiphertextPair;

        let d = derivation();
        let old_hgk = KeyMaterial::random();
        let dgk = d.derive(&old_hgk, tag(HGK_DERIVE_TAG));
        let d_head = KeyMaterial::random();
        let d_head_ct = make_enc(&d, &dgk, &d_head, D_HEAD_ENCRYPT_TAG);
        let stray_ct = make_enc(&d, &dgk, &KeyMaterial::random(), GB_CHAIN_LINK_TAG);

        let survivors = [DeleteKeysSurvivor {
            d_head_seq: 3,
            d_head_commitment: d.commit(&d_head),
        }];
        // Malformed: single-node chain must have None on the tail link.
        let next_links = [GBCiphertextPair {
            older_gb_key_ciphertext: Some(stray_ct),
            d_head_ciphertext: d_head_ct,
        }];

        let result = delete_transition_from_inputs(
            d.commit(&old_hgk),
            d.commit(&dgk),
            &survivors,
            &next_links,
        );
        assert!(result.is_err());
    }

    // --- Positive round-trips (slow; gated behind --ignored) ---

    #[test]
    #[ignore = "slow STARK proof coverage; run with cargo test -- --ignored"]
    fn extend_proof_round_trip() {
        let d = derivation();
        let current_d = KeyMaterial::random();
        let next_d = d.derive(&current_d, tag(D_DERIVE_TAG));

        let transition = build_extend_transition(d.commit(&current_d), d.commit(&next_d));
        assert_eq!(transition.len(), 3);

        let keys = build_extend_witness(&current_d, &next_d);
        let proof = prove_transition(&d, &transition, &keys);
        assert!(verify_transition(&transition, &proof).is_ok());
    }

    #[test]
    #[ignore = "slow STARK proof coverage; run with cargo test -- --ignored"]
    fn rekey_proof_round_trip() {
        let d = derivation();
        let old_hgk = KeyMaterial::random();
        let new_hgk = KeyMaterial::random();
        let new_d_head = KeyMaterial::random();

        let chain_ct = make_enc(&d, &new_hgk, &old_hgk, GB_CHAIN_LINK_TAG);
        let d_head_ct = make_enc(&d, &new_hgk, &new_d_head, D_HEAD_ENCRYPT_TAG);

        let transition = build_rekey_transition(
            d.commit(&old_hgk),
            d.commit(&new_hgk),
            chain_ct,
            d.commit(&new_d_head),
            d_head_ct,
        );
        assert_eq!(transition.len(), 5);

        let keys = build_rekey_witness(&old_hgk, &new_hgk, &new_d_head);
        let proof = prove_transition(&d, &transition, &keys);
        assert!(verify_transition(&transition, &proof).is_ok());
    }

    #[test]
    #[ignore = "slow STARK proof coverage; run with cargo test -- --ignored"]
    fn delete_single_gb_node_proof_round_trip() {
        let d = derivation();
        let old_hgk = KeyMaterial::random();
        let dgk = d.derive(&old_hgk, tag(HGK_DERIVE_TAG));
        let d_head = KeyMaterial::random();

        let d_head_ct = make_enc(&d, &dgk, &d_head, D_HEAD_ENCRYPT_TAG);

        let transition = build_delete_transition(
            d.commit(&old_hgk),
            d.commit(&dgk),
            &[d.commit(&d_head)],
            &[3],
            &[],
            &[d_head_ct],
        )
        .expect("build transition");
        assert_eq!(transition.len(), 5);

        let keys = build_delete_witness(&old_hgk, &dgk, &[], &[d_head], &[3]);
        let proof = prove_transition(&d, &transition, &keys);
        assert!(verify_transition(&transition, &proof).is_ok());
    }

    #[test]
    #[ignore = "slow STARK proof coverage; run with cargo test -- --ignored"]
    fn delete_two_gb_nodes_proof_round_trip() {
        let d = derivation();
        let old_hgk = KeyMaterial::random();
        let dgk = d.derive(&old_hgk, tag(HGK_DERIVE_TAG));
        let b0 = KeyMaterial::random();
        let d_head_0 = KeyMaterial::random();
        let d_head_1 = KeyMaterial::random();

        let chain_ct = make_enc(&d, &dgk, &b0, GB_CHAIN_LINK_TAG);
        let d_head_ct_0 = make_enc(&d, &dgk, &d_head_0, D_HEAD_ENCRYPT_TAG);
        let d_head_ct_1 = make_enc(&d, &b0, &d_head_1, D_HEAD_ENCRYPT_TAG);

        let transition = build_delete_transition(
            d.commit(&old_hgk),
            d.commit(&dgk),
            &[d.commit(&d_head_0), d.commit(&d_head_1)],
            &[5, 2],
            &[chain_ct],
            &[d_head_ct_0, d_head_ct_1],
        )
        .expect("build transition");
        assert_eq!(transition.len(), 8);

        let keys = build_delete_witness(&old_hgk, &dgk, &[b0], &[d_head_0, d_head_1], &[5, 2]);
        let proof = prove_transition(&d, &transition, &keys);
        assert!(verify_transition(&transition, &proof).is_ok());
    }

    // --- Prover adapter round-trips via the trait ---

    #[test]
    #[ignore = "slow STARK proof coverage; run with cargo test -- --ignored"]
    fn stark_prover_extend_round_trip() {
        use super::super::store::DTableRow;

        let d = derivation();
        let current_d = KeyMaterial::random();
        let next_d = d.derive(&current_d, tag(D_DERIVE_TAG));
        let next_row = DTableRow {
            seq: 1,
            commitment: d.commit(&next_d),
        };

        let prover = StarkProver;
        let proof = prover
            .prove_extend(ExtendProofInput {
                current_d_commitment: d.commit(&current_d),
                next_row: &next_row,
                derivation: &d,
                current_d_key: &current_d,
                next_d_key: &next_d,
            })
            .expect("prove");

        prover
            .verify_extend(
                ExtendVerifyInput {
                    current_d_commitment: d.commit(&current_d),
                    next_row: &next_row,
                },
                &proof,
            )
            .expect("verify");
    }

    #[test]
    #[ignore = "slow STARK proof coverage; run with cargo test -- --ignored"]
    fn stark_prover_rekey_round_trip() {
        use super::super::store::{DTableRow, FGKRow, GBCiphertextPair};

        let d = derivation();
        let old_hgk = KeyMaterial::random();
        let new_hgk = KeyMaterial::random();
        let new_d_head = KeyMaterial::random();

        let chain_ct = make_enc(&d, &new_hgk, &old_hgk, GB_CHAIN_LINK_TAG);
        let d_head_ct = make_enc(&d, &new_hgk, &new_d_head, D_HEAD_ENCRYPT_TAG);

        let next_fgk_row = FGKRow {
            d_start: 1,
            commitment: d.commit(&new_hgk),
        };
        let next_row = DTableRow {
            seq: 1,
            commitment: d.commit(&new_d_head),
        };
        let links = GBCiphertextPair {
            older_gb_key_ciphertext: Some(chain_ct),
            d_head_ciphertext: d_head_ct,
        };

        let prover = StarkProver;
        let proof = prover
            .prove_rekey(RekeyProofInput {
                old_hgk_commitment: d.commit(&old_hgk),
                next_fgk_row: &next_fgk_row,
                next_row: &next_row,
                next_head_links: &links,
                derivation: &d,
                old_hgk: &old_hgk,
                new_hgk: &new_hgk,
                new_d_head: &new_d_head,
            })
            .expect("prove");

        prover
            .verify_rekey(
                RekeyVerifyInput {
                    old_hgk_commitment: d.commit(&old_hgk),
                    next_fgk_row: &next_fgk_row,
                    next_row: &next_row,
                    next_head_links: &links,
                },
                &proof,
            )
            .expect("verify");
    }

    #[test]
    #[ignore = "slow STARK proof coverage; run with cargo test -- --ignored"]
    fn stark_prover_delete_keys_round_trip_two_nodes() {
        use super::super::store::GBCiphertextPair;

        let d = derivation();
        let old_hgk = KeyMaterial::random();
        let dgk = d.derive(&old_hgk, tag(HGK_DERIVE_TAG));
        let b0 = KeyMaterial::random();
        let d_head_0 = KeyMaterial::random();
        let d_head_1 = KeyMaterial::random();

        let chain_ct = make_enc(&d, &dgk, &b0, GB_CHAIN_LINK_TAG);
        let d_head_ct_0 = make_enc(&d, &dgk, &d_head_0, D_HEAD_ENCRYPT_TAG);
        let d_head_ct_1 = make_enc(&d, &b0, &d_head_1, D_HEAD_ENCRYPT_TAG);

        let survivors = [
            DeleteKeysSurvivor {
                d_head_seq: 5,
                d_head_commitment: d.commit(&d_head_0),
            },
            DeleteKeysSurvivor {
                d_head_seq: 2,
                d_head_commitment: d.commit(&d_head_1),
            },
        ];
        let next_links = [
            GBCiphertextPair {
                older_gb_key_ciphertext: Some(chain_ct),
                d_head_ciphertext: d_head_ct_0,
            },
            GBCiphertextPair {
                older_gb_key_ciphertext: None,
                d_head_ciphertext: d_head_ct_1,
            },
        ];

        let prover = StarkProver;
        let proof = prover
            .prove_delete_keys(DeleteKeysProofInput {
                old_hgk_commitment: d.commit(&old_hgk),
                dgk_commitment: d.commit(&dgk),
                survivors: &survivors,
                next_links: &next_links,
                derivation: &d,
                old_hgk: &old_hgk,
                new_hgk: &dgk,
                b_keys: &[b0],
                d_head_keys: &[d_head_0, d_head_1],
            })
            .expect("prove");

        prover
            .verify_delete_keys(
                DeleteKeysVerifyInput {
                    old_hgk_commitment: d.commit(&old_hgk),
                    dgk_commitment: d.commit(&dgk),
                    survivors: &survivors,
                    next_links: &next_links,
                },
                &proof,
            )
            .expect("verify");
    }

    // --- Byte corruption rejection ---

    #[test]
    #[ignore = "slow STARK proof coverage; run with cargo test -- --ignored"]
    fn extend_proof_byte_corruption_rejected() {
        let d = derivation();
        let current_d = KeyMaterial::random();
        let next_d = d.derive(&current_d, tag(D_DERIVE_TAG));

        let transition = build_extend_transition(d.commit(&current_d), d.commit(&next_d));
        let keys = build_extend_witness(&current_d, &next_d);
        let proof = prove_transition(&d, &transition, &keys);

        let mut bad_proof = proof.clone();
        if bad_proof.len() > 10 {
            bad_proof[10] ^= 0xff;
        }
        assert!(verify_transition(&transition, &bad_proof).is_err());
    }

    #[test]
    #[ignore = "slow STARK proof coverage; run with cargo test -- --ignored"]
    fn extend_same_shape_commitment_mutation_rejected() {
        let d = derivation();
        let current_d = KeyMaterial::random();
        let next_d = d.derive(&current_d, tag(D_DERIVE_TAG));

        let transition = build_extend_transition(d.commit(&current_d), d.commit(&next_d));
        let keys = build_extend_witness(&current_d, &next_d);
        let proof = prove_transition(&d, &transition, &keys);

        let wrong_transition =
            build_extend_transition(d.commit(&current_d), d.commit(&KeyMaterial::random()));
        assert!(verify_transition(&wrong_transition, &proof).is_err());
    }
}
