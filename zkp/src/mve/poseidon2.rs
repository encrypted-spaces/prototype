use alloc::{vec, vec::Vec};
use core::{borrow::Borrow, marker::PhantomData, ptr};
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use spongefish::{Encoding, VerificationError, VerificationResult};
use std::borrow::BorrowMut;

use crate::{
    hash_preimage::KoalaBearPoseidon2_16PreimageAir,
    mve::{
        expand_challenge, MkemCiphertextGroup, Mve, MveCiphertext, MveError,
        MveRecipientCiphertext, MVE_DEFAULT_K, MVE_DEFAULT_U,
    },
    poseidon2::KoalaBearPoseidon2_16Cols,
};
use encrypted_spaces_crypto::{
    algebraic_encoding::{
        AlgebraicKeyCommitment, AlgebraicKeyMaterial, KEYCOMMITMENT_LIMBS, KEYMATERIAL_LIMBS,
    },
    DerivationKoalaBearPoseidon2_16, KeyCommitment, KeyDerivation, KeyMaterial, Mkem, P2_16_CONFIG,
};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::{dense::DenseMatrix, Matrix};
use p3_maybe_rayon::prelude::*;
use p3_uni_stark::{
    prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed, StarkGenericConfig,
};
use spongefish_stark::{
    ff::{KoalaBearConfig, KoalaBearStarkConfig},
    security_profile::Conservative,
};

const BLOCK_LEN: usize = P2_16_CONFIG.width;
#[cfg(test)]
const RATE_LEN: usize = P2_16_CONFIG.rate;
#[cfg(test)]
use encrypted_spaces_crypto::pke::DefaultMkem;
type HashBlock = [KoalaBear; P2_16_CONFIG.width];
type HashBlockMask = [Option<KoalaBear>; P2_16_CONFIG.width];

/// Public instance for the mVE proof.
///
/// This module proves that all mKEM encaps are made for the public keys `pks` and all encapsulate the same secret
/// committed as `key_commitment`.
/// The instance is encoded as: `pk_len || pks || key_commitment`, and defined the proof statement.
struct MveInstance<'a, M: Mkem, const K: usize, const U: usize> {
    pks: &'a [M::PublicKey],
    key_commitment: KeyCommitment,
}

/// The protocol transcript for the mVE proof.
///
/// This is the payload that the server keeps
#[derive(Clone, Serialize, Deserialize)]
pub struct PoseidonMveProof<M: Mkem> {
    /// Ciphertexts corresponding to the repetitions that remain hidden.
    pub ciphertexts: Vec<MkemCiphertextGroup<M::Ciphertext>>,
    /// Seeds revealing the repetitions that are opened (in challenge order).
    pub opened: Vec<[u8; 32]>,
    /// Commitments for the repetitions that remain hidden (in challenge order).
    pub kept_commitments: Vec<KeyCommitment>,

    /// Fiat-Shamir challenge derived during proving.
    pub challenge: [u8; 32],
    /// Pad values used by the STARK proof.
    ///
    /// The first `KEYMATERIAL_LIMBS` limbs encode prover response.
    pub pads: Vec<HashBlock>,

    /// Serialized STARK proof for the mVE relation.
    /// This is the reduced proof compiled using p3.
    pub proof: Vec<u8>,
}

/// The structure represeting a mVE proof using poseidon.
pub struct PoseidonMve<M: Mkem, const K: usize = MVE_DEFAULT_K, const U: usize = MVE_DEFAULT_U>(
    PhantomData<M>,
);

impl<'a, M: Mkem, const K: usize, const U: usize> Encoding for MveInstance<'a, M, K, U> {
    fn encode(&self) -> impl AsRef<[u8]> {
        let pks_len = self.pks.len().to_le_bytes();
        let pks_bytes = postcard::to_allocvec(self.pks).expect("pk serialization error");
        [
            pks_len.as_slice(),
            pks_bytes.as_slice(),
            self.key_commitment.as_bytes(),
        ]
        .concat()
        .to_vec()
    }
}
impl<'a, M: Mkem, const K: usize, const U: usize> MveInstance<'a, M, K, U> {
    fn new(pks: &'a [M::PublicKey], key_commitment: KeyCommitment) -> Self {
        MveInstance {
            pks,
            key_commitment,
        }
    }
}

fn commitment_to_mask(commitment: &KeyCommitment) -> HashBlockMask {
    let mut masked_state = [None; BLOCK_LEN];
    let limbs = AlgebraicKeyCommitment::from(commitment);
    let limbs: &[KoalaBear; KEYCOMMITMENT_LIMBS] = limbs.as_ref();
    for (dst, limb) in masked_state.iter_mut().zip(limbs.iter()) {
        *dst = Some(*limb);
    }
    masked_state
}

fn expected_blocks_from_commitments(
    key_commitment: &KeyCommitment,
    kept_commitments: &[KeyCommitment],
) -> Vec<HashBlockMask> {
    let real_count = 1 + kept_commitments.len();
    let padded_count = real_count.next_power_of_two();
    // println!("expected_blocks_from_commitments, padding size is {padded_count} (real_count = {real_count})");
    let mut expected_blocks = Vec::with_capacity(padded_count);
    expected_blocks.push(commitment_to_mask(key_commitment));
    expected_blocks.extend(kept_commitments.iter().map(commitment_to_mask));
    let last = *expected_blocks.last().expect("at least key commitment");
    expected_blocks.resize(padded_count, last);
    expected_blocks
}

fn responses_from_pads(
    pads: &[HashBlock],
    num_responses: usize,
) -> Result<Vec<KeyMaterial>, MveError> {
    let expected_len = (num_responses + 1).next_power_of_two() - 1;
    if pads.len() != expected_len {
        return Err(MveError::VerificationInputError);
    }
    Ok(pads[..num_responses]
        .iter()
        .map(|state| KeyMaterial::from_slice(&state[..KEYMATERIAL_LIMBS]))
        .collect::<Vec<_>>())
}

impl<M: Mkem, const K: usize, const U: usize> PoseidonMve<M, K, U> {
    #[tracing::instrument(name = "mVE prove", skip_all)]
    pub fn prove(
        pks: &[M::PublicKey],
        key_commitment: &KeyCommitment,
        key: &KeyMaterial,
        session_identifier: &str,
    ) -> PoseidonMveProof<M> {
        let k = K;
        let u = U;
        let mkem = M::default();
        let derivation = DerivationKoalaBearPoseidon2_16::default();

        debug_assert_eq!(derivation.commit(key), *key_commitment);
        let instance = MveInstance::<M, K, U>::new(pks, *key_commitment);
        let mut prover_state =
            spongefish::domain_separator!("mVE shake128 {{M::NAME}} {{K}} {{U}}")
                .session(session_identifier)
                .instance(&instance)
                .std_prover();

        let mut rng = rand::rng();
        let seeds = (0..k).map(|_| rng.random()).collect::<Vec<_>>();

        let (ciphertexts, messages) = {
            use p3_maybe_rayon::prelude::*;

            let results = seeds
                .par_iter()
                .map(|seed| {
                    let mut rng = rand_chacha::ChaCha12Rng::from_seed(*seed);
                    let (ciphertext, message) = mkem.encaps(&mut rng, pks);
                    (
                        MkemCiphertextGroup {
                            payload: Vec::new(),
                            ciphertext,
                        },
                        message,
                    )
                })
                .collect::<Vec<_>>();
            results.into_iter().unzip::<_, _, Vec<_>, Vec<_>>()
        };
        let committed_messages = messages
            .iter()
            .map(|message| derivation.commit(message))
            .collect::<Vec<_>>();

        // the ctx will be provided outside of the narg string
        prover_state.public_message(
            postcard::to_allocvec(&ciphertexts)
                .expect("error serializing ciphertext")
                .as_slice(),
        );
        // the key commitments will be provided outside of the narg string
        prover_state.public_messages(&committed_messages);

        let challenge = prover_state.verifier_message::<[u8; 32]>();

        let open_indices = expand_challenge(k, u, &challenge);
        let keep_indices = (0..k)
            .filter(|i| !open_indices.contains(i))
            .collect::<Vec<usize>>();

        // Compute the responses
        let opened = open_indices.iter().map(|&i| seeds[i]).collect::<Vec<_>>();
        let kept_ciphertexts = keep_indices
            .iter()
            .map(|&i| ciphertexts[i].clone())
            .collect::<Vec<_>>();

        // build the hash preimage proof
        let keep_messages = keep_indices
            .iter()
            .map(|&i| messages[i].clone())
            .collect::<Vec<_>>();
        let witness = [key]
            .into_iter()
            .chain(keep_messages.iter())
            .cloned()
            .collect::<Vec<_>>();
        let mut hash_inputs = witness
            .iter()
            .map(|x| derivation.key_to_hash_state(x))
            .collect::<Vec<_>>();

        // the first hash input is the key
        debug_assert_eq!(
            KeyMaterial::from_slice(&hash_inputs[0][..KEYMATERIAL_LIMBS]),
            *key
        );
        let key_state = hash_inputs[0];
        let response_states = hash_inputs
            .iter()
            .skip(1)
            .map(|state| {
                let mut diff = HashBlock::default();
                for (dst, (val, key_val)) in diff.iter_mut().zip(state.iter().zip(key_state.iter()))
                {
                    *dst = *val - *key_val;
                }
                diff
            })
            .collect::<Vec<_>>();

        let responses = response_states
            .iter()
            .map(|state| KeyMaterial::from_slice(&state[..KEYMATERIAL_LIMBS]))
            .collect::<Vec<_>>();

        let mut pads = response_states;
        prover_state.prover_messages(&responses);

        // Pad to next power of two as required by plonky3's trace generation.
        let real_count = hash_inputs.len(); // 1 (key) + keep_count
        let padded_count = real_count.next_power_of_two();
        let last_pad = *pads.last().unwrap();
        let last_hash = *hash_inputs.last().unwrap();
        // To pad, use the last pad and hash values
        pads.resize(padded_count - 1, last_pad);
        hash_inputs.resize(padded_count, last_hash);

        let kept_commitments = keep_indices
            .iter()
            .map(|&idx| committed_messages[idx])
            .collect::<Vec<_>>();
        let expected_blocks = expected_blocks_from_commitments(key_commitment, &kept_commitments);
        let pad_blocks = pads.clone();
        let air = MveAirKoalaBearPoseidon2_16::new(&expected_blocks, &pad_blocks);

        let proof = air.prove(&hash_inputs);
        debug_assert!(
            MveAirKoalaBearPoseidon2_16::new(&expected_blocks, &pad_blocks)
                .verify(&proof)
                .is_ok()
        );

        PoseidonMveProof {
            ciphertexts: kept_ciphertexts,
            challenge,
            opened,
            kept_commitments,
            proof,
            pads: pad_blocks,
        }
    }

    #[tracing::instrument(name = "mVE verify", skip_all)]
    pub fn verify(
        proof: &PoseidonMveProof<M>,
        pks: &[M::PublicKey],
        key_commitment: &KeyCommitment,
        session_identifier: &str,
    ) -> Result<MveCiphertext<M>, MveError> {
        let k = K;
        let u = U;
        let open_indices = expand_challenge(k, u, &proof.challenge);
        if proof.opened.len() != open_indices.len() {
            return Err(MveError::VerificationInputError);
        }
        let keep_indices = (0..k)
            .filter(|i| !open_indices.contains(i))
            .collect::<Vec<usize>>();
        if proof.kept_commitments.len() != keep_indices.len()
            || proof.ciphertexts.len() != keep_indices.len()
        {
            return Err(MveError::VerificationInputError);
        }

        let mkem = M::default();
        let derivation = DerivationKoalaBearPoseidon2_16::default();
        let instance = MveInstance::<M, K, U>::new(pks, *key_commitment);
        let open_entries = open_indices
            .par_iter()
            .zip(proof.opened.par_iter())
            .map(|(&idx, &seed)| {
                let mut rng = rand_chacha::ChaCha12Rng::from_seed(seed);
                let (ciphertext, message) = mkem.encaps(&mut rng, pks);
                (
                    idx,
                    MkemCiphertextGroup {
                        payload: Vec::new(),
                        ciphertext,
                    },
                    message,
                )
            })
            .collect::<Vec<_>>();

        let mut entries = vec![None; k];
        for (idx, ct, message) in open_entries {
            if idx >= k {
                return Err(MveError::VerificationInputError);
            }
            entries[idx] = Some((ct, message));
        }

        let mut commitments = Vec::with_capacity(k);
        let mut ciphertexts = Vec::with_capacity(k);
        let mut keep_pos = 0usize;

        for mut entry in entries {
            if let Some((ct, message)) = entry.take() {
                commitments.push(derivation.commit(&message));
                ciphertexts.push(ct);
            } else {
                let ct = proof
                    .ciphertexts
                    .get(keep_pos)
                    .ok_or(MveError::VerificationInputError)?;
                ciphertexts.push(ct.clone());
                commitments.push(
                    *proof
                        .kept_commitments
                        .get(keep_pos)
                        .ok_or(MveError::VerificationInputError)?,
                );
                keep_pos += 1;
            }
        }

        if keep_pos != keep_indices.len() {
            return Err(MveError::VerificationInputError);
        }

        let responses = responses_from_pads(&proof.pads, keep_indices.len())?;

        let mut transcript_state =
            spongefish::domain_separator!("mVE shake128 {{M::NAME}} {{K}} {{U}}")
                .session(session_identifier)
                .instance(&instance)
                .std_prover();
        transcript_state.public_message(
            postcard::to_allocvec(&ciphertexts)
                .expect("error serializing ciphertext")
                .as_slice(),
        );
        transcript_state.public_messages(&commitments);
        let derived_challenge = transcript_state.verifier_message::<[u8; 32]>();
        if derived_challenge != proof.challenge {
            return Err(MveError::VerificationError);
        }
        transcript_state.prover_messages(&responses);
        let generated_responses = transcript_state.narg_string().to_vec();
        let mut verifier_state =
            spongefish::domain_separator!("mVE shake128 {{M::NAME}} {{K}} {{U}}")
                .session(session_identifier)
                .instance(&instance)
                .std_verifier(&generated_responses);
        verifier_state.public_message(
            postcard::to_allocvec(&ciphertexts)
                .expect("error serializing ciphertext")
                .as_slice(),
        );
        verifier_state.public_messages(&commitments);
        let _ = verifier_state.verifier_message::<[u8; 32]>();
        let checked_responses = verifier_state
            .prover_messages_vec::<KeyMaterial>(keep_indices.len())
            .map_err(|_| MveError::VerificationError)?;
        verifier_state
            .check_eof()
            .map_err(|_| MveError::VerificationError)?;

        let expected_blocks =
            expected_blocks_from_commitments(key_commitment, &proof.kept_commitments);
        let air = MveAirKoalaBearPoseidon2_16::new(&expected_blocks, &proof.pads);
        air.verify(&proof.proof)
            .map_err(|_| MveError::VerificationError)?;

        if checked_responses.len() != proof.ciphertexts.len() {
            return Err(MveError::VerificationInputError);
        }

        let ret = proof
            .ciphertexts
            .iter()
            .cloned()
            .zip(checked_responses)
            .map(|(ctexts, response)| (response, ctexts))
            .collect::<Vec<_>>();

        Ok(MveCiphertext(ret))
    }

    #[tracing::instrument(name = "mVE decrypt", skip_all)]
    pub fn decrypt(
        sk: &M::SecretKey,
        ciphertext: &MveRecipientCiphertext<M, KeyMaterial>,
        key_commitment: KeyCommitment,
    ) -> Result<KeyMaterial, MveError> {
        let mkem = M::default();
        let derivation = DerivationKoalaBearPoseidon2_16::default();

        for (response, ct) in ciphertext.0.iter() {
            let message = match mkem.decaps(sk, &ct.ciphertext) {
                Some(message) => message,
                None => continue,
            };
            let message = KeyMaterial::clamp(*message.as_bytes());
            let message_bb = AlgebraicKeyMaterial::from(&message);
            let response_bb = AlgebraicKeyMaterial::from(response);
            let diff = message_bb.0 - response_bb.0;
            let candidate = KeyMaterial::from(AlgebraicKeyMaterial(diff));

            if derivation.commit(&candidate) == key_commitment {
                return Ok(candidate);
            }
        }

        Err(MveError::DecryptionFailure)
    }
}

impl<M: Mkem, const K: usize, const U: usize> Mve for PoseidonMve<M, K, U> {
    type Mkem = M;
    type Instance = KeyCommitment;
    type Witness = KeyMaterial;
    type Proof = PoseidonMveProof<M>;
    type Ciphertext = MveCiphertext<M>;
    type RecipientCiphertext = MveRecipientCiphertext<M, KeyMaterial>;
    type Error = MveError;

    fn prove(
        pks: &[M::PublicKey],
        instance: &Self::Instance,
        witness: &Self::Witness,
        session_identifier: &str,
    ) -> Self::Proof {
        Self::prove(pks, instance, witness, session_identifier)
    }

    fn verify(
        pks: &[M::PublicKey],
        instance: &Self::Instance,
        proof: &Self::Proof,
        session_identifier: &str,
    ) -> Result<Self::Ciphertext, Self::Error> {
        Self::verify(proof, pks, instance, session_identifier)
    }

    fn compress(
        ct: &Self::Ciphertext,
        recipient_index: usize,
    ) -> Option<Self::RecipientCiphertext> {
        ct.get(recipient_index)
    }

    fn decrypt(
        sk: &M::SecretKey,
        ct_i: &Self::RecipientCiphertext,
        instance: &Self::Instance,
    ) -> Result<Self::Witness, Self::Error> {
        Self::decrypt(sk, ct_i, *instance)
    }
}

#[test]
fn test_poseidon_mve() {
    type P = DefaultMkem;

    let mkem = P::default();
    let mut rng = rand::rng();
    let (pk1, sk1) = mkem.keygen(&mut rng);
    let (pk2, sk2) = mkem.keygen(&mut rng);
    let pks = [pk1, pk2];
    let sks = [sk1, sk2];
    let key = KeyMaterial::random();
    let derivation = DerivationKoalaBearPoseidon2_16::default();
    let key_commitment = derivation.commit(&key);
    let proof = PoseidonMve::<P>::prove(&pks, &key_commitment, &key, "test");
    let ciphertexts = PoseidonMve::<P>::verify(&proof, &pks, &key_commitment, "test")
        .expect("verification should succeed");

    for (idx, sk) in sks.iter().enumerate() {
        let recipient_ciphertext = ciphertexts
            .get(idx)
            .expect("recipient index should be in bounds");
        let decrypted = PoseidonMve::<P>::decrypt(sk, &recipient_ciphertext, key_commitment)
            .expect("decryption should succeed");
        assert_eq!(decrypted.as_bytes(), key.as_bytes());
    }
}

/// AIR for the mVE proof relation:
///
/// $$
/// R(t_0, \dots, t_n) = \left{
///     (s_0, \dots, s_n)\colon\quad
///     \forall\,i \geq 0\colon
///         z_i = h(s_i),\;
///         t_i = s_i - s_0
/// \right}
/// $$
///
/// Here `s_0` is the committed key state, and `s_i` for `i > 0` are the hidden
/// encapsulated-message states kept after the cut-and-choose challenge.
///
/// The vector `sum` holds the values `t_i`, with `t_0 = 0`.
/// The vector `selector` selects the committed output limbs of the permutation output.
/// In [`MveAirKoalaBearPoseidon2_16::new`], `expected_blocks` holds the published
/// commitment limbs `z_i`, not the full permutation outputs.
pub struct MveAirKoalaBearPoseidon2_16 {
    air: KoalaBearPoseidon2_16PreimageAir,
    sum: Vec<KoalaBear>,
}

impl MveAirKoalaBearPoseidon2_16 {
    /// Create a new mVE proof.
    ///
    /// The vector `pads` contains the values $t_i$ desired.
    /// The vector `expected_blocks` contains the published commitment limbs $z_i$.
    ///
    /// Note: `pads` has length $n$ and will set internally $t_0 = 0$.
    /// `expected_blocks` has length $n+1$.
    pub fn new(expected_blocks: &[HashBlockMask], pads: &[HashBlock]) -> Self {
        assert_eq!(expected_blocks.len(), pads.len() + 1);
        let air = KoalaBearPoseidon2_16PreimageAir::new(expected_blocks);
        let first_pad = HashBlock::default();
        let pads = [first_pad]
            .iter()
            .chain(pads.iter())
            .flatten()
            .copied()
            .collect::<Vec<_>>();

        Self { air, sum: pads }
    }
}

impl BaseAir<KoalaBear> for MveAirKoalaBearPoseidon2_16 {
    fn width(&self) -> usize {
        self.air.width() + BLOCK_LEN
    }

    /// Creates a matrix of the form:
    ///
    /// ```text
    /// +----------+----------+------+
    /// | selector | expected | pads |
    /// +----------+----------+------+
    /// ```
    ///
    /// where `selector` selects non-`None` elements given in [`MveAirKoalaBearPoseidon2_16::new`].
    /// and `expected` contains the value for the non-`None` elements.
    fn preprocessed_trace(&self) -> Option<p3_matrix::dense::RowMajorMatrix<KoalaBear>> {
        let mut flat_preprocessed = Vec::new();
        for ((selector_chunk, expected_chunk), sum_chunk) in self
            .air
            .selector
            .chunks(BLOCK_LEN)
            .zip(self.air.expected.chunks(BLOCK_LEN))
            .zip(self.sum.chunks(BLOCK_LEN))
        {
            flat_preprocessed.extend_from_slice(selector_chunk);
            flat_preprocessed.extend_from_slice(expected_chunk);
            flat_preprocessed.extend_from_slice(sum_chunk);
        }
        Some(DenseMatrix::new(flat_preprocessed, BLOCK_LEN * 3))
    }
}

#[repr(C)]
pub struct MveKoalaBearPoseidon2_16Cols<T> {
    /// The hash computation trace
    permutation: KoalaBearPoseidon2_16Cols<T>,
    /// The pad trace
    pad: [T; BLOCK_LEN],
}

impl<T> Borrow<MveKoalaBearPoseidon2_16Cols<T>> for [T] {
    fn borrow(&self) -> &MveKoalaBearPoseidon2_16Cols<T> {
        let (prefix, shorts, suffix) =
            unsafe { self.align_to::<MveKoalaBearPoseidon2_16Cols<T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<MveKoalaBearPoseidon2_16Cols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut MveKoalaBearPoseidon2_16Cols<T> {
        let (prefix, shorts, suffix) =
            unsafe { self.align_to_mut::<MveKoalaBearPoseidon2_16Cols<T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}

impl<AB: AirBuilder<F = KoalaBear>> Air<AB> for MveAirKoalaBearPoseidon2_16 {
    fn eval(&self, builder: &mut AB) {
        // check that the preimage is correct
        self.air.eval(builder);

        // check that sum sum with pad is correct
        let main = builder.main();
        let local_columns: &MveKoalaBearPoseidon2_16Cols<_> = main.current_slice().borrow();
        let next_columns: &MveKoalaBearPoseidon2_16Cols<_> = main.next_slice().borrow();

        let preprocessed_columns = builder.preprocessed().current_slice().to_vec();
        let expected = &preprocessed_columns[2 * BLOCK_LEN..];
        let pad = &local_columns.pad;
        let hash_input = &local_columns.permutation.inputs;

        for i in 0..BLOCK_LEN {
            builder.assert_eq(hash_input[i] - pad[i], expected[i]);
            builder.assert_eq(local_columns.pad[i], next_columns.pad[i]);
        }
    }
}

impl MveAirKoalaBearPoseidon2_16 {
    pub fn generate_trace_rows(
        &self,
        inputs: &[HashBlock],
        extra_capacity_bits: usize,
    ) -> DenseMatrix<KoalaBear> {
        let preimage_matrix = self.air.generate_trace_rows(inputs, extra_capacity_bits);

        let s_0 = inputs[0];

        let num_cols = preimage_matrix.width() + BLOCK_LEN;
        let num_rows = preimage_matrix.height();

        let mut trace = DenseMatrix::new(vec![KoalaBear::ZERO; num_cols * num_rows], num_cols);
        for (i, hash_row) in preimage_matrix.row_slices().enumerate() {
            let row = trace.row_mut(i);
            let mve_columns: &mut MveKoalaBearPoseidon2_16Cols<KoalaBear> = (*row).borrow_mut();

            let hash_row: &KoalaBearPoseidon2_16Cols<KoalaBear> = (*hash_row).borrow();
            assert_eq!(hash_row.inputs[1] - s_0[1], self.sum[BLOCK_LEN * i + 1]);

            // Copy the precomputed hash row into the mVE row because the column struct
            // does not implement `Clone`.
            unsafe {
                ptr::copy_nonoverlapping(
                    hash_row as *const _,
                    &mut mve_columns.permutation as *mut _,
                    1,
                );
                ptr::copy_nonoverlapping(s_0.as_ptr(), mve_columns.pad.as_mut_ptr(), BLOCK_LEN);
            }
        }

        trace
    }

    pub fn prove(&self, inputs: &[HashBlock]) -> Vec<u8> {
        assert_eq!(
            inputs.len(),
            self.air.expected.len() / BLOCK_LEN,
            "The inputs should match the number of expected values"
        );
        let trace = self.generate_trace_rows(inputs, 2);
        let trace_height = trace.height();
        assert!(
            trace_height.is_power_of_two(),
            "Trace height must be a power of two"
        );
        let degree_bits = trace_height.trailing_zeros() as usize;

        let preprocessing_config = KoalaBearConfig::<Conservative>::verifier_config();
        let config = KoalaBearConfig::<Conservative>::prover_config();
        let preprocessed = setup_preprocessed(&preprocessing_config, self, degree_bits);
        let proof = prove_with_preprocessed(
            &config,
            self,
            trace,
            &[],
            preprocessed.as_ref().map(|(pp, _)| pp),
        );

        postcard::to_allocvec(&proof).unwrap()
    }

    pub fn verify(&self, narg_string: &[u8]) -> VerificationResult<()> {
        let config = KoalaBearConfig::<Conservative>::verifier_config();
        let proof: p3_uni_stark::Proof<KoalaBearStarkConfig> =
            postcard::from_bytes(narg_string).map_err(|_| VerificationError)?;
        let degree_bits = proof.degree_bits.saturating_sub(config.is_zk());
        let preprocessed = setup_preprocessed(&config, self, degree_bits);
        verify_with_preprocessed(
            &config,
            self,
            &proof,
            &[],
            preprocessed.as_ref().map(|(_, vk)| vk),
        )
        .map_err(|_| VerificationError)
    }
}

#[test]
fn test_koala_bear_preimage() {
    use spongefish::Permutation;
    use spongefish_stark::permutation::poseidon2::KoalaBearPoseidon2_16;

    fn prove_preimage(
        statement: &KoalaBearPoseidon2_16PreimageAir,
        inputs: &[HashBlock],
    ) -> Vec<u8> {
        let trace = statement.generate_trace_rows(inputs, 2);
        let trace_height = trace.height();
        assert!(
            trace_height.is_power_of_two(),
            "Trace height must be a power of two"
        );
        let degree_bits = trace_height.trailing_zeros() as usize;

        let preprocessing_config = KoalaBearConfig::<Conservative>::verifier_config();
        let config = KoalaBearConfig::<Conservative>::prover_config();
        let preprocessed = setup_preprocessed(&preprocessing_config, statement, degree_bits);
        let proof = prove_with_preprocessed(
            &config,
            statement,
            trace,
            &[],
            preprocessed.as_ref().map(|(pp, _)| pp),
        );

        postcard::to_allocvec(&proof).unwrap()
    }

    fn verify_preimage(
        statement: &KoalaBearPoseidon2_16PreimageAir,
        narg_string: &[u8],
    ) -> VerificationResult<()> {
        let config = KoalaBearConfig::<Conservative>::verifier_config();
        let proof: p3_uni_stark::Proof<KoalaBearStarkConfig> =
            postcard::from_bytes(narg_string).map_err(|_| VerificationError)?;
        let degree_bits = proof.degree_bits.saturating_sub(config.is_zk());
        let preprocessed = setup_preprocessed(&config, statement, degree_bits);
        verify_with_preprocessed(
            &config,
            statement,
            &proof,
            &[],
            preprocessed.as_ref().map(|(_, vk)| vk),
        )
        .map_err(|_| VerificationError)
    }

    let hasher = KoalaBearPoseidon2_16::default();
    let inputs = vec![
        [KoalaBear::new(1); BLOCK_LEN],
        [KoalaBear::new(2); BLOCK_LEN],
        [KoalaBear::new(3); BLOCK_LEN],
        [KoalaBear::new(4); BLOCK_LEN],
        [KoalaBear::new(5); BLOCK_LEN],
        [KoalaBear::new(6); BLOCK_LEN],
        [KoalaBear::new(7); BLOCK_LEN],
        [KoalaBear::new(8); BLOCK_LEN],
    ];
    let outputs = inputs
        .iter()
        .map(|input| hasher.permute(input))
        .collect::<Vec<_>>();

    // check that the full permutation output matches the image we got.
    let optional_outputs = outputs
        .iter()
        .map(|block| block.map(Some))
        .collect::<Vec<_>>();
    let statement = KoalaBearPoseidon2_16PreimageAir::new(&optional_outputs);
    let narg_string = prove_preimage(&statement, &inputs);
    assert!(verify_preimage(&statement, &narg_string).is_ok());

    // check that the rate segment of the permutation output matches the image we got.
    let rate_outputs = outputs
        .iter()
        .map(|block| {
            let mut rate_block = [None; BLOCK_LEN];
            (0..RATE_LEN).for_each(|i| rate_block[i] = block[i].into());
            rate_block
        })
        .collect::<Vec<_>>();
    let statement = KoalaBearPoseidon2_16PreimageAir::new(&rate_outputs);
    let narg_string = prove_preimage(&statement, &inputs);
    assert!(verify_preimage(&statement, &narg_string).is_ok());

    let mut bad_narg_string = narg_string.clone();
    bad_narg_string[0] ^= 0x01;
    assert!(verify_preimage(&statement, &bad_narg_string).is_err());
    assert!(verify_preimage(&statement, &[]).is_err());
}

#[test]
fn test_koala_bear_mve() {
    use spongefish::Permutation;
    use spongefish_stark::permutation::poseidon2::KoalaBearPoseidon2_16;
    let hasher = KoalaBearPoseidon2_16::default();
    let inputs = vec![
        [KoalaBear::new(1); BLOCK_LEN],
        [KoalaBear::new(2); BLOCK_LEN],
        [KoalaBear::new(3); BLOCK_LEN],
        [KoalaBear::new(4); BLOCK_LEN],
        [KoalaBear::new(5); BLOCK_LEN],
        [KoalaBear::new(6); BLOCK_LEN],
        [KoalaBear::new(7); BLOCK_LEN],
        [KoalaBear::new(8); BLOCK_LEN],
    ];
    let outputs = inputs
        .iter()
        .map(|input| hasher.permute(input))
        .collect::<Vec<_>>();
    let pads = [
        [KoalaBear::new(2 - 1); BLOCK_LEN],
        [KoalaBear::new(3 - 1); BLOCK_LEN],
        [KoalaBear::new(4 - 1); BLOCK_LEN],
        [KoalaBear::new(5 - 1); BLOCK_LEN],
        [KoalaBear::new(6 - 1); BLOCK_LEN],
        [KoalaBear::new(7 - 1); BLOCK_LEN],
        [KoalaBear::new(8 - 1); BLOCK_LEN],
    ];

    // check that the full permutation output matches the image we got.
    let optional_outputs = outputs
        .iter()
        .map(|block| block.map(Some))
        .collect::<Vec<_>>();
    let mveprover = MveAirKoalaBearPoseidon2_16::new(&optional_outputs, &pads);
    let narg_string = mveprover.prove(&inputs);
    assert!(mveprover.verify(&narg_string).is_ok());

    let mut bad_narg_string = narg_string.clone();
    bad_narg_string[0] ^= 0x01;
    assert!(mveprover.verify(&bad_narg_string).is_err());
    assert!(mveprover.verify(&[]).is_err());

    // // check that the rate segment of the permutation output matches the image we got.
    // let rate_outputs = outputs
    //     .iter()
    //     .map(|block| {
    //         let mut rate_block = [None; P2_16_CONFIG.width];
    //         (0..RATE_LEN).for_each(|i| rate_block[i] = block[i].into());
    //         rate_block
    //     })
    //     .collect::<Vec<_>>();
    // let mveprover = KoalaBearPoseidon2_16PreimageAir::new(&rate_outputs);
    // let narg_string = mveprover.prove(&inputs);
    // assert!(mveprover.verify(&narg_string).is_ok());
}

#[test]
fn test_poseidon_mve_rejects_tampered_proof() {
    type M = DefaultMkem;

    let mkem = M::default();
    let mut rng = rand::rng();
    let mut pks = Vec::new();
    for _ in 0..4 {
        let (pk, _sk) = mkem.keygen(&mut rng);
        pks.push(pk);
    }

    let key = KeyMaterial::random();
    let derivation = DerivationKoalaBearPoseidon2_16::default();
    let key_commitment = derivation.commit(&key);

    let proof = PoseidonMve::<M>::prove(&pks, &key_commitment, &key, "tamper_test");
    assert!(PoseidonMve::<M>::verify(&proof, &pks, &key_commitment, "tamper_test").is_ok());

    let mut tampered_proof = proof.clone();
    tampered_proof.proof[0] ^= 0x01;
    assert!(
        PoseidonMve::<M>::verify(&tampered_proof, &pks, &key_commitment, "tamper_test").is_err()
    );
}

#[test]
#[ignore = "test too slow"]
fn test_poseidon_mve_print_sizes() {
    use crate::mve::MVE_PARAMS;
    type P = DefaultMkem;

    for num_recipients in [10, 50, 256] {
        for (k, u) in MVE_PARAMS {
            match (k, u) {
                (247, 30) => test_poseidon_mve_print_sizes_helper::<P, 247, 30>(num_recipients),
                (100, 50) => test_poseidon_mve_print_sizes_helper::<P, 100, 50>(num_recipients),
                (126, 30) => test_poseidon_mve_print_sizes_helper::<P, 126, 30>(num_recipients),
                (443, 16) => test_poseidon_mve_print_sizes_helper::<P, 443, 16>(num_recipients),
                _ => panic!("unsupported mVE parameter set ({k}, {u})"),
            }
        }
    }
}

#[allow(dead_code)]
fn test_poseidon_mve_print_sizes_helper<M: Mkem, const K: usize, const U: usize>(
    num_recipients: usize,
) {
    let mkem = M::default();
    let mut rng = rand::rng();
    let mut pks = Vec::with_capacity(num_recipients);
    for _ in 0..num_recipients {
        let (pk, _sk) = mkem.keygen(&mut rng);
        pks.push(pk);
    }

    let key = KeyMaterial::random();
    let derivation = DerivationKoalaBearPoseidon2_16::default();
    let key_commitment = derivation.commit(&key);

    let proof = PoseidonMve::<M, K, U>::prove(&pks, &key_commitment, &key, "size_test");
    let ciphertexts = PoseidonMve::<M, K, U>::verify(&proof, &pks, &key_commitment, "size_test")
        .expect("verification should succeed");

    let proof_size = postcard::to_allocvec(&proof).unwrap().len();
    let total_ct_size = postcard::to_allocvec(&ciphertexts).unwrap().len();
    let recipient_ct = ciphertexts.get(0).expect("at least one recipient");
    let recipient_ct_size = postcard::to_allocvec(&recipient_ct).unwrap().len();

    // Field-level breakdown of |tr|
    let ciphertexts_size = postcard::to_allocvec(&proof.ciphertexts).unwrap().len();
    let opened_size = postcard::to_allocvec(&proof.opened).unwrap().len();
    let kept_commitments_size = postcard::to_allocvec(&proof.kept_commitments)
        .unwrap()
        .len();
    let challenge_size = proof.challenge.len();
    let pads_size = postcard::to_allocvec(&proof.pads).unwrap().len();
    let stark_proof_size = proof.proof.len();

    println!(
        "Poseidon mVE sizes: n={num_recipients}, k={K}, u={U} | |tr|={} | |ctx|={} | |ctx_i|={}",
        format_size(proof_size),
        format_size(total_ct_size),
        format_size(recipient_ct_size),
    );
    println!(
        "  |tr| breakdown: ciphertexts={} opened={} kept_commitments={} challenge={} pads={} stark_proof={}",
        format_size(ciphertexts_size),
        format_size(opened_size),
        format_size(kept_commitments_size),
        format_size(challenge_size),
        format_size(pads_size),
        format_size(stark_proof_size),
    );
}

fn format_size(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} kB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}
