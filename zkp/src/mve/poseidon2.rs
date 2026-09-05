use alloc::{vec, vec::Vec};
use core::{borrow::Borrow, marker::PhantomData, ptr};
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use spongefish::{Encoding, VerificationResult};
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
#[cfg(test)]
use p3_uni_stark::StarkGenericConfig;
#[cfg(test)]
use p3_uni_stark::{setup_preprocessed, verify_with_preprocessed};
#[cfg(test)]
use spongefish_stark::ff::KoalaBearStarkConfig;
use spongefish_stark::{
    air::{AirTracePadding, PreparedAir},
    ff::KoalaBearConfig,
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
    /// Real response pad values used by the STARK proof.
    ///
    /// The first `KEYMATERIAL_LIMBS` limbs encode prover responses. Deterministic
    /// trace padding is reconstructed by the AIR and is not serialized.
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
    let mut expected_blocks = Vec::with_capacity(real_count);
    expected_blocks.push(commitment_to_mask(key_commitment));
    expected_blocks.extend(kept_commitments.iter().map(commitment_to_mask));
    expected_blocks
}

fn responses_from_pads(
    pads: &[HashBlock],
    num_responses: usize,
) -> Result<Vec<KeyMaterial>, MveError> {
    if pads.len() != num_responses {
        return Err(MveError::VerificationInputError);
    }
    Ok(pads
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
        let hash_inputs = witness
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

        let pads = response_states;
        prover_state.prover_messages(&responses);

        let kept_commitments = keep_indices
            .iter()
            .map(|&idx| committed_messages[idx])
            .collect::<Vec<_>>();
        let expected_blocks = expected_blocks_from_commitments(key_commitment, &kept_commitments);
        let air = MveAirKoalaBearPoseidon2_16::new(&expected_blocks, &pads);

        let proof = air.prove(&hash_inputs);
        debug_assert!(MveAirKoalaBearPoseidon2_16::new(&expected_blocks, &pads)
            .verify(&proof)
            .is_ok());

        PoseidonMveProof {
            ciphertexts: kept_ciphertexts,
            challenge,
            opened,
            kept_commitments,
            proof,
            pads,
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
        let pads = core::iter::once(HashBlock::default())
            .chain(pads.iter().copied())
            .flatten()
            .collect::<Vec<_>>();

        Self { air, sum: pads }
    }

    fn prepare(&self) -> PreparedAir<'_, Self> {
        KoalaBearConfig::<Conservative>::prepare_air(
            self,
            self.air.input_count(),
            AirTracePadding::RepeatLast,
        )
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

    fn preprocessed_width(&self) -> usize {
        BLOCK_LEN * 3
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
    fn generate_trace_rows(
        &self,
        inputs: Vec<HashBlock>,
        extra_capacity_bits: usize,
    ) -> DenseMatrix<KoalaBear> {
        let s_0 = inputs[0];
        let preimage_matrix = self.air.generate_trace_rows(inputs, extra_capacity_bits);

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
            self.air.input_count(),
            "inputs should match the number of unpadded expected values"
        );
        let prepared = self.prepare();
        let trace = prepared.generate_trace(inputs, |inputs| self.generate_trace_rows(inputs, 2));
        KoalaBearConfig::<Conservative>::prove_prepared_air(&prepared, trace, &[])
    }

    pub fn verify(&self, narg_string: &[u8]) -> VerificationResult<()> {
        let prepared = self.prepare();
        KoalaBearConfig::<Conservative>::verify_prepared_air(&prepared, narg_string, &[])
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
        let prepared = KoalaBearConfig::<Conservative>::prepare_air(
            statement,
            statement.input_count(),
            AirTracePadding::RepeatLast,
        );
        let trace =
            prepared.generate_trace(inputs, |inputs| statement.generate_trace_rows(inputs, 2));
        KoalaBearConfig::<Conservative>::prove_prepared_air(&prepared, trace, &[])
    }

    fn verify_preimage(
        statement: &KoalaBearPoseidon2_16PreimageAir,
        narg_string: &[u8],
    ) -> VerificationResult<()> {
        let prepared = KoalaBearConfig::<Conservative>::prepare_air(
            statement,
            statement.input_count(),
            AirTracePadding::RepeatLast,
        );
        KoalaBearConfig::<Conservative>::verify_prepared_air(&prepared, narg_string, &[])
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

    let proof: p3_uni_stark::Proof<KoalaBearStarkConfig> =
        postcard::from_bytes(&narg_string).expect("valid proof bytes");
    let config = KoalaBearConfig::<Conservative>::verifier_config();
    let degree_bits = proof.degree_bits.saturating_sub(config.is_zk());
    let min_hiding_trace_height = KoalaBearConfig::<Conservative>::hiding_trace_height();
    assert_eq!(
        1usize << degree_bits,
        min_hiding_trace_height,
        "the AIR proof boundary should pad short traces to the PCS hiding minimum"
    );

    let mut under_height_proof = proof;
    under_height_proof.degree_bits =
        min_hiding_trace_height.trailing_zeros() as usize - 1 + config.is_zk();
    let under_height_proof = postcard::to_allocvec(&under_height_proof).unwrap();
    assert!(
        mveprover.verify(&under_height_proof).is_err(),
        "the verifier should reject proofs below the PCS hiding minimum"
    );

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
    assert_eq!(
        proof.pads.len(),
        proof.kept_commitments.len(),
        "only real response pads should be serialized"
    );

    let mut excess_pads_proof = proof.clone();
    excess_pads_proof
        .pads
        .push(*excess_pads_proof.pads.last().expect("at least one pad"));
    assert!(
        PoseidonMve::<M>::verify(&excess_pads_proof, &pks, &key_commitment, "tamper_test").is_err(),
        "the verifier should reject serialized deterministic padding"
    );

    let mut missing_pad_proof = proof.clone();
    missing_pad_proof.pads.pop();
    assert!(
        PoseidonMve::<M>::verify(&missing_pad_proof, &pks, &key_commitment, "tamper_test").is_err(),
        "the verifier should reject a missing real response pad"
    );

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

/// Plonky3's hiding-FRI masking (`p3_fri::HidingFriPcs`) only statistically
/// hides a trace column as long as the verifier learns fewer evaluations of
/// it than the number of interleaved random rows. This test reads the mVE
/// trace height straight from the AIR's deterministic padding,
/// builds the same interleaved-masking construction `HidingFriPcs::commit`
/// uses, reveals however many points a real Conservative-profile proof
/// actually reveals, and checks the group key baked into the `pad` column
/// isn't recoverable from them.
#[test]
fn test_mve_hiding_margin_protects_group_key() {
    use p3_field::{PrimeCharacteristicRing, PrimeField32};

    let derivation = DerivationKoalaBearPoseidon2_16::default();
    let key = KeyMaterial::random();
    let key_commitment = derivation.commit(&key);
    let key_state = derivation.key_to_hash_state(&key);

    // The real trace height for MVE_DEFAULT_K/U, straight from the
    // production padding logic: this test tracks whatever height the code
    // actually produces, rather than a value we'd have to keep in sync by
    // hand.
    let kept_commitments: Vec<KeyCommitment> = (0..MVE_DEFAULT_U)
        .map(|_| derivation.commit(&KeyMaterial::random()))
        .collect();
    let expected_blocks = expected_blocks_from_commitments(&key_commitment, &kept_commitments);
    let pads = vec![HashBlock::default(); kept_commitments.len()];
    let air = MveAirKoalaBearPoseidon2_16::new(&expected_blocks, &pads);
    let n = air.prepare().trace_height();

    // The real number of points a Conservative-profile proof reveals: FRI
    // query openings plus the two out-of-domain openings, each an element
    // of the quartic extension field.
    let num_revealed = KoalaBearConfig::<Conservative>::hiding_revealed_base_field_constraints();

    let mut rng = rand::rng();
    let mut recovered = [KoalaBear::ZERO; KEYMATERIAL_LIMBS];

    for (limb, recovered_limb) in recovered.iter_mut().enumerate() {
        let secret = key_state[limb];

        // The masked column: `n` real rows holding `secret` (the `pad`
        // column is constant across rows, matching the real AIR), then `n`
        // interleaved random rows, exactly as `HidingFriPcs::commit` builds
        // its degree-<2n masked polynomial.
        let mut domain: Vec<(KoalaBear, KoalaBear)> =
            (0..n).map(|i| (KoalaBear::new(i as u32), secret)).collect();
        // `rng.random()` can't be used directly here: the workspace's
        // `rand` and the one `p3_koala_bear`'s `Distribution<KoalaBear>`
        // impl is built against are different major versions, so reduce a
        // raw `u32` by hand instead.
        domain.extend((0..n).map(|i| {
            (
                KoalaBear::new((n + i) as u32),
                KoalaBear::new(rng.random::<u32>() % KoalaBear::ORDER_U32),
            )
        }));

        // What the verifier actually sees: `num_revealed` evaluations of
        // that masked polynomial, standing in for the FRI query openings
        // and the OOD openings at zeta/zeta*g.
        let revealed: Vec<(KoalaBear, KoalaBear)> = (0..num_revealed)
            .map(|i| {
                let x = KoalaBear::new((2 * n + i) as u32);
                (x, lagrange_eval(&domain, x))
            })
            .collect();

        // Reconstruct whatever polynomial fits all the revealed points and
        // read off row 0. When `num_revealed >= 2n` this is, by
        // uniqueness, exactly the real degree-<2n masked polynomial, and
        // the group key comes out exactly. When `num_revealed < 2n` it's
        // some other, wrong polynomial that only agrees with the truth at
        // the revealed points -- evaluating it at row 0 gives an
        // effectively random wrong value instead.
        *recovered_limb = lagrange_eval(&revealed, KoalaBear::new(0));
    }

    assert_ne!(
        recovered.as_slice(),
        &key_state[..KEYMATERIAL_LIMBS],
        "hiding margin at N={n} is unsafe: {num_revealed} revealed points \
         are enough to recover the group key by interpolation"
    );
}

/// Evaluates the unique polynomial of degree `< points.len()` interpolating
/// `points`, at `x`, via the textbook Lagrange formula. `O(n^2)`; fine for
/// the small `n` used by the test above.
#[cfg(test)]
fn lagrange_eval(points: &[(KoalaBear, KoalaBear)], x: KoalaBear) -> KoalaBear {
    use p3_field::Field;

    let mut acc = KoalaBear::ZERO;
    for &(xi, yi) in points {
        let mut term = yi;
        for &(xj, _) in points {
            if xj == xi {
                continue;
            }
            term = term * (x - xj) * (xi - xj).try_inverse().expect("distinct domain points");
        }
        acc += term;
    }
    acc
}

/// A [`p3_challenger`] wrapper that transparently delegates every operation
/// to a real challenger, but also records the return value of every
/// `sample_bits` call. Plugged into a real, unmodified verification run,
/// this recovers the real FRI query indices a real verifier derives from
/// the transcript, without re-deriving that transcript by hand: the
/// verification logic that computes them stays untouched, so a mistake in
/// this wrapper makes the wrapped `verify` call itself fail rather than
/// silently returning wrong indices.
#[cfg(test)]
#[derive(Clone)]
struct IndexLoggingChallenger<C> {
    inner: C,
    indices: std::sync::Arc<std::sync::Mutex<Vec<usize>>>,
}

#[cfg(test)]
impl<C, T> p3_challenger::CanObserve<T> for IndexLoggingChallenger<C>
where
    C: p3_challenger::CanObserve<T>,
{
    fn observe(&mut self, value: T) {
        self.inner.observe(value);
    }

    fn observe_slice(&mut self, values: &[T])
    where
        T: Clone,
    {
        self.inner.observe_slice(values);
    }
}

#[cfg(test)]
impl<C, T> p3_challenger::CanSample<T> for IndexLoggingChallenger<C>
where
    C: p3_challenger::CanSample<T>,
{
    fn sample(&mut self) -> T {
        self.inner.sample()
    }
}

#[cfg(test)]
impl<C> p3_challenger::CanSampleBits<usize> for IndexLoggingChallenger<C>
where
    C: p3_challenger::CanSampleBits<usize>,
{
    fn sample_bits(&mut self, bits: usize) -> usize {
        let index = self.inner.sample_bits(bits);
        self.indices.lock().unwrap().push(index);
        index
    }
}

#[cfg(test)]
impl<C> p3_challenger::FieldChallenger<KoalaBear> for IndexLoggingChallenger<C> where
    C: p3_challenger::FieldChallenger<KoalaBear>
{
}

#[cfg(test)]
impl<C> p3_challenger::GrindingChallenger for IndexLoggingChallenger<C>
where
    C: p3_challenger::GrindingChallenger<Witness = KoalaBear> + Clone + Sync,
{
    type Witness = KoalaBear;

    fn grind(&mut self, bits: usize) -> Self::Witness {
        // Never exercised on the verifier path this wrapper is used for
        // (grinding is a prover-only operation); delegate for completeness.
        self.inner.grind(bits)
    }
}

/// A [`StarkGenericConfig`] identical to the real `KoalaBearStarkConfig`,
/// except its `Challenger` is wrapped in [`IndexLoggingChallenger`] so a
/// real verification run's FRI query indices can be recovered afterward.
/// Concrete rather than generic over `SC`: `p3_fri`'s `Pcs<Challenge,
/// Challenger>` impls are generic over the challenger type, but nothing
/// carries that through an abstract `SC: StarkGenericConfig` bound, so this
/// is written directly against the one config used here.
#[cfg(test)]
#[derive(Clone)]
struct IndexLoggingConfig {
    inner: spongefish_stark::ff::KoalaBearStarkConfig,
    indices: std::sync::Arc<std::sync::Mutex<Vec<usize>>>,
}

#[cfg(test)]
impl StarkGenericConfig for IndexLoggingConfig {
    type Pcs = <spongefish_stark::ff::KoalaBearStarkConfig as StarkGenericConfig>::Pcs;
    type Challenge = <spongefish_stark::ff::KoalaBearStarkConfig as StarkGenericConfig>::Challenge;
    type Challenger = IndexLoggingChallenger<
        <spongefish_stark::ff::KoalaBearStarkConfig as StarkGenericConfig>::Challenger,
    >;

    fn pcs(&self) -> &Self::Pcs {
        self.inner.pcs()
    }

    fn initialise_challenger(&self) -> Self::Challenger {
        IndexLoggingChallenger {
            inner: self.inner.initialise_challenger(),
            indices: self.indices.clone(),
        }
    }
}

/// Recovers the group key from nothing but a real, serialized
/// `PoseidonMveProof` and the public commitments that go with it -- no
/// access to the trace, the witness, or any prover-side randomness.
///
/// This is exactly what an honest-but-curious server holding a stored proof
/// could do: run the real verifier (confirming the proof is genuinely
/// valid), recover the real FRI query indices it derives along the way
/// (via [`IndexLoggingChallenger`]), read the actual opened trace values
/// straight out of the proof bytes (already there, in the clear), and
/// interpolate the masked `pad` column back to a value at row 0. Whether
/// that value is the real key depends entirely on whether the trace height
/// gave hiding mode enough masking rows relative to how many points get
/// revealed -- see `test_mve_proof_hiding_margin_protects_group_key`.
#[cfg(test)]
fn attack_from_proof(
    key_commitment: &KeyCommitment,
    kept_commitments: &[KeyCommitment],
    pads: &[HashBlock],
    proof_bytes: &[u8],
) -> [KoalaBear; KEYMATERIAL_LIMBS] {
    use p3_field::{Field, PrimeCharacteristicRing, TwoAdicField};

    // `p3_util::reverse_bits_len` isn't a direct dependency of this crate;
    // inlined rather than adding one just for this.
    fn reverse_bits_len(x: usize, bit_len: usize) -> usize {
        x.reverse_bits()
            .overflowing_shr(usize::BITS - bit_len as u32)
            .0
    }

    // Reconstruct the AIR from public data only -- the same commitments and
    // `pads` a real verifier reconstructs it from, never the real witness.
    let expected_blocks = expected_blocks_from_commitments(key_commitment, kept_commitments);
    let air = MveAirKoalaBearPoseidon2_16::new(&expected_blocks, pads);

    // Built from a *fresh* `verifier_config()` call, not a `.clone()` of one:
    // `ChaChaCsrng::clone()` re-seeds from entropy instead of copying state,
    // so cloning here would silently re-randomize the salt
    // `commit_preprocessing` uses, and the recomputed `preprocessed_commit`
    // would stop matching the one baked into the proof's transcript.
    let indices = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let logging_config = IndexLoggingConfig {
        inner: KoalaBearConfig::<Conservative>::verifier_config(),
        indices: indices.clone(),
    };

    let proof: p3_uni_stark::Proof<IndexLoggingConfig> =
        postcard::from_bytes(proof_bytes).expect("valid proof bytes");
    let degree_bits = proof.degree_bits.saturating_sub(logging_config.is_zk());
    let prepared = air.prepare();
    let preprocessed = setup_preprocessed(&logging_config, &prepared, degree_bits);

    // Run the real, unmodified verifier. If this is `Err`, the proof itself
    // is invalid and nothing below should be trusted -- but our own sanity
    // check already confirmed this exact proof verifies, so this should
    // always succeed; it's here so a bug in the wrapper fails loudly
    // instead of silently producing wrong indices.
    verify_with_preprocessed(
        &logging_config,
        &prepared,
        &proof,
        &[],
        preprocessed.as_ref().map(|(_, vk)| vk),
    )
    .expect("a real, honestly generated proof must verify");

    // The trace round is the second commitment round whenever ZK randomizes
    // the trace (always true here): [random, trace, quotient, preprocessed].
    assert!(
        proof.commitments.random.is_some(),
        "expected ZK to be enabled"
    );
    const TRACE_ROUND: usize = 1;
    let pad_start = prepared.width() - BLOCK_LEN;
    let fri_proof = &proof.opening_proof.1;

    // `IndexLoggingChallenger::sample_bits` logs *every* `sample_bits` call,
    // not just the per-query domain indices `verify_fri`'s query loop
    // derives: `check_witness` (used for both the per-commit-phase-round PoW
    // check and the one query PoW check) also calls `sample_bits`. Those
    // precede the real per-query indices in the log, one per commit phase
    // round plus one for the query PoW, so skip exactly that many.
    let logged = indices.lock().unwrap().clone();
    let pow_checks = fri_proof.commit_phase_commits.len() + 1;
    let query_indices = &logged[pow_checks..];

    // For each FRI query, recompute the exact domain point the opening was
    // taken at (the same formula `p3_fri::verifier::open_input` uses), and
    // read the actual opened trace row straight out of the proof's batch
    // openings -- these are genuine, in-the-clear field elements the proof
    // already contains, not recomputed or assumed. `degree_bits` (read
    // straight off the proof, not hardcoded) is the pre-doubling trace
    // height's exponent, so this tracks whatever height the proof actually
    // used.
    let log_blowup = 3; // Conservative
    let log_final_poly_len = 3; // Conservative
    let total_log_reduction: usize = fri_proof.query_proofs[0]
        .commit_phase_openings
        .iter()
        .map(|o| o.log_arity as usize)
        .sum();
    let log_global_max_height = total_log_reduction + log_blowup + log_final_poly_len;
    let trace_log_height = degree_bits + 1 + log_blowup; // degree_bits is pre-doubling
    assert_eq!(
        log_global_max_height, trace_log_height,
        "expected the trace matrix to be the tallest committed matrix"
    );

    let g = KoalaBear::two_adic_generator(trace_log_height);
    let domain_point = |index: usize| -> KoalaBear {
        KoalaBear::GENERATOR * g.exp_u64(reverse_bits_len(index, trace_log_height) as u64)
    };

    // Queries are sampled with replacement from a domain of only
    // `2^trace_log_height` points, so among the revealed draws a handful of
    // repeats is expected (birthday paradox). A repeated index is the same
    // point again, not a new constraint, so pin the polynomial down using
    // only *distinct* points -- Lagrange interpolation over a point that
    // appears more than once doesn't error, it just silently reconstructs
    // the wrong polynomial (fewer real constraints than points).
    let mut seen = std::collections::HashSet::new();
    let mut points: Vec<(KoalaBear, &[KoalaBear])> = Vec::new();
    for (&index, query_proof) in query_indices.iter().zip(&fri_proof.query_proofs) {
        if !seen.insert(index) {
            continue;
        }
        let row = query_proof.input_proof[TRACE_ROUND].opened_values[0].as_slice();
        points.push((domain_point(index), row));
    }

    // Row 0 of the un-blown trace domain is `domain.shift() = Val::ONE`
    // (`TwoAdicFriPcs::natural_domain_for_degree` always shifts by `ONE`;
    // the LDE domain the FRI queries actually land on is separately
    // re-shifted to `GENERATOR` by `commit`, which `domain_point` already
    // accounts for).
    let row0 = KoalaBear::ONE;

    // Reconstruct whatever polynomial fits all the distinct revealed points
    // and read off row 0. If the trace has fewer masking rows than points
    // revealed here, this is, by uniqueness, exactly the real masked
    // polynomial and the key comes out exactly. Otherwise it's some other,
    // wrong polynomial that only agrees with the truth at the revealed
    // points -- evaluating it at row 0 gives an effectively random wrong
    // value instead.
    let mut recovered = [KoalaBear::ZERO; KEYMATERIAL_LIMBS];
    for (limb, recovered_limb) in recovered.iter_mut().enumerate() {
        let limb_points: Vec<(KoalaBear, KoalaBear)> = points
            .iter()
            .map(|&(x, row)| (x, row[pad_start + limb]))
            .collect();
        *recovered_limb = lagrange_eval(&limb_points, row0);
    }
    recovered
}

/// Runs [`attack_from_proof`] against a real, serialized `PoseidonMveProof`
/// built at the real production padding height (not a hardcoded one), and
/// checks the group key can't be recovered from nothing but the proof
/// bytes and the public commitments a real verifier already has.
///
#[test]
fn test_mve_proof_hiding_margin_protects_group_key() {
    let derivation = DerivationKoalaBearPoseidon2_16::default();

    let key = KeyMaterial::random();
    let key_commitment = derivation.commit(&key);
    let kept_messages: Vec<KeyMaterial> =
        (0..MVE_DEFAULT_U).map(|_| KeyMaterial::random()).collect();
    let kept_commitments: Vec<KeyCommitment> =
        kept_messages.iter().map(|m| derivation.commit(m)).collect();

    let hash_inputs: Vec<HashBlock> = std::iter::once(&key)
        .chain(kept_messages.iter())
        .map(|k| derivation.key_to_hash_state(k))
        .collect();
    let key_state = hash_inputs[0];
    let pads: Vec<HashBlock> = hash_inputs[1..]
        .iter()
        .map(|state| {
            let mut diff = HashBlock::default();
            for (dst, (val, key_val)) in diff.iter_mut().zip(state.iter().zip(key_state.iter())) {
                *dst = *val - *key_val;
            }
            diff
        })
        .collect();

    let expected_blocks = expected_blocks_from_commitments(&key_commitment, &kept_commitments);
    let air = MveAirKoalaBearPoseidon2_16::new(&expected_blocks, &pads);
    let padded_count = air.prepare().trace_height();

    // The only proof bytes a server, or anyone else, ever actually sees.
    let proof_bytes = air.prove(&hash_inputs);
    assert!(
        air.verify(&proof_bytes).is_ok(),
        "sanity check: the real, unwrapped verifier should accept this proof"
    );

    // The attack: only the proof bytes and the public commitments, never
    // `hash_inputs`/`key` -- those are passed separately below purely to
    // check the attack's answer against ground truth.
    let recovered = attack_from_proof(&key_commitment, &kept_commitments, &pads, &proof_bytes);

    assert_ne!(
        recovered.as_slice(),
        &key_state[..KEYMATERIAL_LIMBS],
        "hiding margin at padded height {padded_count} is unsafe: the real proof leaked the pad column"
    );
}
