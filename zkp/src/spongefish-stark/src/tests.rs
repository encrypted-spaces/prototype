#![allow(dead_code, unused_imports)]

#[cfg(all(feature = "keccak256", feature = "p3-baby-bear"))]
use crate::permutation::keccak::KECCAK_WIDTH;
#[cfg(all(feature = "poseidon2", feature = "p3-baby-bear"))]
use crate::permutation::poseidon2::BabyBearPoseidon2_16;
#[cfg(feature = "poseidon2")]
use crate::permutation::poseidon2::POSEIDON2_16_WIDTH;
#[cfg(all(feature = "poseidon2", feature = "p3-koala-bear"))]
use crate::permutation::poseidon2::{KoalaBearPoseidon2_16, KoalaBearPoseidon2_16_Aggressive};
use crate::{relation, HashRelationBackend, RelationChallenge, RelationField};
use alloc::vec::Vec;
use p3_air::SymbolicExpressionExt;
#[cfg(all(feature = "keccak256", feature = "p3-baby-bear"))]
use p3_field::PrimeField64;
use p3_field::{Algebra, BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField};
use p3_uni_stark::StarkGenericConfig;
use spongefish::{Permutation, Unit};
use spongefish_circuit::{
    allocator::FieldVar,
    permutation::{LinearEquation, PermutationInstanceBuilder, PermutationWitnessBuilder},
};

#[cfg(all(feature = "poseidon2", feature = "p3-koala-bear"))]
use crate::{
    ff::{KoalaBearConfig, KoalaBearStarkConfig},
    permutation::poseidon2::KoalaBearPoseidon2_16HashAir,
    security_profile::{Aggressive, Conservative, SecurityParameters, SecurityProfile},
};

#[cfg(all(feature = "keccak256", feature = "p3-baby-bear"))]
use hex_literal::hex;

const TEST_LINEAR_WIDTH: usize = 1;
const TEST_LINEAR_WIDTH_2: usize = 2;

#[derive(Clone)]
struct ProveOnlyBackend<B>(B);

impl<B, const WIDTH: usize> HashRelationBackend<WIDTH> for ProveOnlyBackend<B>
where
    B: HashRelationBackend<WIDTH>,
{
    type Config = B::Config;
    type Air = B::Air;
    type Permutation = B::Permutation;

    fn prover_config(&self) -> Self::Config {
        self.0.prover_config()
    }

    fn verifier_config(&self) -> Self::Config {
        self.0.verifier_config()
    }

    fn security_parameters(&self) -> crate::security_profile::SecurityParameters {
        self.0.security_parameters()
    }

    fn air(&self) -> Self::Air {
        self.0.air()
    }

    fn permutation(&self) -> Self::Permutation {
        self.0.permutation()
    }
}

#[derive(Clone)]
struct VerifyOnlyBackend<B>(B);

impl<B, const WIDTH: usize> HashRelationBackend<WIDTH> for VerifyOnlyBackend<B>
where
    B: HashRelationBackend<WIDTH>,
{
    type Config = B::Config;
    type Air = B::Air;
    type Permutation = B::Permutation;

    fn prover_config(&self) -> Self::Config {
        panic!("verify must not request prover config")
    }

    fn verifier_config(&self) -> Self::Config {
        self.0.verifier_config()
    }

    fn security_parameters(&self) -> crate::security_profile::SecurityParameters {
        self.0.security_parameters()
    }

    fn air(&self) -> Self::Air {
        self.0.air()
    }

    fn permutation(&self) -> Self::Permutation {
        self.0.permutation()
    }
}

#[cfg(all(feature = "poseidon2", feature = "p3-koala-bear"))]
#[derive(Clone)]
struct ParameterizedKoalaBearBackend {
    permutation: KoalaBearPoseidon2_16,
    security_parameters: SecurityParameters,
}

#[cfg(all(feature = "poseidon2", feature = "p3-koala-bear"))]
impl ParameterizedKoalaBearBackend {
    fn new(security_parameters: SecurityParameters) -> Self {
        Self {
            permutation: KoalaBearPoseidon2_16::new(),
            security_parameters,
        }
    }
}

#[cfg(all(feature = "poseidon2", feature = "p3-koala-bear"))]
impl HashRelationBackend<POSEIDON2_16_WIDTH> for ParameterizedKoalaBearBackend {
    type Config = KoalaBearStarkConfig;
    type Air = KoalaBearPoseidon2_16HashAir;
    type Permutation = KoalaBearPoseidon2_16;

    fn prover_config(&self) -> Self::Config {
        KoalaBearConfig::<Conservative>::prover_config_with_security_parameters(
            self.security_parameters,
        )
    }

    fn verifier_config(&self) -> Self::Config {
        KoalaBearConfig::<Conservative>::verifier_config_with_security_parameters(
            self.security_parameters,
        )
    }

    fn security_parameters(&self) -> SecurityParameters {
        self.security_parameters
    }

    fn air(&self) -> Self::Air {
        KoalaBearPoseidon2_16HashAir::default()
    }

    fn permutation(&self) -> Self::Permutation {
        self.permutation.clone()
    }
}

#[cfg(all(feature = "keccak256", feature = "p3-baby-bear"))]
type RelationCase<B, const WIDTH: usize> = (
    [RelationField<B, { WIDTH }>; WIDTH],
    Vec<(usize, RelationField<B, { WIDTH }>)>,
);

#[cfg(all(feature = "keccak256", feature = "p3-baby-bear"))]
/// Source hashes generated via https://emn178.github.io/online-tools/keccak_256.html
const KECCAK256_PREIMAGE_VECTORS: [(&str, [u8; 32]); 4] = [
    (
        "testing",
        hex!("5f16f4c7f149ac4f9510d9cf8cf384038ad348b3bcdc01915f95de12df9d1b02"),
    ),
    (
        "foobar",
        hex!("38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e"),
    ),
    (
        "spongefish test",
        hex!("3a0b0512da20c3b789806be8538789ae85550f63d034b1a6ba242f018a079c9f"),
    ),
    (
        "abcdefghilmn",
        hex!("f560efad31de65af6d82893de70a71a7f32e72b9ea44c3b42fe2da5f641845e5"),
    ),
];

fn sample_input<F, const WIDTH: usize>() -> [F; WIDTH]
where
    F: Field + Unit + PartialEq,
{
    core::array::from_fn(|i| F::from_usize(i + 1))
}

#[cfg(all(feature = "keccak256", feature = "p3-baby-bear"))]
fn keccak256_single_block_input<F>(message: &str) -> [F; 100]
where
    F: PrimeField64 + Unit,
{
    const RATE_BYTES: usize = 136;
    let message = message.as_bytes();
    assert!(
        message.len() < RATE_BYTES,
        "test helper only supports one Keccak-256 block"
    );

    let mut block = [0u8; 200];
    block[..message.len()].copy_from_slice(message);
    block[message.len()] ^= 0x01;
    block[RATE_BYTES - 1] ^= 0x80;

    core::array::from_fn(|idx| {
        let limb_offset = idx * 2;
        let limb = u16::from_le_bytes([block[limb_offset], block[limb_offset + 1]]);
        F::from_u16(limb)
    })
}

#[cfg(all(feature = "keccak256", feature = "p3-baby-bear"))]
fn keccak256_public_outputs<B>(digest: [u8; 32]) -> Vec<(usize, RelationField<B, KECCAK_WIDTH>)>
where
    B: HashRelationBackend<KECCAK_WIDTH>,
    RelationField<B, KECCAK_WIDTH>: PrimeField64 + Field + Unit + PartialEq + Send + Sync,
{
    (0..16)
        .map(|idx| {
            let limb = u16::from_le_bytes([digest[2 * idx], digest[2 * idx + 1]]);
            (idx, RelationField::<B, KECCAK_WIDTH>::from_u16(limb))
        })
        .collect()
}

#[cfg(all(feature = "keccak256", feature = "p3-baby-bear"))]
fn keccak256_digest_from_state<F>(state: &[F; 100]) -> [u8; 32]
where
    F: PrimeField64,
{
    let mut digest = [0u8; 32];
    for limb_idx in 0..16 {
        let limb = state[limb_idx].as_canonical_u64() as u16;
        let bytes = limb.to_le_bytes();
        digest[2 * limb_idx] = bytes[0];
        digest[2 * limb_idx + 1] = bytes[1];
    }
    digest
}

#[cfg(all(feature = "keccak256", feature = "p3-baby-bear"))]
fn keccak256_vector_cases<B>() -> Vec<RelationCase<B, 100>>
where
    B: HashRelationBackend<KECCAK_WIDTH>,
    RelationField<B, KECCAK_WIDTH>: PrimeField64 + Field + Unit + PartialEq + Send + Sync,
{
    KECCAK256_PREIMAGE_VECTORS
        .iter()
        .map(|(message, expected_digest)| {
            let input = keccak256_single_block_input::<RelationField<B, KECCAK_WIDTH>>(message);
            let public_outputs = keccak256_public_outputs::<B>(*expected_digest);
            (input, public_outputs)
        })
        .collect()
}

#[cfg(all(feature = "keccak256", feature = "p3-baby-bear"))]
fn build_private_input_relation_instance_and_witness<
    B,
    P,
    const WIDTH: usize,
    const LIN_WIDTH: usize,
>(
    permutation: P,
    cases: impl IntoIterator<Item = RelationCase<B, WIDTH>>,
) -> (
    PermutationInstanceBuilder<RelationField<B, { WIDTH }>, WIDTH>,
    PermutationWitnessBuilder<P, WIDTH>,
)
where
    B: HashRelationBackend<{ WIDTH }>,
    P: Permutation<WIDTH, U = RelationField<B, { WIDTH }>>,
    RelationField<B, { WIDTH }>: Field + Unit + PartialEq + Send + Sync,
{
    let instance = PermutationInstanceBuilder::<RelationField<B, { WIDTH }>, WIDTH>::new();
    let witness = PermutationWitnessBuilder::<P, WIDTH>::new(permutation);

    for (input, public_outputs) in cases {
        let input_vars = instance.allocator().allocate_vars::<WIDTH>();
        let output_vars = instance.allocate_permutation(&input_vars);
        let output_vals = witness.allocate_permutation(&input);

        instance.allocator().set_public_vars(
            public_outputs.iter().map(|(idx, _)| output_vars[*idx]),
            public_outputs.iter().map(|(_, val)| *val),
        );

        instance.add_equation(LinearEquation::new(
            core::iter::once((
                <RelationField<B, { WIDTH }> as PrimeCharacteristicRing>::ONE,
                output_vars[0],
            ))
            .chain((1..LIN_WIDTH).map(|_| {
                (
                    <RelationField<B, { WIDTH }> as PrimeCharacteristicRing>::ZERO,
                    FieldVar::ZERO,
                )
            })),
            output_vals[0],
        ));
        witness.add_equation(LinearEquation::new(
            core::iter::once((
                <RelationField<B, { WIDTH }> as PrimeCharacteristicRing>::ONE,
                output_vals[0],
            ))
            .chain((1..LIN_WIDTH).map(|_| {
                (
                    <RelationField<B, { WIDTH }> as PrimeCharacteristicRing>::ZERO,
                    <RelationField<B, { WIDTH }> as PrimeCharacteristicRing>::ZERO,
                )
            })),
            output_vals[0],
        ));
    }

    (instance, witness)
}

fn build_relation_instance_and_witness<B, P, const WIDTH: usize, const LIN_WIDTH: usize>(
    permutation: P,
    input: [RelationField<B, { WIDTH }>; WIDTH],
    public_outputs: &[(usize, RelationField<B, { WIDTH }>)],
) -> (
    PermutationInstanceBuilder<RelationField<B, { WIDTH }>, WIDTH>,
    PermutationWitnessBuilder<P, WIDTH>,
)
where
    B: HashRelationBackend<{ WIDTH }>,
    P: Permutation<WIDTH, U = RelationField<B, { WIDTH }>>,
    RelationField<B, { WIDTH }>: Field + Unit + PartialEq + Send + Sync,
{
    let instance = PermutationInstanceBuilder::<RelationField<B, { WIDTH }>, WIDTH>::new();
    let witness = PermutationWitnessBuilder::<P, WIDTH>::new(permutation);

    let input_vars = instance.allocator().allocate_public::<WIDTH>(&input);
    let output_vars = instance.allocate_permutation(&input_vars);
    let output_vals = witness.allocate_permutation(&input);

    instance.allocator().set_public_vars(
        public_outputs.iter().map(|(idx, _)| output_vars[*idx]),
        public_outputs.iter().map(|(_, val)| *val),
    );

    instance.add_equation(LinearEquation::new(
        core::iter::once((
            <RelationField<B, { WIDTH }> as PrimeCharacteristicRing>::ONE,
            output_vars[0],
        ))
        .chain((1..LIN_WIDTH).map(|_| {
            (
                <RelationField<B, { WIDTH }> as PrimeCharacteristicRing>::ZERO,
                FieldVar::ZERO,
            )
        })),
        output_vals[0],
    ));
    witness.add_equation(LinearEquation::new(
        core::iter::once((
            <RelationField<B, { WIDTH }> as PrimeCharacteristicRing>::ONE,
            output_vals[0],
        ))
        .chain((1..LIN_WIDTH).map(|_| {
            (
                <RelationField<B, { WIDTH }> as PrimeCharacteristicRing>::ZERO,
                <RelationField<B, { WIDTH }> as PrimeCharacteristicRing>::ZERO,
            )
        })),
        output_vals[0],
    ));

    (instance, witness)
}

fn prove_relation<B, const WIDTH: usize>(
    backend: &B,
    instance: &PermutationInstanceBuilder<RelationField<B, { WIDTH }>, WIDTH>,
    witness: &PermutationWitnessBuilder<B::Permutation, WIDTH>,
) -> (relation::PreparedRelation<B, WIDTH>, Vec<u8>)
where
    B: HashRelationBackend<{ WIDTH }>,
    RelationField<B, { WIDTH }>: PrimeField + Unit + PartialEq + Send + Sync,
    RelationChallenge<B, { WIDTH }>: BasedVectorSpace<RelationField<B, { WIDTH }>>,
    SymbolicExpressionExt<RelationField<B, { WIDTH }>, RelationChallenge<B, { WIDTH }>>:
        Algebra<RelationChallenge<B, { WIDTH }>>,
    p3_uni_stark::Domain<B::Config>: Send + Sync,
    <B::Config as StarkGenericConfig>::Pcs: Sync,
    <<B::Config as StarkGenericConfig>::Pcs as p3_commit::Pcs<
        RelationChallenge<B, { WIDTH }>,
        <B::Config as StarkGenericConfig>::Challenger,
    >>::ProverData: Sync,
    <<B::Config as StarkGenericConfig>::Pcs as p3_commit::Pcs<
        RelationChallenge<B, { WIDTH }>,
        <B::Config as StarkGenericConfig>::Challenger,
    >>::Commitment: Sync,
{
    let relation = relation::PreparedRelation::new(backend, instance);
    let witness = relation.prepare_witness(witness);
    let proof = relation.prove(backend, &witness);
    (relation, proof)
}

fn run_hash_relation_checks<B, const WIDTH: usize, const LIN_WIDTH: usize>(backend: &B)
where
    B: HashRelationBackend<{ WIDTH }>,
    RelationField<B, { WIDTH }>: PrimeField + Unit + PartialEq + Send + Sync,
    RelationChallenge<B, { WIDTH }>: BasedVectorSpace<RelationField<B, { WIDTH }>>,
    SymbolicExpressionExt<RelationField<B, { WIDTH }>, RelationChallenge<B, { WIDTH }>>:
        Algebra<RelationChallenge<B, { WIDTH }>>,
    p3_uni_stark::Domain<B::Config>: Send + Sync,
    <B::Config as StarkGenericConfig>::Pcs: Sync,
    <<B::Config as StarkGenericConfig>::Pcs as p3_commit::Pcs<
        RelationChallenge<B, { WIDTH }>,
        <B::Config as StarkGenericConfig>::Challenger,
    >>::ProverData: Sync,
    <<B::Config as StarkGenericConfig>::Pcs as p3_commit::Pcs<
        RelationChallenge<B, { WIDTH }>,
        <B::Config as StarkGenericConfig>::Challenger,
    >>::Commitment: Sync,
{
    let permutation = backend.permutation();
    let input = sample_input::<RelationField<B, { WIDTH }>, WIDTH>();
    let expected_output = permutation.permute(&input);
    let public_outputs = Vec::from([
        (1usize, expected_output[1]),
        (2usize, expected_output[2]),
        (3usize, expected_output[3]),
    ]);

    let (instance, witness) = build_relation_instance_and_witness::<
        B,
        B::Permutation,
        WIDTH,
        LIN_WIDTH,
    >(permutation.clone(), input, &public_outputs);

    let (relation, proof) = prove_relation(backend, &instance, &witness);
    assert!(relation.verify(backend, &proof).is_ok());

    let mut bad_proof = proof.clone();
    bad_proof[0] ^= 0x01;
    assert!(relation.verify(backend, &bad_proof).is_err());

    let bad_public_outputs = Vec::from([
        (
            1usize,
            expected_output[1] + <RelationField<B, { WIDTH }> as PrimeCharacteristicRing>::ONE,
        ),
        (2usize, expected_output[2]),
        (3usize, expected_output[3]),
    ]);
    let (bad_instance, _) = build_relation_instance_and_witness::<
        B,
        B::Permutation,
        WIDTH,
        LIN_WIDTH,
    >(permutation, input, &bad_public_outputs);
    let bad_relation = relation::PreparedRelation::new(backend, &bad_instance);
    assert!(bad_relation.verify(backend, &proof).is_err());

    let mut shifted_proof = proof;
    shifted_proof.insert(0, 0x00);
    assert!(relation.verify(backend, &shifted_proof).is_err());
}

#[cfg(all(feature = "poseidon2", feature = "p3-baby-bear"))]
#[test]
fn babybear_poseidon2_16_relation_proof_and_false_checks() {
    run_hash_relation_checks::<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH, TEST_LINEAR_WIDTH>(
        &BabyBearPoseidon2_16::new(),
    );
}

#[cfg(all(feature = "poseidon2", feature = "p3-koala-bear"))]
#[test]
fn koalabear_poseidon2_16_relation_proof_and_false_checks() {
    run_hash_relation_checks::<KoalaBearPoseidon2_16, POSEIDON2_16_WIDTH, TEST_LINEAR_WIDTH>(
        &KoalaBearPoseidon2_16::new(),
    );
}

#[cfg(all(feature = "poseidon2", feature = "p3-koala-bear"))]
#[test]
fn koalabear_poseidon2_16_aggressive_relation_proof_and_false_checks() {
    run_hash_relation_checks::<
        KoalaBearPoseidon2_16_Aggressive,
        POSEIDON2_16_WIDTH,
        TEST_LINEAR_WIDTH,
    >(&KoalaBearPoseidon2_16_Aggressive::new());
}

#[cfg(all(feature = "poseidon2", feature = "p3-baby-bear"))]
#[test]
fn poseidon2_16_relation_can_be_proven_repeatedly_after_padding() {
    type B = BabyBearPoseidon2_16;

    let backend = B::new();
    let permutation = backend.permutation();
    let instance = PermutationInstanceBuilder::<
        RelationField<B, POSEIDON2_16_WIDTH>,
        POSEIDON2_16_WIDTH,
    >::new();
    let witness = PermutationWitnessBuilder::<
        <B as HashRelationBackend<POSEIDON2_16_WIDTH>>::Permutation,
        POSEIDON2_16_WIDTH,
    >::new(permutation.clone());

    for offset in 0..3 {
        let input = core::array::from_fn(|i| {
            RelationField::<B, POSEIDON2_16_WIDTH>::from_usize(offset * 17 + i + 1)
        });
        let expected_output = permutation.permute(&input);
        let input_vars = instance
            .allocator()
            .allocate_public::<POSEIDON2_16_WIDTH>(&input);
        let output_vars = instance.allocate_permutation(&input_vars);
        let _output_vals = witness.allocate_permutation(&input);
        instance
            .allocator()
            .set_public_vars([output_vars[0]], [expected_output[0]]);
    }

    let (relation, proof) = prove_relation(&backend, &instance, &witness);
    assert!(relation.verify(&backend, &proof).is_ok());

    let (relation, proof) = prove_relation(&backend, &instance, &witness);
    assert!(relation.verify(&backend, &proof).is_ok());
}

#[cfg(all(feature = "poseidon2", feature = "p3-baby-bear"))]
#[test]
fn poseidon2_16_relation_honors_configured_minimum_trace_height() {
    type B = BabyBearPoseidon2_16;

    const MIN_TRACE_HEIGHT: usize = 256;

    let backend = B::new();
    let default_min_trace_height =
        crate::ff::BabyBearConfig::<crate::security_profile::Conservative>::hiding_trace_height();
    let permutation = backend.permutation();
    let input = sample_input::<RelationField<B, POSEIDON2_16_WIDTH>, POSEIDON2_16_WIDTH>();
    let expected_output = permutation.permute(&input);
    let (instance, witness) = build_relation_instance_and_witness::<
        B,
        _,
        POSEIDON2_16_WIDTH,
        TEST_LINEAR_WIDTH,
    >(permutation, input, &[(0, expected_output[0])]);

    let default_relation = relation::PreparedRelation::new(&backend, &instance);
    let default_witness = default_relation.prepare_witness(&witness);
    let default_proof = default_relation.prove(&backend, &default_witness);
    let decoded_default = postcard::from_bytes::<
        p3_batch_stark::BatchProof<<B as HashRelationBackend<POSEIDON2_16_WIDTH>>::Config>,
    >(&default_proof)
    .expect("default proof should deserialize");
    let default_degree_bits =
        default_min_trace_height.trailing_zeros() as usize + backend.verifier_config().is_zk();
    assert_eq!(decoded_default.degree_bits, vec![default_degree_bits; 3]);
    assert!(default_relation.verify(&backend, &default_proof).is_ok());

    let lower_relation =
        relation::PreparedRelation::new_with_min_trace_height(&backend, &instance, 32);
    let lower_witness = lower_relation.prepare_witness(&witness);
    let lower_proof = lower_relation.prove(&backend, &lower_witness);
    let decoded_lower = postcard::from_bytes::<
        p3_batch_stark::BatchProof<<B as HashRelationBackend<POSEIDON2_16_WIDTH>>::Config>,
    >(&lower_proof)
    .expect("proof with lower caller floor should deserialize");
    assert_eq!(decoded_lower.degree_bits, vec![default_degree_bits; 3]);
    assert!(lower_relation.verify(&backend, &lower_proof).is_ok());

    let relation = relation::PreparedRelation::new_with_min_trace_height(
        &backend,
        &instance,
        MIN_TRACE_HEIGHT,
    );
    let witness = relation.prepare_witness(&witness);
    let proof = relation.prove(&backend, &witness);
    let decoded = postcard::from_bytes::<
        p3_batch_stark::BatchProof<<B as HashRelationBackend<POSEIDON2_16_WIDTH>>::Config>,
    >(&proof)
    .expect("proof should deserialize");
    let expected_degree_bits =
        MIN_TRACE_HEIGHT.trailing_zeros() as usize + backend.verifier_config().is_zk();

    assert_eq!(decoded.degree_bits, vec![expected_degree_bits; 3]);
    assert!(relation.verify(&backend, &proof).is_ok());
}

#[cfg(all(feature = "poseidon2", feature = "p3-koala-bear"))]
#[test]
fn prepared_relation_rejects_backend_security_parameter_mismatch() {
    let aggressive = ParameterizedKoalaBearBackend::new(Aggressive::security_parameters());
    let conservative = ParameterizedKoalaBearBackend::new(Conservative::security_parameters());
    let permutation = aggressive.permutation();
    let input = sample_input::<p3_koala_bear::KoalaBear, POSEIDON2_16_WIDTH>();
    let output = permutation.permute(&input);
    let (instance, witness) = build_relation_instance_and_witness::<
        ParameterizedKoalaBearBackend,
        _,
        POSEIDON2_16_WIDTH,
        TEST_LINEAR_WIDTH,
    >(permutation, input, &[(0, output[0])]);
    let relation = relation::PreparedRelation::new(&aggressive, &instance);
    let witness = relation.prepare_witness(&witness);

    let mismatched_prover = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        relation.prove(&conservative, &witness)
    }));
    assert!(mismatched_prover.is_err());

    let proof = relation.prove(&aggressive, &witness);
    assert!(relation.verify(&aggressive, &proof).is_ok());
    assert!(relation.verify(&conservative, &proof).is_err());
}

#[cfg(all(feature = "poseidon2", feature = "p3-baby-bear"))]
#[test]
#[should_panic(expected = "minimum trace height must be a non-zero power of two")]
fn poseidon2_16_relation_rejects_invalid_minimum_trace_height() {
    type B = BabyBearPoseidon2_16;

    let backend = B::new();
    let instance = PermutationInstanceBuilder::<
        RelationField<B, POSEIDON2_16_WIDTH>,
        POSEIDON2_16_WIDTH,
    >::new();

    let _ = relation::PreparedRelation::new_with_min_trace_height(&backend, &instance, 96);
}

#[cfg(all(feature = "poseidon2", feature = "p3-baby-bear"))]
#[test]
#[should_panic(expected = "minimum trace height must be a non-zero power of two")]
fn poseidon2_16_relation_rejects_zero_minimum_trace_height() {
    type B = BabyBearPoseidon2_16;

    let backend = B::new();
    let instance = PermutationInstanceBuilder::<
        RelationField<B, POSEIDON2_16_WIDTH>,
        POSEIDON2_16_WIDTH,
    >::new();

    let _ = relation::PreparedRelation::new_with_min_trace_height(&backend, &instance, 0);
}

#[cfg(all(feature = "poseidon2", feature = "p3-baby-bear"))]
#[test]
fn poseidon2_16_relation_proof_and_false_checks_lw2() {
    run_hash_relation_checks::<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH, TEST_LINEAR_WIDTH_2>(
        &BabyBearPoseidon2_16::new(),
    );
}

#[cfg(all(feature = "poseidon2", feature = "p3-baby-bear"))]
#[test]
fn relation_prove_and_verify_use_role_specific_configs() {
    type B = BabyBearPoseidon2_16;

    let backend = B::new();
    let permutation = backend.permutation();
    let input = sample_input::<RelationField<B, POSEIDON2_16_WIDTH>, POSEIDON2_16_WIDTH>();
    let expected_output = permutation.permute(&input);
    let public_outputs = Vec::from([
        (1usize, expected_output[1]),
        (2usize, expected_output[2]),
        (3usize, expected_output[3]),
    ]);
    let (instance, witness) = build_relation_instance_and_witness::<
        B,
        <B as HashRelationBackend<POSEIDON2_16_WIDTH>>::Permutation,
        POSEIDON2_16_WIDTH,
        TEST_LINEAR_WIDTH,
    >(permutation, input, &public_outputs);

    let prove_backend = ProveOnlyBackend(backend.clone());
    let prove_relation = relation::PreparedRelation::new(&prove_backend, &instance);
    let prove_witness = prove_relation.prepare_witness(&witness);
    let proof = prove_relation.prove(&prove_backend, &prove_witness);
    let verify_backend = VerifyOnlyBackend(backend);
    let verify_relation = relation::PreparedRelation::new(&verify_backend, &instance);
    let verify_result = verify_relation.verify(&verify_backend, &proof);
    assert!(verify_result.is_ok(), "{verify_result:?}");
}

#[cfg(all(feature = "poseidon2", feature = "p3-baby-bear"))]
#[test]
fn poseidon2_16_relation_proof_without_linear_equations_lw2() {
    type B = BabyBearPoseidon2_16;

    let backend = B::new();
    let permutation = BabyBearPoseidon2_16::new();
    let input = sample_input::<RelationField<B, POSEIDON2_16_WIDTH>, POSEIDON2_16_WIDTH>();
    let expected_output = permutation.permute(&input);
    let public_outputs = Vec::from([
        (1usize, expected_output[1]),
        (2usize, expected_output[2]),
        (3usize, expected_output[3]),
    ]);

    let instance = PermutationInstanceBuilder::<
        RelationField<B, POSEIDON2_16_WIDTH>,
        POSEIDON2_16_WIDTH,
    >::new();
    let witness =
        PermutationWitnessBuilder::<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH>::new(permutation);

    let input_vars = instance
        .allocator()
        .allocate_public::<POSEIDON2_16_WIDTH>(&input);
    let output_vars = instance.allocate_permutation(&input_vars);
    let _output_vals = witness.allocate_permutation(&input);

    instance.allocator().set_public_vars(
        public_outputs.iter().map(|(idx, _)| output_vars[*idx]),
        public_outputs.iter().map(|(_, val)| *val),
    );

    let (relation, proof) = prove_relation(&backend, &instance, &witness);
    assert!(relation.verify(&backend, &proof).is_ok());
}

#[cfg(all(feature = "poseidon2", feature = "p3-baby-bear"))]
#[test]
fn poseidon2_16_relation_proof_with_two_nonzero_linear_terms_lw2() {
    type B = BabyBearPoseidon2_16;

    let backend = B::new();
    let permutation = BabyBearPoseidon2_16::new();
    let input = sample_input::<RelationField<B, POSEIDON2_16_WIDTH>, POSEIDON2_16_WIDTH>();
    let expected_output = permutation.permute(&input);
    let public_outputs = Vec::from([
        (1usize, expected_output[1]),
        (2usize, expected_output[2]),
        (3usize, expected_output[3]),
    ]);

    let instance = PermutationInstanceBuilder::<
        RelationField<B, POSEIDON2_16_WIDTH>,
        POSEIDON2_16_WIDTH,
    >::new();
    let witness =
        PermutationWitnessBuilder::<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH>::new(permutation);

    let input_vars = instance
        .allocator()
        .allocate_public::<POSEIDON2_16_WIDTH>(&input);
    let output_vars = instance.allocate_permutation(&input_vars);
    let output_vals = witness.allocate_permutation(&input);

    instance.allocator().set_public_vars(
        public_outputs.iter().map(|(idx, _)| output_vars[*idx]),
        public_outputs.iter().map(|(_, val)| *val),
    );

    let image = output_vals[0]
        + <RelationField<B, POSEIDON2_16_WIDTH> as PrimeCharacteristicRing>::from_u8(7)
            * output_vals[1];
    instance.add_equation(LinearEquation::new(
        [
            (
                <RelationField<B, POSEIDON2_16_WIDTH> as PrimeCharacteristicRing>::ONE,
                output_vars[0],
            ),
            (
                <RelationField<B, POSEIDON2_16_WIDTH> as PrimeCharacteristicRing>::from_u8(7),
                output_vars[1],
            ),
        ],
        image,
    ));
    witness.add_equation(LinearEquation::new(
        [
            (
                <RelationField<B, POSEIDON2_16_WIDTH> as PrimeCharacteristicRing>::ONE,
                output_vals[0],
            ),
            (
                <RelationField<B, POSEIDON2_16_WIDTH> as PrimeCharacteristicRing>::from_u8(7),
                output_vals[1],
            ),
        ],
        image,
    ));

    let (relation, proof) = prove_relation(&backend, &instance, &witness);
    assert!(relation.verify(&backend, &proof).is_ok());
}

#[cfg(all(feature = "poseidon2", feature = "p3-baby-bear"))]
#[test]
fn poseidon2_16_relation_supports_mixed_width_linear_equations() {
    type B = BabyBearPoseidon2_16;

    let backend = B::new();
    let permutation = backend.permutation();
    let input = sample_input::<RelationField<B, POSEIDON2_16_WIDTH>, POSEIDON2_16_WIDTH>();
    let expected_output = permutation.permute(&input);
    let public_outputs = Vec::from([(1usize, expected_output[1])]);
    let (instance, witness) = build_relation_instance_and_witness::<B, _, POSEIDON2_16_WIDTH, 1>(
        permutation,
        input,
        &public_outputs,
    );
    let output_vars = instance.constraints().as_ref()[0].output;
    let output_vals = witness.trace().as_ref()[0].output;
    let image = output_vals[2]
        + <RelationField<B, POSEIDON2_16_WIDTH> as PrimeCharacteristicRing>::from_u8(9)
            * output_vals[3];

    instance.add_equation(LinearEquation::new(
        [
            (
                <RelationField<B, POSEIDON2_16_WIDTH> as PrimeCharacteristicRing>::ONE,
                output_vars[2],
            ),
            (
                <RelationField<B, POSEIDON2_16_WIDTH> as PrimeCharacteristicRing>::from_u8(9),
                output_vars[3],
            ),
        ],
        image,
    ));
    witness.add_equation(LinearEquation::new(
        [
            (
                <RelationField<B, POSEIDON2_16_WIDTH> as PrimeCharacteristicRing>::ONE,
                output_vals[2],
            ),
            (
                <RelationField<B, POSEIDON2_16_WIDTH> as PrimeCharacteristicRing>::from_u8(9),
                output_vals[3],
            ),
        ],
        image,
    ));

    let (relation, proof) = prove_relation(&backend, &instance, &witness);
    assert!(relation.verify(&backend, &proof).is_ok());
}

#[cfg(all(feature = "poseidon2", feature = "p3-baby-bear"))]
#[test]
fn poseidon2_16_relation_supports_large_relation() {
    type B = BabyBearPoseidon2_16;

    let backend = B::new();
    let permutation = backend.permutation();
    let instance = PermutationInstanceBuilder::<
        RelationField<B, POSEIDON2_16_WIDTH>,
        POSEIDON2_16_WIDTH,
    >::new();
    let witness =
        PermutationWitnessBuilder::<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH>::new(permutation);

    for case_idx in 0..17 {
        let input = core::array::from_fn(|i| {
            RelationField::<B, POSEIDON2_16_WIDTH>::from_usize(case_idx * 31 + i + 1)
        });
        let input_vars = instance
            .allocator()
            .allocate_public::<POSEIDON2_16_WIDTH>(&input);
        let output_vars = instance.allocate_permutation(&input_vars);
        let output_vals = witness.allocate_permutation(&input);
        instance.allocator().set_public_vars(
            [output_vars[case_idx % POSEIDON2_16_WIDTH]],
            [output_vals[case_idx % POSEIDON2_16_WIDTH]],
        );
        instance.add_equation(LinearEquation::new(
            [(
                <RelationField<B, POSEIDON2_16_WIDTH> as PrimeCharacteristicRing>::ONE,
                output_vars[0],
            )],
            output_vals[0],
        ));
        witness.add_equation(LinearEquation::new(
            [(
                <RelationField<B, POSEIDON2_16_WIDTH> as PrimeCharacteristicRing>::ONE,
                output_vals[0],
            )],
            output_vals[0],
        ));
    }

    let (relation, proof) = prove_relation(&backend, &instance, &witness);
    assert!(relation.verify(&backend, &proof).is_ok());
}

#[cfg(all(feature = "poseidon2", feature = "p3-baby-bear"))]
#[test]
fn poseidon2_16_relation_does_not_revalidate_witness_linear_coefficients() {
    type B = BabyBearPoseidon2_16;

    let backend = B::new();
    let permutation = backend.permutation();
    let input = sample_input::<RelationField<B, POSEIDON2_16_WIDTH>, POSEIDON2_16_WIDTH>();
    let output = permutation.permute(&input);
    let instance = PermutationInstanceBuilder::<
        RelationField<B, POSEIDON2_16_WIDTH>,
        POSEIDON2_16_WIDTH,
    >::new();
    let witness =
        PermutationWitnessBuilder::<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH>::new(permutation);
    let input_vars = instance
        .allocator()
        .allocate_public::<POSEIDON2_16_WIDTH>(&input);
    let output_vars = instance.allocate_permutation(&input_vars);
    let output_vals = witness.allocate_permutation(&input);
    instance.add_equation(LinearEquation::new(
        [(
            <RelationField<B, POSEIDON2_16_WIDTH> as PrimeCharacteristicRing>::ONE,
            output_vars[0],
        )],
        output[0],
    ));
    witness.add_equation(LinearEquation::new(
        [(
            <RelationField<B, POSEIDON2_16_WIDTH> as PrimeCharacteristicRing>::from_u8(2),
            output_vals[0],
        )],
        output[0],
    ));

    let (relation, proof) = prove_relation(&backend, &instance, &witness);
    assert!(relation.verify(&backend, &proof).is_ok());
}

#[cfg(all(feature = "poseidon2", feature = "p3-baby-bear"))]
#[test]
fn poseidon2_16_relation_does_not_revalidate_witness_linear_images() {
    type B = BabyBearPoseidon2_16;

    let backend = B::new();
    let permutation = backend.permutation();
    let input = sample_input::<RelationField<B, POSEIDON2_16_WIDTH>, POSEIDON2_16_WIDTH>();
    let instance = PermutationInstanceBuilder::<
        RelationField<B, POSEIDON2_16_WIDTH>,
        POSEIDON2_16_WIDTH,
    >::new();
    let witness =
        PermutationWitnessBuilder::<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH>::new(permutation);
    let input_vars = instance
        .allocator()
        .allocate_public::<POSEIDON2_16_WIDTH>(&input);
    let output_vars = instance.allocate_permutation(&input_vars);
    let output_vals = witness.allocate_permutation(&input);
    instance.add_equation(LinearEquation::new(
        [(
            <RelationField<B, POSEIDON2_16_WIDTH> as PrimeCharacteristicRing>::ONE,
            output_vars[0],
        )],
        output_vals[0],
    ));
    witness.add_equation(LinearEquation::new(
        [(
            <RelationField<B, POSEIDON2_16_WIDTH> as PrimeCharacteristicRing>::ONE,
            output_vals[0],
        )],
        output_vals[0] + <RelationField<B, POSEIDON2_16_WIDTH> as PrimeCharacteristicRing>::ONE,
    ));

    let (relation, proof) = prove_relation(&backend, &instance, &witness);
    assert!(relation.verify(&backend, &proof).is_ok());
}

#[cfg(all(feature = "poseidon2", feature = "p3-baby-bear"))]
#[test]
fn poseidon2_16_relation_rejects_witness_coefficients_changed_to_satisfy_false_relation() {
    type B = BabyBearPoseidon2_16;

    let backend = B::new();
    let permutation = backend.permutation();
    let input = sample_input::<RelationField<B, POSEIDON2_16_WIDTH>, POSEIDON2_16_WIDTH>();
    let instance = PermutationInstanceBuilder::<
        RelationField<B, POSEIDON2_16_WIDTH>,
        POSEIDON2_16_WIDTH,
    >::new();
    let witness =
        PermutationWitnessBuilder::<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH>::new(permutation);
    let input_vars = instance
        .allocator()
        .allocate_public::<POSEIDON2_16_WIDTH>(&input);
    let output_vars = instance.allocate_permutation(&input_vars);
    let output_vals = witness.allocate_permutation(&input);
    let false_image =
        output_vals[0] + <RelationField<B, POSEIDON2_16_WIDTH> as PrimeCharacteristicRing>::ONE;
    instance.add_equation(LinearEquation::new(
        [(
            <RelationField<B, POSEIDON2_16_WIDTH> as PrimeCharacteristicRing>::ONE,
            output_vars[0],
        )],
        false_image,
    ));
    witness.add_equation(LinearEquation::new(
        [(
            <RelationField<B, POSEIDON2_16_WIDTH> as PrimeCharacteristicRing>::ZERO,
            output_vals[0],
        )],
        false_image,
    ));

    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let (relation, proof) = prove_relation(&backend, &instance, &witness);
        relation.verify(&backend, &proof).is_err()
    }))
    .unwrap_or(true);
    assert!(rejected);
}

#[cfg(all(feature = "poseidon2", feature = "p3-baby-bear"))]
#[test]
fn poseidon2_16_relation_supports_reused_secret_inputs() {
    type B = BabyBearPoseidon2_16;
    let backend = B::new();
    let permutation = BabyBearPoseidon2_16::new();
    let input = sample_input::<RelationField<B, POSEIDON2_16_WIDTH>, POSEIDON2_16_WIDTH>();
    let expected_output = permutation.permute(&input);

    let instance = PermutationInstanceBuilder::<
        RelationField<B, POSEIDON2_16_WIDTH>,
        POSEIDON2_16_WIDTH,
    >::new();
    let witness = PermutationWitnessBuilder::<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH>::new(
        permutation.clone(),
    );

    let shared_input_vars = instance.allocator().allocate_vars::<POSEIDON2_16_WIDTH>();
    let output_vars_a = instance.allocate_permutation(&shared_input_vars);
    let output_vals_a = witness.allocate_permutation(&input);
    let output_vars_b = instance.allocate_permutation(&shared_input_vars);
    let output_vals_b = witness.allocate_permutation(&input);

    instance.allocator().set_public_vars(
        [(1usize, output_vars_a[1]), (2usize, output_vars_b[2])]
            .into_iter()
            .map(|(_, var)| var),
        [expected_output[1], expected_output[2]],
    );

    instance.add_equation(LinearEquation::new(
        core::iter::once((
            <RelationField<B, POSEIDON2_16_WIDTH> as PrimeCharacteristicRing>::ONE,
            output_vars_a[0],
        )),
        output_vals_a[0],
    ));
    witness.add_equation(LinearEquation::new(
        core::iter::once((
            <RelationField<B, POSEIDON2_16_WIDTH> as PrimeCharacteristicRing>::ONE,
            output_vals_a[0],
        )),
        output_vals_a[0],
    ));
    instance.add_equation(LinearEquation::new(
        core::iter::once((
            <RelationField<B, POSEIDON2_16_WIDTH> as PrimeCharacteristicRing>::ONE,
            output_vars_b[0],
        )),
        output_vals_b[0],
    ));
    witness.add_equation(LinearEquation::new(
        core::iter::once((
            <RelationField<B, POSEIDON2_16_WIDTH> as PrimeCharacteristicRing>::ONE,
            output_vals_b[0],
        )),
        output_vals_b[0],
    ));

    let (relation, proof) = prove_relation(&backend, &instance, &witness);
    assert!(relation.verify(&backend, &proof).is_ok());
}

#[cfg(all(feature = "poseidon2", feature = "p3-baby-bear"))]
#[test]
fn poseidon2_16_relation_rejects_reused_secret_inputs_with_inconsistent_witness_values() {
    type B = BabyBearPoseidon2_16;
    let backend = B::new();
    let permutation = BabyBearPoseidon2_16::new();
    let input_a = sample_input::<RelationField<B, POSEIDON2_16_WIDTH>, POSEIDON2_16_WIDTH>();
    let mut input_b = input_a;
    input_b[0] += <RelationField<B, POSEIDON2_16_WIDTH> as PrimeCharacteristicRing>::ONE;

    let instance = PermutationInstanceBuilder::<
        RelationField<B, POSEIDON2_16_WIDTH>,
        POSEIDON2_16_WIDTH,
    >::new();
    let witness = PermutationWitnessBuilder::<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH>::new(
        permutation.clone(),
    );

    let shared_input_vars = instance.allocator().allocate_vars::<POSEIDON2_16_WIDTH>();
    let _ = instance.allocate_permutation(&shared_input_vars);
    let _ = witness.allocate_permutation(&input_a);
    let _ = instance.allocate_permutation(&shared_input_vars);
    let _ = witness.allocate_permutation(&input_b);

    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let (relation, proof) = prove_relation(&backend, &instance, &witness);
        relation.verify(&backend, &proof).is_err()
    }))
    .unwrap_or(true);
    assert!(rejected);
}

#[cfg(all(feature = "keccak256", feature = "p3-baby-bear"))]
#[test]
fn keccak256_single_block_vectors_match_reference() {
    use crate::permutation::keccak::{BabyBearKeccakF1600, KeccakF1600Permutation};

    type B = BabyBearKeccakF1600;
    let permutation = KeccakF1600Permutation::<RelationField<B, KECCAK_WIDTH>>::default();

    for (message, expected_digest) in KECCAK256_PREIMAGE_VECTORS {
        let input = keccak256_single_block_input::<RelationField<B, KECCAK_WIDTH>>(message);
        let output = permutation.permute(&input);
        assert_eq!(
            keccak256_digest_from_state(&output),
            expected_digest,
            "Keccak-256 digest mismatch for message {message:?}"
        );
    }
}

#[cfg(all(feature = "keccak256", feature = "p3-baby-bear"))]
#[test]
fn keccak256_hash_relation_keeps_secret_preimages_private() {
    use crate::permutation::keccak::{BabyBearKeccakF1600, KeccakF1600Permutation, KECCAK_WIDTH};

    type B = BabyBearKeccakF1600;
    let cases = keccak256_vector_cases::<B>();

    let (instance, witness) =
        build_private_input_relation_instance_and_witness::<B, _, KECCAK_WIDTH, TEST_LINEAR_WIDTH>(
            KeccakF1600Permutation::<RelationField<B, KECCAK_WIDTH>>::default(),
            vec![cases[0].clone()],
        );

    let public_vars = instance.public_vars();
    assert_eq!(public_vars.len(), 1 + 16);
    assert!(public_vars
        .iter()
        .all(|(var, _)| var.index() == 0 || var.index() > KECCAK_WIDTH));

    let witness_trace = witness.trace();
    let output = witness_trace.as_ref()[0].output;
    assert_eq!(
        keccak256_digest_from_state(&output),
        KECCAK256_PREIMAGE_VECTORS[0].1
    );
}

#[cfg(all(feature = "keccak256", feature = "p3-baby-bear"))]
#[test]
#[ignore = "too slow for the default test suite"]
fn keccak256_secret_preimages_match_documented_vectors_in_one_proof() {
    use crate::permutation::keccak::{BabyBearKeccakF1600, KECCAK_WIDTH};

    type B = BabyBearKeccakF1600;
    let backend = B::default();
    let permutation = backend.permutation();

    let cases = keccak256_vector_cases::<B>();
    let (instance, witness) =
        build_private_input_relation_instance_and_witness::<B, _, KECCAK_WIDTH, TEST_LINEAR_WIDTH>(
            permutation,
            cases.clone(),
        );

    // Only the digest limbs should be public, not the 100-limb padded preimages.
    assert_eq!(
        instance.public_vars().len(),
        1 + 16 * KECCAK256_PREIMAGE_VECTORS.len()
    );

    let (relation, proof) = prove_relation(&backend, &instance, &witness);
    assert!(relation.verify(&backend, &proof).is_ok());

    let mut bad_cases = cases;
    bad_cases[0].1[0].1 += <RelationField<B, KECCAK_WIDTH> as PrimeCharacteristicRing>::ONE;
    let (bad_instance, _) =
        build_private_input_relation_instance_and_witness::<B, _, KECCAK_WIDTH, TEST_LINEAR_WIDTH>(
            backend.permutation(),
            bad_cases,
        );
    let bad_relation = relation::PreparedRelation::new(&backend, &bad_instance);
    assert!(bad_relation.verify(&backend, &proof).is_err());

    let mut bad_proof = proof;
    bad_proof[0] ^= 0x01;
    assert!(relation.verify(&backend, &bad_proof).is_err());
}

#[cfg(all(feature = "keccak256", feature = "p3-baby-bear"))]
#[test]
fn keccak_relation_rejects_non_16_bit_inputs() {
    use crate::permutation::keccak::{BabyBearKeccakF1600, KECCAK_WIDTH};

    type B = BabyBearKeccakF1600;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let backend = B::default();
        let permutation = backend.permutation();
        let input = core::array::from_fn(|i| {
            if i == 0 {
                RelationField::<B, KECCAK_WIDTH>::from_u32(1 << 20)
            } else {
                RelationField::<B, KECCAK_WIDTH>::from_u16(i as u16)
            }
        });
        let public_outputs = Vec::from([
            (
                1usize,
                <RelationField<B, KECCAK_WIDTH> as PrimeCharacteristicRing>::ZERO,
            ),
            (
                2usize,
                <RelationField<B, KECCAK_WIDTH> as PrimeCharacteristicRing>::ZERO,
            ),
            (
                3usize,
                <RelationField<B, KECCAK_WIDTH> as PrimeCharacteristicRing>::ZERO,
            ),
        ]);
        let (instance, witness) = build_relation_instance_and_witness::<
            B,
            _,
            KECCAK_WIDTH,
            TEST_LINEAR_WIDTH,
        >(permutation, input, &public_outputs);
        prove_relation(&backend, &instance, &witness)
    }));
    assert!(result.is_err());
}

#[cfg(all(feature = "poseidon2", feature = "p3-baby-bear"))]
#[test]
fn poseidon2_16_relation_rejects_wrong_witness_outputs() {
    let backend = BabyBearPoseidon2_16::new();
    let permutation = BabyBearPoseidon2_16::new();
    let input = sample_input::<
        RelationField<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH>,
        POSEIDON2_16_WIDTH,
    >();
    let expected_output = permutation.permute(&input);

    let instance = PermutationInstanceBuilder::<
        RelationField<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH>,
        POSEIDON2_16_WIDTH,
    >::new();
    let witness =
        PermutationWitnessBuilder::<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH>::new(permutation);

    let input_vars = instance
        .allocator()
        .allocate_public::<POSEIDON2_16_WIDTH>(&input);
    let output_vars = instance.allocate_permutation(&input_vars);
    let mut wrong_output_vals = expected_output;
    wrong_output_vals[0] +=
        <RelationField<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH> as PrimeCharacteristicRing>::ONE;
    witness.add_permutation(&input, &wrong_output_vals);

    instance.allocator().set_public_vars(
        [
            (1usize, output_vars[1]),
            (2usize, output_vars[2]),
            (3usize, output_vars[3]),
        ]
        .into_iter()
        .map(|(_, var)| var),
        [expected_output[1], expected_output[2], expected_output[3]],
    );

    instance.add_equation(LinearEquation::new(
        core::iter::once((
            <RelationField<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH> as PrimeCharacteristicRing>::ONE,
            output_vars[0],
        )),
        expected_output[0],
    ));
    witness.add_equation(LinearEquation::new(
        core::iter::once((
            <RelationField<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH> as PrimeCharacteristicRing>::ONE,
            wrong_output_vals[0],
        )),
        wrong_output_vals[0],
    ));

    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let (relation, proof) = prove_relation(&backend, &instance, &witness);
        relation.verify(&backend, &proof).is_err()
    }))
    .unwrap_or(true);
    assert!(rejected);
}

#[cfg(all(feature = "poseidon2", feature = "p3-baby-bear"))]
#[test]
fn poseidon2_16_relation_allows_empty_linear_equations() {
    let backend = BabyBearPoseidon2_16::new();
    let permutation = BabyBearPoseidon2_16::new();
    let input = sample_input::<
        RelationField<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH>,
        POSEIDON2_16_WIDTH,
    >();

    let instance = PermutationInstanceBuilder::<
        RelationField<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH>,
        POSEIDON2_16_WIDTH,
    >::new();
    let witness =
        PermutationWitnessBuilder::<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH>::new(permutation);

    let input_vars = instance
        .allocator()
        .allocate_public::<POSEIDON2_16_WIDTH>(&input);
    let _ = instance.allocate_permutation(&input_vars);
    let _ = witness.allocate_permutation(&input);

    instance.add_equation(LinearEquation::new(
        core::iter::empty::<(
            RelationField<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH>,
            FieldVar,
        )>(),
        <RelationField<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH> as PrimeCharacteristicRing>::ZERO,
    ));
    witness.add_equation(LinearEquation::new(
        [(
            <RelationField<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH> as PrimeCharacteristicRing>::ZERO,
            <RelationField<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH> as PrimeCharacteristicRing>::ZERO,
        )],
        <RelationField<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH> as PrimeCharacteristicRing>::ZERO,
    ));

    let (relation, proof) = prove_relation(&backend, &instance, &witness);
    assert!(relation.verify(&backend, &proof).is_ok());
}

#[cfg(all(feature = "poseidon2", feature = "p3-baby-bear"))]
#[test]
#[should_panic(
    expected = "nonzero linear terms must reference a permutation input or output variable"
)]
fn poseidon2_16_relation_panics_on_unbound_linear_variable() {
    let backend = BabyBearPoseidon2_16::new();
    let permutation = BabyBearPoseidon2_16::new();
    let input = sample_input::<
        RelationField<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH>,
        POSEIDON2_16_WIDTH,
    >();

    let instance = PermutationInstanceBuilder::<
        RelationField<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH>,
        POSEIDON2_16_WIDTH,
    >::new();
    let witness =
        PermutationWitnessBuilder::<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH>::new(permutation);

    let input_vars = instance
        .allocator()
        .allocate_public::<POSEIDON2_16_WIDTH>(&input);
    let _ = instance.allocate_permutation(&input_vars);
    let _ = witness.allocate_permutation(&input);

    instance.add_equation(LinearEquation::new(
        [(
            <RelationField<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH> as PrimeCharacteristicRing>::ONE,
            instance.allocator().new_field_var(),
        )],
        <RelationField<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH> as PrimeCharacteristicRing>::ZERO,
    ));
    witness.add_equation(LinearEquation::new(
        [(
            <RelationField<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH> as PrimeCharacteristicRing>::ONE,
            <RelationField<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH> as PrimeCharacteristicRing>::ZERO,
        )],
        <RelationField<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH> as PrimeCharacteristicRing>::ZERO,
    ));

    let _ = prove_relation(&backend, &instance, &witness);
}

#[cfg(all(feature = "poseidon2", feature = "p3-baby-bear"))]
#[test]
fn poseidon2_16_relation_uses_spongefish_public_assignment_semantics() {
    let backend = BabyBearPoseidon2_16::new();
    let input = sample_input::<
        RelationField<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH>,
        POSEIDON2_16_WIDTH,
    >();

    let instance = PermutationInstanceBuilder::<
        RelationField<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH>,
        POSEIDON2_16_WIDTH,
    >::new();
    let input_vars = instance
        .allocator()
        .allocate_public::<POSEIDON2_16_WIDTH>(&input);
    instance.allocator().set_public_var(input_vars[0], input[0]);
    let _ = instance.allocate_permutation(&input_vars);

    let public_vars = instance.public_vars();
    assert_eq!(
        public_vars
            .iter()
            .filter(|(var, _)| *var == input_vars[0])
            .count(),
        1
    );
    let _ = relation::PreparedRelation::new(&backend, &instance);
}

#[cfg(all(feature = "poseidon2", feature = "p3-baby-bear"))]
#[test]
#[should_panic(expected = "permutation count mismatch")]
fn poseidon2_16_relation_rejects_missing_witness_permutation() {
    let backend = BabyBearPoseidon2_16::new();
    let permutation = BabyBearPoseidon2_16::new();
    let input = sample_input::<
        RelationField<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH>,
        POSEIDON2_16_WIDTH,
    >();

    let instance = PermutationInstanceBuilder::<
        RelationField<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH>,
        POSEIDON2_16_WIDTH,
    >::new();
    let witness =
        PermutationWitnessBuilder::<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH>::new(permutation);
    let input_vars = instance
        .allocator()
        .allocate_public::<POSEIDON2_16_WIDTH>(&input);
    let _ = instance.allocate_permutation(&input_vars);

    let relation = relation::PreparedRelation::new(&backend, &instance);
    let _ = relation.prepare_witness(&witness);
}

#[cfg(all(feature = "poseidon2", feature = "p3-baby-bear"))]
#[test]
fn poseidon2_16_relation_rejects_wrong_degree_without_panicking() {
    type B = BabyBearPoseidon2_16;

    let backend = B::new();
    let permutation = backend.permutation();
    let input = sample_input::<RelationField<B, POSEIDON2_16_WIDTH>, POSEIDON2_16_WIDTH>();
    let output = permutation.permute(&input);
    let (instance, witness) = build_relation_instance_and_witness::<
        B,
        _,
        POSEIDON2_16_WIDTH,
        TEST_LINEAR_WIDTH,
    >(permutation, input, &[(0, output[0])]);
    let (relation, proof) = prove_relation(&backend, &instance, &witness);

    let mut proof = postcard::from_bytes::<
        p3_batch_stark::BatchProof<<B as HashRelationBackend<POSEIDON2_16_WIDTH>>::Config>,
    >(&proof)
    .expect("proof should deserialize");
    proof.degree_bits[0] += 1;
    let proof = postcard::to_allocvec(&proof).expect("proof should serialize");

    assert!(relation.verify(&backend, &proof).is_err());
}
