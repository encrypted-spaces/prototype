use alloc::{vec, vec::Vec};

use p3_baby_bear::{
    BabyBear, GenericPoseidon2LinearLayersBabyBear, BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS,
    BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16, BABYBEAR_POSEIDON2_RC_16_EXTERNAL_FINAL,
    BABYBEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL, BABYBEAR_POSEIDON2_RC_16_INTERNAL,
    BABYBEAR_S_BOX_DEGREE,
};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{HidingFriPcs, TwoAdicFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_merkle_tree::{MerkleTreeHidingMmcs, MerkleTreeMmcs};
use p3_poseidon2_air::{Poseidon2Air, RoundConstants};
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
use p3_uni_stark::{prove, verify, StarkConfig};
use rand_10::rngs::SmallRng;
use rand_10::SeedableRng;
use spongefish_stark::security_profile::{Conservative, SecurityProfile};

const WIDTH: usize = 16;
const SBOX_DEGREE: u64 = BABYBEAR_S_BOX_DEGREE;
const SBOX_REGISTERS: usize = 0;
const HALF_FULL_ROUNDS: usize = BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS;
const PARTIAL_ROUNDS: usize = BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16;

#[cfg(feature = "parallel")]
type Dft = p3_dft::Radix2DitParallel<BabyBear>;
#[cfg(not(feature = "parallel"))]
type Dft = p3_dft::Radix2Bowers;

type BabyBearPoseidon2_16RoundConstants =
    RoundConstants<BabyBear, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>;

fn poseidon_round_constants() -> BabyBearPoseidon2_16RoundConstants {
    RoundConstants::new(
        BABYBEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL,
        BABYBEAR_POSEIDON2_RC_16_INTERNAL,
        BABYBEAR_POSEIDON2_RC_16_EXTERNAL_FINAL,
    )
}

pub fn poseidon2_baby_bear(batch_size: usize) -> Vec<u8> {
    // Print the number of threads being used
    #[cfg(feature = "parallel")]
    {
        use p3_maybe_rayon::prelude::*;
        tracing::info!(
            "Running with {} threads (rayon parallelization enabled)",
            current_num_threads()
        );
    }

    type Val = BabyBear;
    type Challenge = BinomialExtensionField<Val, 4>;

    type ByteHash = Keccak256Hash;
    let byte_hash = ByteHash {};

    type U64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
    let u64_hash = U64Hash::new(KeccakF {});

    type FieldHash = SerializingHasher<U64Hash>;
    let field_hash = FieldHash::new(u64_hash);

    type MyCompress = CompressionFunctionFromHasher<U64Hash, 2, 4>;
    let compress = MyCompress::new(u64_hash);

    type ValMmcs = MerkleTreeMmcs<
        [Val; p3_keccak::VECTOR_LEN],
        [u64; p3_keccak::VECTOR_LEN],
        FieldHash,
        MyCompress,
        2,
        4,
    >;
    let val_mmcs = ValMmcs::new(field_hash, compress, 0);
    let constants = poseidon_round_constants();

    type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
    let challenger = Challenger::from_hasher(vec![], byte_hash);

    let air: Poseidon2Air<
        Val,
        GenericPoseidon2LinearLayersBabyBear,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    > = Poseidon2Air::new(constants);

    let fri_params = Conservative::security_parameters().fri_params_zk(challenge_mmcs);

    let trace = air.generate_trace_rows(batch_size, fri_params.log_blowup);

    let dft = Dft::default();

    type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
    let pcs = Pcs::new(dft, val_mmcs, fri_params);

    type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;
    let config = MyConfig::new(pcs, challenger);

    let proof = prove(&config, &air, trace, &[]);
    let serialized = postcard::to_allocvec(&proof).unwrap();
    // // //     let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    // // // //     encoder.write_all(&serialized).unwrap();
    // // // //     let compressed = encoder.finish().unwrap();
    // // // //     tracing::info!("Serialized size (gzipped): {}", compressed.len());
    tracing::info!("Batch size: {}", batch_size);
    verify(&config, &air, &proof, &[]).unwrap();

    serialized
}

pub fn poseidon2_baby_bear_zk(batch_size: usize) -> Vec<u8> {
    type Val = BabyBear;
    type Challenge = BinomialExtensionField<Val, 4>;

    type ByteHash = Keccak256Hash;
    let byte_hash = ByteHash {};

    type U64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
    let u64_hash = U64Hash::new(KeccakF {});

    type FieldHash = SerializingHasher<U64Hash>;
    let field_hash = FieldHash::new(u64_hash);

    type MyCompress = CompressionFunctionFromHasher<U64Hash, 2, 4>;
    let compress = MyCompress::new(u64_hash);

    type ValMmcs = MerkleTreeHidingMmcs<
        [Val; p3_keccak::VECTOR_LEN],
        [u64; p3_keccak::VECTOR_LEN],
        FieldHash,
        MyCompress,
        SmallRng,
        2,
        4,
        4,
    >;
    let rng = SmallRng::seed_from_u64(1);
    let constants = poseidon_round_constants();
    let val_mmcs = ValMmcs::new(field_hash, compress, 0, rng);

    type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
    let challenger = Challenger::from_hasher(vec![], byte_hash);

    let air: Poseidon2Air<
        Val,
        GenericPoseidon2LinearLayersBabyBear,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    > = Poseidon2Air::new(constants);

    let fri_params = Conservative::security_parameters().fri_params_zk(challenge_mmcs);

    let trace = air.generate_trace_rows(batch_size, fri_params.log_blowup);

    let dft = Dft::default();

    type Pcs = HidingFriPcs<Val, Dft, ValMmcs, ChallengeMmcs, SmallRng>;
    let pcs = Pcs::new(dft, val_mmcs, fri_params, 4, SmallRng::seed_from_u64(1));

    type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;
    let config = MyConfig::new(pcs, challenger);

    let proof = prove(&config, &air, trace, &[]);
    let serialized = postcard::to_allocvec(&proof).unwrap();
    // // //     let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    // // // //     encoder.write_all(&serialized).unwrap();
    // // // //     let compressed = encoder.finish().unwrap();
    // // // //     tracing::info!("Serialized size (gzipped): {}", compressed.len());
    tracing::info!("Batch size: {}", batch_size);
    verify(&config, &air, &proof, &[]).unwrap();

    serialized
}
