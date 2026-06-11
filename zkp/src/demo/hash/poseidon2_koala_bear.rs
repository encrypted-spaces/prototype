use alloc::{vec, vec::Vec};

use encrypted_spaces_crypto::P2_16_CONFIG;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{HidingFriPcs, TwoAdicFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_koala_bear::{GenericPoseidon2LinearLayersKoalaBear, KoalaBear};
use p3_merkle_tree::{MerkleTreeHidingMmcs, MerkleTreeMmcs};
use p3_poseidon2_air::{Poseidon2Air, RoundConstants};
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
use p3_uni_stark::{prove, verify, StarkConfig};
use rand_10::rngs::SmallRng;
use rand_10::SeedableRng;
use spongefish_stark::security_profile::{Conservative, SecurityProfile};

const WIDTH: usize = P2_16_CONFIG.width;
const SBOX_DEGREE: u64 = 3;
const SBOX_REGISTERS: usize = P2_16_CONFIG.sbox_registers;
const HALF_FULL_ROUNDS: usize = P2_16_CONFIG.half_full_rounds;
const PARTIAL_ROUNDS: usize = P2_16_CONFIG.partial_rounds;

#[cfg(feature = "parallel")]
type Dft = p3_dft::Radix2DitParallel<KoalaBear>;
#[cfg(not(feature = "parallel"))]
type Dft = p3_dft::Radix2Bowers;

pub fn poseidon2_koala_bear(batch_size: usize) -> Vec<u8> {
    type Val = KoalaBear;
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

    type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
    let challenger = Challenger::from_hasher(vec![], byte_hash);

    // WARNING: DO NOT USE SmallRng in proper applications! Use a real PRNG instead!
    let mut rng = SmallRng::seed_from_u64(1);
    let constants = RoundConstants::from_rng(&mut rng);
    let air: Poseidon2Air<
        Val,
        GenericPoseidon2LinearLayersKoalaBear,
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
    tracing::info!("Batch size: {}", batch_size);
    let serialized = postcard::to_allocvec(&proof).unwrap();
    // // //     let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    // // // //     encoder.write_all(&serialized).unwrap();
    // // // //     let compressed = encoder.finish().unwrap();
    // // // //     tracing::info!("Serialized size (gzipped): {}", compressed.len());

    verify(&config, &air, &proof, &[]).unwrap();

    serialized
}

pub fn poseidon2_koala_bear_zk(batch_size: usize) -> Vec<u8> {
    type Val = KoalaBear;
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
    let val_mmcs = ValMmcs::new(field_hash, compress, 0, rng);

    type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
    let challenger = Challenger::from_hasher(vec![], byte_hash);

    // WARNING: DO NOT USE SmallRng in proper applications! Use a real PRNG instead!
    let mut rng = SmallRng::seed_from_u64(1);
    let constants = RoundConstants::from_rng(&mut rng);
    let air: Poseidon2Air<
        Val,
        GenericPoseidon2LinearLayersKoalaBear,
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
