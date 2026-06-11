use alloc::{vec, vec::Vec};

use p3_blake3_air::{generate_trace_rows, Blake3Air};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{HidingFriPcs, TwoAdicFriPcs};
use p3_koala_bear::KoalaBear;
use p3_merkle_tree::{MerkleTreeHidingMmcs, MerkleTreeMmcs};
use p3_sha256::Sha256;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::{prove, verify, StarkConfig};
use rand_10::rngs::SmallRng;
use rand_10::{RngExt, SeedableRng};
use spongefish_stark::security_profile::{Conservative, SecurityProfile};

#[cfg(feature = "parallel")]
type Dft = p3_dft::Radix2DitParallel<KoalaBear>;
#[cfg(not(feature = "parallel"))]
type Dft = p3_dft::Radix2Bowers;

pub fn blake3_koala_bear(batch_size: usize) -> Vec<u8> {
    type Val = KoalaBear;
    type Challenge = BinomialExtensionField<Val, 4>;

    type ByteHash = Sha256;
    type FieldHash = SerializingHasher<ByteHash>;
    let byte_hash = ByteHash {};
    let field_hash = FieldHash::new(Sha256);

    type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
    let compress = MyCompress::new(byte_hash);

    type ValMmcs = MerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 2, 32>;
    let val_mmcs = ValMmcs::new(field_hash, compress, 0);

    type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    let dft = Dft::default();

    type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
    let challenger = Challenger::from_hasher(vec![], byte_hash);

    let fri_params = Conservative::security_parameters().fri_params_zk(challenge_mmcs);

    // Generate random Blake3 inputs (24 u32s per hash)
    let mut rng = SmallRng::seed_from_u64(1);
    let inputs: Vec<[u32; 24]> = (0..batch_size).map(|_| rng.random::<[u32; 24]>()).collect();

    let trace = generate_trace_rows::<Val>(inputs, fri_params.log_blowup);

    type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
    let pcs = Pcs::new(dft, val_mmcs, fri_params);

    type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;
    let config = MyConfig::new(pcs, challenger);

    let proof = prove(&config, &Blake3Air {}, trace, &[]);

    let serialized = postcard::to_allocvec(&proof).unwrap();
    // // //     let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    // // // //     encoder.write_all(&serialized).unwrap();
    // // // //     let compressed = encoder.finish().unwrap();
    // // // //     tracing::info!("Serialized size (gzipped): {}", compressed.len());
    tracing::info!("Batch size: {}", batch_size);

    verify(&config, &Blake3Air {}, &proof, &[]).unwrap();

    serialized
}

pub fn blake3_koala_bear_zk(batch_size: usize) -> Vec<u8> {
    type Val = KoalaBear;
    type Challenge = BinomialExtensionField<Val, 4>;

    type ByteHash = Sha256;
    type FieldHash = SerializingHasher<ByteHash>;
    let byte_hash = ByteHash {};
    let field_hash = FieldHash::new(Sha256);

    type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
    let compress = MyCompress::new(byte_hash);

    // WARNING: DO NOT USE ChaCha20Rng in proper applications! Use a real PRNG instead!
    type ValMmcs = MerkleTreeHidingMmcs<Val, u8, FieldHash, MyCompress, SmallRng, 2, 32, 32>;
    let rng = SmallRng::seed_from_u64(1);
    let val_mmcs = ValMmcs::new(field_hash, compress, 0, rng);

    type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    let dft = Dft::default();

    type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
    let challenger = Challenger::from_hasher(vec![], byte_hash);

    let fri_params = Conservative::security_parameters().fri_params_zk(challenge_mmcs);

    // Generate random Blake3 inputs (24 u32s per hash)
    let mut rng = SmallRng::seed_from_u64(1);
    let inputs: Vec<[u32; 24]> = (0..batch_size).map(|_| rng.random::<[u32; 24]>()).collect();

    let trace = generate_trace_rows::<Val>(inputs, fri_params.log_blowup);

    type Pcs = HidingFriPcs<Val, Dft, ValMmcs, ChallengeMmcs, SmallRng>;
    let pcs = Pcs::new(dft, val_mmcs, fri_params, 32, SmallRng::seed_from_u64(1));

    type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;
    let config = MyConfig::new(pcs, challenger);

    let proof = prove(&config, &Blake3Air {}, trace, &[]);

    // Print proof statistics
    let serialized = postcard::to_allocvec(&proof).unwrap();
    // // //     let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    // // // //     encoder.write_all(&serialized).unwrap();
    // // // //     let compressed = encoder.finish().unwrap();
    // // // //     tracing::info!("Serialized size (gzipped): {}", compressed.len());
    tracing::info!("Batch size: {}", batch_size);
    verify(&config, &Blake3Air {}, &proof, &[]).unwrap();

    serialized
}
