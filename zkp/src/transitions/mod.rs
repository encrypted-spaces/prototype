use std::collections::HashMap;

use encrypted_spaces_crypto::algebraic_encoding::KEYMATERIAL_LIMBS;
use encrypted_spaces_crypto::key_derivation::poseidon2::{
    HASHBLOCK_COM_RANGE, HASHBLOCK_KEY_RANGE, HASHBLOCK_TAG_RANGE,
};
use encrypted_spaces_crypto::{DerivationKoalaBearPoseidon2_16, KeyMaterial};
use p3_koala_bear::KoalaBear;
use spongefish::VerificationError;
use spongefish_circuit::permutation::{PermutationInstanceBuilder, PermutationWitnessBuilder};
use spongefish_stark::{
    permutation::poseidon2::{KoalaBearPoseidon2_16, POSEIDON2_16_WIDTH},
    relation::PreparedRelation,
};

mod canonical_path;
mod relation;
mod witness;

pub use canonical_path::CanonicalPath;
use relation::TransitionInstanceBuilder;
pub use relation::{KeyTreeOp, KeyTreeTransition};
use witness::TransitionWitnessBuilder;

type RelationInstance = PermutationInstanceBuilder<KoalaBear, POSEIDON2_16_WIDTH>;
type RelationWitness = PermutationWitnessBuilder<KoalaBearPoseidon2_16, POSEIDON2_16_WIDTH>;

pub fn prove_transition(
    derivation: &DerivationKoalaBearPoseidon2_16,
    transition: &KeyTreeTransition,
    keys: &HashMap<CanonicalPath, KeyMaterial>,
) -> Vec<u8> {
    let instance = TransitionInstanceBuilder::new().build(transition);
    let witness = TransitionWitnessBuilder::new(derivation, keys).build(transition);
    let backend = KoalaBearPoseidon2_16::new();
    let statement = PreparedRelation::new(&backend, &instance);
    let witness = statement.prepare_witness(&witness);
    statement.prove(&backend, &witness)
}

pub fn verify_transition(
    transition: &KeyTreeTransition,
    proof: &[u8],
) -> Result<(), VerificationError> {
    let instance = TransitionInstanceBuilder::new().build(transition);
    let backend = KoalaBearPoseidon2_16::new();
    let statement = PreparedRelation::new(&backend, &instance);
    statement.verify(&backend, proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use encrypted_spaces_crypto::key_derivation::DerivationTag;
    use encrypted_spaces_crypto::{EncryptedKeyMaterial, KeyCommitment, KeyDerivation};
    use p3_field::PrimeField32;
    use p3_uni_stark::StarkGenericConfig;
    use spongefish_stark::ff::{KoalaBearConfig, KoalaBearStarkConfig};
    use spongefish_stark::security_profile::Conservative;

    #[test]
    fn test_koala_bear_poseidon2_16_derivation() {
        let derivation = DerivationKoalaBearPoseidon2_16::default();

        let key = KeyMaterial::random();
        let commitment = derivation.commit(&key);
        let tag = DerivationTag::from_bytes(b"test derivation tag");
        let derived_key = derivation.derive(&key, tag);
        let derived_commitment: KeyCommitment = derivation.commit(&derived_key);

        let parent = CanonicalPath::root();
        let child = parent.child("child");
        let mut transition = KeyTreeTransition::new();
        transition
            .commit(parent.clone(), commitment)
            .derive(parent.clone(), child.clone(), tag)
            .commit(child.clone(), derived_commitment);
        let encryption_tag = DerivationTag::from_bytes(b"test encryption tag");
        let under = derivation.derive(&derived_key, encryption_tag);
        transition.encrypt(
            child.clone(),
            child.clone(),
            encryption_tag,
            EncryptedKeyMaterial::encrypt(derived_key.clone(), &under),
        );
        let keys = HashMap::from([(parent, key), (child, derived_key)]);

        let raw_instance = TransitionInstanceBuilder::new().build(&transition);
        let min_trace_height = KoalaBearConfig::<Conservative>::hiding_trace_height();
        assert!(
            raw_instance.constraints().as_ref().len() < min_trace_height,
            "transition builders should leave deterministic padding to PreparedRelation"
        );
        let backend = KoalaBearPoseidon2_16::new();
        let statement = PreparedRelation::new(&backend, &raw_instance);
        let weighted_height_sum = statement.logup_weighted_height_sum();
        // Pin the count weights and 128-row heights for a production-shaped
        // commit/derive/encrypt relation. It retains more than 18 bits of
        // headroom before multiplicities could wrap in KoalaBear.
        assert_eq!(weighted_height_sum, 7_168);
        assert!(weighted_height_sum * (1 << 18) < u128::from(KoalaBear::ORDER_U32));

        let proof = prove_transition(&derivation, &transition, &keys);
        let decoded: p3_batch_stark::BatchProof<KoalaBearStarkConfig> =
            postcard::from_bytes(&proof).expect("valid transition proof");
        let config = KoalaBearConfig::<Conservative>::verifier_config();
        let expected_degree_bits = min_trace_height.trailing_zeros() as usize + config.is_zk();
        assert_eq!(decoded.degree_bits, vec![expected_degree_bits; 3]);
        assert!(verify_transition(&transition, &proof).is_ok());
    }
}
