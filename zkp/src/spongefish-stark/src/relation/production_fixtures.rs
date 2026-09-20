use std::collections::HashMap;

use encrypted_spaces_crypto::algebraic_encoding::KEYMATERIAL_LIMBS;
use encrypted_spaces_crypto::key_derivation::poseidon2::{
    HASHBLOCK_COM_RANGE, HASHBLOCK_KEY_RANGE, HASHBLOCK_TAG_RANGE,
};
use encrypted_spaces_crypto::key_derivation::DerivationTag;
use encrypted_spaces_crypto::{
    DerivationKoalaBearPoseidon2_16, EncryptedKeyMaterial, KeyDerivation, KeyMaterial,
};
use p3_koala_bear::KoalaBear;
use spongefish_circuit::permutation::{PermutationInstanceBuilder, PermutationWitnessBuilder};

use super::{PreparedRelation, PreparedWitness};
use crate::permutation::poseidon2::{KoalaBearPoseidon2_16, POSEIDON2_16_WIDTH};

type RelationInstance = PermutationInstanceBuilder<KoalaBear, 16>;
type RelationWitness = PermutationWitnessBuilder<KoalaBearPoseidon2_16, 16>;

#[path = "../../../transitions/canonical_path.rs"]
mod canonical_path;
#[path = "../../../transitions/relation.rs"]
mod relation;
#[path = "../../../transitions/witness.rs"]
mod witness;

use canonical_path::CanonicalPath;
use relation::{KeyTreeOp, KeyTreeTransition, TransitionInstanceBuilder};
use witness::TransitionWitnessBuilder;

pub(super) fn fixture(
    operation: &str,
    repetitions: usize,
) -> (
    PreparedRelation<KoalaBearPoseidon2_16, 16>,
    PreparedWitness<KoalaBearPoseidon2_16, 16>,
) {
    let derivation = DerivationKoalaBearPoseidon2_16::default();
    let tag = DerivationTag::from_bytes(b"terminal-mask-benchmark");
    let mut transition = KeyTreeTransition::new();
    let mut keys = HashMap::new();
    for repetition in 0..repetitions {
        let root = CanonicalPath::new(format!("/benchmark/{repetition}"));
        let old_path = root.child("old");
        let new_path = root.child("new");
        let head_path = root.child("head");
        let old_key = KeyMaterial::random();
        let new_key = if operation == "rekey" {
            KeyMaterial::random()
        } else {
            derivation.derive(&old_key, tag)
        };
        transition.commit(old_path.clone(), derivation.commit(&old_key));
        if operation != "rekey" {
            transition.derive(old_path.clone(), new_path.clone(), tag);
        }
        transition.commit(new_path.clone(), derivation.commit(&new_key));
        if operation == "rekey" {
            transition.encrypt(
                old_path.clone(),
                new_path.clone(),
                tag,
                EncryptedKeyMaterial::encrypt(derivation.derive(&new_key, tag), &old_key),
            );
        }
        if operation != "extend" {
            let head_key = KeyMaterial::random();
            transition.commit(head_path.clone(), derivation.commit(&head_key));
            transition.encrypt(
                head_path.clone(),
                new_path.clone(),
                tag,
                EncryptedKeyMaterial::encrypt(derivation.derive(&new_key, tag), &head_key),
            );
            keys.insert(head_path, head_key);
        }
        keys.insert(old_path, old_key);
        keys.insert(new_path, new_key);
    }
    let instance = TransitionInstanceBuilder::new().build(&transition);
    let witness = TransitionWitnessBuilder::new(&derivation, &keys).build(&transition);
    let backend = KoalaBearPoseidon2_16::new();
    let relation = PreparedRelation::new(&backend, &instance);
    let witness = relation.prepare_witness(&witness);
    (relation, witness)
}
