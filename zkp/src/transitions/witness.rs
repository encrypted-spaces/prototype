use std::collections::HashMap;

use encrypted_spaces_crypto::algebraic_encoding::AlgebraicKeyMaterial;
use encrypted_spaces_crypto::key_derivation::DerivationTag;
use encrypted_spaces_crypto::EncryptedKeyMaterial;
use encrypted_spaces_crypto::{DerivationKoalaBearPoseidon2_16, KeyMaterial};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use spongefish_circuit::permutation::LinearEquation;
use spongefish_stark::permutation::poseidon2::KoalaBearPoseidon2_16;

use super::canonical_path::CanonicalPath;
use super::{
    KeyTreeOp, KeyTreeTransition, RelationWitness, HASHBLOCK_KEY_RANGE, KEYMATERIAL_LIMBS,
};

pub(super) struct TransitionWitnessBuilder<'a> {
    derivation: &'a DerivationKoalaBearPoseidon2_16,
    witness: RelationWitness,
    keys: &'a HashMap<CanonicalPath, KeyMaterial>,
    known_values: HashMap<CanonicalPath, [KoalaBear; KEYMATERIAL_LIMBS]>,
}

impl<'a> TransitionWitnessBuilder<'a> {
    pub(super) fn new(
        derivation: &'a DerivationKoalaBearPoseidon2_16,
        keys: &'a HashMap<CanonicalPath, KeyMaterial>,
    ) -> Self {
        Self {
            derivation,
            witness: RelationWitness::new(KoalaBearPoseidon2_16::default()),
            keys,
            known_values: HashMap::new(),
        }
    }

    pub(super) fn build(mut self, transition: &KeyTreeTransition) -> RelationWitness {
        for op in transition.ops() {
            match op {
                KeyTreeOp::Commit { key, .. } => self.add_commit(key),
                KeyTreeOp::Derive { parent, child, tag } => self.add_derive(parent, child, *tag),
                KeyTreeOp::Encrypt {
                    key,
                    parent,
                    tag,
                    ciphertext,
                } => self.add_encrypt(key, parent, *tag, ciphertext),
            }
        }
        self.witness
    }

    fn add_commit(&mut self, key: &CanonicalPath) {
        let key_value = KeyMaterial::from(AlgebraicKeyMaterial::from_slice(
            &self.ensure_key_values(key),
        ));
        let input = self.derivation.commit_input_state(&key_value);
        let _ = self.witness.allocate_permutation(&input);
    }

    fn add_derive(&mut self, parent: &CanonicalPath, child: &CanonicalPath, tag: DerivationTag) {
        let parent_value = KeyMaterial::from(AlgebraicKeyMaterial::from_slice(
            &self.ensure_key_values(parent),
        ));
        let input = self.derivation.derivation_input_state(&parent_value, tag);
        let output = self.witness.allocate_permutation(&input);
        let child_output_values: [KoalaBear; KEYMATERIAL_LIMBS] = output[HASHBLOCK_KEY_RANGE]
            .try_into()
            .expect("hash key range should match key material limbs");
        self.bind_or_insert_key_values(child, child_output_values);
    }

    fn add_encrypt(
        &mut self,
        key: &CanonicalPath,
        parent: &CanonicalPath,
        tag: DerivationTag,
        ciphertext: &EncryptedKeyMaterial,
    ) {
        let key_values = self.ensure_key_values(key);
        let parent_value = KeyMaterial::from(AlgebraicKeyMaterial::from_slice(
            &self.ensure_key_values(parent),
        ));
        let input = self.derivation.derivation_input_state(&parent_value, tag);
        let output = self.witness.allocate_permutation(&input);
        let under_values: [KoalaBear; KEYMATERIAL_LIMBS] = output[HASHBLOCK_KEY_RANGE]
            .try_into()
            .expect("hash key range should match key material limbs");
        let ciphertext_limbs: [KoalaBear; KEYMATERIAL_LIMBS] =
            *AlgebraicKeyMaterial::from(ciphertext).as_ref();

        for idx in 0..KEYMATERIAL_LIMBS {
            self.witness.add_equation(LinearEquation::new(
                [
                    (KoalaBear::ONE, key_values[idx]),
                    (KoalaBear::ONE, under_values[idx]),
                ],
                ciphertext_limbs[idx],
            ));
        }
    }

    fn ensure_key_values(&mut self, key: &CanonicalPath) -> [KoalaBear; KEYMATERIAL_LIMBS] {
        if let Some(values) = self.known_values.get(key) {
            return *values;
        }

        let values = self
            .keys
            .get(key)
            .map(|value| *AlgebraicKeyMaterial::from(value).as_ref())
            .unwrap_or_else(|| panic!("missing key material for {key}"));
        self.known_values.insert(key.clone(), values);
        values
    }

    fn bind_or_insert_key_values(
        &mut self,
        key: &CanonicalPath,
        new_values: [KoalaBear; KEYMATERIAL_LIMBS],
    ) {
        if let Some(existing_values) = self.known_values.get(key).copied() {
            for idx in 0..KEYMATERIAL_LIMBS {
                self.witness.add_equation(LinearEquation::new(
                    [
                        (KoalaBear::ONE, new_values[idx]),
                        (-KoalaBear::ONE, existing_values[idx]),
                    ],
                    KoalaBear::ZERO,
                ));
            }
            return;
        }

        self.known_values.insert(key.clone(), new_values);
    }
}
