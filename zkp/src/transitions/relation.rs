use std::collections::HashMap;

use encrypted_spaces_crypto::algebraic_encoding::{AlgebraicKeyCommitment, AlgebraicKeyMaterial};
use encrypted_spaces_crypto::key_derivation::DerivationTag;
use encrypted_spaces_crypto::EncryptedKeyMaterial;
use encrypted_spaces_crypto::KeyCommitment;
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use spongefish::Unit;
use spongefish_circuit::allocator::FieldVar;
use spongefish_circuit::permutation::LinearEquation;

use super::canonical_path::CanonicalPath;
use super::{
    RelationInstance, HASHBLOCK_COM_RANGE, HASHBLOCK_KEY_RANGE, HASHBLOCK_TAG_RANGE,
    KEYMATERIAL_LIMBS, POSEIDON2_16_WIDTH,
};

#[derive(Clone, Debug)]
pub enum KeyTreeOp {
    Commit {
        key: CanonicalPath,
        commitment: KeyCommitment,
    },
    Derive {
        parent: CanonicalPath,
        child: CanonicalPath,
        tag: DerivationTag,
    },
    Encrypt {
        key: CanonicalPath,
        parent: CanonicalPath,
        tag: DerivationTag,
        ciphertext: EncryptedKeyMaterial,
    },
}

#[derive(Clone, Debug, Default)]
pub struct KeyTreeTransition {
    ops: Vec<KeyTreeOp>,
}

impl KeyTreeTransition {
    pub fn new() -> Self {
        Self { ops: Vec::new() }
    }

    pub fn len(&self) -> usize {
        self.ops.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    pub(super) fn ops(&self) -> &[KeyTreeOp] {
        &self.ops
    }

    pub fn commit(&mut self, key: CanonicalPath, commitment: KeyCommitment) -> &mut Self {
        self.ops.push(KeyTreeOp::Commit { key, commitment });
        self
    }

    pub fn derive(
        &mut self,
        parent: CanonicalPath,
        child: CanonicalPath,
        tag: DerivationTag,
    ) -> &mut Self {
        self.ops.push(KeyTreeOp::Derive { parent, child, tag });
        self
    }

    pub fn encrypt(
        &mut self,
        key: CanonicalPath,
        parent: CanonicalPath,
        tag: DerivationTag,
        ciphertext: EncryptedKeyMaterial,
    ) -> &mut Self {
        self.ops.push(KeyTreeOp::Encrypt {
            key,
            parent,
            tag,
            ciphertext,
        });
        self
    }
}

pub(super) struct TransitionInstanceBuilder {
    instance: RelationInstance,
    known_vars: HashMap<CanonicalPath, [FieldVar; KEYMATERIAL_LIMBS]>,
}

impl TransitionInstanceBuilder {
    pub(super) fn new() -> Self {
        Self {
            instance: RelationInstance::new(),
            known_vars: HashMap::new(),
        }
    }

    pub(super) fn build(mut self, transition: &KeyTreeTransition) -> RelationInstance {
        for op in transition.ops() {
            match op {
                KeyTreeOp::Commit { key, commitment } => self.add_commit(key, commitment),
                KeyTreeOp::Derive { parent, child, tag } => self.add_derive(parent, child, *tag),
                KeyTreeOp::Encrypt {
                    key,
                    parent,
                    tag,
                    ciphertext,
                } => self.add_encrypt(key, parent, *tag, ciphertext),
            }
        }
        self.instance
    }

    fn add_commit(&mut self, key: &CanonicalPath, commitment: &KeyCommitment) {
        let key_vars = self.ensure_key_vars(key);
        let input_vars = key_input_state_vars(&key_vars);
        let output_vars = self.instance.allocate_permutation(&input_vars);
        let commitment_limbs: [KoalaBear; HASHBLOCK_COM_RANGE.end - HASHBLOCK_COM_RANGE.start] =
            *AlgebraicKeyCommitment::from(commitment).as_ref();
        self.instance.allocator().set_public_vars(
            output_vars[super::HASHBLOCK_COM_RANGE].iter(),
            commitment_limbs.iter(),
        );
    }

    fn add_derive(&mut self, parent: &CanonicalPath, child: &CanonicalPath, tag: DerivationTag) {
        let parent_vars = self.ensure_key_vars(parent);
        let input_vars = derivation_input_state_vars(&self.instance, &parent_vars, tag);
        let output_vars = self.instance.allocate_permutation(&input_vars);
        let child_output_vars: [FieldVar; KEYMATERIAL_LIMBS] = output_vars[HASHBLOCK_KEY_RANGE]
            .try_into()
            .expect("hash key range should match key material limbs");
        self.bind_or_insert_key(child, child_output_vars);
    }

    fn add_encrypt(
        &mut self,
        key: &CanonicalPath,
        parent: &CanonicalPath,
        tag: DerivationTag,
        ciphertext: &EncryptedKeyMaterial,
    ) {
        let key_vars = self.ensure_key_vars(key);
        let parent_vars = self.ensure_key_vars(parent);
        let input_vars = derivation_input_state_vars(&self.instance, &parent_vars, tag);
        let output_vars = self.instance.allocate_permutation(&input_vars);
        let under_vars: [FieldVar; KEYMATERIAL_LIMBS] = output_vars[HASHBLOCK_KEY_RANGE]
            .try_into()
            .expect("hash key range should match key material limbs");
        let ciphertext_limbs: [KoalaBear; KEYMATERIAL_LIMBS] =
            *AlgebraicKeyMaterial::from(ciphertext).as_ref();

        for idx in 0..KEYMATERIAL_LIMBS {
            self.instance.add_equation(LinearEquation::new(
                [
                    (KoalaBear::ONE, key_vars[idx]),
                    (KoalaBear::ONE, under_vars[idx]),
                ],
                ciphertext_limbs[idx],
            ));
        }
    }

    fn ensure_key_vars(&mut self, key: &CanonicalPath) -> [FieldVar; KEYMATERIAL_LIMBS] {
        if let Some(vars) = self.known_vars.get(key) {
            return *vars;
        }

        let vars = self
            .instance
            .allocator()
            .allocate_vars::<KEYMATERIAL_LIMBS>();
        self.known_vars.insert(key.clone(), vars);
        vars
    }

    fn bind_or_insert_key(&mut self, key: &CanonicalPath, new_vars: [FieldVar; KEYMATERIAL_LIMBS]) {
        if let Some(existing_vars) = self.known_vars.get(key).copied() {
            for idx in 0..KEYMATERIAL_LIMBS {
                self.instance.add_equation(LinearEquation::new(
                    [
                        (KoalaBear::ONE, new_vars[idx]),
                        (-KoalaBear::ONE, existing_vars[idx]),
                    ],
                    <KoalaBear as PrimeCharacteristicRing>::ZERO,
                ));
            }
            return;
        }

        self.known_vars.insert(key.clone(), new_vars);
    }
}

fn key_input_state_vars(
    key_vars: &[FieldVar; KEYMATERIAL_LIMBS],
) -> [FieldVar; POSEIDON2_16_WIDTH] {
    let mut state = [<FieldVar as Unit>::ZERO; POSEIDON2_16_WIDTH];
    state[HASHBLOCK_KEY_RANGE].clone_from_slice(key_vars);
    state
}

fn derivation_input_state_vars(
    instance: &RelationInstance,
    key_vars: &[FieldVar; KEYMATERIAL_LIMBS],
    tag: DerivationTag,
) -> [FieldVar; POSEIDON2_16_WIDTH] {
    let mut state = key_input_state_vars(key_vars);
    let tag_vars = instance
        .allocator()
        .allocate_public(&tag.as_koalabear_limbs());
    state[HASHBLOCK_TAG_RANGE].clone_from_slice(&tag_vars);
    state
}
