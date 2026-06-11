use core::ops::Range;
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use serde::{Deserialize, Serialize};
use spongefish::Permutation;
use spongefish_stark::permutation::poseidon2::KoalaBearPoseidon2_16;

use crate::{
    algebraic_encoding::{AlgebraicKeyMaterial, KEYCOMMITMENT_LIMBS, KEYMATERIAL_LIMBS},
    key_derivation::DerivationTag,
    KeyCommitment, KeyMaterial, P2_16_CONFIG,
};

use super::KeyDerivation;

const HASHBLOCK_WIDTH: usize = P2_16_CONFIG.width;
const HASHBLOCK_RATE: usize = P2_16_CONFIG.rate;
const TAG_LIMBS: usize = DerivationTag::TAG_LIMBS;
type HashBlock = [KoalaBear; HASHBLOCK_WIDTH];
type HashMask = [Option<KoalaBear>; HASHBLOCK_WIDTH];

/// The indices in an input block where we store the key material.
///
/// With 8-limb key material this fills the Poseidon2-16 rate segment.
pub const HASHBLOCK_KEY_RANGE: Range<usize> = 0..KEYMATERIAL_LIMBS;
/// The indices in an input block where we store the tag.
///
/// Tags occupy the capacity segment, adjacent to but not overlapping the key.
pub const HASHBLOCK_TAG_RANGE: Range<usize> = HASHBLOCK_WIDTH - TAG_LIMBS..HASHBLOCK_WIDTH;
/// The indices in an output block where we read the key commitment.
///
/// Commitments are read strictly from the rate segment.
pub const HASHBLOCK_COM_RANGE: Range<usize> = 0..KEYCOMMITMENT_LIMBS;

const _: () = {
    // Key material fills the Poseidon2-16 rate segment.
    assert!(KEYMATERIAL_LIMBS == 8);
    assert!(KEYMATERIAL_LIMBS == HASHBLOCK_RATE);

    // Commitments are read from the output rate segment.
    assert!(KEYCOMMITMENT_LIMBS == HASHBLOCK_RATE);

    // Tags fit exactly in the capacity segment.
    assert!(TAG_LIMBS == HASHBLOCK_WIDTH - HASHBLOCK_RATE);

    // The key range is the rate segment.
    assert!(HASHBLOCK_KEY_RANGE.start == 0);
    assert!(HASHBLOCK_KEY_RANGE.end == HASHBLOCK_RATE);

    // The tag range is the capacity segment.
    assert!(HASHBLOCK_TAG_RANGE.start == HASHBLOCK_RATE);
    assert!(HASHBLOCK_TAG_RANGE.end == HASHBLOCK_WIDTH);

    // The commitment range is the output rate segment.
    assert!(HASHBLOCK_COM_RANGE.start == 0);
    assert!(HASHBLOCK_COM_RANGE.end == HASHBLOCK_RATE);
};

/// Poseidon2-based key derivation over KoalaBear.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct DerivationKoalaBearPoseidon2_16 {
    // KoalaBearPoseidon2_16 is always stateless and reconstructed via Default.
    #[serde(skip)]
    hasher: KoalaBearPoseidon2_16,
}

impl DerivationKoalaBearPoseidon2_16 {
    /// Map a [`KeyMaterial`] to a hash block.
    ///
    /// The key is placed in the first `KEYMATERIAL_LIMBS` elements of the state,
    /// and the rest of the state is padded with zeros.
    pub fn key_to_hash_state(&self, key: &KeyMaterial) -> HashBlock {
        let alg_key = AlgebraicKeyMaterial::from(key);
        assert_eq!(alg_key.0 .0.len(), KEYMATERIAL_LIMBS);
        alg_key.0.pad_with(KoalaBear::ZERO).0
    }

    pub fn commit_input_state(&self, key: &KeyMaterial) -> HashBlock {
        self.key_to_hash_state(key)
    }

    pub fn derivation_input_state(&self, key: &KeyMaterial, tag: DerivationTag) -> HashBlock {
        let mut state = self.key_to_hash_state(key);
        self.apply_tag_to_hash_state(&mut state, tag);
        state
    }

    /// Read a [`KeyMaterial`] from a hash block.
    ///
    /// The key is placed in the first `KEYMATERIAL_LIMBS` elements of the state.
    pub fn key_from_hash_state(&self, state: HashBlock) -> KeyMaterial {
        KeyMaterial::from_slice(&state[HASHBLOCK_KEY_RANGE])
    }

    /// Apply a tag to the hash state.
    ///
    /// Convert the tag into TAG_LIMBS KoalaBear elements, and then apply it to the hash state.
    pub fn apply_tag_to_hash_state(&self, state: &mut HashBlock, tag: DerivationTag) {
        let koala_tag = tag.as_koalabear_limbs();
        state[HASHBLOCK_TAG_RANGE].clone_from_slice(&koala_tag);
    }

    /// Read a [`KeyCommitment`] from a hash block.
    ///
    /// The commitment is read from the first `KEYCOMMITMENT_LIMBS` cells of the output rate
    /// segment.
    pub fn read_commitment_from_hash_state(&self, state: HashBlock) -> KeyCommitment {
        KeyCommitment::from_slice(&state[HASHBLOCK_COM_RANGE])
    }

    pub fn mask_commitment(&self, state: HashBlock) -> HashMask {
        let mut masked_state = [None; HASHBLOCK_WIDTH];
        for i in HASHBLOCK_COM_RANGE {
            masked_state[i] = Some(state[i])
        }
        masked_state
    }
}

impl KeyDerivation for DerivationKoalaBearPoseidon2_16 {
    fn commit(&self, key: &KeyMaterial) -> KeyCommitment {
        let mut hash_state = self.key_to_hash_state(key);
        self.hasher.permute_mut(&mut hash_state);
        self.read_commitment_from_hash_state(hash_state)
    }

    fn derive(&self, parent: &KeyMaterial, tag: DerivationTag) -> KeyMaterial {
        let mut hash_state = self.key_to_hash_state(parent);
        // add a tag for derivation and domain separation
        self.apply_tag_to_hash_state(&mut hash_state, tag);
        self.hasher.permute_mut(&mut hash_state);

        self.key_from_hash_state(hash_state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_to_hash_state() {
        let mut rng = rand::rng();
        let derivation = DerivationKoalaBearPoseidon2_16::default();
        for _ in 0..256 {
            let key = KeyMaterial::random_with(&mut rng);
            let state = derivation.key_to_hash_state(&key);
            let recovered = derivation.key_from_hash_state(state);
            assert_eq!(key.as_bytes(), recovered.as_bytes());
        }
    }
}
