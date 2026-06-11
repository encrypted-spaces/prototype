use crate::{KeyCommitment, KeyMaterial};
use num_bigint::BigUint;
use num_traits::{ToPrimitive, Zero};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::KoalaBear;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use spongefish::{instantiations::Shake128, DuplexSpongeInterface};

pub mod poseidon2;
pub use poseidon2::DerivationKoalaBearPoseidon2_16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Hash)]
pub struct DerivationTag([u8; 32]);

/// A non-zero derivation tag.
///
/// # Invariants
///
/// `DerivationTag` is the type-safety boundary for derivation tags: safe code
/// outside this module cannot manufacture arbitrary tag bytes.
///
/// The tag bytes are the packed little-endian representation of an integer in
/// `1..KoalaBear::ORDER_U32^TAG_LIMBS`. This lets [`AlgebraicKeyCommitment`]
/// represent the tag as `TAG_LIMBS` [`KoalaBear`] elements in proofs without
/// reducing unchecked input.
///
/// Zero is excluded because it is reserved for commitments.
///
/// This invariant relies on code in this module and its children continuing to
/// use the checked constructors rather than constructing `DerivationTag`
/// directly from unchecked bytes.
impl DerivationTag {
    pub const TAG_LIMBS: usize = 8;
    const TAG_DOMAIN: &'static [u8] = b"encrypted_spaces:derivation-tag:v1";

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut shake = Shake128::default();
        shake.absorb(Self::TAG_DOMAIN).absorb(bytes);

        loop {
            let tag = Self::canonicalize(shake.squeeze_array());
            if !Self::is_zero(&tag) {
                return Self(tag);
            }
        }
    }

    pub fn from_canonical_bytes(bytes: [u8; 32]) -> Option<Self> {
        if Self::is_zero(&bytes) || !Self::is_canonical(&bytes) {
            None
        } else {
            Some(Self(bytes))
        }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn as_koalabear_limbs(&self) -> [KoalaBear; Self::TAG_LIMBS] {
        let modulus = BigUint::from(KoalaBear::ORDER_U32);
        let mut remaining = BigUint::from_bytes_le(&self.0);
        let mut limbs = [KoalaBear::ZERO; Self::TAG_LIMBS];

        for limb in limbs.iter_mut() {
            if remaining.is_zero() {
                break;
            }
            let rem = &remaining % &modulus;
            let rem_u32 = rem.to_u32().expect("remainder fits in u32");
            *limb = KoalaBear::from_u32(rem_u32);
            remaining /= &modulus;
        }

        debug_assert!(
            remaining.is_zero(),
            "canonical derivation tag exceeds tag capacity"
        );
        limbs
    }

    fn tag_capacity() -> BigUint {
        BigUint::from(KoalaBear::ORDER_U32).pow(Self::TAG_LIMBS as u32)
    }

    fn canonicalize(bytes: [u8; 32]) -> [u8; 32] {
        let value = BigUint::from_bytes_le(&bytes) % Self::tag_capacity();
        Self::biguint_to_bytes(value)
    }

    fn is_canonical(bytes: &[u8; 32]) -> bool {
        BigUint::from_bytes_le(bytes) < Self::tag_capacity()
    }

    fn is_zero(bytes: &[u8; 32]) -> bool {
        bytes.iter().all(|byte| *byte == 0)
    }

    fn biguint_to_bytes(value: BigUint) -> [u8; 32] {
        let value_bytes = value.to_bytes_le();
        debug_assert!(value_bytes.len() <= 32);
        let mut bytes = [0u8; 32];
        let copy_len = value_bytes.len().min(bytes.len());
        bytes[..copy_len].copy_from_slice(&value_bytes[..copy_len]);
        bytes
    }
}

impl Serialize for DerivationTag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DerivationTag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = <[u8; 32]>::deserialize(deserializer)?;
        Self::from_canonical_bytes(bytes)
            .ok_or_else(|| serde::de::Error::custom("derivation tag is invalid"))
    }
}

/// Trait for key derivation operations (PRF-based).
pub trait KeyDerivation: Clone {
    /// Get a commitment from the key material.
    fn commit(&self, key: &KeyMaterial) -> KeyCommitment;

    /// Derive a child key from a parent key using a tag.
    fn derive(&self, parent: &KeyMaterial, tag: DerivationTag) -> KeyMaterial;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zero_canonical_bytes() {
        assert!(DerivationTag::from_canonical_bytes([0u8; 32]).is_none());
    }

    #[test]
    fn rejects_tag_capacity_as_non_canonical() {
        let capacity_bytes = DerivationTag::biguint_to_bytes(DerivationTag::tag_capacity());
        assert!(DerivationTag::from_canonical_bytes(capacity_bytes).is_none());

        let capacity_plus_one_bytes =
            DerivationTag::biguint_to_bytes(DerivationTag::tag_capacity() + 1u8);
        assert!(DerivationTag::from_canonical_bytes(capacity_plus_one_bytes).is_none());
    }

    #[test]
    fn from_bytes_returns_non_zero_canonical_tag() {
        let tag = DerivationTag::from_bytes(b"domain-separated tag input");
        assert!(!DerivationTag::is_zero(tag.as_bytes()));
        assert!(DerivationTag::is_canonical(tag.as_bytes()));
    }

    #[test]
    fn derivationtag_test_cases() {
        // One is a valid tag
        let one = DerivationTag::from_canonical_bytes({
            let mut bytes = [0u8; 32];
            bytes[0] = 1;
            bytes
        })
        .expect("one is a valid tag");

        // We pack tags in base p, so p+1 is still a valid tag
        let modulus_plus_one = DerivationTag::from_canonical_bytes({
            let value = BigUint::from(KoalaBear::ORDER_U32) + 1u8;
            DerivationTag::biguint_to_bytes(value)
        })
        .expect("p + 1 is a valid tag");

        assert_ne!(
            one.as_koalabear_limbs(),
            modulus_plus_one.as_koalabear_limbs()
        );
    }

    #[test]
    fn serde_rejects_invalid_tags() {
        let zero = serde_json::to_vec(&[0u8; 32]).expect("serialize zero tag bytes");
        let decoded = serde_json::from_slice::<DerivationTag>(&zero);
        assert!(decoded.is_err());

        let tag = DerivationTag::from_bytes(b"serde roundtrip tag");
        let encoded = serde_json::to_vec(&tag).expect("serialize tag");
        let decoded = serde_json::from_slice::<DerivationTag>(&encoded).expect("deserialize tag");
        assert_eq!(decoded, tag);
    }
}
