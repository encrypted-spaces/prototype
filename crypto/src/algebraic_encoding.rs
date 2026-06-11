//!
//! Encoding utilities for [`KeyMaterial`] expressed as fixed KoalaBear limbs.
use alloc::vec::Vec;
use core::ops::{Add, AddAssign, Neg, Sub, SubAssign};
use std::ops::Deref;

use crate::{KeyCommitment, KeyMaterial, P2_16_CONFIG};
use num_bigint::BigUint;
use num_traits::{ops::euclid::Euclid, ToPrimitive, Zero};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::KoalaBear;
use spongefish::Encoding;

/// An encoding of an object as an array of `N` elements of type `T`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AlgebraicEncoding<T, const N: usize>(pub [T; N]);

pub(crate) const FIELD_MODULUS: u32 = KoalaBear::ORDER_U32;
const FIELD_BITS: usize = 31;

/// The key material size assumes that the key is clamped.
///
/// For the current 32-byte [`KeyMaterial`], this yields 8 KoalaBear limbs,
/// which fills the Poseidon2-16 rate segment used by key derivation proofs.
pub const KEYMATERIAL_LIMBS: usize = (KeyMaterial::SIZE * 8) / FIELD_BITS;

/// Key commitments are encoded from the full Poseidon2-16 rate segment.
pub const KEYCOMMITMENT_LIMBS: usize = P2_16_CONFIG.rate;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AlgebraicKeyMaterial(pub AlgebraicEncoding<KoalaBear, KEYMATERIAL_LIMBS>);

#[derive(Clone, PartialEq, Eq)]
pub struct AlgebraicKeyCommitment(pub AlgebraicEncoding<KoalaBear, KEYCOMMITMENT_LIMBS>);

impl<T: AddAssign, const N: usize> Add for AlgebraicEncoding<T, N> {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        for (lhs, rhs_elem) in self.0.iter_mut().zip(rhs.0) {
            *lhs += rhs_elem;
        }
        self
    }
}

impl<T: SubAssign, const N: usize> Sub for AlgebraicEncoding<T, N> {
    type Output = Self;

    fn sub(mut self, rhs: Self) -> Self::Output {
        for (lhs, rhs_elem) in self.0.iter_mut().zip(rhs.0) {
            *lhs -= rhs_elem;
        }
        self
    }
}

impl<T: Neg<Output = T> + Clone, const N: usize> Neg for AlgebraicEncoding<T, N> {
    type Output = Self;

    fn neg(mut self) -> Self::Output {
        for elem in self.0.iter_mut() {
            *elem = elem.clone().neg();
        }
        self
    }
}

impl<T: Copy, const N: usize> AlgebraicEncoding<T, N> {
    pub fn pad_with<const M: usize>(&self, value: T) -> AlgebraicEncoding<T, M> {
        assert!(N <= M);
        let mut state = [value; M];
        state[..N].clone_from_slice(&self.0);
        AlgebraicEncoding(state)
    }
}

impl Deref for AlgebraicKeyMaterial {
    type Target = AlgebraicEncoding<KoalaBear, KEYMATERIAL_LIMBS>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[KoalaBear]> for AlgebraicKeyMaterial {
    fn as_ref(&self) -> &[KoalaBear] {
        &self.0 .0
    }
}

impl AsRef<[KoalaBear; KEYMATERIAL_LIMBS]> for AlgebraicKeyMaterial {
    fn as_ref(&self) -> &[KoalaBear; KEYMATERIAL_LIMBS] {
        &self.0 .0
    }
}

impl AlgebraicKeyMaterial {
    pub fn from_slice(slice: &[KoalaBear]) -> Self {
        Self(AlgebraicEncoding(
            slice
                .try_into()
                .expect("slice length does not match key material limbs"),
        ))
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        canonical_encoding_from_bytes(bytes, KeyMaterial::SIZE).map(Self)
    }

    #[cfg(test)]
    pub(crate) fn encoding_capacity() -> BigUint {
        BigUint::from(FIELD_MODULUS).pow(KEYMATERIAL_LIMBS as u32)
    }
}

impl KeyMaterial {
    pub fn from_slice(slice: &[KoalaBear]) -> Self {
        AlgebraicKeyMaterial::from_slice(slice).into()
    }
}

impl AlgebraicKeyCommitment {
    pub fn from_slice(slice: &[KoalaBear]) -> Self {
        Self(AlgebraicEncoding(
            slice
                .try_into()
                .expect("slice length does not match key commitment limbs"),
        ))
    }

    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Option<Self> {
        canonical_encoding_from_bytes(bytes, KeyCommitment::SIZE).map(Self)
    }

    #[cfg(test)]
    pub(crate) fn encoding_capacity() -> BigUint {
        BigUint::from(FIELD_MODULUS).pow(KEYCOMMITMENT_LIMBS as u32)
    }
}

impl AsRef<[KoalaBear]> for AlgebraicKeyCommitment {
    fn as_ref(&self) -> &[KoalaBear] {
        &self.0 .0
    }
}

impl AsRef<[KoalaBear; KEYCOMMITMENT_LIMBS]> for AlgebraicKeyCommitment {
    fn as_ref(&self) -> &[KoalaBear; KEYCOMMITMENT_LIMBS] {
        &self.0 .0
    }
}

impl KeyCommitment {
    pub fn from_slice(slice: &[KoalaBear]) -> Self {
        AlgebraicKeyCommitment::from_slice(slice).into()
    }
}

impl From<&KeyMaterial> for AlgebraicKeyMaterial {
    fn from(value: &KeyMaterial) -> Self {
        Self::from_bytes(value.as_bytes()).expect("KeyMaterial can't be represented in the field")
    }
}

impl From<KeyMaterial> for AlgebraicKeyMaterial {
    fn from(value: KeyMaterial) -> Self {
        AlgebraicKeyMaterial::from(&value)
    }
}

impl From<&KeyCommitment> for AlgebraicKeyCommitment {
    fn from(value: &KeyCommitment) -> Self {
        Self::from_canonical_bytes(value.as_bytes()).expect("key commitments are canonical")
    }
}

impl From<KeyCommitment> for AlgebraicKeyCommitment {
    fn from(value: KeyCommitment) -> Self {
        AlgebraicKeyCommitment::from(&value)
    }
}

impl Encoding for AlgebraicKeyMaterial {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.0
             .0
            .iter()
            .flat_map(|elt| elt.as_canonical_u32().to_le_bytes())
            .collect::<Vec<_>>()
    }
}

impl KeyMaterial {
    pub(crate) fn add_algebraic(&self, other: &KeyMaterial) -> KeyMaterial {
        let self_encoded = AlgebraicKeyMaterial::from(self);
        let other_encoded = AlgebraicKeyMaterial::from(other);
        Self::from(AlgebraicKeyMaterial(self_encoded.0 + other_encoded.0))
    }
}

fn canonical_encoding_from_bytes<const N: usize>(
    bytes: &[u8],
    expected_len: usize,
) -> Option<AlgebraicEncoding<KoalaBear, N>> {
    if bytes.len() != expected_len {
        return None;
    }

    let modulus = BigUint::from(FIELD_MODULUS);
    let mut remaining = BigUint::from_bytes_le(bytes);
    let mut state = [KoalaBear::ZERO; N];

    for limb in state.iter_mut() {
        if remaining.is_zero() {
            break;
        }

        let (quot, rem) = remaining.div_rem_euclid(&modulus);
        let rem_u32 = rem.to_u32().expect("remainder fits in u32");
        *limb = KoalaBear::from_u32(rem_u32);
        remaining = quot;
    }

    remaining.is_zero().then_some(AlgebraicEncoding(state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DerivationKoalaBearPoseidon2_16, KeyDerivation};
    use num_bigint::BigUint;

    #[test]
    fn test_encoding_decoding() {
        let mut rng = rand::rng();
        for _ in 0..512 {
            let key = KeyMaterial::random_with(&mut rng);
            let encoded = AlgebraicKeyMaterial::from(&key);
            let decoded = KeyMaterial::from(&encoded);
            assert_eq!(key.as_bytes(), decoded.as_bytes());
            assert_eq!(key, KeyMaterial::clamp(*key.as_bytes()));
        }
    }

    #[test]
    fn test_keycommitment_encoding_decoding() {
        let mut rng = rand::rng();
        let derivation = DerivationKoalaBearPoseidon2_16::default();
        for _ in 0..256 {
            let random_key = KeyMaterial::random_with(&mut rng);
            let commitment = derivation.commit(&random_key);
            let encoded = AlgebraicKeyCommitment::from(&commitment);
            let decoded = KeyCommitment::from(&encoded);
            assert_eq!(commitment.as_bytes(), decoded.as_bytes());
        }
    }

    #[test]
    fn test_clamp_roundtrip_boundaries() {
        let modulus = BigUint::from(FIELD_MODULUS).pow(KEYMATERIAL_LIMBS as u32);
        let cases = [
            BigUint::from(0u8),
            BigUint::from(1u8),
            &modulus - 1u8,
            modulus.clone(),
            &modulus + 1u8,
        ];

        for value in cases {
            let mut bytes = [0u8; KeyMaterial::SIZE];
            let encoded = value.to_bytes_le();
            let copy_len = encoded.len().min(KeyMaterial::SIZE);
            bytes[..copy_len].copy_from_slice(&encoded[..copy_len]);
            let key = KeyMaterial::clamp(bytes);
            let algebraic = AlgebraicKeyMaterial::from(&key);
            let recovered = KeyMaterial::from(&algebraic);
            assert_eq!(key.as_bytes(), recovered.as_bytes());
            assert_eq!(key, KeyMaterial::clamp(*key.as_bytes()));
        }
    }

    #[test]
    fn test_algebraic_encoding_neg() {
        let encoding = AlgebraicEncoding([KoalaBear::ONE; 4]);
        let neg_encoding = -encoding;
        for limb in neg_encoding.0 {
            assert_eq!(limb, -KoalaBear::ONE);
        }
    }
}
