use num_bigint::BigUint;
use p3_field::PrimeField32;
use rand::{
    distr::{Distribution, StandardUniform},
    Rng, RngCore,
};
use serde::{Deserialize, Serialize};
use spongefish::{DuplexSpongeInterface, Encoding, NargDeserialize, StdHash, VerificationError};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::algebraic_encoding::{
    AlgebraicKeyCommitment, AlgebraicKeyMaterial, FIELD_MODULUS, KEYMATERIAL_LIMBS,
};

/// Fixed-size wrapper around raw key bytes.
///
/// [`KeyMaterial`] is a vector of [`KEYMATERIAL_LIMBS`] field elements,
/// stored as bytes.
#[derive(Clone, Serialize, Zeroize, Eq)]
#[zeroize(drop)]
pub struct KeyMaterial([u8; Self::SIZE]);

impl KeyMaterial {
    /// Serialized size in bytes of key material.
    ///
    /// Key material is clamped into the range represented by
    /// `KEYMATERIAL_LIMBS` KoalaBear field elements before it is used in
    /// algebraic proof relations.
    ///
    /// There are a few places in this code that make assumptions about the size
    /// - the implementation `From<[u8; 32]>` makes sense only if `SIZE <= 32`;
    /// - the implementation `From<[u8; 64]>` makes sense only if `SIZE <= 64`.
    pub const SIZE: usize = 32;

    pub fn clamp(value: [u8; Self::SIZE]) -> Self {
        let int_keymaterial = BigUint::from_bytes_le(value.as_slice());
        let modulus = BigUint::from(FIELD_MODULUS).pow(KEYMATERIAL_LIMBS as u32);
        use num_traits::Euclid;
        let remainder = int_keymaterial.rem_euclid(&modulus);
        let remainder_bytes = remainder.to_bytes_le();
        let mut clamped_key = [0u8; Self::SIZE];
        clamped_key[..remainder_bytes.len()].copy_from_slice(&remainder_bytes);
        Self(clamped_key)
    }

    fn bytes_array(bytes: &[u8]) -> Option<[u8; Self::SIZE]> {
        if bytes.len() != Self::SIZE {
            return None;
        }

        let mut inner = [0u8; Self::SIZE];
        inner.copy_from_slice(bytes);
        Some(inner)
    }

    /// Construct a zeroed key material instance.
    pub fn zero() -> Self {
        Self([0u8; Self::SIZE])
    }

    /// Clamp any 32-byte slice into the field-limb encoding range.
    ///
    /// This is appropriate for turning arbitrary entropy into key material,
    /// but not for decoding persisted or adversarial bytes.
    pub fn clamp_from_bytes(bytes: &[u8]) -> Option<Self> {
        Self::bytes_array(bytes).map(Self::clamp)
    }

    /// Construct from canonical bytes if they fit in the field-limb encoding.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Self::bytes_array(bytes).and_then(Self::from_canonical_array)
    }

    fn from_canonical_array(value: [u8; Self::SIZE]) -> Option<Self> {
        AlgebraicKeyMaterial::from_bytes(&value).map(|_| Self(value))
    }

    /// Generate a fresh random key using the system RNG.
    pub fn random() -> Self {
        let mut rng = rand::rng();
        Self::random_with(&mut rng)
    }

    /// Generate a fresh random key using the provided RNG.
    pub fn random_with<R: RngCore + ?Sized>(rng: &mut R) -> Self {
        let mut inner = [0u8; Self::SIZE];
        rng.fill_bytes(&mut inner);
        Self::clamp(inner)
    }

    /// Derive key material by hashing the input bytes.
    pub fn digest(secret: &[u8]) -> Self {
        let bytes = StdHash::default()
            .absorb(secret)
            .squeeze_array::<{ Self::SIZE }>();
        Self::clamp(bytes)
    }

    /// Return self padded on the right
    pub fn to_rjust_bytes<const N: usize>(&self) -> [u8; N] {
        assert!(N > Self::SIZE);
        let mut ret = [0; N];
        ret[..Self::SIZE].copy_from_slice(self.as_bytes());
        ret
    }

    /// Borrow the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.0
    }
}

impl From<[u8; 64]> for KeyMaterial {
    /// Compress 64-bytes of entropy into a valid [`KeyMaterial`].
    fn from(value: [u8; 64]) -> Self {
        let mut inner = [0u8; Self::SIZE];
        inner.copy_from_slice(&value[..Self::SIZE]);
        Self::clamp(inner)
    }
}

impl core::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "KeyMaterial(**redacted**)") // avoid leaking key material in logs
    }
}

impl Distribution<KeyMaterial> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> KeyMaterial {
        KeyMaterial::random_with(rng)
    }
}

impl PartialEq for KeyMaterial {
    /// Constant-time comparison: `KeyMaterial` wraps secret key bytes, so
    /// equality must not leak how many leading bytes match via timing.
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl<'de> Deserialize<'de> for KeyMaterial {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let inner = <[u8; Self::SIZE]>::deserialize(deserializer)?;
        Self::from_canonical_array(inner)
            .ok_or_else(|| serde::de::Error::custom("invalid key material"))
    }
}

impl Encoding for KeyMaterial {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.0
    }
}

impl NargDeserialize for KeyMaterial {
    fn deserialize_from_narg(buf: &mut &[u8]) -> spongefish::VerificationResult<Self> {
        if buf.len() < Self::SIZE {
            return Err(VerificationError);
        }

        let (head, tail) = buf.split_at(Self::SIZE);
        let value = Self::from_bytes(head).ok_or(VerificationError)?;
        *buf = tail;
        Ok(value)
    }
}

impl From<&AlgebraicKeyMaterial> for KeyMaterial {
    fn from(value: &AlgebraicKeyMaterial) -> Self {
        let modulus = BigUint::from(FIELD_MODULUS);
        let mut acc = BigUint::from(0u8);
        let mut base_pow = BigUint::from(1u8);

        for limb in value.0 .0.iter() {
            let limb_val = limb.as_canonical_u32();
            if limb_val != 0 {
                let limb_big = BigUint::from(limb_val);
                acc += &limb_big * &base_pow;
            }
            base_pow *= &modulus;
        }

        let bytes_le = acc.to_bytes_le();
        debug_assert!(
            bytes_le.len() <= Self::SIZE,
            "algebraic key material should fit in the raw key size"
        );
        let mut bytes = [0u8; Self::SIZE];
        let copy_len = bytes_le.len().min(Self::SIZE);
        bytes[..copy_len].copy_from_slice(&bytes_le[..copy_len]);
        Self(bytes)
    }
}

impl From<AlgebraicKeyMaterial> for KeyMaterial {
    fn from(value: AlgebraicKeyMaterial) -> Self {
        KeyMaterial::from(&value)
    }
}

/// Commitment derived from key material via the base derivation function.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
pub struct KeyCommitment([u8; Self::SIZE]);

impl KeyCommitment {
    pub const SIZE: usize = 32;

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        AlgebraicKeyCommitment::from_canonical_bytes(bytes).map(Into::into)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for KeyCommitment {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let inner = <[u8; Self::SIZE]>::deserialize(deserializer)?;
        Self::from_bytes(&inner)
            .ok_or_else(|| serde::de::Error::custom("non-canonical key commitment"))
    }
}

impl From<&AlgebraicKeyCommitment> for KeyCommitment {
    fn from(value: &AlgebraicKeyCommitment) -> Self {
        let modulus = BigUint::from(FIELD_MODULUS);
        let mut acc = BigUint::from(0u8);
        let mut base_pow = BigUint::from(1u8);

        for limb in value.0 .0.iter() {
            let limb_val = limb.as_canonical_u32();
            if limb_val != 0 {
                let limb_big = BigUint::from(limb_val);
                acc += &limb_big * &base_pow;
            }
            base_pow *= &modulus;
        }

        let bytes_le = acc.to_bytes_le();
        debug_assert!(
            bytes_le.len() <= Self::SIZE,
            "algebraic commitment should fit in the raw commitment size"
        );
        let mut bytes = [0u8; Self::SIZE];
        let copy_len = bytes_le.len().min(Self::SIZE);
        bytes[..copy_len].copy_from_slice(&bytes_le[..copy_len]);
        Self(bytes)
    }
}

impl From<AlgebraicKeyCommitment> for KeyCommitment {
    fn from(value: AlgebraicKeyCommitment) -> Self {
        KeyCommitment::from(&value)
    }
}

impl Encoding for KeyCommitment {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keymaterial_modulus() -> BigUint {
        AlgebraicKeyMaterial::encoding_capacity()
    }

    fn commitment_modulus() -> BigUint {
        AlgebraicKeyCommitment::encoding_capacity()
    }

    fn key_material_bytes(value: BigUint) -> [u8; KeyMaterial::SIZE] {
        let encoded = value.to_bytes_le();
        assert!(encoded.len() <= KeyMaterial::SIZE);

        let mut bytes = [0u8; KeyMaterial::SIZE];
        bytes[..encoded.len()].copy_from_slice(&encoded);
        bytes
    }

    fn key_commitment_bytes(value: BigUint) -> [u8; KeyCommitment::SIZE] {
        let encoded = value.to_bytes_le();
        assert!(encoded.len() <= KeyCommitment::SIZE);

        let mut bytes = [0u8; KeyCommitment::SIZE];
        bytes[..encoded.len()].copy_from_slice(&encoded);
        bytes
    }

    #[test]
    fn keymaterial_from_bytes_accepts_canonical_boundaries() {
        let modulus = keymaterial_modulus();
        let cases = [
            BigUint::from(0u8),
            BigUint::from(1u8),
            &modulus - BigUint::from(1u8),
        ];

        for value in cases {
            let bytes = key_material_bytes(value);
            let key =
                KeyMaterial::from_bytes(&bytes).expect("canonical key bytes should be accepted");
            assert_eq!(key.as_bytes(), &bytes);
        }
    }

    #[test]
    fn keymaterial_from_bytes_rejects_non_canonical_boundaries() {
        let modulus = keymaterial_modulus();
        let cases = [modulus.clone(), &modulus + BigUint::from(1u8)];

        for value in cases {
            let bytes = key_material_bytes(value);
            assert!(KeyMaterial::from_bytes(&bytes).is_none());
        }
    }

    #[test]
    fn keymaterial_serde_roundtrips_canonical_value() {
        let bytes = key_material_bytes(BigUint::from(42u8));
        let key = KeyMaterial::from_bytes(&bytes).expect("test key should be canonical");

        let encoded = serde_json::to_vec(&key).expect("serialize key material");
        let decoded: KeyMaterial =
            serde_json::from_slice(&encoded).expect("deserialize key material");

        assert_eq!(decoded, key);
    }

    #[test]
    fn keymaterial_serde_rejects_non_canonical_value() {
        let bytes = key_material_bytes(keymaterial_modulus());
        let encoded = serde_json::to_vec(&bytes).expect("serialize raw key bytes");

        let decoded = serde_json::from_slice::<KeyMaterial>(&encoded);

        assert!(decoded.is_err());
    }

    #[test]
    fn encrypted_keymaterial_serde_roundtrips_canonical_value() {
        let bytes = key_material_bytes(BigUint::from(42u8));
        let key = KeyMaterial::zero();
        let message = KeyMaterial::from_bytes(&bytes).expect("test key should be canonical");
        let encrypted = EncryptedKeyMaterial::encrypt(key, &message);

        let encoded = serde_json::to_vec(&encrypted).expect("serialize encrypted key material");
        let decoded: EncryptedKeyMaterial =
            serde_json::from_slice(&encoded).expect("deserialize encrypted key material");

        assert_eq!(decoded.decrypt(KeyMaterial::zero()), message);
    }

    #[test]
    fn encrypted_keymaterial_serde_rejects_non_canonical_value() {
        let bytes = key_material_bytes(keymaterial_modulus());
        let encoded = serde_json::to_vec(&bytes).expect("serialize raw encrypted key bytes");

        let decoded = serde_json::from_slice::<EncryptedKeyMaterial>(&encoded);

        assert!(decoded.is_err());
    }

    #[test]
    fn keycommitment_from_bytes_accepts_canonical_boundaries() {
        let modulus = commitment_modulus();
        let cases = [
            BigUint::from(0u8),
            BigUint::from(1u8),
            &modulus - BigUint::from(1u8),
        ];

        for value in cases {
            let bytes = key_commitment_bytes(value);
            let commitment = KeyCommitment::from_bytes(&bytes)
                .expect("canonical commitment bytes should be accepted");
            assert_eq!(commitment.as_bytes(), &bytes);
        }
    }

    #[test]
    fn keycommitment_from_bytes_rejects_non_canonical_boundaries() {
        let modulus = commitment_modulus();
        let cases = [modulus.clone(), &modulus + BigUint::from(1u8)];

        for value in cases {
            let bytes = key_commitment_bytes(value);
            assert!(KeyCommitment::from_bytes(&bytes).is_none());
        }
    }

    #[test]
    fn keycommitment_serde_roundtrips_canonical_value() {
        let bytes = key_commitment_bytes(BigUint::from(42u8));
        let commitment =
            KeyCommitment::from_bytes(&bytes).expect("test commitment should be canonical");

        let encoded = serde_json::to_vec(&commitment).expect("serialize key commitment");
        let decoded: KeyCommitment =
            serde_json::from_slice(&encoded).expect("deserialize key commitment");

        assert_eq!(decoded, commitment);
    }

    #[test]
    fn keycommitment_serde_rejects_non_canonical_value() {
        let bytes = key_commitment_bytes(commitment_modulus());
        let encoded = serde_json::to_vec(&bytes).expect("serialize raw commitment bytes");

        let decoded = serde_json::from_slice::<KeyCommitment>(&encoded);

        assert!(decoded.is_err());
    }

    #[test]
    fn keycommitment_spongefish_encoding_is_canonical_bytes() {
        let bytes = key_commitment_bytes(BigUint::from(7u8));
        let commitment =
            KeyCommitment::from_bytes(&bytes).expect("test commitment should be canonical");

        assert_eq!(commitment.encode().as_ref(), bytes);
    }
}

/// Key material encrypted with a one-time pad derived from another key.
///
/// # Safety
///
/// The keys for an encrypted key material are assumed to be used **only once**.
/// The ciphertexts are **not** uniformly distributed; they are most likely
/// uniformly distributed field elements, which makes them easy to prove over.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EncryptedKeyMaterial(KeyMaterial);

impl From<EncryptedKeyMaterial> for AlgebraicKeyMaterial {
    fn from(value: EncryptedKeyMaterial) -> Self {
        value.0.into()
    }
}

impl From<&EncryptedKeyMaterial> for AlgebraicKeyMaterial {
    fn from(value: &EncryptedKeyMaterial) -> Self {
        value.clone().into()
    }
}

impl EncryptedKeyMaterial {
    /// Construct encrypted key material from canonical bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        KeyMaterial::from_bytes(bytes).map(Self)
    }

    /// Create a new ciphertext, consuming the key material and the message.
    ///
    /// # Safety
    ///
    /// This "encryption" is actually just a one-time pad!
    /// This means that using the same key multiple times will be fatal;
    /// that the ciphertext is malleable;
    /// and that it's the caller responsability to make sure that key and message
    /// are properly generated and not swapped.
    pub fn encrypt(key: KeyMaterial, message: &KeyMaterial) -> Self {
        let ciphertext = key.add_algebraic(message);
        Self(ciphertext)
    }

    /// Decrypt the ciphertext into a [`KeyMaterial`], consuming it to prevent re-use.
    pub fn decrypt(&self, key: KeyMaterial) -> KeyMaterial {
        let ciphertext = AlgebraicKeyMaterial::from(self.0.clone());
        let key = AlgebraicKeyMaterial::from(key);
        KeyMaterial::from(AlgebraicKeyMaterial(ciphertext.0 - key.0))
    }
}

impl<'de> Deserialize<'de> for EncryptedKeyMaterial {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        KeyMaterial::deserialize(deserializer).map(Self)
    }
}
