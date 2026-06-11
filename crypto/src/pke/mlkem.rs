use core::{fmt, ops::Deref};
#[cfg(feature = "avx2")]
use libcrux_ml_kem::mlkem768::avx2::{decapsulate, encapsulate, generate_key_pair};
#[cfg(not(feature = "avx2"))]
use libcrux_ml_kem::mlkem768::{decapsulate, encapsulate, generate_key_pair};
use libcrux_ml_kem::mlkem768::{MlKem768Ciphertext, MlKem768PrivateKey, MlKem768PublicKey};
use rand::Rng;
use rand_core::{CryptoRng, RngCore};
use serde::{de, Deserialize, Serialize};

use crate::{pke::Kem, KeyMaterial};

/// Wrapper that provides cloning support for libcrux' non-Clone public keys.
#[derive(Clone)]
pub struct WrappedMlKemPublicKey(MlKem768PublicKey);

/// Wrapper that provides serde support for libcrux private keys.
#[derive(Clone)]
pub struct WrappedMlKemPrivateKey(MlKem768PrivateKey);

impl fmt::Debug for WrappedMlKemPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WrappedMlKemPublicKey(**redacted**)")
    }
}

impl fmt::Debug for WrappedMlKemPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WrappedMlKemPrivateKey(**redacted**)")
    }
}

impl From<MlKem768PublicKey> for WrappedMlKemPublicKey {
    fn from(value: MlKem768PublicKey) -> Self {
        Self(value)
    }
}

impl From<MlKem768PrivateKey> for WrappedMlKemPrivateKey {
    fn from(value: MlKem768PrivateKey) -> Self {
        Self(value)
    }
}

impl WrappedMlKemPublicKey {
    pub fn into_inner(self) -> MlKem768PublicKey {
        self.0
    }
}

impl WrappedMlKemPrivateKey {
    pub fn into_inner(self) -> MlKem768PrivateKey {
        self.0
    }
}

impl Deref for WrappedMlKemPublicKey {
    type Target = MlKem768PublicKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for WrappedMlKemPrivateKey {
    type Target = MlKem768PrivateKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Serialize for WrappedMlKemPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self.0.as_slice())
    }
}

impl Serialize for WrappedMlKemPrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self.0.as_slice())
    }
}

impl<'de> Deserialize<'de> for WrappedMlKemPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const KEY_SIZE: usize = MlKem768PublicKey::len();
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        if bytes.len() != KEY_SIZE {
            return Err(de::Error::custom(format!(
                "expected {KEY_SIZE} bytes, got {}",
                bytes.len()
            )));
        }
        let array: [u8; KEY_SIZE] = bytes
            .try_into()
            .map_err(|_| de::Error::custom("incorrect ML-KEM public key length"))?;
        Ok(Self(MlKem768PublicKey::from(array)))
    }
}

impl<'de> Deserialize<'de> for WrappedMlKemPrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const KEY_SIZE: usize = MlKem768PrivateKey::len();
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        if bytes.len() != KEY_SIZE {
            return Err(de::Error::custom(format!(
                "expected {KEY_SIZE} bytes, got {}",
                bytes.len()
            )));
        }
        let array: [u8; KEY_SIZE] = bytes
            .try_into()
            .map_err(|_| de::Error::custom("incorrect ML-KEM private key length"))?;
        Ok(Self(MlKem768PrivateKey::from(array)))
    }
}

#[derive(Clone, Debug, Default)]
pub struct MlKem768;

impl Kem for MlKem768 {
    type PublicKey = WrappedMlKemPublicKey;
    type SecretKey = WrappedMlKemPrivateKey;
    type Ciphertext = Vec<u8>;
    const NAME: &'static str = "ML-KEM-768";

    fn keygen<R: CryptoRng + RngCore>(&self, rng: &mut R) -> (Self::PublicKey, Self::SecretKey) {
        let keypair = generate_key_pair(rng.random());
        let (sk, pk) = keypair.into_parts();
        (pk.into(), sk.into())
    }

    fn encaps<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        pk: &Self::PublicKey,
    ) -> (Self::Ciphertext, KeyMaterial) {
        let (ct, shared_secret) = encapsulate(pk, rng.random());
        let ct_vec = Vec::from(ct.as_slice());
        (ct_vec, KeyMaterial::digest(shared_secret.as_ref()))
    }

    fn decaps(&self, sk: &Self::SecretKey, ct: &Self::Ciphertext) -> Option<KeyMaterial> {
        let ciphertext = MlKem768Ciphertext::try_from(ct.as_slice()).ok()?;
        let shared_secret = decapsulate(sk, &ciphertext);
        Some(KeyMaterial::digest(shared_secret.as_ref()))
    }
}
