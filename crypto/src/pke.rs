/// Public-key encryption and key encapsulation primitives.
///
/// This module defines the traits [`Kem`], and [`Mkem`]. We include some implementations:
///
/// - [`MlKem768`], the standard ML-KEM (Kyber) with the Level-3 768-bit parameters, using the `libcrux_ml_kem::mlkem768` implementation
/// - [`XWing`], the XWing hybrid KEM as specified in CFRG draft `draft-connolly-cfrg-xwing-kem-09`. It uses the `libcrux_ml_kem::mlkem768` implementation of kyber, and the `libcrux-ecdh` implementation of X25519;
/// - [`XWingRistrettoMkem`], nearly identical to [`XWing`], but the ECDH implementation is based on `curve25519_dalek::ristretto`, since the Edwards curve representation of curve25519 gives
///   better implementation performance than the Montgomery representation required by `x25519`.
/// - [`Ristretto255Dh`], the simple implementation of Diffie-Hellman that uses the Ristretto group, again since it has better performance than the x25519 option.
///
/// # Default
///
/// External users of this library should rely on [`DefaultMkem`] and not worry about which KEM to pick. **The default implementation is `XWingRistrettoMkem`**.
/// Other options are included for comparison and experimentation.
/// For example, if PQ-privacy is not required, much shorter ciphertexts are possible using only the Ristretto option.
/// Or if hybrid security is not a requirement, much faster encryption and decryption is possible by using only ML-KEM.
///
/// # Single & multi-recipient
///
/// There is a blanket mKEM implementation for any KEM, which just uses the KEM scheme for each recipient.
/// For now, only the ECDH component is specialized for multi-recipient  ([`Ristretto255`], and the ECDH part of [`XwingRistrettoKem`]. [`XWing`])  by using the same ephemeral DH key pair for each recipient.
/// This reduced both computation time and bandwidth.
/// A similar [optimization is known for Kyber](https://www.cryptojedi.org/papers/mkem-20220812.pdf), but is yet to be implemented.
use crate::{EncryptedKeyMaterial, KeyMaterial};
use rand_core::{CryptoRng, RngCore};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::vec::Vec;

pub mod mlkem;
pub mod ristretto255;
pub mod xwing;
pub mod xwing_ristretto255;

pub use mlkem::MlKem768;
pub use ristretto255::Ristretto255Dh;
pub use xwing::XWing;
pub use xwing::XWingMkem;
pub use xwing_ristretto255::XWingRistretto;
pub use xwing_ristretto255::XWingRistrettoMkem;
pub type DefaultMkem = XWingRistrettoMkem;

#[cfg(test)]
pub mod tests;

/// A key-encapsulation mechanism.
pub trait Kem: Clone + Send + Sync + Default {
    type PublicKey: Clone + Send + Sync + Serialize + DeserializeOwned;
    type Ciphertext: Clone + Send + Sync + Serialize + DeserializeOwned;
    type SecretKey;
    const NAME: &'static str;

    fn keygen<R: CryptoRng + RngCore>(&self, rng: &mut R) -> (Self::PublicKey, Self::SecretKey);

    fn encaps<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        pk: &Self::PublicKey,
    ) -> (Self::Ciphertext, KeyMaterial);

    fn decaps(&self, sk: &Self::SecretKey, ct: &Self::Ciphertext) -> Option<KeyMaterial>;
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MkemCiphertext<Ct> {
    pub kem_ct: Ct,
    pub pad: EncryptedKeyMaterial,
}

/// A multi-recipient key encapsulation mechanism (mKEM).
///
/// This trait provides all the functions that are needed by the cryptographic system,
/// and they can be put in the same implementation block,
/// however the type [`KemKeyPair`] is most likely more appropriate for development.
///
///
/// # Implementations
///
/// Any key encapsulation mechanism is also a multi-recipient key-encapsulation mechanism.
/// As such, there is a blanket implementation of this trait for any [`Kem`] to facilitate future adoptions.
pub trait Mkem: Clone + Send + Sync + Default {
    /// The name of the mKEM (for domain separation).
    const NAME: &'static str;

    /// The type of the public key to be used in the system.
    type PublicKey: Clone + Send + Sync + Serialize + DeserializeOwned;
    /// The ciphertexts to be decrypted by the user
    type IndividualCiphertext: Clone + Send + Sync + Serialize + DeserializeOwned;
    /// The (multi-recipient) ciphertext produced by the key-encapsulation function.
    type Ciphertext: Clone + Send + Sync + Serialize + DeserializeOwned;
    //// The secret key type.
    type SecretKey: Clone + Serialize + DeserializeOwned;

    /// The key generation function.
    fn keygen<R: CryptoRng + RngCore>(&self, rng: &mut R) -> (Self::PublicKey, Self::SecretKey);

    /// The key encapsulation function.
    ///
    /// # Determinism
    ///
    /// This function should produce deterministic outputs when the random number generator `rng` is a [`rand::SeedableRng`].
    fn encaps<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        pks: &[Self::PublicKey],
    ) -> (Self::Ciphertext, KeyMaterial);

    /// The ciphertext extraction function.
    ///
    /// Return the i-th individual ciphertext from a batch, or `None` if no such index is found.
    fn get(&self, cts: &Self::Ciphertext, index: usize) -> Option<Self::IndividualCiphertext>;

    /// The key decapsulation mechanism.
    ///
    /// Return the de-caps'd key material using the i-th secret key and the i-th ciphertext.
    /// If decryption fails, [`None`][Option] is returned
    fn decaps(&self, sk: &Self::SecretKey, ct: &Self::IndividualCiphertext) -> Option<KeyMaterial>;
}

impl<K: Kem> Mkem for K
where
    K::SecretKey: Clone + Serialize + DeserializeOwned,
{
    type PublicKey = K::PublicKey;
    type IndividualCiphertext = MkemCiphertext<K::Ciphertext>;
    type Ciphertext = Vec<Self::IndividualCiphertext>;
    type SecretKey = K::SecretKey;
    const NAME: &'static str = K::NAME;

    fn keygen<R: CryptoRng + RngCore>(&self, rng: &mut R) -> (Self::PublicKey, Self::SecretKey) {
        Kem::keygen(self, rng)
    }

    fn encaps<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        pks: &[Self::PublicKey],
    ) -> (Self::Ciphertext, KeyMaterial) {
        let key = KeyMaterial::random_with(rng);
        let mut cts = Vec::with_capacity(pks.len());
        for pk in pks {
            let (kem_ct, shared) = Kem::encaps(self, rng, pk);
            let pad = EncryptedKeyMaterial::encrypt(shared, &key);
            cts.push(MkemCiphertext { kem_ct, pad });
        }
        (cts, key)
    }

    fn get(&self, cts: &Self::Ciphertext, index: usize) -> Option<Self::IndividualCiphertext> {
        cts.get(index).cloned()
    }

    fn decaps(&self, sk: &Self::SecretKey, ct: &Self::IndividualCiphertext) -> Option<KeyMaterial> {
        let shared = Kem::decaps(self, sk, &ct.kem_ct)?;
        Some(ct.pad.decrypt(shared))
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct KemKeyPair<M = DefaultMkem>(M::SecretKey, M::PublicKey)
where
    M: Mkem;

impl<M: Mkem> From<(M::PublicKey, M::SecretKey)> for KemKeyPair<M> {
    fn from((public, private): (M::PublicKey, M::SecretKey)) -> Self {
        Self(private, public)
    }
}

impl<M: Mkem> KemKeyPair<M> {
    pub fn new<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let pke = M::default();
        pke.keygen(rng).into()
    }

    pub fn with_kem<R: CryptoRng + RngCore>(pke: &M, rng: &mut R) -> Self {
        pke.keygen(rng).into()
    }

    /// The public key.
    pub fn public(&self) -> &M::PublicKey {
        &self.1
    }

    /// The decapsulation secret.
    pub fn secret(&self) -> &M::SecretKey {
        &self.0
    }
}
