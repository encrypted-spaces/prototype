/// Public-key encryption and key encapsulation primitives.
///
/// This module defines the traits [`Kem`], and [`Mkem`]. We include some implementations:
///
/// - [`MlKem768`], the standard ML-KEM (Kyber) with the Level-3 768-bit parameters, using the `libcrux_ml_kem::mlkem768` implementation
/// - [`XWing`], the XWing hybrid KEM as specified in CFRG draft `draft-connolly-cfrg-xwing-kem-09`. It uses the `libcrux_ml_kem::mlkem768` implementation of kyber, and the `libcrux-ecdh` implementation of X25519;
/// - [`XWingRistrettoMkem`], nearly identical to [`XWing`], but the ECDH implementation is based on `curve25519_dalek::ristretto`, since the Edwards curve representation of curve25519 gives
///   better implementation performance than the Montgomery representation required by `x25519`. This substitutes the group, so it is **not** the draft scheme.
/// - [`Ristretto255Dh`], the simple implementation of Diffie-Hellman that uses the Ristretto group, again since it has better performance than the x25519 option.
///
/// # Default
///
/// [`DefaultMkem`] is the production choice; other implementations are experimental.
///
/// # Single & multi-recipient
///
/// There is a blanket mKEM implementation for any KEM, which just uses the KEM scheme for each recipient.
/// For now, only the ECDH component is specialized for multi-recipient  ([`Ristretto255Dh`], and the ECDH part of [`XWingRistrettoMkem`] and [`XWingMkem`])  by using the same ephemeral DH key pair for each recipient.
/// This reduces both computation time and bandwidth: the shared ephemeral is stored once per group ciphertext
/// and recombined by [`Mkem::get`], so each recipient still receives a self-contained ciphertext.
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
pub use xwing::XWingPublicKey;
pub use xwing_ristretto255::XWingRistretto;
pub use xwing_ristretto255::XWingRistrettoMkem;
pub use xwing_ristretto255::XWingRistrettoPublicKey;

/// The mKEM production uses.
pub type DefaultMkem = XWingRistrettoMkem;

/// Reports the packed and precomputed ML-KEM backends used by this process.
///
/// Packed encapsulation may use libcrux's runtime multiplexer; the unpacked API requires
/// explicit runtime dispatch. Benchmarks should report this value instead of inferring
/// the backend from Cargo features.
pub fn mlkem_backend() -> &'static str {
    match xwing_ristretto255::unpacked_mlkem::backend_name() {
        "avx2" => "packed=multiplexed unpacked=avx2",
        "neon" => "packed=multiplexed unpacked=neon",
        _ => "packed=multiplexed unpacked=portable",
    }
}

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

    /// State prepared for a fixed ordered recipient set.
    type Prepared: Send + Sync;

    /// The key generation function.
    fn keygen<R: CryptoRng + RngCore>(&self, rng: &mut R) -> (Self::PublicKey, Self::SecretKey);

    /// Precompute recipient-key state for repeated encapsulation to the same ordered set.
    /// Implementations with nothing to precompute may retain the keys unchanged.
    fn prepare(&self, pks: &[Self::PublicKey]) -> Self::Prepared;

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

    /// Encapsulate against a precomputed recipient set.
    ///
    /// # Correctness
    ///
    /// For the same recipients and RNG state, this must match [`Mkem::encaps`] exactly,
    /// including RNG consumption; mVE verification recomputes opened repetitions.
    fn encaps_prepared<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        prepared: &Self::Prepared,
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
    type Prepared = Vec<K::PublicKey>;
    const NAME: &'static str = K::NAME;

    fn keygen<R: CryptoRng + RngCore>(&self, rng: &mut R) -> (Self::PublicKey, Self::SecretKey) {
        Kem::keygen(self, rng)
    }

    fn prepare(&self, pks: &[Self::PublicKey]) -> Self::Prepared {
        pks.to_vec()
    }

    fn encaps_prepared<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        prepared: &Self::Prepared,
    ) -> (Self::Ciphertext, KeyMaterial) {
        <Self as Mkem>::encaps(self, rng, prepared)
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
