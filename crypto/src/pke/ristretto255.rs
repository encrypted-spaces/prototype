// Ristretto Diffie-Hellman multi-recipient KEM (mKEM)
//
// This is an optimized mKEM implementation using the Ristretto group from
// curve25519-dalek. It reuses a single ephemeral keypair across all recipients,
// reducing both computation time and ciphertext size compared to running
// independent DH exchanges per recipient.

use rand_core::{CryptoRng, RngCore};

use crate::pke::Mkem;
use crate::{EncryptedKeyMaterial, KeyMaterial};

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar as RistrettoScalar;

/// Ristretto Diffie-Hellman mKEM with ephemeral key reuse optimization.
#[derive(Clone, Debug, Default)]
pub struct Ristretto255Dh;

impl Mkem for Ristretto255Dh {
    type PublicKey = RistrettoPoint;
    type SecretKey = RistrettoScalar;
    type IndividualCiphertext = (CompressedRistretto, EncryptedKeyMaterial);
    type Ciphertext = (CompressedRistretto, Vec<EncryptedKeyMaterial>);
    const NAME: &'static str = "RistrettoDh";

    fn keygen<R: CryptoRng + RngCore>(&self, rng: &mut R) -> (Self::PublicKey, Self::SecretKey) {
        let mut scalar_bytes = [0u8; 64];
        rng.fill_bytes(&mut scalar_bytes);
        let sk = RistrettoScalar::from_bytes_mod_order_wide(&scalar_bytes);
        let pk = RistrettoPoint::mul_base(&sk);

        (pk, sk)
    }

    fn get(&self, cts: &Self::Ciphertext, index: usize) -> Option<Self::IndividualCiphertext> {
        cts.1
            .get(index)
            .map(|key_material| (cts.0, key_material.clone()))
    }

    fn encaps<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        pks: &[Self::PublicKey],
    ) -> (Self::Ciphertext, KeyMaterial) {
        let mut randomness = [0u8; 64];
        rng.fill_bytes(&mut randomness);
        let ephemeral_sk = RistrettoScalar::from_bytes_mod_order_wide(&randomness);
        let ephemeral_pk = RistrettoPoint::mul_base(&ephemeral_sk);
        let message = KeyMaterial::random_with(rng);
        let shared_secrets = pks
            .iter()
            .map(|pk| {
                let shared_secret = pk * ephemeral_sk;
                let key = KeyMaterial::digest(shared_secret.compress().as_bytes());
                EncryptedKeyMaterial::encrypt(key, &message)
            })
            .collect::<Vec<_>>();
        ((ephemeral_pk.compress(), shared_secrets), message)
    }

    fn decaps(&self, sk: &Self::SecretKey, ct: &Self::IndividualCiphertext) -> Option<KeyMaterial> {
        let ephemeral_pk = ct.0.decompress()?;
        let shared_secret = ephemeral_pk * sk;
        let key = KeyMaterial::digest(shared_secret.compress().as_bytes());
        Some(ct.1.decrypt(key))
    }
}
