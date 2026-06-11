// X-Wing KEM implementation following draft-connolly-cfrg-xwing-kem-09
//
// X-Wing is a post-quantum/traditional hybrid KEM combining ML-KEM-768 and X25519.
// This implementation uses libcrux for both primitives (libcrux-ml-kem and libcrux-ecdh).
//
// ## Performance note
// libcrux-ecdh v0.0.5 uses HACL's variable-base scalar multiplication for keygen
// (`secret_to_public`), which is ~2.5x slower than x25519-dalek's fixed-base
// implementation with precomputed tables. The libjade backend in libcrux does have
// optimized `jade_scalarmult_curve25519_amd64_mulx_base` functions, but they are
// not exposed through libcrux-ecdh.
//
// Switching to x25519-dalek for X25519 would give a ~16% improvement in encaps.
// We use libcrux for consistency across all cryptographic primitives.

use core::fmt;

use libcrux_ecdh::{self, X25519PrivateKey, X25519PublicKey};
#[cfg(feature = "avx2")]
use libcrux_ml_kem::mlkem768::avx2::{decapsulate, encapsulate, generate_key_pair};
#[cfg(not(feature = "avx2"))]
use libcrux_ml_kem::mlkem768::{decapsulate, encapsulate, generate_key_pair};
use libcrux_ml_kem::mlkem768::{MlKem768Ciphertext, MlKem768PrivateKey, MlKem768PublicKey};

use rand_core::{CryptoRng, RngCore};
use serde::{de, Deserialize, Serialize};
use sha3::{Digest, Sha3_256, Shake256};

use crate::{
    pke::{Kem, Mkem},
    EncryptedKeyMaterial, KeyMaterial,
};

/// ML-KEM-768 public key size
const MLKEM_PK_SIZE: usize = 1184;
/// X25519 public key size
const X25519_PK_SIZE: usize = 32;
/// X-Wing encapsulation key (public key) size: ML-KEM-768 pk || X25519 pk
const XWING_PK_SIZE: usize = MLKEM_PK_SIZE + X25519_PK_SIZE;

/// ML-KEM-768 ciphertext size
const MLKEM_CT_SIZE: usize = 1088;
/// X-Wing ciphertext size: ML-KEM-768 ct || X25519 ephemeral pk
const XWING_CT_SIZE: usize = MLKEM_CT_SIZE + X25519_PK_SIZE;

/// X-Wing shared secret size (SHA3-256 output)
const XWING_SS_SIZE: usize = 32;

/// Domain separation label following X-Wing spec.
/// XWingLabel = "\./^\" = 0x5c2e2f2f5e5c (6 bytes ASCII)
///
/// From the spec:
/// ```text
/// XWingLabel = concat(
///     "\./",  // 0x5c2e2f
///     "/^\",  // 0x2f5e5c
/// )
/// ```
const XWING_LABEL: &[u8; 6] = b"\\.//^\\";

/// X-Wing public key (encapsulation key).
///
/// Layout: pk_M (1184 bytes) || pk_X (32 bytes)
#[derive(Clone)]
pub struct XWingPublicKey([u8; XWING_PK_SIZE]);

impl fmt::Debug for XWingPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("XWingPublicKey(**redacted**)")
    }
}

impl XWingPublicKey {
    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; XWING_PK_SIZE]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; XWING_PK_SIZE] {
        &self.0
    }

    /// Extract ML-KEM-768 public key portion.
    fn mlkem_pk(&self) -> MlKem768PublicKey {
        let mut pk_bytes = [0u8; MLKEM_PK_SIZE];
        pk_bytes.copy_from_slice(&self.0[..MLKEM_PK_SIZE]);
        MlKem768PublicKey::from(pk_bytes)
    }

    /// Extract X25519 public key portion.
    fn x25519_pk(&self) -> X25519PublicKey {
        let mut pk_bytes = [0u8; X25519_PK_SIZE];
        pk_bytes.copy_from_slice(&self.0[MLKEM_PK_SIZE..]);
        X25519PublicKey::from(&pk_bytes)
    }

    /// Get X25519 public key bytes.
    fn x25519_pk_bytes(&self) -> [u8; 32] {
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(&self.0[MLKEM_PK_SIZE..]);
        pk_bytes
    }
}

impl Serialize for XWingPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for XWingPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        if bytes.len() != XWING_PK_SIZE {
            return Err(de::Error::custom(format!(
                "expected {XWING_PK_SIZE} bytes for X-Wing public key, got {}",
                bytes.len()
            )));
        }
        let mut pk = [0u8; XWING_PK_SIZE];
        pk.copy_from_slice(&bytes);
        Ok(Self(pk))
    }
}

/// X-Wing ciphertext.
///
/// Layout: ct_M (1088 bytes) || ct_X (32 bytes)
#[derive(Clone)]
pub struct XWingCiphertext([u8; XWING_CT_SIZE]);

impl fmt::Debug for XWingCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("XWingCiphertext(**redacted**)")
    }
}

impl XWingCiphertext {
    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; XWING_CT_SIZE]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; XWING_CT_SIZE] {
        &self.0
    }

    /// Extract ML-KEM-768 ciphertext portion.
    fn mlkem_ct(&self) -> MlKem768Ciphertext {
        let mut ct_bytes = [0u8; MLKEM_CT_SIZE];
        ct_bytes.copy_from_slice(&self.0[..MLKEM_CT_SIZE]);
        MlKem768Ciphertext::from(ct_bytes)
    }

    /// Extract X25519 ephemeral public key (ciphertext portion).
    fn x25519_ct(&self) -> X25519PublicKey {
        let mut ct_bytes = [0u8; X25519_PK_SIZE];
        ct_bytes.copy_from_slice(&self.0[MLKEM_CT_SIZE..]);
        X25519PublicKey::from(&ct_bytes)
    }

    /// Get X25519 ciphertext bytes.
    fn x25519_ct_bytes(&self) -> [u8; 32] {
        let mut ct_bytes = [0u8; 32];
        ct_bytes.copy_from_slice(&self.0[MLKEM_CT_SIZE..]);
        ct_bytes
    }
}

impl Serialize for XWingCiphertext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for XWingCiphertext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        if bytes.len() != XWING_CT_SIZE {
            return Err(de::Error::custom(format!(
                "expected {XWING_CT_SIZE} bytes for X-Wing ciphertext, got {}",
                bytes.len()
            )));
        }
        let mut ct = [0u8; XWING_CT_SIZE];
        ct.copy_from_slice(&bytes);
        Ok(Self(ct))
    }
}

/// X-Wing secret key (decapsulation key).
///
/// The 32-byte seed from which the expanded keys are derived.
/// We also cache the expanded keys for efficiency (as recommended by the spec).
#[derive(Clone)]
pub struct XWingSecretKey {
    /// The original 32-byte seed.
    seed: [u8; 32],
    /// Cached ML-KEM-768 secret key.
    sk_m: MlKem768PrivateKey,
    /// Cached X25519 secret key bytes (X25519PrivateKey doesn't impl Clone).
    sk_x_bytes: [u8; 32],
    /// Cached X25519 public key (needed for combiner during decapsulation).
    pk_x: [u8; 32],
}

impl XWingSecretKey {
    /// Get the seed bytes.
    pub fn as_seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// Get the X25519 private key.
    fn sk_x(&self) -> X25519PrivateKey {
        X25519PrivateKey::from(&self.sk_x_bytes)
    }
}

impl Serialize for XWingSecretKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.seed.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for XWingSecretKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let seed = <[u8; 32]>::deserialize(deserializer)?;
        let (sk_m, sk_x_bytes, _pk_m, pk_x) = expand_decapsulation_key(&seed);
        Ok(Self {
            seed,
            sk_m,
            sk_x_bytes,
            pk_x,
        })
    }
}

/// Expand a 32-byte seed into ML-KEM and X25519 key material.
///
/// From the spec:
/// ```text
/// def expandDecapsulationKey(sk):
///   expanded = SHAKE256(sk, 96*8)  # 96 bytes
///   (pk_M, sk_M) = ML-KEM-768.KeyGen_internal(expanded[0:32], expanded[32:64])
///   sk_X = expanded[64:96]
///   pk_X = X25519(sk_X, X25519_BASE)
///   return (sk_M, sk_X, pk_M, pk_X)
/// ```
///
/// Returns (sk_m, sk_x_bytes, pk_m, pk_x_bytes)
fn expand_decapsulation_key(
    seed: &[u8; 32],
) -> (MlKem768PrivateKey, [u8; 32], MlKem768PublicKey, [u8; 32]) {
    use sha3::digest::{ExtendableOutput, Update, XofReader};

    // Expand seed to 96 bytes using SHAKE256
    let mut shake = Shake256::default();
    Update::update(&mut shake, seed);
    let mut reader = shake.finalize_xof();
    let mut expanded = [0u8; 96];
    reader.read(&mut expanded);

    // ML-KEM-768 keygen from the first 64 bytes (d || z)
    // libcrux's generate_key_pair takes 64 bytes of randomness
    let mut mlkem_seed = [0u8; 64];
    mlkem_seed.copy_from_slice(&expanded[0..64]);
    let keypair = generate_key_pair(mlkem_seed);
    let (sk_m, pk_m) = keypair.into_parts();

    // X25519 secret key from bytes 64-96
    let mut sk_x_bytes = [0u8; 32];
    sk_x_bytes.copy_from_slice(&expanded[64..96]);
    let sk_x = X25519PrivateKey::from(&sk_x_bytes);

    // Compute X25519 public key
    let pk_x_bytes = libcrux_ecdh::secret_to_public(libcrux_ecdh::Algorithm::X25519, &sk_x)
        .expect("X25519 secret_to_public should not fail");
    let mut pk_x = [0u8; 32];
    pk_x.copy_from_slice(pk_x_bytes.as_slice());

    (sk_m, sk_x_bytes, pk_m, pk_x)
}

/// The X-Wing combiner function.
///
/// From the spec:
/// ```text
/// def Combiner(ss_M, ss_X, ct_X, pk_X):
///     return SHA3-256(
///         ss_M ||
///         ss_X ||
///         ct_X ||
///         pk_X ||
///         XWingLabel
///     )
/// ```
fn combiner(
    ss_m: &[u8; 32],
    ss_x: &[u8; 32],
    ct_x: &[u8; 32],
    pk_x: &[u8; 32],
) -> [u8; XWING_SS_SIZE] {
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, ss_m);
    Digest::update(&mut hasher, ss_x);
    Digest::update(&mut hasher, ct_x);
    Digest::update(&mut hasher, pk_x);
    Digest::update(&mut hasher, XWING_LABEL);
    let result = Digest::finalize(hasher);
    let mut ss = [0u8; XWING_SS_SIZE];
    ss.copy_from_slice(&result);
    ss
}

/// X-Wing KEM following draft-connolly-cfrg-xwing-kem-09.
#[derive(Clone, Debug, Default)]
pub struct XWing;

impl Kem for XWing {
    type PublicKey = XWingPublicKey;
    type SecretKey = XWingSecretKey;
    type Ciphertext = XWingCiphertext;
    const NAME: &'static str = "X-Wing";

    fn keygen<R: CryptoRng + RngCore>(&self, rng: &mut R) -> (Self::PublicKey, Self::SecretKey) {
        // Generate random 32-byte seed
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);

        self.keygen_from_seed(seed)
    }

    fn encaps<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        pk: &Self::PublicKey,
    ) -> (Self::Ciphertext, KeyMaterial) {
        // Generate random 64-byte encapsulation seed
        let mut eseed = [0u8; 64];
        rng.fill_bytes(&mut eseed);

        self.encaps_deterministic(pk, &eseed)
    }

    fn decaps(&self, sk: &Self::SecretKey, ct: &Self::Ciphertext) -> Option<KeyMaterial> {
        // ML-KEM-768 decapsulation
        let ct_m = ct.mlkem_ct();
        let ss_m = decapsulate(&sk.sk_m, &ct_m);

        // X25519 DH
        let ct_x = ct.x25519_ct();
        let sk_x = sk.sk_x();
        let ss_x = libcrux_ecdh::derive(libcrux_ecdh::Algorithm::X25519, &ct_x, &sk_x).ok()?;

        // Combine shared secrets
        let mut ss_m_bytes = [0u8; 32];
        ss_m_bytes.copy_from_slice(ss_m.as_ref());
        let mut ss_x_bytes = [0u8; 32];
        ss_x_bytes.copy_from_slice(ss_x.as_ref());

        let ss = combiner(&ss_m_bytes, &ss_x_bytes, &ct.x25519_ct_bytes(), &sk.pk_x);
        Some(KeyMaterial::digest(&ss))
    }
}

impl XWing {
    /// Deterministic key generation from a 32-byte seed.
    /// This is `GenerateKeyPairDerand` from the spec.
    pub fn keygen_from_seed(&self, seed: [u8; 32]) -> (XWingPublicKey, XWingSecretKey) {
        let (sk_m, sk_x_bytes, pk_m, pk_x) = expand_decapsulation_key(&seed);

        // Construct public key: pk_M || pk_X
        let mut pk_bytes = [0u8; XWING_PK_SIZE];
        pk_bytes[..MLKEM_PK_SIZE].copy_from_slice(pk_m.as_slice());
        pk_bytes[MLKEM_PK_SIZE..].copy_from_slice(&pk_x);

        let pk = XWingPublicKey(pk_bytes);
        let sk = XWingSecretKey {
            seed,
            sk_m,
            sk_x_bytes,
            pk_x,
        };

        (pk, sk)
    }

    /// Deterministic encapsulation from a 64-byte seed.
    /// This is `EncapsulateDerand` from the spec.
    pub fn encaps_deterministic(
        &self,
        pk: &XWingPublicKey,
        eseed: &[u8; 64],
    ) -> (XWingCiphertext, KeyMaterial) {
        let pk_m = pk.mlkem_pk();
        let pk_x = pk.x25519_pk();
        let pk_x_bytes = pk.x25519_pk_bytes();

        // X25519 ephemeral keypair from eseed[32:64]
        let mut ek_x_bytes = [0u8; 32];
        ek_x_bytes.copy_from_slice(&eseed[32..64]);
        let ek_x = X25519PrivateKey::from(&ek_x_bytes);

        // ct_X = X25519(ek_X, BASE)
        let ct_x_bytes_vec = libcrux_ecdh::secret_to_public(libcrux_ecdh::Algorithm::X25519, &ek_x)
            .expect("X25519 secret_to_public should not fail");
        let mut ct_x_bytes = [0u8; 32];
        ct_x_bytes.copy_from_slice(ct_x_bytes_vec.as_slice());

        // ss_X = X25519(ek_X, pk_X)
        let ss_x_bytes_vec = libcrux_ecdh::derive(libcrux_ecdh::Algorithm::X25519, &pk_x, &ek_x)
            .expect("X25519 derive should not fail");
        let mut ss_x_bytes = [0u8; 32];
        ss_x_bytes.copy_from_slice(ss_x_bytes_vec.as_ref());

        // ML-KEM-768 encapsulation with eseed[0:32] as randomness
        let mut mlkem_rand = [0u8; 32];
        mlkem_rand.copy_from_slice(&eseed[0..32]);
        let (ct_m, ss_m) = encapsulate(&pk_m, mlkem_rand);
        let mut ss_m_bytes = [0u8; 32];
        ss_m_bytes.copy_from_slice(ss_m.as_ref());

        // Construct ciphertext: ct_M || ct_X
        let mut ct_bytes = [0u8; XWING_CT_SIZE];
        ct_bytes[..MLKEM_CT_SIZE].copy_from_slice(ct_m.as_slice());
        ct_bytes[MLKEM_CT_SIZE..].copy_from_slice(&ct_x_bytes);

        // Combine shared secrets
        let ss = combiner(&ss_m_bytes, &ss_x_bytes, &ct_x_bytes, &pk_x_bytes);

        (XWingCiphertext(ct_bytes), KeyMaterial::digest(&ss))
    }

    /// Get the raw 32-byte shared secret without KeyMaterial transformation.
    /// This is useful for testing against spec test vectors.
    pub fn encaps_deterministic_raw(
        &self,
        pk: &XWingPublicKey,
        eseed: &[u8; 64],
    ) -> (XWingCiphertext, [u8; 32]) {
        let pk_m = pk.mlkem_pk();
        let pk_x = pk.x25519_pk();
        let pk_x_bytes = pk.x25519_pk_bytes();

        // X25519 ephemeral keypair from eseed[32:64]
        let mut ek_x_bytes = [0u8; 32];
        ek_x_bytes.copy_from_slice(&eseed[32..64]);
        let ek_x = X25519PrivateKey::from(&ek_x_bytes);

        // ct_X = X25519(ek_X, BASE)
        let ct_x_bytes_vec = libcrux_ecdh::secret_to_public(libcrux_ecdh::Algorithm::X25519, &ek_x)
            .expect("X25519 secret_to_public should not fail");
        let mut ct_x_bytes = [0u8; 32];
        ct_x_bytes.copy_from_slice(ct_x_bytes_vec.as_slice());

        // ss_X = X25519(ek_X, pk_X)
        let ss_x_bytes_vec = libcrux_ecdh::derive(libcrux_ecdh::Algorithm::X25519, &pk_x, &ek_x)
            .expect("X25519 derive should not fail");
        let mut ss_x_bytes = [0u8; 32];
        ss_x_bytes.copy_from_slice(ss_x_bytes_vec.as_ref());

        // ML-KEM-768 encapsulation with eseed[0:32] as randomness
        let mut mlkem_rand = [0u8; 32];
        mlkem_rand.copy_from_slice(&eseed[0..32]);
        let (ct_m, ss_m) = encapsulate(&pk_m, mlkem_rand);
        let mut ss_m_bytes = [0u8; 32];
        ss_m_bytes.copy_from_slice(ss_m.as_ref());

        // Construct ciphertext: ct_M || ct_X
        let mut ct_bytes = [0u8; XWING_CT_SIZE];
        ct_bytes[..MLKEM_CT_SIZE].copy_from_slice(ct_m.as_slice());
        ct_bytes[MLKEM_CT_SIZE..].copy_from_slice(&ct_x_bytes);

        // Combine shared secrets
        let ss = combiner(&ss_m_bytes, &ss_x_bytes, &ct_x_bytes, &pk_x_bytes);

        (XWingCiphertext(ct_bytes), ss)
    }

    /// Get the raw 32-byte shared secret from decapsulation.
    /// This is useful for testing against spec test vectors.
    pub fn decaps_raw(&self, sk: &XWingSecretKey, ct: &XWingCiphertext) -> Option<[u8; 32]> {
        // ML-KEM-768 decapsulation
        let ct_m = ct.mlkem_ct();
        let ss_m = decapsulate(&sk.sk_m, &ct_m);

        // X25519 DH
        let ct_x = ct.x25519_ct();
        let sk_x = sk.sk_x();
        let ss_x = libcrux_ecdh::derive(libcrux_ecdh::Algorithm::X25519, &ct_x, &sk_x).ok()?;

        // Combine shared secrets
        let mut ss_m_bytes = [0u8; 32];
        ss_m_bytes.copy_from_slice(ss_m.as_ref());
        let mut ss_x_bytes = [0u8; 32];
        ss_x_bytes.copy_from_slice(ss_x.as_ref());

        Some(combiner(
            &ss_m_bytes,
            &ss_x_bytes,
            &ct.x25519_ct_bytes(),
            &sk.pk_x,
        ))
    }
}

// ============================================================================
// Optimized multi-recipient KEM (mKEM) implementation for X-Wing
// ============================================================================
//
// This provides a specialized `Mkem` implementation for X-Wing that is more efficient
// than the generic blanket implementation in `pke.rs`. It reuses the X25519 ephemeral
// key for all recipients.

#[derive(Clone, Debug, Default)]
pub struct XWingMkem(XWing);

/// Ciphertext for the X-Wing-based mKEM.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct XWingMkemCiphertext {
    /// Shared ephemeral X25519 public key (ct_x), used by all recipients.
    ct_x: [u8; 32],
    /// Per-recipient ciphertexts containing ML-KEM ciphertext and encrypted key.
    cts: Vec<XWingMkemIndividualCiphertext>,
}

/// Individual ciphertext for a single recipient.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct XWingMkemIndividualCiphertext {
    /// The shared ephemeral X25519 public key (needed for decapsulation).
    ct_x: [u8; 32],
    /// Per-recipient ML-KEM-768 ciphertext (1088 bytes).
    ct_m: Vec<u8>,
    /// Encrypted key material for the shared group key.
    ct_key: EncryptedKeyMaterial,
}

impl Mkem for XWingMkem {
    const NAME: &'static str = "X-Wing-mKEM";

    type PublicKey = XWingPublicKey;
    type IndividualCiphertext = XWingMkemIndividualCiphertext;
    type Ciphertext = XWingMkemCiphertext;
    type SecretKey = XWingSecretKey;

    fn keygen<R: CryptoRng + RngCore>(&self, rng: &mut R) -> (Self::PublicKey, Self::SecretKey) {
        // Key generation is the same as regular X-Wing
        Kem::keygen(&self.0, rng)
    }

    fn encaps<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        pks: &[Self::PublicKey],
    ) -> (Self::Ciphertext, KeyMaterial) {
        // Generate the shared key that all recipients will recover
        let key = KeyMaterial::random_with(rng);

        // Generate ONE ephemeral X25519 keypair (reused across all recipients)
        let mut ek_x_bytes = [0u8; 32];
        rng.fill_bytes(&mut ek_x_bytes);
        let ek_x = X25519PrivateKey::from(&ek_x_bytes);

        // ct_x = X25519(ek_x, BASE) — the shared ephemeral public key
        let ct_x_vec = libcrux_ecdh::secret_to_public(libcrux_ecdh::Algorithm::X25519, &ek_x)
            .expect("X25519 secret_to_public should not fail");
        let mut ct_x = [0u8; 32];
        ct_x.copy_from_slice(ct_x_vec.as_slice());

        let mut cts = Vec::with_capacity(pks.len());

        for pk in pks {
            // Extract recipient's component keys
            let pk_m = pk.mlkem_pk();
            let pk_x = pk.x25519_pk();
            let pk_x_bytes = pk.x25519_pk_bytes();

            // X25519 DH with recipient's public key (reusing our ephemeral key)
            let ss_x_vec = libcrux_ecdh::derive(libcrux_ecdh::Algorithm::X25519, &pk_x, &ek_x)
                .expect("X25519 derive should not fail");
            let mut ss_x = [0u8; 32];
            ss_x.copy_from_slice(ss_x_vec.as_ref());

            // Fresh ML-KEM encapsulation for this recipient
            let mut mlkem_rand = [0u8; 32];
            rng.fill_bytes(&mut mlkem_rand);
            let (ct_m, ss_m) = encapsulate(&pk_m, mlkem_rand);
            let mut ss_m_bytes = [0u8; 32];
            ss_m_bytes.copy_from_slice(ss_m.as_ref());

            // Combine to get per-recipient shared secret (using X-Wing combiner)
            let ss = combiner(&ss_m_bytes, &ss_x, &ct_x, &pk_x_bytes);
            let shared = KeyMaterial::digest(&ss);

            let ct_key = EncryptedKeyMaterial::encrypt(shared, &key);

            cts.push(XWingMkemIndividualCiphertext {
                ct_x,
                ct_m: ct_m.as_slice().to_vec(),
                ct_key,
            });
        }

        (XWingMkemCiphertext { ct_x, cts }, key)
    }

    fn get(&self, cts: &Self::Ciphertext, index: usize) -> Option<Self::IndividualCiphertext> {
        cts.cts.get(index).cloned()
    }

    fn decaps(&self, sk: &Self::SecretKey, ct: &Self::IndividualCiphertext) -> Option<KeyMaterial> {
        // Reconstruct ML-KEM ciphertext
        if ct.ct_m.len() != MLKEM_CT_SIZE {
            return None;
        }
        let mut ct_m_bytes = [0u8; MLKEM_CT_SIZE];
        ct_m_bytes.copy_from_slice(&ct.ct_m);
        let ct_m = MlKem768Ciphertext::from(ct_m_bytes);

        // ML-KEM decapsulation
        let ss_m = decapsulate(&sk.sk_m, &ct_m);
        let mut ss_m_bytes = [0u8; 32];
        ss_m_bytes.copy_from_slice(ss_m.as_ref());

        // X25519 DH with the shared ephemeral public key
        let ct_x_pk = X25519PublicKey::from(&ct.ct_x);
        let sk_x = sk.sk_x();
        let ss_x_vec =
            libcrux_ecdh::derive(libcrux_ecdh::Algorithm::X25519, &ct_x_pk, &sk_x).ok()?;
        let mut ss_x = [0u8; 32];
        ss_x.copy_from_slice(ss_x_vec.as_ref());

        // Combine using X-Wing combiner (pk_x is our own public key)
        let ss = combiner(&ss_m_bytes, &ss_x, &ct.ct_x, &sk.pk_x);
        let shared = KeyMaterial::digest(&ss);

        Some(ct.ct_key.decrypt(shared))
    }
}

impl XWingMkem {
    /// Create a new X-Wing mKEM instance.
    pub fn new() -> Self {
        Self(XWing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the X-Wing label matches the spec.
    /// XWingLabel = 0x5c2e2f2f5e5c = "\.//^\"
    #[test]
    fn test_xwing_label() {
        assert_eq!(XWING_LABEL.len(), 6);
        assert_eq!(hex::encode(XWING_LABEL), "5c2e2f2f5e5c");

        // Verify each byte matches the spec
        assert_eq!(XWING_LABEL[0], b'\\'); // 0x5c
        assert_eq!(XWING_LABEL[1], b'.'); // 0x2e
        assert_eq!(XWING_LABEL[2], b'/'); // 0x2f
        assert_eq!(XWING_LABEL[3], b'/'); // 0x2f
        assert_eq!(XWING_LABEL[4], b'^'); // 0x5e
        assert_eq!(XWING_LABEL[5], b'\\'); // 0x5c
    }

    /// Test combiner determinism.
    #[test]
    fn test_combiner_deterministic() {
        let ss_m = [0u8; 32];
        let ss_x = [1u8; 32];
        let ct_x = [2u8; 32];
        let pk_x = [3u8; 32];

        let result1 = combiner(&ss_m, &ss_x, &ct_x, &pk_x);
        let result2 = combiner(&ss_m, &ss_x, &ct_x, &pk_x);

        assert_eq!(result1, result2);
    }

    /// Test that changing any combiner input changes the output.
    #[test]
    fn test_combiner_input_sensitivity() {
        let ss_m = [0u8; 32];
        let ss_x = [1u8; 32];
        let ct_x = [2u8; 32];
        let pk_x = [3u8; 32];

        let baseline = combiner(&ss_m, &ss_x, &ct_x, &pk_x);

        // Change ss_m
        let mut ss_m_alt = ss_m;
        ss_m_alt[0] = 0xff;
        assert_ne!(baseline, combiner(&ss_m_alt, &ss_x, &ct_x, &pk_x));

        // Change ss_x
        let mut ss_x_alt = ss_x;
        ss_x_alt[0] = 0xff;
        assert_ne!(baseline, combiner(&ss_m, &ss_x_alt, &ct_x, &pk_x));

        // Change ct_x
        let mut ct_x_alt = ct_x;
        ct_x_alt[0] = 0xff;
        assert_ne!(baseline, combiner(&ss_m, &ss_x, &ct_x_alt, &pk_x));

        // Change pk_x
        let mut pk_x_alt = pk_x;
        pk_x_alt[0] = 0xff;
        assert_ne!(baseline, combiner(&ss_m, &ss_x, &ct_x, &pk_x_alt));
    }

    /// Test basic roundtrip: keygen -> encaps -> decaps.
    #[test]
    fn test_xwing_roundtrip() {
        let xwing = XWing;
        let mut rng = rand::rng();

        let (pk, sk) = Kem::keygen(&xwing, &mut rng);
        let (ct, expected_key) = Kem::encaps(&xwing, &mut rng, &pk);
        let decapped_key = Kem::decaps(&xwing, &sk, &ct).expect("decaps should succeed");

        assert_eq!(expected_key.as_bytes(), decapped_key.as_bytes());
    }

    /// Test roundtrip with raw shared secrets.
    #[test]
    fn test_xwing_roundtrip_raw() {
        let xwing = XWing;

        let seed = [0x42u8; 32];
        let eseed = [0x37u8; 64];

        let (pk, sk) = xwing.keygen_from_seed(seed);
        let (ct, ss_encaps) = xwing.encaps_deterministic_raw(&pk, &eseed);
        let ss_decaps = xwing.decaps_raw(&sk, &ct).expect("decaps should succeed");

        assert_eq!(ss_encaps, ss_decaps);
    }

    /// Test vector 1 from draft-connolly-cfrg-xwing-kem-09 Appendix C.
    ///
    /// seed:  7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26
    /// eseed: 3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2
    ///        35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2
    /// ss:    d2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384
    #[test]
    fn test_spec_vector_1() {
        let xwing = XWing;

        let seed = hex::decode("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
            .unwrap();
        let mut seed_array = [0u8; 32];
        seed_array.copy_from_slice(&seed);

        let eseed = hex::decode(
            "3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2\
             35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2",
        )
        .unwrap();
        let mut eseed_array = [0u8; 64];
        eseed_array.copy_from_slice(&eseed);

        let expected_pk = hex::decode(
            "e2236b35a8c24b39b10aa1323a96a919a2ced88400633a7b07131713fc14b2b5b19cfc3d\
             a5fa1a92c49f25513e0fd30d6b1611c9ab9635d7086727a4b7d21d34244e66969cf15b3b\
             2a785329f61b096b277ea037383479a6b556de7231fe4b7fa9c9ac24c0699a0018a52534\
             01bacfa905ca816573e56a2d2e067e9b7287533ba13a937dedb31fa44baced4076992361\
             0034ae31e619a170245199b3c5c39864859fe1b4c9717a07c30495bdfb98a0a002ccf56c\
             1286cef5041dede3c44cf16bf562c7448518026b3d8b9940680abd38a1575fd27b58da06\
             3bfac32c39c30869374c05c1aeb1898b6b303cc68be455346ee0af699636224a148ca2ae\
             a10463111c709f69b69c70ce8538746698c4c60a9aef0030c7924ceec42a5d36816f545e\
             ae13293460b3acb37ea0e13d70e4aa78686da398a8397c08eaf96882113fe4f7bad4da40\
             b0501e1c753efe73053c87014e8661c33099afe8bede414a5b1aa27d8392b3e131e9a70c\
             1055878240cad0f40d5fe3cdf85236ead97e2a97448363b2808caafd516cd25052c5c362\
             543c2517e4acd0e60ec07163009b6425fc32277acee71c24bab53ed9f29e74c66a0a3564\
             955998d76b96a9a8b50d1635a4d7a67eb42df5644d330457293a8042f53cc7a69288f17e\
             d55827e82b28e82665a86a14fbd96645eca8172c044f83bc0d8c0b4c8626985631ca87af\
             829068f1358963cb333664ca482763ba3b3bb208577f9ba6ac62c25f76592743b64be519\
             317714cb4102cb7b2f9a25b2b4f0615de31decd9ca55026d6da0b65111b16fe52feed8a4\
             87e144462a6dba93728f500b6ffc49e515569ef25fed17aff520507368253525860f58be\
             3be61c964604a6ac814e6935596402a520a4670b3d284318866593d15a4bb01c35e3e587\
             ee0c67d2880d6f2407fb7a70712b838deb96c5d7bf2b44bcf6038ccbe33fbcf51a54a584\
             fe90083c91c7a6d43d4fb15f48c60c2fd66e0a8aad4ad64e5c42bb8877c0ebec2b5e387c\
             8a988fdc23beb9e16c8757781e0a1499c61e138c21f216c29d076979871caa6942bafc09\
             0544bee99b54b16cb9a9a364d6246d9f42cce53c66b59c45c8f9ae9299a75d15180c3c95\
             2151a91b7a10772429dc4cbae6fcc622fa8018c63439f890630b9928db6bb7f9438ae406\
             5ed34d73d486f3f52f90f0807dc88dfdd8c728e954f1ac35c06c000ce41a0582580e3bb5\
             7b672972890ac5e7988e7850657116f1b57d0809aaedec0bede1ae148148311c6f7e3173\
             46e5189fb8cd635b986f8c0bdd27641c584b778b3a911a80be1c9692ab8e1bbb12839573\
             cce19df183b45835bbb55052f9fc66a1678ef2a36dea78411e6c8d60501b4e60592d1369\
             8a943b509185db912e2ea10be06171236b327c71716094c964a68b03377f513a05bcd99c\
             1f346583bb052977a10a12adfc758034e5617da4c1276585e5774e1f3b9978b09d0e9c44\
             d3bc86151c43aad185712717340223ac381d21150a04294e97bb13bbda21b5a182b6da96\
             9e19a7fd072737fa8e880a53c2428e3d049b7d2197405296ddb361912a7bcf4827ced611\
             d0c7a7da104dde4322095339f64a61d5bb108ff0bf4d780cae509fb22c256914193ff734\
             9042581237d522828824ee3bdfd07fb03f1f942d2ea179fe722f06cc03de5b69859edb06\
             eff389b27dce59844570216223593d4ba32d9abac8cd049040ef6534",
        )
        .unwrap();

        let expected_ct = hex::decode(
            "b83aa828d4d62b9a83ceffe1d3d3bb1ef31264643c070c5798927e41fb07914a273f8f96\
             e7826cd5375a283d7da885304c5de0516a0f0654243dc5b97f8bfeb831f68251219aabdd\
             723bc6512041acbaef8af44265524942b902e68ffd23221cda70b1b55d776a92d1143ea3\
             a0c475f63ee6890157c7116dae3f62bf72f60acd2bb8cc31ce2ba0de364f52b8ed38c79d\
             719715963a5dd3842d8e8b43ab704e4759b5327bf027c63c8fa857c4908d5a8a7b88ac7f\
             2be394d93c3706ddd4e698cc6ce370101f4d0213254238b4a2e8821b6e414a1cf20f6c12\
             44b699046f5a01caa0a1a55516300b40d2048c77cc73afba79afeea9d2c0118bdf2adb88\
             70dc328c5516cc45b1a2058141039e2c90a110a9e16b318dfb53bd49a126d6b73f215787\
             517b8917cc01cabd107d06859854ee8b4f9861c226d3764c87339ab16c3667d2f49384e5\
             5456dd40414b70a6af841585f4c90c68725d57704ee8ee7ce6e2f9be582dbee985e038ff\
             c346ebfb4e22158b6c84374a9ab4a44e1f91de5aac5197f89bc5e5442f51f9a5937b102b\
             a3beaebf6e1c58380a4a5fedce4a4e5026f88f528f59ffd2db41752b3a3d90efabe46389\
             9b7d40870c530c8841e8712b733668ed033adbfafb2d49d37a44d4064e5863eb0af0a08d\
             47b3cc888373bc05f7a33b841bc2587c57eb69554e8a3767b7506917b6b70498727f16ea\
             c1a36ec8d8cfaf751549f2277db277e8a55a9a5106b23a0206b4721fa9b3048552c5bd5b\
             594d6e247f38c18c591aea7f56249c72ce7b117afcc3a8621582f9cf71787e183dee0936\
             7976e98409ad9217a497df888042384d7707a6b78f5f7fb8409e3b535175373461b77600\
             2d799cbad62860be70573ecbe13b246e0da7e93a52168e0fb6a9756b895ef7f0147a0dc8\
             1bfa644b088a9228160c0f9acf1379a2941cd28c06ebc80e44e17aa2f8177010afd78a97\
             ce0868d1629ebb294c5151812c583daeb88685220f4da9118112e07041fcc24d5564a99f\
             dbde28869fe0722387d7a9a4d16e1cc8555917e09944aa5ebaaaec2cf62693afad42a3f5\
             18fce67d273cc6c9fb5472b380e8573ec7de06a3ba2fd5f931d725b493026cb0acbd3fe6\
             2d00e4c790d965d7a03a3c0b4222ba8c2a9a16e2ac658f572ae0e746eafc4feba023576f\
             08942278a041fb82a70a595d5bacbf297ce2029898a71e5c3b0d1c6228b485b1ade509b3\
             5fbca7eca97b2132e7cb6bc465375146b7dceac969308ac0c2ac89e7863eb8943015b243\
             14cafb9c7c0e85fe543d56658c213632599efabfc1ec49dd8c88547bb2cc40c9d38cbd30\
             99b4547840560531d0188cd1e9c23a0ebee0a03d5577d66b1d2bcb4baaf21cc7fef1e038\
             06ca96299df0dfbc56e1b2b43e4fc20c37f834c4af62127e7dae86c3c25a2f696ac8b589\
             dec71d595bfbe94b5ed4bc07d800b330796fda89edb77be0294136139354eb8cd3759157\
             8f9c600dd9be8ec6219fdd507adf3397ed4d68707b8d13b24ce4cd8fb22851bfe9d63240\
             7f31ed6f7cb1600de56f17576740ce2a32fc5145030145cfb97e63e0e41d354274a079d3\
             e6fb2e15",
        )
        .unwrap();

        let expected_ss =
            hex::decode("d2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384")
                .unwrap();

        // Generate keypair from seed
        let (pk, sk) = xwing.keygen_from_seed(seed_array);

        // Verify public key matches
        assert_eq!(
            pk.as_bytes().as_slice(),
            expected_pk.as_slice(),
            "Public key mismatch"
        );

        // Encapsulate with deterministic seed
        let (ct, ss) = xwing.encaps_deterministic_raw(&pk, &eseed_array);

        // Verify ciphertext matches
        assert_eq!(
            ct.as_bytes().as_slice(),
            expected_ct.as_slice(),
            "Ciphertext mismatch"
        );

        // Verify shared secret matches
        assert_eq!(
            ss.as_slice(),
            expected_ss.as_slice(),
            "Shared secret mismatch"
        );

        // Verify decapsulation produces same shared secret
        let ss_dec = xwing.decaps_raw(&sk, &ct).expect("decaps should succeed");
        assert_eq!(
            ss_dec.as_slice(),
            expected_ss.as_slice(),
            "Decapsulated shared secret mismatch"
        );
    }

    /// Test vector 2 from draft-connolly-cfrg-xwing-kem-09 Appendix C.
    #[test]
    fn test_spec_vector_2() {
        let xwing = XWing;

        let seed = hex::decode("badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea")
            .unwrap();
        let mut seed_array = [0u8; 32];
        seed_array.copy_from_slice(&seed);

        // eseed is 64 bytes, split across two lines in the spec
        let eseed = hex::decode(
            "17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdefaee7eef4\
             7cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32d",
        )
        .unwrap();
        assert_eq!(eseed.len(), 64, "eseed should be 64 bytes");

        let mut eseed_array = [0u8; 64];
        eseed_array.copy_from_slice(&eseed);

        let expected_ss =
            hex::decode("f2e86241c64d60f6649fbc6c5b7d17180b780a3f34355e64a85749949c45f150")
                .unwrap();

        // Generate keypair from seed
        let (pk, sk) = xwing.keygen_from_seed(seed_array);

        // Encapsulate with deterministic seed
        let (ct, ss) = xwing.encaps_deterministic_raw(&pk, &eseed_array);

        // Verify shared secret matches
        assert_eq!(
            ss.as_slice(),
            expected_ss.as_slice(),
            "Shared secret mismatch for vector 2"
        );

        // Verify decapsulation produces same shared secret
        let ss_dec = xwing.decaps_raw(&sk, &ct).expect("decaps should succeed");
        assert_eq!(
            ss_dec.as_slice(),
            expected_ss.as_slice(),
            "Decapsulated shared secret mismatch for vector 2"
        );
    }

    /// Test vector 3 from draft-connolly-cfrg-xwing-kem-09 Appendix C.
    #[test]
    fn test_spec_vector_3() {
        let xwing = XWing;

        let seed = hex::decode("ef58538b8d23f87732ea63b02b4fa0f4873360e2841928cd60dd4cee8cc0d4c9")
            .unwrap();
        let mut seed_array = [0u8; 32];
        seed_array.copy_from_slice(&seed);

        // eseed is 64 bytes, split across two lines in the spec
        let eseed = hex::decode(
            "22a96188d032675c8ac850933c7aff1533b94c834adbb69c6115bad4692d8619f90b0cdf\
             8a7b9c264029ac185b70b83f2801f2f4b3f70c593ea3aeeb613a7f1b",
        )
        .unwrap();
        assert_eq!(eseed.len(), 64, "eseed should be 64 bytes");

        let mut eseed_array = [0u8; 64];
        eseed_array.copy_from_slice(&eseed);

        let expected_ss =
            hex::decode("953f7f4e8c5b5049bdc771d1dffada0dd961477d1a2ae0988baa7ea6898d893f")
                .unwrap();

        // Generate keypair from seed
        let (pk, sk) = xwing.keygen_from_seed(seed_array);

        // Encapsulate with deterministic seed
        let (ct, ss) = xwing.encaps_deterministic_raw(&pk, &eseed_array);

        // Verify shared secret matches
        assert_eq!(
            ss.as_slice(),
            expected_ss.as_slice(),
            "Shared secret mismatch for vector 3"
        );

        // Verify decapsulation produces same shared secret
        let ss_dec = xwing.decaps_raw(&sk, &ct).expect("decaps should succeed");
        assert_eq!(
            ss_dec.as_slice(),
            expected_ss.as_slice(),
            "Decapsulated shared secret mismatch for vector 3"
        );
    }

    /// Test that the combiner matches the X-Wing spec intermediate values from test vector 1.
    ///
    /// These intermediate values were computed using the Python reference implementation.
    #[test]
    fn test_combiner_with_spec_intermediates() {
        // Intermediate values from test vector 1 encapsulation (computed by Python script)
        let ss_m = hex::decode("7631eaf24bcc7ba2d1656d8f53778f8caa5f1ce33180e8ab405b9247eab76dfc")
            .unwrap();
        let ss_x = hex::decode("1e53cb26910141b4a09b0664deb8ec55376bcdbdfe2bfc8277883939a76d6131")
            .unwrap();
        let ct_x = hex::decode("e56f17576740ce2a32fc5145030145cfb97e63e0e41d354274a079d3e6fb2e15")
            .unwrap();
        let pk_x = hex::decode("859edb06eff389b27dce59844570216223593d4ba32d9abac8cd049040ef6534")
            .unwrap();

        let expected_ss =
            hex::decode("d2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384")
                .unwrap();

        let mut ss_m_arr = [0u8; 32];
        ss_m_arr.copy_from_slice(&ss_m);
        let mut ss_x_arr = [0u8; 32];
        ss_x_arr.copy_from_slice(&ss_x);
        let mut ct_x_arr = [0u8; 32];
        ct_x_arr.copy_from_slice(&ct_x);
        let mut pk_x_arr = [0u8; 32];
        pk_x_arr.copy_from_slice(&pk_x);

        let ss = combiner(&ss_m_arr, &ss_x_arr, &ct_x_arr, &pk_x_arr);

        assert_eq!(
            ss.as_slice(),
            expected_ss.as_slice(),
            "Combiner output should match spec test vector 1"
        );
    }

    /// Test size constants.
    #[test]
    fn test_sizes() {
        assert_eq!(XWING_PK_SIZE, 1216);
        assert_eq!(XWING_CT_SIZE, 1120);
        assert_eq!(XWING_SS_SIZE, 32);
    }

    /// Test XWingMkem roundtrip with multiple recipients.
    #[test]
    fn test_xwing_mkem_roundtrip() {
        let mkem = XWingMkem::default();
        let mut rng = rand::rng();

        // Generate keypairs for 3 recipients
        let (pk1, sk1) = Mkem::keygen(&mkem, &mut rng);
        let (pk2, sk2) = Mkem::keygen(&mkem, &mut rng);
        let (pk3, sk3) = Mkem::keygen(&mkem, &mut rng);

        let pks = vec![pk1, pk2, pk3];
        let sks = [sk1, sk2, sk3];

        // Encapsulate to all recipients
        let (ct, expected_key) = mkem.encaps(&mut rng, &pks);

        // Each recipient should be able to decapsulate
        for (i, sk) in sks.iter().enumerate() {
            let individual_ct = mkem.get(&ct, i).expect("should get ciphertext");
            let decapped = mkem
                .decaps(sk, &individual_ct)
                .expect("decaps should succeed");
            assert_eq!(
                expected_key.as_bytes(),
                decapped.as_bytes(),
                "recipient {} should recover same key",
                i
            );
        }
    }
}
