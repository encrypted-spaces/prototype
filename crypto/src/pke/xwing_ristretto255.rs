// X-Wing-Ristretto KEM implementation (variant of X-Wing with Ristretto instead of X25519)
//
// This is a modified X-Wing implementation that replaces X25519 with Ristretto
// for better performance. The Ristretto group provides similar security properties
// to X25519 but with faster scalar multiplication.
//
// NOTE: This variant does NOT pass X-Wing KAT tests since it uses a different
// elliptic curve group. Roundtrip tests verify correctness.

use core::fmt;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar as RistrettoScalar;
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
/// Ristretto compressed point size
const RISTRETTO_PK_SIZE: usize = 32;
/// X-Wing-Ristretto encapsulation key (public key) size: ML-KEM-768 pk || Ristretto pk
const XWING_RISTRETTO_PK_SIZE: usize = MLKEM_PK_SIZE + RISTRETTO_PK_SIZE;

/// ML-KEM-768 ciphertext size
const MLKEM_CT_SIZE: usize = 1088;
/// X-Wing-Ristretto ciphertext size: ML-KEM-768 ct || Ristretto ephemeral pk
const XWING_RISTRETTO_CT_SIZE: usize = MLKEM_CT_SIZE + RISTRETTO_PK_SIZE;

/// X-Wing-Ristretto shared secret size (SHA3-256 output)
const XWING_RISTRETTO_SS_SIZE: usize = 32;

/// Domain separation label for X-Wing-Ristretto (distinct from X-Wing).
/// ```text
///     \./    ~
///     /^\  c[_]
/// ```
/// Concatenated (no whitespace): `\.//^\~c[_]` = 11 bytes
const XWING_RISTRETTO_LABEL: &[u8; 11] = b"\\.//^\\~c[_]";

/// X-Wing-Ristretto public key (encapsulation key).
///
/// Layout: pk_M (1184 bytes) || pk_R (32 bytes, compressed Ristretto point)
#[derive(Clone)]
pub struct XWingRistrettoPublicKey([u8; XWING_RISTRETTO_PK_SIZE]);

impl fmt::Debug for XWingRistrettoPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("XWingRistrettoPublicKey(**redacted**)")
    }
}

impl XWingRistrettoPublicKey {
    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; XWING_RISTRETTO_PK_SIZE]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; XWING_RISTRETTO_PK_SIZE] {
        &self.0
    }

    /// Extract ML-KEM-768 public key portion.
    fn mlkem_pk(&self) -> MlKem768PublicKey {
        let mut pk_bytes = [0u8; MLKEM_PK_SIZE];
        pk_bytes.copy_from_slice(&self.0[..MLKEM_PK_SIZE]);
        MlKem768PublicKey::from(pk_bytes)
    }

    /// Extract Ristretto public key portion as compressed point.
    fn ristretto_pk(&self) -> CompressedRistretto {
        let mut pk_bytes = [0u8; RISTRETTO_PK_SIZE];
        pk_bytes.copy_from_slice(&self.0[MLKEM_PK_SIZE..]);
        CompressedRistretto(pk_bytes)
    }

    /// Get Ristretto public key bytes.
    fn ristretto_pk_bytes(&self) -> [u8; 32] {
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(&self.0[MLKEM_PK_SIZE..]);
        pk_bytes
    }
}

impl Serialize for XWingRistrettoPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for XWingRistrettoPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        if bytes.len() != XWING_RISTRETTO_PK_SIZE {
            return Err(de::Error::custom(format!(
                "expected {XWING_RISTRETTO_PK_SIZE} bytes for X-Wing-Ristretto public key, got {}",
                bytes.len()
            )));
        }
        let mut pk = [0u8; XWING_RISTRETTO_PK_SIZE];
        pk.copy_from_slice(&bytes);
        Ok(Self(pk))
    }
}

/// X-Wing-Ristretto ciphertext.
///
/// Layout: ct_M (1088 bytes) || ct_R (32 bytes, compressed Ristretto ephemeral public key)
#[derive(Clone)]
pub struct XWingRistrettoCiphertext([u8; XWING_RISTRETTO_CT_SIZE]);

impl fmt::Debug for XWingRistrettoCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("XWingRistrettoCiphertext(**redacted**)")
    }
}

impl XWingRistrettoCiphertext {
    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; XWING_RISTRETTO_CT_SIZE]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; XWING_RISTRETTO_CT_SIZE] {
        &self.0
    }

    /// Extract ML-KEM-768 ciphertext portion.
    fn mlkem_ct(&self) -> MlKem768Ciphertext {
        let mut ct_bytes = [0u8; MLKEM_CT_SIZE];
        ct_bytes.copy_from_slice(&self.0[..MLKEM_CT_SIZE]);
        MlKem768Ciphertext::from(ct_bytes)
    }

    /// Extract Ristretto ephemeral public key (ciphertext portion).
    fn ristretto_ct(&self) -> CompressedRistretto {
        let mut ct_bytes = [0u8; RISTRETTO_PK_SIZE];
        ct_bytes.copy_from_slice(&self.0[MLKEM_CT_SIZE..]);
        CompressedRistretto(ct_bytes)
    }

    /// Get Ristretto ciphertext bytes.
    fn ristretto_ct_bytes(&self) -> [u8; 32] {
        let mut ct_bytes = [0u8; 32];
        ct_bytes.copy_from_slice(&self.0[MLKEM_CT_SIZE..]);
        ct_bytes
    }
}

impl Serialize for XWingRistrettoCiphertext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for XWingRistrettoCiphertext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        if bytes.len() != XWING_RISTRETTO_CT_SIZE {
            return Err(de::Error::custom(format!(
                "expected {XWING_RISTRETTO_CT_SIZE} bytes for X-Wing-Ristretto ciphertext, got {}",
                bytes.len()
            )));
        }
        let mut ct = [0u8; XWING_RISTRETTO_CT_SIZE];
        ct.copy_from_slice(&bytes);
        Ok(Self(ct))
    }
}

/// X-Wing-Ristretto secret key (decapsulation key).
///
/// The 32-byte seed from which the expanded keys are derived.
/// We also cache the expanded keys for efficiency (as recommended by the spec).
#[derive(Clone)]
pub struct XWingRistrettoSecretKey {
    /// The original 32-byte seed.
    seed: [u8; 32],
    /// Cached ML-KEM-768 secret key.
    sk_m: MlKem768PrivateKey,
    /// Cached Ristretto secret key (scalar).
    sk_r: RistrettoScalar,
    /// Cached Ristretto public key bytes (needed for combiner during decapsulation).
    pk_r: [u8; 32],
}

impl XWingRistrettoSecretKey {
    /// Get the seed bytes.
    pub fn as_seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// Get the Ristretto secret scalar.
    fn sk_r(&self) -> &RistrettoScalar {
        &self.sk_r
    }
}

impl Serialize for XWingRistrettoSecretKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.seed.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for XWingRistrettoSecretKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let seed = <[u8; 32]>::deserialize(deserializer)?;
        let (sk_m, sk_r, _pk_m, pk_r) = expand_decapsulation_key(&seed);
        Ok(XWingRistrettoSecretKey {
            seed,
            sk_m,
            sk_r,
            pk_r,
        })
    }
}

/// Expand a 32-byte seed into ML-KEM and Ristretto key material.
///
/// Similar to X-Wing's expandDecapsulationKey but uses Ristretto instead of X25519.
///
/// Returns (sk_m, sk_r, pk_m, pk_r_bytes)
fn expand_decapsulation_key(
    seed: &[u8; 32],
) -> (
    MlKem768PrivateKey,
    RistrettoScalar,
    MlKem768PublicKey,
    [u8; 32],
) {
    use sha3::digest::{ExtendableOutput, Update, XofReader};

    // Expand seed to 128 bytes using SHAKE256 (need 64 bytes for Ristretto scalar)
    let mut shake = Shake256::default();
    Update::update(&mut shake, seed);
    let mut reader = shake.finalize_xof();
    let mut expanded = [0u8; 128];
    reader.read(&mut expanded);

    // ML-KEM-768 keygen from the first 64 bytes (d || z)
    // libcrux's generate_key_pair takes 64 bytes of randomness
    let mut mlkem_seed = [0u8; 64];
    mlkem_seed.copy_from_slice(&expanded[0..64]);
    let keypair = generate_key_pair(mlkem_seed);
    let (sk_m, pk_m) = keypair.into_parts();

    // Ristretto secret key from bytes 64-128 (use 64 bytes for wide reduction)
    let mut sk_r_bytes = [0u8; 64];
    sk_r_bytes.copy_from_slice(&expanded[64..128]);
    let sk_r = RistrettoScalar::from_bytes_mod_order_wide(&sk_r_bytes);

    // Compute Ristretto public key
    let pk_r_point = RistrettoPoint::mul_base(&sk_r);
    let pk_r = pk_r_point.compress().to_bytes();

    (sk_m, sk_r, pk_m, pk_r)
}

/// The X-Wing-Ristretto combiner function.
///
/// Same structure as X-Wing combiner but works with Ristretto shared secrets.
fn combiner(
    ss_m: &[u8; 32],
    ss_r: &[u8; 32],
    ct_r: &[u8; 32],
    pk_r: &[u8; 32],
) -> [u8; XWING_RISTRETTO_SS_SIZE] {
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, ss_m);
    Digest::update(&mut hasher, ss_r);
    Digest::update(&mut hasher, ct_r);
    Digest::update(&mut hasher, pk_r);
    Digest::update(&mut hasher, XWING_RISTRETTO_LABEL);
    let result = Digest::finalize(hasher);
    let mut ss = [0u8; XWING_RISTRETTO_SS_SIZE];
    ss.copy_from_slice(&result);
    ss
}

/// X-Wing-Ristretto KEM (X-Wing variant with Ristretto instead of X25519).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct XWingRistretto;

impl Kem for XWingRistretto {
    type PublicKey = XWingRistrettoPublicKey;
    type SecretKey = XWingRistrettoSecretKey;
    type Ciphertext = XWingRistrettoCiphertext;
    const NAME: &'static str = "X-Wing-Ristretto";

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
        // Generate random 96-byte encapsulation seed (need 64 for Ristretto scalar + 32 for ML-KEM)
        let mut eseed = [0u8; 96];
        rng.fill_bytes(&mut eseed);

        self.encaps_deterministic(pk, &eseed)
    }

    fn decaps(&self, sk: &Self::SecretKey, ct: &Self::Ciphertext) -> Option<KeyMaterial> {
        // ML-KEM-768 decapsulation
        let ct_m = ct.mlkem_ct();
        let ss_m = decapsulate(&sk.sk_m, &ct_m);

        // Ristretto DH
        let ct_r = ct.ristretto_ct();
        let ephemeral_pk = ct_r.decompress()?;
        let ss_r_point = ephemeral_pk * sk.sk_r();
        let ss_r = ss_r_point.compress().to_bytes();

        // Combine shared secrets
        let mut ss_m_bytes = [0u8; 32];
        ss_m_bytes.copy_from_slice(ss_m.as_ref());

        let ss = combiner(&ss_m_bytes, &ss_r, &ct.ristretto_ct_bytes(), &sk.pk_r);
        Some(KeyMaterial::digest(&ss))
    }
}

impl XWingRistretto {
    /// Deterministic key generation from a 32-byte seed.
    pub fn keygen_from_seed(
        &self,
        seed: [u8; 32],
    ) -> (XWingRistrettoPublicKey, XWingRistrettoSecretKey) {
        let (sk_m, sk_r, pk_m, pk_r) = expand_decapsulation_key(&seed);

        // Construct public key: pk_M || pk_R
        let mut pk_bytes = [0u8; XWING_RISTRETTO_PK_SIZE];
        pk_bytes[..MLKEM_PK_SIZE].copy_from_slice(pk_m.as_slice());
        pk_bytes[MLKEM_PK_SIZE..].copy_from_slice(&pk_r);

        let pk = XWingRistrettoPublicKey(pk_bytes);
        let sk = XWingRistrettoSecretKey {
            seed,
            sk_m,
            sk_r,
            pk_r,
        };

        (pk, sk)
    }

    /// Deterministic encapsulation from a 96-byte seed.
    /// Layout: eseed[0:32] = ML-KEM randomness, eseed[32:96] = Ristretto scalar (64 bytes for wide reduction)
    pub fn encaps_deterministic(
        &self,
        pk: &XWingRistrettoPublicKey,
        eseed: &[u8; 96],
    ) -> (XWingRistrettoCiphertext, KeyMaterial) {
        let pk_m = pk.mlkem_pk();
        let pk_r = pk.ristretto_pk();
        let pk_r_bytes = pk.ristretto_pk_bytes();

        // Ristretto ephemeral keypair from eseed[32:96]
        let mut ek_r_bytes = [0u8; 64];
        ek_r_bytes.copy_from_slice(&eseed[32..96]);
        let ek_r = RistrettoScalar::from_bytes_mod_order_wide(&ek_r_bytes);

        // ct_R = ek_R * G (ephemeral public key)
        let ct_r_point = RistrettoPoint::mul_base(&ek_r);
        let ct_r_bytes = ct_r_point.compress().to_bytes();

        // ss_R = ek_R * pk_R (shared secret via DH)
        let pk_r_point = pk_r
            .decompress()
            .expect("public key should be valid Ristretto point");
        let ss_r_point = pk_r_point * ek_r;
        let ss_r_bytes = ss_r_point.compress().to_bytes();

        // ML-KEM-768 encapsulation with eseed[0:32] as randomness
        let mut mlkem_rand = [0u8; 32];
        mlkem_rand.copy_from_slice(&eseed[0..32]);
        let (ct_m, ss_m) = encapsulate(&pk_m, mlkem_rand);
        let mut ss_m_bytes = [0u8; 32];
        ss_m_bytes.copy_from_slice(ss_m.as_ref());

        // Construct ciphertext: ct_M || ct_R
        let mut ct_bytes = [0u8; XWING_RISTRETTO_CT_SIZE];
        ct_bytes[..MLKEM_CT_SIZE].copy_from_slice(ct_m.as_slice());
        ct_bytes[MLKEM_CT_SIZE..].copy_from_slice(&ct_r_bytes);

        // Combine shared secrets
        let ss = combiner(&ss_m_bytes, &ss_r_bytes, &ct_r_bytes, &pk_r_bytes);

        (XWingRistrettoCiphertext(ct_bytes), KeyMaterial::digest(&ss))
    }

    /// Get the raw 32-byte shared secret without KeyMaterial transformation.
    pub fn encaps_deterministic_raw(
        &self,
        pk: &XWingRistrettoPublicKey,
        eseed: &[u8; 96],
    ) -> (XWingRistrettoCiphertext, [u8; 32]) {
        let pk_m = pk.mlkem_pk();
        let pk_r = pk.ristretto_pk();
        let pk_r_bytes = pk.ristretto_pk_bytes();

        // Ristretto ephemeral keypair from eseed[32:96]
        let mut ek_r_bytes = [0u8; 64];
        ek_r_bytes.copy_from_slice(&eseed[32..96]);
        let ek_r = RistrettoScalar::from_bytes_mod_order_wide(&ek_r_bytes);

        // ct_R = ek_R * G (ephemeral public key)
        let ct_r_point = RistrettoPoint::mul_base(&ek_r);
        let ct_r_bytes = ct_r_point.compress().to_bytes();

        // ss_R = ek_R * pk_R (shared secret via DH)
        let pk_r_point = pk_r
            .decompress()
            .expect("public key should be valid Ristretto point");
        let ss_r_point = pk_r_point * ek_r;
        let ss_r_bytes = ss_r_point.compress().to_bytes();

        // ML-KEM-768 encapsulation with eseed[0:32] as randomness
        let mut mlkem_rand = [0u8; 32];
        mlkem_rand.copy_from_slice(&eseed[0..32]);
        let (ct_m, ss_m) = encapsulate(&pk_m, mlkem_rand);
        let mut ss_m_bytes = [0u8; 32];
        ss_m_bytes.copy_from_slice(ss_m.as_ref());

        // Construct ciphertext: ct_M || ct_R
        let mut ct_bytes = [0u8; XWING_RISTRETTO_CT_SIZE];
        ct_bytes[..MLKEM_CT_SIZE].copy_from_slice(ct_m.as_slice());
        ct_bytes[MLKEM_CT_SIZE..].copy_from_slice(&ct_r_bytes);

        // Combine shared secrets
        let ss = combiner(&ss_m_bytes, &ss_r_bytes, &ct_r_bytes, &pk_r_bytes);

        (XWingRistrettoCiphertext(ct_bytes), ss)
    }

    /// Get the raw 32-byte shared secret from decapsulation.
    pub fn decaps_raw(
        &self,
        sk: &XWingRistrettoSecretKey,
        ct: &XWingRistrettoCiphertext,
    ) -> Option<[u8; 32]> {
        // ML-KEM-768 decapsulation
        let ct_m = ct.mlkem_ct();
        let ss_m = decapsulate(&sk.sk_m, &ct_m);

        // Ristretto DH
        let ct_r = ct.ristretto_ct();
        let ephemeral_pk = ct_r.decompress()?;
        let ss_r_point = ephemeral_pk * sk.sk_r();
        let ss_r = ss_r_point.compress().to_bytes();

        // Combine shared secrets
        let mut ss_m_bytes = [0u8; 32];
        ss_m_bytes.copy_from_slice(ss_m.as_ref());

        Some(combiner(
            &ss_m_bytes,
            &ss_r,
            &ct.ristretto_ct_bytes(),
            &sk.pk_r,
        ))
    }
}

// ============================================================================
// Optimized multi-recipient KEM (mKEM) implementation for X-Wing-Ristretto
// ============================================================================
//
// This provides a specialized `Mkem` implementation for X-Wing-Ristretto that is more efficient
// than the generic blanket implementation in `pke.rs`. It reuses the Ristretto ephemeral
// key for all recipients.

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct XWingRistrettoMkem(XWingRistretto);

/// Ciphertext for the X-Wing-Ristretto-based mKEM.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct XWingRistrettoMkemCiphertext {
    /// Shared ephemeral Ristretto public key (ct_r), used by all recipients.
    ct_r: [u8; 32],
    /// Per-recipient ciphertexts containing ML-KEM ciphertext and encrypted key.
    cts: Vec<XWingRistrettoMkemIndividualCiphertext>,
}

/// Individual ciphertext for a single recipient.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct XWingRistrettoMkemIndividualCiphertext {
    /// The shared ephemeral Ristretto public key (needed for decapsulation).
    ct_r: [u8; 32],
    /// Per-recipient ML-KEM-768 ciphertext (1088 bytes).
    ct_m: Vec<u8>,
    /// Encrypted key material for the shared group key.
    ct_key: EncryptedKeyMaterial,
}

impl Mkem for XWingRistrettoMkem {
    const NAME: &'static str = "X-Wing-Ristretto-mKEM";

    type PublicKey = XWingRistrettoPublicKey;
    type IndividualCiphertext = XWingRistrettoMkemIndividualCiphertext;
    type Ciphertext = XWingRistrettoMkemCiphertext;
    type SecretKey = XWingRistrettoSecretKey;

    fn keygen<R: CryptoRng + RngCore>(&self, rng: &mut R) -> (Self::PublicKey, Self::SecretKey) {
        // Key generation is the same as regular X-Wing-Ristretto
        Kem::keygen(&self.0, rng)
    }

    fn encaps<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        pks: &[Self::PublicKey],
    ) -> (Self::Ciphertext, KeyMaterial) {
        // Generate the shared key that all recipients will recover
        let key = KeyMaterial::random_with(rng);

        // Generate one ephemeral Ristretto keypair (reused across all recipients)
        let mut ek_r_bytes = [0u8; 64];
        rng.fill_bytes(&mut ek_r_bytes);
        let ek_r = RistrettoScalar::from_bytes_mod_order_wide(&ek_r_bytes);

        // ct_r = ek_r * G — the shared ephemeral public key
        let ct_r_point = RistrettoPoint::mul_base(&ek_r);
        let ct_r = ct_r_point.compress().to_bytes();

        let mut cts = Vec::with_capacity(pks.len());

        for pk in pks {
            // Extract recipient's component keys
            let pk_m = pk.mlkem_pk();
            let pk_r = pk.ristretto_pk();
            let pk_r_bytes = pk.ristretto_pk_bytes();

            // Ristretto DH with recipient's public key (reusing our ephemeral key)
            let pk_r_point = pk_r
                .decompress()
                .expect("public key should be valid Ristretto point");
            let ss_r_point = pk_r_point * ek_r;
            let ss_r = ss_r_point.compress().to_bytes();

            // Fresh ML-KEM encapsulation for this recipient
            let mut mlkem_rand = [0u8; 32];
            rng.fill_bytes(&mut mlkem_rand);
            let (ct_m, ss_m) = encapsulate(&pk_m, mlkem_rand);
            let mut ss_m_bytes = [0u8; 32];
            ss_m_bytes.copy_from_slice(ss_m.as_ref());

            // Combine to get per-recipient shared secret (using combiner)
            let ss = combiner(&ss_m_bytes, &ss_r, &ct_r, &pk_r_bytes);
            let shared = KeyMaterial::digest(&ss);

            let ct_key = EncryptedKeyMaterial::encrypt(shared, &key);

            cts.push(XWingRistrettoMkemIndividualCiphertext {
                ct_r,
                ct_m: ct_m.as_slice().to_vec(),
                ct_key,
            });
        }

        (XWingRistrettoMkemCiphertext { ct_r, cts }, key)
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

        // Ristretto DH with the shared ephemeral public key
        let ct_r = CompressedRistretto(ct.ct_r);
        let ephemeral_pk = ct_r.decompress()?;
        let ss_r_point = ephemeral_pk * sk.sk_r();
        let ss_r = ss_r_point.compress().to_bytes();

        // Combine using combiner (pk_r is our own public key)
        let ss = combiner(&ss_m_bytes, &ss_r, &ct.ct_r, &sk.pk_r);
        let shared = KeyMaterial::digest(&ss);

        Some(ct.ct_key.decrypt(shared))
    }
}

impl XWingRistrettoMkem {
    /// Create a new X-Wing-Ristretto mKEM instance.
    pub fn new() -> Self {
        Self(XWingRistretto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test combiner determinism.
    #[test]
    fn test_combiner_deterministic() {
        let ss_m = [0u8; 32];
        let ss_r = [1u8; 32];
        let ct_r = [2u8; 32];
        let pk_r = [3u8; 32];

        let result1 = combiner(&ss_m, &ss_r, &ct_r, &pk_r);
        let result2 = combiner(&ss_m, &ss_r, &ct_r, &pk_r);

        assert_eq!(result1, result2);
    }

    /// Test that changing any combiner input changes the output.
    #[test]
    fn test_combiner_input_sensitivity() {
        let ss_m = [0u8; 32];
        let ss_r = [1u8; 32];
        let ct_r = [2u8; 32];
        let pk_r = [3u8; 32];

        let baseline = combiner(&ss_m, &ss_r, &ct_r, &pk_r);

        // Change ss_m
        let mut ss_m_alt = ss_m;
        ss_m_alt[0] = 0xff;
        assert_ne!(baseline, combiner(&ss_m_alt, &ss_r, &ct_r, &pk_r));

        // Change ss_r
        let mut ss_r_alt = ss_r;
        ss_r_alt[0] = 0xff;
        assert_ne!(baseline, combiner(&ss_m, &ss_r_alt, &ct_r, &pk_r));

        // Change ct_r
        let mut ct_r_alt = ct_r;
        ct_r_alt[0] = 0xff;
        assert_ne!(baseline, combiner(&ss_m, &ss_r, &ct_r_alt, &pk_r));

        // Change pk_r
        let mut pk_r_alt = pk_r;
        pk_r_alt[0] = 0xff;
        assert_ne!(baseline, combiner(&ss_m, &ss_r, &ct_r, &pk_r_alt));
    }

    /// Test basic roundtrip: keygen -> encaps -> decaps.
    #[test]
    fn test_xwing_ristretto_roundtrip() {
        let kem = XWingRistretto;
        let mut rng = rand::rng();

        let (pk, sk) = Kem::keygen(&kem, &mut rng);
        let (ct, expected_key) = Kem::encaps(&kem, &mut rng, &pk);
        let decapped_key = Kem::decaps(&kem, &sk, &ct).expect("decaps should succeed");

        assert_eq!(expected_key.as_bytes(), decapped_key.as_bytes());
    }

    /// Test roundtrip with raw shared secrets.
    #[test]
    fn test_xwing_ristretto_roundtrip_raw() {
        let kem = XWingRistretto;

        let seed = [0x42u8; 32];
        let eseed = [0x37u8; 96];

        let (pk, sk) = kem.keygen_from_seed(seed);
        let (ct, ss_encaps) = kem.encaps_deterministic_raw(&pk, &eseed);
        let ss_decaps = kem.decaps_raw(&sk, &ct).expect("decaps should succeed");

        assert_eq!(ss_encaps, ss_decaps);
    }

    /// Test multiple roundtrips with different seeds.
    #[test]
    fn test_xwing_ristretto_multiple_roundtrips() {
        let kem = XWingRistretto;
        let mut rng = rand::rng();

        for _ in 0..10 {
            let (pk, sk) = Kem::keygen(&kem, &mut rng);
            let (ct, expected_key) = Kem::encaps(&kem, &mut rng, &pk);
            let decapped_key = Kem::decaps(&kem, &sk, &ct).expect("decaps should succeed");

            assert_eq!(expected_key.as_bytes(), decapped_key.as_bytes());
        }
    }

    /// Test size constants.
    #[test]
    fn test_sizes() {
        assert_eq!(XWING_RISTRETTO_PK_SIZE, 1216);
        assert_eq!(XWING_RISTRETTO_CT_SIZE, 1120);
        assert_eq!(XWING_RISTRETTO_SS_SIZE, 32);
    }

    /// Test XWingRistrettoMkem roundtrip with multiple recipients.
    #[test]
    fn test_xwing_ristretto_mkem_roundtrip() {
        let mkem = XWingRistrettoMkem::default();
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

    /// Test mKEM with larger recipient sets.
    #[test]
    fn test_xwing_ristretto_mkem_many_recipients() {
        let mkem = XWingRistrettoMkem::default();
        let mut rng = rand::rng();

        // Generate keypairs for 10 recipients
        let keypairs: Vec<_> = (0..10).map(|_| Mkem::keygen(&mkem, &mut rng)).collect();
        let pks: Vec<_> = keypairs.iter().map(|(pk, _)| pk.clone()).collect();

        // Encapsulate to all recipients
        let (ct, expected_key) = mkem.encaps(&mut rng, &pks);

        // Each recipient should be able to decapsulate
        for (i, (_, sk)) in keypairs.iter().enumerate() {
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
