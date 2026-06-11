use core::{array::TryFromSliceError, ops::Deref};
use ml_dsa::{KeyGen, KeyPair, MlDsa65, Signature, SigningKey};
use rand::RngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const MLDSA_CTX: &[u8] = b"Encrypted Spaces MLDSA v1";

#[derive(Clone, Serialize, Deserialize)]
pub struct MlDsaVerificationKey(
    #[serde(
        serialize_with = "serialize_verification_key",
        deserialize_with = "deserialize_verification_key"
    )]
    ml_dsa::VerifyingKey<MlDsa65>,
);

#[derive(Clone, Serialize, Deserialize)]
pub struct MlDsaSigningKey(
    #[serde(
        serialize_with = "serialize_signing_key",
        deserialize_with = "deserialize_signing_key"
    )]
    SigningKey<MlDsa65>,
);

impl From<ml_dsa::VerifyingKey<MlDsa65>> for MlDsaVerificationKey {
    fn from(value: ml_dsa::VerifyingKey<MlDsa65>) -> Self {
        MlDsaVerificationKey(value)
    }
}

impl From<SigningKey<MlDsa65>> for MlDsaSigningKey {
    fn from(value: SigningKey<MlDsa65>) -> Self {
        MlDsaSigningKey(value)
    }
}

impl Deref for MlDsaSigningKey {
    type Target = SigningKey<MlDsa65>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<TryFromSliceError> for super::SignatureVerificationError {
    fn from(error: TryFromSliceError) -> Self {
        super::SignatureVerificationError::new(error.to_string())
    }
}

fn serialize_verification_key<S>(
    key: &ml_dsa::VerifyingKey<MlDsa65>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_bytes(key.encode().as_slice())
}

fn deserialize_verification_key<'de, D>(
    deserializer: D,
) -> Result<ml_dsa::VerifyingKey<MlDsa65>, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes = Vec::<u8>::deserialize(deserializer)?;
    let enc = ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(bytes.as_slice()).map_err(|_| {
        serde::de::Error::invalid_length(bytes.len(), &"ML-DSA verification key bytes")
    })?;
    Ok(ml_dsa::VerifyingKey::<MlDsa65>::decode(&enc))
}

fn serialize_signing_key<S>(key: &SigningKey<MlDsa65>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_bytes(key.encode().as_slice())
}

fn deserialize_signing_key<'de, D>(deserializer: D) -> Result<SigningKey<MlDsa65>, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes = Vec::<u8>::deserialize(deserializer)?;
    let enc = ml_dsa::EncodedSigningKey::<MlDsa65>::try_from(bytes.as_slice())
        .map_err(|_| serde::de::Error::invalid_length(bytes.len(), &"ML-DSA signing key bytes"))?;
    Ok(SigningKey::<MlDsa65>::decode(&enc))
}

impl crate::Signature for MlDsa65 {
    type VerificationKey = MlDsaVerificationKey;
    type SigningKey = MlDsaSigningKey;
    type Message = [u8];

    fn keygen() -> (Self::VerificationKey, Self::SigningKey) {
        // XXX. goddammit ml-dsa operates over yet another version of rand that is incompatible
        let mut seed = ml_dsa::B32::default();
        rand::rng().fill_bytes(seed.as_mut_slice());
        let key_pair: KeyPair<MlDsa65> = MlDsa65::key_gen_internal(&seed);
        (
            key_pair.verifying_key().clone().into(),
            key_pair.signing_key().clone().into(),
        )
    }

    fn sign(sk: &Self::SigningKey, _vk: &Self::VerificationKey, msg: &Self::Message) -> Vec<u8> {
        sk.sign_deterministic(msg, MLDSA_CTX)
            .expect("the constant MLDSA_CTX is too long")
            .encode()
            .to_vec()
    }

    fn verify(
        vk: &Self::VerificationKey,
        msg: &[u8],
        signature: &[u8],
    ) -> Result<(), super::SignatureVerificationError> {
        let signature = Signature::decode(signature.try_into()?).ok_or_else(|| {
            super::SignatureVerificationError::new("invalid ML-DSA signature encoding")
        })?;
        if vk.0.verify_with_context(msg, MLDSA_CTX, &signature) {
            Ok(())
        } else {
            Err(super::SignatureVerificationError::new(
                "ML-DSA signature verification failed",
            ))
        }
    }
}
