use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Ed25519Signature {}

impl From<ed25519_dalek::ed25519::Error> for super::SignatureVerificationError {
    fn from(error: ed25519_dalek::ed25519::Error) -> Self {
        super::SignatureVerificationError::new(error.to_string())
    }
}

impl super::Signature for Ed25519Signature {
    type VerificationKey = ed25519_dalek::VerifyingKey;
    type SigningKey = ed25519_dalek::SigningKey;
    type Message = [u8];

    fn keygen() -> (Self::VerificationKey, Self::SigningKey) {
        let seed = rand::random();
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        (verifying_key, signing_key)
    }

    fn sign(sk: &Self::SigningKey, _vk: &Self::VerificationKey, msg: &Self::Message) -> Vec<u8> {
        let signature: Signature = sk.sign(msg);
        signature.to_bytes().to_vec()
    }

    fn verify(
        vk: &Self::VerificationKey,
        msg: &[u8],
        signature_bytes: &[u8],
    ) -> Result<(), super::SignatureVerificationError> {
        let signature = Signature::from_slice(signature_bytes)?;
        vk.verify(msg, &signature)?;
        Ok(())
    }
}
