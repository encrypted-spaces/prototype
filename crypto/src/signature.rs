use serde::{de::DeserializeOwned, Serialize};

mod ed25519;
mod mldsa;

pub use ed25519::Ed25519Signature;

#[derive(Debug, Clone)]
pub struct SignatureVerificationError {
    reason: String,
}

impl SignatureVerificationError {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl std::fmt::Display for SignatureVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl std::error::Error for SignatureVerificationError {}

pub trait Signature: Clone + Send + Sync {
    type VerificationKey: Clone + Send + Sync + Serialize + DeserializeOwned;
    type SigningKey: Clone + Serialize + DeserializeOwned;
    type Message: ?Sized;

    fn keygen() -> (Self::VerificationKey, Self::SigningKey);
    fn sign(sk: &Self::SigningKey, vk: &Self::VerificationKey, msg: &Self::Message) -> Vec<u8>;
    fn verify(
        vk: &Self::VerificationKey,
        msg: &[u8],
        signature: &[u8],
    ) -> Result<(), SignatureVerificationError>;
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct SignatureKeyPair<S: Signature>(pub S::SigningKey, pub S::VerificationKey);

impl<S: Signature> Clone for SignatureKeyPair<S>
where
    S::SigningKey: Clone,
    S::VerificationKey: Clone,
{
    fn clone(&self) -> Self {
        SignatureKeyPair(self.0.clone(), self.1.clone())
    }
}

impl<S: Signature> SignatureKeyPair<S> {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let (vk, sk) = S::keygen();
        Self(sk, vk)
    }

    pub fn verification_key(&self) -> &S::VerificationKey {
        &self.1
    }

    fn signing_key(&self) -> &S::SigningKey {
        &self.0
    }

    pub fn sign(&self, message: &S::Message) -> impl AsRef<[u8]> {
        S::sign(self.signing_key(), self.verification_key(), message)
    }
}
