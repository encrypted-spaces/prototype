use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use encrypted_spaces_changelog_core::changelog::FastForwardRange;
use risc0_zkvm::Receipt;
use serde::{Deserialize, Serialize};

/// The wire-format FF proof.
///
/// The verifier checks the receipt against an image ID supplied by the
/// caller (sourced from the app's trust bundle, typically
/// `sdk_codegen::FF_GUEST_IMAGE_ID`), not against any value carried in
/// the proof itself.
#[derive(Serialize, Deserialize)]
pub struct FFProof {
    pub io: FastForwardRange,
    pub receipt: Receipt,
}

impl FFProof {
    pub fn serialize(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("Failed to serialize FFProof")
    }

    pub fn deserialize(bytes: &[u8]) -> Result<FFProof, FFProofError> {
        postcard::from_bytes(bytes).map_err(|_| FFProofError::DeserializationError)
    }

    // base 64 serialization for wasm
    #[allow(dead_code)]
    pub fn serialize_b64(&self) -> String {
        let bytes = self.serialize();
        URL_SAFE.encode(bytes)
    }
    #[allow(dead_code)]
    pub fn deserialize_b64(proof: &str) -> Result<FFProof, FFProofError> {
        let proof_bytes = URL_SAFE
            .decode(proof)
            .map_err(|_| FFProofError::DecodingError)?;

        Self::deserialize(&proof_bytes)
    }
}

#[derive(Debug)]
pub enum FFProofError {
    DecodingError,
    DeserializationError,
    VerificationFailed,
}

impl std::fmt::Display for FFProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FFProofError::DecodingError => write!(f, "Failed to decode base64"),
            FFProofError::DeserializationError => write!(f, "Failed to deserialize proof"),
            FFProofError::VerificationFailed => write!(f, "Proof verification failed"),
        }
    }
}

impl std::error::Error for FFProofError {}
