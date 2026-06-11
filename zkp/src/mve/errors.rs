//! Errors related to multi-recipient verifiable encryption

use thiserror::Error;

/// Represents an error in proof creation, verification, or parsing.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum MveError {
    /// This error occurs when a proof failed to verify.
    #[error("Proof verification failed.")]
    VerificationError,

    #[error("Proof verification failed (bad input).")]
    VerificationInputError,

    #[error("Decryption failed")]
    DecryptionFailure,
}
