use std::{fmt, string::String};

/// Errors produced by field-level encryption / decryption.
#[derive(Debug)]
pub enum EncryptionError {
    /// Key derivation failed with additional context.
    Derivation(String),
    /// Encryption or decryption failed.
    Encryption(String),
    /// Provided key material was not valid.
    InvalidKey(String),
    /// Ciphertext is too short or structurally malformed.
    InvalidCiphertext,
    /// The version byte is not recognised.
    UnsupportedVersion(u8),
    /// No key available for the given key ID (serialized bytes).
    MissingKey(Vec<u8>),
}

impl fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncryptionError::Derivation(msg) => write!(f, "Key derivation failed: {msg}"),
            EncryptionError::Encryption(msg) => write!(f, "Encryption failed: {msg}"),
            EncryptionError::InvalidKey(msg) => write!(f, "Invalid key material: {msg}"),
            EncryptionError::InvalidCiphertext => {
                write!(f, "Ciphertext is too short or malformed")
            }
            EncryptionError::UnsupportedVersion(v) => {
                write!(f, "Unsupported ciphertext version: {v}")
            }
            EncryptionError::MissingKey(id) => write!(f, "No key available for key ID {id:?}"),
        }
    }
}

impl std::error::Error for EncryptionError {}

/// Convenience result alias for encryption operations.
pub type Result<T> = std::result::Result<T, EncryptionError>;
