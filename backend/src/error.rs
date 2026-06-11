use encrypted_spaces_storage_encoding::stored_value::StoredValueError;
use encrypted_spaces_storage_encoding::TupleConversionError;
use std::fmt;

/// Reported when the server's view of a space has diverged from the
/// client's at a given `change_id`. The server only ever sends 16-byte
/// prefixes of its CLC and data commitment so the client can detect
/// divergence without ever having a server-supplied authoritative root
/// available to adopt as its own.
#[derive(Debug)]
pub struct StateDivergence {
    pub change_id: u32,
    pub client_clc_prefix: [u8; 16],
    pub server_clc_prefix: [u8; 16],
    pub client_data_commitment_prefix: [u8; 16],
    pub server_data_commitment_prefix: [u8; 16],
}

#[derive(Debug)]
pub enum SdkError {
    DatabaseError(String),
    SerializationError(String),
    ValidationError(String),
    AccessDenied(String),
    NotFound,
    InvalidQuery(String),
    SequentialIdError(String),
    RootHashError(String),
    MerkOpenError(String),
    InsertError(String),
    UpdateError(String),
    DeleteError(String),
    TransactionCommitError(String),
    InvalidRowData(String),
    BackendError(String),
    /// Client is out of sync with the server and must run a fast-forward
    /// cycle before retrying. Carries a human-readable `reason` describing
    /// which check failed (commitment mismatch, out-of-sequence change,
    /// etc.) for logging only — callers shouldn't pattern-match on it.
    FastForwardRequired {
        reason: String,
    },
    /// The client's local state advanced (e.g. a concurrent broadcast was
    /// applied) while a fast-forward request was in flight, invalidating
    /// the in-progress FF anchor. The caller should retry the fast-forward
    /// from the new anchor. Distinct from `FastForwardRequired` so the
    /// retry loop can detect this case without string-matching `reason`.
    FastForwardStateAdvanced,
    /// The client and server agree on `change_id` but their CLC and/or
    /// data-commitment prefixes disagree. This is a terminal divergence:
    /// re-running fast-forward will not help. Carries the prefixes for
    /// diagnostic logging only.
    StateDiverged(Box<StateDivergence>),
    MissingKeyCommitment,
    SchemaParsingError(String),
    JoinError(String),
    DecryptionError(String),
}

impl fmt::Display for SdkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SdkError::DatabaseError(msg) => write!(f, "Database error: {msg}"),
            SdkError::SerializationError(msg) => write!(f, "Serialization error: {msg}"),
            SdkError::ValidationError(msg) => write!(f, "Validation error: {msg}"),
            SdkError::AccessDenied(msg) => write!(f, "Access denied: {msg}"),
            SdkError::NotFound => write!(f, "Record not found"),
            SdkError::InvalidQuery(msg) => write!(f, "Invalid query: {msg}"),
            SdkError::SequentialIdError(msg) => {
                write!(f, "Failed to get next sequential ID: {msg}")
            }
            SdkError::RootHashError(msg) => write!(f, "Failed to get root hash: {msg}"),
            SdkError::MerkOpenError(msg) => write!(f, "Failed to open merk at path: {msg}"),
            SdkError::InsertError(msg) => write!(f, "Failed to insert row: {msg}"),
            SdkError::UpdateError(msg) => write!(f, "Failed to update row: {msg}"),
            SdkError::DeleteError(msg) => write!(f, "Failed to delete row: {msg}"),
            SdkError::TransactionCommitError(msg) => {
                write!(f, "Failed to commit transaction: {msg}")
            }
            SdkError::InvalidRowData(msg) => write!(f, "Invalid row data: {msg}"),
            SdkError::BackendError(msg) => write!(f, "Backend error: {msg}"),
            SdkError::FastForwardRequired { reason } => {
                write!(f, "Fast forward required: {reason}")
            }
            SdkError::FastForwardStateAdvanced => {
                write!(
                    f,
                    "client state advanced during fast-forward; retry from the new anchor"
                )
            }
            SdkError::StateDiverged(divergence) => {
                write!(
                    f,
                    "State diverged at change_id {change_id}: client_clc_prefix={client_clc}, server_clc_prefix={server_clc}, client_data_commitment_prefix={client_dc}, server_data_commitment_prefix={server_dc}",
                    change_id = divergence.change_id,
                    client_clc = hex::encode(divergence.client_clc_prefix),
                    server_clc = hex::encode(divergence.server_clc_prefix),
                    client_dc = hex::encode(divergence.client_data_commitment_prefix),
                    server_dc = hex::encode(divergence.server_data_commitment_prefix)
                )
            }
            SdkError::MissingKeyCommitment => {
                write!(f, "Missing required key commitment for space")
            }
            SdkError::SchemaParsingError(msg) => write!(f, "Failed to parse schema: {msg}"),
            SdkError::JoinError(msg) => write!(f, "Failed to join space: {msg}"),
            SdkError::DecryptionError(msg) => write!(f, "Decryption failed: {msg}"),
        }
    }
}

impl std::error::Error for SdkError {}

impl From<serde_json::Error> for SdkError {
    fn from(err: serde_json::Error) -> Self {
        SdkError::SerializationError(err.to_string())
    }
}

impl From<TupleConversionError> for SdkError {
    fn from(err: TupleConversionError) -> Self {
        SdkError::InvalidQuery(err.to_string())
    }
}

impl From<StoredValueError> for SdkError {
    fn from(err: StoredValueError) -> Self {
        SdkError::SerializationError(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, SdkError>;
