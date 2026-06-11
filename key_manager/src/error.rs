/// Error type for key manager operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyManagerError;

impl std::fmt::Display for KeyManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "key manager error")
    }
}

impl std::error::Error for KeyManagerError {}
