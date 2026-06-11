use std::future::Future;
use std::pin::Pin;

use crate::error::KeyManagerError;

/// Output from a finalized [`OperationBuilder`].
pub struct OperationOutput {
    /// Key-value writes accumulated during the operation.
    pub writes: Vec<(String, Vec<u8>)>,
    /// Serialized proofs recorded during the operation.
    pub proofs: Vec<Vec<u8>>,
    /// Whether the operation requires a post-apply delivery-slot fetch.
    pub needs_delivery: bool,
}

/// Read-only view of key-management state.
///
/// Provides the `get` accessor without any write or proof-accumulation
/// methods. Use this in function signatures that only need to read state.
#[async_trait::async_trait]
pub trait OperationReader: Send + Sync {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, KeyManagerError>;
}

/// Builder that accumulates reads, writes, and proofs for a key management
/// operation.
///
/// Created per-operation (e.g. for the lifetime of a `rotate()` call).
/// Reads happen in real-time; writes and proofs are collected and returned
/// via the concrete implementation's `finalize()` method.
#[async_trait::async_trait]
pub trait OperationBuilder: OperationReader {
    async fn put(&mut self, key: &str, value: Vec<u8>);
    async fn record_proof(&mut self, proof: Vec<u8>);

    /// Signal that the operation requires a post-apply delivery-slot fetch.
    /// Called by [`SpaceKey`] implementations when they write retention state
    /// that introduces a new group key needing distribution.
    fn mark_needs_delivery(&mut self) {}

    /// Whether any operation marked this builder as needing delivery.
    fn needs_delivery(&self) -> bool {
        false
    }
}

/// The reader function type for [`CollectingOperationBuilder`].
///
/// An async closure that resolves a key to an optional value.
pub type AsyncReader = Box<
    dyn for<'a> Fn(
            &'a str,
        ) -> Pin<
            Box<dyn Future<Output = Result<Option<Vec<u8>>, KeyManagerError>> + Send + 'a>,
        > + Send
        + Sync,
>;

/// [`OperationBuilder`] that collects writes and proofs in memory and
/// delegates reads to an async closure.
pub struct CollectingOperationBuilder {
    reader: AsyncReader,
    writes: Vec<(String, Vec<u8>)>,
    proofs: Vec<Vec<u8>>,
    needs_delivery: bool,
}

impl CollectingOperationBuilder {
    pub fn new(reader: AsyncReader) -> Self {
        Self {
            reader,
            writes: Vec::new(),
            proofs: Vec::new(),
            needs_delivery: false,
        }
    }

    /// Create a builder pre-seeded with existing writes.
    /// Reads check these writes first (read-your-writes), then fall back to the reader.
    pub fn with_writes(reader: AsyncReader, writes: Vec<(String, Vec<u8>)>) -> Self {
        Self {
            reader,
            writes,
            proofs: Vec::new(),
            needs_delivery: false,
        }
    }

    /// Create a builder with a no-op reader (always returns None).
    pub fn noop() -> Self {
        Self::new(Box::new(|_| Box::pin(async { Ok(None) })))
    }

    /// Consume the builder and return the accumulated output.
    pub fn finalize(self) -> OperationOutput {
        OperationOutput {
            writes: self.writes,
            proofs: self.proofs,
            needs_delivery: self.needs_delivery,
        }
    }
}

#[async_trait::async_trait]
impl OperationReader for CollectingOperationBuilder {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, KeyManagerError> {
        // Check local writes first (read-your-writes).
        for (k, v) in self.writes.iter().rev() {
            if k == key {
                return Ok(Some(v.clone()));
            }
        }
        (self.reader)(key).await
    }
}

#[async_trait::async_trait]
impl OperationBuilder for CollectingOperationBuilder {
    async fn put(&mut self, key: &str, value: Vec<u8>) {
        self.writes.push((key.to_string(), value));
    }

    async fn record_proof(&mut self, proof: Vec<u8>) {
        self.proofs.push(proof);
    }

    fn mark_needs_delivery(&mut self) {
        self.needs_delivery = true;
    }

    fn needs_delivery(&self) -> bool {
        self.needs_delivery
    }
}

/// In-memory [`OperationBuilder`] backed by a HashMap. Useful for tests.
#[derive(Default)]
pub struct MemoryOperationBuilder {
    data: std::collections::HashMap<String, Vec<u8>>,
    proofs: Vec<Vec<u8>>,
    needs_delivery: bool,
}

impl MemoryOperationBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn remove(&mut self, key: &str) {
        self.data.remove(key);
    }

    pub fn proofs(&self) -> &[Vec<u8>] {
        &self.proofs
    }
}

#[async_trait::async_trait]
impl OperationReader for MemoryOperationBuilder {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, KeyManagerError> {
        Ok(self.data.get(key).cloned())
    }
}

#[async_trait::async_trait]
impl OperationBuilder for MemoryOperationBuilder {
    async fn put(&mut self, key: &str, value: Vec<u8>) {
        self.data.insert(key.to_string(), value);
    }

    async fn record_proof(&mut self, proof: Vec<u8>) {
        self.proofs.push(proof);
    }

    fn mark_needs_delivery(&mut self) {
        self.needs_delivery = true;
    }

    fn needs_delivery(&self) -> bool {
        self.needs_delivery
    }
}

/// Read-only [`OperationReader`] view over an operation's pending writes.
///
/// Verifier-side companion to [`CollectingOperationBuilder`]. Reads look up
/// keys in the provided slice; missing keys return `None` with **no fallback
/// to pre-op state**. That strictness is load-bearing for retention-proof
/// verifiers: if post-op rows could fall through to existing storage, an
/// attacker could submit an operation with an empty or partial payload and
/// have verification succeed against stale canonical rows.
pub struct PendingWritesView<'a> {
    pending: &'a [(String, Vec<u8>)],
}

impl<'a> PendingWritesView<'a> {
    pub fn new(pending: &'a [(String, Vec<u8>)]) -> Self {
        Self { pending }
    }
}

#[async_trait::async_trait]
impl<'a> OperationReader for PendingWritesView<'a> {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, KeyManagerError> {
        for (k, v) in self.pending.iter().rev() {
            if k == key {
                return Ok(Some(v.clone()));
            }
        }
        Ok(None)
    }
}
