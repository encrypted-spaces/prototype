//! Row types and data-access layer for SimpleLine2.
//!
//! This module owns the canonical row shapes for the four SimpleLine2 tables
//! (FGK, DGK, D, GB ciphertext), the storage key layout, per-field row
//! encoding/decoding, and scalar metadata handling.
//!
//! Storage identity:
//! - D rows are keyed by sequence number
//! - FGK and DGK rows are keyed by dense append-only ordinals
//! - GB ciphertext rows are keyed by the matching FGK row's ordinal
//!
//! Each logical row field is stored at its own KV key (e.g.
//! `sl2/fgk/row/{ord}/commitment`). Integer fields use fixed-width big-endian
//! encoding, `KeyCommitment` fields use raw bytes, and
//! `EncryptedKeyMaterial` fields use serde.
//!
//! GB ciphertext tail semantics are structural: `older_gb_key_ciphertext` is
//! only meaningful for non-tail chain nodes. Tail rows do not need a physical
//! `None` encoding in storage; chain-aware callers determine tailness from the
//! reconstructed live chain and treat the tail link as absent.

use std::ops::Range;

use encrypted_spaces_crypto::EncryptedKeyMaterial;
use encrypted_spaces_crypto::KeyCommitment;
use encrypted_spaces_key_manager::error::KeyManagerError;
use encrypted_spaces_key_manager::{OperationBuilder, OperationReader};
use serde::{Deserialize, Serialize};

// =========================================================================
// Row types
// =========================================================================

/// Fresh Group Key table row. One per rekey, append-only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FGKRow {
    pub d_start: u64,
    pub commitment: KeyCommitment,
}

/// Derived Group Key commitment. One per delete-keys, cleared on rekey.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DGKRow {
    pub commitment: KeyCommitment,
}

/// D table row (data key commitment).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DTableRow {
    pub seq: u64,
    pub commitment: KeyCommitment,
}

/// Ciphertext pair for a chain node: encrypts the D-head key under the
/// node's GB key, and optionally encrypts the older GB key under this
/// node's GB key (chain link).
///
/// Stored at `sl2/gbct/row/{fgk_ordinal}`, matching the FGK row identity.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GBCiphertextPair {
    pub older_gb_key_ciphertext: Option<EncryptedKeyMaterial>,
    pub d_head_ciphertext: EncryptedKeyMaterial,
}

impl PartialEq for GBCiphertextPair {
    fn eq(&self, other: &Self) -> bool {
        fn ciphertext_eq(a: &EncryptedKeyMaterial, b: &EncryptedKeyMaterial) -> bool {
            serde_json::to_vec(a).ok() == serde_json::to_vec(b).ok()
        }

        self.older_gb_key_ciphertext
            .iter()
            .zip(other.older_gb_key_ciphertext.iter())
            .all(|(a, b)| ciphertext_eq(a, b))
            && self.older_gb_key_ciphertext.is_some() == other.older_gb_key_ciphertext.is_some()
            && ciphertext_eq(&self.d_head_ciphertext, &other.d_head_ciphertext)
    }
}

impl Eq for GBCiphertextPair {}

/// A node in the reconstructed live FGK chain.
///
/// `fgk_ordinal` is the dense append-only storage identity for this node's
/// FGK row and its matching GBCT row. `d_range` is the D-sequence interval
/// that the node covers.
pub struct LiveChainNode {
    pub fgk_ordinal: u64,
    pub d_range: Range<u64>,
}

// =========================================================================
// Storage key constants
// =========================================================================

const FGK_NEXT_KEY: &str = "sl2/fgk/next";
const DGK_NEXT_KEY: &str = "sl2/dgk/next";
const D_MIN_KEY: &str = "sl2/d/min";
const D_NEXT_KEY: &str = "sl2/d/next";

fn fgk_row_key(ordinal: u64) -> String {
    format!("sl2/fgk/row/{ordinal}")
}

fn dgk_row_key(ordinal: u64) -> String {
    format!("sl2/dgk/row/{ordinal}")
}

fn d_row_key(seq: u64) -> String {
    format!("sl2/d/row/{seq}")
}

fn gbct_row_key(fgk_ordinal: u64) -> String {
    format!("sl2/gbct/row/{fgk_ordinal}")
}

// =========================================================================
// Scalar metadata helpers
// =========================================================================

/// Load a `u64` scalar from storage. Returns `None` if the key is missing.
pub(crate) async fn load_u64(
    reader: &dyn OperationReader,
    key: &str,
) -> Result<Option<u64>, KeyManagerError> {
    match reader.get(key).await? {
        None => Ok(None),
        Some(bytes) => {
            let arr: [u8; 8] = bytes.as_slice().try_into().map_err(|_| KeyManagerError)?;
            Ok(Some(u64::from_be_bytes(arr)))
        }
    }
}

/// Load a required `u64` scalar. Returns `Err` if the key is missing.
pub(crate) async fn load_u64_required(
    reader: &dyn OperationReader,
    key: &str,
) -> Result<u64, KeyManagerError> {
    load_u64(reader, key).await?.ok_or(KeyManagerError)
}

/// Save a `u64` scalar to storage (big-endian).
pub(crate) async fn save_u64(builder: &mut dyn OperationBuilder, key: &str, value: u64) {
    builder.put(key, value.to_be_bytes().to_vec()).await;
}

// =========================================================================
// Per-field encoding helpers
// =========================================================================

/// Load a required `KeyCommitment` field from storage.
async fn load_commitment(
    reader: &dyn OperationReader,
    key: &str,
) -> Result<KeyCommitment, KeyManagerError> {
    let bytes = reader.get(key).await?.ok_or(KeyManagerError)?;
    KeyCommitment::from_bytes(&bytes).ok_or(KeyManagerError)
}

/// Save a `KeyCommitment` field to storage.
async fn save_commitment(
    builder: &mut dyn OperationBuilder,
    key: &str,
    commitment: &KeyCommitment,
) {
    builder.put(key, commitment.as_bytes().to_vec()).await;
}

/// Load a required `EncryptedKeyMaterial` field from storage.
async fn load_ciphertext(
    reader: &dyn OperationReader,
    key: &str,
) -> Result<EncryptedKeyMaterial, KeyManagerError> {
    let bytes = reader.get(key).await?.ok_or(KeyManagerError)?;
    serde_json::from_slice(&bytes).map_err(|_| KeyManagerError)
}

/// Load an optional `EncryptedKeyMaterial` field. Missing key means `None`.
async fn load_optional_ciphertext(
    reader: &dyn OperationReader,
    key: &str,
) -> Result<Option<EncryptedKeyMaterial>, KeyManagerError> {
    match reader.get(key).await? {
        None => Ok(None),
        Some(bytes) => serde_json::from_slice(&bytes).map_err(|_| KeyManagerError),
    }
}

/// Save an `EncryptedKeyMaterial` field to storage.
async fn save_ciphertext(
    builder: &mut dyn OperationBuilder,
    key: &str,
    ciphertext: &EncryptedKeyMaterial,
) {
    let bytes = serde_json::to_vec(ciphertext).expect("EncryptedKeyMaterial serializes");
    builder.put(key, bytes).await;
}

// =========================================================================
// Table-specific load/save
// =========================================================================

// --- FGK table ---

/// Load the next-ordinal counter for the FGK table.
///
/// FGK rows are keyed by a dense append-only ordinal. `fgk_next` is the next
/// ordinal to allocate; the latest live FGK row is at ordinal `fgk_next - 1`.
pub(crate) async fn load_fgk_next(reader: &dyn OperationReader) -> Result<u64, KeyManagerError> {
    load_u64_required(reader, FGK_NEXT_KEY).await
}

pub(crate) async fn save_fgk_next(builder: &mut dyn OperationBuilder, value: u64) {
    save_u64(builder, FGK_NEXT_KEY, value).await;
}

pub(crate) async fn load_fgk_row(
    reader: &dyn OperationReader,
    ordinal: u64,
) -> Result<FGKRow, KeyManagerError> {
    let prefix = fgk_row_key(ordinal);
    let d_start = load_u64_required(reader, &format!("{prefix}/d_start")).await?;
    let commitment = load_commitment(reader, &format!("{prefix}/commitment")).await?;
    Ok(FGKRow {
        d_start,
        commitment,
    })
}

pub(crate) async fn save_fgk_row(builder: &mut dyn OperationBuilder, ordinal: u64, row: &FGKRow) {
    let prefix = fgk_row_key(ordinal);
    save_u64(builder, &format!("{prefix}/d_start"), row.d_start).await;
    save_commitment(builder, &format!("{prefix}/commitment"), &row.commitment).await;
}

// --- DGK table ---

/// Load the next-ordinal counter for the DGK table.
///
/// `dgk_next` is the next ordinal to allocate. The last live DGK row is
/// `dgk_next - 1` when `dgk_next > 0`; when `dgk_next == 0` the DGK table
/// is logically empty (e.g. fresh state, or just after a rekey).
pub(crate) async fn load_dgk_next(reader: &dyn OperationReader) -> Result<u64, KeyManagerError> {
    load_u64_required(reader, DGK_NEXT_KEY).await
}

pub(crate) async fn save_dgk_next(builder: &mut dyn OperationBuilder, value: u64) {
    save_u64(builder, DGK_NEXT_KEY, value).await;
}

pub(crate) async fn load_dgk_row(
    reader: &dyn OperationReader,
    ordinal: u64,
) -> Result<DGKRow, KeyManagerError> {
    let prefix = dgk_row_key(ordinal);
    let commitment = load_commitment(reader, &format!("{prefix}/commitment")).await?;
    Ok(DGKRow { commitment })
}

pub(crate) async fn save_dgk_row(builder: &mut dyn OperationBuilder, ordinal: u64, row: &DGKRow) {
    let prefix = dgk_row_key(ordinal);
    save_commitment(builder, &format!("{prefix}/commitment"), &row.commitment).await;
}

// --- D table ---

/// Load the inclusive lower bound of live D sequences.
pub(crate) async fn load_d_min(reader: &dyn OperationReader) -> Result<u64, KeyManagerError> {
    load_u64_required(reader, D_MIN_KEY).await
}

pub(crate) async fn save_d_min(builder: &mut dyn OperationBuilder, value: u64) {
    save_u64(builder, D_MIN_KEY, value).await;
}

/// Load the exclusive upper bound / next D sequence to allocate.
pub(crate) async fn load_d_next(reader: &dyn OperationReader) -> Result<u64, KeyManagerError> {
    load_u64_required(reader, D_NEXT_KEY).await
}

pub(crate) async fn save_d_next(builder: &mut dyn OperationBuilder, value: u64) {
    save_u64(builder, D_NEXT_KEY, value).await;
}

pub(crate) async fn load_d_row(
    reader: &dyn OperationReader,
    seq: u64,
) -> Result<DTableRow, KeyManagerError> {
    let prefix = d_row_key(seq);
    let commitment = load_commitment(reader, &format!("{prefix}/commitment")).await?;
    Ok(DTableRow { seq, commitment })
}

pub(crate) async fn save_d_row(builder: &mut dyn OperationBuilder, row: &DTableRow) {
    let prefix = d_row_key(row.seq);
    save_commitment(builder, &format!("{prefix}/commitment"), &row.commitment).await;
}

// --- GB ciphertext table (no index, keyed by matching FGK ordinal) ---

/// Load the ciphertext pair for a chain node.
///
/// `d_head_ciphertext` is always loaded from storage. `older_gb_key_ciphertext`
/// is interpreted structurally:
/// - on non-tail rows, it is loaded from storage and may be `None` only if the
///   caller wants to validate a malformed row
/// - on tail rows, it is forced to `None` regardless of any stored bytes
pub(crate) async fn load_gbct_row(
    reader: &dyn OperationReader,
    fgk_ordinal: u64,
    is_tail: bool,
) -> Result<GBCiphertextPair, KeyManagerError> {
    let prefix = gbct_row_key(fgk_ordinal);
    let d_head_ciphertext = load_ciphertext(reader, &format!("{prefix}/d_head_ct")).await?;
    let older_gb_key_ciphertext = if is_tail {
        None
    } else {
        load_optional_ciphertext(reader, &format!("{prefix}/gb_ct")).await?
    };
    Ok(GBCiphertextPair {
        older_gb_key_ciphertext,
        d_head_ciphertext,
    })
}

/// Load only the D-head ciphertext for a chain node.
pub(crate) async fn load_gbct_d_head(
    reader: &dyn OperationReader,
    fgk_ordinal: u64,
) -> Result<EncryptedKeyMaterial, KeyManagerError> {
    let prefix = gbct_row_key(fgk_ordinal);
    load_ciphertext(reader, &format!("{prefix}/d_head_ct")).await
}

/// Save the ciphertext pair for a chain node.
///
/// `d_head_ciphertext` is always written. `older_gb_key_ciphertext` is written
/// only when present; tail rows simply omit the field.
pub(crate) async fn save_gbct_row(
    builder: &mut dyn OperationBuilder,
    fgk_ordinal: u64,
    pair: &GBCiphertextPair,
) {
    let prefix = gbct_row_key(fgk_ordinal);
    save_ciphertext(
        builder,
        &format!("{prefix}/d_head_ct"),
        &pair.d_head_ciphertext,
    )
    .await;
    if let Some(older) = pair.older_gb_key_ciphertext.as_ref() {
        save_ciphertext(builder, &format!("{prefix}/gb_ct"), older).await;
    }
}
