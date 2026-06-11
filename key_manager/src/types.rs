use encrypted_spaces_crypto::pke::DefaultMkem;
use encrypted_spaces_crypto::{KeyCommitment, KeyMaterial};
use encrypted_spaces_zkp::mve::{MveCiphertext, MveRecipientCiphertext, PoseidonMveProof};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Rekey (remove user)
// ---------------------------------------------------------------------------

/// Client -> Server: request to rekey after removing member(s).
#[derive(Clone, Serialize, Deserialize)]
pub struct RekeyRequest {
    pub new_root_commitment: KeyCommitment,
    pub proof: PoseidonMveProof<DefaultMkem>,
}

/// Server -> remaining members: verified rekey result.
/// Returned by `verify_rekey`.
#[derive(Clone, Serialize, Deserialize)]
pub struct RekeyResult {
    pub ciphertexts: MveCiphertext<DefaultMkem, KeyMaterial>,
}

// ---------------------------------------------------------------------------
// Invite (add user)
// ---------------------------------------------------------------------------

/// Client -> Server: request to invite a new member.
#[derive(Clone, Serialize, Deserialize)]
pub struct InviteRequest {
    pub root_commitment: KeyCommitment,
    pub proof: PoseidonMveProof<DefaultMkem>,
}

/// Server verification result after handling an invite.
/// Returned by `verify_invite`.
#[derive(Clone, Serialize, Deserialize)]
pub struct InviteResult {
    pub ciphertexts: MveCiphertext<DefaultMkem, KeyMaterial>,
    pub root_commitment: KeyCommitment,
}

// ---------------------------------------------------------------------------
// GK delivery slot
// ---------------------------------------------------------------------------

/// Per-recipient envelope that bundles an mVE ciphertext with the binding
/// commitment a recipient needs to decapsulate it. Stored in the server's
/// GK delivery slots and fetched via `fetch_my_key_delivery`.
#[derive(Clone, Serialize, Deserialize)]
pub struct GkDeliveryEnvelope {
    pub binding_commitment: KeyCommitment,
    pub ciphertext: MveRecipientCiphertext<DefaultMkem, KeyMaterial>,
}
