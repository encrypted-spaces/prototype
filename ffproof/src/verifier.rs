use crate::common::{FFProof, FFProofError};
use encrypted_spaces_changelog_core::changelog::{ClcState, FastForwardRange};
use risc0_zkvm::sha::Digest as Risc0Digest;
use std::collections::BTreeMap;

#[cfg(target_arch = "wasm32")]
use base64::{engine::general_purpose::URL_SAFE, Engine as _};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::wasm_bindgen;

/// Verified output of a FastForward proof.
#[derive(Clone, Debug)]
pub struct VerifiedFfOutput {
    pub start_clc_state: ClcState,
    pub end_clc_state: ClcState,
    pub start_dc: [u8; 32],
    pub end_dc: [u8; 32],
    pub end_change_id: u32,
    pub sigref_map: BTreeMap<u32, (u32, [u8; 32])>,
    pub timestamp_hwm: u64,
}

/// Verify the FF proof and return the decoded proof output.
///
/// `expected_image_id` must come from the verifier's trusted system
/// parameters (typically `sdk_codegen::FF_GUEST_IMAGE_ID`, baked into
/// the app at build time). The receipt is verified against this value,
/// not against any hash carried inside the proof itself.
pub fn verify_ff(
    proof_bytes: &[u8],
    expected_image_id: [u32; 8],
) -> Result<VerifiedFfOutput, FFProofError> {
    crate::ensure_risc0_proof_mode();

    let proof = FFProof::deserialize(proof_bytes).map_err(|_| {
        log::error!("verify_ff: Failed to deserialize proof");
        FFProofError::DecodingError
    })?;

    if verify_ff_internal(&proof, expected_image_id) {
        Ok(VerifiedFfOutput {
            start_clc_state: proof.io.start_clc_state.clone(),
            end_clc_state: proof.io.end_clc_state.clone(),
            start_dc: proof.io.start_dc.as_bytes().try_into().unwrap(),
            end_dc: proof.io.end_dc.as_bytes().try_into().unwrap(),
            end_change_id: proof.io.end_change_id,
            sigref_map: proof.io.sigref_map.clone(),
            timestamp_hwm: proof.io.timestamp_hwm,
        })
    } else {
        Err(FFProofError::VerificationFailed)
    }
}

pub(crate) fn verify_ff_internal(proof: &FFProof, expected_image_id: [u32; 8]) -> bool {
    // Verify the receipt against the trusted image ID, not against
    // anything carried in the proof itself.  Rotating this constant is
    // currently an app-release event (old apps reject proofs from a new
    // prover, and vice versa); accepting a set of trusted IDs to allow
    // rolling upgrades is future work.
    let extend_ff_id: Risc0Digest = expected_image_id.into();

    let start_time = std::time::Instant::now();
    if proof.receipt.verify(extend_ff_id).is_err() {
        log::error!("Receipt verification failed");
        return false;
    }

    let io: FastForwardRange = match proof.receipt.journal.decode() {
        Ok(decoded) => decoded,
        Err(_) => {
            log::error!("Failed to decode journal");
            return false;
        }
    };

    log::debug!(
        "Verification took {:?}",
        std::time::Instant::now() - start_time
    );

    if io.start_clc_state != proof.io.start_clc_state {
        log::error!("Starting CLC state mismatch!");
        return false;
    }

    if io.end_clc_state != proof.io.end_clc_state {
        log::error!("Ending CLC state mismatch!");
        return false;
    }

    if io.start_dc != proof.io.start_dc {
        log::error!("Starting DC mismatch!");
        return false;
    }

    if io.end_dc != proof.io.end_dc {
        log::error!("Ending DC mismatch!");
        return false;
    }

    if io.sigref_map != proof.io.sigref_map {
        log::error!("Sigref map mismatch!");
        return false;
    }

    if io.timestamp_hwm != proof.io.timestamp_hwm {
        log::error!("Timestamp HWM mismatch!");
        return false;
    }

    if io.end_change_id != proof.io.end_change_id {
        log::error!("end_change_id mismatch!");
        return false;
    }

    true
}
