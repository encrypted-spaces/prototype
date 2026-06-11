//! Per-recipient group-key delivery slots — the generic server-side delivery
//! channel for retention-backed key systems. After an accepted membership or
//! key-rotation op commits its canonical writes, the server puts a
//! per-recipient envelope (an opaque blob to this module) in each affected
//! member's slot; the recipient fetches it via `fetch_my_key_delivery` once
//! their local retention snapshot is current.
//!
//! Slot writes are intentionally **not transactional** with the underlying
//! retention mutation: the canonical commit happens first, then slots are
//! updated best-effort in runtime memory. Retention-specific envelope
//! construction, binding-commitment semantics, and when-to-fetch policy all
//! live in the retention implementation (`retention::simple_line2` for SL2
//! today); this module only stores and hands back opaque per-recipient bytes.
//!
//! # Persistence
//!
//! Slots are runtime-owned state, not canonical database rows:
//!
//! - the authoritative retention state lives in the changelog + `_retention`;
//! - slots are lost on process restart because there is no durable slot store;
//! - a recipient whose slot was lost that way, and who has missed a key
//!   rotation, must wait for another rotation to be able to recover a usable
//!   group key. This tradeoff is acceptable because losing a slot never leaves
//!   canonical retention state inconsistent.

use std::collections::HashMap;

use encrypted_spaces_backend::access_control::AuthContext;
use encrypted_spaces_backend::proto::{self, db_response, DbResponse};

use crate::app_config::AppConfig;
use crate::db::{error_response, get_or_create_space, ok_response, SpaceState};

/// Per-recipient GK delivery slots, keyed by authenticated user id.
///
/// Each slot stores the serialized [`GkDeliveryEnvelope`] bytes addressed to
/// that recipient. Slots are overwritten in place on accepted rekey/add-user
/// events and removed when a user is removed from the space.
#[derive(Clone, Default)]
pub struct GroupKeyDeliverySlots {
    pub slots: HashMap<i64, Vec<u8>>,
}

impl GroupKeyDeliverySlots {
    /// Insert or overwrite a recipient's slot bytes.
    pub fn put(&mut self, recipient_uid: i64, payload: Vec<u8>) {
        self.slots.insert(recipient_uid, payload);
    }

    /// Read a recipient's slot bytes, if any.
    pub fn get(&self, recipient_uid: i64) -> Option<Vec<u8>> {
        self.slots.get(&recipient_uid).cloned()
    }

    /// Remove a recipient's slot. Used when the user leaves the space.
    pub fn remove(&mut self, recipient_uid: i64) {
        self.slots.remove(&recipient_uid);
    }
}

/// Handle a `FetchMyKeyDelivery` request: return the slot for the authenticated user.
pub(crate) async fn handle_fetch_my_key_delivery_request(
    request_id: &str,
    _req: proto::FetchMyKeyDeliveryRequest,
    app_cfg: &AppConfig,
    auth_context: &AuthContext,
) -> DbResponse {
    let uid = match auth_context.uid {
        Some(uid) => uid,
        None => {
            return error_response(
                request_id,
                "fetch_my_key_delivery requires authenticated user",
            );
        }
    };

    let slot = get_or_create_space(auth_context.space_id, Some(app_cfg))
        .await
        .lock()
        .await
        .key_delivery_slots
        .get(uid);

    let (has_delivery, payload) = match slot {
        Some(bytes) => (true, bytes),
        None => (false, Vec::new()),
    };

    ok_response(
        request_id,
        db_response::Result::FetchMyKeyDelivery(proto::FetchMyKeyDeliveryResponse {
            has_delivery,
            payload,
        }),
    )
}

#[allow(dead_code)] // Convenience accessor used by future PRs / tests.
impl SpaceState {
    pub fn get_delivery_slot(&self, recipient_uid: i64) -> Option<Vec<u8>> {
        self.key_delivery_slots.get(recipient_uid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_then_get_returns_payload() {
        let mut slots = GroupKeyDeliverySlots::default();
        slots.put(7, b"hello".to_vec());
        assert_eq!(slots.get(7).as_deref(), Some(&b"hello"[..]));
    }

    #[test]
    fn get_absent_is_none() {
        let slots = GroupKeyDeliverySlots::default();
        assert!(slots.get(42).is_none());
    }

    #[test]
    fn put_overwrites_in_place() {
        let mut slots = GroupKeyDeliverySlots::default();
        slots.put(3, b"first".to_vec());
        slots.put(3, b"second".to_vec());
        assert_eq!(slots.get(3).as_deref(), Some(&b"second"[..]));
        assert_eq!(slots.slots.len(), 1);
    }

    #[test]
    fn remove_drops_slot() {
        let mut slots = GroupKeyDeliverySlots::default();
        slots.put(9, b"payload".to_vec());
        slots.remove(9);
        assert!(slots.get(9).is_none());
    }

    #[test]
    fn remove_absent_is_noop() {
        let mut slots = GroupKeyDeliverySlots::default();
        slots.remove(99);
        assert!(slots.get(99).is_none());
    }

    #[test]
    fn slots_are_per_recipient() {
        let mut slots = GroupKeyDeliverySlots::default();
        slots.put(1, b"for-1".to_vec());
        slots.put(2, b"for-2".to_vec());
        assert_eq!(slots.get(1).as_deref(), Some(&b"for-1"[..]));
        assert_eq!(slots.get(2).as_deref(), Some(&b"for-2"[..]));
        slots.remove(1);
        assert!(slots.get(1).is_none());
        assert_eq!(slots.get(2).as_deref(), Some(&b"for-2"[..]));
    }
}
