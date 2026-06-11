use crate::key_manager::SpacePublicKey;
use crate::{Space, Table};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::{SigningKey, VerifyingKey};
use encrypted_spaces_backend::error::SdkError;
use encrypted_spaces_backend::internal_schemas::{key_history_schema, users_schema};
use encrypted_spaces_backend::SpaceId;
use encrypted_spaces_changelog_core::changelog::OpType;
use encrypted_spaces_crypto::pke::{KemKeyPair, XWingRistretto};
use encrypted_spaces_crypto::signature::SignatureKeyPair;
use encrypted_spaces_crypto::{default_rng, Mkem, Signature};
use encrypted_spaces_key_manager::{DefaultMkem, DefaultSignature, InviteRequest};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A representation of a user record, with secret key material
#[derive(Clone)]
pub(crate) struct UserWithSecrets<M = DefaultMkem, S = DefaultSignature>
where
    M: Mkem,
    S: Signature,
    KemKeyPair<M>: Clone,
    SignatureKeyPair<S>: Clone,
{
    pub id: Option<i64>,
    pub update_key_pair: KemKeyPair<M>,
    pub auth_key_pair: SignatureKeyPair<S>,
    pub status: UserStatus,
}

impl Default for UserWithSecrets {
    fn default() -> Self {
        Self::new()
    }
}

impl UserWithSecrets {
    pub fn new() -> Self {
        let mut rng = default_rng();
        let update_key_pair = KemKeyPair::new(&mut rng);
        let auth_key_pair = SignatureKeyPair::<DefaultSignature>::new();

        Self {
            id: None,
            update_key_pair,
            auth_key_pair,
            status: UserStatus::Full,
        }
    }

    pub(crate) fn provisional() -> Self {
        let mut user = Self::new();
        user.status = UserStatus::Provisional;
        user
    }

    pub fn as_record(&self) -> UserRecord {
        UserRecord {
            id: self.id,
            update_key: self.update_key_pair.public().clone(),
            auth_key: *self.auth_key_pair.verification_key(),
            status: self.status,
        }
    }
}

// Serde helper for `UserWithSecrets<DefaultMkem, DefaultSignature>` so we can persist key material.
//
// Only the secret material is stored; public keys are derived from secrets on load.
#[derive(Serialize, Deserialize)]
struct UserWithSecretsSerde {
    id: Option<i64>,
    /// 32-byte seed for XWingRistrettoSecretKey, base64-encoded.
    update_secret_seed: String,
    /// ed25519 signing key bytes, base64-encoded.
    auth_secret: String,
    status: i64,
}

impl Serialize for UserWithSecrets<DefaultMkem, DefaultSignature> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let helper = UserWithSecretsSerde {
            id: self.id,
            update_secret_seed: BASE64.encode(self.update_key_pair.secret().as_seed()),
            auth_secret: BASE64.encode(self.auth_key_pair.0.to_bytes()),
            status: self.status as i64,
        };

        helper.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for UserWithSecrets<DefaultMkem, DefaultSignature> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let helper = UserWithSecretsSerde::deserialize(deserializer)?;

        // Reconstruct the KEM keypair from the 32-byte seed.
        let seed_bytes: [u8; 32] = BASE64
            .decode(helper.update_secret_seed)
            .map_err(serde::de::Error::custom)?
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid seed length, expected 32 bytes"))?;
        let kem = XWingRistretto;
        let (update_public, update_secret) = kem.keygen_from_seed(seed_bytes);
        let update_key_pair = KemKeyPair::from((update_public, update_secret));

        // Reconstruct the auth keypair from the signing key bytes (public key is derived).
        let auth_sk_bytes: [u8; 32] = BASE64
            .decode(helper.auth_secret)
            .map_err(serde::de::Error::custom)?
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid auth signing key length"))?;
        let auth_sk = SigningKey::from_bytes(&auth_sk_bytes);
        let auth_vk = VerifyingKey::from(&auth_sk);

        let status = match helper.status {
            0 => Ok(UserStatus::Provisional),
            1 => Ok(UserStatus::Full),
            other => Err(serde::de::Error::custom(format!(
                "unknown UserStatus value: {other}"
            ))),
        }?;

        Ok(Self {
            id: helper.id,
            update_key_pair,
            auth_key_pair: SignatureKeyPair(auth_sk, auth_vk),
            status,
        })
    }
}

/// Membership status for a user in the space.
///
/// Stored as an integer column: `Pending = 0`, `Active = 1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum UserStatus {
    /// Invited but has not yet called [`Space::join`].
    Provisional = 0,
    /// Has accepted the invite and rotated to permanent keypairs.
    Full = 1,
}

impl Serialize for UserStatus {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_i64(*self as i64)
    }
}

impl<'de> Deserialize<'de> for UserStatus {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = i64::deserialize(deserializer)?;
        match value {
            0 => Ok(UserStatus::Provisional),
            1 => Ok(UserStatus::Full),
            other => Err(serde::de::Error::custom(format!(
                "unknown UserStatus value: {other}"
            ))),
        }
    }
}

/// A representation of a user in the membership table.
///
/// This is just a placeholder for building apps, will
/// in reality have more data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRecord<M = DefaultMkem, S = DefaultSignature>
where
    M: Mkem,
    S: Signature,
{
    pub id: Option<i64>,
    #[serde(
        serialize_with = "serialize_as_base64",
        deserialize_with = "deserialize_from_base64"
    )]
    pub update_key: M::PublicKey,
    #[serde(
        serialize_with = "serialize_as_base64",
        deserialize_with = "deserialize_from_base64"
    )]
    pub auth_key: S::VerificationKey,
    pub status: UserStatus,
}

/// A bundle handed to an invited user so they can call [`Space::join`].
///
/// Contains everything the new member needs: their private key material and
/// the ID of the space they have been invited to.
#[derive(Serialize, Deserialize)]
pub struct SpaceInvite {
    pub(crate) user: UserWithSecrets,
    pub(crate) space_id: SpaceId,
}

impl SpaceInvite {
    /// The user id assigned to the invitee by the server.
    pub fn id(&self) -> Option<i64> {
        self.user.id
    }

    /// Membership status of the invitee (always `Provisional` for a fresh invite).
    pub fn status(&self) -> UserStatus {
        self.user.status
    }

    /// The id of the space the invitee has been invited to.
    pub fn space_id(&self) -> SpaceId {
        self.space_id
    }
}

pub(crate) use encrypted_spaces_backend::internal_schemas::USERS_TABLE_NAME;

impl Space {
    pub(crate) async fn initialize_users(&self) -> Result<(), SdkError> {
        self.register_table_schema(users_schema());

        // Warm users cache
        self.users().select().all().await?;

        Ok(())
    }

    pub(crate) fn initialize_key_history(&self) {
        self.register_table_schema(key_history_schema());
    }

    /// Access the built-in `users` table, to read from or modify it.
    pub fn users(&self) -> Table<UserRecord> {
        // Table is already initialized by Space::create
        self.table(USERS_TABLE_NAME)
    }

    pub async fn invite_user(&self) -> Result<SpaceInvite, SdkError> {
        // 1. Create the new user's keypairs (ID is assigned by the server during add_member).
        let new_user = UserWithSecrets::provisional();

        // 2. Build the invite request (only needs the new member's PK).
        let mut invite_builder = self.retention_builder();
        let add_request: InviteRequest = self
            .key_manager()
            .create_invite(new_user.update_key_pair.public(), &mut invite_builder)
            .await?;
        let invite_output = invite_builder.finalize();
        let invite_retention_writes = invite_output.writes;
        let invite_proofs = invite_output.proofs;

        // 3. Prepare the insert for the new user record (builds the query + changelog entry).
        let mut pending_record = new_user.as_record();
        pending_record.status = UserStatus::Provisional;
        let mut insert_builder = self.users().insert(&pending_record);
        insert_builder.take_pending_error()?;
        crate::crypto::encrypt_query_fields(&mut insert_builder.query, self).await?;
        let change = {
            use crate::changelog::ChangeBuilder;
            ChangeBuilder::new(&mut insert_builder.query, std::sync::Arc::new(self.clone()))
                .build_invite_user(&invite_retention_writes)
                .await?
        };

        // 4. Send to the server.
        let change_response = self
            .transport
            .add_member(add_request, &change, invite_proofs)
            .await?;

        // 5. Apply the insert changelog entry to local state and extract
        //    the new user's ID. Issue #212: only report success once the exact
        //    InviteUser entry is proven incorporated (sequential append or a
        //    fast-forward ragged apply / inclusion proof); fail closed otherwise.
        let completed = self.complete_submitted(change, change_response).await?;
        let new_user_id = if let Some(writes) = &completed.sequential_writes {
            crate::cache::update_cache_from_proven_writes(self, &completed.change, writes).await;
            crate::cache::new_row_id_for_table(self, writes, USERS_TABLE_NAME).ok_or_else(|| {
                SdkError::InsertError("InviteUser proof did not write any new row to _users".into())
            })?
        } else if let Some(id) = completed
            .ff_inserted_ids
            .get(&completed.change.entry.signature)
            .copied()
        {
            id
        } else {
            // Proof-covered fast-forward: extract the new uid from the
            // acknowledged response after discharge was proven on the verified
            // CLC chain. Same unanchored-id limitation as
            // `InsertBuilder::execute_as` (not a false success; entry is proven).
            // Tracked in https://github.com/encrypted-spaces/prototype/issues/232.
            let writes =
                self.validate_and_apply_change(&completed.change.entry, &completed.response)?;
            crate::cache::update_cache_from_proven_writes(self, &completed.change, &writes).await;
            crate::cache::new_row_id_for_table(self, &writes, USERS_TABLE_NAME).ok_or_else(
                || {
                    SdkError::InsertError(
                        "InviteUser proof did not write any new row to _users".into(),
                    )
                },
            )?
        };

        // 7. Post-apply delivery-slot recovery if the builder flagged it.
        self.post_apply_delivery_slot_recovery(invite_output.needs_delivery)
            .await?;

        let mut result_user = new_user;
        result_user.id = Some(new_user_id);
        Ok(SpaceInvite {
            user: result_user,
            space_id: self.id,
        })
    }

    pub async fn remove_user(&self, user_id: i64) -> Result<(), SdkError> {
        use encrypted_spaces_backend::internal_schemas::{
            KEY_HISTORY_COL_OLD_AUTH_KEY, KEY_HISTORY_COL_UID, KEY_HISTORY_COL_VALID_FROM,
            KEY_HISTORY_COL_VALID_TO, KEY_HISTORY_TABLE_NAME,
        };
        use encrypted_spaces_backend::query::QueryParam;

        // 1. Fetch all current users
        let all_users: Vec<UserRecord> = self.users().select().all().await?;

        // 2. Separate the target from remaining members
        let target = all_users
            .iter()
            .find(|u| u.id == Some(user_id))
            .ok_or(SdkError::NotFound)?;
        let remaining: Vec<&UserRecord> =
            all_users.iter().filter(|u| u.id != Some(user_id)).collect();

        // 3. Collect remaining PKs and UIDs (same order)
        let remaining_pks: Vec<SpacePublicKey> =
            remaining.iter().map(|u| u.update_key.clone()).collect();
        let remaining_uids: Vec<i64> = remaining.iter().map(|u| u.id.unwrap_or(0)).collect();

        // 4. Generate the rekey request for remaining members
        let mut rekey_builder = self.retention_builder();
        let delete_request = self
            .key_manager()
            .rekey(&remaining_pks, &mut rekey_builder)
            .await?;
        let rekey_output = rekey_builder.finalize();
        let rekey_retention_writes = rekey_output.writes;
        let rekey_proofs = rekey_output.proofs;
        // 5. Build _key_history insert for the removed user's current auth key.
        //    Encode the auth key the same way as RefreshKeys (base64 of JSON-serialized vk).
        let target_auth_key_b64 = {
            let vk_json = serde_json::to_vec(&target.auth_key)
                .map_err(|e| SdkError::SerializationError(e.to_string()))?;
            BASE64.encode(vk_json)
        };

        // Determine valid_from: check _key_history for this user's most recent entry.
        // If they have rotated before, valid_from = max(valid_to) + 1 from their entries.
        // Otherwise, valid_from = 0 (original key, never rotated).
        let kh_table: crate::Table<serde_json::Value> = self.table(KEY_HISTORY_TABLE_NAME);
        let user_kh: Vec<serde_json::Value> =
            kh_table.select().where_eq("uid", user_id).all().await?;
        let valid_from: u32 = user_kh
            .iter()
            .filter_map(|row| {
                row.get("valid_to_change_id")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32 + 1)
            })
            .max()
            .unwrap_or(0);

        // valid_to = current_change_id (the last change before this RemoveUser)
        let valid_to = self.with_state(|state| state.current_change_id);

        let key_history_data: Vec<(String, QueryParam)> = vec![
            (
                KEY_HISTORY_COL_UID.to_string(),
                QueryParam::Integer(user_id),
            ),
            (
                KEY_HISTORY_COL_OLD_AUTH_KEY.to_string(),
                QueryParam::Text(target_auth_key_b64),
            ),
            (
                KEY_HISTORY_COL_VALID_FROM.to_string(),
                QueryParam::Integer(valid_from as i64),
            ),
            (
                KEY_HISTORY_COL_VALID_TO.to_string(),
                QueryParam::Integer(valid_to as i64),
            ),
        ];

        // 6. Prepare the delete query + changelog entry covering the user
        //    delete, the key-history insert, and the retention writes.
        let mut delete_builder = self.users().delete().where_eq("id", user_id);
        crate::crypto::encrypt_query_fields(&mut delete_builder.query, self).await?;
        let delete_change = {
            use crate::changelog::ChangeBuilder;
            ChangeBuilder::new(&mut delete_builder.query, std::sync::Arc::new(self.clone()))
                .build_remove_user(&key_history_data, &rekey_retention_writes)
                .await?
                .ok_or(SdkError::InvalidQuery(
                    "failed to build changelog entry for query".to_string(),
                ))?
        };

        // 7. Send to server
        let change_response = self
            .transport
            .remove_member(
                delete_request,
                &remaining_uids,
                &delete_change,
                rekey_proofs,
            )
            .await?;

        // 8. Apply the change locally.  The entry keeps the client's original
        //    valid_to guess; the proof carries the server-assigned value (which will usually be equal).
        //    Issue #212: fail closed unless the exact RemoveUser entry is proven.
        let completed = self
            .complete_submitted(delete_change, change_response)
            .await?;
        if let Some(writes) = &completed.sequential_writes {
            crate::cache::update_cache_from_proven_writes(self, &completed.change, writes).await;
        }

        // 10. Post-apply delivery-slot recovery if the builder flagged it.
        self.post_apply_delivery_slot_recovery(rekey_output.needs_delivery)
            .await?;

        Ok(())
    }

    /// Replace this member's update and auth key pairs with freshly generated versions.
    ///
    /// Called by [`Space::join`] immediately after bootstrapping from the invite to shift
    /// from provisional -> permanent keys.
    ///
    /// Alongside the `_users` update, inserts a `_key_history` row recording the
    /// old auth key and the range of change_ids it was valid for.
    pub(crate) async fn rotate_user_keys(&self) -> Result<UserWithSecrets, SdkError> {
        use crate::changelog::ChangeBuilder;
        use crate::crypto::encrypt_query_fields;
        use encrypted_spaces_backend::internal_schemas::USERS_TABLE_NAME;
        use encrypted_spaces_backend::internal_schemas::{
            KEY_HISTORY_COL_OLD_AUTH_KEY, KEY_HISTORY_COL_UID, KEY_HISTORY_COL_VALID_FROM,
            KEY_HISTORY_COL_VALID_TO,
        };
        use encrypted_spaces_backend::query::{
            ComparisonOperator, Predicate, Query, QueryOperation, QueryParam,
        };

        let user_id =
            self.with_state(|state| state.auth_context.uid)
                .ok_or(SdkError::AccessDenied(
                    "Must be authenticated in order to rotate user keys".to_string(),
                ))?;

        let mut fresh_user = UserWithSecrets::new();
        fresh_user.id = Some(user_id);

        // Serialize via the UserRecord serde impl (which uses serialize_as_base64)
        // so the values match the format written during Table::insert.
        let record_json = serde_json::to_value(fresh_user.as_record())
            .map_err(|e| SdkError::SerializationError(e.to_string()))?;
        let update_key_str = record_json["update_key"]
            .as_str()
            .ok_or_else(|| {
                SdkError::SerializationError("failed to serialize update_key".to_string())
            })?
            .to_string();
        let auth_key_str = record_json["auth_key"]
            .as_str()
            .ok_or_else(|| {
                SdkError::SerializationError("failed to serialize auth_key".to_string())
            })?
            .to_string();

        // Capture old auth key (base64-encoded) and validity range BEFORE
        // building the change (which will be signed by the old key).
        let (old_auth_key_b64, key_valid_from, valid_to) = {
            let km = self.key_manager.lock().await;
            let old_vk = km.auth_key_pair().verification_key();
            let vk_json = serde_json::to_vec(old_vk).expect("serialize vk");
            let b64 = BASE64.encode(vk_json);
            let (kv, ml) =
                self.with_state(|state| (state.key_valid_from_change_id, state.my_last_change_id));
            (b64, kv, ml)
        };

        // Build _users update query
        let mut users_query = Query::new(
            USERS_TABLE_NAME.to_string(),
            QueryOperation::Update(vec![
                ("update_key".to_string(), QueryParam::Text(update_key_str)),
                ("auth_key".to_string(), QueryParam::Text(auth_key_str)),
                (
                    "status".to_string(),
                    QueryParam::Integer(UserStatus::Full as i64),
                ),
            ]),
        );
        users_query.predicate = Some(Predicate {
            column: "id".to_string(),
            operator: ComparisonOperator::Equal,
            values: vec![QueryParam::Integer(user_id)],
            cursor_id: None,
        });

        encrypt_query_fields(&mut users_query, self).await?;

        // Build _key_history insert data
        let key_history_data: Vec<(String, QueryParam)> = vec![
            (
                KEY_HISTORY_COL_UID.to_string(),
                QueryParam::Integer(user_id),
            ),
            (
                KEY_HISTORY_COL_OLD_AUTH_KEY.to_string(),
                QueryParam::Text(old_auth_key_b64),
            ),
            (
                KEY_HISTORY_COL_VALID_FROM.to_string(),
                QueryParam::Integer(key_valid_from as i64),
            ),
            (
                KEY_HISTORY_COL_VALID_TO.to_string(),
                QueryParam::Integer(valid_to as i64),
            ),
        ];

        // Build combined changelog entry covering the `_users` update and
        // the matching `_key_history` insert.
        let space_arc = std::sync::Arc::new(self.clone());
        let mut builder = ChangeBuilder::new(&mut users_query, space_arc);
        let change = match builder.build_refresh_keys(&key_history_data).await? {
            Some(c) => c,
            None => {
                return Err(SdkError::DatabaseError(
                    "No matching user row for RefreshKeys".into(),
                ))
            }
        };

        let change_response = self.transport.submit_change(&change, vec![]).await?;

        // Issue #212: only advance cryptographic signer state (install the new
        // key pairs / bump `key_valid_from_change_id`) once the *exact*
        // rotation entry is proven incorporated on the verified chain. We submit
        // directly (no stale-parent re-sign) because re-anchoring would
        // invalidate the `_key_history.valid_to` baked into this entry; on an
        // accepted-but-not-sequential response `complete_submitted` recovers via
        // fast-forward and fails closed if the rotation entry is not proven.
        let completed = self.complete_submitted(change, change_response).await?;
        if let Some(writes) = &completed.sequential_writes {
            crate::cache::update_cache_from_proven_writes(self, &completed.change, writes).await;
        }

        // Update key_valid_from_change_id to this rotation's change_id
        self.with_state_mut(|state| {
            state.key_valid_from_change_id = completed.response.change_id;
        });
        {
            let mut km = self.key_manager.lock().await;
            km.set_update_key_pair(fresh_user.update_key_pair.clone());
            km.set_auth_key_pair(fresh_user.auth_key_pair.clone());
        }

        Ok(fresh_user)
    }

    /// Resolve the authentication (signature verification) key for a given user
    /// at a specific change_id.
    ///
    /// 1. Look up the user's current key in `_users`.
    /// 2. Read `_key_history` rows for that `uid` from the local merk table.
    /// 3. Return whichever key covers `change_id` — current or historical.
    #[allow(dead_code)] // convenience wrapper; used by tests and future callers
    pub(crate) async fn resolve_signing_key(
        &self,
        uid: u32,
        change_id: u32,
    ) -> Result<VerifyingKey, SdkError> {
        self.resolve_signing_key_for_change(uid, change_id, OpType::Update, 0)
            .await
    }

    /// Resolve the signing key for a specific change, taking into account the
    /// change's op_type and sig_ref (signer's previous change_id).
    ///
    /// For `RefreshKeys` changes the signing key is the *predecessor* key — the
    /// one that was rotated out by this very change. We locate it via `sig_ref`
    /// (the signer's `my_last_change_id` recorded in the changelog entry).
    //
    // TODO (perf): we currently always read from _key_history, because we don't have a
    //              valid_from change_id for the current key.  If _users auth_key had some metadata
    //             about when the key was created (in terms of change_id) we could know if the current
    //             key was the right one (and it usually would be), saving reads to _key_history. Since
    //             _key_history is lazily cached after the first read, and doesn't change much, the current
    //             approach is not so bad
    pub(crate) async fn resolve_signing_key_for_change(
        &self,
        uid: u32,
        change_id: u32,
        op_type: OpType,
        sig_ref: u32,
    ) -> Result<VerifyingKey, SdkError> {
        use encrypted_spaces_backend::internal_schemas::KEY_HISTORY_TABLE_NAME;

        // Step 1: Look up the user's current key in `_users`.
        // Read as raw JSON so that stub / partial rows (e.g. from seed_user_cache)
        // that lack update_key don't fail deserialization — we only need auth_key.
        let current_key = {
            let users_raw: crate::Table<serde_json::Value> = self.table("_users");
            let row = users_raw
                .select()
                .where_eq("id", uid as i64)
                .first()
                .await?;
            if let Some(row) = row.as_ref() {
                if let Some(b64) = row.get("auth_key").and_then(|v| v.as_str()) {
                    Some(deserialize_verification_key_from_base64(b64)?)
                } else {
                    None
                }
            } else {
                None
            }
        };

        // Step 2: Read _key_history rows for this uid.
        let kh_table: crate::Table<serde_json::Value> = self.table(KEY_HISTORY_TABLE_NAME);
        let history: Vec<serde_json::Value> =
            kh_table.select().where_eq("uid", uid as i64).all().await?;

        // Step 3: RefreshKeys special case — the change is signed by the key
        // that is being rotated OUT. Find the history row whose valid_to matches
        // the signer's previous change (sig_ref).
        if op_type == OpType::RefreshKeys {
            if let Some(row) = history.iter().find(|row| {
                row.get("valid_to_change_id")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32)
                    == Some(sig_ref)
            }) {
                let auth_key_b64 = row
                    .get("old_auth_key")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        SdkError::ValidationError(
                            "missing old_auth_key in _key_history".to_string(),
                        )
                    })?;
                return deserialize_verification_key_from_base64(auth_key_b64);
            }
            // No matching history row for RefreshKeys — this is the first
            // rotation (or the history hasn't been applied yet). Fall through
            // to use the current key in _users, which still holds the old key
            // at the time of broadcast.
        }

        // Step 4: Find old key whose validity range covers change_id.
        for row in &history {
            let valid_from = row
                .get("valid_from_change_id")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;
            let valid_to = row
                .get("valid_to_change_id")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;
            if valid_from <= change_id && change_id <= valid_to {
                let auth_key_b64 = row
                    .get("old_auth_key")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        SdkError::ValidationError(
                            "missing old_auth_key in _key_history".to_string(),
                        )
                    })?;
                return deserialize_verification_key_from_base64(auth_key_b64);
            }
        }

        // Step 5: No old key covers this change_id — use the current key.
        if let Some(vk) = current_key {
            return Ok(vk);
        }

        // Step 6: User not found anywhere (deleted with no history match).
        Err(SdkError::NotFound)
    }
}

/// Decode a verification key from the base64(json) format used by `_key_history.old_auth_key`
/// and `_users.auth_key`.
pub(crate) fn deserialize_verification_key_from_base64(
    b64: &str,
) -> Result<VerifyingKey, SdkError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| SdkError::SerializationError(format!("base64 decode failed: {e}")))?;
    let json_string = String::from_utf8(bytes)
        .map_err(|e| SdkError::SerializationError(format!("UTF-8 decode failed: {e}")))?;
    serde_json::from_str(&json_string)
        .map_err(|e| SdkError::SerializationError(format!("VerifyingKey parse failed: {e}")))
}

// Custom serialization helpers to ensure keys are serialized as base64 strings
// instead of as JSON arrays (which get converted to string representations)
pub(crate) fn serialize_as_base64<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: Serialize,
    S: Serializer,
{
    // First serialize to JSON to get the underlying representation
    let json_value = serde_json::to_value(value).map_err(serde::ser::Error::custom)?;
    // Then convert to base64 string
    let json_string = serde_json::to_string(&json_value).map_err(serde::ser::Error::custom)?;
    let base64_string = base64::engine::general_purpose::STANDARD.encode(json_string.as_bytes());
    serializer.serialize_str(&base64_string)
}

pub(crate) fn deserialize_from_base64<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: serde::de::DeserializeOwned,
    D: Deserializer<'de>,
{
    use serde::de::Error;
    let base64_string = String::deserialize(deserializer)?;
    // Decode from base64
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&base64_string)
        .map_err(|e| {
            D::Error::custom(format!(
                "base64 decode failed for field (input={:?}): {e}",
                if base64_string.len() > 40 {
                    format!("{}...", &base64_string[..40])
                } else {
                    base64_string.clone()
                }
            ))
        })?;
    let json_string = String::from_utf8(bytes).map_err(|e| {
        D::Error::custom(format!(
            "UTF-8 decode failed for base64 field (input={:?}): {e}",
            if base64_string.len() > 40 {
                format!("{}...", &base64_string[..40])
            } else {
                base64_string.clone()
            }
        ))
    })?;
    // Deserialize from JSON
    let json_value: serde_json::Value = serde_json::from_str(&json_string).map_err(|e| {
        D::Error::custom(format!(
            "JSON parse failed for base64 field (decoded={:?}): {e}",
            if json_string.len() > 80 {
                format!("{}...", &json_string[..80])
            } else {
                json_string.clone()
            }
        ))
    })?;
    serde_json::from_value(json_value)
        .map_err(|e| D::Error::custom(format!("deserialization failed for base64 field: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------
    // UserStatus serde
    // ---------------------------------------------------------------------

    #[test]
    fn user_status_serializes_to_expected_integers() {
        assert_eq!(serde_json::to_value(UserStatus::Provisional).unwrap(), 0);
        assert_eq!(serde_json::to_value(UserStatus::Full).unwrap(), 1);
    }

    #[test]
    fn user_status_deserializes_known_values() {
        let prov: UserStatus = serde_json::from_value(serde_json::json!(0)).unwrap();
        assert_eq!(prov, UserStatus::Provisional);
        let full: UserStatus = serde_json::from_value(serde_json::json!(1)).unwrap();
        assert_eq!(full, UserStatus::Full);
    }

    #[test]
    fn user_status_rejects_unknown_integer() {
        let err = serde_json::from_value::<UserStatus>(serde_json::json!(2)).unwrap_err();
        assert!(
            err.to_string().contains("unknown UserStatus value"),
            "unexpected error: {err}"
        );
    }

    // ---------------------------------------------------------------------
    // UserWithSecrets serde
    // ---------------------------------------------------------------------

    fn assert_kem_seed_eq(a: &UserWithSecrets, b: &UserWithSecrets) {
        assert_eq!(
            a.update_key_pair.secret().as_seed(),
            b.update_key_pair.secret().as_seed(),
            "kem seed mismatch"
        );
    }

    fn assert_auth_bytes_eq(a: &UserWithSecrets, b: &UserWithSecrets) {
        assert_eq!(
            a.auth_key_pair.0.to_bytes(),
            b.auth_key_pair.0.to_bytes(),
            "auth signing key bytes mismatch"
        );
    }

    #[test]
    fn user_with_secrets_serde_roundtrip_preserves_secrets_and_status() {
        let mut original = UserWithSecrets::new();
        original.id = Some(42);
        original.status = UserStatus::Provisional;

        let json = serde_json::to_string(&original).unwrap();
        let restored: UserWithSecrets = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.id, original.id);
        assert_eq!(restored.status, original.status);
        assert_kem_seed_eq(&original, &restored);
        assert_auth_bytes_eq(&original, &restored);
    }

    #[test]
    fn user_with_secrets_serde_roundtrip_for_full_status() {
        let mut original = UserWithSecrets::new();
        original.id = Some(7);
        original.status = UserStatus::Full;

        let json = serde_json::to_string(&original).unwrap();
        let restored: UserWithSecrets = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.status, UserStatus::Full);
        assert_kem_seed_eq(&original, &restored);
    }

    #[test]
    fn user_with_secrets_serde_roundtrip_with_id_none() {
        let original = UserWithSecrets::new(); // id defaults to None
        assert!(original.id.is_none());

        let json = serde_json::to_string(&original).unwrap();
        let restored: UserWithSecrets = serde_json::from_str(&json).unwrap();

        assert!(restored.id.is_none());
        assert_kem_seed_eq(&original, &restored);
        assert_auth_bytes_eq(&original, &restored);
    }

    #[test]
    fn user_with_secrets_deserialize_rejects_short_seed() {
        // 16-byte seed instead of 32; valid base64 of 16 bytes.
        let short_seed_b64 = BASE64.encode([0u8; 16]);
        let auth_b64 = BASE64.encode([1u8; 32]);
        let bad = serde_json::json!({
            "id": null,
            "update_secret_seed": short_seed_b64,
            "auth_secret": auth_b64,
            "status": 1,
        });
        let err = serde_json::from_value::<UserWithSecrets>(bad)
            .err()
            .expect("expected deserialization to fail");
        assert!(
            err.to_string().contains("invalid seed length"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn user_with_secrets_deserialize_rejects_invalid_base64_seed() {
        let auth_b64 = BASE64.encode([1u8; 32]);
        let bad = serde_json::json!({
            "id": null,
            "update_secret_seed": "!!!not-base64!!!",
            "auth_secret": auth_b64,
            "status": 1,
        });
        let err = serde_json::from_value::<UserWithSecrets>(bad)
            .err()
            .expect("expected deserialization to fail");
        // base64 decode failure is surfaced through serde::de::Error::custom.
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn user_with_secrets_deserialize_rejects_short_auth_secret() {
        let seed_b64 = BASE64.encode([0u8; 32]);
        let short_auth_b64 = BASE64.encode([1u8; 16]); // 16 bytes, want 32
        let bad = serde_json::json!({
            "id": null,
            "update_secret_seed": seed_b64,
            "auth_secret": short_auth_b64,
            "status": 1,
        });
        let err = serde_json::from_value::<UserWithSecrets>(bad)
            .err()
            .expect("expected deserialization to fail");
        assert!(
            err.to_string().contains("invalid auth signing key length"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn user_with_secrets_deserialize_rejects_unknown_status() {
        let seed_b64 = BASE64.encode([0u8; 32]);
        let auth_b64 = BASE64.encode([1u8; 32]);
        let bad = serde_json::json!({
            "id": null,
            "update_secret_seed": seed_b64,
            "auth_secret": auth_b64,
            "status": 99,
        });
        let err = serde_json::from_value::<UserWithSecrets>(bad)
            .err()
            .expect("expected deserialization to fail");
        assert!(
            err.to_string().contains("unknown UserStatus value"),
            "unexpected error: {err}"
        );
    }

    // ---------------------------------------------------------------------
    // SpaceInvite accessors
    // ---------------------------------------------------------------------

    #[test]
    fn space_invite_accessors_return_construction_inputs() {
        let mut user = UserWithSecrets::provisional();
        user.id = Some(123);
        let space_id = SpaceId::random();

        let invite = SpaceInvite { user, space_id };

        assert_eq!(invite.id(), Some(123));
        assert_eq!(invite.status(), UserStatus::Provisional);
        assert_eq!(invite.space_id(), space_id);
    }

    #[test]
    fn space_invite_id_is_none_when_user_id_unset() {
        let user = UserWithSecrets::provisional(); // id defaults to None
        let invite = SpaceInvite {
            user,
            space_id: SpaceId::random(),
        };
        assert!(invite.id().is_none());
    }

    // ---------------------------------------------------------------------
    // base64 helpers (serialize_as_base64 / deserialize_from_base64)
    // ---------------------------------------------------------------------

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Wrapper {
        #[serde(
            serialize_with = "serialize_as_base64",
            deserialize_with = "deserialize_from_base64"
        )]
        payload: Vec<u8>,
    }

    #[test]
    fn base64_helpers_roundtrip_simple_payload() {
        let original = Wrapper {
            payload: b"hello".to_vec(),
        };
        let json = serde_json::to_string(&original).unwrap();
        let restored: Wrapper = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, original);
    }

    #[test]
    fn base64_helpers_field_value_is_a_base64_string() {
        let original = Wrapper {
            payload: vec![0xAA, 0xBB, 0xCC],
        };
        let json: serde_json::Value = serde_json::to_value(&original).unwrap();
        let s = json
            .get("payload")
            .and_then(|v| v.as_str())
            .expect("payload should serialize as a string");
        // Confirm it decodes as base64 (it wraps a json-encoded body, but
        // the surface contract is "is decodable base64").
        assert!(BASE64.decode(s).is_ok());
    }

    #[test]
    fn deserialize_from_base64_rejects_invalid_base64() {
        let bad = serde_json::json!({ "payload": "***not-base64***" });
        let err = serde_json::from_value::<Wrapper>(bad).unwrap_err();
        assert!(
            err.to_string().contains("base64 decode failed"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn deserialize_from_base64_rejects_invalid_utf8() {
        let bad_utf8 = BASE64.encode([0xFFu8, 0xFE, 0xFD]);
        let bad = serde_json::json!({ "payload": bad_utf8 });
        let err = serde_json::from_value::<Wrapper>(bad).unwrap_err();
        assert!(
            err.to_string().contains("UTF-8 decode failed"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn deserialize_from_base64_rejects_invalid_json() {
        let bad_json = BASE64.encode(b"not valid json");
        let bad = serde_json::json!({ "payload": bad_json });
        let err = serde_json::from_value::<Wrapper>(bad).unwrap_err();
        assert!(
            err.to_string().contains("JSON parse failed"),
            "unexpected error: {err}"
        );
    }

    // ---------------------------------------------------------------------
    // deserialize_verification_key_from_base64
    // ---------------------------------------------------------------------

    #[test]
    fn verification_key_from_base64_roundtrips() {
        let user = UserWithSecrets::new();
        let vk = *user.auth_key_pair.verification_key();

        let vk_json = serde_json::to_vec(&vk).unwrap();
        let b64 = BASE64.encode(vk_json);

        let restored = deserialize_verification_key_from_base64(&b64).unwrap();
        assert_eq!(restored, vk);
    }

    #[test]
    fn verification_key_from_base64_rejects_invalid_base64() {
        let err = deserialize_verification_key_from_base64("!!!not-base64!!!").unwrap_err();
        assert!(
            matches!(err, SdkError::SerializationError(ref m) if m.contains("base64 decode failed")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn verification_key_from_base64_rejects_invalid_utf8() {
        let bad = BASE64.encode([0xFFu8, 0xFE, 0xFD]);
        let err = deserialize_verification_key_from_base64(&bad).unwrap_err();
        assert!(
            matches!(err, SdkError::SerializationError(ref m) if m.contains("UTF-8 decode failed")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn verification_key_from_base64_rejects_invalid_json() {
        let bad = BASE64.encode(b"not valid json");
        let err = deserialize_verification_key_from_base64(&bad).unwrap_err();
        assert!(
            matches!(err, SdkError::SerializationError(ref m) if m.contains("VerifyingKey parse failed")),
            "unexpected error: {err:?}"
        );
    }
}
