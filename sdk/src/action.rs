//! Client-side action invocation.
//!
//! Three entry points map to the three primary-leg shapes the verifier
//! supports: [`Space::call_insert_action`],
//! [`Space::call_update_action`], [`Space::call_delete_action`].  Each
//! routes through the standard insert/update/delete pipeline
//! (encryption, large-value hashing, signing) and prepends an
//! **action-marker kv** at position 0 of the entry's kvs so the
//! verifier can identify which action was invoked.
//!
//! For delete actions with trailing `cascade_delete` legs, the SDK
//! sends only the primary row's column kvs; the verifier reads the
//! FK secondary index per cascade leg and derives the child rows
//! itself.

use crate::changelog::ChangeBuilder;
use crate::table::InsertBuilder;
use crate::Space;
use encrypted_spaces_acl_types::{Action, ActionLeg};
use encrypted_spaces_backend::error::{Result, SdkError};
use encrypted_spaces_backend::query::{
    ComparisonOperator, Predicate, Query, QueryOperation, QueryParam,
};
use encrypted_spaces_backend::sign_change::sign_change;
use encrypted_spaces_changelog_core::changelog::{Change, OpType, ROOT_TREE_PATH};
use encrypted_spaces_storage_encoding::action_marker_key;
use encrypted_spaces_storage_encoding::keys::column_key;
use std::sync::Arc;

impl Space {
    /// Register an action in the SDK's local cache.  Actions are
    /// normally populated from the imported schema bundle during space
    /// init; this method covers test setups that bootstrap from an
    /// explicit-schemas `ApplicationSchema::WithDataCommitment` and
    /// need to add actions after the fact.
    pub fn register_action(&self, action: Action) {
        self.with_state_mut(|state| {
            state.actions.insert(action.name.clone(), action);
        });
    }

    /// Look up a registered action, validate its primary-leg shape
    /// against the expected variant for this call site, and return the
    /// action + its primary table.
    fn load_action_with_leg(
        &self,
        action_name: &str,
        expected_primary: fn(&ActionLeg) -> bool,
        expected_label: &str,
        allow_cascade_tail: bool,
    ) -> Result<(Action, String)> {
        let action = self
            .with_state(|state| state.actions.get(action_name).cloned())
            .ok_or_else(|| {
                SdkError::ValidationError(format!(
                    "action '{action_name}' is not registered in this space"
                ))
            })?;
        if action.legs.is_empty() {
            return Err(SdkError::ValidationError(format!(
                "action '{action_name}' has no legs"
            )));
        }
        if !expected_primary(&action.legs[0]) {
            return Err(SdkError::ValidationError(format!(
                "action '{action_name}' primary leg is not an {expected_label} leg"
            )));
        }
        for (i, leg) in action.legs.iter().enumerate().skip(1) {
            let ok = matches!(leg, ActionLeg::CascadeDelete { .. }) && allow_cascade_tail;
            if !ok {
                return Err(SdkError::ValidationError(format!(
                    "action '{action_name}' leg {i} ({leg:?}) is not callable through the \
                     {expected_label} entry point"
                )));
            }
        }
        let table = action.legs[0].table().to_string();
        Ok((action, table))
    }

    /// Invoke an insert-leg action with the row's column values.
    pub async fn call_insert_action(
        &self,
        action_name: &str,
        fields: Vec<(String, QueryParam)>,
    ) -> Result<i64> {
        let (_, table) = self.load_action_with_leg(
            action_name,
            |l| matches!(l, ActionLeg::Insert { .. }),
            "insert",
            false,
        )?;

        let space = Arc::new(self.clone());
        let mut insert_builder =
            InsertBuilder::<()>::from_fields(table.clone(), space.clone(), fields);
        crate::crypto::encrypt_query_fields(&mut insert_builder.query, self).await?;

        let change = ChangeBuilder::new(&mut insert_builder.query, space.clone())
            .with_op_type(OpType::Action)
            .with_prepended_kv(action_marker_key(&table), action_name.as_bytes().to_vec())
            .build()
            .await?
            .ok_or_else(|| {
                SdkError::DatabaseError(format!(
                    "action '{action_name}': insert leg built no change"
                ))
            })?;

        let response = self.transport.submit_change(&change, vec![]).await?;
        // Issue #212: prove the exact action entry was incorporated before
        // reporting a row id. Submit directly (no stale-parent re-sign) so the
        // baked action-marker kv stays valid; discharge via fast-forward on an
        // accepted-but-not-sequential response.
        let completed = self.complete_submitted(change, response).await?;
        if let Some(writes) = &completed.sequential_writes {
            crate::cache::update_cache_from_proven_writes(self, &completed.change, writes).await;
            return crate::cache::new_row_id_for_table(self, writes, &table).ok_or_else(|| {
                SdkError::InsertError(format!(
                    "action '{action_name}' produced no new row id on table '{table}'"
                ))
            });
        }
        if let Some(row_id) = completed
            .ff_inserted_ids
            .get(&completed.change.entry.signature)
            .copied()
        {
            return Ok(row_id);
        }
        // Proof-covered fast-forward: re-verify the acknowledged response in
        // isolation only to extract the row id (discharge already proven on the
        // verified CLC chain). Same unanchored-row-id limitation as
        // `InsertBuilder::execute_as` — not a false success; the entry is proven.
        // Tracked in https://github.com/encrypted-spaces/prototype/issues/232.
        let writes =
            self.validate_and_apply_change(&completed.change.entry, &completed.response)?;
        crate::cache::update_cache_from_proven_writes(self, &completed.change, &writes).await;
        crate::cache::new_row_id_for_table(self, &writes, &table).ok_or_else(|| {
            SdkError::InsertError(format!(
                "action '{action_name}' produced no new row id on table '{table}'"
            ))
        })
    }

    /// Invoke an update-leg action targeting `row_id` with the given
    /// column updates.
    pub async fn call_update_action(
        &self,
        action_name: &str,
        row_id: i64,
        set_fields: Vec<(String, QueryParam)>,
    ) -> Result<usize> {
        let (_, table) = self.load_action_with_leg(
            action_name,
            |l| matches!(l, ActionLeg::Update { .. }),
            "update",
            false,
        )?;

        let mut query = Query::new(table.clone(), QueryOperation::Update(set_fields));
        query.predicate = Some(Predicate {
            column: "id".to_string(),
            operator: ComparisonOperator::Equal,
            values: vec![QueryParam::Integer(row_id)],
            cursor_id: None,
        });

        let space = Arc::new(self.clone());
        crate::crypto::encrypt_query_fields(&mut query, self).await?;

        let change_opt = ChangeBuilder::new(&mut query, space.clone())
            .with_op_type(OpType::Action)
            .with_prepended_kv(action_marker_key(&table), action_name.as_bytes().to_vec())
            .build()
            .await?;
        let Some(change) = change_opt else {
            return Ok(0);
        };

        let response = self.transport.submit_change(&change, vec![]).await?;
        let completed = self.complete_submitted(change, response).await?;
        if let Some(writes) = &completed.sequential_writes {
            crate::cache::update_cache_from_proven_writes(self, &completed.change, writes).await;
        }
        Ok(completed.response.rows_affected as usize)
    }

    /// Invoke a delete-leg action targeting `row_id`.
    ///
    /// The signed entry carries only the primary row's column kvs plus
    /// the action-marker.  Trailing `cascade_delete` legs are derived
    /// at verification time: the verifier reads the FK secondary
    /// index for each cascade leg and constructs the child-row deletes
    /// itself.
    pub async fn call_delete_action(&self, action_name: &str, row_id: i64) -> Result<usize> {
        let (_action, _table) = self.load_action_with_leg(
            action_name,
            |l| matches!(l, ActionLeg::Delete { .. }),
            "delete",
            true,
        )?;

        let primary_table = _action.legs[0].table().to_string();

        // Build the signed entry's kvs: only the primary leg's row.
        // Cascade legs are derived at verification time by reading the
        // FK secondary indexes against this row.
        let schema = self.get_table_schema(&primary_table).ok_or_else(|| {
            SdkError::InvalidQuery(format!("table '{primary_table}' is not registered locally"))
        })?;
        let mut keys: Vec<Vec<u8>> = schema
            .columns
            .iter()
            .filter(|c| c.name != "id")
            .map(|c| column_key(&primary_table, row_id, &c.name))
            .collect();
        keys.sort();
        let values = vec![vec![]; keys.len()];

        // Prepend the action-marker kv.
        let mut all_keys = vec![action_marker_key(&primary_table)];
        let mut all_values = vec![action_name.as_bytes().to_vec()];
        all_keys.extend(keys);
        all_values.extend(values);

        let (uid, current_change_id, my_last_change_id, current_clc) = {
            // Issue #212 (#4): capture the signing anchor under the mutation
            // guard so it is verified, committed state — never a provisional
            // fast-forward position.
            let _guard = self.serialize_mutations.lock().await;
            self.with_state(|state| {
                let uid = state.auth_context.uid.ok_or_else(|| {
                    SdkError::DatabaseError("User is not authenticated".to_string())
                })?;
                let clc_root: [u8; 32] = state.current_clc_state.root.into();
                Ok::<_, SdkError>((
                    uid as u32,
                    state.current_change_id,
                    state.my_last_change_id,
                    clc_root,
                ))
            })?
        };
        let key_refs: Vec<&[u8]> = all_keys.iter().map(|k| k.as_slice()).collect();
        let value_refs: Vec<&[u8]> = all_values.iter().map(|v| v.as_slice()).collect();
        let mut change = Change::new(
            OpType::Action,
            uid,
            ROOT_TREE_PATH,
            &key_refs,
            &value_refs,
            current_change_id,
            my_last_change_id,
            current_clc,
        )
        .map_err(|e| {
            SdkError::DatabaseError(format!(
                "action '{action_name}': failed to build delete change: {e}"
            ))
        })?;
        {
            let km = self.key_manager.lock().await;
            sign_change(&mut change.entry, km.auth_key_pair());
        }

        let response = self.transport.submit_change(&change, vec![]).await?;
        let completed = self.complete_submitted(change, response).await?;
        if let Some(writes) = &completed.sequential_writes {
            crate::cache::update_cache_from_proven_writes(self, &completed.change, writes).await;
        }
        Ok(completed.response.rows_affected as usize)
    }
}
