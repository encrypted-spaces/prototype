use crate::{error::SdkError, query, schema, SpaceId};
use encrypted_spaces_changelog_core::changelog;
use encrypted_spaces_storage_encoding::hashstore_hash;

include!(concat!(env!("OUT_DIR"), "/database.rs"));

impl From<&query::QueryParam> for QueryParam {
    fn from(param: &query::QueryParam) -> Self {
        match param {
            query::QueryParam::Null => QueryParam { value: None },
            query::QueryParam::Integer(val) => QueryParam {
                value: Some(query_param::Value::IntValue(*val)),
            },
            query::QueryParam::Text(val) => QueryParam {
                value: Some(query_param::Value::TextValue(val.clone())),
            },
            query::QueryParam::Real(val) => QueryParam {
                value: Some(query_param::Value::RealValue(*val)),
            },
            query::QueryParam::Blob(val) => QueryParam {
                value: Some(query_param::Value::BlobValue(val.clone())),
            },
            query::QueryParam::Boolean(val) => QueryParam {
                value: Some(query_param::Value::BoolValue(*val)),
            },
        }
    }
}

impl From<QueryParam> for query::QueryParam {
    fn from(param: QueryParam) -> Self {
        match param.value {
            Some(query_param::Value::IntValue(val)) => query::QueryParam::Integer(val),
            Some(query_param::Value::TextValue(val)) => query::QueryParam::Text(val),
            Some(query_param::Value::RealValue(val)) => query::QueryParam::Real(val),
            Some(query_param::Value::BlobValue(val)) => query::QueryParam::Blob(val),
            Some(query_param::Value::BoolValue(val)) => query::QueryParam::Boolean(val),
            None => query::QueryParam::Null,
        }
    }
}

impl From<&schema::Schema> for Schema {
    fn from(schema: &schema::Schema) -> Self {
        Schema {
            name: schema.name.clone(),
            columns: schema.columns.iter().map(|c| c.into()).collect(),
            auto_increment: schema.auto_increment,
        }
    }
}

impl From<Schema> for schema::Schema {
    fn from(schema: Schema) -> Self {
        schema::Schema {
            name: schema.name,
            columns: schema.columns.into_iter().map(|c| c.into()).collect(),
            auto_increment: schema.auto_increment,
        }
    }
}

impl From<&schema::ColumnDefinition> for ColumnDefinition {
    fn from(col: &schema::ColumnDefinition) -> Self {
        ColumnDefinition {
            name: col.name.clone(),
            column_type: match col.column_type {
                schema::ColumnType::Integer => ColumnType::Integer as i32,
                schema::ColumnType::String => ColumnType::String as i32,
                schema::ColumnType::Real => ColumnType::Real as i32,
                schema::ColumnType::FileRef => ColumnType::FileRef as i32,
                schema::ColumnType::List => ColumnType::List as i32,
                schema::ColumnType::Text => ColumnType::Text as i32,
                schema::ColumnType::Blob => ColumnType::Blob as i32,
            },
            plaintext: col.plaintext,
            indexed: col.indexed,
        }
    }
}

impl From<ColumnDefinition> for schema::ColumnDefinition {
    fn from(col: ColumnDefinition) -> Self {
        schema::ColumnDefinition {
            name: col.name,
            column_type: match col.column_type {
                0 => schema::ColumnType::Integer, // INTEGER
                1 => schema::ColumnType::Real,    // REAL
                2 => schema::ColumnType::String,  // STRING
                3 => schema::ColumnType::Text,    // TEXT
                4 => schema::ColumnType::Blob,    // BLOB
                5 => schema::ColumnType::FileRef, // FILE_REF
                6 => schema::ColumnType::List,    // LIST
                _ => schema::ColumnType::String,  // default
            },
            plaintext: col.plaintext,
            indexed: col.indexed,
        }
    }
}

// Query conversions
impl From<&crate::query::Query> for Query {
    fn from(q: &crate::query::Query) -> Self {
        Query {
            table: q.table.clone(),
            operation: Some((&q.operation).into()),
            predicate: q.predicate.as_ref().map(|p| p.into()),
            join: q.join.as_ref().map(|j| j.into()),
            order: (&q.order).into(),
            limit: q.limit,
        }
    }
}

impl From<Query> for crate::query::Query {
    fn from(q: Query) -> Self {
        crate::query::Query {
            table: q.table,
            operation: q
                .operation
                .map(Into::into)
                .unwrap_or(crate::query::QueryOperation::Select(vec![])),
            predicate: q.predicate.map(Into::into),
            join: q.join.map(Into::into),
            order: q.order.into(),
            limit: q.limit,
        }
    }
}

impl From<&crate::query::QueryOperation> for QueryOperation {
    fn from(op: &crate::query::QueryOperation) -> Self {
        use crate::query::QueryOperation as QO;
        match op {
            QO::Select(cols) => QueryOperation {
                operation: Some(query_operation::Operation::Select(SelectOperation {
                    columns: cols.clone(),
                })),
            },
            QO::Insert(fields) => QueryOperation {
                operation: Some(query_operation::Operation::Insert(InsertOperation {
                    fields: fields
                        .iter()
                        .map(|(name, val)| FieldValue {
                            name: name.clone(),
                            value: Some(val.into()),
                        })
                        .collect(),
                })),
            },
            QO::Update(fields) => QueryOperation {
                operation: Some(query_operation::Operation::Update(UpdateOperation {
                    fields: fields
                        .iter()
                        .map(|(name, val)| UpdateField {
                            name: name.clone(),
                            value: Some(val.into()),
                        })
                        .collect(),
                })),
            },
            QO::Delete => QueryOperation {
                operation: Some(query_operation::Operation::Delete(DeleteOperation {})),
            },
        }
    }
}

impl From<QueryOperation> for crate::query::QueryOperation {
    fn from(op: QueryOperation) -> Self {
        use query_operation::Operation;
        match op.operation {
            Some(Operation::Select(s)) => crate::query::QueryOperation::Select(s.columns),
            Some(Operation::Insert(i)) => crate::query::QueryOperation::Insert(
                i.fields
                    .into_iter()
                    .map(|f| {
                        (
                            f.name,
                            f.value.map(Into::into).unwrap_or(query::QueryParam::Null),
                        )
                    })
                    .collect(),
            ),
            Some(Operation::Update(u)) => crate::query::QueryOperation::Update(
                u.fields
                    .into_iter()
                    .map(|f| {
                        (
                            f.name,
                            f.value.map(Into::into).unwrap_or(query::QueryParam::Null),
                        )
                    })
                    .collect(),
            ),
            Some(Operation::Delete(_)) => crate::query::QueryOperation::Delete,
            None => crate::query::QueryOperation::Select(vec![]),
        }
    }
}

impl From<&crate::query::Predicate> for Predicate {
    fn from(p: &crate::query::Predicate) -> Self {
        Predicate {
            column: p.column.clone(),
            operator: (&p.operator).into(),
            values: p.values.iter().map(|v| v.into()).collect(),
            cursor_id: p.cursor_id,
        }
    }
}

impl From<Predicate> for crate::query::Predicate {
    fn from(p: Predicate) -> Self {
        crate::query::Predicate {
            column: p.column,
            operator: p.operator.into(),
            values: p.values.into_iter().map(Into::into).collect(),
            cursor_id: p.cursor_id,
        }
    }
}

impl From<&crate::query::ComparisonOperator> for i32 {
    fn from(op: &crate::query::ComparisonOperator) -> Self {
        use crate::query::ComparisonOperator as CO;
        match op {
            CO::Equal => ComparisonOperator::Equal as i32,
            CO::GreaterThan => ComparisonOperator::GreaterThan as i32,
            CO::GreaterThanOrEqual => ComparisonOperator::GreaterThanOrEqual as i32,
            CO::LessThan => ComparisonOperator::LessThan as i32,
            CO::LessThanOrEqual => ComparisonOperator::LessThanOrEqual as i32,
            CO::In => ComparisonOperator::In as i32,
            CO::Between => ComparisonOperator::Between as i32,
        }
    }
}

impl From<i32> for crate::query::ComparisonOperator {
    fn from(op: i32) -> Self {
        match ComparisonOperator::try_from(op).unwrap_or(ComparisonOperator::Equal) {
            ComparisonOperator::Equal => crate::query::ComparisonOperator::Equal,
            ComparisonOperator::GreaterThan => crate::query::ComparisonOperator::GreaterThan,
            ComparisonOperator::GreaterThanOrEqual => {
                crate::query::ComparisonOperator::GreaterThanOrEqual
            }
            ComparisonOperator::LessThan => crate::query::ComparisonOperator::LessThan,
            ComparisonOperator::LessThanOrEqual => {
                crate::query::ComparisonOperator::LessThanOrEqual
            }
            ComparisonOperator::In => crate::query::ComparisonOperator::In,
            ComparisonOperator::Between => crate::query::ComparisonOperator::Between,
        }
    }
}

impl From<&crate::query::JoinClause> for JoinClause {
    fn from(j: &crate::query::JoinClause) -> Self {
        JoinClause {
            table: j.table.clone(),
            left_column: j.on_condition.0.clone(),
            right_column: j.on_condition.1.clone(),
        }
    }
}

impl From<JoinClause> for crate::query::JoinClause {
    fn from(j: JoinClause) -> Self {
        crate::query::JoinClause {
            table: j.table,
            on_condition: (j.left_column, j.right_column),
        }
    }
}

impl From<&crate::query::Order> for i32 {
    fn from(d: &crate::query::Order) -> Self {
        match d {
            crate::query::Order::Asc => Order::Asc as i32,
            crate::query::Order::Desc => Order::Desc as i32,
        }
    }
}

impl From<i32> for crate::query::Order {
    fn from(d: i32) -> Self {
        match Order::try_from(d).unwrap_or(Order::Asc) {
            Order::Asc => crate::query::Order::Asc,
            Order::Desc => crate::query::Order::Desc,
        }
    }
}

// AuthContext conversions
impl From<&crate::access_control::AuthContext> for AuthContext {
    fn from(auth: &crate::access_control::AuthContext) -> Self {
        AuthContext {
            uid: auth.uid,
            space_id: auth.space_id.as_bytes().to_vec(),
        }
    }
}

impl From<AuthContext> for crate::access_control::AuthContext {
    fn from(auth: AuthContext) -> Self {
        crate::access_control::AuthContext::new(
            auth.uid,
            auth.space_id.try_into().unwrap_or_else(|e| {
                log::warn!("AuthContext.space_id invalid value {}; defaulting", e);
                SpaceId::from([0u8; 16])
            }),
        )
    }
}

// ChangelogEntry conversions
impl From<ChangelogEntry> for changelog::ChangelogEntry {
    fn from(entry: ChangelogEntry) -> Self {
        let message = entry.message.unwrap_or_else(|| LogMessage {
            op_type: 0,
            tree_path: vec![],
            entries: vec![KvData {
                key: vec![],
                value: vec![],
            }],
        });

        changelog::ChangelogEntry {
            timestamp: entry.timestamp,
            uid: entry.uid,
            parent_change: entry.parent_change,
            message: message.into(),
            sig_ref: entry.sig_ref,
            parent_clc: entry.parent_clc.try_into().unwrap_or_else(|v: Vec<u8>| {
                log::warn!(
                    "parent_clc has invalid length {}, expected 32; defaulting to zeros",
                    v.len()
                );
                [0u8; 32]
            }),
            signature: entry.signature,
        }
    }
}

impl From<&changelog::ChangelogEntry> for ChangelogEntry {
    fn from(entry: &changelog::ChangelogEntry) -> Self {
        ChangelogEntry {
            timestamp: entry.timestamp,
            uid: entry.uid,
            parent_change: entry.parent_change,
            message: Some((&entry.message).into()),
            sig_ref: entry.sig_ref,
            parent_clc: entry.parent_clc.to_vec(),
            signature: entry.signature.clone(),
        }
    }
}

// LogMessage conversions
impl From<LogMessage> for changelog::LogMessage {
    fn from(msg: LogMessage) -> Self {
        use changelog::OpType;

        let op_type = changelog::OpType::from_u8(msg.op_type as u8).unwrap_or_else(|| {
            log::warn!(
                "LogMessage.op_type invalid value {}; defaulting to Insert",
                msg.op_type
            );
            OpType::Insert
        });

        let entries: Vec<changelog::KvData> = msg
            .entries
            .into_iter()
            .map(|e| changelog::KvData {
                key: e.key,
                value: e.value,
            })
            .collect();

        if entries.is_empty() {
            log::warn!("LogMessage has no entries; inserting sentinel entry");
        }
        let entries = if entries.is_empty() {
            vec![changelog::KvData {
                key: vec![],
                value: vec![],
            }]
        } else {
            entries
        };

        changelog::LogMessage {
            op_type,
            tree_path: msg.tree_path,
            entries,
        }
    }
}

impl From<&changelog::LogMessage> for LogMessage {
    fn from(msg: &changelog::LogMessage) -> Self {
        if msg.entries.is_empty() {
            log::warn!("Core LogMessage has no entries during proto conversion");
        }
        LogMessage {
            op_type: msg.op_type.as_u8() as u32,
            tree_path: msg.tree_path.clone(),
            entries: msg
                .entries
                .iter()
                .map(|e| KvData {
                    key: e.key.clone(),
                    value: e.value.clone(),
                })
                .collect(),
        }
    }
}

// ChangeResponse conversions
impl From<&changelog::ChangeResponse> for ChangeResponse {
    fn from(response: &changelog::ChangeResponse) -> Self {
        ChangeResponse {
            change_id: response.change_id,
            old_root: response.old_root.to_vec(),
            new_root: response.new_root.to_vec(),
            pruned_merkle_tree: response.pruned_merkle_tree.clone(),
            rows_affected: response.rows_affected,
            values_sidecar: values_sidecar_to_proto(&response.hashed_values),
            accepted_at_server_time: response.accepted_at_server_time,
        }
    }
}

fn decode_root(field: &str, bytes: Vec<u8>) -> Result<[u8; 32], SdkError> {
    bytes.try_into().map_err(|v: Vec<u8>| {
        SdkError::SerializationError(format!("{field} must be 32 bytes, got {}", v.len()))
    })
}

impl TryFrom<ChangeResponse> for changelog::ChangeResponse {
    type Error = SdkError;

    fn try_from(response: ChangeResponse) -> Result<Self, Self::Error> {
        let old_root = decode_root("ChangeResponse.old_root", response.old_root)?;
        let new_root = decode_root("ChangeResponse.new_root", response.new_root)?;

        Ok(changelog::ChangeResponse {
            change_id: response.change_id,
            old_root,
            new_root,
            pruned_merkle_tree: response.pruned_merkle_tree,
            rows_affected: response.rows_affected,
            accepted_at_server_time: response.accepted_at_server_time,
            hashed_values: values_sidecar_from_proto(response.values_sidecar),
        })
    }
}

/// Serialize a `HashedValues` map for the wire by emitting just the values.
/// The receiver re-hashes each one and rebuilds the map, so a peer can't ship
/// `(signed_hash, garbage_value)` pairs and have the garbage land under the
/// signed key.
pub fn values_sidecar_to_proto(map: &changelog::HashedValues) -> Vec<Vec<u8>> {
    map.values().cloned().collect()
}

/// Build a `HashedValues` map from the wire by re-hashing each value with
/// `hashstore_hash` — the same function the storage layer keys hash-backed
/// columns by — so the keys are server-recomputed, never sender-supplied.
pub fn values_sidecar_from_proto(items: Vec<Vec<u8>>) -> changelog::HashedValues {
    items
        .into_iter()
        .map(|value| (hashstore_hash(&value), value))
        .collect()
}

// FastForwardResponse conversions
impl From<&changelog::FastForwardData> for FastForwardResponse {
    fn from(data: &changelog::FastForwardData) -> Self {
        let (server_change_id, server_clc_prefix, server_data_commitment_prefix) = data
            .server_head
            .as_ref()
            .map(|head| {
                (
                    head.change_id,
                    head.clc_prefix.to_vec(),
                    head.data_commitment_prefix.to_vec(),
                )
            })
            .unwrap_or_default();
        FastForwardResponse {
            changes: data.changes.iter().map(|c| c.into()).collect(),
            responses: data.responses.iter().map(|r| r.into()).collect(),
            proof: data.proof.as_ref().map(|p| p.into()),
            server_change_id,
            server_clc_prefix,
            server_data_commitment_prefix,
        }
    }
}

impl TryFrom<FastForwardResponse> for changelog::FastForwardData {
    type Error = SdkError;

    fn try_from(response: FastForwardResponse) -> Result<Self, Self::Error> {
        let server_head = if response.server_clc_prefix.len() == 16
            && response.server_data_commitment_prefix.len() == 16
        {
            let mut clc_prefix = [0u8; 16];
            clc_prefix.copy_from_slice(&response.server_clc_prefix);

            let mut data_commitment_prefix = [0u8; 16];
            data_commitment_prefix.copy_from_slice(&response.server_data_commitment_prefix);

            Some(changelog::FastForwardServerHead {
                change_id: response.server_change_id,
                clc_prefix,
                data_commitment_prefix,
            })
        } else {
            None
        };

        Ok(changelog::FastForwardData {
            changes: response.changes.into_iter().map(Into::into).collect(),
            responses: response
                .responses
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
            proof: response.proof.map(TryInto::try_into).transpose()?,
            server_head,
        })
    }
}

impl From<&changelog::FastForwardProof> for FastForwardProof {
    fn from(proof: &changelog::FastForwardProof) -> Self {
        let sigref_entries_bytes = postcard::to_allocvec(&proof.sigref_entries)
            .expect("Failed to serialize sigref_entries");
        let from_inclusion_proof_bytes = postcard::to_allocvec(&proof.from_inclusion_proof)
            .expect("Failed to serialize from_inclusion_proof");
        let end_entry_bytes = proof
            .end_entry
            .as_ref()
            .map(|end_entry| {
                postcard::to_allocvec(end_entry).expect("Failed to serialize end_entry")
            })
            .unwrap_or_default();
        let end_entry_inclusion_proof_bytes = proof
            .end_entry_inclusion_proof
            .as_ref()
            .map(|proof| {
                postcard::to_allocvec(proof).expect("Failed to serialize end_entry_inclusion_proof")
            })
            .unwrap_or_default();
        let expected_inclusion_proofs_bytes =
            postcard::to_allocvec(&proof.expected_inclusion_proofs)
                .expect("Failed to serialize expected_inclusion_proofs");
        FastForwardProof {
            end_change_id: proof.end_change_id,
            proof: proof.proof.clone(),
            sigref_entries: sigref_entries_bytes,
            from_inclusion_proof: from_inclusion_proof_bytes,
            end_entry: end_entry_bytes,
            end_entry_inclusion_proof: end_entry_inclusion_proof_bytes,
            expected_inclusion_proofs: expected_inclusion_proofs_bytes,
        }
    }
}

fn decode_fast_forward_field<T>(bytes: &[u8], field: &str) -> Result<T, SdkError>
where
    T: serde::de::DeserializeOwned,
{
    postcard::from_bytes(bytes).map_err(|e| {
        SdkError::SerializationError(format!("failed to deserialize fast-forward {field}: {e}"))
    })
}

impl TryFrom<FastForwardProof> for changelog::FastForwardProof {
    type Error = SdkError;

    fn try_from(proof: FastForwardProof) -> Result<Self, Self::Error> {
        let sigref_entries = if proof.sigref_entries.is_empty() {
            std::collections::BTreeMap::new()
        } else {
            decode_fast_forward_field(&proof.sigref_entries, "sigref_entries")?
        };
        let from_inclusion_proof = if proof.from_inclusion_proof.is_empty() {
            None
        } else {
            decode_fast_forward_field(&proof.from_inclusion_proof, "from_inclusion_proof")?
        };
        let end_entry = if proof.end_entry.is_empty() {
            None
        } else {
            Some(decode_fast_forward_field(&proof.end_entry, "end_entry")?)
        };
        let end_entry_inclusion_proof = if proof.end_entry_inclusion_proof.is_empty() {
            None
        } else {
            Some(decode_fast_forward_field(
                &proof.end_entry_inclusion_proof,
                "end_entry_inclusion_proof",
            )?)
        };
        if end_entry.is_some() != end_entry_inclusion_proof.is_some() {
            return Err(SdkError::SerializationError(
                "fast-forward end_entry and end_entry_inclusion_proof must both be present or both be omitted"
                    .to_string(),
            ));
        }
        let expected_inclusion_proofs = if proof.expected_inclusion_proofs.is_empty() {
            std::collections::BTreeMap::new()
        } else {
            decode_fast_forward_field(
                &proof.expected_inclusion_proofs,
                "expected_inclusion_proofs",
            )?
        };
        Ok(changelog::FastForwardProof {
            end_change_id: proof.end_change_id,
            proof: proof.proof,
            sigref_entries,
            from_inclusion_proof,
            end_entry,
            end_entry_inclusion_proof,
            expected_inclusion_proofs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use changelog::{
        ChangelogEntry as CoreEntry, KvData as CoreKvData, LogMessage as CoreLogMessage, OpType,
    };
    use encrypted_spaces_changelog_core::mmr_tree::InclusionProof;

    fn sample_changelog_entry() -> CoreEntry {
        CoreEntry {
            timestamp: 1234567890,
            uid: 2,
            parent_change: 4,
            message: CoreLogMessage {
                op_type: OpType::RefreshKeys,
                tree_path: b"/".to_vec(),
                entries: vec![
                    CoreKvData {
                        key: b"_users/auth_key/2".to_vec(),
                        value: vec![0xab; 32],
                    },
                    CoreKvData {
                        key: b"_users/update_key/2".to_vec(),
                        value: vec![1, 2, 3, 4],
                    },
                    CoreKvData {
                        key: b"_key_history/3".to_vec(),
                        value: vec![5, 6, 7, 8],
                    },
                ],
            },
            sig_ref: 3,
            parent_clc: [0xcd; 32],
            signature: vec![9, 10, 11, 12, 13],
        }
    }

    fn sample_fast_forward_proof() -> changelog::FastForwardProof {
        changelog::FastForwardProof {
            end_change_id: 1,
            proof: vec![0x42],
            sigref_entries: std::collections::BTreeMap::new(),
            from_inclusion_proof: None,
            end_entry: Some(sample_changelog_entry()),
            end_entry_inclusion_proof: Some(InclusionProof {
                i: 1,
                tree_size: 2,
                siblings: Vec::new(),
            }),
            expected_inclusion_proofs: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn changelog_entry_proto_roundtrip_preserves_as_bytes() {
        let entry = sample_changelog_entry();

        let original_bytes = entry.as_bytes();

        // Native → Proto → Native
        let proto: ChangelogEntry = (&entry).into();
        let roundtripped: CoreEntry = proto.into();

        assert_eq!(
            original_bytes,
            roundtripped.as_bytes(),
            "as_bytes() changed after proto roundtrip!\n\
             original entry: {entry:?}\n\
             roundtripped:   {roundtripped:?}"
        );
    }

    #[test]
    fn fast_forward_proof_proto_decode_accepts_legacy_empty_from_inclusion() {
        let mut proto = FastForwardProof::from(&sample_fast_forward_proof());
        proto.from_inclusion_proof.clear();

        let decoded = changelog::FastForwardProof::try_from(proto)
            .expect("legacy empty from_inclusion_proof should decode as None");

        assert!(decoded.from_inclusion_proof.is_none());
    }

    #[test]
    fn fast_forward_proof_proto_roundtrip_preserves_anchor_fields() {
        let mut proof = sample_fast_forward_proof();
        proof.from_inclusion_proof = Some(InclusionProof {
            i: 4,
            tree_size: 8,
            siblings: vec![changelog::Digest::from([0x33; 32])],
        });
        proof.end_entry_inclusion_proof = Some(InclusionProof {
            i: 7,
            tree_size: 8,
            siblings: vec![changelog::Digest::from([0x44; 32])],
        });

        let proto = FastForwardProof::from(&proof);
        let decoded = changelog::FastForwardProof::try_from(proto)
            .expect("FastForwardProof should roundtrip");

        assert_eq!(decoded.from_inclusion_proof, proof.from_inclusion_proof);
        assert_eq!(
            decoded.end_entry.as_ref().map(|entry| entry.as_bytes()),
            proof.end_entry.as_ref().map(|entry| entry.as_bytes())
        );
        assert_eq!(
            decoded.end_entry_inclusion_proof,
            proof.end_entry_inclusion_proof
        );
    }

    #[test]
    fn fast_forward_proof_proto_decode_accepts_omitted_end_anchor() {
        let mut proto = FastForwardProof::from(&sample_fast_forward_proof());
        proto.end_entry.clear();
        proto.end_entry_inclusion_proof.clear();

        let decoded = changelog::FastForwardProof::try_from(proto)
            .expect("omitted end anchor should decode as None");

        assert!(decoded.end_entry.is_none());
        assert!(decoded.end_entry_inclusion_proof.is_none());
    }

    #[test]
    fn fast_forward_proof_proto_decode_rejects_partial_end_anchor() {
        let mut missing_entry = FastForwardProof::from(&sample_fast_forward_proof());
        missing_entry.end_entry.clear();
        assert!(changelog::FastForwardProof::try_from(missing_entry).is_err());

        let mut missing_end_proof = FastForwardProof::from(&sample_fast_forward_proof());
        missing_end_proof.end_entry_inclusion_proof.clear();
        assert!(changelog::FastForwardProof::try_from(missing_end_proof).is_err());
    }

    #[test]
    fn fast_forward_proof_proto_decode_rejects_malformed_new_fields() {
        let proto = FastForwardProof::from(&sample_fast_forward_proof());

        let mut bad_from = proto.clone();
        bad_from.from_inclusion_proof = vec![0xff];
        assert!(changelog::FastForwardProof::try_from(bad_from).is_err());

        let mut bad_entry = proto.clone();
        bad_entry.end_entry = vec![0xff];
        assert!(changelog::FastForwardProof::try_from(bad_entry).is_err());

        let mut bad_end_proof = proto;
        bad_end_proof.end_entry_inclusion_proof = vec![0xff];
        assert!(changelog::FastForwardProof::try_from(bad_end_proof).is_err());
    }

    #[test]
    fn hash_backed_column_type_proto_roundtrip() {
        let text_col = schema::ColumnDefinition {
            name: "content".to_string(),
            column_type: schema::ColumnType::Text,
            plaintext: false,
            indexed: false,
        };
        let proto_col: ColumnDefinition = (&text_col).into();
        assert_eq!(proto_col.column_type, ColumnType::Text as i32);
        let roundtripped: schema::ColumnDefinition = proto_col.into();
        assert_eq!(roundtripped.column_type, schema::ColumnType::Text);

        let blob_col = schema::ColumnDefinition {
            name: "data".to_string(),
            column_type: schema::ColumnType::Blob,
            plaintext: false,
            indexed: false,
        };
        let proto_col: ColumnDefinition = (&blob_col).into();
        assert_eq!(proto_col.column_type, ColumnType::Blob as i32);
        let roundtripped: schema::ColumnDefinition = proto_col.into();
        assert_eq!(roundtripped.column_type, schema::ColumnType::Blob);
    }

    #[test]
    fn values_sidecar_proto_roundtrip() {
        let value = b"test data".to_vec();
        let mut map = changelog::HashedValues::new();
        map.insert(hashstore_hash(&value), value.clone());

        let wire = values_sidecar_to_proto(&map);
        assert_eq!(wire, vec![value]);

        let back = values_sidecar_from_proto(wire);
        assert_eq!(back, map);
    }

    #[test]
    fn values_sidecar_from_proto_rehashes_all() {
        let items = vec![vec![1], vec![2]];
        let result = values_sidecar_from_proto(items);
        assert_eq!(result.len(), 2);
        assert_eq!(result.get(&hashstore_hash(&[1])), Some(&vec![1]));
    }

    #[test]
    fn hash_backed_change_response_proto_roundtrips_material() {
        let value = b"full value".to_vec();
        let hash = hashstore_hash(&value);
        let mut hashed_values = changelog::HashedValues::new();
        hashed_values.insert(hash, value.clone());
        let response = changelog::ChangeResponse {
            change_id: 4,
            old_root: [1u8; 32],
            new_root: [2u8; 32],
            pruned_merkle_tree: vec![3, 4],
            rows_affected: 1,
            accepted_at_server_time: 1234,
            hashed_values: hashed_values.clone(),
        };

        let proto = ChangeResponse::from(&response);
        assert_eq!(proto.values_sidecar.len(), 1);
        assert_eq!(proto.values_sidecar[0], value);

        let roundtripped = changelog::ChangeResponse::try_from(proto).unwrap();
        assert_eq!(roundtripped.hashed_values, hashed_values);
        assert_eq!(roundtripped.accepted_at_server_time, 1234);
    }

    #[test]
    fn change_response_proto_rejects_short_old_root() {
        let proto = ChangeResponse {
            change_id: 4,
            old_root: vec![1u8; 31],
            new_root: vec![2u8; 32],
            pruned_merkle_tree: vec![],
            rows_affected: 0,
            values_sidecar: vec![],
            accepted_at_server_time: 0,
        };

        let err = changelog::ChangeResponse::try_from(proto).unwrap_err();
        assert!(err.to_string().contains("ChangeResponse.old_root"));
    }

    #[test]
    fn change_response_proto_rejects_long_old_root() {
        let proto = ChangeResponse {
            change_id: 4,
            old_root: vec![1u8; 33],
            new_root: vec![2u8; 32],
            pruned_merkle_tree: vec![],
            rows_affected: 0,
            values_sidecar: vec![],
            accepted_at_server_time: 0,
        };

        let err = changelog::ChangeResponse::try_from(proto).unwrap_err();
        assert!(err.to_string().contains("ChangeResponse.old_root"));
    }

    #[test]
    fn change_response_proto_rejects_short_new_root() {
        let proto = ChangeResponse {
            change_id: 4,
            old_root: vec![1u8; 32],
            new_root: vec![2u8; 31],
            pruned_merkle_tree: vec![],
            rows_affected: 0,
            values_sidecar: vec![],
            accepted_at_server_time: 0,
        };

        let err = changelog::ChangeResponse::try_from(proto).unwrap_err();
        assert!(err.to_string().contains("ChangeResponse.new_root"));
    }

    #[test]
    fn change_response_proto_rejects_long_new_root() {
        let proto = ChangeResponse {
            change_id: 4,
            old_root: vec![1u8; 32],
            new_root: vec![2u8; 33],
            pruned_merkle_tree: vec![],
            rows_affected: 0,
            values_sidecar: vec![],
            accepted_at_server_time: 0,
        };

        let err = changelog::ChangeResponse::try_from(proto).unwrap_err();
        assert!(err.to_string().contains("ChangeResponse.new_root"));
    }
}
