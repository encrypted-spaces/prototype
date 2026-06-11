//! Storage benchmarks for `MerkStorage`.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::sync::atomic::{AtomicUsize, Ordering};

use encrypted_spaces_backend::{
    access_control::AuthContext,
    query::{ComparisonOperator, Order, Predicate, Query, QueryOperation, QueryParam},
    schema::{ColumnDefinition, ColumnType, Schema},
    storage::Storage,
    SpaceId,
};

#[cfg(feature = "merk")]
use encrypted_spaces_backend::merk_storage::{
    proofs as merk_proofs, test_helpers as merk_test_helpers, MerkStorage,
};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn unique_id() -> usize {
    COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// uid used by proof benches. Must match the user registered by
/// `merk_setup::setup_for_proof` so `extract_and_validate`'s
/// `validate_user_access` check succeeds.
#[cfg(feature = "merk")]
const BENCH_UID: u32 = 1;

fn test_auth() -> AuthContext {
    AuthContext::new(Some(1), SpaceId::from([0u8; 16]))
}

fn test_schema(table_name: &str) -> Schema {
    Schema {
        name: table_name.to_string(),
        columns: vec![
            ColumnDefinition {
                name: "id".to_string(),
                column_type: ColumnType::Integer,
                plaintext: true,
                indexed: false,
            },
            ColumnDefinition {
                name: "name".to_string(),
                column_type: ColumnType::String,
                plaintext: true,
                indexed: true,
            },
            ColumnDefinition {
                name: "age".to_string(),
                column_type: ColumnType::Integer,
                plaintext: true,
                indexed: false,
            },
            ColumnDefinition {
                name: "email".to_string(),
                column_type: ColumnType::String,
                plaintext: true,
                indexed: false,
            },
        ],
        auto_increment: true,
    }
}

/// Schema without indexes for proof benchmarks (matches the test schema structure)
fn proof_schema(table_name: &str) -> Schema {
    Schema {
        name: table_name.to_string(),
        columns: vec![
            ColumnDefinition {
                name: "id".to_string(),
                column_type: ColumnType::Integer,
                plaintext: true,
                indexed: false,
            },
            ColumnDefinition {
                name: "name".to_string(),
                column_type: ColumnType::String,
                plaintext: true,
                indexed: false,
            },
            ColumnDefinition {
                name: "age".to_string(),
                column_type: ColumnType::Integer,
                plaintext: true,
                indexed: false,
            },
        ],
        auto_increment: true,
    }
}

fn insert_query(table: &str, name: &str, age: i64, email: &str) -> Query {
    Query {
        table: table.to_string(),
        operation: QueryOperation::Insert(vec![
            ("name".to_string(), QueryParam::Text(name.to_string())),
            ("age".to_string(), QueryParam::Integer(age)),
            ("email".to_string(), QueryParam::Text(email.to_string())),
        ]),
        predicate: None,
        order: Order::Asc,
        limit: None,
        join: None,
    }
}

fn select_by_id_query(table: &str, id: i64) -> Query {
    Query {
        table: table.to_string(),
        operation: QueryOperation::Select(vec![]),
        predicate: Some(Predicate {
            column: "id".to_string(),
            operator: ComparisonOperator::Equal,
            values: vec![QueryParam::Integer(id)],
            cursor_id: None,
        }),
        order: Order::Asc,
        limit: None,
        join: None,
    }
}

fn select_all_query(table: &str) -> Query {
    Query {
        table: table.to_string(),
        operation: QueryOperation::Select(vec![]),
        predicate: None,
        order: Order::Asc,
        limit: None,
        join: None,
    }
}

fn update_query(table: &str, id: i64, new_age: i64) -> Query {
    Query {
        table: table.to_string(),
        operation: QueryOperation::Update(vec![
            ("id".to_string(), QueryParam::Integer(id)),
            ("age".to_string(), QueryParam::Integer(new_age)),
        ]),
        predicate: Some(Predicate {
            column: "id".to_string(),
            operator: ComparisonOperator::Equal,
            values: vec![QueryParam::Integer(id)],
            cursor_id: None,
        }),
        order: Order::Asc,
        limit: None,
        join: None,
    }
}

fn delete_query(table: &str, id: i64) -> Query {
    Query {
        table: table.to_string(),
        operation: QueryOperation::Delete,
        predicate: Some(Predicate {
            column: "id".to_string(),
            operator: ComparisonOperator::Equal,
            values: vec![QueryParam::Integer(id)],
            cursor_id: None,
        }),
        order: Order::Asc,
        limit: None,
        join: None,
    }
}

#[cfg(feature = "merk")]
mod merk_setup {
    use super::*;

    pub fn create_storage() -> MerkStorage {
        MerkStorage::new()
    }

    pub fn setup_with_rows(n: usize) -> (MerkStorage, String, tokio::runtime::Runtime) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let storage = create_storage();
        let table = format!("bench_table_{}", unique_id());
        let schema = test_schema(&table);
        rt.block_on(storage.create_table(&schema)).unwrap();

        let auth = test_auth();
        for i in 0..n {
            let query = insert_query(
                &table,
                &format!("User{i}"),
                (20 + i % 50) as i64,
                &format!("user{i}@example.com"),
            );
            rt.block_on(storage.insert(query, &auth)).unwrap();
        }

        (storage, table, rt)
    }

    pub fn setup_for_proof(n: usize) -> (MerkStorage, String, tokio::runtime::Runtime) {
        use encrypted_spaces_backend::internal_schemas;

        let rt = tokio::runtime::Runtime::new().unwrap();
        let storage = create_storage();

        // Create the internal tables and register a non-provisional user
        // (uid=1) so the `extract_and_validate` `validate_user_access`
        // check inside `apply_change_with_pruned_tree` succeeds. This must match
        // the uid baked
        // into `test_auth()` and the `change` passed to the proof entry
        // points.
        rt.block_on(storage.create_table(&internal_schemas::access_control_schema()))
            .unwrap();
        rt.block_on(storage.create_table(&internal_schemas::users_schema()))
            .unwrap();
        let setup_auth = AuthContext::anonymous(SpaceId::from([0u8; 16]));
        let user_query = Query::new(
            internal_schemas::USERS_TABLE_NAME.to_string(),
            QueryOperation::Insert(vec![
                ("update_key".to_string(), QueryParam::Text(String::new())),
                ("auth_key".to_string(), QueryParam::Text(String::new())),
                ("status".to_string(), QueryParam::Integer(1)),
            ]),
        );
        let registered_uid = rt
            .block_on(storage.insert(user_query, &setup_auth))
            .unwrap();
        assert_eq!(
            registered_uid, BENCH_UID as i64,
            "registered uid must match BENCH_UID for proof benches"
        );

        let table = format!("proof_table_{}", unique_id());
        let schema = proof_schema(&table);
        rt.block_on(storage.create_table(&schema)).unwrap();

        let auth = test_auth();
        for i in 0..n {
            let row_data = vec![
                ("name".to_string(), QueryParam::Text(format!("User{i}"))),
                ("age".to_string(), QueryParam::Integer((20 + i % 50) as i64)),
            ];
            let query = Query::new(table.clone(), QueryOperation::Insert(row_data));
            rt.block_on(storage.insert(query, &auth)).unwrap();
        }

        (storage, table, rt)
    }
}

// ============================================================================
// CRUD BENCHMARKS
// ============================================================================

#[cfg(feature = "merk")]
fn bench_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("insert");
    group.throughput(Throughput::Elements(1));

    group.bench_function(BenchmarkId::from_parameter("merk"), |b| {
        let (storage, table, rt) = merk_setup::setup_with_rows(0);
        let auth = test_auth();
        b.iter(|| {
            let query = insert_query(&table, "TestUser", 30, "test@example.com");
            black_box(rt.block_on(storage.insert(query, &auth)).unwrap())
        });
    });

    group.finish();
}

#[cfg(feature = "merk")]
fn bench_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("update");
    group.throughput(Throughput::Elements(1));

    group.bench_function(BenchmarkId::from_parameter("merk"), |b| {
        let (storage, table, rt) = merk_setup::setup_with_rows(100);
        let auth = test_auth();
        let mut age = 0i64;
        b.iter(|| {
            age += 1;
            let query = update_query(&table, 50, age);
            black_box(rt.block_on(storage.update_or_delete(query, &auth)).unwrap())
        });
    });

    group.finish();
}

#[cfg(feature = "merk")]
fn bench_delete(c: &mut Criterion) {
    let mut group = c.benchmark_group("delete");
    group.throughput(Throughput::Elements(1));
    group.sample_size(20);

    group.bench_function(BenchmarkId::from_parameter("merk"), |b| {
        b.iter_with_setup(
            || merk_setup::setup_with_rows(100),
            |(storage, table, rt)| {
                let auth = test_auth();
                let query = delete_query(&table, 50);
                black_box(rt.block_on(storage.update_or_delete(query, &auth)).unwrap())
            },
        );
    });

    group.finish();
}

#[cfg(feature = "merk")]
fn bench_select_by_id(c: &mut Criterion) {
    let mut group = c.benchmark_group("select_by_id");
    group.throughput(Throughput::Elements(1));

    group.bench_function(BenchmarkId::from_parameter("merk"), |b| {
        let (storage, table, rt) = merk_setup::setup_with_rows(100);
        b.iter(|| {
            let query = select_by_id_query(&table, 50);
            let result: Option<serde_json::Value> = rt.block_on(storage.select_one(query)).unwrap();
            black_box(result)
        });
    });

    group.finish();
}

#[cfg(feature = "merk")]
fn bench_select_all(c: &mut Criterion) {
    let row_counts = [10, 50, 100];

    for &row_count in &row_counts {
        let mut group = c.benchmark_group(format!("select_all/{}_rows", row_count));
        group.throughput(Throughput::Elements(row_count as u64));

        group.bench_function(BenchmarkId::from_parameter("merk"), |b| {
            let (storage, table, rt) = merk_setup::setup_with_rows(row_count);
            b.iter(|| {
                let query = select_all_query(&table);
                let result: Vec<serde_json::Value> =
                    rt.block_on(storage.select_all(query)).unwrap();
                black_box(result)
            });
        });

        group.finish();
    }
}

// ============================================================================
// PROOF BENCHMARKS
// ============================================================================

#[cfg(feature = "merk")]
fn bench_insert_with_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("insert_with_proof");
    group.throughput(Throughput::Elements(1));
    group.sample_size(10);

    group.bench_function(BenchmarkId::from_parameter("merk"), |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;
            for _ in 0..iters {
                let (storage, table, rt) = merk_setup::setup_for_proof(1);
                let row_data = vec![
                    ("id".to_string(), QueryParam::Integer(0)),
                    (
                        "name".to_string(),
                        QueryParam::Text("ProofUser".to_string()),
                    ),
                    ("age".to_string(), QueryParam::Integer(42)),
                ];
                let query = Query::new(table, QueryOperation::Insert(row_data));
                let change = merk_test_helpers::insert_change_for_query(&query, BENCH_UID).unwrap();
                let start = std::time::Instant::now();
                black_box(
                    rt.block_on(storage.apply_change_with_pruned_tree(&change, 1))
                        .unwrap(),
                );
                total += start.elapsed();
            }
            total
        });
    });

    group.finish();
}

#[cfg(feature = "merk")]
fn bench_update_with_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("update_with_proof");
    group.throughput(Throughput::Elements(1));
    group.sample_size(10);

    group.bench_function(BenchmarkId::from_parameter("merk"), |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;
            for _ in 0..iters {
                let (storage, table, rt) = merk_setup::setup_for_proof(10);
                let update_data = vec![
                    ("id".to_string(), QueryParam::Integer(5)),
                    (
                        "name".to_string(),
                        QueryParam::Text("UpdatedUser".to_string()),
                    ),
                    ("age".to_string(), QueryParam::Integer(99)),
                ];
                let mut query = Query::new(table.clone(), QueryOperation::Update(update_data));
                query.predicate = Some(Predicate {
                    column: "id".to_string(),
                    operator: ComparisonOperator::Equal,
                    values: vec![QueryParam::Integer(5)],
                    cursor_id: None,
                });
                let change = merk_test_helpers::update_change_for_query(&query, BENCH_UID).unwrap();
                let start = std::time::Instant::now();
                black_box(
                    rt.block_on(storage.apply_change_with_pruned_tree(&change, 2))
                        .unwrap(),
                );
                total += start.elapsed();
            }
            total
        });
    });

    group.finish();
}

#[cfg(feature = "merk")]
fn bench_prove_query(c: &mut Criterion) {
    let row_counts = [10, 50, 100];

    for &row_count in &row_counts {
        let mut group = c.benchmark_group(format!("prove_query/{}_rows", row_count));
        group.throughput(Throughput::Elements(row_count as u64));

        group.bench_function(BenchmarkId::from_parameter("merk"), |b| {
            let (storage, table, rt) = merk_setup::setup_with_rows(row_count);
            b.iter(|| {
                let query = select_all_query(&table);
                black_box(rt.block_on(storage.prove_query(&query)).unwrap())
            });
        });

        group.finish();
    }
}

#[cfg(feature = "merk")]
fn bench_verify_query_proof(c: &mut Criterion) {
    let row_counts = [10, 50, 100];

    for &row_count in &row_counts {
        let mut group = c.benchmark_group(format!("verify_query_proof/{}_rows", row_count));
        group.throughput(Throughput::Elements(row_count as u64));

        group.bench_function(BenchmarkId::from_parameter("merk"), |b| {
            let (storage, table, rt) = merk_setup::setup_with_rows(row_count);
            let query = select_all_query(&table);
            let proof = rt.block_on(storage.prove_query(&query)).unwrap();
            let root = storage.root_hash();

            b.iter(|| {
                let verified = merk_proofs::verify_query_proof(&query, &proof, &root).unwrap();
                let result = encrypted_spaces_backend::merk_storage::process_query_results(
                    verified.main_rows,
                    &query,
                )
                .unwrap();
                black_box(result)
            });
        });

        group.finish();
    }
}

#[cfg(feature = "merk")]
fn bench_verify_insert_proof(c: &mut Criterion) {
    use encrypted_spaces_changelog_core::changelog::ChangeLog;

    let mut group = c.benchmark_group("verify_insert_proof");
    group.throughput(Throughput::Elements(1));

    group.bench_function(BenchmarkId::from_parameter("merk"), |b| {
        let (storage, table, rt) = merk_setup::setup_for_proof(10);
        let row_data = vec![
            ("id".to_string(), QueryParam::Integer(0)),
            (
                "name".to_string(),
                QueryParam::Text("ProofUser".to_string()),
            ),
            ("age".to_string(), QueryParam::Integer(42)),
        ];
        let query = Query::new(table, QueryOperation::Insert(row_data));
        let change = merk_test_helpers::insert_change_for_query(&query, BENCH_UID).unwrap();
        let root_before = storage.root_hash();
        let proof = rt
            .block_on(storage.apply_change_with_pruned_tree(&change, 1))
            .unwrap();
        let root_after = storage.root_hash();

        b.iter(|| {
            black_box(
                ChangeLog::verify_proof_and_validate(
                    &change.entry,
                    &proof,
                    &root_before,
                    &root_after,
                    1,
                )
                .unwrap(),
            )
        });
    });

    group.finish();
}

#[cfg(feature = "merk")]
fn bench_verify_pruned_tree_update(c: &mut Criterion) {
    use encrypted_spaces_changelog_core::changelog::ChangeLog;

    let mut group = c.benchmark_group("verify_pruned_tree_update");
    group.throughput(Throughput::Elements(1));

    group.bench_function(BenchmarkId::from_parameter("merk"), |b| {
        let (storage, table, rt) = merk_setup::setup_for_proof(10);
        let update_data = vec![
            ("id".to_string(), QueryParam::Integer(5)),
            (
                "name".to_string(),
                QueryParam::Text("UpdatedUser".to_string()),
            ),
            ("age".to_string(), QueryParam::Integer(99)),
        ];
        let mut query = Query::new(table.clone(), QueryOperation::Update(update_data));
        query.predicate = Some(Predicate {
            column: "id".to_string(),
            operator: ComparisonOperator::Equal,
            values: vec![QueryParam::Integer(5)],
            cursor_id: None,
        });
        let change = merk_test_helpers::update_change_for_query(&query, BENCH_UID).unwrap();
        let root_before = storage.root_hash();
        let proof = rt
            .block_on(storage.apply_change_with_pruned_tree(&change, 2))
            .unwrap();
        let root_after = storage.root_hash();

        b.iter(|| {
            black_box(
                ChangeLog::verify_proof_and_validate(
                    &change.entry,
                    &proof,
                    &root_before,
                    &root_after,
                    2,
                )
                .unwrap(),
            )
        });
    });

    group.finish();
}

// ============================================================================
// CRITERION GROUPS
// ============================================================================

#[cfg(feature = "merk")]
criterion_group!(
    crud_benchmarks,
    bench_insert,
    bench_update,
    bench_delete,
    bench_select_by_id,
    bench_select_all,
);

#[cfg(feature = "merk")]
criterion_group!(
    proof_benchmarks,
    bench_insert_with_proof,
    bench_update_with_proof,
    bench_prove_query,
    bench_verify_query_proof,
);

#[cfg(feature = "merk")]
criterion_group!(
    merk_verify_benchmarks,
    bench_verify_insert_proof,
    bench_verify_pruned_tree_update,
);

#[cfg(feature = "merk")]
criterion_main!(crud_benchmarks, proof_benchmarks, merk_verify_benchmarks);

#[cfg(not(feature = "merk"))]
fn main() {}
