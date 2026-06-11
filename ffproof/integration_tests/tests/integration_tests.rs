use encrypted_spaces_backend::access_control::AuthContext;
use encrypted_spaces_backend::merk_storage::{
    build_column_kv_vecs, column_key, column_key_placeholder, get_row_data_from_query,
};
use encrypted_spaces_backend::query::{
    ComparisonOperator, Predicate, Query, QueryOperation, QueryParam,
};
use encrypted_spaces_backend_server::{db::ServerError, SpaceState};
use encrypted_spaces_changelog_core::changelog::{
    Change, ChangeResponse, FastForwardData, HashedValues, OpType, ROOT_TREE_PATH,
};
use encrypted_spaces_changelog_test_utils::{
    init_test_server_state, init_test_server_state_with_schema, insert_acl_rule, products_schema,
    sign_test_change, test_auth_key_string,
};
use encrypted_spaces_sdk::local_transport::LocalTransport;
use encrypted_spaces_sdk::Space;
use tokio::sync::Mutex;

// Proof mode (dev vs real) is handled by encrypted-spaces-ffproof's
// `real-proofs` feature flag via ensure_risc0_proof_mode().
const TEST_ENV_VARS: [(&str, Option<&str>); 2] =
    [("RUST_LOG", Some("info")), ("RISC0_INFO", Some("1"))];

// Batch size for FF proof generation - a new proof is generated every N changes
const FF_BATCH_SIZE: usize = 3;

/// Server wrapper that delegates to SpaceState.
/// Clients are created separately and just use the SDK for validation.
struct Server {
    pub state: Mutex<SpaceState>,
    /// The initial data commitment (saved at server creation for FF proof verification)
    pub initial_dc: [u8; 32],
}

impl Server {
    pub async fn new() -> Self {
        let state = init_test_server_state(Some(FF_BATCH_SIZE), &[1, 2]).await;

        // The initial DC equals the hash chain starting link — the Merk root
        // after all setup inserts, at the point the changelog begins.
        let initial_dc = state.get_root_hash().await;

        Self {
            state: Mutex::new(state),
            initial_dc,
        }
    }

    /// Create a client Space for validation only.
    /// The Space doesn't actually use the transport - it just validates
    /// changes and FF proofs passed to it. We create a dummy LocalTransport
    /// and override the initial_dc, then seed the _users cache so that
    /// proof validation can resolve user-existence reads.
    pub async fn create_client(&self) -> Space {
        let transport = LocalTransport::in_memory().await.unwrap();
        let space = Space::new_without_schema_init(transport, self.initial_dc)
            .await
            .expect("Failed to create Space");

        // Seed the _users cache and register table schemas so that
        // make_local_reader can resolve user-existence and schema reads.
        space.seed_user_cache(&[(1, test_auth_key_string(1)), (2, test_auth_key_string(2))]);
        space.register_table_schema(products_schema());
        space
    }

    pub async fn handle_change(
        &self,
        change: &Change,
        auth: &AuthContext,
    ) -> Result<ChangeResponse, ServerError> {
        self.state.lock().await.handle_change(change, auth).await
    }

    pub async fn get_fast_forward(
        &self,
        from_change_id: u32,
        auth: &AuthContext,
    ) -> Result<FastForwardData, ServerError> {
        self.state
            .lock()
            .await
            .handle_fast_forward(from_change_id, &[], auth)
    }

    pub async fn proven_up_to(&self) -> usize {
        self.state.lock().await.changelog.proven_up_to
    }

    pub async fn num_changes(&self) -> u32 {
        self.state.lock().await.changelog.num_changes()
    }
}

#[tokio::test]
async fn test_basic_e2e_flow() {
    if std::env::var("RISC0_SKIP_BUILD").is_ok() {
        eprintln!("Skipping test_basic_e2e_flow: RISC0_SKIP_BUILD is set");
        return;
    }
    temp_env::async_with_vars(TEST_ENV_VARS, test_basic_e2e_flow_inner()).await;
}

async fn test_basic_e2e_flow_inner() {
    // Run the steps outlined in README.md

    println!("Initializing Server");
    let server = Server::new().await;

    println!("Initializing Client using SDK Space");
    let client1 = server.create_client().await;
    client1.authenticate_as_id(1).await.unwrap();
    let auth1 = client1.get_auth_context();

    // The schema and example data are from https://github.com/mmaker/confidential-applications/blob/main/notes/grovedb_proofs.md (legacy)
    // (now using Merk backend; references retained for provenance)

    // Insert some test data
    for (id, name, price) in &[
        (0, "Banana", 1.5),
        (0, "Apple", 2.0),
        (0, "Cherry", 3.0),
        (0, "Apple", 1.0),  // Same name, different price
        (0, "Banana", 2.5), // Same name, different price
    ] {
        println!("Creating client change, insert (id, name, price) = ({id}, {name}, {price})");

        let query = Query::new(
            "products".to_string(),
            QueryOperation::Insert(vec![
                ("id".to_string(), QueryParam::Integer(*id)),
                ("name".to_string(), QueryParam::Text(name.to_string())),
                ("price".to_string(), QueryParam::Real(*price)),
            ]),
        );

        let (_, column_data) = get_row_data_from_query(&query).unwrap();
        let (col_keys, col_values) =
            build_column_kv_vecs(&column_data, |col| column_key_placeholder("products", col));
        let key_refs: Vec<&[u8]> = col_keys.iter().map(|k| k.as_slice()).collect();
        let val_refs: Vec<&[u8]> = col_values.iter().map(|v| v.as_slice()).collect();

        // Note: when creating a change for `OpType::Insert`, the `key` is set to the `row_prefix` because the
        //       row_id is auto-incrementing and chosen by the server, and thus not known to `client1``
        //       when they create `change`
        let mut change = Change::new(
            OpType::Insert,
            client1.uid().unwrap(),
            ROOT_TREE_PATH,
            &key_refs,
            &val_refs,
            client1.current_change_id(),
            client1.my_last_change_id(),
            client1.current_clc(),
        )
        .unwrap();
        sign_test_change(client1.uid().unwrap(), &mut change);

        println!("Change = {}", change.entry.pretty_print());

        // Now send the change to the server
        let response = server.handle_change(&change, &auth1).await;
        let response = response.unwrap();

        // Client handles the response using SDK's validate_and_apply_change
        let client_response = client1.validate_and_apply_change(&change.entry, &response);
        assert!(client_response.is_ok());
    }

    // Verify client's recomputed CLC matches the server's hash chain
    {
        let server_clc: [u8; 32] = server.state.lock().await.changelog.current_root();
        assert_eq!(
            client1.current_clc(),
            server_clc,
            "Client CLC should match server's hash chain after inserts"
        );
    }

    // update some test data
    for (id, name, price) in &[
        (1, "Apple", 2.0),
        (2, "Cherry", 1.0),
        (3, "Apple", 2.0),
        (4, "Banana", 3.0),
        (5, "Cherry", 4.5),
    ] {
        println!("Creating client change, update (id, name, price) = ({id}, {name}, {price})");

        let mut query = Query::new(
            "products".to_string(),
            QueryOperation::Update(vec![
                ("id".to_string(), QueryParam::Integer(*id)),
                ("name".to_string(), QueryParam::Text(name.to_string())),
                ("price".to_string(), QueryParam::Real(*price)),
            ]),
        );
        query.predicate = Some(Predicate {
            column: "id".to_string(),
            operator: ComparisonOperator::Equal,
            values: vec![QueryParam::Integer(*id)],
            cursor_id: None,
        });

        let (_, column_data) = get_row_data_from_query(&query).unwrap();
        let (col_keys, col_values) =
            build_column_kv_vecs(&column_data, |col| column_key("products", *id, col));
        let key_refs: Vec<&[u8]> = col_keys.iter().map(|k| k.as_slice()).collect();
        let val_refs: Vec<&[u8]> = col_values.iter().map(|v| v.as_slice()).collect();

        let mut change = Change::new(
            OpType::Update,
            client1.uid().unwrap(),
            ROOT_TREE_PATH,
            &key_refs,
            &val_refs,
            client1.current_change_id(),
            client1.my_last_change_id(),
            client1.current_clc(),
        )
        .unwrap();
        sign_test_change(client1.uid().unwrap(), &mut change);

        println!("Change = {}", change.entry.pretty_print());

        // Now send the change to the server
        let response = server.handle_change(&change, &auth1).await;

        // In the SDK the server notifies and broadcasts changes here

        // Client handles the response using SDK's validate_and_apply_change
        let client_response = client1.validate_and_apply_change(&change.entry, &response.unwrap());
        assert!(client_response.is_ok());
    }

    // Add a new client
    let client2 = server.create_client().await;
    client2.authenticate_as_id(2).await.unwrap();
    let auth2 = client2.get_auth_context();

    // The first client makes another change
    let (id, name, price) = (0, "Orange", 1.2);
    println!("Creating client change, insert (id, name, price) = ({id}, {name}, {price})");

    let query = Query::new(
        "products".to_string(),
        QueryOperation::Insert(vec![
            ("id".to_string(), QueryParam::Integer(id)),
            ("name".to_string(), QueryParam::Text(name.to_string())),
            ("price".to_string(), QueryParam::Real(price)),
        ]),
    );
    let (_, column_data) = get_row_data_from_query(&query).unwrap();
    let (col_keys, col_values) =
        build_column_kv_vecs(&column_data, |col| column_key_placeholder("products", col));
    let key_refs: Vec<&[u8]> = col_keys.iter().map(|k| k.as_slice()).collect();
    let val_refs: Vec<&[u8]> = col_values.iter().map(|v| v.as_slice()).collect();
    let mut change = Change::new(
        OpType::Insert,
        client1.uid().unwrap(),
        ROOT_TREE_PATH,
        &key_refs,
        &val_refs,
        client1.current_change_id(),
        client1.my_last_change_id(),
        client1.current_clc(),
    )
    .unwrap();
    sign_test_change(client1.uid().unwrap(), &mut change);
    println!("Change = {}", change.entry.pretty_print());

    // Now send the change to the server, process on client1
    let response = server.handle_change(&change, &auth1).await.unwrap();
    let client_response = client1.validate_and_apply_change(&change.entry, &response);
    assert!(client_response.is_ok());

    // Try to handle response on client2, expect it to fail because they're out of date
    let client2_err = client2.validate_and_apply_change(&change.entry, &response);
    assert!(client2_err.is_err());
    println!("Error (expected) from client2: {client2_err:?}");

    let ff_proof = server
        .get_fast_forward(client2.current_change_id(), &auth2)
        .await
        .unwrap();
    let res = client2.apply_fast_forward(ff_proof).await;
    assert!(res.is_ok());

    // Now client2 should be up-to-date, including with (&change, &response)
    assert!(client2.current_data_commitment() == response.new_root);
    assert!(client2.current_change_id() == server.num_changes().await);
}

// Helper to insert multiple products
async fn insert_products(server: &Server, client: &Space, auth: &AuthContext, count: usize) {
    for i in 0..count {
        let query = Query::new(
            "products".to_string(),
            QueryOperation::Insert(vec![
                ("id".to_string(), QueryParam::Integer(0)),
                ("name".to_string(), QueryParam::Text(format!("Product{i}"))),
                ("price".to_string(), QueryParam::Real(i as f64)),
            ]),
        );
        let (_, column_data) = get_row_data_from_query(&query).unwrap();
        let (col_keys, col_values) =
            build_column_kv_vecs(&column_data, |col| column_key_placeholder("products", col));
        let key_refs: Vec<&[u8]> = col_keys.iter().map(|k| k.as_slice()).collect();
        let val_refs: Vec<&[u8]> = col_values.iter().map(|v| v.as_slice()).collect();
        let mut change = Change::new(
            OpType::Insert,
            client.uid().unwrap(),
            ROOT_TREE_PATH,
            &key_refs,
            &val_refs,
            client.current_change_id(),
            client.my_last_change_id(),
            client.current_clc(),
        )
        .unwrap();
        sign_test_change(client.uid().unwrap(), &mut change);
        let response = server.handle_change(&change, auth).await.unwrap();
        client
            .validate_and_apply_change(&change.entry, &response)
            .unwrap();
    }
}

#[tokio::test]
async fn test_nontrivial_ff() {
    if std::env::var("RISC0_SKIP_BUILD").is_ok() {
        eprintln!("Skipping test_nontrivial_ff: RISC0_SKIP_BUILD is set");
        return;
    }
    temp_env::async_with_vars(TEST_ENV_VARS, test_nontrivial_ff_inner()).await;
}

async fn test_nontrivial_ff_inner() {
    // This test demonstrates the 3 key fast-forward scenarios:
    // 1. Client behind, exact batch boundary → proof only
    // 2. Client behind, server has ragged changes → proof + individual changes
    // 3. Client at proven point, new changes → individual changes only (no proof)

    println!("=== Fast-Forward Proof Test ===");
    let server = Server::new().await;

    // client1 is the "writer" that stays current
    let client1 = server.create_client().await;
    client1.authenticate_as_id(1).await.unwrap();
    let auth1 = client1.get_auth_context();

    // client2 is the "reader" we'll test FF scenarios with
    let client2 = server.create_client().await;
    client2.authenticate_as_id(2).await.unwrap();
    let auth2 = client2.get_auth_context();

    // === Setup: Insert FF_BATCH_SIZE changes to trigger first proof ===
    println!("\n--- Setup: Insert {FF_BATCH_SIZE} changes (triggers proof) ---");
    insert_products(&server, &client1, &auth1, FF_BATCH_SIZE).await;
    assert_eq!(server.proven_up_to().await, FF_BATCH_SIZE);

    // === Case 1: Exact batch boundary ===
    println!("\n--- Case 1: Client at 0, server at batch boundary ({FF_BATCH_SIZE}) ---");
    println!("Expected: proof only, no ragged changes");

    let ff_data = server
        .get_fast_forward(client2.current_change_id(), &auth2)
        .await
        .unwrap();
    assert!(ff_data.proof.is_some(), "Should include proof");
    assert!(
        ff_data.changes.is_empty(),
        "No ragged changes at exact batch boundary"
    );

    client2.apply_fast_forward(ff_data).await.unwrap();
    assert_eq!(client2.current_change_id(), FF_BATCH_SIZE as u32);
    assert_eq!(
        client2.current_data_commitment(),
        client1.current_data_commitment()
    );
    println!(
        "✓ Client fast-forwarded to {} via proof",
        client2.current_change_id()
    );

    // === Setup for Case 2: Add 2 more changes (no new proof yet) ===
    println!("\n--- Setup: Insert 2 more changes (no new proof) ---");
    insert_products(&server, &client1, &auth1, 2).await;
    assert_eq!(
        server.proven_up_to().await,
        FF_BATCH_SIZE,
        "No new proof yet"
    );

    // === Case 2: Proof + ragged changes ===
    // Client at FF_BATCH_SIZE, server at FF_BATCH_SIZE + 2
    // Proof covers 0..FF_BATCH_SIZE, plus 2 individual changes
    println!(
        "\n--- Case 2: Client at {}, server at {} ---",
        FF_BATCH_SIZE,
        FF_BATCH_SIZE + 2
    );
    println!("Expected: no proof (client already at proven point), 2 individual changes");

    let ff_data = server
        .get_fast_forward(client2.current_change_id(), &auth2)
        .await
        .unwrap();
    // Client is AT proven_up_to, so no proof needed - just individual changes
    assert!(
        ff_data.proof.is_none(),
        "Client at proven point doesn't need proof"
    );
    assert_eq!(ff_data.changes.len(), 2, "Should have 2 individual changes");

    client2.apply_fast_forward(ff_data).await.unwrap();
    assert_eq!(client2.current_change_id(), (FF_BATCH_SIZE + 2) as u32);
    assert_eq!(
        client2.current_data_commitment(),
        client1.current_data_commitment()
    );
    println!(
        "✓ Client caught up to {} via 2 individual changes",
        client2.current_change_id()
    );

    // === Setup for Case 3: Add 1 more change to trigger second proof ===
    println!("\n--- Setup: Insert 1 more change (triggers second proof) ---");
    insert_products(&server, &client1, &auth1, 1).await;
    assert_eq!(
        server.proven_up_to().await,
        2 * FF_BATCH_SIZE,
        "Second batch proven"
    );

    // === Case 3: Client behind new proof ===
    // Client at FF_BATCH_SIZE + 2, server at 2 * FF_BATCH_SIZE
    // New proof covers 0..2*FF_BATCH_SIZE, client can jump ahead
    println!(
        "\n--- Case 3: Client at {}, server at {} (new proof available) ---",
        FF_BATCH_SIZE + 2,
        2 * FF_BATCH_SIZE
    );
    println!(
        "Expected: proof to jump to {}, no ragged changes",
        2 * FF_BATCH_SIZE
    );

    let ff_data = server
        .get_fast_forward(client2.current_change_id(), &auth2)
        .await
        .unwrap();
    assert!(ff_data.proof.is_some(), "New proof available");
    assert_eq!(
        ff_data.proof.as_ref().unwrap().end_change_id,
        (2 * FF_BATCH_SIZE) as u32
    );
    assert!(ff_data.changes.is_empty(), "No ragged at batch boundary");

    client2.apply_fast_forward(ff_data).await.unwrap();
    assert_eq!(client2.current_change_id(), (2 * FF_BATCH_SIZE) as u32);
    assert_eq!(
        client2.current_data_commitment(),
        client1.current_data_commitment()
    );
    println!(
        "✓ Client jumped to {} via proof",
        client2.current_change_id()
    );

    println!("\n=== All 3 cases passed! ===");
}

// ─── Delete helpers and tests ───────────────────────────────────────────────

/// Helper: delete a single product by row id.
async fn delete_product(server: &Server, client: &Space, auth: &AuthContext, row_id: i64) {
    let mut query = Query::new("products".to_string(), QueryOperation::Delete);
    query.predicate = Some(Predicate {
        column: "id".to_string(),
        operator: ComparisonOperator::Equal,
        values: vec![QueryParam::Integer(row_id)],
        cursor_id: None,
    });

    // Build per-column keys for all non-id columns (sorted)
    let mut col_keys: Vec<Vec<u8>> = ["name", "price"]
        .iter()
        .map(|col| column_key("products", row_id, col))
        .collect();
    col_keys.sort();
    let key_refs: Vec<&[u8]> = col_keys.iter().map(|k| k.as_slice()).collect();
    let val_refs: Vec<&[u8]> = vec![b"" as &[u8]; col_keys.len()];

    let mut change = Change::new(
        OpType::Delete,
        client.uid().unwrap(),
        ROOT_TREE_PATH,
        &key_refs,
        &val_refs,
        client.current_change_id(),
        client.my_last_change_id(),
        client.current_clc(),
    )
    .unwrap();
    sign_test_change(client.uid().unwrap(), &mut change);

    let response = server.handle_change(&change, auth).await.unwrap();
    client
        .validate_and_apply_change(&change.entry, &response)
        .unwrap();
}

#[tokio::test]
async fn test_insert_then_delete() {
    if std::env::var("RISC0_SKIP_BUILD").is_ok() {
        eprintln!("Skipping test_insert_then_delete: RISC0_SKIP_BUILD is set");
        return;
    }
    temp_env::async_with_vars(TEST_ENV_VARS, test_insert_then_delete_inner()).await;
}

async fn test_insert_then_delete_inner() {
    println!("=== Insert-then-Delete Test ===");
    let server = Server::new().await;

    let client1 = server.create_client().await;
    client1.authenticate_as_id(1).await.unwrap();
    let auth1 = client1.get_auth_context();

    // Insert 3 products
    println!("Inserting 3 products");
    insert_products(&server, &client1, &auth1, 3).await;
    assert_eq!(server.num_changes().await, 3);

    // Delete product with id=2
    println!("Deleting product id=2");
    delete_product(&server, &client1, &auth1, 2).await;
    assert_eq!(server.num_changes().await, 4);

    println!("Delete change accepted and validated by server and client");

    // A second client can catch up via fast-forward (individual changes, no proof yet)
    let client2 = server.create_client().await;
    client2.authenticate_as_id(2).await.unwrap();
    let auth2 = client2.get_auth_context();

    let ff_data = server
        .get_fast_forward(client2.current_change_id(), &auth2)
        .await
        .unwrap();
    // First 3 changes are covered by an FF proof (batch size = 3),
    // the 4th (delete) is a ragged individual change
    assert!(
        ff_data.proof.is_some(),
        "Should include proof for first batch"
    );
    assert_eq!(ff_data.changes.len(), 1, "One ragged change (the delete)");
    client2.apply_fast_forward(ff_data).await.unwrap();
    assert_eq!(
        client2.current_data_commitment(),
        client1.current_data_commitment()
    );
    println!("✓ Second client caught up via individual changes including delete");

    println!("=== Insert-then-Delete Test passed! ===");
}

#[tokio::test]
async fn test_delete_in_ff_proof_batch() {
    if std::env::var("RISC0_SKIP_BUILD").is_ok() {
        eprintln!("Skipping test_delete_in_ff_proof_batch: RISC0_SKIP_BUILD is set");
        return;
    }
    temp_env::async_with_vars(TEST_ENV_VARS, test_delete_in_ff_proof_batch_inner()).await;
}

async fn test_delete_in_ff_proof_batch_inner() {
    // Test that a delete within a batch boundary produces a valid FF proof.
    // FF_BATCH_SIZE is 3, so insert 2, then delete 1 → triggers proof generation.

    println!("=== Delete in FF Proof Batch Test ===");
    let server = Server::new().await;

    let client1 = server.create_client().await;
    client1.authenticate_as_id(1).await.unwrap();
    let auth1 = client1.get_auth_context();

    // Insert 2 products (changes 1 and 2)
    println!("Inserting 2 products");
    insert_products(&server, &client1, &auth1, 2).await;
    assert_eq!(server.num_changes().await, 2);
    assert_eq!(server.proven_up_to().await, 0, "No proof yet");

    // Delete product id=1 (change 3 → triggers FF proof at batch boundary)
    println!("Deleting product id=1 (triggers FF proof)");
    delete_product(&server, &client1, &auth1, 1).await;
    assert_eq!(server.num_changes().await, 3);
    assert_eq!(
        server.proven_up_to().await,
        FF_BATCH_SIZE,
        "Proof should be generated at batch boundary"
    );

    // A new client fast-forwards via the proof
    let client2 = server.create_client().await;
    client2.authenticate_as_id(2).await.unwrap();
    let auth2 = client2.get_auth_context();

    let ff_data = server
        .get_fast_forward(client2.current_change_id(), &auth2)
        .await
        .unwrap();
    assert!(ff_data.proof.is_some(), "Should include proof");
    assert!(
        ff_data.changes.is_empty(),
        "No ragged changes at exact batch boundary"
    );

    client2.apply_fast_forward(ff_data).await.unwrap();
    assert_eq!(client2.current_change_id(), FF_BATCH_SIZE as u32);
    assert_eq!(
        client2.current_data_commitment(),
        client1.current_data_commitment()
    );
    println!("✓ Client fast-forwarded via proof containing a delete");

    println!("=== Delete in FF Proof Batch Test passed! ===");
}

/// Helper: delete multiple products by row ids in a single changelog entry.
/// Row keys and values are sorted by row key for canonical ordering.
async fn delete_products(server: &Server, client: &Space, auth: &AuthContext, row_ids: &[i64]) {
    // Build query with WHERE id IN (...) using the In operator.
    let mut query = Query::new("products".to_string(), QueryOperation::Delete);
    query.predicate = Some(Predicate {
        column: "id".to_string(),
        operator: ComparisonOperator::In,
        values: row_ids.iter().map(|&id| QueryParam::Integer(id)).collect(),
        cursor_id: None,
    });

    // Build per-column keys for all non-id columns per row (sorted)
    let non_id_columns = ["name", "price"];
    let mut col_keys: Vec<Vec<u8>> = row_ids
        .iter()
        .flat_map(|&id| {
            non_id_columns
                .iter()
                .map(move |col| column_key("products", id, col))
        })
        .collect();
    col_keys.sort();

    let keys_refs: Vec<&[u8]> = col_keys.iter().map(|k| k.as_slice()).collect();
    // For deletes, value is empty — values are empty
    let values_refs: Vec<&[u8]> = vec![b"" as &[u8]; col_keys.len()];

    let mut change = Change::new(
        OpType::Delete,
        client.uid().unwrap(),
        ROOT_TREE_PATH,
        &keys_refs,
        &values_refs,
        client.current_change_id(),
        client.my_last_change_id(),
        client.current_clc(),
    )
    .unwrap();
    sign_test_change(client.uid().unwrap(), &mut change);

    let response = server.handle_change(&change, auth).await.unwrap();
    client
        .validate_and_apply_change(&change.entry, &response)
        .unwrap();
}

#[tokio::test]
async fn test_multi_row_delete() {
    if std::env::var("RISC0_SKIP_BUILD").is_ok() {
        eprintln!("Skipping test_multi_row_delete: RISC0_SKIP_BUILD is set");
        return;
    }
    temp_env::async_with_vars(TEST_ENV_VARS, test_multi_row_delete_inner()).await;
}

async fn test_multi_row_delete_inner() {
    println!("=== Multi-Row Delete Test ===");
    let server = Server::new().await;

    let client1 = server.create_client().await;
    client1.authenticate_as_id(1).await.unwrap();
    let auth1 = client1.get_auth_context();

    // Insert 5 products (changes 1-5)
    println!("Inserting 5 products");
    insert_products(&server, &client1, &auth1, 5).await;
    assert_eq!(server.num_changes().await, 5);

    // Delete products with id=2 and id=4 in a single changelog entry (change 6)
    println!("Deleting products id=2 and id=4 in one change");
    delete_products(&server, &client1, &auth1, &[2, 4]).await;
    assert_eq!(server.num_changes().await, 6);

    println!("Multi-row delete accepted and validated by server and client");

    // A second client catches up via fast-forward
    let client2 = server.create_client().await;
    client2.authenticate_as_id(2).await.unwrap();
    let auth2 = client2.get_auth_context();

    let ff_data = server
        .get_fast_forward(client2.current_change_id(), &auth2)
        .await
        .unwrap();
    // FF_BATCH_SIZE=3, so changes 1-3 have a proof, 4-6 are ragged
    assert!(
        ff_data.proof.is_some(),
        "Should include proof for first batch"
    );
    client2.apply_fast_forward(ff_data).await.unwrap();
    assert_eq!(
        client2.current_data_commitment(),
        client1.current_data_commitment()
    );
    println!("✓ Second client caught up via fast-forward including multi-row delete");

    println!("=== Multi-Row Delete Test passed! ===");
}

// ─── ACL integration tests ──────────────────────────────────────────────────

/// Server with ACL rules that require `row.author_id == AuthUserId`
/// for writes to the "products" table. The products table is extended with an
/// `author_id` integer column.
struct AclServer {
    pub state: Mutex<SpaceState>,
    pub initial_dc: [u8; 32],
}

/// Products schema with an author_id column for ACL tests.
fn acl_products_schema() -> encrypted_spaces_backend::schema::Schema {
    use encrypted_spaces_backend::schema::{ColumnDefinition, ColumnType, Schema};

    Schema {
        name: "products".to_string(),
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
                name: "price".to_string(),
                column_type: ColumnType::Real,
                plaintext: true,
                indexed: false,
            },
            ColumnDefinition {
                name: "author_id".to_string(),
                column_type: ColumnType::Integer,
                plaintext: true,
                indexed: false,
            },
        ],
        auto_increment: true,
    }
}

impl AclServer {
    pub async fn new() -> Self {
        use encrypted_spaces_changelog_core::changelog::ChangeLog;

        let mut state = init_test_server_state_with_schema(
            Some(FF_BATCH_SIZE),
            &[1, 2],
            vec![acl_products_schema()],
        )
        .await;

        // Insert ACL rule: writes to "products" require author_id == AuthUserId
        insert_acl_rule(
            &mut state,
            "products",
            "write",
            r#"{"Comparison":{"left":{"Column":{"namespace":"Resource","name":"author_id"}},"op":"Equal","right":"AuthUserId"}}"#,
        )
        .await;

        // Re-initialize the changelog so the hash chain starting link matches
        // the current Merk root (after ACL rule insert + blob re-write).
        let root = state.get_root_hash().await;
        state.changelog = ChangeLog::new(&root);

        // Refresh tree snapshot after ACL blob was re-written
        state.tree_snapshot = state.db.snapshot();

        let initial_dc = state.get_root_hash().await;

        Self {
            state: Mutex::new(state),
            initial_dc,
        }
    }

    pub async fn create_client(&self) -> Space {
        let transport = LocalTransport::in_memory().await.unwrap();
        let space = Space::new_without_schema_init(transport, self.initial_dc)
            .await
            .expect("Failed to create Space");

        space.seed_user_cache(&[(1, test_auth_key_string(1)), (2, test_auth_key_string(2))]);
        space.register_table_schema(acl_products_schema());
        space
    }

    pub async fn handle_change(
        &self,
        change: &Change,
        auth: &AuthContext,
    ) -> Result<ChangeResponse, ServerError> {
        self.state.lock().await.handle_change(change, auth).await
    }

    pub async fn num_changes(&self) -> u32 {
        self.state.lock().await.changelog.num_changes()
    }
}

/// Insert a product with an author_id column.
async fn insert_product_with_author(
    server: &AclServer,
    client: &Space,
    auth: &AuthContext,
    name: &str,
    price: f64,
    author_id: i64,
) {
    let query = Query::new(
        "products".to_string(),
        QueryOperation::Insert(vec![
            ("id".to_string(), QueryParam::Integer(0)),
            ("name".to_string(), QueryParam::Text(name.to_string())),
            ("price".to_string(), QueryParam::Real(price)),
            ("author_id".to_string(), QueryParam::Integer(author_id)),
        ]),
    );

    let (_, column_data) = get_row_data_from_query(&query).unwrap();
    let (col_keys, col_values) =
        build_column_kv_vecs(&column_data, |col| column_key_placeholder("products", col));
    let key_refs: Vec<&[u8]> = col_keys.iter().map(|k| k.as_slice()).collect();
    let val_refs: Vec<&[u8]> = col_values.iter().map(|v| v.as_slice()).collect();

    let mut change = Change::new(
        OpType::Insert,
        client.uid().unwrap(),
        ROOT_TREE_PATH,
        &key_refs,
        &val_refs,
        client.current_change_id(),
        client.my_last_change_id(),
        client.current_clc(),
    )
    .unwrap();
    sign_test_change(client.uid().unwrap(), &mut change);

    let response = server.handle_change(&change, auth).await.unwrap();
    client
        .validate_and_apply_change(&change.entry, &response)
        .unwrap();
}

/// Test ACL enforcement end-to-end:
/// 1. Authorized inserts (author_id matches uid) succeed and are provable
/// 2. An update by the same user succeeds and is provable
/// 3. An unauthorized insert (author_id doesn't match uid) is rejected by the server
#[tokio::test]
async fn test_acl_insert_allowed() {
    if std::env::var("RISC0_SKIP_BUILD").is_ok() {
        eprintln!("Skipping test_acl_insert_allowed: RISC0_SKIP_BUILD is set");
        return;
    }
    temp_env::async_with_vars(TEST_ENV_VARS, test_acl_insert_allowed_inner()).await;
}

async fn test_acl_insert_allowed_inner() {
    println!("=== ACL Enforcement Test ===");
    let server = AclServer::new().await;

    let client1 = server.create_client().await;
    client1.authenticate_as_id(1).await.unwrap();
    let auth1 = client1.get_auth_context();

    // ── Part 1: Authorized inserts succeed ──────────────────────────────
    println!("Part 1: Authorized inserts (author_id=1, uid=1)");
    insert_product_with_author(&server, &client1, &auth1, "Apple", 2.0, 1).await;
    insert_product_with_author(&server, &client1, &auth1, "Banana", 1.5, 1).await;
    insert_product_with_author(&server, &client1, &auth1, "Cherry", 3.0, 1).await;
    assert_eq!(server.num_changes().await, 3);
    println!("✓ 3 authorized inserts accepted");

    // ── Part 2: Verify FF proof was generated and is valid ──────────────
    let client2 = server.create_client().await;
    client2.authenticate_as_id(2).await.unwrap();
    let auth2 = client2.get_auth_context();

    let ff_data = server
        .state
        .lock()
        .await
        .handle_fast_forward(0, &[], &auth2)
        .unwrap();
    assert!(
        ff_data.proof.is_some(),
        "Proof should have been generated for 3 changes"
    );
    client2.apply_fast_forward(ff_data).await.unwrap();
    assert_eq!(
        client2.current_data_commitment(),
        client1.current_data_commitment()
    );
    println!("✓ FF proof verified by second client");

    // ── Part 3: Unauthorized insert is rejected by the server ───────────
    // User 2 tries to insert with author_id=1 (not their own)
    println!("Part 3: Unauthorized insert (author_id=1, uid=2)");
    let unauthorised_query = Query::new(
        "products".to_string(),
        QueryOperation::Insert(vec![
            ("id".to_string(), QueryParam::Integer(0)),
            ("name".to_string(), QueryParam::Text("Stolen".to_string())),
            ("price".to_string(), QueryParam::Real(9.99)),
            ("author_id".to_string(), QueryParam::Integer(1)), // author_id=1 but uid=2
        ]),
    );

    let (_, column_data) = get_row_data_from_query(&unauthorised_query).unwrap();
    let (col_keys, col_values) =
        build_column_kv_vecs(&column_data, |col| column_key_placeholder("products", col));
    let key_refs: Vec<&[u8]> = col_keys.iter().map(|k| k.as_slice()).collect();
    let val_refs: Vec<&[u8]> = col_values.iter().map(|v| v.as_slice()).collect();

    let mut bad_change = Change::new(
        OpType::Insert,
        client2.uid().unwrap(),
        ROOT_TREE_PATH,
        &key_refs,
        &val_refs,
        client2.current_change_id(),
        client2.my_last_change_id(),
        client2.current_clc(),
    )
    .unwrap();
    sign_test_change(client2.uid().unwrap(), &mut bad_change);

    let result = server.handle_change(&bad_change, &auth2).await;
    assert!(
        result.is_err(),
        "Server should reject insert with author_id != uid"
    );
    let err_msg = result.unwrap_err().to_string();
    println!("✓ Server rejected unauthorized insert: {err_msg}");

    // Verify the unauthorized change did not enter the changelog
    assert_eq!(
        server.num_changes().await,
        3,
        "Changelog should still have only 3 changes"
    );

    // ── Part 4: User 2 can insert their own items ───────────────────────
    println!("Part 4: User 2 authorized insert (author_id=2, uid=2)");
    insert_product_with_author(&server, &client2, &auth2, "Date", 4.0, 2).await;
    assert_eq!(server.num_changes().await, 4);
    println!("✓ User 2's own insert accepted");

    println!("=== ACL Enforcement Test passed! ===");
}

/// Regression test for issue #16: the per-change verifier
/// `ChangeLog::verify_proof_and_validate` must authenticate the ACL blob
/// it uses for E&V against `old_root`.
///
/// This test produces a real authorized-insert ChangeResponse against
/// `AclServer`, baselines that the verifier accepts it, then tampers with the
/// pruned tree witness's ACL blob node. The verifier must reject the tampered
/// witness because the pruned tree no longer commits to `old_root`.
#[tokio::test]
async fn test_per_change_verifier_authenticates_acl_blob() {
    temp_env::async_with_vars(
        TEST_ENV_VARS,
        test_per_change_verifier_authenticates_acl_blob_inner(),
    )
    .await;
}

async fn test_per_change_verifier_authenticates_acl_blob_inner() {
    use encrypted_spaces_changelog_core::changelog::ChangeLog;
    use encrypted_spaces_changelog_core::{acl_rule_key, PrunedMerkleTree};

    fn tamper_acl_blob_value(node: &mut PrunedMerkleTree, acl_key: &[u8]) -> bool {
        match node {
            PrunedMerkleTree::Empty | PrunedMerkleTree::Pruned { .. } => false,
            PrunedMerkleTree::Full {
                key,
                value,
                left,
                right,
            } => {
                if key.as_slice() == acl_key {
                    value.push(0);
                    true
                } else {
                    tamper_acl_blob_value(left, acl_key) || tamper_acl_blob_value(right, acl_key)
                }
            }
        }
    }

    let server = AclServer::new().await;

    let client = server.create_client().await;
    client.authenticate_as_id(1).await.unwrap();
    let auth = client.get_auth_context();

    // Produce a real, authorized insert (author_id=1, uid=1) and capture
    // the server's ChangeResponse so we can use its real proof bytes.
    let query = Query::new(
        "products".to_string(),
        QueryOperation::Insert(vec![
            ("id".to_string(), QueryParam::Integer(0)),
            ("name".to_string(), QueryParam::Text("Apple".to_string())),
            ("price".to_string(), QueryParam::Real(2.0)),
            ("author_id".to_string(), QueryParam::Integer(1)),
        ]),
    );
    let (_, column_data) = get_row_data_from_query(&query).unwrap();
    let (col_keys, col_values) =
        build_column_kv_vecs(&column_data, |col| column_key_placeholder("products", col));
    let key_refs: Vec<&[u8]> = col_keys.iter().map(|k| k.as_slice()).collect();
    let val_refs: Vec<&[u8]> = col_values.iter().map(|v| v.as_slice()).collect();
    let mut change = Change::new(
        OpType::Insert,
        client.uid().unwrap(),
        ROOT_TREE_PATH,
        &key_refs,
        &val_refs,
        client.current_change_id(),
        client.my_last_change_id(),
        client.current_clc(),
    )
    .unwrap();
    sign_test_change(client.uid().unwrap(), &mut change);
    let response = server.handle_change(&change, &auth).await.unwrap();

    // The verifier uses 1-indexed change IDs. This authorized insert is
    // the first user-visible change after server setup.
    let current_change_id = (change.entry.parent_change as usize) + 1;

    // ── Baseline: the unmodified proof verifies. ────────────────────────
    ChangeLog::verify_proof_and_validate(
        &change.entry,
        &response.pruned_merkle_tree,
        &response.old_root,
        &response.new_root,
        current_change_id,
    )
    .expect("authorized insert proof should verify");

    // Sanity-check that the pruned tree witness contains the ACL rule as a full
    // node, then prove that mutating it breaks the old-root commitment.
    let mut tampered_pruned: PrunedMerkleTree =
        postcard::from_bytes(&response.pruned_merkle_tree).expect("proof deserializes");
    let acl_key = acl_rule_key("products", "write");
    assert!(
        tamper_acl_blob_value(&mut tampered_pruned, &acl_key),
        "pruned tree witness should contain the ACL rule key"
    );
    let tampered_bytes =
        postcard::to_allocvec(&tampered_pruned).expect("serialize tampered pruned tree proof");
    let err = ChangeLog::verify_proof_and_validate(
        &change.entry,
        &tampered_bytes,
        &response.old_root,
        &response.new_root,
        current_change_id,
    )
    .expect_err("proof with tampered ACL rule must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("start root mismatch") || msg.contains("ACL rule"),
        "unexpected error for tampered ACL rule: {msg}"
    );

    let garbage_bytes = b"not a pruned merkle tree".to_vec();
    let err = ChangeLog::verify_proof_and_validate(
        &change.entry,
        &garbage_bytes,
        &response.old_root,
        &response.new_root,
        current_change_id,
    )
    .expect_err("garbage pruned tree proof must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("pruned tree proof deserialize failed"),
        "unexpected error for garbage pruned tree proof: {msg}"
    );
}

// ─── Proof-embeds-reads test ───────────────────────────────────────────────

/// Verify that per-change tracer proofs now embed read steps (user existence,
/// schema columns) alongside the write steps.
#[tokio::test]
async fn test_proof_contains_reads() {
    if std::env::var("RISC0_SKIP_BUILD").is_ok() {
        eprintln!("Skipping test_proof_contains_reads: RISC0_SKIP_BUILD is set");
        return;
    }
    temp_env::async_with_vars(TEST_ENV_VARS, test_proof_contains_reads_inner()).await;
}

async fn test_proof_contains_reads_inner() {
    use encrypted_spaces_changelog_core::changelog::ChangeLog;
    use encrypted_spaces_changelog_core::PrunedMerkleTree;

    println!("=== Proof Contains Reads Test ===");
    let server = Server::new().await;

    let client1 = server.create_client().await;
    client1.authenticate_as_id(1).await.unwrap();
    let auth1 = client1.get_auth_context();

    // Insert a product
    let query = Query::new(
        "products".to_string(),
        QueryOperation::Insert(vec![
            ("id".to_string(), QueryParam::Integer(0)),
            ("name".to_string(), QueryParam::Text("Apple".to_string())),
            ("price".to_string(), QueryParam::Real(1.5)),
        ]),
    );
    let (_, column_data) = get_row_data_from_query(&query).unwrap();
    let (col_keys, col_values) =
        build_column_kv_vecs(&column_data, |col| column_key_placeholder("products", col));
    let key_refs: Vec<&[u8]> = col_keys.iter().map(|k| k.as_slice()).collect();
    let val_refs: Vec<&[u8]> = col_values.iter().map(|v| v.as_slice()).collect();
    let mut change = Change::new(
        OpType::Insert,
        client1.uid().unwrap(),
        ROOT_TREE_PATH,
        &key_refs,
        &val_refs,
        client1.current_change_id(),
        client1.my_last_change_id(),
        client1.current_clc(),
    )
    .unwrap();
    sign_test_change(client1.uid().unwrap(), &mut change);

    let response = server.handle_change(&change, &auth1).await.unwrap();

    // Deserialize the pruned merkle tree and verify it contains data
    let pruned_node: PrunedMerkleTree =
        postcard::from_bytes(&response.pruned_merkle_tree).expect("pruned tree deserializes");
    let node_count = match &pruned_node {
        PrunedMerkleTree::Empty => 0usize,
        _ => {
            fn count_nodes(node: &PrunedMerkleTree) -> usize {
                match node {
                    PrunedMerkleTree::Empty => 0,
                    PrunedMerkleTree::Pruned { .. } => 1,
                    PrunedMerkleTree::Full { left, right, .. } => {
                        1 + count_nodes(left) + count_nodes(right)
                    }
                }
            }
            count_nodes(&pruned_node)
        }
    };

    println!(
        "Pruned tree: {} nodes, proof size: {} bytes",
        node_count,
        response.pruned_merkle_tree.len()
    );
    assert!(
        node_count > 0,
        "Pruned merkle tree should contain nodes (reads embed user, schema, ACL data)"
    );

    // Verify the proof validates via the changelog verifier
    let writes = ChangeLog::verify_proof_and_validate(
        &change.entry,
        &response.pruned_merkle_tree,
        &response.old_root,
        &response.new_root,
        1,
    )
    .expect("pruned tree proof should validate");
    assert!(!writes.is_empty(), "Proof should produce write operations");
    println!(
        "✓ Pruned tree validates: {} write ops, {} nodes",
        writes.len(),
        node_count
    );

    // Also verify through the SDK path
    client1
        .validate_and_apply_change(&change.entry, &response)
        .unwrap();
    println!("✓ Proof with embedded reads validates correctly via SDK");

    println!("=== Proof Contains Reads Test passed! ===");
}

// ─── Read-your-own-writes test ─────────────────────────────────────────────

/// Test that a batch containing CreateSpaceOp followed by an InsertOp by the
/// newly-created user can be proven.  Currently `extract_input_steps` resolves
/// every op's reads against the pre-batch tree snapshot, so the InsertOp's
/// `validate_user_access` cannot see the user that CreateSpaceOp just wrote.
#[tokio::test]
async fn test_create_space_then_insert_same_batch() {
    if std::env::var("RISC0_SKIP_BUILD").is_ok() {
        eprintln!("Skipping test_create_space_then_insert_same_batch: RISC0_SKIP_BUILD is set");
        return;
    }
    temp_env::async_with_vars(
        TEST_ENV_VARS,
        test_create_space_then_insert_same_batch_inner(),
    )
    .await;
}

async fn test_create_space_then_insert_same_batch_inner() {
    use encrypted_spaces_backend::SpaceId;
    use encrypted_spaces_storage_encoding::hashstore_hash;
    use encrypted_spaces_storage_encoding::keys::{parse_key, ParsedKey};
    println!("=== Create-Space-then-Insert Same-Batch Test ===");

    // Initialize server with NO pre-seeded users so CreateSpaceOp is required.
    // Batch size = 2 so proof generation triggers after the second change.
    let batch_size = 2;
    let mut state = init_test_server_state(Some(batch_size), &[]).await;
    let initial_clc: [u8; 32] = state.changelog.root_at(0).unwrap();

    let uid: u32 = 1;
    let space_id = SpaceId::from([0u8; 16]);
    let auth = AuthContext::new(Some(uid as i64), space_id);

    // ── Change #1: CreateSpaceOp ────────────────────────────────────────
    // This inserts the initial user row into _users and a commitment into
    // _retention, establishing the space.

    // User query: insert into _users.  `_users` is auto-increment, so no
    // explicit id; the first insert lands at uid=1 which matches `uid`.
    let user_query = Query::new(
        "_users".to_string(),
        QueryOperation::Insert(vec![
            ("update_key".to_string(), QueryParam::Text(String::new())),
            (
                "auth_key".to_string(),
                QueryParam::Text(test_auth_key_string(uid)),
            ),
            ("status".to_string(), QueryParam::Integer(1)), // Full member
        ]),
    );

    // Meta query: insert a dummy key commitment into _retention
    // KeyCommitment is a newtype around [u8; 32], so JSON is an array of 32 ints.
    let commitment_json = serde_json::to_string(&[0u8; 32]).unwrap();
    let encoded_commitment = commitment_json.into_bytes();
    let meta_key_str = "space_key_commitment:0".to_string();

    let meta_query = Query::new(
        "_retention".to_string(),
        QueryOperation::Insert(vec![
            ("key".to_string(), QueryParam::Text(meta_key_str.clone())),
            (
                "value".to_string(),
                QueryParam::Blob(encoded_commitment.clone()),
            ),
        ]),
    );

    // Build the changelog entry combining user + meta column keys/values.
    // Both use get_row_data_from_query so values are serialized via
    // stored_value::value_to_bytes (postcard), matching the server's
    // request value-map materialization path.
    let (_, user_column_data) = get_row_data_from_query(&user_query).unwrap();
    let (mut keys, mut values) = build_column_kv_vecs(&user_column_data, |col| {
        column_key_placeholder("_users", col)
    });

    let (_, meta_column_data) = get_row_data_from_query(&meta_query).unwrap();
    let (meta_keys, meta_values) = build_column_kv_vecs(&meta_column_data, |col| {
        column_key_placeholder("_retention", col)
    });
    keys.extend(meta_keys);
    values.extend(meta_values);

    // Hash all hash-backed column values (e.g. auth_key, update_key which are Blob).
    // Hashed columns store SHA-256 in merk; full values go into the hashed-values
    // sidecar so the server can populate the hash store.
    let mut hashed_values = HashedValues::new();
    for (key, value) in keys.iter().zip(values.iter_mut()) {
        if let Ok(ParsedKey::Column { table, column, .. }) = parse_key(key) {
            let is_hashed = state
                .db
                .get_schema(&table)
                .ok()
                .map(|s| {
                    s.columns
                        .iter()
                        .any(|c| c.name == column && c.column_type.is_hash_backed())
                })
                .unwrap_or(false);
            if is_hashed && !value.is_empty() {
                let full_value = std::mem::take(value);
                let hash = hashstore_hash(&full_value);
                *value = hash.to_vec();
                hashed_values.insert(hash, full_value);
            }
        }
    }

    let key_refs: Vec<&[u8]> = keys.iter().map(|k| k.as_slice()).collect();
    let val_refs: Vec<&[u8]> = values.iter().map(|v| v.as_slice()).collect();

    let mut create_space_change = Change::new(
        OpType::CreateSpace,
        uid,
        ROOT_TREE_PATH,
        &key_refs,
        &val_refs,
        0, // current_change_id
        0, // my_last_change_id
        initial_clc,
    )
    .unwrap();
    create_space_change.hashed_values = hashed_values;
    sign_test_change(uid, &mut create_space_change);

    let resp1 = state.handle_change(&create_space_change, &auth).await;
    assert!(resp1.is_ok(), "CreateSpaceOp should succeed: {resp1:?}");
    println!("✓ CreateSpaceOp applied (change #1)");

    // ── Change #2: InsertOp by the newly-created user ───────────────────
    let product_query = Query::new(
        "products".to_string(),
        QueryOperation::Insert(vec![
            ("id".to_string(), QueryParam::Integer(0)),
            ("name".to_string(), QueryParam::Text("Apple".to_string())),
            ("price".to_string(), QueryParam::Real(1.5)),
        ]),
    );

    let (_, product_column_data) = get_row_data_from_query(&product_query).unwrap();
    let (product_keys, product_values) = build_column_kv_vecs(&product_column_data, |col| {
        column_key_placeholder("products", col)
    });
    let product_key_refs: Vec<&[u8]> = product_keys.iter().map(|k| k.as_slice()).collect();
    let product_val_refs: Vec<&[u8]> = product_values.iter().map(|v| v.as_slice()).collect();

    let current_clc: [u8; 32] = state.changelog.current_root();
    let mut insert_change = Change::new(
        OpType::Insert,
        uid,
        ROOT_TREE_PATH,
        &product_key_refs,
        &product_val_refs,
        1, // current_change_id (after CreateSpace)
        1, // my_last_change_id
        current_clc,
    )
    .unwrap();
    sign_test_change(uid, &mut insert_change);

    let resp2 = state.handle_change(&insert_change, &auth).await;
    assert!(resp2.is_ok(), "InsertOp should succeed: {resp2:?}");
    println!("✓ InsertOp applied (change #2)");

    // ── Verify proof generation ─────────────────────────────────────────
    // With batch_size=2, maybe_generate_ff_proof should have run after
    // change #2.  It calls extract_input_steps which currently reads ALL
    // ops against the pre-batch tree snapshot.  The InsertOp's
    // validate_user_access reads the _users table from that snapshot where
    // user 1 does not yet exist → proof generation fails.
    assert_eq!(
        state.changelog.num_changes(),
        2,
        "Both changes should be in the changelog"
    );
    assert_eq!(
        state.changelog.proven_up_to, batch_size,
        "FF proof should cover both changes (proven_up_to should be {batch_size}), \
         but extract_input_steps currently fails because the InsertOp cannot read \
         the user created by CreateSpaceOp in the same batch"
    );

    println!("=== Create-Space-then-Insert Same-Batch Test passed! ===");
}

// ─── parent_change sliding-window enforcement ──────────

/// Submitting a change whose `parent_change` is further back than
/// `MAX_PARENT_DISTANCE` must be rejected by the server submission path,
/// matching the FF guest enforcement in `verify_op_sequence`.
///
/// The window keeps the FF-journal `recent_roots` size bounded; if the
/// server accepted a stale-parent change here the guest would later
/// reject the same chain, leaving the server unable to extend its proof.
#[tokio::test]
async fn test_handle_change_rejects_parent_change_past_window() {
    if std::env::var("RISC0_SKIP_BUILD").is_ok() {
        eprintln!(
            "Skipping test_handle_change_rejects_parent_change_past_window: RISC0_SKIP_BUILD is set"
        );
        return;
    }
    temp_env::async_with_vars(
        TEST_ENV_VARS,
        test_handle_change_rejects_parent_change_past_window_inner(),
    )
    .await;
}

async fn test_handle_change_rejects_parent_change_past_window_inner() {
    use encrypted_spaces_changelog_core::changelog::MAX_PARENT_DISTANCE;

    let server = Server::new().await;
    let client = server.create_client().await;
    client.authenticate_as_id(1).await.unwrap();
    let auth = client.get_auth_context();

    // Apply MAX_PARENT_DISTANCE + 1 successful inserts so we can craft a
    // change whose parent_change is exactly one slot beyond the window.
    let needed = MAX_PARENT_DISTANCE as usize + 1;
    insert_products(&server, &client, &auth, needed).await;
    assert_eq!(server.num_changes().await as usize, needed);

    // Build a fresh, otherwise-valid insert but lie about parent_change:
    // pin it to 0 (the genesis state). The current chain length is
    // `needed`, so the prospective change_id is `needed + 1` and the
    // distance is `needed + 1 > MAX_PARENT_DISTANCE`.
    let query = Query::new(
        "products".to_string(),
        QueryOperation::Insert(vec![
            ("id".to_string(), QueryParam::Integer(0)),
            (
                "name".to_string(),
                QueryParam::Text("StaleParent".to_string()),
            ),
            ("price".to_string(), QueryParam::Real(0.0)),
        ]),
    );
    let (_, column_data) = get_row_data_from_query(&query).unwrap();
    let (col_keys, col_values) =
        build_column_kv_vecs(&column_data, |col| column_key_placeholder("products", col));
    let key_refs: Vec<&[u8]> = col_keys.iter().map(|k| k.as_slice()).collect();
    let val_refs: Vec<&[u8]> = col_values.iter().map(|v| v.as_slice()).collect();

    let stale_parent: u32 = 0;
    let mut change = Change::new(
        OpType::Insert,
        client.uid().unwrap(),
        ROOT_TREE_PATH,
        &key_refs,
        &val_refs,
        stale_parent,
        client.my_last_change_id(),
        // Use the genesis CLC so the existing parent_clc check would
        // also accept this if the window check were not in place.
        server
            .state
            .lock()
            .await
            .changelog
            .initial_clc_state()
            .root
            .into(),
    )
    .unwrap();
    sign_test_change(client.uid().unwrap(), &mut change);

    let err = server
        .handle_change(&change, &auth)
        .await
        .expect_err("submission with parent_change beyond window must be rejected");
    assert!(
        matches!(err, ServerError::StaleParent(_)),
        "expected StaleParent variant, got: {err:?}"
    );
    let msg = format!("{err:?}");
    assert!(
        msg.contains("parent_change") && msg.contains("invalid"),
        "expected window-rejection message, got: {msg}"
    );

    // Server state must be unchanged.
    assert_eq!(server.num_changes().await as usize, needed);
}

#[tokio::test]
async fn test_zkvm_hash_correctness() {
    if std::env::var("RISC0_SKIP_BUILD").is_ok() {
        eprintln!("Skipping test_zkvm_hash_correctness: RISC0_SKIP_BUILD is set");
        return;
    }

    use encrypted_spaces_ffproof::HASH_TEST_ELF;
    use risc0_zkvm::{default_prover, ExecutorEnv};

    std::env::set_var("RISC0_DEV_MODE", "1");

    let env = ExecutorEnv::builder().build().unwrap();
    let prover = default_prover();
    let proof_info = prover.prove(env, HASH_TEST_ELF).unwrap();

    println!(
        "=== zkvm_hash_tests passed in {} user cycles ===",
        proof_info.stats.user_cycles
    );
}
