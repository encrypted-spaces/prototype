//! Fixed-seed smoke test for the SDK fuzzer.
//!
//! Excluded from CI by virtue of `encrypted-spaces-sdk-fuzzer` not being in
//! `CI_PACKAGES` (see `.github/workflows/build-prototype.yml`). Run on
//! demand with `cargo test -p encrypted-spaces-sdk-fuzzer`.

use encrypted_spaces_sdk::{LocalTransport, Space};
use encrypted_spaces_sdk_fuzzer::{
    executor, is_known_acl_infra_error,
    model::{Actor, FuzzOp, ModelState},
};
use rand::{rngs::StdRng, Rng, SeedableRng};

const HOST_UID: i64 = 1;

async fn run_seed(seed: u64, ops_per_iter: usize) {
    let mut rng = StdRng::seed_from_u64(seed);

    let host_transport = LocalTransport::in_memory()
        .await
        .expect("LocalTransport::in_memory");
    let host_space = Space::new(host_transport.clone())
        .await
        .expect("Space::new");
    host_space
        .authenticate_as_id(HOST_UID)
        .await
        .expect("authenticate_as_id host");

    let mut model = ModelState::new(Actor {
        uid: HOST_UID,
        space: host_space,
    });

    let bootstrap_tables = rng.random_range(2..=4);
    for _ in 0..bootstrap_tables {
        executor::step_force(&mut rng, &mut model, &host_transport, FuzzOp::CreateTable)
            .await
            .expect("bootstrap CreateTable");
    }
    // ACL rule installation goes through the same baseline-resetting code
    // path as `create_table`, so it must run before any tracked changes.
    executor::install_bootstrap_acl_rules(&mut rng, &mut model)
        .await
        .expect("bootstrap install_acl_rules");

    for _ in 0..3 {
        match executor::step_force(&mut rng, &mut model, &host_transport, FuzzOp::Insert).await {
            Ok(()) => {}
            Err(e) if is_known_acl_infra_error(&e) => return,
            Err(e) => panic!("bootstrap Insert failed: {e:?}"),
        }
    }

    for op_index in 0..ops_per_iter {
        match executor::step(&mut rng, &mut model, &host_transport).await {
            Ok(_) => {}
            Err(e) if is_known_acl_infra_error(&e) => return,
            Err(e) => panic!("seed={seed} op_index={op_index} returned SdkError: {e:?}"),
        }
    }
}

#[tokio::test]
async fn fuzz_smoke_seeds() {
    // Fixed seeds so a regression always reproduces.
    for seed in [1u64, 7, 13, 21, 42] {
        run_seed(seed, 50).await;
    }
}
