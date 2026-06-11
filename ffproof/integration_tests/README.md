# Fast-Forward Integration Tests

This crate exercises the fast-forward proof path against the same server and SDK
types used by the rest of the prototype. The tests run entirely in-process: a
`SpaceState` stands in for the server, SDK `Space` instances stand in for
clients, and the test harness calls the server handlers directly instead of
using WebSockets.

The goal is to verify that a client can trust the data commitment and changelog
state it reaches through either per-change validation or a fast-forward proof.
At a high level, the tests cover normal client writes, clients catching up from
different changelog positions, proof-backed replay of database state, and the
security checks needed to reject invalid or stale changelog data.

Most tests use a small FF batch size so proof-generation boundaries are reached
quickly. Clients that are kept current validate each `ChangeResponse` directly;
clients that fall behind call `apply_fast_forward` on the `FastForwardData`
returned by the server.

## Running the Tests

From the repository root:

```bash
cargo test -p encrypted-spaces-ff-test
```

By default the fast proof path uses RISC Zero dev-mode receipts unless the
workspace is built with the real-proof feature. That keeps normal test runs
fast while still exercising the guest input construction and verification path.
The tests set useful RISC Zero logging variables internally.

To run a single test with output:

```bash
cargo test -p encrypted-spaces-ff-test test_nontrivial_ff -- --nocapture
```

If you are intentionally building without the RISC Zero guest artifacts, set
`RISC0_SKIP_BUILD=1`. The proof-dependent tests detect that variable and skip
themselves.

```bash
RISC0_SKIP_BUILD=1 cargo test -p encrypted-spaces-ff-test
```

To exercise real RISC Zero proofs, enable the passthrough feature:

```bash
cargo test -p encrypted-spaces-ff-test --features real-proofs
```

Real proof generation is much slower than dev mode. Use a CUDA-capable prover
when measuring real proving cost:

```bash
cargo test -p encrypted-spaces-ff-test --features real-proofs,cuda
```

## Benchmarks

This crate also contains Criterion benchmark targets for proof costs and proof
payload sizes. Common entry points are:

```bash
# RISC0 user-cycle benchmarks for fast-forward workloads
cargo bench -p encrypted-spaces-ff-test --bench ff_cycle_benchmarks

# Wall-clock proving benchmarks for realistic table/list workloads
cargo bench -p encrypted-spaces-ff-test --bench ff_time_benchmarks

# Per-change pruned tree witness sizes
cargo bench -p encrypted-spaces-ff-test --bench update_proof_size_benchmarks

# SELECT query proof sizes
cargo bench -p encrypted-spaces-ff-test --bench select_proof_size_benchmarks

# Action-layer proof size and cycle benchmarks
cargo bench -p encrypted-spaces-ff-test --bench action_proof_size_benchmarks
cargo bench -p encrypted-spaces-ff-test --bench action_cycle_benchmarks
```

For real wall-clock proof measurements, use:

```bash
cargo bench -p encrypted-spaces-ff-test --bench ff_time_benchmarks \
   --features real-proofs,cuda
```

`ff_profile` is a CLI-style bench that runs the realistic fast-forward
workloads with RISC Zero pprof output enabled and prints `go tool pprof`
commands for inspecting the generated profiles:

```bash
cargo bench -p encrypted-spaces-ff-test --bench ff_profile
```
