# spongefish-stark

`spongefish-stark` allows to prove circuits built with the `spongefish` ecosystem
using [Plonky3](https://github.com/Plonky3).

This is a locally maintained vendored copy. See [VENDOR.md](VENDOR.md) for its
upstream revision and the security-sensitive local changes.

The `relation` module proves generic statements about hash preimages:
public limbs, reused secret inputs, sponge modes, and runtime-width linear equations.

The crate ships with backend presets for Poseidon2 and Keccak-f[1600].
Field-specific proof configuration lives under `fields`, and hash permutation
backends live under `permutation`.

All supported hash and fields are enabled by default. Tests can be run with

```bash
cargo test
```

## Example

A small example can be run with: 

```bash
cargo run --example poseidon2
```

To build a relation instance for `Poseidon2` we can use [`spongefish_circuit`](https://github.com/arkworks-rs/spongefish)'s
[`PermutationWitnessBuilder`](https://docs.rs/spongefish-circuit/latest/spongefish_circuit/permutation/struct.PermutationWitnessBuilder.html)
and
[`PermutationInstanceBuilder`](https://docs.rs/spongefish-circuit/latest/spongefish_circuit/permutation/struct.PermutationInstanceBuilder.html).
The backend supplies only proof components: the Plonky3 config, hash AIR, and
executable permutation. Instance and witness builders remain explicit.

```rust
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use spongefish::Permutation;
use spongefish_circuit::permutation::{PermutationInstanceBuilder, PermutationWitnessBuilder};
use spongefish_stark::{
    permutation::poseidon2::{KoalaBearPoseidon2_16, POSEIDON2_16_WIDTH},
    HashRelationBackend,
};

let backend = KoalaBearPoseidon2_16::new();
let permutation = backend.permutation();
let instance = PermutationInstanceBuilder::<KoalaBear, POSEIDON2_16_WIDTH>::new();
let witness =
    PermutationWitnessBuilder::<KoalaBearPoseidon2_16, POSEIDON2_16_WIDTH>::new(permutation.clone());

let input = core::array::from_fn(|i| KoalaBear::from_usize(i + 1));
let expected_output = permutation.permute(&input);
let input_vars = instance
    .allocator()
    .allocate_public::<POSEIDON2_16_WIDTH>(&input);
let output_vars = instance.allocate_permutation(&input_vars);
let _output_vals = witness.allocate_permutation(&input);

instance.allocator().set_public_vars(
    [1usize, 2, 3].into_iter().map(|idx| output_vars[idx]),
    [expected_output[1], expected_output[2], expected_output[3]],
);
```

Once the statement and witness are built, prepare the relation, prepare the
witness against it, and prove or verify through the prepared relation.

```rust
use spongefish_stark::relation::PreparedRelation;

let relation = PreparedRelation::new(&backend, &instance);
let witness = relation.prepare_witness(&witness);
let proof = relation.prove(&backend, &witness);
relation.verify(&backend, &proof)?;
# Ok::<(), spongefish::VerificationError>(())
```

`PreparedRelation::new` derives the minimum trace height required by the
backend's hiding PCS from its security profile and challenge field, then
normalizes the symbolic relation and witness to that height. Callers do not
need to select a row count or validate the encoded proof degree.

Custom AIRs can use `KoalaBearConfig::<Conservative>::prepare_air` with an
explicit `AirTracePadding` contract. The resulting `PreparedAir` derives the
padded height required by the selected profile's hiding PCS, pads main and
preprocessed rows together, and keeps exact statement-degree binding inside
this crate. Padding remains explicit because a strategy such as `RepeatLast`
is valid only when the AIR's row and transition semantics permit it.

The conservative opening budget is `wt + 2d`, where `t` is the number of FRI
queries, `d` is the challenge-field extension degree, and `w = MAX_ROW_WINDOW`
is currently 2. The `wt` term covers query evaluations across the row window;
the `2d` term covers the current protocol's two out-of-domain opening points.
The minimum trace height rounds this budget up to a power of two. Debug builds
check the AIR's main/preprocessed next-row metadata and lookup interactions
against this limit. Since that metadata currently distinguishes only one-row
and two-row constraints, they also check Plonky3's declared
`AirBuilder::WINDOW`. Wider windows require re-evaluating the hiding budget,
not just increasing the constant.

See [`examples/poseidon2.rs`](examples/poseidon2.rs) for a
complete executable example with a linear equation.


## Soundness tuning

Run the configured security-profile sweep with:

```bash
cargo bench --bench security_profile_sweep --features poseidon2,p3-koala-bear
```

The benchmark sweeps candidate security profiles, including eta choices for the selected soundness regime, measures proving time and proof size for each case, and writes the results to `target/soundness.csv`.
