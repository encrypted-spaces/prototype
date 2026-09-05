use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use spongefish::Permutation;
use spongefish_circuit::permutation::{
    LinearEquation, PermutationInstanceBuilder, PermutationWitnessBuilder,
};
use spongefish_stark::{
    permutation::poseidon2::{KoalaBearPoseidon2_16, POSEIDON2_16_WIDTH},
    relation::PreparedRelation,
    HashRelationBackend,
};

fn main() {
    let backend = KoalaBearPoseidon2_16::new();
    let permutation = backend.permutation();

    let input = core::array::from_fn(|i| KoalaBear::from_usize(i + 1));
    let expected_output = permutation.permute(&input);
    let public_outputs = [
        (1usize, expected_output[1]),
        (2usize, expected_output[2]),
        (3usize, expected_output[3]),
    ];

    let instance = PermutationInstanceBuilder::<KoalaBear, POSEIDON2_16_WIDTH>::new();
    let witness =
        PermutationWitnessBuilder::<KoalaBearPoseidon2_16, POSEIDON2_16_WIDTH>::new(permutation);

    let input_vars = instance
        .allocator()
        .allocate_public::<POSEIDON2_16_WIDTH>(&input);
    let output_vars = instance.allocate_permutation(&input_vars);
    let output_vals = witness.allocate_permutation(&input);

    instance.allocator().set_public_vars(
        public_outputs.iter().map(|(idx, _)| output_vars[*idx]),
        public_outputs.iter().map(|(_, value)| *value),
    );

    // Add a simple width-1 linear constraint so the relation includes both
    // hash lookups and linear equations.
    instance.add_equation(LinearEquation::new(
        [(KoalaBear::ONE, output_vars[0])],
        output_vals[0],
    ));
    witness.add_equation(LinearEquation::new(
        [(KoalaBear::ONE, output_vals[0])],
        output_vals[0],
    ));

    let relation = PreparedRelation::new(&backend, &instance);
    let witness = relation.prepare_witness(&witness);
    let proof = relation.prove(&backend, &witness);

    relation
        .verify(&backend, &proof)
        .expect("proof should verify");

    println!(
        "verified a Poseidon2 relation proof ({} bytes)",
        proof.len()
    );
}
