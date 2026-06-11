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

fn sample_input() -> [KoalaBear; POSEIDON2_16_WIDTH] {
    core::array::from_fn(|i| KoalaBear::new(i as u32 + 1))
}

fn build_relation_instance_and_witness(
    permutation: KoalaBearPoseidon2_16,
    input: [KoalaBear; POSEIDON2_16_WIDTH],
    public_outputs: &[(usize, KoalaBear)],
) -> (
    PermutationInstanceBuilder<KoalaBear, POSEIDON2_16_WIDTH>,
    PermutationWitnessBuilder<KoalaBearPoseidon2_16, POSEIDON2_16_WIDTH>,
) {
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
        public_outputs.iter().map(|(_, val)| *val),
    );

    instance.add_equation(LinearEquation::new(
        [(KoalaBear::new(1), output_vars[0])],
        output_vals[0],
    ));
    witness.add_equation(LinearEquation::new(
        [(KoalaBear::new(1), output_vals[0])],
        output_vals[0],
    ));
    (instance, witness)
}

#[test]
fn poseidon2_16_relation_proof_and_false_checks() {
    let backend = KoalaBearPoseidon2_16::new();
    let permutation = backend.permutation();

    let input = sample_input();
    let expected_output = permutation.permute(&input);
    let public_outputs = vec![
        (1usize, expected_output[1]),
        (2usize, expected_output[2]),
        (3usize, expected_output[3]),
    ];

    let (instance, witness) =
        build_relation_instance_and_witness(permutation.clone(), input, &public_outputs);

    let statement = PreparedRelation::new(&backend, &instance);
    let prepared_witness = statement.prepare_witness(&witness);
    let proof = statement.prove(&backend, &prepared_witness);

    assert!(statement.verify(&backend, &proof).is_ok());

    let mut bad_proof = proof.clone();
    bad_proof[0] ^= 0x01;
    assert!(statement.verify(&backend, &bad_proof).is_err());

    let bad_public_outputs = vec![
        (1usize, expected_output[1] + KoalaBear::new(1)),
        (2usize, expected_output[2]),
        (3usize, expected_output[3]),
    ];
    let (bad_instance, _) =
        build_relation_instance_and_witness(permutation, input, &bad_public_outputs);
    let bad_relation = PreparedRelation::new(&backend, &bad_instance);
    assert!(bad_relation.verify(&backend, &proof).is_err());

    let mut shifted_proof = proof;
    shifted_proof.insert(0, 0x00);
    assert!(statement.verify(&backend, &shifted_proof).is_err());
}
