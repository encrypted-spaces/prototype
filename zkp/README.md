# encrypted-spaces-zkp

`encrypted-spaces-zkp` is the layer that turns protocol claims into concrete proof
statements and verifies them. 
The crate uses a specialized proof system rather than a generic VM. 

It hosts the zero-knowledge statement builders, witness generation procedures,
and proof-system integration used by `encrypted-spaces-keymaker`.


The crate sits on top of:

- Plonky3 for AIR/STARK/FRI components
- spongefish for permutation interfaces, Fiat-Shamir plumbing, and symbolic
  circuit recording
- the Encrypted Spaces crypto layer for key derivation, commitments, and mKEM
  primitives

## Organization

The current crate surface is organized around a few proof-oriented modules:

- `transitions`: transition proofs over key-derivation statements such as
  commitments, derivations, and encryptions
- `mve`: multi-recipient verifiable encryption proofs
- `air`: AIR helpers for hash/preimage statements
- `poseidon2`: Poseidon2-related proof configuration used by the crate
- `errors`: proof verification and decryption error types

In particular, `transitions` is the public interface for proving and verifying
statements about key evolution:

```rust
pub fn prove_transition(...)
pub fn verify_transition(...)
```

## Transition Statements

Statements about key management are expressed as:

1. a list of linear equations over symbolic wires
2. permutation query/answer pairs
3. a map from public field elements to symbolic wire variables

At the API level, key-management statements are written as a sequence of
transition operations:

```rust
use encrypted_spaces_crypto::fade::transition::KeyTreeTransition;

let mut transition = KeyTreeTransition::new();
transition
    .commit(root_id.clone(), root_commitment)
    .derive(root_id.clone(), child_id.clone(), tag)
    .commit(child_id.clone(), child_commitment);
```

The crate lowers those statements into constraints of the form:

- `Commit(key, C)`: `C` is the commitment to the secret key material
- `Derive(parent, child, tag)`: `child` is obtained by constraining the parent
  key under `tag`
- `Encrypt(key, parent, tag, ctx)`: `ctx` is the linear combination of the
  target key and the derived key under `tag`

Internally, constraints are recorded through a symbolic allocator and then
translated into spongefish-stark relations over:

- hash input/output lookups
- repeated secret-input consistency checks
- public-wire checks
- fixed-width linear equations

This restricted model is much narrower than a general-purpose zkVM, but it is
also much cheaper to build and verify for the proof statements this crate cares
about.

## Relation Building

The `transitions` module compiles a `KeyTreeTransition` into a relation over a
Poseidon2 width-16 permutation.

Conceptually, the crate builds symbolic state vectors like:

```rust
let allocator = instance.allocator();
let tag_vars = allocator.allocate_public::<4>(&tag_limbs);
let mut input = [FieldVar::ZERO; 16];
input[HASHBLOCK_KEY_RANGE].clone_from_slice(key_vars);
input[HASHBLOCK_TAG_RANGE].clone_from_slice(&tag_vars);
let output = instance.allocate_permutation(&input);
```

The resulting relation is then proven with `spongefish-stark`, which combines:

- an AIR for the underlying permutation
- lookup arguments connecting outputs back to later inputs
- checks for repeated secret inputs
- linear-constraint AIRs for symbolic wire equations

## Multi-Recipient Verifiable Encryption

The crate also provides mVE constructions used by the higher-level rekeying
protocols. The `mve` module includes:

- mVE proofs for Poseidon2 hashes
- shared ciphertext and recipient-ciphertext types

These proofs are used to show that a distributed ciphertext is consistent with
an instance while keeping witness values hidden.

## Security

At a high level, the public transcript reveals:

- key identifiers and transition topology
- public commitments and ciphertexts
- mVE challenge/opening metadata

It does not reveal the committed key material or the hidden witnesses used to
construct valid proofs, assuming the underlying commitment and encryption
primitives provide their intended hiding/confidentiality properties.
