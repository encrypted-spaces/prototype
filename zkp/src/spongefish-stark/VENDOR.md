# Vendoring provenance

This crate was imported from
[`mmaker/spongefish-stark`](https://github.com/mmaker/spongefish-stark) at commit
`44e111df21444be4faf94dd54ed03ad26d513de5`.

The in-tree copy subsequently diverged to support Encrypted Spaces' proof
requirements. The material local changes include:

- profile-derived hiding-safe trace preparation, valid-row padding, and exact
  proof-degree binding;
- the Plonky3 0.6 interaction-based LogUp migration, including tight count
  bounds and boolean lookup selectors; and
- the workspace's Plonky3 0.6.3 and Spongefish 0.7.4 dependency set.

The repository-root `Cargo.lock` is authoritative because this crate is a
workspace member. Do not add a nested lockfile.
