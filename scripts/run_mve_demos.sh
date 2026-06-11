#!/usr/bin/env bash
set -euo pipefail

schemes=(
  "mVE::mlkem768+poseidon2"
  "mVE::xwing+poseidon2"
  "mVE::xwing-ristretto+poseidon2"
  "mVE::ristretto255dh+poseidon2"
)

sizes=(10 20 50 100 200)

for scheme in "${schemes[@]}"; do
  for size in "${sizes[@]}"; do
    echo "Running ${scheme} ${size}"
    cargo run --bin zkp --release --features parallel -- "${scheme}" "${size}"
  done
done
