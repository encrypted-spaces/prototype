#!/bin/bash
# Run all benchmark fixtures and collect results
# Usage: ./tools/run_comparison.sh [output_file]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TRACER_DIR="$(dirname "$SCRIPT_DIR")"
PROTOTYPE_DIR="$(dirname "$(dirname "$(dirname "$TRACER_DIR")")")"
FIXTURES_DIR="$TRACER_DIR/test_fixtures"

OUTPUT_FILE="${1:-results.txt}"

cd "$PROTOTYPE_DIR"

echo "Running ffproof_tracer benchmarks..."
echo "Results will be saved to: $OUTPUT_FILE"
echo ""

# Clear output file
> "$TRACER_DIR/$OUTPUT_FILE"

# Function to run a single benchmark and extract metrics
run_benchmark() {
    local fixture=$1
    local name=$(basename "$fixture" .json)

    echo "=== Running $name ===" | tee -a "$TRACER_DIR/$OUTPUT_FILE"

    # Run the benchmark and capture output
    output=$(RISC0_DEV_MODE=1 cargo run -p ffproof-tracer --release -- -i "$fixture" --debug 2>&1)

    # Extract key metrics
    full_nodes=$(echo "$output" | grep "Pruned tree:" | sed 's/.*: \([0-9]*\) Full.*/\1/')
    pruned_nodes=$(echo "$output" | grep "Pruned tree:" | sed 's/.*Full nodes, \([0-9]*\) Pruned.*/\1/')
    stage1=$(echo "$output" | grep "Stage 1" | sed 's/.*: \([0-9,]*\) cycles/\1/' | tr -d ',')
    stage2=$(echo "$output" | grep "Stage 2" | sed 's/.*: \([0-9,]*\) cycles/\1/' | tr -d ',')
    total=$(echo "$output" | grep "Total user cycles:" | sed 's/.*: \([0-9,]*\)/\1/' | tr -d ',')

    # Output in CSV-friendly format
    echo "RESULT: $name | Full=$full_nodes | Pruned=$pruned_nodes | Stage1=$stage1 | Stage2=$stage2 | Total=$total" | tee -a "$TRACER_DIR/$OUTPUT_FILE"
    echo "" | tee -a "$TRACER_DIR/$OUTPUT_FILE"
}

# Run all insert benchmarks
echo "--- INSERT BENCHMARKS ---" | tee -a "$TRACER_DIR/$OUTPUT_FILE"
for n in 1 10 25 50 100; do
    run_benchmark "$FIXTURES_DIR/insert_$n.json"
done

# Run all update benchmarks
echo "--- UPDATE BENCHMARKS ---" | tee -a "$TRACER_DIR/$OUTPUT_FILE"
for n in 1 10 25 50 100; do
    run_benchmark "$FIXTURES_DIR/update_$n.json"
done

# Run all delete benchmarks
echo "--- DELETE BENCHMARKS ---" | tee -a "$TRACER_DIR/$OUTPUT_FILE"
for n in 1 10 25 50 100; do
    run_benchmark "$FIXTURES_DIR/delete_$n.json"
done

# Run read (key) benchmarks
echo "--- READ KEY BENCHMARKS ---" | tee -a "$TRACER_DIR/$OUTPUT_FILE"
for n in 1 10 25 50 100; do
    run_benchmark "$FIXTURES_DIR/read_$n.json"
done

# Run read range benchmarks
echo "--- READ RANGE BENCHMARKS ---" | tee -a "$TRACER_DIR/$OUTPUT_FILE"
for n in 1 10 25 50 100; do
    run_benchmark "$FIXTURES_DIR/read_range_$n.json"
done

# Run read prefix benchmarks
echo "--- READ PREFIX BENCHMARKS ---" | tee -a "$TRACER_DIR/$OUTPUT_FILE"
for n in 1 10 25 50 100; do
    run_benchmark "$FIXTURES_DIR/read_prefix_$n.json"
done

# Run mixed benchmarks
echo "--- MIXED BENCHMARKS ---" | tee -a "$TRACER_DIR/$OUTPUT_FILE"
for n in 1 10 25 50 100; do
    run_benchmark "$FIXTURES_DIR/mixed_$n.json"
done

echo ""
echo "=== SUMMARY ===" | tee -a "$TRACER_DIR/$OUTPUT_FILE"
echo "All benchmarks complete. Results saved to $OUTPUT_FILE"

# Parse results into a table
echo "" | tee -a "$TRACER_DIR/$OUTPUT_FILE"
echo "| Type | N | Full Nodes | Total Cycles |" | tee -a "$TRACER_DIR/$OUTPUT_FILE"
echo "|------|---|------------|--------------|" | tee -a "$TRACER_DIR/$OUTPUT_FILE"
grep "^RESULT:" "$TRACER_DIR/$OUTPUT_FILE" | while read line; do
    name=$(echo "$line" | sed 's/RESULT: \([^ ]*\).*/\1/')
    type=$(echo "$name" | sed 's/_[0-9]*//')
    n=$(echo "$name" | sed 's/[a-z]*_//')
    full=$(echo "$line" | sed 's/.*Full=\([0-9]*\).*/\1/')
    total=$(echo "$line" | sed 's/.*Total=\([0-9]*\).*/\1/')
    echo "| $type | $n | $full | $total |" | tee -a "$TRACER_DIR/$OUTPUT_FILE"
done
