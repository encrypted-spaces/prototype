#!/usr/bin/env python3
"""
Generate test fixtures for ffproof_tracer.

Produces JSON with either:
- Legacy format: initial_entries + operations (flat list of Put/Delete)
- Steps format:  initial_entries + steps (ordered list of Read/Write steps)

The steps format is used when --run includes read operations (read_key, read_prefix,
read_range) or when --steps is passed explicitly.

Keys are 16 bytes (32 hex chars), values are 32 bytes (64 hex chars).
"""

import argparse
import json
import secrets
import random


def gen_key():
    """Generate a random 16-byte key as hex string."""
    return secrets.token_hex(16)


def gen_value():
    """Generate a random 32-byte value as hex string."""
    return secrets.token_hex(32)


def main():
    parser = argparse.ArgumentParser(
        description="Generate test fixtures for ffproof_tracer"
    )
    parser.add_argument(
        "--tree-size",
        type=int,
        default=100,
        help="Number of initial entries in the tree",
    )
    parser.add_argument(
        "--num-ops",
        type=int,
        default=0,
        help="Number of random operations to generate",
    )
    parser.add_argument(
        "--insert-prob",
        type=float,
        default=0.2,
        help="Probability of insert operation (0-1)",
    )
    parser.add_argument(
        "--update-prob",
        type=float,
        default=0.6,
        help="Probability of update operation (0-1)",
    )
    parser.add_argument(
        "--delete-prob",
        type=float,
        default=0.2,
        help="Probability of delete operation (0-1)",
    )
    parser.add_argument(
        "--run",
        action="append",
        metavar="TYPE:COUNT",
        help="Generate sequential run of operations. Each --run becomes a step. "
        "Write types: insert, update, delete. Read types: read_key, read_prefix, read_range. "
        "e.g., --run insert:50 --run read_key:10 --run update:100 --run read_range:5",
    )
    parser.add_argument(
        "--steps",
        action="store_true",
        help="Force output in steps format even for write-only fixtures",
    )
    parser.add_argument(
        "--no-duplicates",
        action="store_true",
        help="For updates/deletes, each key is only operated on once (sample without replacement)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Random seed for reproducibility",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default="fixture.json",
        help="Output JSON file path",
    )

    args = parser.parse_args()

    # Set random seed if provided
    if args.seed is not None:
        random.seed(args.seed)
        # Also seed secrets module for reproducibility
        # Note: secrets.token_hex uses os.urandom which isn't seedable
        # For reproducibility, we'll use random.randbytes instead
        global gen_key, gen_value

        def gen_key():
            return random.randbytes(16).hex()

        def gen_value():
            return random.randbytes(32).hex()

    # Generate initial entries
    initial_entries = []
    existing_keys = set()

    for _ in range(args.tree_size):
        key = gen_key()
        value = gen_value()
        initial_entries.append({"key": key, "value": value})
        existing_keys.add(key)

    # Convert to list for random access
    existing_keys_list = list(existing_keys)

    # Generate operations/steps
    operations = []  # flat list for legacy format
    steps = []       # list of steps for steps format
    has_reads = False

    if args.run:
        # Sequential runs mode — each --run becomes a step
        for run_spec in args.run:
            try:
                op_type, count = run_spec.split(":")
                count = int(count)
            except ValueError:
                parser.error(f"Invalid --run format: {run_spec}. Use TYPE:COUNT")

            if op_type == "insert":
                write_ops = []
                for _ in range(count):
                    key = gen_key()
                    value = gen_value()
                    write_ops.append({"Put": {"key": key, "value": value}})
                    existing_keys_list.append(key)
                steps.append({"Write": write_ops})
                operations.extend(write_ops)

            elif op_type == "update":
                write_ops = []
                if args.no_duplicates:
                    if count > len(existing_keys_list):
                        parser.error(f"Cannot generate {count} unique updates with only {len(existing_keys_list)} keys")
                    keys_to_update = random.sample(existing_keys_list, count)
                    for key in keys_to_update:
                        value = gen_value()
                        write_ops.append({"Put": {"key": key, "value": value}})
                else:
                    for _ in range(count):
                        if not existing_keys_list:
                            continue
                        key = random.choice(existing_keys_list)
                        value = gen_value()
                        write_ops.append({"Put": {"key": key, "value": value}})
                steps.append({"Write": write_ops})
                operations.extend(write_ops)

            elif op_type == "delete":
                write_ops = []
                if args.no_duplicates:
                    if count > len(existing_keys_list):
                        parser.error(f"Cannot generate {count} unique deletes with only {len(existing_keys_list)} keys")
                    keys_to_delete = random.sample(existing_keys_list, count)
                    for key in keys_to_delete:
                        write_ops.append({"Delete": {"key": key}})
                else:
                    for _ in range(count):
                        if not existing_keys_list:
                            continue
                        key = random.choice(existing_keys_list)
                        write_ops.append({"Delete": {"key": key}})
                steps.append({"Write": write_ops})
                operations.extend(write_ops)

            elif op_type == "read_key":
                has_reads = True
                read_ops = []
                if not existing_keys_list:
                    parser.error("Cannot generate key reads with no existing keys")
                for _ in range(count):
                    key = random.choice(existing_keys_list)
                    read_ops.append({"Key": key})
                steps.append({"Read": read_ops})

            elif op_type == "read_prefix":
                has_reads = True
                read_ops = []
                if not existing_keys_list:
                    parser.error("Cannot generate prefix reads with no existing keys")
                for _ in range(count):
                    key = random.choice(existing_keys_list)
                    # Use first 1-4 bytes as prefix
                    prefix_len = random.randint(1, min(4, len(key) // 2))
                    prefix = key[:prefix_len * 2]
                    read_ops.append({"Prefix": prefix})
                steps.append({"Read": read_ops})

            elif op_type == "read_range":
                has_reads = True
                read_ops = []
                if len(existing_keys_list) < 2:
                    parser.error("Need at least 2 existing keys for range reads")
                for _ in range(count):
                    k1, k2 = random.sample(existing_keys_list, 2)
                    start, end = (k1, k2) if k1 < k2 else (k2, k1)
                    read_ops.append({"Range": {"start": start, "end": end}})
                steps.append({"Read": read_ops})

            else:
                parser.error(
                    f"Unknown operation type: {op_type}. "
                    "Valid types: insert, update, delete, read_key, read_prefix, read_range"
                )

    elif args.num_ops > 0:
        # Random operations mode (legacy — flat list, no reads)
        probs = [args.insert_prob, args.update_prob, args.delete_prob]
        total = sum(probs)
        if abs(total - 1.0) > 0.01:
            print(
                f"Warning: probabilities sum to {total}, normalizing to 1.0"
            )
            probs = [p / total for p in probs]

        for _ in range(args.num_ops):
            r = random.random()
            cumulative = 0

            # Insert
            cumulative += probs[0]
            if r < cumulative:
                key = gen_key()
                value = gen_value()
                operations.append({"Put": {"key": key, "value": value}})
                existing_keys_list.append(key)
                continue

            # Update
            cumulative += probs[1]
            if r < cumulative:
                if existing_keys_list:
                    key = random.choice(existing_keys_list)
                    value = gen_value()
                    operations.append({"Put": {"key": key, "value": value}})
                continue

            # Delete
            if existing_keys_list:
                key = random.choice(existing_keys_list)
                operations.append({"Delete": {"key": key}})

    # Output fixture
    use_steps = has_reads or args.steps

    if use_steps and steps:
        fixture = {
            "initial_entries": initial_entries,
            "steps": steps,
        }
    else:
        fixture = {
            "initial_entries": initial_entries,
            "operations": operations,
        }

    with open(args.output, "w") as f:
        json.dump(fixture, f, indent=2)

    print(f"Generated fixture: {args.output}")
    print(f"  Initial entries: {len(initial_entries)}")

    if use_steps and steps:
        print(f"  Steps: {len(steps)}")
        write_steps = [s for s in steps if "Write" in s]
        read_steps = [s for s in steps if "Read" in s]
        write_op_count = sum(len(s["Write"]) for s in write_steps)
        read_op_count = sum(len(s["Read"]) for s in read_steps)
        put_count = sum(
            1 for s in write_steps for op in s["Write"] if "Put" in op
        )
        delete_count = sum(
            1 for s in write_steps for op in s["Write"] if "Delete" in op
        )
        print(f"    Write steps: {len(write_steps)} ({write_op_count} ops: {put_count} Put, {delete_count} Delete)")
        print(f"    Read steps: {len(read_steps)} ({read_op_count} queries)")
    else:
        print(f"  Operations: {len(operations)}")
        put_count = sum(1 for op in operations if "Put" in op)
        delete_count = sum(1 for op in operations if "Delete" in op)
        print(f"    Put: {put_count}")
        print(f"    Delete: {delete_count}")


if __name__ == "__main__":
    main()
