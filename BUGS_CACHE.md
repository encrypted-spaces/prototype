# KV Cache Bugs — `nt/kvcache` branch

Status after fixes in commits `8cb07be3`, `4609efc2`, `4a54a53d`.

---

## Fixed

### Fix 1. Vestigial `apply_broadcast_cache_updates` (commit `8cb07be3`)

`validate_and_apply_change` already spliced writes into the KV cache
atomically inside `apply_state_update`. The separate
`apply_broadcast_cache_updates` was a no-op for non-Reduce ops and
redundantly reanchored for Reduce ops. Collapsed `Applied` and
`AppliedCacheInvalidated` into a single `Applied` variant with no fields
and removed `apply_broadcast_cache_updates`.

### Fix 2. PutHash sidecar not re-verified (commit `4609efc2`)

`cache_update_from_writes` trusted `change.hashed_values.get(value_hash)`
without checking that the returned bytes actually hash to the expected
digest. Added `ValueOrHash::from_value(bytes).value_hash() != *value_hash`
check; mismatched entries are tainted (same as the missing-sidecar path).

### Fix 3. Reduce ops wasted splice before reanchor (commit `4a54a53d`)

Both the splice and reanchor ran for Reduce ops — the splice was
immediately destroyed. Now we check `op_type == Reduce` before building
the `CacheUpdate` and pass `None`, letting `apply_state_update` reanchor
directly.

---

## Remaining (design tradeoffs, not correctness bugs)

### 4. Join cache miss discards already-resolved main rows

**Severity:** Performance

`try_get_cached` resolves the main query from cache, decrypts the rows,
then attempts the join lookup. If the join misses, the entire result is
discarded and `fetch_and_decrypt` re-fetches everything from the server —
including the main table rows already in hand.

Not a correctness issue. Fixing it properly requires returning main rows
alongside a "join missed" signal so the caller can fetch only the joined
table. Adds complexity for a marginal perf gain on a narrow case (main
cached, join not cached).

### 5. No eviction — cache grows monotonically

**Severity:** Resource leak (gradual memory growth)

Every `apply_select` and every write splice adds point entries and
coverage intervals that are never removed (except on `reanchor`, which
clears everything). A long-lived Space querying many tables accumulates
unbounded cache state.

The old row-level cache had `max_tables` LRU eviction. Neither KV cache
branch carries this forward. Worth adding eventually but not a
correctness issue.

### 6. Index coverage not extended on writes

**Severity:** Missed cache hit (not a correctness bug)

`cache_update_from_writes` only extends **row-range** coverage when a
write covers every non-id column. Index entries are spliced as point
writes but the index key range is never marked as covered.

After an insert, `WHERE indexed_col = new_value` still misses the cache
even though the index entry is physically present — the index range
isn't covered. The next server fetch for that bucket establishes coverage.

Conservative and correct; just leaves performance on the table.

---

## Previously reported, not actually reachable

### ~~Full-table fallback wrong on encrypted columns~~

The `full_table_fallback` filters rows using `row_matches_predicate` on
raw (encrypted) stored values. For encrypted columns this would compare
ciphertext against plaintext predicate values, silently returning empty
results.

**Not reachable:** `validate_original_select_predicate` in `table.rs`
rejects WHERE predicates on non-indexed columns with `InvalidQuery`
before the query reaches the cache. Encrypted columns cannot be indexed,
so the fallback path is never entered with an encrypted-column predicate.
