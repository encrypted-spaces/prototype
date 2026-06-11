#![no_main]

use encrypted_spaces_changelog_core::changelog::{
    verify_op_sequence_timed_flat, FastForwardJournal, FastForwardRange, FlatEntryBytes,
};
use risc0_zkvm::guest::env;
use risc0_zkvm::serde;
use std::collections::BTreeMap;

risc0_zkvm::guest::entry!(main);

fn main() {
    let t0 = env::cycle_count();

    let is_first: bool = env::read();

    let mut previous_output = FastForwardRange::default();
    let mut recursive_verify_cycles: u64 = 0;
    if !is_first {
        let io_byte_len: usize = env::read();
        let mut io_bytes = vec![0u8; io_byte_len];
        env::read_slice(&mut io_bytes);
        let previous_journal: FastForwardJournal = postcard::from_bytes(&io_bytes).unwrap();
        previous_output = previous_journal.output.clone();

        #[allow(non_snake_case)]
        let mut PROGRAM_ID = [0u32; 8];
        env::read_slice(&mut PROGRAM_ID);

        let tv0 = env::cycle_count();
        let inputs = &serde::to_vec(&previous_journal).unwrap();
        env::verify(PROGRAM_ID, inputs).unwrap();
        recursive_verify_cycles = env::cycle_count() - tv0;
    }

    // Read flat entry bytes: entry_count, entries_byte_len, entry_ends, entries_bytes
    let entry_count: usize = env::read();
    let entries_byte_len: usize = env::read();
    let mut entry_ends = vec![0u32; entry_count];
    env::read_slice(&mut entry_ends);
    let mut entries_bytes = vec![0u8; entries_byte_len];
    env::read_slice(&mut entries_bytes);
    let entries = FlatEntryBytes::new(&entries_bytes, &entry_ends).unwrap();

    let range_byte_len: usize = env::read();
    let mut range_bytes = vec![0u8; range_byte_len];
    env::read_slice(&mut range_bytes);
    let verify_range: FastForwardRange = postcard::from_bytes(&range_bytes).unwrap();

    let pruned_tree_byte_len: usize = env::read();
    let mut pruned_tree_bytes = vec![0u8; pruned_tree_byte_len];
    env::read_slice(&mut pruned_tree_bytes);

    let t1 = env::cycle_count();
    let deserialize_cycles = (t1 - t0) - recursive_verify_cycles;

    let num_changes = entries.len();

    assert_eq!(
        verify_range.end_change_id as usize, num_changes,
        "end_change_id must match number of entries in this chunk"
    );

    if !is_first {
        assert_eq!(
            verify_range.start_clc_state, previous_output.end_clc_state,
            "extended FF range must start at the previous proof's ending tree head"
        );
        assert_eq!(
            verify_range.start_dc, previous_output.end_dc,
            "extended FF range must start at the previous proof's ending DC"
        );
    }

    let start_change_id = if is_first {
        0
    } else {
        previous_output.end_change_id
    };

    let mut sigref_map: BTreeMap<u32, (u32, [u8; 32])> = if is_first {
        BTreeMap::new()
    } else {
        previous_output.sigref_map.clone()
    };

    // Thread recent_roots: empty for first chunks (verify_op_sequence_timed_flat
    // seeds it with the initial state), inherited from previous_output for
    // extension chunks.
    let mut recent_roots: Vec<(u32, [u8; 32])> = if is_first {
        Vec::new()
    } else {
        previous_output.recent_roots.clone()
    };

    let mut timestamp_hwm = if is_first {
        0
    } else {
        previous_output.timestamp_hwm
    };

    let (chain_valid, loop_timings) = verify_op_sequence_timed_flat(
        entries,
        &verify_range,
        &pruned_tree_bytes,
        start_change_id,
        &mut sigref_map,
        &mut recent_roots,
        &mut timestamp_hwm,
        env::cycle_count,
    );
    assert!(chain_valid, "Chain verification failed");

    let output = FastForwardRange {
        start_clc_state: if is_first {
            verify_range.start_clc_state.clone()
        } else {
            previous_output.start_clc_state.clone()
        },
        end_clc_state: verify_range.end_clc_state,
        start_dc: if is_first {
            verify_range.start_dc
        } else {
            previous_output.start_dc
        },
        end_dc: verify_range.end_dc,
        end_change_id: if is_first {
            num_changes as u32
        } else {
            previous_output.end_change_id + num_changes as u32
        },
        sigref_map,
        recent_roots,
        timestamp_hwm,
    };

    env::commit(&FastForwardJournal {
        output,
        guest_deserialize_cycles: deserialize_cycles,
        guest_recursive_verify_cycles: recursive_verify_cycles,
        loop_timings,
    });
}
