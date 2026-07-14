// Derive the changelog MMR view at a given cursor. Each ChangelogAppend
// adds one leaf; peak structure is fully determined by leaf count (set
// bits in n, high → low). This is an educational mirror, not a faithful
// hash-accumulator — we surface shape, not commitments.

import type { ChangelogAppendEv, InspectorEvent } from "../types/events";

export interface MmrLeaf {
  index: number; // 0-based leaf index
  change_id: number;
  op_type: string;
  clc_root: string;
  entry_size_bytes: number;
  ts_ms: number;
}

export interface MmrPeak {
  height: number; // 0 = single leaf, 1 = covers 2, 2 = covers 4, ...
  leafCount: number; // 2^height
  startIndex: number; // first leaf covered (inclusive)
  endIndex: number; // last leaf covered (inclusive)
}

export interface MmrState {
  leaves: MmrLeaf[];
  peaks: MmrPeak[];
  treeSize: number;
  clcRoot: string | null;
  lastAppendTs: number | null;
}

function peaksForSize(n: number): { height: number; leafCount: number }[] {
  const out: { height: number; leafCount: number }[] = [];
  for (let h = 31; h >= 0; h--) {
    if (n & (1 << h)) out.push({ height: h, leafCount: 1 << h });
  }
  return out;
}

export function deriveMmrAt(
  events: InspectorEvent[],
  cursor: number,
): MmrState {
  const leaves: MmrLeaf[] = [];
  let clcRoot: string | null = null;
  let lastAppendTs: number | null = null;

  const upto = Math.min(cursor + 1, events.length);
  for (let i = 0; i < upto; i++) {
    const ev = events[i];
    if (ev.kind !== "ChangelogAppend") continue;
    const a = ev as ChangelogAppendEv;
    leaves.push({
      index: leaves.length,
      change_id: a.change_id,
      op_type: a.op_type,
      clc_root: a.clc_root,
      entry_size_bytes: a.entry_size_bytes,
      ts_ms: a.ts_ms,
    });
    clcRoot = a.clc_root;
    lastAppendTs = a.ts_ms;
  }

  const sizes = peaksForSize(leaves.length);
  let cursorLeaf = 0;
  const peaks: MmrPeak[] = sizes.map(({ height, leafCount }) => {
    const startIndex = cursorLeaf;
    const endIndex = cursorLeaf + leafCount - 1;
    cursorLeaf += leafCount;
    return { height, leafCount, startIndex, endIndex };
  });

  return {
    leaves,
    peaks,
    treeSize: leaves.length,
    clcRoot,
    lastAppendTs,
  };
}
