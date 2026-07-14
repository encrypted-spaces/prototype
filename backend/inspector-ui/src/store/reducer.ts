// Derived "current view" computed by replaying events 0..=cursor.
// Cheap to recompute on every cursor change for Phase-1-sized recordings;
// later phases can memoize incrementally.

import type { InspectorEvent } from "../types/events";

export interface DerivedState {
  spaceIds: string[];
  changeCount: number;
  currentMerkRoot: string | null;
  lastClcRoot: string | null;
  members: Set<number>;
  proofsByKind: Record<string, number>;
  eventsByKind: Record<string, number>;
}

export function emptyState(): DerivedState {
  return {
    spaceIds: [],
    changeCount: 0,
    currentMerkRoot: null,
    lastClcRoot: null,
    members: new Set(),
    proofsByKind: {},
    eventsByKind: {},
  };
}

export function deriveStateAt(
  events: InspectorEvent[],
  cursor: number,
): DerivedState {
  const s = emptyState();
  const spaceSet = new Set<string>();
  const upTo = Math.min(cursor, events.length - 1);
  for (let i = 0; i <= upTo; i++) {
    const ev = events[i];
    spaceSet.add(ev.space_id);
    s.eventsByKind[ev.kind] = (s.eventsByKind[ev.kind] ?? 0) + 1;
    switch (ev.kind) {
      case "MerkUpdate":
        s.currentMerkRoot = ev.new_root;
        s.changeCount = Math.max(s.changeCount, ev.change_id);
        break;
      case "ChangelogAppend":
        s.lastClcRoot = ev.clc_root;
        break;
      case "Membership":
        if (ev.uid != null) {
          if (ev.event === "add") s.members.add(ev.uid);
          else s.members.delete(ev.uid);
        }
        break;
      case "ProofEmitted":
        s.proofsByKind[ev.proof_kind] =
          (s.proofsByKind[ev.proof_kind] ?? 0) + 1;
        break;
    }
  }
  s.spaceIds = Array.from(spaceSet);
  return s;
}

export function truncHex(hex: string | null, n = 8): string {
  if (!hex) return "—";
  return hex.length <= n ? hex : `${hex.slice(0, n)}…`;
}

export function fmtMs(ts: number): string {
  const d = new Date(ts);
  const pad = (n: number, w = 2) => n.toString().padStart(w, "0");
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
}

/// Seconds-precision clock time (HH:MM:SS), for summary stats where the
/// millisecond tail from `fmtMs` is just noise.
export function fmtSec(ts: number): string {
  return fmtMs(ts).split(".")[0];
}
