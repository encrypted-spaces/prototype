// Derive the current membership view at a given cursor: the active member
// set and the key epoch, computed by replaying Membership and key-rotating
// ChangelogAppend events (InviteUser / RemoveUser / RefreshKeys / Rekey).

import type { InspectorEvent } from "../types/events";

export interface MembershipState {
  members: number[];
  epoch: number;
  lastRekeyTs: number | null;
  events: { ts_ms: number; kind: "add" | "remove"; uid: number | null; change_id: number }[];
}

const KEY_ROTATION_OPS = new Set([
  "InviteUser",
  "RemoveUser",
  "RefreshKeys",
  "Rekey",
]);

export function deriveMembershipAt(
  events: InspectorEvent[],
  cursor: number,
): MembershipState {
  const memberSet = new Set<number>();
  const log: MembershipState["events"] = [];
  let epoch = 0;
  let lastRekeyTs: number | null = null;

  const upto = Math.min(cursor + 1, events.length);
  for (let i = 0; i < upto; i++) {
    const ev = events[i];
    if (ev.kind === "Membership") {
      if (ev.uid != null) {
        if (ev.event === "add") memberSet.add(ev.uid);
        else memberSet.delete(ev.uid);
      }
      log.push({
        ts_ms: ev.ts_ms,
        kind: ev.event,
        uid: ev.uid,
        change_id: ev.change_id,
      });
    } else if (
      ev.kind === "ChangelogAppend" &&
      KEY_ROTATION_OPS.has(ev.op_type)
    ) {
      epoch += 1;
      lastRekeyTs = ev.ts_ms;
    }
  }

  return {
    members: [...memberSet].sort((a, b) => a - b),
    epoch,
    lastRekeyTs,
    events: log,
  };
}
