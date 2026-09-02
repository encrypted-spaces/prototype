// Phase 1: simple windowed list (no react-virtual yet). Renders a fixed
// slice around the cursor + the past N for scroll context. Phase 2 will
// switch to a proper virtualized list when recordings grow large.

import { useEffect, useMemo, useRef } from "react";
import type { InspectorEvent } from "../types/events";
import { fmtMs, truncHex } from "../store/reducer";

const WINDOW_BEHIND = 200;
const WINDOW_AHEAD = 50;

interface Props {
  events: InspectorEvent[];
  cursor: number;
  onSelect: (i: number) => void;
}

export function WireLog({ events, cursor, onSelect }: Props) {
  const lo = Math.max(0, cursor - WINDOW_BEHIND);
  const hi = Math.min(events.length, cursor + WINDOW_AHEAD + 1);

  const slice = useMemo(() => events.slice(lo, hi), [events, lo, hi]);

  const rowRefs = useRef<Record<number, HTMLDivElement | null>>({});
  useEffect(() => {
    const el = rowRefs.current[cursor];
    if (el) el.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }, [cursor]);

  if (events.length === 0) {
    return (
      <div className="wire-log empty">
        Load an <code>inspector.ndjson</code> file to begin.
      </div>
    );
  }

  return (
    <div className="wire-log">
      {slice.map((ev, idx) => {
        const i = lo + idx;
        const active = i === cursor;
        const past = i < cursor;
        return (
          <div
            key={i}
            ref={(el) => {
              rowRefs.current[i] = el;
            }}
            className={`wire-row kind-${ev.kind} ${active ? "active" : past ? "past" : "future"}`}
            onClick={() => onSelect(i)}
          >
            <span className="col-idx">{i}</span>
            <span className="col-ts mono">{fmtMs(ev.ts_ms)}</span>
            <span className={`col-kind kind-tag tag-${ev.kind}`}>{ev.kind}</span>
            <span className="col-summary">{summarize(ev)}</span>
          </div>
        );
      })}
    </div>
  );
}

function summarize(ev: InspectorEvent): string {
  switch (ev.kind) {
    case "SchemaSnapshot":
      return `${ev.tables.length} tables, ${ev.tables.reduce((n, t) => n + t.columns.length, 0)} columns total`;
    case "Connection":
      return `${ev.event} uid=${ev.uid ?? "-"}`;
    case "Request":
      return `op=${ev.op}${ev.uid != null ? ` uid=${ev.uid}` : ""}`;
    case "MerkUpdate": {
      const cols = ev.entries.filter((e) => e.key_kind === "column").length;
      return `change=${ev.change_id} ${ev.op_type} ${truncHex(ev.old_root)}→${truncHex(ev.new_root)} (${cols} col${cols === 1 ? "" : "s"}, ${ev.rows_affected} row${ev.rows_affected === 1 ? "" : "s"})`;
    }
    case "ChangelogAppend":
      return `change=${ev.change_id} ${ev.op_type} clc=${truncHex(ev.clc_root)} (${ev.entry_size_bytes}B)`;
    case "Membership":
      return `${ev.event} uid=${ev.uid ?? "-"} at change=${ev.change_id}`;
    case "ProofEmitted":
      return `${ev.proof_kind} ${ev.proof_size_bytes}B${ev.covers_entries != null ? ` covers=${ev.covers_entries}` : ""}`;
  }
}
