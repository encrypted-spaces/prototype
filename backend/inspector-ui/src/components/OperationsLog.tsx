// Operations view: collapses the raw event stream into one card per
// `Request`, with the contributing MerkUpdate / MerkSnapshot /
// ChangelogAppend / Membership / ProofEmitted events attached as children.
// Standalone events (Connection, SchemaSnapshot before any Request) render
// as inline separators so the timeline stays coherent.

import { useEffect, useMemo, useRef, useState } from "react";
import type { InspectorEvent } from "../types/events";
import { fmtMs, truncHex } from "../store/reducer";

interface Props {
  events: InspectorEvent[];
  cursor: number;
  onSelect: (i: number) => void;
}

type Group =
  | { kind: "op"; headIdx: number; childIdxs: number[] }
  | { kind: "standalone"; idx: number };

function groupEvents(events: InspectorEvent[]): Group[] {
  const groups: Group[] = [];
  let current: { kind: "op"; headIdx: number; childIdxs: number[] } | null =
    null;
  for (let i = 0; i < events.length; i++) {
    const ev = events[i];
    if (ev.kind === "Request") {
      if (current) groups.push(current);
      current = { kind: "op", headIdx: i, childIdxs: [] };
    } else if (ev.kind === "Connection" || ev.kind === "SchemaSnapshot") {
      // Connections and the startup schema snapshot don't belong to any
      // operation — render them inline.
      if (current) {
        groups.push(current);
        current = null;
      }
      groups.push({ kind: "standalone", idx: i });
    } else {
      if (current) current.childIdxs.push(i);
      else groups.push({ kind: "standalone", idx: i });
    }
  }
  if (current) groups.push(current);
  return groups;
}

export function OperationsLog({ events, cursor, onSelect }: Props) {
  const groups = useMemo(() => groupEvents(events), [events]);

  // Cards default to collapsed. Track per-group expansion explicitly so
  // re-renders don't lose user state.
  const [expanded, setExpanded] = useState<Record<number, boolean>>({});
  const toggle = (key: number) =>
    setExpanded((m) => ({ ...m, [key]: !m[key] }));

  // Auto-scroll the row containing the cursor into view.
  const rowRefs = useRef<Record<number, HTMLDivElement | null>>({});
  useEffect(() => {
    const el = rowRefs.current[cursor];
    if (el) el.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }, [cursor]);

  if (events.length === 0) {
    return (
      <div className="ops-log empty">
        Load an <code>inspector.ndjson</code> file or connect a live source.
      </div>
    );
  }

  return (
    <div className="ops-log">
      {groups.map((g) => {
        if (g.kind === "standalone") {
          const ev = events[g.idx];
          const active = g.idx === cursor;
          return (
            <div
              key={`s-${g.idx}`}
              ref={(el) => {
                rowRefs.current[g.idx] = el;
              }}
              className={`ops-standalone kind-${ev.kind} ${active ? "active" : ""}`}
              onClick={() => onSelect(g.idx)}
            >
              <span className="col-idx">{g.idx}</span>
              <span className="col-ts mono">{fmtMs(ev.ts_ms)}</span>
              <span className={`kind-tag tag-${ev.kind}`}>{ev.kind}</span>
              <span className="col-summary">{standaloneSummary(ev)}</span>
            </div>
          );
        }

        const head = events[g.headIdx];
        if (head.kind !== "Request") return null;
        const isOpen = !!expanded[g.headIdx];
        const headerActive =
          g.headIdx === cursor ||
          (!isOpen && g.childIdxs.includes(cursor));
        const stats = summarizeChildren(g.childIdxs.map((i) => events[i]));

        return (
          <div key={`o-${g.headIdx}`} className="ops-card">
            <div
              ref={(el) => {
                rowRefs.current[g.headIdx] = el;
              }}
              className={`ops-header ${headerActive ? "active" : ""}`}
              onClick={() => {
                onSelect(g.headIdx);
                toggle(g.headIdx);
              }}
            >
              <span className={`ops-chevron ${isOpen ? "open" : ""}`}>▸</span>
              <span className="col-idx">{g.headIdx}</span>
              <span className="col-ts mono">{fmtMs(head.ts_ms)}</span>
              <span className="ops-op">{head.op}</span>
              {head.uid != null && (
                <span className="ops-uid">uid={head.uid}</span>
              )}
              <span className="ops-stats">{stats}</span>
              <span className="ops-count">{g.childIdxs.length}</span>
            </div>
            {isOpen &&
              g.childIdxs.map((i) => {
                const ev = events[i];
                const active = i === cursor;
                return (
                  <div
                    key={i}
                    ref={(el) => {
                      rowRefs.current[i] = el;
                    }}
                    className={`ops-child kind-${ev.kind} ${active ? "active" : ""}`}
                    onClick={(e) => {
                      e.stopPropagation();
                      onSelect(i);
                    }}
                  >
                    <span className="col-idx">{i}</span>
                    <span className="col-ts mono">{fmtMs(ev.ts_ms)}</span>
                    <span className={`kind-tag tag-${ev.kind}`}>{ev.kind}</span>
                    <span className="col-summary">{childSummary(ev)}</span>
                  </div>
                );
              })}
          </div>
        );
      })}
    </div>
  );
}

function standaloneSummary(ev: InspectorEvent): string {
  switch (ev.kind) {
    case "Connection":
      return `${ev.event} uid=${ev.uid ?? "-"}`;
    case "SchemaSnapshot":
      return `${ev.tables.length} tables, ${ev.tables.reduce((n, t) => n + t.columns.length, 0)} columns`;
    default:
      return "";
  }
}

function childSummary(ev: InspectorEvent): string {
  switch (ev.kind) {
    case "MerkUpdate": {
      const cols = ev.entries.filter((e) => e.key_kind === "column").length;
      return `change=${ev.change_id} ${ev.op_type} ${truncHex(ev.old_root)}→${truncHex(ev.new_root)} (${cols} col${cols === 1 ? "" : "s"}, ${ev.rows_affected} row${ev.rows_affected === 1 ? "" : "s"})`;
    }
    case "MerkSnapshot":
      return `change=${ev.change_id} · ${ev.node_count} node${ev.node_count === 1 ? "" : "s"}`;
    case "ChangelogAppend":
      return `change=${ev.change_id} clc=${truncHex(ev.clc_root)} (${ev.entry_size_bytes}B)`;
    case "Membership":
      return `${ev.event} uid=${ev.uid ?? "-"} at change=${ev.change_id}`;
    case "ProofEmitted":
      return `${ev.proof_kind} ${ev.proof_size_bytes}B${ev.covers_entries != null ? ` covers=${ev.covers_entries}` : ""}`;
    default:
      return "";
  }
}

// Single-line digest of what happened inside this operation, shown in the
// collapsed header so the user gets the gist without expanding.
function summarizeChildren(children: InspectorEvent[]): string {
  if (children.length === 0) return "(no side-effects)";
  const parts: string[] = [];
  const tables = new Set<string>();
  let rowsAffected = 0;
  let proofBytes = 0;
  let memberChange: string | null = null;

  for (const ev of children) {
    if (ev.kind === "MerkUpdate") {
      rowsAffected += ev.rows_affected;
      for (const e of ev.entries) {
        if (e.key_kind === "column" || e.key_kind === "row" || e.key_kind === "index") {
          tables.add(e.table);
        }
      }
    } else if (ev.kind === "ProofEmitted") {
      proofBytes += ev.proof_size_bytes;
    } else if (ev.kind === "Membership") {
      memberChange = `${ev.event} uid=${ev.uid ?? "-"}`;
    }
  }

  if (tables.size > 0)
    parts.push(`${rowsAffected} row${rowsAffected === 1 ? "" : "s"} in ${[...tables].join(", ")}`);
  if (memberChange) parts.push(memberChange);
  if (proofBytes > 0) parts.push(`proof ${proofBytes}B`);
  return parts.join(" · ") || `${children.length} sub-event${children.length === 1 ? "" : "s"}`;
}
