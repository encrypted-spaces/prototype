// Right-pane panel: every ProofEmitted event up to the cursor, newest first.
// Surfaces the size / generation time / coverage so a viewer can see what
// the server actually hands out.

import type { InspectorEvent, ProofEmittedEv } from "../types/events";
import { fmtMs } from "../store/reducer";

interface Props {
  events: InspectorEvent[];
  cursor: number;
  onSelect: (i: number) => void;
}

function explain(kind: ProofEmittedEv["proof_kind"]): string {
  switch (kind) {
    case "select":
      return "Proves the query result matches the current Merk root — the client verifies without trusting the server. Size scales with the rows covered: a point lookup proves one row; a wide range or high limit proves many and is larger.";
    case "fast_forward":
      return "Lets a joining (or stale) client skip past changelog entries: one proof replaces replaying every change.";
    case "update":
      return "Attached to an applied change so clients can verify the new Merk root incrementally.";
  }
}

export function ProofPanel({ events, cursor, onSelect }: Props) {
  const proofs: { i: number; ev: ProofEmittedEv }[] = [];
  const upto = Math.min(cursor + 1, events.length);
  for (let i = 0; i < upto; i++) {
    const ev = events[i];
    if (ev.kind === "ProofEmitted") proofs.push({ i, ev });
  }

  if (proofs.length === 0) {
    return (
      <div className="proof-panel empty">
        No proofs emitted yet. Run a <code>Select</code> or trigger a
        <code> FastForward</code> to see one here.
      </div>
    );
  }

  return (
    <div className="proof-panel">
      {proofs.reverse().map(({ i, ev }) => (
        <div
          key={i}
          className={`proof-card kind-${ev.proof_kind} ${i === cursor ? "active" : ""}`}
          onClick={() => onSelect(i)}
        >
          <div className="proof-header">
            <span className="proof-kind">{ev.proof_kind}</span>
            <span className="proof-ts mono">{fmtMs(ev.ts_ms)}</span>
          </div>
          <div className="proof-stats">
            <div className="proof-stat">
              <div className="proof-stat-label">Size</div>
              <div className="proof-stat-value mono">
                {ev.proof_size_bytes.toLocaleString()} B
              </div>
            </div>
            {ev.covers_entries != null && (
              <div className="proof-stat">
                <div className="proof-stat-label">Covers</div>
                <div className="proof-stat-value mono">
                  {ev.covers_entries} entr{ev.covers_entries === 1 ? "y" : "ies"}
                </div>
              </div>
            )}
            {ev.gen_ms != null && (
              <div className="proof-stat">
                <div className="proof-stat-label">Gen time</div>
                <div className="proof-stat-value mono">{ev.gen_ms} ms</div>
              </div>
            )}
          </div>
          {ev.query && (
            <div className="proof-query">
              <div className="proof-stat-label">Query</div>
              <div className="proof-query-text mono">{ev.query}</div>
            </div>
          )}
          <div className="proof-explain">{explain(ev.proof_kind)}</div>
        </div>
      ))}
    </div>
  );
}
