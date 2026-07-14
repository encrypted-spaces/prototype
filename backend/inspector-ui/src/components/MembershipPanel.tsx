// Right-pane panel: current membership + recent ratchet events. Reads from
// the membership store; cursor-sensitive so it matches playback.

import type { MembershipState } from "../store/membership";
import { fmtSec } from "../store/reducer";

interface Props {
  state: MembershipState;
}

export function MembershipPanel({ state }: Props) {
  if (state.members.length === 0 && state.events.length === 0) {
    return (
      <div className="membership-panel empty">
        No membership events yet.
      </div>
    );
  }

  return (
    <div className="membership-panel">
      <div className="memb-summary">
        <div className="memb-stat">
          <div className="memb-stat-label">Members</div>
          <div className="memb-stat-value">{state.members.length}</div>
        </div>
        <div className="memb-stat">
          <div className="memb-stat-label">Key epoch</div>
          <div className="memb-stat-value">{state.epoch}</div>
        </div>
        <div className="memb-stat">
          <div className="memb-stat-label">Last rekey</div>
          <div className="memb-stat-value mono">
            {state.lastRekeyTs != null ? fmtSec(state.lastRekeyTs) : "—"}
          </div>
        </div>
      </div>

      <div className="memb-section-title">Active member UIDs</div>
      <div className="memb-members">
        {state.members.length === 0 ? (
          <span className="memb-empty">(none)</span>
        ) : (
          state.members.map((uid) => (
            <span key={uid} className="memb-chip mono">
              uid={uid}
            </span>
          ))
        )}
      </div>

      <div className="memb-section-title">Ratchet history</div>
      <div className="memb-events">
        {state.events.length === 0 ? (
          <span className="memb-empty">(none yet)</span>
        ) : (
          state.events
            .slice()
            .reverse()
            .map((e, i) => (
              <div key={i} className={`memb-event memb-${e.kind}`}>
                <span className="memb-event-ts mono">{fmtSec(e.ts_ms)}</span>
                <span className="memb-event-kind">{e.kind}</span>
                <span className="memb-event-uid mono">
                  uid={e.uid ?? "-"}
                </span>
                <span className="memb-event-change mono">
                  @change={e.change_id}
                </span>
              </div>
            ))
        )}
      </div>

      <div className="memb-hint">
        Each <code>add</code> / <code>remove</code> triggers a key ratchet so
        prior ciphertexts stay unreadable for removed members and joining
        members can't decrypt past traffic.
      </div>
    </div>
  );
}
