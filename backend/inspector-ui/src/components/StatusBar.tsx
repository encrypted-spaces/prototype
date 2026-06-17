import type { DerivedState } from "../store/reducer";
import { truncHex } from "../store/reducer";

interface Props {
  state: DerivedState;
  filename: string | null;
  totalEvents: number;
  cursor: number;
}

export function StatusBar({ state, filename, totalEvents, cursor }: Props) {
  return (
    <header className="status-bar">
      <div className="status-section">
        <span className="status-label">Source</span>
        <span className="status-value">{filename ?? "—"}</span>
      </div>
      <div className="status-section">
        <span className="status-label">Space</span>
        <span className="status-value mono">
          {state.spaceIds[0] ? truncHex(state.spaceIds[0], 12) : "—"}
        </span>
      </div>
      <div className="status-section">
        <span className="status-label">Merk root</span>
        <span className="status-value mono">{truncHex(state.currentMerkRoot, 12)}</span>
      </div>
      <div className="status-section">
        <span className="status-label">CLC root</span>
        <span className="status-value mono">{truncHex(state.lastClcRoot, 12)}</span>
      </div>
      <div className="status-section">
        <span className="status-label">Changes</span>
        <span className="status-value">{state.changeCount}</span>
      </div>
      <div className="status-section">
        <span className="status-label">Members</span>
        <span className="status-value">{state.members.size}</span>
      </div>
      <div className="status-section">
        <span className="status-label">Position</span>
        <span className="status-value">
          {totalEvents === 0 ? "—" : `${cursor + 1} / ${totalEvents}`}
        </span>
      </div>
    </header>
  );
}
