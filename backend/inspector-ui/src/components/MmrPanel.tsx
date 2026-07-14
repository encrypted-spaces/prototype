// Right-pane panel: changelog MMR visualization. Peaks render as triangles
// (taller = covers more leaves); recent leaves listed below. Cursor-aware
// via deriveMmrAt.

import { useState } from "react";
import type { MmrLeaf, MmrPeak, MmrState } from "../store/mmr";
import { fmtMs } from "../store/reducer";

const PEAK_BASE = 26; // px per leaf at the base of the smallest peak
const PEAK_UNIT_H = 18; // vertical px per height level
const PEAK_GAP = 14;
const PEAK_TOP_MARGIN = 16;
const PEAK_BOTTOM_MARGIN = 28;

interface Props {
  state: MmrState;
}

export function MmrPanel({ state }: Props) {
  const [hover, setHover] = useState<MmrPeak | null>(null);

  if (state.treeSize === 0) {
    return (
      <div className="mmr-panel empty">
        Waiting for a <code>ChangelogAppend</code> event…
      </div>
    );
  }

  const layout = layoutPeaks(state.peaks);

  return (
    <div className="mmr-panel">
      <div className="mmr-toolbar">
        <span className="badge">{state.treeSize} leaves</span>
        <span className="badge">
          {state.peaks.length} peak{state.peaks.length === 1 ? "" : "s"}
        </span>
        {state.clcRoot && (
          <span className="badge mono" title={state.clcRoot}>
            clc {state.clcRoot.slice(0, 10)}…
          </span>
        )}
      </div>

      <div className="mmr-scroll">
        <svg width={layout.width} height={layout.height} className="mmr-svg">
          {layout.peaks.map((p, i) => (
            <PeakTriangle
              key={i}
              peak={p}
              hover={hover === p.peak}
              onHover={() => setHover(p.peak)}
              onLeave={() => setHover((h) => (h === p.peak ? null : h))}
            />
          ))}
        </svg>
      </div>

      {hover && <PeakDetails peak={hover} />}

      <div className="mmr-section-title">
        Leaves <span className="mmr-leaf-count">({state.leaves.length})</span>
      </div>
      <div className="mmr-leaves">
        {[...state.leaves].reverse().map((leaf) => (
          <LeafRow key={leaf.index} leaf={leaf} />
        ))}
      </div>
    </div>
  );
}

// --------------------------------------------------------------- subcomponents

interface LaidOutPeak {
  peak: MmrPeak;
  x: number; // center x
  baseY: number;
  width: number;
  height: number;
}

function layoutPeaks(peaks: MmrPeak[]): {
  peaks: LaidOutPeak[];
  width: number;
  height: number;
} {
  // Sort tallest first (highest height) for the classic mountain-range look.
  const sorted = [...peaks].sort((a, b) => b.height - a.height);
  const maxH = sorted[0]?.height ?? 0;
  const baseY = PEAK_TOP_MARGIN + (maxH + 1) * PEAK_UNIT_H;

  let x = PEAK_GAP;
  const laid: LaidOutPeak[] = sorted.map((peak) => {
    const w = PEAK_BASE * Math.max(peak.leafCount, 1);
    const h = (peak.height + 1) * PEAK_UNIT_H;
    const cx = x + w / 2;
    x += w + PEAK_GAP;
    return { peak, x: cx, baseY, width: w, height: h };
  });

  return {
    peaks: laid,
    width: Math.max(x, 360),
    height: baseY + PEAK_BOTTOM_MARGIN,
  };
}

function PeakTriangle({
  peak: p,
  hover,
  onHover,
  onLeave,
}: {
  peak: LaidOutPeak;
  hover: boolean;
  onHover: () => void;
  onLeave: () => void;
}) {
  const apexX = p.x;
  const apexY = p.baseY - p.height;
  const leftX = p.x - p.width / 2;
  const rightX = p.x + p.width / 2;
  const d = `M${leftX},${p.baseY} L${apexX},${apexY} L${rightX},${p.baseY} Z`;
  return (
    <g
      className={`mmr-peak ${hover ? "hover" : ""}`}
      onMouseEnter={onHover}
      onMouseLeave={onLeave}
    >
      <path d={d} className="mmr-peak-path" />
      <text x={apexX} y={apexY - 5} className="mmr-peak-label">
        h={p.peak.height}
      </text>
      <text x={apexX} y={p.baseY + 14} className="mmr-peak-count">
        {p.peak.leafCount}
        {p.peak.leafCount === 1 ? " leaf" : " leaves"}
      </text>
    </g>
  );
}

function PeakDetails({ peak }: { peak: MmrPeak }) {
  return (
    <div className="mmr-details">
      <div>
        <span className="detail-label">height</span>
        <span className="detail-value">{peak.height}</span>
      </div>
      <div>
        <span className="detail-label">covers</span>
        <span className="detail-value">
          {peak.leafCount} leaf{peak.leafCount === 1 ? "" : "s"}
        </span>
      </div>
      <div>
        <span className="detail-label">range</span>
        <span className="detail-value mono">
          [{peak.startIndex}, {peak.endIndex}]
        </span>
      </div>
    </div>
  );
}

function LeafRow({ leaf }: { leaf: MmrLeaf }) {
  return (
    <div className="mmr-leaf">
      <span className="mmr-leaf-idx mono">#{leaf.index}</span>
      <span className="mmr-leaf-op">{leaf.op_type}</span>
      <span className="mmr-leaf-size mono">{leaf.entry_size_bytes} B</span>
      <span className="mmr-leaf-root mono" title={leaf.clc_root}>
        {leaf.clc_root.slice(0, 10)}…
      </span>
      <span className="mmr-leaf-ts mono">{fmtMs(leaf.ts_ms)}</span>
    </div>
  );
}
