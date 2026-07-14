import { useEffect, useMemo, useRef, useState } from "react";
import { hierarchy, tree as d3tree, type HierarchyPointNode } from "d3-hierarchy";
import { diffTrees } from "../store/tree";
import type { MerkTreeNode } from "../types/events";
import type { TreeState } from "../store/tree";

const NODE_W = 110;
const NODE_H = 40;
const ROW_GAP = 70;
const SIBLING_GAP = 14;
const MARGIN = 30;
const MIN_SCALE = 0.15;
const MAX_SCALE = 3;
const ZOOM_STEP = 1.15;

interface Viewport {
  tx: number;
  ty: number;
  scale: number;
}

const IDENTITY_VIEWPORT: Viewport = { tx: 0, ty: 0, scale: 1 };

interface Props {
  state: TreeState;
}

export function MerkTreePanel({ state }: Props) {
  const [showInternal, setShowInternal] = useState(true);
  const [hover, setHover] = useState<MerkTreeNode | null>(null);
  const [vp, setVp] = useState<Viewport>(IDENTITY_VIEWPORT);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const dragRef = useRef<{ x: number; y: number; tx: number; ty: number } | null>(
    null,
  );

  const visibleRoot = useMemo(
    () => (showInternal ? state.current : filterInternal(state.current)),
    [state.current, showInternal],
  );
  const previousVisible = useMemo(
    () => (showInternal ? state.previous : filterInternal(state.previous)),
    [state.previous, showInternal],
  );

  const layout = useMemo(() => layoutWithD3(visibleRoot), [visibleRoot]);
  const diff = useMemo(
    () => diffTrees(visibleRoot, previousVisible),
    [visibleRoot, previousVisible],
  );

  if (!state.current) {
    return (
      <div className="merk-tree empty">
        Waiting for a <code>MerkSnapshot</code> event…
      </div>
    );
  }
  if (!layout) {
    return (
      <div className="merk-tree empty">
        No visible nodes — try toggling <em>show internal</em>.
      </div>
    );
  }

  const { nodes, links, width, height } = layout;

  // Convert a pointer event's client coords into the SVG's intrinsic
  // (pre-transform) coordinate space. Needed for "zoom toward cursor".
  const svgPoint = (clientX: number, clientY: number) => {
    const svg = svgRef.current;
    if (!svg) return { x: 0, y: 0 };
    const rect = svg.getBoundingClientRect();
    return { x: clientX - rect.left, y: clientY - rect.top };
  };

  const onWheel: React.WheelEventHandler<SVGSVGElement> = (e) => {
    e.preventDefault();
    const factor = e.deltaY < 0 ? ZOOM_STEP : 1 / ZOOM_STEP;
    setVp((cur) => {
      const next = Math.max(MIN_SCALE, Math.min(MAX_SCALE, cur.scale * factor));
      // Zoom toward the cursor: keep the point under the pointer stationary.
      const p = svgPoint(e.clientX, e.clientY);
      const k = next / cur.scale;
      return {
        scale: next,
        tx: p.x - (p.x - cur.tx) * k,
        ty: p.y - (p.y - cur.ty) * k,
      };
    });
  };

  const onMouseDown: React.MouseEventHandler<SVGSVGElement> = (e) => {
    // Left button only; ignore clicks on nodes (the elements have their
    // own hover/select handlers and shouldn't steal a pan).
    if (e.button !== 0) return;
    if ((e.target as Element).closest(".merk-node")) return;
    dragRef.current = { x: e.clientX, y: e.clientY, tx: vp.tx, ty: vp.ty };
  };

  // Global window listeners so the drag survives the cursor leaving the SVG.
  useEffect(() => {
    const onMove = (e: MouseEvent) => {
      const d = dragRef.current;
      if (!d) return;
      setVp((cur) => ({
        ...cur,
        tx: d.tx + (e.clientX - d.x),
        ty: d.ty + (e.clientY - d.y),
      }));
    };
    const onUp = () => {
      dragRef.current = null;
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
    return () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
  }, []);

  const resetView = () => setVp(IDENTITY_VIEWPORT);

  return (
    <div className="merk-tree">
      <div className="merk-toolbar">
        <span className="badge">{state.nodeCount} nodes total</span>
        <span className="badge">{nodes.length} shown</span>
        <span className="badge">change #{state.changeId}</span>
        <span className="legend">
          <span className="dot legend-added" /> added
          <span className="dot legend-changed" /> changed
        </span>
        <button
          className="merk-reset"
          onClick={resetView}
          title="Reset pan/zoom"
        >
          Reset view ({Math.round(vp.scale * 100)}%)
        </button>
        <label className="internal-toggle">
          <input
            type="checkbox"
            checked={showInternal}
            onChange={(e) => setShowInternal(e.target.checked)}
          />
          Show internal nodes
        </label>
      </div>
      <div className="merk-scroll">
        <svg
          ref={svgRef}
          className="merk-svg merk-svg-pannable"
          width="100%"
          height="100%"
          onWheel={onWheel}
          onMouseDown={onMouseDown}
        >
          <g transform={`translate(${vp.tx}, ${vp.ty}) scale(${vp.scale})`}>
            {/* Underlay sized to the laid-out tree so blank space inside
                the panned area is clickable for pans. */}
            <rect
              width={width}
              height={height}
              fill="transparent"
              pointerEvents="all"
            />
            <g className="edges">
              {links.map((l) => {
                const key = `${l.source.data.key_hex}-${l.target.data.key_hex}`;
                return <Edge key={key} source={l.source} target={l.target} />;
              })}
            </g>
            <g className="nodes">
              {nodes.map((n) => (
                <TreeNode
                  key={n.data.key_hex}
                  node={n}
                  change={diff.get(n.data.key_hex) ?? "unchanged"}
                  hover={hover === n.data}
                  onHover={() => setHover(n.data)}
                  onLeave={() => setHover((h) => (h === n.data ? null : h))}
                />
              ))}
            </g>
          </g>
        </svg>
      </div>
      {hover && <NodeDetails node={hover} />}
    </div>
  );
}

// --------------------------------------------------------------- subcomponents

function Edge({
  source,
  target,
}: {
  source: HierarchyPointNode<MerkTreeNode>;
  target: HierarchyPointNode<MerkTreeNode>;
}) {
  // Smooth cubic bezier from parent bottom to child top — looks more like a
  // typical tree visualizer than straight lines.
  const x1 = source.x;
  const y1 = source.y + NODE_H / 2;
  const x2 = target.x;
  const y2 = target.y - NODE_H / 2;
  const my = (y1 + y2) / 2;
  const d = `M${x1},${y1} C${x1},${my} ${x2},${my} ${x2},${y2}`;
  return <path d={d} className="merk-edge" />;
}

function TreeNode({
  node,
  change,
  hover,
  onHover,
  onLeave,
}: {
  node: HierarchyPointNode<MerkTreeNode>;
  change: "added" | "changed" | "unchanged";
  hover: boolean;
  onHover: () => void;
  onLeave: () => void;
}) {
  const d = node.data;
  const cls = [
    "merk-node",
    `kind-${d.kind}`,
    change !== "unchanged" ? `change-${change}` : "",
    hover ? "hover" : "",
  ]
    .filter(Boolean)
    .join(" ");
  return (
    <g
      className={cls}
      transform={`translate(${node.x},${node.y})`}
      onMouseEnter={onHover}
      onMouseLeave={onLeave}
    >
      <rect
        x={-NODE_W / 2}
        y={-NODE_H / 2}
        width={NODE_W}
        height={NODE_H}
        rx={6}
        ry={6}
        className="merk-node-rect"
      />
      <text y={-3} className="merk-node-label">
        {truncate(d.label, 16)}
      </text>
      <text y={12} className="merk-node-hash">
        {d.hash.slice(0, 10)}…
      </text>
    </g>
  );
}

function NodeDetails({ node }: { node: MerkTreeNode }) {
  return (
    <div className="merk-details">
      <div>
        <span className="detail-label">label</span>
        <span className="detail-value mono">{node.label}</span>
      </div>
      <div>
        <span className="detail-label">kind</span>
        <span className="detail-value">{node.kind}</span>
      </div>
      <div>
        <span className="detail-label">hash</span>
        <span className="detail-value mono">{node.hash}…</span>
      </div>
      <div>
        <span className="detail-label">value size</span>
        <span className="detail-value">{node.value_size} B</span>
      </div>
      <div>
        <span className="detail-label">key (hex)</span>
        <span className="detail-value mono">{truncate(node.key_hex, 80)}</span>
      </div>
    </div>
  );
}

function truncate(s: string, n: number): string {
  if (s.length <= n) return s;
  return s.slice(0, n - 1) + "…";
}

// --------------------------------------------------------------- layout

interface LayoutResult {
  nodes: HierarchyPointNode<MerkTreeNode>[];
  links: { source: HierarchyPointNode<MerkTreeNode>; target: HierarchyPointNode<MerkTreeNode> }[];
  width: number;
  height: number;
}

function layoutWithD3(root: MerkTreeNode | null): LayoutResult | null {
  if (!root) return null;
  const h = hierarchy(root, (d) => {
    const children: MerkTreeNode[] = [];
    if (d.left) children.push(d.left);
    if (d.right) children.push(d.right);
    return children.length ? children : null;
  });
  const leafCount = h.leaves().length;
  const depth = h.height;
  const treeWidth = Math.max(leafCount * (NODE_W + SIBLING_GAP), 400);
  const treeHeight = (depth + 1) * ROW_GAP;
  const layout = d3tree<MerkTreeNode>()
    .size([treeWidth, treeHeight])
    .separation((a, b) => (a.parent === b.parent ? 1 : 1.4));
  layout(h);
  // Shift everything by margin so root isn't clipped at the edges.
  h.each((n) => {
    n.x = (n.x ?? 0) + MARGIN;
    n.y = (n.y ?? 0) + MARGIN;
  });
  const nodes = h.descendants() as HierarchyPointNode<MerkTreeNode>[];
  const links = h.links().map((l) => ({
    source: l.source as HierarchyPointNode<MerkTreeNode>,
    target: l.target as HierarchyPointNode<MerkTreeNode>,
  }));
  return {
    nodes,
    links,
    width: treeWidth + MARGIN * 2,
    height: treeHeight + MARGIN * 2,
  };
}

/**
 * Strip internal-table subtrees. Returns a new tree with internal-kind
 * nodes elided; their non-internal descendants are promoted into the
 * parent's child slot. This is an educational view, not a faithful AVL.
 */
function filterInternal(root: MerkTreeNode | null): MerkTreeNode | null {
  if (!root) return null;
  function isInternal(n: MerkTreeNode): boolean {
    if (n.label.startsWith("_")) return true;
    if (n.label.startsWith("schema:_")) return true;
    if (n.label.startsWith("idx:_")) return true;
    return false;
  }
  function walk(n: MerkTreeNode | null): MerkTreeNode | null {
    if (!n) return null;
    const left = walk(n.left);
    const right = walk(n.right);
    if (isInternal(n)) return left ?? right;
    return { ...n, left, right };
  }
  return walk(root);
}
