// Tracks the current Merk tree (latest MerkSnapshot ≤ cursor) and the
// previous one so the UI can diff them and highlight changed nodes.

import type { InspectorEvent, MerkTreeNode } from "../types/events";

export interface TreeState {
  current: MerkTreeNode | null;
  previous: MerkTreeNode | null;
  changeId: number;
  nodeCount: number;
}

export function emptyTreeState(): TreeState {
  return { current: null, previous: null, changeId: 0, nodeCount: 0 };
}

/** Linear scan: small recordings, so recomputing from scratch is fine. */
export function deriveTreeAt(
  events: InspectorEvent[],
  cursor: number,
): TreeState {
  const state = emptyTreeState();
  const upTo = Math.min(cursor, events.length - 1);
  for (let i = 0; i <= upTo; i++) {
    const ev = events[i];
    if (ev.kind !== "MerkSnapshot") continue;
    state.previous = state.current;
    state.current = ev.root;
    state.changeId = ev.change_id;
    state.nodeCount = ev.node_count;
  }
  return state;
}

/** Flatten a tree to a Map<key_hex, hash> for diffing. */
export function flattenHashes(root: MerkTreeNode | null): Map<string, string> {
  const out = new Map<string, string>();
  function walk(n: MerkTreeNode | null) {
    if (!n) return;
    out.set(n.key_hex, n.hash);
    walk(n.left);
    walk(n.right);
  }
  walk(root);
  return out;
}

export type NodeChange = "added" | "changed" | "unchanged";

/** Diff two trees by key. Returns a map from key_hex → change kind. */
export function diffTrees(
  current: MerkTreeNode | null,
  previous: MerkTreeNode | null,
): Map<string, NodeChange> {
  const out = new Map<string, NodeChange>();
  const prev = flattenHashes(previous);
  function walk(n: MerkTreeNode | null) {
    if (!n) return;
    const prevHash = prev.get(n.key_hex);
    if (prevHash == null) out.set(n.key_hex, "added");
    else if (prevHash !== n.hash) out.set(n.key_hex, "changed");
    else out.set(n.key_hex, "unchanged");
    walk(n.left);
    walk(n.right);
  }
  walk(current);
  return out;
}

// ---------------------------------------------------------------- layout

export interface LaidOutNode {
  node: MerkTreeNode;
  x: number;
  y: number;
  /** Width in "leaf slots" of this subtree. */
  width: number;
  depth: number;
  parentX: number | null;
  parentY: number | null;
}

export interface Layout {
  nodes: LaidOutNode[];
  width: number;  // total in leaf slots
  height: number; // max depth
}

/**
 * Lay out the tree with leaves at unit-width positions and internal nodes
 * centered above their subtrees. Simple post-order pass; good enough for
 * trees up to a few hundred nodes.
 */
export function layoutTree(root: MerkTreeNode | null): Layout {
  if (!root) return { nodes: [], width: 0, height: 0 };
  const nodes: LaidOutNode[] = [];
  let cursorX = 0;
  let maxDepth = 0;

  function walk(
    n: MerkTreeNode,
    depth: number,
    parentX: number | null,
  ): { x: number; width: number } {
    if (depth > maxDepth) maxDepth = depth;

    // Visit left subtree first to keep in-order layout (smaller keys to
    // the left), then assign this node's own slot, then right subtree.
    let leftX: number | null = null;
    let rightX: number | null = null;
    let leftWidth = 0;
    let rightWidth = 0;
    if (n.left) {
      const l = walk(n.left, depth + 1, /* will overwrite */ 0);
      leftX = l.x;
      leftWidth = l.width;
    }
    const myX = cursorX;
    cursorX += 1;
    if (n.right) {
      const r = walk(n.right, depth + 1, 0);
      rightX = r.x;
      rightWidth = r.width;
    }

    const width = 1 + leftWidth + rightWidth;
    nodes.push({
      node: n,
      x: myX,
      y: depth,
      width,
      depth,
      parentX,
      parentY: parentX == null ? null : depth - 1,
    });
    // patch children we just walked to record their parent coords
    if (leftX != null) {
      const idx = nodes.findIndex((ln) => ln.node === n.left);
      if (idx >= 0) {
        nodes[idx].parentX = myX;
        nodes[idx].parentY = depth;
      }
    }
    if (rightX != null) {
      const idx = nodes.findIndex((ln) => ln.node === n.right);
      if (idx >= 0) {
        nodes[idx].parentX = myX;
        nodes[idx].parentY = depth;
      }
    }
    return { x: myX, width };
  }

  walk(root, 0, null);
  return { nodes, width: cursorX, height: maxDepth + 1 };
}
