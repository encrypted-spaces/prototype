// Mirror of backend/server/src/inspector/mod.rs `InspectorEvent`.
// Hand-maintained for Phase 1. Phase 1+ may codegen from a JSON Schema.

export type ConnectionEvent = "connect" | "disconnect";
export type MembershipEventKind = "add" | "remove";
export type ProofKind = "update" | "select" | "fast_forward";

export interface ColumnInfo {
  name: string;
  type_label: string;
  plaintext: boolean;
  indexed: boolean;
}

export interface TableInfo {
  name: string;
  internal: boolean;
  auto_increment: boolean;
  columns: ColumnInfo[];
}

export type EntrySummary =
  | {
      key_kind: "column";
      table: string;
      row_id: number;
      column: string;
      encrypted: boolean;
      value_size: number;
      value_preview: string;
    }
  | { key_kind: "row"; table: string; row_id: number; value_size: number }
  | {
      key_kind: "index";
      table: string;
      column: string;
      row_id: number;
      value_size: number;
    }
  | { key_kind: "other"; label: string; value_size: number };

export interface SchemaSnapshotEv {
  kind: "SchemaSnapshot";
  ts_ms: number;
  space_id: string;
  tables: TableInfo[];
}

export interface MerkTreeNode {
  key_hex: string;
  label: string;
  kind: "column" | "row" | "index" | "schema" | "other";
  hash: string;
  value_size: number;
  left: MerkTreeNode | null;
  right: MerkTreeNode | null;
}

export interface MerkSnapshotEv {
  kind: "MerkSnapshot";
  ts_ms: number;
  space_id: string;
  change_id: number;
  node_count: number;
  root: MerkTreeNode | null;
}

export interface ConnectionEv {
  kind: "Connection";
  ts_ms: number;
  space_id: string;
  uid: number | null;
  event: ConnectionEvent;
}

export interface RequestEv {
  kind: "Request";
  ts_ms: number;
  space_id: string;
  request_id: string;
  op: string;
  uid: number | null;
}

export interface MerkUpdateEv {
  kind: "MerkUpdate";
  ts_ms: number;
  space_id: string;
  change_id: number;
  op_type: string;
  old_root: string;
  new_root: string;
  rows_affected: number;
  entries: EntrySummary[];
}

export interface ChangelogAppendEv {
  kind: "ChangelogAppend";
  ts_ms: number;
  space_id: string;
  change_id: number;
  op_type: string;
  clc_root: string;
  entry_size_bytes: number;
}

export interface MembershipEv {
  kind: "Membership";
  ts_ms: number;
  space_id: string;
  event: MembershipEventKind;
  change_id: number;
  uid: number | null;
}

export interface ProofEmittedEv {
  kind: "ProofEmitted";
  ts_ms: number;
  space_id: string;
  proof_kind: ProofKind;
  proof_size_bytes: number;
  covers_entries: number | null;
  gen_ms: number | null;
}

export type InspectorEvent =
  | SchemaSnapshotEv
  | MerkSnapshotEv
  | ConnectionEv
  | RequestEv
  | MerkUpdateEv
  | ChangelogAppendEv
  | MembershipEv
  | ProofEmittedEv;

export const EVENT_KINDS: InspectorEvent["kind"][] = [
  "SchemaSnapshot",
  "MerkSnapshot",
  "Connection",
  "Request",
  "MerkUpdate",
  "ChangelogAppend",
  "Membership",
  "ProofEmitted",
];

export function parseNdjson(text: string): InspectorEvent[] {
  const out: InspectorEvent[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line) continue;
    try {
      out.push(JSON.parse(line) as InspectorEvent);
    } catch (e) {
      console.warn("inspector: skipping malformed line", line, e);
    }
  }
  return out;
}
