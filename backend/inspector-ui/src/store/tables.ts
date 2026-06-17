// Row-mirror reducer: derives a virtual DB view by replaying events 0..=cursor.
// Recomputed from scratch per cursor change (cheap for Phase-1-sized recordings);
// Phase 4+ can memoize incrementally if needed.

import type {
  EntrySummary,
  InspectorEvent,
  TableInfo,
} from "../types/events";

export interface Cell {
  encrypted: boolean;
  value_size: number;
  /** Short preview string (decoded for plaintext, hex hint for ciphertext) */
  preview: string;
  /** Index of the most recent event that wrote this cell — used for flash */
  last_event_idx: number;
}

export interface RowMirror {
  /** When did this row last change? (event index) */
  last_event_idx: number;
  /** Column name → cell */
  columns: Map<string, Cell>;
}

export interface TableMirror {
  /** Row id → row */
  rows: Map<number, RowMirror>;
}

export interface TablesState {
  /** Latest schema snapshot, or null until one arrives. */
  schema: TableInfo[] | null;
  /** Table name → table */
  tables: Map<string, TableMirror>;
}

export function emptyTablesState(): TablesState {
  return { schema: null, tables: new Map() };
}

export function deriveTablesAt(
  events: InspectorEvent[],
  cursor: number,
): TablesState {
  const state = emptyTablesState();
  const upTo = Math.min(cursor, events.length - 1);
  for (let i = 0; i <= upTo; i++) {
    const ev = events[i];
    if (ev.kind === "SchemaSnapshot") {
      state.schema = ev.tables;
      // Seed empty table mirrors for every known table so the UI has
      // something to render even before any change lands.
      for (const t of ev.tables) {
        if (!state.tables.has(t.name)) {
          state.tables.set(t.name, { rows: new Map() });
        }
      }
    } else if (ev.kind === "MerkUpdate") {
      applyEntries(state, ev.entries, i, ev.op_type);
    }
  }
  return state;
}

function applyEntries(
  state: TablesState,
  entries: EntrySummary[],
  evIdx: number,
  opType: string,
) {
  // Delete ops first: clear the affected rows before processing columns. The
  // entry list for a Delete contains all the column tombstones, so we identify
  // the row from the first column entry and erase it.
  if (opType === "Delete") {
    for (const e of entries) {
      if (e.key_kind === "column" || e.key_kind === "row") {
        const t = state.tables.get(e.table);
        if (t) t.rows.delete(e.row_id);
      }
    }
    return;
  }
  for (const e of entries) {
    if (e.key_kind !== "column") continue;
    const table = ensureTable(state, e.table);
    const row = ensureRow(table, e.row_id, evIdx);
    row.last_event_idx = evIdx;
    row.columns.set(e.column, {
      encrypted: e.encrypted,
      value_size: e.value_size,
      preview: e.value_preview,
      last_event_idx: evIdx,
    });
  }
}

function ensureTable(state: TablesState, name: string): TableMirror {
  let t = state.tables.get(name);
  if (!t) {
    t = { rows: new Map() };
    state.tables.set(name, t);
  }
  return t;
}

function ensureRow(
  table: TableMirror,
  rowId: number,
  evIdx: number,
): RowMirror {
  let r = table.rows.get(rowId);
  if (!r) {
    r = { last_event_idx: evIdx, columns: new Map() };
    table.rows.set(rowId, r);
  }
  return r;
}
