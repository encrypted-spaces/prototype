import { useMemo, useState } from "react";
import type { TablesState } from "../store/tables";
import type { ColumnInfo, TableInfo } from "../types/events";

const FLASH_WINDOW = 6;

interface Props {
  state: TablesState;
  cursor: number;
}

export function TablesPanel({ state, cursor }: Props) {
  const [showInternal, setShowInternal] = useState(false);
  const [activeTable, setActiveTable] = useState<string | null>(null);

  const visibleTables = useMemo(() => {
    if (!state.schema) return [];
    return state.schema.filter((t) => showInternal || !t.internal);
  }, [state.schema, showInternal]);

  // Default the active tab to the first non-internal table once schema arrives.
  const active = useMemo(() => {
    if (activeTable && visibleTables.find((t) => t.name === activeTable)) {
      return activeTable;
    }
    return visibleTables[0]?.name ?? null;
  }, [activeTable, visibleTables]);

  if (!state.schema) {
    return (
      <div className="tables-panel empty">
        Waiting for a <code>SchemaSnapshot</code> event…
      </div>
    );
  }

  return (
    <div className="tables-panel">
      <div className="tables-tabs">
        {visibleTables.map((t) => {
          const rowCount = state.tables.get(t.name)?.rows.size ?? 0;
          return (
            <button
              key={t.name}
              className={`tables-tab ${active === t.name ? "active" : ""} ${t.internal ? "internal" : ""}`}
              onClick={() => setActiveTable(t.name)}
            >
              <span className="tab-name">{t.name}</span>
              <span className="tab-count">{rowCount}</span>
            </button>
          );
        })}
        <label className="internal-toggle">
          <input
            type="checkbox"
            checked={showInternal}
            onChange={(e) => setShowInternal(e.target.checked)}
          />
          Show internal
        </label>
      </div>

      {active && (
        <TableView
          schema={visibleTables.find((t) => t.name === active)!}
          state={state}
          cursor={cursor}
        />
      )}
    </div>
  );
}

function TableView({
  schema,
  state,
  cursor,
}: {
  schema: TableInfo;
  state: TablesState;
  cursor: number;
}) {
  const tbl = state.tables.get(schema.name);
  const rowIds = useMemo(() => {
    if (!tbl) return [] as number[];
    return Array.from(tbl.rows.keys()).sort((a, b) => a - b);
  }, [tbl]);

  return (
    <div className="table-view">
      <div className="table-meta">
        <span className="badge">{schema.columns.length} cols</span>
        <span className="badge">{rowIds.length} rows</span>
        {schema.internal && <span className="badge internal-badge">internal</span>}
        {!schema.auto_increment && (
          <span className="badge">manual id</span>
        )}
        <ColumnLegend columns={schema.columns} />
      </div>
      <div className="table-scroll">
        <table className="data-table">
          <thead>
            <tr>
              {schema.columns.map((c) => (
                <th key={c.name} className={c.plaintext ? "col-plaintext" : "col-encrypted"}>
                  <div className="th-name">
                    {!c.plaintext && <span className="lock">🔒</span>}
                    {c.name}
                  </div>
                  <div className="th-type">
                    {c.type_label}
                    {c.indexed && " · idx"}
                  </div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rowIds.length === 0 ? (
              <tr>
                <td colSpan={schema.columns.length} className="empty-row">
                  no rows yet
                </td>
              </tr>
            ) : (
              rowIds.map((rid) => (
                <DataRow
                  key={rid}
                  rowId={rid}
                  schema={schema}
                  row={tbl!.rows.get(rid)!}
                  cursor={cursor}
                />
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function DataRow({
  rowId,
  schema,
  row,
  cursor,
}: {
  rowId: number;
  schema: TableInfo;
  row: { last_event_idx: number; columns: Map<string, { encrypted: boolean; value_size: number; preview: string; last_event_idx: number }> };
  cursor: number;
}) {
  return (
    <tr>
      {schema.columns.map((c) => {
        const cell = row.columns.get(c.name);
        // The `id` column is the row's primary key: it lives in the Merk key,
        // not as a written column value, so a row never has an `id` cell.
        // Render it from `rowId` rather than showing an empty "—".
        if (c.name === "id") {
          const recent =
            cell != null && cursor - cell.last_event_idx <= FLASH_WINDOW;
          const cls = ["cell", "cell-pk", recent ? "cell-recent" : ""]
            .filter(Boolean)
            .join(" ");
          return (
            <td key={c.name} className={cls}>
              {rowId}
            </td>
          );
        }
        if (!cell) {
          return <td key={c.name} className="cell empty-cell">—</td>;
        }
        const recent = cursor - cell.last_event_idx <= FLASH_WINDOW;
        const cls = [
          "cell",
          cell.encrypted ? "cell-encrypted" : "cell-plaintext",
          recent ? "cell-recent" : "",
        ]
          .filter(Boolean)
          .join(" ");
        return (
          <td key={c.name} className={cls} title={cell.preview}>
            {cell.preview}
          </td>
        );
      })}
    </tr>
  );
}

function ColumnLegend({ columns }: { columns: ColumnInfo[] }) {
  const plain = columns.filter((c) => c.plaintext).length;
  const enc = columns.length - plain;
  return (
    <span className="legend">
      <span className="dot plain" /> {plain} plaintext
      <span className="dot enc" /> {enc} encrypted
    </span>
  );
}
