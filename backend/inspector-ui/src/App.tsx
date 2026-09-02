import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { FilePicker } from "./components/FilePicker";
import { LiveSource } from "./components/LiveSource";
import { StatusBar } from "./components/StatusBar";
import { WireLog } from "./components/WireLog";
import { OperationsLog } from "./components/OperationsLog";
import { PlaybackControls } from "./components/PlaybackControls";
import { JsonDrawer } from "./components/JsonDrawer";
import { TablesPanel } from "./components/TablesPanel";
import { MmrPanel } from "./components/MmrPanel";
import { MembershipPanel } from "./components/MembershipPanel";
import { ProofPanel } from "./components/ProofPanel";
import { ExplainBanner } from "./components/Explain";
import { deriveStateAt } from "./store/reducer";
import { deriveTablesAt } from "./store/tables";
import { deriveMmrAt } from "./store/mmr";
import { deriveMembershipAt } from "./store/membership";
import { usePlayback } from "./store/playback";
import type { InspectorEvent } from "./types/events";
import "./app.css";

type RightTab = "tables" | "mmr" | "members" | "proofs" | "json";
type SourceMode = "file" | "live";
type ViewMode = "operations" | "raw";

export default function App() {
  const [events, setEvents] = useState<InspectorEvent[]>([]);
  const [filename, setFilename] = useState<string | null>(null);
  const [drawerIdx, setDrawerIdx] = useState<number | null>(null);
  const [rightTab, setRightTab] = useState<RightTab>("tables");
  const [sourceMode, setSourceMode] = useState<SourceMode>("file");
  const [viewMode, setViewMode] = useState<ViewMode>("operations");
  const [explainMode, setExplainMode] = useState<boolean>(false);
  const [hideSelects, setHideSelects] = useState<boolean>(false);
  const playback = usePlayback(events);
  const playbackRef = useRef(playback);
  useEffect(() => {
    playbackRef.current = playback;
  }, [playback]);

  const derived = useMemo(
    () => deriveStateAt(events, playback.cursor),
    [events, playback.cursor],
  );
  const tables = useMemo(
    () => deriveTablesAt(events, playback.cursor),
    [events, playback.cursor],
  );
  const mmr = useMemo(
    () => deriveMmrAt(events, playback.cursor),
    [events, playback.cursor],
  );
  const membership = useMemo(
    () => deriveMembershipAt(events, playback.cursor),
    [events, playback.cursor],
  );

  const drawerEvent = drawerIdx == null ? null : events[drawerIdx] ?? null;

  // When a wire-log row is clicked, switch to the JSON tab so the user
  // actually sees what they asked for instead of just changing cursor.
  useEffect(() => {
    if (drawerIdx != null) setRightTab("json");
  }, [drawerIdx]);

  const handleLiveEvent = useCallback((ev: InspectorEvent) => {
    setEvents((prev) => {
      const next = [...prev, ev];
      // Live mode pins the cursor to the newest event so the user sees it
      // arrive. A click in the wire log breaks the pin via setCursor.
      playbackRef.current.setCursor(next.length - 1);
      return next;
    });
  }, []);

  const handleClear = useCallback(() => {
    setEvents([]);
    setDrawerIdx(null);
    setFilename(null);
  }, []);

  return (
    <div className="app">
      <StatusBar
        state={derived}
        filename={filename ?? (sourceMode === "live" ? "live" : null)}
        totalEvents={events.length}
        cursor={playback.cursor}
      />

      <div className="toolbar">
        <div className="source-toggle">
          <button
            className={sourceMode === "file" ? "active" : ""}
            onClick={() => setSourceMode("file")}
          >
            File
          </button>
          <button
            className={sourceMode === "live" ? "active" : ""}
            onClick={() => setSourceMode("live")}
          >
            Live
          </button>
        </div>
        {sourceMode === "file" ? (
          <FilePicker
            onLoad={(evs, name) => {
              setEvents(evs);
              setFilename(name);
              setDrawerIdx(null);
              setRightTab("tables");
            }}
          />
        ) : (
          <LiveSource onEvent={handleLiveEvent} onClear={handleClear} />
        )}
        <div className="source-toggle view-toggle">
          <button
            className={viewMode === "operations" ? "active" : ""}
            onClick={() => setViewMode("operations")}
          >
            Operations
          </button>
          <button
            className={viewMode === "raw" ? "active" : ""}
            onClick={() => setViewMode("raw")}
          >
            Raw
          </button>
        </div>
        <button
          className={`explain-toggle ${explainMode ? "active" : ""}`}
          onClick={() => setExplainMode((v) => !v)}
          title="Show plain-English annotations on every panel"
        >
          {explainMode ? "Explain: on" : "Explain"}
        </button>
        {viewMode === "operations" && (
          <button
            className={`explain-toggle ${hideSelects ? "active" : ""}`}
            onClick={() => setHideSelects((v) => !v)}
            title="Hide read-only Select operations (and their proofs) from the log"
          >
            {hideSelects ? "Selects: hidden" : "Hide selects"}
          </button>
        )}
        <PlaybackControls playback={playback} total={events.length} />
      </div>

      <main className="main">
        {viewMode === "raw" ? (
          <div className="panel-with-explain">
            {explainMode && <ExplainBanner topic="wire" />}
            <WireLog
              events={events}
              cursor={playback.cursor}
              onSelect={(i) => {
                playback.setCursor(i);
                setDrawerIdx(i);
              }}
            />
          </div>
        ) : (
          <div className="panel-with-explain">
            {explainMode && <ExplainBanner topic="operations" />}
            <OperationsLog
              events={events}
              cursor={playback.cursor}
              hideSelects={hideSelects}
              onSelect={(i) => {
                playback.setCursor(i);
                setDrawerIdx(i);
              }}
            />
          </div>
        )}
        <div className="right-pane">
          <div className="right-tabs">
            <button
              className={`right-tab ${rightTab === "tables" ? "active" : ""}`}
              onClick={() => setRightTab("tables")}
            >
              Tables
            </button>
            <button
              className={`right-tab ${rightTab === "mmr" ? "active" : ""}`}
              onClick={() => setRightTab("mmr")}
            >
              Changelog MMR
            </button>
            <button
              className={`right-tab ${rightTab === "members" ? "active" : ""}`}
              onClick={() => setRightTab("members")}
            >
              Members
            </button>
            <button
              className={`right-tab ${rightTab === "proofs" ? "active" : ""}`}
              onClick={() => setRightTab("proofs")}
            >
              Proofs
            </button>
            <button
              className={`right-tab ${rightTab === "json" ? "active" : ""}`}
              onClick={() => setRightTab("json")}
              disabled={!drawerEvent}
            >
              Event JSON {drawerEvent ? `· #${drawerIdx}` : ""}
            </button>
          </div>
          <div className="right-body">
            {rightTab === "tables" && (
              <div className="panel-with-explain">
                {explainMode && <ExplainBanner topic="tables" />}
                <TablesPanel state={tables} cursor={playback.cursor} />
              </div>
            )}
            {rightTab === "mmr" && (
              <div className="panel-with-explain">
                {explainMode && <ExplainBanner topic="mmr" />}
                <MmrPanel state={mmr} />
              </div>
            )}
            {rightTab === "members" && (
              <div className="panel-with-explain">
                {explainMode && <ExplainBanner topic="members" />}
                <MembershipPanel state={membership} />
              </div>
            )}
            {rightTab === "proofs" && (
              <div className="panel-with-explain">
                {explainMode && <ExplainBanner topic="proofs" />}
                <ProofPanel
                  events={events}
                  cursor={playback.cursor}
                  onSelect={(i) => {
                    playback.setCursor(i);
                    setDrawerIdx(i);
                  }}
                />
              </div>
            )}
            {rightTab === "json" && (
              <JsonDrawer event={drawerEvent} onClose={() => setDrawerIdx(null)} />
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
