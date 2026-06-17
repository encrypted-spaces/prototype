import type { PlaybackState } from "../store/playback";

const SPEEDS = [0.25, 0.5, 1, 2, 4, 8];

interface Props {
  playback: PlaybackState;
  total: number;
}

export function PlaybackControls({ playback, total }: Props) {
  const { cursor, playing, speed, setCursor, setPlaying, setSpeed,
          step, jumpToStart, jumpToEnd } = playback;
  const atEnd = cursor >= total - 1;

  return (
    <div className="playback-controls">
      <button onClick={jumpToStart} title="Jump to start">⏮</button>
      <button onClick={() => step(-1)} title="Previous event">◀︎</button>
      <button
        onClick={() => {
          if (atEnd) jumpToStart();
          setPlaying(!playing);
        }}
        title={playing ? "Pause" : "Play"}
      >
        {playing ? "⏸" : "▶︎"}
      </button>
      <button onClick={() => step(1)} title="Next event">▶▶︎</button>
      <button onClick={jumpToEnd} title="Jump to end">⏭</button>

      <label className="speed">
        Speed
        <select
          value={speed}
          onChange={(e) => setSpeed(Number(e.target.value))}
        >
          {SPEEDS.map((s) => (
            <option key={s} value={s}>{s}×</option>
          ))}
        </select>
      </label>

      <input
        type="range"
        className="scrubber"
        min={0}
        max={Math.max(0, total - 1)}
        value={cursor}
        onChange={(e) => setCursor(Number(e.target.value))}
        disabled={total === 0}
      />
    </div>
  );
}
