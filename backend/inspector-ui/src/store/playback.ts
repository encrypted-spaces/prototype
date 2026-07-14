// Playback state hook. One RAF loop that advances the cursor at a fixed rate
// (events per second scaled by `speed`). Independent of `ts_ms` gaps so dense
// bursts of events don't stall the cursor.

import { useCallback, useEffect, useRef, useState } from "react";
import type { InspectorEvent } from "../types/events";

export interface PlaybackState {
  cursor: number;
  playing: boolean;
  speed: number;
  setCursor: (i: number) => void;
  setPlaying: (p: boolean) => void;
  setSpeed: (s: number) => void;
  step: (delta: number) => void;
  jumpToStart: () => void;
  jumpToEnd: () => void;
}

/** ms between event advances at 1× speed. */
const BASE_INTERVAL_MS = 220;

export function usePlayback(events: InspectorEvent[]): PlaybackState {
  const [cursor, setCursorState] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);

  // Refs let the RAF loop see current values without re-mounting on every
  // cursor change (which would otherwise tear down the loop each tick).
  const cursorRef = useRef(0);
  const speedRef = useRef(1);
  const eventsRef = useRef(events);

  useEffect(() => {
    cursorRef.current = cursor;
  }, [cursor]);
  useEffect(() => {
    speedRef.current = speed;
  }, [speed]);
  useEffect(() => {
    eventsRef.current = events;
  }, [events]);

  const setCursor = useCallback(
    (i: number) => {
      const max = Math.max(0, eventsRef.current.length - 1);
      const clamped = Math.max(0, Math.min(max, i));
      cursorRef.current = clamped;
      setCursorState(clamped);
    },
    [],
  );

  useEffect(() => {
    if (!playing || events.length === 0) return;
    let raf = 0;
    let last = performance.now();
    const tick = (now: number) => {
      const interval = Math.max(20, BASE_INTERVAL_MS / speedRef.current);
      const ahead = Math.floor((now - last) / interval);
      if (ahead > 0) {
        last += ahead * interval;
        const evs = eventsRef.current;
        const next = Math.min(evs.length - 1, cursorRef.current + ahead);
        if (next !== cursorRef.current) {
          cursorRef.current = next;
          setCursorState(next);
        }
        if (next >= evs.length - 1) {
          setPlaying(false);
          return;
        }
      }
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [playing, events]);

  return {
    cursor,
    playing,
    speed,
    setCursor,
    setPlaying,
    setSpeed,
    step: (delta) => setCursor(cursorRef.current + delta),
    jumpToStart: () => setCursor(0),
    jumpToEnd: () => setCursor(events.length - 1),
  };
}
