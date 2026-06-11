"use client";

import { useRef, useEffect, useCallback, useState } from "react";
import { useSpace, useSpaceDispatch } from "@/lib/store";
import { listen } from "@tauri-apps/api/event";
import * as api from "@/lib/api";

const DEBOUNCE_MS = 300;
const CURSOR_THROTTLE_MS = 50;

/**
 * Feature flag: render remote collaborators' cursor indicators (the small
 * coloured caret + name flag that floats over the notes textarea).
 * Disabled for now — flip to `true` to re-enable.
 */
const SHOW_REMOTE_CURSORS = true;

/** Assign a stable colour to each remote user based on their uid. */
const CURSOR_COLORS = [
  "#e06c75",
  "#61afef",
  "#e5c07b",
  "#98c379",
  "#c678dd",
  "#56b6c2",
  "#d19a66",
];
function colorForUid(uid: number): string {
  return CURSOR_COLORS[uid % CURSOR_COLORS.length];
}

interface RemoteCursor {
  uid: number;
  user_name: string;
  cursor: number;
  sel_end: number;
  /** Timestamp of last update — used to fade stale cursors. */
  ts: number;
}

/** Shape of ephemeral events coming from the Tauri backend. */
interface EphemeralEnvelope {
  uid: number;
  kind: string;
  payload: number[]; // serde Vec<u8> → JSON number array
}

/**
 * Shift a cursor position to account for an edit at `pos`:
 * delete `deleteCount` characters, then insert `insertLen` characters.
 */
function adjustCursor(cursor: number, pos: number, deleteCount: number, insertLen: number): number {
  if (cursor <= pos) return cursor;
  if (cursor <= pos + deleteCount) return pos + insertLen;
  return cursor - deleteCount + insertLen;
}

/**
 * Compute a minimal edit (delete + insert) between two strings by
 * finding the longest common prefix and suffix.
 */
function diffTexts(
  oldText: string,
  newText: string
): { pos: number; deleteCount: number; inserted: string } | null {
  if (oldText === newText) return null;

  // Common prefix length
  let prefix = 0;
  const minLen = Math.min(oldText.length, newText.length);
  while (prefix < minLen && oldText[prefix] === newText[prefix]) {
    prefix++;
  }

  // Common suffix length (don't overlap with prefix)
  let suffix = 0;
  while (
    suffix < oldText.length - prefix &&
    suffix < newText.length - prefix &&
    oldText[oldText.length - 1 - suffix] === newText[newText.length - 1 - suffix]
  ) {
    suffix++;
  }

  const deleteCount = oldText.length - prefix - suffix;
  const inserted = newText.slice(prefix, newText.length - suffix);
  return { pos: prefix, deleteCount, inserted };
}

export default function SharedNotes() {
  const { notesText, user } = useSpace();
  const dispatch = useSpaceDispatch();
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const mirrorRef = useRef<HTMLDivElement>(null);

  // Remote cursors keyed by uid.
  const [remoteCursors, setRemoteCursors] = useState<Map<number, RemoteCursor>>(new Map());

  // The last text confirmed from the server — our baseline for diffing.
  const lastSyncedText = useRef("");
  // Debounce timer handle.
  const debounceTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  // Whether a flush is in progress.
  const flushing = useRef(false);
  // Whether we have un-flushed local edits.
  const dirty = useRef(false);

  const myUid = user?.user_id ?? -1;

  // ── Cursor notification (throttled) ──────────────────────────────
  //
  // We deliberately broadcast the cursor only when the local text matches
  // what the server (and therefore other clients) currently has. While the
  // user is typing, the local cursor is ahead of remote text — broadcasting
  // it would make the cursor visibly overshoot on remote clients and snap
  // back when the text catches up. Instead, we broadcast on selection /
  // navigation changes (no pending edits) and once after every flush.

  const lastCursorSent = useRef(0);
  const sendCursor = useCallback((opts?: { force?: boolean }) => {
    const ta = textareaRef.current;
    if (!ta) return;
    // Suppress while local edits haven't been flushed — otherwise the
    // remote cursor jumps to a position that doesn't yet exist there.
    if (!opts?.force && ta.value !== lastSyncedText.current) return;
    const now = Date.now();
    if (!opts?.force && now - lastCursorSent.current < CURSOR_THROTTLE_MS) return;
    lastCursorSent.current = now;
    const payload = JSON.stringify({
      cursor: ta.selectionStart,
      sel_end: ta.selectionEnd,
      user_name: user?.user_name ?? "?",
    });
    api.sendEphemeral("cursor", payload).catch(() => {});
  }, [user?.user_name]);

  // ── Flush: compute diff and send to backend ──────────────────────

  const flush = useCallback(async () => {
    const ta = textareaRef.current;
    if (!ta || flushing.current) return;

    // Snapshot the textarea value at flush start. If the user keeps typing
    // during the awaits below, ta.value will diverge — we must NOT clear
    // `dirty` in the finally block in that case, or the next store update
    // would overwrite the typed-but-unsynced characters.
    const valueAtFlush = ta.value;
    const diff = diffTexts(lastSyncedText.current, valueAtFlush);
    if (!diff) {
      console.debug("[notes] flush: no diff, skipping");
      dirty.current = false;
      return;
    }

    console.debug("[notes] flush: diff", diff, "synced_len=", lastSyncedText.current.length, "local_len=", valueAtFlush.length);
    flushing.current = true;
    try {
      if (diff.deleteCount > 0) {
        console.debug("[notes] flush: notesDelete pos=", diff.pos, "count=", diff.deleteCount);
        await api.notesDelete(diff.pos, diff.deleteCount);
      }
      if (diff.inserted.length > 0) {
        console.debug("[notes] flush: notesInsert pos=", diff.pos, "text=", JSON.stringify(diff.inserted));
        await api.notesInsert(diff.pos, diff.inserted);
      }
      // Re-fetch server state to reconcile (picks up our changes + any
      // concurrent remote edits merged by the server).
      const serverText = await api.getNotes();
      console.debug("[notes] flush: reconciled, server_len=", serverText.length, "text=", JSON.stringify(serverText.slice(0, 80)));
      lastSyncedText.current = serverText;
      dispatch({ type: "setNotesText", notesText: serverText });

      // Send updated cursor position after reconciliation. Force past the
      // throttle + suppression so the remote cursor immediately reflects
      // post-flush state.
      sendCursor({ force: true });
    } catch (err) {
      console.error("Notes flush failed:", err);
      // Re-sync to recover from any inconsistency.
      try {
        const serverText = await api.getNotes();
        console.debug("[notes] flush: error-recovery, server_len=", serverText.length);
        lastSyncedText.current = serverText;
        dispatch({ type: "setNotesText", notesText: serverText });
      } catch {}
    } finally {
      flushing.current = false;
      // Only clear `dirty` if the textarea hasn't been modified since flush
      // started. Otherwise the user typed during the flush and we have
      // unflushed edits that must survive the upcoming store update.
      const stillDirty = ta.value !== valueAtFlush;
      dirty.current = stillDirty;
      if (stillDirty) {
        // Schedule another flush so the in-flight typing makes it to the server.
        if (debounceTimer.current) clearTimeout(debounceTimer.current);
        debounceTimer.current = setTimeout(() => {
          debounceTimer.current = null;
          flush();
        }, DEBOUNCE_MS);
      }
    }
  }, [dispatch, sendCursor]);

  // ── Input handler: mark dirty, reset debounce ────────────────────

  const handleInput = useCallback(() => {
    dirty.current = true;
    console.debug("[notes] input: dirty, scheduling debounce", DEBOUNCE_MS, "ms");
    if (debounceTimer.current) clearTimeout(debounceTimer.current);
    debounceTimer.current = setTimeout(() => {
      debounceTimer.current = null;
      console.debug("[notes] debounce fired, flushing");
      flush();
    }, DEBOUNCE_MS);
    // Intentionally do NOT broadcast the cursor here — sendCursor() would be
    // suppressed anyway (local text != synced text) and the post-flush
    // sendCursor({ force: true }) updates remote clients with the correct
    // post-merge position.
  }, [flush]);

  // ── On blur: flush immediately ───────────────────────────────────

  const handleBlur = useCallback(() => {
    if (debounceTimer.current) {
      clearTimeout(debounceTimer.current);
      debounceTimer.current = null;
    }
    if (dirty.current) flush();
  }, [flush]);

  // ── Send cursor on selection change ──────────────────────────────

  const handleSelect = useCallback(() => {
    sendCursor();
  }, [sendCursor]);

  // ── Sync from store (broadcast or post-flush) ───────────────────

  useEffect(() => {
    const ta = textareaRef.current;
    if (!ta) return;

    // If the user is actively typing (dirty local edits), don't clobber.
    // Our flush will reconcile.
    if (dirty.current || flushing.current) {
      console.debug("[notes] store update: SKIPPED (dirty=%s flushing=%s) notesText_len=%d", dirty.current, flushing.current, notesText.length);
      return;
    }

    // Defence in depth: even if `dirty` was cleared, never overwrite the
    // textarea while it holds characters the server hasn't seen yet. This
    // catches the race where a broadcast arrives between the input handler
    // setting `dirty=true` and React running this effect.
    if (ta.value !== lastSyncedText.current && ta.value !== notesText) {
      console.debug("[notes] store update: SKIPPED (unflushed local edits) ta_len=%d synced_len=%d notesText_len=%d",
        ta.value.length, lastSyncedText.current.length, notesText.length);
      // Make sure we eventually flush them.
      dirty.current = true;
      if (!debounceTimer.current && !flushing.current) {
        debounceTimer.current = setTimeout(() => {
          debounceTimer.current = null;
          flush();
        }, DEBOUNCE_MS);
      }
      return;
    }

    console.debug("[notes] store update: applying notesText_len=%d ta_len=%d focused=%s", notesText.length, ta.value.length, document.activeElement === ta);

    // Compute the diff so we can adjust remote cursors
    const oldText = ta.value;
    const diff = diffTexts(oldText, notesText);

    lastSyncedText.current = notesText;
    if (document.activeElement === ta) {
      const cursor = ta.selectionStart;
      const prevLen = ta.value.length;
      ta.value = notesText;
      const delta = notesText.length - prevLen;
      const newCursor = Math.max(0, Math.min(cursor + delta, notesText.length));
      ta.selectionStart = newCursor;
      ta.selectionEnd = newCursor;
    } else {
      ta.value = notesText;
    }

    // Adjust remote cursor positions to account for the text change
    if (diff) {
      setRemoteCursors((prev) => {
        const next = new Map<number, RemoteCursor>();
        prev.forEach((c, uid) => {
          next.set(uid, {
            ...c,
            cursor: adjustCursor(c.cursor, diff.pos, diff.deleteCount, diff.inserted.length),
            sel_end: adjustCursor(c.sel_end, diff.pos, diff.deleteCount, diff.inserted.length),
          });
        });
        return next;
      });
    }
  }, [notesText]);

  // ── Listen for remote cursor events ──────────────────────────────

  useEffect(() => {
    const unlisten = listen<EphemeralEnvelope>("ephemeral:cursor", (event) => {
      const env = event.payload;
      if (env.uid === myUid) return; // Ignore own cursor echoed back
      try {
        const decoded = new TextDecoder().decode(new Uint8Array(env.payload));
        const data = JSON.parse(decoded) as { cursor: number; sel_end: number; user_name?: string };
        setRemoteCursors((prev) => {
          const next = new Map(prev);
          next.set(env.uid, {
            uid: env.uid,
            user_name: data.user_name ?? `User ${env.uid}`,
            cursor: data.cursor,
            sel_end: data.sel_end,
            ts: Date.now(),
          });
          return next;
        });
      } catch {
        // Malformed payload — ignore
      }
    });

    // Expire stale cursors every 5 seconds
    const expiry = setInterval(() => {
      const cutoff = Date.now() - 10_000;
      setRemoteCursors((prev) => {
        let changed = false;
        const next = new Map<number, RemoteCursor>();
        prev.forEach((c, uid) => {
          if (c.ts >= cutoff) {
            next.set(uid, c);
          } else {
            changed = true;
          }
        });
        return changed ? next : prev;
      });
    }, 5000);

    return () => {
      unlisten.then((fn) => fn());
      clearInterval(expiry);
    };
  }, [myUid]);

  // Clean up timer on unmount.
  useEffect(() => {
    return () => {
      if (debounceTimer.current) clearTimeout(debounceTimer.current);
    };
  }, []);

  // ── Compute pixel position for a character offset ────────────────

  const cursorPixelPos = useCallback(
    (offset: number): { top: number; left: number } | null => {
      const ta = textareaRef.current;
      const mirror = mirrorRef.current;
      if (!ta || !mirror) return null;

      const text = ta.value;
      const before = text.slice(0, offset);

      // Copy textarea styles to the mirror element
      const cs = getComputedStyle(ta);
      mirror.style.font = cs.font;
      mirror.style.letterSpacing = cs.letterSpacing;
      mirror.style.wordSpacing = cs.wordSpacing;
      mirror.style.lineHeight = cs.lineHeight;
      mirror.style.whiteSpace = "pre-wrap";
      mirror.style.overflowWrap = "break-word";
      mirror.style.width = cs.width;
      mirror.style.padding = cs.padding;
      mirror.style.border = cs.border;
      mirror.style.boxSizing = cs.boxSizing;

      // Text before cursor + a marker span
      mirror.innerHTML = "";
      mirror.appendChild(document.createTextNode(before));
      const marker = document.createElement("span");
      marker.textContent = "\u200b"; // zero-width space
      mirror.appendChild(marker);
      mirror.appendChild(document.createTextNode(text.slice(offset) || " "));

      const markerRect = marker.getBoundingClientRect();
      const mirrorRect = mirror.getBoundingClientRect();
      const taRect = ta.getBoundingClientRect();
      const wrapperRect = ta.parentElement!.getBoundingClientRect();

      // Marker offset within mirror = "document" position of the cursor
      const docTop = markerRect.top - mirrorRect.top;
      const docLeft = markerRect.left - mirrorRect.left;

      // Position relative to wrapper: textarea offset + document offset - scroll
      return {
        top: (taRect.top - wrapperRect.top) + docTop - ta.scrollTop,
        left: (taRect.left - wrapperRect.left) + docLeft - ta.scrollLeft,
      };
    },
    []
  );

  // ── Render ───────────────────────────────────────────────────────

  return (
    <div className="notes-container" ref={containerRef} style={{ position: "relative" }}>
      <div className="notes-header">
        <span className="notes-header-label">Shared Notes</span>
        {SHOW_REMOTE_CURSORS && remoteCursors.size > 0 && (
          <span className="notes-header-users">
            {Array.from(remoteCursors.values()).map((c) => (
              <span
                key={c.uid}
                style={{
                  color: colorForUid(c.uid),
                  marginLeft: 8,
                  fontSize: "0.85em",
                }}
              >
                {c.user_name}
              </span>
            ))}
          </span>
        )}
      </div>
      <div style={{ position: "relative", flex: 1, display: "flex", flexDirection: "column", minHeight: 0 }}>
        <textarea
          ref={textareaRef}
          className="notes-textarea"
          defaultValue={notesText}
          onInput={handleInput}
          onBlur={handleBlur}
          onSelect={handleSelect}
          placeholder="Start typing to collaborate…"
          spellCheck={false}
        />
        {/* Hidden mirror for computing cursor pixel positions */}
        <div
          ref={mirrorRef}
          aria-hidden
          style={{
            position: "absolute",
            top: 0,
            left: 0,
            visibility: "hidden",
            pointerEvents: "none",
            zIndex: -1,
          }}
        />
        {/* Remote cursor indicators */}
        {SHOW_REMOTE_CURSORS && Array.from(remoteCursors.values()).map((c) => {
          const pos = cursorPixelPos(c.cursor);
          if (!pos) return null;
          return (
            <div
              key={c.uid}
              style={{
                position: "absolute",
                top: pos.top,
                left: pos.left,
                width: 2,
                height: "1.2em",
                backgroundColor: colorForUid(c.uid),
                pointerEvents: "none",
                zIndex: 10,
                transition: "top 0.1s, left 0.1s",
              }}
            >
              <span
                style={{
                  position: "absolute",
                  top: "-1.4em",
                  left: 0,
                  fontSize: "0.7em",
                  backgroundColor: colorForUid(c.uid),
                  color: "#fff",
                  padding: "1px 4px",
                  borderRadius: 3,
                  whiteSpace: "nowrap",
                  lineHeight: "1.3",
                }}
              >
                {c.user_name}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
