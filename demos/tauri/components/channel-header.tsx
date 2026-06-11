"use client";

import { useState, useRef, useEffect } from "react";
import { useSpace, useSpaceDispatch } from "@/lib/store";
import * as api from "@/lib/api";

export default function ChannelHeader() {
  const { channels, currentChannelId } = useSpace();
  const dispatch = useSpaceDispatch();
  const [editingDesc, setEditingDesc] = useState(false);
  const [descText, setDescText] = useState("");
  const [saving, setSaving] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const currentChannel = channels.find((c) => c.id === currentChannelId);
  const description = currentChannel?.description;

  // Reset editing state when channel changes
  useEffect(() => {
    setEditingDesc(false);
  }, [currentChannelId]);

  // Focus input when entering edit mode
  useEffect(() => {
    if (editingDesc && inputRef.current) {
      inputRef.current.focus();
      inputRef.current.select();
    }
  }, [editingDesc]);

  function startEditDesc() {
    setDescText(description || "");
    setEditingDesc(true);
  }

  async function saveDesc() {
    if (saving || !currentChannelId) return;
    setSaving(true);
    try {
      const newDesc = descText.trim() || null;
      await api.updateChannelDescription(currentChannelId, newDesc);
      const updated = await api.getChannels();
      dispatch({ type: "setChannels", channels: updated });
      setEditingDesc(false);
    } catch (e) {
      console.error("Failed to update description:", e);
    } finally {
      setSaving(false);
    }
  }

  function handleDescKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Enter") {
      e.preventDefault();
      saveDesc();
    } else if (e.key === "Escape") {
      setEditingDesc(false);
    }
  }

  return (
    <div className="channel-header">
      <div className="channel-header-info">
        <div className="channel-header-name">
          <span className="channel-hash">#</span>
          {currentChannel?.name ?? "unknown"}
        </div>

        {editingDesc ? (
          <div className="channel-desc-edit">
            <input
              ref={inputRef}
              className="channel-desc-input"
              value={descText}
              onChange={(e) => setDescText(e.target.value)}
              onKeyDown={handleDescKeyDown}
              onBlur={saveDesc}
              placeholder="Add a description..."
              disabled={saving}
            />
          </div>
        ) : (
          <button
            className="channel-desc-display"
            onClick={startEditDesc}
            title="Click to edit description"
          >
            {description || (
              <span className="channel-desc-placeholder">Add a description...</span>
            )}
          </button>
        )}
      </div>
    </div>
  );
}
