"use client";

import { useState } from "react";
import { useSpaceDispatch } from "@/lib/store";
import * as api from "@/lib/api";

interface Props {
  onClose: () => void;
}

export default function ChannelCreateDialog({ onClose }: Props) {
  const dispatch = useSpaceDispatch();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function handleCreate() {
    if (!name.trim()) return;
    setLoading(true);
    setError("");
    try {
      const channel = await api.createChannel(name.trim());
      // Set description if provided
      if (description.trim() && channel.id) {
        await api.updateChannelDescription(channel.id, description.trim());
      }
      const channels = await api.getChannels();
      dispatch({ type: "setChannels", channels });

      // Switch to the new channel
      if (channel.id) {
        await api.switchChannel(channel.id, channel.name);
        dispatch({ type: "switchChannel", channelId: channel.id });
        // New channel — start with empty state, then fetch from server.
        dispatch({ type: "setMessages", messages: [] });
        dispatch({ type: "setReactions", reactions: {} });
        dispatch({ type: "setTasks", tasks: [] });
        dispatch({ type: "setNotesText", notesText: "" });
        const [messages, reactions, tasks, notesText] = await Promise.all([
          api.getMessages(channel.id),
          api.getReactions(channel.id),
          api.getTasks(),
          api.getNotes(),
        ]);
        dispatch({ type: "setMessages", messages });
        dispatch({ type: "setReactions", reactions });
        dispatch({ type: "setTasks", tasks });
        dispatch({ type: "setNotesText", notesText });
      }

      onClose();
    } catch (e: any) {
      setError(e?.toString() || "Failed to create channel");
    } finally {
      setLoading(false);
    }
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Enter") {
      e.preventDefault();
      handleCreate();
    }
  }

  return (
    <div className="dialog-overlay" onClick={onClose}>
      <div className="dialog" onClick={(e) => e.stopPropagation()}>
        <h2>New Channel</h2>
        <div className="field-group">
          <label>Channel Name</label>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="e.g. random"
            autoFocus
          />
        </div>
        <div className="field-group">
          <label>Description <span style={{ color: "var(--text-muted)", fontWeight: 400 }}>(optional)</span></label>
          <input
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="What's this channel about?"
          />
        </div>
        {error && <p className="error-text">{error}</p>}
        <div className="dialog-actions">
          <button className="cancel-btn" onClick={onClose}>
            Cancel
          </button>
          <button
            className="primary-btn"
            onClick={handleCreate}
            disabled={loading || !name.trim()}
            style={{ marginTop: 0 }}
          >
            {loading ? "Creating..." : "Create"}
          </button>
        </div>
      </div>
    </div>
  );
}
