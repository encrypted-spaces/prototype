"use client";

import { useState } from "react";
import { useSpace, useSpaceDispatch } from "@/lib/store";
import * as api from "@/lib/api";
import ChannelCreateDialog from "./channel-create-dialog";
import UserManagementPanel from "./user-management-panel";
import TaskList from "./task-list";

export default function ChannelList() {
  const { channels, currentChannelId, unreadChannels, user } = useSpace();
  const dispatch = useSpaceDispatch();
  const [showCreate, setShowCreate] = useState(false);
  const [showMembers, setShowMembers] = useState(false);

  async function handleSwitch(channelId: number, channelName: string) {
    if (channelId === currentChannelId) return;
    try {
      await api.switchChannel(channelId, channelName);
      dispatch({ type: "switchChannel", channelId });
      const [messages, reactions, tasks, notesText] = await Promise.all([
        api.getMessages(channelId),
        api.getReactions(channelId),
        api.getTasks(),
        api.getNotes(),
      ]);
      dispatch({ type: "setMessages", messages });
      dispatch({ type: "setReactions", reactions });
      dispatch({ type: "setTasks", tasks });
      dispatch({ type: "setNotesText", notesText });
    } catch (e) {
      console.error("Failed to switch channel:", e);
    }
  }

  return (
    <div className="sidebar">
      <div className="sidebar-brand">
        <pre className="sidebar-ascii">{`████ ████ ████ ████ ████ ████
██   █  █ █  █ █    ███  ██
  ██ ████ ████ █    █      ██
████ █    █  █ ████ ████ ████`}</pre>
      </div>

      <div className="channel-section">
        <div className="channel-section-label">Channels</div>
        <div className="channel-list">
          {channels.map((ch) => {
            const isActive = ch.id === currentChannelId;
            const isUnread = ch.id !== null && unreadChannels.includes(ch.id);
            return (
              <div
                key={ch.id}
                className={`channel-item ${isActive ? "active" : ""} ${isUnread ? "unread" : ""}`}
                onClick={() => ch.id && handleSwitch(ch.id, ch.name)}
              >
                <span className="hash">#</span>
                <span className="channel-name">{ch.name}</span>
                {isUnread && <span className="channel-badge" />}
              </div>
            );
          })}
        </div>
      </div>

      <TaskList />

      <div className="sidebar-actions">
        <button className="sidebar-btn" onClick={() => setShowCreate(true)}>
          + New Channel
        </button>
        <button className="sidebar-btn sidebar-btn-members" onClick={() => setShowMembers(true)}>
          <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
            <path d="M8 8a3 3 0 100-6 3 3 0 000 6zm-5 6a5 5 0 0110 0H3zm9-9a2.5 2.5 0 110 5M13 14a4 4 0 00-2-3.46" />
          </svg>
          Members
        </button>
      </div>

      {user && (
        <div className="sidebar-user">
          <div className="sidebar-user-dot" />
          <div className="sidebar-user-info">
            <div className="sidebar-user-name">{user.user_name}</div>
            <div className="sidebar-user-status">Connected</div>
          </div>
        </div>
      )}

      {showCreate && (
        <ChannelCreateDialog onClose={() => setShowCreate(false)} />
      )}
      {showMembers && (
        <UserManagementPanel onClose={() => setShowMembers(false)} />
      )}
    </div>
  );
}
