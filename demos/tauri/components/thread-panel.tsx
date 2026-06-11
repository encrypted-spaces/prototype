"use client";

import { useEffect, useRef, useState } from "react";
import { useSpace, useSpaceDispatch } from "@/lib/store";
import * as api from "@/lib/api";
import type { MessageWithUser } from "@/lib/types";

const AUTHOR_COLORS = [
  "#00d4aa", "#f0a030", "#a78bfa", "#f472b6",
  "#60a5fa", "#4ade80", "#fb923c", "#22d3ee",
];

function getAuthorColor(name: string): string {
  let hash = 0;
  for (let i = 0; i < name.length; i++) {
    hash = name.charCodeAt(i) + ((hash << 5) - hash);
  }
  return AUTHOR_COLORS[Math.abs(hash) % AUTHOR_COLORS.length];
}

interface Props {
  threadId: number;
  onClose: () => void;
}

export default function ThreadPanel({ threadId, onClose }: Props) {
  const { messages, currentChannelId, user } = useSpace();
  const dispatch = useSpaceDispatch();
  const bottomRef = useRef<HTMLDivElement>(null);
  const [replyText, setReplyText] = useState("");
  const [sending, setSending] = useState(false);

  // Find the parent message from global messages
  const parentMsg = messages.find((m) => m.id === threadId);
  // Thread replies are messages in the store with thread_id === threadId
  const replies = messages.filter((m) => m.thread_id === threadId);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [replies.length]);

  async function handleSendReply() {
    if (!replyText.trim() || !currentChannelId || sending) return;
    setSending(true);
    try {
      await api.sendMessage(currentChannelId, replyText.trim(), threadId);
      setReplyText("");
      if (currentChannelId) {
        const updated = await api.getMessages(currentChannelId);
        dispatch({ type: "setMessages", messages: updated });
      }
    } catch (e) {
      console.error("Failed to send reply:", e);
    } finally {
      setSending(false);
    }
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSendReply();
    }
  }

  function formatTime(ts: number): string {
    const d = new Date(ts * 1000);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }

  function renderMessage(msg: MessageWithUser, idx: number) {
    return (
      <div key={msg.id ?? idx} className="thread-message">
        <div className="message-header">
          {msg.is_deleted_user ? (
            <span className="message-author-deleted">[deleted]</span>
          ) : (
            <span
              className="message-author"
              style={{ color: getAuthorColor(msg.author) }}
            >
              {msg.author}
            </span>
          )}
          <span className="message-time">{formatTime(msg.timestamp)}</span>
        </div>
        <div className="message-content">{msg.content}</div>
      </div>
    );
  }

  return (
    <div className="thread-panel">
      <div className="thread-header">
        <span className="thread-header-title">Thread</span>
        <button className="thread-close-btn" onClick={onClose}>
          &times;
        </button>
      </div>

      <div className="thread-messages">
        {parentMsg && (
          <div className="thread-parent">
            {renderMessage(parentMsg, -1)}
          </div>
        )}

        {replies.length > 0 && (
          <div className="thread-divider">
            <span>{replies.length} {replies.length === 1 ? "reply" : "replies"}</span>
          </div>
        )}

        {replies.map((msg, idx) => renderMessage(msg, idx))}
        <div ref={bottomRef} />
      </div>

      <div className="thread-input-area">
        <div className="message-input-wrapper">
          <input
            value={replyText}
            onChange={(e) => setReplyText(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Reply..."
            disabled={sending}
            autoFocus
          />
          <button
            className="send-btn"
            onClick={handleSendReply}
            disabled={!replyText.trim() || sending}
          >
            <svg
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <line x1="22" y1="2" x2="11" y2="13" />
              <polygon points="22 2 15 22 11 13 2 9 22 2" />
            </svg>
          </button>
        </div>
      </div>
    </div>
  );
}
