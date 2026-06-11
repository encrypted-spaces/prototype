"use client";

import { useState, useEffect, useCallback } from "react";
import { listen } from "@tauri-apps/api/event";
import { useSpace } from "@/lib/store";
import * as api from "@/lib/api";
import type { UserRecord } from "@/lib/types";

interface Props {
  onClose: () => void;
}

type View = "list" | "invite";

export default function UserManagementPanel({ onClose }: Props) {
  const { user } = useSpace();
  const [view, setView] = useState<View>("list");
  const [members, setMembers] = useState<UserRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // Invite state
  const [inviteResult, setInviteResult] = useState("");
  const [inviting, setInviting] = useState(false);

  // Remove state
  const [removingId, setRemovingId] = useState<number | null>(null);
  const [confirmRemoveId, setConfirmRemoveId] = useState<number | null>(null);

  const loadMembers = useCallback(async () => {
    try {
      setLoading(true);
      const users = await api.getUsers();
      setMembers(users);
    } catch (e: any) {
      setError(e?.toString() || "Failed to load members");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadMembers();
  }, [loadMembers]);

  // Re-fetch members when a broadcast arrives (user added/removed)
  useEffect(() => {
    const unlisten = listen("space-updated", () => {
      loadMembers();
    });
    return () => {
      unlisten.then((fn) => fn());
    };
  }, [loadMembers]);

  async function handleInvite() {
    setInviting(true);
    setError("");
    try {
      const json = await api.inviteUser();
      setInviteResult(btoa(json));
    } catch (e: any) {
      setError(e?.toString() || "Invite failed");
    } finally {
      setInviting(false);
    }
  }

  async function handleExportFile() {
    setInviting(true);
    setError("");
    try {
      const path = await api.exportInviteToFile();
      setInviteResult(`Saved to: ${path}`);
    } catch (e: any) {
      if (!e?.toString()?.includes("cancelled")) {
        setError(e?.toString() || "Export failed");
      }
    } finally {
      setInviting(false);
    }
  }

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(inviteResult);
    } catch {}
  }

  async function handleRemove(userId: number) {
    if (confirmRemoveId !== userId) {
      setConfirmRemoveId(userId);
      return;
    }
    setRemovingId(userId);
    setError("");
    try {
      await api.removeUser(userId);
      setConfirmRemoveId(null);
      await loadMembers();
    } catch (e: any) {
      setError(e?.toString() || "Remove failed");
    } finally {
      setRemovingId(null);
    }
  }

  function resetInviteView() {
    setInviteResult("");
    setError("");
    setView("invite");
  }

  const currentUserId = user?.user_id;

  return (
    <div className="dialog-overlay" onClick={onClose}>
      <div className="um-panel" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="um-header">
          <div className="um-header-left">
            <div className="um-title">Members</div>
            <div className="um-count">{members.length}</div>
          </div>
          <button className="um-close" onClick={onClose} aria-label="Close">
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
              <path d="M1 1L13 13M13 1L1 13" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
            </svg>
          </button>
        </div>

        {/* Navigation */}
        <div className="um-nav">
          <button
            className={`um-nav-tab ${view === "list" ? "active" : ""}`}
            onClick={() => { setView("list"); setError(""); }}
          >
            <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
              <path d="M8 8a3 3 0 100-6 3 3 0 000 6zm-5 6a5 5 0 0110 0H3z" />
            </svg>
            All Members
          </button>
          <button
            className={`um-nav-tab ${view === "invite" ? "active" : ""}`}
            onClick={resetInviteView}
          >
            <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
              <path d="M8 2a.75.75 0 01.75.75v4.5h4.5a.75.75 0 010 1.5h-4.5v4.5a.75.75 0 01-1.5 0v-4.5h-4.5a.75.75 0 010-1.5h4.5v-4.5A.75.75 0 018 2z" />
            </svg>
            Invite
          </button>
        </div>

        {/* Error */}
        {error && (
          <div className="um-error">
            <svg width="13" height="13" viewBox="0 0 16 16" fill="currentColor">
              <path d="M8 15A7 7 0 108 1a7 7 0 000 14zm0-9.5a.75.75 0 01.75.75v3a.75.75 0 01-1.5 0v-3A.75.75 0 018 5.5zm0 7a.75.75 0 100-1.5.75.75 0 000 1.5z" />
            </svg>
            {error}
          </div>
        )}

        {/* Content */}
        <div className="um-content">
          {view === "list" && (
            <div className="um-member-list">
              {loading ? (
                <div className="um-loading">Loading members...</div>
              ) : members.length === 0 ? (
                <div className="um-empty">No members found</div>
              ) : (
                members.map((m) => {
                  const isYou = m.id === currentUserId;
                  const isConfirming = confirmRemoveId === m.id;
                  const isRemoving = removingId === m.id;
                  return (
                    <div
                      key={m.id}
                      className={`um-member ${isConfirming ? "confirming" : ""}`}
                    >
                      <span className={`um-status-tag ${m.status}`}>
                        {m.status === "pending" ? "pending" : "member"}
                      </span>
                      <div className="um-member-info">
                        <div className="um-member-name">
                          {m.name}
                          {isYou && <span className="um-you-badge">you</span>}
                        </div>
                      </div>
                      {!isYou && (
                        <button
                          className={`um-remove-btn ${isConfirming ? "confirm" : ""}`}
                          onClick={() => handleRemove(m.id)}
                          disabled={isRemoving}
                        >
                          {isRemoving
                            ? "Removing..."
                            : isConfirming
                              ? "Confirm"
                              : "Remove"}
                        </button>
                      )}
                      {isConfirming && !isRemoving && (
                        <button
                          className="um-cancel-remove"
                          onClick={() => setConfirmRemoveId(null)}
                        >
                          Cancel
                        </button>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          )}

          {view === "invite" && (
            <div className="um-invite-view">
              {!inviteResult ? (
                <>
                  <p className="um-invite-hint">
                    Generate an invite code to share with a new user. They will choose their own username when joining.
                  </p>
                  <div className="um-invite-actions">
                    <button
                      className="primary-btn"
                      onClick={handleInvite}
                      disabled={inviting}
                    >
                      {inviting ? "Creating..." : "Generate Invite"}
                    </button>
                    <button
                      className="cancel-btn"
                      onClick={handleExportFile}
                      disabled={inviting}
                    >
                      Save to File
                    </button>
                  </div>
                </>
              ) : (
                <>
                  <div className="um-invite-success">
                    <svg width="16" height="16" viewBox="0 0 16 16" fill="var(--accent)">
                      <path d="M8 15A7 7 0 108 1a7 7 0 000 14zm3.78-9.28a.75.75 0 00-1.06-1.06L7 8.38 5.28 6.66a.75.75 0 00-1.06 1.06l2.25 2.25a.75.75 0 001.06 0l4.25-4.25z" />
                    </svg>
                    <span>Invite created</span>
                  </div>
                  <p className="um-invite-hint">
                    Share this code with the user so they can join:
                  </p>
                  <div className="invite-output">{inviteResult}</div>
                  <div className="um-invite-actions">
                    <button className="primary-btn" onClick={handleCopy}>
                      Copy to Clipboard
                    </button>
                    <button className="cancel-btn" onClick={() => setInviteResult("")}>
                      Invite Another
                    </button>
                  </div>
                </>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
