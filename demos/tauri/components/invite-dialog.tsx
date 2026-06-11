"use client";

import { useState } from "react";
import * as api from "@/lib/api";

interface Props {
  onClose: () => void;
}

export default function InviteDialog({ onClose }: Props) {
  const [inviteJson, setInviteJson] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function handleInvite() {
    setLoading(true);
    setError("");
    try {
      const json = await api.inviteUser();
      setInviteJson(btoa(json));
    } catch (e: any) {
      setError(e?.toString() || "Invite failed");
    } finally {
      setLoading(false);
    }
  }

  async function handleExportFile() {
    setLoading(true);
    setError("");
    try {
      const path = await api.exportInviteToFile();
      setInviteJson(`Saved to: ${path}`);
    } catch (e: any) {
      if (e?.toString()?.includes("cancelled")) {
        // User cancelled the dialog
      } else {
        setError(e?.toString() || "Export failed");
      }
    } finally {
      setLoading(false);
    }
  }

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(inviteJson);
    } catch {
      // Fallback: select the text
    }
  }

  return (
    <div className="dialog-overlay" onClick={onClose}>
      <div className="dialog" onClick={(e) => e.stopPropagation()}>
        <h2>Invite User</h2>

        {!inviteJson ? (
          <>
            <p style={{ fontSize: 13, color: "var(--text-secondary)", marginBottom: 8 }}>
              Generate an invite code to share with a new user. They will choose their own username when joining.
            </p>
            {error && <p className="error-text">{error}</p>}
            <div className="dialog-actions">
              <button className="cancel-btn" onClick={onClose}>
                Cancel
              </button>
              <button
                className="primary-btn"
                onClick={handleInvite}
                disabled={loading}
                style={{ marginTop: 0 }}
              >
                {loading ? "Creating..." : "Generate Invite"}
              </button>
              <button
                className="primary-btn"
                onClick={handleExportFile}
                disabled={loading}
                style={{ marginTop: 0 }}
              >
                Save to File
              </button>
            </div>
          </>
        ) : (
          <>
            <p style={{ fontSize: 13, color: "var(--text-secondary)", marginBottom: 8 }}>
              Share this invite code with the user:
            </p>
            <div className="invite-output" style={{ wordBreak: "break-all" }}>{inviteJson}</div>
            <div className="dialog-actions">
              <button className="cancel-btn" onClick={handleCopy}>
                Copy
              </button>
              <button className="primary-btn" onClick={onClose} style={{ marginTop: 0 }}>
                Done
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
