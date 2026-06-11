"use client";

import { Suspense, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useSpaceDispatch } from "@/lib/store";
import * as api from "@/lib/api";

type Tab = "create" | "join" | "restore";

function SetupInner() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const dispatch = useSpaceDispatch();
  const hasRestore = searchParams.get("restore") === "1";

  const [tab, setTab] = useState<Tab>(hasRestore ? "restore" : "create");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // Create form
  const [wsAddress, setWsAddress] = useState("ws://127.0.0.1:8080/ws");
  const [username, setUsername] = useState("");
  const [channelName, setChannelName] = useState("general");

  // Join form
  const [joinWs, setJoinWs] = useState("ws://127.0.0.1:8080/ws");
  const [inviteJson, setInviteJson] = useState("");
  const [joinUsername, setJoinUsername] = useState("");
  const [joinChannel, setJoinChannel] = useState("general");

  async function handleCreate() {
    if (!username.trim()) return;
    setLoading(true);
    setError("");
    try {
      const user = await api.createSpace(
        wsAddress,
        username.trim(),
        channelName.trim() || "general"
      );
      dispatch({ type: "setUser", user });
      const [channels, messages, reactions, tasks, notesText] = await Promise.all([
        api.getChannels(),
        api.getMessages(user.current_channel_id),
        api.getReactions(user.current_channel_id),
        api.getTasks(),
        api.getNotes(),
      ]);
      dispatch({ type: "setChannels", channels });
      dispatch({ type: "setMessages", messages });
      dispatch({ type: "setReactions", reactions });
      dispatch({ type: "setTasks", tasks });
      dispatch({ type: "setNotesText", notesText });
      dispatch({ type: "setInitialized" });
      router.replace("/chat");
    } catch (e: any) {
      setError(e?.toString() || "Failed to create space");
    } finally {
      setLoading(false);
    }
  }

  async function handleJoin() {
    if (!inviteJson.trim()) return;
    setLoading(true);
    setError("");
    try {
      let decoded: string;
      try {
        decoded = atob(inviteJson.trim());
      } catch {
        throw new Error("Invalid invite code. Make sure you pasted the full code.");
      }
      const user = await api.joinSpace(
        joinWs,
        decoded,
        joinUsername.trim(),
        joinChannel.trim() || "general"
      );
      dispatch({ type: "setUser", user });
      const [channels, messages, reactions, tasks, notesText] = await Promise.all([
        api.getChannels(),
        api.getMessages(user.current_channel_id),
        api.getReactions(user.current_channel_id),
        api.getTasks(),
        api.getNotes(),
      ]);
      dispatch({ type: "setChannels", channels });
      dispatch({ type: "setMessages", messages });
      dispatch({ type: "setReactions", reactions });
      dispatch({ type: "setTasks", tasks });
      dispatch({ type: "setNotesText", notesText });
      dispatch({ type: "setInitialized" });
      router.replace("/chat");
    } catch (e: any) {
      setError(e?.toString() || "Failed to join space");
    } finally {
      setLoading(false);
    }
  }

  async function handleRestore() {
    setLoading(true);
    setError("");
    try {
      const user = await api.restoreSpace();
      dispatch({ type: "setUser", user });
      const [channels, messages, reactions, tasks, notesText] = await Promise.all([
        api.getChannels(),
        api.getMessages(user.current_channel_id),
        api.getReactions(user.current_channel_id),
        api.getTasks(),
        api.getNotes(),
      ]);
      dispatch({ type: "setChannels", channels });
      dispatch({ type: "setMessages", messages });
      dispatch({ type: "setReactions", reactions });
      dispatch({ type: "setTasks", tasks });
      dispatch({ type: "setNotesText", notesText });
      dispatch({ type: "setInitialized" });
      router.replace("/chat");
    } catch (e: any) {
      setError(e?.toString() || "Failed to restore");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="setup-container">
      <div className="setup-card">
        <div className="setup-brand">
          <pre className="setup-ascii">{`████ ████ ████ ████ ████ ████
██   █  █ █  █ █    ███  ██
  ██ ████ ████ █    █      ██
████ █    █  █ ████ ████ ████`}</pre>
        </div>

        <div className="setup-tabs">
          <button
            className={`setup-tab ${tab === "create" ? "active" : ""}`}
            onClick={() => { setTab("create"); setError(""); }}
          >
            Create
          </button>
          <button
            className={`setup-tab ${tab === "join" ? "active" : ""}`}
            onClick={() => { setTab("join"); setError(""); }}
          >
            Join
          </button>
          {hasRestore && (
            <button
              className={`setup-tab ${tab === "restore" ? "active" : ""}`}
              onClick={() => { setTab("restore"); setError(""); }}
            >
              Restore
            </button>
          )}
        </div>

        {tab === "create" && (
          <div className="setup-form">
            <div className="field-group">
              <label>Server Address</label>
              <input
                value={wsAddress}
                onChange={(e) => setWsAddress(e.target.value)}
                placeholder="ws://127.0.0.1:8080/ws"
              />
            </div>
            <div className="field-group">
              <label>Username</label>
              <input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter your username"
                autoFocus
              />
            </div>
            <div className="field-group">
              <label>Initial Channel</label>
              <input
                value={channelName}
                onChange={(e) => setChannelName(e.target.value)}
                placeholder="general"
              />
            </div>
            <button
              className="primary-btn"
              onClick={handleCreate}
              disabled={loading || !username.trim()}
            >
              {loading ? "Creating..." : "Create Space"}
            </button>
          </div>
        )}

        {tab === "join" && (
          <div className="setup-form">
            <div className="field-group">
              <label>Server Address</label>
              <input
                value={joinWs}
                onChange={(e) => setJoinWs(e.target.value)}
                placeholder="ws://127.0.0.1:8080/ws"
              />
            </div>
            <div className="field-group">
              <label>Username</label>
              <input
                value={joinUsername}
                onChange={(e) => setJoinUsername(e.target.value)}
                placeholder="Choose your username"
                autoFocus
              />
            </div>
            <div className="field-group">
              <label>Invite Code</label>
              <textarea
                value={inviteJson}
                onChange={(e) => setInviteJson(e.target.value)}
                placeholder="Paste the invite code here..."
              />
            </div>
            <div className="field-group">
              <label>Initial Channel</label>
              <input
                value={joinChannel}
                onChange={(e) => setJoinChannel(e.target.value)}
                placeholder="general"
              />
            </div>
            <button
              className="primary-btn"
              onClick={handleJoin}
              disabled={loading || !inviteJson.trim() || !joinUsername.trim()}
            >
              {loading ? "Joining..." : "Join Space"}
            </button>
          </div>
        )}

        {tab === "restore" && (
          <div className="setup-form">
            <p style={{ color: "var(--text-secondary)", fontSize: 14, textAlign: "center" }}>
              A previous session was found. Click below to restore it.
            </p>
            <button
              className="primary-btn"
              onClick={handleRestore}
              disabled={loading}
            >
              {loading ? "Restoring..." : "Restore Session"}
            </button>
          </div>
        )}

        {error && <p className="error-text" style={{ marginTop: 12 }}>{error}</p>}
      </div>
    </div>
  );
}

export default function SetupPage() {
  return (
    <Suspense fallback={<div className="loading-container">Loading...</div>}>
      <SetupInner />
    </Suspense>
  );
}
