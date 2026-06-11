"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { listen } from "@tauri-apps/api/event";
import { useSpace, useSpaceDispatch } from "@/lib/store";
import ChannelList from "@/components/channel-list";
import ChannelHeader from "@/components/channel-header";
import MessageList from "@/components/message-list";
import MessageInput from "@/components/message-input";
import ThreadPanel from "@/components/thread-panel";
import SharedNotes from "@/components/shared-notes";
import Calendar from "@/components/calendar";
import Files from "@/components/files";

export default function ChatPage() {
  const router = useRouter();
  const { initialized, currentChannelId } = useSpace();
  const dispatch = useSpaceDispatch();
  const [activeThreadId, setActiveThreadId] = useState<number | null>(null);
  const [activeTab, setActiveTab] = useState<"chat" | "notes" | "calendar" | "files">("chat");

  useEffect(() => {
    if (!initialized) {
      router.replace("/");
    }
  }, [initialized, router]);

  // Close thread when switching channels
  useEffect(() => {
    setActiveThreadId(null);
  }, [currentChannelId]);

  // Listen for logout event from OS menu
  useEffect(() => {
    const unlisten = listen("logout", () => {
      dispatch({ type: "reset" });
      router.replace("/setup");
    });
    return () => {
      unlisten.then((fn) => fn());
    };
  }, [dispatch, router]);

  if (!initialized) {
    return <div className="loading-container">Loading...</div>;
  }

  return (
    <div className={`app-layout ${activeTab === "chat" && activeThreadId ? "with-thread" : ""}`}>
      <ChannelList />
      <div className="main-panel">
        <div className="main-tabs">
          <button
            className={`main-tab ${activeTab === "chat" ? "active" : ""}`}
            onClick={() => setActiveTab("chat")}
          >
            Chat
          </button>
          <button
            className={`main-tab ${activeTab === "notes" ? "active" : ""}`}
            onClick={() => setActiveTab("notes")}
          >
            Notes
          </button>
          <button
            className={`main-tab ${activeTab === "calendar" ? "active" : ""}`}
            onClick={() => setActiveTab("calendar")}
          >
            Calendar
          </button>
          <button
            className={`main-tab ${activeTab === "files" ? "active" : ""}`}
            onClick={() => setActiveTab("files")}
          >
            Files
          </button>
        </div>
        {activeTab === "chat" ? (
          <>
            <ChannelHeader />
            <MessageList onOpenThread={(id) => setActiveThreadId(id)} />
            <MessageInput />
          </>
        ) : activeTab === "notes" ? (
          <SharedNotes />
        ) : activeTab === "calendar" ? (
          <Calendar />
        ) : (
          <Files />
        )}
      </div>
      {activeTab === "chat" && activeThreadId && (
        <ThreadPanel
          threadId={activeThreadId}
          onClose={() => setActiveThreadId(null)}
        />
      )}
    </div>
  );
}
