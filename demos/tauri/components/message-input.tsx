"use client";

import { useState } from "react";
import { useSpace, useSpaceDispatch } from "@/lib/store";
import * as api from "@/lib/api";
import { open } from "@tauri-apps/plugin-dialog";
import { stat } from "@tauri-apps/plugin-fs";
import { convertFileSrc } from "@tauri-apps/api/core";

interface StagedFile {
  path: string;
  name: string;
  ext: string;
  size: number | null;
  previewUrl: string | null;
}

const IMAGE_EXTS = new Set(["png", "jpg", "jpeg", "gif", "webp", "svg", "bmp", "ico"]);

function getExt(filename: string): string {
  return filename.split(".").pop()?.toLowerCase() ?? "";
}

function getFilename(path: string): string {
  return path.split("/").pop()?.split("\\").pop() ?? path;
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}

function FileTypeIcon({ ext }: { ext: string }) {
  const isImage = IMAGE_EXTS.has(ext);
  const isAudio = ["mp3", "wav", "ogg", "flac", "aac", "m4a"].includes(ext);
  const isVideo = ["mp4", "mov", "avi", "mkv", "webm"].includes(ext);
  const isDoc = ["pdf", "doc", "docx", "txt", "md", "rtf"].includes(ext);
  const isCode = ["js", "ts", "rs", "py", "json", "html", "css", "toml", "yaml"].includes(ext);
  const isArchive = ["zip", "tar", "gz", "rar", "7z"].includes(ext);

  let color = "var(--text-muted)";
  let label = ext.toUpperCase() || "FILE";
  if (isImage) color = "#a78bfa";
  else if (isAudio) color = "#fb923c";
  else if (isVideo) color = "#f472b6";
  else if (isDoc) color = "#60a5fa";
  else if (isCode) color = "#4ade80";
  else if (isArchive) color = "#eea020";

  return (
    <div className="file-type-badge" style={{ borderColor: color }}>
      <span className="file-type-label" style={{ color }}>{label}</span>
    </div>
  );
}

export default function MessageInput() {
  const { currentChannelId } = useSpace();
  const dispatch = useSpaceDispatch();
  const [text, setText] = useState("");
  const [sending, setSending] = useState(false);
  const [uploadProgress, setUploadProgress] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [stagedFiles, setStagedFiles] = useState<StagedFile[]>([]);

  async function handleAttach() {
    try {
      const selected = await open({ multiple: true, title: "Attach files" });
      if (!selected) return;
      const paths = Array.isArray(selected) ? selected : [selected];

      const newFiles: StagedFile[] = [];
      for (const p of paths) {
        const name = getFilename(p);
        const ext = getExt(name);
        let size: number | null = null;
        try { const info = await stat(p); size = info.size; } catch {}
        const previewUrl = IMAGE_EXTS.has(ext) ? convertFileSrc(p) : null;
        newFiles.push({ path: p, name, ext, size, previewUrl });
      }
      setStagedFiles((prev) => [...prev, ...newFiles]);
    } catch (e) {
      console.error("Failed to open file dialog:", e);
    }
  }

  function removeFile(index: number) {
    setStagedFiles((prev) => prev.filter((_, i) => i !== index));
  }

  async function handleSend() {
    if ((!text.trim() && stagedFiles.length === 0) || !currentChannelId || sending) return;
    setSending(true);
    setError(null);
    try {
      if (stagedFiles.length > 0) {
        const count = stagedFiles.length;
        setUploadProgress(`Uploading ${count} file${count > 1 ? "s" : ""}...`);
        await api.sendMessageWithAttachments(
          currentChannelId,
          text.trim() || "(attachment)",
          stagedFiles.map((f) => f.path)
        );
        setUploadProgress(null);
      } else {
        await api.sendMessage(currentChannelId, text.trim());
      }
      setText("");
      setStagedFiles([]);
      const messages = await api.getMessages(currentChannelId);
      dispatch({ type: "setMessages", messages });
    } catch (e: any) {
      console.error("Failed to send message:", e);
      setUploadProgress(null);
      setError(typeof e === "string" ? e : e?.message ?? "Failed to send message");
    } finally {
      setSending(false);
    }
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  }

  return (
    <div className="message-input-area">
      {/* Error banner */}
      {error && (
        <div className="upload-error-banner">
          <span>{error}</span>
          <button className="upload-error-dismiss" onClick={() => setError(null)}>&times;</button>
        </div>
      )}

      {/* Upload progress banner */}
      {uploadProgress && (
        <div className="upload-banner">
          <div className="upload-banner-spinner" />
          <span className="upload-banner-text">{uploadProgress}</span>
        </div>
      )}

      {stagedFiles.length > 0 && (
        <div className="staged-files">
          {stagedFiles.map((file, i) => (
            <div key={i} className="staged-file">
              <button className="staged-file-remove" onClick={() => removeFile(i)} title="Remove">
                &times;
              </button>
              {file.previewUrl ? (
                <img src={file.previewUrl} alt={file.name} className="staged-file-preview" />
              ) : (
                <div className="staged-file-icon-area">
                  <FileTypeIcon ext={file.ext} />
                </div>
              )}
              <div className="staged-file-info">
                <span className="staged-file-name" title={file.name}>{file.name}</span>
                {file.size != null && (
                  <span className="staged-file-size">{formatSize(file.size)}</span>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
      <div className="message-input-wrapper">
        <button className="attach-btn" onClick={handleAttach} disabled={sending} title="Attach files">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
            stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48" />
          </svg>
        </button>
        <input
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder={sending ? "Sending..." : "Type a message..."}
          disabled={sending}
          autoFocus
        />
        <button
          className={`send-btn ${sending ? "send-btn-uploading" : ""}`}
          onClick={handleSend}
          disabled={(!text.trim() && stagedFiles.length === 0) || sending}
        >
          {sending ? (
            <div className="attachment-loading-spinner small" />
          ) : (
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
              stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <line x1="22" y1="2" x2="11" y2="13" />
              <polygon points="22 2 15 22 11 13 2 9 22 2" />
            </svg>
          )}
        </button>
      </div>
    </div>
  );
}

export { FileTypeIcon, formatSize, IMAGE_EXTS };
export type { StagedFile };
