"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import { useSpace, useSpaceDispatch } from "@/lib/store";
import * as api from "@/lib/api";
import type { Attachment } from "@/lib/types";
import { save } from "@tauri-apps/plugin-dialog";
import { writeFile } from "@tauri-apps/plugin-fs";
import { FileTypeIcon, formatSize } from "./message-input";

const QUICK_EMOJIS = ["\u{1F44D}", "\u{1F44E}", "\u{2764}\u{FE0F}", "\u{1F602}", "\u{1F440}"];

const AUTHOR_COLORS = [
  "#00d4aa", "#f0a030", "#a78bfa", "#f472b6",
  "#60a5fa", "#4ade80", "#fb923c", "#22d3ee",
];

const IMAGE_MIMES = new Set([
  "image/png", "image/jpeg", "image/gif", "image/webp",
  "image/svg+xml", "image/bmp", "image/x-icon",
]);
const AUDIO_MIMES = new Set(["audio/mpeg", "audio/wav", "audio/ogg", "audio/flac", "audio/aac", "audio/mp4", "audio/webm"]);
const VIDEO_MIMES = new Set(["video/mp4", "video/webm", "video/ogg", "video/quicktime"]);
const MAX_GRID = 4; // max images shown in grid before +N overflow

function getAuthorColor(name: string): string {
  let hash = 0;
  for (let i = 0; i < name.length; i++) hash = name.charCodeAt(i) + ((hash << 5) - hash);
  return AUTHOR_COLORS[Math.abs(hash) % AUTHOR_COLORS.length];
}

function getExt(filename: string): string {
  return filename.split(".").pop()?.toLowerCase() ?? "";
}

function DownloadIcon({ saving }: { saving: boolean }) {
  if (saving) return <div className="attachment-loading-spinner small" />;
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <polyline points="7 10 12 15 17 10" /><line x1="12" y1="15" x2="12" y2="3" />
    </svg>
  );
}

interface Props { onOpenThread?: (messageId: number) => void; }

export default function MessageList({ onOpenThread }: Props) {
  const { messages, reactions, currentChannelId, user } = useSpace();
  const dispatch = useSpaceDispatch();
  const bottomRef = useRef<HTMLDivElement>(null);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [editText, setEditText] = useState("");
  const [attachmentsMap, setAttachmentsMap] = useState<Record<number, Attachment[]>>({});
  const [fileCache, setFileCache] = useState<Record<string, string>>({});
  const [savingHash, setSavingHash] = useState<string | null>(null);
  // Gallery state: all attachments for the message + current index
  const [gallery, setGallery] = useState<{ attachments: Attachment[]; index: number } | null>(null);

  const topLevelMessages = messages.filter((m) => m.thread_id === 0);
  const replyCounts: Record<number, number> = {};
  for (const m of messages) {
    if (m.thread_id !== 0) replyCounts[m.thread_id] = (replyCounts[m.thread_id] || 0) + 1;
  }

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: "smooth" }); }, [topLevelMessages.length]);

  useEffect(() => {
    async function loadAttachments() {
      const newMap: Record<number, Attachment[]> = {};
      for (const msg of topLevelMessages) {
        if (msg.id != null) {
          try {
            const atts = await api.getAttachments(msg.id);
            if (atts.length > 0) newMap[msg.id] = atts;
          } catch { }
        }
      }
      setAttachmentsMap(newMap);
    }
    loadAttachments();
  }, [messages, currentChannelId]);

  const loadFile = useCallback(async (hash: string, mimeType: string) => {
    if (fileCache[hash]) return;
    try {
      const bytes = await api.downloadFile(hash);
      const uint8 = new Uint8Array(bytes);
      const blob = new Blob([uint8], { type: mimeType });
      setFileCache((prev) => ({ ...prev, [hash]: URL.createObjectURL(blob) }));
    } catch (e) { console.error("Failed to download file:", e); }
  }, [fileCache]);

  function ensureFileLoaded(hash: string, mimeType: string) {
    if (!fileCache[hash]) loadFile(hash, mimeType);
  }

  async function handleSaveFile(att: Attachment) {
    setSavingHash(att.file_hash);
    try {
      const dest = await save({ title: "Save attachment", defaultPath: att.filename });
      if (!dest) return;
      const bytes = await api.downloadFile(att.file_hash);
      await writeFile(dest, new Uint8Array(bytes));
    } catch (e) { console.error("Failed to save file:", e); }
    finally { setSavingHash(null); }
  }

  function openGallery(allAtts: Attachment[], startIndex: number) {
    setGallery({ attachments: allAtts, index: startIndex });
  }

  // ── Attachment rendering ──────────────────────────────────────────────

  function renderAttachments(atts: Attachment[]) {
    const images = atts.filter((a) => IMAGE_MIMES.has(a.mime_type));
    const nonImages = atts.filter((a) => !IMAGE_MIMES.has(a.mime_type));

    return (
      <>
        {images.length > 0 && renderImageGrid(images, atts)}
        {nonImages.map((att) => renderNonImageAttachment(att, atts))}
      </>
    );
  }

  function renderImageGrid(images: Attachment[], allAtts: Attachment[]) {
    images.forEach((a) => ensureFileLoaded(a.file_hash, a.mime_type));
    const visible = images.slice(0, MAX_GRID);
    const overflow = images.length - MAX_GRID;
    const gridClass = `att-grid att-grid-${Math.min(visible.length, MAX_GRID)}`;

    return (
      <div className={gridClass}>
        {visible.map((att, i) => {
          const isLast = i === visible.length - 1 && overflow > 0;
          const attIndex = allAtts.indexOf(att);
          return (
            <div
              key={att.id}
              className="att-grid-cell"
              onClick={() => openGallery(allAtts, attIndex)}
            >
              {fileCache[att.file_hash] ? (
                <img src={fileCache[att.file_hash]} alt={att.filename} className="att-grid-img" />
              ) : (
                <div className="att-grid-loading"><div className="attachment-loading-spinner small" /></div>
              )}
              {isLast && (
                <div className="att-grid-overflow">
                  <span>+{overflow}</span>
                </div>
              )}
            </div>
          );
        })}
      </div>
    );
  }

  function renderNonImageAttachment(att: Attachment, allAtts: Attachment[]) {
    const isAudio = AUDIO_MIMES.has(att.mime_type);
    const isVideo = VIDEO_MIMES.has(att.mime_type);
    const isPdf = att.mime_type === "application/pdf";
    const ext = getExt(att.filename);

    if (isAudio || isVideo || isPdf) ensureFileLoaded(att.file_hash, att.mime_type);

    const attIndex = allAtts.indexOf(att);

    if (isAudio) {
      return (
        <div key={att.id} className="message-attachment">
          <div className="attachment-audio-card">
            <div className="attachment-audio-header">
              <FileTypeIcon ext={ext} />
              <span className="attachment-audio-name" title={att.filename}>{att.filename}</span>
              <span className="attachment-card-meta">{formatSize(att.size)}</span>
              <button className="attachment-save-btn" onClick={() => handleSaveFile(att)}
                disabled={savingHash === att.file_hash} title="Save to disk">
                <DownloadIcon saving={savingHash === att.file_hash} />
              </button>
            </div>
            {fileCache[att.file_hash] ? (
              <audio controls className="attachment-audio-player" preload="metadata">
                <source src={fileCache[att.file_hash]} type={att.mime_type} />
              </audio>
            ) : (
              <div className="attachment-loading-inline"><div className="attachment-loading-spinner small" /></div>
            )}
          </div>
        </div>
      );
    }

    if (isVideo) {
      return (
        <div key={att.id} className="message-attachment">
          <div className="attachment-video-wrapper">
            {fileCache[att.file_hash] ? (
              <video controls className="attachment-video-player" preload="metadata">
                <source src={fileCache[att.file_hash]} type={att.mime_type} />
              </video>
            ) : (
              <div className="attachment-image-loading"><div className="attachment-loading-spinner" /></div>
            )}
            <div className="attachment-video-footer">
              <span className="attachment-card-name" title={att.filename}>{att.filename}</span>
              <span className="attachment-card-meta">{formatSize(att.size)}</span>
              <button className="attachment-expand-btn" onClick={() => openGallery(allAtts, attIndex)} title="Expand">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="15 3 21 3 21 9" /><polyline points="9 21 3 21 3 15" />
                  <line x1="21" y1="3" x2="14" y2="10" /><line x1="3" y1="21" x2="10" y2="14" />
                </svg>
              </button>
              <button className="attachment-save-btn" onClick={() => handleSaveFile(att)}
                disabled={savingHash === att.file_hash} title="Save">
                <DownloadIcon saving={savingHash === att.file_hash} />
              </button>
            </div>
          </div>
        </div>
      );
    }

    // PDF and generic files — card style
    return (
      <div key={att.id} className="message-attachment">
        <div className="attachment-card attachment-clickable" onClick={() => openGallery(allAtts, attIndex)}>
          <FileTypeIcon ext={ext} />
          <div className="attachment-card-info">
            <span className="attachment-card-name" title={att.filename}>{att.filename}</span>
            <span className="attachment-card-meta">
              {formatSize(att.size)}
              {isPdf && <> &middot; Click to preview</>}
              {!isPdf && att.mime_type !== "application/octet-stream" && <> &middot; {att.mime_type}</>}
            </span>
          </div>
          <button className="attachment-save-btn" onClick={(e) => { e.stopPropagation(); handleSaveFile(att); }}
            disabled={savingHash === att.file_hash} title="Save">
            <DownloadIcon saving={savingHash === att.file_hash} />
          </button>
        </div>
      </div>
    );
  }

  // ── Message rendering helpers ─────────────────────────────────────────

  async function handleReaction(messageId: number, emoji: string) {
    try {
      await api.toggleReaction(messageId, emoji);
      if (currentChannelId) {
        const [r, m] = await Promise.all([api.getReactions(currentChannelId), api.getMessages(currentChannelId)]);
        dispatch({ type: "setReactions", reactions: r });
        dispatch({ type: "setMessages", messages: m });
      }
    } catch (e) { console.error("Failed to toggle reaction:", e); }
  }

  async function handleDelete(messageId: number) {
    try {
      await api.deleteMessage(messageId);
      if (currentChannelId) {
        const [m, r] = await Promise.all([api.getMessages(currentChannelId), api.getReactions(currentChannelId)]);
        dispatch({ type: "setMessages", messages: m });
        dispatch({ type: "setReactions", reactions: r });
      }
    } catch (e) { console.error("Failed to delete message:", e); }
  }

  function startEdit(messageId: number, content: string) { setEditingId(messageId); setEditText(content); }

  async function handleEditSave(messageId: number) {
    if (!editText.trim()) return;
    try {
      await api.editMessage(messageId, editText.trim());
      setEditingId(null);
      if (currentChannelId) {
        const m = await api.getMessages(currentChannelId);
        dispatch({ type: "setMessages", messages: m });
      }
    } catch (e) { console.error("Failed to edit message:", e); }
  }

  function handleEditKeyDown(e: React.KeyboardEvent, messageId: number) {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); handleEditSave(messageId); }
    else if (e.key === "Escape") setEditingId(null);
  }

  function formatTime(ts: number): string {
    return new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }

  function formatDate(ts: number): string {
    const d = new Date(ts * 1000);
    const today = new Date();
    if (d.getFullYear() === today.getFullYear() && d.getMonth() === today.getMonth() && d.getDate() === today.getDate())
      return "Today";
    return d.toLocaleDateString([], { weekday: "long", month: "long", day: "numeric" });
  }

  let lastDate = "";

  return (
    <div className="message-area">
      {topLevelMessages.length === 0 && (
        <div className="message-empty">
          <div className="message-empty-icon">#</div>
          <div className="message-empty-text">No messages yet. Start the conversation!</div>
        </div>
      )}
      {topLevelMessages.map((msg, idx) => {
        const msgId = msg.id ?? -(idx + 1);
        const msgReactions = reactions[msgId] || {};
        const isOwn = msg.user_id === user?.user_id;
        const dateStr = formatDate(msg.timestamp);
        const showDateSep = dateStr !== lastDate;
        if (showDateSep) lastDate = dateStr;
        const hasReactions = Object.keys(msgReactions).length > 0;
        const replyCount = replyCounts[msgId] || 0;
        const isGrouped = !showDateSep && idx > 0 && topLevelMessages[idx - 1].author === msg.author
          && msg.timestamp - topLevelMessages[idx - 1].timestamp < 300;

        return (
          <div key={msgId}>
            {showDateSep && <div className="date-separator"><span>{dateStr}</span></div>}
            <div className={`message ${isGrouped ? "message-grouped" : ""}`}>
              {!isGrouped && (
                <div className="message-header">
                  {msg.is_deleted_user ? (
                    <span className="message-author-deleted">[deleted]</span>
                  ) : (
                    <span className="message-author" style={{ color: getAuthorColor(msg.author) }}>{msg.author}</span>
                  )}
                  <span className="message-time">{formatTime(msg.timestamp)}</span>
                </div>
              )}

              {editingId === msgId ? (
                <div className="message-edit-wrapper">
                  <input className="message-edit-input" value={editText}
                    onChange={(e) => setEditText(e.target.value)}
                    onKeyDown={(e) => handleEditKeyDown(e, msgId)} autoFocus />
                  <div className="message-edit-hint">Enter to save &middot; Esc to cancel</div>
                </div>
              ) : (
                <div className="message-content">{msg.content}</div>
              )}

              {attachmentsMap[msgId] && renderAttachments(attachmentsMap[msgId])}

              {hasReactions && (
                <div className="message-reactions">
                  {Object.entries(msgReactions).sort(([a], [b]) => a.localeCompare(b)).map(([emoji, info]) => (
                    <button key={emoji} className="reaction-btn" onClick={() => handleReaction(msgId, emoji)}>
                      {emoji} {info.count}
                      <span className="reaction-tooltip">
                        <span className="reaction-tooltip-emoji">{emoji}</span>
                        <span className="reaction-tooltip-users">{info.users.join(", ")}</span>
                      </span>
                    </button>
                  ))}
                </div>
              )}

              {replyCount > 0 && (
                <button className="thread-indicator" onClick={() => onOpenThread?.(msgId)}>
                  {replyCount} {replyCount === 1 ? "reply" : "replies"}
                </button>
              )}

              <div className="message-toolbar">
                {QUICK_EMOJIS.map((e) => (
                  <button key={e} className="toolbar-btn" onClick={() => handleReaction(msgId, e)} title={`React with ${e}`}>{e}</button>
                ))}
                <button className="toolbar-btn toolbar-thread" onClick={() => onOpenThread?.(msgId)} title="Reply in thread">&#x21B3;</button>
                {isOwn && (
                  <>
                    <button className="toolbar-btn toolbar-edit" onClick={() => startEdit(msgId, msg.content)} title="Edit">&#x270E;</button>
                    <button className="toolbar-btn toolbar-delete" onClick={() => handleDelete(msgId)} title="Delete">&times;</button>
                  </>
                )}
              </div>
            </div>
          </div>
        );
      })}
      <div ref={bottomRef} />

      {gallery && (
        <GalleryLightbox
          attachments={gallery.attachments}
          startIndex={gallery.index}
          fileCache={fileCache}
          onClose={() => setGallery(null)}
          onSave={handleSaveFile}
          savingHash={savingHash}
          ensureFileLoaded={ensureFileLoaded}
        />
      )}
    </div>
  );
}

/* ── Gallery Lightbox ────────────────────────────────────────────────────── */

function GalleryLightbox({ attachments, startIndex, fileCache, onClose, onSave, savingHash, ensureFileLoaded }: {
  attachments: Attachment[];
  startIndex: number;
  fileCache: Record<string, string>;
  onClose: () => void;
  onSave: (att: Attachment) => void;
  savingHash: string | null;
  ensureFileLoaded: (hash: string, mime: string) => void;
}) {
  const [index, setIndex] = useState(startIndex);
  const att = attachments[index];
  const total = attachments.length;
  const blobUrl = fileCache[att.file_hash] ?? null;

  // Ensure current attachment is loaded
  useEffect(() => { ensureFileLoaded(att.file_hash, att.mime_type); }, [att.file_hash, att.mime_type]);

  // Preload adjacent
  useEffect(() => {
    if (index > 0) ensureFileLoaded(attachments[index - 1].file_hash, attachments[index - 1].mime_type);
    if (index < total - 1) ensureFileLoaded(attachments[index + 1].file_hash, attachments[index + 1].mime_type);
  }, [index, attachments, total]);

  const goPrev = useCallback(() => setIndex((i) => Math.max(0, i - 1)), []);
  const goNext = useCallback(() => setIndex((i) => Math.min(total - 1, i + 1)), [total]);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
      else if (e.key === "ArrowLeft") goPrev();
      else if (e.key === "ArrowRight") goNext();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose, goPrev, goNext]);

  const isImage = IMAGE_MIMES.has(att.mime_type);
  const isVideo = VIDEO_MIMES.has(att.mime_type);
  const isPdf = att.mime_type === "application/pdf";
  const isAudio = att.mime_type.startsWith("audio/");

  return (
    <div className="lightbox-backdrop" onClick={onClose}>
      <div className="lightbox-container" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="lightbox-header">
          <span className="lightbox-filename" title={att.filename}>{att.filename}</span>
          {total > 1 && (
            <span className="lightbox-counter">{index + 1} / {total}</span>
          )}
          <span className="lightbox-meta">{formatSize(att.size)}</span>
          <div className="lightbox-actions">
            <button className="lightbox-btn" onClick={() => onSave(att)} disabled={savingHash === att.file_hash} title="Save to disk">
              <DownloadIcon saving={savingHash === att.file_hash} />
            </button>
            <button className="lightbox-btn lightbox-close" onClick={onClose} title="Close (Esc)">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
                stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
              </svg>
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="lightbox-content">
          {/* Navigation arrows */}
          {total > 1 && index > 0 && (
            <button className="lightbox-nav lightbox-nav-prev" onClick={goPrev} title="Previous (Left arrow)">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="15 18 9 12 15 6" />
              </svg>
            </button>
          )}
          {total > 1 && index < total - 1 && (
            <button className="lightbox-nav lightbox-nav-next" onClick={goNext} title="Next (Right arrow)">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="9 18 15 12 9 6" />
              </svg>
            </button>
          )}

          {!blobUrl ? (
            <div className="lightbox-loading"><div className="attachment-loading-spinner" /></div>
          ) : isImage ? (
            <img key={att.file_hash} src={blobUrl} alt={att.filename} className="lightbox-image" />
          ) : isVideo ? (
            <video key={att.file_hash} controls autoPlay className="lightbox-video">
              <source src={blobUrl} type={att.mime_type} />
            </video>
          ) : isPdf ? (
            <iframe key={att.file_hash + "-lb"} src={blobUrl} className="lightbox-pdf" />
          ) : isAudio ? (
            <div className="lightbox-audio-wrapper">
              <FileTypeIcon ext={getExt(att.filename)} />
              <audio key={att.file_hash} controls autoPlay className="lightbox-audio">
                <source src={blobUrl} type={att.mime_type} />
              </audio>
            </div>
          ) : (
            <div className="lightbox-unsupported">
              <FileTypeIcon ext={getExt(att.filename)} />
              <p>Preview not available</p>
              <button className="lightbox-save-large" onClick={() => onSave(att)}>Save to view</button>
            </div>
          )}
        </div>

        {/* Thumbnail strip for multi-attachment */}
        {total > 1 && (
          <div className="lightbox-strip">
            {attachments.map((a, i) => (
              <button
                key={a.id}
                className={`lightbox-thumb ${i === index ? "lightbox-thumb-active" : ""}`}
                onClick={() => setIndex(i)}
              >
                {IMAGE_MIMES.has(a.mime_type) && fileCache[a.file_hash] ? (
                  <img src={fileCache[a.file_hash]} alt={a.filename} />
                ) : (
                  <FileTypeIcon ext={getExt(a.filename)} />
                )}
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
