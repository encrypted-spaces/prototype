"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import { open, save, confirm } from "@tauri-apps/plugin-dialog";
import { writeFile } from "@tauri-apps/plugin-fs";
import { listen } from "@tauri-apps/api/event";
import { useSpace, useSpaceDispatch } from "@/lib/store";
import * as api from "@/lib/api";
import { INODE_FILE, INODE_FOLDER, ROOT_PARENT, type InodeWithAuthor } from "@/lib/types";
import { FileTypeIcon, formatSize } from "./message-input";

const IMAGE_MIMES = new Set([
  "image/png", "image/jpeg", "image/gif", "image/webp",
  "image/svg+xml", "image/bmp", "image/x-icon",
]);
const VIDEO_MIMES = new Set(["video/mp4", "video/webm", "video/ogg", "video/quicktime"]);

function getExt(name: string): string {
  return name.split(".").pop()?.toLowerCase() ?? "";
}

function formatDate(ts: number): string {
  return new Date(ts * 1000).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function Files() {
  const { inodes } = useSpace();
  const dispatch = useSpaceDispatch();
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [creatingFolder, setCreatingFolder] = useState(false);
  const [newFolderName, setNewFolderName] = useState("");
  const [renamingId, setRenamingId] = useState<number | null>(null);
  const [renameValue, setRenameValue] = useState("");
  // Navigation stack: array of { id, name } representing the folder path
  const [pathStack, setPathStack] = useState<{ id: number; name: string }[]>([
    { id: ROOT_PARENT, name: "Files" },
  ]);
  // File cache for lightbox blob URLs
  const [fileCache, setFileCache] = useState<Record<string, string>>({});
  const [lightboxIndex, setLightboxIndex] = useState<number | null>(null);
  const [savingHash, setSavingHash] = useState<string | null>(null);

  const currentParentId = pathStack[pathStack.length - 1].id;

  // Load inodes for current directory
  const refresh = useCallback(async () => {
    try {
      const items = await api.listInodes(currentParentId);
      dispatch({ type: "setInodes", inodes: items });
    } catch {
      // ignore — will show stale data
    }
  }, [currentParentId, dispatch]);

  useEffect(() => { refresh(); }, [refresh]);

  // Refresh when broadcast arrives (e.g. another user uploaded)
  useEffect(() => {
    const unlisten = listen("space-updated", () => { refresh(); });
    return () => { unlisten.then((fn) => fn()); };
  }, [refresh]);

  // Separate folders and files
  const folders = useMemo(() => inodes.filter((n) => n.type === INODE_FOLDER), [inodes]);
  const files = useMemo(() => inodes.filter((n) => n.type === INODE_FILE), [inodes]);

  // Previewable files (for lightbox navigation)
  const previewableFiles = useMemo(
    () => files.filter((f) => IMAGE_MIMES.has(f.mime_type) || VIDEO_MIMES.has(f.mime_type) || f.mime_type === "application/pdf" || f.mime_type.startsWith("audio/")),
    [files],
  );

  // Breadcrumbs from path stack
  const breadcrumbs = pathStack;

  // Ensure a file is loaded into cache (for lightbox)
  const ensureFileLoaded = useCallback(async (hash: string, mimeType: string) => {
    if (!hash || fileCache[hash]) return;
    try {
      const bytes = await api.downloadFile(hash);
      const blob = new Blob([new Uint8Array(bytes)], { type: mimeType });
      setFileCache((prev) => ({ ...prev, [hash]: URL.createObjectURL(blob) }));
    } catch { /* ignore */ }
  }, [fileCache]);

  function navigateToFolder(folderId: number, folderName: string) {
    setPathStack((prev) => [...prev, { id: folderId, name: folderName }]);
  }

  function navigateToBreadcrumb(index: number) {
    setPathStack((prev) => prev.slice(0, index + 1));
  }

  async function handleUpload() {
    const selected = await open({ multiple: true, title: "Upload files" });
    if (!selected) return;
    const paths = Array.isArray(selected) ? selected : [selected];
    if (paths.length === 0) return;

    setUploading(true);
    setError(null);
    try {
      await api.uploadInodes(paths, currentParentId);
      await refresh();
    } catch (e: any) {
      setError(typeof e === "string" ? e : e?.message ?? "Upload failed");
    } finally {
      setUploading(false);
    }
  }

  async function handleDownload(fileHash: string, filename: string) {
    setError(null);
    try {
      const dest = await save({ title: "Save file", defaultPath: filename });
      if (!dest) return;
      setSavingHash(fileHash);
      const data = await api.downloadFile(fileHash);
      await writeFile(dest, new Uint8Array(data));
    } catch (e: any) {
      setError(typeof e === "string" ? e : e?.message ?? "Download failed");
    } finally {
      setSavingHash(null);
    }
  }

  async function handleDelete(inodeId: number, name: string, isFolder: boolean) {
    const msg = isFolder
      ? `Delete folder "${name}" and all its contents? This cannot be undone.`
      : `Delete "${name}"? This cannot be undone.`;
    try {
      const ok = await confirm(msg, {
        title: isFolder ? "Delete folder" : "Delete file",
        kind: "warning",
      });
      if (!ok) return;
      await api.deleteInode(inodeId);
      await refresh();
    } catch (e: any) {
      setError(typeof e === "string" ? e : e?.message ?? "Delete failed");
    }
  }

  async function handleCreateFolder() {
    const name = newFolderName.trim();
    if (!name || name.includes("/")) return;
    setCreatingFolder(false);
    setNewFolderName("");
    try {
      await api.createFolderInode(currentParentId, name);
      await refresh();
    } catch (e: any) {
      setError(typeof e === "string" ? e : e?.message ?? "Create folder failed");
    }
  }

  async function handleRename(inodeId: number) {
    const name = renameValue.trim();
    if (!name) return;
    try {
      await api.renameInode(inodeId, name);
      await refresh();
    } catch (e: any) {
      setError(typeof e === "string" ? e : e?.message ?? "Rename failed");
    } finally {
      setRenamingId(null);
      setRenameValue("");
    }
  }

  function openPreview(file: InodeWithAuthor) {
    const idx = previewableFiles.findIndex((f) => f.id === file.id);
    if (idx >= 0) {
      setLightboxIndex(idx);
    }
  }

  function isPreviewable(mime: string): boolean {
    return IMAGE_MIMES.has(mime) || VIDEO_MIMES.has(mime) || mime === "application/pdf" || mime.startsWith("audio/");
  }

  const isEmpty = folders.length === 0 && files.length === 0;

  return (
    <div className="files-container">
      <div className="files-header">
        <div className="files-breadcrumbs">
          {breadcrumbs.map((bc, i) => (
            <span key={bc.id + ":" + i}>
              {i > 0 && <span className="files-bc-sep">/</span>}
              {i < breadcrumbs.length - 1 ? (
                <button className="files-bc-btn" onClick={() => navigateToBreadcrumb(i)}>
                  {bc.name}
                </button>
              ) : (
                <span className="files-bc-current">{bc.name}</span>
              )}
            </span>
          ))}
        </div>
        <div className="files-header-actions">
          <button
            className="files-newfolder-btn"
            onClick={() => setCreatingFolder(!creatingFolder)}
            title="New Folder"
          >
            <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor" style={{marginRight:4,verticalAlign:"middle"}}><path d="M1 3v10h14V5H7.5L6 3H1zm1 1h3.3l1.5 2H14v6H2V4z"/></svg>
            New Folder
          </button>
          <button className="files-upload-btn" onClick={handleUpload} disabled={uploading}>
            {uploading ? "Uploading\u2026" : (<><svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor" style={{marginRight:4,verticalAlign:"middle"}}><path d="M8 1L3 6h3v5h4V6h3L8 1z"/><path d="M2 13v1h12v-1H2z"/></svg>Upload</>)}
          </button>
        </div>
      </div>

      {creatingFolder && (
        <div className="files-newfolder-input">
          <input
            autoFocus
            placeholder="Folder name"
            value={newFolderName}
            onChange={(e) => setNewFolderName(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") handleCreateFolder();
              if (e.key === "Escape") { setCreatingFolder(false); setNewFolderName(""); }
            }}
          />
          <button onClick={handleCreateFolder} disabled={!newFolderName.trim()}>Create</button>
          <button onClick={() => { setCreatingFolder(false); setNewFolderName(""); }}>Cancel</button>
        </div>
      )}

      {error && (
        <div className="files-error">
          <span>{error}</span>
          <button onClick={() => setError(null)}>&times;</button>
        </div>
      )}

      {isEmpty ? (
        <div className="files-empty">
          <p>No files here yet.</p>
          <p className="files-empty-hint">Upload files or create a folder to get started.</p>
        </div>
      ) : (
        <div className="files-list">
          {/* Folders first */}
          {folders.map((node) => (
            <div
              key={node.id}
              className="files-row files-folder-row"
            >
              <span
                className="files-icon files-folder-icon"
                onClick={() => node.id !== null && navigateToFolder(node.id, node.name)}
              >
                <svg width="20" height="20" viewBox="0 0 16 16" fill="currentColor"><path d="M1 3v10h14V5H7.5L6 3H1zm1 1h3.3l1.5 2H14v6H2V4z"/></svg>
              </span>
              <div className="files-info" onClick={() => node.id !== null && navigateToFolder(node.id, node.name)}>
                {renamingId === node.id ? (
                  <input
                    className="files-rename-input"
                    autoFocus
                    value={renameValue}
                    onChange={(e) => setRenameValue(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" && node.id !== null) handleRename(node.id);
                      if (e.key === "Escape") { setRenamingId(null); setRenameValue(""); }
                    }}
                    onBlur={() => { setRenamingId(null); setRenameValue(""); }}
                    onClick={(e) => e.stopPropagation()}
                  />
                ) : (
                  <span className="files-name">{node.name}</span>
                )}
                <span className="files-meta">
                  {node.author_name} &middot; {formatDate(node.ctime)}
                </span>
              </div>
              <div className="files-actions">
                <button
                  className="files-action-btn"
                  title="Rename"
                  onClick={(e) => { e.stopPropagation(); setRenamingId(node.id); setRenameValue(node.name); }}
                >
                  <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M12.1 1.3a1 1 0 0 1 1.4 0l1.2 1.2a1 1 0 0 1 0 1.4l-8.5 8.5L3 13l.6-3.2 8.5-8.5zM11.4 4L5 10.4l-.3 1.6 1.6-.3L12.7 5.3 11.4 4z"/></svg>
                </button>
                <button
                  className="files-action-btn files-delete-btn"
                  title="Delete folder"
                  onClick={(e) => { e.stopPropagation(); node.id !== null && handleDelete(node.id, node.name, true); }}
                >
                  <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M5 2V1h6v1h4v1H1V2h4zm0 2h6l-.5 10h-5L5 4zm2 1.5v7h2v-7H7z"/></svg>
                </button>
              </div>
            </div>
          ))}

          {/* Files */}
          {files.map((node) => {
            const canPreview = isPreviewable(node.mime_type);
            const isImage = IMAGE_MIMES.has(node.mime_type);
            const thumbUrl = isImage ? fileCache[node.file_hash] : null;

            // Lazy-load thumbnail for images
            if (isImage && !fileCache[node.file_hash] && node.file_hash) {
              ensureFileLoaded(node.file_hash, node.mime_type);
            }

            return (
              <div key={node.id} className="files-row">
                <span
                  className={`files-icon ${canPreview ? "files-icon-clickable" : ""}`}
                  onClick={() => canPreview && openPreview(node)}
                  title={canPreview ? "Preview" : undefined}
                >
                  {thumbUrl ? (
                    <img className="files-thumb" src={thumbUrl} alt={node.name} />
                  ) : (
                    <FileTypeIcon ext={getExt(node.name)} />
                  )}
                </span>
                <div className="files-info">
                  {renamingId === node.id ? (
                    <input
                      className="files-rename-input"
                      autoFocus
                      value={renameValue}
                      onChange={(e) => setRenameValue(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" && node.id !== null) handleRename(node.id);
                        if (e.key === "Escape") { setRenamingId(null); setRenameValue(""); }
                      }}
                      onBlur={() => { setRenamingId(null); setRenameValue(""); }}
                    />
                  ) : (
                    <span
                      className={`files-name ${canPreview ? "files-name-clickable" : ""}`}
                      onClick={() => canPreview && openPreview(node)}
                    >
                      {node.name}
                    </span>
                  )}
                  <span className="files-meta">
                    {formatSize(node.size)} &middot; {node.author_name} &middot; {formatDate(node.ctime)}
                  </span>
                </div>
                <div className="files-actions">
                  <button
                    className="files-action-btn"
                    title="Rename"
                    onClick={() => { setRenamingId(node.id); setRenameValue(node.name); }}
                  >
                    <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M12.1 1.3a1 1 0 0 1 1.4 0l1.2 1.2a1 1 0 0 1 0 1.4l-8.5 8.5L3 13l.6-3.2 8.5-8.5zM11.4 4L5 10.4l-.3 1.6 1.6-.3L12.7 5.3 11.4 4z"/></svg>
                  </button>
                  {canPreview && (
                    <button
                      className="files-action-btn"
                      title="Preview"
                      onClick={() => openPreview(node)}
                    >
                      <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M8 3C3 3 0 8 0 8s3 5 8 5 8-5 8-5-3-5-8-5zm0 8a3 3 0 1 1 0-6 3 3 0 0 1 0 6zm0-4.5a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3z"/></svg>
                    </button>
                  )}
                  <button
                    className="files-action-btn"
                    title="Download"
                    disabled={savingHash === node.file_hash}
                    onClick={() => handleDownload(node.file_hash, node.name)}
                  >
                    {savingHash === node.file_hash ? (
                      <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor" className="spin"><circle cx="8" cy="8" r="6" fill="none" stroke="currentColor" strokeWidth="2" strokeDasharray="28" strokeDashoffset="8"/></svg>
                    ) : (
                      <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M8 1v9M8 10l-3-3M8 10l3-3"/><path d="M8 1v9" stroke="currentColor" strokeWidth="2" fill="none"/><path d="M5 7l3 3 3-3" stroke="currentColor" strokeWidth="2" fill="none" strokeLinejoin="round"/><path d="M2 13v1h12v-1H2z"/></svg>
                    )}
                  </button>
                  <button
                    className="files-action-btn files-delete-btn"
                    title="Delete"
                    onClick={() => node.id !== null && handleDelete(node.id, node.name, false)}
                  >
                    <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M5 2V1h6v1h4v1H1V2h4zm0 2h6l-.5 10h-5L5 4zm2 1.5v7h2v-7H7z"/></svg>
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Lightbox */}
      {lightboxIndex !== null && previewableFiles[lightboxIndex] && (
        <FileLightbox
          files={previewableFiles}
          startIndex={lightboxIndex}
          fileCache={fileCache}
          onClose={() => setLightboxIndex(null)}
          onSave={(f) => handleDownload(f.file_hash, f.name)}
          savingHash={savingHash}
          ensureFileLoaded={ensureFileLoaded}
        />
      )}
    </div>
  );
}

// ─── File Lightbox ──────────────────────────────────────────────────────────

function FileLightbox({ files, startIndex, fileCache, onClose, onSave, savingHash, ensureFileLoaded }: {
  files: InodeWithAuthor[];
  startIndex: number;
  fileCache: Record<string, string>;
  onClose: () => void;
  onSave: (f: InodeWithAuthor) => void;
  savingHash: string | null;
  ensureFileLoaded: (hash: string, mime: string) => void;
}) {
  const [index, setIndex] = useState(startIndex);
  const node = files[index];
  const total = files.length;
  const blobUrl = fileCache[node.file_hash] ?? null;

  useEffect(() => { ensureFileLoaded(node.file_hash, node.mime_type); }, [node.file_hash, node.mime_type]);

  // Preload adjacent
  useEffect(() => {
    if (index > 0) ensureFileLoaded(files[index - 1].file_hash, files[index - 1].mime_type);
    if (index < total - 1) ensureFileLoaded(files[index + 1].file_hash, files[index + 1].mime_type);
  }, [index, files, total]);

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

  const isImage = IMAGE_MIMES.has(node.mime_type);
  const isVideo = VIDEO_MIMES.has(node.mime_type);
  const isPdf = node.mime_type === "application/pdf";
  const isAudio = node.mime_type.startsWith("audio/");

  return (
    <div className="lightbox-backdrop" onClick={onClose}>
      <div className="lightbox-container" onClick={(e) => e.stopPropagation()}>
        <div className="lightbox-header">
          <span className="lightbox-filename" title={node.name}>{node.name}</span>
          {total > 1 && (
            <span className="lightbox-counter">{index + 1} / {total}</span>
          )}
          <span className="lightbox-meta">{formatSize(node.size)} &middot; {node.author_name}</span>
          <div className="lightbox-actions">
            <button className="lightbox-btn" onClick={() => onSave(node)} disabled={savingHash === node.file_hash} title="Save to disk">
              {savingHash === node.file_hash ? (
                <div className="attachment-loading-spinner small" />
              ) : (
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
                  stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                  <polyline points="7 10 12 15 17 10" /><line x1="12" y1="15" x2="12" y2="3" />
                </svg>
              )}
            </button>
            <button className="lightbox-btn lightbox-close" onClick={onClose} title="Close (Esc)">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
                stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
              </svg>
            </button>
          </div>
        </div>

        <div className="lightbox-content">
          {total > 1 && index > 0 && (
            <button className="lightbox-nav lightbox-nav-prev" onClick={goPrev} title="Previous">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="15 18 9 12 15 6" />
              </svg>
            </button>
          )}
          {total > 1 && index < total - 1 && (
            <button className="lightbox-nav lightbox-nav-next" onClick={goNext} title="Next">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="9 18 15 12 9 6" />
              </svg>
            </button>
          )}

          {!blobUrl ? (
            <div className="lightbox-loading"><div className="attachment-loading-spinner" /></div>
          ) : isImage ? (
            <img key={node.file_hash} src={blobUrl} alt={node.name} className="lightbox-image" />
          ) : isVideo ? (
            <video key={node.file_hash} controls autoPlay className="lightbox-video">
              <source src={blobUrl} type={node.mime_type} />
            </video>
          ) : isPdf ? (
            <iframe key={node.file_hash + "-lb"} src={blobUrl} className="lightbox-pdf" />
          ) : isAudio ? (
            <div className="lightbox-audio-wrapper">
              <FileTypeIcon ext={getExt(node.name)} />
              <audio key={node.file_hash} controls autoPlay className="lightbox-audio">
                <source src={blobUrl} type={node.mime_type} />
              </audio>
            </div>
          ) : (
            <div className="lightbox-unsupported">
              <FileTypeIcon ext={getExt(node.name)} />
              <p>Preview not available</p>
              <button className="lightbox-save-large" onClick={() => onSave(node)}>Save to view</button>
            </div>
          )}
        </div>

        {total > 1 && (
          <div className="lightbox-strip">
            {files.map((f, i) => (
              <button
                key={f.id}
                className={`lightbox-thumb ${i === index ? "lightbox-thumb-active" : ""}`}
                onClick={() => setIndex(i)}
              >
                {IMAGE_MIMES.has(f.mime_type) && fileCache[f.file_hash] ? (
                  <img src={fileCache[f.file_hash]} alt={f.name} />
                ) : (
                  <FileTypeIcon ext={getExt(f.name)} />
                )}
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
