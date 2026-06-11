import { invoke } from "@tauri-apps/api/core";
import type {
  UserInfo,
  Channel,
  MessageWithUser,
  ReactionMap,
  UserRecord,
  TaskItem,
  CalendarItem,
  Attachment,
  InodeWithAuthor,
} from "./types";

export type { InodeWithAuthor };

// ─── Initialization ──────────────────────────────────────────────────────────

export async function checkSnapshot(): Promise<boolean> {
  return invoke<boolean>("check_snapshot");
}

export async function createSpace(
  wsAddress: string,
  username: string,
  channelName: string
): Promise<UserInfo> {
  return invoke<UserInfo>("create_space", {
    wsAddress,
    username,
    channelName,
  });
}

export async function joinSpace(
  wsAddress: string,
  inviteJson: string,
  username: string,
  channelName: string
): Promise<UserInfo> {
  return invoke<UserInfo>("join_space", {
    wsAddress,
    inviteJson,
    username,
    channelName,
  });
}

export async function restoreSpace(): Promise<UserInfo> {
  return invoke<UserInfo>("restore_space");
}

export async function logout(): Promise<void> {
  return invoke<void>("logout");
}

// ─── Channels ────────────────────────────────────────────────────────────────

export async function getChannels(): Promise<Channel[]> {
  return invoke<Channel[]>("get_channels");
}

export async function createChannel(name: string): Promise<Channel> {
  return invoke<Channel>("create_channel", { name });
}

export async function updateChannelDescription(
  channelId: number,
  description: string | null
): Promise<boolean> {
  return invoke<boolean>("update_channel_description", {
    channelId,
    description,
  });
}

export async function switchChannel(
  channelId: number,
  channelName: string
): Promise<void> {
  return invoke<void>("switch_channel", { channelId, channelName });
}

// ─── Messages ────────────────────────────────────────────────────────────────

export async function getMessages(
  channelId: number
): Promise<MessageWithUser[]> {
  return invoke<MessageWithUser[]>("get_messages", { channelId });
}

export async function getThreadMessages(
  threadId: number
): Promise<MessageWithUser[]> {
  return invoke<MessageWithUser[]>("get_thread_messages", { threadId });
}

export async function sendMessage(
  channelId: number,
  content: string,
  threadId?: number
): Promise<number> {
  return invoke<number>("send_message", {
    channelId,
    content,
    threadId: threadId ?? 0,
  });
}

export async function editMessage(
  messageId: number,
  content: string
): Promise<boolean> {
  return invoke<boolean>("edit_message", { messageId, content });
}

export async function deleteMessage(messageId: number): Promise<boolean> {
  return invoke<boolean>("delete_message", { messageId });
}

// ─── Attachments ────────────────────────────────────────────────────────────

export async function sendMessageWithAttachments(
  channelId: number,
  content: string,
  filePaths: string[],
  threadId?: number
): Promise<number> {
  return invoke<number>("send_message_with_attachments", {
    channelId,
    content,
    filePaths,
    threadId: threadId ?? 0,
  });
}

export async function getAttachments(
  messageId: number
): Promise<Attachment[]> {
  return invoke<Attachment[]>("get_attachments", { messageId });
}

export async function downloadFile(hash: string): Promise<number[]> {
  return invoke<number[]>("download_file", { hash });
}

// ─── Reactions ───────────────────────────────────────────────────────────────

export async function getReactions(channelId: number): Promise<ReactionMap> {
  return invoke<ReactionMap>("get_reactions", { channelId });
}

export async function toggleReaction(
  messageId: number,
  emoji: string
): Promise<string> {
  return invoke<string>("toggle_reaction", { messageId, emoji });
}

// ─── Invites ─────────────────────────────────────────────────────────────────

export async function inviteUser(): Promise<string> {
  return invoke<string>("invite_user");
}

export async function exportInviteToFile(): Promise<string> {
  return invoke<string>("export_invite_to_file");
}

// ─── Users ───────────────────────────────────────────────────────────────────

export async function getUsers(): Promise<UserRecord[]> {
  return invoke<UserRecord[]>("get_users");
}

// ─── Tasks ───────────────────────────────────────────────────────────────────

export async function getTasks(): Promise<TaskItem[]> {
  return invoke<TaskItem[]>("get_tasks");
}

export async function addTask(title: string): Promise<TaskItem> {
  return invoke<TaskItem>("add_task", { title });
}

export async function toggleTask(key: string): Promise<boolean> {
  return invoke<boolean>("toggle_task", { key });
}

export async function updateTaskTitle(
  key: string,
  title: string
): Promise<void> {
  return invoke<void>("update_task_title", { key, title });
}

export async function deleteTask(key: string): Promise<void> {
  return invoke<void>("delete_task", { key });
}

export async function removeUser(userId: number): Promise<void> {
  return invoke<void>("remove_user", { userId });
}

// ─── Inodes (Files & Folders) ──────────────────────────────────────────────

export async function listInodes(parentId: number): Promise<InodeWithAuthor[]> {
  return invoke<InodeWithAuthor[]>("list_inodes", { parentId });
}

export async function uploadInodes(filePaths: string[], parentId: number = 0): Promise<unknown[]> {
  return invoke<unknown[]>("upload_inodes", { filePaths, parentId });
}

export async function deleteInode(inodeId: number): Promise<boolean> {
  return invoke<boolean>("delete_inode", { inodeId });
}

export async function moveInode(inodeId: number, newParentId: number): Promise<boolean> {
  return invoke<boolean>("move_inode", { inodeId, newParentId });
}

export async function renameInode(inodeId: number, newName: string): Promise<boolean> {
  return invoke<boolean>("rename_inode", { inodeId, newName });
}

export async function createFolderInode(parentId: number, name: string): Promise<unknown> {
  return invoke<unknown>("create_folder_inode", { parentId, name });
}

// ─── Shared Notes ──────────────────────────────────────────────────────────────

export async function getNotes(): Promise<string> {
  return invoke<string>("get_notes");
}

export async function notesInsert(pos: number, text: string): Promise<void> {
  return invoke<void>("notes_insert", { pos, text });
}

export async function notesDelete(pos: number, count: number): Promise<void> {
  return invoke<void>("notes_delete", { pos, count });
}

// ─── Calendar ──────────────────────────────────────────────────────────────────

export async function getCalendarEvents(): Promise<CalendarItem[]> {
  return invoke<CalendarItem[]>("get_calendar_events");
}

export async function addCalendarEvent(
  startTime: number,
  endTime: number,
  title: string,
  description: string
): Promise<CalendarItem> {
  return invoke<CalendarItem>("add_calendar_event", { startTime, endTime, title, description });
}

export async function updateCalendarEvent(
  eventId: number,
  startTime: number,
  endTime: number,
  title: string,
  description: string
): Promise<boolean> {
  return invoke<boolean>("update_calendar_event", { eventId, startTime, endTime, title, description });
}

export async function deleteCalendarEvent(eventId: number): Promise<boolean> {
  return invoke<boolean>("delete_calendar_event", { eventId });
}

export async function sendEphemeral(kind: string, payload: string): Promise<void> {
  return invoke<void>("send_ephemeral", { kind, payload });
}

// ─── Settings ────────────────────────────────────────────────────────────────

export async function getDefaultZoom(): Promise<number> {
  return invoke<number>("get_default_zoom");
}

// ─── Logging ─────────────────────────────────────────────────────────────────

export async function logMessage(
  level: string,
  message: string
): Promise<void> {
  return invoke<void>("log_message", { level, message });
}

