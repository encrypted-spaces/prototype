"use client";

import {
  createContext,
  useContext,
  useReducer,
  useEffect,
  useRef,
  type ReactNode,
  type Dispatch,
} from "react";
import { listen } from "@tauri-apps/api/event";
import type {
  UserInfo,
  Channel,
  MessageWithUser,
  ReactionMap,
  TaskItem,
  CalendarItem,
  InodeWithAuthor,
} from "./types";
import * as api from "./api";
import { log } from "./log";

// ─── State ───────────────────────────────────────────────────────────────────

interface SpaceState {
  user: UserInfo | null;
  channels: Channel[];
  currentChannelId: number | null;
  messages: MessageWithUser[];
  reactions: ReactionMap;
  unreadChannels: number[];
  tasks: TaskItem[];
  notesText: string;
  calendarEvents: CalendarItem[];
  inodes: InodeWithAuthor[];
  initialized: boolean;
  fontScale: number;
}

const initialState: SpaceState = {
  user: null,
  channels: [],
  currentChannelId: null,
  messages: [],
  reactions: {},
  unreadChannels: [],
  tasks: [],
  notesText: "",
  calendarEvents: [],
  inodes: [],
  initialized: false,
  fontScale: 100,
};

// ─── Actions ─────────────────────────────────────────────────────────────────

type Action =
  | { type: "setUser"; user: UserInfo }
  | { type: "setChannels"; channels: Channel[] }
  | { type: "setMessages"; messages: MessageWithUser[] }
  | { type: "setReactions"; reactions: ReactionMap }
  | { type: "switchChannel"; channelId: number }
  | { type: "markUnread"; channelIds: number[] }
  | { type: "setTasks"; tasks: TaskItem[] }
  | { type: "setNotesText"; notesText: string }
  | { type: "setCalendarEvents"; events: CalendarItem[] }
  | { type: "setInodes"; inodes: InodeWithAuthor[] }
  | { type: "setInitialized" }
  | { type: "setFontScale"; scale: number }
  | { type: "reset" };

function reducer(state: SpaceState, action: Action): SpaceState {
  switch (action.type) {
    case "setUser":
      return {
        ...state,
        user: action.user,
        currentChannelId: action.user.current_channel_id,
      };
    case "setChannels":
      return { ...state, channels: action.channels };
    case "setMessages":
      return { ...state, messages: action.messages };
    case "setReactions":
      return { ...state, reactions: action.reactions };
    case "setTasks":
      return { ...state, tasks: action.tasks };
    case "setNotesText":
      return { ...state, notesText: action.notesText };
    case "setCalendarEvents":
      return { ...state, calendarEvents: action.events };
    case "setInodes":
      return { ...state, inodes: action.inodes };
    case "switchChannel":
      return {
        ...state,
        currentChannelId: action.channelId,
        unreadChannels: state.unreadChannels.filter((id) => id !== action.channelId),
      };
    case "markUnread": {
      const newIds = action.channelIds.filter(
        (id) => id !== state.currentChannelId && !state.unreadChannels.includes(id)
      );
      if (newIds.length === 0) return state;
      return { ...state, unreadChannels: [...state.unreadChannels, ...newIds] };
    }
    case "setInitialized":
      return { ...state, initialized: true };
    case "setFontScale":
      return { ...state, fontScale: action.scale };
    case "reset":
      return { ...initialState };
    default:
      return state;
  }
}

// ─── Context ─────────────────────────────────────────────────────────────────

const SpaceContext = createContext<SpaceState>(initialState);
const SpaceDispatchContext = createContext<Dispatch<Action>>(() => {});

export function SpaceProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(reducer, initialState);
  // Track message counts per channel to detect actual new messages
  const messageCountsRef = useRef<Record<number, number> | null>(null);

  // Fetch default zoom from backend on mount
  useEffect(() => {
    api.getDefaultZoom().then((zoom) => {
      dispatch({ type: "setFontScale", scale: zoom });
    }).catch(() => {});
  }, []);

  // Apply font scale to the document
  useEffect(() => {
    document.body.style.zoom = `${state.fontScale}%`;
  }, [state.fontScale]);

  const fontScaleRef = useRef(state.fontScale);
  fontScaleRef.current = state.fontScale;

  useEffect(() => {
    const listeners = [
      listen("zoom_in", () => {
        dispatch({ type: "setFontScale", scale: Math.min(200, fontScaleRef.current + 10) });
      }),
      listen("zoom_out", () => {
        dispatch({ type: "setFontScale", scale: Math.max(50, fontScaleRef.current - 10) });
      }),
      listen("zoom_reset", () => {
        dispatch({ type: "setFontScale", scale: 100 });
      }),
    ];
    return () => {
      listeners.forEach((p) => p.then((fn) => fn()));
    };
  }, []);

  // Listen for broadcast updates and refresh data
  useEffect(() => {
    if (!state.initialized || !state.currentChannelId) return;

    const unlisten = listen("space-updated", async () => {
      console.debug("[store] space-updated received, fetching all data");
      try {
        // Use allSettled so transient proof failures (during multi-step
        // changes like message+attachments) don't block the whole refresh.
        const results = await Promise.allSettled([
          api.getChannels(),
          api.getMessages(state.currentChannelId!),
          api.getReactions(state.currentChannelId!),
          api.getTasks(),
          api.getNotes(),
          api.getCalendarEvents(),
        ]);
        const [channels, messages, reactions, tasks, notesText, calendarEvents] = results;
        if (channels.status === "fulfilled") dispatch({ type: "setChannels", channels: channels.value });
        if (messages.status === "fulfilled") dispatch({ type: "setMessages", messages: messages.value });
        if (reactions.status === "fulfilled") dispatch({ type: "setReactions", reactions: reactions.value });
        if (tasks.status === "fulfilled") dispatch({ type: "setTasks", tasks: tasks.value });
        if (notesText.status === "fulfilled") {
          console.debug("[store] space-updated: notesText_len=%d", notesText.value.length);
          dispatch({ type: "setNotesText", notesText: notesText.value });
        }
        if (calendarEvents.status === "fulfilled") dispatch({ type: "setCalendarEvents", events: calendarEvents.value });

        // Fetch message counts for non-current channels
        if (channels.status === "fulfilled" && messages.status === "fulfilled") {
          const otherChannels = channels.value.filter(
            (c) => c.id !== null && c.id !== state.currentChannelId
          );
          const countResults = await Promise.all(
            otherChannels.map(async (ch) => {
              const msgs = await api.getMessages(ch.id!);
              return { channelId: ch.id!, count: msgs.length };
            })
          );

          // Build new counts map
          const newCounts: Record<number, number> = {
            [state.currentChannelId!]: messages.value.length,
          };
          for (const { channelId, count } of countResults) {
            newCounts[channelId] = count;
          }

        if (messageCountsRef.current === null) {
          // First broadcast after init — populate counts, don't badge
          messageCountsRef.current = newCounts;
        } else {
          // Compare with previous counts, only badge channels with new messages
          const prevCounts = messageCountsRef.current;
          const unreadIds = countResults
            .filter(({ channelId, count }) => count > (prevCounts[channelId] ?? 0))
            .map(({ channelId }) => channelId);
          messageCountsRef.current = newCounts;
          if (unreadIds.length > 0) {
            dispatch({ type: "markUnread", channelIds: unreadIds });
          }
        }
        }
      } catch (e) {
        log.error("Failed to refresh after broadcast:", e);
      }
    });

    return () => {
      unlisten.then((fn) => fn());
    };
  }, [state.initialized, state.currentChannelId]);

  return (
    <SpaceContext.Provider value={state}>
      <SpaceDispatchContext.Provider value={dispatch}>
        {children}
      </SpaceDispatchContext.Provider>
    </SpaceContext.Provider>
  );
}

export function useSpace() {
  return useContext(SpaceContext);
}

export function useSpaceDispatch() {
  return useContext(SpaceDispatchContext);
}
