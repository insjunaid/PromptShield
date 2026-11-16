import { create } from "zustand";

import type { LiveEvent } from "@/api/types";

// The feed only needs the recent past. Older events are fetched page by page when asked for.
export const MAX_EVENTS = 500;

export type ConnectionStatus = "connecting" | "live" | "reconnecting";

interface LiveState {
  events: LiveEvent[];
  status: ConnectionStatus;
  lastEventId: string | null;
  addEvents: (incoming: LiveEvent[]) => void;
  setStatus: (status: ConnectionStatus) => void;
  reset: () => void;
}

/** Ids are ULIDs, which sort by creation time, so string order is time order. */
function newestFirst(a: LiveEvent, b: LiveEvent): number {
  if (a.id === b.id) return 0;
  return a.id < b.id ? 1 : -1;
}

/**
 * Merges events from the live stream and from catch-up fetches. The same event can arrive both
 * ways around a reconnect, so duplicates are dropped by id.
 */
export function mergeEvents(current: LiveEvent[], incoming: LiveEvent[]): LiveEvent[] {
  const byId = new Map(current.map((event) => [event.id, event]));
  for (const event of incoming) byId.set(event.id, event);
  return [...byId.values()].sort(newestFirst).slice(0, MAX_EVENTS);
}

export const useLiveStore = create<LiveState>()((set) => ({
  events: [],
  status: "connecting",
  lastEventId: null,
  addEvents: (incoming) =>
    set((state) => {
      if (incoming.length === 0) return state;
      const events = mergeEvents(state.events, incoming);
      const newest = events[0]?.id ?? null;
      const lastEventId =
        state.lastEventId !== null && newest !== null && state.lastEventId > newest
          ? state.lastEventId
          : newest;
      return { events, lastEventId };
    }),
  setStatus: (status) => set({ status }),
  reset: () => set({ events: [], status: "connecting", lastEventId: null }),
}));
