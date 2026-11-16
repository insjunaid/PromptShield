import { create } from "zustand";

export type TimeWindow = "1h" | "24h" | "all";

interface UiState {
  window: TimeWindow;
  setWindow: (window: TimeWindow) => void;
}

/** The global time window every page reads. Kept in memory: a reload starts at the last hour. */
export const useUiStore = create<UiState>()((set) => ({
  window: "1h",
  setWindow: (window) => set({ window }),
}));
