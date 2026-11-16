import type { LiveEvent, Verdict } from "@/api/types";
import type { TimeWindow } from "@/store/ui";

const WINDOW_MS: Record<Exclude<TimeWindow, "all">, number> = {
  "1h": 60 * 60 * 1000,
  "24h": 24 * 60 * 60 * 1000,
};

// The pipeline's order, so the icons read left to right the way a scan runs.
const LAYER_ORDER = ["L0", "L2", "L1", "CANARY", "L3", "L4", "REGISTRY"];

export type VerdictEvent = LiveEvent & { verdict: Verdict };

export function windowStart(window: TimeWindow, now: Date): Date | null {
  return window === "all" ? null : new Date(now.getTime() - WINDOW_MS[window]);
}

/** Events that carry a verdict, inside the window. The store already keeps them newest first. */
export function feedItems(events: LiveEvent[], window: TimeWindow, now: Date): VerdictEvent[] {
  const start = windowStart(window, now);
  return events.filter(
    (event): event is VerdictEvent =>
      event.verdict != null && (start === null || new Date(event.ts) >= start),
  );
}

export function topReason(verdict: Verdict): string {
  return verdict.reasons?.[0] ?? "No issues found.";
}

/** Each layer that reported a finding, once, in pipeline order. */
export function layersFired(verdict: Verdict): string[] {
  const fired = new Set<string>((verdict.findings ?? []).map((finding) => finding.layer));
  return LAYER_ORDER.filter((layer) => fired.has(layer));
}

/** The tool if the gateway recorded one, else the scanned source, else a dash. */
export function eventTool(event: LiveEvent): string {
  if (event.tool) return event.tool;
  const sources = (event.payload as { sources?: unknown } | undefined)?.sources;
  if (Array.isArray(sources) && typeof sources[0] === "string") return sources[0];
  return "—";
}

export function formatMs(ms: number): string {
  if (ms < 1) return "<1 ms";
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(1)} s`;
}

export function formatTime(ts: string): string {
  return new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function shortId(id: string | null | undefined): string {
  return id ? id.slice(-6) : "—";
}
