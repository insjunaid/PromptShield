import { describe, expect, it } from "vitest";

import type { LiveEvent, Verdict } from "@/api/types";

import { eventTool, feedItems, formatMs, layersFired, shortId, topReason, windowStart } from "./feed";

const NOW = new Date("2026-11-13T12:00:00Z");

function verdict(overrides: Partial<Verdict> = {}): Verdict {
  return { decision: "BLOCK", risk_score: 0.9, reasons: ["Hidden instruction"], findings: [], ...overrides } as Verdict;
}

function event(id: string, minutesAgo: number, withVerdict = true, extra: Partial<LiveEvent> = {}): LiveEvent {
  return {
    id,
    ts: new Date(NOW.getTime() - minutesAgo * 60_000).toISOString(),
    type: "verdict",
    ...(withVerdict ? { verdict: verdict() } : {}),
    ...extra,
  } as LiveEvent;
}

describe("windowStart", () => {
  it("is an hour or a day back, or none for all", () => {
    expect(windowStart("1h", NOW)?.toISOString()).toBe("2026-11-13T11:00:00.000Z");
    expect(windowStart("24h", NOW)?.toISOString()).toBe("2026-11-12T12:00:00.000Z");
    expect(windowStart("all", NOW)).toBeNull();
  });
});

describe("feedItems", () => {
  const events = [event("03", 5), event("02", 90), event("01", 10, false)];

  it("keeps only events with a verdict, inside the window", () => {
    expect(feedItems(events, "1h", NOW).map((e) => e.id)).toEqual(["03"]);
  });

  it("widens with the window", () => {
    expect(feedItems(events, "24h", NOW).map((e) => e.id)).toEqual(["03", "02"]);
    expect(feedItems(events, "all", NOW).map((e) => e.id)).toEqual(["03", "02"]);
  });
});

describe("verdict helpers", () => {
  it("shows the first reason, or says nothing was found", () => {
    expect(topReason(verdict())).toBe("Hidden instruction");
    expect(topReason(verdict({ reasons: [] }))).toBe("No issues found.");
  });

  it("lists each layer that fired once, in pipeline order", () => {
    const findings = ["L1", "L2", "L1", "L0"].map((layer) => ({
      layer, rule_id: `${layer}.x`, title: "t", severity: "HIGH", score: 0.9, evidence: "", latency_ms: 1,
    })) as Verdict["findings"];
    expect(layersFired(verdict({ findings }))).toEqual(["L0", "L2", "L1"]);
  });
});

describe("eventTool", () => {
  it("prefers the tool, then the scanned source, then a dash", () => {
    expect(eventTool(event("a", 1, true, { tool: "web.web_fetch" }))).toBe("web.web_fetch");
    expect(eventTool(event("b", 1, true, { payload: { sources: ["read_file"] } }))).toBe("read_file");
    expect(eventTool(event("c", 1))).toBe("—");
  });
});

describe("formatting", () => {
  it("formats latency for people", () => {
    expect(formatMs(0.2)).toBe("<1 ms");
    expect(formatMs(153.4)).toBe("153 ms");
    expect(formatMs(12_500)).toBe("12.5 s");
  });

  it("shortens ids to their tail", () => {
    expect(shortId("01M7ACESG0FGWQKP6FE0XNBY5B")).toBe("XNBY5B");
    expect(shortId(null)).toBe("—");
  });
});
