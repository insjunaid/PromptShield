import { beforeEach, describe, expect, it } from "vitest";

import type { LiveEvent } from "@/api/types";

import { MAX_EVENTS, mergeEvents, useLiveStore } from "./live";

function event(id: string): LiveEvent {
  return { id, ts: "2026-11-13T12:00:00Z", type: "verdict" } as LiveEvent;
}

describe("mergeEvents", () => {
  it("puts the newest first, by id", () => {
    const merged = mergeEvents([event("01B")], [event("01A"), event("01C")]);
    expect(merged.map((e) => e.id)).toEqual(["01C", "01B", "01A"]);
  });

  it("drops an event that arrives twice around a reconnect", () => {
    const merged = mergeEvents([event("01A")], [event("01A"), event("01B")]);
    expect(merged.map((e) => e.id)).toEqual(["01B", "01A"]);
  });

  it("keeps only the most recent events", () => {
    const many = Array.from({ length: MAX_EVENTS + 20 }, (_, i) => event(`01${String(i).padStart(4, "0")}`));
    const merged = mergeEvents([], many);
    expect(merged).toHaveLength(MAX_EVENTS);
    expect(merged[0]?.id).toBe(`01${String(MAX_EVENTS + 19).padStart(4, "0")}`);
  });
});

describe("useLiveStore", () => {
  beforeEach(() => useLiveStore.getState().reset());

  it("remembers the newest id, for catching up after a reconnect", () => {
    useLiveStore.getState().addEvents([event("01A"), event("01C"), event("01B")]);
    expect(useLiveStore.getState().lastEventId).toBe("01C");
  });

  it("never moves the last id backwards when older events arrive", () => {
    const { addEvents } = useLiveStore.getState();
    addEvents([event("01C")]);
    addEvents([event("01A")]);
    expect(useLiveStore.getState().lastEventId).toBe("01C");
  });

  it("ignores an empty batch", () => {
    const before = useLiveStore.getState();
    before.addEvents([]);
    expect(useLiveStore.getState().events).toBe(before.events);
  });

  it("tracks the connection status", () => {
    useLiveStore.getState().setStatus("live");
    expect(useLiveStore.getState().status).toBe("live");
  });
});
