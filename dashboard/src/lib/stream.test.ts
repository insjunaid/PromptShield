import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { LiveEvent } from "@/api/types";
import type { ConnectionStatus } from "@/store/live";

import { LiveStream, PING_MS, retryDelay } from "./stream";

/** A WebSocket stand-in the test drives by hand. */
class FakeSocket {
  static instances: FakeSocket[] = [];
  readyState = 0;
  sent: string[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((message: { data: unknown }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;

  constructor(readonly url: string) {
    FakeSocket.instances.push(this);
  }

  open(): void {
    this.readyState = WebSocket.OPEN;
    this.onopen?.();
  }

  receive(data: unknown): void {
    this.onmessage?.({ data });
  }

  send(data: string): void {
    this.sent.push(data);
  }

  close(): void {
    this.readyState = WebSocket.CLOSED;
    this.onclose?.();
  }
}

function event(id: string): LiveEvent {
  return { id, ts: "2026-11-13T12:00:00Z", type: "verdict" } as LiveEvent;
}

interface Harness {
  stream: LiveStream;
  received: LiveEvent[];
  statuses: ConnectionStatus[];
  fetchMissed: ReturnType<typeof vi.fn>;
  last: { id: string | null };
}

function harness(): Harness {
  const received: LiveEvent[] = [];
  const statuses: ConnectionStatus[] = [];
  const last = { id: null as string | null };
  const fetchMissed = vi.fn(async (afterId: string) => [event(`${afterId}-next`)]);
  const stream = new LiveStream({
    url: "ws://test/v1/stream",
    fetchMissed,
    onEvents: (events) => received.push(...events),
    onStatus: (status) => statuses.push(status),
    lastEventId: () => last.id,
    createSocket: (url) => new FakeSocket(url) as unknown as WebSocket,
    random: () => 0,
  });
  return { stream, received, statuses, fetchMissed, last };
}

function latest(): FakeSocket {
  const socket = FakeSocket.instances.at(-1);
  if (socket === undefined) throw new Error("no socket opened");
  return socket;
}

describe("retryDelay", () => {
  it("doubles each time and stops at 30 seconds", () => {
    expect([0, 1, 2, 3, 10].map((attempt) => retryDelay(attempt, () => 0))).toEqual([
      1000, 2000, 4000, 8000, 30000,
    ]);
  });

  it("adds at most 20% jitter", () => {
    expect(retryDelay(0, () => 1)).toBe(1200);
  });
});

describe("LiveStream", () => {
  beforeEach(() => {
    FakeSocket.instances = [];
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("reports live once connected", () => {
    const h = harness();
    h.stream.connect();
    latest().open();
    expect(h.statuses).toEqual(["live"]);
  });

  it("passes events through", () => {
    const h = harness();
    h.stream.connect();
    latest().open();
    latest().receive(JSON.stringify({ type: "event", data: event("01A") }));
    expect(h.received.map((e) => e.id)).toEqual(["01A"]);
  });

  it("ignores messages it can't read", () => {
    const h = harness();
    h.stream.connect();
    latest().open();
    latest().receive("not json");
    latest().receive(JSON.stringify({ type: "event", data: { no: "id" } }));
    latest().receive(JSON.stringify({ type: "stats", data: {} }));
    latest().receive(new ArrayBuffer(4));
    expect(h.received).toEqual([]);
  });

  it("reconnects with backoff after the connection drops", () => {
    const h = harness();
    h.stream.connect();
    latest().open();
    latest().close();
    expect(h.statuses.at(-1)).toBe("reconnecting");
    expect(FakeSocket.instances).toHaveLength(1);
    vi.advanceTimersByTime(1000);
    expect(FakeSocket.instances).toHaveLength(2);
  });

  it("waits longer after each failed attempt", () => {
    const h = harness();
    h.stream.connect();
    latest().close(); // first retry after 1 s
    vi.advanceTimersByTime(1000);
    latest().close(); // second retry after 2 s
    vi.advanceTimersByTime(1999);
    expect(FakeSocket.instances).toHaveLength(2);
    vi.advanceTimersByTime(1);
    expect(FakeSocket.instances).toHaveLength(3);
  });

  it("fetches what it missed after reconnecting", async () => {
    const h = harness();
    h.last.id = "01A";
    h.stream.connect();
    latest().open();
    await vi.runOnlyPendingTimersAsync();
    expect(h.fetchMissed).toHaveBeenCalledWith("01A");
    expect(h.received.map((e) => e.id)).toEqual(["01A-next"]);
  });

  it("doesn't fetch history on a first connection with nothing seen", () => {
    const h = harness();
    h.stream.connect();
    latest().open();
    expect(h.fetchMissed).not.toHaveBeenCalled();
  });

  it("survives a failed catch-up", async () => {
    const h = harness();
    h.last.id = "01A";
    h.fetchMissed.mockRejectedValueOnce(new Error("down"));
    h.stream.connect();
    latest().open();
    await vi.runOnlyPendingTimersAsync();
    expect(h.statuses).toEqual(["live"]);
  });

  it("pings to keep the connection open", () => {
    const h = harness();
    h.stream.connect();
    latest().open();
    vi.advanceTimersByTime(PING_MS);
    expect(latest().sent).toEqual([JSON.stringify({ type: "ping" })]);
  });

  it("stays closed once closed on purpose", () => {
    const h = harness();
    h.stream.connect();
    latest().open();
    h.stream.close();
    vi.advanceTimersByTime(60_000);
    expect(FakeSocket.instances).toHaveLength(1);
    expect(h.statuses).not.toContain("reconnecting");
  });
});
