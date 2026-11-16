import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { LiveEvent, StatsSnapshot } from "@/api/types";
import { useLiveStore } from "@/store/live";
import { useUiStore } from "@/store/ui";

import { OverviewPage } from "./Overview";

function stats(overrides: Partial<StatsSnapshot> = {}): StatsSnapshot {
  return {
    window: "1h",
    scans: 0,
    blocked: 0,
    sanitized: 0,
    approvals_pending: 0,
    canaries_tripped: 0,
    p50_ms: 0,
    p95_ms: 0,
    findings_by_layer: {},
    top_rules: {},
    series: [],
    ...overrides,
  } as StatsSnapshot;
}

function blockEvent(): LiveEvent {
  return {
    id: "01M7ACESG0FGWQKP6FE0XNBY5B",
    ts: new Date().toISOString(),
    session_id: "01M7ACESG0SESSION0000AB12",
    type: "verdict",
    tool: "web.web_fetch",
    verdict: {
      decision: "BLOCK",
      risk_score: 0.83,
      reasons: ["Instruction in text hidden by CSS"],
      layers_run: { L0: "ran", L2: "ran", L1: "ran" },
      total_latency_ms: 153,
      findings: [
        {
          layer: "L2",
          rule_id: "L2.CSS.color_match",
          title: "Instruction in text matching its background",
          severity: "HIGH",
          score: 0.85,
          evidence: "hidden text",
          latency_ms: 2,
        },
      ],
    },
  } as LiveEvent;
}

function mockStats(snapshot: StatsSnapshot): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response(JSON.stringify(snapshot), { status: 200 })),
  );
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <OverviewPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("OverviewPage", () => {
  beforeEach(() => {
    useLiveStore.getState().reset();
    useUiStore.getState().setWindow("1h");
    // jsdom lays nothing out, so every element measures 0x0 and the virtual list (which reads
    // clientWidth and clientHeight) would show no rows. A browser-sized box lets it render.
    vi.spyOn(HTMLElement.prototype, "clientHeight", "get").mockReturnValue(560);
    vi.spyOn(HTMLElement.prototype, "clientWidth", "get").mockReturnValue(800);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("invites a lab run when there is no traffic", async () => {
    mockStats(stats());
    renderPage();
    expect(await screen.findByText("No traffic yet.")).toBeDefined();
    expect(screen.getByRole("link", { name: "Red-Team Lab" })).toBeDefined();
  });

  it("shows the numbers and the feed", async () => {
    mockStats(stats({ scans: 7, blocked: 2, sanitized: 1, p95_ms: 153, top_rules: { "L2.CSS.color_match": 2 } }));
    useLiveStore.getState().addEvents([blockEvent()]);
    renderPage();
    expect(await screen.findByText("7")).toBeDefined();
    expect(screen.getByText("153 ms")).toBeDefined();
    expect(screen.getByText("Blocked")).toBeDefined();
    expect(screen.getByText("Instruction in text hidden by CSS")).toBeDefined();
    expect(screen.getByText("L2.CSS.color_match")).toBeDefined();
  });

  it("opens the verdict detail from a feed row", async () => {
    mockStats(stats({ scans: 1, blocked: 1 }));
    useLiveStore.getState().addEvents([blockEvent()]);
    renderPage();
    fireEvent.click(await screen.findByText("Instruction in text hidden by CSS"));
    expect(await screen.findByRole("dialog")).toBeDefined();
    expect(screen.getByText("Verdict")).toBeDefined();
    expect(screen.getAllByText("L2.CSS.color_match").length).toBeGreaterThan(0);
    expect(screen.getByRole("link", { name: "Open the session replay" })).toBeDefined();
  });

  it("raises the alarm when a canary tried to leave", async () => {
    mockStats(stats({ scans: 1, blocked: 1, canaries_tripped: 1 }));
    useLiveStore.getState().addEvents([blockEvent()]);
    renderPage();
    expect(await screen.findByText("Exfiltration attempt stopped")).toBeDefined();
  });

  it("says when the numbers couldn't load, with a retry", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("down", { status: 500 })));
    useLiveStore.getState().addEvents([blockEvent()]);
    renderPage();
    await waitFor(() => expect(screen.getByRole("alert").textContent).toContain("Couldn't load"));
    expect(screen.getByRole("button", { name: "Retry" })).toBeDefined();
  });
});
