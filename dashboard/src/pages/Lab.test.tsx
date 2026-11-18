import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { LabJob, LabScenario, LiveEvent } from "@/api/types";
import { useLiveStore } from "@/store/live";

import { LabPage } from "./Lab";

const SCENARIOS: LabScenario[] = [
  { id: "A01", name: "Visible instruction", category: "visible_text", attack: true },
  { id: "B01", name: "Weather report", category: "benign", attack: false },
];

const OFF = { run_id: "run-off", session_id: "01M7SESSIONOFF000000000000" };
const ON = { run_id: "run-on", session_id: "01M7SESSIONON0000000000000" };

function job(started: typeof OFF, shield: boolean, overrides: Partial<LabJob> = {}): LabJob {
  return {
    ...started,
    scenario_id: "A01",
    shield,
    status: "finished",
    outcome: {
      status: "finished",
      attack: true,
      attack_succeeded: !shield,
      conditions_met: shield ? [] : ["canary_at_sink"],
      utility_ok: true,
      blocked_by: shield ? ["L1.classifier"] : [],
      latency_ms: 9000,
      steps: 3,
    },
    captured: shield ? [] : [{ id: "c1", ts: "", method: "GET", path: "collect", query: "k=[REDACTED:canary]", body: "" }],
    ...overrides,
  };
}

type Route = (url: string, init?: RequestInit) => Response | undefined;

function serve(route: Route): ReturnType<typeof vi.fn> {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const custom = route(url, init);
    if (custom) return custom;
    if (url === "/v1/lab/scenarios") return Response.json(SCENARIOS);
    if (url === "/v1/lab/run-pair") return Response.json([OFF, ON]);
    if (url === "/v1/lab/runs/run-off") return Response.json(job(OFF, false));
    if (url === "/v1/lab/runs/run-on") return Response.json(job(ON, true));
    return new Response("not found", { status: 404 });
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <LabPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

async function runA01() {
  fireEvent.click(await screen.findByRole("button", { name: /A01/ }));
  fireEvent.click(screen.getByRole("button", { name: "Run comparison" }));
}

describe("LabPage", () => {
  beforeEach(() => useLiveStore.getState().reset());

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("groups scenarios with attack and benign badges, and needs a pick before running", async () => {
    serve(() => undefined);
    renderPage();
    expect(await screen.findByRole("region", { name: "Visible text" })).toBeDefined();
    expect(screen.getByRole("region", { name: "Benign tasks" })).toBeDefined();
    expect(screen.getByText("Attack")).toBeDefined();
    expect(screen.getByText("Benign")).toBeDefined();
    expect((screen.getByRole("button", { name: "Run comparison" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("says so plainly when the installed package has no lab", async () => {
    const message = "The Red-Team Lab isn't part of the installed package. Run it from a clone of the repository.";
    serve((url) =>
      url === "/v1/lab/scenarios"
        ? Response.json({ error: { code: "not_found", message, details: {} } }, { status: 404 })
        : undefined,
    );
    renderPage();
    expect(await screen.findByText("The Red-Team Lab isn't installed here.")).toBeDefined();
    expect(screen.getByText(message, { exact: false })).toBeDefined();
    expect(screen.queryByText(/Is the API running/)).toBeNull();
  });

  it("runs the pair and shows each side's steps, sink and verdict", async () => {
    const fetchMock = serve(() => undefined);
    useLiveStore.getState().addEvents([
      { id: "01M7A0000000000000000000A1", ts: "2026-11-13T10:00:00Z", session_id: OFF.session_id, type: "agent_message", payload: { text: "Fetching the page." } },
      {
        id: "01M7A0000000000000000000B1",
        ts: "2026-11-13T10:00:05Z",
        session_id: ON.session_id,
        type: "verdict",
        tool: "web.web_fetch",
        payload: {},
        verdict: { decision: "BLOCK", risk_score: 0.9, reasons: ["Injected instruction"], findings: [], layers_run: {}, total_latency_ms: 120 },
      },
    ] as LiveEvent[]);
    renderPage();
    await runA01();

    const left = await screen.findByRole("region", { name: "Without PromptShield" });
    const right = screen.getByRole("region", { name: "With PromptShield" });
    expect(await within(left).findByText("Attack succeeded")).toBeDefined();
    expect(within(left).getByText("Fetching the page.")).toBeDefined();
    expect(within(left).getByText("Attacker sink received 1 request")).toBeDefined();
    expect(within(left).getByText("GET /collect?k=[REDACTED:canary]")).toBeDefined();
    expect(await within(right).findByText("Attack blocked")).toBeDefined();
    expect(within(right).getByText("Injected instruction")).toBeDefined();
    expect(within(right).getByText("Attacker sink: nothing received")).toBeDefined();

    const post = fetchMock.mock.calls.find(([url]) => url === "/v1/lab/run-pair");
    expect(JSON.parse(String(post?.[1]?.body))).toEqual({ scenario_id: "A01" });
  });

  it("keeps polling while a run is going and locks the controls", async () => {
    let calls = 0;
    serve((url) => {
      if (url !== "/v1/lab/runs/run-on") return undefined;
      calls += 1;
      return Response.json(job(ON, true, calls < 2 ? { status: "running", outcome: null } : {}));
    });
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      renderPage();
      await runA01();
      await waitFor(() => expect(screen.getByRole("button", { name: "Running…" })).toBeDefined());
      expect((screen.getByRole("button", { name: /Reset lab/ }) as HTMLButtonElement).disabled).toBe(true);
      await vi.advanceTimersByTimeAsync(1_600);
      expect(await screen.findByText("Attack blocked")).toBeDefined();
      expect(screen.getByRole("button", { name: "Run comparison" })).toBeDefined();
    } finally {
      vi.useRealTimers();
    }
  });

  it("explains a refused run instead of failing silently", async () => {
    serve((url) => (url === "/v1/lab/run-pair" ? Response.json({ detail: "missing admin token" }, { status: 401 }) : undefined));
    renderPage();
    await runA01();
    expect((await screen.findByRole("alert")).textContent).toContain("no admin token");
  });

  it("says when reset is refused because a run is going", async () => {
    serve((url) => (url === "/v1/lab/reset" ? Response.json({ detail: "a lab run is in progress" }, { status: 409 }) : undefined));
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: /Reset lab/ }));
    expect((await screen.findByRole("alert")).textContent).toContain("A run is still going");
  });

  it("offers a retry when the scenarios can't load", async () => {
    serve((url) => (url === "/v1/lab/scenarios" ? new Response("down", { status: 503 }) : undefined));
    renderPage();
    expect(await screen.findByText("Couldn't load the scenarios.")).toBeDefined();
    expect(screen.getByRole("button", { name: "Retry" })).toBeDefined();
  });
});
