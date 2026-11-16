import type {
  ApprovalView,
  LabJob,
  LabReport,
  LabScenario,
  LiveEvent,
  PolicyDocument,
  RegistryTool,
  ReportSummary,
  RuntimeConfig,
  SessionReplay,
  StartedRun,
  StatsSnapshot,
} from "./types";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    /** The API's `error.details`, such as the list of problems in a refused policy. */
    readonly details: Record<string, unknown> = {},
  ) {
    super(message);
  }
}

/** Requests go to /v1 on the same origin; Vite proxies them to the API in development. */
async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(path, { headers: { Accept: "application/json" } });
  if (!response.ok) throw new ApiError(response.status, `${path} returned ${response.status}`);
  return (await response.json()) as T;
}

interface ErrorBody {
  error?: { message?: unknown; details?: unknown };
}

/**
 * Changes go through the same proxy. The browser sends this page's Origin with every change, and
 * the Vite proxy adds the admin token only for that origin (vite.config.ts).
 */
async function sendJson<T>(method: "POST" | "PUT", path: string, body?: unknown): Promise<T> {
  const response = await fetch(path, {
    method,
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) {
    let message = `${path} returned ${response.status}`;
    let details: Record<string, unknown> = {};
    try {
      const parsed = (await response.json()) as ErrorBody;
      if (typeof parsed.error?.message === "string") message = parsed.error.message;
      if (parsed.error?.details && typeof parsed.error.details === "object") {
        details = parsed.error.details as Record<string, unknown>;
      }
    } catch {
      // not JSON: keep the status line
    }
    throw new ApiError(response.status, message, details);
  }
  return (await response.json()) as T;
}

function postJson<T>(path: string, body?: unknown): Promise<T> {
  return sendJson<T>("POST", path, body);
}

export function fetchApprovals(status: "pending" | null = "pending"): Promise<ApprovalView[]> {
  return getJson<ApprovalView[]>(status ? `/v1/approvals?status=${status}` : "/v1/approvals");
}

export function decideApproval(id: string, decision: "approve" | "deny"): Promise<unknown> {
  return postJson(`/v1/approvals/${encodeURIComponent(id)}`, { decision });
}

export function fetchRegistry(): Promise<RegistryTool[]> {
  return getJson<RegistryTool[]>("/v1/registry/tools");
}

export function approveTool(server: string, tool: string): Promise<unknown> {
  return postJson(`/v1/registry/tools/${encodeURIComponent(server)}/${encodeURIComponent(tool)}/approve`);
}

export function fetchPolicy(): Promise<PolicyDocument> {
  return getJson<PolicyDocument>("/v1/policy");
}

export function savePolicy(yaml: string): Promise<PolicyDocument> {
  return sendJson<PolicyDocument>("PUT", "/v1/policy", { yaml });
}

export function setPolicyMode(mode: "enforce" | "monitor"): Promise<PolicyDocument> {
  return postJson<PolicyDocument>("/v1/policy/mode", { mode });
}

export function fetchReports(): Promise<ReportSummary[]> {
  return getJson<ReportSummary[]>("/v1/bench/reports");
}

export function fetchReport(id: string): Promise<LabReport> {
  return getJson<LabReport>(`/v1/bench/reports/${encodeURIComponent(id)}`);
}
export function fetchScenarios(): Promise<LabScenario[]> {
  return getJson<LabScenario[]>("/v1/lab/scenarios");
}

/** Queues the shield-off run, then the shield-on run, for one scenario. */
export function startPair(scenarioId: string): Promise<StartedRun[]> {
  return postJson<StartedRun[]>("/v1/lab/run-pair", { scenario_id: scenarioId });
}

export function fetchRun(runId: string): Promise<LabJob> {
  return getJson<LabJob>(`/v1/lab/runs/${encodeURIComponent(runId)}`);
}

export function resetLab(): Promise<{ status: string }> {
  return postJson<{ status: string }>("/v1/lab/reset");
}

export function fetchReplay(sessionId: string): Promise<SessionReplay> {
  return getJson<SessionReplay>(`/v1/sessions/${encodeURIComponent(sessionId)}/replay`);
}

export function fetchEventsAfter(afterId: string): Promise<LiveEvent[]> {
  const query = new URLSearchParams({ after: afterId, limit: "500" });
  return getJson<LiveEvent[]>(`/v1/events?${query.toString()}`);
}

export function fetchRecentEvents(limit = 200): Promise<LiveEvent[]> {
  return getJson<LiveEvent[]>(`/v1/events?limit=${limit}`);
}

export function fetchConfig(): Promise<RuntimeConfig> {
  return getJson<RuntimeConfig>("/v1/config");
}

export function fetchStats(window: "1h" | "24h" | "all"): Promise<StatsSnapshot> {
  return getJson<StatsSnapshot>(`/v1/stats?window=${window}`);
}
