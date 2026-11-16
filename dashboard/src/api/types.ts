import type { components } from "./schema";

// Short names for the generated API types. Regenerate with `pnpm gen:api` after an API change.
type Schemas = components["schemas"];

// The server always fills `id` and `ts`, but the schema marks them optional because they have
// defaults. Events the dashboard receives always carry both.
export type LiveEvent = Schemas["Event"] & { id: string; ts: string };
export type Verdict = Schemas["Verdict"];
export type Finding = Schemas["Finding"];
export type Decision = Schemas["Decision"];
export type Severity = Schemas["Severity"];
export type RuntimeConfig = Schemas["RuntimeConfig"];
export type StatsSnapshot = Schemas["StatsSnapshot"];
export type StatsBucket = Schemas["StatsBucket"];

export type LabScenario = Schemas["ScenarioSummary"];
export type StartedRun = Schemas["StartedRun"];
export type Direction = Schemas["Direction"];

// GET /v1/lab/runs/{id} returns the job as a plain dict (the lab's types stay out of the API's
// startup), so it has no generated type. Kept in step with lab/jobs.py and models.LabRunOutcome.
export type LabJobStatus = "queued" | "running" | "finished" | "failed";

export interface LabOutcome {
  status: "finished" | "step_limit" | "timeout" | "error";
  error?: string | null;
  attack: boolean;
  attack_succeeded?: boolean | null;
  conditions_met: string[];
  utility_ok?: boolean | null;
  blocked_by: string[];
  latency_ms: number;
  steps: number;
}

/** One request the attacker's sink received. Redacted by the API. */
export interface SinkCapture {
  id: string;
  ts: string;
  method: string;
  path: string;
  query: string;
  body: string;
}

export interface LabJob {
  run_id: string;
  session_id: string;
  scenario_id: string;
  shield: boolean;
  status: LabJobStatus;
  outcome: LabOutcome | null;
  captured: SinkCapture[];
}

export type SessionSummary = Schemas["SessionSummary"];
export type SessionReplay = Schemas["SessionReplay"] & { events: LiveEvent[] };
export type Segment = Schemas["Segment"];
export type SegmentOrigin = Segment["origin"];
export type LayerStatus = NonNullable<Verdict["layers_run"]>[string];

export type ApprovalView = Schemas["ApprovalView"];
export type RegistryTool = Schemas["RegistryTool"];
export type PolicyDocument = Schemas["PolicyDocument"];
/** One problem in a refused policy (422 body). Not in the schema: it comes back as an error. */
export interface PolicyProblem {
  where: string;
  message: string;
}
export type ReportSummary = Schemas["ReportSummary"];

/** A lab report from eval/reports, written by eval/report.py. Only the fields the page reads. */
export interface HitRate {
  hits: number;
  total: number;
}

export interface LabReport {
  info: { batch: string; date: string; git: string; machine?: string; agent_model?: string; repeats?: number; shield?: boolean };
  summary: {
    runs: number;
    attack_success: HitRate;
    utility_benign: HitRate;
    utility_under_attack: HitRate;
    unknown_attacks?: number;
    by_category: Record<string, HitRate>;
    p50_seconds?: number;
    p95_seconds?: number;
  };
}
