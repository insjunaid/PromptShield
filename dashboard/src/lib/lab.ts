import type { LabJob, LabScenario, LiveEvent, Verdict } from "@/api/types";

// The order categories appear in the picker: the plain cases first, then the trickier ones.
const CATEGORY_ORDER = [
  "visible_text",
  "hidden_text",
  "markdown",
  "encoded",
  "unicode",
  "multilingual",
  "image",
  "metadata",
  "payload_split",
  "email",
  "tool_poisoning",
  "rug_pull",
  "benign",
];

const CATEGORY_LABEL: Record<string, string> = {
  visible_text: "Visible text",
  hidden_text: "Hidden text",
  markdown: "Markdown",
  encoded: "Encoded",
  unicode: "Unicode tricks",
  multilingual: "Other languages",
  image: "Text in images",
  metadata: "Metadata",
  payload_split: "Split payloads",
  email: "Email",
  tool_poisoning: "Tool poisoning",
  rug_pull: "Rug pull",
  benign: "Benign tasks",
};

export interface ScenarioGroup {
  category: string;
  label: string;
  scenarios: LabScenario[];
}

export function categoryLabel(category: string): string {
  return CATEGORY_LABEL[category] ?? category.replace(/_/g, " ");
}

/** Scenarios grouped by category, known categories in a fixed order and unknown ones after. */
export function groupScenarios(scenarios: LabScenario[]): ScenarioGroup[] {
  const groups = new Map<string, LabScenario[]>();
  for (const scenario of scenarios) {
    const list = groups.get(scenario.category) ?? [];
    list.push(scenario);
    groups.set(scenario.category, list);
  }
  const rank = (category: string) => {
    const index = CATEGORY_ORDER.indexOf(category);
    return index === -1 ? CATEGORY_ORDER.length : index;
  };
  return [...groups.entries()]
    .sort(([a], [b]) => rank(a) - rank(b) || a.localeCompare(b))
    .map(([category, list]) => ({
      category,
      label: categoryLabel(category),
      scenarios: [...list].sort((a, b) => a.id.localeCompare(b.id)),
    }));
}

export type TimelineItem =
  | { kind: "thought"; id: string; text: string }
  | { kind: "call"; id: string; tool: string; args: string }
  | { kind: "result"; id: string; tool: string; text: string; marked: boolean }
  | { kind: "check"; id: string; tool: string; stage: "action" | "content"; verdict: Verdict }
  | { kind: "alert"; id: string; title: string; detail: string };

function text(value: unknown): string {
  if (typeof value === "string") return value;
  if (value === undefined || value === null) return "";
  return JSON.stringify(value);
}

function payload(event: LiveEvent): Record<string, unknown> {
  return (event.payload ?? {}) as Record<string, unknown>;
}

// promptshield/sanitize.py wraps scanned results like this and puts the policy's marker ("^" by
// default) between words, so the AI can tell the data from instructions.
const WRAPPER_OPEN = /^<<UNTRUSTED_TOOL_DATA[^\n]*>>\n?/;
const WRAPPER_CLOSE = "\n<</UNTRUSTED_TOOL_DATA>>";
const DATAMARK = /\^/g;

/**
 * A wrapped, datamarked result as a person would read it: no wrapper, spaces for the marks. The
 * step says it was marked, because this is not literally what the AI received. Real carets in the
 * content also become spaces; that only affects this view.
 */
export function readableResult(raw: string): { text: string; marked: boolean } {
  if (!WRAPPER_OPEN.test(raw)) return { text: raw, marked: false };
  const body = raw.replace(WRAPPER_OPEN, "");
  const end = body.indexOf(WRAPPER_CLOSE);
  const inside = end === -1 ? body : body.slice(0, end);
  const after = end === -1 ? "" : body.slice(end + WRAPPER_CLOSE.length);
  return { text: (inside.replace(DATAMARK, " ") + after).trim(), marked: true };
}

function timelineItem(event: LiveEvent): TimelineItem | null {
  const data = payload(event);
  const tool = event.tool ?? "unknown tool";
  switch (event.type) {
    case "agent_message":
      return { kind: "thought", id: event.id, text: text(data.text) };
    case "tool_call":
      // The gateway's record of a call carries its verdict; the agent's own record doesn't.
      if (event.verdict != null) return { kind: "check", id: event.id, tool, stage: "action", verdict: event.verdict };
      return { kind: "call", id: event.id, tool, args: text(data.args) };
    case "verdict":
      return event.verdict == null ? null : { kind: "check", id: event.id, tool, stage: "content", verdict: event.verdict };
    case "tool_result":
      return { kind: "result", id: event.id, tool, ...readableResult(text(data.text)) };
    case "canary_tripped":
      return { kind: "alert", id: event.id, title: "Canary in an outgoing call", detail: `${tool} tried to send a planted secret.` };
    case "registry_alert": {
      const rules = Array.isArray(data.rules) ? data.rules.map(text).join(", ") : "";
      const tools = Array.isArray(data.tools) ? data.tools.map(text).join(", ") : (event.tool ?? "");
      return { kind: "alert", id: event.id, title: `Tool ${text(data.status) || "flagged"}`, detail: [tools, rules].filter(Boolean).join(" · ") };
    }
    default:
      return null;
  }
}

/** One run's steps, oldest first. ULIDs sort by time, and the store keeps newest first. */
export function timelineItems(events: LiveEvent[], sessionId: string): TimelineItem[] {
  return events
    .filter((event) => event.session_id === sessionId)
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
    .map(timelineItem)
    .filter((item): item is TimelineItem => item !== null);
}

export function isActive(job: LabJob | undefined): boolean {
  return job === undefined || job.status === "queued" || job.status === "running";
}

export type Tone = "bad" | "good" | "neutral";

export interface RunVerdict {
  tone: Tone;
  title: string;
  detail: string;
}

/**
 * The banner under each panel. It says what happened, including the cases that don't flatter
 * the shield: an attack that got through, or one the agent simply ignored.
 */
export function runVerdict(job: LabJob | undefined): RunVerdict | null {
  if (job === undefined || isActive(job)) return null;
  const outcome = job.outcome;
  if (job.status === "failed" || outcome === null) {
    return { tone: "neutral", title: "Run failed", detail: "The run stopped before it finished. Check the API log." };
  }
  if (outcome.status === "error") {
    return { tone: "neutral", title: "Run failed", detail: outcome.error ?? "The agent hit an error." };
  }
  const task = outcome.utility_ok === true ? "task completed" : outcome.utility_ok === false ? "task not completed" : "task not checked";
  if (!outcome.attack) {
    return { tone: outcome.utility_ok === false ? "bad" : "good", title: outcome.utility_ok === false ? "Task not completed" : "Task completed", detail: "Benign scenario: nothing to block." };
  }
  if (outcome.attack_succeeded === true) {
    const how = outcome.conditions_met.length > 0 ? outcome.conditions_met.join(", ") : "the attack's goal was met";
    return { tone: "bad", title: "Attack succeeded", detail: how };
  }
  if (outcome.attack_succeeded === false && outcome.blocked_by.length > 0) {
    return { tone: "good", title: "Attack blocked", detail: `${task} · ${outcome.blocked_by.join(", ")}` };
  }
  if (outcome.attack_succeeded === false) {
    return { tone: "neutral", title: "Attack didn't land", detail: `The agent didn't act on it this time · ${task}` };
  }
  return { tone: "neutral", title: "No result", detail: `The run ended (${outcome.status}) without a verdict.` };
}

/** A short line for one sink capture: method, path and the start of what was sent. */
export function describeCapture(capture: LabJob["captured"][number]): string {
  const query = capture.query ? `?${capture.query}` : "";
  const body = capture.body ? ` ${capture.body}` : "";
  const line = `${capture.method} /${capture.path.replace(/^\//, "")}${query}${body}`;
  return line.length > 160 ? `${line.slice(0, 159)}…` : line;
}
