import type { Decision, LayerStatus, LiveEvent, Segment, SegmentOrigin, Verdict } from "@/api/types";

// ---- Where text came from -------------------------------------------------------------------

export interface OriginStyle {
  label: string;
  /** Tailwind classes for the highlighted span. Colour is never the only signal: spans carry the label. */
  className: string;
}

// Built from the theme tokens, so both themes keep their contrast (D062).
export const ORIGIN_STYLE: Record<Exclude<SegmentOrigin, "visible">, OriginStyle> = {
  hidden_css: { label: "Hidden by CSS", className: "bg-block/15 text-block" },
  hidden_markup: { label: "Hidden markup", className: "bg-block/15 text-block" },
  html_comment: { label: "HTML comment", className: "bg-sanitize/15 text-sanitize" },
  attribute: { label: "Attribute", className: "bg-approval/15 text-approval" },
  meta: { label: "Metadata", className: "bg-approval/15 text-approval" },
  zero_width: { label: "Zero-width", className: "bg-sev-high/15 text-sev-high" },
  unicode_tag: { label: "Unicode tags (decoded)", className: "bg-sev-high/15 text-sev-high" },
  decoded_payload: { label: "Decoded payload", className: "bg-accent/15 text-accent" },
  ocr: { label: "Text in image (OCR)", className: "bg-allow/15 text-allow" },
  tool_description: { label: "Tool description", className: "bg-sanitize/15 text-sanitize" },
};

const HIDDEN_BY_LABEL: Record<NonNullable<Segment["hidden_by"]>, string> = {
  display_none: "display: none",
  tiny_font: "tiny font",
  color_match: "text colour matches the background",
  offscreen: "positioned off screen",
};

/** A person looking at the page sees visible text that no style hides. */
export function humanSees(segment: Segment): boolean {
  return segment.origin === "visible" && segment.hidden_by == null;
}

export interface AiPart {
  text: string;
  hidden: boolean;
  label: string | null;
  className: string | null;
  detail: string | null;
}

function encodingNote(segment: Segment): string | null {
  if (segment.encoding) return `was ${segment.encoding}`;
  return null;
}

/** Every segment, in order, with the hidden ones marked by where they came from. */
export function aiParts(segments: Segment[]): AiPart[] {
  return segments.map((segment) => {
    if (humanSees(segment)) return { text: segment.text, hidden: false, label: null, className: null, detail: null };
    if (segment.origin === "visible") {
      // Styled out of sight: the text is "visible" in the markup but no person sees it.
      const how = segment.hidden_by ? HIDDEN_BY_LABEL[segment.hidden_by] : "hidden";
      return { text: segment.text, hidden: true, label: "Hidden by CSS", className: ORIGIN_STYLE.hidden_css.className, detail: how };
    }
    const style = ORIGIN_STYLE[segment.origin];
    const detail = segment.hidden_by ? HIDDEN_BY_LABEL[segment.hidden_by] : encodingNote(segment);
    return { text: segment.text, hidden: true, label: style.label, className: style.className, detail };
  });
}

/** The legend lists only origins that appear, so it explains this result and nothing else. */
export function legendFor(parts: AiPart[]): OriginStyle[] {
  const seen = new Map<string, OriginStyle>();
  for (const part of parts) {
    if (part.hidden && part.label && part.className) seen.set(part.label, { label: part.label, className: part.className });
  }
  return [...seen.values()];
}

/** What a person reads: the visible text, with a placeholder where an image was. */
export function humanText(segments: Segment[]): string {
  return segments
    .filter((segment) => humanSees(segment) || segment.origin === "ocr")
    .map((segment) => (segment.origin === "ocr" ? "[image]" : segment.text))
    .join("\n");
}

// ---- The scan pipeline ----------------------------------------------------------------------

const PIPELINE: { layer: string; label: string }[] = [
  { layer: "L0", label: "L0 Normalize" },
  { layer: "L2", label: "L2 Hidden" },
  { layer: "L1", label: "L1 Classifier" },
  { layer: "CANARY", label: "Canary" },
  { layer: "L3", label: "L3 Judge" },
  { layer: "L4", label: "L4 Action" },
  { layer: "REGISTRY", label: "Registry" },
];

export type NodeTone = "clear" | "fired" | "skipped" | "error" | "absent";

export interface PipelineNode {
  layer: string;
  label: string;
  status: LayerStatus | "not run";
  tone: NodeTone;
  findings: number;
  /** Known only when the layer reported a finding: findings carry the layer's time. */
  ms: number | null;
}

/**
 * One node per layer in pipeline order, then the policy. L4 and Registry appear only when they
 * ran, since content scans never use them.
 */
export function pipelineNodes(verdict: Verdict): PipelineNode[] {
  const statuses = verdict.layers_run ?? {};
  const findings = verdict.findings ?? [];
  return PIPELINE.filter(({ layer }) => !(layer === "L4" || layer === "REGISTRY") || layer in statuses || findings.some((f) => f.layer === layer)).map(
    ({ layer, label }) => {
      const own = findings.filter((finding) => finding.layer === layer);
      const status = statuses[layer] ?? (own.length > 0 ? "ran" : "not run");
      const tone: NodeTone =
        status === "error" ? "error" : status === "skipped" ? "skipped" : status === "not run" ? "absent" : own.length > 0 ? "fired" : "clear";
      const ms = own.length > 0 ? Math.max(...own.map((finding) => finding.latency_ms)) : null;
      return { layer, label, status, tone, findings: own.length, ms };
    },
  );
}

// ---- Timeline steps -------------------------------------------------------------------------

export type StepKind = "start" | "end" | "thought" | "call" | "check" | "result" | "alert" | "approval";

export interface ReplayStep {
  id: string;
  ts: string;
  kind: StepKind;
  title: string;
  tool: string | null;
  decision: Decision | null;
  /** Steps that need a look open by default: anything the shield didn't simply allow. */
  flagged: boolean;
  event: LiveEvent;
}

function str(value: unknown): string {
  if (typeof value === "string") return value;
  if (value === undefined || value === null) return "";
  return JSON.stringify(value);
}

function step(event: LiveEvent): ReplayStep {
  const tool = event.tool ?? null;
  const verdict = event.verdict ?? null;
  const base = { id: event.id, ts: event.ts, tool, decision: verdict?.decision ?? null, event };
  const flagged = verdict != null && verdict.decision !== "ALLOW";
  switch (event.type) {
    case "session_start":
      return { ...base, kind: "start", title: "Session started", flagged: false };
    case "session_end":
      return { ...base, kind: "end", title: "Session ended", flagged: false };
    case "agent_message":
      return { ...base, kind: "thought", title: "Agent", flagged: false };
    case "tool_call":
      if (verdict != null) return { ...base, kind: "check", title: "Action check", flagged };
      return { ...base, kind: "call", title: "Tool call", flagged: false };
    case "verdict":
      return { ...base, kind: "check", title: "Content scan", flagged };
    case "tool_result":
      return { ...base, kind: "result", title: "Tool result", flagged: false };
    case "canary_tripped":
      return { ...base, kind: "alert", title: "Canary in an outgoing call", flagged: true };
    case "registry_alert":
      return { ...base, kind: "alert", title: `Tool ${str(event.payload?.status) || "flagged"}`, flagged: true };
    case "approval_requested":
      return { ...base, kind: "approval", title: "Approval requested", flagged: true };
    case "approval_resolved":
      return { ...base, kind: "approval", title: `Approval ${str(event.payload?.status) || "resolved"}`, flagged: false };
    default:
      return { ...base, kind: "alert", title: event.type, flagged: false };
  }
}

/** The session's steps in the order they happened. */
export function replaySteps(events: LiveEvent[]): ReplayStep[] {
  return [...events].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)).map(step);
}

/** Text worth showing for a step that isn't a check: the message, the arguments, the result. */
export function stepText(event: LiveEvent): string {
  const payload = (event.payload ?? {}) as Record<string, unknown>;
  if (event.type === "tool_call") return str(payload.args);
  if (event.type === "registry_alert") {
    return [str(payload.tools ?? event.tool), str(payload.rules)].filter(Boolean).join(" · ");
  }
  return str(payload.text ?? payload.reason ?? "");
}

export function sessionEnded(events: LiveEvent[]): boolean {
  return events.some((event) => event.type === "session_end");
}
