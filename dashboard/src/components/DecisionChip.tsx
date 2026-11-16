import type { Decision, Severity } from "@/api/types";
import { cn } from "@/lib/cn";

// Colour is never the only signal: every chip carries its label as text.
const DECISION_STYLE: Record<Decision, string> = {
  ALLOW: "bg-allow/15 text-allow",
  SANITIZE: "bg-sanitize/15 text-sanitize",
  REQUIRE_APPROVAL: "bg-approval/15 text-approval",
  BLOCK: "bg-block/15 text-block",
};

const DECISION_LABEL: Record<Decision, string> = {
  ALLOW: "Allowed",
  SANITIZE: "Sanitized",
  REQUIRE_APPROVAL: "Needs approval",
  BLOCK: "Blocked",
};

export function DecisionChip({ decision }: { decision: Decision }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-chip px-2 py-0.5 text-xs font-medium",
        DECISION_STYLE[decision],
      )}
    >
      {DECISION_LABEL[decision]}
    </span>
  );
}

const SEVERITY_STYLE: Record<Severity, string> = {
  INFO: "bg-sev-info/15 text-sev-info",
  LOW: "bg-sev-low/15 text-sev-low",
  MEDIUM: "bg-sev-medium/15 text-sev-medium",
  HIGH: "bg-sev-high/15 text-sev-high",
  CRITICAL: "bg-sev-critical text-white",
};

export function SeverityChip({ severity }: { severity: Severity }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-chip px-2 py-0.5 font-mono text-[11px] font-medium",
        SEVERITY_STYLE[severity],
      )}
    >
      {severity}
    </span>
  );
}
