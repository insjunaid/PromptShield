import type { HitRate, LabReport, ReportSummary } from "@/api/types";

// ---- Policy text ----------------------------------------------------------------------------

export type ThresholdKey = "sanitize" | "block";

/**
 * Change one number inside the `thresholds:` block and nothing else, so the file keeps its
 * comments and layout. Returns null if the line isn't there, so the caller can say so instead of
 * silently doing nothing.
 */
export function setThreshold(yaml: string, key: ThresholdKey, value: number): string | null {
  const lines = yaml.split("\n");
  const start = lines.findIndex((line) => /^thresholds:\s*(#.*)?$/.test(line));
  if (start === -1) return null;
  const pattern = new RegExp(`^(\\s+${key}:\\s*)([0-9.]+)(.*)$`);
  for (let index = start + 1; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    if (/^\S/.test(line)) break; // the next top-level key: the block has ended
    const match = pattern.exec(line);
    if (match) {
      lines[index] = `${match[1]}${value.toFixed(2)}${match[3]}`;
      return lines.join("\n");
    }
  }
  return null;
}

// ---- Benchmarks -----------------------------------------------------------------------------

export interface ReportPair {
  off: ReportSummary | null;
  on: ReportSummary | null;
}

/**
 * The comparison the page leads with: for each shield setting, the report with the most
 * repeats, newest first among equals. More repeats means a steadier number.
 */
export function pickPair(reports: ReportSummary[]): ReportPair {
  const best = (shield: boolean) =>
    reports
      .filter((report) => report.kind === "lab" && report.shield === shield)
      .sort((a, b) => (b.repeats ?? 0) - (a.repeats ?? 0) || b.modified - a.modified)[0] ?? null;
  return { off: best(false), on: best(true) };
}

export function rate(value: HitRate | undefined): number | null {
  if (!value || value.total === 0) return null;
  return value.hits / value.total;
}

export function percent(value: HitRate | undefined): string {
  const share = rate(value);
  return share === null ? "—" : `${Math.round(share * 100)}%`;
}

export function fraction(value: HitRate | undefined): string {
  return value ? `${value.hits}/${value.total}` : "—";
}

export interface CategoryRow {
  category: string;
  off: number | null;
  on: number | null;
  offLabel: string;
  onLabel: string;
}

/** Attack success per category, both settings, as percentages. Missing data stays missing. */
export function categoryRows(off: LabReport | undefined, on: LabReport | undefined): CategoryRow[] {
  const names = new Set([...Object.keys(off?.summary.by_category ?? {}), ...Object.keys(on?.summary.by_category ?? {})]);
  return [...names].sort().map((category) => {
    const before = off?.summary.by_category[category];
    const after = on?.summary.by_category[category];
    const toPercent = (value: HitRate | undefined) => {
      const share = rate(value);
      return share === null ? null : Math.round(share * 100);
    };
    return { category, off: toPercent(before), on: toPercent(after), offLabel: fraction(before), onLabel: fraction(after) };
  });
}

// ---- Approvals ------------------------------------------------------------------------------

/** Seconds left until the approval times out and is denied, never below zero. */
export function secondsLeft(expires: string, now: number): number {
  return Math.max(0, Math.round((new Date(expires).getTime() - now) / 1000));
}

/** How much of the wait is left, 0 to 1, for the countdown ring. */
export function remainingShare(created: string, expires: string, now: number): number {
  const start = new Date(created).getTime();
  const end = new Date(expires).getTime();
  if (end <= start) return 0;
  return Math.min(1, Math.max(0, (end - now) / (end - start)));
}
