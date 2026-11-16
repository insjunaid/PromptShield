import { describe, expect, it } from "vitest";

import type { LabReport, ReportSummary } from "@/api/types";

import { categoryRows, fraction, percent, pickPair, remainingShare, secondsLeft, setThreshold } from "./admin";

const POLICY = `version: 1
mode: enforce            # enforce | monitor

thresholds:
  sanitize: 0.35
  block: 0.75
  judge_band: [0.30, 0.80]

weights:
  block: 9
`;

describe("setThreshold", () => {
  it("changes one number in the thresholds block and keeps everything else", () => {
    const next = setThreshold(POLICY, "block", 0.8);
    expect(next).toBe(POLICY.replace("  block: 0.75", "  block: 0.80"));
    expect(next).toContain("# enforce | monitor");
    expect(next).toContain("  block: 9"); // a same-named key in another block is untouched
  });

  it("keeps a trailing comment on the line", () => {
    const text = "thresholds:\n  sanitize: 0.35   # lower = stricter\n";
    expect(setThreshold(text, "sanitize", 0.3)).toBe("thresholds:\n  sanitize: 0.30   # lower = stricter\n");
  });

  it("says when it can't find the line instead of guessing", () => {
    expect(setThreshold("mode: enforce\n", "block", 0.8)).toBeNull();
    expect(setThreshold("thresholds:\n  judge_band: [0.3, 0.8]\nblock: 1\n", "block", 0.8)).toBeNull();
  });
});

function summary(id: string, shield: boolean, repeats: number, modified: number): ReportSummary {
  return { id, kind: "lab", shield, repeats, modified } as ReportSummary;
}

describe("pickPair", () => {
  it("takes the most repeats for each setting, newest among equals, and ignores other reports", () => {
    const pair = pickPair([
      summary("baseline_1", false, 1, 300),
      summary("baseline3_a", false, 3, 100),
      summary("baseline3_b", false, 3, 200),
      summary("shieldon1", true, 1, 400),
      { id: "judge_check", kind: "other", modified: 500 } as ReportSummary,
    ]);
    expect(pair.off?.id).toBe("baseline3_b");
    expect(pair.on?.id).toBe("shieldon1");
  });
});

describe("categoryRows", () => {
  it("lines up both reports by category and keeps missing data missing", () => {
    const off = { summary: { by_category: { hidden_text: { hits: 6, total: 6 }, email: { hits: 0, total: 3 } } } } as unknown as LabReport;
    const on = { summary: { by_category: { hidden_text: { hits: 0, total: 6 } } } } as unknown as LabReport;
    expect(categoryRows(off, on)).toEqual([
      { category: "email", off: 0, on: null, offLabel: "0/3", onLabel: "—" },
      { category: "hidden_text", off: 100, on: 0, offLabel: "6/6", onLabel: "0/6" },
    ]);
  });

  it("formats rates without dividing by zero", () => {
    expect(percent({ hits: 12, total: 39 })).toBe("31%");
    expect(percent({ hits: 0, total: 0 })).toBe("—");
    expect(fraction(undefined)).toBe("—");
  });
});

describe("approval countdown", () => {
  const created = "2026-11-14T10:00:00Z";
  const expires = "2026-11-14T10:02:00Z";
  it("counts down and stops at zero", () => {
    expect(secondsLeft(expires, Date.parse("2026-11-14T10:01:30Z"))).toBe(30);
    expect(secondsLeft(expires, Date.parse("2026-11-14T10:05:00Z"))).toBe(0);
    expect(remainingShare(created, expires, Date.parse("2026-11-14T10:01:30Z"))).toBeCloseTo(0.25);
    expect(remainingShare(created, expires, Date.parse("2026-11-14T10:05:00Z"))).toBe(0);
  });
});
