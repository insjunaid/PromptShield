import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { titleFor } from "@/routes";

import { ConnectionDot } from "./ConnectionDot";
import { DecisionChip, SeverityChip } from "./DecisionChip";

// Colour is never the only signal (UI_DESIGN.md §6), so every state must have readable text.

describe("chips", () => {
  it.each([
    ["ALLOW", "Allowed"],
    ["SANITIZE", "Sanitized"],
    ["REQUIRE_APPROVAL", "Needs approval"],
    ["BLOCK", "Blocked"],
  ] as const)("decision %s reads as %s", (decision, label) => {
    render(<DecisionChip decision={decision} />);
    expect(screen.getByText(label)).toBeDefined();
  });

  it("severity is written out", () => {
    render(<SeverityChip severity="CRITICAL" />);
    expect(screen.getByText("CRITICAL")).toBeDefined();
  });

  it.each([
    ["live", "Live"],
    ["connecting", "Connecting"],
    ["reconnecting", "Reconnecting"],
  ] as const)("connection %s reads as %s", (status, label) => {
    render(<ConnectionDot status={status} />);
    expect(screen.getByRole("status").textContent).toBe(label);
  });
});

describe("titleFor", () => {
  it("names each page", () => {
    expect(titleFor("/")).toBe("Overview");
    expect(titleFor("/lab")).toBe("Red-Team Lab");
    expect(titleFor("/sessions/01ABC")).toBe("Attack Replay");
    expect(titleFor("/nowhere")).toBe("Not found");
  });
});
