import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it } from "vitest";

import type { LiveEvent } from "@/api/types";
import { useLiveStore } from "@/store/live";

import { ApprovalWatcher } from "./ApprovalWatcher";

function approvalEvent(id: string, type: "approval_requested" | "approval_resolved", approvalId: string, ts = new Date().toISOString()): LiveEvent {
  return { id, ts, session_id: "s", type, tool: "http.http_post", payload: { approval_id: approvalId } } as LiveEvent;
}

function renderWatcher() {
  return render(
    <QueryClientProvider client={new QueryClient()}>
      <MemoryRouter>
        <ApprovalWatcher />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("ApprovalWatcher", () => {
  beforeEach(() => useLiveStore.getState().reset());

  it("toasts a new request, not old ones, and clears the toast once it is decided", () => {
    useLiveStore.getState().addEvents([approvalEvent("01", "approval_requested", "old")]);
    renderWatcher();
    expect(screen.queryByRole("status")).toBeNull();

    act(() => useLiveStore.getState().addEvents([approvalEvent("02", "approval_requested", "ap1")]));
    expect(screen.getByRole("status").textContent).toContain("Approval needed: http.http_post");
    expect(screen.getByRole("link", { name: "Review" }).getAttribute("href")).toBe("/approvals");

    act(() => useLiveStore.getState().addEvents([approvalEvent("03", "approval_resolved", "ap1")]));
    expect(screen.queryByRole("status")).toBeNull();
  });

  it("doesn't toast history that loads after the page opens, decided or not", () => {
    renderWatcher();
    const hourAgo = new Date(Date.now() - 3_600_000).toISOString();
    act(() =>
      useLiveStore.getState().addEvents([
        approvalEvent("01", "approval_requested", "old", hourAgo),
        approvalEvent("02", "approval_requested", "ap2"),
        approvalEvent("03", "approval_resolved", "ap2"),
      ]),
    );
    expect(screen.queryByRole("status")).toBeNull();
  });
});
