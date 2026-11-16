import { useQuery } from "@tanstack/react-query";
import { PanelLeftClose, PanelLeftOpen, Shield } from "lucide-react";
import { NavLink } from "react-router";

import { fetchConfig } from "@/api/client";
import { usePendingApprovals } from "@/components/ApprovalWatcher";
import { ConnectionDot } from "@/components/ConnectionDot";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/cn";
import { NAV_ROUTES } from "@/routes";
import { useLiveStore } from "@/store/live";

function ModePill() {
  const { data } = useQuery({ queryKey: ["config"], queryFn: fetchConfig });
  if (data === undefined) {
    return <span className="text-xs text-muted">Mode unknown</span>;
  }
  const monitoring = data.mode === "monitor";
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full px-2.5 py-0.5 font-mono text-[11px] font-semibold tracking-wide",
        monitoring ? "bg-sanitize/15 text-sanitize" : "bg-allow/15 text-allow",
      )}
      title={monitoring ? "Monitor: verdicts are recorded, nothing is blocked" : "Enforce: verdicts are applied"}
    >
      {monitoring ? "MONITOR" : "ENFORCE"}
    </span>
  );
}

export function Sidebar({ collapsed, onToggle }: { collapsed: boolean; onToggle: () => void }) {
  const status = useLiveStore((state) => state.status);
  const pending = usePendingApprovals().data?.length ?? 0;
  return (
    <aside
      className={cn(
        "flex h-full flex-col border-r border-border bg-surface transition-[width]",
        collapsed ? "w-16" : "w-60",
      )}
    >
      <div className="flex h-14 items-center gap-2 px-4">
        <Shield className="h-5 w-5 shrink-0 text-accent" aria-hidden="true" />
        {!collapsed && <span className="text-sm font-semibold tracking-tight">PromptShield</span>}
      </div>
      <nav className="flex-1 space-y-1 px-2" aria-label="Main">
        {NAV_ROUTES.map(({ path, title, icon: Icon }) => (
          <NavLink
            key={path}
            to={path}
            end={path === "/"}
            title={collapsed ? title : undefined}
            className={({ isActive }) =>
              cn(
                "flex h-9 items-center gap-3 rounded-chip px-3 text-sm transition-colors",
                isActive ? "bg-surface-2 text-text" : "text-muted hover:bg-surface-2 hover:text-text",
              )
            }
          >
            <span className="relative">
              <Icon className="h-4 w-4 shrink-0" aria-hidden="true" />
              {path === "/approvals" && pending > 0 && collapsed && (
                <span className="absolute -right-1.5 -top-1.5 h-2.5 w-2.5 rounded-full bg-approval" aria-hidden="true" />
              )}
            </span>
            {!collapsed && <span>{title}</span>}
            {path === "/approvals" && pending > 0 && (
              <span className={cn("ml-auto rounded-full bg-approval px-1.5 text-[11px] font-semibold text-white tabular", collapsed && "sr-only")}>
                {pending}
                <span className="sr-only"> waiting</span>
              </span>
            )}
          </NavLink>
        ))}
      </nav>
      <div className="space-y-3 border-t border-border p-3">
        {!collapsed && (
          <div className="flex items-center justify-between">
            <ModePill />
            <ConnectionDot status={status} />
          </div>
        )}
        <Button
          variant="ghost"
          size="icon"
          onClick={onToggle}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {collapsed ? <PanelLeftOpen className="h-4 w-4" /> : <PanelLeftClose className="h-4 w-4" />}
        </Button>
      </div>
    </aside>
  );
}
