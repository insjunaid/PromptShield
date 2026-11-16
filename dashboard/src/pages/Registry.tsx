import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Package } from "lucide-react";
import { Fragment, useState } from "react";

import { ApiError, approveTool, fetchRegistry } from "@/api/client";
import type { RegistryTool } from "@/api/types";
import { SeverityChip } from "@/components/DecisionChip";
import { EmptyState } from "@/components/EmptyState";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { cn } from "@/lib/cn";

const STATUS: Record<RegistryTool["status"], { label: string; className: string }> = {
  trusted: { label: "Trusted", className: "bg-allow/15 text-allow" },
  flagged: { label: "Flagged", className: "bg-sanitize/15 text-sanitize" },
  quarantined: { label: "Quarantined", className: "bg-block/15 text-block" },
};

function short(hash: string | null | undefined): string {
  return hash ? hash.slice(0, 12) : "—";
}

/** A pinned tool whose definition no longer matches its pin: the rug-pull case. */
export function changed(tool: RegistryTool): boolean {
  return tool.pinned_sha256 != null && tool.pinned_sha256 !== tool.sha256;
}

function ToolRow({ tool }: { tool: RegistryTool }) {
  const client = useQueryClient();
  const [problem, setProblem] = useState<string | null>(null);
  const approve = useMutation({
    mutationFn: () => approveTool(tool.server, tool.tool),
    onSuccess: () => void client.invalidateQueries({ queryKey: ["registry"] }),
    onError: (error) =>
      setProblem(error instanceof ApiError && error.status === 401 ? "The API turned this away (no admin token)." : "Couldn't re-approve. Try again."),
  });
  const status = STATUS[tool.status];
  const definitionChanged = changed(tool);
  const needsReview = tool.status !== "trusted";
  return (
    <Fragment>
      <tr className="border-t border-border align-top">
        <td className="py-3 pr-3">
          <div className="font-mono text-sm text-text">
            {tool.server}.{tool.tool}
          </div>
          {tool.description && <div className="mt-0.5 line-clamp-2 max-w-md text-xs text-muted">{tool.description}</div>}
        </td>
        <td className="py-3 pr-3">
          <span className={cn("rounded-chip px-2 py-0.5 text-xs font-medium", status.className)}>{status.label}</span>
        </td>
        <td className="py-3 pr-3 font-mono text-xs text-muted" title={tool.pinned_sha256 ?? undefined}>
          {short(tool.pinned_sha256)}
        </td>
        <td className="py-3 pr-3 text-xs text-muted tabular">{tool.pinned_updated ? new Date(tool.pinned_updated).toLocaleString() : "Not pinned yet"}</td>
        <td className="py-3 pr-3">
          {tool.findings.length === 0 ? (
            <span className="text-xs text-muted">None</span>
          ) : (
            <ul className="space-y-1">
              {tool.findings.map((finding) => (
                <li key={finding.rule_id} className="flex items-center gap-2">
                  <SeverityChip severity={finding.severity} />
                  <span className="font-mono text-xs text-text">{finding.rule_id}</span>
                </li>
              ))}
            </ul>
          )}
        </td>
        <td className="py-3 text-right">
          {needsReview && (
            <Button size="sm" variant="outline" disabled={approve.isPending} onClick={() => approve.mutate()}>
              Re-approve
            </Button>
          )}
        </td>
      </tr>
      {(definitionChanged || problem) && (
        <tr>
          <td colSpan={6} className="pb-3">
            {definitionChanged && (
              <div className="rounded-chip border border-block/30 bg-block/10 px-3 py-2 text-xs text-block">
                <p className="font-medium">Definition changed since it was approved</p>
                <p className="mt-0.5 font-mono">
                  pinned {short(tool.pinned_sha256)} → now {short(tool.sha256)}
                </p>
                <p className="mt-0.5 text-text">
                  Only the fingerprint is kept, not the old text, so read the new description above before re-approving.
                </p>
              </div>
            )}
            {problem && (
              <p className="mt-1 text-xs text-block" role="alert">
                {problem}
              </p>
            )}
          </td>
        </tr>
      )}
    </Fragment>
  );
}

export function RegistryPage() {
  const tools = useQuery({ queryKey: ["registry"], queryFn: fetchRegistry, refetchInterval: 10_000 });
  if (tools.isPending) return <div className="h-64 animate-pulse rounded-card bg-surface-2" aria-label="Loading tools" />;
  if (tools.isError) {
    return (
      <EmptyState icon={Package} title="Couldn't load the tool registry.">
        <button type="button" className="text-accent underline-offset-4 hover:underline" onClick={() => void tools.refetch()}>
          Retry
        </button>
      </EmptyState>
    );
  }
  if (tools.data.length === 0) {
    return (
      <EmptyState icon={Package} title="No upstream tools seen yet.">
        Tools appear once a client lists them through the gateway, or a lab run with the shield on does.
      </EmptyState>
    );
  }
  const review = tools.data.filter((tool) => tool.status !== "trusted").length;
  return (
    <Card className="p-4">
      <p className="mb-3 text-sm text-muted">
        {tools.data.length === 1 ? "1 tool" : `${tools.data.length} tools`} · {review === 0 ? "all trusted" : `${review} need review`}. Hashes pin each definition the first time it is seen.
      </p>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="text-xs text-muted">
            <tr>
              <th className="py-1 pr-3 font-medium">Tool</th>
              <th className="py-1 pr-3 font-medium">Status</th>
              <th className="py-1 pr-3 font-medium">Pinned hash</th>
              <th className="py-1 pr-3 font-medium">Pinned</th>
              <th className="py-1 pr-3 font-medium">Findings</th>
              <th className="py-1 font-medium">
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {[...tools.data]
              .sort((a, b) => Number(b.status !== "trusted") - Number(a.status !== "trusted") || `${a.server}.${a.tool}`.localeCompare(`${b.server}.${b.tool}`))
              .map((tool) => (
                <ToolRow key={`${tool.server}.${tool.tool}`} tool={tool} />
              ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
