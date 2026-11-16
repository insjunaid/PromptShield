import { cn } from "@/lib/cn";
import type { ConnectionStatus } from "@/store/live";

const STYLE: Record<ConnectionStatus, { dot: string; label: string }> = {
  live: { dot: "bg-allow", label: "Live" },
  connecting: { dot: "bg-muted", label: "Connecting" },
  reconnecting: { dot: "bg-sanitize", label: "Reconnecting" },
};

/** The status is written out as well, so it doesn't rely on colour alone. */
export function ConnectionDot({ status }: { status: ConnectionStatus }) {
  const { dot, label } = STYLE[status];
  return (
    <span className="inline-flex items-center gap-2 text-xs text-muted" role="status">
      <span className={cn("h-2 w-2 rounded-full", dot)} aria-hidden="true" />
      {label}
    </span>
  );
}
