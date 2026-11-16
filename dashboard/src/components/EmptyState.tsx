import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

export function EmptyState({
  icon: Icon,
  title,
  children,
}: {
  icon: LucideIcon;
  title: string;
  children?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-card border border-dashed border-border px-6 py-16 text-center">
      <Icon className="h-6 w-6 text-muted" aria-hidden="true" />
      <p className="text-sm font-medium text-text">{title}</p>
      {children !== undefined && <div className="max-w-md text-sm text-muted">{children}</div>}
    </div>
  );
}
