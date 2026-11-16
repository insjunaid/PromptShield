import { Moon, Sun } from "lucide-react";
import { useLocation } from "react-router";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/cn";
import type { Theme } from "@/lib/theme";
import { titleFor } from "@/routes";
import { type TimeWindow, useUiStore } from "@/store/ui";

const WINDOWS: { value: TimeWindow; label: string }[] = [
  { value: "1h", label: "1h" },
  { value: "24h", label: "24h" },
  { value: "all", label: "All" },
];

export function TopBar({ theme, onToggleTheme }: { theme: Theme; onToggleTheme: () => void }) {
  const { pathname } = useLocation();
  const window = useUiStore((state) => state.window);
  const setWindow = useUiStore((state) => state.setWindow);
  return (
    <header className="flex h-14 items-center justify-between border-b border-border px-6">
      <h1 className="text-[22px] font-semibold tracking-tight">{titleFor(pathname)}</h1>
      <div className="flex items-center gap-3">
        <div className="flex rounded-chip border border-border p-0.5" role="group" aria-label="Time window">
          {WINDOWS.map(({ value, label }) => (
            <button
              key={value}
              type="button"
              onClick={() => setWindow(value)}
              aria-pressed={window === value}
              className={cn(
                "h-7 rounded-[4px] px-3 text-xs font-medium tabular",
                window === value ? "bg-surface-2 text-text" : "text-muted hover:text-text",
              )}
            >
              {label}
            </button>
          ))}
        </div>
        <Button
          variant="ghost"
          size="icon"
          onClick={onToggleTheme}
          aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
        >
          {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
        </Button>
      </div>
    </header>
  );
}
