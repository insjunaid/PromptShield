import { useEffect, useState } from "react";
import { Outlet } from "react-router";

import { ApprovalWatcher } from "@/components/ApprovalWatcher";
import { Sidebar } from "@/components/Sidebar";
import { TopBar } from "@/components/TopBar";
import { useLiveStream } from "@/hooks/useLiveStream";
import { applyTheme, readTheme, saveTheme, type Theme } from "@/lib/theme";
import { useLiveStore } from "@/store/live";

function ReconnectBanner() {
  const status = useLiveStore((state) => state.status);
  if (status !== "reconnecting") return null;
  return (
    <div className="border-b border-sanitize/30 bg-sanitize/10 px-6 py-2 text-xs text-sanitize" role="alert">
      Reconnecting to PromptShield… Live events will resume, and anything missed will be fetched.
    </div>
  );
}

export function AppShell() {
  const [collapsed, setCollapsed] = useState(false);
  const [theme, setTheme] = useState<Theme>(readTheme);
  useLiveStream();

  useEffect(() => {
    applyTheme(theme);
    saveTheme(theme);
  }, [theme]);

  return (
    <div className="flex h-full">
      <Sidebar collapsed={collapsed} onToggle={() => setCollapsed((value) => !value)} />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar theme={theme} onToggleTheme={() => setTheme((value) => (value === "dark" ? "light" : "dark"))} />
        <ReconnectBanner />
        <main className="flex-1 overflow-y-auto">
          <div className="mx-auto max-w-[1440px] p-6">
            <Outlet />
          </div>
        </main>
      </div>
      <ApprovalWatcher />
    </div>
  );
}
