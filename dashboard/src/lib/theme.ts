export type Theme = "dark" | "light";

const KEY = "promptshield.theme";

/**
 * The theme is a per-viewer convenience, so it lives in localStorage. Storage can be blocked or
 * throw (private windows, strict settings), so every access is guarded and dark is the default.
 */
export function readTheme(storage: Pick<Storage, "getItem"> | undefined = globalThis.localStorage): Theme {
  try {
    return storage?.getItem(KEY) === "light" ? "light" : "dark";
  } catch {
    return "dark";
  }
}

export function saveTheme(
  theme: Theme,
  storage: Pick<Storage, "setItem"> | undefined = globalThis.localStorage,
): void {
  try {
    storage?.setItem(KEY, theme);
  } catch {
    // Not remembered next time, which is fine.
  }
}

export function applyTheme(theme: Theme, root: HTMLElement = document.documentElement): void {
  root.dataset.theme = theme;
}
