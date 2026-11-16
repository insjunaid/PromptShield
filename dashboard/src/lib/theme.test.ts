import { describe, expect, it } from "vitest";

import { applyTheme, readTheme, saveTheme } from "./theme";

const throwing = {
  getItem: () => {
    throw new Error("blocked");
  },
  setItem: () => {
    throw new Error("blocked");
  },
};

describe("theme", () => {
  it("defaults to dark", () => {
    expect(readTheme({ getItem: () => null })).toBe("dark");
  });

  it("reads a saved light theme", () => {
    expect(readTheme({ getItem: () => "light" })).toBe("light");
  });

  it("treats an unknown saved value as dark", () => {
    expect(readTheme({ getItem: () => "purple" })).toBe("dark");
  });

  it("survives storage that throws", () => {
    expect(readTheme(throwing)).toBe("dark");
    expect(() => saveTheme("light", throwing)).not.toThrow();
  });

  it("applies the theme to the root element", () => {
    const root = document.createElement("html");
    applyTheme("light", root);
    expect(root.dataset.theme).toBe("light");
  });
});
