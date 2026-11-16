import "./index.css";

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "@/App";
import { applyTheme, readTheme } from "@/lib/theme";

// Set the theme before the first paint, so a light-theme user doesn't see a dark flash.
applyTheme(readTheme());

const root = document.getElementById("root");
if (root === null) throw new Error("index.html is missing #root");

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
